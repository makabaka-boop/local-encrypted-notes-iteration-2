import {
  decryptNote,
  deriveKek,
  generateDataKey,
  KDF_ITERATIONS,
  openManifest,
  randomBytes,
  unwrapDataKey,
  wrapDataKey,
} from './crypto';
import {
  canonicalManifestBytes,
  createBackupFile,
  parseBackupFile,
  timingSafeEqual,
} from './backup';
import { META_WRAPPED_KEY, NotesDB } from './db';
import { AuthError, BackupError, LockedError } from './errors';
import type { LockBus } from './lockbus';
import { MAX_NOTES, NoteStore } from './store';
import type { WrappedKeyRecord } from './types';

export interface SessionOptions {
  /** PBKDF2 迭代次数，测试可注入小值 */
  iterations?: number;
}

/**
 * 会话：负责解锁/锁定/改口令。
 *
 * - 口令只在 unlock / initialize / changePassphrase 调用期间存在于内存，
 *   派生出 KEK 后立即丢弃引用，绝不写盘；
 * - 数据密钥解锁期间驻留内存，锁定（本地或收到广播）时立即销毁，
 *   并触发 onWipe 让 UI 撤去一切明文；
 * - 改口令只重新封装数据密钥（带修订号的原子 CAS），不触碰任何便笺密文；
 *   写入失败时 IndexedDB 事务回滚，旧封装保持不变。
 *
 * 会话代际（generation）：每次进入锁定状态代际 +1。跨越多个 await 的操作
 * （解锁、加解密、改口令）必须在完成时确认代际未变，否则结果作废——
 * 这杜绝了「解锁还没完成就被锁定，迟到的结果又把明文送回锁定页」之类
 * 的竞态。NoteStore 的每个方法还会在入口、await 边界和事务写入前
 * 反复校验。
 */
export class Session {
  private dataKey: CryptoKey | null = null;
  private store: NoteStore | null = null;
  private generation = 0;
  private readonly iterations: number;

  /** 锁定（含其它标签页广播导致的锁定）后回调，UI 用它立即清空明文 */
  onWipe: (() => void) | null = null;

  constructor(
    private readonly db: NotesDB,
    private readonly bus: LockBus,
    options: SessionOptions = {},
  ) {
    this.iterations = options.iterations ?? KDF_ITERATIONS;
    this.bus.onLock(() => this.wipe());
    // 其它标签页改了口令：本标签页内存中的 KEK/口令语境已失效，
    // 立即撤去明文回到锁定页，由用户用新口令重新解锁。
    this.bus.onPassphraseChanged(() => this.wipe());
  }

  get unlocked(): boolean {
    return this.store !== null;
  }

  /** 已解锁时返回业务层；锁定状态调用即抛错 */
  get noteStore(): NoteStore {
    if (this.store === null) throw new LockedError('工作台已锁定');
    return this.store;
  }

  async isInitialized(): Promise<boolean> {
    return (await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY)) !== undefined;
  }

  /** 首次使用：生成随机数据密钥，用口令派生的 KEK 封装后落盘 */
  async initialize(passphrase: string): Promise<void> {
    if (await this.isInitialized()) {
      throw new AuthError('工作台已初始化，请直接解锁');
    }
    const generation = this.generation;
    const dataKey = await generateDataKey();
    const salt = randomBytes(16);
    const kek = await deriveKek(passphrase, salt, this.iterations);
    const { wrapIv, wrappedKey } = await wrapDataKey(dataKey, kek);
    const record: WrappedKeyRecord = {
      kdf: { salt, iterations: this.iterations },
      wrapIv,
      wrappedKey,
      revision: 1,
    };
    // 事务级「不存在才写入」：另一标签页抢先初始化/恢复时本调用被拒绝，
    // 不会静默覆盖获胜方的封装记录
    await this.db.initWrappedKey(record);
    // 落盘完成期间可能恰好被（另一标签页的）锁定广播打断
    this.ensureGeneration(generation);
    this.setUnlocked(dataKey);
  }

  /** 解锁：口令错误抛 AuthError，且不会改动任何已存数据 */
  async unlock(passphrase: string): Promise<void> {
    const generation = this.generation;
    const record = await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    if (record === undefined) throw new AuthError('工作台尚未初始化');
    const kek = await deriveKek(passphrase, record.kdf.salt, record.kdf.iterations);
    let dataKey: CryptoKey;
    try {
      dataKey = await unwrapDataKey(record.wrappedKey, record.wrapIv, kek);
    } catch {
      throw new AuthError();
    }
    // 解锁跨越多个 await：若期间被锁定（本地操作或其它标签页广播），
    // 本次结果必须作废，不能把已解锁状态/明文重新装回已锁定的页面。
    this.ensureGeneration(generation);
    this.setUnlocked(dataKey);
  }

  /**
   * 改口令：先验证当前口令，再用新盐派生 KEK 重新封装同一数据密钥。
   * 便笺密文一个字节都不动。
   *
   * 并发安全：封装记录带修订号，最终写入是事务内的比较并交换（CAS）——
   * 两个标签页几乎同时改口令时，先提交的一方使另一方读到的修订号过期，
   * 后者收到 ConflictError 且其封装不会落盘，不会出现「双方都报成功、
   * 最终却只有一方口令有效」。成功后广播通知其它标签页立即锁定。
   * 中途失败（掉电/配额/异常）时旧封装原样保留，旧口令依然有效。
   */
  async changePassphrase(current: string, next: string): Promise<void> {
    if (this.dataKey === null) throw new LockedError('工作台已锁定');
    const generation = this.generation;
    const dataKey = this.dataKey;
    const record = await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    if (record === undefined) throw new AuthError('工作台尚未初始化');
    this.ensureGeneration(generation);

    const oldKek = await deriveKek(current, record.kdf.salt, record.kdf.iterations);
    try {
      await unwrapDataKey(record.wrappedKey, record.wrapIv, oldKek);
    } catch {
      throw new AuthError('当前口令错误');
    }
    this.ensureGeneration(generation);

    const salt = randomBytes(16);
    const newKek = await deriveKek(next, salt, this.iterations);
    const { wrapIv, wrappedKey } = await wrapDataKey(dataKey, newKek);
    this.ensureGeneration(generation);
    const nextRecord: WrappedKeyRecord = {
      kdf: { salt, iterations: this.iterations },
      wrapIv,
      wrappedKey,
      revision: record.revision + 1,
    };
    // CAS：事务内再次比对修订号；其它标签页先改过、或本标签页已被
    // 口令变更广播撤去会话（checkpoint），都中止事务
    await this.db.putWrappedKeyIfRevision(nextRecord, record.revision, () =>
      this.ensureGeneration(generation),
    );
    // 写入期间若本标签页被锁定，不广播（锁定语义优先），也不恢复解锁态
    this.ensureGeneration(generation);
    // 改口令是高安全操作：广播让其它标签页立即撤去明文（不会回送自己），
    // 同时本标签页也锁定——所有标签页都需用新口令重新认证，
    // 杜绝「落败方仍显示可编辑」的竞态窗口。
    this.bus.broadcastPassphraseChanged();
    this.wipe();
  }

  /** 主动锁定：销毁内存中的密钥与明文，并广播给其它标签页 */
  lock(): void {
    this.bus.broadcastLock();
    this.wipe();
  }

  /**
   * 导出加密备份（仅已解锁会话可调用）：
   * 读取封装记录与全部便笺密文，用内存中的数据密钥对清单做认证加密，
   * 产出带格式版本的 JSON 文本。不解密便笺、不触碰口令，
   * 因此备份里没有口令、KEK/DK 原始字节或任何明文；
   * 锁定跨越任一 await 发生时以 LockedError 失败，绝不吐出备份。
   */
  async exportBackup(): Promise<string> {
    if (this.dataKey === null) throw new LockedError('工作台已锁定');
    const generation = this.generation;
    const dataKey = this.dataKey;
    const wrapped = await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    if (wrapped === undefined) throw new BackupError('工作台尚未初始化，无可导出的数据');
    this.ensureGeneration(generation);
    const notes = await this.db.listNotes();
    this.ensureGeneration(generation);
    if (notes.length > MAX_NOTES) {
      throw new BackupError(`便笺数量超过 ${MAX_NOTES} 条上限，备份中止`);
    }
    return createBackupFile({ wrapped, notes, dataKey });
  }

  /**
   * 从备份恢复到**空库**。
   *
   * 成功边界（全部满足才写入，任一失败则库与锁定页原样不变）：
   *  1. 文件结构/版本/字段/ID 唯一性/100 条上限（parseBackupFile）；
   *  2. 输入口令经备份内盐与迭代次数派生 KEK 并解封数据密钥，否则 AuthError；
   *  3. 用数据密钥打开清单封套（GCM 认证），并与重算的规范化清单逐字节一致；
   *  4. 逐条用数据密钥解密验证每条密文（明文立即丢弃，绝不显示/保留）；
   *  5. 同一 IndexedDB 事务内权威确认目标库确实为空（防另一标签页抢先初始化），
   *     再写入封装元数据与全部便笺；checkpoint 拦截恢复期间发生的锁定，
   *     配额失败/异常则事务整体回滚。
   *
   * 事务提交后再次确认会话代际：恢复期间被锁定则不进入解锁态、不显示明文，
   * 数据已原子落盘，可用口令重新解锁。
   */
  async restoreFromBackup(backupText: string, passphrase: string): Promise<void> {
    if (this.store !== null) {
      throw new BackupError('当前工作台已解锁，请先锁定后再恢复');
    }
    const generation = this.generation;

    // 友好预检：非空库直接拒绝，事务内还会再做权威检查
    if (await this.isInitialized()) {
      throw new BackupError('目标工作台非空：仅可在空库上恢复，已取消以保护现有数据');
    }
    const backup = parseBackupFile(backupText);
    if (backup.notes.length > MAX_NOTES) {
      throw new BackupError(`备份包含 ${backup.notes.length} 条便笺，超过 ${MAX_NOTES} 条上限`);
    }

    // 用备份自带的 KDF 参数解封数据密钥；口令错误时 GCM 校验失败
    const kek = await deriveKek(
      passphrase,
      backup.wrapped.kdf.salt,
      backup.wrapped.kdf.iterations,
    );
    let dataKey: CryptoKey;
    try {
      dataKey = await unwrapDataKey(backup.wrapped.wrappedKey, backup.wrapped.wrapIv, kek);
    } catch {
      throw new AuthError();
    }
    this.ensureGeneration(generation);

    // 打开清单封套：删条、换 ID、调换密文、替换封装记录都会在此暴露
    let opened: ArrayBuffer;
    try {
      opened = await openManifest(dataKey, backup.manifest.iv, backup.manifest.sealed);
    } catch {
      throw new BackupError('备份清单认证失败：文件可能被篡改或已损坏');
    }
    const canonical = canonicalManifestBytes(backup.wrapped, backup.notes);
    if (!timingSafeEqual(new Uint8Array(opened), canonical)) {
      throw new BackupError('备份清单与内容不一致：文件可能被篡改或已损坏');
    }
    this.ensureGeneration(generation);

    // 逐条验证密文（明文即时丢弃，不保留、不显示）：
    // 任何一条解不开都拒绝整包恢复
    for (const note of backup.notes) {
      try {
        await decryptNote(dataKey, note.iv, note.ciphertext);
      } catch {
        throw new BackupError(`便笺「${note.id}」密文校验失败，恢复已取消`);
      }
    }
    this.ensureGeneration(generation);

    // 全部通过：同一事务内确认空库并写入元数据 + 全部便笺
    await this.db.restoreIntoEmpty(backup.wrapped, backup.notes, () =>
      this.ensureGeneration(generation),
    );
    // 提交期间会话被锁定：不恢复解锁态、不显示明文（数据已完整落盘）
    this.ensureGeneration(generation);
    this.setUnlocked(dataKey);
  }

  /** 若当前已不是发起操作时的会话代际，抛错（会话已被锁定） */
  private ensureGeneration(generation: number): void {
    if (generation !== this.generation) {
      throw new LockedError('工作台已锁定');
    }
  }

  private wipe(): void {
    this.dataKey = null;
    this.store = null;
    this.generation += 1;
    this.onWipe?.();
  }

  private setUnlocked(dataKey: CryptoKey): void {
    this.dataKey = dataKey;
    const generation = this.generation;
    this.store = new NoteStore(this.db, dataKey, () => this.ensureGeneration(generation));
  }
}
