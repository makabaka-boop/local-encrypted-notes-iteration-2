import {
  deriveKek,
  generateDataKey,
  KDF_ITERATIONS,
  randomBytes,
  unwrapDataKey,
  wrapDataKey,
} from './crypto';
import { createBackupFile, parseBackupJson, verifyBackupWithDataKey } from './backup';
import { META_WRAPPED_KEY, NotesDB } from './db';
import { AuthError, ConflictError, LockedError } from './errors';
import type { LockBus } from './lockbus';
import { MAX_NOTES, NoteStore } from './store';
import type { BackupFile, WrappedKeyRecord } from './types';

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

  /** 首次使用：目标库必须确实为空；生成随机 DK 并用口令派生 KEK 封装后原子落盘 */
  async initialize(passphrase: string): Promise<void> {
    const generation = this.generation;
    const dataKey = await generateDataKey();
    const salt = randomBytes(16);
    const kek = await deriveKek(passphrase, salt, this.iterations);
    const { wrapIv, wrappedKey } = await wrapDataKey(dataKey, kek);
    this.ensureGeneration(generation);
    const record: WrappedKeyRecord = {
      kdf: { salt, iterations: this.iterations },
      wrapIv,
      wrappedKey,
      revision: 1,
    };
    try {
      await this.db.initializeEmpty(record, () => this.ensureGeneration(generation));
    } catch (err) {
      if (err instanceof ConflictError) throw new AuthError('工作台已初始化，请直接解锁');
      throw err;
    }
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
   * 导出格式化加密备份。只允许已解锁会话调用；读取封装记录与密文后，
   * 由当前数据密钥认证完整清单。口令和明文均不进入备份。
   */
  async exportBackup(): Promise<BackupFile> {
    if (this.dataKey === null) throw new LockedError('工作台已锁定');
    const generation = this.generation;
    const dataKey = this.dataKey;
    const wrappedKeyRecord = await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    if (wrappedKeyRecord === undefined) throw new AuthError('工作台尚未初始化');
    const notes = await this.db.listNotes();
    this.ensureGeneration(generation);
    const backup = await createBackupFile(wrappedKeyRecord, notes, dataKey);
    this.ensureGeneration(generation);
    return backup;
  }

  /**
   * 空库恢复：全程不进入已解锁状态，成功后仍停留在锁定页，由用户重新输入口令。
   *
   * 先离线解析备份、用输入口令解封 DK、认证整包清单、逐条验证密文和 100 条上限；
   * 全部通过后才进入唯一的跨 meta/notes 写入事务。事务内最后一次确认库为空，
   * 因此另一标签页抢先初始化、配额失败或异步处理中锁定都只能整体中止，
   * 不会写入元数据后再留下便笺，也不会把明文送回界面。
   */
  async restoreBackup(backupText: string, passphrase: string): Promise<void> {
    const generation = this.generation;
    this.ensureGeneration(generation);
    const parsed = parseBackupJson(backupText);

    const existing = await this.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    if (existing !== undefined) {
      throw new AuthError('目标工作台已有数据，已取消恢复以保护现有数据');
    }
    const noteCount = await this.db.countNotes();
    if (noteCount !== 0) throw new AuthError('目标工作台包含便笺，已取消恢复以保护现有数据');
    this.ensureGeneration(generation);

    const kek = await deriveKek(
      passphrase,
      parsed.wrappedKey.kdf.salt,
      parsed.wrappedKey.kdf.iterations,
    );
    let dataKey: CryptoKey;
    try {
      dataKey = await unwrapDataKey(
        parsed.wrappedKey.wrappedKey,
        parsed.wrappedKey.wrapIv,
        kek,
      );
    } catch {
      throw new AuthError('备份口令错误，未写入任何数据');
    }
    this.ensureGeneration(generation);

    const verified = await verifyBackupWithDataKey(parsed, dataKey, MAX_NOTES, () =>
      this.ensureGeneration(generation),
    );
    this.ensureGeneration(generation);

    await this.db.restoreBackupIfEmpty(
      verified.wrappedKey,
      verified.notes,
      MAX_NOTES,
      () => this.ensureGeneration(generation),
    );
    // 事务已整体提交即视为恢复成功；代际变化时也绝不设置解锁态，
    // 已落盘的是完整新库，界面仍停留在锁定页且不持有明文。
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
