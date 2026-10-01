import { decryptNote, encryptNote } from './crypto';
import type { NotesDB } from './db';
import { AuthError, IntegrityError, NotFoundError } from './errors';
import type { NoteMeta, NoteRecord } from './types';

/** 便笺数量硬上限 */
export const MAX_NOTES = 100;

export interface NoteContent {
  plaintext: string;
  revision: number;
}

/**
 * 业务层：加解密 + 容量/修订号约束。
 * 只在解锁后的会话内存中持有数据密钥，锁定即销毁本对象。
 *
 * 每个方法都绑定一个 live() 检查：确认本次调用仍属于发起时的那个
 * 「已解锁会话代际」。锁定（本地或广播导致）会让 live() 立即抛错——
 * 这样解锁/读取/保存跨越多个 await 时若会话被锁定，迟到的结果不会
 * 再把明文吐给已锁定的页面；写入路径还会在 IndexedDB 事务内、
 * 实际写入前一刻再查一次，杜绝锁定前发出的写请求在锁定后落盘。
 */
export class NoteStore {
  constructor(
    private readonly db: NotesDB,
    private readonly dataKey: CryptoKey,
    private readonly live: () => void,
  ) {}

  /** 列表只返回元信息，不触碰明文 */
  async list(): Promise<NoteMeta[]> {
    this.live();
    const records = await this.db.listNotes();
    this.live();
    return records
      .map(({ id, revision, updatedAt }) => ({ id, revision, updatedAt }))
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }

  async count(): Promise<number> {
    this.live();
    return this.db.countNotes();
  }

  async read(id: string): Promise<NoteContent> {
    this.live();
    const record = await this.db.getNote(id);
    this.live();
    if (record === undefined) throw new NotFoundError(id);
    const plaintext = await this.decrypt(record);
    this.live(); // 解密是异步的：返回明文前确认会话仍处于解锁状态
    return { plaintext, revision: record.revision };
  }

  /** 解密并校验完整性；篡改会抛 IntegrityError */
  async decrypt(record: NoteRecord): Promise<string> {
    try {
      return await decryptNote(this.dataKey, record.iv, record.ciphertext);
    } catch {
      throw new IntegrityError(`便笺「${record.id}」解密失败：密文可能被篡改`);
    }
  }

  async create(id: string, plaintext: string): Promise<NoteMeta> {
    this.live();
    const { iv, ciphertext } = await encryptNote(this.dataKey, plaintext);
    this.live();
    const record: NoteRecord = { id, iv, ciphertext, revision: 1, updatedAt: Date.now() };
    // 事务内写入前再查一次：锁定后绝不落盘
    await this.db.createNote(record, MAX_NOTES, this.live);
    return { id, revision: record.revision, updatedAt: record.updatedAt };
  }

  /**
   * 更新便笺：调用方必须给出自己读到的修订号。
   * 若其它标签页已先写入，事务内校验失败并抛 ConflictError，
   * 先写的内容不会被覆盖。
   */
  async update(id: string, plaintext: string, expectedRevision: number): Promise<NoteMeta> {
    this.live();
    const { iv, ciphertext } = await encryptNote(this.dataKey, plaintext);
    this.live();
    const record: NoteRecord = {
      id,
      iv,
      ciphertext,
      revision: expectedRevision + 1,
      updatedAt: Date.now(),
    };
    // 事务内写入前再查一次：锁定后绝不落盘
    await this.db.updateNote(record, expectedRevision, this.live);
    return { id, revision: record.revision, updatedAt: record.updatedAt };
  }

  async remove(id: string): Promise<void> {
    this.live();
    // 事务内删除前再查一次：锁定后不再删除
    await this.db.deleteNote(id, this.live);
  }
}
