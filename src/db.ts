import { CapacityError, ConflictError } from './errors';
import type { NoteRecord, WrappedKeyRecord } from './types';

const DB_VERSION = 1;
const NOTES_STORE = 'notes';
const META_STORE = 'meta';
export const META_WRAPPED_KEY = 'wrappedDataKey';

function reqToPromise<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB 请求失败'));
  });
}

/**
 * IndexedDB 访问层。
 *
 * 所有「检查 + 写入」都在同一个 readwrite 事务内完成：
 * 事务要么整体提交、要么整体回滚，因此容量检查、修订号校验、
 * 口令更换时的元信息写入都不会留下半截状态——失败时旧数据原样保留。
 */
export class NotesDB {
  private constructor(private readonly db: IDBDatabase) {}

  static open(name = 'secure-notes-workbench'): Promise<NotesDB> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(name, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(NOTES_STORE)) {
          db.createObjectStore(NOTES_STORE, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(META_STORE)) {
          db.createObjectStore(META_STORE);
        }
      };
      req.onsuccess = () => resolve(new NotesDB(req.result));
      req.onerror = () => reject(req.error ?? new Error('无法打开 IndexedDB'));
      req.onblocked = () => reject(new Error('IndexedDB 被其它连接占用'));
    });
  }

  close(): void {
    this.db.close();
  }

  /** 在单个事务里执行 work；work 抛错则中止事务，保证不落下半截写入 */
  private runTx<T>(
    storeNames: string[],
    mode: IDBTransactionMode,
    work: (tx: IDBTransaction) => Promise<T>,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const tx = this.db.transaction(storeNames, mode);
      let result: T;
      let workError: unknown = null;

      work(tx).then(
        (value) => {
          result = value;
        },
        (err) => {
          workError = err;
          try {
            tx.abort();
          } catch {
            // 事务可能已结束，忽略
          }
        },
      );

      tx.oncomplete = () => {
        if (workError !== null) reject(workError);
        else resolve(result);
      };
      tx.onabort = () => reject(workError ?? tx.error ?? new Error('事务已中止'));
      tx.onerror = () => reject(workError ?? tx.error ?? new Error('事务失败'));
    });
  }

  async getMeta<T>(key: string): Promise<T | undefined> {
    return this.runTx([META_STORE], 'readonly', (tx) =>
      reqToPromise(tx.objectStore(META_STORE).get(key) as IDBRequest<T | undefined>),
    );
  }

  /** 单条 put，本身即原子：失败时旧值保持不变（首次初始化依赖这一点） */
  async putMeta(key: string, value: unknown): Promise<void> {
    await this.runTx([META_STORE], 'readwrite', async (tx) => {
      await reqToPromise(tx.objectStore(META_STORE).put(value, key));
    });
  }

  /**
   * 改口令专用的比较并交换（CAS）：在同一个 readwrite 事务内
   * 读取当前封装记录、比对修订号，再写入新记录。
   * 其它标签页先改了口令（修订号已变）时本事务中止，
   * 后改的一方收到 ConflictError 且不会覆盖先改的一方——
   * IndexedDB 事务在同一 origin 内串行，跨标签页同样成立。
   *
   * checkpoint 在事务内、实际写入前执行：本标签页若已被
   * 「口令已更改」广播撤去会话，事务同样中止，防止排队中的
   * 迟到写入反过来覆盖获胜方的封装。
   */
  async putWrappedKeyIfRevision(
    nextRecord: WrappedKeyRecord,
    expectedRevision: number,
    checkpoint: (() => void) | null = null,
  ): Promise<void> {
    await this.runTx([META_STORE], 'readwrite', async (tx) => {
      const store = tx.objectStore(META_STORE);
      const existing = (await reqToPromise(
        store.get(META_WRAPPED_KEY),
      )) as WrappedKeyRecord | undefined;
      if (existing === undefined) {
        throw new ConflictError('工作台尚未初始化，请刷新后重试');
      }
      if (existing.revision !== expectedRevision) {
        throw new ConflictError('口令已在其它标签页被修改，请重新解锁后再试');
      }
      checkpoint?.();
      await reqToPromise(store.put(nextRecord, META_WRAPPED_KEY));
    });
  }

  async getNote(id: string): Promise<NoteRecord | undefined> {
    return this.runTx([NOTES_STORE], 'readonly', (tx) =>
      reqToPromise(tx.objectStore(NOTES_STORE).get(id) as IDBRequest<NoteRecord | undefined>),
    );
  }

  async listNotes(): Promise<NoteRecord[]> {
    return this.runTx([NOTES_STORE], 'readonly', (tx) =>
      reqToPromise(tx.objectStore(NOTES_STORE).getAll() as IDBRequest<NoteRecord[]>),
    );
  }

  async countNotes(): Promise<number> {
    return this.runTx([NOTES_STORE], 'readonly', (tx) =>
      reqToPromise(tx.objectStore(NOTES_STORE).count()),
    );
  }

  /**
   * 新建便笺：同一事务内检查 id 未占用且数量未超上限，再写入。
   * 任一项不满足或写入失败（如配额）都会回滚，已有数据不受影响。
   *
   * checkpoint 在事务内、实际写入前一刻执行：会话已被锁定时抛错中止，
   * 保证「锁定前发起的保存」不会在锁定之后落盘。
   */
  async createNote(
    record: NoteRecord,
    maxCount: number,
    checkpoint: (() => void) | null = null,
  ): Promise<void> {
    await this.runTx([NOTES_STORE], 'readwrite', async (tx) => {
      const store = tx.objectStore(NOTES_STORE);
      const existing = await reqToPromise(store.get(record.id));
      if (existing !== undefined) {
        throw new ConflictError(`便笺已存在：${record.id}`);
      }
      const count = await reqToPromise(store.count());
      if (count >= maxCount) {
        throw new CapacityError();
      }
      checkpoint?.();
      await reqToPromise(store.put(record));
    });
  }

  /**
   * 更新便笺：同一事务内比对当前修订号，不一致即中止——
   * 后写的一方无法覆盖先写的一方（跨标签页同样成立，
   * 因为 IndexedDB 事务在同一 origin 内串行执行）。
   *
   * checkpoint 在事务内、实际写入前一刻执行：会话已被锁定时抛错中止，
   * 保证「锁定前发起的保存」不会在锁定之后落盘。
   */
  async updateNote(
    record: NoteRecord,
    expectedRevision: number,
    checkpoint: (() => void) | null = null,
  ): Promise<void> {
    await this.runTx([NOTES_STORE], 'readwrite', async (tx) => {
      const store = tx.objectStore(NOTES_STORE);
      const existing = (await reqToPromise(store.get(record.id))) as NoteRecord | undefined;
      if (existing === undefined) {
        throw new ConflictError('便笺已被删除或不存在，请重新载入');
      }
      if (existing.revision !== expectedRevision) {
        throw new ConflictError();
      }
      checkpoint?.();
      await reqToPromise(store.put(record));
    });
  }

  /**
   * 删除便笺。checkpoint 在事务内、实际删除前一刻执行：
   * 锁定前发起的删除不会在锁定之后生效。
   */
  async deleteNote(id: string, checkpoint: (() => void) | null = null): Promise<void> {
    await this.runTx([NOTES_STORE], 'readwrite', async (tx) => {
      checkpoint?.();
      await reqToPromise(tx.objectStore(NOTES_STORE).delete(id));
    });
  }
}
