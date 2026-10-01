import { describe, expect, it, vi } from 'vitest';
import { base64ToBytes } from '../src/backup';
import { AuthError, CapacityError, ConflictError, IntegrityError, LockedError } from '../src/errors';
import { MAX_NOTES } from '../src/store';
import type { BackupFile, NoteRecord, WrappedKeyRecord } from '../src/types';
import { makeSession, makeTabPair, toBytes } from './helpers';

const PASSPHRASE = 'backup-passphrase';

async function makeBackup(noteCount = 2) {
  const source = await makeSession();
  await source.session.initialize(PASSPHRASE);
  for (let i = 0; i < noteCount; i += 1) {
    await source.session.noteStore.create(`note-${i}`, `第 ${i} 条明文 secret-${i}`);
  }
  const file = await source.session.exportBackup();
  return { ...source, file, text: JSON.stringify(file) };
}

interface DbSnapshot {
  meta?: WrappedKeyRecord;
  notes: Map<string, { iv: Uint8Array; ciphertext: Uint8Array; revision: number; updatedAt: number }>;
}

async function snapshot(db: Awaited<ReturnType<typeof makeSession>>['db']): Promise<DbSnapshot> {
  const meta = await db.getMeta<WrappedKeyRecord>('wrappedDataKey');
  const notes = new Map<
    string,
    { iv: Uint8Array; ciphertext: Uint8Array; revision: number; updatedAt: number }
  >();
  for (const record of await db.listNotes()) {
    notes.set(record.id, {
      iv: record.iv.slice(),
      ciphertext: toBytes(record.ciphertext).slice(),
      revision: record.revision,
      updatedAt: record.updatedAt,
    });
  }
  return { meta, notes };
}

function expectSameSnapshot(actual: DbSnapshot, expected: DbSnapshot): void {
  expect(actual.meta === undefined).toBe(expected.meta === undefined);
  if (actual.meta !== undefined && expected.meta !== undefined) {
    expect(toBytes(actual.meta.wrappedKey)).toEqual(toBytes(expected.meta.wrappedKey));
    expect(actual.meta.revision).toBe(expected.meta.revision);
  }
  expect(actual.notes.size).toBe(expected.notes.size);
  for (const [id, note] of expected.notes) {
    const current = actual.notes.get(id);
    expect(current).toBeDefined();
    expect(current!.ciphertext).toEqual(note.ciphertext);
    expect(current!.iv).toEqual(note.iv);
    expect(current!.revision).toBe(note.revision);
    expect(current!.updatedAt).toBe(note.updatedAt);
  }
}

function flipBase64(value: string): string {
  const index = Math.max(0, value.length - 2);
  const replacement = value[index] === 'A' ? 'B' : 'A';
  return `${value.slice(0, index)}${replacement}${value.slice(index + 1)}`;
}

describe('加密备份导出', () => {
  it('仅已解锁会话可导出；文件有格式版本、封装记录、DK 认证清单和全部密文', async () => {
    const { session, text, file } = await makeBackup(2);
    expect(file.format).toBe('secure-notes-workbench-backup');
    expect(file.version).toBe(1);
    expect(file.notes).toHaveLength(2);
    expect(file.manifest.ciphertext).not.toHaveLength(0);

    expect(text).not.toContain('第 0 条明文');
    expect(text).not.toContain('secret-0');
    expect(text).not.toContain(PASSPHRASE);

    session.lock();
    await expect(session.exportBackup()).rejects.toThrow(LockedError);
  });

  it('备份可恢复到空库；恢复后仍锁定，重新解锁后逐条数据一致', async () => {
    const backup = await makeBackup(3);
    const target = await makeSession();
    expect(await target.session.isInitialized()).toBe(false);

    await target.session.restoreBackup(backup.text, PASSPHRASE);
    expect(target.session.unlocked).toBe(false);
    expect(await target.session.isInitialized()).toBe(true);

    await target.session.unlock(PASSPHRASE);
    expect(target.session.noteStore).toBeDefined();
    for (let i = 0; i < 3; i += 1) {
      await expect(target.session.noteStore.read(`note-${i}`)).resolves.toEqual({
        plaintext: `第 ${i} 条明文 secret-${i}`,
        revision: 1,
      });
    }

    const restored = await snapshot(target.db);
    const expectedNotes = new Map(
      backup.file.notes.map((note) => [
        note.id,
        {
          iv: base64ToBytes(note.iv).slice(),
          ciphertext: base64ToBytes(note.ciphertext).slice(),
          revision: note.revision,
          updatedAt: note.updatedAt,
        },
      ]),
    );
    expect(restored.notes).toEqual(expectedNotes);
  });
});

describe('恢复失败保护', () => {
  it('错误口令不写入，目标空库逐字节保持为空', async () => {
    const backup = await makeBackup();
    const target = await makeSession();
    const before = await snapshot(target.db);

    await expect(target.session.restoreBackup(backup.text, 'wrong-password')).rejects.toThrow(
      AuthError,
    );
    expect(target.session.unlocked).toBe(false);
    expectSameSnapshot(await snapshot(target.db), before);
  });

  it('目标库已有封装记录时拒绝恢复，已有数据逐项不变', async () => {
    const backup = await makeBackup();
    const target = await makeSession();
    await target.session.initialize('existing-password');
    await target.session.noteStore.create('existing', '已有数据，不可覆盖');
    target.session.lock();
    const before = await snapshot(target.db);

    await expect(target.session.restoreBackup(backup.text, PASSPHRASE)).rejects.toThrow(AuthError);
    expectSameSnapshot(await snapshot(target.db), before);

    await target.session.unlock('existing-password');
    await expect(target.session.noteStore.read('existing')).resolves.toMatchObject({
      plaintext: '已有数据，不可覆盖',
    });
  });

  it('目标库存在游离便笺时同样拒绝恢复', async () => {
    const backup = await makeBackup();
    const target = await makeSession();
    await target.session.initialize('existing-password');
    await target.session.noteStore.create('orphan', '游离便笺');
    const before = await snapshot(target.db);

    await expect(target.session.restoreBackup(backup.text, PASSPHRASE)).rejects.toThrow();
    expectSameSnapshot(await snapshot(target.db), before);
  });

  it.each([
    ['删除一条外层便笺', (file: BackupFile) => file.notes.pop()],
    ['调换两条便笺 ID', (file: BackupFile) => {
      const firstId = file.notes[0]!.id;
      file.notes[0]!.id = file.notes[1]!.id;
      file.notes[1]!.id = firstId;
    }],
    ['调换两条密文', (file: BackupFile) => {
      const firstCipher = file.notes[0]!.ciphertext;
      file.notes[0]!.ciphertext = file.notes[1]!.ciphertext;
      file.notes[1]!.ciphertext = firstCipher;
    }],
    ['篡改单条密文', (file: BackupFile) => {
      file.notes[0]!.ciphertext = flipBase64(file.notes[0]!.ciphertext);
    }],
    ['篡改认证清单', (file: BackupFile) => {
      file.manifest.ciphertext = flipBase64(file.manifest.ciphertext);
    }],
  ])('%s：整包拒绝且空库不变', async (_name, mutate) => {
    const backup = await makeBackup(2);
    const tampered = structuredClone(backup.file);
    mutate(tampered);

    const target = await makeSession();
    const before = await snapshot(target.db);
    await expect(
      target.session.restoreBackup(JSON.stringify(tampered), PASSPHRASE),
    ).rejects.toThrow(IntegrityError);
    expectSameSnapshot(await snapshot(target.db), before);
    expect(target.session.unlocked).toBe(false);
  });

  it('外层包含 101 条时在解封前拒绝，并保持空库', async () => {
    const backup = await makeBackup(1);
    const overflow = structuredClone(backup.file);
    const extra = structuredClone(overflow.notes[0]!);
    extra.id = 'note-overflow';
    overflow.notes.push(extra);
    expect(overflow.notes).toHaveLength(2);

    // 直接构造到硬上限之后，验证格式层先拒绝，不进行 KDF/写入
    overflow.notes = Array.from({ length: MAX_NOTES + 1 }, (_, index) => ({
      ...structuredClone(extra),
      id: `note-${index}`,
    }));

    const target = await makeSession();
    const before = await snapshot(target.db);
    await expect(target.session.restoreBackup(JSON.stringify(overflow), PASSPHRASE)).rejects.toThrow(
      CapacityError,
    );
    expectSameSnapshot(await snapshot(target.db), before);
  });

  it('恢复写入事务中配额失败：元数据与便笺一起回滚，不留半个库', async () => {
    const backup = await makeBackup(2);
    const target = await makeSession();
    const before = await snapshot(target.db);

    vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementationOnce(function (
      this: IDBObjectStore,
    ) {
      throw new DOMException('The quota has been exceeded.', 'QuotaExceededError');
    });

    await expect(target.session.restoreBackup(backup.text, PASSPHRASE)).rejects.toThrow(
      'The quota has been exceeded.',
    );
    expectSameSnapshot(await snapshot(target.db), before);
    expect(target.session.unlocked).toBe(false);

    // 失败后同一空库仍可重新恢复，证明事务中止没有污染数据库或会话
    await target.session.restoreBackup(backup.text, PASSPHRASE);
    expect(await target.db.countNotes()).toBe(2);
  });
});

describe('恢复并发与锁定边界', () => {
  it('另一标签页抢先初始化：恢复事务拒绝，获胜标签页的数据逐项不变', async () => {
    const backup = await makeBackup(2);
    const { a, b } = await makeTabPair();
    const original = b.db.restoreBackupIfEmpty.bind(b.db);
    vi.spyOn(b.db, 'restoreBackupIfEmpty').mockImplementationOnce(async (...args) => {
      // B 已完成解封/清单校验、正要进入写事务；A 在此刻抢先初始化
      await a.session.initialize('winner-pass');
      await a.session.noteStore.create('winner-note', '抢先初始化的数据');
      return original(...args);
    });

    const restoring = b.session.restoreBackup(backup.text, PASSPHRASE);
    await expect(restoring).rejects.toThrow(ConflictError);
    expect(b.session.unlocked).toBe(false);

    const winnerSnapshot = await snapshot(a.db);
    expect(winnerSnapshot.meta).toBeDefined();
    expect(winnerSnapshot.notes.has('winner-note')).toBe(true);
    expect(winnerSnapshot.notes.has('note-0')).toBe(false);

    const laterSnapshot = await snapshot(b.db);
    expectSameSnapshot(laterSnapshot, winnerSnapshot);
    await expect(b.session.unlock(PASSPHRASE)).rejects.toThrow(AuthError);
    await b.session.unlock('winner-pass');
    await expect(b.session.noteStore.read('winner-note')).resolves.toMatchObject({
      plaintext: '抢先初始化的数据',
    });
  });

  it('恢复的异步解封/校验期间收到锁定广播：抛 LockedError 且不写库、不显示明文', async () => {
    const backup = await makeBackup(2);
    const { a, b } = await makeTabPair();
    const before = await snapshot(b.db);

    // 在第一个 IndexedDB 异步等待处挂起 B；A 触发锁定并让 B 收到广播后再放行
    vi.spyOn(b.db, 'getMeta').mockImplementationOnce(async () => {
      a.session.lock();
      await new Promise((resolve) => setTimeout(resolve, 0));
      return undefined;
    });
    const restoring = b.session.restoreBackup(backup.text, PASSPHRASE);
    restoring.catch(() => {});

    await expect(restoring).rejects.toThrow(LockedError);
    expect(b.session.unlocked).toBe(false);
    expect(() => b.session.noteStore).toThrow(LockedError);
    expectSameSnapshot(await snapshot(b.db), before);
  });
});
