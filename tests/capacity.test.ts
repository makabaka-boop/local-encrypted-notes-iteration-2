import { describe, expect, it, vi } from 'vitest';
import { CapacityError } from '../src/errors';
import { MAX_NOTES } from '../src/store';
import { makeSession } from './helpers';

describe('容量上限与存储失败', () => {
  it(`最多 ${MAX_NOTES} 条：第 101 条被拒绝且已有数据不变`, async () => {
    const { session } = await makeSession();
    await session.initialize('p@ssw0rd!');
    const store = session.noteStore;

    for (let i = 0; i < MAX_NOTES; i += 1) {
      await store.create(`note-${i}`, `内容 ${i}`);
    }
    expect(await store.count()).toBe(MAX_NOTES);

    await expect(store.create('note-overflow', '装不下')).rejects.toThrow(CapacityError);
    expect(await store.count()).toBe(MAX_NOTES);

    // 抽查已有便笺完好，且已有便笺仍可更新
    await expect(store.read('note-0')).resolves.toMatchObject({ plaintext: '内容 0' });
    await expect(store.read(`note-${MAX_NOTES - 1}`)).resolves.toMatchObject({
      plaintext: `内容 ${MAX_NOTES - 1}`,
    });
    const { revision } = await store.read('note-0');
    await store.update('note-0', '更新后', revision);
    await expect(store.read('note-0')).resolves.toMatchObject({ plaintext: '更新后' });
  });

  it('新建时底层存储失败（如配额耗尽）：事务回滚，旧数据不受影响', async () => {
    const { db, session } = await makeSession();
    await session.initialize('p@ssw0rd!');
    await session.noteStore.create('kept', '必须保住的数据');

    vi.spyOn(db, 'createNote').mockRejectedValueOnce(
      new DOMException('The quota has been exceeded.', 'QuotaExceededError'),
    );
    await expect(session.noteStore.create('doomed', '写不进去')).rejects.toThrow();

    expect(await session.noteStore.count()).toBe(1);
    await expect(session.noteStore.read('kept')).resolves.toMatchObject({
      plaintext: '必须保住的数据',
    });
  });

  it('更新时底层存储失败：旧内容原样保留', async () => {
    const { db, session } = await makeSession();
    await session.initialize('p@ssw0rd!');
    await session.noteStore.create('n1', '旧内容');

    vi.spyOn(db, 'updateNote').mockRejectedValueOnce(
      new DOMException('The quota has been exceeded.', 'QuotaExceededError'),
    );
    await expect(session.noteStore.update('n1', '新内容', 1)).rejects.toThrow();

    await expect(session.noteStore.read('n1')).resolves.toEqual({
      plaintext: '旧内容',
      revision: 1,
    });
  });
});
