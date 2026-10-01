import { describe, expect, it, vi } from 'vitest';
import { AuthError } from '../src/errors';
import { makeSession, toBytes } from './helpers';

describe('修改口令', () => {
  it('改口令只重新封装数据密钥：便笺密文逐字节不变，新口令可解锁', async () => {
    const { db, session } = await makeSession();
    await session.initialize('old-passphrase');
    await session.noteStore.create('n1', '第一条');
    await session.noteStore.create('n2', '第二条');

    const before = new Map(
      (await db.listNotes()).map((r) => [
        r.id,
        { ciphertext: toBytes(r.ciphertext), iv: r.iv, revision: r.revision },
      ]),
    );

    await session.changePassphrase('old-passphrase', 'new-passphrase');

    // 便笺记录完全未被改写
    for (const record of await db.listNotes()) {
      const prev = before.get(record.id)!;
      expect(toBytes(record.ciphertext)).toEqual(prev.ciphertext);
      expect(record.iv).toEqual(prev.iv);
      expect(record.revision).toBe(prev.revision);
    }

    // 改口令后本标签页也立即锁定，需用新口令重新认证
    expect(session.unlocked).toBe(false);
    await expect(session.unlock('old-passphrase')).rejects.toThrow(AuthError);
    await session.unlock('new-passphrase');
    await expect(session.noteStore.read('n1')).resolves.toMatchObject({ plaintext: '第一条' });
    await expect(session.noteStore.read('n2')).resolves.toMatchObject({ plaintext: '第二条' });
  });

  it('当前口令错误时拒绝修改，旧封装保持原样', async () => {
    const { db, session } = await makeSession();
    await session.initialize('real-pass');
    const wrappedBefore = toBytes((await db.getMeta<{ wrappedKey: ArrayBuffer }>('wrappedDataKey'))!.wrappedKey);

    await expect(session.changePassphrase('wrong-pass', 'whatever-1')).rejects.toThrow(AuthError);

    const wrappedAfter = toBytes((await db.getMeta<{ wrappedKey: ArrayBuffer }>('wrappedDataKey'))!.wrappedKey);
    expect(wrappedAfter).toEqual(wrappedBefore);

    session.lock();
    await session.unlock('real-pass');
    expect(session.unlocked).toBe(true);
  });

  it('改口令写入中途失败（模拟掉电/存储错误）：旧口令依然有效，新口令无效', async () => {
    const { db, session } = await makeSession();
    await session.initialize('old-passphrase');
    await session.noteStore.create('n1', '关键数据');

    // 让封装密钥的原子 CAS 写入失败一次，模拟改口令过程被中断
    vi.spyOn(db, 'putWrappedKeyIfRevision').mockRejectedValueOnce(
      new Error('simulated storage crash'),
    );

    await expect(session.changePassphrase('old-passphrase', 'new-passphrase')).rejects.toThrow(
      'simulated storage crash',
    );

    session.lock();
    await expect(session.unlock('new-passphrase')).rejects.toThrow(AuthError);
    await session.unlock('old-passphrase');
    await expect(session.noteStore.read('n1')).resolves.toMatchObject({ plaintext: '关键数据' });
  });
});
