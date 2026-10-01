import { describe, expect, it } from 'vitest';
import { AuthError } from '../src/errors';
import { BroadcastLockBus } from '../src/lockbus';
import { Session } from '../src/session';
import { NotesDB } from '../src/db';
import { makeSession, TEST_ITERATIONS, toBytes } from './helpers';
import type { WrappedKeyRecord } from '../src/types';

describe('解锁 / 锁定', () => {
  it('初始化后写入便笺，锁定再解锁可原样读出', async () => {
    const { session } = await makeSession();
    expect(session.unlocked).toBe(false);
    expect(await session.isInitialized()).toBe(false);

    await session.initialize('passphrase-1');
    expect(session.unlocked).toBe(true);
    await session.noteStore.create('n1', '你好，浏览器');

    session.lock();
    expect(session.unlocked).toBe(false);
    expect(() => session.noteStore).toThrow(AuthError);

    await session.unlock('passphrase-1');
    await expect(session.noteStore.read('n1')).resolves.toEqual({
      plaintext: '你好，浏览器',
      revision: 1,
    });
  });

  it('错误口令解锁失败，且旧数据（封装密钥与密文）一个字节都不变', async () => {
    const { db, session } = await makeSession();
    await session.initialize('right-pass');
    await session.noteStore.create('n1', '不可丢失的内容');
    session.lock();

    const wrappedBefore = await db.getMeta<WrappedKeyRecord>('wrappedDataKey');
    const noteBefore = await db.getNote('n1');

    await expect(session.unlock('wrong-pass')).rejects.toThrow(AuthError);
    expect(session.unlocked).toBe(false);

    const wrappedAfter = await db.getMeta<WrappedKeyRecord>('wrappedDataKey');
    const noteAfter = await db.getNote('n1');
    expect(toBytes(wrappedAfter!.wrappedKey)).toEqual(toBytes(wrappedBefore!.wrappedKey));
    expect(toBytes(noteAfter!.ciphertext)).toEqual(toBytes(noteBefore!.ciphertext));
    expect(noteAfter!.revision).toBe(noteBefore!.revision);

    // 正确口令仍可解锁
    await session.unlock('right-pass');
    await expect(session.noteStore.read('n1')).resolves.toMatchObject({
      plaintext: '不可丢失的内容',
    });
  });

  it('重复初始化被拒绝', async () => {
    const { session } = await makeSession();
    await session.initialize('first-pass');
    await expect(session.initialize('second-pass')).rejects.toThrow();
  });

  it('明文与口令不会出现在持久化记录里', async () => {
    const { db, session } = await makeSession();
    const secret = 'TOP-SECRET-PLAINTEXT-不落地';
    await session.initialize('TOP-SECRET-PASSPHRASE');
    await session.noteStore.create('n1', secret);

    const haystack: number[] = [];
    for (const record of await db.listNotes()) {
      haystack.push(...toBytes(record.ciphertext), ...record.iv);
    }
    const wrapped = await db.getMeta<WrappedKeyRecord>('wrappedDataKey');
    haystack.push(...toBytes(wrapped!.wrappedKey), ...wrapped!.wrapIv, ...wrapped!.kdf.salt);

    const dump = new TextDecoder().decode(new Uint8Array(haystack));
    expect(dump).not.toContain('TOP-SECRET-PLAINTEXT');
    expect(dump).not.toContain('TOP-SECRET-PASSPHRASE');
  });

  it('锁定广播：一个标签页锁定，其它标签页立即被撤去会话', async () => {
    if (typeof BroadcastChannel === 'undefined') return;
    const name = `test-db-broadcast-${Math.random().toString(36).slice(2)}`;
    const dbA = await NotesDB.open(name);
    const dbB = await NotesDB.open(name);
    const busA = new BroadcastLockBus(`test-lock-${name}`);
    const busB = new BroadcastLockBus(`test-lock-${name}`);
    const a = new Session(dbA, busA, { iterations: TEST_ITERATIONS });
    const b = new Session(dbB, busB, { iterations: TEST_ITERATIONS });

    await a.initialize('shared-pass');
    await b.unlock('shared-pass');
    expect(b.unlocked).toBe(true);

    let bWiped = false;
    b.onWipe = () => {
      bWiped = true;
    };
    a.lock();
    // BroadcastChannel 投递是异步的，等一个事件循环
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(bWiped).toBe(true);
    expect(b.unlocked).toBe(false);
    busA.close();
    busB.close();
  });
});
