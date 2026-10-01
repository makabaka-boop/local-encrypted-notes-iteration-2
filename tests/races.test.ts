import { describe, expect, it } from 'vitest';
import { ConflictError, LockedError } from '../src/errors';
import type { WrappedKeyRecord } from '../src/types';
import { makeProbe, makeSession, makeTabPair } from './helpers';

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('解锁与锁定竞态（会话代际防护）', () => {
  it('解锁尚未完成时被锁定：迟到的解锁结果作废，页面保持锁定', async () => {
    const { a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');

    // B 开始解锁（PBKDF2/解封跨越多个 await）
    const unlocking = b.session.unlock('shared-pass');
    // 解锁完成前，A 触发全标签页锁定
    a.session.lock();
    await flush();

    // B 这次解锁必须以「已锁定」失败收场，而不是进入已解锁状态
    await expect(unlocking).rejects.toThrow(LockedError);
    expect(b.session.unlocked).toBe(false);
    expect(() => b.session.noteStore).toThrow(LockedError);

    // 之后仍可用正确口令正常解锁（证明状态没有被污染）
    await b.session.unlock('shared-pass');
    expect(b.session.unlocked).toBe(true);
  });

  it('本地解锁途中主动 lock()：解锁结果同样作废', async () => {
    const { session } = await makeSession();
    await session.initialize('shared-pass');
    session.lock();

    const unlocking = session.unlock('shared-pass');
    session.lock(); // 解锁结果返回前再次锁定
    await expect(unlocking).rejects.toThrow(LockedError);
    expect(session.unlocked).toBe(false);
  });

  it('锁定前发起的读取：锁定后明文不会再返回给调用方', async () => {
    const { session } = await makeSession();
    await session.initialize('shared-pass');
    await session.noteStore.create('n1', '迟到的明文');

    const reading = session.noteStore.read('n1');
    session.lock();
    await expect(reading).rejects.toThrow(LockedError);
  });

  it('锁定前发起的保存：事务内写入前检查点拦截，锁定后绝不落盘', async () => {
    const { session, db } = await makeSession();
    await session.initialize('shared-pass');
    await session.noteStore.create('n1', '旧内容');
    const { revision } = await session.noteStore.read('n1');

    const saving = session.noteStore.update('n1', '锁定前发起的新内容', revision);
    session.lock();

    await expect(saving).rejects.toThrow(LockedError);
    // 重新解锁后落盘的仍是锁定前的内容与修订号
    await session.unlock('shared-pass');
    await expect(session.noteStore.read('n1')).resolves.toEqual({
      plaintext: '旧内容',
      revision,
    });
    expect((await db.getNote('n1'))!.revision).toBe(revision);
  });

  it('锁定前发起的新建：加解密等待期间锁定，事务内检查点拦截，绝不落盘', async () => {
    const { session, db } = await makeSession();
    await session.initialize('shared-pass');

    const creating = session.noteStore.create('n2', '不应落盘');
    session.lock();

    await expect(creating).rejects.toThrow(LockedError);
    expect(await db.countNotes()).toBe(0);
    expect(await db.getNote('n2')).toBeUndefined();
  });
});

describe('两个标签页几乎同时改口令', () => {
  it('只有一方成功：落败方失败且被广播锁定，最终只有一个口令有效', async () => {
    const { name, a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');
    await b.session.unlock('shared-pass');
    await a.session.noteStore.create('n1', '密文不受影响');

    // 两边几乎同时用旧口令改成各自的新口令
    const results = await Promise.allSettled([
      a.session.changePassphrase('shared-pass', 'new-pass'),
      b.session.changePassphrase('shared-pass', 'new-pass'),
    ]);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    // 落败方要么在 CAS 处被 ConflictError 拦下，要么先被获胜方的广播
    // 撤去会话（LockedError）——两种情况下它的封装都不会落盘、都不会报成功
    const reason = (rejected[0] as PromiseRejectedResult).reason;
    expect(reason instanceof ConflictError || reason instanceof LockedError).toBe(true);

    // 两个标签页都回到锁定页（落败者被广播锁定，获胜者不会自接收广播）
    await flush();
    await flush();
    expect(a.session.unlocked).toBe(false);
    expect(b.session.unlocked).toBe(false);

    // 封装记录只前进了一个修订号，最终新口令有效、旧口令失效
    const meta = (await a.db.getMeta<WrappedKeyRecord>('wrappedDataKey'))!;
    expect(meta.revision).toBe(2);
    const probeOld = await makeProbe(name);
    await expect(probeOld.session.unlock('shared-pass')).rejects.toThrow();
    const probeNew = await makeProbe(name);
    await probeNew.session.unlock('new-pass');
    await expect(probeNew.session.noteStore.read('n1')).resolves.toMatchObject({
      plaintext: '密文不受影响',
    });
  });

  it('落败方的新封装没有落盘：存储里的修订号与获胜方一致', async () => {
    const { name, a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');
    await b.session.unlock('shared-pass');

    await Promise.allSettled([
      a.session.changePassphrase('shared-pass', 'pass-A'),
      b.session.changePassphrase('shared-pass', 'pass-B'),
    ]);
    await flush();

    // 两边读到的是同一份封装，修订号恰好前进一格
    const metaA = await a.db.getMeta<WrappedKeyRecord>('wrappedDataKey');
    const metaB = await b.db.getMeta<WrappedKeyRecord>('wrappedDataKey');
    expect(metaA!.revision).toBe(2);
    expect(metaB!.revision).toBe(2);
    expect(metaA!.wrappedKey).toEqual(metaB!.wrappedKey);

    // 在同一个库上依次尝试候选口令：恰好有一个新口令能解锁，旧口令失效
    async function tryUnlock(pass: string): Promise<boolean> {
      const probe = await makeProbe(name);
      try {
        await probe.session.unlock(pass);
        return true;
      } catch {
        return false;
      }
    }
    const gotA = await tryUnlock('pass-A');
    const gotB = await tryUnlock('pass-B');
    expect(Number(gotA) + Number(gotB)).toBe(1);
    expect(await tryUnlock('shared-pass')).toBe(false);
  });

  it('确定性串行：后改口令的一方在 CAS 处被 ConflictError 拦下，先改方不受影响', async () => {
    const { name, a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');
    await b.session.unlock('shared-pass');

    // A 先完成改口令（meta revision 1 → 2）并广播；B 收到广播被撤去会话
    await a.session.changePassphrase('shared-pass', 'pass-A');
    await flush();
    expect(b.session.unlocked).toBe(false);

    // 直接验证 DB 层 CAS 语义：拿过期修订号 1 的写入必被拒绝
    const stale: WrappedKeyRecord = {
      kdf: { salt: new Uint8Array(16), iterations: 1000 },
      wrapIv: new Uint8Array(12),
      wrappedKey: new ArrayBuffer(40),
      revision: 2,
    };
    await expect(b.db.putWrappedKeyIfRevision(stale, 1)).rejects.toThrow(ConflictError);

    // 库里只有 A 的新口令有效；B 设想的口令与旧口令都无效
    const probeB = await makeProbe(name);
    await expect(probeB.session.unlock('pass-B')).rejects.toThrow();
    const probeOld = await makeProbe(name);
    await expect(probeOld.session.unlock('shared-pass')).rejects.toThrow();
    const probeA = await makeProbe(name);
    await probeA.session.unlock('pass-A');
    expect(probeA.session.unlocked).toBe(true);
  });
});
