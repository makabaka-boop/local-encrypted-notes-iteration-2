import { describe, expect, it } from 'vitest';
import { ConflictError } from '../src/errors';
import { makeTabPair } from './helpers';

describe('跨标签页并发（修订号乐观锁）', () => {
  it('两个标签页同时改同一便笺：后写者被 ConflictError 拦下，先写内容不丢', async () => {
    const { a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');
    await b.session.unlock('shared-pass');

    // 标签页 A 创建便笺（revision 1）
    await a.session.noteStore.create('shared', '初始内容');

    // 两个标签页都读到了 revision 1
    const readA = await a.session.noteStore.read('shared');
    const readB = await b.session.noteStore.read('shared');
    expect(readA.revision).toBe(1);
    expect(readB.revision).toBe(1);

    // A 先保存：revision 1 → 2
    await a.session.noteStore.update('shared', 'A 的修改', readA.revision);

    // B 拿着过期的 revision 1 保存 → 必须被拒绝，A 的内容不能被覆盖
    await expect(b.session.noteStore.update('shared', 'B 的修改', readB.revision)).rejects.toThrow(
      ConflictError,
    );
    await expect(a.session.noteStore.read('shared')).resolves.toMatchObject({
      plaintext: 'A 的修改',
      revision: 2,
    });

    // B 重新载入后再保存即可成功
    const fresh = await b.session.noteStore.read('shared');
    expect(fresh.plaintext).toBe('A 的修改');
    await b.session.noteStore.update('shared', 'B 基于新版本的修改', fresh.revision);
    await expect(a.session.noteStore.read('shared')).resolves.toMatchObject({
      plaintext: 'B 基于新版本的修改',
      revision: 3,
    });
  });

  it('另一标签页删除便笺后，本地保存同样被拦下', async () => {
    const { a, b } = await makeTabPair();
    await a.session.initialize('shared-pass');
    await b.session.unlock('shared-pass');
    await a.session.noteStore.create('doomed', '将被删除');

    const readB = await b.session.noteStore.read('doomed');
    await a.session.noteStore.remove('doomed');

    await expect(
      b.session.noteStore.update('doomed', '试图写回', readB.revision),
    ).rejects.toThrow(ConflictError);
    expect(await b.session.noteStore.list()).toHaveLength(0);
  });
});
