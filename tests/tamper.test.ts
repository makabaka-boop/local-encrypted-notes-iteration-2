import { describe, expect, it } from 'vitest';
import { IntegrityError } from '../src/errors';
import { makeSession } from './helpers';

describe('密文篡改', () => {
  it('篡改密文字节 → 解密抛 IntegrityError，其它便笺不受影响', async () => {
    const { db, session } = await makeSession();
    await session.initialize('p@ssw0rd!');
    await session.noteStore.create('victim', '受害者便笺');
    await session.noteStore.create('bystander', '旁观者便笺');

    // 直接改写 IndexedDB 里的密文（保持修订号不变，模拟外部篡改）
    const record = (await db.getNote('victim'))!;
    const tampered = new Uint8Array(record.ciphertext.slice(0));
    tampered[3] = (tampered[3] ?? 0) ^ 0x01;
    await db.updateNote({ ...record, ciphertext: tampered.buffer }, record.revision);

    await expect(session.noteStore.read('victim')).rejects.toThrow(IntegrityError);
    // 未篡改的便笺仍可正常解密
    await expect(session.noteStore.read('bystander')).resolves.toMatchObject({
      plaintext: '旁观者便笺',
    });
    // 列表元信息也不受影响
    await expect(session.noteStore.list()).resolves.toHaveLength(2);
  });

  it('篡改 IV 同样被检出', async () => {
    const { db, session } = await makeSession();
    await session.initialize('p@ssw0rd!');
    await session.noteStore.create('n1', '内容');

    const record = (await db.getNote('n1'))!;
    const iv = record.iv.slice();
    iv[0] = (iv[0] ?? 0) ^ 0x80;
    await db.updateNote({ ...record, iv }, record.revision);

    await expect(session.noteStore.read('n1')).rejects.toThrow(IntegrityError);
  });
});
