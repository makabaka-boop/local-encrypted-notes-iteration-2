import { describe, expect, it } from 'vitest';
import {
  decryptNote,
  deriveKek,
  encryptNote,
  generateDataKey,
  unwrapDataKey,
  wrapDataKey,
} from '../src/crypto';
import { TEST_ITERATIONS } from './helpers';

describe('加密原语', () => {
  it('便笺加密/解密往返一致，且每次 IV 不同', async () => {
    const key = await generateDataKey();
    const a = await encryptNote(key, '同一条明文');
    const b = await encryptNote(key, '同一条明文');
    expect(a.iv).not.toEqual(b.iv);
    expect(new Uint8Array(a.ciphertext)).not.toEqual(new Uint8Array(b.ciphertext));
    await expect(decryptNote(key, a.iv, a.ciphertext)).resolves.toBe('同一条明文');
  });

  it('相同口令 + 相同盐可解封；口令错误则解封失败', async () => {
    const dataKey = await generateDataKey();
    const salt = new Uint8Array(16).fill(7);
    const kek = await deriveKek('correct horse', salt, TEST_ITERATIONS);
    const { wrapIv, wrappedKey } = await wrapDataKey(dataKey, kek);

    const kekAgain = await deriveKek('correct horse', salt, TEST_ITERATIONS);
    const unwrapped = await unwrapDataKey(wrappedKey, wrapIv, kekAgain);
    const probe = await encryptNote(unwrapped, '探针');
    await expect(decryptNote(dataKey, probe.iv, probe.ciphertext)).resolves.toBe('探针');

    const wrongKek = await deriveKek('wrong', salt, TEST_ITERATIONS);
    await expect(unwrapDataKey(wrappedKey, wrapIv, wrongKek)).rejects.toThrow();
  });

  it('密文被篡改时 AES-GCM 校验失败', async () => {
    const key = await generateDataKey();
    const { iv, ciphertext } = await encryptNote(key, '原始内容');
    const tampered = new Uint8Array(ciphertext.slice(0));
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    await expect(decryptNote(key, iv, tampered.buffer)).rejects.toThrow();
  });
});
