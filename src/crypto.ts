/**
 * 加密原语（全部基于 WebCrypto，密钥不离开内存）：
 *
 *   口令 ──PBKDF2(SHA-256, salt, iterations)──▶ KEK（仅内存）
 *   数据密钥 DK：首次创建时随机生成的 AES-GCM-256 密钥
 *   DK 由 KEK 以 AES-GCM 封装（wrapKey）后存入 IndexedDB；
 *   每条便笺用 DK + 独立随机 IV 以 AES-GCM 加密。
 *
 * 改口令 = 用新 KEK 重新封装同一个 DK，便笺密文完全不动。
 */

const subtle = globalThis.crypto.subtle;

/** PBKDF2 默认迭代次数（测试可注入更小的值以提速） */
export const KDF_ITERATIONS = 250_000;

const DATA_KEY_ALGO: AesKeyAlgorithm = { name: 'AES-GCM', length: 256 };

export function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/** 生成随机数据密钥（可导出，仅为了能被 wrapKey 封装；封装结果落盘，原始密钥只在内存） */
export function generateDataKey(): Promise<CryptoKey> {
  return subtle.generateKey(DATA_KEY_ALGO, true, ['encrypt', 'decrypt']);
}

/** 由口令派生密钥封装密钥（KEK），仅允许 wrap/unwrap，不可导出 */
export async function deriveKek(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    DATA_KEY_ALGO,
    false,
    ['wrapKey', 'unwrapKey'],
  );
}

export interface WrappedDataKey {
  wrapIv: Uint8Array;
  wrappedKey: ArrayBuffer;
}

/** 用 KEK 封装数据密钥（随机 wrap IV） */
export async function wrapDataKey(dataKey: CryptoKey, kek: CryptoKey): Promise<WrappedDataKey> {
  const wrapIv = randomBytes(12);
  const wrappedKey = await subtle.wrapKey('raw', dataKey, kek, { name: 'AES-GCM', iv: wrapIv });
  return { wrapIv, wrappedKey };
}

/** 用 KEK 解封数据密钥；口令错误时 AES-GCM 校验失败并抛异常 */
export function unwrapDataKey(
  wrappedKey: ArrayBuffer,
  wrapIv: Uint8Array,
  kek: CryptoKey,
): Promise<CryptoKey> {
  return subtle.unwrapKey(
    'raw',
    wrappedKey,
    kek,
    { name: 'AES-GCM', iv: wrapIv },
    DATA_KEY_ALGO,
    true,
    ['encrypt', 'decrypt'],
  );
}

export interface EncryptedNote {
  iv: Uint8Array;
  ciphertext: ArrayBuffer;
}

/** 每条便笺使用全新的随机 IV */
export async function encryptNote(dataKey: CryptoKey, plaintext: string): Promise<EncryptedNote> {
  const iv = randomBytes(12);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    dataKey,
    new TextEncoder().encode(plaintext),
  );
  return { iv, ciphertext };
}

/** AES-GCM 自带完整性校验：密文/IV 被篡改时 reject */
export async function decryptNote(
  dataKey: CryptoKey,
  iv: Uint8Array,
  ciphertext: ArrayBuffer,
): Promise<string> {
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, dataKey, ciphertext);
  return new TextDecoder().decode(plain);
}

export interface SealedManifest {
  /** 清单封套的独立随机 IV（AES-GCM，96 bit） */
  manifestIv: Uint8Array;
  /** 经数据密钥 AES-GCM 认证加密后的清单（密文 + GCM 认证标签） */
  sealed: ArrayBuffer;
}

/**
 * 用数据密钥对备份清单的规范化字节做认证加密（随机 IV）。
 * 数据密钥只有持有正确口令解封后才能得到，因此这份 GCM 封套
 * 同时保证清单的机密性与完整性：删条、换 ID、调换密文等任何篡改
 * 都会在 openManifest 时被认证标签拒绝。
 */
export async function sealManifest(dataKey: CryptoKey, canonical: Uint8Array): Promise<SealedManifest> {
  const manifestIv = randomBytes(12);
  const sealed = await subtle.encrypt({ name: 'AES-GCM', iv: manifestIv }, dataKey, canonical);
  return { manifestIv, sealed };
}

/** 打开清单封套；数据密钥不符或封套被篡改时 AES-GCM 校验失败并 reject */
export function openManifest(
  dataKey: CryptoKey,
  manifestIv: Uint8Array,
  sealed: ArrayBuffer,
): Promise<ArrayBuffer> {
  return subtle.decrypt({ name: 'AES-GCM', iv: manifestIv }, dataKey, sealed);
}
