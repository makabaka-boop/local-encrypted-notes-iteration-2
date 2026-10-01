import { decryptNote, openWithDataKey, sealWithDataKey, sha256 } from './crypto';
import { CapacityError, IntegrityError } from './errors';
import { MAX_NOTES } from './store';
import type {
  BackupFile,
  NoteRecord,
  PortableNote,
  PortableWrappedKey,
  WrappedKeyRecord,
} from './types';

export const BACKUP_FORMAT = 'secure-notes-workbench-backup';
export const BACKUP_VERSION = 1;

interface ManifestNote {
  id: string;
  revision: number;
  updatedAt: number;
  iv: string;
  /** 对 IV + 密文的摘要；调换密文即使仍可解密也无法通过清单校验 */
  digest: string;
}

interface BackupManifest {
  format: typeof BACKUP_FORMAT;
  version: typeof BACKUP_VERSION;
  exportedAt: number;
  wrappedKey: PortableWrappedKey;
  noteCount: number;
  notes: ManifestNote[];
}

export interface ParsedBackup {
  file: BackupFile;
  wrappedKey: WrappedKeyRecord;
  notes: NoteRecord[];
  manifestSealed: {
    iv: Uint8Array;
    ciphertext: ArrayBuffer;
  };
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buffer));
}

function base64ToArrayBuffer(value: string): ArrayBuffer {
  const bytes = base64ToBytes(value);
  // 复制成独立 ArrayBuffer，避免调用方意外修改 DataView 背后的分配
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** 稳定序列化：对象键按字典序输出，避免不同 JSON 实现导致的清单字节差异 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
}

function portableWrappedKey(record: WrappedKeyRecord): PortableWrappedKey {
  return {
    kdf: {
      salt: bytesToBase64(record.kdf.salt),
      iterations: record.kdf.iterations,
    },
    wrapIv: bytesToBase64(record.wrapIv),
    wrappedKey: arrayBufferToBase64(record.wrappedKey),
    revision: record.revision,
  };
}

function portableNote(record: NoteRecord): PortableNote {
  return {
    id: record.id,
    iv: bytesToBase64(record.iv),
    ciphertext: arrayBufferToBase64(record.ciphertext),
    revision: record.revision,
    updatedAt: record.updatedAt,
  };
}

async function digestNote(iv: Uint8Array, ciphertext: ArrayBuffer): Promise<string> {
  const data = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  data.set(iv, 0);
  data.set(new Uint8Array(ciphertext), iv.byteLength);
  return bytesToBase64(await sha256(data));
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new IntegrityError(message);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isBase64(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.length % 4 === 0;
}

/**
 * 仅在已解锁会话中调用：导出封装密钥、数据密钥认证的清单与全部密文。
 * 不接触明文，也不包含口令。
 */
export async function createBackupFile(
  wrappedKeyRecord: WrappedKeyRecord,
  noteRecords: NoteRecord[],
  dataKey: CryptoKey,
  exportedAt = Date.now(),
): Promise<BackupFile> {
  const records = [...noteRecords].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const wrappedKey = portableWrappedKey(wrappedKeyRecord);
  const manifestNotes: ManifestNote[] = [];
  for (const record of records) {
    manifestNotes.push({
      id: record.id,
      revision: record.revision,
      updatedAt: record.updatedAt,
      iv: bytesToBase64(record.iv),
      digest: await digestNote(record.iv, record.ciphertext),
    });
  }

  const manifest: BackupManifest = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exportedAt,
    wrappedKey,
    noteCount: manifestNotes.length,
    notes: manifestNotes,
  };
  const sealed = await sealWithDataKey(dataKey, new TextEncoder().encode(canonicalJson(manifest)));

  return {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exportedAt,
    wrappedKey,
    manifest: {
      iv: bytesToBase64(sealed.iv),
      ciphertext: arrayBufferToBase64(sealed.ciphertext),
    },
    notes: records.map(portableNote),
  };
}

/** 先做无需密钥的结构解析；任何封装内容写入都必须等完整校验之后 */
export function parseBackupFile(value: unknown): ParsedBackup {
  assert(value !== null && typeof value === 'object', '备份格式错误');
  const file = value as Partial<BackupFile>;
  assert(file.format === BACKUP_FORMAT, '备份格式错误');
  assert(file.version === BACKUP_VERSION, '备份版本不受支持');
  assert(isPositiveSafeInteger(file.exportedAt), '备份时间戳无效');
  assert(Array.isArray(file.notes), '备份缺少便笺清单');
  // 硬上限属于包结构，不依赖口令；解封 DK 前先拒绝超限包
  if (file.notes.length > MAX_NOTES) throw new CapacityError('备份包含超过 100 条便笺');

  const wrapperSource = file.wrappedKey as Partial<PortableWrappedKey> | undefined;
  assert(wrapperSource !== undefined, '备份缺少密钥封装记录');
  assert(isBase64(wrapperSource.wrapIv), '密钥封装 IV 无效');
  assert(isBase64(wrapperSource.wrappedKey), '密钥封装数据无效');
  assert(
    wrapperSource.kdf !== undefined &&
      isBase64(wrapperSource.kdf.salt) &&
      isPositiveSafeInteger(wrapperSource.kdf.iterations),
    '密钥派生参数无效',
  );
  assert(isPositiveSafeInteger(wrapperSource.revision), '封装修订号无效');

  const wrapIv = base64ToBytes(wrapperSource.wrapIv);
  const salt = base64ToBytes(wrapperSource.kdf.salt);
  assert(wrapIv.length === 12 && salt.length >= 16, '密钥参数长度无效');

  const wrappedKey: WrappedKeyRecord = {
    kdf: { salt, iterations: wrapperSource.kdf!.iterations },
    wrapIv,
    wrappedKey: base64ToArrayBuffer(wrapperSource.wrappedKey),
    revision: wrapperSource.revision,
  };

  const seen = new Set<string>();
  const notes: NoteRecord[] = [];
  for (const item of file.notes) {
    assert(item !== null && typeof item === 'object', '便笺记录格式错误');
    assert(typeof item.id === 'string' && item.id !== '', '便笺 ID 无效');
    assert(!seen.has(item.id), '备份包含重复便笺 ID');
    seen.add(item.id);
    assert(isBase64(item.iv) && isBase64(item.ciphertext), '便笺密文格式错误');
    assert(isPositiveSafeInteger(item.revision), '便笺修订号无效');
    assert(isPositiveSafeInteger(item.updatedAt), '便笺时间戳无效');
    const iv = base64ToBytes(item.iv);
    assert(iv.length === 12, '便笺 IV 长度无效');
    notes.push({
      id: item.id,
      iv,
      ciphertext: base64ToArrayBuffer(item.ciphertext),
      revision: item.revision,
      updatedAt: item.updatedAt,
    });
  }

  assert(
    file.manifest !== undefined &&
      isBase64(file.manifest.iv) &&
      isBase64(file.manifest.ciphertext),
    '备份认证清单无效',
  );
  const manifestIv = base64ToBytes(file.manifest.iv);
  assert(manifestIv.length === 12, '备份清单 IV 长度无效');

  return {
    file: file as BackupFile,
    wrappedKey,
    notes,
    manifestSealed: {
      iv: manifestIv,
      ciphertext: base64ToArrayBuffer(file.manifest.ciphertext),
    },
  };
}

/**
 * 用解封出的数据密钥认证整个清单，并逐条校验摘要与 AES-GCM 密文。
 * 通过后调用方才可进入唯一的写入事务；返回值不带明文。
 */
export async function verifyBackupWithDataKey(
  parsed: ParsedBackup,
  dataKey: CryptoKey,
  maxNotes = MAX_NOTES,
  checkpoint: (() => void) | null = null,
): Promise<{ wrappedKey: WrappedKeyRecord; notes: NoteRecord[] }> {
  if (parsed.notes.length > maxNotes) throw new CapacityError('备份包含超过 100 条便笺');
  checkpoint?.();

  let manifest: BackupManifest;
  try {
    const plain = await openWithDataKey(dataKey, parsed.manifestSealed);
    manifest = JSON.parse(new TextDecoder().decode(plain)) as BackupManifest;
  } catch {
    throw new IntegrityError('备份清单认证失败，文件可能已被篡改');
  }
  checkpoint?.();

  assert(manifest.format === BACKUP_FORMAT && manifest.version === BACKUP_VERSION, '备份清单版本无效');
  assert(manifest.exportedAt === parsed.file.exportedAt, '备份时间戳与清单不一致');
  assert(manifest.noteCount === parsed.notes.length, '备份便笺数量与清单不一致');
  assert(canonicalJson(manifest.wrappedKey) === canonicalJson(parsed.file.wrappedKey), '密钥封装记录与清单不一致');

  const outer = new Map(parsed.notes.map((note) => [note.id, note]));
  assert(manifest.notes.length === outer.size, '备份清单包含重复便笺');
  const expectedIds = new Set(manifest.notes.map((note) => note.id));
  assert(expectedIds.size === manifest.notes.length, '备份清单包含重复便笺');
  for (const id of outer.keys()) assert(expectedIds.has(id), '备份便笺未通过清单认证');

  for (const item of manifest.notes) {
    const note = outer.get(item.id);
    assert(note !== undefined, '备份便笺未通过清单认证');
    assert(note.revision === item.revision && note.updatedAt === item.updatedAt, '备份便笺元信息与清单不一致');
    assert(bytesToBase64(note.iv) === item.iv, '备份便笺 IV 与清单不一致');
    assert((await digestNote(note.iv, note.ciphertext)) === item.digest, '备份密文与清单不一致');
    checkpoint?.();
    // 逐条 GCM 解密验证；解密明文随循环结束释放，不返回给调用方
    await decryptNote(dataKey, note.iv, note.ciphertext);
    checkpoint?.();
  }

  return { wrappedKey: parsed.wrappedKey, notes: parsed.notes };
}

export function backupToJson(file: BackupFile): string {
  return JSON.stringify(file);
}

export function parseBackupJson(text: string): ParsedBackup {
  try {
    return parseBackupFile(JSON.parse(text) as unknown);
  } catch (err) {
    if (err instanceof IntegrityError || err instanceof CapacityError) throw err;
    throw new IntegrityError('备份不是有效的 JSON 文件');
  }
}
