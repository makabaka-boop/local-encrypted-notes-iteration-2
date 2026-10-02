/**
 * 加密备份文件（版本 1）。
 *
 * 文件是带格式版本标记的 JSON，只包含三类数据：
 *   1. 数据密钥的封装记录（KDF 盐/迭代次数、wrap IV、被 KEK 封装的 DK）；
 *   2. 各便笺的密文记录（id、IV、密文、修订号、时间戳）；
 *   3. 用数据密钥 AES-GCM 认证加密的「清单封套」。
 *
 * 备份中**绝不**包含口令、KEK、DK 原始字节或任何便笺明文。
 *
 * 清单的身份：清单的规范化字节（canonical encoding）由数据密钥做
 * AES-GCM 认证加密。恢复时先用输入口令解封数据密钥，再打开封套并逐字节
 * 重算比对——因此删除一条、替换 id、调换两条密文、改写时间戳或替换封装
 * 记录，都无法伪装成一份完整自洽的备份：要么解封失败，要么清单不认。
 */
import { sealManifest, type SealedManifest } from './crypto';
import { BackupError } from './errors';
import { MAX_NOTES } from './store';
import type { NoteRecord, WrappedKeyRecord } from './types';

export const BACKUP_FORMAT = 'secure-notes-workbench/backup';
export const BACKUP_VERSION = 1;
const BACKUP_ID_PREFIX = 'backup-';

/** 清单规范化字节的魔数与版本（4 字节：'S' 'N' 'M' 0x01） */
const CANON_MAGIC = Uint8Array.of(0x53, 0x4e, 0x4d, 0x01);
const IV_LENGTH = 12;

/** 解析后的备份：所有二进制字段已转为与存储层一致的类型 */
export interface ParsedBackup {
  format: string;
  version: typeof BACKUP_VERSION;
  exportedAt: number;
  id: string;
  wrapped: WrappedKeyRecord;
  notes: NoteRecord[];
  manifest: { iv: Uint8Array; sealed: ArrayBuffer };
}

interface BackupFileJSON {
  format: unknown;
  version: unknown;
  exportedAt: unknown;
  id: unknown;
  wrapped: unknown;
  notes: unknown;
  manifest: unknown;
}

// ---------- Base64（浏览器与 Node 20 均提供 btoa/atob） ----------

/** 字节 → base64 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

/** base64 → 字节；非法字符直接拒绝（atob 本身会抛，但再做一次完整校验） */
export function base64ToBytes(value: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new BackupError('备份文件含非法的 Base64 字段');
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new BackupError('备份文件含非法的 Base64 字段');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // slice 得到独立且从偏移 0 开始的底层缓冲
  return bytes.slice().buffer as ArrayBuffer;
}

// ---------- 规范化清单编码 ----------

/** 追加式小工具：所有整数大端写入，保证跨实现逐字节一致 */
class ByteWriter {
  private parts: number[] = [];

  u32(value: number): this {
    this.parts.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
    return this;
  }

  /** JavaScript 数字按 IEEE-754 双精度大端写入（修订号/时间戳） */
  f64(value: number): this {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value, false);
    for (let i = 0; i < 8; i += 1) this.parts.push(view.getUint8(i));
    return this;
  }

  bytes(value: Uint8Array): this {
    this.u32(value.length);
    for (let i = 0; i < value.length; i += 1) this.parts.push(value[i]!);
    return this;
  }

  fixed(value: Uint8Array, length: number): this {
    if (value.length !== length) throw new BackupError(`字段长度应为 ${length} 字节`);
    for (let i = 0; i < value.length; i += 1) this.parts.push(value[i]!);
    return this;
  }

  utf8(value: string): this {
    return this.bytes(new TextEncoder().encode(value));
  }

  toUint8Array(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

function asBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

/**
 * 清单的规范化字节：字段顺序固定、长度前缀明确、便笺按 id 排序。
 * JSON 里的顺序、空白、exportedAt、封套本身都不影响身份——
 * 参与认证的只有「封装记录 + 全部便笺条目」。
 */
export function canonicalManifestBytes(
  wrapped: WrappedKeyRecord,
  notes: NoteRecord[],
): Uint8Array {
  if (!Number.isFinite(wrapped.kdf.iterations) || !Number.isFinite(wrapped.revision)) {
    throw new BackupError('封装记录字段不合法');
  }
  const sorted = [...notes].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const w = new ByteWriter();
  w.fixed(CANON_MAGIC, 4);
  w.bytes(wrapped.kdf.salt);
  w.u32(wrapped.kdf.iterations);
  w.fixed(wrapped.wrapIv, IV_LENGTH);
  w.bytes(asBytes(wrapped.wrappedKey));
  w.f64(wrapped.revision);
  w.u32(sorted.length);
  for (const note of sorted) {
    if (!Number.isFinite(note.revision) || !Number.isFinite(note.updatedAt)) {
      throw new BackupError(`便笺「${note.id}」的修订号或时间戳不合法`);
    }
    w.utf8(note.id);
    w.fixed(note.iv, IV_LENGTH);
    w.bytes(asBytes(note.ciphertext));
    w.f64(note.revision);
    w.f64(note.updatedAt);
  }
  return w.toUint8Array();
}

/** 常数时间比较：清单重算结果必须与封套打开结果逐字节一致 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

// ---------- 序列化 ----------

/** 把（已含清单封套的）备份序列化为带缩进的 JSON 文本 */
export function serializeBackupFile(
  wrapped: WrappedKeyRecord,
  notes: NoteRecord[],
  manifest: SealedManifest,
  exportedAt: number,
): string {
  const payload: BackupFileJSON = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exportedAt,
    id: `${BACKUP_ID_PREFIX}${globalThis.crypto.randomUUID()}`,
    wrapped: {
      kdf: { salt: bytesToBase64(wrapped.kdf.salt), iterations: wrapped.kdf.iterations },
      wrapIv: bytesToBase64(wrapped.wrapIv),
      wrappedKey: bytesToBase64(asBytes(wrapped.wrappedKey)),
      revision: wrapped.revision,
    },
    notes: notes.map((note) => ({
      id: note.id,
      iv: bytesToBase64(note.iv),
      ciphertext: bytesToBase64(asBytes(note.ciphertext)),
      revision: note.revision,
      updatedAt: note.updatedAt,
    })),
    manifest: {
      iv: bytesToBase64(manifest.manifestIv),
      sealed: bytesToBase64(asBytes(manifest.sealed)),
    },
  };
  return `${JSON.stringify(payload, null, 2)}\n`;
}

/**
 * 导出：对当前库的封装记录与全部便笺密文计算规范化清单，
 * 用数据密钥做认证加密后序列化为备份文本。全程只读取密文，
 * 不解密任何便笺，输出不含口令或明文。
 */
export async function createBackupFile(input: {
  wrapped: WrappedKeyRecord;
  notes: NoteRecord[];
  dataKey: CryptoKey;
}): Promise<string> {
  const { wrapped, notes, dataKey } = input;
  if (notes.length > MAX_NOTES) {
    throw new BackupError(`备份包含 ${notes.length} 条便笺，超过 ${MAX_NOTES} 条上限`);
  }
  const canonical = canonicalManifestBytes(wrapped, notes);
  const sealed = await sealManifest(dataKey, canonical);
  return serializeBackupFile(wrapped, notes, sealed, Date.now());
}

// ---------- 解析（严格，任何不符都抛 BackupError） ----------

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asSafeInteger(value: unknown, field: string, min = 1): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) {
    throw new BackupError(`备份字段「${field}」不合法`);
  }
  return value;
}

function b64Field(obj: Record<string, unknown>, field: string): Uint8Array {
  const raw = obj[field];
  if (typeof raw !== 'string') throw new BackupError(`备份字段「${field}」缺失或不合法`);
  return base64ToBytes(raw);
}

function parseWrapped(value: unknown): WrappedKeyRecord {
  if (!isObject(value)) throw new BackupError('备份缺少密钥封装记录');
  const kdfRaw = value.kdf;
  if (!isObject(kdfRaw)) throw new BackupError('备份缺少 KDF 参数');
  const salt = b64Field(kdfRaw, 'salt');
  const iterations = asSafeInteger(kdfRaw.iterations, 'kdf.iterations', 1);
  if (iterations > 0xffffffff) throw new BackupError('KDF 迭代次数超出范围');
  const wrapIv = b64Field(value, 'wrapIv');
  if (wrapIv.length !== IV_LENGTH) throw new BackupError('封装 IV 长度不合法');
  const wrappedKey = b64Field(value, 'wrappedKey');
  if (wrappedKey.length === 0) throw new BackupError('封装数据密钥为空');
  const revision = asSafeInteger(value.revision, 'wrapped.revision', 1);
  return {
    kdf: { salt, iterations },
    wrapIv,
    wrappedKey: toArrayBuffer(wrappedKey),
    revision,
  };
}

function parseNote(value: unknown, index: number): NoteRecord {
  if (!isObject(value)) throw new BackupError(`第 ${index + 1} 条便笺记录不合法`);
  const id = value.id;
  if (typeof id !== 'string' || id.length === 0) {
    throw new BackupError(`第 ${index + 1} 条便笺缺少 id`);
  }
  const iv = b64Field(value, 'iv');
  if (iv.length !== IV_LENGTH) throw new BackupError(`便笺「${id}」的 IV 长度不合法`);
  const ciphertext = b64Field(value, 'ciphertext');
  if (ciphertext.length === 0) throw new BackupError(`便笺「${id}」的密文为空`);
  const revision = asSafeInteger(value.revision, `notes[${index}].revision`, 1);
  const updatedAt = asSafeInteger(value.updatedAt, `notes[${index}].updatedAt`, 0);
  return { id, iv, ciphertext: toArrayBuffer(ciphertext), revision, updatedAt };
}

/**
 * 解析备份文本：结构、类型、版本、长度、ID 唯一性、100 条上限全部在此校验。
 * 不做任何加密运算（密钥尚未解封），也不触碰 IndexedDB。
 */
export function parseBackupFile(text: string): ParsedBackup {
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    throw new BackupError('备份文件不是合法的 JSON');
  }
  if (!isObject(raw)) throw new BackupError('备份文件结构不合法');
  const file = raw as unknown as BackupFileJSON;

  if (file.format !== BACKUP_FORMAT) {
    throw new BackupError('不是本工作台的备份文件（格式标识不符）');
  }
  if (file.version !== BACKUP_VERSION) {
    throw new BackupError(`不支持的备份版本：${String(file.version)}`);
  }
  if (typeof file.exportedAt !== 'number' || !Number.isFinite(file.exportedAt)) {
    throw new BackupError('备份缺少导出时间');
  }
  const id = typeof file.id === 'string' && file.id.length > 0 ? file.id : '';
  if (id === '') throw new BackupError('备份缺少导出标识');

  const wrapped = parseWrapped(file.wrapped);

  if (!Array.isArray(file.notes)) throw new BackupError('备份缺少便笺清单');
  if (file.notes.length > MAX_NOTES) {
    throw new BackupError(`备份包含 ${file.notes.length} 条便笺，超过 ${MAX_NOTES} 条上限`);
  }
  const notes = file.notes.map(parseNote);
  const seen = new Set<string>();
  for (const note of notes) {
    if (seen.has(note.id)) throw new BackupError(`备份中便笺 id 重复：${note.id}`);
    seen.add(note.id);
  }

  if (!isObject(file.manifest)) throw new BackupError('备份缺少认证清单');
  const manifestIv = b64Field(file.manifest, 'iv');
  if (manifestIv.length !== IV_LENGTH) throw new BackupError('清单 IV 长度不合法');
  const sealed = b64Field(file.manifest, 'sealed');
  if (sealed.length === 0) throw new BackupError('清单封套为空');

  return {
    format: file.format as string,
    version: BACKUP_VERSION,
    exportedAt: file.exportedAt,
    id,
    wrapped,
    notes,
    manifest: { iv: manifestIv, sealed: toArrayBuffer(sealed) },
  };
}
