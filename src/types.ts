export interface NoteRecord {
  id: string;
  /** 每条便笺独立的随机 IV（AES-GCM，96 bit） */
  iv: Uint8Array;
  ciphertext: ArrayBuffer;
  /** 乐观锁修订号，每次成功写入 +1 */
  revision: number;
  updatedAt: number;
}

/** PBKDF2 参数（盐与迭代次数不是秘密，可以明文存储） */
export interface KdfParams {
  salt: Uint8Array;
  iterations: number;
}

/** 用口令派生密钥（KEK）封装后的数据密钥 */
export interface WrappedKeyRecord {
  kdf: KdfParams;
  wrapIv: Uint8Array;
  wrappedKey: ArrayBuffer;
  /**
   * 封装记录的修订号，首次初始化为 1，每次改口令 +1。
   * 跨标签页改口令时做乐观锁：事务内比对，不一致即中止，
   * 避免两个标签页的盲写互相静默覆盖。
   */
  revision: number;
}

/** 便笺列表用的元信息（不含明文） */
export interface NoteMeta {
  id: string;
  revision: number;
  updatedAt: number;
}

/** JSON 备份文件中可移植的封装密钥记录（二进制字段使用 base64） */
export interface PortableWrappedKey {
  kdf: {
    salt: string;
    iterations: number;
  };
  wrapIv: string;
  wrappedKey: string;
  revision: number;
}

/** 备份文件里的单条密文便笺（不含明文） */
export interface PortableNote {
  id: string;
  iv: string;
  ciphertext: string;
  revision: number;
  updatedAt: number;
}

/** 已格式化、带版本号的加密备份文件 */
export interface BackupFile {
  format: 'secure-notes-workbench-backup';
  version: 1;
  exportedAt: number;
  wrappedKey: PortableWrappedKey;
  /** 清单由数据密钥以 AES-GCM 加密并认证 */
  manifest: {
    iv: string;
    ciphertext: string;
  };
  notes: PortableNote[];
}
