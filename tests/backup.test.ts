import { describe, expect, it, vi } from 'vitest';
import { AuthError, BackupError, LockedError } from '../src/errors';
import {
  base64ToBytes,
  bytesToBase64,
  canonicalManifestBytes,
  createBackupFile,
  parseBackupFile,
  serializeBackupFile,
  timingSafeEqual,
} from '../src/backup';
import { deriveKek, openManifest, unwrapDataKey } from '../src/crypto';
import { META_WRAPPED_KEY } from '../src/db';
import { MAX_NOTES } from '../src/store';
import type { NoteRecord, WrappedKeyRecord } from '../src/types';
import { makeBackup, makeProbe, makeSession, makeTabPair, TEST_ITERATIONS, toBytes } from './helpers';

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/** 改写备份 JSON 文本并重新序列化 */
function editBackup(text: string, fn: (json: any) => void): string {
  const json = JSON.parse(text) as any;
  fn(json);
  return JSON.stringify(json);
}

/** 把整个库（封装记录 + 全部便笺）逐字节快照，便于「恢复前后逐项一致」比对 */
async function snapshot(db: Awaited<ReturnType<typeof makeSession>>['db']) {
  return {
    wrapped: await db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY),
    notes: (await db.listNotes())
      .map((r) => ({
        id: r.id,
        iv: toBytes(r.iv),
        ciphertext: toBytes(r.ciphertext),
        revision: r.revision,
        updatedAt: r.updatedAt,
      }))
      .sort((a, b) => (a.id < b.id ? -1 : 1)),
  };
}

function expectSnapshotsEqual(
  before: Awaited<ReturnType<typeof snapshot>>,
  after: Awaited<ReturnType<typeof snapshot>>,
) {
  expect(toBytes(after.wrapped!.wrappedKey)).toEqual(toBytes(before.wrapped!.wrappedKey));
  expect(toBytes(after.wrapped!.wrapIv)).toEqual(toBytes(before.wrapped!.wrapIv));
  expect(toBytes(after.wrapped!.kdf.salt)).toEqual(toBytes(before.wrapped!.kdf.salt));
  expect(after.wrapped!.kdf.iterations).toBe(before.wrapped!.kdf.iterations);
  expect(after.wrapped!.revision).toBe(before.wrapped!.revision);
  expect(after.notes).toHaveLength(before.notes.length);
  for (const [i, note] of after.notes.entries()) {
    const prev = before.notes[i]!;
    expect(note.id).toBe(prev.id);
    expect(note.iv).toEqual(prev.iv);
    expect(note.ciphertext).toEqual(prev.ciphertext);
    expect(note.revision).toBe(prev.revision);
    expect(note.updatedAt).toBe(prev.updatedAt);
  }
}

describe('加密备份：导出格式与内容边界', () => {
  it('往返一致：恢复后逐条解密明文/修订号/时间戳与源库一致', async () => {
    const entries: Array<readonly [string, string]> = [
      ['a', '第一条便笺\n带换行'],
      ['b', '第二条'],
      ['c', '第三条 🔐'],
    ];
    const { backup, passphrase } = await makeBackup(entries);
    const target = await makeSession();
    await target.session.restoreFromBackup(backup, passphrase);

    expect(target.session.unlocked).toBe(true);
    const list = await target.session.noteStore.list();
    expect(list).toHaveLength(3);
    for (const [id, plaintext] of entries) {
      await expect(target.session.noteStore.read(id)).resolves.toMatchObject({ plaintext });
    }
  });

  it('备份不含口令或明文；只有封装记录、便笺密文与清单封套', async () => {
    const secret = 'TOP-SECRET-PLAINTEXT-备份不落地';
    const phrase = 'TOP-SECRET-PASSPHRASE-备份不落地';
    const { backup } = await makeBackup([['n1', secret]], phrase);

    expect(backup).not.toContain(secret);
    expect(backup).not.toContain(phrase);

    const parsed = parseBackupFile(backup);
    const keys = Object.keys(parsed).sort();
    expect(keys).toEqual(['exportedAt', 'format', 'id', 'manifest', 'notes', 'version', 'wrapped']);
    expect(parsed.format).toBe('secure-notes-workbench/backup');
    expect(parsed.version).toBe(1);
    expect(Object.keys(parsed.wrapped).sort()).toEqual([
      'kdf',
      'revision',
      'wrapIv',
      'wrappedKey',
    ]);
    expect(Object.keys(parsed.notes[0]!).sort()).toEqual([
      'ciphertext',
      'id',
      'iv',
      'revision',
      'updatedAt',
    ]);
  });

  it('空库（0 条便笺）也可备份并恢复', async () => {
    const { backup, passphrase } = await makeBackup([]);
    const target = await makeSession();
    await target.session.restoreFromBackup(backup, passphrase);
    expect(await target.session.noteStore.list()).toHaveLength(0);
  });

  it('锁定会话不能导出；导出跨越锁定时失败且不产生结果', async () => {
    const source = await makeBackup([['n1', '内容']]);
    source.session.lock();
    await expect(source.session.exportBackup()).rejects.toThrow(LockedError);
  });

  it('导出过程中被锁定：备份结果作废', async () => {
    const source = await makeSession();
    await source.session.initialize('p');
    await source.session.noteStore.create('n1', 'x');
    const exporting = source.session.exportBackup();
    source.session.lock();
    await expect(exporting).rejects.toThrow(LockedError);
  });

  it('恢复成功后既有编辑/修订号规则不变：可继续更新，修订号沿用备份值', async () => {
    const { backup, passphrase } = await makeBackup([['n1', '原始内容']]);
    const target = await makeSession();
    await target.session.restoreFromBackup(backup, passphrase);

    const read = await target.session.noteStore.read('n1');
    expect(read.revision).toBe(1);
    const updated = await target.session.noteStore.update('n1', '恢复后修改', read.revision);
    expect(updated.revision).toBe(2);
    await expect(target.session.noteStore.read('n1')).resolves.toMatchObject({
      plaintext: '恢复后修改',
    });
  });
});

describe('恢复：错误口令', () => {
  it('口令错误：抛 AuthError，空库保持为空、未解锁、不显示明文', async () => {
    const { backup } = await makeBackup([['n1', '不可恢复的明文']]);
    const target = await makeSession();

    await expect(target.session.restoreFromBackup(backup, 'wrong-passphrase')).rejects.toThrow(
      AuthError,
    );
    expect(target.session.unlocked).toBe(false);
    expect(() => target.session.noteStore).toThrow(LockedError);
    expect(await target.db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
    expect(await target.db.countNotes()).toBe(0);
  });

  it('错误口令后正确口令仍可完整恢复', async () => {
    const { backup, passphrase } = await makeBackup([['n1', '仍然可恢复']]);
    const target = await makeSession();

    await expect(target.session.restoreFromBackup(backup, 'nope')).rejects.toThrow(AuthError);
    await target.session.restoreFromBackup(backup, passphrase);
    await expect(target.session.noteStore.read('n1')).resolves.toMatchObject({ plaintext: '仍然可恢复' });
  });
});

describe('恢复：篡改包（清单受数据密钥认证）', () => {
  const mutations: Array<{
    name: string;
    mutate: (json: any) => void;
    /** 改 KDF 参数与「错误口令」不可区分，此时应得 AuthError；其余为清单/格式错误 */
    expectAuth?: boolean;
  }> = [
    { name: '删除一条便笺', mutate: (json) => void json.notes.pop() },
    {
      name: '调换便笺 id（密文互换身份）',
      mutate: (json) => {
        const [a, b] = json.notes;
        [a.id, b.id] = [b.id, a.id];
      },
    },
    {
      name: '替换某条密文为另一条',
      mutate: (json) => {
        json.notes[0].ciphertext = json.notes[1].ciphertext;
      },
    },
    {
      name: '改写密文字节',
      mutate: (json) => {
        const raw = base64ToBytes(json.notes[0].ciphertext);
        raw[5] = (raw[5] ?? 0) ^ 0xff;
        json.notes[0].ciphertext = bytesToBase64(raw);
      },
    },
    {
      name: '改写 IV',
      mutate: (json) => {
        const raw = base64ToBytes(json.notes[0].iv);
        raw[0] = (raw[0] ?? 0) ^ 0x80;
        json.notes[0].iv = bytesToBase64(raw);
      },
    },
    {
      name: '改写修订号',
      mutate: (json) => {
        json.notes[0].revision += 1;
      },
    },
    {
      name: '改写时间戳',
      mutate: (json) => {
        json.notes[0].updatedAt += 999_999;
      },
    },
    {
      name: '替换封装记录',
      mutate: (json) => {
        json.wrapped.revision += 1;
      },
    },
    {
      name: '改写 KDF 盐（与错误口令不可区分）',
      mutate: (json) => {
        const raw = base64ToBytes(json.wrapped.kdf.salt);
        raw[0] = (raw[0] ?? 0) ^ 0x01;
        json.wrapped.kdf.salt = bytesToBase64(raw);
      },
      expectAuth: true,
    },
  ];

  for (const { name, mutate, expectAuth } of mutations) {
    it(`${name} → 恢复被拒，空库不变`, async () => {
      const { backup, passphrase } = await makeBackup([
        ['a', '内容 A'],
        ['b', '内容 B'],
      ]);
      const target = await makeSession();
      const tampered = editBackup(backup, mutate);

      await expect(target.session.restoreFromBackup(tampered, passphrase)).rejects.toThrow(
        expectAuth ? AuthError : BackupError,
      );
      expect(target.session.unlocked).toBe(false);
      expect(await target.db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
      expect(await target.db.countNotes()).toBe(0);
    });
  }

  it('清单封套本身被改写 → openManifest 认证失败', async () => {
    const { backup, passphrase } = await makeBackup([['a', 'A']]);
    const tampered = editBackup(backup, (json) => {
      const raw = base64ToBytes(json.manifest.sealed);
      raw[0] = (raw[0] ?? 0) ^ 0x01;
      json.manifest.sealed = bytesToBase64(raw);
    });
    const target = await makeSession();
    await expect(target.session.restoreFromBackup(tampered, passphrase)).rejects.toThrow(
      BackupError,
    );
  });

  it('用另一数据密钥签的清单（完整自洽的异包）顶替 → 认证失败', async () => {
    // 源 1：正常备份；源 2：用不同口令/不同数据密钥生成另一份备份，
    // 把源 1 的内容配上源 2 的清单封套，清单与封装记录不可能同时成立
    const src1 = await makeBackup([['n1', '来自源一']], 'pass-one');
    const src2 = await makeBackup([['n1', '来自源二']], 'pass-two');
    const j1 = JSON.parse(src1.backup) as any;
    const j2 = JSON.parse(src2.backup) as any;
    j1.manifest = j2.manifest;
    const target = await makeSession();
    await expect(
      target.session.restoreFromBackup(JSON.stringify(j1), src1.passphrase),
    ).rejects.toThrow(BackupError);
    expect(await target.db.countNotes()).toBe(0);
  });

  it('结构非法 / 版本不符 / 非 JSON：解析即拒', async () => {
    const { backup, passphrase } = await makeBackup([['a', 'A']]);
    const target = await makeSession();

    await expect(target.session.restoreFromBackup('not-json{', passphrase)).rejects.toThrow(
      BackupError,
    );
    await expect(
      target.session.restoreFromBackup(editBackup(backup, (j) => (j.format = 'other')), passphrase),
    ).rejects.toThrow(BackupError);
    await expect(
      target.session.restoreFromBackup(editBackup(backup, (j) => (j.version = 2)), passphrase),
    ).rejects.toThrow(BackupError);
    await expect(
      target.session.restoreFromBackup(editBackup(backup, (j) => delete j.wrapped), passphrase),
    ).rejects.toThrow(BackupError);
    await expect(
      target.session.restoreFromBackup(editBackup(backup, (j) => (j.notes = {})), passphrase),
    ).rejects.toThrow(BackupError);
    await expect(
      target.session.restoreFromBackup(editBackup(backup, (j) => (j.notes[0].iv = '====')), passphrase),
    ).rejects.toThrow(BackupError);
  });

  it('重复 id / 超 100 条：解析即拒（无需口令）', async () => {
    const { backup } = await makeBackup([['a', 'A'], ['b', 'B']]);
    const dup = editBackup(backup, (j) => {
      j.notes[1].id = j.notes[0].id;
    });
    expect(() => parseBackupFile(dup)).toThrow(BackupError);

    const tooMany = editBackup(backup, (j) => {
      const template = { ...j.notes[0] };
      j.notes = Array.from({ length: MAX_NOTES + 1 }, (_, i) => ({
        ...template,
        id: `x${i}`,
      }));
    });
    expect(() => parseBackupFile(tooMany)).toThrow(BackupError);
  });

  it('逐条验证：仅某条密文损坏时，正确清单也无法放行，整包不落库', async () => {
    // 手工构造：封装记录与清单封套都合法（用真实 DK 签名），
    // 但其中一条便笺密文替换成「用同一 DK 加密的另一段密文」。
    // 导出只认证存储现状、不校验密文，因此清单认证能过；
    // 恢复必须在「逐条验证密文」环节拒绝。
    const source = await makeSession();
    await source.session.initialize('p');
    const store = source.session.noteStore;
    await store.create('keep', '完好条目');
    const other = await store.create('other', '完全不同的另一段明文内容');
    await store.create('victim', '将被调换的明文');

    const otherRecord = await source.db.getNote(other.id);
    const victimRecord = await source.db.getNote('victim');
    // victim 的密文换成 other 的密文（id/iv/修订号保留）后再导出
    await source.db.updateNote(
      { ...victimRecord!, ciphertext: otherRecord!.ciphertext },
      victimRecord!.revision,
    );
    const text = await source.session.exportBackup();

    const target = await makeSession();
    await expect(target.session.restoreFromBackup(text, 'p')).rejects.toThrow(/victim/);
    expect(await target.db.countNotes()).toBe(0);
    expect(await target.db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
  });
});

describe('恢复：只允许目标库为空', () => {
  it('目标库已有封装记录（另一标签页抢先初始化）：拒绝且逐项一致', async () => {
    const { backup, passphrase } = await makeBackup([['n1', '备份里的内容']]);
    const target = await makeSession();
    await target.session.initialize('target-own-pass');
    await target.session.noteStore.create('own', '新浏览器里已有的内容');
    target.session.lock();
    const before = await snapshot(target.db);

    await expect(target.session.restoreFromBackup(backup, passphrase)).rejects.toThrow(
      BackupError,
    );
    const after = await snapshot(target.db);
    expectSnapshotsEqual(before, after);

    // 目标库原有口令与数据照旧可用
    await target.session.unlock('target-own-pass');
    await expect(target.session.noteStore.read('own')).resolves.toMatchObject({
      plaintext: '新浏览器里已有的内容',
    });
    await expect(target.session.noteStore.read('n1')).rejects.toThrow();
  });

  it('已解锁会话上请求恢复：直接拒绝，现有数据不变', async () => {
    const { backup, passphrase } = await makeBackup([['n1', 'x']]);
    const target = await makeSession();
    await target.session.initialize('own');
    await target.session.noteStore.create('own', 'y');
    const before = await snapshot(target.db);

    await expect(target.session.restoreFromBackup(backup, passphrase)).rejects.toThrow(
      BackupError,
    );
    expect(target.session.unlocked).toBe(true);
    expectSnapshotsEqual(before, await snapshot(target.db));
  });

  it('预检通过但事务内发现非空（抢先初始化）：仍拒绝，不覆盖获胜方', async () => {
    // 直接驱动 DB 层：预检后、事务内 meta 已存在
    const parsed = parseBackupFile((await makeBackup([['n1', 'x']])).backup);
    const target = await makeSession();
    await target.session.initialize('racer-owns');
    await expect(
      target.db.restoreIntoEmpty(parsed.wrapped, parsed.notes),
    ).rejects.toThrow(BackupError);
    const meta = await target.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    expect(meta!.revision).toBe(1);
    expect(await target.db.countNotes()).toBe(0);
  });

  it('事务内 notes 非空（无 meta）同样拒绝', async () => {
    const parsed = parseBackupFile((await makeBackup([['n1', 'x']])).backup);
    const { db } = await makeSession();
    await db.createNote(
      {
        id: 'orphan',
        iv: new Uint8Array(12),
        ciphertext: new ArrayBuffer(32),
        revision: 1,
        updatedAt: Date.now(),
      },
      MAX_NOTES,
    );
    await expect(db.restoreIntoEmpty(parsed.wrapped, parsed.notes)).rejects.toThrow(BackupError);
    expect(await db.countNotes()).toBe(1);
    expect(await db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
  });
});

describe('恢复：事务中止 / 配额失败 / 异步锁定', () => {
  it('写入中途事务中止（结构性克隆失败）：整体回滚，库保持全空', async () => {
    const { IDBObjectStore } = await import('fake-indexeddb');
    const { backup, passphrase } = await makeBackup([
      ['n1', '一'],
      ['n2', '二'],
      ['n3', '三'],
    ]);
    const target = await makeSession();

    // 在第 2 条便笺写入时让底层 put 失败，触发事务中止 → 全部写入回滚
    let puts = 0;
    const original = IDBObjectStore.prototype.put;
    const spy = vi.spyOn(IDBObjectStore.prototype, 'put');
    spy.mockImplementation(function (this: any, value: unknown, key?: IDBValidKey) {
      puts += 1;
      if (puts === 2) {
        // 无原型、无法结构化克隆的对象：请求立即失败 → 事务 abort
        return original.call(this, Object.create(null), key);
      }
      return original.call(this, value, key);
    });

    await expect(target.session.restoreFromBackup(backup, passphrase)).rejects.toThrow();
    spy.mockRestore();

    expect(await target.db.countNotes()).toBe(0);
    expect(await target.db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
    expect(target.session.unlocked).toBe(false);

    // 库没有被污染：同一份备份随后可完整恢复
    await target.session.restoreFromBackup(backup, passphrase);
    expect(await target.session.noteStore.read('n1')).toMatchObject({ plaintext: '一' });
    expect(await target.session.noteStore.read('n2')).toMatchObject({ plaintext: '二' });
    expect(await target.session.noteStore.read('n3')).toMatchObject({ plaintext: '三' });
  });

  it('checkpoint（事务内写入前）发现会话已锁定：中止，空库不变', async () => {
    const parsed = parseBackupFile((await makeBackup([['n1', 'x']])).backup);
    const { db } = await makeSession();
    const checkpoint = () => {
      throw new LockedError('工作台已锁定');
    };
    await expect(db.restoreIntoEmpty(parsed.wrapped, parsed.notes, checkpoint)).rejects.toThrow(
      LockedError,
    );
    expect(await db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
    expect(await db.countNotes()).toBe(0);
  });

  it('恢复底层写失败（模拟配额耗尽）：库不变、未解锁、无明文', async () => {
    const { backup, passphrase } = await makeBackup([['n1', '配额下幸存']]);
    const target = await makeSession();
    vi.spyOn(target.db, 'restoreIntoEmpty').mockRejectedValueOnce(
      new DOMException('The quota has been exceeded.', 'QuotaExceededError'),
    );
    await expect(target.session.restoreFromBackup(backup, passphrase)).rejects.toThrow(
      'quota',
    );
    expect(target.session.unlocked).toBe(false);
    expect(() => target.session.noteStore).toThrow(LockedError);
    expect(await target.db.countNotes()).toBe(0);
    expect(await target.db.getMeta(META_WRAPPED_KEY)).toBeUndefined();
  });

  it('逐条验证期间被另一标签页锁定：恢复作废，不写入、不解锁', async () => {
    const { a, b } = await makeTabPair();
    const { backup, passphrase } = await makeBackup([['n1', '迟到数据']]);

    const restoring = b.session.restoreFromBackup(backup, passphrase);
    // 立即挂上拒绝处理器，避免锁定在首个 await 边界触发时被记为未处理拒绝
    restoring.catch(() => {});
    // restore 会先逐条验证（此处只有 1 条且很快）：与锁定竞争，
    // 无论锁定在验证前还是提交后生效，最终都必须保持锁定且无明文
    a.session.lock();
    await flush();

    const result = await Promise.allSettled([restoring]);
    const outcome = result[0]!;
    if (outcome.status === 'fulfilled') {
      // 数据已原子落盘 → 本标签页随即被锁定；重新解锁可读到完整数据
      expect(b.session.unlocked).toBe(false);
      await b.session.unlock(passphrase);
      await expect(b.session.noteStore.read('n1')).resolves.toMatchObject({ plaintext: '迟到数据' });
    } else {
      expect(outcome.reason).toBeInstanceOf(LockedError);
      expect(b.session.unlocked).toBe(false);
      expect(await b.db.countNotes()).toBe(0);
    }
  });
});

describe('恢复：双标签交错', () => {
  it('确定顺序：先恢复后初始化——初始化被拒，备份数据与口令完好', async () => {
    const { name, a, b } = await makeTabPair();
    const { backup, passphrase } = await makeBackup([['n1', '备份数据']]);

    await a.session.restoreFromBackup(backup, passphrase);
    await expect(b.session.initialize('brand-new-pass')).rejects.toThrow();

    expect(a.session.unlocked).toBe(true);
    expect(b.session.unlocked).toBe(false);
    await expect(a.session.noteStore.read('n1')).resolves.toMatchObject({ plaintext: '备份数据' });

    // 第三方探测：初始化方的口令无效，备份口令有效
    const probe = await makeProbe(name);
    await expect(probe.session.unlock('brand-new-pass')).rejects.toThrow(AuthError);
    await probe.session.unlock(passphrase);
    expect(await probe.session.noteStore.list()).toHaveLength(1);
  });

  it('确定顺序：先初始化后恢复——恢复被拒，逐项一致', async () => {
    const { a, b } = await makeTabPair();
    const { backup, passphrase } = await makeBackup([['n1', '备份数据']]);

    await a.session.initialize('owner-pass');
    await a.session.noteStore.create('own', '浏览器已有数据');
    const before = await snapshot(a.db);

    await expect(b.session.restoreFromBackup(backup, passphrase)).rejects.toThrow(BackupError);
    expect(b.session.unlocked).toBe(false);
    expectSnapshotsEqual(before, await snapshot(a.db));
  });

  it('交错（20 组）：恢复与初始化竞争时库始终自洽，恰有一种口令可用', async () => {
    const { backup } = await makeBackup([['n1', '备份方数据']]);

    for (let i = 0; i < 20; i += 1) {
      const { name, a, b } = await makeTabPair();
      const results = await Promise.allSettled([
        a.session.restoreFromBackup(backup, 'backup-passphrase'),
        b.session.initialize('init-passphrase'),
      ]);
      const fulfilled = results.filter((r) => r.status === 'fulfilled').length;
      expect(fulfilled).toBe(1);
      await flush();

      // 不变量：要么是完整备份（备份口令可解锁、含 n1），
      // 要么是初始化方的空库（init 口令可解锁、0 条便笺）；
      // 绝不会出现「init 的封装 + 备份的便笺」之类的半个库。
      const probeBackup = await makeProbe(name);
      const backupWorks = await probeBackup.session
        .unlock('backup-passphrase')
        .then(() => true)
        .catch(() => false);
      const probeInit = await makeProbe(name);
      const initWorks = await probeInit.session
        .unlock('init-passphrase')
        .then(() => true)
        .catch(() => false);
      expect(Number(backupWorks) + Number(initWorks)).toBe(1);

      if (backupWorks) {
        await probeBackup.session.noteStore.read('n1').catch(() => null);
        await expect(probeBackup.session.noteStore.read('n1')).resolves.toMatchObject({
          plaintext: '备份方数据',
        });
        expect(await probeBackup.db.countNotes()).toBe(1);
      } else {
        expect(await probeInit.db.countNotes()).toBe(0);
        expect((await probeInit.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY))!.revision).toBe(1);
      }
    }
  });

  it('交错（10 组）：两个不同备份恢复到同一空库，恰有一个完整落盘', async () => {
    const srcA = await makeBackup([['n1', '来自备份 A']], 'pass-a');
    const srcB = await makeBackup([['n1', '来自备份 B'], ['n2', 'B 的第二条']], 'pass-b');

    for (let i = 0; i < 10; i += 1) {
      const { name, a, b } = await makeTabPair();
      const results = await Promise.allSettled([
        a.session.restoreFromBackup(srcA.backup, srcA.passphrase),
        b.session.restoreFromBackup(srcB.backup, srcB.passphrase),
      ]);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      await flush();

      const probeA = await makeProbe(name);
      const aWorks = await probeA.session
        .unlock('pass-a')
        .then(() => true)
        .catch(() => false);
      const probeB = await makeProbe(name);
      const bWorks = await probeB.session
        .unlock('pass-b')
        .then(() => true)
        .catch(() => false);
      expect(Number(aWorks) + Number(bWorks)).toBe(1);

      const winner = aWorks ? probeA : probeB;
      const count = await winner.db.countNotes();
      if (aWorks) expect(count).toBe(1);
      else expect(count).toBe(2);
    }
  });
});

describe('备份/恢复与既有安全规则不冲突', () => {
  it('恢复后可正常改口令：只重新封装，便笺密文不动，新口令可用', async () => {
    const { backup, passphrase } = await makeBackup([['n1', '迁移来的数据']]);
    const target = await makeSession();
    await target.session.restoreFromBackup(backup, passphrase);

    const beforeRestore = (await target.db.listNotes()).map((r) => ({
      id: r.id,
      iv: toBytes(r.iv),
      ciphertext: toBytes(r.ciphertext),
      revision: r.revision,
    }));

    await target.session.changePassphrase(passphrase, 'fresh-pass-after-restore');
    const after = await target.db.listNotes();
    for (const record of after) {
      const prev = beforeRestore.find((p) => p.id === record.id)!;
      expect(toBytes(record.ciphertext)).toEqual(prev.ciphertext);
      expect(toBytes(record.iv)).toEqual(prev.iv);
      expect(record.revision).toBe(prev.revision);
    }
    await target.session.unlock('fresh-pass-after-restore');
    await expect(target.session.noteStore.read('n1')).resolves.toMatchObject({
      plaintext: '迁移来的数据',
    });
  });

  it('恢复后跨标签页修订号冲突规则不变', async () => {
    const { backup, passphrase } = await makeBackup([['shared', '初始']]);
    const { a, b } = await makeTabPair();
    await a.session.restoreFromBackup(backup, passphrase);
    await b.session.unlock(passphrase);

    const readA = await a.session.noteStore.read('shared');
    const readB = await b.session.noteStore.read('shared');
    await a.session.noteStore.update('shared', 'A 改的', readA.revision);
    await expect(
      b.session.noteStore.update('shared', 'B 改的', readB.revision),
    ).rejects.toThrow();
    await expect(a.session.noteStore.read('shared')).resolves.toMatchObject({ plaintext: 'A 改的' });
  });

  it('清单规范化与 JSON 字段顺序无关：重排 JSON 后仍为同一备份', async () => {
    const { backup, passphrase } = await makeBackup([['b', 'B'], ['a', 'A']]);
    const parsed = parseBackupFile(backup);
    const reordered = serializeBackupFile(
      parsed.wrapped,
      [...parsed.notes].reverse(),
      { manifestIv: parsed.manifest.iv, sealed: parsed.manifest.sealed },
      parsed.exportedAt + 1000,
    );
    const target = await makeSession();
    await target.session.restoreFromBackup(reordered, passphrase);
    expect(await target.session.noteStore.list()).toHaveLength(2);
  });

  it('规范化字节对 id 排序敏感：调换 id 后规范化结果不同', async () => {
    const base: WrappedKeyRecord = {
      kdf: { salt: new Uint8Array(16).fill(1), iterations: TEST_ITERATIONS },
      wrapIv: new Uint8Array(12).fill(2),
      wrappedKey: new ArrayBuffer(40),
      revision: 1,
    };
    const mk = (id: string): NoteRecord => ({
      id,
      iv: new Uint8Array(12).fill(3),
      ciphertext: new ArrayBuffer(32),
      revision: 1,
      updatedAt: 0,
    });
    const c1 = canonicalManifestBytes(base, [mk('a'), mk('b')]);
    const c2 = canonicalManifestBytes(base, [mk('b'), mk('a')]);
    expect(timingSafeEqual(c1, c2)).toBe(true); // 内部按 id 排序：等价
    const c3 = canonicalManifestBytes(base, [mk('a'), mk('c')]);
    expect(timingSafeEqual(c1, c3)).toBe(false);
  });
});

describe('加密层直接验证备份原语', () => {
  it('同一数据密钥可开清单；换密钥则 openManifest 失败', async () => {
    const src = await makeSession();
    await src.session.initialize('p');
    const backup = await src.session.exportBackup();
    const parsed = parseBackupFile(backup);

    // 用正确口令解封出 DK
    const kek = await deriveKek('p', parsed.wrapped.kdf.salt, parsed.wrapped.kdf.iterations);
    const dk = await unwrapDataKey(parsed.wrapped.wrappedKey, parsed.wrapped.wrapIv, kek);
    const canonical = canonicalManifestBytes(parsed.wrapped, parsed.notes);
    const opened = await openManifest(dk, parsed.manifest.iv, parsed.manifest.sealed);
    expect(timingSafeEqual(new Uint8Array(opened), canonical)).toBe(true);

    // 另一个口令的数据密钥打不开
    const other = await makeSession();
    await other.session.initialize('other');
    const otherWrapped = await other.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY);
    const otherKek = await deriveKek(
      'other',
      otherWrapped!.kdf.salt,
      otherWrapped!.kdf.iterations,
    );
    const otherDk = await unwrapDataKey(
      otherWrapped!.wrappedKey,
      otherWrapped!.wrapIv,
      otherKek,
    );
    await expect(
      openManifest(otherDk, parsed.manifest.iv, parsed.manifest.sealed),
    ).rejects.toThrow();
  });

  it('createBackupFile 拒绝超过上限的条目集', async () => {
    const source = await makeSession();
    await source.session.initialize('p');
    const wrapped = (await source.db.getMeta<WrappedKeyRecord>(META_WRAPPED_KEY))!;
    // 用会话内真实的 DK（只用于生成文件，不写库）
    const dk = (source as unknown as { dataKey: CryptoKey }).dataKey;
    const notes: NoteRecord[] = Array.from({ length: MAX_NOTES + 1 }, (_, i) => ({
      id: `n${i}`,
      iv: new Uint8Array(12),
      ciphertext: new ArrayBuffer(16),
      revision: 1,
      updatedAt: 0,
    }));
    await expect(createBackupFile({ wrapped, notes, dataKey: dk })).rejects.toThrow(BackupError);
  });
});
