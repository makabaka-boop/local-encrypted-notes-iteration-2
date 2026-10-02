import { NotesDB } from '../src/db';
import { BROKER_CHANNEL, LocalLockBus } from '../src/lockbus';
import { Session } from '../src/session';

/** 测试用低迭代次数，保持 PBKDF2 代码路径不变但跑得动 */
export const TEST_ITERATIONS = 1_000;

let seq = 0;

export async function makeSession(dbName?: string) {
  const db = await NotesDB.open(dbName ?? `test-db-${++seq}`);
  const bus = new LocalLockBus();
  const session = new Session(db, bus, { iterations: TEST_ITERATIONS });
  return { db, bus, session };
}

/**
 * 模拟两个标签页：两条 IndexedDB 连接指向同一个库，
 * 且两个 LocalLockBus 挂在同名频道上（可互收广播）。
 */
export async function makeTabPair() {
  const name = `test-db-tabs-${++seq}`;
  const a = await makeSessionWithBus(name, new LocalLockBus(`${BROKER_CHANNEL}-${name}`));
  const b = await makeSessionWithBus(name, new LocalLockBus(`${BROKER_CHANNEL}-${name}`));
  return { name, a, b };
}

async function makeSessionWithBus(name: string, bus: LocalLockBus) {
  const db = await NotesDB.open(name);
  const session = new Session(db, bus, { iterations: TEST_ITERATIONS });
  return { db, bus, session };
}

/** 在已存在的库上再开一个独立会话（不挂广播总线，用于探测口令） */
export async function makeProbe(dbName: string) {
  const db = await NotesDB.open(dbName);
  const bus = new LocalLockBus(`probe-${dbName}-${Math.random()}`);
  const session = new Session(db, bus, { iterations: TEST_ITERATIONS });
  return { db, bus, session };
}

/** 读取 Uint8Array/ArrayBuffer 的便捷断言辅助 */
export function toBytes(buf: ArrayBuffer | Uint8Array): Uint8Array {
  return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
}

/**
 * 构造一份带若干便笺的源库，并导出其加密备份文本。
 * 供备份恢复相关测试使用。
 */
export async function makeBackup(
  entries: ReadonlyArray<readonly [id: string, plaintext: string]>,
  passphrase = 'backup-passphrase',
) {
  const source = await makeSession();
  await source.session.initialize(passphrase);
  for (const [id, plaintext] of entries) {
    await source.session.noteStore.create(id, plaintext);
  }
  const text = await source.session.exportBackup();
  return { ...source, backup: text, passphrase };
}
