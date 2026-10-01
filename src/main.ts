import { NotesDB } from './db';
import { BroadcastLockBus } from './lockbus';
import { Session } from './session';
import { WorkbenchUI } from './ui';

async function main(): Promise<void> {
  const root = document.getElementById('app');
  if (root === null) throw new Error('找不到 #app 挂载点');

  const db = await NotesDB.open();
  const bus = new BroadcastLockBus();
  const session = new Session(db, bus);
  const ui = new WorkbenchUI(root, session);
  await ui.start();
}

main().catch((err: unknown) => {
  const root = document.getElementById('app');
  if (root !== null) {
    root.textContent = `初始化失败：${err instanceof Error ? err.message : String(err)}`;
  }
});
