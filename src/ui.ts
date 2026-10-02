import {
  AuthError,
  BackupError,
  CapacityError,
  ConflictError,
  IntegrityError,
  LockedError,
} from './errors';
import type { Session } from './session';
import { MAX_NOTES } from './store';

type ElProps = Record<string, string | boolean | ((ev: Event) => void)>;

function h(tag: string, props: ElProps = {}, ...children: (Node | string)[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === 'function') el.addEventListener(key, value);
    else if (typeof value === 'boolean') {
      if (value) el.setAttribute(key, '');
    } else el.setAttribute(key, value);
  }
  el.append(...children);
  return el;
}

function titleOf(plaintext: string): string {
  const firstLine = plaintext.split('\n', 1)[0]?.trim() ?? '';
  if (firstLine === '') return '（空白便笺）';
  return firstLine.length > 24 ? `${firstLine.slice(0, 24)}…` : firstLine;
}

/**
 * 纯 DOM 界面。所有明文只存在于内存与 DOM 中；
 * 锁定（含其它标签页广播）时立即整体销毁并回到解锁页。
 */
export class WorkbenchUI {
  private currentId: string | null = null;
  private currentRevision = 0;
  /** 列表标题缓存（明文派生物，仅内存，锁定即清） */
  private titles = new Map<string, string>();
  /** 带到下一个锁定页的提示（如改口令成功），显示后即清 */
  private lockedNotice = '';

  constructor(
    private readonly root: HTMLElement,
    private readonly session: Session,
  ) {}

  async start(): Promise<void> {
    this.session.onWipe = () => {
      this.currentId = null;
      this.currentRevision = 0;
      this.titles.clear();
      void this.renderLocked();
    };
    await this.renderLocked();
  }

  // ---------- 锁定页 ----------

  private async renderLocked(): Promise<void> {
    this.root.replaceChildren();
    const initialized = await this.session.isInitialized();
    const message = h('p', { class: 'msg', role: 'alert' });
    if (this.lockedNotice !== '') {
      message.textContent = this.lockedNotice;
      this.lockedNotice = '';
    }

    const showError = (err: unknown) => {
      message.textContent = err instanceof Error ? err.message : String(err);
    };

    let form: HTMLElement;
    // 空库恢复面板：仅在未初始化（库为空）的锁定页出现
    let restorePanel: HTMLElement | null = null;
    if (initialized) {
      const input = h('input', {
        type: 'password',
        placeholder: '口令',
        autocomplete: 'current-password',
      }) as HTMLInputElement;
      form = h(
        'form',
        {
          submit: async (ev) => {
            ev.preventDefault();
            message.textContent = '';
            try {
              await this.session.unlock(input.value);
              input.value = '';
              await this.renderMain();
            } catch (err) {
              input.value = '';
              input.focus();
              if (err instanceof LockedError) {
                showError('解锁期间工作台已被锁定，请重新输入口令');
              } else {
                showError(err instanceof AuthError ? '口令错误，请重试' : err);
              }
            }
          },
        },
        h('h1', {}, '解锁工作台'),
        input,
        h('button', { type: 'submit' }, '解锁'),
        message,
      );
    } else {
      const pass = h('input', {
        type: 'password',
        placeholder: '设置口令（至少 8 位）',
        autocomplete: 'new-password',
      }) as HTMLInputElement;
      const confirm = h('input', {
        type: 'password',
        placeholder: '再次输入口令',
        autocomplete: 'new-password',
      }) as HTMLInputElement;
      form = h(
        'form',
        {
          submit: async (ev) => {
            ev.preventDefault();
            message.textContent = '';
            if (pass.value.length < 8) {
              message.textContent = '口令至少需要 8 个字符';
              return;
            }
            if (pass.value !== confirm.value) {
              message.textContent = '两次输入的口令不一致';
              return;
            }
            try {
              await this.session.initialize(pass.value);
              pass.value = '';
              confirm.value = '';
              await this.renderMain();
            } catch (err) {
              showError(err);
            }
          },
        },
        h('h1', {}, '创建加密工作台'),
        h('p', { class: 'hint' }, '数据只保存在本浏览器（IndexedDB），全部经 AES-GCM 加密。'),
        pass,
        confirm,
        h('button', { type: 'submit' }, '创建'),
        message,
      );

      // 「加密备份与空库恢复」：只有空库才允许恢复，
      // 成功后进入主界面；任何校验失败都不写入、不显示明文。
      const restoreFile = h('input', {
        type: 'file',
        accept: '.json,application/json',
      }) as HTMLInputElement;
      const restorePass = h('input', {
        type: 'password',
        placeholder: '备份的口令',
        autocomplete: 'current-password',
      }) as HTMLInputElement;
      const restoreMessage = h('p', { class: 'msg', role: 'alert' });
      const restoreBtn = h('button', { type: 'submit' }, '从备份恢复') as HTMLButtonElement;
      restorePanel = h(
        'form',
        {
          class: 'restore-panel',
          submit: async (ev) => {
            ev.preventDefault();
            restoreMessage.textContent = '';
            const file = restoreFile.files?.[0];
            if (file === undefined) {
              restoreMessage.textContent = '请先选择备份文件';
              return;
            }
            restoreBtn.disabled = true;
            try {
              const text = await file.text();
              await this.session.restoreFromBackup(text, restorePass.value);
              restorePass.value = '';
              restoreFile.value = '';
              await this.renderMain();
            } catch (err) {
              restorePass.value = '';
              restoreBtn.disabled = false;
              restoreMessage.textContent =
                err instanceof AuthError
                  ? '口令错误，或备份已损坏，恢复未执行；空库保持原样'
                  : err instanceof BackupError
                    ? err.message
                    : `恢复失败：${err instanceof Error ? err.message : String(err)}`;
            }
          },
        },
        h('h2', {}, '从加密备份恢复'),
        h(
          'p',
          { class: 'hint' },
          '仅在当前工作台为空时可用；恢复会逐条校验全部密文，任何失败都不会写入数据。',
        ),
        restoreFile,
        restorePass,
        restoreBtn,
        restoreMessage,
      );
    }
    const lockedMain = h('main', { class: 'locked' }, form);
    if (restorePanel !== null) lockedMain.append(restorePanel);
    this.root.append(lockedMain);
  }

  // ---------- 主界面 ----------

  private async renderMain(): Promise<void> {
    this.root.replaceChildren();
    this.currentId = null;

    const listEl = h('ul', { class: 'note-list' });
    const countEl = h('span', { class: 'count' });
    const editorStatus = h('p', { class: 'msg', role: 'alert' });
    const banner = h('div', { class: 'banner', hidden: true });
    const textarea = h('textarea', {
      placeholder: '在此输入便笺内容…',
      disabled: true,
    }) as HTMLTextAreaElement;
    const saveBtn = h('button', { type: 'button', disabled: true }, '保存') as HTMLButtonElement;
    const deleteBtn = h('button', { type: 'button', disabled: true }, '删除') as HTMLButtonElement;
    const newBtn = h('button', { type: 'button' }, '新建便笺') as HTMLButtonElement;
    const exportStatus = h('span', { class: 'export-status' });
    const exportBtn = h('button', { type: 'button' }, '导出加密备份') as HTMLButtonElement;

    exportBtn.addEventListener('click', () => {
      exportStatus.textContent = '';
      // 异步导出：锁定/失败时不产生下载，不泄露任何明文
      void (async () => {
        try {
          const backup = await this.session.exportBackup();
          const blob = new Blob([backup], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const stamp = new Date().toISOString().replaceAll(':', '-');
          const a = h('a', { href: url, download: `secure-notes-backup-${stamp}.json` });
          a.style.display = 'none';
          document.body.append(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
          exportStatus.textContent = '备份已导出';
        } catch (err) {
          exportStatus.textContent = `导出失败：${err instanceof Error ? err.message : String(err)}`;
        }
      })();
    });

    const store = this.session.noteStore;

    const setBanner = (text: string, onReload?: () => void) => {
      banner.replaceChildren();
      if (text === '') {
        banner.setAttribute('hidden', '');
        return;
      }
      banner.removeAttribute('hidden');
      banner.append(h('span', {}, text));
      if (onReload) {
        banner.append(
          h('button', { type: 'button', click: () => onReload() }, '重新载入'),
        );
      }
    };

    const refreshList = async () => {
      const metas = await store.list();
      countEl.textContent = `${metas.length} / ${MAX_NOTES}`;
      newBtn.disabled = metas.length >= MAX_NOTES;
      listEl.replaceChildren();
      for (const meta of metas) {
        if (!this.titles.has(meta.id)) {
          try {
            const { plaintext } = await store.read(meta.id);
            this.titles.set(meta.id, titleOf(plaintext));
          } catch (err) {
            this.titles.set(
              meta.id,
              err instanceof IntegrityError ? '⚠ 密文损坏，无法解密' : '⚠ 读取失败',
            );
          }
        }
        const item = h(
          'li',
          {
            class: meta.id === this.currentId ? 'active' : '',
            click: () => void openNote(meta.id),
          },
          this.titles.get(meta.id) ?? meta.id,
        );
        listEl.append(item);
      }
    };

    const openNote = async (id: string) => {
      editorStatus.textContent = '';
      setBanner('');
      try {
        const { plaintext, revision } = await store.read(id);
        this.currentId = id;
        this.currentRevision = revision;
        textarea.value = plaintext;
        textarea.disabled = false;
        saveBtn.disabled = false;
        deleteBtn.disabled = false;
        textarea.focus();
      } catch (err) {
        this.currentId = null;
        textarea.value = '';
        textarea.disabled = true;
        saveBtn.disabled = true;
        deleteBtn.disabled = true;
        editorStatus.textContent =
          err instanceof IntegrityError
            ? err.message
            : `读取失败：${err instanceof Error ? err.message : String(err)}`;
      }
      await refreshList();
    };

    newBtn.addEventListener('click', async () => {
      editorStatus.textContent = '';
      try {
        const id = globalThis.crypto.randomUUID();
        await store.create(id, '');
        this.titles.set(id, titleOf(''));
        await openNote(id);
      } catch (err) {
        editorStatus.textContent =
          err instanceof CapacityError
            ? err.message
            : `新建失败：${err instanceof Error ? err.message : String(err)}`;
        await refreshList();
      }
    });

    saveBtn.addEventListener('click', async () => {
      if (this.currentId === null) return;
      editorStatus.textContent = '';
      const id = this.currentId;
      try {
        const meta = await store.update(id, textarea.value, this.currentRevision);
        this.currentRevision = meta.revision;
        this.titles.set(id, titleOf(textarea.value));
        editorStatus.textContent = '已保存';
        await refreshList();
      } catch (err) {
        if (err instanceof ConflictError) {
          setBanner('该便笺已在其它标签页被修改，当前内容未保存。', () => void openNote(id));
        } else {
          editorStatus.textContent = `保存失败：${err instanceof Error ? err.message : String(err)}`;
        }
      }
    });

    deleteBtn.addEventListener('click', async () => {
      if (this.currentId === null) return;
      const id = this.currentId;
      try {
        await store.remove(id);
        this.titles.delete(id);
        this.currentId = null;
        textarea.value = '';
        textarea.disabled = true;
        saveBtn.disabled = true;
        deleteBtn.disabled = true;
        await refreshList();
      } catch (err) {
        editorStatus.textContent = `删除失败：${err instanceof Error ? err.message : String(err)}`;
      }
    });

    // 修改口令面板
    const pwMessage = h('p', { class: 'msg', role: 'alert' });
    const pwCurrent = h('input', { type: 'password', placeholder: '当前口令' }) as HTMLInputElement;
    const pwNext = h('input', { type: 'password', placeholder: '新口令（至少 8 位）' }) as HTMLInputElement;
    const pwConfirm = h('input', { type: 'password', placeholder: '确认新口令' }) as HTMLInputElement;
    const pwPanel = h(
      'form',
      {
        class: 'pw-panel',
        hidden: true,
        submit: async (ev) => {
          ev.preventDefault();
          pwMessage.textContent = '';
          if (pwNext.value.length < 8) {
            pwMessage.textContent = '新口令至少需要 8 个字符';
            return;
          }
          if (pwNext.value !== pwConfirm.value) {
            pwMessage.textContent = '两次输入的新口令不一致';
            return;
          }
          // 成功后会话会立即锁定并重渲染锁定页，先把提示放好
          this.lockedNotice = '口令已更新，请用新口令解锁；其它标签页也已锁定';
          try {
            await this.session.changePassphrase(pwCurrent.value, pwNext.value);
          } catch (err) {
            this.lockedNotice = '';
            pwMessage.textContent =
              err instanceof ConflictError
                ? '口令已在其它标签页被修改，本次修改未生效，请用当前口令重新解锁后再试'
                : err instanceof Error
                  ? err.message
                  : String(err);
          }
          pwCurrent.value = '';
          pwNext.value = '';
          pwConfirm.value = '';
        },
      },
      pwCurrent,
      pwNext,
      pwConfirm,
      h('button', { type: 'submit' }, '确认修改'),
      pwMessage,
    );

    const lockBtn = h(
      'button',
      {
        type: 'button',
        click: () => {
          // 立即撤去明文：清空编辑器与缓存，再由 onWipe 回到锁定页
          textarea.value = '';
          this.session.lock();
        },
      },
      '锁定',
    );

    const togglePwBtn = h(
      'button',
      {
        type: 'button',
        click: () => {
          if (pwPanel.hasAttribute('hidden')) pwPanel.removeAttribute('hidden');
          else pwPanel.setAttribute('hidden', '');
        },
      },
      '修改口令',
    );

    this.root.append(
      h(
        'main',
        { class: 'workbench' },
        h(
          'header',
          {},
          h('strong', {}, '加密便笺'),
          countEl,
          h('span', { class: 'spacer' }),
          newBtn,
          exportBtn,
          exportStatus,
          togglePwBtn,
          lockBtn,
        ),
        pwPanel,
        banner,
        h(
          'div',
          { class: 'body' },
          h('aside', {}, listEl),
          h(
            'section',
            { class: 'editor' },
            textarea,
            h('div', { class: 'editor-bar' }, saveBtn, deleteBtn, editorStatus),
          ),
        ),
      ),
    );

    await refreshList();
  }
}
