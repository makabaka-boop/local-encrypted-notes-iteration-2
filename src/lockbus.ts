/**
 * 跨标签页事件总线：
 * - lock：任一标签页锁定，所有标签页立即撤去明文；
 * - passphrase-changed：某标签页改了口令，其余标签页持有的旧口令已失效，
 *   必须立即回到锁定页（事件不回送发送者本人，BroadcastChannel 语义即如此）。
 */
export interface LockBus {
  broadcastLock(): void;
  onLock(handler: () => void): void;
  /** 广播「口令已被其它标签页更换」，不回送发送者 */
  broadcastPassphraseChanged(): void;
  onPassphraseChanged(handler: () => void): void;
  close(): void;
}

type BusEventType = 'lock' | 'passphrase-changed';
interface BusMessage {
  sender: string;
  type: BusEventType;
}
type BusHandler = (message: BusMessage) => void;

export const BROKER_CHANNEL = 'secure-notes-workbench-lock';

/**
 * 进程内广播代理：按频道名分组，模拟 BroadcastChannel——
 * 消息异步投递（microtask）且不回送发送者，供测试模拟多个标签页。
 */
class LocalBroker {
  private static channels = new Map<string, Map<string, BusHandler>>();

  static connect(channel: string, sender: string, handler: BusHandler): () => void {
    let members = this.channels.get(channel);
    if (members === undefined) {
      members = new Map();
      this.channels.set(channel, members);
    }
    members.set(sender, handler);
    return () => {
      this.channels.get(channel)?.delete(sender);
    };
  }

  static post(channel: string, message: BusMessage): void {
    for (const [sender, handler] of this.channels.get(channel) ?? []) {
      if (sender === message.sender) continue; // 不回送发送者
      const member = handler;
      queueMicrotask(() => member(message));
    }
  }
}

export class BroadcastLockBus implements LockBus {
  private readonly channel: BroadcastChannel;

  constructor(channelName = BROKER_CHANNEL) {
    this.channel = new BroadcastChannel(channelName);
  }

  broadcastLock(): void {
    this.channel.postMessage({ type: 'lock' });
  }

  onLock(handler: () => void): void {
    this.channel.addEventListener('message', (event: MessageEvent) => {
      if ((event.data as { type?: string } | null)?.type === 'lock') handler();
    });
  }

  broadcastPassphraseChanged(): void {
    this.channel.postMessage({ type: 'passphrase-changed' });
  }

  onPassphraseChanged(handler: () => void): void {
    this.channel.addEventListener('message', (event: MessageEvent) => {
      if ((event.data as { type?: string } | null)?.type === 'passphrase-changed') {
        handler();
      }
    });
  }

  close(): void {
    this.channel.close();
  }
}

/** 进程内总线：同名频道的实例互为「其它标签页」，语义对齐 BroadcastChannel */
export class LocalLockBus implements LockBus {
  private readonly sender = `sender-${Math.random().toString(36).slice(2)}-${Date.now()}`;
  private lockHandler: (() => void) | null = null;
  private passphraseHandler: (() => void) | null = null;
  private readonly disconnect: () => void;

  constructor(private readonly channelName: string = BROKER_CHANNEL) {
    this.disconnect = LocalBroker.connect(channelName, this.sender, (message) => {
      if (message.type === 'lock') this.lockHandler?.();
      else if (message.type === 'passphrase-changed') this.passphraseHandler?.();
    });
  }

  broadcastLock(): void {
    LocalBroker.post(this.channelName, { sender: this.sender, type: 'lock' });
  }

  broadcastPassphraseChanged(): void {
    LocalBroker.post(this.channelName, { sender: this.sender, type: 'passphrase-changed' });
  }

  onLock(handler: () => void): void {
    this.lockHandler = handler;
  }

  onPassphraseChanged(handler: () => void): void {
    this.passphraseHandler = handler;
  }

  close(): void {
    this.disconnect();
  }
}
