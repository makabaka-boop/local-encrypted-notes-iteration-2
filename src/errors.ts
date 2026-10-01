/** 口令错误或无法解封数据密钥 */
export class AuthError extends Error {
  constructor(message = '口令错误') {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * 异步操作跨越 await 期间会话被锁定：操作结果作废。
 * 仍是 AuthError（锁定本质就是认证态失效），调用方可据此区别于口令错误。
 */
export class LockedError extends AuthError {
  constructor(message = '工作台已锁定') {
    super(message);
    this.name = 'LockedError';
  }
}

/** 修订号冲突：其它标签页已先行写入 */
export class ConflictError extends Error {
  constructor(message = '该便笺已被其它标签页修改，请重新载入') {
    super(message);
    this.name = 'ConflictError';
  }
}

/** 便笺数量达到上限 */
export class CapacityError extends Error {
  constructor(message = '便笺数量已达上限（100 条）') {
    super(message);
    this.name = 'CapacityError';
  }
}

/** 密文完整性校验失败（被篡改或密钥不符） */
export class IntegrityError extends Error {
  constructor(message = '密文校验失败，数据可能被篡改') {
    super(message);
    this.name = 'IntegrityError';
  }
}

/** 便笺不存在 */
export class NotFoundError extends Error {
  constructor(id: string) {
    super(`便笺不存在：${id}`);
    this.name = 'NotFoundError';
  }
}
