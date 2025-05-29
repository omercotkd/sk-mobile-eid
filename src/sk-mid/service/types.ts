export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

export enum StartAuthenticationErrors {
  MissingRequiredParam = 'MissingRequiredParam',
  MismatchedHashLength = 'MismatchedHashLength',
  HashNotBase64 = 'HashNotBase64',
  FaildToAuthorizeUser = 'FaildToAuthorizeUser',
  MethodNotAllowed = 'MethodNotAllowed',
  InternalServerError = 'InternalServerError',
  UnknownError = 'UnknownError',
}

export enum GetAuthenticationStatusErrors {
  RequiredSessionIdMissing = 'RequiredSessionIdMissing',
  FailedToAuthorizeUser = 'FailedToAuthorizeUser',
  SessionIdNotFound = 'SessionIdNotFound',
  MethodNotAllowed = 'MethodNotAllowed',
  InternalServerError = 'InternalServerError',
  UnknownError = 'UnknownError',
}
