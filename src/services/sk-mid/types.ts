export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

export enum StartAuthenticationErrorCodes {
  MissingRequiredParam = 'MissingRequiredParam',
  MismatchedHashLength = 'MismatchedHashLength',
  HashNotBase64 = 'HashNotBase64',
  FaildToAuthorizeUser = 'FaildToAuthorizeUser',
  MethodNotAllowed = 'MethodNotAllowed',
  InternalServerError = 'InternalServerError',
  UnknownError = 'UnknownError',
}

export enum GetAuthenticationStatusErrorCodes {
  RequiredSessionIdMissing = 'RequiredSessionIdMissing',
  FailedToAuthorizeUser = 'FailedToAuthorizeUser',
  SessionIdNotFound = 'SessionIdNotFound',
  MethodNotAllowed = 'MethodNotAllowed',
  InternalServerError = 'InternalServerError',
  UnknownError = 'UnknownError',
}

export enum AuthenticationStates {
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
}

export enum AuthenticationResultCodes {
  OK = 'OK',
  TIMEOUT = 'TIMEOUT',
  NOT_MID_CLIENT = 'NOT_MID_CLIENT',
  USER_CANCELLED = 'USER_CANCELLED',
  SIGNATURE_HASH_MISMATCH = 'SIGNATURE_HASH_MISMATCH',
  PHONE_ABSENT = 'PHONE_ABSENT',
  DELIVERY_ERROR = 'DELIVERY_ERROR',
  SIM_ERROR = 'SIM_ERROR',
}

export enum SignatureAlgorithm {
  SHA256WithECEncryption = 'SHA256WithECEncryption',
  SHA256WithRSAEncryption = 'SHA256WithRSAEncryption',
  SHA384WithECEncryption = 'SHA384WithECEncryption',
  SHA384WithRSAEncryption = 'SHA384WithRSAEncryption',
  SHA512WithECEncryption = 'SHA512WithECEncryption',
  SHA512WithRSAEncryption = 'SHA512WithRSAEncryption',
}
