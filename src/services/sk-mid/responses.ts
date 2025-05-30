import {
  StartAuthenticationErrorCodes,
  GetAuthenticationStatusErrorCodes,
  SignatureAlgorithm,
  AuthenticationResultCodes,
  AuthenticationStates,
} from './types';
import { AxiosError } from 'axios';

export class StartAuthenticationSuccess {
  public readonly sessionID: string;
  constructor({ sessionID }: { sessionID: string }) {
    this.sessionID = sessionID;
  }
}

export class StartAuthenticationError {
  public readonly time: Date;
  public readonly traceId: string;
  /**
   * Error message returned by the TSP service.
   */
  public readonly error: string;
  public readonly erroType: StartAuthenticationErrorCodes;

  public axiosError: AxiosError<any>;

  private constructor({
    error,
    time,
    traceId,
    errorType,
    axiosError,
  }: {
    error: string;
    time: string;
    traceId: string;
    errorType: StartAuthenticationErrorCodes;
    axiosError: AxiosError<any>;
  }) {
    this.error = error;
    this.time = new Date(time);
    this.traceId = traceId;
    this.erroType = errorType;
    this.axiosError = axiosError;
  }

  /**
   * Maps an AxiosError to a StartAuthenticationError.
   * According to the docs:
   * https://github.com/SK-EID/MID?tab=readme-ov-file#326-error-conditions
   */
  public static fromAxiosError(
    axiosError: AxiosError<any>,
  ): StartAuthenticationError {
    const response = axiosError.response;
    if (response && response.data && typeof response.data.error === 'string') {
      const { error } = response.data;
      switch (axiosError.status) {
        case 400:
          if (error.includes('Base64')) {
            return new StartAuthenticationError({
              ...response.data,
              errorType: StartAuthenticationErrorCodes.HashNotBase64,
              axiosError,
            });
          } else if (error.includes('length')) {
            return new StartAuthenticationError({
              ...response.data,
              errorType: StartAuthenticationErrorCodes.MismatchedHashLength,
              axiosError,
            });
            // The missing required param error message is always different for each field
            // so this is the last option in the if-else chain
          } else {
            return new StartAuthenticationError({
              ...response.data,
              errorType: StartAuthenticationErrorCodes.MissingRequiredParam,
              axiosError,
            });
          }
        case 401:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrorCodes.FaildToAuthorizeUser,
            axiosError,
          });
        case 405:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrorCodes.MethodNotAllowed,
            axiosError,
          });
        case 500:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrorCodes.InternalServerError,
            axiosError,
          });
        default:
          return new StartAuthenticationError({
            error: 'Unknown error',
            time: new Date().toISOString(),
            traceId: 'unknown',
            errorType: StartAuthenticationErrorCodes.UnknownError,
            axiosError,
          });
      }
    }
    return new StartAuthenticationError({
      error: 'Unknown error',
      time: new Date().toISOString(),
      traceId: 'unknown',
      errorType: StartAuthenticationErrorCodes.UnknownError,
      axiosError,
    });
  }
}

/**
 * https://github.com/SK-EID/MID?tab=readme-ov-file#335-response-structure
 */
export class GetAuthenticationStatusSuccess {
  public readonly state: AuthenticationStates;
  public readonly time: Date;
  public readonly traceId: string;
  public readonly result?: AuthenticationResultCodes;
  public readonly signature?: {
    value: string;
    algorithm: SignatureAlgorithm;
  };
  public readonly cert?: string;

  constructor(data: any) {
    this.state = data.state;
    this.time = new Date(data.time);
    this.traceId = data.traceId;
    this.result = data.result;
    this.signature = data.signature;
    this.cert = data.cert;
  }

  /**
   * Helper to check if the authentication is still running.
   */
  isRunning(): boolean {
    return this.state === AuthenticationStates.RUNNING;
  }

  /**
   * Helper to check if the authentication is complete and successful.
   */
  isSuccess(): boolean {
    return (
      this.state === AuthenticationStates.COMPLETED &&
      this.result === AuthenticationResultCodes.OK
    );
  }

  /**
   * Helper to check if the authentication is complete but failed/cancelled.
   */
  isFailure(): boolean {
    return (
      this.state === AuthenticationStates.COMPLETED &&
      this.result !== AuthenticationResultCodes.OK
    );
  }
}

export class GetAuthenticationStatusError {
  public readonly time: Date;
  public readonly traceId: string;
  /**
   * Error message returned by the TSP service.
   */
  public readonly error: string;
  public readonly erroType: GetAuthenticationStatusErrorCodes;

  public axiosError: AxiosError<any>;

  private constructor({
    error,
    time,
    traceId,
    errorType,
    axiosError,
  }: {
    error: string;
    time: string;
    traceId: string;
    errorType: GetAuthenticationStatusErrorCodes;
    axiosError: AxiosError<any>;
  }) {
    this.error = error;
    this.time = new Date(time);
    this.traceId = traceId;
    this.erroType = errorType;
    this.axiosError = axiosError;
  }

  /**
   * Maps an AxiosError to a StartAuthenticationError.
   * According to the docs:
   * https://github.com/SK-EID/MID?tab=readme-ov-file#339-http-error-codes
   */
  public static fromAxiosError(
    axiosError: AxiosError<any>,
  ): GetAuthenticationStatusError {
    const response = axiosError.response;
    if (response && response.data && typeof response.data.error === 'string') {
      switch (axiosError.status) {
        case 400:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType:
              GetAuthenticationStatusErrorCodes.RequiredSessionIdMissing,
            axiosError,
          });
        case 401:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrorCodes.FailedToAuthorizeUser,
            axiosError,
          });
        case 404:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrorCodes.SessionIdNotFound,
            axiosError,
          });
        case 405:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrorCodes.MethodNotAllowed,
            axiosError,
          });
        case 500:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrorCodes.InternalServerError,
            axiosError,
          });
        default:
          return new GetAuthenticationStatusError({
            error: 'Unknown error',
            time: new Date().toISOString(),
            traceId: 'unknown',
            errorType: GetAuthenticationStatusErrorCodes.UnknownError,
            axiosError,
          });
      }
    }
    return new GetAuthenticationStatusError({
      error: 'Unknown error',
      time: new Date().toISOString(),
      traceId: 'unknown',
      errorType: GetAuthenticationStatusErrorCodes.UnknownError,
      axiosError,
    });
  }
}
