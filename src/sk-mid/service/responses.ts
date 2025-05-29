import {
  StartAuthenticationErrors,
  GetAuthenticationStatusErrors,
} from './types';
import { AxiosError } from 'axios';

export class StartAuthenticationResponse {
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
  public readonly erroType: StartAuthenticationErrors;

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
    errorType: StartAuthenticationErrors;
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
              errorType: StartAuthenticationErrors.HashNotBase64,
              axiosError,
            });
          } else if (error.includes('length')) {
            return new StartAuthenticationError({
              ...response.data,
              errorType: StartAuthenticationErrors.MismatchedHashLength,
              axiosError,
            });
            // The missing required param error message is always different for each field
            // so this is the last option in the if-else chain
          } else {
            return new StartAuthenticationError({
              ...response.data,
              errorType: StartAuthenticationErrors.MissingRequiredParam,
              axiosError,
            });
          }
        case 401:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrors.FaildToAuthorizeUser,
            axiosError,
          });
        case 405:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrors.MethodNotAllowed,
            axiosError,
          });
        case 500:
          return new StartAuthenticationError({
            ...response.data,
            errorType: StartAuthenticationErrors.InternalServerError,
            axiosError,
          });
        default:
          return new StartAuthenticationError({
            error: 'Unknown error',
            time: new Date().toISOString(),
            traceId: 'unknown',
            errorType: StartAuthenticationErrors.UnknownError,
            axiosError,
          });
      }
    }
    return new StartAuthenticationError({
      error: 'Unknown error',
      time: new Date().toISOString(),
      traceId: 'unknown',
      errorType: StartAuthenticationErrors.UnknownError,
      axiosError,
    });
  }
}

export class GetAuthenticationStatusResponse {}


export class GetAuthenticationStatusError {
  public readonly time: Date;
  public readonly traceId: string;
  /**
   * Error message returned by the TSP service.
   */
  public readonly error: string;
  public readonly erroType: GetAuthenticationStatusErrors;

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
    errorType: GetAuthenticationStatusErrors;
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
            errorType: GetAuthenticationStatusErrors.RequiredSessionIdMissing,
            axiosError,
          });
        case 401:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrors.FailedToAuthorizeUser,
            axiosError,
          });
        case 404:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrors.SessionIdNotFound,
            axiosError,
          });
        case 405:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrors.MethodNotAllowed,
            axiosError,
          });
        case 500:
          return new GetAuthenticationStatusError({
            ...response.data,
            errorType: GetAuthenticationStatusErrors.InternalServerError,
            axiosError,
          });
        default:
          return new GetAuthenticationStatusError({
            error: 'Unknown error',
            time: new Date().toISOString(),
            traceId: 'unknown',
            errorType: GetAuthenticationStatusErrors.UnknownError,
            axiosError,
          });
      }
    }
    return new GetAuthenticationStatusError({
      error: 'Unknown error',
      time: new Date().toISOString(),
      traceId: 'unknown',
      errorType: GetAuthenticationStatusErrors.UnknownError,
      axiosError,
    });
  }
}
