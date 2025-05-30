import axios from 'axios';
import { RandomHash } from './randomHash';
import settings from './settings';
import { MidHashTypes } from './midHashTypes';
import { Result } from './types';
import { AuthenticationCertificate } from './authenticationCertificate';
import {
  StartAuthenticationSuccess,
  GetAuthenticationStatusError,
  StartAuthenticationError,
  GetAuthenticationStatusSuccess,
} from './responses';

// Create a new Axios instance
const apiClient = axios.create({
  baseURL: 'https://tsp.demo.sk.ee/mid-api',
  headers: { 'Content-Type': 'application/json' },
});

const baseRequestPayload = {
  relyingPartyUUID: settings.RELYING_PARTY_UUID,
  relyingPartyName: settings.RELYING_PARTY_NAME,
};

/**
 * Starts the authentication process by sending a request to the TSP service.
 * https://github.com/SK-EID/MID?tab=readme-ov-file#32-initiating-signing-and-authentication
 */
export async function startAuthentication({
  phoneNumber,
  nationalIdentityNumber,
  randomHash,
}: {
  phoneNumber: string;
  nationalIdentityNumber: string;
  randomHash: RandomHash;
}): Promise<Result<StartAuthenticationSuccess, StartAuthenticationError>> {
  const payload = {
    ...baseRequestPayload,
    phoneNumber,
    nationalIdentityNumber,
    hash: randomHash.hashToBase64(),
    hashType: MidHashTypes.getHashTypeName(randomHash.hashType),
    language: 'ENG',
    displayText: 'Hopae authentication request',
    displayTextFormat: 'GSM-7',
  };

  try {
    console.debug('Sending authentication request with payload:', payload);
    const response = await apiClient.post('/authentication', payload);
    return { ok: true, value: new StartAuthenticationSuccess(response.data) };
  } catch (error) {
    return { ok: false, error: StartAuthenticationError.fromAxiosError(error) };
  }
}

export async function getAuthenticationStatus({
  sessionId,
  timeoutMs,
}: {
  sessionId: string;
  timeoutMs?: number;
}): Promise<
  Result<GetAuthenticationStatusSuccess, GetAuthenticationStatusError>
> {
  /**
   * Checks the status of the authentication process.
   * Returns the status and any additional information.
   */
  try {
    const response = await apiClient.get(
      `/authentication/session/${sessionId}`,
      {
        params: { timeoutMs },
      },
    );
    return {
      ok: true,
      value: new GetAuthenticationStatusSuccess(response.data),
    };
  } catch (error) {
    return {
      ok: false,
      error: GetAuthenticationStatusError.fromAxiosError(error),
    };
  }
}

export { RandomHash, MidHashTypes, AuthenticationCertificate };
