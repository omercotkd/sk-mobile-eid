import axios from 'axios';
import { RandomHash } from './randomHash';
import settings from './settings';
import { MidHashTypes } from './midHashTypes';

// Create a new Axios instance
const apiClient = axios.create({
  baseURL: 'https://tsp.demo.sk.ee/mid-api',
  headers: { 'Content-Type': 'application/json' },
});

const baseRequestPayload = {
  relyingPartyUUID: settings.RELYING_PARTY_UUID,
  relyingPartyName: settings.RELYING_PARTY_NAME,
};

export async function startAuthentication(
  phoneNumber: string,
  nationalIdentityNumber: string,
  randomHash: RandomHash,
): Promise<string> {
  /**
   * Starts the authentication process by sending a request to the TSP service.
   * Returns the authentication session ID.
   */
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

  const response = await apiClient.post('/authentication', payload);
  return response.data.sessionID;
}

export async function getAuthenticationStatus(
  sessionId: string,
): Promise<Record<string, any>> {
  /**
   * Checks the status of the authentication process.
   * Returns the status and any additional information.
   */
  const url = `/authentication/session/${sessionId}?timeoutMs=10000`;
  const response = await apiClient.get(url);
  return response.data;
}
