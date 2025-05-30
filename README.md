# SK MID Authentication Flow

This project demonstrates the authentication flow using the Estonian Mobile-ID (SK MID) system.

## Flow Overview

1. **User Initiates Authentication**: The user provides their ID number and phone number to start the authentication process.
2. **API Sends Authentication Request**: The API sends these credentials to the MID-SK API, along with a random message. This message is used to verify the user's signature and to generate a verification code displayed on the user's phone.
3. **User Authenticates on Phone**: The user receives a prompt on their phone (via the MID-SK app) and completes the authentication process.
4. **Polling for Status**: The client polls the API for the authentication status while the user is authenticating.
5. **API Receives Authentication Result**: Once the user completes authentication, the MID-SK API returns the result to the server.
6. **Verification**: The server verifies the response, ensuring the signature is valid and the response is authentic.
7. **Authentication Success**: If all checks pass, the user is considered authenticated.

---

## Example Code (Logic Only)

Below is a simplified example of the authentication flow, focusing on the core logic (without API endpoints):

```ts
import {
  startAuthentication,
  getAuthenticationStatus,
  RandomHash,
  MidHashTypes,
  AuthenticationCertificate,
} from './services/sk-mid';

async function main() {
  // Generate a random hash (SHA256)
  const randomHash = new RandomHash(MidHashTypes.SHA256);

  // Start authentication
  const startAuthRes = await startAuthentication({
    phoneNumber: '+37269930366',
    nationalIdentityNumber: '+37069930366',
    randomHash,
  });

  if (!startAuthRes.ok) {
    console.error('Failed to start authentication');
    return;
  }

  // Display verification code to user
  console.log(`Verification code: ${randomHash.generateVerificationCode()}`);

  // Simulate waiting for user to authenticate on their phone
  await new Promise((resolve) => setTimeout(resolve, 10000));

  // Poll for authentication status
  const statusRes = await getAuthenticationStatus({
    sessionId: startAuthRes.value.sessionID,
  });

  if (!statusRes.ok) {
    console.error('Failed to get authentication status');
    return;
  }

  if (!statusRes.value.isSuccess()) {
    console.error('Authentication was not successful');
    return;
  }

  // Verify the authentication certificate
  const certToVerify = new AuthenticationCertificate(statusRes.value.cert!);
  if (!certToVerify.isValid()) {
    console.error('Certificate is not valid');
    return;
  }

  // Verify the signature
  const signatureDecoded = Buffer.from(statusRes.value.signature?.value!, 'base64');
  const isSignatureValid = randomHash.verifySignature({
    publicKey: certToVerify.getPublicKey(),
    signature: signatureDecoded,
  });

  if (!isSignatureValid) {
    console.error('Signature is not valid');
    return;
  }

  console.log('Authentication successful! User verified.');
}
```

---

## Notes
- This example omits error handling and production-level security for brevity.
- The phone number and national identity number are from the test environment and should not be used in production.
- The actual implementation should use secure storage and proper error reporting.

---

## Deploying to Production
- Obtain production certificates and the API URL from the official documentation: [SK-EID Environment Technical Parameters](https://github.com/SK-EID/MID/wiki/Environment-technical-parameters)


## Test Data
- You can find phone numbers and national identity numbers for testing in the official documentation: [Test Numbers for Automated Testing in DEMO](https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO#personal-data-structure-overview-that-is-located-on-the-certificates-subject-field)
- These test credentials are only valid in the DEMO environment and will not work in production.

---
