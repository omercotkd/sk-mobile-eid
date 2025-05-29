import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import settings from './sk-mid/settings';
import { RandomHash } from './sk-mid/randomHash';
import { MidHashTypes } from './sk-mid/midHashTypes';
import { startAuthentication, getAuthenticationStatus } from './sk-mid/service';
import { AuthenticationCertificate } from './sk-mid/authenticationCertificate';

async function main() {
  // Create a random hash using SHA256
  const randomHash = new RandomHash(MidHashTypes.SHA256);

  // Start the authentication process
  const startAuthRes = await startAuthentication({
    phoneNumber: settings.PHONE_NUMBER,
    nationalIdentityNumber: settings.ID_NUMBER,
    randomHash,
  });

  if (!startAuthRes.ok) {
    console.error('Error starting authentication:', startAuthRes.error);
    return;
  }

  // Generate and display the verification code
  const verificationCode = randomHash.generateVerificationCode();
  console.log(`Verification code: ${verificationCode}`);

  // Display the session ID
  console.log(`Session ID: ${startAuthRes.value.sessionID}`);

  // Get the authentication status
  const statusRes = await getAuthenticationStatus({
    sessionId: startAuthRes.value.sessionID,
  });

  if (!statusRes.ok) {
    console.error('Error getting authentication status:', statusRes.error);
    return;
  }

  // Decode the signature
  const signature: string = statusRes.value.signature.value;

  const signatureDecoded = Buffer.from(signature, 'base64');

  // Load the certificate for verification

  const certToVerify = new AuthenticationCertificate(statusRes.value.cert);

  // Verify the certificate
  const res = certToVerify.verifyCertificate();
  console.log(`Certificate verification result: ${res}`);
  // const publicKey = certificate.publicKey.export({
  //   type: 'spki',
  //   format: 'pem',
  // });
  // // Verify the signature
  const isSignatureValid = randomHash.verifySignature(
    certToVerify.getPublicKey(),
    signatureDecoded,
  );

  console.log(`Signature valid: ${isSignatureValid}`);
}

// Run the main function
main().catch((error) => {
  console.error('An error occurred:', error);
});

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
