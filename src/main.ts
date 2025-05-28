import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import settings from './lib/settings';
import {
  RandomHash,
  // AuthenticationCertificate,
} from './lib/randomHash';
import { MidHashTypes } from './lib/midHashTypes';
import { startAuthentication, getAuthenticationStatus } from './lib/service';
import { X509Certificate } from 'crypto';

async function main() {
  // Create a random hash using SHA256
  const randomHash = new RandomHash(MidHashTypes.SHA256);

  // Start the authentication process
  const sessionId = await startAuthentication(
    settings.PHONE_NUMBER,
    settings.ID_NUMBER,
    randomHash,
  );

  // Generate and display the verification code
  const verificationCode = randomHash.generateVerificationCode();
  console.log(`Verification code: ${verificationCode}`);

  // Display the session ID
  console.log(`Session ID: ${sessionId}`);

  // Get the authentication status
  const status = await getAuthenticationStatus(sessionId);

  // Decode the signature
  const signature: string = status.signature.value;
  console.log(`Signature: ${signature}`);
  const signatureDecoded = Buffer.from(signature, 'base64');

  // Load the certificate for verification
  const certificate = new X509Certificate(Buffer.from(status.cert, 'base64'));
  console.log(`Certificate: ${certificate.subject}`);
  // const certToVerify = new AuthenticationCertificate(status.cert);

  // Verify the certificate
  // certToVerify.verifyCertificate();
  // const publicKey = certificate.publicKey.export({
  //   type: 'spki',
  //   format: 'pem',
  // });
  // // Verify the signature
  const isSignatureValid = randomHash.verifySignature(
    certificate.publicKey,
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
