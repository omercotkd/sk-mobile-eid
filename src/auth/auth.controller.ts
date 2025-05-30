import {
  Body,
  Controller,
  Post,
  BadRequestException,
  Get,
} from '@nestjs/common';
import { StartAuthDto, GetAuthStatusDto } from './auth.dto';
import {
  startAuthentication,
  RandomHash,
  MidHashTypes,
  getAuthenticationStatus,
  AuthenticationCertificate,
} from '../services/sk-mid';
import { signIdToken } from './idtoken';

@Controller('auth')
export class AuthController {
  @Post('start')
  async startAuth(@Body() body: StartAuthDto) {
    // Only allow phone numbers from Estonia and Lithuania
    if (
      !body.phoneNumber.startsWith('+372') &&
      !body.phoneNumber.startsWith('+370')
    )
      throw new BadRequestException(
        'Phone number must start with +372 or +370',
      );

    // Generate a random hash for authentication
    const randomHash = new RandomHash(MidHashTypes.SHA256);

    const result = await startAuthentication({
      phoneNumber: body.phoneNumber,
      nationalIdentityNumber: body.nationalIdentityNumber,
      randomHash,
    });

    if (result.ok) {
      return {
        code: randomHash.generateVerificationCode(),
        // In a real application, you would not return the session ID directly
        // but rather store it in a session or database
        sessionId: result.value.sessionID,
        // Same here, do not return the hash directly in production
        // This is just for demonstration purposes
        randomMessage: randomHash.messageToBase64(),
      };
    } else {
      throw new BadRequestException(result.error.erroType);
    }
  }

  @Post('status')
  async getAuthStatus(@Body() body: GetAuthStatusDto) {
    const result = await getAuthenticationStatus({
      sessionId: body.sessionId,
      timeoutMs: 120000,
    });
    if (!result.ok) {
      throw new BadRequestException(result.error.erroType || 'Unknown error');
    }
    if (result.value.isRunning()) {
      return {
        status: 'running',
      };
    }
    if (result.value.isFailure()) {
      return {
        status: 'failure',
        error: result.value.result,
      };
    }
    // The only option left is success
    // so now we need to verify the signature and certificate
    if (!result.value.cert) {
      throw new BadRequestException(
        'No certificate found in authentication result',
      );
    }
    const certToVerify = new AuthenticationCertificate(result.value.cert);

    if (!certToVerify.isValid()) {
      throw new BadRequestException(
        'Invalid certificate, not signed by a trusted authority',
      );
    }
    // Verify the signature against the hash we generated earlier
    const randomHash = RandomHash.fromMessageBase64(body.randomMessage);

    if (
      !randomHash.verifySignature({
        publicKey: certToVerify.getPublicKey(),
        signature: Buffer.from(result.value.signature?.value || '', 'base64'),
      })
    ) {
      throw new BadRequestException('Signature verification failed');
    }

    const userInfo = certToVerify.getSignedUserData();

    return {
      status: 'success',
      userInfo: userInfo,
      idToken: signIdToken(userInfo),
    };
  }
}
