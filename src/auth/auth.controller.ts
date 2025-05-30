import {
  Body,
  Controller,
  Post,
  BadRequestException,
  Get,
} from '@nestjs/common';
import { StartAuthDto } from './start-auth.dto';
import {
  startAuthentication,
  RandomHash,
  MidHashTypes,
  getAuthenticationStatus,
  AuthenticationCertificate,
} from '../services/sk-mid';

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
        sessionId: result.value.sessionID,
        randomHash: randomHash.messageToBase64(),
      };
    } else {
      throw new BadRequestException(result.error.erroType);
    }
  }

  @Get('status')
  async getAuthStatus(@Body() body: { sessionId: string }) {
    if (!body || !body.sessionId) {
      throw new BadRequestException('Missing required field: sessionId');
    }
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
    const randomHash = RandomHash.fromMessageBase64('');

    if (
      !randomHash.verifySignature({
        publicKey: certToVerify.getPublicKey(),
        signature: Buffer.from(result.value.signature?.value || '', 'base64'),
      })
    ) {
      throw new BadRequestException('Signature verification failed');
    }

    return {
      status: 'success',
      // shuld send here any tokenId, as the user is authenticated against the sk-mid service
    };
  }
}
