import { MidHashTypes } from './midHashTypes';
import { KeyObject } from 'crypto';
import * as crypto from 'crypto';

export class RandomHash {
  public readonly hashType: MidHashTypes;
  public readonly hash: Uint8Array;
  public readonly message: Uint8Array;

  constructor(hashType: MidHashTypes, message?: Uint8Array | null) {
    this.hashType = hashType;
    if (message) {
      this.message = message;
    } else {
      const randomValue = crypto.randomBytes(
        // can use any length for the random message if not provided one
        // using the hash type length as a default
        MidHashTypes.getLengthInBytes(hashType),
      );
      this.message = randomValue;
    }
    const hash = crypto.createHash(MidHashTypes.getHashTypeName(hashType));
    hash.update(this.message);
    this.hash = new Uint8Array(hash.digest());
  }

  static fromMessageBase64(base64String: string): RandomHash {
    const [hashTypeName, messageBase64] = base64String.split(':');
    const hashType = MidHashTypes.fromHashTypeName(hashTypeName);
    const message = Buffer.from(messageBase64, 'base64');
    return new RandomHash(hashType, new Uint8Array(message));
  }

  toString() {
    return `RandomHash(${this.hashType}, ${Buffer.from(this.hash).toString('hex')}, ${this.message})`;
  }
  hashToBase64(): string {
    return Buffer.from(this.hash).toString('base64');
  }
  messageToBase64(): string {
    return `${MidHashTypes.getHashTypeName(
      this.hashType,
    )}:${Buffer.from(this.message).toString('base64')}`;
  }
  /**
   *
   *6 bits from the beginning of hash and 7 bits from the end of hash are taken.
   *The resulting 13 bits are transformed into decimal number and printed out.
   *The Verification code is a decimal 4-digits number in range 0000...8192,
   *always 4 digits are displayed (e.g. 0041).
   */
  generateVerificationCode(): string {
    const first6Bits = this.hash[0] & 0b00111111; // 6 bits from the beginning
    const last7Bits = this.hash[this.hash.length - 1] & 0b01111111; // 7 bits from the end
    const verificationCode = (first6Bits << 7) | last7Bits; // Combine the bits
    return verificationCode.toString().padStart(4, '0'); // Ensure it's 4 digits
  }
  /**
   * Converts a signature in CVC encoding to ASN.1 format.
   * CVC encoding is a compact representation of a signature.
   * as shown in the java MID client:
   * https://github.com/SK-EID/mid-rest-java-client/blob/cf04a090e7cd932633db5bd25b6ce174ab136042/src/main/java/ee/sk/mid/MidSignatureVerifier.java#L83
   */
  private static signatureFromCvcEncoding(signature: Uint8Array): Uint8Array {
    const mid = Math.floor(signature.length / 2);
    let r = signature.slice(0, mid);
    let s = signature.slice(mid);

    // Remove leading zeros
    r = r[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), r]) : r;
    s = s[0] & 0x80 ? Buffer.concat([Buffer.from([0x00]), s]) : s;

    function encodeInteger(buf: Uint8Array) {
      return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
    }

    const encodedR = encodeInteger(r);
    const encodedS = encodeInteger(s);
    const sequenceLen = encodedR.length + encodedS.length;

    return Buffer.concat([
      Buffer.from([0x30, sequenceLen]),
      encodedR,
      encodedS,
    ]);
  }

  private verifyRsaSignature(
    publicKey: KeyObject,
    signature: Uint8Array,
  ): boolean {
    console.debug(
      'Verifying signature with RSA public key, hash type:',
      this.hashType,
    );
    const signedDigestHash = Buffer.concat([
      MidHashTypes.getDigestInfoPrefix(this.hashType),
      this.hash,
    ]);

    const decrypted = crypto.publicDecrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      signature,
    );

    return decrypted.equals(signedDigestHash);
  }

  private verifyEcdsaSignature(
    publicKey: KeyObject,
    signature: Uint8Array,
  ): boolean {
    console.debug(
      'Verifying signature with ECDSA public key, hash type:',
      this.hashType,
    );
    const signatureAsn1 = RandomHash.signatureFromCvcEncoding(signature);
    const createdVe = crypto.createVerify(
      MidHashTypes.getAlgorithm(this.hashType),
    );
    // due to crypto module limitations, we need to use the original message
    // instead of the hash, as the verify method expects the original data
    createdVe.update(this.message!); // NOT the hash!
    createdVe.end();
    return createdVe.verify(publicKey, signatureAsn1);
  }

  /**
   * verifySignature verifies the signature using the provided public key.
   * Jave MID implementation:
   * https://github.com/SK-EID/mid-rest-java-client/blob/cf04a090e7cd932633db5bd25b6ce174ab136042/src/main/java/ee/sk/mid/MidSignatureVerifier.java#L66
   */
  verifySignature({
    publicKey,
    signature,
  }: {
    publicKey: KeyObject;
    signature: Uint8Array;
  }): boolean {
    switch (publicKey.asymmetricKeyType) {
      case 'rsa':
        return this.verifyRsaSignature(publicKey, signature);
      case 'ec':
        return this.verifyEcdsaSignature(publicKey, signature);
      default:
        throw new Error(
          `Unsupported public key type: ${publicKey.asymmetricKeyType}`,
        );
    }
  }
}
