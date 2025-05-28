import { MidHashTypes } from './midHashTypes';
import crypto, {
  randomBytes,
  verify,
  constants,
  createVerify,
  KeyObject,
} from 'crypto';
import asn1 from 'asn1.js';

export class RandomHash {
  public readonly value: Uint8Array;
  constructor(
    public readonly hashType: MidHashTypes,
    value?: Uint8Array | null,
  ) {
    if (value) {
      this.value = value;
    } else {
      this.value = new Uint8Array(
        randomBytes(MidHashTypes.getLengthInBytes(hashType)),
      );
    }
  }

  toString() {
    return `RandomHash(${this.hashType}, ${Buffer.from(this.value).toString('hex')})`;
  }

  static fromBase64(base64String: string): RandomHash {
    const value = Uint8Array.from(Buffer.from(base64String, 'base64'));
    const hashType = MidHashTypes.fromBytesLength(value.length);
    return new RandomHash(hashType, value);
  }

  toBase64(): string {
    return Buffer.from(this.value).toString('base64');
  }
  /**
   *
   *6 bits from the beginning of hash and 7 bits from the end of hash are taken.
   *The resulting 13 bits are transformed into decimal number and printed out.
   *The Verification code is a decimal 4-digits number in range 0000...8192,
   *always 4 digits are displayed (e.g. 0041).
   */
  generateVerificationCode(): string {
    const first6Bits = this.value[0] & 0b00111111; // 6 bits from the beginning
    const last7Bits = this.value[this.value.length - 1] & 0b01111111; // 7 bits from the end
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

    const EcdsaDerSig = asn1.define('EcdsaDerSig', function () {
      this.seq().obj(this.key('r').int(), this.key('s').int());
    });

    const encodedR = encodeInteger(r);
    const encodedS = encodeInteger(s);
    const sequenceLen = encodedR.length + encodedS.length;

    return Buffer.concat([
      Buffer.from([0x30, sequenceLen]),
      encodedR,
      encodedS,
    ]);
  }

  /**
   * verifySignature verifies the signature using the provided public key.
   * Jave MID implementation:
   * https://github.com/SK-EID/mid-rest-java-client/blob/cf04a090e7cd932633db5bd25b6ce174ab136042/src/main/java/ee/sk/mid/MidSignatureVerifier.java#L66
   */
  verifySignature(publicKey: KeyObject, signature: Uint8Array): boolean {
    console.log('Starting signature verification...');
    try {
      // Combine the digest info prefix with the signature
      const signedDigest = Buffer.concat([
        MidHashTypes.getDigestInfoPrefix(this.hashType),
        signature,
      ]);

      const isRsaValid = verify(
        null, // Use null for PKCS1v15 padding
        this.value,
        {
          padding: constants.RSA_PKCS1_PADDING,
          key: publicKey,
        },
        signedDigest,
      );

      if (isRsaValid) {
        console.log('Signature verified successfully with RSA');
        return true;
      }
    } catch (err) {
      console.error('RSA verification failed:', err);
    }
    // If RSA verification fails, try ECDSA
    try {
      console.log('Trying ECDSA verification...');
      const signatureAsn1 = RandomHash.signatureFromCvcEncoding(signature);

      console.log('value langth:', this.value.length);
      return verify(null, this.value, publicKey, signatureAsn1);
    } catch (ecdsaErr) {
      console.error('ECDSA verification failed:', ecdsaErr);
    }
    // If both RSA and ECDSA verification fail
    return false;
  }
}
