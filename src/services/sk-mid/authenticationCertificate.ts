import { X509Certificate, KeyObject } from 'crypto';
import * as fs from 'fs';

export class AuthenticationCertificate {
  static readonly DEFAULT_VERIFIED_CERTIFICATES_FOLDER = 'certificates';

  readonly cert: string;
  readonly certificate: X509Certificate;
  readonly verifiedCertificatesFolder: string;

  /**
   * Represents an authentication certificate.
   * @param cert - The base64 encoded certificate string.
   * @param verifiedCertificatesFolder - Optional folder path containing verified certificates.
   * @throws {Error} If the certificate is invalid or cannot be parsed.
   */
  constructor(cert: string, verifiedCertificatesFolder: string | null = null) {
    this.certificate = new X509Certificate(Buffer.from(cert, 'base64'));
    this.verifiedCertificatesFolder =
      verifiedCertificatesFolder ||
      AuthenticationCertificate.DEFAULT_VERIFIED_CERTIFICATES_FOLDER;
    this.cert = cert;
  }

  private loadVerifiedCertificates(): X509Certificate[] {
    if (
      !this.verifiedCertificatesFolder ||
      !fs.existsSync(this.verifiedCertificatesFolder)
    ) {
      console.error(
        `Verified certificates folder does not exist: ${this.verifiedCertificatesFolder}`,
      );
      return [];
    }

    const certificates: X509Certificate[] = [];

    for (const filename of fs.readdirSync(this.verifiedCertificatesFolder)) {
      const filePath = `${this.verifiedCertificatesFolder}/${filename}`;
      if (fs.statSync(filePath).isFile()) {
        const certContent = fs.readFileSync(filePath, 'utf-8');
        try {
          const certificate = new X509Certificate(certContent);
          certificates.push(certificate);
        } catch (error) {
          console.error(`Error loading certificate from ${filePath}:`, error);
        }
      }
    }

    return certificates;
  }

  isValid(): boolean {
    for (const cert of this.loadVerifiedCertificates()) {
      if (this.certificate.verify(cert.publicKey)) {
        console.debug(
          `Signature verified successfully with certificate: ${cert.subject}`,
        );
        return true;
      }
    }
    return false;
  }

  getPublicKey(): KeyObject {
    return this.certificate.publicKey;
  }

  /**
   * Extracts signed user data from the certificate's subject fields.
   *
   * https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO#personal-data-structure-overview-that-is-located-on-the-certificates-subject-field
   */
  getSignedUserData(): Record<string, string> {
    const subject = this.certificate.subject;
    // The DOB is not on the certificate,
    // But you can calculate it from the personal ID of the user:
    // https://github.com/dknight/Isikukood-js/blob/master/src/isikukood.ts

    const userData: Record<string, string> = {};
    subject.split('\n').forEach((line) => {
      const [key, value] = line.split('=');
      if (key && value) {
        userData[key.trim()] = value.trim();
      }
    });

    return userData;
  }
}
