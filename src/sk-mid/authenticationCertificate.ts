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

  verifyCertificate(): boolean {
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
}
