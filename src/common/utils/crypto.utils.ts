import { Injectable } from '@nestjs/common';
import * as crypto from 'node:crypto';

@Injectable()
export class CryptoService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;

  constructor() {
    const secret = process.env.ENCRYPTION_KEY;
    if (!secret) throw new Error('PII_SECRET_KEY missing');

    this.key = crypto.createHash('sha256').update(secret).digest();
  }

  encrypt(plain: string): string {
    // Store as uppercase for consistency
    const plainUpper = plain.toUpperCase();

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

    const encrypted = Buffer.concat([
      cipher.update(plainUpper, 'utf8'),
      cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, tag, encrypted]).toString('hex');
  }

  decrypt(hex: string): string {
    try {
      const buf = Buffer.from(hex, 'hex');

      const iv = buf.subarray(0, 12);
      const tag = buf.subarray(12, 28);
      const encrypted = buf.subarray(28);

      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]).toString('utf8');

      return decrypted;
    } catch (error) {
      console.error('Decryption error:', error.message);
      throw error;
    }
  }

  // Helper method to check if data is encrypted
  isEncryptedData(data: string): boolean {
    if (!data) return false;
    // Encrypted data is hex string (aes-256-gcm produces 64+ chars)
    return /^[0-9a-f]{64,}$/i.test(data.trim());
  }

  // Safe decrypt that handles single or double encryption
  safeDecrypt(encryptedData: string): {
    value: string;
    wasDoubleEncrypted: boolean;
  } {
    try {
      // First decryption
      const firstPass = this.decrypt(encryptedData);

      // Check if result is still encrypted
      if (this.isEncryptedData(firstPass)) {
        // Second decryption (was double encrypted)
        const secondPass = this.decrypt(firstPass);
        return { value: secondPass, wasDoubleEncrypted: true };
      }

      return { value: firstPass, wasDoubleEncrypted: false };
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}
