import {
  Injectable,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHmac,
} from 'node:crypto';
import type { Request } from 'express';

import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../types/auth.type';

@Injectable()
export class AuthUtilsService {
  private readonly logger = new Logger(AuthUtilsService.name);

  private readonly ALGORITHM = 'aes-256-gcm';
  private readonly IV_LENGTH = 16; // 128 bits
  private readonly KEY_LENGTH = 32; // 256 bits
  private readonly secretKey: Buffer;

  constructor(
    private readonly jwt: JwtService,
    private readonly configService: ConfigService,
  ) {
    const key = this.configService.get<string>('security.authKeySecret');

    if (!key) {
      throw new Error('Environment variable AUTH_SECRET_KEY is not set');
    }

    const keyBuffer = Buffer.from(key, 'hex');
    if (keyBuffer.length !== this.KEY_LENGTH) {
      throw new Error(
        `AUTH_SECRET_KEY must be ${this.KEY_LENGTH} bytes in hex`,
      );
    }

    this.secretKey = keyBuffer;
  }

  // Encrypt password (store in DB)
  hashPassword(password: string): string {
    try {
      const iv = randomBytes(this.IV_LENGTH);
      const cipher = createCipheriv(this.ALGORITHM, this.secretKey, iv);

      let encrypted = cipher.update(password, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();
      return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    } catch (error) {
      this.logger.error('Encryption failed:', error);
      throw new InternalServerErrorException('Encryption failed');
    }
  }

  // only for seed
  static hashPasswordforSeed(password: string): string {
    try {
      const keyHex = process.env.CRYPTO_SECRET_KEY;
      if (!keyHex) throw new Error('AUTH_SECRET_KEY missing in .env');

      const secretKey = Buffer.from(keyHex, 'hex');
      if (secretKey.length !== 32) {
        throw new Error('AUTH_SECRET_KEY must be 32 bytes (64 hex chars)');
      }

      const iv = randomBytes(16);
      const cipher = createCipheriv('aes-256-gcm', secretKey, iv);

      let encrypted = cipher.update(password, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    } catch (error) {
      // static method → cannot use this.logger
      console.error('Seed encryption failed:', error);
      throw new InternalServerErrorException('Seed encryption failed');
    }
  }

  // Decrypt password (show in dashboard)
  decryptPassword(encrypted: string): string {
    try {
      const [ivHex, encryptedHex, authTagHex] = encrypted.split(':');
      if (!ivHex || !encryptedHex || !authTagHex)
        throw new InternalServerErrorException('Invalid encrypted format');

      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');

      const decipher = createDecipheriv(this.ALGORITHM, this.secretKey, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      this.logger.error('Decryption failed:', error);
      throw new InternalServerErrorException('Decryption failed');
    }
  }

  verifyPassword(plain: string, encrypted: string): boolean {
    const decrypted = this.decryptPassword(encrypted);
    return plain === decrypted;
  }

  generateRandomPassword(length = 12): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let result = '';
    const rnd = randomBytes(length);

    for (let i = 0; i < length; i++) {
      result += chars[rnd[i] % chars.length];
    }
    return result;
  }

  // Transaction PIN ke liye methods
  generateRandomTransactionPin(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  hashResetToken(token: string) {
    const secret = this.configService.get<string>('security.authKeySecret');

    if (!secret) {
      throw new Error('security.authKeySecret is not set in configuration');
    }

    return createHmac('sha256', secret).update(token).digest('hex');
  }

  generateTokens(payload: JwtPayload) {
    return {
      accessToken: this.jwt.sign(payload, { expiresIn: '1h' }),
      refreshToken: this.jwt.sign(payload, { expiresIn: '30d' }),
    };
  }

  stripSensitive<T extends object>(obj: T, fields: readonly (keyof T)[]): T {
    const clone: Partial<T> = { ...obj };

    for (const field of fields) {
      delete clone[field];
    }

    return clone as T;
  }

  getClientIp(req: Request): string | null {
    const forwarded = req.headers['x-forwarded-for'];

    let ip: string | null = null;

    if (typeof forwarded === 'string') {
      ip = forwarded.split(',')[0]?.trim() || null;
    } else if (Array.isArray(forwarded)) {
      ip = forwarded[0]?.trim() || null;
    } else {
      ip = req.ip ?? req.socket?.remoteAddress ?? null;
    }

    if (!ip) return null;

    // Normalize IPv6-mapped IPv4 → "::ffff:127.0.0.1"
    if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');

    // Normalize IPv6 localhost
    if (ip === '::1') ip = '127.0.0.1';

    return ip;
  }

  getClientOrigin(req: Request): string | null {
    return req.get('origin') || req.get('Origin') || null;
  }

  getClientUserAgent(req: Request): string | null {
    return (req.headers['user-agent'] as string) || null;
  }

  isValidOrigin(
    origin: string | null,
    allowed: string[],
    isProd = this.configService.get<string>('security.production') ===
      'production',
  ): boolean {
    // DEV MODE: Origin null allowed (Postman, Thunder, REST Client)
    if (!isProd && !origin) return true;

    // PROD MODE: Origin null NEVER allowed (strict security)
    if (isProd && !origin) return false;

    const cleaned = allowed.filter(Boolean);

    // Prod: whitelist empty = deny
    if (isProd && !cleaned.length) return false;

    // Dev: whitelist empty = allow all
    if (!isProd && !cleaned.length) return true;

    const raw = origin!; // now safe to use (we checked above)

    let hostname: string;
    let protocol: string;

    try {
      const u = new URL(raw);
      hostname = u.hostname;
      protocol = u.protocol;
    } catch {
      return false;
    }

    return cleaned.some((domain) => {
      try {
        const d = new URL(domain);

        if (d.protocol !== protocol) return false;

        return d.hostname === hostname;
      } catch {
        // Bare domain fallback
        return domain === hostname;
      }
    });
  }

  private ipToLong(ip: string): number {
    return (
      ip
        .split('.')
        .map((x) => parseInt(x, 10))
        .reduce((acc, val) => acc * 256 + val) >>> 0
    );
  }

  private inCidr(ip: string, cidr: string): boolean {
    try {
      const [range, bits] = cidr.split('/');
      const mask = ~(2 ** (32 - Number(bits)) - 1);

      return (this.ipToLong(ip) & mask) === (this.ipToLong(range) & mask);
    } catch {
      return false;
    }
  }

  isValidIp(
    clientIp: string | null,
    allowedIps: string[],
    isProd = this.configService.get<string>('security.production') ===
      'production',
  ): boolean {
    if (!clientIp) return false;

    const cleaned = allowedIps.filter(Boolean);

    // DEV MODE — allow localhost & LAN always
    if (!isProd) {
      if (
        clientIp === '127.0.0.1' ||
        clientIp.startsWith('192.168.') ||
        clientIp.startsWith('10.') ||
        clientIp.startsWith('172.')
      ) {
        return true;
      }

      // Dev: if no whitelist → allow all
      if (!cleaned.length) return true;
    }

    // PROD MODE RESTRICTIONS
    if (isProd && !cleaned.length) return false;

    // Exact match
    if (cleaned.includes(clientIp)) return true;

    // CIDR match
    return cleaned.some(
      (range) => range.includes('/') && this.inCidr(clientIp, range),
    );
  }

  // Converts paise(BigInt) -> rupees -> string   (SAFE)
  money(value?: bigint | number | null): string {
    if (value === null || value === undefined) return '0';

    if (typeof value === 'bigint') {
      return (value / 100n).toString();
    }

    return (value / 100).toString();
  }
}
