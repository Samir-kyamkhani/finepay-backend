import { Injectable, Logger } from '@nestjs/common';
import {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { createReadStream, unlinkSync, existsSync } from 'fs';
import * as path from 'path';
import { lookup as mimeLookup } from 'mime-types';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class S3Service {
  private readonly s3: S3Client;
  private readonly bucket: string;
  private readonly region: string;
  private readonly accessKey: string;
  private readonly secretKey: string;
  private readonly MAIN_FOLDER = 'fintech';
  private readonly logger = new Logger(S3Service.name);

  constructor(private readonly configService: ConfigService) {
    this.region = this.configService.get<string>('s3.region', '');
    this.bucket = this.configService.get<string>('s3.bucket', '');
    this.accessKey = this.configService.get<string>('s3.accessKey', '');
    this.secretKey = this.configService.get<string>('s3.secretKey', '');

    this.s3 = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: this.accessKey,
        secretAccessKey: this.secretKey,
      },
    });
  }

  async uploadBuffer(
    file: Express.Multer.File,
    category: string,
  ): Promise<string | null> {
    try {
      if (!file) {
        this.logger.error('No file provided');
        return null;
      }

      const uniqueFileName = `${Date.now()}_${file.originalname}`;
      const s3Key = `${this.MAIN_FOLDER}/${category}/${uniqueFileName}`;

      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: s3Key,
          Body: file.buffer,
          ContentType: file.mimetype,
        }),
      );

      return `https://${this.bucket}.s3.${this.region}.amazonaws.com/${s3Key}`;
    } catch (err: unknown) {
      if (err instanceof Error) {
        this.logger.error(`S3 uploadBuffer error: ${err.message}`);
      } else {
        this.logger.error('Unknown S3 uploadBuffer error');
      }

      return null;
    }
  }

  async upload(
    localFilePath: string,
    category: string,
  ): Promise<string | null> {
    try {
      if (!localFilePath) {
        this.logger.error('No file path provided');
        return null;
      }

      const lookup = mimeLookup(localFilePath);
      const mimeType =
        typeof lookup === 'string' ? lookup : 'application/octet-stream';

      this.logger.error('11111111', mimeType);

      const fileStream = createReadStream(localFilePath);
      const fileName = path.basename(localFilePath);
      const uniqueFileName = `${Date.now()}_${fileName}`;
      const s3Key = `${this.MAIN_FOLDER}/${category}/${uniqueFileName}`;

      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: s3Key,
          Body: fileStream,
          ContentType: mimeType,
        }),
      );

      unlinkSync(localFilePath);

      return `https://${this.bucket}.s3.${this.region}.amazonaws.com/${s3Key}`;
    } catch (err: unknown) {
      if (existsSync(localFilePath)) unlinkSync(localFilePath);

      if (err instanceof Error) {
        this.logger.error(`S3 upload error: ${err.message}`);
      } else {
        this.logger.error('Unknown S3 upload error');
      }

      return null;
    }
  }

  async delete(fileData: { fileUrl: string }): Promise<boolean> {
    try {
      const fileUrl = fileData.fileUrl;

      const key = fileUrl.split('.amazonaws.com/')[1];
      if (!key) return false;

      await this.s3.send(
        new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: key,
        }),
      );

      return true;
    } catch (err: unknown) {
      if (err instanceof Error) {
        this.logger.error(`S3 delete error: ${err.message}`);
      } else {
        this.logger.error('Unknown S3 delete error');
      }

      return false;
    }
  }
}
