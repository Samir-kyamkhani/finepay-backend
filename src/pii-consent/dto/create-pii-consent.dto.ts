import { IsString, IsOptional, IsNotEmpty, IsDate } from 'class-validator';
import { Type } from 'class-transformer';

export class CreatePiiConsentDto {
  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsString()
  @IsNotEmpty()
  piiType: string;

  @IsString()
  @IsNotEmpty()
  scope: string;

  @IsString()
  @IsNotEmpty()
  piiHash: string;

  @IsOptional()
  @IsString()
  businessKycId?: string;

  @IsOptional()
  @IsString()
  userKycId?: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  providedAt?: Date;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  expiresAt?: Date;
}
