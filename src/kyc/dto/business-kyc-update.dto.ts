import { IsString, IsOptional, IsNumber, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateBusinessKycDto {
  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  pinCode?: string;

  @IsOptional()
  @IsUUID()
  cityId?: string;

  @IsOptional()
  @IsUUID()
  stateId?: string;

  @IsOptional()
  @IsString()
  pan?: string;

  @IsOptional()
  @IsString()
  gst?: string;

  @IsOptional()
  @IsString()
  udhyamAadhar?: string;

  @IsOptional()
  @IsString()
  cin?: string;

  // ---------- PARTNERSHIP ----------
  @IsNumber()
  @Type(() => Number)
  partnerKycNumbers?: number;

  // ---------- PRIVATE LIMITED ----------
  @IsNumber()
  @Type(() => Number)
  directorsCount?: number;

  @IsOptional()
  panFile?: string;

  @IsOptional()
  gstFile?: string;

  @IsOptional()
  directorShareholding?: string;

  @IsOptional()
  aoaFile?: string;

  @IsOptional()
  moaFile?: string;
}
