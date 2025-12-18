import { IsString, IsOptional, IsNumber, IsUUID } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateBusinessKycDto {
  @IsString()
  address: string;

  @IsString()
  pinCode: string;

  @IsUUID()
  cityId: string;

  @IsUUID()
  stateId: string;

  @IsString()
  pan: string;

  @IsString()
  gst: string;

  @IsOptional()
  @IsString()
  udhyamAadhar?: string;

  @IsOptional()
  @IsString()
  cin?: string;

  @IsNumber()
  @Type(() => Number)
  partnerKycNumbers?: number;

  @IsNumber()
  @Type(() => Number)
  directorsCount?: number;

  /** Files are injected, not validated */
  panFile: string;
  gstFile: string;

  @IsOptional()
  directorShareholding?: string;

  @IsOptional()
  aoaFile?: string;

  @IsOptional()
  moaFile?: string;
}
