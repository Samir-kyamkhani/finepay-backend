import { IsString, IsOptional, IsNotEmpty } from 'class-validator';

export class UpdatePiiConsentDto {
  @IsString()
  @IsNotEmpty()
  id: string;

  @IsOptional()
  piiType?: string;

  @IsOptional()
  scope?: string;

  @IsOptional()
  piiHash?: string;

  @IsOptional()
  businessKycId?: string;

  @IsOptional()
  userKycId?: string;
}
