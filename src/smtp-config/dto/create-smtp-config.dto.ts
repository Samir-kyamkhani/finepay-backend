import {
  IsString,
  IsEmail,
  IsNumber,
  IsBoolean,
  IsOptional,
  IsEnum,
} from 'class-validator';
import { SmtpProvider } from '../../../generated/prisma/enums';

export class CreateSmtpConfigDto {
  @IsEnum(SmtpProvider)
  provider: SmtpProvider;

  @IsString()
  host: string;

  @IsNumber()
  port: number;

  @IsBoolean()
  secure: boolean;

  @IsString()
  username: string;

  @IsString()
  password: string;

  @IsEmail()
  fromEmail: string;

  @IsEmail()
  @IsOptional()
  supportEmail?: string; // Made optional

  @IsString()
  @IsOptional()
  fromName?: string;
}

// Types for internal use
export type CreateSmtpConfigData = {
  provider: SmtpProvider;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromEmail: string;
  supportEmail?: string;
  fromName?: string;
  userId: string;
  passwordEnc: string;
};
