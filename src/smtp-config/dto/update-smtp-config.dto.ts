import { PartialType } from '@nestjs/mapped-types';
import { CreateSmtpConfigDto } from './create-smtp-config.dto';
import { IsOptional, IsBoolean } from 'class-validator';
import { SmtpProvider } from '../../../generated/prisma/enums';

export class UpdateSmtpConfigDto extends PartialType(CreateSmtpConfigDto) {
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

// Types for internal use
export type UpdateSmtpConfigData = Partial<{
  provider: SmtpProvider;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromEmail: string;
  supportEmail?: string;
  fromName?: string;
  isActive?: boolean;
}>;
