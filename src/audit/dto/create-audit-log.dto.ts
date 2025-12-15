import { IsString, IsOptional, IsEnum, IsObject, IsIP } from 'class-validator';
import { Prisma } from 'generated/prisma/client';
import { AuditStatus } from 'src/common/enums/audit.enum';

export class CreateAuditLogDto {
  performerType: string;

  @IsString()
  performerId: string;

  targetUserType: string;

  @IsString()
  targetUserId: string;

  @IsString()
  action: string;

  @IsString()
  description: string;

  @IsString()
  resourceType: string;

  @IsString()
  resourceId: string;

  @IsOptional()
  @IsObject()
  oldData?: Record<string, any>;

  @IsOptional()
  @IsObject()
  newData?: Record<string, any>;

  @IsEnum(AuditStatus)
  status: AuditStatus;

  @IsOptional()
  @IsString()
  @IsIP()
  ipAddress?: string;

  @IsOptional()
  @IsString()
  userAgent?: string;

  @IsOptional()
  @IsObject()
  metadata?: Prisma.InputJsonValue;
}
