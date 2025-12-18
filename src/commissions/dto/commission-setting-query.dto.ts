import { IsEnum, IsOptional, IsUUID, IsBoolean } from 'class-validator';
import { CommissionScope } from '../../../generated/prisma/enums';

export class CommissionSettingQueryDto {
  @IsOptional()
  @IsEnum(CommissionScope)
  scope?: CommissionScope;

  @IsOptional()
  @IsUUID()
  roleId?: string;

  @IsOptional()
  @IsUUID()
  targetUserId?: string;

  @IsOptional()
  @IsUUID()
  serviceId?: string;

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  page?: number;

  @IsOptional()
  limit?: number;
}
