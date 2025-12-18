// create-commission-setting.dto.ts
import {
  IsEnum,
  IsOptional,
  IsUUID,
  IsBoolean,
  IsNumber,
  IsDateString,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  CommissionScope,
  CommissionType,
  CreatorType,
} from '../../../generated/prisma/enums';

export class CreateCommissionSettingDto {
  // ===== SCOPE =====
  @IsEnum(CommissionScope)
  scope: CommissionScope;

  @IsOptional()
  @IsUUID()
  roleId?: string;

  @IsOptional()
  @IsUUID()
  targetUserId?: string;

  @IsOptional()
  @IsUUID()
  serviceId?: string;

  // ===== COMMISSION (CREDIT) =====
  @IsOptional()
  @IsEnum(CommissionType)
  commissionType?: CommissionType;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  commissionValue?: number;

  // ===== SURCHARGE (DEBIT) =====
  @IsOptional()
  @IsEnum(CommissionType)
  surchargeType?: CommissionType;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  surchargeValue?: number;

  // ===== SLABS =====
  @IsOptional()
  @Type(() => Number)
  minAmount?: number;

  @IsOptional()
  @Type(() => Number)
  maxAmount?: number;

  // ===== TAX =====
  @IsOptional()
  @IsBoolean()
  applyTDS?: boolean;

  @IsOptional()
  @Type(() => Number)
  tdsPercent?: number;

  @IsOptional()
  @IsBoolean()
  applyGST?: boolean;

  @IsOptional()
  @Type(() => Number)
  gstPercent?: number;

  // ===== STATUS =====
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  @IsDateString()
  effectiveFrom?: string;

  @IsOptional()
  @IsDateString()
  effectiveTo?: string;

  // ===== AUDIT =====
  @IsEnum(CreatorType)
  createdByType: CreatorType;

  @IsOptional()
  @IsUUID()
  createdByUserId?: string;

  @IsOptional()
  @IsUUID()
  createdByRootId?: string;

  @IsOptional()
  @IsUUID()
  createdByEmployeeId?: string;
}
