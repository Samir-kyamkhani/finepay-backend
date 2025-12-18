import { IsEnum, IsOptional, IsString } from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { KycStatus, SortOrder } from '../../common/enums/kyc.enum';

export class BusinessKycQueryDto {
  @IsOptional()
  @IsEnum(KycStatus)
  status?: KycStatus;

  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @Type(() => Number)
  @Transform(({ value }) => Number(value))
  page = 1;

  @IsOptional()
  @Type(() => Number)
  @Transform(({ value }) => Number(value))
  limit = 10;

  @IsOptional()
  @IsEnum(SortOrder)
  sort: SortOrder = SortOrder.DESC;
}
