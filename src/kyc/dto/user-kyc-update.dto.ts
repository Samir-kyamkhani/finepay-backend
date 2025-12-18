import { IsOptional, IsString, IsDateString, IsEnum } from 'class-validator';
import { RoleType, UserGender } from '../../common/enums/kyc.enum';

export class UpdateUserKycDto {
  @IsString()
  id: string;

  @IsOptional() @IsString() firstName?: string;
  @IsOptional() @IsString() lastName?: string;
  @IsOptional() @IsString() fatherName?: string;

  @IsOptional()
  @IsDateString()
  dob?: string;

  @IsOptional()
  @IsEnum(UserGender)
  gender?: UserGender;

  @IsOptional()
  @IsEnum(RoleType)
  roleType?: RoleType;

  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  pinCode?: string;

  @IsOptional()
  @IsString()
  cityId?: string;

  @IsOptional()
  @IsString()
  stateId?: string;

  @IsOptional()
  @IsString()
  pan?: string;

  @IsOptional()
  @IsString()
  aadhaar?: string;
}
