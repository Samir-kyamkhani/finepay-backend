import {
  IsString,
  IsDateString,
  IsEnum,
  Matches,
  Length,
  IsOptional,
} from 'class-validator';
import { RoleType, UserGender } from '../../common/enums/kyc.enum';

export class CreateUserKycDto {
  @IsString()
  firstName: string;

  @IsString()
  lastName: string;

  @IsString()
  fatherName: string;

  @IsDateString()
  dob: string;

  @IsEnum(UserGender)
  gender: UserGender;

  @IsString()
  address: string;

  @IsString()
  pinCode: string;

  @IsString()
  cityId: string;

  @IsString()
  stateId: string;

  @IsOptional()
  @IsString()
  businessKycId?: string;

  @IsOptional()
  @IsEnum(RoleType)
  roleType?: RoleType;

  @Matches(/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/)
  pan: string;

  @Length(12, 12)
  aadhaar: string;
}
