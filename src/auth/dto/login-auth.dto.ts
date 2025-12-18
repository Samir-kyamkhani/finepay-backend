import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { CreatorType } from '../../../generated/prisma/enums';

export class LoginDto {
  @IsEmail()
  @MinLength(1)
  @MaxLength(255)
  email: string;

  @IsString()
  @MinLength(1)
  @MaxLength(255)
  password: string;

  @IsEnum(['USER', 'EMPLOYEE'])
  actorType: 'USER' | 'EMPLOYEE';

  @IsOptional()
  latitude?: number;

  @IsOptional()
  longitude?: number;

  @IsOptional()
  accuracy?: number;
}

export class SignupDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(8)
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsString()
  @IsNotEmpty()
  phoneNumber: string;

  @IsString()
  @IsOptional()
  parentId?: string;

  @IsString()
  @IsOptional()
  businessId?: string;

  @IsEnum(CreatorType)
  @IsOptional()
  userType?: CreatorType = CreatorType.USER;

  @IsString()
  @IsOptional()
  roleId?: string;

  @IsString()
  @Matches(/^\d{4,6}$/, {
    message: 'Transaction PIN must be 4-6 digits',
  })
  @IsOptional()
  transactionPin?: string;
}
