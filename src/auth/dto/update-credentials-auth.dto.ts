import {
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  Matches,
  ValidateIf,
  IsUUID,
} from 'class-validator';

export class UpdateCredentialsParamsDto {
  @IsUUID('4')
  userId: string;
}

export class UpdateCredentialsDto {
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  currentPassword: string;

  @IsOptional()
  @IsString()
  @MinLength(8)
  @MaxLength(255)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain uppercase, lowercase, number, and special character',
  })
  newPassword?: string;

  @ValidateIf((o: UpdateCredentialsDto) => !!o.newPassword)
  @IsString()
  confirmNewPassword?: string;

  @IsOptional()
  @Matches(/^\d{4,6}$/, {
    message: 'Current transaction PIN must be 4–6 digits',
  })
  currentTransactionPin?: string;

  @IsOptional()
  @Matches(/^\d{4,6}$/, {
    message: 'New transaction PIN must be 4–6 digits',
  })
  newTransactionPin?: string;

  @ValidateIf((o: UpdateCredentialsDto) => !!o.newTransactionPin)
  @IsString()
  confirmNewTransactionPin?: string;
}
