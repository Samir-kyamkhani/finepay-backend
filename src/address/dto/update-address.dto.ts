import { IsOptional, IsString, IsUUID, Length } from 'class-validator';

export class UpdateAddressDto {
  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  @Length(3, 10)
  pinCode?: string;

  @IsOptional()
  @IsUUID()
  stateId?: string;

  @IsOptional()
  @IsUUID()
  cityId?: string;
}
