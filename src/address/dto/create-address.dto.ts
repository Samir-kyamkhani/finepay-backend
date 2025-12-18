import { IsNotEmpty, IsString, IsUUID, Length } from 'class-validator';

export class CreateAddressDto {
  @IsString()
  @IsNotEmpty()
  address: string;

  @IsString()
  @Length(3, 10)
  pinCode: string;

  @IsUUID()
  stateId: string;

  @IsUUID()
  cityId: string;
}
