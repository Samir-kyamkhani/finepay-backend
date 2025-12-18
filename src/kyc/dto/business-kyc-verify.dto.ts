import { IsEnum, IsString, ValidateIf } from 'class-validator';
import { KycStatus } from '../../common/enums/kyc.enum';

export class VerifyBusinessKycDto {
  @IsEnum(KycStatus)
  status: KycStatus;

  @ValidateIf(
    (o: VerifyBusinessKycDto) =>
      o.status === KycStatus.REJECTED || o.status === KycStatus.SUSPENDED,
  )
  @IsString()
  actionReason?: string;
}
