import { IsEnum, IsString, ValidateIf } from 'class-validator';
import { KycStatus } from '../../common/enums/kyc.enum';

export class VerifyUserKycDto {
  @IsEnum(KycStatus)
  status: KycStatus;

  @ValidateIf((o: VerifyUserKycDto) => o.status === KycStatus.REJECTED)
  @IsString()
  actionReason?: string;
}
