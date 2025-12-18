import { UserKycStatus } from '../../../generated/prisma';

export class GetAllUserKycDto {
  page?: number;
  limit?: number;
  search?: string; // name, phone, email, customerId
  status?: UserKycStatus;
}
