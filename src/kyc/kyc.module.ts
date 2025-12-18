import { Module } from '@nestjs/common';
import { UserKYCController } from './controllers/user-kyc.controller';
import { BusinessKYCController } from './controllers/business-kyc.controller';
import { UserKycService } from './services/user-kyc.service';
import { BusinessKycService } from './services/business-kyc.service';
import { PrismaService } from '../database/prisma-service';
import { AddressModule } from '../address/address.module';
import { PiiConsentModule } from '../pii-consent/pii-consent.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AddressModule, PiiConsentModule, AuditModule],
  controllers: [UserKYCController, BusinessKYCController],
  providers: [UserKycService, BusinessKycService, PrismaService],
  exports: [UserKycService, BusinessKycService],
})
export class KycModule {}
