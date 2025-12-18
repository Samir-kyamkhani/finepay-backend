import { Module } from '@nestjs/common';
import { PiiConsentService } from './service/pii-consent.service.js';
import { PrismaService } from '../database/prisma-service.js';
import { AuditModule } from '../audit/audit.module.js';

@Module({
  imports: [AuditModule],
  providers: [PiiConsentService, PrismaService],
  exports: [PiiConsentService],
})
export class PiiConsentModule {}
