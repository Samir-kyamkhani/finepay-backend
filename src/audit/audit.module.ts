import { Module } from '@nestjs/common';
import { AuditLogService } from './service/audit.service';

@Module({
  providers: [AuditLogService],
  exports: [AuditLogService],
})
export class AuditModule {}
