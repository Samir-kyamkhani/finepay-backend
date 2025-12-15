import { Module } from '@nestjs/common';
import { AuditService } from './service/audit.service';

@Module({
  controllers: [],
  providers: [AuditService],
})
export class AuditModule {}
