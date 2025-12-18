import { Module } from '@nestjs/common';
import { SystemService } from './services/system.service';
import { SystemController } from './system.controller';
import { AuditModule } from '../audit/audit.module';
import { PrismaService } from '../database/prisma-service';

@Module({
  imports: [AuditModule],
  controllers: [SystemController],
  providers: [SystemService, PrismaService],
  exports: [SystemService],
})
export class SystemModule {}
