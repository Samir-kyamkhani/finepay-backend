import { Module } from '@nestjs/common';
import { AddressService } from './address.service';
import { CityService } from './city.service';
import { StateService } from './state.service';
import { PrismaService } from '../database/prisma-service';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AuditModule],
  providers: [AddressService, CityService, StateService, PrismaService],
  exports: [AddressService, CityService, StateService],
})
export class AddressModule {}
