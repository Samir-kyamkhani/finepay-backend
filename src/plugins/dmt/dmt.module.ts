import { Module } from '@nestjs/common';
import { DmtService } from './dmt.service';
import { DmtController } from './dmt.controller';

@Module({
  controllers: [DmtController],
  providers: [DmtService],
})
export class DmtModule {}
