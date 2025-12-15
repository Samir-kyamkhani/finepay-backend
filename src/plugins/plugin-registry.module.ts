import { Module } from '@nestjs/common';
import { DmtModule } from './dmt/dmt.module';

@Module({
  imports: [DmtModule],
  controllers: [],
  providers: [],
})
export class LedgerModule {}
