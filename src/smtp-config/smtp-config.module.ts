import { Module } from '@nestjs/common';
import { SmtpConfigService } from './smtp-config.service';
import { SmtpConfigController } from './smtp-config.controller';

@Module({
  controllers: [SmtpConfigController],
  providers: [SmtpConfigService],
})
export class SmtpConfigModule {}
