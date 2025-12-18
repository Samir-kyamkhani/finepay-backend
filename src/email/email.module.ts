import { Module } from '@nestjs/common';
import { EmailService } from './email.service';
import EmailTemplates from './email-templates';

@Module({
  providers: [EmailService, EmailTemplates],
  exports: [EmailService, EmailTemplates],
})
export class EmailModule {}
