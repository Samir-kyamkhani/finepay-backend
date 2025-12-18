import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { AclModule } from './acl/acl.module';
import { RootsModule } from './roots/roots.module';
import { UsersModule } from './users/users.module';
import { EmployeesModule } from './employees/employees.module';
import { KycModule } from './kyc/kyc.module';
import { SystemModule } from './system/system.module';
import { IntegrationsModule } from './integrations/integrations.module';
import { WebhooksModule } from './webhooks/webhooks.module';
import { AuditModule } from './audit/audit.module';
import { WalletsModule } from './wallets/wallets.module';
import { LedgerModule } from './ledger/ledger.module';
import { TransactionsModule } from './transactions/transactions.module';
import { CommissionsModule } from './commissions/commissions.module';
import { HealthController } from './health/health.controller';
import { HealthService } from './health/health.service';
import { EmailModule } from './email/email.module';
import { SmtpConfigModule } from './smtp-config/smtp-config.module';

@Module({
  imports: [
    AuthModule,
    AclModule,
    RootsModule,
    UsersModule,
    EmployeesModule,
    KycModule,
    SystemModule,
    IntegrationsModule,
    WebhooksModule,
    AuditModule,
    WalletsModule,
    LedgerModule,
    TransactionsModule,
    CommissionsModule,
    EmailModule,
    SmtpConfigModule,
  ],
  controllers: [HealthController],
  providers: [HealthService],
})
export class AppModule {}
