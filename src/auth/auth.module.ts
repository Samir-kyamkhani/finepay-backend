import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { AuthService } from './services/auth.service';
import { RootResolver } from './resolvers/root.resolver';
import { EmployeeResolver } from './resolvers/employee.resolver';
import { IdentityProvider } from '../common/strategies/identity.provider';
import { AuthUtilsService } from '../common/utils/auth.utils';
import { AuthController } from './controllers/auth.controller';
import { EmailModule } from '../email/email.module';
import { UserAuthResolver } from './resolvers/user.resolver';
import { PrismaModule } from '../database/prisma.module';
import { AuthInfraModule } from './auth-infra.module';

@Module({
  imports: [AuthInfraModule, AuditModule, EmailModule, PrismaModule],

  providers: [
    AuthService,
    IdentityProvider,
    AuthUtilsService,
    RootResolver,
    UserAuthResolver,
    EmployeeResolver,
  ],

  controllers: [AuthController],

  exports: [AuthUtilsService],
})
export class AuthModule {}
