import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RootAuthService } from './services/root.auth.service';
import { UserAuthService } from './services/user.auth.service';
import { EmployeeAuthService } from './services/employee.auth.service';
import { RootAuthController } from './controllers/root.auth.controller';
import { ConfigService } from '@nestjs/config';
import { IdentityProvider } from './strategies/identity.provider';
import { UserAuthController } from './controllers/user.auth.controller';
import { AuditModule } from 'src/audit/audit.module';
import { PrismaService } from 'src/database/prisma-service';
import { AuthUtilsService } from 'src/common/utils/auth.utils';
import { EmailService } from 'src/email/email.service';
import { S3Service } from 'src/common/utils/s3.service';
import { AuditService } from 'src/audit/service/audit.service';

@Module({
  imports: [
    CacheModule.register({
      ttl: 5 * 60 * 1000,
      isGlobal: true,
    }),

    PassportModule.register({ defaultStrategy: 'jwt' }),

    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('security.jwtSecret'),
        signOptions: { expiresIn: '1h' },
      }),
    }),

    AuditModule,
  ],

  providers: [
    PrismaService,
    RootAuthService,
    UserAuthService,
    EmployeeAuthService,
    JwtStrategy,
    IdentityProvider,
    AuthUtilsService,
    EmailService,
    S3Service,
    AuditService,
  ],

  controllers: [RootAuthController, UserAuthController],

  exports: [
    RootAuthService,
    UserAuthService,
    EmployeeAuthService,
    JwtModule,
    AuthUtilsService,
  ],
})
export class AuthModule {}
