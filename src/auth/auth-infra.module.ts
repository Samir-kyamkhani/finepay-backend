import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { JwtStrategy } from '../common/strategies/jwt.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),

    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('security.jwtSecret'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  providers: [JwtStrategy],
  exports: [PassportModule, JwtModule, JwtStrategy],
})
export class AuthInfraModule {}
