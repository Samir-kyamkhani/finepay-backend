import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { IdentityProvider } from './identity.provider';
import { JwtPayload, SessionUser } from '../types/auth.type';
import { cookieJwtExtractor } from '../utils/jwt-cookie.extractor';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    configService: ConfigService,
    private readonly identityProvider: IdentityProvider,
  ) {
    const jwtSecret = configService.get<string>('security.jwtSecret');

    if (!jwtSecret) {
      throw new Error(
        'Missing JWT secret in configuration: security.jwtSecret',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        cookieJwtExtractor,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(payload: JwtPayload): Promise<SessionUser> {
    return this.identityProvider.getActorFromPayload(payload);
  }
}
