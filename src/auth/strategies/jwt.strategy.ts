import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

import { JwtPayload, AuthActor } from '../interface/auth.interface'
import { IdentityProvider } from './identity.provider'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
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
        (req: Request) => req?.cookies?.access_token ?? null,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      passReqToCallback: false,
    });
  }

  async validate(payload: JwtPayload): Promise<AuthActor> {
    if (!payload) {
      throw new UnauthorizedException('Empty JWT payload');
    }

    return await this.identityProvider.getActorFromPayload(payload);
  }
}
