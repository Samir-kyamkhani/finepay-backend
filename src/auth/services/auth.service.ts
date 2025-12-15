// src/auth/auth.service.ts
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response, CookieOptions } from 'express';

import { AuthUtilsService } from './helper/auth-utils';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly accessTokenCookieOptions: CookieOptions;
  private readonly refreshTokenCookieOptions: CookieOptions;

  private static readonly ACCESS_TOKEN_COOKIE_NAME = 'access_token';
  private static readonly REFRESH_TOKEN_COOKIE_NAME = 'refresh_token';

  constructor(
    private readonly configService: ConfigService,
    private readonly authUtils: AuthUtilsService,
    private readonly tokenService: TokenService,
    private readonly rootResolver: RootAuthResolver,
    private readonly userResolver: UserAuthResolver,
    private readonly employeeResolver: EmployeeAuthResolver,
  ) {
    const isProd = this.configService.get<string>('NODE_ENV') === 'production';

    const baseCookieOptions: CookieOptions = {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      path: '/',
    };

    this.accessTokenCookieOptions = {
      ...baseCookieOptions,
      maxAge: 1000 * 60 * 60 * 24 * 1, // 1 day
    };

    this.refreshTokenCookieOptions = {
      ...baseCookieOptions,
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    };
  }

  // Cookie management methods
  setAuthCookies(res: Response, tokens: TokenPair, actorType: string): void {
    res.cookie(
      AuthService.ACCESS_TOKEN_COOKIE_NAME,
      tokens.accessToken,
      this.accessTokenCookieOptions,
    );

    res.cookie(
      AuthService.REFRESH_TOKEN_COOKIE_NAME,
      tokens.refreshToken,
      this.refreshTokenCookieOptions,
    );
  }

  clearAuthCookies(res: Response, actorType: string): void {
    res.clearCookie(AuthService.ACCESS_TOKEN_COOKIE_NAME, {
      path: '/',
    });

    res.clearCookie(AuthService.REFRESH_TOKEN_COOKIE_NAME, {
      path: '/',
    });
  }

  // Main authentication methods
  async login(dto: LoginDto, req: Request): Promise<any> {
    let result;

    // Determine actor type and delegate to appropriate resolver
    if (dto.email.includes('@admin.')) {
      // Root user login
      result = await this.rootResolver.login(dto, req);
    } else if (dto.customerId) {
      // Business user login with customerId
      result = await this.userResolver.login(dto, req);
    } else {
      // Try employee login
      try {
        result = await this.employeeResolver.login(dto, req);
      } catch (error) {
        // Fallback to user login
        result = await this.userResolver.login(dto, req);
      }
    }

    return result;
  }

  async refreshToken(req: Request): Promise<any> {
    const refreshToken = req.cookies?.[AuthService.REFRESH_TOKEN_COOKIE_NAME];

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is missing');
    }

    // Verify and extract payload from token
    const payload = this.tokenService.verifyRefreshToken(refreshToken);
    if (!payload) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Delegate to appropriate resolver based on actor type
    switch (payload.actorType) {
      case 'ROOT':
        return await this.rootResolver.refreshToken(refreshToken, req);
      case 'USER':
        return await this.userResolver.refreshToken(refreshToken, req);
      case 'EMPLOYEE':
        return await this.employeeResolver.refreshToken(refreshToken, req);
      default:
        throw new UnauthorizedException('Invalid actor type');
    }
  }

  async logout(
    actorId: string,
    actorType: string,
    req?: Request,
  ): Promise<void> {
    switch (actorType) {
      case 'ROOT':
        await this.rootResolver.logout(actorId, req);
        break;
      case 'USER':
        await this.userResolver.logout(actorId, req);
        break;
      case 'EMPLOYEE':
        await this.employeeResolver.logout(actorId);
        break;
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async requestPasswordReset(
    dto: ForgotPasswordDto,
    currentUser: AuthActor,
  ): Promise<any> {
    switch (currentUser.principalType) {
      case 'ROOT':
        return await this.rootResolver.requestPasswordReset(dto, currentUser);
      case 'USER':
        return await this.userResolver.requestPasswordReset(dto, currentUser);
      case 'EMPLOYEE':
        return await this.employeeResolver.requestPasswordReset(dto);
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async confirmPasswordReset(
    dto: ConfirmPasswordResetDto,
    currentUser: AuthActor,
  ): Promise<any> {
    switch (currentUser.principalType) {
      case 'ROOT':
        return await this.rootResolver.confirmPasswordReset(dto, currentUser);
      case 'USER':
        return await this.userResolver.confirmPasswordReset(dto, currentUser);
      case 'EMPLOYEE':
        return await this.employeeResolver.confirmPasswordReset(dto);
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async getCurrentUser(actorId: string, actorType: string): Promise<any> {
    switch (actorType) {
      case 'ROOT':
        return await this.rootResolver.getCurrentUser(actorId);
      case 'USER':
        return await this.userResolver.getCurrentUser(actorId);
      case 'EMPLOYEE':
        return await this.employeeResolver.getCurrentUser(actorId);
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async getDashboard(actorId: string, actorType: string): Promise<any> {
    switch (actorType) {
      case 'ROOT':
        return await this.rootResolver.getDashboard(actorId);
      case 'USER':
        return await this.userResolver.getDashboard(actorId);
      case 'EMPLOYEE':
        throw new ForbiddenException('Dashboard not available for employees');
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async updateCredentials(
    actorId: string,
    actorType: string,
    dto: UpdateCredentialsDto,
  ): Promise<any> {
    switch (actorType) {
      case 'ROOT':
        return await this.rootResolver.updateCredentials(actorId, dto);
      case 'USER':
        return await this.userResolver.updateCredentials(actorId, dto);
      case 'EMPLOYEE':
        return await this.employeeResolver.updateCredentials(actorId, dto);
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async updateProfile(
    actorId: string,
    actorType: string,
    dto: UpdateProfileDto,
  ): Promise<any> {
    switch (actorType) {
      case 'ROOT':
        return await this.rootResolver.updateProfile(actorId, dto);
      case 'USER':
        return await this.userResolver.updateProfile(actorId, dto);
      case 'EMPLOYEE':
        return await this.employeeResolver.updateProfile(actorId, dto);
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  async updateProfileImage(
    actorId: string,
    actorType: string,
    file: Express.Multer.File,
    req?: Request,
  ): Promise<any> {
    switch (actorType) {
      case 'ROOT':
        return await this.rootResolver.updateProfileImage(actorId, file, req);
      case 'USER':
        return await this.userResolver.updateProfileImage(actorId, file, req);
      case 'EMPLOYEE':
        // Employee profile image update not implemented in original
        throw new ForbiddenException(
          'Profile image update not available for employees',
        );
      default:
        throw new BadRequestException('Invalid actor type');
    }
  }

  // Hierarchy methods (USER actor only)
  async getDownlineUsers(userId: string): Promise<any> {
    return await this.userResolver.getDownlineUsers(userId);
  }

  async getHierarchyInfo(userId: string): Promise<any> {
    return await this.userResolver.getHierarchyInfo(userId);
  }

  async validateHierarchyAccess(
    requesterId: string,
    targetId: string,
  ): Promise<boolean> {
    return await this.userResolver.validateHierarchyAccess(
      requesterId,
      targetId,
    );
  }
}
