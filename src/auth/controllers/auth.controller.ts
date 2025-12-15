// src/auth/auth.controller.ts
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
  Req,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  MaxFileSizeValidator,
  FileTypeValidator,
  ParseFilePipe,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { LoginDto } from '../dto/login-auth.dto';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ success: true }> {
    const result = await this.authService.login(dto, req);

    // Set cookies based on actor type
    this.authService.setAuthCookies(
      res,
      result.tokens,
      result.actor.principalType,
    );

    return { success: true };
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  async refreshToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ success: true }> {
    const result = await this.authService.refreshToken(req);

    // Set cookies based on actor type
    this.authService.setAuthCookies(
      res,
      result.tokens,
      result.actor.principalType,
    );

    return { success: true };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: Request,
    @CurrentUser() user: AuthActor,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    if (!user) {
      throw new UnauthorizedException();
    }

    this.authService.clearAuthCookies(res, user.principalType);
    await this.authService.logout(user.id, user.principalType, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('request-password-reset')
  @HttpCode(HttpStatus.ACCEPTED)
  async requestPasswordReset(
    @CurrentUser() user: AuthActor,
    @Body() dto: ForgotPasswordDto,
  ): Promise<{ success: true; message: string }> {
    const result = await this.authService.requestPasswordReset(dto, user);
    return { success: true, message: result.message };
  }

  @UseGuards(JwtAuthGuard)
  @Post('confirm-password-reset')
  @HttpCode(HttpStatus.OK)
  async confirmPasswordReset(
    @CurrentUser() user: AuthActor,
    @Body() dto: ConfirmPasswordResetDto,
  ): Promise<{ success: true; message: string }> {
    const result = await this.authService.confirmPasswordReset(dto, user);
    return { success: true, message: result.message };
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard)
  @Get('me')
  async getMe(@CurrentUser() user: AuthActor) {
    if (!user) {
      throw new UnauthorizedException();
    }

    return this.authService.getCurrentUser(user.id, user.principalType);
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard, RolesGuard)
  @Roles('ROOT')
  @Get('dashboard')
  async getDashboard(@CurrentUser() user: AuthActor) {
    if (!user) {
      throw new UnauthorizedException();
    }

    return this.authService.getDashboard(user.id, user.principalType);
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard)
  @Patch('credentials')
  async updateCredentials(
    @CurrentUser() user: AuthActor,
    @Body() dto: UpdateCredentialsDto,
  ) {
    if (!user) {
      throw new UnauthorizedException();
    }

    return this.authService.updateCredentials(user.id, user.principalType, dto);
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard)
  @Patch('profile')
  async updateProfile(
    @CurrentUser() user: AuthActor,
    @Body() dto: UpdateProfileDto,
  ) {
    if (!user) {
      throw new UnauthorizedException();
    }

    return this.authService.updateProfile(user.id, user.principalType, dto);
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard)
  @Patch('profile-image')
  @UseInterceptors(FileInterceptor('profileImage'))
  async updateProfileImage(
    @Req() req: Request,
    @CurrentUser() user: AuthActor,
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),
          new FileTypeValidator({
            fileType: /^(image\/jpeg|image\/png|image\/webp)$/,
          }),
        ],
      }),
    )
    file: Express.Multer.File,
  ) {
    if (!user) {
      throw new UnauthorizedException();
    }

    if (!file) {
      throw new BadRequestException('profileImage file is required');
    }

    return this.authService.updateProfileImage(
      user.id,
      user.principalType,
      file,
      req,
    );
  }

  // Hierarchy-specific endpoints (only for USER actor type)
  @UseGuards(JwtAuthGuard, IpWhitelistGuard, RolesGuard)
  @Roles('ADMIN', 'STATE_HEAD', 'MASTER_DISTRIBUTOR', 'DISTRIBUTOR')
  @Get('downline')
  async getDownlineUsers(@CurrentUser() user: AuthActor) {
    if (!user || user.principalType !== 'USER') {
      throw new UnauthorizedException();
    }

    return await this.authService.getDownlineUsers(user.id);
  }

  @UseGuards(JwtAuthGuard, IpWhitelistGuard, RolesGuard)
  @Get('hierarchy-info')
  async getHierarchyInfo(@CurrentUser() user: AuthActor) {
    if (!user || user.principalType !== 'USER') {
      throw new UnauthorizedException();
    }

    return await this.authService.getHierarchyInfo(user.id);
  }
}
