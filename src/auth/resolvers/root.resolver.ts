import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';
import { ForgotPasswordDto } from '../dto/forgot-password-auth.dto';
import { ConfirmPasswordResetDto } from '../dto/confirm-password-reset-auth.dto';
import { UpdateCredentialsDto } from '../dto/update-credentials-auth.dto';
import { UpdateProfileDto } from '../dto/update-profile-auth.dto';
import { AuthActor } from '../../common/types/auth.type';
import { AuthUtilsService } from '../../common/utils/auth.utils';
import { randomBytes } from 'node:crypto';
import { LoginDto } from '../dto/login-auth.dto';
import type { Request } from 'express';
import { AuditStatus } from '../../common/enums/audit.enum';
import { S3Service } from '../../common/utils/s3.service';
import { ConfigService } from '@nestjs/config';
import { EmailService } from '../../email/email.service';
import { Prisma } from '../../../generated/prisma/client';
import { FileDeleteHelper } from '../../common/utils/file.delete.utils';

@Injectable()
export class RootResolver {
  private logger = new Logger(RootResolver.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly authUtils: AuthUtilsService,
    private readonly emailService: EmailService,
    private readonly s3: S3Service,
    private readonly configService: ConfigService,
  ) {}

  private async logAuthEvent(params: {
    performerId: string | null;
    action: string;
    status: AuditStatus;
    req?: Request;
    metadata?: Prisma.InputJsonValue;
  }) {
    const { performerId, action, status, metadata, req } = params;

    await this.authUtils.createAuthAuditLog({
      performerType: 'ROOT',
      performerId: performerId,
      action,
      status,
      ipAddress: req ? this.authUtils.getClientIp(req) : null,
      userAgent: req ? this.authUtils.getClientUserAgent(req) : null,
      metadata: metadata || {},
    });
  }

  async login(dto: LoginDto, req: Request) {
    const root = await this.prisma.root.findFirst({
      where: { email: dto.email },
      include: {
        role: { select: { name: true } },
      },
    });

    const ip = this.authUtils.getClientIp(req);
    const origin = this.authUtils.getClientOrigin(req);

    if (!root || root.deletedAt || root.status !== 'ACTIVE') {
      await this.logAuthEvent({
        performerId: root?.id ?? null,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: { reason: 'USER_NOT_FOUND_OR_INACTIVE', email: dto.email },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // 🔥 Password verify
    if (!this.authUtils.verifyPassword(dto.password, root.password)) {
      await this.logAuthEvent({
        performerId: root.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: { reason: 'INVALID_PASSWORD', email: dto.email },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // 🔥 Actor + tokens
    const actor: AuthActor = this.authUtils.createActor({
      id: root.id,
      roleId: root.roleId,
      principalType: 'ROOT',
      isRoot: true,
    });

    const tokens = this.authUtils.generateTokens(actor);

    // 🔐 Refresh token should be hashed before saving!
    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.root.update({
      where: { id: root.id },
      data: {
        refreshToken: hashedRefresh,
        lastLoginAt: new Date(),
        lastLoginIp: ip,
        lastLoginOrigin: origin,
      },
    });

    await this.logAuthEvent({
      performerId: root.id,
      action: 'LOGIN_SUCCESS',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { origin },
    });

    return {
      user: this.authUtils.stripSensitive(root, [
        'password',
        'refreshToken',
        'passwordResetToken',
      ]),
      actor,
      tokens,
    };
  }

  async logout(rootId: string, req: Request) {
    await this.prisma.root.update({
      where: { id: rootId },
      data: { refreshToken: null },
    });

    await this.logAuthEvent({
      performerId: rootId,
      action: 'LOGOUT',
      status: AuditStatus.SUCCESS,
      req,
    });

    return { message: 'Logged out successfully' };
  }

  async refreshToken(rawToken: string, req: Request) {
    const payload = this.authUtils.verifyJwt(rawToken);

    if (!payload || payload.principalType !== 'ROOT') {
      throw new UnauthorizedException('Invalid token');
    }

    const root = await this.prisma.root.findUnique({
      where: { id: payload.sub },
    });

    if (!root || !this.authUtils.verifyPassword(rawToken, root.refreshToken!)) {
      await this.logAuthEvent({
        performerId: payload.sub,
        action: 'REFRESH_TOKEN_INVALID',
        status: AuditStatus.FAILED,
        req,
      });

      throw new UnauthorizedException('Invalid refresh token');
    }

    const actor = this.authUtils.createActor({
      id: root.id,
      principalType: 'ROOT',
      roleId: root.roleId,
      isRoot: true,
    });

    const tokens = this.authUtils.generateTokens(actor);

    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.root.update({
      where: { id: root.id },
      data: { refreshToken: hashedRefresh },
    });

    await this.logAuthEvent({
      performerId: root.id,
      action: 'REFRESH_TOKEN_SUCCESS',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      user: this.authUtils.stripSensitive(root, [
        'password',
        'refreshToken',
        'passwordResetToken',
      ]),
      actor,
      tokens,
    };
  }

  async requestPasswordReset(
    dto: ForgotPasswordDto,
    currentUser: AuthActor,
    req?: Request,
  ) {
    const authenticatedUser = await this.prisma.root.findUnique({
      where: { id: currentUser.id },
    });

    if (!authenticatedUser) {
      throw new UnauthorizedException('User not found');
    }

    if (authenticatedUser.email !== dto.email) {
      await this.logAuthEvent({
        performerId: currentUser.id,
        action: 'PASSWORD_RESET_REQUEST_FAILED',
        status: AuditStatus.FAILED,
        metadata: {
          details: `Attempted to reset password for email: ${dto.email}`,
        },
        req,
      });

      throw new ForbiddenException('You can only reset your own password');
    }

    const root = await this.prisma.root.findUnique({
      where: { email: dto.email },
    });

    if (!root) {
      return { message: 'If account exists, password reset email sent.' };
    }

    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = this.authUtils.hashResetToken(rawToken);

    await this.prisma.root.update({
      where: { id: root.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: new Date(Date.now() + 3 * 60 * 1000),
      },
    });

    await this.emailService.sendPasswordResetEmail({
      firstName: root.firstName,
      supportEmail: root.email,
      resetUrl: `${this.configService.get<string>('security.resetPasswordBaseUrl')}?token=${rawToken}`,
      expiryMinutes: 3,
    });

    await this.logAuthEvent({
      performerId: root.id,
      action: 'PASSWORD_RESET_REQUESTED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return { message: 'If account exists, password reset email sent.' };
  }

  async confirmPasswordReset(
    dto: ConfirmPasswordResetDto,
    currentUser?: AuthActor,
    req?: Request,
  ) {
    const hashedToken = this.authUtils.hashResetToken(dto.token);

    const root = await this.prisma.root.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() },
      },
    });

    if (!root) {
      await this.logAuthEvent({
        performerId: null,
        action: 'PASSWORD_RESET_FAILED',
        status: AuditStatus.FAILED,
        req,
      });
      throw new BadRequestException('Invalid or expired token');
    }

    if (currentUser && root.id !== currentUser.id) {
      throw new ForbiddenException('You can only reset your own password');
    }

    const newPasswordPlain = this.authUtils.generateRandomPassword();
    const newHashed = this.authUtils.hashPassword(newPasswordPlain);

    await this.prisma.root.update({
      where: { id: root.id },
      data: {
        password: newHashed,
        refreshToken: null,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    await this.emailService.sendRootUserCredentialsEmail({
      firstName: root.firstName,
      username: root.username,
      email: root.email,
      password: newPasswordPlain,
      actionType: 'reset',
    });

    await this.logAuthEvent({
      performerId: root.id,
      action: 'PASSWORD_RESET_CONFIRMED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return { message: 'Password reset successful. New password sent.' };
  }

  async getCurrentUser(rootId: string) {
    const root = await this.prisma.root.findUnique({
      where: { id: rootId },
      include: { role: true },
    });

    if (!root) throw new NotFoundException('Root user not found');

    return this.authUtils.stripSensitive(root, [
      'password',
      'refreshToken',
      'passwordResetToken',
    ]);
  }

  async getDashboard(rootId: string, req?: Request) {
    const [admins, users, employees] = await Promise.all([
      this.prisma.user.count({
        where: { rootParentId: rootId, role: { name: 'ADMIN' } },
      }),
      this.prisma.user.count({
        where: { rootParentId: rootId, role: { NOT: { name: 'ADMIN' } } },
      }),
      this.prisma.employee.count({
        where: { createdByRootId: rootId },
      }),
    ]);

    await this.logAuthEvent({
      performerId: rootId,
      action: 'DASHBOARD_ACCESSED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      totalAdmins: admins,
      totalBusinessUsers: users,
      totalEmployees: employees,
    };
  }

  async updateCredentials(
    rootId: string,
    dto: UpdateCredentialsDto,
    req?: Request,
  ) {
    const root = await this.prisma.root.findUnique({
      where: { id: rootId },
    });

    if (!root) throw new NotFoundException('Root user not found');

    if (!dto.newPassword || !dto.currentPassword) {
      throw new BadRequestException('Current & new password required');
    }

    if (!this.authUtils.verifyPassword(dto.currentPassword, root.password)) {
      throw new UnauthorizedException('Invalid current password');
    }

    const newHashed = this.authUtils.hashPassword(dto.newPassword);

    await this.prisma.root.update({
      where: { id: root.id },
      data: {
        password: newHashed,
        refreshToken: null, // logout from all devices
      },
    });

    await this.logAuthEvent({
      performerId: rootId,
      action: 'CREDENTIALS_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { updatedFields: ['password'] },
    });

    return { message: 'Credentials updated successfully' };
  }

  async updateProfile(rootId: string, dto: UpdateProfileDto, req?: Request) {
    const root = await this.prisma.root.findUnique({
      where: { id: rootId },
    });

    if (!root) throw new NotFoundException('Root user not found');

    const data = {
      firstName: dto.firstName ?? root.firstName,
      lastName: dto.lastName ?? root.lastName,
      username: dto.username ?? root.username,
      phoneNumber: dto.phoneNumber ?? root.phoneNumber,
      email: dto.email ?? root.email,
    };

    await this.prisma.root.update({ where: { id: rootId }, data });

    await this.logAuthEvent({
      performerId: rootId,
      action: 'PROFILE_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { updatedFields: Object.keys(data) },
    });

    return this.getCurrentUser(rootId);
  }

  async updateProfileImage(
    rootId: string,
    file: Express.Multer.File,
    req?: Request,
  ) {
    if (!file) throw new BadRequestException('Profile image required');

    const root = await this.prisma.root.findUnique({
      where: { id: rootId },
    });

    if (!root) throw new NotFoundException('Root user not found');

    const oldImage = root.profileImage;

    const uploadedUrl = await this.s3.uploadBuffer(file, 'root-profile-images');

    if (!uploadedUrl) throw new BadRequestException('Upload failed');

    if (oldImage) {
      await this.s3.delete({ fileUrl: oldImage }).catch(() => null);
    }

    await this.prisma.root.update({
      where: { id: rootId },
      data: { profileImage: uploadedUrl },
    });

    FileDeleteHelper.deleteUploadedImages(file);

    await this.logAuthEvent({
      performerId: rootId,
      action: 'PROFILE_IMAGE_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { oldImageDeleted: !!oldImage },
    });

    return this.getCurrentUser(rootId);
  }
}
