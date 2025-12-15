// src/auth/resolvers/user-auth.resolver.ts
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import type { Request } from 'express';

import { PrismaService } from '../../database/database.connection';
import { AuthUtilsService } from '../helper/auth-utils';
import { EmailService } from '../email/email.service';
import { S3Service } from '../../utils/s3/s3.service';
import { IpWhitelistService } from '../../common/ip-whitelist/service/ip-whitelist.service';
import { FileDeleteHelper } from '../../utils/helper/file-delete-helper.service';
import { ConfigService } from '@nestjs/config';
import { TokenService } from '../token.service';

import { LoginDto } from '../dto/login-auth.dto';
import { ForgotPasswordDto } from '../dto/forgot-password-auth.dto';
import { ConfirmPasswordResetDto } from '../dto/confirm-password-reset-auth.dto';
import { UpdateCredentialsDto } from '../dto/update-credentials-auth.dto';
import { UpdateProfileDto } from '../dto/update-profile-auth.dto';

import type { AuthActor } from '../interface/auth.interface';
import { randomBytes } from 'node:crypto';

@Injectable()
export class UserAuthResolver {
  private logger = new Logger(UserAuthResolver.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly authUtils: AuthUtilsService,
    private readonly tokenService: TokenService,
    private readonly emailService: EmailService,
    private readonly s3: S3Service,
    private readonly ipWhitelistService: IpWhitelistService,
    private readonly configService: ConfigService,
  ) {}

  private toSafeUser(user: any) {
    return this.authUtils.stripSensitive(user, [
      'password',
      'refreshToken',
      'passwordResetToken',
      'transactionPin',
      'transactionPinSalt',
    ]);
  }

  private async logAuthEvent(params: {
    performerId: string | null;
    action: string;
    status: string;
    req?: Request;
    metadata?: any;
  }) {
    const { performerId, action, status, metadata, req } = params;

    await this.authUtils.createAuthAuditLog({
      performerType: 'USER',
      performerId: performerId,
      action,
      status,
      ipAddress: req ? this.authUtils.getClientIp(req) : null,
      userAgent: req ? this.authUtils.getClientUserAgent(req) : null,
      metadata: metadata || {},
    });
  }

  async login(dto: LoginDto, req: Request): Promise<any> {
    const user = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: dto.email }, { customerId: dto.customerId }],
      },
      include: {
        role: true,
        rootParent: {
          select: {
            id: true,
            username: true,
            status: true,
          },
        },
        parent: {
          select: {
            id: true,
            username: true,
            role: true,
          },
        },
      },
    });

    const ip = this.authUtils.getClientIp(req);
    const origin = this.authUtils.getClientOrigin(req);

    if (!user || user.deletedAt) {
      await this.logAuthEvent({
        performerId: user?.id ?? null,
        action: 'LOGIN_FAILED',
        status: 'FAILED',
        req,
        metadata: {
          reason: 'USER_NOT_FOUND_OR_DELETED',
          identifier: dto.email || dto.customerId,
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== 'ACTIVE') {
      await this.logAuthEvent({
        performerId: user.id,
        action: 'LOGIN_FAILED',
        status: 'FAILED',
        req,
        metadata: {
          reason: 'USER_INACTIVE',
          status: user.status,
        },
      });
      throw new UnauthorizedException(
        `Account is ${user.status.toLowerCase()}`,
      );
    }

    if (!this.authUtils.verifyPassword(dto.password, user.password)) {
      await this.logAuthEvent({
        performerId: user.id,
        action: 'LOGIN_FAILED',
        status: 'FAILED',
        req,
        metadata: { reason: 'INVALID_PASSWORD' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // ADMIN users special checks
    if (user.role.name === 'ADMIN') {
      if (!user.rootParent) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: { reason: 'ADMIN_NO_ROOT_PARENT' },
        });
        throw new UnauthorizedException(
          'Admin account configuration incomplete',
        );
      }

      if (user.rootParent.status !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'ADMIN_ROOT_PARENT_INACTIVE',
            rootStatus: user.rootParent.status,
          },
        });
        throw new UnauthorizedException('Root account is not active');
      }
    } else {
      // Other hierarchy users
      if (!user.rootParent) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: { reason: 'NO_ROOT_PARENT' },
        });
        throw new UnauthorizedException('Account configuration incomplete');
      }

      if (user.rootParent.status !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'ROOT_PARENT_INACTIVE',
            rootStatus: user.rootParent.status,
          },
        });
        throw new UnauthorizedException('Root account is not active');
      }

      if (!user.parent) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'NO_PARENT_USER',
            role: user.role.name,
          },
        });
        throw new UnauthorizedException('Parent user account not found');
      }

      const parentUser = await this.prisma.user.findUnique({
        where: { id: user.parent.id },
        select: { status: true },
      });

      if (!parentUser || parentUser.status !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'PARENT_USER_INACTIVE',
            parentId: user.parent.id,
          },
        });
        throw new UnauthorizedException('Parent user account is not active');
      }
    }

    // IP Whitelist resolution logic
    let allowedDomains: string[] = [];
    let allowedIps: string[] = [];
    let whitelistSource = '';

    if (user.role.name === 'ADMIN') {
      const adminWhitelist = await this.ipWhitelistService.findUserWhitelist(
        user.id,
      );
      allowedDomains = adminWhitelist.map((w) => w.domainName).filter(Boolean);
      allowedIps = adminWhitelist.map((w) => w.serverIp).filter(Boolean);
      whitelistSource = 'ADMIN_OWN';

      if (allowedDomains.length === 0 && allowedIps.length === 0) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'ADMIN_NO_WHITELIST',
            role: user.role.name,
          },
        });
        throw new ForbiddenException(
          'Admin IP whitelist not configured. Please contact administrator.',
        );
      }
    } else {
      if (!user.parent) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'NO_PARENT_FOR_WHITELIST',
            role: user.role.name,
          },
        });
        throw new UnauthorizedException('Cannot determine IP whitelist source');
      }

      const parentAdminWhitelist =
        await this.ipWhitelistService.findUserWhitelist(user.parent.id);
      allowedDomains = parentAdminWhitelist
        .map((w) => w.domainName)
        .filter(Boolean);
      allowedIps = parentAdminWhitelist.map((w) => w.serverIp).filter(Boolean);
      whitelistSource = 'INHERITED_FROM_ADMIN';

      if (allowedDomains.length === 0 && allowedIps.length === 0) {
        await this.logAuthEvent({
          performerId: user.id,
          action: 'LOGIN_FAILED',
          status: 'FAILED',
          req,
          metadata: {
            reason: 'PARENT_ADMIN_NO_WHITELIST',
            role: user.role.name,
            parentId: user.parent.id,
          },
        });
        throw new ForbiddenException(
          'Parent admin has no IP whitelist configured',
        );
      }
    }

    if (
      allowedDomains.length > 0 &&
      !this.authUtils.isValidOrigin(origin, allowedDomains)
    ) {
      await this.logAuthEvent({
        performerId: user.id,
        action: 'LOGIN_FAILED',
        status: 'FAILED',
        req,
        metadata: {
          reason: 'ORIGIN_NOT_ALLOWED',
          origin,
          allowedDomains,
          userRole: user.role.name,
          whitelistSource,
        },
      });
      throw new ForbiddenException('Origin not allowed');
    }

    if (allowedIps.length > 0 && !this.authUtils.isValidIp(ip, allowedIps)) {
      await this.logAuthEvent({
        performerId: user.id,
        action: 'LOGIN_FAILED',
        status: 'FAILED',
        req,
        metadata: {
          reason: 'IP_NOT_ALLOWED',
          ip,
          allowedIps,
          userRole: user.role.name,
          whitelistSource,
        },
      });
      throw new ForbiddenException('IP address not allowed');
    }

    const actor: AuthActor = this.authUtils.createActor({
      id: user.id,
      roleId: user.roleId,
      principalType: 'USER',
      isRoot: false,
    });

    const tokens = this.tokenService.generateTokens(actor);
    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken: hashedRefresh,
        lastLoginAt: new Date(),
        lastLoginIp: ip,
        lastLoginOrigin: origin,
      },
    });

    await this.logAuthEvent({
      performerId: user.id,
      action: 'LOGIN_SUCCESS',
      status: 'SUCCESS',
      req,
      metadata: {
        role: user.role.name,
        rootParentId: user.rootParentId,
        parentId: user.parentId,
        hasTransactionPin: !!user.transactionPin,
        ip,
        origin,
        whitelistSource,
      },
    });

    const response = {
      user: this.toSafeUser(user),
      actor,
      tokens,
      hasTransactionPin: !!user.transactionPin,
      ipWhitelistInfo: {
        hasWhitelist: true,
        source: whitelistSource,
        domains: allowedDomains,
        ips: allowedIps,
      },
    };

    if (user.role.name === 'ADMIN') {
      response['hierarchyInfo'] = {
        type: 'ADMIN',
        rootParent: user.rootParent,
        parent: null,
        canCreateDownline: true,
        canAccessAllDownline: true,
        ipWhitelistRule: 'SELF_CONFIGURED_MANDATORY',
      };
    } else {
      response['hierarchyInfo'] = {
        type: user.role.name,
        rootParent: user.rootParent,
        parent: user.parent,
        canAccessDownline: await this.canAccessDownline(
          user.id,
          user.role.name,
        ),
        ipWhitelistRule: 'INHERITED_FROM_ADMIN_MANDATORY',
      };
    }

    return response;
  }

  async refreshToken(rawToken: string, req: Request): Promise<any> {
    const payload = this.tokenService.verifyRefreshToken(rawToken);

    if (!payload || payload.principalType !== 'USER') {
      throw new UnauthorizedException('Invalid token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !this.authUtils.verifyPassword(rawToken, user.refreshToken!)) {
      await this.logAuthEvent({
        performerId: payload.sub,
        action: 'REFRESH_TOKEN_INVALID',
        status: 'FAILED',
        req,
      });

      throw new UnauthorizedException('Invalid refresh token');
    }

    const actor = this.authUtils.createActor({
      id: user.id,
      principalType: 'USER',
      roleId: user.roleId,
      isRoot: false,
    });

    const tokens = this.tokenService.generateTokens(actor);
    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: hashedRefresh },
    });

    await this.logAuthEvent({
      performerId: user.id,
      action: 'REFRESH_TOKEN_SUCCESS',
      status: 'SUCCESS',
      req,
    });

    return {
      user: this.toSafeUser(user),
      actor,
      tokens,
    };
  }

  async logout(userId: string, req?: Request): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    await this.logAuthEvent({
      performerId: userId,
      action: 'LOGOUT',
      status: 'SUCCESS',
      req,
    });
  }

  async requestPasswordReset(
    dto: ForgotPasswordDto,
    currentUser: AuthActor,
    req?: Request,
  ): Promise<any> {
    const authenticatedUser = await this.prisma.user.findUnique({
      where: { id: currentUser.id },
    });

    if (!authenticatedUser) {
      throw new UnauthorizedException('User not found');
    }

    if (authenticatedUser.email !== dto.email) {
      await this.logAuthEvent({
        performerId: currentUser.id,
        action: 'PASSWORD_RESET_REQUEST_FAILED',
        status: 'FAILED',
        metadata: {
          details: `Attempted to reset password for email: ${dto.email}`,
        },
        req,
      });

      throw new ForbiddenException('You can only reset your own password');
    }

    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      return { message: 'If account exists, password reset email sent.' };
    }

    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = this.authUtils.hashResetToken(rawToken);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: new Date(Date.now() + 3 * 60 * 1000),
      },
    });

    await this.emailService.sendPasswordResetEmail({
      firstName: user.firstName,
      supportEmail: user.email,
      resetUrl: `${this.configService.get<string>('security.resetPasswordBaseUrl')}?token=${rawToken}`,
      expiryMinutes: 3,
    });

    await this.logAuthEvent({
      performerId: user.id,
      action: 'PASSWORD_RESET_REQUESTED',
      status: 'SUCCESS',
      req,
    });

    return { message: 'Password reset email sent.' };
  }

  async confirmPasswordReset(
    dto: ConfirmPasswordResetDto,
    currentUser?: AuthActor,
    req?: Request,
  ): Promise<any> {
    const hashedToken = this.authUtils.hashResetToken(dto.token);

    const user = await this.prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() },
      },
    });

    if (!user) {
      await this.logAuthEvent({
        performerId: currentUser?.id || null,
        action: 'PASSWORD_RESET_FAILED',
        status: 'FAILED',
        req,
      });
      throw new BadRequestException('Invalid or expired token');
    }

    if (currentUser && user.id !== currentUser.id) {
      throw new ForbiddenException('You can only reset your own password');
    }

    const newPasswordPlain = this.authUtils.generateRandomPassword();
    const newPinPlain = this.authUtils.generateRandomTransactionPin();
    const newHashed = this.authUtils.hashPassword(newPasswordPlain);
    const newPinHashed = this.authUtils.hashPassword(newPinPlain);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: newHashed,
        transactionPin: newPinHashed,
        refreshToken: null,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    await this.emailService.sendBusinessUserCredentialsEmail({
      firstName: user.firstName,
      username: user.username,
      email: user.email,
      password: newPasswordPlain,
      transactionPin: newPinPlain,
      actionType: 'reset',
    });

    await this.logAuthEvent({
      performerId: user.id,
      action: 'PASSWORD_RESET_CONFIRMED',
      status: 'SUCCESS',
      req,
    });

    return {
      message:
        'Password reset successful. New password and transaction PIN sent to your email.',
      hasTransactionPin: true,
    };
  }

  async getCurrentUser(userId: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        role: true,
        rootParent: { select: { id: true, username: true } },
        parent: { select: { id: true, username: true, role: true } },
        businessKyc: { select: { status: true } },
      },
    });

    if (!user) throw new NotFoundException('User not found');

    return this.toSafeUser(user);
  }

  async getDashboard(userId: string, req?: Request): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true },
    });

    if (!user) throw new NotFoundException('User not found');

    const [directChildren, totalDownline, totalEmployees, walletBalance] =
      await Promise.all([
        this.prisma.user.count({
          where: { parentId: userId },
        }),
        this.prisma.user.count({
          where: {
            hierarchyPath: { startsWith: user.hierarchyPath },
            id: { not: userId },
          },
        }),
        this.prisma.employee.count({
          where: { createdByUserId: userId },
        }),
        this.prisma.wallet.aggregate({
          where: { userId, walletType: 'PRIMARY' },
          _sum: { availableBalance: true },
        }),
      ]);

    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const todayTransactions = await this.prisma.transaction.count({
      where: {
        userId,
        initiatedAt: { gte: startOfDay },
        status: 'SUCCESS',
      },
    });

    await this.logAuthEvent({
      performerId: userId,
      action: 'DASHBOARD_ACCESSED',
      status: 'SUCCESS',
      req,
    });

    return {
      userInfo: {
        role: user.role.name,
        hierarchyLevel: user.hierarchyLevel,
        isKycVerified: user.isKycVerified,
        hasTransactionPin: !!user.transactionPin,
      },
      stats: {
        directDownline: directChildren,
        totalDownlineUsers: totalDownline,
        totalEmployees: totalEmployees,
        walletBalance: this.authUtils.money(
          walletBalance._sum.availableBalance,
        ),
        todayTransactions: todayTransactions,
      },
    };
  }

  async updateCredentials(
    userId: string,
    dto: UpdateCredentialsDto,
    req?: Request,
  ): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException('User not found');

    if (!dto.newPassword || !dto.currentPassword) {
      throw new BadRequestException('Current & new password required');
    }

    if (!this.authUtils.verifyPassword(dto.currentPassword, user.password)) {
      throw new UnauthorizedException('Invalid current password');
    }

    const newHashed = this.authUtils.hashPassword(dto.newPassword);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: newHashed,
        refreshToken: null,
      },
    });

    await this.logAuthEvent({
      performerId: userId,
      action: 'CREDENTIALS_UPDATED',
      status: 'SUCCESS',
      req,
      metadata: { updatedFields: ['password'] },
    });

    return { message: 'Credentials updated successfully' };
  }

  async updateProfile(
    userId: string,
    dto: UpdateProfileDto,
    req?: Request,
  ): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException('User not found');

    if (dto.email && dto.email !== user.email) {
      const existingEmail = await this.prisma.user.findUnique({
        where: { email: dto.email },
      });
      if (existingEmail) {
        throw new BadRequestException('Email already exists');
      }
    }

    if (dto.phoneNumber && dto.phoneNumber !== user.phoneNumber) {
      const existingPhone = await this.prisma.user.findUnique({
        where: { phoneNumber: dto.phoneNumber },
      });
      if (existingPhone) {
        throw new BadRequestException('Phone number already exists');
      }
    }

    if (dto.username && dto.username !== user.username) {
      const existingUsername = await this.prisma.user.findUnique({
        where: { username: dto.username },
      });
      if (existingUsername) {
        throw new BadRequestException('Username already exists');
      }
    }

    const data = {
      firstName: dto.firstName ?? user.firstName,
      lastName: dto.lastName ?? user.lastName,
      username: dto.username ?? user.username,
      phoneNumber: dto.phoneNumber ?? user.phoneNumber,
      email: dto.email ?? user.email,
    };

    await this.prisma.user.update({ where: { id: userId }, data });

    await this.logAuthEvent({
      performerId: userId,
      action: 'PROFILE_UPDATED',
      status: 'SUCCESS',
      req,
      metadata: { updatedFields: Object.keys(data) },
    });

    return this.getCurrentUser(userId);
  }

  async updateProfileImage(
    userId: string,
    file: Express.Multer.File,
    req?: Request,
  ): Promise<any> {
    if (!file) throw new BadRequestException('Profile image required');

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException('User not found');

    const oldImage = user.profileImage;

    const uploadedUrl = await this.s3.uploadBuffer(file, 'user-profile-images');

    if (!uploadedUrl) throw new BadRequestException('Upload failed');

    if (oldImage) {
      await this.s3.delete({ fileUrl: oldImage }).catch(() => null);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { profileImage: uploadedUrl },
    });

    FileDeleteHelper.deleteUploadedImages(file);

    await this.logAuthEvent({
      performerId: userId,
      action: 'PROFILE_IMAGE_UPDATED',
      status: 'SUCCESS',
      req,
      metadata: { oldImageDeleted: !!oldImage },
    });

    return this.getCurrentUser(userId);
  }

  // Hierarchy methods
  async getDownlineUsers(userId: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: true },
    });

    if (!user) throw new NotFoundException('User not found');

    const downlineUsers = await this.prisma.user.findMany({
      where: {
        hierarchyPath: { startsWith: user.hierarchyPath },
        id: { not: userId },
      },
      include: {
        role: true,
        wallets: {
          where: { walletType: 'PRIMARY' },
          select: { availableBalance: true },
        },
      },
      orderBy: { hierarchyLevel: 'desc' },
    });

    return {
      currentUser: {
        id: user.id,
        username: user.username,
        role: user.role.name,
        hierarchyLevel: user.hierarchyLevel,
      },
      downlineUsers: downlineUsers.map((u) => ({
        id: u.id,
        username: u.username,
        email: u.email,
        phoneNumber: u.phoneNumber,
        role: u.role.name,
        hierarchyLevel: u.hierarchyLevel,
        status: u.status,
        walletBalance: this.authUtils.money(u.wallets[0]?.availableBalance),
        isKycVerified: u.isKycVerified,
      })),
      totalDownline: downlineUsers.length,
    };
  }

  async getHierarchyInfo(userId: string): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        role: true,
        parent: {
          include: { role: true },
        },
        rootParent: {
          include: { role: true },
        },
        children: {
          include: {
            role: true,
            children: true,
          },
        },
      },
    });

    if (!user) throw new NotFoundException('User not found');

    const isAdmin = user.role.name === 'ADMIN';
    const selectedUpline = isAdmin ? user.rootParent : user.parent;

    const upline = selectedUpline
      ? {
          id: selectedUpline.id,
          username: selectedUpline.username,
          role: selectedUpline.role?.name ?? 'ROOT',
          hierarchyLevel: selectedUpline.hierarchyLevel,
        }
      : null;

    return {
      current: {
        id: user.id,
        username: user.username,
        role: user.role.name,
        hierarchyLevel: user.hierarchyLevel,
      },
      upline,
      downline: user.children.map((child) => ({
        id: child.id,
        username: child.username,
        role: child.role.name,
        hierarchyLevel: child.hierarchyLevel,
        childrenCount: child.children.length,
      })),
    };
  }

  async validateHierarchyAccess(
    requesterId: string,
    targetId: string,
  ): Promise<boolean> {
    const [requester, target] = await Promise.all([
      this.prisma.user.findUnique({
        where: { id: requesterId },
      }),
      this.prisma.user.findUnique({
        where: { id: targetId },
      }),
    ]);

    if (!requester || !target) {
      return false;
    }

    if (requester.rootParentId !== target.rootParentId) {
      return false;
    }

    if (!target.hierarchyPath.startsWith(requester.hierarchyPath)) {
      return false;
    }

    return true;
  }

  private async canAccessDownline(
    userId: string,
    roleName: string,
  ): Promise<{ roleName: string; canAccess: boolean }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { role: { select: { name: true } } },
    });

    if (!user) return { roleName, canAccess: false };

    const downlineCount = await this.prisma.user.count({
      where: {
        hierarchyPath: { startsWith: user.hierarchyPath },
        id: { not: userId },
      },
    });

    return { roleName, canAccess: downlineCount > 0 };
  }
}
