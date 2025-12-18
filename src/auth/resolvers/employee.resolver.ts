import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';
import { ForgotPasswordDto } from '../dto/forgot-password-auth.dto';
import { ConfirmPasswordResetDto } from '../dto/confirm-password-reset-auth.dto';
import { UpdateCredentialsDto } from '../dto/update-credentials-auth.dto';
import { UpdateProfileDto } from '../dto/update-profile-auth.dto';
import { randomBytes } from 'node:crypto';
import { AuthUtilsService } from '../../common/utils/auth.utils';
import { LoginDto } from '../dto/login-auth.dto';
import type { Request } from 'express';
import { AuthActor } from '../../common/types/auth.type';
import { AuditStatus } from '../../common/enums/audit.enum';
import { ConfigService } from '@nestjs/config';
import { S3Service } from '../../common/utils/s3.service';
// import { IpWhitelistService } from '../../common/ip-whitelist/service/ip-whitelist.service';
import { Prisma } from '../../../generated/prisma/client';
import { EmailService } from '../../email/email.service';
import { FileDeleteHelper } from '../../common/utils/file.delete.utils';

@Injectable()
export class EmployeeResolver {
  private logger = new Logger(EmployeeResolver.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly authUtils: AuthUtilsService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly s3: S3Service,
    // private readonly ipWhitelistService: IpWhitelistService,
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
      performerType: 'EMPLOYEE',
      performerId: performerId,
      action,
      status,
      ipAddress: req ? this.authUtils.getClientIp(req) : null,
      userAgent: req ? this.authUtils.getClientUserAgent(req) : null,
      metadata: metadata || {},
    });
  }

  async login(dto: LoginDto, req: Request) {
    const employee = await this.prisma.employee.findFirst({
      where: { email: dto.email },
      include: {
        department: true,
        createdByUser: {
          select: {
            id: true,
            username: true,
            status: true,
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
                status: true,
              },
            },
          },
        },
        createdByRoot: {
          select: {
            id: true,
            username: true,
            status: true,
          },
        },
      },
    });

    const ip = this.authUtils.getClientIp(req);
    const origin = this.authUtils.getClientOrigin(req);

    // 1. Basic checks
    if (!employee || employee.deletedAt) {
      await this.logAuthEvent({
        performerId: employee?.id ?? null,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: {
          reason: 'EMPLOYEE_NOT_FOUND_OR_DELETED',
          email: dto.email,
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // 2. Employee status check
    if (employee.status !== 'ACTIVE') {
      await this.logAuthEvent({
        performerId: employee.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: {
          reason: 'EMPLOYEE_INACTIVE',
          status: employee.status,
        },
      });
      throw new UnauthorizedException(
        `Account is ${employee.status.toLowerCase()}`,
      );
    }

    // 3. Password verification
    if (!this.authUtils.verifyPassword(dto.password, employee.password)) {
      await this.logAuthEvent({
        performerId: employee.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: { reason: 'INVALID_PASSWORD' },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // 4. Check creator status (either Root or Admin User)
    let creatorStatus = 'UNKNOWN';
    let creatorId = '';
    let creatorType = '';
    let rootParentId = '';

    if (employee.createdByRootId) {
      // Employee created by Root
      creatorStatus = employee.createdByRoot?.status || 'UNKNOWN';
      creatorId = employee.createdByRootId;
      creatorType = 'ROOT';
      rootParentId = employee.createdByRootId;

      if (creatorStatus !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: employee.id,
          action: 'LOGIN_FAILED',
          status: AuditStatus.FAILED,
          req,
          metadata: {
            reason: 'ROOT_CREATOR_INACTIVE',
            rootStatus: creatorStatus,
          },
        });
        throw new UnauthorizedException('Root creator account is not active');
      }
    } else if (employee.createdByUserId) {
      // Employee created by Admin User
      const adminUser = employee.createdByUser;
      if (!adminUser) {
        await this.logAuthEvent({
          performerId: employee.id,
          action: 'LOGIN_FAILED',
          status: AuditStatus.FAILED,
          req,
          metadata: { reason: 'ADMIN_CREATOR_NOT_FOUND' },
        });
        throw new UnauthorizedException('Admin creator account not found');
      }

      // Check admin user status
      if (adminUser.status !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: employee.id,
          action: 'LOGIN_FAILED',
          status: AuditStatus.FAILED,
          req,
          metadata: {
            reason: 'ADMIN_CREATOR_INACTIVE',
            adminStatus: adminUser.status,
          },
        });
        throw new UnauthorizedException('Admin creator account is not active');
      }

      // Check admin's root parent status
      if (!adminUser.rootParent || adminUser.rootParent.status !== 'ACTIVE') {
        await this.logAuthEvent({
          performerId: employee.id,
          action: 'LOGIN_FAILED',
          status: AuditStatus.FAILED,
          req,
          metadata: {
            reason: 'ROOT_PARENT_INACTIVE',
            rootStatus: adminUser.rootParent?.status,
          },
        });
        throw new UnauthorizedException('Root parent account is not active');
      }

      creatorStatus = adminUser.status;
      creatorId = employee.createdByUserId;
      creatorType = 'ADMIN';
      rootParentId = adminUser.rootParent.id;
    } else {
      await this.logAuthEvent({
        performerId: employee.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: { reason: 'NO_CREATOR_FOUND' },
      });
      throw new UnauthorizedException('Employee configuration incomplete');
    }

    // 5. IP Whitelist check
    let allowedDomains: string[] = [];
    let allowedIps: string[] = [];
    let whitelistSource = '';

    if (creatorType === 'ADMIN') {
      // RULE: Admin ke employees ke liye admin se whitelist inherit karo
      const adminWhitelist =
        await this.ipWhitelistService.findUserWhitelist(creatorId);
      allowedDomains = adminWhitelist.map((w) => w.domainName).filter(Boolean);
      allowedIps = adminWhitelist.map((w) => w.serverIp).filter(Boolean);
      whitelistSource = 'INHERITED_FROM_ADMIN';

      // Agar admin ke paas whitelist nahi hai to root se check karo
      if (allowedDomains.length === 0 && allowedIps.length === 0) {
        const rootWhitelist =
          await this.ipWhitelistService.findRootWhitelist(rootParentId);
        allowedDomains = rootWhitelist.map((w) => w.domainName).filter(Boolean);
        allowedIps = rootWhitelist.map((w) => w.serverIp).filter(Boolean);
        whitelistSource = 'INHERITED_FROM_ROOT_VIA_ADMIN';
      }
    }

    // 6. Domain/Origin validation (if whitelist exists)
    if (
      allowedDomains.length > 0 &&
      !this.authUtils.isValidOrigin(origin, allowedDomains)
    ) {
      await this.logAuthEvent({
        performerId: employee.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: {
          reason: 'ORIGIN_NOT_ALLOWED',
          origin,
          allowedDomains,
          creatorType,
          whitelistSource,
        },
      });
      throw new ForbiddenException('Origin not allowed');
    }

    if (allowedIps.length > 0 && !this.authUtils.isValidIp(ip, allowedIps)) {
      await this.logAuthEvent({
        performerId: employee.id,
        action: 'LOGIN_FAILED',
        status: AuditStatus.FAILED,
        req,
        metadata: {
          reason: 'IP_NOT_ALLOWED',
          ip,
          allowedIps,
          creatorType,
          whitelistSource,
        },
      });
      throw new ForbiddenException('IP address not allowed');
    }

    // 7. Create actor with complete hierarchy information
    const actor: AuthActor = this.authUtils.createActor({
      id: employee.id,
      principalType: 'EMPLOYEE',
      parentId: employee.createdByUserId
        ? employee.createdByUserId
        : employee.createdByRootId,
      roleId: employee.departmentId,
    });

    const tokens = this.authUtils.generateTokens(actor);
    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    // 8. Update employee login info
    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        refreshToken: hashedRefresh,
        lastLoginAt: new Date(),
        lastLoginIp: ip,
        lastLoginOrigin: origin,
      },
    });

    // 9. Log success
    await this.logAuthEvent({
      performerId: employee.id,
      action: 'LOGIN_SUCCESS',
      status: AuditStatus.SUCCESS,
      req,
      metadata: {
        creatorType,
        creatorId,
        rootParentId,
        department: employee.department?.name,
        ip,
        origin,
        whitelistSource,
        whitelistDomains: allowedDomains,
        whitelistIps: allowedIps,
      },
    });

    // Prepare response
    const response = {
      user: this.authUtils.stripSensitive(employee, [
        'password',
        'refreshToken',
        'passwordResetToken',
      ]),
      actor,
      tokens,
      ipWhitelistInfo: {
        hasWhitelist: allowedDomains.length > 0 || allowedIps.length > 0,
        source: whitelistSource,
        domains: allowedDomains,
        ips: allowedIps,
      },
    };

    // Add hierarchy info
    response['hierarchyInfo'] = {
      type: 'EMPLOYEE',
      creatorType,
      creatorId,
      rootParentId,
      department: employee.department?.name,
      ipWhitelistRule:
        creatorType === 'ROOT'
          ? 'INHERITED_FROM_ROOT'
          : 'INHERITED_FROM_ADMIN_OR_ROOT',
    };

    return response;
  }

  async logout(employeeId: string, req: Request) {
    await this.prisma.employee.update({
      where: { id: employeeId },
      data: { refreshToken: null },
    });

    await this.logAuthEvent({
      performerId: employeeId,
      action: 'LOGOUT',
      status: AuditStatus.SUCCESS,
      req,
    });

    return { message: 'Logged out successfully' };
  }

  async refreshToken(rawToken: string, req: Request) {
    const payload = this.authUtils.verifyJwt(rawToken);

    if (!payload || payload.principalType !== 'EMPLOYEE') {
      throw new UnauthorizedException('Invalid token');
    }

    const employee = await this.prisma.employee.findUnique({
      where: { id: payload.sub },
      include: {
        department: true,
        createdByUser: {
          select: {
            id: true,
            rootParent: {
              select: { id: true },
            },
          },
        },
        createdByRoot: {
          select: { id: true },
        },
      },
    });

    if (
      !employee ||
      !this.authUtils.verifyPassword(rawToken, employee.refreshToken!)
    ) {
      await this.logAuthEvent({
        performerId: payload.sub,
        action: 'REFRESH_TOKEN_INVALID',
        status: AuditStatus.FAILED,
        req,
      });

      throw new UnauthorizedException('Invalid refresh token');
    }

    // Determine root parent ID
    let rootParentId = '';
    if (employee.createdByRootId) {
      rootParentId = employee.createdByRootId;
    } else if (employee.createdByUserId && employee.createdByUser?.rootParent) {
      rootParentId = employee.createdByUser.rootParent.id;
    }

    const actor = this.authUtils.createActor({
      id: employee.id,
      principalType: 'EMPLOYEE',
      parentId: employee.createdByRootId
        ? rootParentId
        : employee.createdByUserId,
      roleId: employee.departmentId,
    });

    const tokens = this.authUtils.generateTokens(actor);
    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: { refreshToken: hashedRefresh },
    });

    await this.logAuthEvent({
      performerId: employee.id,
      action: 'REFRESH_TOKEN_SUCCESS',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      user: this.authUtils.stripSensitive(employee, [
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
    // 1. Authenticated employee ka email verify karo
    const authenticatedEmployee = await this.prisma.employee.findUnique({
      where: { id: currentUser.id },
    });

    if (!authenticatedEmployee) {
      throw new UnauthorizedException('Employee not found');
    }

    // 2. Verify that the requested email belongs to current employee
    if (authenticatedEmployee.email !== dto.email) {
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

    const employee = await this.prisma.employee.findUnique({
      where: { email: dto.email },
      include: {
        createdByUser: {
          select: {
            email: true,
            firstName: true,
          },
        },
        createdByRoot: {
          select: {
            email: true,
            firstName: true,
          },
        },
      },
    });

    if (!employee) {
      return {
        message:
          'If an account with that email exists, a password reset link has been sent.',
      };
    }

    const rawToken = randomBytes(32).toString('hex');
    const hashedToken = this.authUtils.hashResetToken(rawToken);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: new Date(Date.now() + 3 * 60 * 1000),
      },
    });

    // Determine who created this employee for email context
    const creator = employee.createdByUser || employee.createdByRoot;

    await this.emailService.sendPasswordResetEmail({
      firstName: employee.firstName,
      supportEmail: creator?.email || employee.email,
      resetUrl: `${this.configService.get<string>('security.resetPasswordBaseUrl')}?token=${rawToken}`,
      expiryMinutes: 3,
    });

    await this.logAuthEvent({
      performerId: employee.id,
      action: 'PASSWORD_RESET_REQUESTED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      message:
        'If an account with that email exists, a password reset link has been sent.',
    };
  }

  async confirmPasswordReset(
    dto: ConfirmPasswordResetDto,
    currentUser?: AuthActor,
    req?: Request,
  ) {
    const hashedToken = this.authUtils.hashResetToken(dto.token);

    const employee = await this.prisma.employee.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() },
      },
      include: {
        createdByUser: {
          select: {
            email: true,
            firstName: true,
          },
        },
        createdByRoot: {
          select: {
            email: true,
            firstName: true,
          },
        },
      },
    });

    if (!employee) {
      await this.logAuthEvent({
        performerId: currentUser?.id || null,
        action: 'PASSWORD_RESET_FAILED',
        status: AuditStatus.FAILED,
        req,
      });
      throw new BadRequestException('Invalid or expired token');
    }

    if (currentUser && employee.id !== currentUser.id) {
      throw new ForbiddenException('You can only reset your own password');
    }

    const newPasswordPlain = this.authUtils.generateRandomPassword();
    const newHashed = this.authUtils.hashPassword(newPasswordPlain);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        password: newHashed,
        refreshToken: null,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    await this.emailService.sendEmployeeCredentialsEmail({
      firstName: employee.firstName,
      username: employee.username,
      email: employee.email,
      password: newPasswordPlain,
      actionType: 'reset',
      role: employee.departmentId,
    });

    await this.logAuthEvent({
      performerId: employee.id,
      action: 'PASSWORD_RESET_CONFIRMED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      message: 'Password reset successful. New password sent to your email.',
    };
  }

  async getCurrentUser(employeeId: string) {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
      include: {
        department: true,
        createdByUser: {
          select: {
            id: true,
            username: true,
            role: {
              select: {
                name: true,
              },
            },
          },
        },
        createdByRoot: {
          select: {
            id: true,
            username: true,
          },
        },
      },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    return this.authUtils.stripSensitive(employee, [
      'password',
      'refreshToken',
      'passwordResetToken',
    ]);
  }

  async getDashboard(employeeId: string, req?: Request) {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
      include: {
        department: true,
      },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    // Employees typically have limited dashboard access
    // You can customize this based on your requirements
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const permissionsAssigned = await this.prisma.permission.count({
      where: {
        assignedToEmployeeId: employeeId,
        createdAt: { gte: today },
      },
    });

    await this.logAuthEvent({
      performerId: employeeId,
      action: 'DASHBOARD_ACCESSED',
      status: AuditStatus.SUCCESS,
      req,
    });

    return {
      employeeInfo: {
        firstName: employee.firstName,
        lastName: employee.lastName,
        department: employee.department?.name,
        employeeId: employee.id,
      },
      stats: {
        permissionsAssigned: permissionsAssigned,
      },
    };
  }

  async updateCredentials(
    employeeId: string,
    dto: UpdateCredentialsDto,
    req?: Request,
  ) {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    if (!dto.newPassword || !dto.currentPassword) {
      throw new BadRequestException(
        'Current password and new password are required',
      );
    }

    if (
      !this.authUtils.verifyPassword(dto.currentPassword, employee.password)
    ) {
      throw new UnauthorizedException('Invalid current password');
    }

    const newHashed = this.authUtils.hashPassword(dto.newPassword);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        password: newHashed,
        refreshToken: null,
      },
    });

    await this.logAuthEvent({
      performerId: employeeId,
      action: 'CREDENTIALS_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { updatedFields: ['password'] },
    });

    return { message: 'Credentials updated successfully' };
  }

  async updateProfile(
    employeeId: string,
    dto: UpdateProfileDto,
    req?: Request,
  ) {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    if (dto.email && dto.email !== employee.email) {
      const existingEmail = await this.prisma.employee.findUnique({
        where: { email: dto.email },
      });
      if (existingEmail) {
        throw new BadRequestException('Email already exists');
      }
    }

    if (dto.phoneNumber && dto.phoneNumber !== employee.phoneNumber) {
      const existingPhone = await this.prisma.employee.findUnique({
        where: { phoneNumber: dto.phoneNumber },
      });
      if (existingPhone) {
        throw new BadRequestException('Phone number already exists');
      }
    }

    if (dto.username && dto.username !== employee.username) {
      const existingUsername = await this.prisma.employee.findUnique({
        where: { username: dto.username },
      });
      if (existingUsername) {
        throw new BadRequestException('Username already exists');
      }
    }

    const data = {
      firstName: dto.firstName ?? employee.firstName,
      lastName: dto.lastName ?? employee.lastName,
      username: dto.username ?? employee.username,
      phoneNumber: dto.phoneNumber ?? employee.phoneNumber,
      email: dto.email ?? employee.email,
    };

    await this.prisma.employee.update({ where: { id: employeeId }, data });

    await this.logAuthEvent({
      performerId: employeeId,
      action: 'PROFILE_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { updatedFields: Object.keys(data) },
    });

    return this.getCurrentUser(employeeId);
  }

  async updateProfileImage(
    employeeId: string,
    file: Express.Multer.File,
    req: Request,
  ) {
    if (!file) throw new BadRequestException('Profile image required');

    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    const oldImage = employee.profileImage;

    const uploadedUrl = await this.s3.uploadBuffer(
      file,
      'employee-profile-images',
    );

    if (!uploadedUrl) throw new BadRequestException('Upload failed');

    if (oldImage) {
      await this.s3.delete({ fileUrl: oldImage }).catch(() => null);
    }

    await this.prisma.employee.update({
      where: { id: employeeId },
      data: { profileImage: uploadedUrl },
    });

    FileDeleteHelper.deleteUploadedImages(file);

    await this.logAuthEvent({
      performerId: employeeId,
      action: 'PROFILE_IMAGE_UPDATED',
      status: AuditStatus.SUCCESS,
      req,
      metadata: { oldImageDeleted: !!oldImage },
    });

    return this.getCurrentUser(employeeId);
  }

  // Helper methods for hierarchy validation
  async validateEmployeeAccess(
    requesterId: string,
    targetEmployeeId: string,
  ): Promise<boolean> {
    const [requester, target] = await Promise.all([
      this.prisma.employee.findUnique({
        where: { id: requesterId },
        include: {
          createdByUser: {
            select: { rootParentId: true },
          },
          createdByRoot: {
            select: { id: true },
          },
        },
      }),
      this.prisma.employee.findUnique({
        where: { id: targetEmployeeId },
        include: {
          createdByUser: {
            select: { rootParentId: true },
          },
          createdByRoot: {
            select: { id: true },
          },
        },
      }),
    ]);

    if (!requester || !target) {
      return false;
    }

    // Check if they share the same root parent
    const requesterRootId =
      requester.createdByRootId || requester.createdByUser?.rootParentId;
    const targetRootId =
      target.createdByRootId || target.createdByUser?.rootParentId;

    if (requesterRootId !== targetRootId) {
      return false;
    }

    // Check if requester is the creator of target or shares the same creator
    if (requester.createdByRootId && target.createdByRootId) {
      return requester.createdByRootId === target.createdByRootId;
    }

    if (requester.createdByUserId && target.createdByUserId) {
      return requester.createdByUserId === target.createdByUserId;
    }

    return false;
  }

  // Get employee's creator info
  async getCreatorInfo(employeeId: string) {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
      include: {
        createdByUser: {
          select: {
            id: true,
            username: true,
            email: true,
            role: {
              select: {
                name: true,
              },
            },
          },
        },
        createdByRoot: {
          select: {
            id: true,
            username: true,
            email: true,
          },
        },
      },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    if (employee.createdByRoot) {
      return {
        type: 'ROOT',
        creator: employee.createdByRoot,
      };
    } else if (employee.createdByUser) {
      return {
        type: 'ADMIN',
        creator: employee.createdByUser,
      };
    }

    return {
      type: 'UNKNOWN',
      creator: null,
    };
  }
}
