// src/auth/resolvers/employee-auth.resolver.ts
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';

import { PrismaService } from '../../database/database.connection';
import { AuthUtilsService } from '../helper/auth-utils';
import { TokenService } from '../token.service';

import { LoginDto } from '../dto/login-auth.dto';
import { ForgotPasswordDto } from '../dto/forgot-password-auth.dto';
import { ConfirmPasswordResetDto } from '../dto/confirm-password-reset-auth.dto';
import { UpdateCredentialsDto } from '../dto/update-credentials-auth.dto';
import { UpdateProfileDto } from '../dto/update-profile-auth.dto';

import type { AuthActor } from '../interface/auth.interface';
import { randomBytes } from 'node:crypto';

@Injectable()
export class EmployeeAuthResolver {
  private logger = new Logger(EmployeeAuthResolver.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly authUtils: AuthUtilsService,
    private readonly tokenService: TokenService,
  ) {}

  async login(dto: LoginDto): Promise<any> {
    const employee = await this.prisma.employee.findFirst({
      where: { email: dto.email },
      include: { department: true },
    });

    if (!employee || employee.deletedAt || employee.status !== 'ACTIVE') {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!this.authUtils.verifyPassword(dto.password, employee.password)) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const actor: AuthActor = this.authUtils.createActor({
      id: employee.id,
      principalType: 'EMPLOYEE',
      roleId: employee.departmentId,
    });

    const tokens = this.tokenService.generateTokens(actor);

    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        refreshToken: hashedRefresh,
        lastLoginAt: new Date(),
      },
    });

    const safeEmployee = this.authUtils.stripSensitive(employee, [
      'password',
      'refreshToken',
    ]);

    return {
      user: safeEmployee,
      actor,
      tokens,
    };
  }

  async refreshToken(rawToken: string): Promise<any> {
    const payload = this.tokenService.verifyRefreshToken(rawToken);

    if (!payload || payload.principalType !== 'EMPLOYEE') {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const employee = await this.prisma.employee.findUnique({
      where: { id: payload.sub },
    });

    if (
      !employee ||
      employee.deletedAt ||
      employee.status !== 'ACTIVE' ||
      !this.authUtils.verifyPassword(rawToken, employee.refreshToken!)
    ) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const actor = this.authUtils.createActor({
      id: employee.id,
      principalType: 'EMPLOYEE',
      roleId: employee.departmentId,
    });

    const tokens = this.tokenService.generateTokens(actor);

    const hashedRefresh = this.authUtils.hashPassword(tokens.refreshToken);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: { refreshToken: hashedRefresh },
    });

    const safeEmployee = this.authUtils.stripSensitive(employee, [
      'password',
      'refreshToken',
    ]);

    return {
      user: safeEmployee,
      actor,
      tokens,
    };
  }

  async logout(employeeId: string): Promise<void> {
    await this.prisma.employee.update({
      where: { id: employeeId },
      data: { refreshToken: null },
    });
  }

  async requestPasswordReset(dto: ForgotPasswordDto): Promise<any> {
    const employee = await this.prisma.employee.findUnique({
      where: { email: dto.email },
    });

    if (!employee) {
      return {
        message:
          'If an account with that email exists, a password reset link has been sent.',
      };
    }

    const rawToken = randomBytes(32).toString('hex');
    const hashed = this.authUtils.hashPassword(rawToken);
    const expires = new Date(Date.now() + 1000 * 60 * 30);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        passwordResetToken: hashed,
        passwordResetExpires: expires,
      },
    });

    return {
      message:
        'If an account with that email exists, a password reset link has been sent.',
    };
  }

  async confirmPasswordReset(dto: ConfirmPasswordResetDto): Promise<any> {
    const { token } = dto;

    const candidateEmployees = await this.prisma.employee.findMany({
      where: {
        passwordResetToken: { not: null },
        passwordResetExpires: { gt: new Date() },
      },
    });

    const matching = candidateEmployees.find((emp) => {
      try {
        this.authUtils.verifyPassword(token, emp.passwordResetToken!);
        return true;
      } catch {
        return false;
      }
    });

    if (!matching) {
      throw new BadRequestException('Invalid or expired token');
    }

    const newPasswordPlain = this.authUtils.generateRandomPassword();
    const newHashed = this.authUtils.hashPassword(newPasswordPlain);

    await this.prisma.employee.update({
      where: { id: matching.id },
      data: {
        password: newHashed,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    return {
      message: 'Password reset successfully.',
    };
  }

  async getCurrentUser(employeeId: string): Promise<any> {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
      include: { department: true },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    const safeEmployee = this.authUtils.stripSensitive(employee, [
      'password',
      'refreshToken',
      'passwordResetToken',
    ]);

    return safeEmployee;
  }

  async updateCredentials(
    employeeId: string,
    dto: UpdateCredentialsDto,
  ): Promise<any> {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    if (!dto.newPassword || !dto.currentPassword) {
      throw new BadRequestException(
        'Current password and new password are required',
      );
    }

    this.authUtils.verifyPassword(dto.currentPassword, employee.password);

    const newHashed = this.authUtils.hashPassword(dto.newPassword);

    await this.prisma.employee.update({
      where: { id: employee.id },
      data: {
        password: newHashed,
        refreshToken: null,
      },
    });

    return { message: 'Credentials updated successfully' };
  }

  async updateProfile(employeeId: string, dto: UpdateProfileDto): Promise<any> {
    const employee = await this.prisma.employee.findUnique({
      where: { id: employeeId },
    });

    if (!employee) throw new NotFoundException('Employee not found');

    await this.prisma.employee.update({
      where: { id: employeeId },
      data: {
        firstName: dto.firstName ?? employee.firstName,
        lastName: dto.lastName ?? employee.lastName,
        username: dto.username ?? employee.username,
        phoneNumber: dto.phoneNumber ?? employee.phoneNumber,
        email: dto.email ?? employee.email,
      },
    });

    return this.getCurrentUser(employeeId);
  }
}
