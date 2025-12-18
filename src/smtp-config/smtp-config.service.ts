import {
  Injectable,
  InternalServerErrorException,
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../database/prisma-service';
import { CreateSmtpConfigDto } from './dto/create-smtp-config.dto';
import { UpdateSmtpConfigDto } from './dto/update-smtp-config.dto';
import { CryptoService } from '../common/utils/crypto.utils';
import { AuditLogService } from '../audit/service/audit.service';
import { AuthActor } from '../common/types/auth.type';
import { AuditStatus } from '../../generated/prisma/enums';
import { Prisma } from '../../generated/prisma/client';
import { EmailService } from '../email/email.service';
import { SentMessageInfo } from 'nodemailer';

@Injectable()
export class SmtpConfigService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cryptoService: CryptoService,
    private readonly auditService: AuditLogService,
    private readonly sendMailService: EmailService,
  ) {}

  // ================= CREATE =================
  async create(currentUser: AuthActor, dto: CreateSmtpConfigDto) {
    try {
      // Check if SMTP already exists for user
      const existing = await this.prisma.smtpConfig.findUnique({
        where: { userId: currentUser.id },
      });

      if (existing) {
        throw new ConflictException('SMTP already configured for this user');
      }

      const smtp = await this.prisma.smtpConfig.create({
        data: {
          userId: currentUser.id,
          provider: dto.provider,
          host: dto.host,
          port: dto.port,
          secure: dto.secure,
          username: dto.username,
          passwordEnc: this.cryptoService.encrypt(dto.password),
          fromEmail: dto.fromEmail,
          supportEmail: dto.supportEmail || '',
          fromName: dto.fromName,
        },
      });

      await this.auditService.create({
        performerType: currentUser.principalType,
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: currentUser.id,
        action: 'SMTP_CREATE',
        description: 'SMTP configuration created',
        resourceType: 'SmtpConfig',
        resourceId: smtp.id,
        newData: {
          ...dto,
          password: '***ENCRYPTED***', // Don't log actual password
        },
        status: AuditStatus.SUCCESS,
      });

      return smtp;
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ConflictException('SMTP already configured for this user');
        }
      }
      if (err instanceof ConflictException) {
        throw err;
      }
      throw new InternalServerErrorException(
        'Failed to create SMTP configuration',
      );
    }
  }

  // ================= UPDATE =================
  async update(userId: string, dto: UpdateSmtpConfigDto) {
    try {
      const existing = await this.prisma.smtpConfig.findUnique({
        where: { userId },
      });

      if (!existing) {
        throw new NotFoundException('SMTP configuration not found');
      }

      const data: UpdateSmtpConfigDto = { ...dto };

      // Handle password update
      if (dto.password) {
        data.password = this.cryptoService.encrypt(dto.password);
        delete data.password; // Remove plain password field
      }

      const updatedSmtp = await this.prisma.smtpConfig.update({
        where: { userId },
        data,
      });

      await this.auditService.create({
        performerType: 'USER',
        performerId: userId,
        targetUserType: 'USER',
        targetUserId: userId,
        action: 'SMTP_UPDATE',
        description: 'SMTP configuration updated',
        resourceType: 'SmtpConfig',
        resourceId: updatedSmtp.id,
        newData: {
          ...dto,
          password: dto.password ? '***ENCRYPTED***' : undefined,
        },
        status: AuditStatus.SUCCESS,
      });

      return updatedSmtp;
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2025') {
          throw new NotFoundException('SMTP configuration not found');
        }
      }
      if (err instanceof NotFoundException) {
        throw err;
      }
      throw new InternalServerErrorException(
        'Failed to update SMTP configuration',
      );
    }
  }

  // ================= DELETE =================
  async remove(userId: string) {
    try {
      const existing = await this.prisma.smtpConfig.findUnique({
        where: { userId },
      });

      if (!existing) {
        throw new NotFoundException('SMTP configuration not found');
      }

      await this.prisma.smtpConfig.delete({
        where: { userId },
      });

      await this.auditService.create({
        performerType: 'USER',
        performerId: userId,
        targetUserType: 'USER',
        targetUserId: userId,
        action: 'SMTP_DELETE',
        description: 'SMTP configuration deleted',
        resourceType: 'SmtpConfig',
        resourceId: existing.id,
        oldData: {
          ...existing,
          passwordEnc: '***ENCRYPTED***',
        },
        status: AuditStatus.SUCCESS,
      });

      return { message: 'SMTP configuration deleted successfully' };
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2025') {
          throw new NotFoundException('SMTP configuration not found');
        }
      }
      if (err instanceof NotFoundException) {
        throw err;
      }
      throw new InternalServerErrorException(
        'Failed to delete SMTP configuration',
      );
    }
  }

  // ================= GET BY USER =================
  async getByUserId(userId: string) {
    const smtp = await this.prisma.smtpConfig.findUnique({
      where: { userId },
    });

    if (!smtp) {
      throw new NotFoundException('SMTP configuration not found');
    }

    return smtp;
  }

  // ================= GET ALL =================
  async getAll() {
    return this.prisma.smtpConfig.findMany({
      orderBy: { createdAt: 'desc' },
    });
  }

  // ================= HIERARCHY SMTP RESOLVE =================
  async resolveSmtpConfig(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, hierarchyPath: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    /**
     * Example hierarchyPath: 0/1/2
     * Effective chain: [self, parent, root]
     */
    const hierarchyChain = [
      user.id,
      ...user.hierarchyPath.split('/').filter(Boolean).reverse(),
    ];

    const smtpConfigs = await this.prisma.smtpConfig.findMany({
      where: {
        userId: { in: hierarchyChain },
        isActive: true,
      },
    });

    // closest ancestor SMTP wins
    for (const uid of hierarchyChain) {
      const smtp = smtpConfigs.find((s) => s.userId === uid);
      if (smtp) return smtp;
    }

    throw new NotFoundException('SMTP configuration not found in hierarchy');
  }

  // ================= GET SUPPORT EMAIL =================
  async getSupportEmail(userId: string) {
    try {
      const smtp = await this.resolveSmtpConfig(userId);
      return smtp.supportEmail || smtp.fromEmail;
    } catch (err) {
      const error = err as Error;
      throw new BadRequestException(
        'Could not determine support email',
        error.message,
      );
    }
  }

  // ================= TEST SMTP =================
  async testSmtp(
    currentUser: AuthActor,
    testEmail: string,
  ): Promise<SentMessageInfo> {
    const supportEmail = await this.getSupportEmail(currentUser.id);

    return this.sendMailService.sendMail(
      currentUser.id,
      testEmail,
      'SMTP Test - Successful',
      `
    <div style="font-family: Arial, sans-serif; padding: 20px;">
      <h2 style="color: #4CAF50;">✅ SMTP Configuration Test Successful</h2>
      <p>Your SMTP configuration is working correctly.</p>
      <p><strong>Test Time:</strong> ${new Date().toLocaleString()}</p>
      <p><strong>Tested By:</strong> User ID: ${currentUser.id}</p>
      <p><strong>Support Email:</strong> ${supportEmail}</p>
      <hr>
      <p style="color: #666; font-size: 12px;">
        This is an automated test email from the platform.
      </p>
    </div>
  `,
      `Your SMTP configuration is working correctly.
Test Time: ${new Date().toLocaleString()}
Support Email: ${supportEmail}`,
    );
  }
}
