import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';

import { S3Service } from '../../common/utils/s3.utils';
import { FileDeleteHelper } from '../../common/utils/file-delete-helper.utils';
import { AuditLogService } from '../../audit/service/audit.service';

import { UpsertSystemSettingDto } from '../dto/upsert-system-setting.dto';
import { AuthActor } from '../../common/types/auth.type';

@Injectable()
export class SystemService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly s3Service: S3Service,
    private readonly auditService: AuditLogService,
  ) {}

  // ================= UPSERT =================
  async upsert(
    actor: AuthActor,
    dto: UpsertSystemSettingDto,
    files?: Express.Multer.File[],
  ) {
    let uploadedLogo: string | null = null;
    let uploadedFavicon: string | null = null;

    const fileMap = this.mapFiles(files);
    const userId = await this.getUserId(actor);

    try {
      uploadedLogo = await this.safeUpload(
        fileMap['companyLogo'],
        'system-setting/logo',
      );

      uploadedFavicon = await this.safeUpload(
        fileMap['favIcon'],
        'system-setting/favicon',
      );

      if (uploadedLogo) dto.companyLogo = uploadedLogo;
      if (uploadedFavicon) dto.favIcon = uploadedFavicon;

      const existing = await this.prisma.systemSetting.findUnique({
        where: { userId },
      });

      const setting = await this.prisma.systemSetting.upsert({
        where: { userId },
        create: {
          ...dto,
          userId,
          updatedBy: actor.id,
        },
        update: {
          ...dto,
          updatedBy: actor.id,
        },
      });

      // delete old files
      if (uploadedLogo && existing?.companyLogo) {
        await this.s3Service.delete({ fileUrl: existing.companyLogo });
      }

      if (uploadedFavicon && existing?.favIcon) {
        await this.s3Service.delete({ fileUrl: existing.favIcon });
      }

      return setting;
    } catch (err) {
      if (uploadedLogo) {
        await this.s3Service.delete({ fileUrl: uploadedLogo });
      }
      if (uploadedFavicon) {
        await this.s3Service.delete({ fileUrl: uploadedFavicon });
      }
      throw err;
    } finally {
      FileDeleteHelper.deleteUploadedImages(files);
    }
  }

  // ================= GET =================
  async get(actor: AuthActor) {
    const userId = await this.getUserId(actor);

    const setting = await this.prisma.systemSetting.findUnique({
      where: { userId },
    });

    if (!setting) {
      throw new ForbiddenException('System setting not found');
    }

    return setting;
  }

  // ================= DELETE =================
  async delete(actor: AuthActor) {
    const userId = await this.getUserId(actor);

    const existing = await this.prisma.systemSetting.findUnique({
      where: { userId },
    });

    if (!existing) {
      throw new ForbiddenException('Setting not found');
    }

    return this.prisma.systemSetting.delete({
      where: { userId },
    });
  }

  // ================= HELPERS =================
  private async getUserId(actor: AuthActor): Promise<string> {
    if (actor.principalType === 'USER') return actor.id;

    if (actor.principalType === 'EMPLOYEE') {
      if (!actor.roleId) throw new ForbiddenException('RoleId missing');

      const dept = await this.prisma.department.findFirst({
        where: { id: actor.roleId },
        select: { createdByUserId: true },
      });

      if (!dept?.createdByUserId) {
        throw new ForbiddenException('User not found');
      }

      return dept.createdByUserId;
    }

    throw new ForbiddenException();
  }

  // ================= FILE HELPERS =================
  private mapFiles(files?: Express.Multer.File[]) {
    const map: Record<string, Express.Multer.File | undefined> = {};
    if (!files) return map;

    for (const file of files) {
      map[file.fieldname] = file;
    }
    return map;
  }

  private async safeUpload(
    file?: Express.Multer.File | null,
    prefix = '',
  ): Promise<string | null> {
    if (!file) return null;
    return this.s3Service.upload(file.path, prefix);
  }
}
