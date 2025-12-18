import {
  Injectable,
  BadRequestException,
  ConflictException,
  NotFoundException,
  Logger,
  ForbiddenException,
} from '@nestjs/common';
import { AuthActor } from '../../common/types/auth.type';

import { CryptoService } from '../../common/utils/crypto.utils';
import { S3Service } from '../../common/utils/s3.utils';
import { MaskService } from '../../common/utils/mask.utils';
import { FileDeleteHelper } from '../../common/utils/file-delete-helper.utils';

import { PrismaService } from '../../database/prisma-service';
import { AuditLogService } from '../../audit/service/audit.service';
import { AddressService } from '../../address/address.service';
import { PiiConsentService } from '../../pii-consent/service/pii-consent.service';

import { BusinessKycQueryDto } from '../dto/business-kyc-query.dto';
import { CreateBusinessKycDto } from '../dto/business-kyc-create.dto';
import { UpdateBusinessKycDto } from '../dto/business-kyc-update.dto';
import { VerifyBusinessKycDto } from '../dto/business-kyc-verify.dto';
import { UpdatePiiConsentDto } from '../../pii-consent/dto/update-pii-consent.dto';
import { CreatePiiConsentDto } from '../../pii-consent/dto/create-pii-consent.dto';

import {
  AuditStatus,
  BusinessType,
  Prisma,
} from '../../../generated/prisma/client';
import { KycStatus } from '../../common/enums/kyc.enum';

@Injectable()
export class BusinessKycService {
  private readonly logger = new Logger(BusinessKycService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly piiService: PiiConsentService,
    private readonly cryptoService: CryptoService,
    private readonly auditService: AuditLogService,
    private readonly addressService: AddressService,
    private readonly maskService: MaskService,
    private readonly s3Service?: S3Service,
  ) {}

  // ================= GET ALL by root and employee =================
  async getAll(query: BusinessKycQueryDto, currentUser: AuthActor) {}

  // ================= CREATE by admin =================
  async create(
    dto: CreateBusinessKycDto,
    currentUser: AuthActor,
    files?: Record<string, Express.Multer.File[]>,
  ) {
    if (!currentUser?.id) {
      throw new BadRequestException('Invalid user');
    }

    const role = await this.validateRole(currentUser);
    const fileMap = this.mapFiles(files);

    try {
      return await this.prisma.$transaction(async (tx) => {
        // Get user with business info
        const user = await tx.user.findUnique({
          where: { id: currentUser.id },
          include: {
            business: true,
          },
        });

        if (!user) {
          throw new NotFoundException('User not found');
        }

        if (!user.businessId) {
          throw new BadRequestException(
            'User is not associated with a business',
          );
        }

        const exists = await tx.businessKyc.findFirst({
          where: { businessId: user.businessId },
        });

        if (exists) {
          throw new ConflictException(
            'Business KYC already exists for this business',
          );
        }

        // ---------- FILE VALIDATION ----------
        if (!fileMap.panFile) {
          throw new BadRequestException('PAN file is required');
        }

        // GST file is optional according to schema (? mark)
        if (!fileMap.gstFile) {
          this.logger.warn(
            'GST file not provided, KYC will be created without GST',
          );
        }

        // ---------- ADDRESS ----------
        const address = await this.addressService.create(
          {
            address: dto.address,
            pinCode: dto.pinCode,
            cityId: dto.cityId,
            stateId: dto.stateId,
          },
          currentUser,
          tx,
        );

        if (!user.business) {
          throw new NotFoundException('User has no business');
        }

        // ---------- BUSINESS RULE VALIDATION ----------
        // Get business type from user's business
        const businessType = user.business.businessType;

        if (
          businessType === BusinessType.PRIVATE_LIMITED &&
          dto.directorsCount === undefined
        ) {
          throw new BadRequestException(
            'directorsCount is required for PRIVATE_LIMITED',
          );
        }

        if (
          businessType === BusinessType.PARTNERSHIP &&
          dto.partnerKycNumbers === undefined
        ) {
          throw new BadRequestException(
            'partnerKycNumbers is required for PARTNERSHIP',
          );
        }

        // Set defaults based on business type
        const directorsCount =
          dto.directorsCount ??
          (businessType === BusinessType.PRIVATE_LIMITED ? 1 : 0);

        const partnerKycNumbers =
          dto.partnerKycNumbers ??
          (businessType === BusinessType.PARTNERSHIP ? 1 : null);

        // ---------- PRISMA CREATE INPUT ----------
        const kycData: Prisma.BusinessKycCreateInput = {
          // Required connections
          business: { connect: { id: user.businessId } },
          address: { connect: { id: address.id } },
          submittedByUser: { connect: { id: currentUser.id } },

          // Required fields
          panFile: await this.safeUpload(fileMap.panFile, 'business/pan'),
          directorsCount,

          // Optional fields (according to schema)
          gstFile: fileMap.gstFile
            ? await this.safeUpload(fileMap.gstFile, 'business/gst')
            : undefined,
          cin: dto.cin ?? undefined,
          moaFile: fileMap.moaFile
            ? await this.safeUpload(fileMap.moaFile, 'business/moa')
            : undefined,
          aoaFile: fileMap.aoaFile
            ? await this.safeUpload(fileMap.aoaFile, 'business/aoa')
            : undefined,
          brDoc: fileMap.brDoc
            ? await this.safeUpload(fileMap.brDoc, 'business/br-doc')
            : undefined,
          partnershipDeed: fileMap.partnershipDeed
            ? await this.safeUpload(
                fileMap.partnershipDeed,
                'business/partnership-deed',
              )
            : undefined,
          partnerKycNumbers,
          directorShareholding: fileMap.directorShareholding
            ? await this.safeUpload(
                fileMap.directorShareholding,
                'business/director-shareholding',
              )
            : undefined,
        };

        const kyc = await tx.businessKyc.create({ data: kycData });

        // ---------- PII ----------
        const expiresAt = new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000);
        const piiPayloads: CreatePiiConsentDto[] = [];

        if (dto.pan) {
          piiPayloads.push({
            userId: currentUser.id,
            piiType: 'PAN',
            piiHash: this.cryptoService.encrypt(dto.pan.toUpperCase()),
            scope: 'BUSINESS_KYC',
            businessKycId: kyc.id,
            providedAt: new Date(),
            expiresAt,
          });
        }

        if (dto.gst) {
          piiPayloads.push({
            userId: currentUser.id,
            piiType: 'GST',
            piiHash: this.cryptoService.encrypt(dto.gst.toUpperCase()),
            scope: 'BUSINESS_KYC',
            businessKycId: kyc.id,
            providedAt: new Date(),
            expiresAt,
          });
        }

        if (dto.cin) {
          piiPayloads.push({
            userId: currentUser.id,
            piiType: 'CIN',
            piiHash: this.cryptoService.encrypt(dto.cin.toUpperCase()),
            scope: 'BUSINESS_KYC',
            businessKycId: kyc.id,
            providedAt: new Date(),
            expiresAt,
          });
        }

        if (piiPayloads.length) {
          await this.piiService.create(piiPayloads, currentUser, tx);
        }

        // ---------- AUDIT ----------
        await this.auditService.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: role.name,
            targetUserId: currentUser.id,
            action: 'CREATE_BUSINESS_KYC',
            resourceType: 'BusinessKyc',
            resourceId: kyc.id,
            description: 'Business KYC created',
            status: AuditStatus.SUCCESS,
          },
          tx,
        );

        return kyc;
      });
    } finally {
      FileDeleteHelper.deleteUploadedImages(files);
    }
  }

  // ================= UPDATE by admin =================
  async update(
    id: string,
    dto: UpdateBusinessKycDto,
    currentUser: AuthActor,
    files?: Record<string, Express.Multer.File[]>,
  ) {
    if (!currentUser?.id) {
      throw new BadRequestException('Invalid user');
    }

    const role = await this.validateRole(currentUser);
    const fileMap = this.mapFiles(files);

    try {
      return await this.prisma.$transaction(async (tx) => {
        // ---------- EXISTING KYC ----------
        const existing = await tx.businessKyc.findUnique({
          where: { id },
          include: {
            business: true,
          },
        });

        if (!existing) {
          throw new NotFoundException('Business KYC not found');
        }

        if (!existing.business) {
          throw new NotFoundException('User has no business');
        }

        // ---------- BUSINESS TYPE ----------
        const businessType = existing.business.businessType;

        if (
          businessType === BusinessType.PRIVATE_LIMITED &&
          (dto.directorsCount ?? existing.directorsCount) === 0
        ) {
          throw new BadRequestException(
            'directorsCount is required for PRIVATE_LIMITED',
          );
        }

        if (
          businessType === BusinessType.PARTNERSHIP &&
          (dto.partnerKycNumbers ?? existing.partnerKycNumbers) == null
        ) {
          throw new BadRequestException(
            'partnerKycNumbers is required for PARTNERSHIP',
          );
        }

        // ---------- PRISMA UPDATE INPUT ----------
        const updateData: Prisma.BusinessKycUpdateInput = {
          ...(dto.cin !== undefined && { cin: dto.cin }),
          ...(dto.directorsCount !== undefined && {
            directorsCount: dto.directorsCount,
          }),
          ...(dto.partnerKycNumbers !== undefined && {
            partnerKycNumbers: dto.partnerKycNumbers,
          }),
        };

        // ---------- FILE UPDATES ----------
        if (fileMap.panFile) {
          updateData.panFile = await this.safeUpload(
            fileMap.panFile,
            'business/pan',
          );
        }

        if (fileMap.gstFile) {
          updateData.gstFile = await this.safeUpload(
            fileMap.gstFile,
            'business/gst',
          );
        }

        if (fileMap.moaFile) {
          updateData.moaFile = await this.safeUpload(
            fileMap.moaFile,
            'business/moa',
          );
        }

        if (fileMap.aoaFile) {
          updateData.aoaFile = await this.safeUpload(
            fileMap.aoaFile,
            'business/aoa',
          );
        }

        if (fileMap.directorShareholding) {
          updateData.directorShareholding = await this.safeUpload(
            fileMap.directorShareholding,
            'business/director-shareholding',
          );
        }

        // ---------- UPDATE BUSINESS KYC ----------
        const updated = await tx.businessKyc.update({
          where: { id },
          data: updateData,
        });

        // ---------- ADDRESS UPDATE ----------
        if (dto.address || dto.pinCode || dto.cityId || dto.stateId) {
          await this.addressService.update(
            existing.addressId,
            {
              address: dto.address,
              pinCode: dto.pinCode,
              cityId: dto.cityId,
              stateId: dto.stateId,
            },
            currentUser,
            tx,
          );
        }

        // ---------- PII UPDATE ----------
        const piiConsents = await tx.piiConsent.findMany({
          where: {
            businessKycId: id,
            piiType: { in: ['PAN', 'GST', 'UDHYAM'] },
          },
        });

        const piiMap = Object.fromEntries(
          piiConsents.map((p) => [p.piiType, p]),
        );

        const piiUpdates: UpdatePiiConsentDto[] = [];
        const piiCreates: CreatePiiConsentDto[] = [];
        const expiresAt = new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000);

        const handlePii = (type: 'PAN' | 'GST' | 'UDHYAM', value?: string) => {
          if (!value?.trim()) return;

          const encrypted = this.cryptoService.encrypt(
            value.trim().toUpperCase(),
          );

          if (piiMap[type]) {
            piiUpdates.push({
              id: piiMap[type].id,
              piiType: type,
              piiHash: encrypted,
              scope: piiMap[type].scope,
              businessKycId: id,
            });
          } else {
            piiCreates.push({
              userId: existing.submittedByUserId,
              piiType: type,
              piiHash: encrypted,
              scope: 'BUSINESS_KYC',
              businessKycId: id,
              providedAt: new Date(),
              expiresAt,
            });
          }
        };

        handlePii('PAN', dto.pan);
        handlePii('GST', dto.gst);
        handlePii('UDHYAM', dto.udhyamAadhar);

        if (piiUpdates.length) {
          await this.piiService.update(piiUpdates, currentUser, tx);
        }

        if (piiCreates.length) {
          await this.piiService.create(piiCreates, currentUser, tx);
        }

        // ---------- AUDIT ----------
        await this.auditService.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: role.name,
            targetUserId: currentUser.id,
            action: 'UPDATE_BUSINESS_KYC',
            resourceType: 'BusinessKyc',
            resourceId: id,
            description: 'Business KYC updated',
            newData: dto,
            status: AuditStatus.SUCCESS,
          },
          tx,
        );

        return updated;
      });
    } finally {
      FileDeleteHelper.deleteUploadedImages(files);
    }
  }

  // ================= GET BY ID =================
  async getById(id: string) {
    const kyc = await this.prisma.businessKyc.findUnique({
      where: { id },
      include: {
        address: { include: { city: true, state: true } },
        piiConsents: true,
      },
    });

    if (!kyc) throw new NotFoundException('Business KYC not found');

    return kyc;
  }

  // ================= verify by admin & =================
  async verify(
    kycId: string,
    dto: VerifyBusinessKycDto,
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    if (currentUser.principalType === 'USER') {
      throw new ForbiddenException('User cannot verify KYC');
    }

    // Update KYC status
    const updatedKyc = await this.prisma.businessKyc.update({
      where: { id: kycId },
      data: {
        status: dto.status,
        actionReason:
          dto.status === KycStatus.REJECTED ||
          dto.status === KycStatus.SUSPENDED
            ? dto.actionReason
            : null,
        actionedAt: new Date(),
      },
    });

    // Create audit log
    await this.auditService.create(
      {
        performerType: currentUser.principalType || 'UNKNOWN', // make sure role exists
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: currentUser.id,
        action: 'UPDATE_BUSINESS_KYC',
        resourceType: 'BusinessKyc',
        resourceId: kycId,
        description: 'Business KYC updated',
        newData: dto,
        status: AuditStatus.SUCCESS,
      },
      tx, // pass transaction if any
    );

    return updatedKyc;
  }

  // ---------------- DELETE ----------------
  async delete(kycId: string, currentUser: AuthActor) {
    const role = await this.validateRole(currentUser);

    const kyc = await this.prisma.businessKyc.findUnique({
      where: { id: kycId },
      include: {
        business: true,
        submittedByUser: {
          select: {
            id: true,
            role: {
              select: {
                name: true,
              },
            },
          },
        },
      },
    });

    if (!kyc) {
      throw new NotFoundException('Business KYC not found');
    }

    // Check permissions
    const user = await this.prisma.user.findUnique({
      where: { id: currentUser.id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Root/Employee can delete any KYC, but users can only delete their own business KYC
    if (
      currentUser.principalType === 'USER' &&
      user.businessId !== kyc.businessId
    ) {
      throw new ForbiddenException(
        'You can only delete KYC for your own business',
      );
    }

    await this.prisma.$transaction(async (tx) => {
      const piiConsents = await tx.piiConsent.findMany({
        where: { businessKycId: kycId },
      });

      if (piiConsents.length === 0) {
        throw new NotFoundException('piiConsent not found');
      }

      for (const consent of piiConsents) {
        await this.piiService.delete(consent.id, currentUser, tx);
      }

      // Delete Business KYC
      await tx.businessKyc.delete({
        where: { id: kycId },
      });

      // Delete Address
      await this.addressService.delete(kyc.addressId, currentUser, tx);

      // Audit Log
      await this.auditService.create(
        {
          performerType: role.name,
          performerId: currentUser.id,
          targetUserType: kyc.submittedByUser?.role?.name ?? 'USER',
          targetUserId: kyc.submittedByUserId,
          action: 'DELETE_BUSINESS_KYC',
          description: 'Business KYC deleted',
          resourceType: 'BusinessKyc',
          resourceId: kycId,
          oldData: kyc,
          status: AuditStatus.SUCCESS,
        },
        tx,
      );
    });

    return { message: 'Business KYC deleted successfully' };
  }

  private async validateRole(
    currentUser: AuthActor,
  ): Promise<{ id: string; name: string }> {
    if (!currentUser.roleId) {
      throw new BadRequestException('User role is missing');
    }

    const role = await this.prisma.role.findUnique({
      where: { id: currentUser.roleId },
    });

    if (role) {
      return { id: role.id, name: role.name };
    }

    const department = await this.prisma.department.findUnique({
      where: { id: currentUser.roleId },
    });

    if (department) {
      return { id: department.id, name: department.name };
    }

    throw new NotFoundException('Role or Department not found');
  }

  private mapFiles(files?: Record<string, Express.Multer.File[]>) {
    if (!files) return {};
    return {
      panFile: files.panFile?.[0],
      gstFile: files.gstFile?.[0],
      udhyamAadhar: files.udhyamAadhar?.[0] ?? null,
      moaFile: files.moaFile?.[0] ?? null,
      aoaFile: files.aoaFile?.[0] ?? null,
      brDoc: files.brDoc?.[0] ?? null,
      partnershipDeed: files.partnershipDeed?.[0] ?? null,
      directorShareholding: files.directorShareholding?.[0] ?? null,
    };
  }

  private async safeUpload(
    file: Express.Multer.File,
    prefix = '',
  ): Promise<string> {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    if (!this.s3Service) {
      throw new Error('S3 not initialized');
    }

    const result = await this.s3Service.upload(file.path, prefix);

    if (!result) {
      throw new Error('File upload failed');
    }

    return result;
  }
}
