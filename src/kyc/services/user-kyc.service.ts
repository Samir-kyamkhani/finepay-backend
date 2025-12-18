import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { CryptoService } from '../../common/utils/crypto.utils';
import { S3Service } from '../../common/utils/s3.utils';
import { FileDeleteHelper } from '../../common/utils/file-delete-helper.utils';

import { AuditLogService } from '../../audit/service/audit.service';

import { PrismaService } from '../../database/prisma-service';
import { AddressService } from '../../address/address.service';
import { PiiConsentService } from '../../pii-consent/service/pii-consent.service';

import { AuthActor } from '../../common/types/auth.type';

import { GetAllUserKycDto } from '../dto/user-kyc-get-all.dto';
import { CreateUserKycDto } from '../dto/user-kyc-create.dto';
import { CreatePiiConsentDto } from '../../pii-consent/dto/create-pii-consent.dto';
import { VerifyUserKycDto } from '../dto/user-kyc-verify.dto';
import { UpdateUserKycDto } from '../dto/user-kyc-update.dto';
import { EmailService } from '../../email/email.service';
import { AuditStatus } from '../../common/enums/audit.enum';
import { KycStatus } from '../../common/enums/kyc.enum';

@Injectable()
export class UserKycService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly addressService: AddressService,
    private readonly piiService: PiiConsentService,
    private readonly cryptoService: CryptoService,
    private readonly auditService: AuditLogService,
    private readonly emailService: EmailService,
    private readonly s3Service?: S3Service,
  ) {}

  // ===================================================================
  //  SINGLE API: GET ALL KYC WITH FULL HIERARCHY RULES
  // ===================================================================
  async getAll(dto: GetAllUserKycDto, currentUser: AuthActor) {}

  async create(
    dto: CreateUserKycDto,
    files?: Express.Multer.File[],
    currentUser?: AuthActor,
  ) {
    if (!currentUser?.id) {
      throw new BadRequestException('Invalid user');
    }

    const role = await this.validateRole(currentUser);
    const fileMap: Record<string, Express.Multer.File> = this.mapFiles(files);

    try {
      return await this.prisma.$transaction(async (tx) => {
        // Get user with their business
        const user = await tx.user.findFirst({
          where: {
            id: currentUser.id,
          },
          include: {
            business: true, // Include business to check ownership
          },
        });

        if (!user) {
          throw new NotFoundException('User not found');
        }

        if (!user.businessId || typeof user.businessId !== 'string') {
          throw new BadRequestException(
            'User is not associated with a business',
          );
        }

        const businessKyc = await tx.businessKyc.findUnique({
          where: { businessId: user.businessId },
          include: {
            business: true,
          },
        });

        if (!businessKyc) {
          throw new BadRequestException(
            'Business KYC must be completed before User KYC',
          );
        }

        const existingCount = await tx.userKyc.count({
          where: { businessKycId: businessKyc.id },
        });

        // FIX: Check if current user is the business owner
        // Compare current user ID with business owner's user ID
        const isOwner = user.businessId === businessKyc.businessId;

        // Admin CHILD → ONLY 1
        if (!isOwner && existingCount >= 1) {
          throw new ConflictException(
            'Only one User KYC allowed for admin child users',
          );
        }

        // OWNER RULES
        if (isOwner) {
          // NON-PARTNERSHIP → ONLY 1
          if (
            businessKyc.business.businessType !== 'PARTNERSHIP' &&
            existingCount >= 1
          ) {
            throw new ConflictException(
              'Only one User KYC allowed for business owner',
            );
          }

          // PARTNERSHIP → partnerKycNumbers
          if (
            businessKyc.business.businessType === 'PARTNERSHIP' &&
            businessKyc.partnerKycNumbers != null &&
            existingCount >= businessKyc.partnerKycNumbers
          ) {
            throw new ConflictException(
              `Only ${businessKyc.partnerKycNumbers} User KYC allowed for partnership business`,
            );
          }

          // If PARTNERSHIP but partnerKycNumbers is null, allow unlimited
          if (
            businessKyc.business.businessType === 'PARTNERSHIP' &&
            businessKyc.partnerKycNumbers == null
          ) {
            // No limit, allow creation
          }
        }

        // Rest of the code remains the same...
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

        // Upload files safely
        const panFile = await this.safeUpload(fileMap.panFile, 'user-kyc/pan');
        const aadhaarFile = await this.safeUpload(
          fileMap.aadhaarFile,
          'user-kyc/aadhaar',
        );
        const addressProofFile = await this.safeUpload(
          fileMap.addressProofFile,
          'user-kyc/address-proof',
        );
        const photo = await this.safeUpload(fileMap.photo, 'user-kyc/photo');

        const userKyc = await tx.userKyc.create({
          data: {
            submittedByUserId: currentUser.id,
            businessKycId: businessKyc.id,

            firstName: dto.firstName,
            lastName: dto.lastName,
            fatherName: dto.fatherName,
            dob: new Date(dto.dob),
            gender: dto.gender,

            addressId: address.id,
            panFile,
            aadhaarFile,
            addressProofFile,
            photo,
          },
        });

        const piiPayloads: CreatePiiConsentDto[] = [
          {
            userId: currentUser.id,
            piiType: 'PAN',
            piiHash: this.cryptoService.encrypt(dto.pan),
            scope: 'USER_KYC',
            userKycId: userKyc.id,
            providedAt: new Date(),
            expiresAt: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000),
          },
          {
            userId: currentUser.id,
            piiType: 'AADHAAR',
            piiHash: this.cryptoService.encrypt(dto.aadhaar),
            scope: 'USER_KYC',
            userKycId: userKyc.id,
            providedAt: new Date(),
            expiresAt: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000),
          },
        ];

        await this.piiService.create(piiPayloads, currentUser, tx);

        await this.auditService.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: 'USER',
            targetUserId: currentUser.id,
            action: 'CREATE_USER_KYC',
            description: 'User KYC created',
            resourceType: 'UserKyc',
            resourceId: userKyc.id,
            newData: dto,
            status: AuditStatus.SUCCESS,
          },
          tx,
        );

        if (!user?.email) {
          throw new BadRequestException('User email not found');
        }

        return userKyc;
      });
    } finally {
      FileDeleteHelper.deleteUploadedImages(files);
    }
  }

  // ---------------- GET BY USER ----------------
  async getById(id: string) {
    const kyc = await this.prisma.userKyc.findFirst({
      where: { id },
      include: {
        address: {
          include: {
            city: true,
            state: true,
          },
        },
        piiConsents: true,
      },
    });

    if (!kyc) {
      throw new NotFoundException('User KYC not found');
    }

    // ================== PII FORMAT ==================
    const pii = kyc.piiConsents.map((consent) => {
      let decrypted = '';
      try {
        decrypted = this.cryptoService.decrypt(consent.piiHash);
      } catch {
        decrypted = '';
      }

      return {
        type: consent.piiType,
        value: decrypted, // 🔴 raw encrypted/decrypted value (as in your response)
      };
    });

    // ================== FINAL RESPONSE ==================
    return {
      id: kyc.id,
      submittedByUserId: kyc.submittedByUserId,

      firstName: kyc.firstName,
      lastName: kyc.lastName,
      fatherName: kyc.fatherName,
      dob: kyc.dob,
      gender: kyc.gender,

      status: kyc.status,
      type: kyc.type,
      actionReason: kyc.actionReason ?? null,

      address: {
        address: kyc.address.address,
        pinCode: kyc.address.pinCode,

        cityName: kyc.address.city?.cityName ?? null,
        cityCode: kyc.address.city?.cityCode ?? null,

        stateName: kyc.address.state?.stateName ?? null,
        stateCode: kyc.address.state?.stateCode ?? null,
      },

      pii,

      panFile: kyc.panFile,
      aadhaarFile: kyc.aadhaarFile,
      addressProofFile: kyc.addressProofFile,
      photo: kyc.photo,

      createdAt: kyc.createdAt,
      updatedAt: kyc.updatedAt,

      actionAt: kyc.actionedAt ?? null,
      verifiedByUserId: kyc.verifiedByUserId ?? null,
      verifiedByType: kyc.verifiedByType ?? null,
    };
  }

  // ---------------- UPDATE ----------------
  async update(
    dto: UpdateUserKycDto,
    files?: Express.Multer.File[],
    currentUser?: AuthActor,
  ) {
    if (!currentUser?.id) {
      throw new BadRequestException('Invalid user');
    }

    const role = await this.validateRole(currentUser);
    const fileMap: Record<string, Express.Multer.File> = this.mapFiles(files);

    try {
      return await this.prisma.$transaction(async (tx) => {
        // 1. Get user with business
        const user = await tx.user.findFirst({
          where: { id: currentUser.id },
          include: { business: true },
        });

        if (!user) {
          throw new NotFoundException('User not found');
        }

        if (!user.businessId) {
          throw new BadRequestException(
            'User is not associated with a business',
          );
        }

        // 2. Fetch User KYC
        const existing = await tx.userKyc.findUnique({
          where: { id: dto.id },
          include: {
            businessKyc: {
              include: {
                business: true,
              },
            },
          },
        });

        if (!existing) {
          throw new NotFoundException('User KYC not found');
        }

        if (!existing.businessKyc) {
          throw new BadRequestException('Associated Business KYC not found');
        }

        if (existing.businessKyc.businessId !== user.businessId) {
          throw new ForbiddenException(
            'You are not allowed to update this User KYC',
          );
        }

        // 4. Update address if needed
        if (dto.address || dto.cityId || dto.stateId || dto.pinCode) {
          await this.addressService.update(
            existing.addressId,
            {
              address: dto.address,
              cityId: dto.cityId,
              stateId: dto.stateId,
              pinCode: dto.pinCode,
            },
            currentUser,
            tx,
          );
        }

        // 5. Upload files safely (ONLY if provided)
        const panFile = fileMap.panFile
          ? await this.safeUpload(fileMap.panFile, 'user-kyc/pan')
          : undefined;

        const aadhaarFile = fileMap.aadhaarFile
          ? await this.safeUpload(fileMap.aadhaarFile, 'user-kyc/aadhaar')
          : undefined;

        const addressProofFile = fileMap.addressProofFile
          ? await this.safeUpload(
              fileMap.addressProofFile,
              'user-kyc/address-proof',
            )
          : undefined;

        const photo = fileMap.photo
          ? await this.safeUpload(fileMap.photo, 'user-kyc/photo')
          : undefined;

        // 6. Update User KYC
        const updated = await tx.userKyc.update({
          where: { id: dto.id },
          data: {
            firstName: dto.firstName ?? existing.firstName,
            lastName: dto.lastName ?? existing.lastName,
            fatherName: dto.fatherName ?? existing.fatherName,
            dob: dto.dob ? new Date(dto.dob) : existing.dob,
            gender: dto.gender ?? existing.gender,

            panFile: panFile ? { set: panFile } : undefined,
            aadhaarFile: aadhaarFile ? { set: aadhaarFile } : undefined,
            addressProofFile: addressProofFile
              ? { set: addressProofFile }
              : undefined,
            photo: photo ? { set: photo } : undefined,
          },
          include: {
            submittedByUser: {
              select: {
                role: { select: { name: true } },
                email: true,
              },
            },
          },
        });

        // 7. Update PII if changed
        if (dto.pan || dto.aadhaar) {
          await this.piiService.update(dto, currentUser, tx);
        }

        // 8. Audit log
        await this.auditService.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: updated.submittedByUser.role.name,
            targetUserId: currentUser.id,
            action: 'UPDATE_USER_KYC',
            resourceType: 'UserKyc',
            resourceId: updated.id,
            description: `User KYC updated for ${updated.firstName} ${updated.lastName}`,
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

  // ---------------- VERIFY admin & employee and root ----------------
  async verify(kycId: string, dto: VerifyUserKycDto, currentUser: AuthActor) {
    const role = await this.validateRole(currentUser);

    const kyc = await this.prisma.userKyc.findUnique({
      where: { id: kycId },
    });

    if (!kyc) {
      throw new NotFoundException('User KYC not found');
    }

    const updated = await this.prisma.userKyc.update({
      where: { id: kycId },
      data: {
        status: dto.status,
        actionReason:
          dto.status === KycStatus.REJECTED ? (dto.actionReason ?? '') : '',
        actionedAt: dto.status === KycStatus.VERIFIED ? new Date() : null,
        verifiedByUserId: currentUser.id,
        verifiedByType: role.name,
      },
      include: {
        submittedByUser: {
          include: {
            role: {
              select: {
                name: true,
              },
            },
          },
        },
      },
    });

    // ---------------- AUDIT LOG ----------------
    await this.auditService.create({
      performerType: role.name,
      performerId: currentUser.id,
      targetUserType: updated.submittedByUser.role.name,
      targetUserId: updated.submittedByUser.id,
      action: 'VERIFY_USER_KYC',
      resourceType: 'UserKyc',
      resourceId: kycId,
      description: `User KYC marked as ${dto.status}`,
      newData: dto,
      status: AuditStatus.SUCCESS,
    });

    return updated;
  }

  // ---------------- DELETE ----------------
  async delete(kycId: string, currentUser: AuthActor) {
    const role = await this.validateRole(currentUser);

    const kyc = await this.prisma.userKyc.findUnique({
      where: { id: kycId },
      include: {
        user: true,
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
      throw new NotFoundException('User KYC not found');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: currentUser.id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.$transaction(async (tx) => {
      const piiConsents = await tx.piiConsent.findMany({
        where: { userKycId: kycId },
      });

      if (!piiConsents.length) {
        throw new NotFoundException('piiConsent not found');
      }

      for (const consent of piiConsents) {
        await this.piiService.delete(consent.id, currentUser, tx);
      }

      // Delete User KYC
      await tx.userKyc.delete({
        where: { id: kycId },
      });

      // Delete Address
      if (kyc.addressId) {
        await this.addressService.delete(kyc.addressId, currentUser, tx);
      }

      // Audit log
      await this.auditService.create(
        {
          performerType: role.name,
          performerId: currentUser.id,
          targetUserType: kyc.submittedByUser?.role?.name,
          targetUserId: kyc.submittedByUserId,
          action: 'DELETE_USER_KYC',
          description: 'User KYC deleted',
          resourceType: 'UserKyc',
          resourceId: kycId,
          oldData: kyc,
          status: AuditStatus.SUCCESS,
        },
        tx,
      );
    });

    return { message: 'User KYC deleted successfully' };
  }

  // ---------------- PRIVATE HELPERS ----------------
  private async validateRole(currentUser: AuthActor) {
    if (!currentUser.roleId) throw new BadRequestException('Invalid role');

    const role = await this.prisma.role.findUnique({
      where: { id: currentUser.roleId },
    });

    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  private mapFiles(files?: Express.Multer.File[]) {
    const map = {};

    if (!files) return map;

    files.forEach((file) => {
      map[file.fieldname] = file;
    });

    return map;
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
