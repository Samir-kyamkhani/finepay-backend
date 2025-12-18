import {
  Injectable,
  ConflictException,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';
import { AuditLogService } from '../../audit/service/audit.service';

import { AuthActor } from '../../common/types/auth.type';

import { CryptoService } from '../../common/utils/crypto.utils';

import { CreatePiiConsentDto } from '../dto/create-pii-consent.dto';
import { CreateAuditLogDto } from '../../audit/dto/create-audit-log.dto';
import { UpdatePiiConsentDto } from '../dto/update-pii-consent.dto';

import {
  AuditStatus,
  PiiConsent,
  Prisma,
} from '../../../generated/prisma/client';

@Injectable()
export class PiiConsentService {
  constructor(
    private prisma: PrismaService,
    private crypto: CryptoService,
    private audit: AuditLogService,
  ) {}

  async create(
    payload: CreatePiiConsentDto | CreatePiiConsentDto[],
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    const prisma = tx ?? this.prisma;

    if (!currentUser) {
      throw new UnauthorizedException('Invalid user');
    }

    const items = Array.isArray(payload) ? payload : [payload];
    const results: PiiConsent[] = [];

    try {
      const role = await this.validateRole(currentUser);

      for (const item of items) {
        const {
          userId,
          piiType,
          scope,
          piiHash,
          businessKycId,
          userKycId,
          providedAt,
          expiresAt,
        } = item;

        if (!userId || !piiType || !scope || !piiHash) {
          throw new BadRequestException(
            'userId, piiType, scope and piiHash are required',
          );
        }

        const existing = await prisma.piiConsent.findFirst({
          where: { userId, piiType, scope },
        });

        if (existing) {
          throw new ConflictException('PII Consent already exists');
        }

        const encryptedHash = this.crypto.encrypt(piiHash);

        const fiveYearsFromNow = new Date();
        fiveYearsFromNow.setFullYear(fiveYearsFromNow.getFullYear() + 5);

        const newConsent = await prisma.piiConsent.create({
          data: {
            userId,
            piiType,
            scope,
            piiHash: encryptedHash,
            businessKycId: businessKycId ?? null,
            userKycId: userKycId ?? null,
            providedAt: providedAt ?? new Date(),
            expiresAt: expiresAt ?? fiveYearsFromNow,
          },
        });

        // ✅ Proper audit log for creation
        await this.audit.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: 'USER',
            targetUserId: userId,
            action: 'CREATE_PII_CONSENT',
            description: `Created PII consent of type ${piiType} for user ${userId}`,
            resourceType: 'PiiConsent',
            resourceId: newConsent.id,
            newData: newConsent,
            status: AuditStatus.SUCCESS,
          } satisfies CreateAuditLogDto,
          tx,
        );

        results.push(newConsent);
      }

      return Array.isArray(payload) ? results : results[0];
    } catch (err: unknown) {
      throw new InternalServerErrorException(
        err instanceof Error ? err.message : 'Unknown error',
      );
    }
  }

  async update(
    payload: UpdatePiiConsentDto | UpdatePiiConsentDto[],
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    if (!currentUser?.id) {
      throw new UnauthorizedException('Invalid user');
    }

    const prisma = tx ?? this.prisma;
    const items = Array.isArray(payload) ? payload : [payload];

    const results: PiiConsent[] = [];

    for (const item of items) {
      const { id, piiType, scope, piiHash, businessKycId, userKycId } = item;

      if (!id) {
        throw new BadRequestException('PII Consent ID is required');
      }

      const existing = await prisma.piiConsent.findUnique({
        where: { id },
      });

      if (!existing) {
        throw new NotFoundException('PII Consent not found');
      }

      const duplicate = await prisma.piiConsent.findFirst({
        where: {
          userId: existing.userId,
          piiType: piiType ?? existing.piiType,
          scope: scope ?? existing.scope,
          NOT: { id },
        },
      });

      const role = await this.validateRole(currentUser);

      if (duplicate) {
        await this.audit.create(
          {
            performerType: role.name,
            performerId: currentUser.id,
            targetUserType: 'USER',
            targetUserId: existing.userId,
            action: 'UPDATE_PII_CONSENT',
            description: 'Duplicate PII Consent detected',
            resourceType: 'PiiConsent',
            resourceId: id,
            status: AuditStatus.FAILED,
            metadata: { reason: 'Duplicate PII' },
          } satisfies CreateAuditLogDto,
          tx,
        );

        throw new ConflictException('Duplicate PII Consent exists');
      }

      // FIX 2: Prisma UpdateInput (not DTO)
      const updateData: Prisma.PiiConsentUpdateInput = {};

      if (piiType !== undefined) updateData.piiType = piiType;
      if (scope !== undefined) updateData.scope = scope;

      if (piiHash !== undefined) {
        updateData.piiHash = this.crypto.encrypt(piiHash);
      }

      // ✅ RELATION UPDATE (IMPORTANT)
      if (businessKycId !== undefined) {
        updateData.businessKyc =
          businessKycId === null
            ? { disconnect: true }
            : { connect: { id: businessKycId } };
      }

      if (userKycId !== undefined) {
        updateData.userKyc =
          userKycId === null
            ? { disconnect: true }
            : { connect: { id: userKycId } };
      }

      const updated = await prisma.piiConsent.update({
        where: { id },
        data: updateData,
      });

      results.push(updated); // ✅ FIX 3

      await this.audit.create(
        {
          performerType: role.name,
          performerId: currentUser.id,
          targetUserType: 'USER',
          targetUserId: existing.userId,
          action: 'UPDATE_PII_CONSENT',
          description: 'Updated PII Consent',
          resourceType: 'PiiConsent',
          resourceId: id,
          oldData: existing,
          newData: updateData,
          status: AuditStatus.SUCCESS,
        } satisfies CreateAuditLogDto,
        tx,
      );
    }

    return Array.isArray(payload) ? results : results[0];
  }

  // DELETE
  async delete(
    id: string,
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    if (!currentUser?.id) {
      throw new UnauthorizedException('Invalid user');
    }

    const prisma = tx ?? this.prisma;

    // 🔍 fetch all related PII consents
    const existing = await prisma.piiConsent.findMany({
      where: { id },
    });

    if (existing.length === 0) {
      throw new NotFoundException('PII Consent not found');
    }

    const role = await this.validateRole(currentUser);

    //  delete all related PII
    await prisma.piiConsent.deleteMany({
      where: { id },
    });

    // audit (single log is enough)
    await this.audit.create(
      {
        performerType: role.name,
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: existing[0].userId,
        action: 'DELETE_PII_CONSENT',
        description: 'Deleted PII Consents for Business KYC',
        resourceType: 'PiiConsent',
        resourceId: id,
        oldData: existing,
        status: AuditStatus.SUCCESS,
      } satisfies CreateAuditLogDto,
      tx,
    );

    return { message: 'PII Consents deleted successfully' };
  }

  // ROLE VALIDATION (Reusable)
  private async validateRole(currentUser: AuthActor) {
    const roleId = currentUser.roleId ?? undefined;
    if (!roleId) throw new BadRequestException('Invalid user role');

    const role = await this.prisma.role.findFirst({ where: { id: roleId } });
    if (!role) {
      throw new NotFoundException(`Role not found for roleId=${roleId}`);
    }

    return role;
  }
}
