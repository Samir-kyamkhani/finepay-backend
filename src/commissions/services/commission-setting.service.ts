import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';
import { CreateCommissionSettingDto } from '../dto/create-commission-setting.dto';
import { UpdateCommissionSettingDto } from '../dto/update-commission-setting.dto';
import { CommissionSettingQueryDto } from '../dto/commission-setting-query.dto';
import { AuthActor } from '../../common/types/auth.type';
import { CommissionScope, CreatorType } from '../../../generated/prisma/enums';
import { CommissionSetting } from '../../../generated/prisma/client';

@Injectable()
export class CommissionSettingService {
  constructor(private readonly prisma: PrismaService) {}

  // =====================================================
  // CREATE
  // =====================================================
  async create(dto: CreateCommissionSettingDto, actor: AuthActor) {
    //  PERMISSION
    await this.checkCreatePermission(actor);

    //  VALIDATIONS
    this.validateScope(dto);
    await this.validateCreator(dto, actor);

    return this.prisma.commissionSetting.create({
      data: {
        scope: dto.scope,
        roleId: dto.roleId,
        targetUserId: dto.targetUserId,
        serviceId: dto.serviceId,

        commissionType: dto.commissionType,
        commissionValue: dto.commissionValue,

        surchargeType: dto.surchargeType,
        surchargeValue: dto.surchargeValue,

        minAmount: dto.minAmount,
        maxAmount: dto.maxAmount,

        applyTDS: dto.applyTDS ?? false,
        tdsPercent: dto.tdsPercent,

        applyGST: dto.applyGST ?? false,
        gstPercent: dto.gstPercent,

        isActive: dto.isActive ?? true,
        effectiveFrom: dto.effectiveFrom
          ? new Date(dto.effectiveFrom)
          : new Date(),
        effectiveTo: dto.effectiveTo ? new Date(dto.effectiveTo) : null,

        createdByType: dto.createdByType,
        createdByUserId: dto.createdByUserId,
        createdByRootId: dto.createdByRootId,
        createdByEmployeeId: dto.createdByEmployeeId,
      },
    });
  }

  // =====================================================
  // FIND ALL
  // =====================================================
  async findAll(query: CommissionSettingQueryDto) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where = {
      ...(query.scope && { scope: query.scope }),
      ...(query.roleId && { roleId: query.roleId }),
      ...(query.targetUserId && { targetUserId: query.targetUserId }),
      ...(query.serviceId && { serviceId: query.serviceId }),
      ...(typeof query.isActive === 'boolean' && {
        isActive: query.isActive,
      }),
    };

    const [data, total] = await Promise.all([
      this.prisma.commissionSetting.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.commissionSetting.count({ where }),
    ]);

    return {
      data,
      meta: { page, limit, total },
    };
  }

  // =====================================================
  // FIND BY ID
  // =====================================================
  async findById(id: string): Promise<CommissionSetting> {
    const commission = await this.prisma.commissionSetting.findUnique({
      where: { id },
    });

    if (!commission) {
      throw new NotFoundException('Commission setting not found');
    }

    return commission;
  }

  // =====================================================
  // UPDATE
  // =====================================================
  async update(id: string, dto: UpdateCommissionSettingDto, actor: AuthActor) {
    const existing = await this.findById(id);

    await this.checkUpdatePermission(existing, actor);

    return this.prisma.commissionSetting.update({
      where: { id },
      data: {
        ...dto,
        ...(dto.effectiveFrom && {
          effectiveFrom: new Date(dto.effectiveFrom),
        }),
        ...(dto.effectiveTo && {
          effectiveTo: new Date(dto.effectiveTo),
        }),
      },
    });
  }

  // =====================================================
  // SOFT DISABLE
  // =====================================================
  async disable(id: string, actor: AuthActor) {
    const existing = await this.findById(id);

    await this.checkUpdatePermission(existing, actor);

    return this.prisma.commissionSetting.update({
      where: { id },
      data: { isActive: false },
    });
  }

  // =====================================================
  // PERMISSION RULES
  // =====================================================
  private async checkCreatePermission(actor: AuthActor) {
    if (actor.principalType === 'ROOT') return;
    if (actor.principalType === 'EMPLOYEE') return;

    if (actor.principalType === 'USER') {
      await this.assertAdminRole(actor);
      return;
    }

    throw new ForbiddenException(
      'You are not allowed to create commission settings',
    );
  }

  private async checkUpdatePermission(
    commission: CommissionSetting,
    actor: AuthActor,
  ) {
    if (actor.principalType === 'ROOT') return;
    if (actor.principalType === 'EMPLOYEE') return;

    if (actor.principalType === 'USER') {
      await this.assertAdminRole(actor);

      if (commission.createdByUserId === actor.id) {
        return;
      }
    }

    throw new ForbiddenException(
      'You are not allowed to update this commission',
    );
  }

  // =====================================================
  // VALIDATIONS
  // =====================================================
  private validateScope(dto: CreateCommissionSettingDto) {
    if (dto.scope === CommissionScope.ROLE && !dto.roleId) {
      throw new BadRequestException('roleId is required for ROLE scope');
    }

    if (dto.scope === CommissionScope.ADMIN && !dto.targetUserId) {
      throw new BadRequestException('targetUserId is required for USER scope');
    }
  }

  private async validateCreator(
    dto: CreateCommissionSettingDto,
    actor: AuthActor,
  ) {
    // ROOT
    if (dto.createdByType === CreatorType.ROOT) {
      if (actor.principalType !== 'ROOT') {
        throw new ForbiddenException('Only ROOT can create as ROOT');
      }
      if (dto.createdByRootId !== actor.id) {
        throw new BadRequestException('Invalid root creator');
      }
    }

    // EMPLOYEE
    if (dto.createdByType === CreatorType.EMPLOYEE) {
      if (actor.principalType !== 'EMPLOYEE') {
        throw new ForbiddenException('Only EMPLOYEE can create as EMPLOYEE');
      }
      if (dto.createdByEmployeeId !== actor.id) {
        throw new BadRequestException('Invalid employee creator');
      }
    }

    // ADMIN
    if (dto.createdByType === CreatorType.ADMIN) {
      await this.assertAdminRole(actor);

      if (dto.createdByUserId !== actor.id) {
        throw new BadRequestException('Invalid admin creator');
      }
    }
  }

  // =====================================================
  // ROLE CHECK (DB SOURCE OF TRUTH)
  // =====================================================
  private async assertAdminRole(actor: AuthActor) {
    if (actor.principalType !== 'USER' || !actor.roleId) {
      throw new ForbiddenException('Only ADMIN user allowed');
    }

    const role = await this.prisma.role.findUnique({
      where: { id: actor.roleId },
      select: { name: true },
    });

    if (!role || role.name !== 'ADMIN') {
      throw new ForbiddenException('Only ADMIN user allowed');
    }
  }
}
