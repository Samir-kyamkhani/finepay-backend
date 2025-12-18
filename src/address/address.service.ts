import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';

import { PrismaService } from '../database/prisma-service';
import { AuditLogService } from '../audit/service/audit.service';

import { AuthActor } from '../common/types/auth.type';

import { AuditStatus, Prisma } from '../../generated/prisma/client';

import { CreateAddressDto } from './dto/create-address.dto';
import { UpdateAddressDto } from './dto/update-address.dto';
import { CreateAuditLogDto } from '../audit/dto/create-audit-log.dto';

@Injectable()
export class AddressService {
  constructor(
    private prisma: PrismaService,
    private audit: AuditLogService,
  ) {}

  // CREATE - single
  async create(
    dto: CreateAddressDto,
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    if (!currentUser?.id) {
      throw new UnauthorizedException('Invalid user');
    }

    const { address, pinCode, cityId, stateId } = dto;

    if (!address || !pinCode || !cityId || !stateId) {
      throw new BadRequestException(
        'address, pinCode, cityId and stateId are required',
      );
    }

    const prisma = tx ?? this.prisma;
    const role = await this.validateRole(currentUser);

    const existing = await prisma.address.findFirst({
      where: { address, pinCode, cityId, stateId },
    });

    if (existing) {
      await this.audit.create(
        {
          performerType: role.name,
          performerId: currentUser.id,
          targetUserType: 'USER',
          targetUserId: currentUser.id,
          action: 'CREATE_ADDRESS',
          description: 'Duplicate address detected',
          resourceType: 'Address',
          resourceId: existing.id,
          status: AuditStatus.FAILED,
          metadata: { reason: 'Duplicate Address' },
        },
        tx,
      );

      throw new ConflictException('Address already exists');
    }

    const newAddress = await prisma.address.create({
      data: { address, pinCode, cityId, stateId },
    });

    await this.audit.create(
      {
        performerType: role.name,
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: currentUser.id,
        action: 'CREATE_ADDRESS',
        description: 'Created Address',
        resourceType: 'Address',
        resourceId: newAddress.id,
        newData: newAddress,
        status: AuditStatus.SUCCESS,
      },
      tx,
    );

    return newAddress;
  }

  // UPDATE - single
  async update(
    id: string,
    dto: UpdateAddressDto,
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ) {
    if (!currentUser?.id) {
      throw new UnauthorizedException('Invalid user');
    }

    if (!id) {
      throw new BadRequestException('Address id is required');
    }

    const prisma = tx ?? this.prisma;
    const role = await this.validateRole(currentUser);

    const existing = await prisma.address.findUnique({ where: { id } });
    if (!existing) {
      throw new NotFoundException('Address not found');
    }

    const duplicate = await prisma.address.findFirst({
      where: {
        NOT: { id },
        address: dto.address ?? existing.address,
        pinCode: dto.pinCode ?? existing.pinCode,
        cityId: dto.cityId ?? existing.cityId,
        stateId: dto.stateId ?? existing.stateId,
      },
    });

    if (duplicate) {
      await this.audit.create(
        {
          performerType: role.name,
          performerId: currentUser.id,
          targetUserType: 'USER',
          targetUserId: currentUser.id,
          action: 'UPDATE_ADDRESS',
          description: 'Duplicate address detected on update',
          resourceType: 'Address',
          resourceId: id,
          status: AuditStatus.FAILED,
          metadata: { reason: 'Duplicate Address' },
        },
        tx,
      );

      throw new ConflictException('Duplicate address exists');
    }

    const updateData: UpdateAddressDto = {};
    if (dto.address !== undefined) updateData.address = dto.address;
    if (dto.pinCode !== undefined) updateData.pinCode = dto.pinCode;
    if (dto.cityId !== undefined) updateData.cityId = dto.cityId;
    if (dto.stateId !== undefined) updateData.stateId = dto.stateId;

    const updated = await prisma.address.update({
      where: { id },
      data: updateData,
    });

    await this.audit.create(
      {
        performerType: role.name,
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: currentUser.id,
        action: 'UPDATE_ADDRESS',
        description: 'Updated Address',
        resourceType: 'Address',
        resourceId: id,
        oldData: existing,
        newData: updateData,
        status: AuditStatus.SUCCESS,
      },
      tx,
    );

    return updated;
  }

  // DELETE - single
  async delete(
    id: string,
    currentUser: AuthActor,
    tx?: Prisma.TransactionClient,
  ): Promise<{ message: string }> {
    if (!currentUser?.id) {
      throw new UnauthorizedException('Invalid user');
    }

    if (!id) {
      throw new BadRequestException('Address id is required');
    }

    const prisma = tx ?? this.prisma;

    const existing = await prisma.address.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new NotFoundException('Address not found');
    }

    const role = await this.validateRole(currentUser);

    //  delete inside transaction
    await prisma.address.delete({
      where: { id },
    });

    //  audit inside same transaction
    await this.audit.create(
      {
        performerType: role.name,
        performerId: currentUser.id,
        targetUserType: 'USER',
        targetUserId: currentUser.id,
        action: 'DELETE_ADDRESS',
        description: 'Deleted Address',
        resourceType: 'Address',
        resourceId: id,
        oldData: existing,
        status: AuditStatus.SUCCESS,
      } satisfies CreateAuditLogDto,
      tx,
    );

    return { message: 'Address deleted successfully' };
  }

  // Role validation helper (same pattern as in PiiConsentService)
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
