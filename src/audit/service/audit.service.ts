import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { CreateAuditLogDto } from '../dto/create-audit-log.dto';
import { FilterAuditLogDto } from '../dto/filter-audit-log.dto';
import { PrismaService } from '../../database/prisma-service';
import { Prisma } from '../../../generated/prisma/client';

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);

  constructor(private readonly prisma: PrismaService) {}
  // Create Audit Log

  async create(dto: CreateAuditLogDto, tx?: Prisma.TransactionClient) {
    const prisma = tx ?? this.prisma;

    try {
      return await prisma.auditLog.create({
        data: dto,
      });
    } catch (error) {
      throw new InternalServerErrorException(
        'Failed to create audit log entry',
      );
    }
  }

  // Get audit logs with filtering + pagination
  async findAll(filter: FilterAuditLogDto) {
    try {
      const { year, month, status, role, page = 1, limit = 20 } = filter;
      const skip = (page - 1) * limit;

      const where: Prisma.AuditLogWhereInput = {};

      if (status) where.status = status;
      if (role) where.performerType = role;

      // Date filtering
      if (year) {
        const start = new Date(year, month ? month - 1 : 0, 1);
        const end = new Date(year, month ? month : 12, 1);

        where.createdAt = {
          gte: start,
          lt: end,
        };
      }

      const [total, data] = await Promise.all([
        this.prisma.auditLog.count({ where }),
        this.prisma.auditLog.findMany({
          where,
          orderBy: { createdAt: 'desc' },
          skip,
          take: limit,
        }),
      ]);

      return {
        success: true,
        data,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit),
          hasNextPage: page * limit < total,
          hasPreviousPage: page > 1,
        },
      };
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Unknown error occurred';

      this.logger.error('Failed to fetch audit logs', {
        message,
        filters: filter,
        stack: error instanceof Error ? error.stack : undefined,
      });

      throw new InternalServerErrorException('Failed to fetch audit logs');
    }
  }
}
