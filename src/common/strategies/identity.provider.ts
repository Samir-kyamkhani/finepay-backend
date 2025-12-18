import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../database/prisma-service';
import { JwtPayload, SessionUser } from '../types/auth.type';

@Injectable()
export class IdentityProvider {
  constructor(private readonly prisma: PrismaService) {}

  async getActorFromPayload(payload: JwtPayload): Promise<SessionUser> {
    const { sub, principalType } = payload;

    if (!sub || !principalType) {
      throw new UnauthorizedException('Invalid token payload');
    }

    if (principalType === 'USER') {
      return this.validateUser(sub);
    }

    if (principalType === 'EMPLOYEE') {
      return this.validateEmployee(sub);
    }

    throw new UnauthorizedException('Unknown principal type');
  }

  private async validateUser(id: string): Promise<SessionUser> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        userType: true,
        roleId: true,
        businessId: true,
        status: true,
        deletedAt: true,
      },
    });

    if (!user || user.deletedAt || user.status !== 'ACTIVE') {
      throw new UnauthorizedException();
    }

    return {
      userId: user.id,
      userType: user.userType as 'ROOT' | 'USER',
      roleId: user.roleId,
      businessId: user.businessId,
    };
  }

  private async validateEmployee(id: string): Promise<SessionUser> {
    const employee = await this.prisma.employee.findUnique({
      where: { id },
      select: {
        id: true,
        departmentId: true,
        businessId: true,
        status: true,
      },
    });

    if (!employee || employee.status !== 'ACTIVE') {
      throw new UnauthorizedException();
    }

    return {
      userId: employee.id,
      userType: 'EMPLOYEE',
      departmentId: employee.departmentId,
      businessId: employee.businessId,
    };
  }
}
