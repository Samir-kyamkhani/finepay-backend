import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../database/database.connection'
import { AuthActor, JwtPayload } from '../interface/auth.interface'

@Injectable()
export class IdentityProvider {
  constructor(private readonly prisma: PrismaService) {}

  async getActorFromPayload(payload: JwtPayload): Promise<AuthActor> {
    const { sub, principalType } = payload;

    if (!sub || !principalType) {
      throw new UnauthorizedException('Invalid token payload');
    }

    switch (principalType) {
      case 'ROOT':
        return this.validateRoot(sub);
      case 'USER':
        return this.validateUser(sub);
      case 'EMPLOYEE':
        return this.validateEmployee(sub);
      default:
        throw new UnauthorizedException('Unknown principal type');
    }
  }

  private async validateRoot(id: string): Promise<AuthActor> {
    const root = await this.prisma.root.findUnique({
      where: { id },
      select: {
        id: true,
        roleId: true,
        status: true,
        deletedAt: true,
      },
    });

    if (!root || root.deletedAt || root.status !== 'ACTIVE') {
      throw new UnauthorizedException('Root not found or inactive');
    }

    return {
      id: root.id,
      principalType: 'ROOT',
      isRoot: true,
      roleId: root.roleId,
    };
  }

  private async validateUser(id: string): Promise<AuthActor> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        roleId: true,
        status: true,
        deletedAt: true,
      },
    });

    if (!user || user.deletedAt || user.status !== 'ACTIVE') {
      throw new UnauthorizedException('User not found or inactive');
    }

    return {
      id: user.id,
      principalType: 'USER',
      isRoot: false,
      roleId: user.roleId,
    };
  }

  private async validateEmployee(id: string): Promise<AuthActor> {
    const employee = await this.prisma.employee.findUnique({
      where: { id },
      select: {
        id: true,
        departmentId: true,
        status: true,
        deletedAt: true,
      },
    });

    if (!employee || employee.deletedAt || employee.status !== 'ACTIVE') {
      throw new UnauthorizedException('Employee not found or inactive');
    }

    return {
      id: employee.id,
      principalType: 'EMPLOYEE',
      isRoot: false,
      roleId: employee.departmentId,
    };
  }
}
