import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma-service';

@Injectable()
export class StateService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll() {
    return await this.prisma.state.findMany({
      include: {
        cities: {
          select: {
            id: true,
            cityName: true,
            cityCode: true,
          },
        },
      },
      orderBy: {
        stateName: 'asc',
      },
    });
  }
}
