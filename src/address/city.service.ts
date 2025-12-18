import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma-service';

@Injectable()
export class CityService {
  constructor(private prisma: PrismaService) {}

  async findAll() {
    return await this.prisma.city.findMany({
      include: {
        state: {
          select: {
            id: true,
            stateName: true,
            stateCode: true,
          },
        },
      },
      orderBy: {
        cityName: 'asc',
      },
    });
  }
}
