import { Controller, Get } from '@nestjs/common';
import { HealthService } from './health.service';

@Controller()
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get('api/v1/health')
  getHealth(): { status: string; message: string } {
    return this.healthService.getHealth();
  }
}
