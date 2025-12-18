import { Controller, Get } from '@nestjs/common';
import { HealthService } from './health.service';
import { Public } from '../common/decorators/public.decorator';

@Controller()
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Public()
  @Get('api/v1/health')
  getHealth(): { status: string; message: string } {
    return this.healthService.getHealth();
  }
}
