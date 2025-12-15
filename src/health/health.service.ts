import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);

  getHealth(): { status: string; message: string } {
    const response = {
      status: 'ok',
      message: 'Everything is good!',
    };
    return response;
  }
}
