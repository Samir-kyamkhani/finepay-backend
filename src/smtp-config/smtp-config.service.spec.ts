import { Test, TestingModule } from '@nestjs/testing';
import { SmtpConfigService } from './smtp-config.service';

describe('SmtpConfigService', () => {
  let service: SmtpConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SmtpConfigService],
    }).compile();

    service = module.get<SmtpConfigService>(SmtpConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
