import { Test, TestingModule } from '@nestjs/testing';
import { SmtpConfigController } from './smtp-config.controller';
import { SmtpConfigService } from './smtp-config.service';

describe('SmtpConfigController', () => {
  let controller: SmtpConfigController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SmtpConfigController],
      providers: [SmtpConfigService],
    }).compile();

    controller = module.get<SmtpConfigController>(SmtpConfigController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
