import { Test, TestingModule } from '@nestjs/testing';
import { DmtService } from './dmt.service';

describe('DmtService', () => {
  let service: DmtService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DmtService],
    }).compile();

    service = module.get<DmtService>(DmtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
