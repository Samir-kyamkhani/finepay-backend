import { Test, TestingModule } from '@nestjs/testing';
import { DmtController } from './dmt.controller';
import { DmtService } from './dmt.service';

describe('DmtController', () => {
  let controller: DmtController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [DmtController],
      providers: [DmtService],
    }).compile();

    controller = module.get<DmtController>(DmtController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
