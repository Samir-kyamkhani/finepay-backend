import { Controller } from '@nestjs/common';
import { DmtService } from './dmt.service';

@Controller('dmt')
export class DmtController {
  constructor(private readonly dmtService: DmtService) {}
}
