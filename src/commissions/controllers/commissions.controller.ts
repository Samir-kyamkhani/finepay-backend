import { Controller } from '@nestjs/common';
import { CommissionsService } from './commissions.service';

@Controller('commissions')
export class CommissionsController {
  constructor(private readonly commissionsService: CommissionsService) {}
}
