import { Controller } from '@nestjs/common';
import { RootsService } from './roots.service';

@Controller('roots')
export class RootsController {
  constructor(private readonly rootsService: RootsService) {}
}
