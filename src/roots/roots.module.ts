import { Module } from '@nestjs/common';
import { RootsService } from './roots.service';
import { RootsController } from './roots.controller';

@Module({
  controllers: [RootsController],
  providers: [RootsService],
})
export class RootsModule {}
