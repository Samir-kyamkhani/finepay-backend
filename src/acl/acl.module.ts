import { Module } from '@nestjs/common';
import { AclService } from './acl.service';
import { AclController } from './acl.controller';

@Module({
  controllers: [AclController],
  providers: [AclService],
})
export class AclModule {}
