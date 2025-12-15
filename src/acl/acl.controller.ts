import { Controller } from '@nestjs/common';
import { AclService } from './acl.service';

@Controller('acl')
export class AclController {
  constructor(private readonly aclService: AclService) {}
}
