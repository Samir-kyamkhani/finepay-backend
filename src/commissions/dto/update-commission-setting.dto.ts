import { PartialType } from '@nestjs/mapped-types';
import { CreateCommissionSettingDto } from './create-commission-setting.dto';

export class UpdateCommissionSettingDto extends PartialType(
  CreateCommissionSettingDto,
) {}
