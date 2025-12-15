import { SetMetadata } from '@nestjs/common';
import { Action, Resource } from '../enums/permission.enum';

export interface RequiredPermission {
  resource: Resource;
  actions: Action[];
}

export const PERMISSIONS_KEY = 'permissions';

export const Permissions = (permissions: RequiredPermission[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
