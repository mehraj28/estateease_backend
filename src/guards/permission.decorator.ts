import { SetMetadata } from '@nestjs/common';
import { Permissions } from 'src/utils/permissions.enum';

export const Permission = (...permissions: Permissions[]) =>
  SetMetadata('permissions', permissions);
