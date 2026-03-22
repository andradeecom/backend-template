import { SetMetadata } from '@nestjs/common';
import { UserRoleType } from 'src/users/types/user-roles.type';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRoleType[]) =>
  SetMetadata(ROLES_KEY, roles);
