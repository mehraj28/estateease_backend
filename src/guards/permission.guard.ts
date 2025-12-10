import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Permissions } from 'src/utils/permissions.enum';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.get<Permissions[]>(
      'permissions',
      context.getHandler(),
    );

    if (!requiredPermissions) {
      return true; // No permission specified on the route, allow access.
    }

    const request = context.switchToHttp().getRequest();
    // console.log(request);
    const userPermission: Permissions = request.user?.permissions; // Assuming you store the user object on the request during authentication.
    if (requiredPermissions.includes(userPermission)) {
      return true; // User has the required permission, allow access
    }

    return false; // User doesn't have the required permission, deny access.
  }
}
