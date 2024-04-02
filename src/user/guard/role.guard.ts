import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

 
// const RoleGuard = (role: Role): Type<CanActivate> => {
//   class RoleGuardMixin implements CanActivate {
//     canActivate(context: ExecutionContext) {
//       const request = context.switchToHttp().getRequest<RequestWithUser>();
//       const user = request.user;
 
//       return user?.roles.includes(role);
//     }
//   }
 
//   return mixin(RoleGuardMixin);
// }
 
// export default RoleGuard;

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    // get the roles required
    const roles = this.reflector.getAllAndOverride<string[]>('roles', [context.getHandler(), context.getClass()]);
    if (!roles) {
      return false;
    }
    const request = context.switchToHttp().getRequest();
    const userRoles = request.headers?.role?.split(',');
    return this.validateRoles(roles, userRoles);
  }

  validateRoles(roles: string[], userRoles: string[]) {
    return roles.some(role => userRoles.includes(role));
  }
}