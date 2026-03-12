import type { Request, Response, NextFunction } from 'express';
import { ForbiddenError } from '../errors';
import type { AuthenticatedRequest } from '../types';

/**
 * Middleware: validate that the route's orgId (or query orgId) matches the user's orgId.
 * No cross-org access for any role.
 */
export function tenantGuard(req: Request, _res: Response, next: NextFunction): void {
  const user = (req as AuthenticatedRequest).user;
  if (!user) {
    return next(new ForbiddenError('No authenticated user'));
  }

  // Check route param :orgId
  const routeOrgId = req.params.orgId;
  if (routeOrgId && routeOrgId !== user.orgId) {
    return next(new ForbiddenError('Tenant mismatch: cannot access another organization'));
  }

  // Check query param orgId
  const queryOrgId = req.query.orgId as string | undefined;
  if (queryOrgId && queryOrgId !== user.orgId) {
    return next(new ForbiddenError('Tenant mismatch: cannot access another organization'));
  }

  next();
}
