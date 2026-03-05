import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../jwt-verifier';
import { UnauthorizedError, ForbiddenError } from '../errors';
import type { CurrentUser, AuthenticatedRequest } from '../types';
import { UserRole } from '../types';
import { logger } from '../logger';

const DEV_BYPASS = process.env.DEV_AUTH_BYPASS === 'true';

/**
 * Middleware: require authentication.
 * Verifies the JWT Bearer token and attaches req.user.
 * Supports dev bypass mode via headers.
 */
export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  (async () => {
    try {
      const authReq = req as AuthenticatedRequest;

      if (DEV_BYPASS) {
        const email = req.headers['x-dev-user-email'] as string | undefined;
        const role = req.headers['x-dev-user-role'] as string | undefined;
        const orgId = req.headers['x-dev-org-id'] as string | undefined;

        if (email && role && orgId) {
          authReq.user = {
            sub: 'dev-bypass',
            userId: 'dev-bypass',
            orgId,
            email,
            role: (role.toUpperCase() as UserRole) || UserRole.TENANT,
            name: email,
            scopes: ['api/read', 'api/write', 'api/admin'],
          };
          return next();
        }
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedError('Missing bearer token');
      }

      const token = authHeader.slice(7);
      const payload = await verifyToken(token);

      authReq.user = {
        sub: payload.sub,
        userId: payload.sub,
        orgId: (payload['custom:orgId'] as string) || '',
        email: (payload.email as string) || '',
        role: ((payload['custom:role'] as string) || 'TENANT').toUpperCase() as UserRole,
        name: (payload.email as string) || '',
        scopes: payload.scope ? payload.scope.split(' ') : [],
      };

      next();
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        next(err);
      } else {
        logger.warn({ err }, 'JWT verification failed');
        next(new UnauthorizedError('Invalid or expired token'));
      }
    }
  })();
}

/**
 * Middleware factory: require specific roles.
 */
export function requireRole(...roles: (UserRole | string)[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    if (!user) {
      return next(new UnauthorizedError());
    }
    const upperRoles = roles.map((r) => r.toUpperCase());
    if (!upperRoles.includes(user.role)) {
      return next(new ForbiddenError(`Role ${user.role} is not permitted. Required: ${roles.join(', ')}`));
    }
    next();
  };
}

/**
 * Middleware factory: require specific scopes.
 */
export function requireScope(...scopes: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    if (!user) {
      return next(new UnauthorizedError());
    }
    const missing = scopes.filter((s) => !user.scopes.includes(s));
    if (missing.length > 0) {
      return next(new ForbiddenError(`Missing required scopes: ${missing.join(', ')}`));
    }
    next();
  };
}
