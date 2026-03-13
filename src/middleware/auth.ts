import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../jwt-verifier';
import { UnauthorizedError, ForbiddenError } from '../errors';
import type { CurrentUser, AuthenticatedRequest } from '../types';
import { UserRole } from '../types';
import { logger } from '../logger';
import { queryOne } from '../db';

const DEV_BYPASS = process.env.DEV_AUTH_BYPASS === 'true';

// Fail fast: DEV_AUTH_BYPASS must never be enabled in production
if (DEV_BYPASS && process.env.NODE_ENV === 'production') {
  throw new Error('FATAL: DEV_AUTH_BYPASS=true is not allowed when NODE_ENV=production');
}

if (DEV_BYPASS) {
  logger.warn('⚠ DEV_AUTH_BYPASS is enabled — auth middleware will accept bypass headers');
}

/**
 * Middleware: require authentication.
 *
 * Verifies the JWT Bearer token and attaches req.user.
 * FAIL-CLOSED: if the verified token does not carry `custom:role`,
 * the request is rejected with 401 (no silent downgrade to TENANT).
 *
 * Supports dev bypass mode via headers (non-production only).
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
            role: role.toUpperCase() as UserRole,
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

      // ── Role resolution (fail-closed) ──────────────────────────────────
      // The ONLY accepted source of role is the JWT `custom:role` claim.
      // Cognito ID tokens carry this claim; access tokens do not.
      // If the token lacks `custom:role`, the request is rejected.
      //
      // The final auth authority model (token enrichment, session-based,
      // etc.) will be decided separately. Until then, fail closed.
      const jwtRole = payload['custom:role'] as string | undefined;

      if (!jwtRole) {
        logger.warn(
          { sub: payload.sub, email: payload.email, token_use: payload.token_use },
          'requireAuth: token missing custom:role claim — rejecting (fail-closed)',
        );
        throw new UnauthorizedError(
          'Token missing required role claim. Ensure the correct token type is used.',
        );
      }

      const finalRole = jwtRole.toUpperCase() as UserRole;

      authReq.user = {
        sub: payload.sub,
        userId: payload.sub,
        orgId: (payload['custom:orgId'] as string) || '',
        email: (payload.email as string) || '',
        role: finalRole,
        name: (payload.email as string) || '',
        scopes: payload.scope ? payload.scope.split(' ') : [],
      };

      // ── DB enrichment (fail-open) ─────────────────────────────────────
      // Cognito tokens do not carry orgId. Look up the User row by
      // cognitoSub to populate authoritative orgId, userId, name, and role.
      // If the lookup fails (no DB, no row, error), keep JWT-derived values.
      try {
        const dbUser = await queryOne<{
          id: string;
          organizationId: string;
          email: string;
          name: string;
          role: string;
        }>(
          `SELECT "id", "organizationId", "email", "name", "role" FROM "User" WHERE "cognitoSub" = $1`,
          [payload.sub],
        );

        if (dbUser) {
          authReq.user.userId = dbUser.id;
          authReq.user.orgId = dbUser.organizationId || authReq.user.orgId;
          authReq.user.email = dbUser.email || authReq.user.email;
          authReq.user.name = dbUser.name || authReq.user.name;
          if (dbUser.role) {
            authReq.user.role = dbUser.role.toUpperCase() as UserRole;
          }
        }
      } catch (enrichErr) {
        // Non-fatal: continue with JWT-derived context.
        logger.debug(
          { err: enrichErr, sub: payload.sub },
          'requireAuth: DB enrichment unavailable — using JWT-derived context',
        );
      }

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
