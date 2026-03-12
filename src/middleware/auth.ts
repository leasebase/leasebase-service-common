import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../jwt-verifier';
import { UnauthorizedError, ForbiddenError } from '../errors';
import type { CurrentUser, AuthenticatedRequest } from '../types';
import { UserRole } from '../types';
import { logger } from '../logger';
import { getCachedRole, setCachedRole, setCachedNegative } from './role-cache';

const DEV_BYPASS = process.env.DEV_AUTH_BYPASS === 'true';

// Fail fast: DEV_AUTH_BYPASS must never be enabled in production
if (DEV_BYPASS && process.env.NODE_ENV === 'production') {
  throw new Error('FATAL: DEV_AUTH_BYPASS=true is not allowed when NODE_ENV=production');
}

if (DEV_BYPASS) {
  logger.warn('⚠ DEV_AUTH_BYPASS is enabled — auth middleware will accept bypass headers');
}

// ── DB role fallback ─────────────────────────────────────────────────────────

interface DbRoleResult {
  role: string;
  orgId: string;
  source: 'db-cache' | 'db-lookup';
}

/**
 * Look up the user's role from the database by Cognito subject.
 *
 * Returns the role from cache if available, otherwise queries the User table.
 * On DB errors, returns `null` (caller falls back to TENANT default).
 * Never throws — errors are logged and swallowed.
 */
async function resolveRoleFromDb(sub: string): Promise<DbRoleResult | null> {
  // 1. Check in-process cache
  const cached = getCachedRole(sub);
  if (cached) {
    if (cached.role === null) {
      // Negative cache hit — user was not found recently
      return null;
    }
    return { role: cached.role, orgId: cached.orgId, source: 'db-cache' };
  }

  // 2. Query DB
  try {
    // Late-import to avoid circular dependency and to tolerate services
    // that may not have a DB configured (e.g. BFF gateway).
    const { queryOne } = await import('../db');

    const row = await queryOne<{ role: string; organizationId: string }>(
      'SELECT "role", "organizationId" FROM "User" WHERE "cognitoSub" = $1',
      [sub],
    );

    if (row) {
      setCachedRole(sub, row.role, row.organizationId || '');
      return { role: row.role, orgId: row.organizationId || '', source: 'db-lookup' };
    }

    // User not found — negative cache
    setCachedNegative(sub);
    logger.warn(
      { sub },
      'requireAuth DB fallback: no User row found for cognitoSub',
    );
    return null;
  } catch (err) {
    // DB error — log and continue without role.
    // The caller will fall back to TENANT.
    logger.warn(
      { err, sub },
      'requireAuth DB fallback: query failed — proceeding without DB role',
    );
    return null;
  }
}

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

      // ── Role resolution (priority order) ──────────────────────────────
      // 1. x-lb-enriched-role header (trusted BFF/gateway)
      // 2. JWT custom:role claim (present in Cognito ID tokens)
      // 3. DB fallback by cognitoSub (access tokens lack custom attrs)
      //    → cached in-process with 5-min TTL
      // 4. TENANT default (only if DB is unavailable AND no cache)
      //
      // When a Cognito pre-token-generation Lambda is added later,
      // the access token will carry custom:role and step 3 will
      // never be reached.
      const jwtRole = payload['custom:role'] as string | undefined;
      const enrichedRole = req.headers['x-lb-enriched-role'] as string | undefined;

      let resolvedRole: string = enrichedRole || jwtRole || '';
      let resolvedOrgId: string = (payload['custom:orgId'] as string) || '';
      let roleSource: string = enrichedRole ? 'enriched-header' : jwtRole ? 'jwt-claim' : '';

      // DB fallback: only when no role from header or JWT
      if (!resolvedRole && payload.sub) {
        const dbResult = await resolveRoleFromDb(payload.sub);
        if (dbResult) {
          resolvedRole = dbResult.role;
          resolvedOrgId = dbResult.orgId || resolvedOrgId;
          roleSource = dbResult.source;
        }
      }

      // Final fallback to TENANT if nothing resolved
      if (!resolvedRole) {
        resolvedRole = UserRole.TENANT;
        roleSource = 'default-fallback';
        logger.warn(
          { sub: payload.sub, email: payload.email },
          'requireAuth: no role from header, JWT, or DB — defaulting to TENANT',
        );
      }

      const finalRole = resolvedRole.toUpperCase() as UserRole;

      if (roleSource === 'db-lookup' || roleSource === 'db-cache') {
        logger.debug(
          { sub: payload.sub, role: finalRole, source: roleSource },
          'requireAuth: role resolved via DB fallback',
        );
      }

      authReq.user = {
        sub: payload.sub,
        userId: payload.sub,
        orgId: resolvedOrgId,
        email: (payload.email as string) || '',
        role: finalRole,
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
