// App factory
export { createApp, registerErrorHandler, startApp } from './app';
export type { CreateAppOptions } from './app';

// Types
export {
  UserRole,
  parsePagination,
  paginationMeta,
} from './types';
export type {
  CurrentUser,
  AuthenticatedRequest,
  ApiResponse,
  ApiErrorResponse,
  PaginationMeta,
  PaginationQuery,
} from './types';

// Errors
export {
  AppError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
  ConflictError,
} from './errors';

// JWT
export { verifyToken, getJwtConfig, resetJwksCache, setJwksForTesting } from './jwt-verifier';
export type { JwtConfig, VerifiedToken } from './jwt-verifier';

// Middleware
export { requireAuth, requireRole, requireScope } from './middleware/auth';
export { clearRoleCache, roleCacheSize } from './middleware/role-cache';
export { tenantGuard } from './middleware/tenant-guard';
export { correlationId } from './middleware/correlation-id';
export { securityHeaders } from './middleware/security-headers';
export { createRateLimiter } from './middleware/rate-limit';
export { errorHandler } from './middleware/error-handler';
export { requestLogger } from './middleware/request-logger';

// Validation
export { validateBody, validateQuery, validateParams } from './validation';

// Health
export { healthRoutes } from './health';
export type { HealthCheck } from './health';

// Database
export { getDbConfig, initDb, getPool, checkDbConnection, closePool, query, queryOne } from './db';
export type { DbConfig } from './db';

// Logger
export { logger, createChildLogger } from './logger';
