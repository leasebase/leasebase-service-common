import express, { type Express } from 'express';
import cors from 'cors';
import { correlationId } from './middleware/correlation-id';
import { securityHeaders } from './middleware/security-headers';
import { requestLogger } from './middleware/request-logger';
import { createRateLimiter } from './middleware/rate-limit';
import { errorHandler } from './middleware/error-handler';
import { healthRoutes, type HealthCheck } from './health';
import { logger } from './logger';

export interface CreateAppOptions {
  /** Health checks for /ready endpoint. */
  healthChecks?: HealthCheck[];
  /** Disable rate limiting (e.g. for tests). */
  disableRateLimit?: boolean;
}

/**
 * Creates a fully configured Express app with standard middleware:
 * correlation IDs, security headers, CORS, rate limiting, request logging,
 * health endpoints, and a global error handler.
 *
 * Service-specific routes should be added to the returned app before calling listen().
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();

  // Disable x-powered-by
  app.disable('x-powered-by');

  // Parse JSON and URL-encoded bodies
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // Standard middleware
  app.use(correlationId);
  app.use(securityHeaders);
  app.use(requestLogger);

  // CORS
  const corsOrigin = process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'];
  app.use(cors({
    origin: corsOrigin,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-correlation-id'],
    credentials: false,
  }));

  // Rate limiting
  if (!options.disableRateLimit) {
    app.use(createRateLimiter());
  }

  // Health endpoints (no auth)
  app.use(healthRoutes(options.healthChecks));

  return app;
}

/**
 * Registers the global error handler. Call AFTER all routes are added.
 */
export function registerErrorHandler(app: Express): void {
  app.use(errorHandler);
}

/**
 * Starts the Express app on the configured port.
 */
export function startApp(app: Express): void {
  const port = Number(process.env.PORT) || 3000;
  const serviceName = process.env.SERVICE_NAME || 'unknown';

  registerErrorHandler(app);

  app.listen(port, () => {
    logger.info({ port, serviceName }, `${serviceName} listening on port ${port}`);
  });
}
