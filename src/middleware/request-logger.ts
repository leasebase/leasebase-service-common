import type { Request, Response, NextFunction } from 'express';
import { logger } from '../logger';
import type { AuthenticatedRequest } from '../types';

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const user = (req as AuthenticatedRequest).user;
    const correlationId = (req as any).correlationId || '';

    logger.info({
      method: req.method,
      path: req.originalUrl,
      statusCode: res.statusCode,
      durationMs,
      correlationId,
      userId: user?.userId,
      orgId: user?.orgId,
    }, `${req.method} ${req.originalUrl} ${res.statusCode} ${durationMs}ms`);
  });

  next();
}
