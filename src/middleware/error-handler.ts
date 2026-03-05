import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../errors';
import { logger } from '../logger';

export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  const correlationId = (req as any).correlationId || '';

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
        correlationId,
      },
    });
    return;
  }

  // Unexpected error
  logger.error({ err, correlationId, path: req.path }, 'Unhandled error');

  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      correlationId,
    },
  });
}
