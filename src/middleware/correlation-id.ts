import type { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

const HEADER = 'x-correlation-id';

export function correlationId(req: Request, res: Response, next: NextFunction): void {
  const id = (req.headers[HEADER] as string) || uuidv4();
  (req as any).correlationId = id;
  res.setHeader(HEADER, id);
  next();
}
