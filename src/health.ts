import { Router, type Request, type Response } from 'express';

export interface HealthCheck {
  name: string;
  check: () => Promise<boolean>;
}

const serviceName = process.env.SERVICE_NAME || 'unknown';

export function healthRoutes(checks: HealthCheck[] = []): Router {
  const router = Router();

  router.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: serviceName,
      timestamp: new Date().toISOString(),
    });
  });

  router.get('/ready', async (_req: Request, res: Response) => {
    const results: Record<string, string> = {};
    let allOk = true;

    for (const hc of checks) {
      try {
        const ok = await hc.check();
        results[hc.name] = ok ? 'ok' : 'degraded';
        if (!ok) allOk = false;
      } catch {
        results[hc.name] = 'down';
        allOk = false;
      }
    }

    const statusCode = allOk ? 200 : 503;
    res.status(statusCode).json({
      status: allOk ? 'ready' : 'degraded',
      service: serviceName,
      checks: results,
      timestamp: new Date().toISOString(),
    });
  });

  return router;
}
