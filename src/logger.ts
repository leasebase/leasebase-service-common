import pino from 'pino';

const level = process.env.LOG_LEVEL || 'info';
const serviceName = process.env.SERVICE_NAME || 'unknown';

export const logger = pino({
  level,
  base: { service: serviceName },
  timestamp: pino.stdTimeFunctions.isoTime,
  ...(process.env.NODE_ENV !== 'production' && {
    transport: { target: 'pino/file', options: { destination: 1 } },
  }),
});

export function createChildLogger(bindings: Record<string, unknown>): pino.Logger {
  return logger.child(bindings);
}
