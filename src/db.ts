import { Pool, type PoolConfig } from 'pg';
import { logger } from './logger';

let pool: Pool | null = null;

export interface DbConfig {
  connectionString?: string;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  password?: string;
  schema?: string;
  ssl?: boolean;
}

/**
 * Resolve database connection configuration.
 *
 * Priority:
 *   1. `DATABASE_URL`              — explicit connection string
 *   2. `DATABASE_SECRET_ARN`       — ECS-injected JSON secret payload
 *      (Despite the name, ECS injects the secret VALUE as JSON, not the ARN.)
 *      Expected shape: { host, port, dbname, username, password, schema? }
 *   3. Individual env vars         — DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
 *      (Intended for local development; defaults to localhost.)
 *
 * In non-local environments (NODE_ENV is set and not "development"), if none of
 * the above are configured the function logs an error so the failure is visible
 * rather than silently falling back to localhost.
 */
export function getDbConfig(): DbConfig {
  // ── Priority 1: explicit connection string ────────────────────────────
  if (process.env.DATABASE_URL) {
    logger.info('DB config: using DATABASE_URL');
    return {
      connectionString: process.env.DATABASE_URL,
      schema: process.env.DATABASE_SCHEMA,
    };
  }

  // ── Priority 2: ECS-injected JSON secret ──────────────────────────────
  const secretPayload = process.env.DATABASE_SECRET_ARN;
  if (secretPayload) {
    try {
      const secret = JSON.parse(secretPayload) as Record<string, unknown>;
      const config: DbConfig = {
        host: String(secret.host ?? ''),
        port: Number(secret.port) || 5432,
        database: String(secret.dbname ?? secret.database ?? 'leasebase'),
        user: String(secret.username ?? secret.user ?? ''),
        password: String(secret.password ?? ''),
        schema: String(secret.schema ?? '') || process.env.DATABASE_SCHEMA,
        ssl: secret.ssl !== false, // default true for RDS / Aurora
      };
      logger.info(
        { host: config.host, database: config.database, user: config.user, schema: config.schema },
        'DB config: resolved from DATABASE_SECRET_ARN',
      );
      return config;
    } catch (err) {
      logger.error({ err }, 'DB config: failed to parse DATABASE_SECRET_ARN as JSON');
      throw new Error('DATABASE_SECRET_ARN is set but could not be parsed as JSON');
    }
  }

  // ── Priority 3: individual env vars (local development) ───────────────
  const isLocal = !process.env.NODE_ENV || process.env.NODE_ENV === 'development';
  if (!isLocal && !process.env.DB_HOST) {
    logger.error(
      'DB config: no DATABASE_URL, DATABASE_SECRET_ARN, or DB_HOST configured in a ' +
        `non-local environment (NODE_ENV=${process.env.NODE_ENV}). ` +
        'Database connections will fail. Set one of these before deploying.',
    );
  }

  const config: DbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'leasebase',
    user: process.env.DB_USER || 'leasebase_admin',
    password: process.env.DB_PASSWORD || '',
    schema: process.env.DATABASE_SCHEMA,
    ssl: process.env.DB_SSL === 'true',
  };

  if (isLocal) {
    logger.info({ host: config.host, database: config.database }, 'DB config: using local env vars');
  }

  return config;
}

export function getPool(): Pool {
  if (!pool) {
    const config = getDbConfig();
    const poolConfig: PoolConfig = config.connectionString
      ? { connectionString: config.connectionString, max: 10 }
      : {
          host: config.host,
          port: config.port,
          database: config.database,
          user: config.user,
          password: config.password,
          max: 10,
          ssl: config.ssl ? { rejectUnauthorized: false } : undefined,
        };

    pool = new Pool(poolConfig);

    pool.on('error', (err) => {
      logger.error({ err }, 'Unexpected database pool error');
    });

    // Set search_path to service schema if specified
    if (config.schema) {
      pool.on('connect', (client) => {
        client.query(`SET search_path TO ${config.schema}, public`);
      });
    }

    logger.info({ host: config.host || '(connection-string)', schema: config.schema }, 'Database pool created');
  }

  return pool;
}

export async function checkDbConnection(): Promise<boolean> {
  try {
    const p = getPool();
    const result = await p.query('SELECT 1');
    return result.rowCount === 1;
  } catch (err) {
    logger.warn({ err }, 'Database health check failed');
    return false;
  }
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

/** Helper: execute a query with the pool. */
export async function query<T = any>(text: string, params?: unknown[]): Promise<T[]> {
  const p = getPool();
  const result = await p.query(text, params);
  return result.rows as T[];
}

/** Helper: execute a query and return a single row. */
export async function queryOne<T = any>(text: string, params?: unknown[]): Promise<T | null> {
  const rows = await query<T>(text, params);
  return rows[0] || null;
}
