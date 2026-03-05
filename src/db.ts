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

function getDbConfig(): DbConfig {
  // If DATABASE_URL is set, use it directly
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      schema: process.env.DATABASE_SCHEMA,
    };
  }

  return {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME || 'leasebase',
    user: process.env.DB_USER || 'leasebase_admin',
    password: process.env.DB_PASSWORD || '',
    schema: process.env.DATABASE_SCHEMA,
    ssl: process.env.DB_SSL === 'true',
  };
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

    logger.info({ host: config.host || 'url', schema: config.schema }, 'Database pool created');
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
