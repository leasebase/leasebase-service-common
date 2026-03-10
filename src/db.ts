import { Pool, type PoolConfig } from 'pg';
import { logger } from './logger';

let pool: Pool | null = null;

/**
 * Resolved DB configuration, cached after first resolution.
 * Populated by initDb() (async path) or getDbConfig() (sync path).
 */
let resolvedConfig: DbConfig | null = null;

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

// ---------------------------------------------------------------------------
// Configuration resolution
// ---------------------------------------------------------------------------

/**
 * Parse a JSON secret value (as injected by ECS `secrets` or Secrets Manager).
 *
 * Expected payload:
 * ```json
 * { "host": "…", "port": 5432, "dbname": "…", "username": "…", "password": "…", "schema": "…" }
 * ```
 */
function parseDbSecretJson(raw: string): DbConfig {
  let secret: Record<string, unknown>;
  try {
    secret = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse DATABASE_SECRET_ARN value as JSON: ${err}`);
  }

  const host = secret.host as string | undefined;
  const port = Number(secret.port) || 5432;
  const database = (secret.dbname as string) || (secret.database as string) || undefined;
  const user = (secret.username as string) || (secret.user as string) || undefined;
  const password = secret.password as string | undefined;
  const schema = (secret.schema as string) || process.env.DATABASE_SCHEMA;

  if (!host || !user) {
    throw new Error(
      'DATABASE_SECRET_ARN secret is missing required fields (host, username). ' +
        `Received keys: ${Object.keys(secret).join(', ')}`,
    );
  }

  logger.info(
    { host, port, database, schema: schema || '(default)', user },
    'Database config resolved from secret',
  );

  return { host, port, database, user, password, schema, ssl: true };
}

/**
 * Resolve DATABASE_SECRET_ARN at runtime via AWS Secrets Manager.
 * Used when the env var contains an actual ARN (e.g. local dev against a real DB).
 */
async function resolveSecretArn(arn: string): Promise<DbConfig> {
  // Dynamic import so that @aws-sdk/client-secrets-manager is only loaded when needed.
  const { SecretsManagerClient, GetSecretValueCommand } = await import(
    '@aws-sdk/client-secrets-manager'
  );

  logger.info('Resolving database credentials from Secrets Manager');

  const client = new SecretsManagerClient({});
  const response = await client.send(new GetSecretValueCommand({ SecretId: arn }));

  if (!response.SecretString) {
    throw new Error('DATABASE_SECRET_ARN resolved but SecretString is empty');
  }

  return parseDbSecretJson(response.SecretString);
}

/**
 * Synchronous DB config resolution.
 *
 * Priority:
 *   1. DATABASE_URL  → connection-string mode
 *   2. DATABASE_SECRET_ARN containing JSON → parsed secret (ECS-injected)
 *   3. Explicit DB_HOST / DB_USER / DB_PASSWORD env vars
 *   4. Localhost fallback (development / test only)
 *
 * In non-local environments (NODE_ENV not in development|test and not empty),
 * the function will throw if no explicit config is found — preventing silent
 * fallback to localhost.
 */
function getDbConfig(): DbConfig {
  // Use cached config if already resolved (e.g. by initDb)
  if (resolvedConfig) return resolvedConfig;

  // 1. CONNECTION STRING
  if (process.env.DATABASE_URL) {
    resolvedConfig = {
      connectionString: process.env.DATABASE_URL,
      schema: process.env.DATABASE_SCHEMA,
    };
    return resolvedConfig;
  }

  // 2. SECRET (ECS-injected JSON value)
  const secretValue = process.env.DATABASE_SECRET_ARN;
  if (secretValue) {
    // If it looks like JSON, parse it directly (ECS pre-resolved the secret).
    if (secretValue.trimStart().startsWith('{')) {
      resolvedConfig = parseDbSecretJson(secretValue);
      return resolvedConfig;
    }
    // If it looks like an ARN, we cannot resolve it synchronously.
    // The caller must use initDb() first.
    throw new Error(
      'DATABASE_SECRET_ARN contains an ARN but initDb() was not called. ' +
        'Call await initDb() at service startup before using the database.',
    );
  }

  // 3. EXPLICIT ENV VARS
  if (process.env.DB_HOST) {
    resolvedConfig = {
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME || 'leasebase',
      user: process.env.DB_USER || 'leasebase_admin',
      password: process.env.DB_PASSWORD || '',
      schema: process.env.DATABASE_SCHEMA,
      ssl: process.env.DB_SSL === 'true',
    };
    return resolvedConfig;
  }

  // 4. LOCAL FALLBACK — only allowed in dev / test
  const env = process.env.NODE_ENV || '';
  const isLocal = !env || env === 'development' || env === 'test';

  if (!isLocal) {
    throw new Error(
      'FATAL: No database configuration found. In non-local environments, ' +
        'set DATABASE_URL, DATABASE_SECRET_ARN, or DB_HOST/DB_USER/DB_PASSWORD. ' +
        `Current NODE_ENV=${env}`,
    );
  }

  resolvedConfig = {
    host: 'localhost',
    port: 5432,
    database: 'leasebase',
    user: 'leasebase_admin',
    password: '',
    schema: process.env.DATABASE_SCHEMA,
    ssl: false,
  };
  return resolvedConfig;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/**
 * Pre-initialize the database pool.
 *
 * **Must** be called (and awaited) at service startup when DATABASE_SECRET_ARN
 * contains an ARN that needs runtime resolution via Secrets Manager.
 *
 * Safe to call multiple times — subsequent calls are no-ops.
 * Safe to skip if DATABASE_URL, ECS-injected JSON, or explicit env vars are used.
 */
export async function initDb(): Promise<void> {
  if (pool) return; // already initialised

  // Resolve config asynchronously when an ARN needs Secrets Manager lookup.
  if (!resolvedConfig) {
    const secretValue = process.env.DATABASE_SECRET_ARN;
    if (secretValue && !secretValue.trimStart().startsWith('{')) {
      resolvedConfig = await resolveSecretArn(secretValue);
    }
  }

  // Eagerly create the pool so that getPool() is safe to call synchronously.
  getPool();
}

// ---------------------------------------------------------------------------
// Pool management
// ---------------------------------------------------------------------------

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

    logger.info(
      { host: config.host || 'url', schema: config.schema },
      'Database pool created',
    );
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
    resolvedConfig = null;
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
