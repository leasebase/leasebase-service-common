/**
 * In-process TTL cache for DB-resolved user roles.
 *
 * Keyed by Cognito `sub` (not email — subs are immutable).
 * Positive entries (role found) have a 5-minute TTL.
 * Negative entries (user not found) have a 30-second TTL to allow
 * eventual consistency after registration without hammering the DB.
 *
 * This cache is intentionally simple (Map-based, no LRU eviction).
 * Each service instance has its own cache — this is fine for the
 * current scale. If the fleet grows, replace with Redis or similar.
 *
 * When a Cognito pre-token-generation Lambda is added later, the JWT
 * will carry custom:role directly and this fallback path will never
 * be hit (the cache will naturally go unused).
 */

import { logger } from '../logger';

export interface RoleCacheEntry {
  role: string | null; // null = user not found (negative cache)
  orgId: string;
  expiresAt: number;
}

/** Positive cache TTL: 5 minutes. */
const POSITIVE_TTL_MS = 5 * 60 * 1000;

/** Negative cache TTL: 30 seconds. */
const NEGATIVE_TTL_MS = 30 * 1000;

const cache = new Map<string, RoleCacheEntry>();

/**
 * Get a cached role for the given Cognito subject.
 * Returns `undefined` if there is no cache entry or it has expired.
 */
export function getCachedRole(sub: string): RoleCacheEntry | undefined {
  const entry = cache.get(sub);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(sub);
    return undefined;
  }
  return entry;
}

/**
 * Store a positive (role found) cache entry.
 */
export function setCachedRole(sub: string, role: string, orgId: string): void {
  cache.set(sub, {
    role,
    orgId,
    expiresAt: Date.now() + POSITIVE_TTL_MS,
  });
}

/**
 * Store a negative (user not found) cache entry.
 */
export function setCachedNegative(sub: string): void {
  cache.set(sub, {
    role: null,
    orgId: '',
    expiresAt: Date.now() + NEGATIVE_TTL_MS,
  });
}

/**
 * Clear the entire cache. Useful for testing.
 */
export function clearRoleCache(): void {
  cache.delete;
  cache.clear();
}

/**
 * Return the current cache size. Useful for testing / metrics.
 */
export function roleCacheSize(): number {
  return cache.size;
}

// Periodic cleanup of expired entries to prevent unbounded growth.
// Runs every 60 seconds. Lightweight — just iterates the Map.
const CLEANUP_INTERVAL_MS = 60 * 1000;
let cleanupTimer: ReturnType<typeof setInterval> | null = null;

export function startCacheCleanup(): void {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    const now = Date.now();
    let evicted = 0;
    for (const [key, entry] of cache) {
      if (now > entry.expiresAt) {
        cache.delete(key);
        evicted++;
      }
    }
    if (evicted > 0) {
      logger.debug({ evicted, remaining: cache.size }, 'role-cache cleanup');
    }
  }, CLEANUP_INTERVAL_MS);

  // Allow the process to exit even if the timer is active.
  if (cleanupTimer && typeof cleanupTimer === 'object' && 'unref' in cleanupTimer) {
    cleanupTimer.unref();
  }
}

export function stopCacheCleanup(): void {
  if (cleanupTimer) {
    clearInterval(cleanupTimer);
    cleanupTimer = null;
  }
}

// Start cleanup automatically on module load.
startCacheCleanup();
