/**
 * Tests for requireAuth DB role fallback.
 *
 * Verifies that when neither x-lb-enriched-role header nor JWT custom:role
 * claim is present (standard Cognito access tokens), the middleware falls
 * back to a DB lookup by cognitoSub with in-process caching.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { UserRole, type AuthenticatedRequest } from '../types';

// ── Mock verifyToken ─────────────────────────────────────────────────────────
const mockVerifyToken = vi.fn();
vi.mock('../jwt-verifier', () => ({
  verifyToken: (...args: any[]) => mockVerifyToken(...args),
  getJwtConfig: () => ({ region: 'us-west-2', userPoolId: 'pool-1', clientId: 'client-1' }),
  resetJwksCache: vi.fn(),
  setJwksForTesting: vi.fn(),
}));

// ── Mock DB module ───────────────────────────────────────────────────────────
const mockQueryOne = vi.fn();
vi.mock('../db', () => ({
  queryOne: (...args: any[]) => mockQueryOne(...args),
  query: vi.fn(),
  getPool: vi.fn(),
  getDbConfig: vi.fn(),
  initDb: vi.fn(),
  checkDbConnection: vi.fn(),
  closePool: vi.fn(),
}));

// Import after mocks
import { requireAuth, requireRole } from '../middleware/auth';
import { clearRoleCache, roleCacheSize } from '../middleware/role-cache';

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockReq(headers: Record<string, string> = {}): Request {
  return { headers } as unknown as Request;
}

function mockRes(): Response {
  return {} as unknown as Response;
}

function callRequireAuth(req: Request): Promise<{ user: AuthenticatedRequest['user'] | undefined; error: unknown }> {
  return new Promise((resolve) => {
    const next: NextFunction = (err?: unknown) => {
      resolve({
        user: (req as AuthenticatedRequest).user,
        error: err,
      });
    };
    requireAuth(req, mockRes(), next);
  });
}

function callRequireRole(req: Request, ...roles: string[]): Promise<{ error: unknown }> {
  return new Promise((resolve) => {
    const middleware = requireRole(...roles);
    const next: NextFunction = (err?: unknown) => {
      resolve({ error: err });
    };
    middleware(req, mockRes(), next);
  });
}

// ── Access-token payload (no custom:role) ────────────────────────────────────
const accessTokenPayload = {
  sub: 'owner-sub-1',
  email: 'owner@test.com',
  scope: 'aws.cognito.signin.user.admin',
  // No custom:role — standard Cognito access token
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('requireAuth — DB role fallback', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
    mockQueryOne.mockReset();
    clearRoleCache();
  });

  it('resolves OWNER role from DB when JWT has no custom:role and no enriched header', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER', organizationId: 'org-1' });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    expect(user!.role).toBe(UserRole.OWNER);
    expect(user!.orgId).toBe('org-1');
    expect(user!.sub).toBe('owner-sub-1');

    // DB was queried
    expect(mockQueryOne).toHaveBeenCalledTimes(1);
    expect(mockQueryOne).toHaveBeenCalledWith(
      expect.stringContaining('"cognitoSub"'),
      ['owner-sub-1'],
    );
  });

  it('resolves TENANT role from DB when user is actually TENANT', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'tenant-sub-1',
      email: 'tenant@test.com',
    });
    mockQueryOne.mockResolvedValueOnce({ role: 'TENANT', organizationId: 'org-2' });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT);
    expect(user!.orgId).toBe('org-2');
  });

  it('uses cached role on subsequent requests (no DB query)', async () => {
    // First request — DB lookup
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER', organizationId: 'org-1' });

    const req1 = mockReq({ authorization: 'Bearer fake-token' });
    await callRequireAuth(req1);
    expect(mockQueryOne).toHaveBeenCalledTimes(1);

    // Second request — should hit cache
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    const req2 = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req2);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
    expect(user!.orgId).toBe('org-1');
    // DB NOT queried again
    expect(mockQueryOne).toHaveBeenCalledTimes(1);
    expect(roleCacheSize()).toBe(1);
  });

  it('falls back to TENANT when user is not found in DB', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce(null); // No user row

    const req = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT); // default fallback
    expect(mockQueryOne).toHaveBeenCalledTimes(1);
  });

  it('negative cache prevents repeated DB queries for unknown users', async () => {
    // First request — user not found
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce(null);
    await callRequireAuth(mockReq({ authorization: 'Bearer fake-token' }));
    expect(mockQueryOne).toHaveBeenCalledTimes(1);

    // Second request — negative cache hit, no DB query
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    await callRequireAuth(mockReq({ authorization: 'Bearer fake-token' }));
    expect(mockQueryOne).toHaveBeenCalledTimes(1); // still 1
  });

  it('falls back to TENANT when DB query throws', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const req = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT); // graceful fallback
  });

  it('enriched header still takes priority over DB fallback', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'ORG_ADMIN',
    });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.ORG_ADMIN);
    // DB should NOT be queried when enriched header is present
    expect(mockQueryOne).not.toHaveBeenCalled();
  });

  it('JWT custom:role still takes priority over DB fallback', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      ...accessTokenPayload,
      'custom:role': 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
    // DB should NOT be queried when JWT has custom:role
    expect(mockQueryOne).not.toHaveBeenCalled();
  });
});

describe('requireRole after DB fallback resolution', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
    mockQueryOne.mockReset();
    clearRoleCache();
  });

  it('OWNER from DB can access OWNER-only routes', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER', organizationId: 'org-1' });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    await callRequireAuth(req);
    const { error } = await callRequireRole(req, 'OWNER');

    expect(error).toBeUndefined();
  });

  it('TENANT from DB is rejected from OWNER-only routes', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'tenant-sub',
      email: 'tenant@test.com',
    });
    mockQueryOne.mockResolvedValueOnce({ role: 'TENANT', organizationId: 'org-1' });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    await callRequireAuth(req);
    const { error } = await callRequireRole(req, 'OWNER');

    expect(error).toBeDefined();
  });

  it('OWNER from DB can access routes allowing OWNER or TENANT', async () => {
    mockVerifyToken.mockResolvedValueOnce(accessTokenPayload);
    mockQueryOne.mockResolvedValueOnce({ role: 'OWNER', organizationId: 'org-1' });

    const req = mockReq({ authorization: 'Bearer fake-token' });
    await callRequireAuth(req);
    const { error } = await callRequireRole(req, 'OWNER', 'TENANT');

    expect(error).toBeUndefined();
  });
});
