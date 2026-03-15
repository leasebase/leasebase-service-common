/**
 * Tests for requireAuth fail-closed behavior.
 *
 * After auth hardening, the middleware rejects tokens that lack `custom:role`
 * instead of silently defaulting to TENANT. The only accepted role source is
 * the JWT `custom:role` claim.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
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

// ── Mock DB (prevent real connections in unit tests) ─────────────────────────
vi.mock('../db', () => ({
  queryOne: vi.fn().mockResolvedValue(null),
}));

// Import after mocks
import { requireAuth } from '../middleware/auth';

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

// ── Tests ────────────────────────────────────────────────────────────────────

describe('requireAuth — fail-closed role resolution', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
  });

  it('accepts token with custom:role OWNER', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-1',
      email: 'owner@test.com',
      'custom:role': 'OWNER',
      'custom:orgId': 'org-1',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    expect(user!.role).toBe(UserRole.OWNER);
    expect(user!.orgId).toBe('org-1');
  });

  it('accepts token with custom:role TENANT', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-2',
      email: 'tenant@test.com',
      'custom:role': 'TENANT',
      'custom:orgId': 'org-2',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT);
  });

  it('REJECTS token missing custom:role (fail-closed, no TENANT default)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-3',
      email: 'nope@test.com',
      // No custom:role — access tokens lack this claim
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeDefined();
    expect((error as any).message).toContain('missing required role claim');
    expect(user).toBeUndefined();
  });

  it('REJECTS token with empty custom:role', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-4',
      email: 'empty@test.com',
      'custom:role': '',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeDefined();
    expect(user).toBeUndefined();
  });

  it('ignores x-lb-enriched-role header (no longer accepted)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-5',
      email: 'tricky@test.com',
      // No custom:role in JWT
    });

    const req = mockReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'OWNER', // should be ignored
    });
    const { error } = await callRequireAuth(req);

    // Should still fail — enriched header is no longer accepted
    expect(error).toBeDefined();
  });

  it('role is uppercased from JWT claim', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-6',
      email: 'case@test.com',
      'custom:role': 'owner', // lowercase
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('preserves all user fields from verified token', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-7',
      email: 'full@test.com',
      'custom:role': 'OWNER',
      'custom:orgId': 'org-42',
      scope: 'api/read api/write',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    expect(user!.sub).toBe('user-7');
    expect(user!.email).toBe('full@test.com');
    expect(user!.orgId).toBe('org-42');
    expect(user!.scopes).toEqual(['api/read', 'api/write']);
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('rejects missing Authorization header', async () => {
    const req = mockReq({});
    const { error } = await callRequireAuth(req);
    expect(error).toBeDefined();
  });

  it('rejects invalid JWT', async () => {
    mockVerifyToken.mockRejectedValueOnce(new Error('Invalid token'));
    const req = mockReq({ authorization: 'Bearer bad-token' });
    const { error } = await callRequireAuth(req);
    expect(error).toBeDefined();
  });
});
