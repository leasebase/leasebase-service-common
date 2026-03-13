/**
 * Tests for requireAuth DB enrichment.
 *
 * After JWT verification, requireAuth looks up the User row by cognitoSub
 * to populate authoritative orgId, userId, name, and role from the database.
 * If the DB lookup fails or returns no row, JWT-derived values are preserved.
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

// ── Mock queryOne from db ────────────────────────────────────────────────────
const mockQueryOne = vi.fn();
vi.mock('../db', () => ({
  queryOne: (...args: any[]) => mockQueryOne(...args),
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

/** Standard JWT payload with custom:role but no custom:orgId (realistic scenario). */
const BASE_JWT_PAYLOAD = {
  sub: 'cognito-sub-123',
  email: 'owner@example.com',
  'custom:role': 'OWNER',
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('requireAuth — DB enrichment', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
    mockQueryOne.mockReset();
  });

  it('enriches orgId, userId, email, name, role from DB when user found', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id-456',
      organizationId: 'org-789',
      email: 'owner@example.com',
      name: 'Alice Owner',
      role: 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    expect(user!.sub).toBe('cognito-sub-123');
    expect(user!.userId).toBe('db-user-id-456');
    expect(user!.orgId).toBe('org-789');
    expect(user!.email).toBe('owner@example.com');
    expect(user!.name).toBe('Alice Owner');
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('passes cognitoSub to the DB query', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce(null);

    const req = mockReq({ authorization: 'Bearer valid-token' });
    await callRequireAuth(req);

    expect(mockQueryOne).toHaveBeenCalledWith(
      expect.stringContaining('"cognitoSub"'),
      ['cognito-sub-123'],
    );
  });

  it('falls back to JWT-derived values when DB returns no row', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      ...BASE_JWT_PAYLOAD,
      'custom:orgId': 'jwt-org-fallback',
    });
    mockQueryOne.mockResolvedValueOnce(null);

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    // Falls back to JWT values
    expect(user!.userId).toBe('cognito-sub-123'); // sub as userId fallback
    expect(user!.orgId).toBe('jwt-org-fallback');
    expect(user!.email).toBe('owner@example.com');
    expect(user!.name).toBe('owner@example.com'); // email as name fallback
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('falls back to JWT-derived values when DB query throws', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockRejectedValueOnce(new Error('Connection refused'));

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user, error } = await callRequireAuth(req);

    // Should NOT propagate the DB error — fail-open for enrichment
    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    expect(user!.userId).toBe('cognito-sub-123');
    expect(user!.orgId).toBe(''); // no custom:orgId in JWT, no DB
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('orgId defaults to empty string when neither JWT nor DB provides it', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD); // no custom:orgId
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: '', // empty in DB too
      email: 'owner@example.com',
      name: 'Owner',
      role: 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    // DB orgId is empty, JWT orgId is empty — stays empty
    expect(user!.orgId).toBe('');
  });

  it('DB role overrides JWT role when DB has different value', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      ...BASE_JWT_PAYLOAD,
      'custom:role': 'TENANT', // JWT says TENANT
    });
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-1',
      email: 'user@example.com',
      name: 'User',
      role: 'OWNER', // DB says OWNER (e.g. role was upgraded)
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    expect(user!.role).toBe(UserRole.OWNER); // DB wins
  });

  it('DB role is uppercased', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-1',
      email: 'user@example.com',
      name: 'User',
      role: 'owner', // lowercase in DB
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('preserves scopes from JWT (not overridden by DB)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      ...BASE_JWT_PAYLOAD,
      scope: 'api/read api/write',
    });
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-1',
      email: 'owner@example.com',
      name: 'Owner',
      role: 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    expect(user!.scopes).toEqual(['api/read', 'api/write']);
  });

  it('preserves sub from JWT (not overridden by DB)', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-1',
      email: 'owner@example.com',
      name: 'Owner',
      role: 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    expect(user!.sub).toBe('cognito-sub-123'); // Cognito sub, not DB id
  });

  it('does not override email/name with empty DB values', async () => {
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce({
      id: 'db-user-id',
      organizationId: 'org-1',
      email: '', // empty
      name: '', // empty
      role: 'OWNER',
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { user } = await callRequireAuth(req);

    // Should keep JWT-derived email, not replace with empty
    expect(user!.email).toBe('owner@example.com');
    expect(user!.name).toBe('owner@example.com'); // JWT fallback (email as name)
  });

  it('does not skip DB enrichment for dev-bypass mode', async () => {
    // Dev bypass has its own path and should NOT trigger DB enrichment.
    // This test just verifies normal JWT path does trigger it.
    mockVerifyToken.mockResolvedValueOnce(BASE_JWT_PAYLOAD);
    mockQueryOne.mockResolvedValueOnce(null);

    const req = mockReq({ authorization: 'Bearer valid-token' });
    await callRequireAuth(req);

    expect(mockQueryOne).toHaveBeenCalledTimes(1);
  });

  it('still rejects tokens missing custom:role even with DB available', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-no-role',
      email: 'norole@test.com',
      // No custom:role
    });

    const req = mockReq({ authorization: 'Bearer valid-token' });
    const { error } = await callRequireAuth(req);

    // Fail-closed on missing role happens BEFORE DB enrichment
    expect(error).toBeDefined();
    expect(mockQueryOne).not.toHaveBeenCalled();
  });
});
