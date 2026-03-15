/**
 * Tests for requireAuth JWT-only role resolution.
 *
 * BFF role enrichment (x-lb-enriched-role) has been removed.
 * Role is now resolved exclusively from the JWT custom:role claim.
 * If the claim is absent, the request is rejected (fail closed).
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

import { requireAuth } from '../middleware/auth';

function mockReq(headers: Record<string, string> = {}): Request {
  return { headers } as unknown as Request;
}
function mockRes(): Response {
  return {} as unknown as Response;
}

function callAuth(req: Request): Promise<{ user?: AuthenticatedRequest['user']; error?: unknown }> {
  return new Promise((resolve) => {
    requireAuth(req, mockRes(), (err?: unknown) => {
      resolve({ user: (req as unknown as AuthenticatedRequest).user, error: err });
    });
  });
}

describe('requireAuth — JWT custom:role is the sole role source', () => {
  beforeEach(() => mockVerifyToken.mockReset());

  it('uses JWT custom:role OWNER', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-1', email: 'o@t.com', 'custom:role': 'OWNER', 'custom:orgId': 'org-1',
    });
    const { user, error } = await callAuth(mockReq({ authorization: 'Bearer t' }));
    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('uses JWT custom:role TENANT', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-2', email: 't@t.com', 'custom:role': 'TENANT', 'custom:orgId': 'org-2',
    });
    const { user, error } = await callAuth(mockReq({ authorization: 'Bearer t' }));
    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT);
  });

  it('rejects when JWT custom:role is absent (fail closed)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-3', email: 'u@t.com',
    });
    const { error } = await callAuth(mockReq({ authorization: 'Bearer t' }));
    expect(error).toBeDefined();
    expect((error as any).statusCode || (error as any).status).toBe(401);
  });

  it('ignores x-lb-enriched-role header (enrichment removed)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-4', email: 'u@t.com',
      // No custom:role
    });
    const { error } = await callAuth(mockReq({
      authorization: 'Bearer t',
      'x-lb-enriched-role': 'OWNER',
    }));
    // Should still fail — enriched header is not used
    expect(error).toBeDefined();
  });

  it('role is case-insensitive (uppercased)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-5', email: 'c@t.com', 'custom:role': 'owner', 'custom:orgId': 'org-1',
    });
    const { user, error } = await callAuth(mockReq({ authorization: 'Bearer t' }));
    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('JWT custom:role takes precedence even if enriched header differs', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-6', email: 't@t.com', 'custom:role': 'TENANT',
    });
    const { user, error } = await callAuth(mockReq({
      authorization: 'Bearer t',
      'x-lb-enriched-role': 'OWNER',  // ignored
    }));
    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT);
  });

  it('preserves all user fields from JWT payload', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-full', email: 'full@t.com', 'custom:orgId': 'org-42',
      'custom:role': 'OWNER', scope: 'api/read api/write',
    });
    const { user, error } = await callAuth(mockReq({ authorization: 'Bearer t' }));
    expect(error).toBeUndefined();
    expect(user!.sub).toBe('user-full');
    expect(user!.email).toBe('full@t.com');
    expect(user!.orgId).toBe('org-42');
    expect(user!.scopes).toEqual(['api/read', 'api/write']);
  });

  it('rejects when no Authorization header', async () => {
    const { error } = await callAuth(mockReq({}));
    expect(error).toBeDefined();
  });

  it('rejects when JWT verification fails', async () => {
    mockVerifyToken.mockRejectedValueOnce(new Error('bad'));
    const { error } = await callAuth(mockReq({ authorization: 'Bearer bad' }));
    expect(error).toBeDefined();
  });
});
