/**
 * Tests for requireAuth enriched-role resolution.
 *
 * Verifies that when JWT custom:role is absent, the middleware uses
 * the BFF-set x-lb-enriched-role header before falling back to TENANT.
 *
 * Also verifies that when JWT custom:role IS present, it takes precedence
 * over the enriched header (JWT is authoritative when available).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { UserRole, type AuthenticatedRequest } from '../types';

// ── Mock verifyToken to return controllable payloads ─────────────────────────
const mockVerifyToken = vi.fn();
vi.mock('../jwt-verifier', () => ({
  verifyToken: (...args: any[]) => mockVerifyToken(...args),
  getJwtConfig: () => ({ region: 'us-west-2', userPoolId: 'pool-1', clientId: 'client-1' }),
  resetJwksCache: vi.fn(),
  setJwksForTesting: vi.fn(),
}));

// Import after mocks
import { requireAuth } from '../middleware/auth';

function mockReq(headers: Record<string, string> = {}): Request {
  return { headers } as unknown as Request;
}

function mockRes(): Response {
  return {} as unknown as Response;
}

describe('requireAuth — enriched role resolution', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
  });

  it('uses JWT custom:role when present (ignores enriched header)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-1',
      email: 'owner@test.com',
      'custom:role': 'OWNER',
      'custom:orgId': 'org-1',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'TENANT',  // should be ignored
    });
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      requireAuth(req, mockRes(), (...args: any[]) => {
        next(...args);
        resolve();
      });
    });

    expect(next).toHaveBeenCalledWith();
    const user = (req as unknown as AuthenticatedRequest).user;
    expect(user.role).toBe(UserRole.OWNER);
  });

  it('uses enriched-role header when JWT custom:role is absent', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-2',
      email: 'owner2@test.com',
      // No custom:role claim
      'custom:orgId': 'org-2',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'OWNER',
    });
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      requireAuth(req, mockRes(), (...args: any[]) => {
        next(...args);
        resolve();
      });
    });

    expect(next).toHaveBeenCalledWith();
    const user = (req as unknown as AuthenticatedRequest).user;
    expect(user.role).toBe(UserRole.OWNER);
  });

  it('returns 401 when both JWT claim and enriched header are absent (fail closed)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-3',
      email: 'unknown@test.com',
      // No custom:role, no enriched header
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
    });
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      requireAuth(req, mockRes(), (...args: any[]) => {
        next(...args);
        resolve();
      });
    });

    // next should be called with an UnauthorizedError (no silent TENANT fallback)
    expect(next).toHaveBeenCalledTimes(1);
    const error = next.mock.calls[0][0];
    expect(error).toBeDefined();
    expect(error.statusCode || error.status).toBe(401);
  });

  it('enriched-role header is case-insensitive (uppercased)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-4',
      email: 'pm@test.com',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'org_admin',
    });
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      requireAuth(req, mockRes(), (...args: any[]) => {
        next(...args);
        resolve();
      });
    });

    expect(next).toHaveBeenCalledWith();
    const user = (req as unknown as AuthenticatedRequest).user;
    expect(user.role).toBe(UserRole.ORG_ADMIN);
  });

  it('does NOT trust enriched-role header for privilege escalation when JWT has explicit claim', async () => {
    // Scenario: JWT says TENANT, but forged/stale enriched header says ORG_ADMIN
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-5',
      email: 'tenant@test.com',
      'custom:role': 'TENANT',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'ORG_ADMIN',  // should be ignored
    });
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      requireAuth(req, mockRes(), (...args: any[]) => {
        next(...args);
        resolve();
      });
    });

    expect(next).toHaveBeenCalledWith();
    const user = (req as unknown as AuthenticatedRequest).user;
    expect(user.role).toBe(UserRole.TENANT);  // JWT claim wins
  });
});
