/**
 * Tests for requireAuth enriched-role resolution.
 *
 * Verifies that when JWT custom:role is absent, the middleware uses
 * the BFF-set x-lb-enriched-role header (fail-closed: no TENANT fallback).
 *
 * When both JWT custom:role AND enriched header are present, the enriched
 * header takes priority because the BFF resolves it from the DB (source of
 * truth). The BFF strips this header from external requests, so it can only
 * originate from the trusted gateway layer.
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

  it('enriched header takes priority over JWT custom:role (DB is source of truth)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-1',
      email: 'owner@test.com',
      'custom:role': 'OWNER',
      'custom:orgId': 'org-1',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'TENANT',  // BFF resolved from DB — takes priority
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
    expect(user.role).toBe(UserRole.TENANT);  // enriched wins
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

  it('defaults to TENANT when both JWT claim and enriched header are absent (access token)', async () => {
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

    // next called without error — role defaults to TENANT for access tokens
    expect(next).toHaveBeenCalledWith();
    const user = (req as unknown as AuthenticatedRequest).user;
    expect(user.role).toBe(UserRole.TENANT);
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

  it('enriched header overrides JWT claim when DB role differs (e.g. role promotion)', async () => {
    // Scenario: JWT has stale TENANT role, but DB (via BFF enriched header)
    // shows user was promoted to ORG_ADMIN. Enriched header wins.
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-5',
      email: 'promoted@test.com',
      'custom:role': 'TENANT',
    });

    const req = mockReq({
      authorization: 'Bearer fake-token',
      'x-lb-enriched-role': 'ORG_ADMIN',  // BFF resolved from DB
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
    expect(user.role).toBe(UserRole.ORG_ADMIN);  // enriched (DB) wins
  });
});
