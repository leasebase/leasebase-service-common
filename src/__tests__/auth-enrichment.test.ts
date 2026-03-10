import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import type { AuthenticatedRequest } from '../types';
import { UserRole } from '../types';

// ── Mock the JWT verifier ────────────────────────────────────────────────────
const mockVerifyToken = vi.fn();
vi.mock('../jwt-verifier', () => ({
  verifyToken: (...args: unknown[]) => mockVerifyToken(...args),
  getJwtConfig: () => ({
    region: 'us-west-2',
    userPoolId: 'test-pool',
    clientId: 'test-client',
  }),
  resetJwksCache: vi.fn(),
}));

// Import requireAuth AFTER mocks are set up
import { requireAuth } from '../middleware/auth';

// ── Helpers ──────────────────────────────────────────────────────────────────

function fakeReq(headers: Record<string, string> = {}): Request {
  return { headers } as unknown as Request;
}

function fakeRes(): Response {
  return {} as unknown as Response;
}

/** Wrap requireAuth in a Promise for easier async testing. */
function callRequireAuth(req: Request): Promise<{ user: AuthenticatedRequest['user'] | undefined; error: unknown }> {
  return new Promise((resolve) => {
    const next: NextFunction = (err?: unknown) => {
      resolve({
        user: (req as AuthenticatedRequest).user,
        error: err,
      });
    };
    requireAuth(req, fakeRes(), next);
  });
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('requireAuth — BFF role enrichment', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    mockVerifyToken.mockReset();
    process.env = { ...originalEnv };
    // Ensure dev bypass is off
    delete process.env.DEV_AUTH_BYPASS;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('uses enriched OWNER role when JWT custom:role is missing', async () => {
    // JWT has no custom:role — requireAuth would default to TENANT
    // But BFF enriched header overrides to OWNER
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-123',
      email: 'owner@org.com',
      'custom:orgId': 'org-1',
      // No custom:role — middleware defaults to TENANT
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'OWNER',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user).toBeDefined();
    expect(user!.role).toBe(UserRole.OWNER);
    expect(user!.sub).toBe('user-123');
  });

  it('uses enriched TENANT role (DB confirms TENANT)', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-456',
      email: 'tenant@org.com',
      'custom:orgId': 'org-1',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'TENANT',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.TENANT);
  });

  it('uses enriched ORG_ADMIN role', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'admin-sub',
      email: 'admin@org.com',
      'custom:orgId': 'org-1',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'ORG_ADMIN',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.ORG_ADMIN);
  });

  it('rejects with 401 when no enriched header and no JWT custom:role (fail-closed)', async () => {
    // No x-lb-enriched-role header and no custom:role in JWT → fail closed
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-789',
      email: 'new@org.com',
      'custom:orgId': 'org-1',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      // No x-lb-enriched-role header
    });

    const { error } = await callRequireAuth(req);

    expect(error).toBeDefined();
  });

  it('uses JWT custom:role when present AND no enriched header', async () => {
    // JWT explicitly has custom:role = OWNER, no enriched header
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-abc',
      email: 'owner2@org.com',
      'custom:orgId': 'org-1',
      'custom:role': 'OWNER',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('enriched header overrides even when JWT custom:role is present', async () => {
    // Edge case: JWT says TENANT but DB (via enriched header) says OWNER
    // DB is the source of truth
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-conflict',
      email: 'conflict@org.com',
      'custom:orgId': 'org-1',
      'custom:role': 'TENANT',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'OWNER',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('preserves other user fields when enriched role is applied', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'user-full',
      email: 'full@org.com',
      'custom:orgId': 'org-42',
      scope: 'api/read api/write',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'OWNER',
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.sub).toBe('user-full');
    expect(user!.email).toBe('full@org.com');
    expect(user!.orgId).toBe('org-42');
    expect(user!.scopes).toEqual(['api/read', 'api/write']);
    expect(user!.role).toBe(UserRole.OWNER);
  });

  it('enriched role is case-insensitive', async () => {
    mockVerifyToken.mockResolvedValueOnce({
      sub: 'case-sub',
      email: 'case@org.com',
      'custom:orgId': 'org-1',
    });

    const req = fakeReq({
      authorization: 'Bearer valid-token',
      'x-lb-enriched-role': 'owner', // lowercase
    });

    const { user, error } = await callRequireAuth(req);

    expect(error).toBeUndefined();
    expect(user!.role).toBe(UserRole.OWNER);
  });
});

// Note: DEV_BYPASS is a module-level const in auth.ts, captured at import time.
// To test dev-bypass behavior, the module would need to be re-imported with
// DEV_AUTH_BYPASS=true already set. The dev-bypass flow is already covered by
// auth-middleware.test.ts. Here we verify the enrichment path doesn't interfere
// when the JWT flow is active (DEV_BYPASS = false at import time).

describe('requireAuth — enrichment does not affect JWT flow correctness', () => {
  beforeEach(() => {
    mockVerifyToken.mockReset();
  });

  it('rejects requests with no auth header and no enriched header', async () => {
    const req = fakeReq({});
    const { error } = await callRequireAuth(req);
    expect(error).toBeDefined();
  });

  it('rejects requests with invalid JWT even if enriched header is set', async () => {
    mockVerifyToken.mockRejectedValueOnce(new Error('Invalid token'));

    const req = fakeReq({
      authorization: 'Bearer bad-token',
      'x-lb-enriched-role': 'OWNER',
    });

    const { error } = await callRequireAuth(req);
    expect(error).toBeDefined();
  });
});
