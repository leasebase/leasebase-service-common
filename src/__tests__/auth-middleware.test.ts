import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { requireRole, requireScope } from '../middleware/auth';
import { UserRole, type AuthenticatedRequest } from '../types';
import { ForbiddenError, UnauthorizedError } from '../errors';

function mockReq(user?: Partial<AuthenticatedRequest['user']>): Request {
  const req = { headers: {} } as unknown as AuthenticatedRequest;
  if (user) {
    req.user = {
      sub: 'test-sub',
      userId: 'test-user',
      orgId: 'org-1',
      email: 'test@test.com',
      role: UserRole.TENANT,
      name: 'Test',
      scopes: [],
      ...user,
    };
  }
  return req as unknown as Request;
}

describe('requireRole', () => {
  it('allows user with matching role', () => {
    const middleware = requireRole(UserRole.OWNER);
    const req = mockReq({ role: UserRole.OWNER });
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('rejects user with non-matching role', () => {
    const middleware = requireRole(UserRole.OWNER);
    const req = mockReq({ role: UserRole.TENANT });
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith(expect.any(ForbiddenError));
  });

  it('allows any of multiple roles', () => {
    const middleware = requireRole(UserRole.OWNER, UserRole.TENANT);
    const req = mockReq({ role: UserRole.TENANT });
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('returns unauthorized when no user', () => {
    const middleware = requireRole(UserRole.OWNER);
    const req = mockReq(); // no user set — need to remove it
    delete (req as any).user;
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith(expect.any(UnauthorizedError));
  });
});

describe('requireScope', () => {
  it('allows user with required scope', () => {
    const middleware = requireScope('api/read');
    const req = mockReq({ scopes: ['api/read', 'api/write'] });
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('rejects user missing required scope', () => {
    const middleware = requireScope('api/admin');
    const req = mockReq({ scopes: ['api/read'] });
    const next = vi.fn();
    middleware(req, {} as Response, next);
    expect(next).toHaveBeenCalledWith(expect.any(ForbiddenError));
  });
});
