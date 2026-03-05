import { describe, it, expect } from 'vitest';
import {
  AppError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
  ConflictError,
} from '../errors';

describe('AppError', () => {
  it('sets code, statusCode, and message', () => {
    const err = new AppError('TEST', 418, 'teapot');
    expect(err.code).toBe('TEST');
    expect(err.statusCode).toBe(418);
    expect(err.message).toBe('teapot');
    expect(err).toBeInstanceOf(Error);
  });
});

describe('UnauthorizedError', () => {
  it('uses 401 status', () => {
    const err = new UnauthorizedError();
    expect(err.statusCode).toBe(401);
    expect(err.code).toBe('UNAUTHORIZED');
    expect(err.message).toBe('Authentication required');
  });

  it('accepts custom message', () => {
    const err = new UnauthorizedError('No token');
    expect(err.message).toBe('No token');
  });
});

describe('ForbiddenError', () => {
  it('uses 403 status', () => {
    expect(new ForbiddenError().statusCode).toBe(403);
    expect(new ForbiddenError().code).toBe('FORBIDDEN');
  });
});

describe('NotFoundError', () => {
  it('uses 404 status', () => {
    expect(new NotFoundError().statusCode).toBe(404);
    expect(new NotFoundError().code).toBe('NOT_FOUND');
  });
});

describe('ValidationError', () => {
  it('uses 400 status with details', () => {
    const err = new ValidationError('Bad input', [{ field: 'name' }]);
    expect(err.statusCode).toBe(400);
    expect(err.code).toBe('VALIDATION_ERROR');
    expect(err.details).toEqual([{ field: 'name' }]);
  });
});

describe('ConflictError', () => {
  it('uses 409 status', () => {
    expect(new ConflictError().statusCode).toBe(409);
    expect(new ConflictError().code).toBe('CONFLICT');
  });
});
