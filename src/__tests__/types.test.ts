import { describe, it, expect } from 'vitest';
import { UserRole, parsePagination, paginationMeta } from '../types';

describe('UserRole', () => {
  it('has the correct values', () => {
    expect(UserRole.ORG_ADMIN).toBe('ORG_ADMIN');
    expect(UserRole.PM_STAFF).toBe('PM_STAFF');
    expect(UserRole.OWNER).toBe('OWNER');
    expect(UserRole.TENANT).toBe('TENANT');
  });
});

describe('parsePagination', () => {
  it('returns defaults when no params given', () => {
    const result = parsePagination({});
    expect(result).toEqual({ page: 1, limit: 20, sort: undefined, order: 'asc' });
  });

  it('parses valid page and limit', () => {
    const result = parsePagination({ page: '3', limit: '50' });
    expect(result.page).toBe(3);
    expect(result.limit).toBe(50);
  });

  it('clamps page to minimum 1', () => {
    expect(parsePagination({ page: '-5' }).page).toBe(1);
    expect(parsePagination({ page: '0' }).page).toBe(1);
  });

  it('clamps limit to max 100', () => {
    expect(parsePagination({ limit: '200' }).limit).toBe(100);
  });

  it('defaults limit when given 0 (falsy)', () => {
    expect(parsePagination({ limit: '0' }).limit).toBe(20);
  });

  it('clamps limit to minimum 1', () => {
    expect(parsePagination({ limit: '-10' }).limit).toBe(1);
  });

  it('parses sort and order', () => {
    const result = parsePagination({ sort: 'name', order: 'desc' });
    expect(result.sort).toBe('name');
    expect(result.order).toBe('desc');
  });

  it('defaults order to asc for invalid input', () => {
    expect(parsePagination({ order: 'invalid' }).order).toBe('asc');
  });
});

describe('paginationMeta', () => {
  it('calculates correct metadata', () => {
    const meta = paginationMeta(95, { page: 2, limit: 20 });
    expect(meta).toEqual({ page: 2, limit: 20, total: 95, totalPages: 5 });
  });

  it('handles zero total', () => {
    const meta = paginationMeta(0, { page: 1, limit: 20 });
    expect(meta.totalPages).toBe(0);
  });

  it('handles exact division', () => {
    const meta = paginationMeta(40, { page: 1, limit: 20 });
    expect(meta.totalPages).toBe(2);
  });
});
