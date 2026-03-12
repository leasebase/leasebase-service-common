import type { Request } from 'express';

export enum UserRole {
  OWNER = 'OWNER',
  TENANT = 'TENANT',
}

export interface CurrentUser {
  sub: string;
  userId: string;
  orgId: string;
  email: string;
  role: UserRole;
  name: string;
  scopes: string[];
}

export interface AuthenticatedRequest extends Request {
  user: CurrentUser;
  correlationId: string;
}

export interface ApiResponse<T = unknown> {
  data: T;
  meta?: PaginationMeta;
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown[];
    correlationId?: string;
  };
}

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface PaginationQuery {
  page: number;
  limit: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export function parsePagination(query: Record<string, unknown>): PaginationQuery {
  const page = Math.max(1, Number(query.page) || 1);
  const limit = Math.min(100, Math.max(1, Number(query.limit) || 20));
  const sort = typeof query.sort === 'string' ? query.sort : undefined;
  const order = query.order === 'desc' ? 'desc' : 'asc';
  return { page, limit, sort, order };
}

export function paginationMeta(total: number, query: PaginationQuery): PaginationMeta {
  return {
    page: query.page,
    limit: query.limit,
    total,
    totalPages: Math.ceil(total / query.limit),
  };
}
