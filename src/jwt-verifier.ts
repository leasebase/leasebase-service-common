import { createRemoteJWKSet, createLocalJWKSet, jwtVerify, type JWTPayload, type JSONWebKeySet } from 'jose';
import { logger } from './logger';

type JwksResolver = ReturnType<typeof createRemoteJWKSet>;
let jwks: JwksResolver | null = null;

export interface JwtConfig {
  region: string;
  userPoolId: string;
  clientId: string;
}

/**
 * Cognito token types:
 *
 * - **access** tokens carry `client_id` (NOT `aud`) and `token_use: "access"`.
 *   Used for API authorization.
 * - **id** tokens carry `aud` (set to the app client ID) and `token_use: "id"`.
 *   Used for identity claims.
 *
 * The `jose` library's `audience` option checks the `aud` claim, which does
 * not exist in Cognito access tokens. We therefore verify the audience/client
 * manually after signature + issuer checks.
 */
export interface VerifiedToken extends JWTPayload {
  sub: string;
  email?: string;
  'custom:orgId'?: string;
  'custom:role'?: string;
  scope?: string;
  /** Cognito token type: `"access"` or `"id"`. */
  token_use?: string;
  /** Present on Cognito access tokens (not on ID tokens). */
  client_id?: string;
}

function getIssuer(config: JwtConfig): string {
  return `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`;
}

function getJwksUrl(config: JwtConfig): URL {
  return new URL(`${getIssuer(config)}/.well-known/jwks.json`);
}

export function getJwtConfig(): JwtConfig {
  const region = process.env.COGNITO_REGION || 'us-west-2';
  const userPoolId = process.env.COGNITO_USER_POOL_ID || '';
  const clientId = process.env.COGNITO_CLIENT_ID || '';
  return { region, userPoolId, clientId };
}

/**
 * Verify a Cognito JWT (access or ID token).
 *
 * Checks performed:
 * 1. Signature (via JWKS)
 * 2. Expiry (with 30 s clock tolerance)
 * 3. Issuer (must match the user pool URL)
 * 4. `token_use` must be `"access"` or `"id"`
 * 5. Client validation:
 *    - access token → `client_id` must match configured client ID
 *    - ID token → `aud` must match configured client ID
 */
export async function verifyToken(token: string, config?: JwtConfig): Promise<VerifiedToken> {
  const cfg = config || getJwtConfig();

  if (!cfg.userPoolId || !cfg.clientId) {
    throw new Error('Cognito configuration is missing (COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID)');
  }

  if (!jwks) {
    const url = getJwksUrl(cfg);
    logger.info({ jwksUrl: url.toString() }, 'Initializing JWKS key set');
    jwks = createRemoteJWKSet(url);
  }

  const issuer = getIssuer(cfg);

  // Verify signature, expiry, and issuer.
  // Do NOT pass `audience` here — Cognito access tokens lack an `aud` claim.
  // Client validation is done manually below.
  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    clockTolerance: 30,
  });

  const verified = payload as VerifiedToken;

  // ── token_use gate ──────────────────────────────────────────────────────
  const tokenUse = verified.token_use;
  if (tokenUse !== 'access' && tokenUse !== 'id') {
    throw new Error(
      `Unexpected token_use: ${tokenUse ?? '(missing)'}. Expected "access" or "id".`,
    );
  }

  // ── Client validation ───────────────────────────────────────────────────
  if (tokenUse === 'access') {
    // Access tokens carry `client_id` (not `aud`).
    if (verified.client_id !== cfg.clientId) {
      throw new Error(
        `Access token client_id mismatch: expected ${cfg.clientId}, got ${verified.client_id ?? '(missing)'}`,
      );
    }
  } else {
    // ID tokens carry `aud` (set to the app client ID).
    const aud = Array.isArray(verified.aud) ? verified.aud : [verified.aud];
    if (!aud.includes(cfg.clientId)) {
      throw new Error(
        `ID token aud mismatch: expected ${cfg.clientId}, got ${verified.aud ?? '(missing)'}`,
      );
    }
  }

  return verified;
}

/** Reset the cached JWKS (useful for testing). */
export function resetJwksCache(): void {
  jwks = null;
}

/**
 * Inject a local JWKS for testing. Avoids HTTP calls to Cognito.
 * Call `resetJwksCache()` in `beforeEach` to clear between tests.
 */
export function setJwksForTesting(jwksJson: JSONWebKeySet): void {
  jwks = createLocalJWKSet(jwksJson) as unknown as JwksResolver;
}
