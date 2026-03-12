/**
 * Tests for jwt-verifier.ts — Cognito-style token verification.
 *
 * Uses jose.SignJWT + generateKeyPair to create real signed JWTs locally,
 * then injects the public key as a custom JWKS resolver.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, type KeyLike } from 'jose';
import { verifyToken, resetJwksCache, setJwksForTesting, type JwtConfig } from '../jwt-verifier';

let privateKey: KeyLike;
let publicJwk: any;

const TEST_REGION = 'us-west-2';
const TEST_POOL_ID = 'us-west-2_TestPool';
const TEST_CLIENT_ID = 'test-client-id-123';
const TEST_ISSUER = `https://cognito-idp.${TEST_REGION}.amazonaws.com/${TEST_POOL_ID}`;

const config: JwtConfig = {
  region: TEST_REGION,
  userPoolId: TEST_POOL_ID,
  clientId: TEST_CLIENT_ID,
};

beforeAll(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = await exportJWK(kp.publicKey);
  jwk.kid = 'test-key-1';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  publicJwk = jwk;
});

beforeEach(() => {
  resetJwksCache();
  // Inject local public key so verifyToken skips JWKS HTTP fetch.
  setJwksForTesting({ keys: [publicJwk] });
});

/** Helper: build a signed Cognito-style token. */
async function buildToken(claims: Record<string, unknown>, opts?: { expiresIn?: string }) {
  let builder = new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
    .setIssuer(claims.iss as string ?? TEST_ISSUER)
    .setSubject(claims.sub as string ?? 'user-123')
    .setIssuedAt();

  if (opts?.expiresIn) {
    builder = builder.setExpirationTime(opts.expiresIn);
  } else {
    builder = builder.setExpirationTime('1h');
  }

  return builder.sign(privateKey);
}

/* ------------------------------------------------------------------ */
/*  Valid tokens                                                       */
/* ------------------------------------------------------------------ */

describe('valid tokens', () => {
  it('accepts a valid Cognito access token', async () => {
    const token = await buildToken({
      sub: 'user-abc',
      token_use: 'access',
      client_id: TEST_CLIENT_ID,
      scope: 'openid profile',
      'custom:orgId': 'org-1',
      'custom:role': 'TENANT',
    });

    const result = await verifyToken(token, config);
    expect(result.sub).toBe('user-abc');
    expect(result.token_use).toBe('access');
    expect(result.client_id).toBe(TEST_CLIENT_ID);
    expect(result['custom:orgId']).toBe('org-1');
  });

  it('accepts a valid Cognito ID token', async () => {
    const token = await buildToken({
      sub: 'user-xyz',
      token_use: 'id',
      aud: TEST_CLIENT_ID,
      email: 'user@example.com',
      'custom:orgId': 'org-2',
      'custom:role': 'OWNER',
    });

    const result = await verifyToken(token, config);
    expect(result.sub).toBe('user-xyz');
    expect(result.token_use).toBe('id');
    expect(result.email).toBe('user@example.com');
  });
});

/* ------------------------------------------------------------------ */
/*  Issuer validation                                                  */
/* ------------------------------------------------------------------ */

describe('issuer validation', () => {
  it('rejects a token with the wrong issuer', async () => {
    const token = await buildToken({
      iss: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_WrongPool',
      token_use: 'access',
      client_id: TEST_CLIENT_ID,
    });

    await expect(verifyToken(token, config)).rejects.toThrow();
  });
});

/* ------------------------------------------------------------------ */
/*  client_id / aud validation                                         */
/* ------------------------------------------------------------------ */

describe('client_id validation (access tokens)', () => {
  it('rejects access token with wrong client_id', async () => {
    const token = await buildToken({
      token_use: 'access',
      client_id: 'wrong-client-id',
    });

    await expect(verifyToken(token, config)).rejects.toThrow('client_id mismatch');
  });

  it('rejects access token with missing client_id', async () => {
    const token = await buildToken({
      token_use: 'access',
      // no client_id
    });

    await expect(verifyToken(token, config)).rejects.toThrow('client_id mismatch');
  });
});

describe('aud validation (ID tokens)', () => {
  it('rejects ID token with wrong aud', async () => {
    const token = await buildToken({
      token_use: 'id',
      aud: 'wrong-audience',
    });

    await expect(verifyToken(token, config)).rejects.toThrow('aud mismatch');
  });
});

/* ------------------------------------------------------------------ */
/*  token_use validation                                               */
/* ------------------------------------------------------------------ */

describe('token_use validation', () => {
  it('rejects token with wrong token_use', async () => {
    const token = await buildToken({
      token_use: 'refresh',
      client_id: TEST_CLIENT_ID,
    });

    await expect(verifyToken(token, config)).rejects.toThrow('Unexpected token_use');
  });

  it('rejects token with missing token_use', async () => {
    const token = await buildToken({
      // no token_use
      client_id: TEST_CLIENT_ID,
    });

    await expect(verifyToken(token, config)).rejects.toThrow('Unexpected token_use');
  });
});

/* ------------------------------------------------------------------ */
/*  Expiry                                                             */
/* ------------------------------------------------------------------ */

describe('expiry', () => {
  it('rejects an expired token', async () => {
    // Create a token that expired 2 minutes ago.
    // SignJWT.setExpirationTime accepts a relative time like "2m" from iat,
    // so we set iat in the past.
    const iat = Math.floor(Date.now() / 1000) - 300; // 5 min ago
    const exp = iat + 60; // expired 4 min ago

    const token = await new SignJWT({
      sub: 'user-expired',
      token_use: 'access',
      client_id: TEST_CLIENT_ID,
      iat,
      exp,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(TEST_ISSUER)
      .sign(privateKey);

    await expect(verifyToken(token, config)).rejects.toThrow();
  });
});

/* ------------------------------------------------------------------ */
/*  Missing config                                                     */
/* ------------------------------------------------------------------ */

describe('missing config', () => {
  it('throws when userPoolId is missing', async () => {
    await expect(
      verifyToken('any-token', { ...config, userPoolId: '' }),
    ).rejects.toThrow('Cognito configuration is missing');
  });

  it('throws when clientId is missing', async () => {
    await expect(
      verifyToken('any-token', { ...config, clientId: '' }),
    ).rejects.toThrow('Cognito configuration is missing');
  });
});
