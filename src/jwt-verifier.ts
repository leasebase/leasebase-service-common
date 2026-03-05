import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { logger } from './logger';

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

export interface JwtConfig {
  region: string;
  userPoolId: string;
  clientId: string;
}

export interface VerifiedToken extends JWTPayload {
  sub: string;
  email?: string;
  'custom:orgId'?: string;
  'custom:role'?: string;
  scope?: string;
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

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: cfg.clientId,
    clockTolerance: 30,
  });

  return payload as VerifiedToken;
}

/** Reset the cached JWKS (useful for testing). */
export function resetJwksCache(): void {
  jwks = null;
}
