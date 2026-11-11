import * as crypto from 'node:crypto';

export interface CanaryTokenPayload {
  sub: string;
  iss: string;
  honeypot: true;
  captured_on: string;
  canary_id: string;
  iat: number;
  exp: number;
}

export interface PoisonedSessionArtifact {
  canaryId: string;
  jwtToken: string;
  setCookieHeader: string;
  payload: CanaryTokenPayload;
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecodeToString(input: string): string {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLength), 'base64').toString('utf8');
}

/**
 * Generates a deceptive, structurally valid HMAC-SHA256 JWT and `Set-Cookie` header
 * embedded with canary tracking telemetry (`canary_id`, `captured_on`, `honeypot: true`)
 * to poison an adversary's Evilginx/Modlishka session database.
 */
export function generatePoisonedSession(
  fakeDomain: string,
  targetUsername = 'anonymous',
  signingSecret = 'nullfilter-default-canary-secret'
): PoisonedSessionArtifact {
  const canaryId = `cnry_${crypto.randomBytes(8).toString('hex')}`;
  const nowSec = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'HS256',
    typ: 'JWT',
    kid: 'vault-canary-v1',
  };

  const payload: CanaryTokenPayload = {
    sub: targetUsername,
    iss: 'quellcloud-enterprise-vault',
    honeypot: true,
    captured_on: fakeDomain,
    canary_id: canaryId,
    iat: nowSec,
    exp: nowSec + 86_400,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', signingSecret)
    .update(signingInput)
    .digest();

  const encodedSignature = base64UrlEncode(signature);
  const jwtToken = `${signingInput}.${encodedSignature}`;
  const setCookieHeader = `vault_session=${jwtToken}; Path=/; HttpOnly; SameSite=Lax`;

  return {
    canaryId,
    jwtToken,
    setCookieHeader,
    payload,
  };
}

/**
 * Inspects an incoming `Cookie` header or raw JWT string to determine if the caller
 * is replaying a poisoned honeypot canary session captured by an AiTM proxy.
 */
export function inspectCanarySessionCookie(
  cookieHeaderOrJwt?: string,
  signingSecret = 'nullfilter-default-canary-secret'
): CanaryTokenPayload | null {
  if (!cookieHeaderOrJwt) {
    return null;
  }

  let rawJwt = cookieHeaderOrJwt.trim();
  const match = cookieHeaderOrJwt.match(/(?:^|;\s*)vault_session=([^;]+)/);
  if (match && match[1]) {
    rawJwt = match[1].trim();
  }

  const parts = rawJwt.split('.');
  if (parts.length !== 3) {
    return null;
  }

  const [encodedHeader, encodedPayload, encodedSig] = parts;
  const expectedSig = base64UrlEncode(
    crypto
      .createHmac('sha256', signingSecret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest()
  );

  const sigBufA = Buffer.from(encodedSig, 'utf8');
  const sigBufB = Buffer.from(expectedSig, 'utf8');
  if (sigBufA.length !== sigBufB.length || !crypto.timingSafeEqual(sigBufA, sigBufB)) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecodeToString(encodedPayload)) as Partial<CanaryTokenPayload>;
    if (parsed && parsed.honeypot === true && typeof parsed.canary_id === 'string') {
      return parsed as CanaryTokenPayload;
    }
    return null;
  } catch {
    return null;
  }
}
