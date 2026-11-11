import { VerificationResult } from '@nullfilter/core';
import { OriginLockShield } from '../shield';

export interface ExpressLikeRequest {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: Record<string, unknown>;
  ip?: string;
  socket?: { remoteAddress?: string };
  originLockVerification?: VerificationResult;
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  setHeader(name: string, value: string): void;
  json(payload: unknown): void;
}

export type ExpressNextFunction = (err?: unknown) => void;

export interface ExpressMiddlewareOptions {
  protectedMethods?: string[];
  deceptiveHoneypotResponse?: boolean;
}

/**
 * Express.js middleware adapter for `OriginLockShield`.
 * Automatically verifies incoming state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`)
 * and either blocks or returns a deceptive HTTP 200 honeypot response on AiTM detection.
 */
export function createExpressMiddleware(
  shield: OriginLockShield,
  options: ExpressMiddlewareOptions = {}
) {
  const protectedMethods = new Set(
    (options.protectedMethods ?? ['POST', 'PUT', 'PATCH', 'DELETE']).map((m) =>
      m.toUpperCase()
    )
  );
  const deceptiveHoneypot = options.deceptiveHoneypotResponse ?? true;

  return async (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressNextFunction
  ): Promise<void> => {
    const method = (req.method ?? 'GET').toUpperCase();
    if (!protectedMethods.has(method)) {
      next();
      return;
    }

    const rawHeader =
      req.headers['x-originlock-token'] ?? req.headers['x-nullfilter-token'];
    const headerToken = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
    const bodyToken =
      typeof req.body?._originlock_token === 'string'
        ? req.body._originlock_token
        : undefined;

    const forwardedRaw = req.headers['x-forwarded-for'];
    const forwardedFor = Array.isArray(forwardedRaw)
      ? forwardedRaw.join(', ')
      : forwardedRaw;

    const clientIp =
      req.ip ||
      (forwardedFor ? forwardedFor.split(',')[0].trim() : undefined) ||
      req.socket?.remoteAddress ||
      '127.0.0.1';

    const uaRaw = req.headers['user-agent'];
    const userAgent = (Array.isArray(uaRaw) ? uaRaw[0] : uaRaw) ?? 'unknown';
    const username =
      typeof req.body?.username === 'string' ? req.body.username : undefined;

    const result = await shield.verifyRequest({
      token: headerToken ?? bodyToken,
      clientIp,
      userAgent,
      forwardedFor,
      username,
    });

    req.originLockVerification = result;

    if (result.allowed) {
      next();
      return;
    }

    if (
      result.status === 'BLOCK_AITM_ORIGIN_MISMATCH' &&
      deceptiveHoneypot &&
      result.threatDetails?.poisonedCookieHeader
    ) {
      res.setHeader('Set-Cookie', result.threatDetails.poisonedCookieHeader);
      res.status(200).json({
        status: 'SUCCESS',
        authenticated: true,
        sessionMode: 'HONEYPOT_DECEPTION',
        message: 'Session established.',
      });
      return;
    }

    res.status(403).json({
      error: 'ORIGINLOCK_ATTESTATION_FAILED',
      status: result.status,
      reason: result.reason,
    });
  };
}
