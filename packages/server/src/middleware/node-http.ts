import * as http from 'node:http';
import { VerificationResult } from '@nullfilter/core';
import { OriginLockShield } from '../shield';

export interface NodeHttpVerifyOptions {
  parsedBody?: Record<string, unknown>;
  tokenOverride?: string;
  usernameField?: string;
}

/**
 * Extracts client IP, User-Agent, and the attestation token from a native Node.js
 * `http.IncomingMessage` (checking headers `x-originlock-token`, `x-nullfilter-token`,
 * and parsed form/JSON body field `_originlock_token`) and runs `OriginLockShield.verifyRequest`.
 */
export async function verifyNodeHttpRequest(
  shield: OriginLockShield,
  req: http.IncomingMessage,
  options: NodeHttpVerifyOptions = {}
): Promise<VerificationResult> {
  const headerToken =
    (req.headers['x-originlock-token'] as string | undefined) ??
    (req.headers['x-nullfilter-token'] as string | undefined);

  const bodyToken =
    typeof options.parsedBody?._originlock_token === 'string'
      ? options.parsedBody._originlock_token
      : typeof options.parsedBody?._nullfilter_token === 'string'
      ? options.parsedBody._nullfilter_token
      : undefined;

  const token = options.tokenOverride ?? headerToken ?? bodyToken;

  const forwardedHeader = req.headers['x-forwarded-for'];
  const forwardedFor = Array.isArray(forwardedHeader)
    ? forwardedHeader.join(', ')
    : forwardedHeader;

  const clientIp =
    (forwardedFor ? forwardedFor.split(',')[0].trim() : undefined) ||
    req.socket?.remoteAddress ||
    '127.0.0.1';

  const userAgent = (req.headers['user-agent'] as string | undefined) ?? 'unknown';

  const usernameKey = options.usernameField ?? 'username';
  const username =
    typeof options.parsedBody?.[usernameKey] === 'string'
      ? (options.parsedBody[usernameKey] as string)
      : undefined;

  return shield.verifyRequest({
    token,
    clientIp,
    userAgent,
    forwardedFor,
    username,
  });
}
