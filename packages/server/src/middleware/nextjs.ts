import { VerificationResult } from '@nullfilter/core';
import { OriginLockShield } from '../shield';

export interface NextJsGuardResult {
  verification: VerificationResult;
  response?: Response;
  blockedResponse?: Response;
}

export interface NextJsVerifyOptions {
  shield?: OriginLockShield;
  deceptiveHoneypotResponse?: boolean;
}

/**
 * Next.js App Router / Edge Middleware adapter using the standard Web Fetch `Request` and `Response` APIs.
 * Supports both `verifyNextJsRequest(shield, req, options)` and `verifyNextJsRequest(req, { shield, ...options })`.
 */
export async function verifyNextJsRequest(
  shieldOrReq: OriginLockShield | Request,
  reqOrOptions: Request | (NextJsVerifyOptions & { shield: OriginLockShield }),
  maybeOptions: NextJsVerifyOptions = {}
): Promise<NextJsGuardResult> {
  const isFirstArgShield = shieldOrReq instanceof OriginLockShield;
  const shield = isFirstArgShield
    ? shieldOrReq
    : (reqOrOptions as NextJsVerifyOptions & { shield: OriginLockShield }).shield;
  const req = isFirstArgShield ? (reqOrOptions as Request) : (shieldOrReq as Request);
  const options = isFirstArgShield ? maybeOptions : (reqOrOptions as NextJsVerifyOptions);

  const deceptiveHoneypot = options.deceptiveHoneypotResponse ?? true;

  let token =
    req.headers.get('x-originlock-token') ??
    req.headers.get('x-nullfilter-token') ??
    undefined;

  let username: string | undefined;

  if (!token && req.method === 'POST') {
    const contentType = req.headers.get('content-type') ?? '';
    try {
      const cloned = req.clone();
      if (contentType.includes('application/json')) {
        const body = (await cloned.json()) as Record<string, unknown>;
        if (typeof body._originlock_token === 'string') {
          token = body._originlock_token;
        }
        if (typeof body.username === 'string') {
          username = body.username;
        }
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await cloned.text();
        const params = new URLSearchParams(text);
        token = params.get('_originlock_token') ?? undefined;
        username = params.get('username') ?? undefined;
      }
    } catch {
      // Ignore body parse errors and proceed with header check
    }
  }

  const forwardedFor = req.headers.get('x-forwarded-for') ?? undefined;
  const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : '127.0.0.1';
  const userAgent = req.headers.get('user-agent') ?? 'unknown';

  const verification = await shield.verifyRequest({
    token,
    clientIp,
    userAgent,
    forwardedFor,
    username,
  });

  if (verification.allowed) {
    return { verification };
  }

  if (
    verification.status === 'BLOCK_AITM_ORIGIN_MISMATCH' &&
    deceptiveHoneypot &&
    verification.threatDetails?.poisonedCookieHeader
  ) {
    const response = new Response(
      JSON.stringify({
        status: 'SUCCESS',
        authenticated: true,
        message: 'Authenticated.',
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': verification.threatDetails.poisonedCookieHeader,
        },
      }
    );
    return { verification, response, blockedResponse: response };
  }

  const response = new Response(
    JSON.stringify({
      error: 'ORIGINLOCK_ATTESTATION_FAILED',
      status: verification.status,
      reason: verification.reason,
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );

  return { verification, response, blockedResponse: response };
}
