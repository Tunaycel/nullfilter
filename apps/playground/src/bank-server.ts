import * as crypto from 'node:crypto';
import * as http from 'node:http';
import {
  generateHmacSecret,
  generateRsaKeyPair,
  VerificationResult,
} from '@nullfilter/core';
import { OriginLockShield } from '@nullfilter/server';
import { renderVaultUi } from './ui-template';

function extractClientIp(req: http.IncomingMessage): string {
  const forwardedHeader = req.headers['x-forwarded-for'];
  const forwardedFor = Array.isArray(forwardedHeader)
    ? forwardedHeader.join(', ')
    : forwardedHeader;

  return (
    (forwardedFor ? forwardedFor.split(',')[0].trim() : undefined) ||
    req.socket?.remoteAddress ||
    '127.0.0.1'
  );
}

export interface BankServerInstance {
  server: http.Server;
  shield: OriginLockShield;
  port: number;
  publicKeyPem: string;
  Close: () => Promise<void>;
}

export interface SocBroadcastEvent {
  type: 'VERIFICATION_VERDICT' | 'POLYMORPHIC_ROTATION';
  timestamp: string;
  username?: string;
  observedHttpHost?: string;
  observedHttpOrigin?: string;
  nonce?: string;
  verdict?: VerificationResult;
}

function readRequestBody(req: http.IncomingMessage, maxBytes = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('Request body exceeded maximum allowed byte size.'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    req.on('error', (err) => {
      reject(err);
    });
  });
}

function parseFormOrJsonBody(
  rawBody: string,
  contentType: string
): Record<string, string> {
  const result: Record<string, string> = {};
  if (!rawBody) {
    return result;
  }

  if (contentType.includes('application/json')) {
    try {
      const parsed = JSON.parse(rawBody) as Record<string, unknown>;
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string') {
          result[k] = v;
        }
      }
    } catch {
      // Ignore malformed JSON
    }
    return result;
  }

  const params = new URLSearchParams(rawBody);
  for (const [key, value] of params.entries()) {
    result[key] = value;
  }
  return result;
}

/**
 * Launches the Protected Target Application ("QuellCloud Enterprise Vault") on `http://localhost:3000`.
 */
export function startBankServer(port = 3000): Promise<BankServerInstance> {
  const { publicKeyPem, privateKeyPem } = generateRsaKeyPair();
  const hmacSecret = generateHmacSecret(32);

  const sseClients = new Set<http.ServerResponse>();
  const recentEventsBuffer: SocBroadcastEvent[] = [];

  function broadcastSocEvent(event: SocBroadcastEvent): void {
    recentEventsBuffer.push(event);
    if (recentEventsBuffer.length > 25) {
      recentEventsBuffer.shift();
    }

    const serialized = `data: ${JSON.stringify(event)}\n\n`;
    for (const clientRes of sseClients) {
      try {
        clientRes.write(serialized);
      } catch {
        sseClients.delete(clientRes);
      }
    }
  }

  const shield = new OriginLockShield({
    publicKeyPem,
    privateKeyPem,
    hmacSecret,
    allowedHostnames: ['localhost'],
    allowedOrigins: [`http://localhost:${port}`],
    maxTokenAgeMs: 60_000,
    maxAllowedRttMs: 1_500,
    enableHoneypotPoisoning: true,
  });

  const server = http.createServer(async (req, res) => {
    const method = (req.method ?? 'GET').toUpperCase();
    const urlObj = new URL(req.url ?? '/', `http://localhost:${port}`);
    const pathname = urlObj.pathname;

    // CORS headers for cross-port SSE telemetry and diagnostic pings
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, HEAD, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, x-originlock-token, x-nullfilter-token'
    );

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 1. Lightweight RTT Ping Endpoint
    if (pathname === '/api/ping' && (method === 'HEAD' || method === 'GET')) {
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      });
      res.end('pong');
      return;
    }

    // 2. Server-Sent Events (SSE) Live SOC Telemetry Stream
    if (pathname === '/api/events' && method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      });

      res.write(': connected to NullFilter / OriginLock SOC stream\n\n');
      for (const pastEvent of recentEventsBuffer) {
        res.write(`data: ${JSON.stringify(pastEvent)}\n\n`);
      }

      sseClients.add(res);
      req.on('close', () => {
        sseClients.delete(res);
      });
      return;
    }

    // 3. Main Protected Login Portal UI
    if (pathname === '/' && method === 'GET') {
      const clientIp = extractClientIp(req);
      const challenge = shield.issueChallenge(clientIp, '/api/ping');

      broadcastSocEvent({
        type: 'POLYMORPHIC_ROTATION',
        timestamp: new Date().toISOString(),
        nonce: challenge.nonce,
      });

      const html = renderVaultUi({
        nonce: challenge.nonce,
        polymorphicScript: challenge.script,
      });

      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(html);
      return;
    }

    // 4. Protected Authentication Endpoint
    if (pathname === '/api/login' && method === 'POST') {
      try {
        const rawBody = await readRequestBody(req);
        const contentType = String(req.headers['content-type'] ?? '');
        const parsedFields = parseFormOrJsonBody(rawBody, contentType);

        const headerToken =
          (req.headers['x-originlock-token'] as string | undefined) ??
          (req.headers['x-nullfilter-token'] as string | undefined);
        const token = headerToken || parsedFields['_originlock_token'];
        const username = parsedFields['username'] || 'h.tunay@quellcloud.com';

        const clientIp = extractClientIp(req);
        const userAgent = String(req.headers['user-agent'] ?? 'unknown');
        const observedHttpHost = String(req.headers['host'] ?? 'unknown');
        const observedHttpOrigin = String(req.headers['origin'] ?? 'none');
        const forwardedFor = req.headers['x-forwarded-for']
          ? String(req.headers['x-forwarded-for'])
          : undefined;

        const verdict = await shield.verifyRequest({
          token,
          clientIp,
          userAgent,
          forwardedFor,
          username,
        });

        broadcastSocEvent({
          type: 'VERIFICATION_VERDICT',
          timestamp: new Date().toISOString(),
          username,
          observedHttpHost,
          observedHttpOrigin,
          verdict,
        });

        const nextChallenge = shield.issueChallenge(clientIp, '/api/ping');

        if (verdict.allowed) {
          const realSessionToken = `REAL_AUTHENTICATED_SESSION_TOKEN_${crypto
            .randomBytes(12)
            .toString('hex')}`;

          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': `vault_session=${realSessionToken}; Path=/; HttpOnly; SameSite=Lax`,
          });
          res.end(
            JSON.stringify({
              status: 'SUCCESS',
              message: 'Authenticated to QuellCloud Vault',
              nextNonce: nextChallenge.nonce,
              verdict,
            })
          );
          return;
        }

        // Active Defense: If Honeypot Poisoning generated a Canary Cookie, feed HTTP 200 + Set-Cookie to trap the proxy
        const headers: Record<string, string> = {
          'Content-Type': 'application/json; charset=utf-8',
        };
        if (verdict.threatDetails?.poisonedCookieHeader) {
          headers['Set-Cookie'] = verdict.threatDetails.poisonedCookieHeader;
        }

        res.writeHead(200, headers);
        res.end(
          JSON.stringify({
            status: 'HONEYPOT_TRAPPED',
            message:
              'AiTM Reverse Proxy neutralized! HTTP Host/Origin headers were spoofed, but WebCrypto RSA-OAEP telemetry exposed the proxy origin. Canary session injected into proxy DB.',
            nextNonce: nextChallenge.nonce,
            verdict,
          })
        );
        return;
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Internal error';
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ status: 'ERROR', message: msg }));
        return;
      }
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      resolve({
        server,
        shield,
        port,
        publicKeyPem,
        Close: () =>
          new Promise<void>((resClose) => {
            for (const client of sseClients) {
              client.end();
            }
            sseClients.clear();
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close(() => resClose());
          }),
      });
    });
  });
}
