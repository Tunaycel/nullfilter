import { runSimulateSuite } from '@nullfilter/cli';
import { encryptTelemetryNode, TelemetryPayload } from '@nullfilter/core';
import { startBankServer } from './bank-server';
import { startEvilProxyServer } from './evil-proxy';

async function runLiveHttpSmokeTest(
  bankPort: number,
  proxyPort: number,
  publicKeyPem: string,
  issueNonce: () => string
): Promise<void> {
  const cyan = '\x1b[36m';
  const green = '\x1b[32m';
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';

  console.log(`${bold}${cyan}[LIVE TCP/HTTP E2E CHECK] Testing live servers on :${bankPort} and :${proxyPort}...${reset}`);

  // 1. Direct Legitimate Login against :3000
  const legitPayload: TelemetryPayload = {
    hostname: 'localhost',
    origin: `http://localhost:${bankPort}`,
    port: String(bankPort),
    pathname: '/',
    referrer: `http://localhost:${bankPort}/`,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0',
    webdriver: false,
    canvasHash: 'a4b8019ef23019ca',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 12,
    clientTimestamp: Date.now(),
    nonce: issueNonce(),
  };

  const legitToken = encryptTelemetryNode(legitPayload, publicKeyPem);
  const directRes = await fetch(`http://127.0.0.1:${bankPort}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'x-originlock-token': legitToken,
    },
    body: new URLSearchParams({
      username: 'h.tunay@quellcloud.com',
      password: 'QCloud#ZeroTrust!2026',
      totp_code: '492817',
      _originlock_token: legitToken,
    }).toString(),
  });

  const directJson = (await directRes.json()) as { status: string };
  if (directJson.status !== 'SUCCESS') {
    throw new Error(`Expected SUCCESS on direct :${bankPort} login, got ${directJson.status}`);
  }
  console.log(`  ${green}[PASS]${reset} Direct HTTP POST to http://localhost:${bankPort}/api/login -> ${directJson.status}`);

  // 2. Relayed AiTM Login through Evilginx Proxy (:8080 -> :3000)
  const proxyPayload: TelemetryPayload = {
    hostname: 'localhost',
    origin: `http://localhost:${proxyPort}`,
    port: String(proxyPort),
    pathname: '/',
    referrer: `http://localhost:${proxyPort}/`,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0',
    webdriver: false,
    canvasHash: 'a4b8019ef23019ca',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 64,
    clientTimestamp: Date.now(),
    nonce: issueNonce(),
  };

  const proxyToken = encryptTelemetryNode(proxyPayload, publicKeyPem);
  const relayedRes = await fetch(`http://127.0.0.1:${proxyPort}/api/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'x-originlock-token': proxyToken,
    },
    body: new URLSearchParams({
      username: 'h.tunay@quellcloud.com',
      password: 'QCloud#ZeroTrust!2026',
      totp_code: '492817',
      _originlock_token: proxyToken,
    }).toString(),
  });

  const relayedJson = (await relayedRes.json()) as {
    status: string;
    verdict?: { status: string };
  };
  if (
    relayedJson.status !== 'HONEYPOT_TRAPPED' ||
    relayedJson.verdict?.status !== 'BLOCK_AITM_ORIGIN_MISMATCH'
  ) {
    throw new Error(
      `Expected HONEYPOT_TRAPPED on proxied :${proxyPort} login, got ${JSON.stringify(relayedJson)}`
    );
  }
  console.log(
    `  ${green}[PASS]${reset} Proxied HTTP POST via http://localhost:${proxyPort}/api/login -> ${relayedJson.status} (${relayedJson.verdict.status})\n`
  );
}

async function main(): Promise<void> {
  const isSelfTestOnly = process.argv.includes('--self-test');

  // Step 1: Run the 4-stage cryptographic & AiTM self-test suite
  const suiteResult = await runSimulateSuite(false);
  if (!suiteResult.allPassed) {
    console.error('Cryptographic self-test failed; aborting demo startup.');
    process.exit(1);
  }

  // Step 2: Launch Protected Bank Server (:3000) & Simulated Evilginx Proxy (:8080)
  const bankPort = Number(process.env.BANK_PORT ?? 3000);
  const proxyPort = Number(process.env.PROXY_PORT ?? 8080);

  const bank = await startBankServer(bankPort);
  const proxy = await startEvilProxyServer(proxyPort, bankPort);

  const green = '\x1b[32m';
  const red = '\x1b[31m';
  const cyan = '\x1b[36m';
  const yellow = '\x1b[33m';
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';

  console.log(
    [
      `${bold}${green}╔══════════════════════════════════════════════════════════════════════════════╗${reset}`,
      `${bold}${green}║  NULLFILTER / ORIGINLOCK INTERACTIVE PLAYGROUND & LIVE SOC CONSOLE ONLINE   ║${reset}`,
      `${bold}${green}╠══════════════════════════════════════════════════════════════════════════════╣${reset}`,
      `${green}║${reset}  ${bold}1. Legitimate Protected Target ("QuellCloud Vault"):${reset}                        ${green}║${reset}`,
      `${green}║${reset}     👉 ${cyan}http://localhost:${bankPort}${reset}                                                 ${green}║${reset}`,
      `${green}║${reset}        (Authenticates cleanly; WebCrypto origin matches allowedOrigins)      ${green}║${reset}`,
      `${green}║${reset}                                                                              ${green}║${reset}`,
      `${green}║${reset}  ${bold}2. Simulated Evilginx AiTM Phishing Proxy:${reset}                                  ${green}║${reset}`,
      `${green}║${reset}     👉 ${red}http://localhost:${proxyPort}${reset}                                                 ${green}║${reset}`,
      `${green}║${reset}        (Spoofs HTTP Host/Origin headers to :${bankPort}, rewrites body via          ${green}║${reset}`,
      `${green}║${reset}         sub_filter, intercepts credentials, and gets trapped by OriginLock's ${green}║${reset}`,
      `${green}║${reset}         RSA-OAEP DOM attestation + Canary Honeypot Cookie!)                  ${green}║${reset}`,
      `${green}║${reset}                                                                              ${green}║${reset}`,
      `${green}║${reset}  ${yellow}Tip:${reset} Open both URLs in your browser and watch the Right-Pane Live SOC       ${green}║${reset}`,
      `${green}║${reset}       Console update in real time via Server-Sent Events (SSE).              ${green}║${reset}`,
      `${bold}${green}╚══════════════════════════════════════════════════════════════════════════════╝${reset}`,
      '',
    ].join('\n')
  );

  if (isSelfTestOnly) {
    await runLiveHttpSmokeTest(bankPort, proxyPort, bank.publicKeyPem, () => {
      return bank.shield.issueChallenge('127.0.0.1').nonce;
    });
    await proxy.Close();
    await bank.Close();
    return;
  }

  const shutdown = async () => {
    console.log('\nShutting down Playground servers...');
    await proxy.Close();
    await bank.Close();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
}

void main();
