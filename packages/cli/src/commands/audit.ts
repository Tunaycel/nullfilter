import {
  encryptTelemetryNode,
  generateHmacSecret,
  generateRsaKeyPair,
  TelemetryPayload,
} from '@nullfilter/core';
import { inspectCanarySessionCookie, OriginLockShield } from '@nullfilter/server';

export interface SimulationStepOutcome {
  name: string;
  passed: boolean;
  expectedStatus: string;
  actualStatus: string;
  details: string;
}

/**
 * Programmatically executes the 4-stage cryptographic verification & AiTM simulation suite:
 *   Test 1: Legitimate origin (https://quellcloud.com -> https://quellcloud.com) => ALLOW
 *   Test 2: Evilginx AiTM origin (https://quellcl0ud.com -> https://quellcloud.com) => BLOCK_AITM_ORIGIN_MISMATCH + Honeypot Cookie
 *   Test 3: Replay attack (reusing the same encrypted token twice) => BLOCK_INVALID_NONCE
 *   Test 4: Tampered ciphertext (corrupting bytes in transit) => BLOCK_TAMPERED_CIPHERTEXT
 */
export async function runSimulateSuite(silentBanner = false): Promise<{
  allPassed: boolean;
  outcomes: SimulationStepOutcome[];
}> {
  const { publicKeyPem, privateKeyPem } = generateRsaKeyPair();
  const hmacSecret = generateHmacSecret(32);

  const shield = new OriginLockShield({
    publicKeyPem,
    privateKeyPem,
    hmacSecret,
    allowedHostnames: ['quellcloud.com'],
    allowedOrigins: ['https://quellcloud.com'],
    maxTokenAgeMs: 25_000,
    maxAllowedRttMs: 1_500,
    enableHoneypotPoisoning: true,
  });

  const outcomes: SimulationStepOutcome[] = [];

  // Test 1: Legitimate Origin
  const challenge1 = shield.issueChallenge('198.51.100.10');
  const legitimatePayload: TelemetryPayload = {
    hostname: 'quellcloud.com',
    origin: 'https://quellcloud.com',
    port: '443',
    pathname: '/login',
    referrer: 'https://quellcloud.com/',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0',
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 42,
    clientTimestamp: Date.now(),
    nonce: challenge1.nonce,
  };

  const validToken = encryptTelemetryNode(legitimatePayload, publicKeyPem);
  const res1 = await shield.verifyRequest({
    token: validToken,
    clientIp: '198.51.100.10',
    userAgent: legitimatePayload.userAgent,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 1: Legitimate Origin (quellcloud.com -> quellcloud.com)',
    passed: res1.allowed === true && res1.status === 'ALLOW',
    expectedStatus: 'ALLOW',
    actualStatus: res1.status,
    details: res1.reason,
  });

  // Test 2: Evilginx AiTM Origin (quellcl0ud.com -> quellcloud.com)
  const challenge2 = shield.issueChallenge('203.0.113.88');
  const aitmPayload: TelemetryPayload = {
    hostname: 'quellcl0ud.com',
    origin: 'https://quellcl0ud.com',
    port: '443',
    pathname: '/login',
    referrer: 'https://quellcl0ud.com/',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0',
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 185,
    clientTimestamp: Date.now(),
    nonce: challenge2.nonce,
  };

  const aitmToken = encryptTelemetryNode(aitmPayload, publicKeyPem);
  const res2 = await shield.verifyRequest({
    token: aitmToken,
    clientIp: '203.0.113.88',
    userAgent: aitmPayload.userAgent,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  const poisonedCookie = res2.threatDetails?.poisonedCookieHeader ?? '';
  const verifiedCanary = inspectCanarySessionCookie(poisonedCookie, hmacSecret);
  const test2Passed =
    res2.allowed === false &&
    res2.status === 'BLOCK_AITM_ORIGIN_MISMATCH' &&
    Boolean(verifiedCanary && verifiedCanary.captured_on === 'https://quellcl0ud.com');

  outcomes.push({
    name: 'Test 2: Evilginx AiTM Origin (quellcl0ud.com -> quellcloud.com)',
    passed: test2Passed,
    expectedStatus: 'BLOCK_AITM_ORIGIN_MISMATCH (+ Honeypot Canary)',
    actualStatus: `${res2.status}${
      verifiedCanary ? ` (Canary: ${verifiedCanary.canary_id})` : ''
    }`,
    details: res2.reason,
  });

  // Test 3: Replay Attack (Reusing validToken from Test 1)
  const res3 = await shield.verifyRequest({
    token: validToken,
    clientIp: '198.51.100.10',
    userAgent: legitimatePayload.userAgent,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 3: Replay Attack (Reusing consumed token twice)',
    passed: res3.allowed === false && res3.status === 'BLOCK_INVALID_NONCE',
    expectedStatus: 'BLOCK_INVALID_NONCE',
    actualStatus: res3.status,
    details: res3.reason,
  });

  // Test 4: Tampered Ciphertext (Flipping bytes in the encrypted envelope)
  const rawBuf = Buffer.from(validToken, 'base64');
  rawBuf[128] ^= 0xff;
  rawBuf[rawBuf.length - 4] ^= 0xaa;
  const tamperedToken = rawBuf.toString('base64');

  const res4 = await shield.verifyRequest({
    token: tamperedToken,
    clientIp: '198.51.100.10',
    userAgent: legitimatePayload.userAgent,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 4: Tampered Ciphertext (Bit-flip attack on RSA-OAEP/GCM)',
    passed: res4.allowed === false && res4.status === 'BLOCK_TAMPERED_CIPHERTEXT',
    expectedStatus: 'BLOCK_TAMPERED_CIPHERTEXT',
    actualStatus: res4.status,
    details: res4.reason,
  });

  const allPassed = outcomes.every((o) => o.passed);

  if (!silentBanner) {
    const green = '\x1b[32m';
    const red = '\x1b[31m';
    const cyan = '\x1b[36m';
    const bold = '\x1b[1m';
    const reset = '\x1b[0m';

    console.log(
      `\n${bold}${cyan}┌──────────────────────────────────────────────────────────────────────────────┐${reset}`
    );
    console.log(
      `${bold}${cyan}│  NULLFILTER / ORIGINLOCK CRYPTOGRAPHIC SELF-TEST & AiTM SIMULATION SUITE     │${reset}`
    );
    console.log(
      `${bold}${cyan}└──────────────────────────────────────────────────────────────────────────────┘${reset}`
    );

    for (const item of outcomes) {
      const badge = item.passed ? `${green}[PASS]${reset}` : `${red}[FAIL]${reset}`;
      console.log(`  ${badge} ${bold}${item.name}${reset}`);
      console.log(`         Verdict : ${cyan}${item.actualStatus}${reset}`);
      console.log(`         Reason  : ${item.details}`);
    }

    console.log(
      `\n  ${bold}Overall Suite Result:${reset} ${
        allPassed
          ? `${green}ALL 4 CRYPTOGRAPHIC & AiTM DEFENSES VERIFIED (100%)${reset}`
          : `${red}FAILURE DETECTED${reset}`
      }\n`
    );
  }

  return { allPassed, outcomes };
}

/**
 * Audits a live HTTP/HTTPS endpoint for OriginLock/NullFilter polymorphic probe presence
 * and anti-AiTM security posture.
 */
export async function runEndpointAudit(targetUrl: string): Promise<void> {
  const cyan = '\x1b[36m';
  const green = '\x1b[32m';
  const yellow = '\x1b[33m';
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';

  console.log(`\n${bold}${cyan}[AUDIT] Probing endpoint:${reset} ${targetUrl}`);
  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'NullFilter-Security-Auditor/1.0',
      },
    });

    const html = await response.text();
    const hasOriginLockProbe =
      html.includes('__OriginLock') ||
      html.includes('__NullFilter') ||
      html.includes('data-originlock="true"');
    const cspHeader = response.headers.get('content-security-policy') ?? 'none';

    console.log(`  HTTP Status            : ${response.status}`);
    console.log(
      `  Polymorphic DOM Probe  : ${
        hasOriginLockProbe ? `${green}DETECTED${reset}` : `${yellow}NOT DETECTED${reset}`
      }`
    );
    console.log(`  Content-Security-Policy: ${cspHeader}\n`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Audit connection error: ${msg}\n`);
  }
}
