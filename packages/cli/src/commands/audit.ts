import * as assert from 'node:assert/strict';
import {
  encryptTelemetryNode,
  generateHmacSecret,
  generateRsaKeyPair,
  TelemetryPayload,
} from '@nullfilter/core';
import { inspectCanarySessionCookie, OriginLockShield } from '@nullfilter/server';

export interface SimulationStepOutcome {
  name: string;
  category?: 'DEFENSE' | 'ARCHITECTURAL_LIMIT_POC';
  passed: boolean;
  expectedStatus: string;
  actualStatus: string;
  details: string;
}

export interface WireForgeryResult {
  forgedToken: string;
  extractedNonce: string;
  reconstructedChallengeProof: string;
  reconstructedPublicKeyPem: string;
}

/**
 * Red-Team Standalone Forgery PoC:
 * Accepts ONLY the raw `<script>` string transmitted over the wire to an untrusted client.
 * Never accesses `hmacSecret`, `privateKeyPem`, or `IssuedChallenge.challengeProof`.
 *
 * Extracts the SPKI Public Key, single-use nonce, 8-byte XOR key, affine offset, and split
 * byte arrays (`pA`, `pB`) directly from the obfuscated wire script, reverses the affine+XOR
 * transformation to synthesize `challengeProof`, and encrypts a synthetic TelemetryPayload
 * claiming `spoofedOrigin` without ever executing a victim browser.
 */
export function forgeTokenFromWireScript(
  rawWireScript: string,
  spoofedOrigin = 'https://quellcloud.com',
  spoofedHostname = 'quellcloud.com',
  userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0'
): WireForgeryResult {
  const xorKeyMatch = rawWireScript.match(/var _k_[a-f0-9]+=\[([0-9,]+)\];/);
  const pkMatch = rawWireScript.match(/var _pk_[a-f0-9]+="([^"]+)";/);
  const nonceMatch = rawWireScript.match(/var _nc_[a-f0-9]+="([^"]+)";/);
  const pAMatch = rawWireScript.match(
    /var pA=\[([0-9,]+)\]\.map\(function\(v\)\{return v-(\d+);\}/
  );
  const pBMatch = rawWireScript.match(
    /var pB=\[([0-9,]+)\]\.map\(function\(v\)\{return v-(\d+);\}/
  );

  if (!xorKeyMatch || !pkMatch || !nonceMatch || !pAMatch || !pBMatch) {
    throw new Error('Failed to extract polymorphic parameters from wire script.');
  }

  const xorKey = xorKeyMatch[1].split(',').map((n) => Number(n));
  const spkiBase64 = pkMatch[1];
  const extractedNonce = nonceMatch[1];
  const encodedProofA = pAMatch[1].split(',').map((n) => Number(n));
  const affineOffset = Number(pAMatch[2]);
  const encodedProofB = pBMatch[1].split(',').map((n) => Number(n));

  const decodeHalf = (arr: number[]): string => {
    let out = '';
    for (let i = 0; i < arr.length; i++) {
      const unshifted = arr[i] - affineOffset;
      out += String.fromCharCode(unshifted ^ xorKey[i % xorKey.length]);
    }
    return out;
  };

  const reconstructedChallengeProof = decodeHalf(encodedProofA) + decodeHalf(encodedProofB);
  const reconstructedPublicKeyPem = `-----BEGIN PUBLIC KEY-----\n${spkiBase64}\n-----END PUBLIC KEY-----`;

  const forgedPayload: TelemetryPayload = {
    hostname: spoofedHostname,
    origin: spoofedOrigin,
    port: '443',
    pathname: '/login',
    referrer: `${spoofedOrigin}/`,
    userAgent,
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 31,
    clientTimestamp: Date.now(),
    nonce: extractedNonce,
    challengeProof: reconstructedChallengeProof,
  };

  const forgedToken = encryptTelemetryNode(forgedPayload, reconstructedPublicKeyPem);

  return {
    forgedToken,
    extractedNonce,
    reconstructedChallengeProof,
    reconstructedPublicKeyPem,
  };
}

/**
 * Programmatically executes the 8-stage cryptographic verification, AiTM simulation & Red-Team anti-bypass suite:
 *   Test 1: Legitimate origin (https://quellcloud.com -> https://quellcloud.com) => ALLOW
 *   Test 2: Evilginx AiTM origin (https://quellcl0ud.com -> https://quellcloud.com) => BLOCK_AITM_ORIGIN_MISMATCH + Honeypot Cookie
 *   Test 3: Replay attack (reusing the same encrypted token twice) => BLOCK_INVALID_NONCE
 *   Test 4: Tampered ciphertext (corrupting bytes in transit) => BLOCK_TAMPERED_CIPHERTEXT
 *   Test 5: Red-Team Bypass #1 — Proxy Server-Side Token-Oracle Forgery (missing/forged challengeProof) => BLOCK_FORGED_TOKEN_ORACLE
 *   Test 6: Red-Team Bypass #2 — Pre-Script DOM/WebCrypto Monkey-Patch (domIntegrityValid: false) => BLOCK_DOM_INTEGRITY_VIOLATION
 *   Test 7: Red-Team Bypass #3 — Headless Browser / Puppeteer Token Farm (SwiftShader / webdriver) => BLOCK_HEADLESS_AUTOMATION
 *   Test 8: Red-Team Bypass #4 — Cross-Browser Token Relay (encrypted UA != HTTP UA) => BLOCK_CONTEXT_BINDING_MISMATCH
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
    enforceChallengeProof: true,
    blockHeadlessAutomation: true,
    enforceUserAgentBinding: true,
  });

  const outcomes: SimulationStepOutcome[] = [];
  const standardBrowserUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0';

  // Test 1: Legitimate Origin
  const challenge1 = shield.issueChallenge('198.51.100.10');
  const legitimatePayload: TelemetryPayload = {
    hostname: 'quellcloud.com',
    origin: 'https://quellcloud.com',
    port: '443',
    pathname: '/login',
    referrer: 'https://quellcloud.com/',
    userAgent: standardBrowserUa,
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 42,
    clientTimestamp: Date.now(),
    nonce: challenge1.nonce,
    challengeProof: challenge1.challengeProof,
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
    userAgent: standardBrowserUa,
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 185,
    clientTimestamp: Date.now(),
    nonce: challenge2.nonce,
    challengeProof: challenge2.challengeProof,
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

  // Test 5: Red-Team Bypass #1 — Proxy Server-Side Token-Oracle Forgery
  // Attacker scrapes publicKeyPem + nonce from HTML and encrypts a fake "https://quellcloud.com" payload on the proxy server without evaluating the polymorphic JS closure
  const challenge5 = shield.issueChallenge('203.0.113.99');
  const oracleForgedPayload: TelemetryPayload = {
    hostname: 'quellcloud.com',
    origin: 'https://quellcloud.com',
    port: '443',
    pathname: '/login',
    referrer: 'https://quellcloud.com/',
    userAgent: standardBrowserUa,
    webdriver: false,
    canvasHash: '89f1c3a04b2d9e17',
    webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
    domIntegrityValid: true,
    rttMs: 28,
    clientTimestamp: Date.now(),
    nonce: challenge5.nonce,
    challengeProof: '0000000000000000000000000000dead',
  };
  const oracleForgedToken = encryptTelemetryNode(oracleForgedPayload, publicKeyPem);
  const res5 = await shield.verifyRequest({
    token: oracleForgedToken,
    clientIp: '203.0.113.99',
    userAgent: standardBrowserUa,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 5: Red-Team Bypass #1 — Server-Side Token-Oracle Forgery',
    passed: res5.allowed === false && res5.status === 'BLOCK_FORGED_TOKEN_ORACLE',
    expectedStatus: 'BLOCK_FORGED_TOKEN_ORACLE',
    actualStatus: res5.status,
    details: res5.reason,
  });

  // Test 6: Red-Team Bypass #2 — Pre-Script DOM / WebCrypto / toString Monkey-Patch
  const challenge6 = shield.issueChallenge('203.0.113.100');
  const hookedDomPayload: TelemetryPayload = {
    ...legitimatePayload,
    nonce: challenge6.nonce,
    challengeProof: challenge6.challengeProof,
    domIntegrityValid: false,
  };
  const hookedDomToken = encryptTelemetryNode(hookedDomPayload, publicKeyPem);
  const res6 = await shield.verifyRequest({
    token: hookedDomToken,
    clientIp: '203.0.113.100',
    userAgent: standardBrowserUa,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 6: Red-Team Bypass #2 — Pre-Script WebCrypto/toString Hook',
    passed: res6.allowed === false && res6.status === 'BLOCK_DOM_INTEGRITY_VIOLATION',
    expectedStatus: 'BLOCK_DOM_INTEGRITY_VIOLATION',
    actualStatus: res6.status,
    details: res6.reason,
  });

  // Test 7: Red-Team Bypass #3 — Headless Browser / Puppeteer Token Farm
  const challenge7 = shield.issueChallenge('203.0.113.101');
  const headlessPayload: TelemetryPayload = {
    ...legitimatePayload,
    nonce: challenge7.nonce,
    challengeProof: challenge7.challengeProof,
    webdriver: false,
    webglRenderer: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)))',
  };
  const headlessToken = encryptTelemetryNode(headlessPayload, publicKeyPem);
  const res7 = await shield.verifyRequest({
    token: headlessToken,
    clientIp: '203.0.113.101',
    userAgent: standardBrowserUa,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 7: Red-Team Bypass #3 — Headless Puppeteer / SwiftShader Farm',
    passed: res7.allowed === false && res7.status === 'BLOCK_HEADLESS_AUTOMATION',
    expectedStatus: 'BLOCK_HEADLESS_AUTOMATION',
    actualStatus: res7.status,
    details: res7.reason,
  });

  // Test 8: Red-Team Bypass #4 — Cross-Browser Token Relay Attack
  const challenge8 = shield.issueChallenge('203.0.113.102');
  const relayedTokenPayload: TelemetryPayload = {
    ...legitimatePayload,
    nonce: challenge8.nonce,
    challengeProof: challenge8.challengeProof,
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
  };
  const relayedBrowserToken = encryptTelemetryNode(relayedTokenPayload, publicKeyPem);
  const res8 = await shield.verifyRequest({
    token: relayedBrowserToken,
    clientIp: '203.0.113.102',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/605.1.15',
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  outcomes.push({
    name: 'Test 8: Red-Team Bypass #4 — Cross-Browser Token Relay Attack',
    category: 'DEFENSE',
    passed: res8.allowed === false && res8.status === 'BLOCK_CONTEXT_BINDING_MISMATCH',
    expectedStatus: 'BLOCK_CONTEXT_BINDING_MISMATCH',
    actualStatus: res8.status,
    details: res8.reason,
  });

  // Test 9: ARCHITECTURAL LIMIT PoC — Standalone Wire-Script Forgery (Zero Victim Browser Involvement)
  // An attacker fetches GET / and receives ONLY the raw obfuscated <script> string over the wire.
  // Without touching hmacSecret, IssuedChallenge.challengeProof, or a victim browser, the attacker
  // extracts SPKI publicKey, nonce, xorKey, affineOffset, and pA/pB via regex, synthesizes challengeProof,
  // and encrypts a synthetic 'https://quellcloud.com' payload.
  // PERMANENT ARCHITECTURAL ASSERTION: This MUST return 'ALLOW', proving that client-side public-key
  // telemetry is a commodity detection & canary-deception layer, NOT an authentication boundary.
  const rawWireScriptOnly: string = shield.issueChallenge('203.0.113.200').script;
  const wireForgery = forgeTokenFromWireScript(
    rawWireScriptOnly,
    'https://quellcloud.com',
    'quellcloud.com',
    standardBrowserUa
  );
  const res9 = await shield.verifyRequest({
    token: wireForgery.forgedToken,
    clientIp: '203.0.113.200',
    userAgent: standardBrowserUa,
    username: 'h.tunay@quellcloud.com',
    silenceConsoleAlert: true,
  });

  assert.strictEqual(
    res9.status,
    'ALLOW',
    'Architectural Theorem: Standalone wire-script forgery must return ALLOW because all inputs needed to encrypt with the server public key are present on the wire.'
  );

  outcomes.push({
    name: 'Test 9: Architectural Limit PoC — Standalone Wire-Script Forgery (No Victim Browser)',
    category: 'ARCHITECTURAL_LIMIT_POC',
    passed: res9.allowed === true && res9.status === 'ALLOW',
    expectedStatus: 'ALLOW (Architectural Boundary Proof)',
    actualStatus: res9.status,
    details:
      'Proves telemetry + affine/XOR proof can be synthesized purely from wire script bytes; authentication boundary requires WebAuthn/Passkey.',
  });

  const allPassed = outcomes.every((o) => o.passed);

  if (!silentBanner) {
    const green = '\x1b[32m';
    const yellow = '\x1b[33m';
    const red = '\x1b[31m';
    const cyan = '\x1b[36m';
    const bold = '\x1b[1m';
    const reset = '\x1b[0m';

    console.log(
      `\n${bold}${cyan}┌──────────────────────────────────────────────────────────────────────────────┐${reset}`
    );
    console.log(
      `${bold}${cyan}│  NULLFILTER / ORIGINLOCK TELEMETRY, DECEPTION & ARCHITECTURAL PoC SUITE      │${reset}`
    );
    console.log(
      `${bold}${cyan}└──────────────────────────────────────────────────────────────────────────────┘${reset}`
    );

    for (const item of outcomes) {
      let badge: string;
      if (!item.passed) {
        badge = `${red}[FAIL]${reset}`;
      } else if (item.category === 'ARCHITECTURAL_LIMIT_POC') {
        badge = `${yellow}[ARCHITECTURAL LIMIT — EXPECTED ALLOW]${reset}`;
      } else {
        badge = `${green}[DEFENSE PASS]${reset}`;
      }
      console.log(`  ${badge} ${bold}${item.name}${reset}`);
      console.log(`         Verdict : ${cyan}${item.actualStatus}${reset}`);
      console.log(`         Reason  : ${item.details}`);
    }

    console.log(
      `\n  ${bold}Overall Suite Result:${reset} ${
        allPassed
          ? `${green}8/8 COMMODITY & TAMPERING CHECKS PASSED | 1/1 ARCHITECTURAL LIMIT PoC PROVEN (EXPECTED ALLOW)${reset}`
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
