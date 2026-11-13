import * as assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  encryptTelemetryNode,
  generateHmacSecret,
  generateRsaKeyPair,
  TelemetryPayload,
} from '@nullfilter/core';
import { inspectCanarySessionCookie, OriginLockShield } from '@nullfilter/server';
import { forgeTokenFromWireScript } from './commands/audit';

describe('NullFilter Architectural Boundary & Red-Team Forgery Suite', () => {
  it('ARCHITECTURAL LIMIT PoC: standalone attacker forges ALLOW token purely from GET / wire script bytes without victim browser or server secrets', async () => {
    const { publicKeyPem, privateKeyPem } = generateRsaKeyPair();
    const hmacSecret = generateHmacSecret(32);

    const shield = new OriginLockShield({
      publicKeyPem,
      privateKeyPem,
      hmacSecret,
      allowedHostnames: ['quellcloud.com'],
      allowedOrigins: ['https://quellcloud.com'],
      enforceChallengeProof: true,
      blockHeadlessAutomation: true,
      enforceUserAgentBinding: true,
      enableHoneypotPoisoning: true,
    });

    const spoofedUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0';

    // Step A (Pre-Check): Confirm that `enforceChallengeProof` is actively blocking naive oracle forgeries
    // that do not reverse-engineer the polymorphic wire script.
    const rawWireScriptForNaiveAttempt: string = shield.issueChallenge('203.0.113.249').script;
    const naiveExtraction = forgeTokenFromWireScript(rawWireScriptForNaiveAttempt);
    const naiveTokenWithoutWireProof = encryptTelemetryNode(
      {
        hostname: 'quellcloud.com',
        origin: 'https://quellcloud.com',
        port: '443',
        pathname: '/login',
        referrer: 'https://quellcloud.com/',
        userAgent: spoofedUserAgent,
        webdriver: false,
        canvasHash: '89f1c3a04b2d9e17',
        webglRenderer: 'ANGLE (NVIDIA GeForce RTX 4080 Direct3D11)',
        domIntegrityValid: true,
        rttMs: 31,
        clientTimestamp: Date.now(),
        nonce: naiveExtraction.extractedNonce,
        challengeProof: '0000000000000000000000000000dead',
      },
      naiveExtraction.reconstructedPublicKeyPem
    );

    const naiveVerdict = await shield.verifyRequest({
      token: naiveTokenWithoutWireProof,
      clientIp: '203.0.113.249',
      userAgent: spoofedUserAgent,
      username: 'h.tunay@quellcloud.com',
      silenceConsoleAlert: true,
    });
    assert.strictEqual(naiveVerdict.status, 'BLOCK_FORGED_TOKEN_ORACLE');

    // Step B (Standalone Wire-Script Forgery PoC):
    // The attacker ONLY observes the raw <script> string sent over the wire on `GET /`.
    // The attacker NEVER accesses `hmacSecret`, `privateKeyPem`, or `challenge.challengeProof`.
    const rawWireScript: string = shield.issueChallenge('203.0.113.250').script;

    const forged = forgeTokenFromWireScript(
      rawWireScript,
      'https://quellcloud.com',
      'quellcloud.com',
      spoofedUserAgent
    );

    const verdict = await shield.verifyRequest({
      token: forged.forgedToken,
      clientIp: '203.0.113.250',
      userAgent: spoofedUserAgent,
      username: 'h.tunay@quellcloud.com',
      silenceConsoleAlert: true,
    });

    // PERMANENT ARCHITECTURAL ASSERTION:
    // This assertion MUST remain 'ALLOW' even after WebAuthn is added in subsequent PRs.
    // It proves that client-side public-key encryption + polymorphic obfuscation cannot serve
    // as an unforgeable authentication boundary against a tailored attacker who reverses the wire script.
    assert.strictEqual(verdict.allowed, true);
    assert.strictEqual(verdict.status, 'ALLOW');
    assert.strictEqual(verdict.decryptedPayload?.origin, 'https://quellcloud.com');
    assert.strictEqual(verdict.threatDetails?.canaryId, undefined);
  });

  it('COMMODITY PHISHLET DEFENSE: detects unmodified Evilginx relay and injects signed Canary Honeypot cookie', async () => {
    const { publicKeyPem, privateKeyPem } = generateRsaKeyPair();
    const hmacSecret = generateHmacSecret(32);

    const shield = new OriginLockShield({
      publicKeyPem,
      privateKeyPem,
      hmacSecret,
      allowedHostnames: ['quellcloud.com'],
      allowedOrigins: ['https://quellcloud.com'],
      enforceChallengeProof: true,
      blockHeadlessAutomation: true,
      enforceUserAgentBinding: true,
      enableHoneypotPoisoning: true,
    });

    const rawWireScript: string = shield.issueChallenge('203.0.113.88').script;
    const browserUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0';

    // Commodity phishlet relays the script unmodified to the victim on https://quellcl0ud.com
    const victimBrowserExecution = forgeTokenFromWireScript(
      rawWireScript,
      'https://quellcl0ud.com',
      'quellcl0ud.com',
      browserUa
    );

    const verdict = await shield.verifyRequest({
      token: victimBrowserExecution.forgedToken,
      clientIp: '203.0.113.88',
      userAgent: browserUa,
      username: 'h.tunay@quellcloud.com',
      silenceConsoleAlert: true,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_AITM_ORIGIN_MISMATCH');
    assert.ok(verdict.threatDetails?.poisonedCookieHeader);

    const canary = inspectCanarySessionCookie(
      verdict.threatDetails.poisonedCookieHeader,
      hmacSecret
    );
    assert.ok(canary);
    assert.strictEqual(canary.captured_on, 'https://quellcl0ud.com');
  });
});
