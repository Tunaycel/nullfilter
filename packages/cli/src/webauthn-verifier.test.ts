import * as assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { describe, it } from 'node:test';
import {
  issueWebAuthnChallenge,
  verifyWebAuthnAssertion,
  WebAuthnAssertionInput,
  WebAuthnStoredCredential,
} from '@nullfilter/core';

/**
 * TEST SCOPE & PLATFORM TRUST BOUNDARY NOTE:
 * In this Node.js test suite, the authenticator's ECDSA P-256 private key lives in the same
 * process as the verifier. Consequently, these tests prove:
 *   1. The verifier rejects any assertion not signed by the registered credential's private key.
 *   2. The verifier enforces origin, rpIdHash, challenge, type, crossOrigin, UP/UV flags,
 *      and signCount invariants.
 *
 * These Node tests CANNOT prove:
 *   - Hardware key non-extractability (TPM / Secure Enclave guarantee).
 *   - That the browser's C++ WebAuthn engine (rather than page JS) populated `clientDataJSON.origin`.
 * Those two invariants are platform guarantees enforced by the OS and browser.
 *
 * Production Note: Use an audited library (e.g. `@simplewebauthn/server`) for production
 * deployments requiring full COSE/CBOR registration attestation parsing.
 */

interface SimulatedAuthenticator {
  credentialId: string;
  publicKeySpkiPem: string;
  privateKey: crypto.KeyObject;
}

function createSimulatedP256Authenticator(): SimulatedAuthenticator {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  return {
    credentialId: crypto.randomBytes(32).toString('base64url'),
    publicKeySpkiPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
}

function buildSignedAssertion(params: {
  auth: SimulatedAuthenticator;
  rpId: string;
  origin: string;
  challengeB64Url: string;
  flags?: number;
  signCount?: number;
  type?: string;
  crossOrigin?: boolean;
  rawClientDataOverride?: string;
  signatureEncoding?: 'der' | 'ieee-p1363';
}): WebAuthnAssertionInput {
  const rpIdHash = crypto.createHash('sha256').update(params.rpId, 'utf8').digest();
  const flagsBuf = Buffer.from([params.flags ?? 0x05]); // UP (0x01) | UV (0x04)
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(params.signCount ?? 1, 0);

  const authData = Buffer.concat([rpIdHash, flagsBuf, signCountBuf]);

  const clientDataObj: Record<string, unknown> = {
    type: params.type ?? 'webauthn.get',
    challenge: params.challengeB64Url,
    origin: params.origin,
  };
  if (params.crossOrigin !== undefined) {
    clientDataObj.crossOrigin = params.crossOrigin;
  }

  const clientDataRaw = params.rawClientDataOverride ?? JSON.stringify(clientDataObj);
  const clientDataBytes = Buffer.from(clientDataRaw, 'utf8');
  const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();

  const signedData = Buffer.concat([authData, clientDataHash]);
  const signature = crypto.sign('sha256', signedData, {
    key: params.auth.privateKey,
    dsaEncoding: params.signatureEncoding ?? 'der',
  });

  return {
    credentialId: params.auth.credentialId,
    authenticatorDataB64Url: authData.toString('base64url'),
    clientDataJsonB64Url: clientDataBytes.toString('base64url'),
    signatureB64Url: signature.toString('base64url'),
  };
}

describe('Zero-Dependency WebAuthn Assertion Verifier (PR-B)', () => {
  const hmacSecret = 'a-very-strong-test-hmac-secret-32-chars';
  const expectedRpId = 'quellcloud.com';
  const allowedOrigins = ['https://quellcloud.com'];

  it('Test 10 (Symmetry with Test 9): attacker observing all wire data cannot forge an assertion without the user private key -> BLOCK', () => {
    const victimAuth = createSimulatedP256Authenticator();
    const attackerAuth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();

    const storedCredential: WebAuthnStoredCredential = {
      credentialId: victimAuth.credentialId,
      publicKeySpkiPem: victimAuth.publicKeySpkiPem,
      signCount: 5,
    };

    // Attacker observes the challenge, rpId, allowedOrigins, and victim credentialId on the wire,
    // constructs a valid-looking payload for https://quellcloud.com, and signs with their own P-256 key.
    const challenge = issueWebAuthnChallenge(hmacSecret);
    const forgedAssertion = buildSignedAssertion({
      auth: {
        ...attackerAuth,
        credentialId: victimAuth.credentialId,
      },
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signCount: 6,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion: forgedAssertion,
      storedCredential,
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    // Contrast with Test 9 (telemetry ALLOW): here the attacker lacks the private key -> BLOCK.
    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_INVALID_SIGNATURE');
  });

  it('ALLOW: verifies valid ES256 assertion with incrementing signCount and UP+UV flags', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const storedCredential: WebAuthnStoredCredential = {
      credentialId: auth.credentialId,
      publicKeySpkiPem: auth.publicKeySpkiPem,
      signCount: 10,
    };

    const challenge = issueWebAuthnChallenge(hmacSecret);
    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signCount: 11,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential,
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, true);
    assert.strictEqual(verdict.status, 'ALLOW_WEBAUTHN_ASSERTION');
    assert.strictEqual(verdict.newSignCount, 11);
    assert.strictEqual(verdict.flags?.up, true);
    assert.strictEqual(verdict.flags?.uv, true);
  });

  it('ALLOW: supports synced passkeys where both stored and incoming signCount are 0', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const storedCredential: WebAuthnStoredCredential = {
      credentialId: auth.credentialId,
      publicKeySpkiPem: auth.publicKeySpkiPem,
      signCount: 0,
    };

    const challenge = issueWebAuthnChallenge(hmacSecret);
    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signCount: 0,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential,
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, true);
    assert.strictEqual(verdict.status, 'ALLOW_WEBAUTHN_ASSERTION');
    assert.strictEqual(verdict.newSignCount, 0);
  });

  it('ALLOW: hashes raw clientDataJSON bytes directly (non-canonical key order/whitespace preserved)', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const storedCredential: WebAuthnStoredCredential = {
      credentialId: auth.credentialId,
      publicKeySpkiPem: auth.publicKeySpkiPem,
      signCount: 0,
    };

    const challenge = issueWebAuthnChallenge(hmacSecret);
    // Deliberately non-canonical whitespace & key ordering
    const rawNonCanonical = `{\n  "origin" : "https://quellcloud.com",\n  "challenge": "${challenge.challengeB64Url}",\n  "type": "webauthn.get"\n}`;

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      rawClientDataOverride: rawNonCanonical,
      signCount: 0,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential,
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, true);
    assert.strictEqual(verdict.status, 'ALLOW_WEBAUTHN_ASSERTION');
  });

  it('BLOCK: rejects origin prefix-bypass attempt (https://quellcloud.com.evil.com)', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com.evil.com',
      challengeB64Url: challenge.challengeB64Url,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_ORIGIN_MISMATCH');
  });

  it('BLOCK: rejects rpIdHash mismatch', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: 'quellcl0ud.com',
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_RPID_MISMATCH');
  });

  it('BLOCK: rejects wrong clientDataJSON.type (webauthn.create)', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      type: 'webauthn.create',
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_INVALID_TYPE');
  });

  it('BLOCK: rejects crossOrigin: true', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      crossOrigin: true,
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_CROSS_ORIGIN');
  });

  it('BLOCK: rejects replayed challenge (single-use enforcement)', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const storedCredential: WebAuthnStoredCredential = {
      credentialId: auth.credentialId,
      publicKeySpkiPem: auth.publicKeySpkiPem,
      signCount: 1,
    };

    const challenge = issueWebAuthnChallenge(hmacSecret);
    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signCount: 2,
    });

    const first = verifyWebAuthnAssertion({
      assertion,
      storedCredential,
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });
    assert.strictEqual(first.allowed, true);

    const second = verifyWebAuthnAssertion({
      assertion,
      storedCredential: { ...storedCredential, signCount: 2 },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });
    assert.strictEqual(second.allowed, false);
    assert.strictEqual(second.status, 'BLOCK_WEBAUTHN_CHALLENGE_MISMATCH');
  });

  it('BLOCK: rejects missing UP (User Present) flag', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      flags: 0x04, // UV only, UP=0
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_USER_NOT_PRESENT');
  });

  it('BLOCK: rejects missing UV (User Verified) flag when requireUserVerification is true', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      flags: 0x01, // UP only, UV=0
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
      requireUserVerification: true,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_USER_NOT_VERIFIED');
  });

  it('BLOCK: rejects non-incrementing signCount when storedCount > 0 (cloned authenticator)', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signCount: 10, // Equal to stored signCount 10 -> cloned replay
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 10,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_SIGN_COUNT_REPLAY');
  });

  it('BLOCK: rejects raw IEEE P1363 signature (r||s) when ASN.1 DER is required', () => {
    const auth = createSimulatedP256Authenticator();
    const usedChallenges = new Set<string>();
    const challenge = issueWebAuthnChallenge(hmacSecret);

    const assertion = buildSignedAssertion({
      auth,
      rpId: expectedRpId,
      origin: 'https://quellcloud.com',
      challengeB64Url: challenge.challengeB64Url,
      signatureEncoding: 'ieee-p1363',
    });

    const verdict = verifyWebAuthnAssertion({
      assertion,
      storedCredential: {
        credentialId: auth.credentialId,
        publicKeySpkiPem: auth.publicKeySpkiPem,
        signCount: 0,
      },
      expectedRpId,
      allowedOrigins,
      hmacSecret,
      usedChallengesSet: usedChallenges,
    });

    assert.strictEqual(verdict.allowed, false);
    assert.strictEqual(verdict.status, 'BLOCK_WEBAUTHN_INVALID_SIGNATURE');
  });
});
