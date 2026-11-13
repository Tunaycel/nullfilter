import * as crypto from 'node:crypto';
import { generateNonce, verifyNonce } from './crypto';

/**
 * NOTE ON PRODUCTION USAGE:
 * This zero-dependency WebAuthn Assertion (`navigator.credentials.get`) verifier is built
 * to transparently demonstrate the cryptographic mechanics of FIDO2 origin binding
 * (`authenticatorData || SHA256(clientDataJSON)` verified via ES256 / P-256).
 *
 * For production deployments — especially registration/attestation ceremonies requiring
 * COSE/CBOR parsing, MDS metadata validation, and full edge-case handling — use an audited
 * library such as `@simplewebauthn/server`.
 */

export interface WebAuthnAssertionInput {
  /** Base64url-encoded credential ID returned by the authenticator */
  credentialId: string;
  /** Base64url-encoded raw authenticatorData bytes (>= 37 bytes) */
  authenticatorDataB64Url: string;
  /** Base64url-encoded raw clientDataJSON UTF-8 bytes */
  clientDataJsonB64Url: string;
  /** Base64url-encoded ASN.1 DER ECDSA P-256 signature */
  signatureB64Url: string;
}

export interface WebAuthnStoredCredential {
  credentialId: string;
  /** SPKI PEM of an ECDSA P-256 (prime256v1 / ES256) public key */
  publicKeySpkiPem: string;
  /** Last recorded signCount (0 when authenticator does not maintain a counter, e.g. synced passkeys) */
  signCount: number;
}

export interface IssuedWebAuthnChallenge {
  challengeString: string;
  /** Base64url-encoded challenge bytes for PublicKeyCredentialRequestOptions.challenge */
  challengeB64Url: string;
}

export interface WebAuthnVerifyOptions {
  assertion: WebAuthnAssertionInput;
  storedCredential: WebAuthnStoredCredential;
  /** Expected Relying Party ID (host-only, e.g. 'quellcloud.com' or 'localhost') */
  expectedRpId: string;
  /** Strict exact-match allowlist of permitted origins (e.g. ['https://quellcloud.com']) */
  allowedOrigins: string[];
  /** Server HMAC secret used to validate the single-use challenge */
  hmacSecret: string;
  /** Bounded Set of consumed challenges for single-use replay prevention */
  usedChallengesSet: Set<string>;
  /** Maximum challenge age in milliseconds (default: 60_000) */
  maxChallengeAgeMs?: number;
  /** Optional client IP bound into the challenge */
  clientIp?: string;
  /** Require User Verification (UV bit 0x04). Default: true (required for single-factor passkeys) */
  requireUserVerification?: boolean;
  /** Maximum entries in usedChallengesSet before FIFO eviction (default: 50_000) */
  maxChallengeCacheSize?: number;
}

export type WebAuthnVerdictStatus =
  | 'ALLOW_WEBAUTHN_ASSERTION'
  | 'BLOCK_WEBAUTHN_MALFORMED_INPUT'
  | 'BLOCK_WEBAUTHN_CREDENTIAL_MISMATCH'
  | 'BLOCK_WEBAUTHN_INVALID_TYPE'
  | 'BLOCK_WEBAUTHN_CROSS_ORIGIN'
  | 'BLOCK_WEBAUTHN_CHALLENGE_MISMATCH'
  | 'BLOCK_WEBAUTHN_ORIGIN_MISMATCH'
  | 'BLOCK_WEBAUTHN_RPID_MISMATCH'
  | 'BLOCK_WEBAUTHN_USER_NOT_PRESENT'
  | 'BLOCK_WEBAUTHN_USER_NOT_VERIFIED'
  | 'BLOCK_WEBAUTHN_SIGN_COUNT_REPLAY'
  | 'BLOCK_WEBAUTHN_INVALID_SIGNATURE';

export interface WebAuthnVerificationResult {
  allowed: boolean;
  status: WebAuthnVerdictStatus;
  reason: string;
  newSignCount?: number;
  verifiedOrigin?: string;
  verifiedRpIdHashHex?: string;
  flags?: {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
  };
}

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

function decodeBase64UrlStrict(input: string): Buffer | null {
  if (!input || typeof input !== 'string' || !BASE64URL_REGEX.test(input)) {
    return null;
  }
  try {
    const buf = Buffer.from(input, 'base64url');
    if (buf.length === 0) {
      return null;
    }
    return buf;
  } catch {
    return null;
  }
}

/**
 * Issues a single-use HMAC-SHA256 signed WebAuthn challenge along with its base64url form.
 */
export function issueWebAuthnChallenge(
  hmacSecret: string,
  clientIp?: string
): IssuedWebAuthnChallenge {
  const challengeString = generateNonce(hmacSecret, clientIp);
  const challengeB64Url = Buffer.from(challengeString, 'utf8').toString('base64url');
  return {
    challengeString,
    challengeB64Url,
  };
}

/**
 * Verifies a WebAuthn Assertion (`navigator.credentials.get`) using Node's built-in `node:crypto`
 * with zero external dependencies.
 *
 * Enforces all standard FIDO2 assertion invariants:
 *  - Credential ID match
 *  - `clientDataJSON` raw-byte SHA-256 digest (never parsed & re-stringified)
 *  - `type === 'webauthn.get'` and `crossOrigin !== true`
 *  - Exact origin allowlist match (no `startsWith` prefix matching)
 *  - Single-use HMAC-signed challenge verification with TTL & replay protection
 *  - `rpIdHash === SHA256(expectedRpId)` in constant time (`crypto.timingSafeEqual`)
 *  - `UP` (User Present, `0x01`) and `UV` (User Verified, `0x04`) flag bits
 *  - `signCount` monotonicity (skipping only when both stored and incoming counts are `0`)
 *  - ASN.1 DER ECDSA P-256 (`ES256`) signature over `authenticatorData || SHA256(clientDataJSON)`
 */
export function verifyWebAuthnAssertion(
  options: WebAuthnVerifyOptions
): WebAuthnVerificationResult {
  const {
    assertion,
    storedCredential,
    expectedRpId,
    allowedOrigins,
    hmacSecret,
    usedChallengesSet,
    maxChallengeAgeMs = 60_000,
    clientIp,
    requireUserVerification = true,
    maxChallengeCacheSize = 50_000,
  } = options;

  if (!assertion || !storedCredential || !expectedRpId || !Array.isArray(allowedOrigins)) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
      reason: 'Missing required WebAuthn verification parameters.',
    };
  }

  if (
    !assertion.credentialId ||
    assertion.credentialId !== storedCredential.credentialId
  ) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_CREDENTIAL_MISMATCH',
      reason: 'Assertion credentialId does not match the registered credential.',
    };
  }

  const authDataBytes = decodeBase64UrlStrict(assertion.authenticatorDataB64Url);
  const clientDataBytes = decodeBase64UrlStrict(assertion.clientDataJsonB64Url);
  const signatureBytes = decodeBase64UrlStrict(assertion.signatureB64Url);

  if (!authDataBytes || authDataBytes.length < 37 || !clientDataBytes || !signatureBytes) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
      reason: 'Malformed base64url encoding or truncated authenticatorData (< 37 bytes).',
    };
  }

  let clientData: Record<string, unknown>;
  try {
    const parsed = JSON.parse(clientDataBytes.toString('utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {
        allowed: false,
        status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
        reason: 'clientDataJSON must decode to a JSON object.',
      };
    }
    clientData = parsed as Record<string, unknown>;
  } catch {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
      reason: 'clientDataJSON is not valid UTF-8 JSON.',
    };
  }

  if (clientData.type !== 'webauthn.get') {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_INVALID_TYPE',
      reason: `Expected clientDataJSON.type === 'webauthn.get', received '${String(clientData.type)}'.`,
    };
  }

  if (clientData.crossOrigin === true) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_CROSS_ORIGIN',
      reason: 'Cross-origin WebAuthn assertion (crossOrigin: true) is rejected.',
    };
  }

  // Exact origin allowlist match (strict equality, never startsWith)
  const observedOrigin = typeof clientData.origin === 'string' ? clientData.origin : '';
  const exactOriginSet = new Set(allowedOrigins);
  if (!exactOriginSet.has(observedOrigin)) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_ORIGIN_MISMATCH',
      reason: `clientDataJSON.origin '${observedOrigin}' is not in exact allowedOrigins [${allowedOrigins.join(', ')}].`,
      verifiedOrigin: observedOrigin,
    };
  }

  // Decode and verify single-use challenge
  const rawChallengeB64Url =
    typeof clientData.challenge === 'string' ? clientData.challenge : '';
  const challengeBuf = decodeBase64UrlStrict(rawChallengeB64Url);
  if (!challengeBuf) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_CHALLENGE_MISMATCH',
      reason: 'Missing or malformed base64url challenge in clientDataJSON.',
    };
  }

  const decodedChallenge = challengeBuf.toString('utf8');
  const challengeCheck = verifyNonce(
    decodedChallenge,
    hmacSecret,
    maxChallengeAgeMs,
    usedChallengesSet,
    clientIp,
    maxChallengeCacheSize
  );
  if (!challengeCheck.valid) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_CHALLENGE_MISMATCH',
      reason: `WebAuthn challenge verification failed: ${challengeCheck.reason}`,
    };
  }

  // Verify rpIdHash === SHA-256(expectedRpId) in constant time
  const rpIdHash = authDataBytes.subarray(0, 32);
  const expectedRpIdHash = crypto
    .createHash('sha256')
    .update(expectedRpId.trim(), 'utf8')
    .digest();

  if (!crypto.timingSafeEqual(rpIdHash, expectedRpIdHash)) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_RPID_MISMATCH',
      reason: `authenticatorData rpIdHash does not match SHA-256('${expectedRpId}').`,
      verifiedRpIdHashHex: rpIdHash.toString('hex'),
    };
  }

  // Parse authenticatorData flags byte (offset 32)
  const flagsByte = authDataBytes[32];
  const flags = {
    up: (flagsByte & 0x01) !== 0,
    uv: (flagsByte & 0x04) !== 0,
    be: (flagsByte & 0x08) !== 0,
    bs: (flagsByte & 0x10) !== 0,
    at: (flagsByte & 0x40) !== 0,
    ed: (flagsByte & 0x80) !== 0,
  };

  if (!flags.up) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_USER_NOT_PRESENT',
      reason: 'authenticatorData UP (User Present, 0x01) flag is not set.',
      flags,
    };
  }

  if (requireUserVerification && !flags.uv) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_USER_NOT_VERIFIED',
      reason: 'authenticatorData UV (User Verified, 0x04) flag is required for single-factor passkey authentication.',
      flags,
    };
  }

  // SignCount monotonicity check (synced passkeys report 0 on both sides)
  const incomingSignCount = authDataBytes.readUInt32BE(33);
  if (!(storedCredential.signCount === 0 && incomingSignCount === 0)) {
    if (incomingSignCount <= storedCredential.signCount) {
      return {
        allowed: false,
        status: 'BLOCK_WEBAUTHN_SIGN_COUNT_REPLAY',
        reason: `Potential cloned authenticator: incoming signCount (${incomingSignCount}) <= stored signCount (${storedCredential.signCount}).`,
        newSignCount: incomingSignCount,
        flags,
      };
    }
  }

  // Cryptographic signature verification over: authenticatorData || SHA-256(raw clientDataJSON bytes)
  let publicKeyObj: crypto.KeyObject;
  try {
    publicKeyObj = crypto.createPublicKey(storedCredential.publicKeySpkiPem);
    if (
      publicKeyObj.asymmetricKeyType !== 'ec' ||
      publicKeyObj.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
    ) {
      return {
        allowed: false,
        status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
        reason: 'Stored credential public key must be an ECDSA P-256 (prime256v1 / ES256) key.',
      };
    }
  } catch {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_MALFORMED_INPUT',
      reason: 'Invalid SPKI PEM public key in stored credential.',
    };
  }

  const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();
  const signedData = Buffer.concat([authDataBytes, clientDataHash]);

  let isSignatureValid = false;
  try {
    // WebAuthn ES256 signatures are ASN.1 DER encoded, matching Node crypto.verify default encoding.
    isSignatureValid = crypto.verify('sha256', signedData, publicKeyObj, signatureBytes);
  } catch {
    isSignatureValid = false;
  }

  if (!isSignatureValid) {
    return {
      allowed: false,
      status: 'BLOCK_WEBAUTHN_INVALID_SIGNATURE',
      reason: 'ECDSA P-256 (ES256) assertion signature verification failed.',
      verifiedOrigin: observedOrigin,
      verifiedRpIdHashHex: rpIdHash.toString('hex'),
      flags,
    };
  }

  return {
    allowed: true,
    status: 'ALLOW_WEBAUTHN_ASSERTION',
    reason: `WebAuthn ES256 assertion verified for origin '${observedOrigin}' and rpId '${expectedRpId}'.`,
    newSignCount: incomingSignCount,
    verifiedOrigin: observedOrigin,
    verifiedRpIdHashHex: rpIdHash.toString('hex'),
    flags,
  };
}
