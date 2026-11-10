import * as crypto from 'node:crypto';
import { TelemetryPayload } from './types';

export interface RsaKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface NonceVerificationOutcome {
  valid: boolean;
  status: 'VALID' | 'INVALID_NONCE' | 'EXPIRED_TOKEN';
  reason: string;
  issuedAtMs?: number;
}

const MAX_DEFAULT_NONCE_CACHE_ENTRIES = 50_000;
const HEX_REGEX = /^[0-9a-fA-F]+$/;

/**
 * Generates a 2048-bit RSA keypair formatted as SPKI (PUBLIC KEY) and PKCS8 (PRIVATE KEY) PEM strings.
 */
export function generateRsaKeyPair(): RsaKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
  };
}

/**
 * Generates a high-entropy 256-bit cryptographic secret encoded as hexadecimal.
 */
export function generateHmacSecret(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * Issues a single-use HMAC-SHA256 signed nonce in the format:
 * `${timestampHex}.${randomHex}.${hmacSignatureHex}`
 */
export function generateNonce(hmacSecret: string, clientIp?: string): string {
  if (!hmacSecret || hmacSecret.length < 16) {
    throw new Error('HMAC secret must be at least 16 characters long.');
  }

  const timestampHex = Date.now().toString(16);
  let randomHex: string;

  if (clientIp && clientIp.trim().length > 0) {
    const ipTag = crypto
      .createHmac('sha256', hmacSecret)
      .update(`ip-bind:${clientIp.trim()}`)
      .digest('hex')
      .slice(0, 8);
    randomHex = `b1${crypto.randomBytes(11).toString('hex')}${ipTag}`;
  } else {
    randomHex = `00${crypto.randomBytes(15).toString('hex')}`;
  }

  const payloadToSign = `${timestampHex}.${randomHex}`;
  const hmacSignatureHex = crypto
    .createHmac('sha256', hmacSecret)
    .update(payloadToSign)
    .digest('hex');

  return `${timestampHex}.${randomHex}.${hmacSignatureHex}`;
}

/**
 * Validates a nonce's cryptographic HMAC signature in constant time, verifies its TTL window,
 * and enforces single-use replay prevention with bounded memory cleanup.
 */
export function verifyNonce(
  nonce: string,
  hmacSecret: string,
  maxAgeMs: number,
  usedNoncesSet: Set<string>,
  clientIp?: string
): NonceVerificationOutcome {
  if (!nonce || typeof nonce !== 'string') {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'Missing or non-string nonce token.',
    };
  }

  const segments = nonce.split('.');
  if (segments.length !== 3) {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'Malformed nonce structure; expected 3 hex segments.',
    };
  }

  const [timestampHex, randomHex, providedSignatureHex] = segments;

  if (
    !timestampHex ||
    !randomHex ||
    !providedSignatureHex ||
    providedSignatureHex.length !== 64 ||
    !HEX_REGEX.test(timestampHex) ||
    !HEX_REGEX.test(randomHex) ||
    !HEX_REGEX.test(providedSignatureHex)
  ) {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'Nonce segments contain invalid hexadecimal encoding.',
    };
  }

  const expectedSignatureHex = crypto
    .createHmac('sha256', hmacSecret)
    .update(`${timestampHex}.${randomHex}`)
    .digest('hex');

  const providedSigBuf = Buffer.from(providedSignatureHex, 'hex');
  const expectedSigBuf = Buffer.from(expectedSignatureHex, 'hex');

  if (
    providedSigBuf.length !== expectedSigBuf.length ||
    !crypto.timingSafeEqual(providedSigBuf, expectedSigBuf)
  ) {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'HMAC-SHA256 signature verification failed.',
    };
  }

  if (clientIp && clientIp.trim().length > 0 && randomHex.startsWith('b1') && randomHex.length >= 10) {
    const embeddedIpTag = randomHex.slice(-8);
    const expectedIpTag = crypto
      .createHmac('sha256', hmacSecret)
      .update(`ip-bind:${clientIp.trim()}`)
      .digest('hex')
      .slice(0, 8);

    const embeddedBuf = Buffer.from(embeddedIpTag, 'hex');
    const expectedBuf = Buffer.from(expectedIpTag, 'hex');
    if (embeddedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(embeddedBuf, expectedBuf)) {
      return {
        valid: false,
        status: 'INVALID_NONCE',
        reason: 'Client IP binding mismatch on cryptographic nonce.',
      };
    }
  }

  const issuedAtMs = Number.parseInt(timestampHex, 16);
  if (!Number.isFinite(issuedAtMs) || issuedAtMs <= 0) {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'Invalid nonce timestamp value.',
    };
  }

  const now = Date.now();
  const elapsedMs = now - issuedAtMs;

  if (elapsedMs > maxAgeMs || elapsedMs < -5_000) {
    return {
      valid: false,
      status: 'EXPIRED_TOKEN',
      reason: `Nonce TTL expired (elapsed: ${elapsedMs}ms, maxAllowed: ${maxAgeMs}ms).`,
      issuedAtMs,
    };
  }

  if (usedNoncesSet.has(nonce)) {
    return {
      valid: false,
      status: 'INVALID_NONCE',
      reason: 'Replay attack detected: nonce has already been consumed.',
      issuedAtMs,
    };
  }

  if (usedNoncesSet.size >= MAX_DEFAULT_NONCE_CACHE_ENTRIES) {
    const oldestEntry = usedNoncesSet.values().next().value;
    if (oldestEntry !== undefined) {
      usedNoncesSet.delete(oldestEntry);
    }
  }

  usedNoncesSet.add(nonce);

  const cleanupDelayMs = Math.max(maxAgeMs * 2, 30_000);
  const cleanupTimer = setTimeout(() => {
    usedNoncesSet.delete(nonce);
  }, cleanupDelayMs);

  if (typeof cleanupTimer.unref === 'function') {
    cleanupTimer.unref();
  }

  return {
    valid: true,
    status: 'VALID',
    reason: 'Nonce verified and consumed.',
    issuedAtMs,
  };
}

/**
 * Decrypts a Base64-encoded telemetry token using the server's RSA-2048 Private Key.
 * Supports both Direct RSA-OAEP (<=190-byte plaintext) and Hybrid RSA-OAEP-2048 + AES-256-GCM
 * binary envelope ciphertexts for full-length DOM telemetry payloads.
 */
export function decryptTelemetryPayload(
  encryptedBase64: string,
  privateKeyPem: string
): TelemetryPayload {
  if (!encryptedBase64 || typeof encryptedBase64 !== 'string') {
    throw new Error('Encrypted token must be a non-empty Base64 string.');
  }

  const normalized = encryptedBase64.trim();
  if (normalized.length < 64 || !/^[A-Za-z0-9+/=_-]+$/.test(normalized)) {
    throw new Error('Malformed Base64 token encoding.');
  }

  const rawBuffer = Buffer.from(normalized, 'base64');
  let decryptedUtf8: string;

  if (rawBuffer.length === 256) {
    const decryptedBuf = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      rawBuffer
    );
    decryptedUtf8 = decryptedBuf.toString('utf8');
  } else if (rawBuffer.length > 256 + 16) {
    const rsaKeyEnvelope = rawBuffer.subarray(0, 256);
    const aesGcmEnvelope = rawBuffer.subarray(256);

    const keyAndIvBuffer = crypto.privateDecrypt(
      {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      rsaKeyEnvelope
    );

    if (keyAndIvBuffer.length !== 44) {
      throw new Error(`Invalid hybrid envelope key block length: ${keyAndIvBuffer.length}`);
    }

    const aesKey = keyAndIvBuffer.subarray(0, 32);
    const iv = keyAndIvBuffer.subarray(32, 44);
    const ciphertext = aesGcmEnvelope.subarray(0, aesGcmEnvelope.length - 16);
    const authTag = aesGcmEnvelope.subarray(aesGcmEnvelope.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);

    const decryptedPart1 = decipher.update(ciphertext);
    const decryptedPart2 = decipher.final();
    decryptedUtf8 = Buffer.concat([decryptedPart1, decryptedPart2]).toString('utf8');
  } else {
    throw new Error(`Invalid ciphertext byte length: ${rawBuffer.length}`);
  }

  const parsed = JSON.parse(decryptedUtf8) as Partial<TelemetryPayload>;
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    typeof parsed.hostname !== 'string' ||
    typeof parsed.origin !== 'string' ||
    typeof parsed.nonce !== 'string' ||
    typeof parsed.clientTimestamp !== 'number'
  ) {
    throw new Error('Decrypted payload is missing mandatory TelemetryPayload fields.');
  }

  return {
    hostname: parsed.hostname,
    origin: parsed.origin,
    port: typeof parsed.port === 'string' ? parsed.port : '',
    pathname: typeof parsed.pathname === 'string' ? parsed.pathname : '/',
    referrer: typeof parsed.referrer === 'string' ? parsed.referrer : '',
    userAgent: typeof parsed.userAgent === 'string' ? parsed.userAgent : '',
    webdriver: Boolean(parsed.webdriver),
    canvasHash: typeof parsed.canvasHash === 'string' ? parsed.canvasHash : '00000000',
    rttMs: typeof parsed.rttMs === 'number' && Number.isFinite(parsed.rttMs) ? parsed.rttMs : 0,
    clientTimestamp: parsed.clientTimestamp,
    nonce: parsed.nonce,
    webglRenderer: typeof parsed.webglRenderer === 'string' ? parsed.webglRenderer : undefined,
    domIntegrityValid:
      typeof parsed.domIntegrityValid === 'boolean' ? parsed.domIntegrityValid : true,
  };
}

/**
 * Node-side encryption helper for CLI self-tests, audits, and automated integration suites.
 * Uses direct RSA-OAEP when payload <= 180 bytes, or the RSA-OAEP-2048 + AES-256-GCM binary
 * envelope when the serialized JSON exceeds the 190-byte RSA-2048 OAEP SHA-256 ceiling.
 */
export function encryptTelemetryNode(payload: TelemetryPayload, publicKeyPem: string): string {
  const jsonBytes = Buffer.from(JSON.stringify(payload), 'utf8');

  if (jsonBytes.length <= 180) {
    const encryptedDirect = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      jsonBytes
    );
    return encryptedDirect.toString('base64');
  }

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const keyAndIv = Buffer.concat([aesKey, iv]);

  const encryptedKeyBlock = crypto.publicEncrypt(
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    keyAndIv
  );

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encryptedBody = Buffer.concat([cipher.update(jsonBytes), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([encryptedKeyBlock, encryptedBody, authTag]).toString('base64');
}
