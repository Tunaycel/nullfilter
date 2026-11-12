import { TelemetryPayload } from '@nullfilter/core';
import {
  getCanvasFingerprint,
  getWebglRenderer,
  measureRtt,
  verifyDomCryptoIntegrity,
} from './fingerprint';

export interface OriginLockClientOptions {
  publicKeyPem: string;
  nonce: string;
  pingUrl?: string;
}

export type NullFilterClientOptions = OriginLockClientOptions;

function pemToSpkiArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');

  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Collects live browser DOM telemetry and encrypts it inside an RSA-OAEP (SHA-256) + AES-256-GCM
 * hybrid cryptographic envelope using `window.crypto.subtle`.
 */
export async function createOriginLockToken(options: OriginLockClientOptions): Promise<string> {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('WebCrypto API (window.crypto.subtle) is required to generate an attestation token.');
  }

  const rttMs = await measureRtt(options.pingUrl ?? '/api/ping');

  const payload: TelemetryPayload = {
    hostname: window.location.hostname || '',
    origin: window.location.origin || '',
    port: window.location.port || '',
    pathname: window.location.pathname || '/',
    referrer: typeof document !== 'undefined' ? document.referrer || '' : '',
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent || '' : '',
    webdriver: typeof navigator !== 'undefined' ? Boolean(navigator.webdriver) : false,
    canvasHash: getCanvasFingerprint(),
    webglRenderer: getWebglRenderer(),
    domIntegrityValid: verifyDomCryptoIntegrity(),
    rttMs,
    clientTimestamp: Date.now(),
    nonce: options.nonce,
  };

  const spkiBuffer = pemToSpkiArrayBuffer(options.publicKeyPem);
  const rsaPublicKey = await window.crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-256' },
    },
    false,
    ['encrypt']
  );

  const aesKeyBytes = new Uint8Array(32);
  const ivBytes = new Uint8Array(12);
  window.crypto.getRandomValues(aesKeyBytes);
  window.crypto.getRandomValues(ivBytes);

  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    aesKeyBytes.buffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
  const aesGcmCipherBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
    },
    aesKey,
    encodedPayload
  );

  const keyAndIvBytes = new Uint8Array(44);
  keyAndIvBytes.set(aesKeyBytes, 0);
  keyAndIvBytes.set(ivBytes, 32);

  const rsaEncryptedKeyBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    rsaPublicKey,
    keyAndIvBytes.buffer
  );

  const rsaPart = new Uint8Array(rsaEncryptedKeyBuffer);
  const gcmPart = new Uint8Array(aesGcmCipherBuffer);
  const combinedEnvelope = new Uint8Array(rsaPart.byteLength + gcmPart.byteLength);
  combinedEnvelope.set(rsaPart, 0);
  combinedEnvelope.set(gcmPart, rsaPart.byteLength);

  return arrayBufferToBase64(combinedEnvelope.buffer);
}

export const createNullFilterToken = createOriginLockToken;

/**
 * Intercepts an HTMLFormElement's submit lifecycle, generates a cryptographic attestation token,
 * injects it into `<input type="hidden" name="_originlock_token">`, and submits the form.
 * Returns a cleanup function to detach the listener.
 */
export function protectForm(
  formElement: HTMLFormElement,
  options: OriginLockClientOptions
): () => void {
  let hiddenInput = formElement.querySelector<HTMLInputElement>(
    'input[name="_originlock_token"]'
  );

  if (!hiddenInput) {
    hiddenInput = document.createElement('input');
    hiddenInput.type = 'hidden';
    hiddenInput.name = '_originlock_token';
    formElement.appendChild(hiddenInput);
  }

  const handler = async (event: SubmitEvent) => {
    event.preventDefault();
    try {
      const token = await createOriginLockToken(options);
      if (hiddenInput) {
        hiddenInput.value = token;
      }
    } finally {
      HTMLFormElement.prototype.submit.call(formElement);
    }
  };

  formElement.addEventListener('submit', handler);
  return () => {
    formElement.removeEventListener('submit', handler);
  };
}

/**
 * Creates a wrapped `fetch` function that automatically generates and attaches
 * the `x-originlock-token` header on every outgoing request.
 */
export function createProtectedFetch(
  options: OriginLockClientOptions,
  baseFetch: typeof fetch = fetch
): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const token = await createOriginLockToken(options);
    const headers = new Headers(init?.headers);
    headers.set('x-originlock-token', token);
    headers.set('x-nullfilter-token', token);

    return baseFetch(input, {
      ...init,
      headers,
    });
  };
}

export * from './fingerprint';
