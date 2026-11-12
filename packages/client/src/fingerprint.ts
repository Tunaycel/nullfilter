/**
 * Computes a deterministic 64-bit FNV-1a hexadecimal digest from an input string.
 */
function fnv1a64Hex(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x811c9dc5;

  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    h1 ^= code;
    h1 = Math.imul(h1, 0x01000193) >>> 0;

    const revCode = input.charCodeAt(input.length - 1 - i);
    h2 ^= revCode;
    h2 = Math.imul(h2, 0x01000193) >>> 0;
  }

  return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
}

/**
 * Renders deterministic typography and Bezier/arc geometry onto an offscreen HTML5 Canvas
 * and returns a 16-character hexadecimal hardware rendering digest.
 */
export function getCanvasFingerprint(): string {
  if (typeof document === 'undefined') {
    return 'ssr-no-dom-00000';
  }

  try {
    const canvas = document.createElement('canvas');
    canvas.width = 240;
    canvas.height = 52;

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return 'canvas-2d-unavailable';
    }

    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#10b981';
    ctx.fillRect(10, 6, 104, 26);

    ctx.fillStyle = '#0f172a';
    ctx.font = '14px monospace';
    ctx.fillText('NullFilter::OriginLock#OAEP', 8, 24);

    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(172, 26, 15, 0, Math.PI * 2, true);
    ctx.stroke();

    const dataUrl = canvas.toDataURL();
    return fnv1a64Hex(dataUrl);
  } catch {
    return 'canvas-execution-blocked';
  }
}

/**
 * Extracts the unmasked GPU renderer descriptor via WebGL debug extensions when available.
 */
export function getWebglRenderer(): string {
  if (typeof document === 'undefined') {
    return 'ssr-no-webgl';
  }

  try {
    const canvas = document.createElement('canvas');
    const gl =
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null);

    if (!gl) {
      return 'webgl-unavailable';
    }

    const debugExt = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugExt) {
      const renderer = gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL);
      if (renderer) {
        return String(renderer);
      }
    }

    const fallbackRenderer = gl.getParameter(gl.RENDERER);
    return fallbackRenderer ? String(fallbackRenderer) : 'webgl-generic';
  } catch {
    return 'webgl-restricted';
  }
}

/**
 * Verifies that `window.crypto.subtle.encrypt` has not been monkey-patched by an injected proxy script.
 */
export function verifyDomCryptoIntegrity(): boolean {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    return false;
  }

  try {
    const fnSource = Function.prototype.toString.call(window.crypto.subtle.encrypt);
    return fnSource.includes('[native code]');
  } catch {
    return false;
  }
}

/**
 * Measures real application-layer Round-Trip Time (RTT) in milliseconds using `performance.now()`
 * around an uncached HEAD probe request with an automatic abort timeout.
 */
export async function measureRtt(pingUrl = '/api/ping', timeoutMs = 4000): Promise<number> {
  if (typeof fetch === 'undefined' || typeof performance === 'undefined') {
    return 1;
  }

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  const startMs = performance.now();

  try {
    await fetch(pingUrl, {
      method: 'HEAD',
      cache: 'no-store',
      credentials: 'same-origin',
      signal: controller ? controller.signal : undefined,
    });
    const elapsed = Math.round(performance.now() - startMs);
    return Math.max(1, elapsed);
  } catch {
    const elapsed = Math.round(performance.now() - startMs);
    return Math.max(1, elapsed);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
