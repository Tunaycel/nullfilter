import {
  computeChallengeProof,
  decryptTelemetryPayload,
  generateNonce,
  generatePolymorphicClientScript,
  OriginLockConfig,
  TelemetryPayload,
  ThreatVerdictStatus,
  VerificationResult,
  verifyChallengeProof,
  verifyNonce,
} from '@nullfilter/core';
import { generatePoisonedSession } from './honeypot';
import { dispatchThreatWebhook, formatCefAlert } from './webhooks';

export interface VerifyRequestParams {
  token?: string;
  clientIp: string;
  userAgent: string;
  forwardedFor?: string;
  username?: string;
  silenceConsoleAlert?: boolean;
}

export interface IssuedChallenge {
  nonce: string;
  challengeProof: string;
  script: string;
}

const HEADLESS_GPU_OR_UA_REGEX =
  /swiftshader|llvmpipe|mesa offscreen|virtualbox|headlesschrome|phantomjs|puppeteer|playwright|selenium/i;

function normalizeOrigin(origin: string): string {
  return origin.trim().toLowerCase().replace(/\/+$/, '');
}

function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/:\d+$/, '');
}

/**
 * Primary server-side verification and active defense engine.
 * Manages single-use nonce issuance, polymorphic probe generation, RSA-OAEP/AES-GCM
 * telemetry decryption, origin/RTT verification, and honeypot session poisoning.
 */
export class OriginLockShield {
  private readonly config: Required<
    Pick<
      OriginLockConfig,
      | 'maxTokenAgeMs'
      | 'maxAllowedRttMs'
      | 'enableHoneypotPoisoning'
      | 'maxNonceCacheSize'
      | 'enforceChallengeProof'
      | 'blockHeadlessAutomation'
      | 'enforceUserAgentBinding'
    >
  > &
    OriginLockConfig;

  private readonly usedNoncesSet: Set<string>;
  private readonly normalizedAllowedHostnames: Set<string>;
  private readonly normalizedAllowedOrigins: Set<string>;

  constructor(config: OriginLockConfig) {
    if (!config.publicKeyPem || !config.privateKeyPem) {
      throw new Error('OriginLockShield requires both publicKeyPem and privateKeyPem.');
    }
    if (!config.hmacSecret || config.hmacSecret.length < 16) {
      throw new Error('OriginLockShield requires an hmacSecret of at least 16 characters.');
    }

    this.config = {
      ...config,
      maxTokenAgeMs: config.maxTokenAgeMs ?? 25_000,
      maxAllowedRttMs: config.maxAllowedRttMs ?? 1_500,
      enableHoneypotPoisoning: config.enableHoneypotPoisoning ?? true,
      maxNonceCacheSize: config.maxNonceCacheSize ?? 50_000,
      enforceChallengeProof: config.enforceChallengeProof ?? true,
      blockHeadlessAutomation: config.blockHeadlessAutomation ?? true,
      enforceUserAgentBinding: config.enforceUserAgentBinding ?? true,
    };

    this.usedNoncesSet = new Set<string>();
    this.normalizedAllowedHostnames = new Set(
      config.allowedHostnames.map((h) => normalizeHostname(h))
    );
    this.normalizedAllowedOrigins = new Set(
      config.allowedOrigins.map((o) => normalizeOrigin(o))
    );
  }

  /**
   * Issues a fresh HMAC-signed nonce, a split polymorphic challenge proof, and a uniquely mutated client probe script.
   */
  public issueChallenge(clientIp?: string, pingEndpoint = '/api/ping'): IssuedChallenge {
    const nonce = generateNonce(this.config.hmacSecret, clientIp);
    const challengeProof = computeChallengeProof(nonce, this.config.hmacSecret);
    const script = generatePolymorphicClientScript(
      this.config.publicKeyPem,
      nonce,
      pingEndpoint,
      challengeProof
    );
    return { nonce, challengeProof, script };
  }

  private async finalizeHighRiskBlock(
    status: ThreatVerdictStatus,
    reason: string,
    payload: TelemetryPayload,
    params: VerifyRequestParams,
    nowIso: string,
    riskScore: number
  ): Promise<VerificationResult> {
    let poisonedCookieHeader: string | undefined;
    let canaryId: string | undefined;

    if (this.config.enableHoneypotPoisoning) {
      const artifact = generatePoisonedSession(
        payload.origin || payload.hostname || 'unknown-origin',
        params.username ?? 'targeted-user',
        this.config.hmacSecret
      );
      poisonedCookieHeader = artifact.setCookieHeader;
      canaryId = artifact.canaryId;
    }

    const result: VerificationResult = {
      allowed: false,
      status,
      reason,
      decryptedPayload: payload,
      threatDetails: {
        expectedOrigins: this.config.allowedOrigins,
        actualClientOrigin: payload.origin,
        actualClientHostname: payload.hostname,
        proxyExitIp: params.clientIp,
        forwardedFor: params.forwardedFor,
        userAgent: params.userAgent || payload.userAgent,
        rttDeltaMs: payload.rttMs,
        timestamp: nowIso,
        poisonedCookieHeader,
        canaryId,
        riskScore,
      },
    };

    result.threatDetails!.cefRecord = formatCefAlert(result);

    if (!params.silenceConsoleAlert) {
      this.printTerminalSecurityAlert(result, params.username);
    }

    if (this.config.onThreatDetected) {
      await Promise.resolve(this.config.onThreatDetected(result)).catch(() => {});
    }

    void dispatchThreatWebhook(result, this.config.webhookConfig);

    return result;
  }

  /**
   * Executes the full multi-stage cryptographic origin & adversarial counter-bypass pipeline.
   */
  public async verifyRequest(params: VerifyRequestParams): Promise<VerificationResult> {
    const nowIso = new Date().toISOString();

    if (!params.token || typeof params.token !== 'string' || params.token.trim().length === 0) {
      return {
        allowed: false,
        status: 'BLOCK_MISSING_TOKEN',
        reason: 'Missing cryptographic origin attestation token (x-originlock-token / _originlock_token).',
        threatDetails: {
          expectedOrigins: this.config.allowedOrigins,
          actualClientOrigin: 'missing',
          actualClientHostname: 'missing',
          proxyExitIp: params.clientIp,
          forwardedFor: params.forwardedFor,
          userAgent: params.userAgent,
          timestamp: nowIso,
          riskScore: 85,
        },
      };
    }

    let payload: TelemetryPayload;
    try {
      payload = decryptTelemetryPayload(params.token, this.config.privateKeyPem);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Unknown decryption error';
      return {
        allowed: false,
        status: 'BLOCK_TAMPERED_CIPHERTEXT',
        reason: `RSA-OAEP / AES-GCM envelope decryption failed (${errMsg}).`,
        threatDetails: {
          expectedOrigins: this.config.allowedOrigins,
          actualClientOrigin: 'undecryptable',
          actualClientHostname: 'undecryptable',
          proxyExitIp: params.clientIp,
          forwardedFor: params.forwardedFor,
          userAgent: params.userAgent,
          timestamp: nowIso,
          riskScore: 95,
        },
      };
    }

    const nonceCheck = verifyNonce(
      payload.nonce,
      this.config.hmacSecret,
      this.config.maxTokenAgeMs,
      this.usedNoncesSet,
      params.clientIp,
      this.config.maxNonceCacheSize
    );

    if (!nonceCheck.valid) {
      const verdictStatus =
        nonceCheck.status === 'EXPIRED_TOKEN' ? 'BLOCK_EXPIRED_TOKEN' : 'BLOCK_INVALID_NONCE';
      return {
        allowed: false,
        status: verdictStatus,
        reason: nonceCheck.reason,
        decryptedPayload: payload,
        threatDetails: {
          expectedOrigins: this.config.allowedOrigins,
          actualClientOrigin: payload.origin,
          actualClientHostname: payload.hostname,
          proxyExitIp: params.clientIp,
          forwardedFor: params.forwardedFor,
          userAgent: params.userAgent,
          timestamp: nowIso,
          riskScore: 90,
        },
      };
    }

    if (payload.domIntegrityValid === false) {
      return this.finalizeHighRiskBlock(
        'BLOCK_DOM_INTEGRITY_VIOLATION',
        'Browser WebCrypto / Function.prototype.toString / JSON.stringify integrity check failed (pre-script monkey-patching detected).',
        payload,
        params,
        nowIso,
        98
      );
    }

    if (this.config.enforceChallengeProof) {
      const proofValid = verifyChallengeProof(
        payload.nonce,
        payload.challengeProof,
        this.config.hmacSecret
      );
      if (!proofValid) {
        return this.finalizeHighRiskBlock(
          'BLOCK_FORGED_TOKEN_ORACLE',
          'Server-side token-oracle forgery detected! Payload lacked a valid polymorphic closure challengeProof for the issued nonce.',
          payload,
          params,
          nowIso,
          100
        );
      }
    }

    if (this.config.blockHeadlessAutomation) {
      const isHeadlessGpuOrUa =
        HEADLESS_GPU_OR_UA_REGEX.test(payload.webglRenderer || '') ||
        HEADLESS_GPU_OR_UA_REGEX.test(payload.userAgent || '');
      if (payload.webdriver === true || isHeadlessGpuOrUa) {
        return this.finalizeHighRiskBlock(
          'BLOCK_HEADLESS_AUTOMATION',
          `Headless browser / automated token-harvesting farm detected (webdriver=${String(payload.webdriver)}, webglRenderer='${payload.webglRenderer}').`,
          payload,
          params,
          nowIso,
          96
        );
      }
    }

    if (this.config.enforceUserAgentBinding) {
      const reqUa = (params.userAgent || '').trim();
      const payloadUa = (payload.userAgent || '').trim();
      if (reqUa.length > 0 && payloadUa.length > 0 && reqUa !== 'node' && reqUa !== payloadUa) {
        return this.finalizeHighRiskBlock(
          'BLOCK_CONTEXT_BINDING_MISMATCH',
          `Cross-browser token relay detected! Encrypted telemetry User-Agent ('${payloadUa.slice(0, 48)}...') does not match HTTP request User-Agent ('${reqUa.slice(0, 48)}...').`,
          payload,
          params,
          nowIso,
          97
        );
      }
    }

    const actualHostNorm = normalizeHostname(payload.hostname);
    const actualOriginNorm = normalizeOrigin(payload.origin);

    const isHostnameAllowed = this.normalizedAllowedHostnames.has(actualHostNorm);
    const isOriginAllowed = this.normalizedAllowedOrigins.has(actualOriginNorm);

    if (!isHostnameAllowed || !isOriginAllowed) {
      return this.finalizeHighRiskBlock(
        'BLOCK_AITM_ORIGIN_MISMATCH',
        `AiTM Reverse Proxy detected! Browser executed on '${payload.origin}' (hostname: '${payload.hostname}'), which violates allowed origins [${this.config.allowedOrigins.join(', ')}].`,
        payload,
        params,
        nowIso,
        100
      );
    }

    if (payload.rttMs > this.config.maxAllowedRttMs) {
      return {
        allowed: false,
        status: 'BLOCK_ANOMALOUS_RTT',
        reason: `Application RTT (${payload.rttMs}ms) exceeded maximum threshold (${this.config.maxAllowedRttMs}ms), indicating multi-hop relay latency.`,
        decryptedPayload: payload,
        threatDetails: {
          expectedOrigins: this.config.allowedOrigins,
          actualClientOrigin: payload.origin,
          actualClientHostname: payload.hostname,
          proxyExitIp: params.clientIp,
          forwardedFor: params.forwardedFor,
          userAgent: params.userAgent,
          rttDeltaMs: payload.rttMs - this.config.maxAllowedRttMs,
          timestamp: nowIso,
          riskScore: 75,
        },
      };
    }

    return {
      allowed: true,
      status: 'ALLOW',
      reason: `Cryptographic origin attestation verified (${payload.origin}).`,
      decryptedPayload: payload,
    };
  }

  private printTerminalSecurityAlert(result: VerificationResult, username?: string): void {
    const d = result.threatDetails;
    const p = result.decryptedPayload;
    const red = '\x1b[31m';
    const boldRed = '\x1b[1;31m';
    const yellow = '\x1b[33m';
    const cyan = '\x1b[36m';
    const green = '\x1b[32m';
    const reset = '\x1b[0m';

    const lines = [
      '',
      `${boldRed}╔══════════════════════════════════════════════════════════════════════════════╗${reset}`,
      `${boldRed}║  🚨 [NULLFILTER / ORIGINLOCK] CRITICAL AiTM REVERSE PROXY PHISHING ALERT 🚨  ║${reset}`,
      `${boldRed}╠══════════════════════════════════════════════════════════════════════════════╣${reset}`,
      `${red}║${reset}  ${yellow}Verdict Status     :${reset} ${boldRed}${result.status}${reset}`,
      `${red}║${reset}  ${yellow}Targeted Account   :${reset} ${cyan}${username ?? 'N/A'}${reset}`,
      `${red}║${reset}  ${yellow}Expected Origin(s) :${reset} ${green}${(d?.expectedOrigins ?? []).join(', ')}${reset}`,
      `${red}║${reset}  ${yellow}Decrypted Origin   :${reset} ${boldRed}${d?.actualClientOrigin ?? 'unknown'} (MISMATCH!)${reset}`,
      `${red}║${reset}  ${yellow}Decrypted Hostname :${reset} ${boldRed}${d?.actualClientHostname ?? 'unknown'}${reset}`,
      `${red}║${reset}  ${yellow}Proxy Exit IP      :${reset} ${cyan}${d?.proxyExitIp ?? 'unknown'}${reset}`,
      `${red}║${reset}  ${yellow}Canvas HW Digest   :${reset} ${cyan}${p?.canvasHash ?? 'unknown'}${reset}`,
      `${red}║${reset}  ${yellow}Measured RTT       :${reset} ${cyan}${p?.rttMs ?? 0} ms${reset}`,
      `${red}║${reset}  ${yellow}Honeypot Poisoning :${reset} ${
        d?.canaryId
          ? `${green}ACTIVE (Canary ID: ${d.canaryId} injected into proxy DB)${reset}`
          : 'DISABLED'
      }`,
      `${boldRed}╚══════════════════════════════════════════════════════════════════════════════╝${reset}`,
      '',
    ];

    console.warn(lines.join('\n'));
  }
}

export const NullFilterShield = OriginLockShield;
