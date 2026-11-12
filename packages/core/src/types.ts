export interface TelemetryPayload {
  hostname: string;
  origin: string;
  port: string;
  pathname: string;
  referrer: string;
  userAgent: string;
  webdriver: boolean;
  canvasHash: string;
  rttMs: number;
  clientTimestamp: number;
  nonce: string;
  webglRenderer?: string;
  domIntegrityValid?: boolean;
}

export type ThreatVerdictStatus =
  | 'ALLOW'
  | 'BLOCK_AITM_ORIGIN_MISMATCH'
  | 'BLOCK_INVALID_NONCE'
  | 'BLOCK_EXPIRED_TOKEN'
  | 'BLOCK_TAMPERED_CIPHERTEXT'
  | 'BLOCK_MISSING_TOKEN'
  | 'BLOCK_ANOMALOUS_RTT'
  | 'BLOCK_DOM_INTEGRITY_VIOLATION';

export interface ThreatDetails {
  expectedOrigins: string[];
  actualClientOrigin: string;
  actualClientHostname: string;
  proxyExitIp: string;
  forwardedFor?: string;
  userAgent: string;
  rttDeltaMs?: number;
  timestamp: string;
  poisonedCookieHeader?: string;
  canaryId?: string;
  riskScore?: number;
  cefRecord?: string;
}

export interface VerificationResult {
  allowed: boolean;
  status: ThreatVerdictStatus;
  reason: string;
  decryptedPayload?: TelemetryPayload;
  threatDetails?: ThreatDetails;
}

export interface WebhookConfig {
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
  sentinelWebhookUrl?: string;
  timeoutMs?: number;
}

export interface OriginLockConfig {
  publicKeyPem: string;
  privateKeyPem: string;
  hmacSecret: string;
  allowedHostnames: string[];
  allowedOrigins: string[];
  maxTokenAgeMs?: number;
  maxAllowedRttMs?: number;
  enableHoneypotPoisoning?: boolean;
  maxNonceCacheSize?: number;
  webhookConfig?: WebhookConfig;
  onThreatDetected?: (result: VerificationResult) => void | Promise<void>;
}

export type NullFilterConfig = OriginLockConfig;
