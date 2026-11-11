import { OriginLockConfig, VerificationResult } from '@nullfilter/core';

function escapeCefHeaderField(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ');
}

function escapeCefExtensionValue(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/[\r\n]+/g, ' ');
}

/**
 * Formats a `VerificationResult` into an ArcSight / Microsoft Sentinel Common Event Format (CEF) string
 * with full CRLF and delimiter injection sanitization.
 */
export function formatCefAlert(result: VerificationResult): string {
  const details = result.threatDetails;
  const srcIp = escapeCefExtensionValue(details?.proxyExitIp ?? '0.0.0.0');
  const actualOrigin = escapeCefExtensionValue(details?.actualClientOrigin ?? 'unknown');
  const actualHost = escapeCefExtensionValue(details?.actualClientHostname ?? 'unknown');
  const expectedOrigins = escapeCefExtensionValue(
    (details?.expectedOrigins ?? []).join(',') || 'unknown'
  );
  const userAgent = escapeCefExtensionValue(details?.userAgent ?? 'unknown');
  const canaryId = escapeCefExtensionValue(details?.canaryId ?? 'none');
  const status = escapeCefHeaderField(result.status);
  const reason = escapeCefHeaderField(result.reason);

  const extensions = [
    `src=${srcIp}`,
    `shost=${actualHost}`,
    `request=${actualOrigin}`,
    `cs1Label=ExpectedOrigins`,
    `cs1=${expectedOrigins}`,
    `cs2Label=CanaryTokenId`,
    `cs2=${canaryId}`,
    `requestClientApplication=${userAgent}`,
    `msg=${ escapeCefExtensionValue(result.reason) }`,
  ].join(' ');

  return `CEF:0|NullFilter|OriginLockShield|1.0|${status}|${reason}|10|${extensions}`;
}

async function postJsonWithTimeout(
  url: string,
  body: Record<string, unknown>,
  timeoutMs: number
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'NullFilter-OriginLock-SIEM-Dispatcher/1.0',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    // Non-blocking alert telemetry; network failures must not fail request verification
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Dispatches real-time threat intelligence alerts to configured Slack, Discord,
 * and Microsoft Sentinel / SIEM webhook endpoints.
 */
export async function dispatchThreatWebhook(
  result: VerificationResult,
  config?: OriginLockConfig['webhookConfig']
): Promise<void> {
  if (!config) {
    return;
  }

  const timeoutMs = config.timeoutMs ?? 3000;
  const cefRecord = formatCefAlert(result);
  const details = result.threatDetails;
  const tasks: Promise<void>[] = [];

  if (config.slackWebhookUrl) {
    tasks.push(
      postJsonWithTimeout(
        config.slackWebhookUrl,
        {
          text: `*[ALERT: ${result.status}]* AiTM Reverse Proxy Phishing Attempt Detected`,
          attachments: [
            {
              color: '#ef4444',
              fields: [
                {
                  title: 'Phishing Origin (Decrypted DOM)',
                  value: details?.actualClientOrigin ?? 'unknown',
                  short: true,
                },
                {
                  title: 'Expected Origins',
                  value: (details?.expectedOrigins ?? []).join(', '),
                  short: true,
                },
                {
                  title: 'Attacker Proxy Exit IP',
                  value: details?.proxyExitIp ?? 'unknown',
                  short: true,
                },
                {
                  title: 'Honeypot Canary ID',
                  value: details?.canaryId ?? 'disabled',
                  short: true,
                },
                {
                  title: 'CEF Log Record',
                  value: `\`${cefRecord}\``,
                  short: false,
                },
              ],
            },
          ],
        },
        timeoutMs
      )
    );
  }

  if (config.discordWebhookUrl) {
    tasks.push(
      postJsonWithTimeout(
        config.discordWebhookUrl,
        {
          username: 'NullFilter SOC Shield',
          embeds: [
            {
              title: `🚨 ${result.status}`,
              description: result.reason,
              color: 0xef4444,
              timestamp: details?.timestamp ?? new Date().toISOString(),
              fields: [
                {
                  name: 'Phishing Origin',
                  value: `\`${details?.actualClientOrigin ?? 'unknown'}\``,
                  inline: true,
                },
                {
                  name: 'Expected Origin',
                  value: `\`${(details?.expectedOrigins ?? []).join(', ')}\``,
                  inline: true,
                },
                {
                  name: 'Proxy Exit IP',
                  value: `\`${details?.proxyExitIp ?? 'unknown'}\``,
                  inline: true,
                },
                {
                  name: 'Canary ID',
                  value: `\`${details?.canaryId ?? 'none'}\``,
                  inline: true,
                },
              ],
            },
          ],
        },
        timeoutMs
      )
    );
  }

  if (config.sentinelWebhookUrl) {
    tasks.push(
      postJsonWithTimeout(
        config.sentinelWebhookUrl,
        {
           EventVendor: 'NullFilter',
          EventProduct: 'OriginLockShield',
          EventVersion: '1.0.0',
          Severity: 'High',
          VerdictStatus: result.status,
          Reason: result.reason,
          CefMessage: cefRecord,
          ThreatDetails: details ?? {},
          DecryptedTelemetry: result.decryptedPayload ?? null,
        },
        timeoutMs
      )
    );
  }

  if (tasks.length > 0) {
    await Promise.allSettled(tasks);
  }
}
