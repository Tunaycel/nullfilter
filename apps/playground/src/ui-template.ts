export interface VaultUiRenderOptions {
  nonce: string;
  polymorphicScript: string;
}

/**
 * Renders the split-screen Dark-Mode Cybersecurity UI:
 * - Left Pane: QuellCloud Enterprise Vault Login Form protected by the polymorphic WebCrypto probe
 * - Right Pane: Real-Time SOC & Zero-Trust Telemetry Console powered by Server-Sent Events (SSE)
 */
export function renderVaultUi(options: VaultUiRenderOptions): string {
  const { nonce, polymorphicScript } = options;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>QuellCloud Enterprise Vault — NullFilter / OriginLock Zero-Trust Attestation</title>
  <style>
    :root {
      --bg-primary: #070b14;
      --bg-panel: #0f172a;
      --bg-card: #131d35;
      --bg-input: #091020;
      --border-subtle: #1e293b;
      --border-focus: #38bdf8;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-emerald: #10b981;
      --accent-emerald-bg: rgba(16, 185, 129, 0.12);
      --accent-crimson: #ef4444;
      --accent-crimson-bg: rgba(239, 68, 68, 0.14);
      --accent-amber: #f59e0b;
      --accent-amber-bg: rgba(245, 158, 11, 0.14);
      --accent-cyan: #38bdf8;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-primary);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* Top Environment Switcher Bar */
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 24px;
      background: #050811;
      border-bottom: 1px solid var(--border-subtle);
      flex-wrap: wrap;
      gap: 12px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 15px;
      letter-spacing: 0.4px;
    }

    .brand-shield {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: linear-gradient(135deg, #10b981, #0ea5e9);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: #041019;
      font-weight: 900;
      font-family: var(--font-mono);
    }

    .origin-badge {
      padding: 6px 14px;
      border-radius: 999px;
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid transparent;
    }

    .origin-badge.legit {
      background: var(--accent-emerald-bg);
      color: var(--accent-emerald);
      border-color: rgba(16, 185, 129, 0.35);
    }

    .origin-badge.proxy {
      background: var(--accent-crimson-bg);
      color: #fca5a5;
      border-color: rgba(239, 68, 68, 0.5);
      animation: pulseAlert 2s infinite;
    }

    @keyframes pulseAlert {
      0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
      50% { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
    }

    .env-switch {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .env-btn {
      text-decoration: none;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-family: var(--font-mono);
      font-weight: 600;
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      background: var(--bg-panel);
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .env-btn:hover {
      border-color: var(--accent-cyan);
      color: var(--text-primary);
    }

    .env-btn.danger:hover {
      border-color: var(--accent-crimson);
      color: #fca5a5;
    }

    /* Main Split Layout */
    .split-layout {
      display: grid;
      grid-template-columns: 480px 1fr;
      flex: 1;
      min-height: calc(100vh - 55px);
    }

    @media (max-width: 1080px) {
      .split-layout {
        grid-template-columns: 1fr;
      }
    }

    /* Left Pane: Enterprise Vault Login */
    .vault-pane {
      background: var(--bg-panel);
      border-right: 1px solid var(--border-subtle);
      padding: 28px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 20px;
    }

    .vault-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35);
    }

    .vault-header {
      margin-bottom: 20px;
    }

    .vault-header h1 {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .vault-header p {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.5;
    }

    .form-group {
      margin-bottom: 15px;
    }

    .form-group label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }

    .form-control {
      width: 100%;
      padding: 11px 13px;
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s ease;
    }

    .form-control:focus {
      border-color: var(--border-focus);
    }

    .btn-submit {
      width: 100%;
      padding: 12px 16px;
      background: linear-gradient(135deg, #10b981, #059669);
      color: #03150e;
      font-weight: 700;
      font-size: 14px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: transform 0.1s ease, filter 0.15s ease;
      margin-top: 6px;
    }

    .btn-submit:hover {
      filter: brightness(1.08);
    }

    .btn-submit:active {
      transform: translateY(1px);
    }

    .response-banner {
      margin-top: 16px;
      padding: 14px;
      border-radius: 8px;
      font-size: 12.5px;
      font-family: var(--font-mono);
      line-height: 1.5;
      display: none;
      word-break: break-all;
    }

    .response-banner.success {
      display: block;
      background: var(--accent-emerald-bg);
      border: 1px solid rgba(16, 185, 129, 0.45);
      color: #6ee7b7;
    }

    .response-banner.trapped {
      display: block;
      background: var(--accent-crimson-bg);
      border: 1px solid rgba(239, 68, 68, 0.55);
      color: #fca5a5;
    }

    /* Probe Telemetry Box inside Left Pane */
    .probe-box {
      background: #091020;
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 11.5px;
    }

    .probe-box-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--accent-cyan);
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .probe-kv {
      display: grid;
      grid-template-columns: 125px 1fr;
      gap: 6px;
      margin-bottom: 6px;
      color: var(--text-secondary);
    }

    .probe-kv span:last-child {
      color: var(--text-primary);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* Right Pane: Live SOC Console */
    .soc-pane {
      padding: 28px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      background: var(--bg-primary);
      overflow-y: auto;
      max-height: calc(100vh - 55px);
    }

    .soc-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 14px;
    }

    .soc-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 16px;
      font-weight: 700;
    }

    .sse-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--accent-emerald);
      box-shadow: 0 0 10px var(--accent-emerald);
    }

    .metrics-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }

    @media (max-width: 768px) {
      .metrics-row {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    .metric-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 14px;
    }

    .metric-label {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 6px;
    }

    .metric-value {
      font-size: 20px;
      font-weight: 800;
      font-family: var(--font-mono);
    }

    .feed-container {
      display: flex;
      flex-direction: column;
      gap: 12px;
      flex: 1;
    }

    .event-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-left: 4px solid var(--accent-cyan);
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
    }

    .event-card.allow {
      border-left-color: var(--accent-emerald);
    }

    .event-card.aitm {
      border-left-color: var(--accent-crimson);
      background: rgba(239, 68, 68, 0.06);
      border-color: rgba(239, 68, 68, 0.35);
    }

    .event-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      font-weight: 700;
    }

    .verdict-pill {
      padding: 3px 9px;
      border-radius: 4px;
      font-size: 11px;
    }

    .verdict-pill.allow {
      background: var(--accent-emerald-bg);
      color: var(--accent-emerald);
    }

    .verdict-pill.aitm {
      background: var(--accent-crimson-bg);
      color: #fca5a5;
    }

    .Verdict-pill.rotation {
      background: rgba(56, 189, 248, 0.14);
      color: var(--accent-cyan);
    }

    .event-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
      background: #060a12;
      padding: 12px;
      border-radius: 6px;
      border: 1px solid #162032;
      margin-top: 8px;
    }

    .event-grid div {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .cef-bar {
      margin-top: 10px;
      padding: 8px 10px;
      background: #04070d;
      border: 1px dashed #334155;
      border-radius: 4px;
      color: #cbd5e1;
      font-size: 11px;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-shield">NF</span>
      <span>QuellCloud Enterprise Vault &mdash; NullFilter / OriginLock Zero-Trust Attestation</span>
    </div>
    <div id="originBadge" class="origin-badge legit">
      <span>Checking Execution Origin...</span>
    </div>
    <div class="env-switch">
      <button type="button" class="env-btn" id="btnGoLegit">Legitimate Vault (:3000)</button>
      <button type="button" class="env-btn danger" id="btnGoProxy">Evilginx AiTM Proxy (:8080)</button>
    </div>
  </header>

  <main class="split-layout">
    <!-- Left Pane: Protected Enterprise Login Form -->
    <section class="vault-pane">
      <div class="vault-card">
        <div class="vault-header">
          <h1>QuellCloud Root Key Vault</h1>
          <p>Passkey (WebAuthn ES256) authentication boundary + NullFilter commodity AiTM telemetry &amp; Canary deception.</p>
        </div>

        <!-- Primary Authentication Boundary: FIDO2 / WebAuthn Passkey -->
        <div style="border: 1px solid rgba(16, 185, 129, 0.35); background: rgba(16, 185, 129, 0.06); border-radius: 10px; padding: 14px; margin-bottom: 18px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;">
            <strong style="color: var(--accent-emerald); font-size: 13px;">🔐 Primary Auth Boundary: FIDO2 / WebAuthn Passkey (ES256)</strong>
            <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">rpId: localhost</span>
          </div>
          <p style="font-size: 12px; color: var(--text-secondary); margin: 0 0 10px 0; line-height: 1.45;">
            <strong>localhost Port Simulation Note:</strong> Because <code>rpId</code> is host-only (<code>localhost</code>), the browser signs on both <code>:3000</code> and <code>:8080</code>. This demo exercises the <strong>second line of defense</strong> (server-side <code>clientDataJSON.origin</code> verification). On real lookalike domains (<code>quellcloud.com</code> vs <code>quellcl0ud.com</code>), the <strong>first line of defense</strong> (<code>rpId</code>) fails silently in the browser.
          </p>
          <div style="display:flex; gap: 8px; flex-wrap: wrap;">
            <button type="button" id="btnRegisterPasskey" class="env-btn" style="flex:1; background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.45); color: #34d399; font-weight: 600;">
              1. Register Passkey (:3000 Only)
            </button>
            <button type="button" id="btnLoginPasskey" class="env-btn" style="flex:1; background: rgba(56, 189, 248, 0.15); border-color: rgba(56, 189, 248, 0.45); color: #38bdf8; font-weight: 600;">
              2. Sign In with Passkey
            </button>
          </div>
          <div id="webauthnResponseBanner" class="response-banner" style="margin-top: 10px;"></div>
        </div>

        <!-- Explicitly Labeled Fallback Downgrade Vector -->
        <div style="border: 1px dashed rgba(245, 158, 11, 0.45); border-radius: 10px; padding: 14px; margin-bottom: 8px;">
          <div style="margin-bottom: 10px;">
            <strong style="color: #fbbf24; font-size: 12px;">⚠️ Fallback Password + TOTP Form (Phishable Downgrade Vector)</strong>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">
              Kept open intentionally: if password/OTP fallback remains enabled, a phishlet can hide the Passkey button and downgrade victims here.
            </div>
          </div>

          <form id="vaultLoginForm" action="/api/login" method="POST" data-originlock="true">
          <div class="form-group">
            <label for="username">Enterprise Principal (Email)</label>
            <input
              id="username"
              name="username"
              type="text"
              class="form-control"
              value="h.tunay@quellcloud.com"
              autocomplete="username"
              required
            />
          </div>

          <div class="form-group">
            <label for="password">Master Vault Passphrase</label>
            <input
              id="password"
              name="password"
              type="password"
              class="form-control"
              value="QCloud#ZeroTrust!2026"
              autocomplete="current-password"
              required
            />
          </div>

          <div class="form-group">
            <label for="totp_code">Hardware 2FA / TOTP Code</label>
            <input
              id="totp_code"
              name="totp_code"
              type="text"
              class="form-control"
              value="492817"
              maxlength="6"
              required
            />
          </div>

          <div class="form-group">
            <label for="shield_mode">Server Defense Mode (Live Comparison)</label>
            <select id="shield_mode" name="_shield_mode" class="form-control">
              <option value="ON" selected>🛡️ NullFilter Shield: ON (RSA-OAEP DOM Attestation + Honeypot)</option>
              <option value="OFF">🔓 NullFilter Shield: OFF (Standard Server — Header Check Only)</option>
            </select>
          </div>

          <input type="hidden" name="_originlock_token" id="originlockTokenInput" value="" />

          <button type="submit" class="btn-submit" id="submitBtn">
            Authenticate &amp; Seal Origin Telemetry
          </button>
        </form>
        </div>

        <div id="loginResponseBanner" class="response-banner"></div>
      </div>

      <div class="probe-box">
        <div class="probe-box-title">
          <span>Active Polymorphic Runtime Probe</span>
          <span style="color: var(--accent-emerald);">RSA-OAEP-2048 + AES-256-GCM</span>
        </div>
        <div class="probe-kv">
          <span>DOM Origin:</span>
          <span id="probeOriginText">-</span>
        </div>
        <div class="probe-kv">
          <span>Server Nonce:</span>
          <span id="probeNonceText">${nonce}</span>
        </div>
        <div class="probe-kv">
          <span>Mutated Probe ID:</span>
          <span id="probeFnIdText">-</span>
        </div>
        <div class="probe-kv">
          <span>Per-Load XOR Key:</span>
          <span id="probeXorKeyText">-</span>
        </div>
        <div class="probe-kv">
          <span>Ciphertext Preview:</span>
          <span id="probeCipherPreview">Generating WebCrypto seal...</span>
        </div>
      </div>
    </section>

    <!-- Right Pane: Real-time SSE SOC Telemetry Console -->
    <section class="soc-pane">
      <div class="soc-header">
        <div class="soc-title">
          <span class="sse-dot" id="sseStatusDot"></span>
          <span>Live SOC &amp; Zero-Trust Telemetry Console (SSE Stream)</span>
        </div>
        <span style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);" id="sseConnectionLabel">
          Connected to :3000/api/events
        </span>
      </div>

      <div class="metrics-row">
        <div class="metric-card">
          <div class="metric-label">Verified Logins</div>
          <div class="metric-value" style="color: var(--accent-emerald);" id="metricAllowCount">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">AiTM Proxy Blocks</div>
          <div class="metric-value" style="color: var(--accent-crimson);" id="metricAitmCount">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Canaries Injected</div>
          <div class="metric-value" style="color: var(--accent-amber);" id="metricCanaryCount">0</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Polymorphic Mutations</div>
          <div class="metric-value" style="color: var(--accent-cyan);" id="metricRotationCount">1</div>
        </div>
      </div>

      <div class="feed-container" id="socEventFeed"></div>
    </section>
  </main>

  <!-- Polymorphic Per-Request Probe Script -->
  <script>${polymorphicScript}</script>

  <!-- Interactive Playground Controller & SSE Listener -->
  <script>
    (function () {
      var legitPort = String(1500 * 2);
      var proxyPort = String(4040 * 2);
      var currentOrigin = window.location.origin;
      var currentPort = window.location.port || (window.location.protocol === 'https:' ? '443' : '80');

      var badge = document.getElementById('originBadge');
      var probeOriginText = document.getElementById('probeOriginText');
      var probeFnIdText = document.getElementById('probeFnIdText');
      var probeXorKeyText = document.getElementById('probeXorKeyText');
      var probeCipherPreview = document.getElementById('probeCipherPreview');

      probeOriginText.textContent = currentOrigin;

      if (currentPort === legitPort) {
        badge.className = 'origin-badge legit';
        badge.textContent = 'LEGITIMATE ORIGIN: ' + currentOrigin + ' (Direct TLS/HTTP)';
      } else {
        badge.className = 'origin-badge proxy';
        badge.textContent = 'AiTM PHISHING PROXY ACTIVE: ' + currentOrigin + ' (Relaying to :' + legitPort + ')';
      }

      document.getElementById('btnGoLegit').addEventListener('click', function () {
        window.location.href = 'http://localhost:' + legitPort + '/';
      });
      document.getElementById('btnGoProxy').addEventListener('click', function () {
        window.location.href = 'http://localhost:' + proxyPort + '/';
      });

      if (window.__OriginLock) {
        probeFnIdText.textContent = window.__OriginLock.probeId + '()';
        probeXorKeyText.textContent = '0x' + window.__OriginLock.xorKeyHex;
        window.__OriginLock.getToken().then(function (tok) {
          var input = document.getElementById('originlockTokenInput');
          if (input) input.value = tok;
          probeCipherPreview.textContent = tok.slice(0, 44) + '... (' + tok.length + ' chars)';
        });
      }

      var allowCount = 0;
      var aitmCount = 0;
      var canaryCount = 0;
      var rotationCount = 1;

      function escapeHtml(raw) {
        return String(raw == null ? '' : raw)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function renderSocEvent(evt) {
        var feed = document.getElementById('socEventFeed');
        var card = document.createElement('div');

        if (evt.type === 'WEBAUTHN_EVENT') {
          var wv = evt.webauthnVerdict || {};
          if (wv.allowed) {
            allowCount++;
            document.getElementById('metricAllowCount').textContent = String(allowCount);
            card.className = 'event-card allow';
            card.innerHTML =
              '<div class="event-top">' +
                '<span class="verdict-pill allow">🔐 WEBAUTHN ' + escapeHtml(evt.webauthnAction || 'LOGIN') + ': ' + escapeHtml(wv.status) + '</span>' +
                '<span style="color: var(--text-muted);">' + escapeHtml(evt.timestamp || '') + '</span>' +
              '</div>' +
              '<div>' + escapeHtml(wv.reason || '') + '</div>' +
              '<div class="event-grid">' +
                '<div><strong>Verified Origin:</strong> <span style="color:#10b981;">' + escapeHtml(wv.verifiedOrigin || 'N/A') + '</span></div>' +
                '<div><strong>Spoofed HTTP Origin:</strong> ' + escapeHtml(evt.observedHttpOrigin || 'N/A') + '</div>' +
              '</div>';
          } else {
            aitmCount++;
            document.getElementById('metricAitmCount').textContent = String(aitmCount);
            card.className = 'event-card aitm';
            card.innerHTML =
              '<div class="event-top">' +
                '<span class="verdict-pill aitm">🛡️ WEBAUTHN BLOCK: ' + escapeHtml(wv.status || 'REJECTED') + '</span>' +
                '<span style="color: var(--text-muted);">' + escapeHtml(evt.timestamp || '') + '</span>' +
              '</div>' +
              '<div style="color:#fca5a5; margin-bottom:6px;">' + escapeHtml(wv.reason || '') + '</div>' +
              '<div class="event-grid">' +
                '<div><strong>Spoofed HTTP Origin:</strong> <span style="color:#fbbf24;">' + escapeHtml(evt.observedHttpOrigin || 'N/A') + '</span></div>' +
                '<div><strong>Browser-Signed clientDataJSON.origin:</strong> <span style="color:#ef4444; font-weight:700;">' + escapeHtml(wv.verifiedOrigin || 'mismatch') + '</span></div>' +
              '</div>';
          }
          feed.prepend(card);
          return;
        }

        if (evt.type === 'POLYMORPHIC_ROTATION') {
          rotationCount++;
          document.getElementById('metricRotationCount').textContent = String(rotationCount);
          card.className = 'event-card';
          card.innerHTML =
            '<div class="event-top">' +
              '<span style="color: var(--accent-cyan);">[POLYMORPHIC ENGINE] Per-Request AST &amp; XOR Mutation</span>' +
              '<span style="color: var(--text-muted);">' + escapeHtml(evt.timestamp) + '</span>' +
            '</div>' +
            '<div>Generated unique probe closure &amp; HMAC-SHA256 challenge nonce: <code>' +
            escapeHtml((evt.nonce || '').slice(0, 36)) + '...</code></div>';
          feed.prepend(card);
          return;
        }

        var v = evt.verdict;
        var p = v.decryptedPayload || {};
        var d = v.threatDetails || {};

        if (evt.shieldMode === 'OFF') {
          card.className = 'event-card aitm';
          card.innerHTML =
            '<div class="event-top">' +
              '<span class="verdict-pill aitm">⚠️ SHIELD OFF — STANDARD SERVER COMPROMISED</span>' +
              '<span style="color: var(--text-muted);">' + escapeHtml(evt.timestamp || '') + '</span>' +
            '</div>' +
            '<div style="color:#fbbf24; margin-bottom:6px;">' + escapeHtml(v.reason) + '</div>' +
            '<div class="event-grid">' +
              '<div><strong>Spoofed HTTP Origin:</strong> <span style="color:#fbbf24;">' + escapeHtml(evt.observedHttpOrigin || 'N/A') + ' (Trusted Blindly!)</span></div>' +
              '<div><strong>DOM Crypto Check:</strong> <span style="color:#ef4444;">BYPASSED (Shield Disabled)</span></div>' +
              '<div><strong>Targeted User:</strong> ' + escapeHtml(evt.username || 'N/A') + '</div>' +
              '<div><strong>Result:</strong> <span style="color:#ef4444; font-weight:700;">REAL SESSION HIJACKED BY PROXY</span></div>' +
            '</div>';
          feed.prepend(card);
          return;
        }

        if (v.allowed) {
          allowCount++;
          document.getElementById('metricAllowCount').textContent = String(allowCount);
          card.className = 'event-card allow';
          card.innerHTML =
            '<div class="event-top">' +
              '<span class="verdict-pill allow">✔ VERDICT: ' + escapeHtml(v.status) + '</span>' +
              '<span style="color: var(--text-muted);">' + escapeHtml(evt.timestamp || '') + '</span>' +
            '</div>' +
            '<div>' + escapeHtml(v.reason) + '</div>' +
            '<div class="event-grid">' +
              '<div><strong>HTTP Origin Header:</strong> ' + escapeHtml(evt.observedHttpOrigin || 'N/A') + '</div>' +
              '<div><strong>Decrypted DOM Origin:</strong> <span style="color:#10b981;">' + escapeHtml(p.origin || 'N/A') + '</span></div>' +
              '<div><strong>Canvas HW Hash:</strong> ' + escapeHtml(p.canvasHash || 'N/A') + '</div>' +
              '<div><strong>Application RTT:</strong> ' + escapeHtml(p.rttMs || 0) + ' ms</div>' +
            '</div>';
        } else {
          aitmCount++;
          document.getElementById('metricAitmCount').textContent = String(aitmCount);
          if (d.canaryId) {
            canaryCount++;
            document.getElementById('metricCanaryCount').textContent = String(canaryCount);
          }
          card.className = 'event-card aitm';
          card.innerHTML =
            '<div class="event-top">' +
              '<span class="verdict-pill aitm">🚨 AiTM PHISHING DETECTED: ' + escapeHtml(v.status) + '</span>' +
              '<span style="color: var(--text-muted);">' + escapeHtml(d.timestamp || evt.timestamp || '') + '</span>' +
            '</div>' +
            '<div style="color:#fca5a5; margin-bottom:6px;">' + escapeHtml(v.reason) + '</div>' +
            '<div class="event-grid">' +
              '<div><strong>Spoofed HTTP Header:</strong> <span style="color:#fbbf24;">' + escapeHtml(evt.observedHttpOrigin || 'http://localhost:3000') + ' (Spoofed by Proxy!)</span></div>' +
              '<div><strong>Decrypted DOM Origin:</strong> <span style="color:#ef4444; font-weight:700;">' + escapeHtml(d.actualClientOrigin || p.origin || 'unknown') + ' (CAUGHT!)</span></div>' +
              '<div><strong>Targeted User:</strong> ' + escapeHtml(evt.username || 'N/A') + '</div>' +
              '<div><strong>Canary Poison ID:</strong> <span style="color:#10b981;">' + escapeHtml(d.canaryId || 'none') + '</span></div>' +
              '<div><strong>Canvas HW Hash:</strong> ' + escapeHtml(p.canvasHash || 'N/A') + '</div>' +
              '<div><strong>Measured RTT:</strong> ' + escapeHtml(p.rttMs || 0) + ' ms</div>' +
            '</div>' +
            (d.poisonedCookieHeader
              ? '<div class="cef-bar"><strong>Poisoned Set-Cookie Fed to Evilginx DB:</strong><br/>' + escapeHtml(d.poisonedCookieHeader) + '</div>'
              : '') +
            (d.cefRecord
              ? '<div class="cef-bar"><strong>SIEM / Sentinel CEF Record:</strong><br/>' + escapeHtml(d.cefRecord) + '</div>'
              : '');
        }

        feed.prepend(card);
      }

      // Connect SSE stream directly to Vault Server (:3000) so events appear whether browsing :3000 or :8080
      var sseUrl = 'http://localhost:' + legitPort + '/api/events';
      var es = new EventSource(sseUrl);
      es.onmessage = function (msg) {
        try {
          var parsed = JSON.parse(msg.data);
          renderSocEvent(parsed);
        } catch (_e) {}
      };
      es.onerror = function () {
        document.getElementById('sseStatusDot').style.background = '#f59e0b';
      };

      // WebAuthn / Passkey Helpers (Base64URL <-> ArrayBuffer)
      function b64UrlToUint8(b64Url) {
        var b64 = b64Url.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        var bin = window.atob(b64);
        var arr = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return arr;
      }

      function bufToB64Url(buf) {
        var bytes = new Uint8Array(buf);
        var bin = '';
        for (var i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
        return window.btoa(bin).split('+').join('-').split('/').join('_').replace(/=+$/, '');
      }

      var btnRegPasskey = document.getElementById('btnRegisterPasskey');
      var btnLoginPasskey = document.getElementById('btnLoginPasskey');
      var waBanner = document.getElementById('webauthnResponseBanner');

      if (currentPort !== legitPort && btnRegPasskey) {
        btnRegPasskey.disabled = true;
        btnRegPasskey.style.opacity = '0.5';
        btnRegPasskey.title = 'Registration is locked to :3000 to prevent TOFU session-hijack persistence.';
        btnRegPasskey.textContent = '1. Register Passkey (Locked on :8080)';
      }

      if (btnRegPasskey) {
        btnRegPasskey.addEventListener('click', async function () {
          try {
            if (!window.PublicKeyCredential) {
              throw new Error('WebAuthn PublicKeyCredential API is not supported in this browser.');
            }
            var token = window.__OriginLock ? await window.__OriginLock.getToken() : '';
            var optRes = await fetch('/api/webauthn/register/options', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-originlock-token': token
              },
              body: '{}'
            });
            var optData = await optRes.json();
            if (optData.nextNonce && window.__OriginLock && typeof window.__OriginLock.setNonce === 'function') {
              window.__OriginLock.setNonce(optData.nextNonce, optData.nextChallengeProof);
            }
            if (!optRes.ok) {
              throw new Error(optData.message || 'Registration denied');
            }

            var cred = await navigator.credentials.create({
              publicKey: {
                challenge: b64UrlToUint8(optData.challengeB64Url),
                rp: optData.rp,
                user: {
                  id: b64UrlToUint8(optData.user.idB64Url),
                  name: optData.user.name,
                  displayName: optData.user.displayName
                },
                pubKeyCredParams: optData.pubKeyCredParams,
                authenticatorSelection: {
                  userVerification: 'required',
                  residentKey: 'preferred'
                },
                attestation: 'none',
                timeout: 60000
              }
            });

            // Fail-closed check: require browser getPublicKey() SPKI export (no CBOR/COSE fallback)
            if (!cred || !cred.response || typeof cred.response.getPublicKey !== 'function') {
              throw new Error('Browser does not expose AuthenticatorAttestationResponse.getPublicKey() (fail-closed).');
            }
            var spkiBuf = cred.response.getPublicKey();
            if (!spkiBuf) {
              throw new Error('AuthenticatorAttestationResponse.getPublicKey() returned null (fail-closed).');
            }

            var verifyRes = await fetch('/api/webauthn/register/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                credentialId: cred.id,
                publicKeySpkiB64Url: bufToB64Url(spkiBuf)
              })
            });
            var verifyData = await verifyRes.json();
            if (!verifyRes.ok) {
              throw new Error(verifyData.message || 'Verification failed');
            }
            waBanner.className = 'response-banner success';
            waBanner.innerHTML = '<strong>✔ PASSKEY REGISTERED ON :3000</strong><br/>' + escapeHtml(verifyData.message) + '<br/>Switch to <strong>:8080 (Evilginx Proxy)</strong> and click Sign In with Passkey to observe server-side origin rejection.';
          } catch (err) {
            waBanner.className = 'response-banner trapped';
            waBanner.innerHTML = '<strong>✖ PASSKEY REGISTRATION ERROR</strong><br/>' + escapeHtml(err && err.message ? err.message : String(err));
          }
        });
      }

      if (btnLoginPasskey) {
        btnLoginPasskey.addEventListener('click', async function () {
          try {
            if (!window.PublicKeyCredential) {
              throw new Error('WebAuthn PublicKeyCredential API is not supported in this browser.');
            }
            var optRes = await fetch('/api/webauthn/login/options', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: '{}'
            });
            var optData = await optRes.json();
            var allowCreds = (optData.allowCredentials || []).map(function (id) {
              return { type: 'public-key', id: b64UrlToUint8(id) };
            });

            var assertion = await navigator.credentials.get({
              publicKey: {
                challenge: b64UrlToUint8(optData.challengeB64Url),
                rpId: optData.rpId,
                userVerification: 'required',
                allowCredentials: allowCreds,
                timeout: 60000
              }
            });

            var verifyRes = await fetch('/api/webauthn/login/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                credentialId: assertion.id,
                authenticatorDataB64Url: bufToB64Url(assertion.response.authenticatorData),
                clientDataJsonB64Url: bufToB64Url(assertion.response.clientDataJSON),
                signatureB64Url: bufToB64Url(assertion.response.signature)
              })
            });
            var verifyData = await verifyRes.json();
            if (verifyRes.ok && verifyData.status === 'WEBAUTHN_SUCCESS') {
              waBanner.className = 'response-banner success';
              waBanner.innerHTML = '<strong>✔ PASSKEY LOGIN VERIFIED</strong><br/>' + escapeHtml(verifyData.message);
            } else {
              waBanner.className = 'response-banner trapped';
              waBanner.innerHTML = '<strong>🛡️ PASSKEY AiTM LOGIN BLOCKED</strong><br/>' + escapeHtml(verifyData.message);
            }
          } catch (err) {
            waBanner.className = 'response-banner trapped';
            waBanner.innerHTML = '<strong>✖ PASSKEY LOGIN ERROR</strong><br/>' + escapeHtml(err && err.message ? err.message : String(err));
          }
        });
      }

      // Handle Login Form submission via fetch so the page stays live & updates the banner + SOC feed
      var form = document.getElementById('vaultLoginForm');
      form.addEventListener('submit', async function (ev) {
        ev.preventDefault();
        var submitBtn = document.getElementById('submitBtn');
        var banner = document.getElementById('loginResponseBanner');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Sealing WebCrypto RSA-OAEP Telemetry...';

        try {
          var token = window.__OriginLock ? await window.__OriginLock.getToken() : '';
          probeCipherPreview.textContent = token.slice(0, 44) + '... (' + token.length + ' chars)';

          var bodyData = new URLSearchParams();
          bodyData.set('username', document.getElementById('username').value);
          bodyData.set('password', document.getElementById('password').value);
          bodyData.set('totp_code', document.getElementById('totp_code').value);
          bodyData.set('_shield_mode', document.getElementById('shield_mode').value);
          bodyData.set('_originlock_token', token);

          var res = await fetch('/api/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'x-originlock-token': token
            },
            body: bodyData.toString()
          });

          var data = await res.json();
          if (data.nextNonce && window.__OriginLock && typeof window.__OriginLock.setNonce === 'function') {
            window.__OriginLock.setNonce(data.nextNonce, data.nextChallengeProof);
            var nonceEl = document.getElementById('probeNonceText');
            if (nonceEl) nonceEl.textContent = data.nextNonce;
          }

          if (data.status === 'SUCCESS') {
            banner.className = 'response-banner success';
            banner.innerHTML =
              '<strong>✔ AUTHENTICATED TO QUELLCLOUD VAULT</strong><br/>' +
              'Origin verified via RSA-OAEP-2048 (' + escapeHtml(data.verdict.decryptedPayload.origin) + '). Session cookie issued.';
          } else if (data.status === 'COMPROMISED_UNPROTECTED') {
            banner.className = 'response-banner trapped';
            banner.innerHTML =
              '<strong>⚠️ ACCOUNT COMPROMISED (SHIELD WAS OFF!)</strong><br/>' +
              escapeHtml(data.message);
          } else {
            banner.className = 'response-banner trapped';
            banner.innerHTML =
              '<strong>🚨 AiTM REVERSE PROXY BLOCKED &amp; POISONED (' + escapeHtml(data.verdict.status) + ')</strong><br/>' +
              escapeHtml(data.message) + '<br/>' +
              '<strong>Injected Canary ID:</strong> ' + escapeHtml(data.verdict.threatDetails && data.verdict.threatDetails.canaryId ? data.verdict.threatDetails.canaryId : 'N/A');
          }
        } catch (err) {
          banner.className = 'response-banner trapped';
          banner.textContent = 'Request error: ' + err;
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Authenticate & Seal Origin Telemetry';
        }
      });
    })();
  </script>
</body>
</html>`;
}
