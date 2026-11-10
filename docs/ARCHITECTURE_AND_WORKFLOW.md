# NullFilter (`@nullfilter/*`) — Cryptographic Origin Attestation & Active AiTM Defense Framework

**Author:** Hüseyin Tunay Çelik (`h.tunaycelik@gmail.com`)  
**Repository:** `Tunaycel/nullfilter`  
**License:** MIT

---

## 1. Executive Summary & Architectural Objective

Reverse-proxy Adversary-in-the-Middle (AiTM) frameworks (such as Evilginx2, Modlishka, and Muraena) intercept authentication flows by terminating TLS on a lookalike domain, rewriting HTTP headers (`Host`, `Origin`, `Referer`) and response bodies (`sub_filter`) in transit, and relaying traffic through residential proxy networks. Because the backend server only observes layer-7 HTTP headers that the proxy explicitly rewrites to match the expected origin, conventional server-side origin checks fail.

**NullFilter** neutralizes proxy rewrite layers (`sub_filter`) by shifting origin attestation into the client DOM execution environment using asymmetric hybrid envelope cryptography (`RSA-OAEP-2048` + `AES-256-GCM`), polymorphic runtime script generation, active round-trip time (RTT) triangulation, and honeypot session poisoning.

> **Compatibility Note:** All packages export both `@nullfilter/*` primary interfaces (`NullFilterShield`, `NullFilterConfig`, `createNullFilterToken`) and full `OriginLock*` aliases (`OriginLockShield`, `OriginLockConfig`, `createOriginLockToken`, `x-originlock-token`, `_originlock_token`) for drop-in interoperability.

---

## 2. Adversarial Security Review & Cryptographic Hardening

Every module is designed against adversarial red-team falsification prior to implementation:

### 2.1. Hybrid RSA-OAEP-2048 + AES-256-GCM Envelope Encryption (Overcoming the 190-Byte RSA-OAEP Limit)
- **Cryptographic Constraint:** A 2048-bit RSA modulus ($256\text{ bytes}$) using OAEP with SHA-256 ($hLen = 32\text{ bytes}$) enforces a strict maximum plaintext payload of:
  $$\text{Max Plaintext} = 256 - 2(32) - 2 = 190\text{ bytes}$$
  A serialized `TelemetryPayload` JSON typically spans **380–650 bytes**, which would trigger `ERR_OSSL_RSA_DATA_TOO_LARGE_FOR_KEY_SIZE` in Node.js or `OperationError` in WebCrypto if encrypted directly with raw RSA-2048.
- **Solution:**
  1. **Envelope Mode (`v1.<rsaOaepKeyIvBase64>.<aesGcmCiphertextBase64>`):** The browser generates an ephemeral 256-bit `AES-GCM` key (32 bytes) and 96-bit IV (12 bytes), encrypts the full `TelemetryPayload` JSON with `AES-256-GCM` (128-bit authentication tag), and encrypts only the 44-byte `Key || IV` block with the server's **RSA-2048 SPKI Public Key** (`RSA-OAEP SHA-256`).
  2. **Direct RSA-OAEP Fallback Mode:** Also supports single-segment raw RSA-OAEP Base64 payloads when the serialized payload is $\le 180\text{ bytes}$ or when an RSA-4096 key is configured.

### 2.2. Constant-Time HMAC Nonce Verification & Context Binding
- Nonces follow the structure `${timestampHex}.${randomHex}.${hmacSignatureHex}` and are verified strictly via `crypto.timingSafeEqual` to eliminate timing side-channels.

### 2.3. Bounded Replay Registry (Anti-DoS / OOM Protection)
- Replay prevention uses a bounded nonce cache (configurable cap, default `50,000` entries) with automatic TTL pruning so high-volume floods cannot exhaust server heap memory.

### 2.4. Polymorphic AST-Like Probe & Native WebCrypto Integrity Check
- Sensitive DOM property strings (`location`, `hostname`, `origin`, `subtle`, `RSA-OAEP`, `AES-GCM`, `SHA-256`) are split and XOR-encoded with a per-request CSPRNG key and reconstructed under randomized variable identifiers (`_0x...`).
- Verifies `Function.prototype.toString` on `crypto.subtle.encrypt` to detect client-side script hooking.

### 2.5. Sanitized SIEM / CEF Dispatch with Non-Blocking Timeouts
- Common Event Format (CEF) outputs escape pipe (`|`), backslash (`\`), equals (`=`), and CR/LF characters to prevent SIEM log injection, and dispatch webhooks with a strict `AbortController` timeout.

---

## 3. Monorepo Structure

```text
nullfilter/
├── package.json
├── pnpm-workspace.yaml
├── tsconfig.base.json
├── .gitignore
├── README.md
├── docs/
│   └── ARCHITECTURE_AND_WORKFLOW.md
├── packages/
│   ├── core/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── index.ts
│   │       ├── types.ts
│   │       ├── crypto.ts
│   │       └── polymorphic.ts
│   ├── client/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── index.ts
│   │       └── fingerprint.ts
│   ├── server/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── index.ts
│   │       ├── shield.ts
│   │       ├── honeypot.ts
│   │       ├── webhooks.ts
│   │       └── middleware/
│   │           ├── node-http.ts
│   │           ├── express.ts
│   │           └── nextjs.ts
│   └── cli/
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── index.ts
│           └── commands/
│               ├── init.ts
│               └── audit.ts
└── apps/
    └── playground/
        ├── package.json
        ├── tsconfig.json
        └── src/
            ├── run-demo.ts
            ├── bank-server.ts
            ├── evil-proxy.ts
            └── ui-template.ts
```

---

## 4. Branch & Review Governance

- **Author Identity:** `Hüseyin Tunay Çelik <h.tunaycelik@gmail.com>` exclusively.
- **Branch Isolation:**
  1. `main` — Initial governance & architecture documentation.
  2. `chore/workspace-scaffold` — Root monorepo build & workspace configuration.
  3. `feat/core-engine` — `@nullfilter/core` cryptographic & polymorphic engine.
  4. `feat/client-sdk` — `@nullfilter/client` browser WebCrypto & fingerprinting SDK.
  5. `feat/server-shield` — `@nullfilter/server` verification shield, canary honeypot, SIEM webhooks, and HTTP/Express/Next.js middlewares.
  6. `feat/cli-toolkit` — `@nullfilter/cli` key provisioning and automated self-audit CLI.
  7. `feat/interactive-playground` — Live Vault server (`:3000`), Loopback Proxy Simulator (`:8080`), SSE SOC Telemetry Console, and root `README.md`.
- **Verification Gate:** Every branch is compiled, verified, and reviewed locally before user approval for remote push and Pull Request creation.
