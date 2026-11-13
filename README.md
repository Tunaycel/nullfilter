# NullFilter (`@nullfilter/*` / `OriginLock`)

**AiTM Reverse Proxy Detection Telemetry, Canary Honeypot Deception & Red-Team Security Research Framework**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Zero External Crypto](https://img.shields.io/badge/Crypto-Native%20WebCrypto%20%2B%20node%3Acrypto-10b981)](#3-cryptographic-telemetry--deception-mechanics)
[![Red-Team PoC](https://img.shields.io/badge/Red--Team%20Analysis-Standalone%20Forgery%20PoC%20Included-f59e0b)](./docs/RED_TEAM_ANALYSIS.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## 1. Architectural Positioning & Threat Model Boundary

> **Important Security Boundary Notice (Read First):**  
> Client-side JavaScript telemetry encrypted with a server's public key (`RSA-OAEP-2048` + `AES-256-GCM`) is a **Commodity Phishlet Detection, Early-Warning Threat Intelligence, and Active Deception (Canary Honeypot) layer** — **NOT** an unforgeable cryptographic authentication boundary.
>
> As proven in our executable Red-Team report ([`docs/RED_TEAM_ANALYSIS.md`](./docs/RED_TEAM_ANALYSIS.md) and `Test 9` in [`redteam-forgery.test.ts`](./packages/cli/src/redteam-forgery.test.ts)), because all parameters required to construct and encrypt the client probe travel over the wire on `GET /`, a **tailored attacker** who writes a custom wire-script parser can synthesize a valid token without a victim browser and obtain `ALLOW`. True authentication-time origin binding requires browser/OS-level **FIDO2 / WebAuthn Passkeys**, and post-authentication session protection requires **Token Binding / DPoP / Continuous Access Evaluation (CAE)**.

### Why NullFilter Exists Alongside WebAuthn (Commodity vs. Tailored Scope)

When a user visits a lookalike phishing domain (`https://quellcl0ud.com`), WebAuthn's Relying Party ID (`rpId`) check fails **silently inside the client browser**. While that blocks credential relay on Passkey-only flows, the defender's server never receives a packet — leaving the Security Operations Center (SOC) blind to the active phishing domain, targeted accounts, and proxy exit IPs.

**NullFilter (`OriginLock`)** fills that intelligence and deception gap against **commodity AiTM frameworks** (`Evilginx2/3`, `Modlishka`, `Muraena` running standard YAML `sub_filter` rules):

| Attacker Profile | NullFilter Telemetry (`OriginLockShield`) | NullFilter Canary Honeypot (`generatePoisonedSession`) | True Authentication Boundary (`WebAuthn` + `DPoP/CAE`) |
| :--- | :--- | :--- | :--- |
| **Commodity Phishlet** (Unmodified `Evilginx`/`Modlishka` YAML `sub_filter`) | **Detects & Unmasks:** Decrypts victim's actual `window.location.origin` (`quellcl0ud.com`) and proxy IP; fires SIEM CEF alert. | **Poisons Proxy DB:** Returns HTTP 200 with a signed `HS256` Canary `Set-Cookie` that Evilginx captures and stores. | **Blocks Login:** Browser C++/TPM signs real origin; proxy cannot relay passkey login (`BLOCK_WEBAUTHN_*`). |
| **Tailored Attacker** (Custom wire-script deobfuscator / standalone token forger — `Test 9`) | **Bypassed (`ALLOW`):** Attacker extracts wire parameters and encrypts spoofed origin under server public key. | **Bypassed:** Canary only fires on `BLOCK` verdicts; standalone forgery receives `ALLOW`. | **Blocks Login (`Test 10`):** Attacker observes all wire data (challenge, `rpId`, public key) but lacks the user's private key -> `BLOCK`. |
| **Downgrade Attack** (Phishlet hides passkey UI, pushes victim to password/OTP fallback) | **Detects & Unmasks** (if commodity phishlet relays script on fallback form). | **Poisons Proxy DB** (when commodity phishlet is caught on fallback form). | **Vulnerable if fallback enabled:** Passkeys only prevent AiTM login when phishable fallbacks are disabled or gated. |
| **Post-Auth Non-AiTM Cookie Theft** (Infostealer malware / XSS outside proxy) | **Not Covered** (Pre-auth / login-time probe only). | **Detects Replay** (Only if stolen cookie was a Canary). | **Requires DPoP / DBSC / CAE:** Passkey blocks AiTM login (no cookie lands in proxy), but non-AiTM theft needs key-bound tokens. |

### 1.1. Zero-Dependency WebAuthn Assertion Verifier (`@nullfilter/core`)
To demonstrate the exact cryptographic asymmetry between **Test 9** (wire-script telemetry forgery -> `ALLOW`) and **Test 10** (WebAuthn assertion forgery without the user's private key -> `BLOCK`), `@nullfilter/core` includes [`verifyWebAuthnAssertion`](./packages/core/src/webauthn.ts) using only Node's built-in `node:crypto` (validating `authenticatorData || SHA256(clientDataJSON)` over ECDSA P-256 DER, `rpIdHash`, `UP`/`UV` bits, `signCount`, exact `origin`, and single-use challenges).

> **Production Recommendation:** This zero-dependency verifier is intentionally scoped to `navigator.credentials.get` assertion verification to make the FIDO2 cryptographic mechanics transparent. For production deployments (especially registration/attestation ceremonies requiring COSE/CBOR parsing), use an audited library such as `@simplewebauthn/server`.

---

## 2. How NullFilter Detects & Poisons Commodity AiTM Proxies

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Victim Browser DOM<br/>(window.location = localhost:8080)
    participant Proxy as Commodity Evilginx Proxy<br/>(localhost:8080 -> sub_filter)
    participant Server as Protected Vault Server<br/>(localhost:3000 + OriginLockShield)
    participant SIEM as Live SOC / Microsoft Sentinel<br/>(SSE + CEF Webhooks)

    Browser->>Proxy: GET / (Request Login Page)
    Proxy->>Server: GET / (Spoofed Host: localhost:3000)
    Note over Server: 1. Issue HMAC-SHA256 Nonce<br/>2. Mutate Polymorphic JS (Random 8-byte XOR + Affine Split)
    Server-->>Proxy: 200 OK (HTML + Mutated Polymorphic Probe)
    Note over Proxy: Commodity sub_filter scans JS for "location.hostname"<br/>Misses XOR-masked property lookups & relays script
    Proxy-->>Browser: 200 OK (Relayed HTML + Probe)

    Note over Browser: 3. Probe executes in victim DOM<br/>Reads window.location.origin ("http://localhost:8080")<br/>Computes Canvas/WebGL digest & RTT<br/>Encrypts via WebCrypto (RSA-OAEP-2048 + AES-256-GCM)
    Browser->>Proxy: POST /api/login (user, pass, 2fa, _originlock_token)
    Note over Proxy: Captures credentials; relays opaque RSA-OAEP token<br/>(Commodity proxy cannot sub_filter ciphertext)
    Proxy->>Server: POST /api/login (Spoofed Origin: http://localhost:3000)

    Note over Server: 4. Decrypts RSA-OAEP/AES-GCM envelope<br/>5. Verifies Constant-Time HMAC Nonce<br/>6. Detects Mismatch: Decrypted ("http://localhost:8080") != Allowed ("http://localhost:3000")
    Server->>SIEM: Dispatch CEF Alert + Decrypted Phishing Origin
    Server-->>Proxy: 200 OK + Set-Cookie: vault_session=<Poisoned Canary JWT>
    Note over Proxy: Greedily saves Canary Cookie into Evilginx DB<br/>(Attacker session database is now poisoned!)
```

---

## 3. Cryptographic Telemetry & Deception Mechanics

### 3.1. Hybrid Envelope Encryption (`RSA-OAEP-2048` + `AES-256-GCM`)
A raw 2048-bit RSA modulus ($256\text{ bytes}$) with `RSA-OAEP` and `SHA-256` ($hLen = 32\text{ bytes}$) has a strict mathematical plaintext ceiling:

$$\text{Max Plaintext} = k - 2 \cdot hLen - 2 = 256 - 2(32) - 2 = 190\text{ bytes}$$

Because a full browser telemetry payload (`hostname`, `origin`, `pathname`, `referrer`, `userAgent`, `canvasHash`, `webglRenderer`, `nonce`, `challengeProof`) spans **380–650 bytes**, NullFilter uses a zero-dependency **Hybrid Cryptographic Envelope**:
1. The browser generates a one-time 256-bit `AES-GCM` key ($32\text{ bytes}$) and 96-bit IV ($12\text{ bytes}$) via `window.crypto.getRandomValues`.
2. The serialized `TelemetryPayload` JSON is encrypted with `AES-256-GCM` (producing ciphertext + a 128-bit authentication tag).
3. The $44\text{-byte}$ `AES Key || IV` block is encrypted using the server's **RSA-2048 SPKI Public Key** (`RSA-OAEP` with `SHA-256`), producing a fixed $256\text{-byte}$ RSA key block.
4. This prevents commodity string-replacement proxies (`sub_filter`) from inspecting or rewriting the reported origin after encryption.

### 3.2. Constant-Time Single-Use Nonces & Bounded Replay Registry
- Server nonces follow the format `${randomHex}.${timestampMs}.${hmacSignatureHex}` with optional client IP context binding.
- Verification uses `crypto.timingSafeEqual` to eliminate timing side-channels and stores consumed nonces in a bounded FIFO registry (`maxNonceCacheSize = 50,000`) to prevent memory-exhaustion DoS attacks.

### 3.3. Polymorphic Runtime Script Engine & Its Architectural Limit
- Every call to `generatePolymorphicClientScript()` generates a fresh 8-byte CSPRNG XOR key, an affine offset $\alpha$, and randomized variable/function identifiers.
- Critical DOM property strings (`location`, `hostname`, `origin`, `subtle`, `RSA-OAEP`, `AES-GCM`, `SHA-256`) and the per-nonce `challengeProof` are split and XOR/affine-encoded so they do not appear as static plaintext literals against generic `sub_filter` rules.
- **Architectural Limit (Red-Team PoC):** Because the XOR key, affine offset, split arrays, and SPKI public key are delivered in the `GET /` script, a tailored attacker can parse the wire script and synthesize a forged token without a victim browser (`Test 9`). See [`docs/RED_TEAM_ANALYSIS.md`](./docs/RED_TEAM_ANALYSIS.md) for the complete mathematical breakdown and exploit PoC.

---

## 4. Monorepo Package Architecture

| Package | Description |
| :--- | :--- |
| **`@nullfilter/core`** | Zero-dependency cryptographic primitives (`generateRsaKeyPair`, `generateNonce`, `verifyNonce`, `decryptTelemetryPayload`, `encryptTelemetryNode`) and polymorphic JS generator (`generatePolymorphicClientScript`). |
| **`@nullfilter/client`** | Browser SPA SDK (`createOriginLockToken`, `protectForm`, `createProtectedFetch`, `getCanvasFingerprint`, `getWebglRenderer`, `measureRtt`). |
| **`@nullfilter/server`** | `OriginLockShield` / `NullFilterShield` verification pipeline, Canary Honeypot JWT generator (`generatePoisonedSession`), SIEM/CEF webhook dispatcher (`dispatchThreatWebhook`), and native Node.js, Express, and Next.js middlewares. |
| **`@nullfilter/cli`** | Command-line utility (`init`, `simulate`, `audit`) + automated Red-Team standalone wire-forgery PoC (`forgeTokenFromWireScript` & `redteam-forgery.test.ts`). |
| **`@nullfilter/playground`** | Interactive split-screen demonstration launching both the Protected Target Server (`http://localhost:3000`) and the Simulated Evilginx Reverse Proxy (`http://localhost:8080`) with a `Shield: ON / OFF` toggle and live Server-Sent Events (SSE) SOC Console. |

---

## 5. Quickstart, Red-Team PoC Tests & Interactive Demo

### Prerequisites
- **Node.js** `>= 18.0.0`
- **pnpm** `>= 8.0.0`

### 1. Install, Build & Run the Assertion Test Suite
```bash
pnpm install
pnpm test
```
`pnpm test` compiles all workspace packages and runs the 15-test `node:test` assertion suite (`redteam-forgery.test.js` + `webauthn-verifier.test.js`), verifying:
1. **Architectural Limit PoC (`Test 9 -> ALLOW`):** Standalone attacker script extracts parameters purely from `GET /` wire script bytes and forges a valid telemetry token without a victim browser.
2. **WebAuthn Cryptographic Asymmetry (`Test 10 -> BLOCK_WEBAUTHN_INVALID_SIGNATURE`) + 12 Negative/Invariant Checks:** Attacker observing all wire data cannot forge a WebAuthn assertion without the user's private key.
3. **Commodity Phishlet Defense (`BLOCK_AITM_ORIGIN_MISMATCH`):** Unmodified Evilginx proxy relay is caught and poisoned with a verifiable `HS256` Canary JWT cookie.

### 2. Launch the Live `:3000` vs `:8080` Playground (Passkey + Downgrade Demo)
```bash
pnpm demo
```
When `pnpm demo` runs, it executes the **9-Stage Telemetry, Deception & Architectural Limit Suite** (`8/8 Commodity & Tampering Checks + 1/1 Architectural Limit PoC`), starts the **QuellCloud Enterprise Vault** on `http://localhost:3000`, and starts the **Simulated Evilginx Reverse Proxy** on `http://localhost:8080`.

- **Passkey Demo (`:3000` -> `:8080`):** Register a Passkey (`ES256` SPKI via `getPublicKey()`, fail-closed if unavailable) on `http://localhost:3000`, then switch to `http://localhost:8080` and click **Sign In with Passkey**.
  > **Port-Based `localhost` Simulation Note:** Because WebAuthn `rpId` is host-only (`localhost`), the browser still signs on `:8080` and includes `"origin": "http://localhost:8080"` inside `clientDataJSON`, allowing the server to reject it (`BLOCK_WEBAUTHN_ORIGIN_MISMATCH` — **second line of defense**). On real lookalike domains (`quellcloud.com` vs `quellcl0ud.com`), the **first line of defense** (`rpId` mismatch) fails silently inside the browser before any packet reaches the server.
- **Downgrade Vector:** The password + TOTP form remains intentionally active and labeled so you can observe how an AiTM phishlet downgrades users if phishable fallbacks remain enabled.

---

## 6. Server & Middleware Integration Examples

### Express.js Middleware
```typescript
import express from 'express';
import { OriginLockShield, createExpressMiddleware } from '@nullfilter/server';

const shield = new OriginLockShield({
  publicKeyPem: process.env.ORIGINLOCK_PUBLIC_KEY_PEM!,
  privateKeyPem: process.env.ORIGINLOCK_PRIVATE_KEY_PEM!,
  hmacSecret: process.env.ORIGINLOCK_HMAC_SECRET!,
  allowedHostnames: ['quellcloud.com'],
  allowedOrigins: ['https://quellcloud.com'],
  enableHoneypotPoisoning: true,
  webhookConfig: {
    slackWebhookUrl: process.env.SLACK_WEBHOOK_URL,
    sentinelWebhookUrl: process.env.SENTINEL_WEBHOOK_URL,
  },
});

const app = express();
app.use(express.urlencoded({ extended: false }));

app.post('/api/login', createExpressMiddleware({ shield }), (req, res) => {
  res.json({ authenticated: true });
});
```

---

## Author & License

**Author:** Hüseyin Tunay Çelik (`h.tunaycelik@gmail.com`)  
**License:** MIT
