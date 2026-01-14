# Reviews Coach - Gemini Secure Proxy (Node 20+)

Hardened Fastify proxy for Google Gemini `generateContent` that adds:

- **JWT short-lived tokens** (`/auth/token`, HS256) – default **10 min**
- **Extension-only CORS** (`chrome-extension://<EXTENSION_ID>`) + `X-Extension-Id` header check
- **Model allowlist** (`MODEL_ALLOWLIST`)
- **Rate limit** (@fastify/rate-limit) – default **60 req/min/IP**
- **Body size limit** (25KB default)
- **Security headers** (@fastify/helmet) + `Cache-Control: no-store`
- **Token usage** response headers
- Optional **IP allowlist**

> Keep secrets ONLY in server env. Your extension never sees `GEMINI_API_KEY`.

---

## 1) Quick start

```bash
npm install
# Linux/macOS
env GEMINI_API_KEY=... \
    INTERNAL_AUTH_TOKEN='set-a-long-random-admin-token' \
    AUTH_SECRET='set-a-very-long-random-secret-at-least-32-chars' \
    EXTENSION_ID='abcdefghijklmnopabcdefghijklmnop' \
    CORS_ORIGINS='chrome-extension://abcdefghijklmnopabcdefghijklmnop' \
    LICENSE_KEYS='client-a:PAID-LICENSE-1,client-b:ANOTHER-LICENSE' \
    npm run dev
```

Health:

```bash
curl http://localhost:3000/health
```

### 1.1) Get short-lived JWT

```bash
curl -X POST http://localhost:3000/auth/token \
  -H "Authorization: Bearer set-a-long-random-admin-token" \
  -H "X-Extension-Id: abcdefghijklmnopabcdefghijklmnop"
```

Response:

```json
{ "token": "<jwt>", "expiresIn": 600 }
```

### 1.2) Call Gemini via proxy

```bash
curl -X POST http://localhost:3000/gemini/generate \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -H "Origin: chrome-extension://abcdefghijklmnopabcdefghijklmnop" \
  -H "X-Extension-Id: abcdefghijklmnopabcdefghijklmnop" \
  -d '{
    "model": "gemini-2.0-flash",
    "contents": [
      { "role": "user", "parts": [{ "text": "Write a cheerful 1-sentence greeting." }] }
    ]
  }'
```

---

## 2) Environment variables

| Name | Required | Default | Notes |
| --- | --- | --- | --- |
| `GEMINI_API_KEY` | yes | – | Gemini/Generative Language API key |
| `INTERNAL_AUTH_TOKEN` | yes | – | Admin token to issue JWT at `/auth/token` |
| `AUTH_SECRET` | yes | – | HS256 secret (>=32 chars) for JWT signing |
| `LICENSE_KEYS` | yes | – | Comma/newline separated `label:LICENSE_VALUE` pairs for paying users |
| `EXTENSION_ID` | yes | – | Your Chrome extension ID |
| `CORS_ORIGINS` | yes | `chrome-extension://<EXTENSION_ID>` | Comma-separated origins allowlist |
| `MODEL_ALLOWLIST` | optional | `gemini-2.0-flash,gemini-2.0-flash-lite` | Models allowed via proxy |
| `JWT_TTL_SECONDS` | optional | `600` | Token expiry |
| `RATE_LIMIT_PER_MINUTE` | optional | `60` | Rate limit per IP |
| `BODY_LIMIT_BYTES` | optional | `25600` | Max body size (~25KB) |
| `GEMINI_TIMEOUT_MS` | optional | `15000` | Upstream timeout in ms |
| `USAGE_SERVICE_BASE_URL` | yes | - | Base URL for the backend usage/quota API |
| `ALLOWED_IPS` | optional | – | Comma-separated IP allowlist |
| `PORT` | optional | `3000` | Port to listen on |

---

## 3) How to wire it in your Chrome extension (MV3)

**Service worker (TypeScript/JS):**

```ts
const EXT_ID = chrome.runtime.id;
const BASE = 'https://<your-proxy-host>';
const INSTALL_KEY = 'rcInstallId';

async function ensureInstallId() {
  const existing = await chrome.storage.local.get([INSTALL_KEY]);
  if (existing[INSTALL_KEY]) return existing[INSTALL_KEY];
  const generated = crypto.randomUUID();
  await chrome.storage.local.set({ [INSTALL_KEY]: generated });
  return generated;
}

async function getJwt(licenseKey) {
  const installId = await ensureInstallId();
  const response = await fetch(BASE + '/api/extension/session', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Extension-Id': EXT_ID
    },
    body: JSON.stringify({ licenseKey, extensionId: EXT_ID, installId })
  });
  if (!response.ok) throw new Error('session failed ' + response.status);
  const { token, expiresIn } = await response.json();
  const expAt = Date.now() + Math.max(0, (expiresIn - 10) * 1000);
  await chrome.storage.session.set({ jwt: token, jwtExp: expAt });
  return token;
}

async function ensureJwt(licenseKey) {
  const { jwt, jwtExp } = await chrome.storage.session.get(['jwt', 'jwtExp']);
  if (jwt && jwtExp && Date.now() < jwtExp) return jwt;
  return getJwt(licenseKey);
}

export async function callGeminiViaProxy(payload, licenseKey) {
  const jwt = await ensureJwt(licenseKey);
  const res = await fetch(BASE + '/gemini/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + jwt,
      'X-Extension-Id': EXT_ID
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    if (res.status === 401) {
      const retry = await fetch(BASE + '/gemini/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + await getJwt(licenseKey),
          'X-Extension-Id': EXT_ID
        },
        body: JSON.stringify(payload)
      });
      if (!retry.ok) throw new Error('proxy error ' + retry.status);
      return retry.json();
    }
    throw new Error('proxy error ' + res.status);
  }
  return res.json();
}
```

> **Where does `licenseKey` come from?** Give each paying customer a long unique license key (`LICENSE_KEYS`). They paste it into the extension options and it stays in `chrome.storage.local`, but every request exchanges it for a short-lived JWT at `/api/extension/session`, so the extension never sees `GEMINI_API_KEY`.

---

## 4) Deploy (Render/Railway/Azure App Service)

- **Install**: `npm install`
- **Start**: `npm start`
- **Node**: 20+
- **Env Vars**: set everything from the table above
- **Force HTTPS** on your platform

---

## 5) Security checklist

- [ ] Never expose `GEMINI_API_KEY` or `AUTH_SECRET`
- [ ] Set `EXTENSION_ID` and CORS origins to your extension ID(s)
- [ ] Use strong random strings for `INTERNAL_AUTH_TOKEN` and `AUTH_SECRET`
- [ ] Rotate `INTERNAL_AUTH_TOKEN` periodically
- [ ] Consider `ALLOWED_IPS` if you have predictable networks
- [ ] For scale: move rate limiting/state to Redis, front with WAF/CDN
- [ ] Review logging retention/privacy settings

---

## 6) License

MIT
