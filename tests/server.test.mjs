import { describe, it, expect, vi, afterEach } from 'vitest';
import { jwtVerify } from 'jose';
import { createHash } from 'node:crypto';

const baseEnv = {
  NODE_ENV: 'test',
  PORT: '0',
  GEMINI_API_KEY: 'test-gemini-key',
  INTERNAL_AUTH_TOKEN: 'admin-secret',
  AUTH_SECRET: 'change-me-change-me-change-me-secret-123',
  EXTENSION_ID: 'ext-123',
  LICENSE_KEYS: 'pro:LICENSE-KEY',
  FREE_DAILY_LIMIT: '2',
  UPGRADE_URL: 'https://upgrade.example.com',
  GOOGLE_LOGIN_DEV_MODE: 'true',
  GOOGLE_LOGIN_DEV_DEFAULT_EMAIL: 'tester@example.com',
  PAYU_DEV_MODE: 'true',
  PAYU_POS_ID: 'pos-1',
  PAYU_CLIENT_ID: 'payu-client',
  PAYU_CLIENT_SECRET: 'payu-secret',
  PAYU_SECOND_KEY: 'payu-second',
  PAYU_NOTIFY_URL: 'https://notify.example.com',
  PAYU_CONTINUE_URL: 'https://continue.example.com',
  PAYU_AMOUNT_PRO: '9900',
  MODEL_ALLOWLIST: 'gemini-test-model',
  CORS_ORIGINS: '*',
};

const textEncoder = new TextEncoder();
const originalFetch = globalThis.fetch;

afterEach(() => {
  vi.restoreAllMocks();
  if (originalFetch) {
    globalThis.fetch = originalFetch;
  } else {
    delete globalThis.fetch;
  }
});

function applyEnv(overrides = {}) {
  const keys = new Set([...Object.keys(baseEnv), ...Object.keys(overrides)]);
  const previous = {};
  for (const key of keys) {
    previous[key] = process.env[key];
  }
  Object.entries(baseEnv).forEach(([key, value]) => {
    process.env[key] = value;
  });
  Object.entries(overrides).forEach(([key, value]) => {
    process.env[key] = value;
  });
  return () => {
    for (const key of keys) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
  };
}

async function withServer(envOverrides, fn) {
  const restoreEnv = applyEnv(envOverrides);
  vi.resetModules();
  const { app } = await import('../server.mjs');
  try {
    await fn(app);
  } finally {
    await app.close();
    restoreEnv();
  }
}

describe('server endpoints', () => {
  it('enforces the IP allowlist before hitting routes', async () => {
    await withServer({ ALLOWED_IPS: '10.0.0.1' }, async (app) => {
      const denied = await app.inject({
        method: 'GET',
        url: '/health',
        headers: { 'x-forwarded-for': '1.1.1.1' }
      });
      expect(denied.statusCode).toBe(403);

      const allowed = await app.inject({
        method: 'GET',
        url: '/health',
        headers: { 'x-forwarded-for': '10.0.0.1' }
      });
      expect(allowed.statusCode).toBe(200);
      expect(allowed.json()).toEqual({ status: 'ok' });
    });
  });

  it('issues JWT tokens for /auth/token only when admin credentials match', async () => {
    await withServer({}, async (app) => {
      const missing = await app.inject({ method: 'POST', url: '/auth/token' });
      expect(missing.statusCode).toBe(401);

      const response = await app.inject({
        method: 'POST',
        url: '/auth/token',
        headers: {
          authorization: 'Bearer admin-secret',
          origin: 'chrome-extension://ext-123',
          'x-extension-id': 'ext-123'
        }
      });
      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.token).toBeTruthy();
      const verified = await jwtVerify(
        body.token,
        textEncoder.encode(baseEnv.AUTH_SECRET),
        { issuer: 'reviews-coach-proxy', audience: 'reviews-coach-proxy' }
      );
      expect(verified.payload.extid).toBe('ext-123');
      expect(verified.payload.scope).toBe('gen');
    });
  });

  it('validates /api/extension/jwt secrets', async () => {
    await withServer({}, async (app) => {
      const denied = await app.inject({ method: 'POST', url: '/api/extension/jwt' });
      expect(denied.statusCode).toBe(401);

      const ok = await app.inject({
        method: 'POST',
        url: '/api/extension/jwt',
        headers: { 'x-internal-auth': 'admin-secret' },
        payload: { extensionId: 'ext-123' }
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.json()).toHaveProperty('token');
    });
  });

  it('requires valid license keys for /api/extension/session', async () => {
    await withServer({}, async (app) => {
      const invalid = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'WRONG' }
      });
      expect(invalid.statusCode).toBe(401);

      const valid = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'LICENSE-KEY' }
      });
      expect(valid.statusCode).toBe(200);
      expect(valid.json()).toMatchObject({ license: { id: 'pro' } });
    });
  });

  it('returns dev Google sessions for the extension', async () => {
    await withServer({}, async (app) => {
      const session = await app.inject({
        method: 'POST',
        url: '/api/extension/google-session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { accessToken: 'user@example.com' }
      });
      expect(session.statusCode).toBe(200);
      const body = session.json();
      expect(body.profile).toMatchObject({ email: 'user@example.com' });
      expect(body).toHaveProperty('token');
      expect(body.quota).toBeTruthy();
    });
  });

  it('creates and uses a web session cookie', async () => {
    await withServer({}, async (app) => {
      const login = await app.inject({
        method: 'POST',
        url: '/api/web/google-login',
        payload: { id_token: 'web@example.com' }
      });
      expect(login.statusCode).toBe(200);
      const cookieHeader = login.headers['set-cookie'];
      expect(cookieHeader).toBeTruthy();
      const cookie = Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader;

      const status = await app.inject({
        method: 'GET',
        url: '/api/web/account/status',
        headers: { cookie: cookie.split(';')[0] }
      });
      expect(status.json()).toMatchObject({ plan: 'trial', email: 'web@example.com' });
    });
  });

  it('allows upgrading accounts in dev/mock mode', async () => {
    await withServer({}, async (app) => {
      const login = await app.inject({
        method: 'POST',
        url: '/api/web/google-login',
        payload: { id_token: 'upgrade@example.com' }
      });
      const cookie = (Array.isArray(login.headers['set-cookie'])
        ? login.headers['set-cookie'][0]
        : login.headers['set-cookie']).split(';')[0];

      const upgrade = await app.inject({
        method: 'POST',
        url: '/api/web/account/upgrade',
        headers: { cookie },
        payload: { plan_id: 'pro' }
      });
      expect(upgrade.statusCode).toBe(200);
      expect(upgrade.json()).toMatchObject({ provider: 'payu', mock: true });

      const status = await app.inject({
        method: 'GET',
        url: '/api/web/account/status',
        headers: { cookie }
      });
      expect(status.json().plan).toBe('pro');
    });
  });

  it('validates PayU webhook signatures and applies paid plans', async () => {
    await withServer({ PAYU_DEV_MODE: 'false' }, async (app) => {
      const login = await app.inject({
        method: 'POST',
        url: '/api/web/google-login',
        payload: { id_token: 'payu@example.com' }
      });
      const cookie = (Array.isArray(login.headers['set-cookie'])
        ? login.headers['set-cookie'][0]
        : login.headers['set-cookie']).split(';')[0];
      const userId = login.json().sub;
      const extOrderId = `rc|${Buffer.from(userId).toString('base64url')}|pro|${Date.now()}`;
      const body = { order: { extOrderId, status: 'COMPLETED' } };
      const rawBody = JSON.stringify(body);
      const signature = createHash('md5')
        .update(rawBody + baseEnv.PAYU_SECOND_KEY)
        .digest('hex');

      const bad = await app.inject({
        method: 'POST',
        url: '/api/billing/payu-webhook',
        headers: {
          'openpayu-signature': 'signature=deadbeef;algorithm=MD5',
          'content-type': 'application/json'
        },
        payload: rawBody
      });
      expect(bad.statusCode).toBe(400);

      const ok = await app.inject({
        method: 'POST',
        url: '/api/billing/payu-webhook',
        headers: {
          'openpayu-signature': `signature=${signature};algorithm=MD5`,
          'content-type': 'application/json'
        },
        payload: rawBody
      });
      expect(ok.statusCode).toBe(200);

      const status = await app.inject({
        method: 'GET',
        url: '/api/web/account/status',
        headers: { cookie }
      });
      expect(status.json().plan).toBe('pro');
    });
  });

  it('requires valid JWTs for the log endpoint', async () => {
    await withServer({}, async (app) => {
      const denied = await app.inject({ method: 'POST', url: '/api/extension/log' });
      expect(denied.statusCode).toBe(401);

      const session = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'LICENSE-KEY' }
      });
      const token = session.json().token;

      const ok = await app.inject({
        method: 'POST',
        url: '/api/extension/log',
        headers: { authorization: `Bearer ${token}` },
        payload: { level: 'warn', message: 'hello' }
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.json()).toEqual({ ok: true });
    });
  });

  it('proxies Gemini requests and forwards usage headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => JSON.stringify({
        content: [],
        usageMetadata: {
          totalTokenCount: 10,
          promptTokenCount: 4,
          candidatesTokenCount: 6
        }
      })
    });
    globalThis.fetch = fetchMock;

    await withServer({}, async (app) => {
      const session = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'LICENSE-KEY' }
      });
      const token = session.json().token;

      const proxy = await app.inject({
        method: 'POST',
        url: '/gemini/generate',
        headers: { authorization: `Bearer ${token}` },
        payload: {
          model: 'gemini-test-model',
          contents: [{ role: 'user', parts: [{ text: 'hello' }] }]
        }
      });

      expect(proxy.statusCode).toBe(200);
      expect(proxy.headers['x-free-remaining']).toBe('1');
      expect(proxy.headers['x-token-usage-total']).toBe('10');
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  it('limits Gemini proxy requests once the free quota is reached', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => JSON.stringify({ content: [] })
    });
    globalThis.fetch = fetchMock;

    await withServer({ FREE_DAILY_LIMIT: '1' }, async (app) => {
      const session = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'LICENSE-KEY' }
      });
      const token = session.json().token;

      const first = await app.inject({
        method: 'POST',
        url: '/gemini/generate',
        headers: { authorization: `Bearer ${token}` },
        payload: {
          model: 'gemini-test-model',
          contents: [{ role: 'user', parts: [{ text: 'hello' }] }]
        }
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/gemini/generate',
        headers: { authorization: `Bearer ${token}` },
        payload: {
          model: 'gemini-test-model',
          contents: [{ role: 'user', parts: [{ text: 'hello again' }] }]
        }
      });
      expect(second.statusCode).toBe(402);
      expect(second.json().code).toBe('FREE_LIMIT_REACHED');
    });
  });
});
