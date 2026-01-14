import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { jwtVerify } from 'jose';

const USAGE_BASE_URL = 'https://usage.example.com';
const DEFAULT_UPGRADE_URL = 'https://upgrade.example.com';

const baseEnv = {
  NODE_ENV: 'test',
  PORT: '0',
  GEMINI_API_KEY: 'test-gemini-key',
  INTERNAL_AUTH_TOKEN: 'admin-secret',
  AUTH_SECRET: 'change-me-change-me-change-me-secret-123',
  EXTENSION_ID: 'ext-123',
  LICENSE_KEYS: 'pro:LICENSE-KEY',
  USAGE_SERVICE_BASE_URL: USAGE_BASE_URL,
  MODEL_ALLOWLIST: 'gemini-test-model',
  CORS_ORIGINS: '*'
};

const textEncoder = new TextEncoder();
const originalFetch = globalThis.fetch;
let fetchMock;
let usageState;

beforeEach(() => {
  installFetchMock();
});

afterEach(() => {
  vi.restoreAllMocks();
  usageState = null;
  if (originalFetch) {
    globalThis.fetch = originalFetch;
  } else {
    delete globalThis.fetch;
  }
});

function installFetchMock(options = {}) {
  const { usageLimit = 2, remaining = usageLimit, geminiResponse = buildGeminiResponse() } = options;
  usageState = { limit: usageLimit, remaining };
  fetchMock = vi.fn(async (url, init = {}) => {
    if (typeof url === 'string' && url.startsWith(USAGE_BASE_URL)) {
      return handleUsageRequest(url);
    }
    return typeof geminiResponse === 'function' ? geminiResponse() : geminiResponse;
  });
  globalThis.fetch = fetchMock;
}

function handleUsageRequest(rawUrl) {
  const { pathname } = new URL(rawUrl);
  if (pathname.endsWith('/quota')) {
    return buildJsonResponse(200, { quota: currentQuota() });
  }
  if (pathname.endsWith('/quota/consume')) {
    if (usageState.remaining <= 0) {
      return buildJsonResponse(200, { allowed: false, quota: currentQuota() });
    }
    usageState.remaining -= 1;
    return buildJsonResponse(200, { allowed: true, quota: currentQuota() });
  }
  if (pathname.endsWith('/quota/refund')) {
    usageState.remaining = Math.min(usageState.limit, usageState.remaining + 1);
    return buildJsonResponse(204, {});
  }
  throw new Error(Unexpected usage service path: );
}

function currentQuota() {
  return {
    limit: usageState.limit,
    remaining: usageState.remaining,
    upgradeUrl: DEFAULT_UPGRADE_URL
  };
}

function buildJsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(body);
    },
    async json() {
      return body;
    }
  };
}

function buildGeminiResponse(body) {
  const payload = body || {
    content: [],
    usageMetadata: {
      totalTokenCount: 10,
      promptTokenCount: 4,
      candidatesTokenCount: 6
    }
  };
  return buildJsonResponse(200, payload);
}

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
  const { app } = await import('../server.js');
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
      expect(verified.payload.extid).toBeNull();
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
      const body = ok.json();
      expect(body.token).toBeTruthy();
    });
  });

  it('requires valid license keys for /api/extension/session', async () => {
    await withServer({}, async (app) => {
      const denied = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'INVALID' }
      });
      expect(denied.statusCode).toBe(401);

      const ok = await app.inject({
        method: 'POST',
        url: '/api/extension/session',
        headers: { 'x-extension-id': 'ext-123' },
        payload: { licenseKey: 'LICENSE-KEY', installId: 'install-abc' }
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.json().license.id).toBe('pro');
      expect(ok.json().quota.limit).toBe(2);
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
        headers: { authorization: Bearer  },
        payload: { level: 'warn', message: 'hello' }
      });
      expect(ok.statusCode).toBe(200);
      expect(ok.json()).toEqual({ ok: true });
    });
  });

  it('proxies Gemini requests and forwards usage headers', async () => {
    installFetchMock({ geminiResponse: buildGeminiResponse() });
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
        headers: { authorization: Bearer  },
        payload: {
          model: 'gemini-test-model',
          contents: [{ role: 'user', parts: [{ text: 'hello' }] }]
        }
      });

      expect(proxy.statusCode).toBe(200);
      expect(proxy.headers['x-free-remaining']).toBe('1');
      expect(proxy.headers['x-token-usage-total']).toBe('10');
      expect(fetchMock).toHaveBeenCalledTimes(3);
    });
  });

  it('limits Gemini proxy requests once the free quota is reached', async () => {
    installFetchMock({ usageLimit: 1, remaining: 1, geminiResponse: buildGeminiResponse({ content: [] }) });
    await withServer({}, async (app) => {
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
        headers: { authorization: Bearer  },
        payload: {
          model: 'gemini-test-model',
          contents: [{ role: 'user', parts: [{ text: 'hello' }] }]
        }
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/gemini/generate',
        headers: { authorization: Bearer  },
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
