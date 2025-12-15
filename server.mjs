import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { SignJWT, jwtVerify } from 'jose';
import cookie from '@fastify/cookie';
import fastifyRawBody from 'fastify-raw-body';
import { createHash, timingSafeEqual, randomUUID } from 'node:crypto';

// ===== Env & defaults =====
const PORT = parseInt(process.env.PORT || '3000', 10);
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const INTERNAL_AUTH_TOKEN = process.env.INTERNAL_AUTH_TOKEN || '';      // admin token (do /auth/token i /api/extension/jwt)
const AUTH_SECRET = process.env.AUTH_SECRET || 'change-me-change-me-change-me';
const EXTENSION_ID = process.env.EXTENSION_ID || '';

const JWT_TTL_SECONDS = parseInt(process.env.JWT_TTL_SECONDS || '600', 10);
const RATE_LIMIT_PER_MINUTE = parseInt(process.env.RATE_LIMIT_PER_MINUTE || '60', 10);
const BODY_LIMIT_BYTES = parseInt(process.env.BODY_LIMIT_BYTES || String(25 * 1024), 10);
const GEMINI_TIMEOUT_MS = parseInt(process.env.GEMINI_TIMEOUT_MS || '15000', 10);
const FREE_DAILY_LIMIT = Math.max(0, parseInt(process.env.FREE_DAILY_LIMIT || '5', 10));
const UPGRADE_URL = (process.env.UPGRADE_URL || '').trim();
const PAYU_DEV_MODE = ((process.env.PAYU_DEV_MODE || '').toLowerCase() === 'true');
const PAYU_POS_ID = (process.env.PAYU_POS_ID || '').trim();
const PAYU_CLIENT_ID = (process.env.PAYU_CLIENT_ID || '').trim();
const PAYU_CLIENT_SECRET = (process.env.PAYU_CLIENT_SECRET || '').trim();
const PAYU_SECOND_KEY = (process.env.PAYU_SECOND_KEY || '').trim();
const PAYU_NOTIFY_URL = (process.env.PAYU_NOTIFY_URL || '').trim();
const PAYU_CONTINUE_URL = (process.env.PAYU_CONTINUE_URL || UPGRADE_URL || '').trim();
const PAYU_MOCK_PAYMENT_URL = (process.env.PAYU_MOCK_PAYMENT_URL || 'https://payu.example.com/mock-checkout').trim();
const PAYU_CURRENCY = (process.env.PAYU_CURRENCY || 'PLN').trim().toUpperCase() || 'PLN';
const PAYU_API_BASE_URL = (process.env.PAYU_API_BASE_URL || 'https://secure.snd.payu.com').replace(/\/+$/, '');
const PAYU_AMOUNT_PRO = (process.env.PAYU_AMOUNT_PRO || '9900').trim();
const PAYU_PLAN_DURATION_DAYS = Math.max(1, parseInt(process.env.PAYU_PLAN_DURATION_DAYS || '30', 10));
const PAYU_ENABLED = Boolean(PAYU_POS_ID && PAYU_CLIENT_ID && PAYU_CLIENT_SECRET && PAYU_SECOND_KEY && PAYU_NOTIFY_URL && PAYU_CONTINUE_URL && PAYU_AMOUNT_PRO);
const payuTokenCache = { token: '', expiresAt: 0 };
const payuOrderMap = new Map();
const GOOGLE_LOGIN_DEV_MODE = ((process.env.GOOGLE_LOGIN_DEV_MODE || '').toLowerCase() === 'true');
const GOOGLE_LOGIN_DEV_DEFAULT_EMAIL = (process.env.GOOGLE_LOGIN_DEV_DEFAULT_EMAIL || '').trim();
const WEB_SESSION_COOKIE_NAME = process.env.WEB_SESSION_COOKIE_NAME || 'rc_web_session';
const WEB_SESSION_COOKIE_DOMAIN = process.env.WEB_SESSION_COOKIE_DOMAIN || undefined;
const WEB_SESSION_COOKIE_SECURE = ((process.env.WEB_SESSION_COOKIE_SECURE || '').toLowerCase() === 'true');
const WEB_SESSION_TTL_SECONDS = (() => {
  const fallback = 60 * 60 * 24 * 7;
  const parsed = parseInt(process.env.WEB_SESSION_TTL_SECONDS || String(fallback), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
})();
const WEB_SESSION_COOKIE_SAME_SITE = (() => {
  const raw = (process.env.WEB_SESSION_COOKIE_SAMESITE || (WEB_SESSION_COOKIE_SECURE ? 'none' : 'lax')).toLowerCase();
  if (raw === 'lax' || raw === 'strict' || raw === 'none') return raw;
  return WEB_SESSION_COOKIE_SECURE ? 'none' : 'lax';
})();
const WEB_SESSION_TTL_MS = WEB_SESSION_TTL_SECONDS * 1000;

const EXT_ORIGIN = EXTENSION_ID ? `chrome-extension://${EXTENSION_ID}` : null;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || (EXT_ORIGIN || '*'))
  .split(',').map(s => s.trim()).filter(Boolean);
const MODEL_ALLOWLIST = (process.env.MODEL_ALLOWLIST || 'gemini-2.0-flash,gemini-2.0-flash-lite')
  .split(',').map(s => s.trim()).filter(Boolean);
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const LICENSE_KEYS_SPEC = process.env.LICENSE_KEYS || '';
const LICENSE_RECORDS = parseLicenseList(LICENSE_KEYS_SPEC);
const HAS_LICENSES = LICENSE_RECORDS.length > 0;
const usageCounters = new Map();
const googleUsers = new Map();
const webSessions = new Map();

if (!GEMINI_API_KEY) console.warn('[WARN] GEMINI_API_KEY is not set. Requests will fail.');
if (!INTERNAL_AUTH_TOKEN) console.warn('[WARN] INTERNAL_AUTH_TOKEN is not set.');
if (!EXTENSION_ID) console.warn('[WARN] EXTENSION_ID is not set. CORS/origin checks are relaxed.');
if (AUTH_SECRET.length < 32) console.warn('[WARN] AUTH_SECRET should be >= 32 chars.');
if (!HAS_LICENSES) console.warn('[WARN] No LICENSE_KEYS configured. License session endpoint will reject requests.');

// ===== App =====
const app = Fastify({
  logger: true,
  bodyLimit: BODY_LIMIT_BYTES,
  trustProxy: true
});

await app.register(helmet, { contentSecurityPolicy: false });
await app.register(cors, {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Extension-Id', 'X-Internal-Auth'],
  credentials: false
});
await app.register(rateLimit, {
  max: RATE_LIMIT_PER_MINUTE,
  timeWindow: '1 minute',
  continueExceeding: false,
  addHeaders: {
    'x-ratelimit-limit': true,
    'x-ratelimit-remaining': true,
    'x-ratelimit-reset': true
  }
});
await app.register(cookie, { hook: 'onRequest' });
await app.register(fastifyRawBody, { field: 'rawBody', global: false, runFirst: true, encoding: false });

// ===== Helpers =====
const enc = new TextEncoder();
const jwtKey = enc.encode(AUTH_SECRET);

function stripQuotes(value = '') {
  return value.replace(/^['"\s]+|['"\s]+$/g, '');
}

function sha256Buffer(value = '') {
  return createHash('sha256').update(value).digest();
}

function parseLicenseList(rawList = '') {
  return rawList
    .split(/[,\n]/)
    .map(entry => entry.trim())
    .filter(entry => entry && !entry.startsWith('#'))
    .map((entry, idx) => {
      const delim = entry.indexOf(':');
      let label;
      let secret;
      if (delim >= 0) {
        label = entry.slice(0, delim).trim();
        secret = entry.slice(delim + 1).trim();
      } else {
        label = `license-${idx + 1}`;
        secret = entry;
      }
      const normalized = stripQuotes(secret);
      if (!normalized) return null;
      return {
        id: label || `license-${idx + 1}`,
        hash: sha256Buffer(normalized)
      };
    })
    .filter(Boolean);
}

function constantTimeCompare(bufA, bufB) {
  if (!bufA || !bufB || bufA.length !== bufB.length) return false;
  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function verifyLicenseKey(candidate) {
  if (!candidate || !HAS_LICENSES) return null;
  const normalized = stripQuotes(candidate);
  if (!normalized) return null;
  const hashed = sha256Buffer(normalized);
  for (const record of LICENSE_RECORDS) {
    if (constantTimeCompare(hashed, record.hash)) {
      return record;
    }
  }
  return null;
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
}

function maskContents(contents) {
  try {
    if (!Array.isArray(contents)) return '[invalid-contents]';
    const firstText = contents?.[0]?.parts?.[0]?.text;
    if (typeof firstText !== 'string') return '[no-text]';
    const trimmed = firstText.slice(0, 120);
    return `${trimmed}${firstText.length > 120 ? 'â€¦' : ''}`;
  } catch { return '[mask-error]'; }
}

function usageFrom(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const u = obj.usageMetadata;
  if (u && typeof u === 'object') {
    return {
      total: u.totalTokenCount,
      input: u.promptTokenCount,
      output: u.candidatesTokenCount,
      reasoning: u.reasoningTokenCount,
      input_cached: u.cachedPromptTokenCount
    };
  }
  const u2 = obj.usage;
  if (u2 && typeof u2 === 'object') {
    return {
      total: u2.total_tokens,
      input: u2.prompt_tokens,
      output: u2.completion_tokens,
      reasoning: u2.reasoning_tokens || u2.total_reasoning_tokens,
      input_cached: u2.prompt_tokens_details && u2.prompt_tokens_details.cached_tokens
    };
  }
  return null;
}

function setUsageHeaders(reply, usage) {
  if (!usage) return;
  if (usage.total !== undefined) reply.header('X-Token-Usage-Total', String(usage.total));
  if (usage.input !== undefined) reply.header('X-Token-Usage-Input', String(usage.input));
  if (usage.input_cached !== undefined) reply.header('X-Token-Usage-Input-Cached', String(usage.input_cached));
  if (usage.output !== undefined) reply.header('X-Token-Usage-Output', String(usage.output));
  if (usage.reasoning !== undefined) reply.header('X-Token-Usage-Reasoning', String(usage.reasoning));
}

function getUsageBucket(key) {
  if (!key) return null;
  const today = new Date().toISOString().slice(0, 10);
  let bucket = usageCounters.get(key);
  if (!bucket || bucket.date !== today) {
    bucket = { date: today, count: 0 };
    usageCounters.set(key, bucket);
  }
  return bucket;
}

function quotaSnapshot(bucket) {
  if (!bucket || !FREE_DAILY_LIMIT) return null;
  const remaining = Math.max(0, FREE_DAILY_LIMIT - bucket.count);
  return { limit: FREE_DAILY_LIMIT, remaining };
}

function ensureDevEmail(candidate) {
  const raw = (candidate || '').toString().trim();
  if (raw) return raw.toLowerCase();
  if (GOOGLE_LOGIN_DEV_DEFAULT_EMAIL) return GOOGLE_LOGIN_DEV_DEFAULT_EMAIL.toLowerCase();
  return 'tester@example.com';
}

function ensureGoogleUser(email) {
  const key = email.toLowerCase();
  let user = googleUsers.get(key);
  if (!user) {
    user = { id: key, email: key, plan: 'trial', createdAt: new Date().toISOString() };
    googleUsers.set(key, user);
  }
  return user;
}

function currentQuotaForUser(user) {
  if (!user || user.plan === 'pro') return null;
  const bucket = FREE_DAILY_LIMIT ? getUsageBucket(user.id) : null;
  const snapshot = quotaSnapshot(bucket);
  return snapshot ? { ...snapshot, upgradeUrl: UPGRADE_URL } : null;
}

function accountPayloadForUser(user) {
  if (!user) return { sub: null, email: null, plan: 'none', trial_remaining: null };
  const quota = currentQuotaForUser(user);
  return {
    sub: user.id,
    email: user.email,
    plan: user.plan || 'trial',
    trial_remaining: quota ? quota.remaining : null
  };
}

function createWebSession(userId) {
  if (!userId) throw new Error('Missing user id');
  const id = randomUUID();
  webSessions.set(id, { userId, expiresAt: Date.now() + WEB_SESSION_TTL_MS });
  return id;
}

function getWebSession(sessionId) {
  if (!sessionId) return null;
  const state = webSessions.get(sessionId);
  if (!state) return null;
  if (state.expiresAt <= Date.now()) {
    webSessions.delete(sessionId);
    return null;
  }
  return state;
}

function refreshWebSession(sessionId) {
  const state = webSessions.get(sessionId);
  if (state) state.expiresAt = Date.now() + WEB_SESSION_TTL_MS;
}

function destroyWebSession(sessionId) {
  if (!sessionId) return;
  webSessions.delete(sessionId);
}

function setWebSessionCookie(reply, sessionId) {
  const opts = {
    httpOnly: true,
    sameSite: WEB_SESSION_COOKIE_SAME_SITE,
    path: '/',
    secure: WEB_SESSION_COOKIE_SECURE,
    maxAge: WEB_SESSION_TTL_SECONDS
  };
  if (WEB_SESSION_COOKIE_DOMAIN) opts.domain = WEB_SESSION_COOKIE_DOMAIN;
  reply.setCookie(WEB_SESSION_COOKIE_NAME, sessionId, opts);
}

function clearWebSessionCookie(reply) {
  const opts = { path: '/', sameSite: WEB_SESSION_COOKIE_SAME_SITE };
  if (WEB_SESSION_COOKIE_DOMAIN) opts.domain = WEB_SESSION_COOKIE_DOMAIN;
  reply.clearCookie(WEB_SESSION_COOKIE_NAME, opts);
}

function sessionFromRequest(req) {
  if (!req || !req.cookies) return null;
  const sessionId = req.cookies[WEB_SESSION_COOKIE_NAME];
  if (!sessionId) return null;
  const state = getWebSession(sessionId);
  if (!state) return null;
  refreshWebSession(sessionId);
  return { id: sessionId, userId: state.userId };
}

function payuPlanMeta(planId) {
  const amount = PAYU_AMOUNT_PRO;
  if (!amount) return null;
  const durationMs = PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000;
  return { amount, durationMs, description: 'Reviews Coach PRO' };
}

function buildPayuExtOrderId(userId, planId) {
  const encoded = Buffer.from(userId || 'anon').toString('base64url');
  return `rc|${encoded}|${planId}|${Date.now()}`;
}

function parsePayuExtOrderId(extOrderId) {
  const parts = typeof extOrderId === 'string' ? extOrderId.split('|') : [];
  if (parts.length < 4 || parts[0] !== 'rc') return { userId: null, planId: null };
  let decoded = null;
  try {
    decoded = Buffer.from(parts[1], 'base64url').toString('utf8');
  } catch (_err) {
    decoded = null;
  }
  return { userId: decoded, planId: parts[2] };
}

function rememberPayuOrder(extOrderId, meta) {
  if (!extOrderId) return;
  payuOrderMap.set(extOrderId, { ...meta, createdAt: Date.now() });
}

function consumePayuOrder(extOrderId) {
  if (!extOrderId) return null;
  const meta = payuOrderMap.get(extOrderId) || null;
  payuOrderMap.delete(extOrderId);
  return meta;
}

async function ensurePayuAccessToken() {
  if (!PAYU_ENABLED) throw new Error('PayU is not configured');
  if (payuTokenCache.token && Date.now() < payuTokenCache.expiresAt - 5000) {
    return payuTokenCache.token;
  }
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: PAYU_CLIENT_ID,
    client_secret: PAYU_CLIENT_SECRET
  });
  const resp = await fetch(`${PAYU_API_BASE_URL}/pl/standard/user/oauth/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  if (!resp.ok) {
    throw new Error(`PayU auth failed ${resp.status}`);
  }
  const data = await resp.json();
  const token = (data.access_token || '').trim();
  if (!token) throw new Error('PayU auth returned empty token');
  const expiresIn = Number(data.expires_in || data.expires || 3600);
  payuTokenCache.token = token;
  payuTokenCache.expiresAt = Date.now() + Math.max(0, expiresIn - 10) * 1000;
  return token;
}

async function createPayuOrderForPlan(user, planId, customerIp) {
  if (!PAYU_ENABLED) throw new Error('PayU is not configured');
  const meta = payuPlanMeta(planId);
  if (!meta) throw new Error('Unsupported plan_id');
  const token = await ensurePayuAccessToken();
  const extOrderId = buildPayuExtOrderId(user.id, planId);
  const payload = {
    notifyUrl: PAYU_NOTIFY_URL,
    continueUrl: PAYU_CONTINUE_URL || UPGRADE_URL || 'https://example.com',
    customerIp: customerIp || '127.0.0.1',
    merchantPosId: PAYU_POS_ID || '0',
    description: meta.description,
    currencyCode: PAYU_CURRENCY,
    totalAmount: meta.amount,
    extOrderId,
    buyer: {
      email: user.email || 'customer@example.com',
      language: 'pl'
    },
    products: [
      { name: meta.description, unitPrice: meta.amount, quantity: '1' }
    ]
  };
  const resp = await fetch(`${PAYU_API_BASE_URL}/api/v2_1/orders`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify(payload)
  });
  const data = await resp.json().catch(() => null);
  if (!resp.ok || data?.status?.statusCode !== 'SUCCESS') {
    throw new Error(data?.status?.statusDesc || `PayU order failed ${resp.status}`);
  }
  const redirectUri = data?.redirectUri || (Array.isArray(data?.properties)
    ? (data.properties.find(p => p.name === 'PAYMENT_URL')?.value || null)
    : null);
  if (!redirectUri) throw new Error('PayU order missing redirect URL');
  rememberPayuOrder(extOrderId, { userId: user.id, planId, durationMs: meta.durationMs });
  return { redirectUri, extOrderId };
}

function payuSignatureValid(rawBody, header) {
  if (!PAYU_ENABLED || !PAYU_SECOND_KEY) return false;
  if (!rawBody || !header) return false;
  const parts = Object.create(null);
  header.split(';').forEach(fragment => {
    const [key, value] = fragment.split('=');
    if (key && value) parts[key.trim().toLowerCase()] = value.trim();
  });
  const provided = (parts.signature || '').toLowerCase();
  const algorithm = (parts.algorithm || '').toLowerCase();
  if (!provided || algorithm !== 'md5') return false;
  const expected = createHash('md5').update(String(rawBody) + PAYU_SECOND_KEY).digest('hex');
  return provided.length === expected.length && timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(provided, 'utf8'));
}

async function applyPaidPlan(user, planId, durationMs) {
  if (!user) return;
  user.plan = 'pro';
  if (durationMs) {
    user.planExpiresAt = new Date(Date.now() + durationMs).toISOString();
  }
}

const unauthorized = (reply, msg='Unauthorized') => reply.code(401).send({ error: msg });
const forbidden    = (reply, msg='Forbidden')    => reply.code(403).send({ error: msg });
const badRequest   = (reply, msg='Bad Request')  => reply.code(400).send({ error: msg });

async function signJwt(payload, ttlSec = JWT_TTL_SECONDS) {
  const now = Math.floor(Date.now()/1000);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setIssuer('reviews-coach-proxy')
    .setAudience('reviews-coach-proxy')
    .setExpirationTime(now + ttlSec)
    .sign(jwtKey);
}

async function verifyJwt(token) {
  const { payload } = await jwtVerify(token, jwtKey, {
    issuer: 'reviews-coach-proxy',
    audience: 'reviews-coach-proxy'
  });
  return payload;
}

// ===== Global checks =====
app.addHook('onRequest', async (req, reply) => {
  reply.header('Cache-Control', 'no-store');

  const ip = clientIp(req);
  if (ALLOWED_IPS.length && !ALLOWED_IPS.includes(ip)) {
    return forbidden(reply, 'IP not allowed');
  }
});

// ===== Health =====
app.get('/health', async () => ({ status: 'ok' }));

// ===== Auth #1: nasz dotychczasowy endpoint (Bearer admin token) =====
// Headers: Authorization: Bearer <INTERNAL_AUTH_TOKEN>
// Optionally: X-Extension-Id: <EXTENSION_ID> (sprawdzamy zgodnoĹ›Ä‡ gdy ustawiony EXTENSION_ID)
app.post('/auth/token', async (req, reply) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return unauthorized(reply);
  const token = auth.slice('Bearer '.length);
  if (token !== INTERNAL_AUTH_TOKEN) return unauthorized(reply);

  if (EXTENSION_ID) {
    const origin = req.headers['origin'];
    const xExt = req.headers['x-extension-id'];
    if (origin && origin !== `chrome-extension://${EXTENSION_ID}`) {
      return unauthorized(reply, 'Invalid origin');
    }
    if (xExt && xExt !== EXTENSION_ID) {
      return unauthorized(reply, 'Invalid extension id');
    }
  }

  const signed = await signJwt({ extid: EXTENSION_ID || null, scope: 'gen' }, JWT_TTL_SECONDS);
  return reply.send({ token: signed, expiresIn: JWT_TTL_SECONDS });
});

// ===== Auth #2: alias kompatybilny z obecnÄ… wtyczkÄ… (X-Internal-Auth) =====
// Request:
//   Header: X-Internal-Auth: <INTERNAL_AUTH_TOKEN>
//   Body:   { extensionId, version }
// Response: { token, expiresAt, expiresIn }
app.post('/api/extension/jwt', async (req, reply) => {
  const hdr = req.headers['x-internal-auth'];
  if (!hdr || hdr !== INTERNAL_AUTH_TOKEN) {
    return unauthorized(reply);
  }

  const { extensionId } = req.body || {};
  if (EXTENSION_ID && extensionId && extensionId !== EXTENSION_ID) {
    return unauthorized(reply, 'Invalid extensionId');
  }

  const ttlSec = JWT_TTL_SECONDS;
  const nowMs = Date.now();
  const token = await signJwt({ extid: EXTENSION_ID || extensionId || null, scope: 'gen' }, ttlSec);

  return reply.send({
    token,
    expiresIn: ttlSec,
    expiresAt: new Date(nowMs + ttlSec * 1000).toISOString()
  });
});

// ===== Auth #3: licencje uĹĽytkownikĂłw =====
// Request body: { licenseKey: string, extensionId?: string, installId?: string }
// Header: X-Extension-Id: <EXTENSION_ID>
app.post('/api/extension/session', async (req, reply) => {
  if (!HAS_LICENSES) {
    app.log.warn({ msg: 'Session requested but no LICENSE_KEYS configured' });
    return reply.code(503).send({ error: 'Licensing not configured' });
  }

  const { licenseKey, extensionId, installId } = req.body || {};
  if (!licenseKey || typeof licenseKey !== 'string') {
    return badRequest(reply, 'Field "licenseKey" is required');
  }

  const extFromBody = typeof extensionId === 'string' && extensionId.trim() ? extensionId.trim() : null;
  const headerExt = typeof req.headers['x-extension-id'] === 'string' ? req.headers['x-extension-id'] : null;
  if (EXTENSION_ID) {
    if (headerExt && headerExt !== EXTENSION_ID) {
      return unauthorized(reply, 'Invalid extension id');
    }
    if (extFromBody && extFromBody !== EXTENSION_ID) {
      return unauthorized(reply, 'Invalid extension id');
    }
  }
  const resolvedExt = EXTENSION_ID || extFromBody || headerExt || null;

  const license = verifyLicenseKey(licenseKey);
  if (!license) {
    app.log.warn({ msg: 'Invalid license attempt', ip: clientIp(req), ext: resolvedExt });
    return unauthorized(reply, 'Invalid license key');
  }

  const installTag = typeof installId === 'string' && installId.trim()
    ? installId.trim().slice(0, 64)
    : null;
  const nowMs = Date.now();
  const ttlSec = JWT_TTL_SECONDS;
  const bucket = FREE_DAILY_LIMIT ? getUsageBucket(license.id) : null;
  const quota = quotaSnapshot(bucket);
  const token = await signJwt({ extid: resolvedExt, scope: 'gen', license: license.id, install: installTag }, ttlSec);

  return reply.send({
    token,
    expiresIn: ttlSec,
    expiresAt: new Date(nowMs + ttlSec * 1000).toISOString(),
    license: { id: license.id },
    quota: quota ? { ...quota, upgradeUrl: UPGRADE_URL } : null
  });
});

app.post('/api/extension/google-session', async (req, reply) => {
  if (!GOOGLE_LOGIN_DEV_MODE) {
    app.log.warn({ msg: 'Google session requested but GOOGLE_LOGIN_DEV_MODE=false' });
    return reply.code(503).send({ error: 'Google login not configured' });
  }
  const { accessToken, extensionId, installId } = req.body || {};
  const extFromBody = typeof extensionId === 'string' && extensionId.trim() ? extensionId.trim() : null;
  const headerExt = typeof req.headers['x-extension-id'] === 'string' ? req.headers['x-extension-id'] : null;
  if (EXTENSION_ID) {
    if (headerExt && headerExt !== EXTENSION_ID) {
      return unauthorized(reply, 'Invalid extension id');
    }
    if (extFromBody && extFromBody !== EXTENSION_ID) {
      return unauthorized(reply, 'Invalid extension id');
    }
  }
  const resolvedExt = EXTENSION_ID || extFromBody || headerExt || null;
  const email = ensureDevEmail(accessToken);
  const profile = ensureGoogleUser(email);
  const installTag = typeof installId === 'string' && installId.trim()
    ? installId.trim().slice(0, 64)
    : null;
  const ttlSec = JWT_TTL_SECONDS;
  const nowMs = Date.now();
  const quota = currentQuotaForUser(profile);
  const token = await signJwt({ extid: resolvedExt, scope: 'gen', license: profile.id, install: installTag, user: profile.id }, ttlSec);
  return reply.send({
    token,
    expiresIn: ttlSec,
    expiresAt: new Date(nowMs + ttlSec * 1000).toISOString(),
    profile: { email: profile.email, sub: profile.id },
    quota
  });
});

app.post('/api/web/google-login', async (req, reply) => {
  if (!GOOGLE_LOGIN_DEV_MODE) {
    return reply.code(503).send({ error: 'Google login not configured' });
  }
  const rawToken = req.body && typeof req.body.id_token === 'string' ? req.body.id_token.trim() : '';
  const email = ensureDevEmail(rawToken);
  const user = ensureGoogleUser(email);
  const sessionId = createWebSession(user.id);
  setWebSessionCookie(reply, sessionId);
  reply.header('Cache-Control', 'no-store');
  return reply.send(accountPayloadForUser(user));
});

app.get('/api/web/account/status', async (req, reply) => {
  reply.header('Cache-Control', 'no-store');
  const session = sessionFromRequest(req);
  if (!session) {
    return reply.send(accountPayloadForUser(null));
  }
  const user = googleUsers.get(session.userId);
  if (!user) {
    destroyWebSession(session.id);
    clearWebSessionCookie(reply);
    return reply.send(accountPayloadForUser(null));
  }
  return reply.send(accountPayloadForUser(user));
});

app.post('/api/web/account/upgrade', async (req, reply) => {
  const session = sessionFromRequest(req);
  if (!session) {
    return unauthorized(reply, 'Not authenticated');
  }
  const user = googleUsers.get(session.userId);
  if (!user) {
    destroyWebSession(session.id);
    clearWebSessionCookie(reply);
    return unauthorized(reply, 'Not authenticated');
  }
  const rawPlanId = req.body && typeof req.body.plan_id === 'string' ? req.body.plan_id.trim() : 'pro';
  if (PAYU_DEV_MODE) {
    await applyPaidPlan(user, rawPlanId, PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000);
    const checkout = PAYU_MOCK_PAYMENT_URL || PAYU_CONTINUE_URL || UPGRADE_URL || 'https://payu.example.com/mock';
    return reply.send({ checkout_url: checkout, provider: 'payu', mock: true });
  }
  if (PAYU_ENABLED) {
    try {
      const order = await createPayuOrderForPlan(user, rawPlanId, clientIp(req));
      return reply.send({ checkout_url: order.redirectUri, provider: 'payu', order_id: order.extOrderId });
    } catch (err) {
      app.log.error({ msg: 'PayU order failed', err: err?.message || err, plan: rawPlanId });
    }
  }
  await applyPaidPlan(user, rawPlanId, PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000);
  const redirect = UPGRADE_URL || 'https://example.com/upgrade';
  return reply.send({ checkout_url: redirect, provider: GOOGLE_LOGIN_DEV_MODE ? 'dev' : 'manual' });
});

app.post('/api/billing/payu-webhook', { config: { rawBody: true } }, async (req, reply) => {
  if (!PAYU_ENABLED) {
    app.log.warn({ msg: 'PayU webhook invoked but not configured' });
    return reply.code(503).send({ error: 'PayU not configured' });
  }
  const signatureHeader = req.headers['openpayu-signature'];
  const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
  const rawBody = req.rawBody ? req.rawBody.toString('utf8') : (req.body ? JSON.stringify(req.body) : '');
  if (!payuSignatureValid(rawBody, signature)) {
    app.log.warn({ msg: 'PayU webhook signature invalid' });
    return reply.code(400).send({ error: 'Invalid signature' });
  }
  let payload;
  try {
    payload = rawBody ? JSON.parse(rawBody) : req.body || {};
  } catch (err) {
    return reply.code(400).send({ error: 'Invalid JSON' });
  }
  const order = payload?.order || (Array.isArray(payload?.orders) ? payload.orders[0] : null);
  if (!order) {
    return reply.code(400).send({ error: 'Missing order payload' });
  }
  const extOrderId = order.extOrderId || order.orderId || order?.order?.extOrderId || null;
  const status = (order.status || order.statusCode || '').toString().toUpperCase();
  if (!extOrderId) {
    return reply.code(400).send({ error: 'Missing extOrderId' });
  }
  if (status === 'COMPLETED' || status === 'SUCCESS') {
    const pending = consumePayuOrder(extOrderId) || parsePayuExtOrderId(extOrderId);
    const user = pending?.userId ? googleUsers.get(pending.userId) : null;
    if (user) {
      await applyPaidPlan(user, pending.planId || 'pro', pending.durationMs || (PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000));
    } else {
      app.log.warn({ msg: 'PayU webhook references unknown user', extOrderId, pending });
    }
  }
  return reply.send({ received: true });
});

// ===== Client log collector =====
app.post('/api/extension/log', async (req, reply) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return unauthorized(reply);
  const token = auth.slice('Bearer '.length);
  let payload;
  try {
    payload = await verifyJwt(token);
  } catch (err) {
    app.log.warn({ msg: 'Log endpoint token invalid', err: String(err) });
    return unauthorized(reply, 'Invalid token');
  }
  const rawLevel = (req.body && req.body.level) ? String(req.body.level).toLowerCase() : 'info';
  const allowed = new Set(['trace', 'debug', 'info', 'warn', 'error', 'fatal']);
  const level = allowed.has(rawLevel) ? rawLevel : 'info';
  const message = (req.body && req.body.message) ? String(req.body.message).slice(0, 400) : 'client-log';
  const context = (req.body && typeof req.body.context === 'object') ? req.body.context : null;
  app.log[level]({
    msg: message,
    source: 'extension',
    license: payload.license,
    install: payload.install,
    context
  });
  return reply.send({ ok: true });
});

// ===== Proxy endpoint =====
app.post('/gemini/generate', async (req, reply) => {
  if (!GEMINI_API_KEY) {
    app.log.error('Missing GEMINI_API_KEY');
    return reply.code(500).send({ error: 'Server not configured' });
  }

  // JWT wymagany
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return unauthorized(reply);
  const token = auth.slice('Bearer '.length);

  // weryfikacja
  let tokenPayload;
  try {
    tokenPayload = await verifyJwt(token);
    if (EXTENSION_ID && tokenPayload.extid && tokenPayload.extid !== EXTENSION_ID) {
      return unauthorized(reply, 'Token/ext mismatch');
    }
  } catch (e) {
    app.log.warn({ msg: 'JWT verify failed', err: String(e) });
    return unauthorized(reply, 'Invalid token');
  }

  // ograniczenia modelu + walidacja body
  const body = req.body || {};
  const { model, contents } = body;
  if (!model || typeof model !== 'string') return badRequest(reply, 'Field "model" must be a non-empty string');
  if (!Array.isArray(contents)) return badRequest(reply, 'Field "contents" must be an array');
  if (MODEL_ALLOWLIST.length && !MODEL_ALLOWLIST.includes(model)) {
    return forbidden(reply, 'Model not allowed');
  }

  const licenseId = tokenPayload?.user || tokenPayload?.license || 'dev-user';
  const bucket = FREE_DAILY_LIMIT ? getUsageBucket(licenseId) : null;
  const rejectQuotaResponse = (message, remainingOverride) => {
    reply.header('X-Free-Limit', String(FREE_DAILY_LIMIT));
    reply.header('X-Free-Remaining', String(Math.max(0, remainingOverride ?? 0)));
    return reply.code(402).send({
      error: message,
      code: 'FREE_LIMIT_REACHED',
      limit: FREE_DAILY_LIMIT,
      remaining: Math.max(0, remainingOverride ?? 0),
      upgradeUrl: UPGRADE_URL
    });
  };
  if (bucket && FREE_DAILY_LIMIT && bucket.count >= FREE_DAILY_LIMIT) {
    return rejectQuotaResponse('Limit darmowych wygenerowań został wykorzystany.', 0);
  }

  const stampQuotaHeaders = (remainingOverride) => {
    if (!FREE_DAILY_LIMIT || !bucket) return;
    const remaining = (typeof remainingOverride === 'number')
      ? Math.max(0, remainingOverride)
      : Math.max(0, FREE_DAILY_LIMIT - bucket.count);
    reply.header('X-Free-Limit', String(FREE_DAILY_LIMIT));
    reply.header('X-Free-Remaining', String(remaining));
  };

  // twardy timeout do upstream
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

  try {
    const url = `https://generativelanguage.googleapis.com/v1/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    const text = await res.text();
    let parsed; try { parsed = JSON.parse(text); } catch { parsed = null; }

    if (res.ok) {
      if (bucket && FREE_DAILY_LIMIT) {
        bucket.count += 1;
        const remaining = Math.max(0, FREE_DAILY_LIMIT - bucket.count);
        stampQuotaHeaders(remaining);
        const freeMessage = remaining > 0
          ? `Remaining ${remaining} of ${FREE_DAILY_LIMIT} free responses.`
          : 'Free response limit reached.';
        reply.header('X-Free-Message', freeMessage);
      }
      const usage = usageFrom(parsed);
      if (usage) setUsageHeaders(reply, usage);
      return reply.code(200).type('application/json').send(parsed ?? text);
    } else {
      if (res.status === 429) {
        const quotaPayload = quotaSnapshot(bucket) || { limit: FREE_DAILY_LIMIT || 0, remaining: 0, upgradeUrl: UPGRADE_URL };
        reply.header('X-Free-Limit', String(quotaPayload.limit ?? FREE_DAILY_LIMIT ?? 0));
        reply.header('X-Free-Remaining', '0');
        return reply.code(402).send({
          error: 'Limit darmowych odpowiedzi został wykorzystany.',
          code: 'FREE_LIMIT_REACHED',
          limit: quotaPayload.limit ?? FREE_DAILY_LIMIT ?? 0,
          remaining: 0,
          upgradeUrl: quotaPayload.upgradeUrl ?? UPGRADE_URL
        });
      }
      stampQuotaHeaders();
      app.log.error({
        msg: 'Upstream Gemini error',
        status: res.status,
        statusText: res.statusText,
        bodyPreview: String(text).slice(0, 200),
        promptPreview: maskContents(contents)
      });
      return reply.code(res.status).send({ error: (parsed && parsed.error && parsed.error.message) || `Upstream error ${res.status}` });
    }
  } catch (err) {
    const isTimeout = err?.name === 'AbortError';
    app.log.error({ msg: 'Request to Gemini failed', error: String(err), promptPreview: maskContents(contents) });
    stampQuotaHeaders();
    return reply.code(isTimeout ? 504 : 502).send({ error: isTimeout ? 'Upstream timeout' : 'Upstream failure' });
  } finally {
    clearTimeout(timeout);
  }
});

// ===== Start =====
export { app };

if (process.env.NODE_ENV !== 'test') {
  app.listen({ port: PORT, host: '0.0.0.0' })
    .then(addr => app.log.info(`Server listening on ${addr}`))
    .catch(err => { app.log.error(err); process.exit(1); });
}
