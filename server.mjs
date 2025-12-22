import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { SignJWT, jwtVerify } from 'jose';
import cookie from '@fastify/cookie';
import fastifyRawBody from 'fastify-raw-body';
import { createHash, timingSafeEqual, randomUUID } from 'node:crypto';

import { loadConfig } from './config.mjs';
import { createLicenseVerifier } from './lib/licenses.mjs';
import { getUsageBucket as ensureUsageBucket, quotaSnapshot as quotaSnapshotForLimit } from './lib/quota.mjs';
import { maskContents, usageFrom, setUsageHeaders } from './lib/gemini.mjs';
import { clientIp } from './lib/request.mjs';
import { unauthorized, forbidden, badRequest } from './lib/reply.mjs';
import { createHealthRoutes } from './routes/health.mjs';
import { createAuthRoutes } from './routes/auth.mjs';
import { createExtensionRoutes } from './routes/extension.mjs';
import { createWebRoutes } from './routes/web.mjs';
import { createBillingRoutes } from './routes/billing.mjs';
import { createLogRoutes } from './routes/log.mjs';
import { createProxyRoutes } from './routes/proxy.mjs';


const resolvedConfig = loadConfig();
const app = await createApp(resolvedConfig);

export { app, createApp, resolvedConfig as config };

if (process.env.NODE_ENV !== 'test') {
  app.listen({ port: resolvedConfig.PORT, host: '0.0.0.0' })
    .then(addr => app.log.info(`Server listening on ${addr}`))
    .catch(err => { app.log.error(err); process.exit(1); });
}

async function createApp(providedConfig = loadConfig()) {
  const config = providedConfig;
  const {
    GEMINI_API_KEY,
    INTERNAL_AUTH_TOKEN,
    AUTH_SECRET,
    EXTENSION_ID,
    JWT_TTL_SECONDS,
    RATE_LIMIT_PER_MINUTE,
    BODY_LIMIT_BYTES,
    GEMINI_TIMEOUT_MS,
    FREE_DAILY_LIMIT,
    UPGRADE_URL,
    PAYU_DEV_MODE,
    PAYU_POS_ID,
    PAYU_CLIENT_ID,
    PAYU_CLIENT_SECRET,
    PAYU_SECOND_KEY,
    PAYU_NOTIFY_URL,
    PAYU_CONTINUE_URL,
    PAYU_MOCK_PAYMENT_URL,
    PAYU_CURRENCY,
    PAYU_API_BASE_URL,
    PAYU_AMOUNT_PRO,
    PAYU_PLAN_DURATION_DAYS,
    PAYU_ENABLED,
    GOOGLE_LOGIN_DEV_MODE,
    GOOGLE_LOGIN_DEV_DEFAULT_EMAIL,
    WEB_SESSION_COOKIE_NAME,
    WEB_SESSION_COOKIE_DOMAIN,
    WEB_SESSION_COOKIE_SECURE,
    WEB_SESSION_TTL_SECONDS,
    WEB_SESSION_COOKIE_SAME_SITE,
    WEB_SESSION_TTL_MS,
    CORS_ORIGINS,
    MODEL_ALLOWLIST,
    ALLOWED_IPS,
    LICENSE_RECORDS,
    HAS_LICENSES
  } = config;

  const usageCounters = new Map();
  const googleUsers = new Map();
  const webSessions = new Map();
  const payuTokenCache = { token: '', expiresAt: 0 };
  const payuOrderMap = new Map();

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


  const verifyLicenseKey = createLicenseVerifier(LICENSE_RECORDS, HAS_LICENSES);
  const getUsageBucket = (key) => ensureUsageBucket(usageCounters, key);
  const quotaSnapshot = (bucket) => quotaSnapshotForLimit(FREE_DAILY_LIMIT, bucket);

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

  await app.register(createHealthRoutes());

  await app.register(createAuthRoutes({
    INTERNAL_AUTH_TOKEN,
    EXTENSION_ID,
    JWT_TTL_SECONDS,
    signJwt,
    unauthorized
  }));

  await app.register(createExtensionRoutes({
    HAS_LICENSES,
    verifyLicenseKey,
    FREE_DAILY_LIMIT,
    getUsageBucket,
    quotaSnapshot,
    signJwt,
    JWT_TTL_SECONDS,
    EXTENSION_ID,
    UPGRADE_URL,
    ensureDevEmail,
    ensureGoogleUser,
    currentQuotaForUser,
    unauthorized,
    badRequest,
    GOOGLE_LOGIN_DEV_MODE,
    clientIp
  }));

  await app.register(createWebRoutes({
    GOOGLE_LOGIN_DEV_MODE,
    ensureDevEmail,
    ensureGoogleUser,
    createWebSession,
    setWebSessionCookie,
    accountPayloadForUser,
    sessionFromRequest,
    destroyWebSession,
    clearWebSessionCookie,
    unauthorized,
    applyPaidPlan,
    PAYU_DEV_MODE,
    PAYU_PLAN_DURATION_DAYS,
    PAYU_MOCK_PAYMENT_URL,
    PAYU_CONTINUE_URL,
    UPGRADE_URL,
    PAYU_ENABLED,
    createPayuOrderForPlan,
    clientIp,
    googleUsers
  }));

  await app.register(createBillingRoutes({
    PAYU_ENABLED,
    payuSignatureValid,
    consumePayuOrder,
    parsePayuExtOrderId,
    googleUsers,
    applyPaidPlan,
    PAYU_PLAN_DURATION_DAYS
  }));

  await app.register(createLogRoutes({
    verifyJwt,
    unauthorized
  }));

  await app.register(createProxyRoutes({
    GEMINI_API_KEY,
    EXTENSION_ID,
    verifyJwt,
    unauthorized,
    badRequest,
    forbidden,
    getUsageBucket,
    FREE_DAILY_LIMIT,
    quotaSnapshot,
    UPGRADE_URL,
    GEMINI_TIMEOUT_MS,
    usageFrom,
    setUsageHeaders,
    maskContents,
    MODEL_ALLOWLIST
  }));

  return app;
}








