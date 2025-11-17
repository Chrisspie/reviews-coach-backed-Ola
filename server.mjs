import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { SignJWT, jwtVerify } from 'jose';
import { createHash, timingSafeEqual } from 'node:crypto';

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
    return `${trimmed}${firstText.length > 120 ? '…' : ''}`;
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
// Optionally: X-Extension-Id: <EXTENSION_ID> (sprawdzamy zgodność gdy ustawiony EXTENSION_ID)
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

// ===== Auth #2: alias kompatybilny z obecną wtyczką (X-Internal-Auth) =====
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

// ===== Auth #3: licencje użytkowników =====
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
  const token = await signJwt({ extid: resolvedExt, scope: 'gen', license: license.id, install: installTag }, ttlSec);

  return reply.send({
    token,
    expiresIn: ttlSec,
    expiresAt: new Date(nowMs + ttlSec * 1000).toISOString(),
    license: { id: license.id }
  });
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
  try {
    const payload = await verifyJwt(token);
    if (EXTENSION_ID && payload.extid && payload.extid !== EXTENSION_ID) {
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
      const usage = usageFrom(parsed);
      if (usage) setUsageHeaders(reply, usage);
      return reply.code(200).type('application/json').send(parsed ?? text);
    } else {
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
    return reply.code(isTimeout ? 504 : 502).send({ error: isTimeout ? 'Upstream timeout' : 'Upstream failure' });
  } finally {
    clearTimeout(timeout);
  }
});

// ===== Start =====
app.listen({ port: PORT, host: '0.0.0.0' })
  .then(addr => app.log.info(`Server listening on ${addr}`))
  .catch(err => { app.log.error(err); process.exit(1); });
