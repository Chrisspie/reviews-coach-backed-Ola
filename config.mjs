import { createHash } from 'node:crypto';

function toBool(value = '') {
  return value.toLowerCase() === 'true';
}

function parseInteger(value, fallback) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function loadConfig(env = process.env) {
  const PORT = parseInteger(env.PORT ?? '3000', 3000);
  const GEMINI_API_KEY = env.GEMINI_API_KEY || '';
  const INTERNAL_AUTH_TOKEN = env.INTERNAL_AUTH_TOKEN || '';
  const AUTH_SECRET = env.AUTH_SECRET || 'change-me-change-me-change-me';
  const EXTENSION_ID = env.EXTENSION_ID || '';

  const JWT_TTL_SECONDS = parseInteger(env.JWT_TTL_SECONDS ?? '600', 600);
  const RATE_LIMIT_PER_MINUTE = parseInteger(env.RATE_LIMIT_PER_MINUTE ?? '60', 60);
  const BODY_LIMIT_BYTES = parseInteger(env.BODY_LIMIT_BYTES ?? String(25 * 1024), 25 * 1024);
  const GEMINI_TIMEOUT_MS = parseInteger(env.GEMINI_TIMEOUT_MS ?? '15000', 15000);
  const FREE_DAILY_LIMIT = Math.max(0, parseInteger(env.FREE_DAILY_LIMIT ?? '5', 5));
  const UPGRADE_URL = (env.UPGRADE_URL || '').trim();
  const PAYU_DEV_MODE = toBool(env.PAYU_DEV_MODE || 'false');
  const PAYU_POS_ID = (env.PAYU_POS_ID || '').trim();
  const PAYU_CLIENT_ID = (env.PAYU_CLIENT_ID || '').trim();
  const PAYU_CLIENT_SECRET = (env.PAYU_CLIENT_SECRET || '').trim();
  const PAYU_SECOND_KEY = (env.PAYU_SECOND_KEY || '').trim();
  const PAYU_NOTIFY_URL = (env.PAYU_NOTIFY_URL || '').trim();
  const PAYU_CONTINUE_URL = (env.PAYU_CONTINUE_URL || UPGRADE_URL || '').trim();
  const PAYU_MOCK_PAYMENT_URL = (env.PAYU_MOCK_PAYMENT_URL || 'https://payu.example.com/mock-checkout').trim();
  const PAYU_CURRENCY = ((env.PAYU_CURRENCY || 'PLN').trim().toUpperCase()) || 'PLN';
  const PAYU_API_BASE_URL = (env.PAYU_API_BASE_URL || 'https://secure.snd.payu.com').replace(/\/+$/, '');
  const PAYU_AMOUNT_PRO = (env.PAYU_AMOUNT_PRO || '9900').trim();
  const PAYU_PLAN_DURATION_DAYS = Math.max(1, parseInteger(env.PAYU_PLAN_DURATION_DAYS ?? '30', 30));
  const PAYU_ENABLED = Boolean(
    PAYU_POS_ID && PAYU_CLIENT_ID && PAYU_CLIENT_SECRET && PAYU_SECOND_KEY && PAYU_NOTIFY_URL && PAYU_CONTINUE_URL && PAYU_AMOUNT_PRO
  );
  const GOOGLE_LOGIN_DEV_MODE = toBool(env.GOOGLE_LOGIN_DEV_MODE || 'false');
  const GOOGLE_LOGIN_DEV_DEFAULT_EMAIL = (env.GOOGLE_LOGIN_DEV_DEFAULT_EMAIL || '').trim();
  const WEB_SESSION_COOKIE_NAME = env.WEB_SESSION_COOKIE_NAME || 'rc_web_session';
  const WEB_SESSION_COOKIE_DOMAIN = env.WEB_SESSION_COOKIE_DOMAIN || undefined;
  const WEB_SESSION_COOKIE_SECURE = toBool(env.WEB_SESSION_COOKIE_SECURE || 'false');
  const WEB_SESSION_TTL_SECONDS = (() => {
    const fallback = 60 * 60 * 24 * 7;
    const parsed = parseInteger(env.WEB_SESSION_TTL_SECONDS ?? String(fallback), fallback);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  })();
  const WEB_SESSION_COOKIE_SAME_SITE = (() => {
    const raw = (env.WEB_SESSION_COOKIE_SAMESITE || (WEB_SESSION_COOKIE_SECURE ? 'none' : 'lax')).toLowerCase();
    if (raw === 'lax' || raw === 'strict' || raw === 'none') return raw;
    return WEB_SESSION_COOKIE_SECURE ? 'none' : 'lax';
  })();
  const WEB_SESSION_TTL_MS = WEB_SESSION_TTL_SECONDS * 1000;

  const EXT_ORIGIN = EXTENSION_ID ? `chrome-extension://${EXTENSION_ID}` : null;
  const CORS_ORIGINS = (env.CORS_ORIGINS || (EXT_ORIGIN || '*'))
    .split(',').map(s => s.trim()).filter(Boolean);
  const MODEL_ALLOWLIST = (env.MODEL_ALLOWLIST || 'gemini-2.0-flash,gemini-2.0-flash-lite')
    .split(',').map(s => s.trim()).filter(Boolean);
  const ALLOWED_IPS = (env.ALLOWED_IPS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  const LICENSE_KEYS_SPEC = env.LICENSE_KEYS || '';
  const LICENSE_RECORDS = parseLicenseList(LICENSE_KEYS_SPEC);
  const HAS_LICENSES = LICENSE_RECORDS.length > 0;

  if (!GEMINI_API_KEY) console.warn('[WARN] GEMINI_API_KEY is not set. Requests will fail.');
  if (!INTERNAL_AUTH_TOKEN) console.warn('[WARN] INTERNAL_AUTH_TOKEN is not set.');
  if (!EXTENSION_ID) console.warn('[WARN] EXTENSION_ID is not set. CORS/origin checks are relaxed.');
  if (AUTH_SECRET.length < 32) console.warn('[WARN] AUTH_SECRET should be >= 32 chars.');
  if (!HAS_LICENSES) console.warn('[WARN] No LICENSE_KEYS configured. License session endpoint will reject requests.');

  return {
    PORT,
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
  };
}

export function stripQuotes(value = '') {
  return value.replace(/^['"\s]+|['"\s]+$/g, '');
}

export function sha256Buffer(value = '') {
  return createHash('sha256').update(value).digest();
}

export function parseLicenseList(rawList = '') {
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
