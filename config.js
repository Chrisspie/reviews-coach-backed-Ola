import { createHash } from 'node:crypto';

function parseInteger(value, fallback) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function loadConfig(env = process.env) {
  const PORT = parseInteger(env.PORT ?? '3000', 3000);
  const GEMINI_API_KEY = env.GEMINI_API_KEY || '';
  const INTERNAL_AUTH_TOKEN = env.INTERNAL_AUTH_TOKEN || '';
  const AUTH_SECRET = env.AUTH_SECRET || 'change-me-change-me-change-me';
  const EXTENSION_ID = '';

  const JWT_TTL_SECONDS = parseInteger(env.JWT_TTL_SECONDS ?? '600', 600);
  const RATE_LIMIT_PER_MINUTE = parseInteger(env.RATE_LIMIT_PER_MINUTE ?? '60', 60);
  const BODY_LIMIT_BYTES = parseInteger(env.BODY_LIMIT_BYTES ?? String(25 * 1024), 25 * 1024);
  const GEMINI_TIMEOUT_MS = parseInteger(env.GEMINI_TIMEOUT_MS ?? '15000', 15000);
  const FREE_DAILY_LIMIT = Math.max(0, parseInteger(env.FREE_DAILY_LIMIT ?? '5', 5));
  const UPGRADE_URL = (env.UPGRADE_URL || '').trim();

  const CORS_ORIGINS = ['*'];
  const MODEL_ALLOWLIST = (env.MODEL_ALLOWLIST || 'gemini-2.0-flash,gemini-2.0-flash-lite')
    .split(',').map((s) => s.trim()).filter(Boolean);
  const ALLOWED_IPS = (env.ALLOWED_IPS || '')
    .split(',').map((s) => s.trim()).filter(Boolean);
  const LICENSE_KEYS_SPEC = env.LICENSE_KEYS || '';
  const LICENSE_RECORDS = parseLicenseList(LICENSE_KEYS_SPEC);
  const HAS_LICENSES = LICENSE_RECORDS.length > 0;

  if (!GEMINI_API_KEY) console.warn('[WARN] GEMINI_API_KEY is not set. Requests will fail.');
  if (!INTERNAL_AUTH_TOKEN) console.warn('[WARN] INTERNAL_AUTH_TOKEN is not set.');
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
    CORS_ORIGINS,
    MODEL_ALLOWLIST,
    ALLOWED_IPS,
    LICENSE_RECORDS,
    HAS_LICENSES
  };
}

export function stripQuotes(value = '') {
  return value.replace(/^[\'"\s]+|[\'"\s]+$/g, '');
}

export function sha256Buffer(value = '') {
  return createHash('sha256').update(value).digest();
}

export function parseLicenseList(rawList = '') {
  return rawList
    .split(/[,\n]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry && !entry.startsWith('#'))
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
