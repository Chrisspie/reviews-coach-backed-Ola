import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';

import { loadConfig } from '../config.js';
import { createLicenseVerifier } from '../lib/licenses.js';
import { maskContents, usageFrom, setUsageHeaders } from '../lib/gemini.js';
import { clientIp } from '../lib/request.js';
import { unauthorized, forbidden, badRequest } from '../lib/reply.js';
import { createHealthRoutes } from '../routes/health.js';
import { createAuthRoutes } from '../routes/auth.js';
import { createExtensionRoutes } from '../routes/extension.js';
import { createLogRoutes } from '../routes/log.js';
import { createProxyRoutes } from '../routes/proxy.js';

import { createLicenseQuotaClient } from './services/license-quota-client.js';
import { createJwtService } from './services/jwt-service.js';

export async function createApp(providedConfig = loadConfig()) {
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
    CORS_ORIGINS,
    USAGE_SERVICE_BASE_URL,
    MODEL_ALLOWLIST,
    ALLOWED_IPS,
    LICENSE_RECORDS,
    HAS_LICENSES
  } = config;

  const app = Fastify({
    logger: true,
    bodyLimit: BODY_LIMIT_BYTES,
    trustProxy: true
  });

  await registerBasePlugins(app, { RATE_LIMIT_PER_MINUTE, CORS_ORIGINS });

  const verifyLicenseKey = createLicenseVerifier(LICENSE_RECORDS, HAS_LICENSES);
  const licenseQuotaClient = createLicenseQuotaClient({
    usageBaseUrl: USAGE_SERVICE_BASE_URL,
    internalAuthToken: INTERNAL_AUTH_TOKEN,
    fetchImpl: fetch,
    logger: app.log
  });

  const { signJwt, verifyJwt } = createJwtService({
    authSecret: AUTH_SECRET,
    defaultTtlSeconds: JWT_TTL_SECONDS
  });

  const allowedIps = Array.isArray(ALLOWED_IPS) ? ALLOWED_IPS : [];
  app.addHook('onRequest', async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    const ip = clientIp(req);
    if (allowedIps.length && !allowedIps.includes(ip)) {
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
    licenseQuotaClient,
    signJwt,
    JWT_TTL_SECONDS,
    EXTENSION_ID,

    unauthorized,
    badRequest,
    clientIp
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
    licenseQuotaClient,
    GEMINI_TIMEOUT_MS,
    usageFrom,
    setUsageHeaders,
    maskContents,
    MODEL_ALLOWLIST
  }));

  return app;
}

async function registerBasePlugins(app, { RATE_LIMIT_PER_MINUTE, CORS_ORIGINS }) {
  await app.register(helmet, { contentSecurityPolicy: false });
  const allowedOrigins = '*';
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return cb(null, true);
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
}
