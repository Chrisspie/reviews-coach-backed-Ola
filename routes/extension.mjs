export function createExtensionRoutes({
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
}) {
  return async function extensionRoutes(fastify) {
    fastify.post('/api/extension/session', async (req, reply) => {
      if (!HAS_LICENSES) {
        fastify.log.warn({ msg: 'Session requested but no LICENSE_KEYS configured' });
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
        fastify.log.warn({ msg: 'Invalid license attempt', ip: clientIp(req), ext: resolvedExt });
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

    fastify.post('/api/extension/google-session', async (req, reply) => {
      if (!GOOGLE_LOGIN_DEV_MODE) {
        fastify.log.warn({ msg: 'Google session requested but GOOGLE_LOGIN_DEV_MODE=false' });
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
  };
}
