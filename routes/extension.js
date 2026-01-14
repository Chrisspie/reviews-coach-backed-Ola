export function createExtensionRoutes({
  HAS_LICENSES,
  verifyLicenseKey,
  licenseQuotaClient,
  signJwt,
  JWT_TTL_SECONDS,
  EXTENSION_ID,
  unauthorized,
  badRequest,
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
      let quota = null;
      try {
        quota = await licenseQuotaClient.snapshot(license.id);
      } catch (err) {
        fastify.log.error({ msg: 'Failed to fetch license quota', err: String(err) });
        return reply.code(503).send({ error: 'Usage service unavailable' });
      }
      const token = await signJwt({ extid: resolvedExt, scope: 'gen', license: license.id, install: installTag }, ttlSec);

      return reply.send({
        token,
        expiresIn: ttlSec,
        expiresAt: new Date(nowMs + ttlSec * 1000).toISOString(),
        license: { id: license.id },
        quota: quota || null
      });
    });
  };
}
