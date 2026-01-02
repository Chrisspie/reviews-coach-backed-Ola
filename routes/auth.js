export function createAuthRoutes({ INTERNAL_AUTH_TOKEN, EXTENSION_ID, JWT_TTL_SECONDS, signJwt, unauthorized }) {
  return async function authRoutes(fastify) {
    fastify.post('/auth/token', async (req, reply) => {
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

    fastify.post('/api/extension/jwt', async (req, reply) => {
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
  };
}
