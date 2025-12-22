export function createLogRoutes({ verifyJwt, unauthorized }) {
  return async function logRoutes(fastify) {
    fastify.post('/api/extension/log', async (req, reply) => {
      const auth = req.headers['authorization'];
      if (!auth || !auth.startsWith('Bearer ')) return unauthorized(reply);
      const token = auth.slice('Bearer '.length);
      let payload;
      try {
        payload = await verifyJwt(token);
      } catch (err) {
        fastify.log.warn({ msg: 'Log endpoint token invalid', err: String(err) });
        return unauthorized(reply, 'Invalid token');
      }
      const rawLevel = (req.body && req.body.level) ? String(req.body.level).toLowerCase() : 'info';
      const allowed = new Set(['trace', 'debug', 'info', 'warn', 'error', 'fatal']);
      const level = allowed.has(rawLevel) ? rawLevel : 'info';
      const message = (req.body && req.body.message) ? String(req.body.message).slice(0, 400) : 'client-log';
      const context = (req.body && typeof req.body.context === 'object') ? req.body.context : null;
      fastify.log[level]({
        msg: message,
        source: 'extension',
        license: payload.license,
        install: payload.install,
        context
      });
      return reply.send({ ok: true });
    });
  };
}
