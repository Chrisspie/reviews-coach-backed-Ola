export function createBillingRoutes({
  PAYU_ENABLED,
  payuSignatureValid,
  consumePayuOrder,
  parsePayuExtOrderId,
  googleUsers,
  applyPaidPlan,
  PAYU_PLAN_DURATION_DAYS
}) {
  return async function billingRoutes(fastify) {
    fastify.post('/api/billing/payu-webhook', { config: { rawBody: true } }, async (req, reply) => {
      if (!PAYU_ENABLED) {
        fastify.log.warn({ msg: 'PayU webhook invoked but not configured' });
        return reply.code(503).send({ error: 'PayU not configured' });
      }
      const signatureHeader = req.headers['openpayu-signature'];
      const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
      const rawBody = req.rawBody ? req.rawBody.toString('utf8') : (req.body ? JSON.stringify(req.body) : '');
      if (!payuSignatureValid(rawBody, signature)) {
        fastify.log.warn({ msg: 'PayU webhook signature invalid' });
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
          fastify.log.warn({ msg: 'PayU webhook references unknown user', extOrderId, pending });
        }
      }
      return reply.send({ received: true });
    });
  };
}
