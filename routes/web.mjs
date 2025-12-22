export function createWebRoutes({
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
}) {
  return async function webRoutes(fastify) {
    fastify.post('/api/web/google-login', async (req, reply) => {
      if (!GOOGLE_LOGIN_DEV_MODE) {
        return reply.code(503).send({ error: 'Google login not configured' });
      }
      const rawToken = req.body && typeof req.body.id_token === 'string' ? req.body.id_token.trim() : '';
      const email = ensureDevEmail(rawToken);
      const user = ensureGoogleUser(email);
      const sessionId = createWebSession(user.id);
      setWebSessionCookie(reply, sessionId);
      reply.header('Cache-Control', 'no-store');
      return reply.send(accountPayloadForUser(user));
    });

    fastify.get('/api/web/account/status', async (req, reply) => {
      reply.header('Cache-Control', 'no-store');
      const session = sessionFromRequest(req);
      if (!session) {
        return reply.send(accountPayloadForUser(null));
      }
      const user = googleUsers.get(session.userId);
      if (!user) {
        destroyWebSession(session.id);
        clearWebSessionCookie(reply);
        return reply.send(accountPayloadForUser(null));
      }
      return reply.send(accountPayloadForUser(user));
    });

    fastify.post('/api/web/account/upgrade', async (req, reply) => {
      const session = sessionFromRequest(req);
      if (!session) {
        return unauthorized(reply, 'Not authenticated');
      }
      const user = googleUsers.get(session.userId);
      if (!user) {
        destroyWebSession(session.id);
        clearWebSessionCookie(reply);
        return unauthorized(reply, 'Not authenticated');
      }
      const rawPlanId = req.body && typeof req.body.plan_id === 'string' ? req.body.plan_id.trim() : 'pro';
      if (PAYU_DEV_MODE) {
        await applyPaidPlan(user, rawPlanId, PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000);
        const checkout = PAYU_MOCK_PAYMENT_URL || PAYU_CONTINUE_URL || UPGRADE_URL || 'https://payu.example.com/mock';
        return reply.send({ checkout_url: checkout, provider: 'payu', mock: true });
      }
      if (PAYU_ENABLED) {
        try {
          const order = await createPayuOrderForPlan(user, rawPlanId, clientIp(req));
          return reply.send({ checkout_url: order.redirectUri, provider: 'payu', order_id: order.extOrderId });
        } catch (err) {
          fastify.log.error({ msg: 'PayU order failed', err: err?.message || err, plan: rawPlanId });
        }
      }
      await applyPaidPlan(user, rawPlanId, PAYU_PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000);
      const redirect = UPGRADE_URL || 'https://example.com/upgrade';
      return reply.send({ checkout_url: redirect, provider: GOOGLE_LOGIN_DEV_MODE ? 'dev' : 'manual' });
    });
  };
}
