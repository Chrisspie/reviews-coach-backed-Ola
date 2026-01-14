export function createProxyRoutes({
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
}) {
  return async function proxyRoutes(fastify) {
    fastify.post('/gemini/generate', async (req, reply) => {
      if (!GEMINI_API_KEY) {
        fastify.log.error('Missing GEMINI_API_KEY');
        return reply.code(500).send({ error: 'Server not configured' });
      }

      const auth = req.headers['authorization'];
      if (!auth || !auth.startsWith('Bearer ')) return unauthorized(reply);
      const token = auth.slice('Bearer '.length);

      let tokenPayload;
      try {
        tokenPayload = await verifyJwt(token);
        if (EXTENSION_ID && tokenPayload.extid && tokenPayload.extid !== EXTENSION_ID) {
          return unauthorized(reply, 'Token/ext mismatch');
        }
      } catch (e) {
        fastify.log.warn({ msg: 'JWT verify failed', err: String(e) });
        return unauthorized(reply, 'Invalid token');
      }

      const body = req.body || {};
      const { model, contents } = body;
      if (!model || typeof model !== 'string') return badRequest(reply, 'Field "model" must be a non-empty string');
      if (!Array.isArray(contents)) return badRequest(reply, 'Field "contents" must be an array');
      if (MODEL_ALLOWLIST.length && !MODEL_ALLOWLIST.includes(model)) {
        return forbidden(reply, 'Model not allowed');
      }

      const licenseId = tokenPayload?.license ? String(tokenPayload.license) : null;
      let reservedLicenseUsage = false;
      if (licenseId) {
        try {
          const decision = await licenseQuotaClient.consume(licenseId);
          if (!decision.allowed) {
            applyQuotaHeaders(reply, decision.quota);
            return reply.code(402).send(limitReachedPayload(decision.quota));
          }
          reservedLicenseUsage = true;
          applyQuotaHeaders(reply, decision.quota);
        } catch (err) {
          fastify.log.error({ msg: 'Usage service consume failed', err: String(err) });
          return reply.code(503).send({ error: 'Usage service unavailable' });
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

      try {
        const url = https://generativelanguage.googleapis.com/v1/models/:generateContent?key=;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal
        });

        const textBody = await res.text();
        let parsed; try { parsed = JSON.parse(textBody); } catch { parsed = null; }

        if (res.ok) {
          reservedLicenseUsage = false;
          const usage = usageFrom(parsed);
          if (usage) setUsageHeaders(reply, usage);
          return reply.code(200).type('application/json').send(parsed ?? textBody);
        }

        if (res.status === 429) {
          if (reservedLicenseUsage && licenseId) {
            await licenseQuotaClient.refund(licenseId);
            reservedLicenseUsage = false;
          }
          let quota = null;
          if (licenseId) {
            try {
              quota = await licenseQuotaClient.snapshot(licenseId);
            } catch (err) {
              fastify.log.warn({ msg: 'Usage service snapshot failed', err: String(err) });
            }
          }
          applyQuotaHeaders(reply, quota);
          return reply.code(402).send(limitReachedPayload(quota));
        }

        if (reservedLicenseUsage && licenseId) {
          await licenseQuotaClient.refund(licenseId);
          reservedLicenseUsage = false;
        }

        fastify.log.error({
          msg: 'Upstream Gemini error',
          status: res.status,
          statusText: res.statusText,
          bodyPreview: String(textBody).slice(0, 200),
          promptPreview: maskContents(contents)
        });
        return reply.code(res.status).send({ error: (parsed && parsed.error && parsed.error.message) || Upstream error  });
      } catch (err) {
        const isTimeout = err?.name === 'AbortError';
        fastify.log.error({ msg: 'Request to Gemini failed', error: String(err), promptPreview: maskContents(contents) });
        if (reservedLicenseUsage && licenseId) {
          await licenseQuotaClient.refund(licenseId);
        }
        return reply.code(isTimeout ? 504 : 502).send({ error: isTimeout ? 'Upstream timeout' : 'Upstream failure' });
      } finally {
        clearTimeout(timeout);
      }
    });
  };
}

function limitReachedPayload(quota) {
  const normalizedLimit = typeof quota?.limit === 'number' ? Math.max(0, quota.limit) : 0;
  const normalizedRemaining = typeof quota?.remaining === 'number' ? Math.max(0, quota.remaining) : 0;
  return {
    error: 'Limit darmowych odpowiedzi został wykorzystany.',
    code: 'FREE_LIMIT_REACHED',
    limit: normalizedLimit,
    remaining: normalizedRemaining,
    upgradeUrl: quota?.upgradeUrl || null,
    quota: quota || null
  };
}

function applyQuotaHeaders(reply, quota) {
  if (!quota) return;
  const limit = typeof quota.limit === 'number' ? Math.max(0, quota.limit) : null;
  const remaining = typeof quota.remaining === 'number' ? Math.max(0, quota.remaining) : null;
  if (limit !== null) {
    reply.header('X-Free-Limit', String(limit));
  }
  if (remaining !== null) {
    reply.header('X-Free-Remaining', String(remaining));
    if (limit !== null) {
      const message = remaining > 0
        ? Remaining  of  free responses.
        : 'Free response limit reached.';
      reply.header('X-Free-Message', message);
    }
  }
  if (quota.upgradeUrl) {
    reply.header('X-Free-Upgrade-Url', quota.upgradeUrl);
  }
}
