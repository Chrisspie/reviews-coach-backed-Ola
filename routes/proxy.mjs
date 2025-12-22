export function createProxyRoutes({
  GEMINI_API_KEY,
  EXTENSION_ID,
  verifyJwt,
  unauthorized,
  badRequest,
  forbidden,
  getUsageBucket,
  FREE_DAILY_LIMIT,
  quotaSnapshot,
  UPGRADE_URL,
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

      const licenseId = tokenPayload?.user || tokenPayload?.license || 'dev-user';
      const bucket = FREE_DAILY_LIMIT ? getUsageBucket(licenseId) : null;
      const rejectQuotaResponse = ({
        message,
        remaining = 0,
        limit = FREE_DAILY_LIMIT,
        upgradeUrl = UPGRADE_URL
      }) => {
        const normalizedLimit = Number.isFinite(limit) ? Math.max(0, limit) : 0;
        const normalizedRemaining = Number.isFinite(remaining) ? Math.max(0, remaining) : 0;
        reply.header('X-Free-Limit', String(normalizedLimit));
        reply.header('X-Free-Remaining', String(normalizedRemaining));
        return reply.code(402).send({
          error: message,
          code: 'FREE_LIMIT_REACHED',
          limit: normalizedLimit,
          remaining: normalizedRemaining,
          upgradeUrl
        });
      };
      if (bucket && FREE_DAILY_LIMIT && bucket.count >= FREE_DAILY_LIMIT) {
        return rejectQuotaResponse({ message: 'Limit darmowych odpowiedzi został wykorzystany.', remaining: 0 });
      }

      const stampQuotaHeaders = (remainingOverride) => {
        if (!FREE_DAILY_LIMIT || !bucket) return;
        const remaining = (typeof remainingOverride === 'number')
          ? Math.max(0, remainingOverride)
          : Math.max(0, FREE_DAILY_LIMIT - bucket.count);
        reply.header('X-Free-Limit', String(FREE_DAILY_LIMIT));
        reply.header('X-Free-Remaining', String(remaining));
      };

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

      try {
        const url = `https://generativelanguage.googleapis.com/v1/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal
        });

        const textBody = await res.text();
        let parsed; try { parsed = JSON.parse(textBody); } catch { parsed = null; }

        if (res.ok) {
          if (bucket && FREE_DAILY_LIMIT) {
            bucket.count += 1;
            const remaining = Math.max(0, FREE_DAILY_LIMIT - bucket.count);
            stampQuotaHeaders(remaining);
            const freeMessage = remaining > 0
              ? `Remaining ${remaining} of ${FREE_DAILY_LIMIT} free responses.`
              : 'Free response limit reached.';
            reply.header('X-Free-Message', freeMessage);
          }
          const usage = usageFrom(parsed);
          if (usage) setUsageHeaders(reply, usage);
          return reply.code(200).type('application/json').send(parsed ?? textBody);
        } else {
          if (res.status === 429) {
            const quotaPayload = quotaSnapshot(bucket) || { limit: FREE_DAILY_LIMIT || 0, remaining: 0, upgradeUrl: UPGRADE_URL };
            return rejectQuotaResponse({
              message: 'Limit darmowych odpowiedzi został wykorzystany.',
              limit: quotaPayload.limit ?? FREE_DAILY_LIMIT ?? 0,
              remaining: quotaPayload.remaining ?? 0,
              upgradeUrl: quotaPayload.upgradeUrl ?? UPGRADE_URL
            });
          }
          stampQuotaHeaders();
          fastify.log.error({
            msg: 'Upstream Gemini error',
            status: res.status,
            statusText: res.statusText,
            bodyPreview: String(textBody).slice(0, 200),
            promptPreview: maskContents(contents)
          });
          return reply.code(res.status).send({ error: (parsed && parsed.error && parsed.error.message) || `Upstream error ${res.status}` });
        }
      } catch (err) {
        const isTimeout = err?.name === 'AbortError';
        fastify.log.error({ msg: 'Request to Gemini failed', error: String(err), promptPreview: maskContents(contents) });
        stampQuotaHeaders();
        return reply.code(isTimeout ? 504 : 502).send({ error: isTimeout ? 'Upstream timeout' : 'Upstream failure' });
      } finally {
        clearTimeout(timeout);
      }
    });
  };
}
