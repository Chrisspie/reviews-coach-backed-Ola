export function createHealthRoutes() {
  return async function healthRoutes(fastify) {
    fastify.get('/health', async () => ({ status: 'ok' }));
  };
}
