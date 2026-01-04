import 'dotenv/config';

import { loadConfig } from './config.js';
import { createApp } from './app/create-app.js';

const resolvedConfig = loadConfig();
const app = await createApp(resolvedConfig);

export { app, createApp, resolvedConfig as config };

function resolvePort(defaultPort) {
  const envValue = process.env.PORT;
  if (!envValue) return defaultPort;
  const parsed = Number.parseInt(envValue, 10);
  return Number.isFinite(parsed) ? parsed : defaultPort;
}

if (process.env.NODE_ENV !== 'test') {
  const port = resolvePort(resolvedConfig.PORT ?? 3000);
  app.listen({ port, host: '0.0.0.0' })
    .then((addr) => app.log.info(`Server listening on ${addr}`))
    .catch((err) => {
      app.log.error(err);
      process.exit(1);
    });
}

