import 'dotenv/config';

import { loadConfig } from './config.js';
import { createApp } from './app/create-app.js';

const resolvedConfig = loadConfig();
const app = await createApp(resolvedConfig);

export { app, createApp, resolvedConfig as config };

if (process.env.NODE_ENV !== 'test') {
  app.listen({ port: resolvedConfig.PORT, host: '0.0.0.0' })
    .then((addr) => app.log.info(`Server listening on ${addr}`))
    .catch((err) => {
      app.log.error(err);
      process.exit(1);
    });
}
