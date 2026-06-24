#!/usr/bin/env node
'use strict';

// node src/bin/migrate.js
// Applies db/schema.sql to the configured Postgres (idempotent). The actual SQL
// split/apply lives in store.pg.js#migrate(); this is just the runnable entrypoint.

const config = require('../shared/config');
const log = require('../shared/log');
const { makeStore } = require('../shared/store');

async function main() {
  const store = makeStore('pg', config);
  log.info('migrate: applying db/schema.sql', { databaseUrl: redact(config.databaseUrl) });
  await store.migrate();
  log.info('migrate: schema applied successfully');
  // Release the pool if the store exposes one, so the process can exit cleanly.
  // The pg store exposes end(); tolerate close() too for forward-compat.
  if (typeof store.end === 'function') {
    await store.end();
  } else if (typeof store.close === 'function') {
    await store.close();
  }
}

// Never log the password embedded in the connection string.
function redact(url) {
  if (!url || typeof url !== 'string') return url;
  try {
    return url.replace(/(:\/\/[^:/@]+:)[^@]*(@)/, '$1***$2');
  } catch (_e) {
    return '***';
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    log.error('migrate: failed', { error: err && err.message ? err.message : String(err) });
    process.exit(1);
  }
);
