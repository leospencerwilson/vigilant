'use strict';

// Postgres connection pool factory for Vigilant.
//
// Every pooled connection has its search_path pinned to `vigilant, public` so the
// rest of the store can use bare table names (devices, device_state, …) without
// schema-qualifying every statement. We do this on the pool's `connect` event so it
// applies to every physical connection the pool opens, including ones created lazily
// after the pool warms up.

const { Pool } = require('pg');

/**
 * Build a pg Pool from a database URL.
 * @param {string} databaseUrl  e.g. postgresql://vigilant:pw@host:5432/postgres
 * @returns {import('pg').Pool}
 */
function makePool(databaseUrl) {
  if (!databaseUrl || typeof databaseUrl !== 'string') {
    throw new Error('makePool: databaseUrl is required');
  }

  const pool = new Pool({ connectionString: databaseUrl });

  // Pin search_path on every new physical connection. Runs once per socket, not per
  // query, so it is cheap. If it ever fails we surface it on the connection error.
  pool.on('connect', (client) => {
    client.query('SET search_path = vigilant, public').catch((err) => {
      // Re-emit on the pool so callers/monitoring see it; don't swallow silently.
      pool.emit('error', err, client);
    });
  });

  return pool;
}

module.exports = { makePool };
