'use strict';

// Postgres connection pool factory for Vigilant.
//
// Every pooled connection has its search_path pinned to `vigilant, public` so the
// rest of the store can use bare table names (devices, device_state, …) without
// schema-qualifying every statement. We do this on the pool's `connect` event so it
// applies to every physical connection the pool opens, including ones created lazily
// after the pool warms up.

const { Pool } = require('pg');
const log = require('./log');

/**
 * Build a pg Pool from a database URL.
 * @param {string} databaseUrl  e.g. postgresql://vigilant:pw@host:5432/postgres
 * @returns {import('pg').Pool}
 */
function makePool(databaseUrl) {
  if (!databaseUrl || typeof databaseUrl !== 'string') {
    throw new Error('makePool: databaseUrl is required');
  }

  // SSL is opt-in via env (Supabase poolers usually want it; a local/in-VM socket
  // usually doesn't). rejectUnauthorized:false because self-hosted certs are private.
  const sslOn = /^(1|true|yes|require)$/i.test(String(process.env.VIGILANT_DB_SSL || ''));
  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: sslOn ? { rejectUnauthorized: false } : undefined,
    // Fail fast instead of hanging a request (and a proxy 502) for ages on an
    // unreachable DB host.
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    max: 10,
  });

  // CRITICAL: a pg Pool emits 'error' for failures on IDLE clients (dropped socket,
  // unreachable host re-dial, etc.). With no listener, node throws on the unhandled
  // 'error' event and the whole process crashes/loops. Handle it: log and keep serving
  // — the next query just re-dials. This must exist before anything uses the pool.
  pool.on('error', (err) => {
    log.error('pg pool error (handled, not fatal)', { code: err && err.code, msg: err && err.message });
  });

  // Pin search_path on every new physical connection. Runs once per socket, not per
  // query, so it is cheap. If it ever fails we surface it via the pool error handler.
  pool.on('connect', (client) => {
    client.query('SET search_path = vigilant, public').catch((err) => {
      pool.emit('error', err, client);
    });
  });

  return pool;
}

module.exports = { makePool };
