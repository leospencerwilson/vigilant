'use strict';

// Cluster front-end for vigilant-ingest.
//
// WHY: the ingest is CPU-bound in JavaScript (JSON parse of each telemetry POST,
// normalise/derive bps + roles in transform.js) and Node runs that on ONE thread.
// On the 6-vCPU VM it sat pinned at ~107% — i.e. one core saturated — while the
// box still had spare capacity, so it served a queue rather than the real demand.
// Forking N workers that share the listening socket lets the ingest use several
// cores. Postgres is a separate multi-process server and scales on its own.
//
// SAFETY: this is only valid because the ingest holds no singleton state — no
// server-side timers, crons or in-process caches (retention/pruning runs in the
// separate `worker` container). Each worker just builds its own store + HTTP
// server. If a singleton ever appears in the ingest, gate it on
// `cluster.isPrimary` or move it to the worker.
//
// SIZING: each worker opens its own pg pool (PG_POOL_MAX, default 12), so total
// connections = workers x pool. Keep that comfortably under the server's
// max_connections (200 here) AND remember that more pg backends means more CPU
// contention with the ingest itself. Default leaves 3 cores for Postgres and the
// OS; override with INGEST_WORKERS.

const cluster = require('node:cluster');
const os = require('node:os');
const log = require('../shared/log');

function cpuCount() {
  if (typeof os.availableParallelism === 'function') return os.availableParallelism();
  const c = os.cpus();
  return Array.isArray(c) && c.length ? c.length : 1;
}

function workerCount() {
  const explicit = parseInt(process.env.INGEST_WORKERS, 10);
  if (Number.isFinite(explicit) && explicit > 0) return explicit;
  // Reserve ~3 cores for Postgres + OS; cap at 4 so a big host doesn't open a
  // silly number of pg connections.
  return Math.max(1, Math.min(4, cpuCount() - 3));
}

if (!cluster.isPrimary) {
  // Child: behave exactly like `node src/ingest/server.js`.
  require('./server')
    .startServer()
    .catch((err) => {
      log.error('vigilant-ingest worker failed to start', { msg: err && err.message });
      process.exit(1);
    });
} else {
  const target = workerCount();
  log.info('vigilant-ingest: starting cluster', {
    workers: target,
    cpus: cpuCount(),
    poolMaxPerWorker: Number(process.env.PG_POOL_MAX) || 12,
  });

  for (let i = 0; i < target; i++) cluster.fork();

  // Respawn dead workers, but back off so a worker that dies instantly (bad
  // config, unreachable DB) can't become a tight fork loop.
  let recentExits = 0;
  setInterval(() => {
    recentExits = 0;
  }, 60000).unref();

  let shuttingDown = false;
  cluster.on('exit', (worker, code, signal) => {
    if (shuttingDown) return;
    recentExits++;
    const delay = recentExits > target * 2 ? 5000 : 250;
    log.error('vigilant-ingest worker exited; respawning', {
      pid: worker.process.pid,
      code,
      signal,
      delayMs: delay,
    });
    setTimeout(() => {
      if (!shuttingDown) cluster.fork();
    }, delay).unref();
  });

  // Forward container stop signals so `docker compose up -d` / restarts are clean.
  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      if (shuttingDown) return;
      shuttingDown = true;
      log.info('vigilant-ingest: shutting down cluster', { signal: sig });
      for (const id of Object.keys(cluster.workers || {})) {
        const w = cluster.workers[id];
        if (w) w.kill(sig);
      }
      // Give workers a moment to close their sockets, then exit.
      setTimeout(() => process.exit(0), 5000).unref();
    });
  }
}
