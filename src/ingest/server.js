#!/usr/bin/env node
'use strict';

// Vigilant ingest — HTTP server (stdlib `http`, CJS), matching provisioner/server.js.
//
//   createServer({store, config}) -> http.Server
//
// Routing is a central dispatch by method + path. Device routes authenticate by
// sha256-hashing the Authorization bearer and looking the hash up via
// store.getDeviceByToken; admin routes compare the bearer to config.enrollToken in
// constant time. /healthz is open. The raw bearer token is NEVER logged.
//
// Routes (see docs/CONTRACT.md API table):
//   GET  /healthz                 none    "ok"
//   POST /telemetry               device  ingest telemetry, return control + job
//   GET  /agent/script?serial=    device  current agent script text
//   GET  /config/pending?serial=  device  approved job descriptor or 204
//   GET  /config/:id.rsc          device  job rsc_text (+ X-Vigilant-Sha256 header)
//   POST /config/result           device  record apply result
//   POST /enroll                  admin   create device + token -> {token, bootstrap}
//   GET  /fleet                   admin   fleet read API
//   GET  /devices/:serial         admin   device detail
//   GET  /devices/:serial/history admin   dashboard time-series (window=1h|6h|24h|7d)

const http = require('node:http');
const crypto = require('node:crypto');

const handlers = require('./handlers');
const config = require('../shared/config');
const log = require('../shared/log');
const { makeStore } = require('../shared/store');

// ── helpers ──────────────────────────────────────────────────────────

function json(res, code, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': buf.length });
  res.end(buf);
}

// Read the full request body as a string (handlers parse it; a bad body must not crash).
function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', (c) => {
      buf += c;
    });
    req.on('end', () => resolve(buf));
    req.on('error', reject);
  });
}

// Extract the bearer token from the Authorization header (or '').
function bearer(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : '';
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// Constant-time string compare for the admin token (avoid early-exit timing leaks).
function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Authenticate a device route: hash the bearer, look it up. Returns the device or null.
async function authDevice(req, store) {
  const tok = bearer(req);
  if (!tok) return null;
  const device = await store.getDeviceByToken(sha256Hex(tok));
  return device || null;
}

// Authenticate an admin route against config.enrollToken (constant time).
function authAdmin(req, cfg) {
  const tok = bearer(req);
  if (!tok || !cfg.enrollToken) return false;
  return timingSafeEqual(tok, cfg.enrollToken);
}

// ── server ───────────────────────────────────────────────────────────

/**
 * Build the ingest HTTP server.
 * @param {{store: object, config: object}} deps
 * @returns {import('http').Server}
 */
function createServer({ store, config: cfg }) {
  return http.createServer(async (req, res) => {
    let url;
    try {
      url = new URL(req.url || '/', 'http://localhost');
    } catch (e) {
      return json(res, 400, { ok: false, error: 'bad url' });
    }
    const method = req.method || 'GET';
    const pathname = url.pathname;
    const query = url.searchParams;

    // Base context shared with every handler. Body/device/params filled per route.
    const ctx = { req, res, store, config: cfg, log, query, body: '', device: null, params: {} };

    try {
      // GET /healthz — open, no auth.
      if (method === 'GET' && pathname === '/healthz') {
        return handlers.healthz(ctx);
      }

      // GET / — admin onboarding UI (static HTML shell; enrol/fleet actions inside it
      // call the admin-token-gated JSON endpoints). Also serves as the 2xx root that
      // platform health checks probe.
      if (method === 'GET' && pathname === '/') {
        return handlers.adminUi(ctx);
      }

      // ── device routes ────────────────────────────────────────────
      // POST /telemetry
      if (method === 'POST' && pathname === '/telemetry') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return handlers.telemetry(ctx);
      }

      // GET /agent/script?serial=
      if (method === 'GET' && pathname === '/agent/script') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return handlers.agentScript(ctx);
      }

      // GET /config/pending?serial=
      if (method === 'GET' && pathname === '/config/pending') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return handlers.configPending(ctx);
      }

      // GET /config/:id.rsc
      const mCfg = /^\/config\/([^/]+)\.rsc$/.exec(pathname);
      if (method === 'GET' && mCfg) {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.params = { id: decodeURIComponent(mCfg[1]) };
        return handlers.configScript(ctx);
      }

      // POST /config/result
      if (method === 'POST' && pathname === '/config/result') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return handlers.configResult(ctx);
      }

      // ── admin routes ─────────────────────────────────────────────
      // POST /enroll
      if (method === 'POST' && pathname === '/enroll') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return handlers.enroll(ctx);
      }

      // GET /fleet
      if (method === 'GET' && pathname === '/fleet') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return handlers.fleet(ctx);
      }

      // GET /devices/:serial/history?window=1h (admin) — dashboard chart series.
      // Matched BEFORE /devices/:serial so the trailing /history segment is routed here
      // and not swallowed (the bare-serial regex anchors on a no-slash segment, but keep
      // this first for clarity + defence in depth).
      const mHist = /^\/devices\/([^/]+)\/history$/.exec(pathname);
      if (method === 'GET' && mHist) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mHist[1]) };
        return handlers.deviceHistory(ctx);
      }

      // GET /devices/:serial
      const mDev = /^\/devices\/([^/]+)$/.exec(pathname);
      if (method === 'GET' && mDev) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mDev[1]) };
        return handlers.deviceDetail(ctx);
      }

      return json(res, 404, { ok: false, error: 'not found' });
    } catch (e) {
      // Fail safe: one bad request must never 500-cascade or take the service down.
      log.error('ingest: unhandled request error', { method, path: pathname, msg: e && e.message });
      if (!res.headersSent) return json(res, 500, { ok: false, error: 'internal error' });
      try {
        res.end();
      } catch (e2) {
        /* socket already gone */
      }
    }
  });
}

// ── entrypoint ───────────────────────────────────────────────────────

async function startServer() {
  // Fail loud if a pg store is configured without a connection string (deferred from
  // config load so that merely requiring this module never crashes mem/test processes).
  if (typeof config.assertUsable === 'function') config.assertUsable();
  const store = makeStore(config.storeKind, config);
  const server = createServer({ store, config });
  server.listen(config.port, () => {
    log.info('vigilant-ingest listening', { port: config.port, storeKind: config.storeKind });
  });
  return server;
}

if (require.main === module) {
  startServer().catch((err) => {
    log.error('vigilant-ingest failed to start', { msg: err && err.message });
    process.exit(1);
  });
}

module.exports = { createServer, startServer };
