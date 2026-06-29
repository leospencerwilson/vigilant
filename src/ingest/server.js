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
//   GET  /devices/:serial/config-jobs   admin  list config-push jobs for the device
//   POST /devices/:serial/config-jobs   admin  author a DRAFT config-push job
//   POST /config-jobs/:id/approve       admin  two-person approve a draft
//   POST /config-jobs/:id/cancel        admin  cancel a draft / not-yet-picked-up job
//   GET  /speedtest/pending             device next pending active speedtest (marks running)
//   GET  /speedtest/down?job=&bytes=    device server-timed download payload
//   POST /speedtest/up?job=             device server-timed upload sink
//   POST /speedtest/result              device agent's done/failed finaliser
//   GET  /devices/:serial/speedtests    admin  list recent speedtests
//   POST /devices/:serial/speedtests    admin  request an active speedtest

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

// Field-app auth for the wc_field install wizard: the master admin token OR the SCOPED
// FIELD_ENROLL_TOKEN. Used only for enrol + single-device read so the browser app can carry
// the scoped key instead of the estate master token.
function authField(req, cfg) {
  if (authAdmin(req, cfg)) return true;
  const tok = bearer(req);
  if (!tok || !cfg.fieldEnrollToken) return false;
  return timingSafeEqual(tok, cfg.fieldEnrollToken);
}

// CORS so browser frontends (wc_field) can call the API directly. Auth is a Bearer token (no
// cookies), so echoing the Origin — or '*' — is safe. Lock down via CORS_ALLOW_ORIGINS.
function applyCors(req, res, cfg) {
  const allow = cfg.corsAllowOrigins || '*';
  let value = '*';
  if (allow !== '*') {
    const origin = req.headers['origin'] || '';
    const list = String(allow).split(',').map((s) => s.trim()).filter(Boolean);
    value = list.includes(origin) ? origin : list[0] || '*';
  }
  res.setHeader('Access-Control-Allow-Origin', value);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type');
  res.setHeader('Access-Control-Max-Age', '600');
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

    // CORS for browser frontends (set before any response). Answer the preflight here so a
    // POST /enroll with Authorization + JSON body from wc_field isn't blocked.
    applyCors(req, res, cfg);
    if (method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

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

      // ── speedtest (device) — server-timed active bandwidth test ──
      // GET /speedtest/pending — next pending test for this device.
      if (method === 'GET' && pathname === '/speedtest/pending') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return handlers.speedtestPending(ctx);
      }
      // GET /speedtest/down — streamed download payload (handler writes the body).
      if (method === 'GET' && pathname === '/speedtest/down') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return handlers.speedtestDown(ctx);
      }
      // POST|PUT /speedtest/up — streamed upload; do NOT pre-buffer the body, the handler
      // consumes the stream itself so it can TIME the transfer. We accept PUT as well as POST
      // because RouterOS `/tool fetch upload=yes` issues an HTTP PUT on several builds — a
      // POST-only route 404s that, so the body never arrives and up_bps stays empty.
      if ((method === 'POST' || method === 'PUT') && pathname === '/speedtest/up') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return handlers.speedtestUp(ctx);
      }
      // POST /speedtest/result — optional finaliser from the agent.
      if (method === 'POST' && pathname === '/speedtest/result') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return handlers.speedtestResult(ctx);
      }

      // ── admin routes ─────────────────────────────────────────────
      // POST /enroll — master OR scoped field token (so wc_field can enrol with the scoped key).
      if (method === 'POST' && pathname === '/enroll') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return handlers.enroll(ctx);
      }

      // GET /fleet — master OR scoped field token (read-only device list for wc_field).
      if (method === 'GET' && pathname === '/fleet') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return handlers.fleet(ctx);
      }

      // POST /admin/migrate — apply the bundled idempotent schema.sql (admin only).
      if (method === 'POST' && pathname === '/admin/migrate') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return handlers.adminMigrate(ctx);
      }

      // POST /realtime/config — admin-gated. Mints a short-lived Supabase `authenticated` JWT
      // (+ URL/anon key) so the dashboard can subscribe to Realtime. 501 if not configured.
      if (method === 'POST' && pathname === '/realtime/config') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return handlers.realtimeConfig(ctx);
      }

      // ── alert-rule CRUD (admin) — backs the Rules UI ──
      if (method === 'GET' && pathname === '/alert-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return handlers.alertRulesList(ctx);
      }
      if (method === 'POST' && pathname === '/alert-rules/test') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return handlers.alertRuleTest(ctx);
      }
      if (method === 'POST' && pathname === '/alert-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return handlers.alertRuleCreate(ctx);
      }
      const mRule = /^\/alert-rules\/([^/]+)$/.exec(pathname);
      if (mRule && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mRule[1]) };
        ctx.body = await readBody(req);
        return handlers.alertRuleUpdate(ctx);
      }
      if (mRule && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mRule[1]) };
        return handlers.alertRuleDelete(ctx);
      }

      // GET /devices/:serial/history?window=1h (admin) — dashboard chart series.
      // Matched BEFORE /devices/:serial so the trailing /history segment is routed here
      // and not swallowed (the bare-serial regex anchors on a no-slash segment, but keep
      // this first for clarity + defence in depth).
      const mHist = /^\/devices\/([^/]+)\/history$/.exec(pathname);
      if (method === 'GET' && mHist) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mHist[1]) };
        return handlers.deviceHistory(ctx);
      }

      // GET|POST /devices/:serial/config-jobs (admin) — list / author review-gated config-push
      // jobs. Matched before the bare /devices/:serial route (defence in depth; the bare regex
      // can't match a path with a further /segment anyway).
      const mCfgJobs = /^\/devices\/([^/]+)\/config-jobs$/.exec(pathname);
      if (mCfgJobs && (method === 'GET' || method === 'POST')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mCfgJobs[1]) };
        if (method === 'POST') ctx.body = await readBody(req);
        return method === 'GET' ? handlers.configJobsList(ctx) : handlers.configJobCreate(ctx);
      }

      // POST /config-jobs/:id/approve (admin) — two-person approval of a draft.
      const mCfgApprove = /^\/config-jobs\/([^/]+)\/approve$/.exec(pathname);
      if (method === 'POST' && mCfgApprove) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCfgApprove[1]) };
        ctx.body = await readBody(req);
        return handlers.configJobApprove(ctx);
      }

      // POST /config-jobs/:id/cancel (admin) — cancel a draft / not-yet-picked-up approved job.
      const mCfgCancel = /^\/config-jobs\/([^/]+)\/cancel$/.exec(pathname);
      if (method === 'POST' && mCfgCancel) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCfgCancel[1]) };
        ctx.body = await readBody(req);
        return handlers.configJobCancel(ctx);
      }

      // GET|POST /devices/:serial/speedtests (admin) — list / request an active speedtest.
      const mSt = /^\/devices\/([^/]+)\/speedtests$/.exec(pathname);
      if (mSt && (method === 'GET' || method === 'POST')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mSt[1]) };
        if (method === 'POST') ctx.body = await readBody(req);
        return method === 'GET' ? handlers.speedtestList(ctx) : handlers.speedtestCreate(ctx);
      }

      // GET /devices/:serial — master OR scoped field token (wc_field's "wait until online" step).
      const mDev = /^\/devices\/([^/]+)$/.exec(pathname);
      if (method === 'GET' && mDev) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mDev[1]) };
        return handlers.deviceDetail(ctx);
      }

      // GET /oui/:mac (admin) — OUI -> vendor lookup for the dashboard. The :mac segment may
      // be colon/hyphen/dot-separated or bare hex; the regex accepts hex digits + those
      // separators only (a malformed segment 404s here, a syntactically-ok-but-too-short mac
      // is the handler's 400). Admin-auth gated, same token as /fleet.
      // Allow '%' so percent-encoded separators (e.g. a client that sends "CC%3A2D%3AE0")
      // still match; ctx.params decodeURIComponent's it and the handler normalises.
      const mOui = /^\/oui\/([0-9a-fA-F:.%\-]{1,64})$/.exec(pathname);
      if (method === 'GET' && mOui) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { mac: decodeURIComponent(mOui[1]) };
        return handlers.ouiLookup(ctx);
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

// Process-level safety net. The per-request dispatch in createServer() is wrapped in
// try/catch, but an error thrown from an ASYNC continuation that escapes that scope (an
// unawaited store promise, a stream 'finish'/'end' callback) surfaces as an
// unhandledRejection/uncaughtException — which, on Node ≥15, terminates the process. A
// single malformed request (observed: a bad job_id → "invalid input syntax for type uuid")
// must NEVER take the ingest down for the whole estate. Log loudly and keep serving; the
// source-level guards (isUuid, etc.) are the primary fix — this is defence in depth.
function installProcessGuards() {
  process.on('unhandledRejection', (reason) => {
    log.error('ingest: unhandledRejection (kept alive)', {
      msg: reason && reason.message ? reason.message : String(reason),
    });
  });
  process.on('uncaughtException', (err) => {
    log.error('ingest: uncaughtException (kept alive)', { msg: err && err.message ? err.message : String(err) });
  });
}

async function startServer() {
  installProcessGuards();
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
