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
//   GET  /branding                      field  fleet-wide thin-client branding record
//   PUT  /branding                      admin  set motd / issue / kiosk_message
//   PUT  /branding/splash               admin  upload the boot splash PNG (base64 in JSON)
//   DELETE /branding/splash             admin  drop the boot splash
//   GET  /branding/splash               field|device  the splash PNG bytes
//   GET  /sites/:code/devices           field  site LAN inventory (printer|phone|other + ports)
//   POST /relay/sessions                field  open a LAN-relay session on a thin client
//   GET  /relay/:id/next                device long-poll: next queued request (204 / 410)
//   POST /relay/:id/reply               device the answer to one relayed request
//   GET|POST /relay/:id/p/*             field  browser-facing proxy through the thin client

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

// Field auth for the RELAY PROXY only, which is loaded by an <iframe> and by that page's own
// subresources — neither can carry an Authorization header. RFC 6750 §2.3 defines exactly this
// fallback, so the token may arrive as ?access_token=. Kept to this one route family: every
// other endpoint is called by code that can set a header, and a token in a URL is visible in
// referrers and proxy logs. The handler strips the parameter before anything is forwarded.
function authFieldOrQueryToken(req, cfg, url) {
  if (authField(req, cfg)) return true;
  const tok = (url.searchParams.get('access_token') || '').trim();
  if (!tok) return false;
  if (cfg.enrollToken && timingSafeEqual(tok, cfg.enrollToken)) return true;
  return !!cfg.fieldEnrollToken && timingSafeEqual(tok, cfg.fieldEnrollToken);
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
        return await handlers.healthz(ctx);
      }

      // GET / — admin onboarding UI (static HTML shell; enrol/fleet actions inside it
      // call the admin-token-gated JSON endpoints). Also serves as the 2xx root that
      // platform health checks probe.
      if (method === 'GET' && pathname === '/') {
        return await handlers.adminUi(ctx);
      }

      // ── device routes ────────────────────────────────────────────
      // POST /telemetry
      if (method === 'POST' && pathname === '/telemetry') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return await handlers.telemetry(ctx);
      }

      // GET /agent/script?serial=
      if (method === 'GET' && pathname === '/agent/script') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return await handlers.agentScript(ctx);
      }

      // GET /config/pending?serial=
      if (method === 'GET' && pathname === '/config/pending') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return await handlers.configPending(ctx);
      }

      // GET /config/:id.rsc
      const mCfg = /^\/config\/([^/]+)\.rsc$/.exec(pathname);
      if (method === 'GET' && mCfg) {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.params = { id: decodeURIComponent(mCfg[1]) };
        return await handlers.configScript(ctx);
      }

      // POST /config/result
      if (method === 'POST' && pathname === '/config/result') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return await handlers.configResult(ctx);
      }

      // ── speedtest (device) — server-timed active bandwidth test ──
      // GET /speedtest/pending — next pending test for this device.
      if (method === 'GET' && pathname === '/speedtest/pending') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return await handlers.speedtestPending(ctx);
      }
      // GET /speedtest/down — streamed download payload (handler writes the body).
      if (method === 'GET' && pathname === '/speedtest/down') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return await handlers.speedtestDown(ctx);
      }
      // POST|PUT /speedtest/up — streamed upload; do NOT pre-buffer the body, the handler
      // consumes the stream itself so it can TIME the transfer. We accept PUT as well as POST
      // because RouterOS `/tool fetch upload=yes` issues an HTTP PUT on several builds — a
      // POST-only route 404s that, so the body never arrives and up_bps stays empty.
      if ((method === 'POST' || method === 'PUT') && pathname === '/speedtest/up') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        return await handlers.speedtestUp(ctx);
      }
      // POST /speedtest/result — optional finaliser from the agent.
      if (method === 'POST' && pathname === '/speedtest/result') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return await handlers.speedtestResult(ctx);
      }

      // ── admin routes ─────────────────────────────────────────────
      // POST /enroll — master OR scoped field token (so wc_field can enrol with the scoped key).
      if (method === 'POST' && pathname === '/enroll') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.enroll(ctx);
      }

      // GET /fleet — master OR scoped field token (read-only device list for wc_field).
      if (method === 'GET' && pathname === '/fleet') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.fleet(ctx);
      }

      // POST /admin/migrate — apply the bundled idempotent schema.sql (admin only).
      if (method === 'POST' && pathname === '/admin/migrate') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.adminMigrate(ctx);
      }

      // POST /realtime/config — admin-gated. Mints a short-lived Supabase `authenticated` JWT
      // (+ URL/anon key) so the dashboard can subscribe to Realtime. 501 if not configured.
      if (method === 'POST' && pathname === '/realtime/config') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.realtimeConfig(ctx);
      }

      // ── alert-rule CRUD (admin) — backs the Rules UI ──
      // ── PMR virtual desktop (admin) ────────────────────────────────────────
      // Pharmacies, counters, and counter Pis. A Pi is enrolled as a Vigilant device
      // (kind='counter-pi') so it reuses token auth, telemetry, alerting and tags.
      if (method === 'GET' && pathname === '/pharmacies') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.pharmaciesList(ctx);
      }
      if (method === 'POST' && pathname === '/pharmacies') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.pharmacyCreate(ctx);
      }
      const mPharm = /^\/pharmacies\/([^/]+)$/.exec(pathname);
      if (mPharm && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPharm[1]) };
        return await handlers.pharmacyGet(ctx);
      }
      if (mPharm && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPharm[1]) };
        ctx.body = await readBody(req);
        return await handlers.pharmacyUpdate(ctx);
      }
      if (mPharm && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPharm[1]) };
        return await handlers.pharmacyDelete(ctx);
      }

      if (method === 'GET' && pathname === '/printers/lan') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.lanPrinters(ctx);
      }
      const mPrinterTest = /^\/printers\/([^/]+)\/test-print$/.exec(pathname);
      if (mPrinterTest && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPrinterTest[1]) };
        return await handlers.printerTestPrint(ctx);
      }
      // Site VM list — before /pharmacies/:id so the suffix is not swallowed.
      const mPhVmOne = /^\/pharmacies\/([^/]+)\/vms\/(\d+)$/.exec(pathname);
      if (mPhVmOne && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhVmOne[1]), vmid: mPhVmOne[2] };
        return await handlers.pharmacyVmDetach(ctx);
      }
      const mPhVms = /^\/pharmacies\/([^/]+)\/vms$/.exec(pathname);
      if (mPhVms && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhVms[1]) };
        return await handlers.pharmacyVmsList(ctx);
      }
      if (mPhVms && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhVms[1]) };
        ctx.body = await readBody(req);
        return await handlers.pharmacyVmAttach(ctx);
      }
      // Zero-touch thin-client provisioning. Self-enrol is gated by the SHARED bootstrap
      // token (SELF_ENROL_TOKEN), not the estate master — a leak can only mint an unclaimed
      // device. Unclaimed-list and adopt are estate-admin.
      // Device-authenticated agent download. Placed with the other DEVICE routes: it uses the
      // device bearer token, not the admin token.
      if (method === 'GET' && pathname === '/agent/pi-script') {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        return await handlers.piAgentScript(ctx);
      }
      // POST /screen — thin client uploads its screen thumbnail (device token, not admin).
      if (method === 'POST' && pathname === '/screen') {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        ctx.body = await readBody(req);
        return await handlers.postScreen(ctx);
      }
      // ── fleet-wide thin-client branding ────────────────────────────────────
      // ONE record for the whole estate — no serial and no site code appears in any of these
      // paths, because there is no per-site override by decision.
      //
      // /branding/splash is registered BEFORE /branding. These are exact-string comparisons so
      // they cannot actually collide, but keeping the more specific path first matches how the
      // rest of this dispatch is ordered and survives someone later loosening either match.
      if (method === 'GET' && pathname === '/branding/splash') {
        // Deliberately TWO credentials on one route. The editor preview carries the field token;
        // every thin-client agent fetches the same bytes with its own DEVICE token when its
        // telemetry reply showed a splash_sha256 it does not have. Splitting this into two routes
        // would mean two copies of the same read, and minting a shared fetch secret for the
        // fleet would be strictly worse than the per-device token each Pi already holds.
        if (!authField(req, cfg)) {
          const dev = await authDevice(req, store);
          if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
          ctx.device = dev;
        }
        return await handlers.brandingGetSplash(ctx);
      }
      if (method === 'PUT' && pathname === '/branding/splash') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.brandingPutSplash(ctx);
      }
      if (method === 'DELETE' && pathname === '/branding/splash') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.brandingDeleteSplash(ctx);
      }
      // Read is authField — the same read-only credential the Watchman UI already uses for logs,
      // history and screen thumbnails, so the editor needs no new secret to populate its form.
      if (method === 'GET' && pathname === '/branding') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.brandingGet(ctx);
      }
      // Writes are authAdmin: this changes what every thin client in the estate displays.
      // PATCH is accepted alongside PUT because the body is a PARTIAL update (only the keys
      // present are written), which is what a caller reaching for PATCH would expect anyway.
      if ((method === 'PUT' || method === 'PATCH') && pathname === '/branding') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.brandingPutText(ctx);
      }

      if (method === 'POST' && pathname === '/enrol/self') {
        const tok = bearer(req);
        if (!cfg.selfEnrolToken || !tok || !timingSafeEqual(tok, cfg.selfEnrolToken)) {
          return json(res, 401, { ok: false, error: 'unauthorized' });
        }
        ctx.body = await readBody(req);
        return await handlers.selfEnrol(ctx);
      }
      if (method === 'GET' && pathname === '/pis/unclaimed') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.unclaimedPisList(ctx);
      }
      const mAdopt = /^\/pis\/([^/]+)\/adopt$/.exec(pathname);
      if (mAdopt && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mAdopt[1]) };
        ctx.body = await readBody(req);
        return await handlers.adoptPi(ctx);
      }
      if (method === 'GET' && pathname === '/counters') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.countersList(ctx);
      }
      if (method === 'POST' && pathname === '/counters') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.counterCreate(ctx);
      }
      // Enrol route FIRST — it is more specific than /counters/:id.
      const mCounterPi = /^\/counters\/([^/]+)\/enrol-pi$/.exec(pathname);
      if (mCounterPi && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounterPi[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterEnrolPi(ctx);
      }
      const mCounterAction = /^\/counters\/([^/]+)\/action$/.exec(pathname);
      if (mCounterAction && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounterAction[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterAction(ctx);
      }
      // Support screen sharing. BEFORE /counters/:id for the same specificity reason.
      const mCounterSupport = /^\/counters\/([^/]+)\/support$/.exec(pathname);
      if (mCounterSupport && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounterSupport[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterSupportStart(ctx);
      }
      if (mCounterSupport && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounterSupport[1]) };
        return await handlers.counterSupportStatus(ctx);
      }
      // Boot target BEFORE /counters/:id, same specificity reason as enrol-pi.
      const mCounterBoot = /^\/counters\/([^/]+)\/boot-target$/.exec(pathname);
      if (mCounterBoot && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounterBoot[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterSetBootTarget(ctx);
      }
      const mCounter = /^\/counters\/([^/]+)$/.exec(pathname);
      if (mCounter && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounter[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterUpdate(ctx);
      }
      if (mCounter && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounter[1]) };
        return await handlers.counterDelete(ctx);
      }

      // ── Proxmox discovery (admin) ──────────────────────────────────────────
      if (method === 'POST' && pathname === '/proxmox/report') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.proxmoxReport(ctx);
      }
      if (method === 'GET' && pathname === '/proxmox-vms') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.proxmoxList(ctx);
      }

      // ── printers ───────────────────────────────────────────────────────────
      // Stats are collected by an agent on the pharmacy LAN (the counter Pi), because
      // nothing in the datacentre can reach a printer on a site network.
      if (method === 'GET' && pathname === '/printers') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.printersList(ctx);
      }
      if (method === 'POST' && pathname === '/printers') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.printerUpsert(ctx);
      }
      // DEVICE route — the Pi reports with its own token, not the admin token.
      if (method === 'POST' && pathname === '/printers/report') {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        ctx.body = await readBody(req);
        return await handlers.printersReport(ctx);
      }
      const mPrinter = /^\/printers\/([^/]+)$/.exec(pathname);
      if (mPrinter && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPrinter[1]) };
        return await handlers.printerDelete(ctx);
      }

      // Observed WireGuard state from the hub's collector.
      if (method === 'GET' && pathname === '/wg-peers') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.wgPeersList(ctx);
      }
      if (method === 'POST' && pathname === '/wg-peers/report') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.wgPeersReport(ctx);
      }

      // ── site LAN inventory ─────────────────────────────────────────────────
      // GET /sites/:code/devices — what a site's own telemetry says is on its LAN, classified
      // into printer/phone/other with the admin ports to try. authField, not authAdmin: this is
      // a read of data the Watchman UI already shows, and it is what the relay picker lists.
      const mSiteDevices = /^\/sites\/([^/]+)\/devices$/.exec(pathname);
      if (method === 'GET' && mSiteDevices) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { code: decodeURIComponent(mSiteDevices[1]) };
        return await handlers.siteDevices(ctx);
      }

      // ── LAN relay (long-poll reverse channel through a thin client) ─────────
      // Nothing here may originate towards a Pi — the hub's forward chain forbids it — so the
      // Pi collects work by holding /next open and posts answers back to /reply. See
      // handlers.js for the protocol and why each timeout is the number it is.
      if (method === 'POST' && pathname === '/relay/sessions') {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.relaySessionCreate(ctx);
      }
      // DEVICE routes — the Pi's own bearer, not an operator's token.
      const mRelayNext = /^\/relay\/([^/]+)\/next$/.exec(pathname);
      if (method === 'GET' && mRelayNext) {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        ctx.params = { id: decodeURIComponent(mRelayNext[1]) };
        return await handlers.relayNext(ctx);
      }
      const mRelayReply = /^\/relay\/([^/]+)\/reply$/.exec(pathname);
      if (method === 'POST' && mRelayReply) {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        ctx.params = { id: decodeURIComponent(mRelayReply[1]) };
        ctx.body = await readBody(req);
        return await handlers.relayReply(ctx);
      }
      // Browser-facing proxy. The trailing path is captured RAW (not decoded): it is handed
      // straight to the device, and decoding it here would corrupt an escaped query or path
      // segment the device's own web server expects verbatim.
      const mRelayProxy = /^\/relay\/([^/]+)\/p(\/.*)?$/.exec(pathname);
      if ((method === 'GET' || method === 'POST') && mRelayProxy) {
        // NO bearer here on purpose — the session id IS the credential (see relayProxy,
        // which rejects an unknown, closed or expired one with 404/410). An <iframe> cannot
        // attach an Authorization header, and crucially nor can the subresource fetches the
        // framed page makes: a relative `style.css` arrives here as /relay/<id>/p/style.css
        // with nothing attached, so requiring a token meant only a single self-contained
        // document could ever render. The session is a capability — UUIDv4, <=10 min, one
        // live per device, pinned to one allowlisted ip:port, audited at creation — which is
        // a narrower thing to hold than the field key this replaces.
        ctx.params = { id: decodeURIComponent(mRelayProxy[1]), path: mRelayProxy[2] || '/' };
        if (method === 'POST') ctx.body = await readBody(req);
        return await handlers.relayProxy(ctx);
      }

      // ── tags & smart tags (admin) ──────────────────────────────────────────
      // Tags are the grouping primitive alert_rules.scope_tag and
      // config_jobs.target_tag select on, so these make tag-scoped alerting usable.
      if (method === 'GET' && pathname === '/tags') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.tagsList(ctx);
      }
      if (method === 'GET' && pathname === '/tag-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.tagRulesList(ctx);
      }
      // Preview before create/update, so the UI can show the blast radius first.
      if (method === 'POST' && pathname === '/tag-rules/preview') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.tagRulePreview(ctx);
      }
      // Apply rules now rather than waiting for the worker's next pass.
      if (method === 'POST' && pathname === '/tag-rules/sync') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.tagRulesSync(ctx);
      }
      if (method === 'POST' && pathname === '/tag-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.tagRuleCreate(ctx);
      }
      const mTagRule = /^\/tag-rules\/([^/]+)$/.exec(pathname);
      if (mTagRule && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mTagRule[1]) };
        ctx.body = await readBody(req);
        return await handlers.tagRuleUpdate(ctx);
      }
      if (mTagRule && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mTagRule[1]) };
        return await handlers.tagRuleDelete(ctx);
      }
      // PATCH /devices/:serial/tags — set a device's manual tags.
      const mDevTags = /^\/devices\/([^/]+)\/tags$/.exec(pathname);
      if (mDevTags && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mDevTags[1]) };
        ctx.body = await readBody(req);
        return await handlers.deviceTagsSet(ctx);
      }
      // PATCH /devices/:serial — operator-editable metadata (customer, site_name, …).
      // Registered AFTER /devices/:serial/tags so the more specific path wins.
      const mDevMeta = /^\/devices\/([^/]+)$/.exec(pathname);
      if (mDevMeta && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mDevMeta[1]) };
        ctx.body = await readBody(req);
        return await handlers.deviceMetaSet(ctx);
      }

      if (method === 'GET' && pathname === '/alert-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.alertRulesList(ctx);
      }
      // GET /alerts (admin) — recent alert history (rule hits) for the Rules history view.
      if (method === 'GET' && pathname === '/alerts') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.alertHistory(ctx);
      }
      if (method === 'POST' && pathname === '/alert-rules/test') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.alertRuleTest(ctx);
      }
      if (method === 'POST' && pathname === '/alert-rules') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.alertRuleCreate(ctx);
      }
      const mRule = /^\/alert-rules\/([^/]+)$/.exec(pathname);
      if (mRule && (method === 'PUT' || method === 'PATCH')) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mRule[1]) };
        ctx.body = await readBody(req);
        return await handlers.alertRuleUpdate(ctx);
      }
      if (mRule && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mRule[1]) };
        return await handlers.alertRuleDelete(ctx);
      }

      // GET /devices/:serial/history?window=1h (admin) — dashboard chart series.
      // Matched BEFORE /devices/:serial so the trailing /history segment is routed here
      // and not swallowed (the bare-serial regex anchors on a no-slash segment, but keep
      // this first for clarity + defence in depth).
      const mHist = /^\/devices\/([^/]+)\/history$/.exec(pathname);
      if (method === 'GET' && mHist) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mHist[1]) };
        return await handlers.deviceHistory(ctx);
      }
      // GET /devices/:serial/screen — the thumbnail as an image, for the thin-client list.
      // authField, not authAdmin: this is the same read-only credential the Watchman UI
      // already uses for logs and history, so the <img> needs no new secret.
      const mScreen = /^\/devices\/([^/]+)\/screen$/.exec(pathname);
      if (method === 'GET' && mScreen) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mScreen[1]) };
        return await handlers.deviceScreen(ctx);
      }
      // GET /devices/:serial/logs?q=&topic=&limit= — filtered 30-day log history.
      const mLogs = /^\/devices\/([^/]+)\/logs$/.exec(pathname);
      if (method === 'GET' && mLogs) {
        if (!authField(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mLogs[1]) };
        return await handlers.deviceLogs(ctx);
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
        return await handlers.configJobApprove(ctx);
      }

      // POST /config-jobs/:id/cancel (admin) — cancel a draft / not-yet-picked-up approved job.
      const mCfgCancel = /^\/config-jobs\/([^/]+)\/cancel$/.exec(pathname);
      if (method === 'POST' && mCfgCancel) {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCfgCancel[1]) };
        ctx.body = await readBody(req);
        return await handlers.configJobCancel(ctx);
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
        return await handlers.deviceDetail(ctx);
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
        return await handlers.ouiLookup(ctx);
      }

      return json(res, 404, { ok: false, error: 'not found' });
    } catch (e) {
      // Fail safe: one bad request must never 500-cascade or take the service down.
      //
      // Every dispatch above is `return await handlers.x(ctx)`, NOT `return handlers.x(ctx)`.
      // The await is load-bearing: returning a promise from a try block resolves this function
      // with it WITHOUT awaiting, so a rejecting handler skips this catch entirely, surfaces as
      // an unhandledRejection, and — because nothing ever writes the response — leaves the
      // client hanging until ITS timeout. That is strictly worse than a 500: the caller cannot
      // tell a broken request from a dead server. MEASURED 2026-08-19 on the counter Pi, which
      // read as offline for minutes at a time while the ingest was healthy and serving.
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
