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
//   POST /devices/:serial/config-jobs   admin|OPERATOR  author a DRAFT config-push job
//   POST /config-jobs/:id/approve       admin|OPERATOR  approve a draft. It is a TWO-PERSON
//                                       rule only when author and approver each proved a
//                                       separate operator credential; with the shared admin
//                                       token the response says two_person:false (A6)
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
//   ── the PMR control plane ──────────────────────────────────────────────────
//   Executors are NOT routed here: a counter Pi collects its job on the reply to
//   POST /telemetry and a Proxmox node collects its jobs on the reply to
//   POST /proxmox/report, because both already call outward and nothing may dial in.
//   GET  /pharmacies/:id/hours          admin  effective week + exceptions + state now
//   PUT  /pharmacies/:id/hours          OPERATOR  replace the whole week (manual source).
//                                       This is the write that decides what every gate in the
//                                       platform permits, so it takes a named credential and,
//                                       when the edit would newly arm the nightly restart on a
//                                       day that currently forbids it, the typed site name (A2)
//   PUT  /pharmacies/:id/hours/exception OPERATOR a bank holiday / one-off closure
//   DELETE /pharmacies/:id/hours/exception?on_date=  OPERATOR  drop a one-off day
//   GET  /pmr/intent?pharmacy_id=       admin  intended state + what has been observed
//   PUT  /pmr/intent                    admin  set an intention for a subject
//   DELETE /pmr/intent/:id              admin  drop an intention
//   GET  /pmr/jobs?pharmacy_id=&status= admin  the job list, incl. why one is waiting
//   POST /pmr/jobs                      admin  create a job from a NAMED verb
//   DELETE /pmr/jobs/:id                admin  cancel a job not yet with an executor
//   POST /pmr/jobs/:id/apply-now        OPERATOR  the hours override — needs a named
//                                       per-person token (PMR_OPERATOR_TOKENS); the shared
//                                       admin token is refused
//   POST /pmr/job-result                device a counter Pi reporting applied|failed
//   -- the printer model (docs/pmr-printer-contract.md) --
//   GET  /printer-devices?pharmacy_id= admin  §1's PHYSICAL printers, keyed by USB serial /
//                                       USB path / network address — the identity a rename
//                                       cannot orphan. Carries §3's three-valued status (B10)
//   The queues Watchman INTENDS a counter to have, as opposed to /printers, which is the
//   discovery feed. The effective table rides the reply to POST /telemetry as `printers`,
//   like `settings`; nothing here pushes to a device.
//   GET  /pmr/desktop-printers?pharmacy_id= admin  §7's reading: what each desktop's Windows
//                                       printer list actually holds, and how old that is.
//                                       Written only by the Proxmox collector's outward push.
//   GET  /printer-queues?pharmacy_id=   admin  the intended queues + their assignments
//   POST /printer-queues                admin  create/edit one queue (section 2 enforced
//                                       server-side over the whole resulting table)
//   DELETE /printer-queues/:id          admin  drop one queue
//   POST /printer-queues/test-print     admin  test print addressed by (counter, queue)
//   POST /printers/assign               admin  queue -> desktop. STAGES ONLY: it can never
//                                       reach a counter, and applying is the promote verb
//   POST /counters/:id/printing-promote admin|OPERATOR  section 4's named verb. Stages a
//                                       counter.printing-promote job held to the site's
//                                       overnight window; `now: true` needs the operator
//                                       token and the site's name typed, like apply-now
//   -- the site build lifecycle --
//   GET  /pharmacies/:id/capture        admin  the capture held for this site, or null
//   POST /pharmacies/:id/capture        admin  the capture tool reporting what it took
//   GET  /pharmacies/:id/import         admin  the import run, or null. last_poll_at is the
//                                       only thing separating running from lost
//   POST /pharmacies/:id/import         admin  the import executor reporting progress; a
//                                       'queued' report is REFUSED when the node is short
//   GET  /proxmox-node-capacity         admin  per-node/pool headroom + the site cost
//   ── the capture kit (src/shared/captureToken.js) ───────────────────────────
//   ⛔ The kit runs on a PHARMACY'S OWN PC and carries NO Supabase key, NO estate master
//   token and NO operator token — only a ninety-minute bearer, minted from a site-bound
//   ticket, good for exactly three things. None of its routes takes a site parameter: the
//   pharmacy is a property of the ticket, so the kit cannot name another one.
//   POST /pharmacies/:id/capture-ticket OPERATOR  issue the kit's ticket. Refused during the
//                                       site's opening hours, and the ticket's expiry is
//                                       clamped to the moment the pharmacy reopens
//   GET  /pharmacies/:id/capture-ticket admin  the tickets held for this site (never a secret)
//   DELETE /capture-tickets/:id         admin|OPERATOR  revoke a ticket AND every token it minted
//   POST /capture/token                 TICKET the only route the ticket secret works on:
//                                       exchange it for a scoped token. Redeemable a bounded
//                                       number of times, because the guest-agent install
//                                       reboots the PC mid-capture
//   GET  /capture/sites                 CAPTURE sites:list    — the site this ticket admits
//   GET  /capture/slots                 CAPTURE slots:read    — which roles are already taken
//   POST /capture/register              CAPTURE capture:write — register/resume a capture and
//                                       be told where to upload. It CANNOT create or modify a
//                                       pharmacy; it registers against a site that exists
//   ── the three OLDER paths that can also interrupt a live counter ───────────
//   These predate the job ladder and could each sign a member of staff out with the shared
//   admin token alone. They take EITHER credential; whether the operator one is REQUIRED
//   depends on what the body asks for, so the handler decides and the dispatch only supplies
//   the identity. See the block above the action route.
//   POST /counters/:id/action           admin|OPERATOR  operator token required for
//                                       'reboot' and 'restart-kiosk'
//   PUT|POST /counters/:id/boot-target  admin|OPERATOR  staged by default (interrupts
//                                       nobody); when:"now" requires the operator token
//   DELETE /counters/:id/boot-target/staged  admin  withdraw a staged change
//   PUT|PATCH /counters/:id             admin|OPERATOR  operator token required when the
//                                       save CHANGES a session setting

const http = require('node:http');
const crypto = require('node:crypto');

const handlers = require('./handlers');
const config = require('../shared/config');
const log = require('../shared/log');
const { makeStore } = require('../shared/store');
const captureToken = require('../shared/captureToken');

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

// ── WHO IS ASKING, derived from the credential and never from the body ─────────────────
// Both of these answer a question the request used to answer about ITSELF.
//
// authProxmoxNode: which node is reporting. POST /proxmox/report is authenticated by the
// estate MASTER token, which all three nodes share — so before this, the only thing deciding
// which node's jobs a caller collected was `p.node`, a string in its own request body. A
// scoped per-node token makes the name a property of the secret. The master token still
// authenticates the route (inventory must keep flowing), but it identifies nobody, so it
// receives no jobs: see proxmoxReport.
//
// Returns the node NAME, or null. Compared against every configured secret rather than
// short-circuiting on the first mismatch, so the reply time does not narrow the search.
function authProxmoxNode(req, cfg) {
  const tok = bearer(req);
  if (!tok) return null;
  let found = null;
  for (const cred of cfg.proxmoxNodeTokens || []) {
    if (timingSafeEqual(tok, cred.secret)) found = cred.name;
  }
  return found;
}

// authPmrOperator: WHICH PERSON is applying a disruptive job during opening hours. The
// route it guards suspends the one rule this whole feature exists to enforce — Watchman
// never signs a member of staff out on its own — so the row has to record a person, and a
// name the browser typed into `by` is not one. The master admin token is deliberately NOT
// accepted: it is shared, it is in the browser, and "watchman did it" records nothing.
//
// Unset config means no operator can be identified, which means apply-now is refused. That
// is the correct direction for a route whose effect is a pharmacist signed out
// mid-consultation.
function authPmrOperator(req, cfg) {
  const tok = bearer(req);
  if (!tok) return null;
  let found = null;
  for (const cred of cfg.pmrOperatorTokens || []) {
    if (timingSafeEqual(tok, cred.secret)) found = cred.name;
  }
  return found;
}

// Auth for the PMR gateway agent: the master admin token OR the scoped GATEWAY_PULL_TOKEN.
// Read-only manifest pull, so the gateway can carry the scoped key instead of the estate master.
function authGateway(req, cfg) {
  if (authAdmin(req, cfg)) return true;
  const tok = bearer(req);
  if (!tok || !cfg.gatewayPullToken) return false;
  return timingSafeEqual(tok, cfg.gatewayPullToken);
}

// ── ⛔ THE CAPTURE KIT'S TOKEN, AND THE THREE THINGS IT MAY DO ──────────────
// The kit runs on a PHARMACY'S OWN PC. It carries no Supabase key (that key decodes to
// "role":"service_role" and bypasses row-level security entirely), no estate master token, no
// operator token and no per-node token. It carries a bearer minted from a site-bound ticket,
// good for ninety minutes, that may do exactly three things.
//
// ⛔ THE SCOPE IS ENFORCED AT THE ROUTE, NOT BY CONVENTION, AND IN THAT ORDER:
//
//   1. capabilityForRoute() is consulted FIRST. On any path outside the three-entry table it
//      returns null, and this function is never called at all — so a capture token presented
//      to /fleet, /pharmacies, /pmr/jobs or /proxmox/report is not a credential that lacks a
//      permission, it is not a recognised credential there in the first place. It falls
//      through to the ordinary 401 exactly as a random string would.
//   2. The token row must CARRY the capability that route requires.
//   3. The handler asserts the same capability again for itself (captureCapOk in handlers.js).
//   4. The column carries a CHECK constraint restricting the list to a subset of the three, so
//      a token with a fourth capability cannot be stored, and therefore cannot be presented.
//
// Four locks, one list (captureToken.CAPABILITIES). Adding a capability means changing all of
// them on purpose, which is the point.
//
// Returns the token row (with its pharmacy binding) or null. The SITE comes from this row and
// never from a path, a query or a body — which is why none of the three routes takes a site
// parameter at all.
async function authCaptureToken(req, store, capability) {
  if (!capability) return null;
  if (typeof store.getCaptureTokenByHash !== 'function') return null;
  const tok = bearer(req);
  if (!tok) return null;
  // Hashed, exactly as a device token is: what is stored is a digest, so a database read
  // cannot hand anybody a working credential.
  const row = await store.getCaptureTokenByHash(sha256Hex(tok));
  if (!row) return null;
  // Lock 2. The store already refused a revoked/expired token and a token whose TICKET was
  // revoked or expired; this is the capability itself.
  if (!captureToken.hasCapability(row, capability)) return null;
  return row;
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
    // `actor` and `executorNode` are filled ONLY by the dispatch, and only from a
    // credential — never from a body or a query string. A handler that reads them is reading
    // a verified identity; nothing else in this object is one.
    const ctx = {
      req, res, store, config: cfg, log, query, body: '', device: null, params: {},
      actor: null, executorNode: null, capture: null,
    };

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

      // ══ THE CAPTURE KIT ═══════════════════════════════════════════════════
      // A credential class of its own, kept together and kept FIRST so the whole of what a
      // token from a pharmacy PC can reach is visible in one screenful.
      //
      // ⛔ NONE OF THESE TAKES A SITE PARAMETER. The pharmacy is a property of the ticket the
      // token was minted from, which is what makes "site picked from a live Watchman list,
      // never typed" true by construction rather than by discipline: there is no field in
      // which the kit could name another pharmacy.
      //
      // POST /capture/token — the ONE route the TICKET secret works on. It is not a capture
      // capability and deliberately appears in no capability list: the ticket buys a token and
      // nothing else. Kept out of CAPTURE_ROUTES for that reason.
      if (method === 'POST' && pathname === '/capture/token') {
        ctx.body = await readBody(req);
        return await handlers.captureTokenMint(ctx);
      }
      // The three capabilities, and there are three. The table in captureToken.js decides
      // which capability a path requires; a path that is not in it is not a capture route at
      // all, and a capture bearer presented there is just an unrecognised string.
      const captureCap = captureToken.capabilityForRoute(method, pathname);
      if (captureCap) {
        const tok = await authCaptureToken(req, store, captureCap);
        if (!tok) return json(res, 401, { ok: false, error: 'unauthorized' });
        // ⚠️ FILLED ONLY BY THE DISPATCH, ONLY FROM A CREDENTIAL — like ctx.actor and
        // ctx.executorNode. A handler reading ctx.capture is reading a verified site binding.
        ctx.capture = tok;
        // Best-effort audit stamp. It must never fail the call it is recording.
        if (typeof store.touchCaptureToken === 'function') {
          Promise.resolve(store.touchCaptureToken(tok.id, captureCap)).catch(() => {});
        }
        if (captureCap === 'sites:list') return await handlers.captureSitesList(ctx);
        if (captureCap === 'slots:read') return await handlers.captureSlotsRead(ctx);
        if (captureCap === 'capture:write') {
          ctx.body = await readBody(req);
          return await handlers.captureRegister(ctx);
        }
        // Unreachable while the table and this switch agree. If they ever stop agreeing, the
        // answer is a refusal, not a fall-through into the rest of the dispatch carrying an
        // authenticated capture token.
        return json(res, 403, { ok: false, error: 'unauthorized' });
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
        // The body is READ on a DELETE, which is unusual and deliberate: it carries the
        // typed site name the server now checks (B4). Reading it here rather than in the
        // handler keeps every body-parsing decision in the dispatch, as elsewhere in this
        // file. A client that cannot send a DELETE body may use ?confirm= instead.
        ctx.body = await readBody(req);
        return await handlers.pharmacyDelete(ctx);
      }

      if (method === 'GET' && pathname === '/printers/lan') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.lanPrinters(ctx);
      }
      // ── the printer model (docs/pmr-printer-contract.md §1) ────────────────
      // A DIFFERENT object from /printers, which is the discovery feed. These are the queues
      // Watchman intends a counter to have — the set sent as `printers` on the telemetry
      // reply — and they are keyed by the physical device, so a rename is a rename.
      //
      // Registered BEFORE /printers/:id so the fixed suffix is not swallowed by the id
      // pattern, the same specificity rule the counter routes carry.
      // GET /printer-devices?pharmacy_id= — §1's PHYSICAL devices, keyed by the identity a
      // rename cannot orphan. Routed because store.listPrinterDevices() was implemented and
      // exported with no route at all, which made §3's three-valued `status` — written by the
      // telemetry tick on every counter check-in — write-only (B10).
      if (method === 'GET' && pathname === '/printer-devices') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.printerDevicesList(ctx);
      }
      if (method === 'GET' && pathname === '/printer-queues') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.printerQueuesList(ctx);
      }
      // §7: what each DESKTOP says is in its Windows printer list. READ ONLY, and it cannot be
      // anything else — the reading is written by the Proxmox collector's outward push and
      // Vigilant has no route back to a node, so this route reaches nothing and interrupts
      // nobody. The shared admin token is the right credential for it.
      if (method === 'GET' && pathname === '/pmr/desktop-printers') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.desktopPrintersList(ctx);
      }
      if (method === 'POST' && pathname === '/printer-queues') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.printerQueueUpsert(ctx);
      }
      // Test print addressed by (counter, queue), for a queue with no discovery row yet.
      // BEFORE /printer-queues/:id — 'test-print' would otherwise match as an id.
      if (method === 'POST' && pathname === '/printer-queues/test-print') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.printerQueueTestPrint(ctx);
      }
      const mPrinterQueue = /^\/printer-queues\/([^/]+)$/.exec(pathname);
      if (mPrinterQueue && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPrinterQueue[1]) };
        return await handlers.printerQueueDelete(ctx);
      }
      // The assignment: queue -> desktop. STAGES ONLY — it writes what the tick will send and
      // raises the promotion job, and it cannot reach the counter or restart a session, so
      // the shared admin token is the right credential for it.
      if (method === 'POST' && pathname === '/printers/assign') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.printerAssign(ctx);
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
      // ── the site build lifecycle ──────────────────────────────────────────
      // Two READS a build checklist depends on, and the writes that make them answerable.
      // Both reads ALWAYS emit their key, even as null: the front end does `r.capture ?? null`
      // and an omitted key becomes a confident "nothing held" instead of "we cannot tell".
      // BEFORE /pharmacies/:id so the suffix is not swallowed.
      const mPhCapture = /^\/pharmacies\/([^/]+)\/capture$/.exec(pathname);
      if (mPhCapture && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhCapture[1]) };
        return await handlers.siteCaptureGet(ctx);
      }
      if (mPhCapture && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhCapture[1]) };
        ctx.body = await readBody(req);
        return await handlers.siteCaptureSet(ctx);
      }
      // ── the capture kit's ticket ──────────────────────────────────────────
      // BEFORE /pharmacies/:id, like the rest of this block, so the suffix is not swallowed.
      const mPhTicket = /^\/pharmacies\/([^/]+)\/capture-ticket$/.exec(pathname);
      if (mPhTicket && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhTicket[1]) };
        return await handlers.captureTicketList(ctx);
      }
      if (mPhTicket && method === 'POST') {
        // ⛔ A NAMED PERSON, AND THE SHARED ADMIN TOKEN IS NOT ENOUGH — the same rule
        // apply-now carries, for a related reason. This route hands out a credential that will
        // run on a machine we do not own, at a pharmacy, out of hours; a row that records
        // "watchman issued it" records nothing, and the estate master token is shared and sits
        // in a browser. Unset PMR_OPERATOR_TOKENS therefore means no ticket can be issued at
        // all, which is the correct direction.
        const actor = authPmrOperator(req, cfg);
        if (!actor) {
          return json(res, 401, {
            ok: false,
            error: 'issuing a capture ticket needs a named per-operator token '
                 + '(PMR_OPERATOR_TOKENS) — the shared admin token is not accepted, because the '
                 + 'ticket authorises a credential to run on a pharmacy PC and the record has to '
                 + 'name a person',
          });
        }
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mPhTicket[1]) };
        ctx.body = await readBody(req);
        return await handlers.captureTicketIssue(ctx);
      }
      // DELETE /capture-tickets/:id — the kill switch. Admin OR operator: revoking is the safe
      // direction and must never be the thing nobody on shift can do.
      const mCapTicket = /^\/capture-tickets\/([^/]+)$/.exec(pathname);
      if (mCapTicket && method === 'DELETE') {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCapTicket[1]) };
        return await handlers.captureTicketRevoke(ctx);
      }
      const mPhImport = /^\/pharmacies\/([^/]+)\/import$/.exec(pathname);
      if (mPhImport && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhImport[1]) };
        return await handlers.siteImportGet(ctx);
      }
      if (mPhImport && method === 'POST') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhImport[1]) };
        ctx.body = await readBody(req);
        return await handlers.siteImportSet(ctx);
      }
      // Node headroom. Nothing in the estate feed reported it, which is why "Watchman refuses
      // a site it cannot host and names the resource short" was not implementable.
      if (method === 'GET' && pathname === '/proxmox-node-capacity') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.proxmoxNodeCapacity(ctx);
      }
      // Preview the dnsmasq drop-in a site's network settings produce (read-only).
      const mPhGwCfg = /^\/pharmacies\/([^/]+)\/gateway-config$/.exec(pathname);
      if (mPhGwCfg && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mPhGwCfg[1]) };
        return await handlers.pharmacyGatewayConfig(ctx);
      }
      // The PMR gateway agent pulls every site's dnsmasq drop-in from here (scoped token).
      if (method === 'GET' && pathname === '/gateway/dnsmasq') {
        if (!authGateway(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.gatewayDnsmasqManifest(ctx);
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
      // The on-console toolbox scripts, same device-token contract as pi-script above. Two fixed
      // paths map to a route-chosen allowlist key; the caller never names a file.
      if (method === 'GET' && (pathname === '/agent/pi-toolbox' || pathname === '/agent/pi-toolbox-priv')) {
        const dev = await authDevice(req, store);
        if (!dev) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = dev;
        const which = pathname === '/agent/pi-toolbox-priv' ? 'wcn-toolbox-priv' : 'wcn-toolbox';
        return await handlers.piToolboxScript(ctx, which);
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
      // ⚠️ THE THREE ROUTES THAT CAN INTERRUPT A LIVE DISPENSING SESSION (D1/D2/D3).
      // POST /counters/:id/action, PUT /counters/:id/boot-target and the settings half of
      // PATCH /counters/:id could each sign a member of staff out with only the shared
      // estate token and a name the caller typed into `by`. They now take TWO credentials,
      // the same shape POST /proxmox/report uses and for the same reason:
      //
      //   an OPERATOR token (PMR_OPERATOR_TOKENS) names a person, so it may interrupt;
      //   the shared ADMIN token authenticates the route — everything non-interrupting on
      //   these paths must keep working — but it identifies nobody, so it may not.
      //
      // Which of the two is REQUIRED depends on what the request asks for, and that is in
      // the body: 'restart-agent' interrupts nobody, 'reboot' does; a staged boot target
      // interrupts nobody, when:"now" does; changing the printer poll interval interrupts
      // nobody, changing colour depth does. So the dispatch cannot decide it — it hands the
      // handler an identity when one was proved and null when it was not, and the handler
      // refuses through requireDeliberateInterruption(). ctx.actor is the ONLY thing
      // downstream may treat as this caller's identity; `by` in the body is never read on an
      // interrupting branch.
      const mCounterAction = /^\/counters\/([^/]+)\/action$/.exec(pathname);
      if (mCounterAction && method === 'POST') {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCounterAction[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterAction(ctx);
      }
      // ── §4 of docs/pmr-printer-contract.md: the named promote verb ────────
      // "printing-promote is the named verb that swaps the staged table live and restarts the
      // session as ONE action." DUAL-CREDENTIAL, and for exactly the reason the block above
      // POST /counters/:id/action gives: staging a promotion interrupts nobody and the shared
      // admin token is enough for it, but releasing one during opening hours signs a member of
      // staff out and has to be recorded against a person. The handler decides which of the
      // two the request is asking for, because that is in the body (`now`), and it refuses
      // through the same requireDeliberateInterruption() the other interrupting routes use.
      const mCounterPromote = /^\/counters\/([^/]+)\/printing-promote$/.exec(pathname);
      if (mCounterPromote && method === 'POST') {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCounterPromote[1]) };
        ctx.body = await readBody(req);
        return await handlers.printingPromote(ctx);
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
      // Withdraw a STAGED boot target. Registered before the plain boot-target route because
      // it is the more specific path. Un-scheduling something that has not happened
      // interrupts nobody, so the shared admin token is enough.
      const mCounterBootStaged = /^\/counters\/([^/]+)\/boot-target\/staged$/.exec(pathname);
      if (mCounterBootStaged && method === 'DELETE') {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCounterBootStaged[1]) };
        return await handlers.counterCancelBootTargetStage(ctx);
      }
      // Boot target BEFORE /counters/:id, same specificity reason as enrol-pi. PUT as well as
      // POST: the default is now a STAGED write, which is an idempotent statement of the
      // wanted target rather than a command, and the contract table calls it PUT/POST.
      // Dual-credential — see the block above the action route.
      const mCounterBoot = /^\/counters\/([^/]+)\/boot-target$/.exec(pathname);
      if (mCounterBoot && (method === 'POST' || method === 'PUT')) {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCounterBoot[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterSetBootTarget(ctx);
      }
      const mCounter = /^\/counters\/([^/]+)$/.exec(pathname);
      if (mCounter && (method === 'PUT' || method === 'PATCH')) {
        // Dual-credential for the SETTINGS half only — see the block above the action route.
        // Every other field on this route (label, status, notes, vmid…) is unchanged and
        // still takes the shared admin token.
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mCounter[1]) };
        ctx.body = await readBody(req);
        return await handlers.counterUpdate(ctx);
      }
      if (mCounter && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mCounter[1]) };
        // Same as the pharmacy delete: the body carries the typed confirmation (B4).
        ctx.body = await readBody(req);
        return await handlers.counterDelete(ctx);
      }

      // ── Proxmox discovery (admin) ──────────────────────────────────────────
      if (method === 'POST' && pathname === '/proxmox/report') {
        // TWO credentials, and they are NOT equivalent (S9). A per-node token names the
        // caller, so that caller may be handed jobs and may close its own jobs' results. The
        // estate master token authenticates the same route — three collectors have shared it
        // for a long time and inventory must not stop — but it identifies nobody, so a
        // caller using it gets no jobs and cannot report on any. ctx.executorNode is the
        // ONLY thing downstream may treat as this caller's identity.
        const node = authProxmoxNode(req, cfg);
        if (!node && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.executorNode = node;
        ctx.body = await readBody(req);
        return await handlers.proxmoxReport(ctx);
      }
      if (method === 'GET' && pathname === '/proxmox-vms') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.proxmoxList(ctx);
      }

      // ── the PMR control plane ──────────────────────────────────────────────
      // Opening hours, intended state and jobs. Every EXECUTOR path here rides a reply to a
      // call something already makes outward — the Pi's POST /telemetry and the collector's
      // POST /proxmox/report — so the only routes registered below are the operator's, plus
      // ONE device route for a counter to report what it did.

      // ⛔ OPENING HOURS: THE ONE WRITE THAT DECIDES WHAT EVERY OTHER GATE PERMITS (A2).
      //
      // Reading them is admin. WRITING them is an OPERATOR act, and the reason is the whole
      // point of the feature: every interruption path in this service — the job claim, the
      // nightly pass, the boot-target promoter, the three counter routes — asks
      // pmr_disruptive_allowed(), and pmr_disruptive_allowed() asks these tables. Hardening
      // the doors and leaving the lock's own configuration on a shared token and a name typed
      // into the body means the ceremony can be walked round: mark Tuesday closed, wait for
      // midnight, and the estate restarts a trading counter with nobody's name on it.
      //
      // store.pg.js states the harm in its own words — a stale 'closed' weekday marker on a
      // day that now trades "makes an unattended restart legal on a trading morning" — so
      // these three writes take the same credential apply-now takes, the actor comes from the
      // credential, and the handler asks for the typed site name when the edit would NEWLY
      // arm the nightly restart on a day that currently forbids it.
      //
      // DUAL-CREDENTIAL like the counter routes rather than operator-only: GET must keep
      // working for the browser holding the shared token, and the dispatch cannot tell a read
      // from a write for POST/PUT without the method — so ctx.actor is set only for an
      // operator token and the HANDLER refuses a write without one.
      const mHours = /^\/pharmacies\/([^/]+)\/hours$/.exec(pathname);
      if (mHours && method === 'GET') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mHours[1]) };
        return await handlers.siteHoursGet(ctx);
      }
      if (mHours && (method === 'PUT' || method === 'POST')) {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mHours[1]) };
        ctx.body = await readBody(req);
        return await handlers.siteHoursSet(ctx);
      }
      const mHoursExc = /^\/pharmacies\/([^/]+)\/hours\/exception$/.exec(pathname);
      if (mHoursExc && (method === 'PUT' || method === 'POST')) {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mHoursExc[1]) };
        ctx.body = await readBody(req);
        return await handlers.siteHoursExceptionSet(ctx);
      }
      if (mHoursExc && method === 'DELETE') {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mHoursExc[1]) };
        // ⚠️ A BODY ON A DELETE, and it is read on purpose: the typed site name has to travel
        // on the wire for the same reason it does everywhere else — a confirmation dialog
        // that lives only in the browser is not a boundary. on_date stays in the query string.
        ctx.body = await readBody(req);
        return await handlers.siteHoursExceptionDelete(ctx);
      }

      // Intended state (admin) — what Watchman WANTS for a subject.
      if (method === 'GET' && pathname === '/pmr/intent') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.pmrIntentList(ctx);
      }
      if ((method === 'PUT' || method === 'POST') && pathname === '/pmr/intent') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.pmrIntentSet(ctx);
      }
      const mIntent = /^\/pmr\/intent\/([^/]+)$/.exec(pathname);
      if (mIntent && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mIntent[1]) };
        return await handlers.pmrIntentDelete(ctx);
      }

      // POST /pmr/job-result (DEVICE) — a counter Pi reporting what it did. Registered
      // before the admin job routes so the more specific literal path wins.
      if (method === 'POST' && pathname === '/pmr/job-result') {
        const device = await authDevice(req, store);
        if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.device = device;
        ctx.body = await readBody(req);
        return await handlers.pmrJobResult(ctx);
      }

      // Jobs (admin).
      if (method === 'GET' && pathname === '/pmr/jobs') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        return await handlers.pmrJobsList(ctx);
      }
      if (method === 'POST' && pathname === '/pmr/jobs') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.body = await readBody(req);
        return await handlers.pmrJobCreate(ctx);
      }
      // The hours override — "apply it now, and I know it signs the member of staff out".
      const mJobApply = /^\/pmr\/jobs\/([^/]+)\/apply-now$/.exec(pathname);
      if (mJobApply && method === 'POST') {
        // ⚠️ THE ONE ROUTE THAT WILL NOT TAKE THE ADMIN TOKEN (B6/S7). Everything else here
        // is gated by the shared estate token because everything else is routine. This one
        // releases a disruptive job during opening hours — it signs a member of staff out of
        // a live dispensing session — and the row that records it has to name a PERSON. A
        // name in the request body is not a person; it is a string the browser chose, and
        // the browser is where the shared token already lives.
        const actor = authPmrOperator(req, cfg);
        if (!actor) {
          return json(res, 401, {
            ok: false,
            error: 'apply-now needs a named operator credential (PMR_OPERATOR_TOKENS), not '
                 + 'the shared admin token — this signs a member of staff out and the '
                 + 'override is recorded against a person',
          });
        }
        // Set by the dispatch from the CREDENTIAL. The handler must not read `by` from the
        // body, and does not.
        ctx.actor = actor;
        ctx.params = { id: decodeURIComponent(mJobApply[1]) };
        ctx.body = await readBody(req);
        return await handlers.pmrJobApplyNow(ctx);
      }
      const mJob = /^\/pmr\/jobs\/([^/]+)$/.exec(pathname);
      if (mJob && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { id: decodeURIComponent(mJob[1]) };
        return await handlers.pmrJobCancel(ctx);
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
      // DELETE /devices/:serial — full removal (cascade). Admin token ONLY — the scoped
      // field key can enrol, only ops can destroy. Semantics in handlers.deviceDelete.
      if (mDevMeta && method === 'DELETE') {
        if (!authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.params = { serial: decodeURIComponent(mDevMeta[1]) };
        ctx.body = await readBody(req);
        return await handlers.deviceDelete(ctx);
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
      //
      // ⚠️ DUAL-CREDENTIAL SINCE A6. An operator token names a PERSON and sets ctx.actor; the
      // shared admin token still authenticates both calls. Which one was used is recorded on
      // the row (config_jobs.created_by_credential), because the two-person rule on approve
      // can only be a real rule if BOTH names were proved by a secret rather than typed into
      // a body. Neither call is refused for holding only the admin token — authoring a draft
      // serves no router, and refusing here would push the estate onto SSH.
      const mCfgJobs = /^\/devices\/([^/]+)\/config-jobs$/.exec(pathname);
      if (mCfgJobs && (method === 'GET' || method === 'POST')) {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
        ctx.params = { serial: decodeURIComponent(mCfgJobs[1]) };
        if (method === 'POST') ctx.body = await readBody(req);
        return method === 'GET' ? handlers.configJobsList(ctx) : handlers.configJobCreate(ctx);
      }

      // POST /config-jobs/:id/approve (admin | OPERATOR) — approval of a draft.
      //
      // ⚠️ IT IS A TWO-PERSON RULE ONLY WITH TWO CREDENTIALS (A6). An operator token here
      // makes the approver a proved person; the shared admin token makes them a name in a
      // body, and the handler says so on the response (`two_person: false`) instead of
      // claiming a guarantee it did not obtain.
      const mCfgApprove = /^\/config-jobs\/([^/]+)\/approve$/.exec(pathname);
      if (method === 'POST' && mCfgApprove) {
        const actor = authPmrOperator(req, cfg);
        if (!actor && !authAdmin(req, cfg)) return json(res, 401, { ok: false, error: 'unauthorized' });
        ctx.actor = actor;
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
