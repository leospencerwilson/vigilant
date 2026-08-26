// The capture kit's credential model: the ticket, the scoped token, and the fact that the
// token may do THREE things and no more.
//
// ⛔ THE TEST THIS FILE EXISTS FOR is "a capture token is refused on any route outside its
// three capabilities". The kit runs on a PHARMACY'S OWN PC — a machine we do not own, that we
// are about to image and then hand back — so the blast radius of that bearer leaking is the
// whole of what these tests pin down. A regression here is not a broken feature; it is an
// estate credential on somebody else's computer.
//
// Everything pure (the capability list, the role picker, the out-of-hours judgement, the
// upload-destination refusals, the roll-up) is tested directly. Everything about ROUTING is
// tested over real HTTP against createServer(), because "enforced at the route" is a claim
// about the dispatch and cannot be checked by calling a handler.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");

const captureToken = require("../src/shared/captureToken");
const { createServer } = require("../src/ingest/server");

const ENROLL_TOKEN = "test-enroll-token";
const OPERATOR_TOKEN = "test-operator-secret";

function makeConfig() {
  process.env.STORE_KIND = "mem";
  process.env.ENROLL_TOKEN = ENROLL_TOKEN;
  process.env.PMR_OPERATOR_TOKENS = `leo.wilson:${OPERATOR_TOKEN}`;
  process.env.PORT = "0";
  const cfgPath = require.resolve("../src/shared/config");
  delete require.cache[cfgPath];
  return require("../src/shared/config");
}

function request(port, { method, path, token, body }) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const headers = {};
    if (token) headers["authorization"] = `Bearer ${token}`;
    if (data) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(data.length);
    }
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => {
        let parsed = null;
        try { parsed = buf ? JSON.parse(buf) : null; } catch { parsed = buf; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}
const listen = (server) =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
const close = (server) => new Promise((resolve) => server.close(resolve));

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

// ── a store that DOES support captures ──────────────────────────────────────
// Deliberately a store with full capture support: proving that /fleet refuses a capture token
// on a store that cannot do captures at all would prove nothing. The negative tests below have
// to run against a server that would happily serve a capture call.
//
// The parts that touch real SQL — the partial unique indexes that refuse a duplicate role, the
// redeem statement that spends the budget atomically — are exercised against a real Postgres,
// exactly as the PMR control plane's claim statement is. What is modelled here is the CONTRACT
// the dispatch depends on.
const PHARMACY = {
  id: 7, code: "RX99999", name: "Test Pharmacy", status: "building", idx: 42,
  prefix_len: 27, subnet: "10.200.42.0/27", server_ip: "10.200.42.10",
  proxmox_node: "temeraire", srv_vmid: null, pmr_system: "proscript",
};

// Closed now, reopening in six hours: an ordinary out-of-hours window.
function closedHours() {
  return {
    is_open: false,
    hours_source: "manual",
    next_open_at: new Date(Date.now() + 6 * 3600 * 1000).toISOString(),
    next_close_at: null,
    site_timezone: "Europe/London",
    resolved: true,
    gate_resolved: true,
  };
}

function makeCaptureStore(opts = {}) {
  const hours = opts.hours || closedHours();
  const tickets = new Map();   // secret_hash -> ticket row
  const tokens = new Map();    // token_hash -> token row
  const runs = [];
  const touched = [];
  // Anything that would CREATE OR MODIFY A PHARMACY. Present so a test can assert nothing on
  // the capture path ever reaches them.
  const forbidden = [];

  const store = {
    _tickets: tickets, _tokens: tokens, _runs: runs, _touched: touched, _forbidden: forbidden,

    async getDeviceByToken() { return null; },
    async getPharmacy(idOrCode) {
      const s = String(idOrCode);
      return (s === String(PHARMACY.id) || s.toUpperCase() === PHARMACY.code) ? { ...PHARMACY } : null;
    },
    async getSiteHours() { return hours; },
    async createPharmacy(...a) { forbidden.push(["createPharmacy", a]); throw new Error("must never be called"); },
    async updatePharmacy(...a) { forbidden.push(["updatePharmacy", a]); throw new Error("must never be called"); },
    async createCounter(...a) { forbidden.push(["createCounter", a]); throw new Error("must never be called"); },

    async createCaptureTicket(pharmacyId, f) {
      const row = {
        id: crypto.randomUUID(),
        pharmacy_id: Number(pharmacyId),
        secret_hash: f.secret_hash,
        issued_by: f.issued_by,
        issued_at: new Date().toISOString(),
        expires_at: f.expires_at,
        window_closes_at: f.window_closes_at,
        redeem_max: f.redeem_max || 12,
        redeem_count: 0,
        last_redeemed_at: null,
        revoked_at: null, revoked_by: null, note: f.note || null,
      };
      tickets.set(f.secret_hash, row);
      return row;
    },
    async listCaptureTickets() { return [...tickets.values()]; },
    async revokeCaptureTicket(id, by) {
      for (const t of tickets.values()) {
        if (t.id === id) {
          t.revoked_at = new Date().toISOString();
          t.revoked_by = by;
          for (const k of tokens.values()) if (k.ticket_id === id) k.revoked_at = t.revoked_at;
          return t;
        }
      }
      return null;
    },
    async redeemCaptureTicket(secretHash, f) {
      const t = tickets.get(secretHash);
      if (!t) return { refused: "no-such-ticket" };
      if (t.revoked_at) return { refused: "revoked" };
      if (new Date(t.expires_at).getTime() <= Date.now()) return { refused: "expired" };
      if (t.redeem_count >= t.redeem_max) return { refused: "spent" };
      t.redeem_count += 1;
      t.last_redeemed_at = new Date().toISOString();
      // The real store clamps in SQL with LEAST(now + ttl, ticket.expires_at).
      const exp = new Date(Math.min(
        Date.now() + Number(f.token_ttl_s) * 1000,
        new Date(t.expires_at).getTime()
      )).toISOString();
      const token = {
        id: crypto.randomUUID(),
        ticket_id: t.id,
        pharmacy_id: t.pharmacy_id,
        token_hash: f.token_hash,
        // Whatever the caller asked for is narrowed to the admitted set, as the column's
        // CHECK constraint does in Postgres.
        capabilities: captureToken.admittedCapabilities(f.capabilities),
        issued_at: new Date().toISOString(),
        expires_at: exp,
        revoked_at: null,
        ticket_issued_by: t.issued_by,
        pharmacy_code: PHARMACY.code,
        pharmacy_name: PHARMACY.name,
      };
      tokens.set(f.token_hash, token);
      return { ticket: t, token };
    },
    async getCaptureTokenByHash(hash) {
      const t = tokens.get(hash);
      if (!t) return null;
      if (t.revoked_at) return null;
      if (new Date(t.expires_at).getTime() <= Date.now()) return null;
      return t;
    },
    async touchCaptureToken(id, cap) { touched.push([id, cap]); return { id }; },
    async listCaptureSitesForToken(pharmacyId) {
      return Number(pharmacyId) === PHARMACY.id ? [{ ...PHARMACY }] : [];
    },
    async listCaptureSlots() {
      return { runs: runs.slice(), counters: [], pharmacy: { ...PHARMACY } };
    },
    async listCaptureRuns() { return runs.slice(); },
    async getCaptureRunForRole(pharmacyId, kind, slot) {
      return runs.find((r) => r.role_kind === kind
        && (kind === "server" || Number(r.role_slot) === Number(slot))) || null;
    },
    async upsertCaptureRun(pharmacyId, f) {
      const existing = runs.find((r) => r.role_kind === f.role_kind
        && (f.role_kind === "server" || Number(r.role_slot) === Number(f.role_slot)));
      if (existing) {
        // The ownership guard, as the real ON CONFLICT ... WHERE does it: only the ticket that
        // started this run may resume it. Anything else returns no row -> the handler 409s.
        if (existing.ticket_id !== f.ticket_id) return null;
        Object.assign(existing, { ...f, pharmacy_id: Number(pharmacyId) });
        return existing;
      }
      const row = {
        id: runs.length + 1,
        pharmacy_id: Number(pharmacyId),
        started_at: f.started_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
        ...f,
      };
      runs.push(row);
      return row;
    },
    async setSiteCaptureRollUp(pharmacyId, f) { store._rollUp = f; return f; },
    async getCaptureDropTarget(node) { return opts.dropTarget === undefined ? null : opts.dropTarget; },
  };
  return store;
}

// Issue a ticket and redeem it, returning { ticketSecret, token, ticketId }.
async function standUpKit(port, store) {
  const issued = await request(port, {
    method: "POST", path: `/pharmacies/${PHARMACY.id}/capture-ticket`,
    token: OPERATOR_TOKEN, body: {},
  });
  assert.equal(issued.status, 201, JSON.stringify(issued.body));
  const minted = await request(port, {
    method: "POST", path: "/capture/token", token: issued.body.secret, body: {},
  });
  assert.equal(minted.status, 200, JSON.stringify(minted.body));
  return { ticketSecret: issued.body.secret, token: minted.body.token, issued, minted };
}

// ════════════════════════════════════════════════════════════════════════════
// the capability list itself
// ════════════════════════════════════════════════════════════════════════════

test("there are exactly three capabilities, and they are the three that were agreed", () => {
  assert.deepEqual(captureToken.CAPABILITIES, ["sites:list", "slots:read", "capture:write"]);
  assert.equal(captureToken.CAPABILITIES.length, 3);
  // The full set a mint hands out IS the whole list — there is no wider one to reach for.
  assert.deepEqual(captureToken.fullCapabilitySet(), captureToken.CAPABILITIES.slice());
});

test("the route table has one entry per capability and no others", () => {
  assert.equal(captureToken.CAPTURE_ROUTES.length, 3);
  const caps = captureToken.CAPTURE_ROUTES.map((r) => r.capability).sort();
  assert.deepEqual(caps, captureToken.CAPABILITIES.slice().sort());
});

test("capabilityForRoute answers null for every route that is not a capture route", () => {
  // null is a STRONGER answer than "lacks the capability": it means a capture bearer is not a
  // recognised credential there at all, so the dispatch never even looks it up.
  for (const [m, p] of [
    ["GET", "/fleet"], ["POST", "/enroll"], ["GET", "/pharmacies"], ["POST", "/pharmacies"],
    ["POST", "/proxmox/report"], ["GET", "/pmr/jobs"], ["POST", "/pmr/jobs"],
    ["GET", "/pharmacies/7/capture"], ["POST", "/pharmacies/7/capture"],
    ["POST", "/pharmacies/7/capture-ticket"], ["DELETE", "/capture-tickets/x"],
    ["GET", "/gateway/dnsmasq"], ["GET", "/branding"], ["POST", "/capture/token"],
    // Near-misses: a trailing slash or a different method is not the route.
    ["GET", "/capture/sites/"], ["POST", "/capture/sites"], ["GET", "/capture/register"],
  ]) {
    assert.equal(captureToken.capabilityForRoute(m, p), null, `${m} ${p} must not be a capture route`);
  }
  assert.equal(captureToken.capabilityForRoute("GET", "/capture/sites"), "sites:list");
  assert.equal(captureToken.capabilityForRoute("GET", "/capture/slots"), "slots:read");
  assert.equal(captureToken.capabilityForRoute("POST", "/capture/register"), "capture:write");
});

test("a capability outside the three is refused even when the token claims it", () => {
  const rogue = { capabilities: ["sites:list", "pharmacy:write"] };
  assert.equal(captureToken.hasCapability(rogue, "pharmacy:write"), true, "the string is on the row");
  // …and it still buys nothing: assertCapability refuses a name that is not one of the three,
  // and admittedCapabilities drops it before it ever reaches the wire.
  assert.equal(captureToken.assertCapability(rogue, "pharmacy:write").ok, false);
  assert.deepEqual(captureToken.admittedCapabilities(rogue.capabilities), ["sites:list"]);
});

test("assertCapability refuses a token that lacks the capability, and names the set", () => {
  const tok = { capabilities: ["sites:list"] };
  assert.equal(captureToken.assertCapability(tok, "sites:list").ok, true);
  const r = captureToken.assertCapability(tok, "capture:write");
  assert.equal(r.ok, false);
  assert.match(r.error, /capture:write/);
});

// ════════════════════════════════════════════════════════════════════════════
// the role picker
// ════════════════════════════════════════════════════════════════════════════

test("role is ONE picker: server, or client-01..client-10, and nothing else", () => {
  assert.equal(captureToken.ROLE_VALUES.length, 11);
  assert.equal(captureToken.ROLE_VALUES[0], "server");
  assert.equal(captureToken.ROLE_VALUES[10], "client-10");
  assert.deepEqual(captureToken.parseRole("server"), { ok: true, kind: "server", slot: null, role: "server" });
  assert.deepEqual(captureToken.parseRole("client-03"), { ok: true, kind: "client", slot: 3, role: "client-03" });
});

test("a role is refused, never coerced", () => {
  // "client-3" from a kit is a bug in the kit; parsing it hides the class of bug the closed
  // list exists to catch — the same rule the PMR verb arguments follow.
  for (const bad of ["client-3", "client-00", "client-11", "Client-03", "3", "", null, 3,
    "server ", "client-1 ", "__proto__", "constructor"]) {
    assert.equal(captureToken.parseRole(bad).ok, false, `${String(bad)} must be refused`);
  }
});

test("clients land in the .11-.20 band on a /27 site, which is why 01-10 is the range", () => {
  const p = { idx: 42, prefix_len: 27, server_ip: "10.200.42.10" };
  assert.equal(captureToken.roleAddress(p, "client", 1), "10.200.42.11");
  assert.equal(captureToken.roleAddress(p, "client", 10), "10.200.42.20");
  assert.equal(captureToken.roleAddress(p, "server", null), "10.200.42.10");
});

// ════════════════════════════════════════════════════════════════════════════
// out of hours only — as arithmetic, not as a check
// ════════════════════════════════════════════════════════════════════════════

test("a ticket is refused while the pharmacy is open", () => {
  const r = captureToken.judgeCaptureWindow(
    { is_open: true, hours_source: "manual", resolved: true, gate_resolved: true,
      next_close_at: new Date(Date.now() + 3600e3).toISOString() },
    Date.now()
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "site-open");
});

test("a ticket is refused when the hours are the ESTATE FALLBACK GUESS, not this site's", () => {
  // The fallback fills is_open for every pharmacy in the estate. A gate that read it would
  // declare a trading pharmacy closed on the strength of a default nobody checked — the exact
  // mistake openingHours.js documents having made three times.
  const r = captureToken.judgeCaptureWindow(
    { is_open: false, hours_source: "fallback", resolved: true, gate_resolved: true,
      next_open_at: new Date(Date.now() + 6 * 3600e3).toISOString() },
    Date.now()
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "hours-not-entered");
});

test("a closed site with no known reopening cannot be bounded, so it is refused", () => {
  const r = captureToken.judgeCaptureWindow(
    { is_open: false, hours_source: "manual", resolved: true, gate_resolved: true, next_open_at: null },
    Date.now()
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no-reopen-known");
});

test("a window shorter than a capture is refused rather than issued short", () => {
  const r = captureToken.judgeCaptureWindow(
    { is_open: false, hours_source: "manual", resolved: true, gate_resolved: true,
      next_open_at: new Date(Date.now() + 40 * 60e3).toISOString() },
    Date.now()
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "window-too-short");
  assert.equal(r.window_short, true);
});

test("⛔ the ticket cannot outlive the closed window, and the token cannot outlive the ticket", () => {
  const now = Date.now();
  const reopen = new Date(now + 90 * 60e3).toISOString();   // 90 minutes of window
  const tExp = captureToken.ticketExpiry(now, reopen);
  // The ordinary TTL is twelve hours; the clamp wins.
  assert.equal(tExp, reopen);
  assert.ok(new Date(tExp).getTime() < now + captureToken.TICKET_TTL_S * 1000);
  // A token minted 80 minutes in has 10 minutes, not 90.
  const kExp = captureToken.tokenExpiry(now + 80 * 60e3, tExp);
  assert.equal(kExp, reopen);
  assert.ok(new Date(kExp).getTime() <= new Date(tExp).getTime());
});

test("with a long closed window the ordinary TTL is what bounds the ticket", () => {
  const now = Date.now();
  const reopen = new Date(now + 40 * 3600e3).toISOString();
  const tExp = captureToken.ticketExpiry(now, reopen);
  assert.equal(new Date(tExp).getTime(), now + captureToken.TICKET_TTL_S * 1000);
});

test("ticket state is read from one place: open / expired / spent / revoked", () => {
  const base = { expires_at: new Date(Date.now() + 3600e3).toISOString(), redeem_count: 0, redeem_max: 12 };
  assert.equal(captureToken.ticketState(base), "open");
  assert.equal(captureToken.ticketState({ ...base, revoked_at: new Date().toISOString() }), "revoked");
  assert.equal(captureToken.ticketState({ ...base, expires_at: new Date(Date.now() - 1).toISOString() }), "expired");
  assert.equal(captureToken.ticketState({ ...base, redeem_count: 12 }), "spent");
});

// ════════════════════════════════════════════════════════════════════════════
// the upload destination — the server names it, or names its refusal
// ════════════════════════════════════════════════════════════════════════════

test("⛔ no reported drop directory means a NAMED refusal, never a guessed path", () => {
  const r = captureToken.shapeUploadTarget(null, { code: "RX99999", role: "server", format: "qcow2" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no-target-reported");
  assert.equal(r.target, null);
  // Nothing that looks like a path anywhere in the answer.
  assert.doesNotMatch(JSON.stringify(r), /\/var\/lib\/vz/);
});

test("⛔ the dead NFS share is refused BY NAME, because the far end said it was NFS", () => {
  const r = captureToken.shapeUploadTarget(
    { node: "temeraire", dir: "/mnt/pve/oldshare", fs_type: "nfs4", free_bytes: 9e12 },
    { code: "RX99999", role: "server", format: "qcow2" }
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "target-is-network-storage");
  assert.match(r.message, /local storage/i);
});

test("a drop directory short on space is refused with the figure, not silently accepted", () => {
  const r = captureToken.shapeUploadTarget(
    { node: "temeraire", dir: "/var/lib/vz/dump/pmr-capture", fs_type: "ext4", free_bytes: 40e9 },
    { code: "RX99999", role: "server", format: "qcow2" }
  );
  assert.equal(r.ok, false);
  assert.equal(r.reason, "target-short-on-space");
});

test("a good target yields ONE path the kit writes to, and it is resumable", () => {
  const r = captureToken.shapeUploadTarget(
    { node: "temeraire", storage_name: "local", dir: "/var/lib/vz/dump/pmr-capture/",
      fs_type: "ext4", free_bytes: 900e9, writable: true, reported_at: "2026-08-26T01:00:00.000Z" },
    { code: "RX99999", role: "client-03", format: "qcow2", startedAt: "2026-08-26T02:03:04.000Z" }
  );
  assert.equal(r.ok, true);
  assert.equal(r.target.kind, "proxmox-drop-dir");
  assert.equal(r.target.node, "temeraire");
  assert.equal(r.target.dir, "/var/lib/vz/dump/pmr-capture");
  assert.equal(r.target.path, "/var/lib/vz/dump/pmr-capture/RX99999-client-03-20260826T020304Z.qcow2");
  assert.equal(r.target.resumable, true);
  assert.equal(r.target.source, "node-reported");
  // ⚠️ The PC name is provenance only and survives P2V, so it must never appear in a filename.
  assert.doesNotMatch(r.target.filename, /RECEPTION/i);
});

test("a reported drop target with a relative path or no node is dropped, not stored", () => {
  assert.equal(captureToken.cleanDropTargetRow({ node: "temeraire", dir: "dump/here" }), null);
  assert.equal(captureToken.cleanDropTargetRow({ dir: "/var/lib/vz" }), null);
  const ok = captureToken.cleanDropTargetRow({ node: "temeraire", dir: "/var/lib/vz", free_bytes: -1 });
  // ⛔ A figure that is not a reading is null, never 0 — "full" and "unreadable" are different
  // facts and exactly one of them stops a capture.
  assert.equal(ok.free_bytes, null);
});

// ════════════════════════════════════════════════════════════════════════════
// the site roll-up
// ════════════════════════════════════════════════════════════════════════════

test("⛔ the safety flags roll up pessimistically: any false wins, then any null", () => {
  assert.equal(captureToken.rollUpFlag([true, true, true]), true);
  assert.equal(captureToken.rollUpFlag([true, null, true]), null);
  assert.equal(captureToken.rollUpFlag([true, false, null]), false);
  // "Every machine we checked was clean, and we did not check two of them" is NOT clean.
  assert.equal(captureToken.rollUpFlag([true, undefined]), null);
});

test("a site's capture is not 'held' until every run has finished uploading", () => {
  const roll = captureToken.rollUpRuns([
    { role_kind: "server", started_at: "2026-08-26T01:00:00.000Z", uploaded_at: "2026-08-26T02:00:00.000Z",
      disk_gb: 120, printers_cleared: true, guest_agent_installed: true, source_pc_name: "SRV", out_of_hours: true },
    { role_kind: "client", role_slot: 1, started_at: "2026-08-26T02:10:00.000Z", uploaded_at: null,
      disk_gb: 70, printers_cleared: true, guest_agent_installed: null, out_of_hours: true },
  ]);
  assert.equal(roll.uploaded_at, null, "one run still transferring means the site is not held");
  assert.equal(roll.started_at, "2026-08-26T01:00:00.000Z");
  // The site's real cost on the node is every image it will host.
  assert.equal(roll.disk_gb, 190);
  assert.equal(roll.guest_agent_installed, null);
  assert.equal(roll.printers_cleared, true);
});

// ════════════════════════════════════════════════════════════════════════════
// ⛔ THE ONE THAT MATTERS: a capture token is refused everywhere else
// ════════════════════════════════════════════════════════════════════════════

// Every route a leaked capture token might be pointed at. The list deliberately includes the
// routes that would hurt most: the estate fleet read, pharmacy creation, the PMR job ladder
// (which can sign a pharmacist out), the Proxmox collector push (which hands out jobs), the
// gateway manifest, and the capture kit's OWN admin side — issuing a ticket, listing tickets,
// and the older admin capture write.
const FORBIDDEN_ROUTES = [
  ["GET", "/fleet", undefined],
  ["POST", "/enroll", { serial: "X" }],
  ["GET", "/pharmacies", undefined],
  ["POST", "/pharmacies", { code: "RX00001", idx: 9, name: "Invented" }],
  ["GET", "/pharmacies/7", undefined],
  ["GET", "/pharmacies/7/capture", undefined],
  ["POST", "/pharmacies/7/capture", { disk_gb: 1 }],
  ["GET", "/pharmacies/7/import", undefined],
  ["POST", "/pharmacies/7/import", { state: "queued" }],
  ["GET", "/pharmacies/7/capture-ticket", undefined],
  ["POST", "/pharmacies/7/capture-ticket", {}],
  ["DELETE", "/capture-tickets/00000000-0000-4000-8000-000000000000", undefined],
  ["GET", "/pharmacies/7/hours", undefined],
  ["GET", "/counters", undefined],
  ["POST", "/counters", { pharmacy_id: 7, n: 1 }],
  ["POST", "/counters/1/action", { action: "reboot" }],
  ["GET", "/pmr/jobs", undefined],
  ["POST", "/pmr/jobs", { pharmacy_id: 7, verb: "counter.reboot" }],
  ["GET", "/pmr/intent", undefined],
  ["POST", "/proxmox/report", { vms: [] }],
  ["GET", "/proxmox-node-capacity", undefined],
  ["GET", "/gateway/dnsmasq", undefined],
  ["GET", "/branding", undefined],
  ["GET", "/devices/RB-1", undefined],
  ["GET", "/printer-queues?pharmacy_id=7", undefined],
  ["POST", "/realtime/config", {}],
];

test("⛔ a capture token is REFUSED on every route outside its three capabilities", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);

    // Sanity: the token DOES work on its own three routes, so a blanket 401 below would prove
    // nothing about scoping.
    assert.equal((await request(port, { method: "GET", path: "/capture/sites", token })).status, 200);
    assert.equal((await request(port, { method: "GET", path: "/capture/slots", token })).status, 200);

    for (const [method, path, body] of FORBIDDEN_ROUTES) {
      const r = await request(port, { method, path, token, body });
      assert.ok(
        r.status === 401 || r.status === 403,
        `${method} ${path} answered ${r.status} to a capture token — it must be 401/403. `
        + `Body: ${JSON.stringify(r.body)}`
      );
    }
    // ⛔ And nothing on that sweep reached a pharmacy write.
    assert.deepEqual(store._forbidden, []);
  } finally {
    await close(server);
  }
});

test("⛔ the capture token cannot mint another token from itself", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    // POST /capture/token takes a TICKET. A token presented there is not a ticket, and the
    // ticket is deliberately not one of the three capabilities — it buys a token and nothing
    // else, so a token cannot bootstrap itself a fresh ninety minutes forever.
    const r = await request(port, { method: "POST", path: "/capture/token", token, body: {} });
    assert.equal(r.status, 401);
    assert.equal(r.body.reason, "no-such-ticket");
  } finally {
    await close(server);
  }
});

test("a token missing one capability is refused on THAT route and still works on the others", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    // Narrow the stored row, as if a future mint had issued a partial token.
    const row = store._tokens.get(sha(token));
    row.capabilities = ["sites:list"];

    assert.equal((await request(port, { method: "GET", path: "/capture/sites", token })).status, 200);
    assert.equal((await request(port, { method: "GET", path: "/capture/slots", token })).status, 401);
    const reg = await request(port, {
      method: "POST", path: "/capture/register", token, body: { role: "server" },
    });
    assert.equal(reg.status, 401);
  } finally {
    await close(server);
  }
});

test("the estate admin token and the operator token are NOT capture tokens", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // The scoping runs both ways: the three capture routes read their site from a capture
    // token's ticket binding, so there is no site for a master-token caller to be acting on.
    // Admitting the admin token here would put the estate credential back on the route the kit
    // uses, which is precisely what this design removes.
    for (const t of [ENROLL_TOKEN, OPERATOR_TOKEN, "nonsense"]) {
      assert.equal((await request(port, { method: "GET", path: "/capture/sites", token: t })).status, 401);
      assert.equal((await request(port, { method: "GET", path: "/capture/slots", token: t })).status, 401);
      assert.equal((await request(port, {
        method: "POST", path: "/capture/register", token: t, body: { role: "server" },
      })).status, 401);
    }
  } finally {
    await close(server);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// issuing the ticket
// ════════════════════════════════════════════════════════════════════════════

test("⛔ the shared admin token cannot issue a capture ticket — it names nobody", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "POST", path: `/pharmacies/${PHARMACY.id}/capture-ticket`,
      token: ENROLL_TOKEN, body: {},
    });
    assert.equal(r.status, 401);
    assert.match(r.body.error, /named per-operator token/);
    assert.equal(store._tickets.size, 0);
  } finally {
    await close(server);
  }
});

test("the issued ticket names the person from the CREDENTIAL, and shows the secret once", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "POST", path: `/pharmacies/${PHARMACY.id}/capture-ticket`,
      token: OPERATOR_TOKEN, body: { by: "somebody.else", note: "counter rebuild" },
    });
    assert.equal(r.status, 201);
    // The name is a property of the secret, not a string in the body.
    assert.equal(r.body.ticket.issued_by, "leo.wilson");
    assert.ok(r.body.secret.startsWith("wcncap_t_"));
    assert.deepEqual(r.body.capabilities, captureToken.CAPABILITIES.slice());

    // ⛔ THE SECRET IS NEVER RETURNED AGAIN. Not in the list, not in the shape, not anywhere.
    const list = await request(port, {
      method: "GET", path: `/pharmacies/${PHARMACY.id}/capture-ticket`, token: ENROLL_TOKEN,
    });
    assert.equal(list.status, 200);
    assert.equal(list.body.tickets.length, 1);
    assert.equal(list.body.tickets[0].secret, undefined);
    assert.equal(list.body.tickets[0].secret_hash, undefined);
    assert.doesNotMatch(JSON.stringify(list.body), new RegExp(r.body.secret.slice(9, 25)));
  } finally {
    await close(server);
  }
});

test("⛔ a ticket is refused during the site's opening hours", async () => {
  const config = makeConfig();
  const store = makeCaptureStore({
    hours: {
      is_open: true, hours_source: "voip", resolved: true, gate_resolved: true,
      next_close_at: new Date(Date.now() + 3 * 3600e3).toISOString(), next_open_at: null,
    },
  });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "POST", path: `/pharmacies/${PHARMACY.id}/capture-ticket`,
      token: OPERATOR_TOKEN, body: {},
    });
    assert.equal(r.status, 409);
    assert.equal(r.body.reason, "site-open");
    assert.equal(store._tickets.size, 0);
  } finally {
    await close(server);
  }
});

test("revoking a ticket kills the tokens it already minted, not just future ones", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token, issued } = await standUpKit(port, store);
    assert.equal((await request(port, { method: "GET", path: "/capture/sites", token })).status, 200);

    const ticketId = [...store._tickets.values()][0].id;
    const rv = await request(port, {
      method: "DELETE", path: `/capture-tickets/${ticketId}`, token: OPERATOR_TOKEN,
    });
    assert.equal(rv.status, 200);
    assert.equal(rv.body.ticket.state, "revoked");

    // The live token dies with it. A kill switch that leaves a bearer working for another
    // ninety minutes is not a kill switch.
    assert.equal((await request(port, { method: "GET", path: "/capture/sites", token })).status, 401);
    // And the ticket cannot mint a replacement.
    const again = await request(port, {
      method: "POST", path: "/capture/token", token: issued.body.secret, body: {},
    });
    assert.equal(again.status, 401);
    assert.equal(again.body.reason, "revoked");
  } finally {
    await close(server);
  }
});

// ════════════════════════════════════════════════════════════════════════════
// the three capabilities, doing their three things
// ════════════════════════════════════════════════════════════════════════════

test("sites:list is scoped to the ticket's site and takes no parameter", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    const r = await request(port, { method: "GET", path: "/capture/sites", token });
    assert.equal(r.status, 200);
    assert.equal(r.body.sites.length, 1);
    assert.equal(r.body.sites[0].code, PHARMACY.code);
    assert.equal(r.body.scoped_to_ticket, true);
    // A query string cannot widen it: there is no parameter to widen.
    const wide = await request(port, { method: "GET", path: "/capture/sites?pharmacy_id=1", token });
    assert.equal(wide.status, 200);
    assert.equal(wide.body.sites.length, 1);
    assert.equal(wide.body.sites[0].code, PHARMACY.code);
  } finally {
    await close(server);
  }
});

test("slots:read offers eleven roles with their addresses, and marks what is taken", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    const r = await request(port, { method: "GET", path: "/capture/slots", token });
    assert.equal(r.status, 200);
    assert.equal(r.body.slots.length, 11);
    assert.deepEqual(r.body.roles, captureToken.ROLE_VALUES.slice());
    const c3 = r.body.slots.find((s) => s.role === "client-03");
    assert.equal(c3.address, "10.200.42.13");
    assert.equal(c3.taken, false);
    // ⚠️ ALWAYS PRESENT, null when nothing holds it — an omitted key reads as "free".
    assert.equal(c3.capture, null);
    assert.ok("capture" in c3);
  } finally {
    await close(server);
  }
});

test("capture:write registers a run, is told where to upload, and resumes in place", async () => {
  const config = makeConfig();
  const store = makeCaptureStore({
    dropTarget: {
      node: "temeraire", storage_name: "local", dir: "/var/lib/vz/dump/pmr-capture",
      fs_type: "ext4", free_bytes: 900e9, writable: true,
      reported_at: "2026-08-26T01:00:00.000Z",
    },
  });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    const first = await request(port, {
      method: "POST", path: "/capture/register", token,
      body: { role: "client-03", pc_name: "RECEPTION", image_format: "qcow2", bytes_total: 70e9, bytes_sent: 0 },
    });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.capture.role, "client-03");
    // PROVENANCE ONLY — recorded, and not in the filename the server chose.
    assert.equal(first.body.capture.source_pc_name, "RECEPTION");
    assert.equal(first.body.upload.kind, "proxmox-drop-dir");
    assert.equal(first.body.upload.resumable, true);
    assert.match(first.body.upload.path, /^\/var\/lib\/vz\/dump\/pmr-capture\/RX99999-client-03-/);
    assert.doesNotMatch(first.body.upload.filename, /RECEPTION/);

    // The resume: the SAME ticket re-registers, and is handed the same destination back.
    const resumed = await request(port, {
      method: "POST", path: "/capture/register", token,
      body: { role: "client-03", bytes_sent: 42e9, guest_agent_installed: true },
    });
    assert.equal(resumed.status, 200);
    assert.equal(store._runs.length, 1, "a resume must not create a second run");
    assert.equal(resumed.body.capture.guest_agent_installed, true);

    // ⚠️ A TRI-STATE NOT REPORTED STAYS NULL. "We did not establish it" is not "no".
    assert.equal(resumed.body.capture.printers_cleared, null);
  } finally {
    await close(server);
  }
});

test("⛔ a capture registration cannot name its site", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    for (const key of ["pharmacy_id", "pharmacy_code", "site", "site_code"]) {
      const r = await request(port, {
        method: "POST", path: "/capture/register", token,
        body: { role: "server", [key]: 1 },
      });
      assert.equal(r.status, 400, `${key} must be refused outright`);
      assert.match(r.body.error, /must not name its site/);
    }
    assert.equal(store._runs.length, 0);
    // ⛔ And it never reached anything that creates or modifies a pharmacy.
    assert.deepEqual(store._forbidden, []);
  } finally {
    await close(server);
  }
});

test("⛔ a duplicate role is refused, and the refusal names who holds it", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const a = await standUpKit(port, store);
    const first = await request(port, {
      method: "POST", path: "/capture/register", token: a.token,
      body: { role: "client-03", taken_by: "leo.wilson" },
    });
    assert.equal(first.status, 200);

    // A SECOND ticket — a second engineer, a second kit — picking the same slot.
    const b = await standUpKit(port, store);
    const clash = await request(port, {
      method: "POST", path: "/capture/register", token: b.token, body: { role: "client-03" },
    });
    assert.equal(clash.status, 409);
    assert.match(clash.body.error, /already registered/);
    assert.equal(clash.body.role, "client-03");
    assert.equal(clash.body.capture.taken_by, "leo.wilson");
    assert.equal(store._runs.length, 1);

    // The slots read now shows it taken, so the picker refuses before the ninety minutes.
    const slots = await request(port, { method: "GET", path: "/capture/slots", token: b.token });
    const c3 = slots.body.slots.find((s) => s.role === "client-03");
    assert.equal(c3.taken, true);
    assert.deepEqual(c3.taken_by, ["capture"]);
  } finally {
    await close(server);
  }
});

test("⛔ out_of_hours is decided by the server, and a kit cannot assert its own compliance", async () => {
  const config = makeConfig();
  // The site is OPEN. A kit claiming out_of_hours:true must not be believed.
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    // Swap the site to open AFTER the ticket was issued — which is exactly what happens when a
    // capture overruns into trading hours.
    store.getSiteHours = async () => ({
      is_open: true, hours_source: "manual", resolved: true, gate_resolved: true,
      next_close_at: null, next_open_at: null,
    });
    const r = await request(port, {
      method: "POST", path: "/capture/register", token,
      body: { role: "server", out_of_hours: true },
    });
    assert.equal(r.status, 200);
    assert.equal(r.body.capture.out_of_hours, false, "the server judged it, not the kit");
  } finally {
    await close(server);
  }
});

test("with no drop directory reported the kit is told WHY, and given no path at all", async () => {
  const config = makeConfig();
  const store = makeCaptureStore({ dropTarget: null });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    const r = await request(port, {
      method: "POST", path: "/capture/register", token, body: { role: "server" },
    });
    assert.equal(r.status, 200);
    // The record still exists — the capture happened whether or not we can name a destination.
    assert.equal(r.body.capture.role, "server");
    assert.equal(r.body.upload, null);
    assert.equal(r.body.upload_refused.reason, "no-target-reported");
    assert.match(r.body.upload_refused.message, /USB/i);
  } finally {
    await close(server);
  }
});

test("an expired capture token is refused on its own routes", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { token } = await standUpKit(port, store);
    store._tokens.get(sha(token)).expires_at = new Date(Date.now() - 1000).toISOString();
    for (const [m, p] of [["GET", "/capture/sites"], ["GET", "/capture/slots"]]) {
      assert.equal((await request(port, { method: m, path: p, token })).status, 401);
    }
  } finally {
    await close(server);
  }
});

test("the mint reports the redemption budget, so a reboot is survivable and bounded", async () => {
  const config = makeConfig();
  const store = makeCaptureStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const { issued, minted } = await standUpKit(port, store);
    assert.equal(minted.body.redeem_count, 1);
    assert.equal(minted.body.redeem_max, captureToken.TICKET_REDEEM_MAX);
    assert.deepEqual(minted.body.capabilities, captureToken.CAPABILITIES.slice());
    // The token never outlives the ticket.
    assert.ok(new Date(minted.body.expires_at).getTime()
      <= new Date(minted.body.ticket_expires_at).getTime());

    // Redeem again — the guest-agent reboot case.
    const second = await request(port, {
      method: "POST", path: "/capture/token", token: issued.body.secret, body: {},
    });
    assert.equal(second.status, 200);
    assert.equal(second.body.redeem_count, 2);
    assert.notEqual(second.body.token, minted.body.token);

    // Spend the budget and the ticket refuses, by name.
    [...store._tickets.values()][0].redeem_count = captureToken.TICKET_REDEEM_MAX;
    const spent = await request(port, {
      method: "POST", path: "/capture/token", token: issued.body.secret, body: {},
    });
    assert.equal(spent.status, 401);
    assert.equal(spent.body.reason, "spent");
  } finally {
    await close(server);
  }
});
