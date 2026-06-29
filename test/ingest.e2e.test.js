// End-to-end ingest test: real HTTP POST /telemetry against createServer() backed by the
// in-memory Store. Exercises the full path: auth -> normalize -> derive bps/role/join ->
// upsert -> response shape. (docs/CONTRACT.md §API routes + §Tests.)
//
// The simulator and this test share ONE payload factory (makeTelemetry from simulate.js),
// so they can never drift.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const { createServer } = require("../src/ingest/server");
const { makeTelemetry } = require("../src/bin/simulate");
const transform = require("../src/shared/transform");

const ENROLL_TOKEN = "test-enroll-token";

// Build a config object the way the project's own config loader produces it, so the keys
// (defaultPollS / fastPollS / agentVersion / enrollToken …) match what the server reads.
function makeConfig() {
  process.env.STORE_KIND = "mem";
  process.env.ENROLL_TOKEN = ENROLL_TOKEN;
  process.env.PORT = "0";
  process.env.DEFAULT_POLL_S = process.env.DEFAULT_POLL_S || "10";
  process.env.FAST_POLL_S = process.env.FAST_POLL_S || "3";
  // Clear the require cache so env above is honoured on (re)load.
  const cfgPath = require.resolve("../src/shared/config");
  delete require.cache[cfgPath];
  const mod = require("../src/shared/config");
  if (typeof mod === "function") return mod();
  if (typeof mod.loadConfig === "function") return mod.loadConfig();
  return mod.config || mod;
}

// Issue a real HTTP request to the running server. Returns {status, body(parsed)}.
function request(port, { method, path, token, body }) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(JSON.stringify(body));
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
        try {
          parsed = buf ? JSON.parse(buf) : null;
        } catch {
          parsed = buf;
        }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers });
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}
function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

test("POST /telemetry twice: bps derived, neighbors + mac_hosts stored, response shape", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "HGT0A023T6C";
  const TOKEN = "device-bearer-abc123";
  // The server hashes the bearer (sha256) and looks it up via getDeviceByToken; seed the
  // device with the SAME hash so auth succeeds.
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash });

  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    // ── First POST: baseline counters, no previous sample -> bps null/0. ──
    const t0 = Date.now();
    const p1 = makeTelemetry({
      serial: SERIAL,
      now: t0,
      interfaces: [
        { name: "ether1", type: "ether", running: true, disabled: false, plugged: true,
          is_wan: true, bridge: "", speed: "1Gbps", full_duplex: true,
          rx_byte: 1_000_000, tx_byte: 500_000, rx_packet: 100, tx_packet: 90 },
      ],
      neighbors: [
        { interface: "ether3", identity: "phone-1", mac: "AA:BB:CC:DD:EE:01",
          address: "10.0.0.5", platform: "Yealink" },
      ],
      // mac_hosts intentionally null on the first (fast) tick -> "keep previous"
      mac_hosts: null,
      arp: null,
    });

    const r1 = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p1 });
    assert.equal(r1.status, 200, "first POST is 200");
    assert.equal(r1.body.ok, true);
    assert.equal(typeof r1.body.poll_interval_s, "number");
    assert.ok(r1.body.poll_interval_s > 0, "poll_interval_s present and positive");

    // After the first POST there is no prior sample, so rx_bps must not be a positive spike.
    let detail = await store.getDeviceDetail(SERIAL);
    assert.ok(detail, "device detail readable");
    let eth1 = detail.interfaces.find((i) => i.name === "ether1");
    assert.ok(eth1, "ether1 interface stored");
    assert.ok(eth1.rx_bps == null || eth1.rx_bps === 0, "no bps on first sample");
    // mac_hosts NOT stored on the first tick (payload.mac_hosts was null)
    assert.equal((detail.mac_hosts || []).length, 0, "mac_hosts not stored when null");

    // ── Second POST: counters advanced by a known amount over a known Δt. ──
    const dtMs = 10_000; // 10 seconds
    const t1 = t0 + dtMs;
    const rxBytes2 = 1_000_000 + 1_250_000; // +1.25 MB
    const txBytes2 = 500_000 + 125_000; // +125 KB
    const p2 = makeTelemetry({
      serial: SERIAL,
      now: t1,
      interfaces: [
        { name: "ether1", type: "ether", running: true, disabled: false, plugged: true,
          is_wan: true, bridge: "", speed: "1Gbps", full_duplex: true,
          rx_byte: rxBytes2, tx_byte: txBytes2, rx_packet: 200, tx_packet: 180 },
      ],
      neighbors: [
        { interface: "ether3", identity: "phone-1", mac: "AA:BB:CC:DD:EE:01",
          address: "10.0.0.5", platform: "Yealink" },
      ],
      // slow tick: now mac_hosts present -> must be stored (with DHCP host-name identity)
      mac_hosts: [{ mac: "AA:BB:CC:DD:EE:02", interface: "ether4", hostname: "RECEPTION-PC" }],
      arp: [{ mac: "AA:BB:CC:DD:EE:02", ip: "10.0.0.9" }],
    });

    const r2 = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p2 });
    assert.equal(r2.status, 200, "second POST is 200");
    assert.equal(r2.body.ok, true);
    assert.equal(typeof r2.body.poll_interval_s, "number");

    detail = await store.getDeviceDetail(SERIAL);
    eth1 = detail.interfaces.find((i) => i.name === "ether1");
    assert.ok(eth1, "ether1 still present after 2nd POST");

    // Expected bps from the contract math: bps = (Δbytes * 8) / Δseconds.
    // The server may have measured Δt itself; allow a small tolerance but require the
    // value to be a correct positive number in the right ballpark.
    const expectedRxBps = (1_250_000 * 8) / (dtMs / 1000); // = 1_000_000
    assert.ok(typeof eth1.rx_bps === "number", "rx_bps is a number after 2nd sample");
    assert.ok(eth1.rx_bps > 0, "rx_bps is positive after counters advanced");
    // within 20% of the analytic value (server-measured Δt may differ slightly from 10s)
    const ratio = eth1.rx_bps / expectedRxBps;
    assert.ok(ratio > 0.8 && ratio < 1.25, `rx_bps ~= ${expectedRxBps}, got ${eth1.rx_bps}`);

    // neighbors stored
    const nbr = detail.neighbors.find((n) => transform.normaliseMac(n.mac) === "AA:BB:CC:DD:EE:01");
    assert.ok(nbr, "neighbor stored");
    assert.equal(nbr.interface, "ether3");

    // mac_hosts now stored (provided on the slow tick)
    assert.ok(detail.mac_hosts.length >= 1, "mac_hosts stored when provided");
    const mh = detail.mac_hosts.find((m) => transform.normaliseMac(m.mac) === "AA:BB:CC:DD:EE:02");
    assert.ok(mh, "the provided mac_host is present");
    assert.equal(mh.interface, "ether4");
    assert.equal(mh.hostname, "RECEPTION-PC", "DHCP host-name stored as device identity");

    // LTE: the full lte_state row is stored AND the single-number lte_signal is promoted
    // onto the bounded device_state row for the overview grid (regression: it used to be
    // built but never assigned in handlers, leaving device_state.lte_signal always null).
    const lteRow = Array.isArray(detail.lte) ? detail.lte[0] : detail.lte;
    assert.ok(lteRow, "lte_state row stored when payload carries lte");
    assert.equal(typeof detail.state.lte_signal, "number", "device_state.lte_signal populated from RSRP");
    assert.equal(detail.state.lte_signal, Math.round(lteRow.rsrp), "lte_signal mirrors lte_state RSRP");
  } finally {
    await close(server);
  }
});

test("POST /telemetry: wifi config + clients stored, signal parsed, snapshot replace on next tick", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "WIFI0AX001";
  const TOKEN = "wifi-bearer-xyz";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // Tick 1: two SSIDs + three associated stations (one signal in AC "-NN@rate" form).
    const p1 = makeTelemetry({
      serial: SERIAL,
      wifi: [
        { interface: "wifi1", driver: "AX", band: "5ghz", ssid: "Allied-Staff", passphrase: "s3cret-psk",
          security: "wpa2-psk", channel: "5180/20/ax", frequency_mhz: "5180", width_mhz: "20", disabled: false, hidden: false },
        { interface: "wifi2", driver: "ax", band: "2ghz", ssid: "Allied-Guest", passphrase: "guestpass", security: "wpa2-psk" },
      ],
      wifi_clients: [
        { interface: "wifi1", mac: "AA:BB:CC:00:00:02", signal: "-57@6mbps", rx_rate: "130Mbps", tx_rate: "144Mbps" },
        { interface: "wifi1", mac: "AA:BB:CC:00:00:03", signal: -72 },
        { interface: "wifi2", mac: "AA:BB:CC:00:00:04", signal: -83 },
      ],
    });
    const r1 = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p1 });
    assert.equal(r1.status, 200);

    let detail = await store.getDeviceDetail(SERIAL);
    assert.equal(detail.wifi.length, 2, "two SSIDs stored");
    const staff = detail.wifi.find((w) => w.ssid === "Allied-Staff");
    assert.ok(staff, "staff SSID present");
    assert.equal(staff.driver, "ax", "driver lower-cased");
    assert.equal(staff.passphrase, "s3cret-psk", "plaintext PSK stored for the masked-reveal UI");
    assert.equal(staff.frequency_mhz, 5180, "channel numerics coerced to number");
    assert.equal(staff.clients, 2, "denormalised client count (wifi1 has 2 stations)");

    assert.equal(detail.wifi_clients.length, 3, "three stations stored");
    const c1 = detail.wifi_clients.find((c) => transform.normaliseMac(c.mac) === "AA:BB:CC:00:00:02");
    assert.ok(c1, "station stored");
    assert.equal(c1.signal, -57, "signal '-57@6mbps' parsed to dBm number");

    // Tick 2: one station has left wifi1 -> full-snapshot replace must drop it.
    const p2 = makeTelemetry({
      serial: SERIAL,
      wifi: null, // keep previous config
      wifi_clients: [
        { interface: "wifi1", mac: "AA:BB:CC:00:00:02", signal: -60 },
      ],
    });
    const r2 = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p2 });
    assert.equal(r2.status, 200);
    detail = await store.getDeviceDetail(SERIAL);
    assert.equal(detail.wifi.length, 2, "wifi config kept (payload.wifi was null)");
    assert.equal(detail.wifi_clients.length, 1, "departed stations removed by snapshot replace");
    assert.equal(detail.wifi_clients[0].signal, -60, "remaining station's signal updated");
    const staff2 = detail.wifi.find((w) => w.ssid === "Allied-Staff");
    assert.equal(staff2.clients, 1, "client count reflects the new snapshot");
  } finally {
    await close(server);
  }
});

test("POST /speedtest/result with a malformed job_id -> 404, and the ingest keeps serving", async () => {
  // Regression: a device POSTing job_id="t" hit `WHERE id = $1` on a uuid column. In pg that
  // throws "invalid input syntax for type uuid"; unhandled, it crash-looped the whole ingest.
  // The store now treats a non-UUID id as "not found" -> the handler 404s, and the process
  // survives. (Mem store can't reproduce the pg throw, so this locks the handler contract +
  // proves the server stays up to serve the next request.)
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "ST-BADID";
  const TOKEN = "st-bearer";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const bad = await request(port, {
      method: "POST", path: "/speedtest/result", token: TOKEN,
      body: { job_id: "t", status: "done" },
    });
    assert.equal(bad.status, 404, "malformed job_id is not found, not a crash");

    // Server still alive: a normal telemetry POST right after succeeds.
    const ok = await request(port, {
      method: "POST", path: "/telemetry", token: TOKEN, body: makeTelemetry({ serial: SERIAL }),
    });
    assert.equal(ok.status, 200, "ingest still serving after the bad request");
  } finally {
    await close(server);
  }
});

test("POST /realtime/config: 501 unconfigured; admin-gated; mints a verifiable authenticated JWT", async () => {
  const crypto = require("node:crypto");
  // ── unconfigured → 501 (dashboard stays on polling) ──
  delete process.env.SUPABASE_URL; delete process.env.SUPABASE_ANON_KEY; delete process.env.SUPABASE_JWT_SECRET;
  {
    const server = createServer({ store: makeMemStore(), config: makeConfig() });
    const port = await listen(server);
    try {
      const r = await request(port, { method: "POST", path: "/realtime/config", token: ENROLL_TOKEN });
      assert.equal(r.status, 501, "501 when Supabase isn't configured");
    } finally { await close(server); }
  }
  // ── configured → mints a short-lived authenticated JWT ──
  process.env.SUPABASE_URL = "https://sb.example";
  process.env.SUPABASE_ANON_KEY = "anon-123";
  process.env.SUPABASE_JWT_SECRET = "super-secret-jwt";
  try {
    const server = createServer({ store: makeMemStore(), config: makeConfig() });
    const port = await listen(server);
    try {
      const unauth = await request(port, { method: "POST", path: "/realtime/config" });
      assert.equal(unauth.status, 401, "admin-gated (no token)");

      const r = await request(port, { method: "POST", path: "/realtime/config", token: ENROLL_TOKEN });
      assert.equal(r.status, 200);
      assert.equal(r.body.url, "https://sb.example");
      assert.equal(r.body.anonKey, "anon-123");
      assert.equal(r.body.schema, "vigilant");

      const parts = String(r.body.token).split(".");
      assert.equal(parts.length, 3, "JWT has header.payload.signature");
      const expSig = crypto.createHmac("sha256", "super-secret-jwt").update(parts[0] + "." + parts[1])
        .digest("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      assert.equal(parts[2], expSig, "HS256 signature verifies with the secret");
      const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
      assert.equal(payload.role, "authenticated", "role claim drives RLS");
      assert.ok(payload.exp > Math.floor(Date.now() / 1000), "not already expired");
    } finally { await close(server); }
  } finally {
    delete process.env.SUPABASE_URL; delete process.env.SUPABASE_ANON_KEY; delete process.env.SUPABASE_JWT_SECRET;
  }
});

test("CORS + scoped FIELD_ENROLL_TOKEN: preflight OK; field key enrols + reads (fleet/device/history) but not mutations", async () => {
  process.env.FIELD_ENROLL_TOKEN = "field-key-xyz";
  let server;
  try {
    server = createServer({ store: makeMemStore(), config: makeConfig() });
    const port = await listen(server);

    // CORS preflight must be answered (else the browser blocks the real call).
    const pre = await request(port, { method: "OPTIONS", path: "/enroll" });
    assert.equal(pre.status, 204, "preflight 204");
    assert.ok(pre.headers["access-control-allow-origin"], "CORS allow-origin header present");

    // The scoped field key can enrol…
    const en = await request(port, {
      method: "POST", path: "/enroll", token: "field-key-xyz",
      body: { serial: "FLD-1", site_name: "Field Test" },
    });
    assert.equal(en.status, 200, "field key enrols");
    assert.ok(en.body.token && en.body.install, "enrol returns token + install block");

    // …and read that one device (verify step)…
    const dev = await request(port, { method: "GET", path: "/devices/FLD-1", token: "field-key-xyz" });
    assert.equal(dev.status, 200, "field key reads single device");

    // …and the read-only fleet/history (wc_field stats views)…
    const fleet = await request(port, { method: "GET", path: "/fleet", token: "field-key-xyz" });
    assert.equal(fleet.status, 200, "field key may read the fleet (read-only)");
    const hist = await request(port, { method: "GET", path: "/devices/FLD-1/history?window=1h", token: "field-key-xyz" });
    assert.equal(hist.status, 200, "field key may read history");

    // …but NOT mutation / admin routes (config-push is master-only).
    const cfgJobs = await request(port, { method: "GET", path: "/devices/FLD-1/config-jobs", token: "field-key-xyz" });
    assert.equal(cfgJobs.status, 401, "field key rejected on config-jobs (master-only)");
    const migrate = await request(port, { method: "POST", path: "/admin/migrate", token: "field-key-xyz" });
    assert.equal(migrate.status, 401, "field key rejected on /admin/migrate (master-only)");
  } finally {
    if (server) await close(server);
    delete process.env.FIELD_ENROLL_TOKEN;
  }
});

test("alert-rule CRUD (admin): create → list → update → delete, with validation + auth", async () => {
  const server = createServer({ store: makeMemStore(), config: makeConfig() });
  const port = await listen(server);
  try {
    const c = await request(port, { method: "POST", path: "/alert-rules", token: ENROLL_TOKEN,
      body: { name: "CPU high", metric: "cpu_load", comparator: ">", threshold: 90, severity: "critical", notify_email: "noc@wcn", notify_teams_webhook: "https://teams/x", notify_on: "both" } });
    assert.equal(c.status, 201);
    const id = c.body.rule.id;
    assert.ok(id, "create returns the new rule id");
    assert.equal(c.body.rule.notify_email, "noc@wcn");

    const l = await request(port, { method: "GET", path: "/alert-rules", token: ENROLL_TOKEN });
    assert.equal(l.status, 200);
    assert.ok(l.body.rules.some((r) => r.id === id), "rule appears in the list");

    const u = await request(port, { method: "PUT", path: `/alert-rules/${id}`, token: ENROLL_TOKEN,
      body: { name: "CPU high", metric: "cpu_load", comparator: ">", threshold: 80, severity: "warning", notify_on: "open" } });
    assert.equal(u.status, 200);
    assert.equal(u.body.rule.threshold, 80, "update applied");
    assert.equal(u.body.rule.notify_on, "open");

    const bad = await request(port, { method: "POST", path: "/alert-rules", token: ENROLL_TOKEN, body: { metric: "cpu_load" } });
    assert.equal(bad.status, 400, "name required");
    const noauth = await request(port, { method: "GET", path: "/alert-rules" });
    assert.equal(noauth.status, 401, "admin-gated");

    const d = await request(port, { method: "DELETE", path: `/alert-rules/${id}`, token: ENROLL_TOKEN });
    assert.equal(d.status, 200);
    const d2 = await request(port, { method: "DELETE", path: `/alert-rules/${id}`, token: ENROLL_TOKEN });
    assert.equal(d2.status, 404, "second delete is not-found");

    // test endpoint: needs auth + at least one channel.
    const tNoAuth = await request(port, { method: "POST", path: "/alert-rules/test", body: {} });
    assert.equal(tNoAuth.status, 401, "test endpoint admin-gated");
    const tNoChan = await request(port, { method: "POST", path: "/alert-rules/test", token: ENROLL_TOKEN, body: { name: "x" } });
    assert.equal(tNoChan.status, 400, "test needs a channel");
  } finally {
    await close(server);
  }
});

test("POST /telemetry without a valid bearer -> 401", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  await seedDevice(store, { serial: "RB-AUTH", token: "good-token" });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: "wrong-token",
      body: makeTelemetry({ serial: "RB-AUTH" }),
    });
    assert.equal(r.status, 401, "bad bearer is rejected");
  } finally {
    await close(server);
  }
});

test("GET / serves the admin onboarding UI (handler exported + wired)", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, { method: "GET", path: "/" });
    assert.equal(r.status, 200, "root returns 200 (not a 500 from a missing export)");
    assert.equal(typeof r.body, "string", "root serves HTML, not JSON");
    assert.ok(/Vigilant|onboarding/i.test(r.body), "root is the admin UI page");
  } finally {
    await close(server);
  }
});
