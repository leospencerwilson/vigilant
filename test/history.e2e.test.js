// End-to-end test for the dashboard history API: GET /devices/:serial/history?window=1h
// against createServer() backed by the in-memory Store. Verifies the documented contract
// shape, admin auth, window handling, and 404 on an unknown serial. (docs/CONTRACT.md
// §HISTORY API + the dashboard admin.html consumer.)
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const { createServer } = require("../src/ingest/server");
const { makeTelemetry } = require("../src/bin/simulate");
const transform = require("../src/shared/transform");

const ENROLL_TOKEN = "test-enroll-token";

function makeConfig() {
  process.env.STORE_KIND = "mem";
  process.env.ENROLL_TOKEN = ENROLL_TOKEN;
  process.env.PORT = "0";
  process.env.DEFAULT_POLL_S = process.env.DEFAULT_POLL_S || "10";
  process.env.FAST_POLL_S = process.env.FAST_POLL_S || "3";
  const cfgPath = require.resolve("../src/shared/config");
  delete require.cache[cfgPath];
  const mod = require("../src/shared/config");
  if (typeof mod === "function") return mod();
  if (typeof mod.loadConfig === "function") return mod.loadConfig();
  return mod.config || mod;
}

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
        resolve({ status: res.statusCode, body: parsed });
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

test("GET /devices/:serial/history returns metrics + per-interface series, time-ascending", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "HGT0A96706Z"; // the real Old Swan box
  const TOKEN = "device-bearer-history";
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash, site_name: "Allied Old Swan" });

  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    // Two ticks 10s apart so the second has a real positive bps and we get two metric rows.
    const t0 = Date.now() - 30_000;
    const p1 = makeTelemetry({ serial: SERIAL, tick: 1, now: t0 });
    const p2 = makeTelemetry({ serial: SERIAL, tick: 2, now: t0 + 10_000, prev: p1 });

    let r = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p1 });
    assert.equal(r.status, 200, "tick 1 ingested");
    r = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body: p2 });
    assert.equal(r.status, 200, "tick 2 ingested");

    // Admin GET with the default window.
    const h = await request(port, {
      method: "GET",
      path: `/devices/${SERIAL}/history?window=1h`,
      token: ENROLL_TOKEN,
    });
    assert.equal(h.status, 200, "history is 200 for admin");
    assert.equal(h.body.serial, SERIAL, "serial echoed");
    assert.equal(h.body.window, "1h", "window echoed");

    // Device-level metrics: two rows, time-ascending, with the documented keys.
    assert.ok(Array.isArray(h.body.metrics), "metrics is an array");
    assert.ok(h.body.metrics.length >= 2, "two metric rows appended (one per core tick)");
    const m0 = h.body.metrics[0];
    assert.ok("ts" in m0 && "cpu_load" in m0 && "free_memory" in m0 && "temperature" in m0 && "ppp_sessions" in m0,
      "metric row has the contract keys");
    for (let i = 1; i < h.body.metrics.length; i++) {
      assert.ok(
        new Date(h.body.metrics[i].ts).getTime() >= new Date(h.body.metrics[i - 1].ts).getTime(),
        "metrics are time-ascending"
      );
    }

    // Per-interface series: ether1 (the WAN) present with a points array carrying rx/tx bps.
    assert.ok(Array.isArray(h.body.interfaces), "interfaces is an array");
    const eth1 = h.body.interfaces.find((i) => i.name === "ether1");
    assert.ok(eth1, "ether1 interface series present");
    assert.ok(Array.isArray(eth1.points) && eth1.points.length >= 2, "ether1 has >=2 points");
    const pt = eth1.points[eth1.points.length - 1];
    assert.ok("ts" in pt && "rx_bps" in pt && "tx_bps" in pt, "interface point has the contract keys");
    assert.ok(typeof pt.rx_bps === "number" && pt.rx_bps > 0, "second interface point has a positive rx_bps");
  } finally {
    await close(server);
  }
});

test("GET /devices/:serial/history requires the admin token", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  await seedDevice(store, { serial: "RB-HISTAUTH", token: "good" });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "GET",
      path: "/devices/RB-HISTAUTH/history",
      token: "not-the-admin-token",
    });
    assert.equal(r.status, 401, "non-admin bearer is rejected");
  } finally {
    await close(server);
  }
});

test("GET /devices/:serial/history 404s on an unknown serial", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "GET",
      path: "/devices/NO-SUCH-SERIAL/history",
      token: ENROLL_TOKEN,
    });
    assert.equal(r.status, 404, "unknown serial 404s");
  } finally {
    await close(server);
  }
});

test("store.getDeviceHistory (mem): seeded history returns the contract shape, ascending; null on unknown serial", async () => {
  const store = makeMemStore();
  const SERIAL = "RB-HIST-UNIT";
  const device = await seedDevice(store, { serial: SERIAL });

  // Seed history directly via the store append methods (out of order on purpose, recent).
  const now = Date.now();
  const tA = new Date(now - 20_000).toISOString();
  const tB = new Date(now - 10_000).toISOString();
  // Append B before A to prove getDeviceHistory sorts time-ASCENDING regardless of insert order.
  await store.appendMetricsHistory(device.id, tB, {
    cpu_load: 30, free_memory: 100, temperature: 42, ppp_sessions: 3, conn_count: null,
  });
  await store.appendMetricsHistory(device.id, tA, {
    cpu_load: 20, free_memory: 200, temperature: 41, ppp_sessions: 2, conn_count: null,
  });
  await store.appendInterfaceHistory(device.id, tB, [{ name: "ether1", rx_bps: 2000, tx_bps: 1000 }]);
  await store.appendInterfaceHistory(device.id, tA, [{ name: "ether1", rx_bps: 1000, tx_bps: 500 }]);

  const hist = await store.getDeviceHistory(SERIAL, 3600);
  assert.ok(hist, "history object returned for a known serial");
  assert.equal(hist.serial, SERIAL, "serial echoed");

  // metrics[] in the contract shape, time-ASCENDING.
  assert.ok(Array.isArray(hist.metrics), "metrics is an array");
  assert.equal(hist.metrics.length, 2, "both metric rows in window");
  assert.deepEqual(Object.keys(hist.metrics[0]).sort(),
    ["cpu_load", "free_memory", "ppp_sessions", "temperature", "ts"],
    "metric row carries exactly the contract keys");
  assert.equal(hist.metrics[0].cpu_load, 20, "ascending: oldest (tA) first");
  assert.equal(hist.metrics[1].cpu_load, 30, "ascending: newest (tB) last");
  assert.ok(new Date(hist.metrics[1].ts).getTime() >= new Date(hist.metrics[0].ts).getTime(),
    "metrics time-ascending");

  // interfaces[] -> [{name, points:[{ts,rx_bps,tx_bps}]}], points ascending.
  assert.ok(Array.isArray(hist.interfaces), "interfaces is an array");
  const eth1 = hist.interfaces.find((i) => i.name === "ether1");
  assert.ok(eth1, "ether1 series present");
  assert.equal(eth1.points.length, 2, "two interface points");
  assert.deepEqual(Object.keys(eth1.points[0]).sort(), ["rx_bps", "ts", "tx_bps"],
    "interface point carries exactly the contract keys");
  assert.equal(eth1.points[0].rx_bps, 1000, "points ascending: oldest first");
  assert.equal(eth1.points[1].rx_bps, 2000, "points ascending: newest last");

  // A window that excludes everything yields empty (but non-null) series for a known device.
  const empty = await store.getDeviceHistory(SERIAL, 1);
  assert.ok(empty, "known serial with no in-window rows still returns an object");
  assert.equal(empty.metrics.length, 0, "nothing within a 1s window");
  assert.equal(empty.interfaces.length, 0, "no interface series within a 1s window");

  // Unknown serial -> null (so the route can 404).
  assert.equal(await store.getDeviceHistory("NO-SUCH", 3600), null, "unknown serial -> null");
});

test("GET /devices/:serial/history defaults an unrecognised window to 1h", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "RB-WINDOW";
  const TOKEN = "device-bearer-win";
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "GET",
      path: `/devices/${SERIAL}/history?window=banana`,
      token: ENROLL_TOKEN,
    });
    assert.equal(r.status, 200, "bad window still returns 200 (fail soft)");
    assert.equal(r.body.window, "1h", "unrecognised window falls back to 1h");
  } finally {
    await close(server);
  }
});
