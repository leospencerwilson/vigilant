// Chunked-telemetry e2e: a large tick split across several SMALL POST /telemetry requests.
//
// WHY THIS EXISTS (docs/CONTRACT.md §chunked telemetry): RouterOS /tool fetch caps the size
// of the http-data argument the script can hand the fetch subsystem, so a multi-interface
// router cannot POST its whole rich body at once. The agent therefore splits a tick into a
// CORE chunk (system/device_state, no interfaces) and one or more DETAIL chunks (a few
// interfaces / neighbors each, partial:true). The server must treat EVERY POST as an
// idempotent partial upsert of whatever it carries, and a chunk must NEVER wipe data it does
// not carry.
//
// This proves:
//   1. a CORE-only chunk upserts device_state (status/cpu/uptime) WITHOUT touching interfaces;
//   2. an INTERFACES-only chunk upserts those interfaces (and, on the 2nd such chunk, computes
//      a correct positive bps from the prior sample) WITHOUT touching device_state's system
//      columns and WITHOUT wiping the device 'online' status;
//   3. neither chunk wipes the other's data;
//   4. the existing single full payload path is unaffected (covered by ingest.e2e.test.js).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const { createServer } = require("../src/ingest/server");
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

// A CORE chunk: system/device_state block, NO interfaces array. This is the only chunk that
// writes device_state and carries status:'online'. Bounded size regardless of interface count.
function coreChunk({ serial, now, cpu_load }) {
  return {
    serial,
    ts: now,
    identity: "OldSwan",
    uptime: "5d3h",
    cpu_load,
    free_memory: 123456000,
    total_memory: 268435456,
    ros_version: "7.18",
    pppoe_running: true,
    ppp_sessions: 3,
    dhcp_leases: 41,
    ntp_synced: true,
    public_ip: "84.247.33.71",
    lte: {
      interface: "lte1",
      operator: "23410",
      registration: "registered",
      access_tech: "lte",
      rsrp: "-95",
      rsrq: "-10",
      sinr: "12",
      rssi: "-65",
    },
    // deliberately NO interfaces / neighbors / mac_hosts here
  };
}

// A DETAIL chunk: partial:true + a batch of interfaces (and optional neighbors). Carries NO
// system block, so it must not overwrite device_state's system columns.
function ifaceChunk({ serial, now, interfaces, neighbors }) {
  return {
    serial,
    ts: now,
    partial: true,
    interfaces,
    ...(neighbors ? { neighbors } : {}),
  };
}

test("chunked telemetry: core chunk writes device_state without touching interfaces; iface chunk upserts interfaces + bps without wiping device_state", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "HGT0A96706Z"; // the real Old-Swan serial from the debug evidence
  const TOKEN = "device-bearer-chunked";
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash });

  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    const t0 = Date.now();

    // ── 1. CORE chunk only: device_state upserted, interfaces untouched. ──
    const rCore = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: TOKEN,
      body: coreChunk({ serial: SERIAL, now: t0, cpu_load: 17 }),
    });
    assert.equal(rCore.status, 200, "core chunk 200");
    assert.equal(rCore.body.ok, true);
    // The core chunk is where the agent reads the control fields back.
    assert.equal(typeof rCore.body.poll_interval_s, "number", "core chunk returns control fields");

    let detail = await store.getDeviceDetail(SERIAL);
    assert.ok(detail.state, "device_state row written by core chunk");
    assert.equal(detail.state.status, "online", "core chunk marks device online");
    assert.equal(detail.state.cpu_load, 17, "core chunk wrote cpu_load");
    assert.ok(detail.state.uptime_s > 0, "core chunk parsed uptime");
    // lte_state row + bounded lte_signal mirror both come from the core chunk.
    assert.equal(typeof detail.state.lte_signal, "number", "lte_signal promoted on core chunk");
    // NO interfaces yet — the core chunk carried none, and it must not have invented any.
    assert.equal(detail.interfaces.length, 0, "core chunk did NOT create interface rows");

    // ── 2. INTERFACES chunk (batch 1): upserts a subset, device_state system cols intact. ──
    const ifaceBaseline = [
      { name: "ether1", type: "ether", running: true, disabled: false, plugged: true,
        is_wan: true, bridge: "", speed: "1Gbps", full_duplex: true,
        rx_byte: 1_000_000, tx_byte: 500_000, rx_packet: 100, tx_packet: 90 },
      { name: "bridge-lan", type: "bridge", running: true, disabled: false, plugged: true,
        is_wan: false, bridge: "", speed: "", full_duplex: true,
        rx_byte: 9_000_000, tx_byte: 8_000_000, rx_packet: 7000, tx_packet: 6000 },
    ];
    const rIf1 = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: TOKEN,
      body: ifaceChunk({
        serial: SERIAL,
        now: t0,
        interfaces: ifaceBaseline,
        neighbors: [
          { interface: "bridge-lan", identity: "phone-1", mac: "AA:BB:CC:DD:EE:01",
            address: "10.0.0.5", platform: "Yealink" },
        ],
      }),
    });
    assert.equal(rIf1.status, 200, "iface chunk 1 is 200");
    assert.equal(rIf1.body.ok, true);

    detail = await store.getDeviceDetail(SERIAL);
    // device_state system columns from the core chunk must survive the detail chunk.
    assert.equal(detail.state.cpu_load, 17, "iface chunk did NOT clobber cpu_load");
    assert.equal(detail.state.ros_version, "7.18", "iface chunk did NOT clobber ros_version");
    assert.equal(detail.state.status, "online", "device still online after iface chunk");
    // interfaces now present.
    assert.equal(detail.interfaces.length, 2, "both interfaces in the batch were upserted");
    let eth1 = detail.interfaces.find((i) => i.name === "ether1");
    assert.ok(eth1, "ether1 upserted by iface chunk");
    assert.ok(eth1.rx_bps == null || eth1.rx_bps === 0, "no bps on first interface sample");
    // neighbors upserted by the same detail chunk.
    const nbr = detail.neighbors.find(
      (n) => transform.normaliseMac(n.mac) === "AA:BB:CC:DD:EE:01");
    assert.ok(nbr, "neighbor upserted on detail chunk");

    // ── 3. Second INTERFACES chunk: counters advanced -> correct positive bps across chunks. ──
    const dtMs = 10_000;
    const t1 = t0 + dtMs;
    const rxBytes2 = 1_000_000 + 1_250_000; // +1.25 MB over 10s -> 1,000,000 bps
    const rIf2 = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: TOKEN,
      body: ifaceChunk({
        serial: SERIAL,
        now: t1,
        interfaces: [
          { name: "ether1", type: "ether", running: true, disabled: false, plugged: true,
            is_wan: true, bridge: "", speed: "1Gbps", full_duplex: true,
            rx_byte: rxBytes2, tx_byte: 500_000 + 125_000, rx_packet: 200, tx_packet: 180 },
        ],
      }),
    });
    assert.equal(rIf2.status, 200, "iface chunk 2 is 200");

    detail = await store.getDeviceDetail(SERIAL);
    eth1 = detail.interfaces.find((i) => i.name === "ether1");
    const expectedRxBps = (1_250_000 * 8) / (dtMs / 1000); // 1,000,000
    assert.equal(typeof eth1.rx_bps, "number", "rx_bps computed across chunked iface POSTs");
    assert.ok(eth1.rx_bps > 0, "rx_bps positive after counters advanced across chunks");
    const ratio = eth1.rx_bps / expectedRxBps;
    assert.ok(ratio > 0.8 && ratio < 1.25, `rx_bps ~= ${expectedRxBps}, got ${eth1.rx_bps}`);

    // bridge-lan was NOT in chunk 2 -> it must still be present (subset upsert, not replace).
    const br = detail.interfaces.find((i) => i.name === "bridge-lan");
    assert.ok(br, "bridge-lan from chunk 1 survived a chunk-2 POST that omitted it");
    assert.equal(detail.interfaces.length, 2, "omitted interface not deleted by a later chunk");

    // device_state STILL holds the core-chunk system values (never written by detail chunks).
    assert.equal(detail.state.cpu_load, 17, "system cols still intact after two detail chunks");

    // ── 4. A fresh core chunk updates only the system block, leaving interfaces alone. ──
    const t2 = t1 + dtMs;
    const rCore2 = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: TOKEN,
      body: coreChunk({ serial: SERIAL, now: t2, cpu_load: 42 }),
    });
    assert.equal(rCore2.status, 200, "second core chunk 200");
    detail = await store.getDeviceDetail(SERIAL);
    assert.equal(detail.state.cpu_load, 42, "second core chunk refreshed cpu_load");
    assert.equal(detail.interfaces.length, 2, "core chunk did not disturb interface rows");
    eth1 = detail.interfaces.find((i) => i.name === "ether1");
    assert.ok(eth1.rx_bps > 0, "interface bps preserved across an interleaved core chunk");
  } finally {
    await close(server);
  }
});

test("chunked telemetry: a CORE chunk with QUOTED-string numerics stores numeric device_state ('null' -> null)", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "HGT0A96706Z";
  const TOKEN = "device-bearer-coerce";
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash });

  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    // The real agent emits health numerics as QUOTED strings, and absent values as the
    // literal string 'null'. The ingest must store them as number|null in device_state.
    const body = {
      serial: SERIAL,
      ts: Date.now(),
      identity: "OldSwan",
      uptime: "5d3h",
      cpu_load: "23",
      free_memory: "123456789",
      total_memory: "268435456",
      free_hdd: "100000000",
      temperature: "41.5",
      voltage: "24.1",
      write_sect_total: "987654",
      ppp_sessions: "7",
      dhcp_leases: "30",
      // absent sensors arrive as the literal string 'null'
      cpu_temperature: "null",
      board_temperature: "null",
      fan1_speed: "null",
      ros_version: "7.18",
      pppoe_running: true,
      ntp_synced: true,
      public_ip: "84.247.33.71",
    };

    const r = await request(port, { method: "POST", path: "/telemetry", token: TOKEN, body });
    assert.equal(r.status, 200, "core chunk with quoted numerics accepted");

    const detail = await store.getDeviceDetail(SERIAL);
    const s = detail.state;
    assert.ok(s, "device_state written");

    // Quoted strings stored as real numbers.
    assert.equal(s.cpu_load, 23);
    assert.equal(typeof s.cpu_load, "number", "cpu_load is a number, not the string '23'");
    assert.equal(s.free_memory, 123456789);
    assert.equal(s.total_memory, 268435456);
    assert.equal(s.free_hdd, 100000000);
    assert.equal(s.temperature, 41.5);
    assert.equal(typeof s.temperature, "number");
    assert.equal(s.voltage, 24.1);
    assert.equal(s.write_sect_total, 987654);
    assert.equal(s.ppp_sessions, 7);
    assert.equal(s.dhcp_leases, 30);

    // 'null' string coerced to a real null (never the string 'null').
    assert.equal(s.cpu_temperature, null);
    assert.equal(s.board_temperature, null);
    assert.equal(s.fan1_speed, null);
  } finally {
    await close(server);
  }
});

test("chunked telemetry: a detail chunk that arrives BEFORE any core chunk still marks the device online", async () => {
  const config = makeConfig();
  const store = makeMemStore();

  const SERIAL = "RB-DETAIL-FIRST";
  const TOKEN = "device-bearer-detail-first";
  const tokenHash = transform.sha256Hex(TOKEN);
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    const r = await request(port, {
      method: "POST",
      path: "/telemetry",
      token: TOKEN,
      body: ifaceChunk({
        serial: SERIAL,
        now: Date.now(),
        interfaces: [
          { name: "ether1", type: "ether", running: true, disabled: false, plugged: true,
            is_wan: true, bridge: "", rx_byte: 10, tx_byte: 20, rx_packet: 1, tx_packet: 2 },
        ],
      }),
    });
    assert.equal(r.status, 200, "detail-first chunk accepted");

    const detail = await store.getDeviceDetail(SERIAL);
    assert.ok(detail.state, "touchDeviceState seeded a minimal device_state row");
    assert.equal(detail.state.status, "online", "detail-first chunk marks device online");
    // No core fields were sent, so the system columns must be absent/null, never invented.
    assert.ok(detail.state.cpu_load == null, "detail-first chunk left cpu_load null");
    assert.equal(detail.interfaces.length, 1, "detail-first chunk upserted its interface");
  } finally {
    await close(server);
  }
});
