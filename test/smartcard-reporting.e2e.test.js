// The smartcard fix-stack metric must survive the WHOLE path, agent POST -> device_state.
//
// smartcard-stack.test.js already pins the alert logic, and it passed the entire time the
// feature was broken in production. The gap: normalize() in src/shared/telemetry.js is a strict
// ALLOWLIST, and `smartcard_stack` was never added to it. Every field the agent sent was
// discarded before the handler ran, so smartcard_stack_ok was written as null on every single
// tick — the alert could never fire and the thin-client modal could never show a broken shim.
// Nothing failed, nothing logged, and the pilot Pi reported ok:true throughout. (Found
// 2026-08-19, while checking why the column was still null after the agent rollout.)
//
// The same trap had already been hit once before this: see the comment on the `logs:` line in
// normalize(), "the field whose absence from this list disabled log collection entirely".
// Hence the last test here, which is deliberately about the CLASS rather than this one field.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const { createServer } = require("../src/ingest/server");
const telemetry = require("../src/shared/telemetry");
const transform = require("../src/shared/transform");

// Exactly what the pilot Pi reports (agent smartcard_stack(), verified on 00000000b656f925).
const AGENT_REPORT = {
  shim_present: true,
  shim_sha256: "20e97f4443643960f19c2fea72def04511dbbcabce3c991ae5326bdea9b153d1",
  shim_bytes: 71576,
  shim_active: true,
  freerdp_version: "3.30.0",
  smartcard_flag: true,
  ok: true,
};

function makeConfig() {
  process.env.STORE_KIND = "mem";
  process.env.ENROLL_TOKEN = "test-enroll-token";
  process.env.PORT = "0";
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
    const headers = { "content-type": "application/json" };
    if (token) headers["authorization"] = `Bearer ${token}`;
    if (data) headers["content-length"] = String(data.length);
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

const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
const close = (s) => new Promise((r) => s.close(r));

test("normalize() passes smartcard_stack through instead of dropping it", async () => {
  const out = telemetry.normalize({ serial: "PI-SC", smartcard_stack: AGENT_REPORT });
  assert.ok(out.smartcard_stack, "normalize() must not drop smartcard_stack");
  assert.equal(out.smartcard_stack.ok, true);
  assert.equal(out.smartcard_stack.freerdp_version, "3.30.0", "diagnostics must survive too");
});

test("an agent reporting ok:true lands as smartcard_stack_ok = 1 in device_state", async () => {
  // The end-to-end assertion that was missing. It fails on the un-fixed allowlist.
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "PI-SC";
  const TOKEN = "device-bearer-sc";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });

  // The mem store has no device_state getter, so capture what the handler actually writes.
  // That IS the value under test: the production symptom was smartcard_stack_ok arriving null.
  let written = {};
  const realUpsert = store.upsertDeviceState;
  store.upsertDeviceState = async (id, st) => { written = st; return realUpsert.call(store, id, st); };

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // `uptime` (not uptime_s) is a CORE key — device_state is only written for a core chunk.
    const r = await request(port, {
      method: "POST", path: "/telemetry", token: TOKEN,
      body: { serial: SERIAL, uptime: "1d2h3m", smartcard_stack: AGENT_REPORT },
    });
    assert.equal(r.status, 200);

    assert.equal(
      written.smartcard_stack_ok, 1,
      "a healthy stack must persist as 1 — null means the field was dropped somewhere on the path"
    );
  } finally {
    await close(server);
  }
});

test("a broken stack (ok:false) persists as 0, so the alert has something to fire on", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "PI-SC-BROKEN";
  const TOKEN = "device-bearer-sc2";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });

  let written = {};
  const realUpsert = store.upsertDeviceState;
  store.upsertDeviceState = async (id, st) => { written = st; return realUpsert.call(store, id, st); };

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    await request(port, {
      method: "POST", path: "/telemetry", token: TOKEN,
      body: {
        serial: SERIAL, uptime: "1d2h3m",
        // The realistic failure: an apt upgrade replaces libpcsclite and the kiosk no longer
        // exports the shim, so the shim file is still there but is not in the session.
        smartcard_stack: { ...AGENT_REPORT, shim_active: false, ok: false },
      },
    });
    assert.equal(written.smartcard_stack_ok, 0, "a broken stack must persist as 0, not null");
  } finally {
    await close(server);
  }
});

test("every field the handler reads off the payload is present in normalize()'s allowlist", async () => {
  // The CLASS-level guard. normalize() returns an allowlist, so any payload key the handler
  // reads but normalize never copies is silently and permanently null in production, with no
  // error anywhere. That has now happened twice: `logs` once, `smartcard_stack` once.
  const fs = require("node:fs");
  const handlers = fs.readFileSync(require.resolve("../src/ingest/handlers.js"), "utf8");
  const norm = fs.readFileSync(require.resolve("../src/shared/telemetry.js"), "utf8");

  // Only the telemetry ingest function reads `payload.` — scope to it so other handlers'
  // locals cannot produce phantom names.
  const start = handlers.indexOf("async function telemetryIngest(");
  assert.ok(start > -1, "telemetryIngest must exist");
  const body = handlers.slice(start, handlers.indexOf("\nasync function ", start + 10));

  const read = new Set();
  for (const m of body.matchAll(/\bpayload\.([a-z_][a-z0-9_]*)/gi)) read.add(m[1]);
  assert.ok(read.size > 5, "expected to find several payload reads");

  const missing = [...read].filter((k) => !new RegExp(`^\\s*${k}:`, "m").test(norm));
  assert.deepEqual(
    missing, [],
    "these payload fields are read by the handler but are NOT in normalize()'s allowlist, so " +
      "they arrive as undefined on every tick and are stored as null forever: " + missing.join(", ")
  );
});

test("every device_state field the handler sets is actually written by the POSTGRES store", async () => {
  // The third instance of one trap, and the reason the previous two survived review: the
  // in-memory store keeps whatever object it is handed, so a mem-backed test passes even when
  // the pg store never writes the column. smartcard_stack_ok was added to the schema and to
  // alertMetricColumn's whitelist but NOT to upsertDeviceState's INSERT, so in production it
  // stayed null on every tick while all of its unit tests were green.
  //
  // Compare the handler's deviceState literal against the real INSERT column list, so any new
  // field must be wired all the way through or this fails loudly.
  const fs = require("node:fs");
  const handlers = fs.readFileSync(require.resolve("../src/ingest/handlers.js"), "utf8");
  const pg = fs.readFileSync(require.resolve("../src/shared/store.pg.js"), "utf8");

  const start = handlers.indexOf("const deviceState = {");
  assert.ok(start > -1, "the deviceState literal must exist");
  const lit = handlers.slice(start, handlers.indexOf("\n    };", start));
  // Top-level keys only: nested object properties are indented deeper than 6 spaces.
  const keys = [...lit.matchAll(/^ {6}([a-z_][a-z0-9_]*):/gim)].map((m) => m[1]);
  assert.ok(keys.length > 10, "expected many device_state keys, got " + keys.length);

  const ins = pg.indexOf("INSERT INTO device_state");
  const cols = pg.slice(ins, pg.indexOf(")", pg.indexOf("(", ins)));

  // `raw` and `last_seen_at` are handled positionally/by COALESCE but still appear by name.
  const missing = keys.filter((k) => !new RegExp("\\b" + k + "\\b").test(cols));
  assert.deepEqual(
    missing, [],
    "these fields are set by the ingest handler but are NOT columns in upsertDeviceState's " +
      "INSERT, so postgres silently stores nothing for them (mem-store tests will still pass): " +
      missing.join(", ")
  );
});
