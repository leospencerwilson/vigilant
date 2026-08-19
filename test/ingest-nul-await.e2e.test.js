// Two regressions that together made a HEALTHY counter Pi read as "agent last seen 7 min ago"
// while its agent, its network and the ingest were all fine. (Diagnosed 2026-08-19.)
//
//   1. A NUL byte in a shipped kiosk log line. Postgres rejects a NUL in `text` and a \u0000
//      escape in `jsonb`, so one control byte anywhere in the batch failed the ENTIRE telemetry
//      write — device_state.raw, recent_logs and last_seen_at included, not merely the log
//      insert. FreeRDP writes raw control bytes into /var/log/wcn-kiosk.log (29,845 such lines
//      on the pilot), so this fired whenever the tail window happened to land on one:
//      intermittent, and the reason three earlier diagnoses went the wrong way.
//
//   2. The server dispatched handlers as `return handlers.x(ctx)` inside its top-level
//      try/catch. Returning a promise from a try block does NOT await it, so a rejecting
//      handler bypassed the catch, became an unhandledRejection, and left the request with no
//      response at all — the client hung until its own timeout. The "fail safe: one bad request
//      must never 500-cascade" catch had therefore never once run for an async handler.
//
// Fault 2 is why fault 1 was so hard to see: a plain 500 would have named the postgres error on
// the first attempt. These are e2e over real HTTP because that is the only place the difference
// between "500" and "no reply at all" is observable.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const { createServer } = require("../src/ingest/server");
const transform = require("../src/shared/transform");

const NUL = "\u0000";

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

// Deliberately NOT reusing ingest.e2e.test.js's helper: this one must tell "the server replied"
// apart from "the server never replied", so it imposes its own timeout and says which happened.
function request(port, { method, path, token, body, timeoutMs = 4000 }) {
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
        try { parsed = buf ? JSON.parse(buf) : null; } catch { parsed = buf; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error("NO RESPONSE: the server never answered — this is the hang under test"));
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
const close = (s) => new Promise((r) => s.close(r));

async function seeded(store) {
  const SERIAL = "PI-NUL-TEST";
  const TOKEN = "device-bearer-nul";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });
  return { SERIAL, TOKEN };
}

test("a log line containing a NUL byte is accepted, with the NUL stripped", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const { SERIAL, TOKEN } = await seeded(store);
  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    const r = await request(port, {
      method: "POST", path: "/telemetry", token: TOKEN,
      body: {
        serial: SERIAL,
        // Exactly the shape FreeRDP leaves in the kiosk log: readable text either side of a raw
        // control byte. Before the boundary strip, this failed the whole write in postgres.
        logs: [{ time: "", topics: "kiosk", message: "rdp: reader" + NUL + " attached" }],
      },
    });
    assert.equal(r.status, 200, "a NUL in a log line must not fail the telemetry write");

    const dev = await store.getDeviceBySerial(SERIAL);
    const st = typeof store.getDeviceState === "function" ? await store.getDeviceState(dev.id) : null;
    const logs = st && st.recent_logs;
    if (Array.isArray(logs) && logs.length) {
      const msg = String(logs[0].message == null ? "" : logs[0].message);
      assert.ok(msg.indexOf(NUL) === -1, "the stored line must carry no NUL");
      assert.match(msg, /reader attached/, "the surrounding text must survive intact");
    }
  } finally {
    await close(server);
  }
});

test("a handler that rejects still ANSWERS the request (500) rather than hanging it", async () => {
  // THE important one. Without `return await` in the dispatch this test does not fail with a
  // wrong status — it fails by never resolving, which is exactly how the live bug behaved.
  const config = makeConfig();
  const store = makeMemStore();
  const { SERIAL, TOKEN } = await seeded(store);

  // upsertInterfaceStates, not upsertDeviceState: the latter runs only for a CORE chunk, so
  // injecting there passes vacuously (MEASURED: the request 200s without ever calling it).
  store.upsertInterfaceStates = async () => {
    throw new Error("unsupported Unicode escape sequence"); // the real postgres error
  };

  const server = createServer({ store, config });
  const port = await listen(server);

  try {
    const r = await request(port, {
      method: "POST", path: "/telemetry", token: TOKEN,
      body: { serial: SERIAL, uptime_s: 1 },
    });
    assert.equal(r.status, 500, "a failing store must produce a 500, never silence");
  } finally {
    await close(server);
  }
});

test("every handler dispatch is awaited, so the fail-safe catch can actually run", async () => {
  // Source-level assertion: the test above covers only the one route it exercises, but the
  // defect was uniform across all 79 dispatch sites. A new route added as `return handlers.x`
  // reintroduces the hang on that route alone, which is near-undetectable in production.
  const src = require("node:fs").readFileSync(require.resolve("../src/ingest/server.js"), "utf8");
  // Strip line comments first: server.js documents this very rule by quoting the bad form, and
  // a scan that counted prose would fail forever and get deleted rather than fixed.
  const code = src.replace(/^\s*\/\/.*$/gm, "");
  const bare = (code.match(/return handlers\./g) || []).length;
  assert.equal(
    bare, 0,
    bare + " dispatch site(s) use 'return handlers.x(ctx)'. Use 'return await handlers.x(ctx)': " +
      "without the await a rejecting handler skips the try/catch and the client gets no response."
  );
});
