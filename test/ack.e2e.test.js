// End-to-end test for the woken acknowledgement: POST /devices/:serial/ack.
//
// WHY THIS ROUTE EXISTS. The wake channel carries an operator's click TO a thin client in
// milliseconds, and the agent acts on it at once. But Watchman does not open the viewer until
// the DEVICE confirms the session is up, and that confirmation used to ride the next telemetry
// tick — which on a Pi 3 means building a full ~10s payload first. So the outbound leg was
// instant while the round trip was not. This route is the confirmation, and nothing else.
//
// What matters here and is therefore asserted:
//   * it AUTHENTICATES as a device, and a token for one device cannot speak for another;
//   * ⭐ it MERGES into device_state.raw and cannot blank what the last real tick stored. This
//     is the whole reason it is not just a small /telemetry POST: that path writes raw
//     wholesale, so a partial payload sent there would erase logs, printers and wifi;
//   * it accepts ONLY the whitelisted keys, so one counter's payload cannot set arbitrary raw
//     keys that the UI and the alert rules read;
//   * junk is a 400 and an oversized body is a 413, neither a 500;
//   * a device that has never reported is applied:false, not an error and not a fabricated row.
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

// POST helper. `rawBody` lets a test send text that is deliberately not JSON, and
// `contentLength` lets one claim a size without actually sending it — which is how the 413
// guard is reached, since it reads the header rather than buffering first.
function request(port, { method, path, token, body, rawBody, contentLength }) {
  const payload = rawBody !== undefined ? rawBody : (body !== undefined ? JSON.stringify(body) : "");
  const headers = { "content-type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  headers["content-length"] = contentLength !== undefined
    ? String(contentLength)
    : String(Buffer.byteLength(payload));
  return new Promise((resolve, reject) => {
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
    if (contentLength !== undefined) req.end(); else req.end(payload);
  });
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}
function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

const SERIAL = "0000000051f911a7";
const TOKEN = "device-bearer-ack-1";
const OTHER_SERIAL = "00000000510fe240";

async function harness() {
  const config = makeConfig();
  const store = makeMemStore();
  const device = await seedDevice(store, { serial: SERIAL, tokenHash: transform.sha256Hex(TOKEN) });
  const other = await seedDevice(store, { serial: OTHER_SERIAL, tokenHash: transform.sha256Hex("other-token") });
  const server = createServer({ store, config });
  const port = await listen(server);
  return { store, server, port, device, other };
}

const LIVE = { active: true, port: 5900, expires_in_s: 900, password: "s3cret" };

test("ack: unauthenticated is refused, and a device cannot speak for another device", async () => {
  const { server, port } = await harness();
  try {
    const anon = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, body: { support_vnc: LIVE },
    });
    assert.equal(anon.status, 401, "no bearer must be 401");

    const crossed = await request(port, {
      method: "POST", path: `/devices/${OTHER_SERIAL}/ack`, token: TOKEN, body: { support_vnc: LIVE },
    });
    assert.equal(crossed.status, 403, "a token for device A must not ack for device B");
  } finally {
    await close(server);
  }
});

test("ack: MERGES into raw and cannot blank what the last telemetry tick stored", async () => {
  const { store, server, port, device } = await harness();
  try {
    // A full tick, as the agent would have sent it before anyone clicked anything.
    await store.upsertDeviceState(device.id, {
      status: "online",
      uptime_s: 1667,
      raw: {
        logs: ["kiosk: connected"],
        printers: [{ name: "ZD421" }],
        wifi_link: { connected: true },
        support_vnc: { active: false },
      },
    });

    const r = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN,
      body: { support_vnc: LIVE, wake: { running: true, seq: 9, woken: 8, last_status: 204 } },
    });
    assert.equal(r.status, 200);
    assert.equal(r.body.ok, true);
    assert.equal(r.body.applied, true);

    const after = (await store.getDeviceDetail(SERIAL)).state.raw.support_vnc;
    assert.equal(after.active, true, "the session the operator is waiting for must be visible");
    assert.equal(after.password, "s3cret", "the per-session secret rides the ack, as on a tick");

    // ⭐ THE POINT OF THE WHOLE ROUTE. Everything the last real tick stored is still there.
    const st = (await store.getDeviceDetail(SERIAL)).state;
    const raw = st.raw;
    assert.deepEqual(raw.logs, ["kiosk: connected"], "logs must survive an ack");
    assert.deepEqual(raw.printers, [{ name: "ZD421" }], "printers must survive an ack");
    assert.deepEqual(raw.wifi_link, { connected: true }, "wifi must survive an ack");
    assert.equal(raw.wake.woken, 8, "the wake block is merged too");
    // And the readings columns are untouched — an ack carries none, and must not null them.
    assert.equal(st.uptime_s, 1667, "an ack must not null the readings columns");
  } finally {
    await close(server);
  }
});

test("ack: accepts only the whitelisted keys", async () => {
  const { store, server, port, device } = await harness();
  try {
    await store.upsertDeviceState(device.id, { status: "online", raw: { logs: ["a"] } });
    const r = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN,
      // smartcard_stack and logs are real raw keys the UI and the alert rules read. A device
      // must not be able to set them here, where nothing validates them.
      body: { support_vnc: LIVE, logs: ["forged"], smartcard_stack: { ok: false }, nonsense: 1 },
    });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.keys, ["support_vnc"], "only whitelisted keys are merged");

    const st = (await store.getDeviceDetail(SERIAL)).state;
    assert.deepEqual(st.raw.logs, ["a"], "a forged key must not overwrite the stored one");
    assert.equal(st.raw.smartcard_stack, undefined, "a non-whitelisted key is not written");
    assert.equal(st.raw.nonsense, undefined, "unknown keys are dropped, not stored");
  } finally {
    await close(server);
  }
});

test("ack: junk is a 400, an empty ack is a no-op, and an oversized body is a 413", async () => {
  const { store, server, port, device } = await harness();
  try {
    await store.upsertDeviceState(device.id, { status: "online", raw: {} });

    const junk = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN, rawBody: "{not json",
    });
    assert.equal(junk.status, 400, "malformed json must be a 400, never a 500");

    // A wake for something other than a session has nothing to acknowledge. That is not a
    // failure and the agent must not be taught to retry it.
    const empty = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN, body: {},
    });
    assert.equal(empty.status, 200);
    assert.equal(empty.body.applied, false);

    const big = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN, contentLength: 9999,
    });
    assert.equal(big.status, 413, "an ack is tens of bytes; anything large is refused unread");
  } finally {
    await close(server);
  }
});

test("ack: a device that has never reported is applied:false, not a fabricated row", async () => {
  const { store, server, port, device } = await harness();
  try {
    const r = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/ack`, token: TOKEN, body: { support_vnc: LIVE },
    });
    assert.equal(r.status, 200, "this is an answer, not an error");
    assert.equal(r.body.applied, false, "nothing to merge into yet");

    const st = (await store.getDeviceDetail(SERIAL)).state;
    assert.ok(!st || !st.status, "an ack must not invent an online device out of an empty snapshot");
  } finally {
    await close(server);
  }
});
