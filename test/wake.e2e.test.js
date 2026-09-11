// End-to-end test for the wake channel: GET /devices/:serial/wake, the reverse channel that
// makes an operator's click land on a thin client NOW instead of on its next telemetry tick.
//
// What matters here and is therefore asserted:
//   * it AUTHENTICATES as a device, and a valid token for one device cannot watch another;
//   * it answers 200 the moment wake_seq has moved past the caller's seq — including a wake
//     that happened while the agent was away, which is the whole reason it is a counter and
//     not a bare signal;
//   * it HOLDS the connection open when there is nothing to say, rather than returning at
//     once and turning the agent into a hot loop;
//   * once answered it does not re-fire for the same seq.
//
// The hold is 25s in production, so the "it holds" case is asserted by proving the request is
// still pending after a beat and then abandoning it — waiting the full window out would make
// the suite unusable for a fact that is already established at 600ms.
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

// Like the other e2e tests' helper, but it also hands back the underlying request so a held
// poll can be abandoned instead of waited out.
function start(port, { method, path, token }) {
  const headers = {};
  if (token) headers["authorization"] = `Bearer ${token}`;
  let settle;
  const done = new Promise((resolve, reject) => {
    settle = { resolve, reject };
  });
  const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
    let buf = "";
    res.on("data", (c) => (buf += c));
    res.on("end", () => {
      let parsed = null;
      try { parsed = buf ? JSON.parse(buf) : null; } catch { parsed = buf; }
      settle.resolve({ status: res.statusCode, body: parsed, headers: res.headers });
    });
  });
  req.on("error", (e) => settle.reject(e));
  req.end();
  return { req, done };
}

function request(port, opts) {
  return start(port, opts).done;
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}
function close(server) {
  return new Promise((resolve) => server.close(resolve));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SERIAL = "0000000051f911a7";      // a real counter-Pi serial shape
const TOKEN = "device-bearer-wake-1";
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

test("wake: unauthenticated is refused, and a device cannot watch another device", async () => {
  const { server, port } = await harness();
  try {
    const anon = await request(port, { method: "GET", path: `/devices/${SERIAL}/wake?seq=0` });
    assert.equal(anon.status, 401, "no bearer must be 401");

    // The URL names one serial, the bearer names another. The bearer wins and the answer is a
    // refusal — otherwise any enrolled Pi could watch any other counter's wakes.
    const crossed = await request(port, {
      method: "GET", path: `/devices/${OTHER_SERIAL}/wake?seq=0`, token: TOKEN,
    });
    assert.equal(crossed.status, 403, "a token for device A must not watch device B");
  } finally {
    await close(server);
  }
});

test("wake: answers 200 as soon as wake_seq is ahead, including a wake missed while away", async () => {
  const { store, server, port, device } = await harness();
  try {
    // A wake that fired while the agent was NOT polling. This is the case a bare signal would
    // have dropped on the floor, leaving the operator waiting for the next ordinary tick.
    const seq = await store.bumpDeviceWake(device.id);
    assert.equal(seq, 1, "first bump is 1");

    const started = Date.now();
    const r = await request(port, { method: "GET", path: `/devices/${SERIAL}/wake?seq=0`, token: TOKEN });
    assert.equal(r.status, 200);
    assert.equal(r.body.seq, 1, "the reply carries the seq the agent should remember");
    assert.ok(Date.now() - started < 2000, "a pending wake must answer at once, not after the hold");
  } finally {
    await close(server);
  }
});

test("wake: holds the connection open when nothing has happened, and does not re-fire a seq already seen", async () => {
  const { store, server, port, device } = await harness();
  try {
    await store.bumpDeviceWake(device.id);          // seq is now 1

    // The agent has already acted on seq 1, so polling with seq=1 must NOT return — that is
    // what stops one click from being delivered forever.
    const held = start(port, { method: "GET", path: `/devices/${SERIAL}/wake?seq=1`, token: TOKEN });
    let settled = false;
    held.done.then(() => { settled = true; }).catch(() => { settled = true; });

    await sleep(600);
    assert.equal(settled, false, "with nothing new, the poll must be held open, not answered");

    // …and the moment something DOES happen, the same held request answers.
    await store.bumpDeviceWake(device.id);          // seq is now 2
    const r = await held.done;
    assert.equal(r.status, 200);
    assert.equal(r.body.seq, 2, "the held poll picks up the new seq");
  } finally {
    await close(server);
  }
});

test("wake: a junk or missing seq is treated as no history rather than refused", async () => {
  const { store, server, port, device } = await harness();
  try {
    await store.bumpDeviceWake(device.id);
    // A freshly installed agent has no stored seq. Refusing it with a 400 would leave that Pi
    // unwakeable until its first wake, which is exactly backwards.
    const r = await request(port, { method: "GET", path: `/devices/${SERIAL}/wake?seq=banana`, token: TOKEN });
    assert.equal(r.status, 200);
    assert.equal(r.body.seq, 1);
  } finally {
    await close(server);
  }
});
