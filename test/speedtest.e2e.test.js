// End-to-end test for the server-timed active speedtest, over real HTTP against
// createServer() + the mem store. Exercises: admin requests a test -> device pulls it
// (marked running) -> device downloads /speedtest/down and uploads /speedtest/up -> server
// times both legs and records down_bps/up_bps + status 'done'. Ownership is enforced
// (a device can't touch another device's job).
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
  const cfgPath = require.resolve("../src/shared/config");
  delete require.cache[cfgPath];
  const mod = require("../src/shared/config");
  if (typeof mod === "function") return mod();
  if (typeof mod.loadConfig === "function") return mod.loadConfig();
  return mod.config || mod;
}

// JSON request helper (parsed body).
function request(port, { method, path, token, body }) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(JSON.stringify(body));
    const headers = {};
    if (token) headers["authorization"] = `Bearer ${token}`;
    if (data) { headers["content-type"] = "application/json"; headers["content-length"] = String(data.length); }
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let buf = ""; res.on("data", (c) => (buf += c));
      res.on("end", () => { let p=null; try{p=buf?JSON.parse(buf):null;}catch{p=buf;} resolve({ status: res.statusCode, body: p }); });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

// Raw GET that drains the (binary) body and returns the byte count.
function getBytes(port, path, token) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method: "GET", path, headers: { authorization: `Bearer ${token}` } }, (res) => {
      let n = 0; res.on("data", (c) => (n += c.length)); res.on("end", () => resolve({ status: res.statusCode, bytes: n }));
    });
    req.on("error", reject); req.end();
  });
}

// POST `bytes` of zeros to `path`, return the parsed JSON ack.
function postBytes(port, path, token, bytes) {
  return new Promise((resolve, reject) => {
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/octet-stream", "content-length": String(bytes) };
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path, headers }, (res) => {
      let buf = ""; res.on("data", (c) => (buf += c)); res.on("end", () => { let p=null; try{p=JSON.parse(buf);}catch{} resolve({ status: res.statusCode, body: p }); });
    });
    req.on("error", reject);
    const chunk = Buffer.alloc(64 * 1024);
    let sent = 0;
    const pump = () => { while (sent < bytes) { const len = Math.min(chunk.length, bytes - sent); sent += len; if (!req.write(len === chunk.length ? chunk : chunk.subarray(0, len))) { req.once("drain", pump); return; } } req.end(); };
    pump();
  });
}

const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
const close = (s) => new Promise((r) => s.close(r));

test("speedtest: request -> pull -> download + upload -> server records bps + done", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "RB-SPEED-1", TOKEN = "dev-speed-1";
  const device = await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // admin requests a small test (1 MiB each way to keep the test quick)
    const created = await request(port, {
      method: "POST", path: `/devices/${SERIAL}/speedtests`, token: ENROLL_TOKEN,
      body: { requested_by: "leo", bytes_down: 1048576, bytes_up: 1048576 },
    });
    assert.equal(created.status, 201);
    const jobId = created.body.job.id;
    assert.equal(created.body.job.status, "pending");

    // device pulls it -> marked running, descriptor returned
    const pending = await request(port, { method: "GET", path: "/speedtest/pending", token: TOKEN });
    assert.equal(pending.status, 200);
    assert.ok(pending.body.job, "a job is offered");
    assert.equal(pending.body.job.id, jobId);
    assert.equal((await store.getSpeedtestJob(jobId)).status, "running");
    // pulling again offers nothing (no longer pending)
    const pending2 = await request(port, { method: "GET", path: "/speedtest/pending", token: TOKEN });
    assert.equal(pending2.body.job, undefined);

    // download leg: drain exactly bytes_down bytes
    const dl = await getBytes(port, `/speedtest/down?job=${jobId}&bytes=1048576`, TOKEN);
    assert.equal(dl.status, 200);
    assert.equal(dl.bytes, 1048576, "server streamed the requested byte count");

    // upload leg: POST bytes_up; server times it, records up_bps, marks done
    const ul = await postBytes(port, `/speedtest/up?job=${jobId}`, TOKEN, 1048576);
    assert.equal(ul.status, 200);
    assert.equal(ul.body.bytes, 1048576);

    const done = await store.getSpeedtestJob(jobId);
    assert.equal(done.status, "done");
    assert.ok(done.down_bps == null || done.down_bps >= 0, "down_bps recorded (>=0 or null on sub-ms)");
    assert.ok(done.up_bps == null || done.up_bps >= 0, "up_bps recorded");
    // at least one leg should have produced a positive measurement over 1 MiB
    assert.ok((done.down_bps || 0) > 0 || (done.up_bps || 0) > 0, "a positive throughput was measured");

    // it shows up in the admin list
    const list = await request(port, { method: "GET", path: `/devices/${SERIAL}/speedtests`, token: ENROLL_TOKEN });
    assert.equal(list.status, 200);
    assert.equal(list.body.jobs[0].id, jobId);
  } finally {
    await close(server);
  }
});

test("speedtest: a device cannot touch another device's job; validation", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const A = await seedDevice(store, { serial: "RB-SPEED-A", token: "tok-a", tokenHash: transform.sha256Hex("tok-a") });
  await seedDevice(store, { serial: "RB-SPEED-B", token: "tok-b", tokenHash: transform.sha256Hex("tok-b") });
  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // requested_by required
    const bad = await request(port, { method: "POST", path: `/devices/RB-SPEED-A/speedtests`, token: ENROLL_TOKEN, body: {} });
    assert.equal(bad.status, 400);

    const created = await request(port, { method: "POST", path: `/devices/RB-SPEED-A/speedtests`, token: ENROLL_TOKEN, body: { requested_by: "leo", bytes_down: 1048576, bytes_up: 0 } });
    const jobId = created.body.job.id;

    // device B must not be able to download device A's job
    const stolen = await getBytes(port, `/speedtest/down?job=${jobId}&bytes=1048576`, "tok-b");
    assert.equal(stolen.status, 404, "wrong device is refused");

    // unknown device -> 404 on create
    const nodev = await request(port, { method: "POST", path: `/devices/NOPE/speedtests`, token: ENROLL_TOKEN, body: { requested_by: "leo" } });
    assert.equal(nodev.status, 404);
  } finally {
    await close(server);
  }
});
