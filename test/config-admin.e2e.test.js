// End-to-end test for the OPERATOR side of the review-gated config push: author a draft,
// two-person approve, cancel, and list — over real HTTP against createServer() + the mem store.
// (docs/RUNBOOK-config-push.md §0 two-person rule, §2.1 author, §2.2 approve.)
//
// Non-negotiables exercised here:
//   * a DRAFT is never served to the device (getPendingConfigJob stays null until approved);
//   * the two-person rule rejects approver == author (409);
//   * an APPROVED job IS served to its target device and carries the right checksum descriptor.
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
const listen = (server) =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
const close = (server) => new Promise((resolve) => server.close(resolve));

const RSC = "/system identity set name=canary-test\n";

test("config-push admin flow: author draft -> two-person approve -> served to device", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "RB-CFG-E2E";
  const TOKEN = "device-bearer-cfg";
  const device = await seedDevice(store, {
    serial: SERIAL,
    token: TOKEN,
    tokenHash: transform.sha256Hex(TOKEN),
  });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // admin auth is required
    const noauth = await request(port, { method: "GET", path: `/devices/${SERIAL}/config-jobs` });
    assert.equal(noauth.status, 401, "admin routes reject a missing token");

    // create a DRAFT (author = leo)
    const created = await request(port, {
      method: "POST",
      path: `/devices/${SERIAL}/config-jobs`,
      token: ENROLL_TOKEN,
      body: { created_by: "leo", kind: "snippet", rsc_text: RSC, confirm_window_s: 300 },
    });
    assert.equal(created.status, 201, "draft created");
    const jobId = created.body.job.id;
    assert.equal(created.body.job.status, "draft");
    assert.equal(created.body.job.rsc_sha256, transform.sha256Hex(RSC), "server computes sha256");

    // a draft must NOT be served to the device yet
    assert.equal(await store.getPendingConfigJob(device.id), null, "draft is never served");

    // two-person rule: leo cannot approve leo's own job
    const selfApprove = await request(port, {
      method: "POST",
      path: `/config-jobs/${jobId}/approve`,
      token: ENROLL_TOKEN,
      body: { approved_by: "leo" },
    });
    assert.equal(selfApprove.status, 409, "approver must differ from author");

    // a second operator (jake) approves
    const approved = await request(port, {
      method: "POST",
      path: `/config-jobs/${jobId}/approve`,
      token: ENROLL_TOKEN,
      body: { approved_by: "jake" },
    });
    assert.equal(approved.status, 200, "second-person approval succeeds");
    assert.equal(approved.body.job.status, "approved");
    assert.equal(approved.body.job.approved_by, "jake");

    // now the device IS served the job, with the contract descriptor shape
    const pending = await store.getPendingConfigJob(device.id);
    assert.ok(pending, "approved job is served to its target device");
    assert.equal(pending.id, jobId);
    assert.equal(pending.rsc_sha256, transform.sha256Hex(RSC));

    // double-approve is a no-op (409 — not a draft anymore)
    const reApprove = await request(port, {
      method: "POST",
      path: `/config-jobs/${jobId}/approve`,
      token: ENROLL_TOKEN,
      body: { approved_by: "someone" },
    });
    assert.equal(reApprove.status, 409, "an already-approved job can't be re-approved");

    // the list endpoint shows the job
    const list = await request(port, {
      method: "GET",
      path: `/devices/${SERIAL}/config-jobs`,
      token: ENROLL_TOKEN,
    });
    assert.equal(list.status, 200);
    assert.equal(list.body.jobs.length, 1);
    assert.equal(list.body.jobs[0].id, jobId);
  } finally {
    await close(server);
  }
});

test("config-push admin flow: validation + cancel", async () => {
  const config = makeConfig();
  const store = makeMemStore();
  const SERIAL = "RB-CFG-E2E2";
  const TOKEN = "device-bearer-cfg2";
  await seedDevice(store, { serial: SERIAL, token: TOKEN, tokenHash: transform.sha256Hex(TOKEN) });

  const server = createServer({ store, config });
  const port = await listen(server);
  try {
    // missing rsc_text / created_by -> 400
    const noRsc = await request(port, {
      method: "POST",
      path: `/devices/${SERIAL}/config-jobs`,
      token: ENROLL_TOKEN,
      body: { created_by: "leo", rsc_text: "   " },
    });
    assert.equal(noRsc.status, 400);

    const noAuthor = await request(port, {
      method: "POST",
      path: `/devices/${SERIAL}/config-jobs`,
      token: ENROLL_TOKEN,
      body: { rsc_text: RSC },
    });
    assert.equal(noAuthor.status, 400);

    // confirm window is clamped to a 30s floor
    const created = await request(port, {
      method: "POST",
      path: `/devices/${SERIAL}/config-jobs`,
      token: ENROLL_TOKEN,
      body: { created_by: "leo", rsc_text: RSC, confirm_window_s: 0 },
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.job.confirm_window_s, 30, "confirm window floored at 30s");
    const jobId = created.body.job.id;

    // cancel the draft
    const cancelled = await request(port, {
      method: "POST",
      path: `/config-jobs/${jobId}/cancel`,
      token: ENROLL_TOKEN,
      body: { actor: "leo" },
    });
    assert.equal(cancelled.status, 200);
    assert.equal(cancelled.body.job.status, "cancelled");

    // cancelling again -> 409 (not draft/approved anymore)
    const again = await request(port, {
      method: "POST",
      path: `/config-jobs/${jobId}/cancel`,
      token: ENROLL_TOKEN,
    });
    assert.equal(again.status, 409);

    // unknown device -> 404
    const unknown = await request(port, {
      method: "GET",
      path: `/devices/NO-SUCH-SERIAL/config-jobs`,
      token: ENROLL_TOKEN,
    });
    assert.equal(unknown.status, 404);
  } finally {
    await close(server);
  }
});
