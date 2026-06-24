// Tests for the review-gated config-push lifecycle against the in-memory Store.
// (docs/CONTRACT.md §Store interface + §Config push; db/schema.sql config_jobs.)
//
// Non-negotiable: a job is only ever served when status='approved' AND it targets the
// device (by device_id or its tag); checksum must match rsc_text; result transitions
// status to applied / rolled_back.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");
const transform = require("../src/shared/transform");

const RSC = "/system identity set name=canary-test\n";
const SHA = transform.sha256Hex(RSC);

// Seed a config job into the mem store. The mem store mirrors seedDevice with a
// seedConfigJob helper for tests; fall back to a generic create if exposed.
async function seedJob(store, fields) {
  if (typeof store.seedConfigJob === "function") return store.seedConfigJob(fields);
  if (typeof store.createConfigJob === "function") return store.createConfigJob(fields);
  throw new Error("mem store must expose seedConfigJob() (or createConfigJob()) for tests");
}

test("getPendingConfigJob: returns a job only when status='approved' and targeted", async () => {
  const store = makeMemStore();
  const dev = await seedDevice(store, { serial: "RB-CFG-1", token: "tok-cfg-1" });

  // A draft job for this device must NOT be served.
  await seedJob(store, {
    device_id: dev.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "draft",
    confirm_window_s: 300,
    created_by: "leo",
  });
  assert.equal(await store.getPendingConfigJob(dev.id), null, "draft is not served");

  // Approve it -> now served, with the contract descriptor shape.
  const approved = await seedJob(store, {
    device_id: dev.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "approved",
    confirm_window_s: 300,
    created_by: "leo",
    approved_by: "jake",
  });
  const pending = await store.getPendingConfigJob(dev.id);
  assert.ok(pending, "approved job is served");
  assert.equal(pending.id, approved.id);
  assert.equal(pending.rsc_sha256, SHA);
  assert.equal(pending.confirm_window_s, 300);
});

test("getPendingConfigJob: not served to a non-targeted device", async () => {
  const store = makeMemStore();
  const devA = await seedDevice(store, { serial: "RB-CFG-A", token: "tok-a" });
  const devB = await seedDevice(store, { serial: "RB-CFG-B", token: "tok-b" });

  await seedJob(store, {
    device_id: devA.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "approved",
    confirm_window_s: 300,
    created_by: "leo",
  });

  assert.ok(await store.getPendingConfigJob(devA.id), "served to target");
  assert.equal(await store.getPendingConfigJob(devB.id), null, "not served to other device");
});

test("getConfigJobForFetch: verifies the job targets this device; checksum matches rsc_text", async () => {
  const store = makeMemStore();
  const devA = await seedDevice(store, { serial: "RB-CFG-FETCH", token: "tok-f" });
  const devB = await seedDevice(store, { serial: "RB-CFG-OTHER", token: "tok-o" });

  const job = await seedJob(store, {
    device_id: devA.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "approved",
    confirm_window_s: 300,
    created_by: "leo",
  });

  const fetched = await store.getConfigJobForFetch(job.id, devA.id);
  assert.ok(fetched, "fetch returns the job for the targeted device");
  assert.equal(fetched.rsc_text, RSC);
  assert.equal(fetched.rsc_sha256, SHA);
  // checksum the server computes over rsc_text matches the stored sha256
  assert.equal(transform.sha256Hex(fetched.rsc_text), fetched.rsc_sha256);

  // wrong device must not be able to fetch it
  assert.equal(await store.getConfigJobForFetch(job.id, devB.id), null);
});

test("recordConfigResult: transitions status to 'applied'", async () => {
  const store = makeMemStore();
  const dev = await seedDevice(store, { serial: "RB-CFG-APPLIED", token: "tok-ap" });
  const job = await seedJob(store, {
    device_id: dev.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "approved",
    confirm_window_s: 300,
    created_by: "leo",
  });

  await store.recordConfigResult(job.id, "applied", "import ok; confirmed healthy", "/export post\n");

  // The job must now report status 'applied'. getPendingConfigJob no longer serves it.
  assert.equal(await store.getPendingConfigJob(dev.id), null, "applied job is no longer pending");
});

test("recordConfigResult: transitions status to 'rolled_back' (dead-man's switch fired)", async () => {
  const store = makeMemStore();
  const dev = await seedDevice(store, { serial: "RB-CFG-ROLLBACK", token: "tok-rb" });
  const job = await seedJob(store, {
    device_id: dev.id,
    kind: "snippet",
    rsc_text: RSC,
    rsc_sha256: SHA,
    status: "approved",
    confirm_window_s: 300,
    created_by: "leo",
  });

  await store.recordConfigResult(job.id, "rolled_back", "no confirm within window; reverted");

  assert.equal(
    await store.getPendingConfigJob(dev.id),
    null,
    "rolled_back job is no longer pending",
  );
});
