// The counter-Pi smartcard fix stack alert (added 2026-08-17 with the NHS smartcard fix).
//
// NHS smartcard login over RDP redirection depends on a libpcsclite shim on the Pi plus one
// exported environment variable on the kiosk process. Both are removable by an apt upgrade, an
// edited launcher or a rebuilt image, and NOTHING else in the stack notices: pcscd still runs,
// the reader is still detected, the RDP session still connects. The only symptom is a
// pharmacist who cannot log in. These tests pin the three behaviours that make the alert
// trustworthy enough to page someone.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");

const RULE = {
  name: "Smartcard stack broken",
  metric: "smartcard_stack_ok",
  comparator: "<",
  threshold: 1,
  severity: "critical",
  notify_email: "noc@wcn",
  notify_on: "both",
};

async function setup() {
  const store = makeMemStore();
  await seedDevice(store, { serial: "PI-RX54554-1", token: "t", site_name: "RX54554" });
  const dev = await store.getDeviceBySerial("PI-RX54554-1");
  return { store, deviceId: dev.id };
}

test("a broken smartcard stack (ok=0) opens a critical alert, and repairing it clears", async () => {
  const { store, deviceId } = await setup();
  await store.upsertDeviceState(deviceId, { status: "online", smartcard_stack_ok: 1 });
  store._test.addAlertRule(RULE);
  const rules = await store.getActiveAlertRules();

  // Intact → silent.
  let res = await store.evaluateAndApplyAlerts(rules);
  assert.equal(res.opened, 0, "an intact stack must not alert");

  // The shim disappears (apt upgrade, image rebuild, hand-edit) → fires.
  await store.upsertDeviceState(deviceId, { status: "online", smartcard_stack_ok: 0 });
  res = await store.evaluateAndApplyAlerts(await store.getActiveAlertRules());
  assert.equal(res.opened, 1, "a broken stack must open exactly one alert");

  // Repaired → clears, so the alert is self-resolving and does not need a human to close it.
  await store.upsertDeviceState(deviceId, { status: "online", smartcard_stack_ok: 1 });
  res = await store.evaluateAndApplyAlerts(await store.getActiveAlertRules());
  assert.equal(res.cleared, 1, "repairing the stack must clear the alert");
});

test("null (no smartcards on this counter, or an older agent) never alerts", async () => {
  // THE important case. Most counters in the estate do not do smartcards, and every agent
  // predating this change reports nothing at all. If null were treated as 0 the fleet would
  // light up red on deploy and the alert would be turned off within the hour — which is how
  // monitoring dies. evaluateAlert() ignores nulls; this test pins that it stays that way.
  const { store, deviceId } = await setup();
  await store.upsertDeviceState(deviceId, { status: "online", smartcard_stack_ok: null });
  store._test.addAlertRule(RULE);

  const res = await store.evaluateAndApplyAlerts(await store.getActiveAlertRules());
  assert.equal(res.opened, 0, "null must never be read as a fault");
});

test("the metric is readable by the postgres store, not just the in-memory one", async () => {
  // The trap this repo sets for itself: store.mem reads s[rule.metric] with no whitelist, so a
  // new metric ALWAYS passes the tests above while silently never firing in production, where
  // store.pg gates every metric through alertMetricColumn(). Asserting on the real module
  // keeps the two stores honest with each other.
  const pg = require("../src/shared/store.pg.js");
  const src = require("node:fs").readFileSync(require.resolve("../src/shared/store.pg.js"), "utf8");
  assert.match(
    src,
    /'smartcard_stack_ok'/,
    "smartcard_stack_ok must be in alertMetricColumn's allowed set in store.pg.js, " +
      "or rules against it save fine and never fire"
  );
  assert.ok(pg, "store.pg.js must still load");
});
