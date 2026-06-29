// Alert evaluation — neighbour-drop (e.g. a Yealink phone) + that evaluateAndApplyAlerts
// returns notify-ready transitions. Runs against the in-memory store.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeMemStore, seedDevice } = require("../src/shared/store.mem");

async function setup() {
  const store = makeMemStore();
  await seedDevice(store, { serial: "NB-1", token: "t", site_name: "Allied Old Swan" });
  const dev = await store.getDeviceBySerial("NB-1");
  await store.upsertDeviceState(dev.id, { status: "online" }); // so the device is evaluated
  return { store, deviceId: dev.id };
}

test("neighbor_down: a Yealink not seen for > threshold opens an alert; reappearing clears it", async () => {
  const { store, deviceId } = await setup();

  // A Yealink neighbour, last seen just now.
  await store.upsertNeighbors(deviceId, [
    { interface: "ether3", mac: "AA:BB:CC:00:00:01", identity: "phone-1", platform: "Yealink" },
  ]);
  store._test.addAlertRule({
    name: "Phone offline", metric: "neighbor_down", comparator: ">=", threshold: 120,
    neighbor_platform: "Yealink", severity: "warning",
    notify_email: "noc@wcn", notify_on: "both",
  });

  const rules = await store.getActiveAlertRules();

  // Fresh → not firing.
  let res = await store.evaluateAndApplyAlerts(rules);
  assert.equal(res.opened, 0, "fresh neighbour does not fire");

  // Backdate last_seen_at to 10 minutes ago → "dropped".
  const nmap = store._test._tables.neighbors.get(deviceId);
  for (const row of nmap.values()) row.last_seen_at = new Date(Date.now() - 600 * 1000).toISOString();

  res = await store.evaluateAndApplyAlerts(rules);
  assert.equal(res.opened, 1, "stale Yealink opens an alert");
  const t = res.transitions.find((x) => x.kind === "open");
  assert.ok(t, "open transition emitted");
  assert.equal(t.rule.metric, "neighbor_down");
  assert.equal(t.site_name, "Allied Old Swan", "transition carries the site for the notification");
  assert.match(t.detail, /phone-1/, "detail names the dropped phone");
  assert.equal(t.rule.notify_email, "noc@wcn", "rule carries its notify target");

  // Same eval again → already open, no duplicate.
  res = await store.evaluateAndApplyAlerts(rules);
  assert.equal(res.opened, 0, "no duplicate open while still down");

  // Phone reappears (fresh last_seen) → clears.
  await store.upsertNeighbors(deviceId, [
    { interface: "ether3", mac: "AA:BB:CC:00:00:01", identity: "phone-1", platform: "Yealink" },
  ]);
  res = await store.evaluateAndApplyAlerts(rules);
  assert.equal(res.cleared, 1, "reappearing neighbour clears the alert");
  assert.ok(res.transitions.some((x) => x.kind === "clear"));
});

test("neighbor_down: platform filter ignores non-matching neighbours", async () => {
  const { store, deviceId } = await setup();
  await store.upsertNeighbors(deviceId, [
    { interface: "ether2", mac: "AA:BB:CC:00:00:09", identity: "some-switch", platform: "MikroTik" },
  ]);
  const nmap = store._test._tables.neighbors.get(deviceId);
  for (const row of nmap.values()) row.last_seen_at = new Date(Date.now() - 600 * 1000).toISOString();

  store._test.addAlertRule({ name: "Phone offline", metric: "neighbor_down", threshold: 120, comparator: ">=", neighbor_platform: "Yealink" });
  const res = await store.evaluateAndApplyAlerts(await store.getActiveAlertRules());
  assert.equal(res.opened, 0, "a stale non-Yealink neighbour does not trip a Yealink rule");
});
