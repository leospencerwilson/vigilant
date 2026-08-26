// Every statement the printer, lifecycle and node-capacity store paths issue, RENDERED, with
// its placeholders counted against the values actually bound.
//
// ⛔ WHY THIS EXISTS AS A TEST RATHER THAN AS A ONE-OFF CHECK. An INSERT whose $n list and
// bound array disagree has shipped twice in store.pg.js, and both times it was a column added
// to one side only. Postgres catches it — at runtime, on the write, in production — and every
// one of these paths writes on behalf of a live pharmacy. Counting them by eye is exactly the
// review that missed it twice.
//
// The store is driven against a RECORDING pool: no database, no schema, no fixtures. What is
// asserted is a property of the SQL text and the argument array, which is all that bug ever
// was. Behaviour against real tables belongs in an integration run against a real Postgres.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");

const { makePgStore } = require("../src/shared/store.pg");
const printerQueues = require("../src/shared/printerQueues");

const DEVICE = "11111111-2222-3333-4444-555555555555";

// Answers shaped just enough for each path to keep going. A path that stops early would
// silently test nothing, so the count of rendered statements is asserted at the end too.
function reply(text) {
  const t = String(text);
  if (/FROM counters WHERE id = \$1 AND pharmacy_id/.test(t)) return { rows: [{ id: 7 }] };
  if (/FROM counters WHERE id = \$1/.test(t)) return { rows: [{ id: 7, pharmacy_id: 3 }] };
  if (/FROM counters WHERE pi_device_id/.test(t)) return { rows: [{ id: 7, pharmacy_id: 3 }] };
  if (/FROM pmr_printer_devices/.test(t)) return { rows: [{ id: 11 }] };
  if (/FROM pmr_printer_queues WHERE id/.test(t)) return { rows: [{ id: 5, pharmacy_id: 3 }] };
  if (/DELETE FROM pmr_printer_queues/.test(t)) {
    return { rows: [{ id: 5, pharmacy_id: 3, counter_id: 7, queue: "Label" }] };
  }
  if (/pmr_counter_printer_table_v/.test(t)) {
    return { rows: [{ counter_id: 7, host_counter_id: 7, queue: "Label", driver: "ZDesigner", flags: ["default"] }] };
  }
  return { rows: [{ id: 1, vmids: [305] }] };
}

function recordingStore() {
  const seen = [];
  const note = (text, params) => {
    const t = String(text);
    // BEGIN/COMMIT/ROLLBACK carry no parameters and are not interesting here.
    if (/^\s*(BEGIN|COMMIT|ROLLBACK)\s*$/i.test(t)) return;
    const nums = [...t.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]));
    seen.push({
      max: nums.length ? Math.max(...nums) : 0,
      bound: Array.isArray(params) ? params.length : 0,
      // The VALUES themselves, not just how many. Some of these paths have a rule about WHAT is
      // bound — a NULL that must not become an empty array — and the count cannot see it.
      params: Array.isArray(params) ? params : [],
      sql: t.replace(/\s+/g, " ").trim().slice(0, 120),
    });
  };
  const client = {
    query: async (text, params) => { note(text, params); return reply(text); },
    release() {},
  };
  const pool = {
    query: async (text, params) => { note(text, params); return reply(text); },
    connect: async () => client,
  };
  return { store: makePgStore(pool), seen };
}

const checkSite = (counterId, lines) =>
  printerQueues.validatePrinterTable(lines, `counter ${counterId}`);

test("every printer/lifecycle/capacity statement binds exactly as many values as it names", async () => {
  const { store, seen } = recordingStore();

  // The telemetry-side write (§3), including the multi-row bulk insert — which is where the
  // count is least obvious, because the tuple width and the row array have to agree.
  await store.reportCounterPrinters(DEVICE, [
    { usb_path: "1-1.3", usable_serial: "ZD421-77J", serial: "ZD421-77J", manufacturer: "Zebra", product: "ZD421", status: "attached, no queue" },
    { usb_path: "1-1.4", usable_serial: null, serial: "000000", status: "unknown" },
  ]);
  await store.listPrinterDevices(3);
  await store.listPrinterDevices(null);

  // The queue table (§1/§2): the read, the INSERT arm and the UPDATE arm.
  await store.listPrinterQueues(3);
  await store.listPrinterQueues(null);
  await store.upsertPrinterQueue({
    pharmacy_id: 3, counter_id: 7, queue: "Label", driver: "ZDesigner ZD420-203dpi ZPL",
    flags: ["default"], device_serial: "ZD421-77J", by: "leo",
  }, checkSite);
  await store.upsertPrinterQueue({
    id: 5, pharmacy_id: 3, counter_id: 7, queue: "Label-2", driver: "ZDesigner",
    flags: [], device_serial: "ZD421-77J", by: "leo",
  }, checkSite);
  await store.deletePrinterQueue(5, checkSite);

  // The assignment (§1), both arms: a set, and the delete that means "no opinion" again.
  await store.setPrinterAssignment({ counter_id: 7, queue: "Label", vmids: [305, 306], printer_id: 9, by: "leo" }, checkSite);
  await store.setPrinterAssignment({ counter_id: 7, queue: "Label", vmids: null, by: "leo" }, checkSite);
  await store.listPrinterAssignments(3);

  // What the tick sends, and what the promote job is judged against.
  await store.getCounterPrinterTableForDevice(DEVICE);
  await store.getCounterPrintTabState(7);
  await store.getPendingPmrCounterJob(7, "counter.printing-promote");

  // The build lifecycle and node headroom.
  await store.getSiteCapture(3);
  await store.setSiteCapture(3, {
    source_hostname: "PHARM-PC1", disk_gb: 197, guest_agent_installed: true,
    printers_cleared: null, taken_by: "leo", out_of_hours: true,
  });
  await store.getSiteImport(3);
  await store.setSiteImport(3, { state: "running", pct: 40, node: "wcn1", vmid: 305 });
  // §7's reading: the write, and the per-site read the printers modal polls.
  await store.reportProxmoxVmPrinters([
    { vmid: 305, node: "wcn1", name: "ipharm-cl01", printers: ["Pharmacy-ETP (redirected 2)"],
      read_at: "2026-08-26T09:41:07.000Z", source: "guest-agent", error: null },
    { vmid: 306, node: "wcn1", name: "ipharm-cl02", printers: null, read_at: null,
      source: null, error: "QEMU guest agent is not running" },
  ]);
  await store.listDesktopPrinters(3);
  await store.listNodeCapacity();
  await store.reportNodeCapacity([
    { node: "wcn1", storage_name: "wcn-zfs", mem_total_bytes: 1, mem_free_bytes: 2, storage_total_bytes: 3, storage_free_bytes: 4, cpu_cores: 5, read_error: null },
    { node: "wcn1", storage_name: "local", mem_total_bytes: null, mem_free_bytes: null, storage_total_bytes: null, storage_free_bytes: null, cpu_cores: null, read_error: "no answer" },
  ]);

  const mismatched = seen.filter((s) => s.max !== s.bound);
  assert.deepEqual(mismatched, [],
    mismatched.map((s) => `$${s.max} named, ${s.bound} bound :: ${s.sql}`).join("\n"));

  // A guard on the guard: if a path stopped early — a fixture answer that no longer matches,
  // a function renamed — the assertion above would pass while testing almost nothing.
  assert.ok(seen.length >= 30, `only ${seen.length} statements were rendered`);
});

test("a two-row bulk insert really does reach the second tuple", async () => {
  // The bug this file exists for hides in the WIDTH of a bulk tuple, which a single-row insert
  // cannot expose: with one row, an off-by-one width and an off-by-one array often still meet
  // at the same number.
  const { store, seen } = recordingStore();
  await store.reportNodeCapacity([
    { node: "a", storage_name: "p1", mem_free_bytes: 1 },
    { node: "b", storage_name: "p2", mem_free_bytes: 2 },
  ]);
  const insert = seen.find((s) => /INSERT INTO proxmox_node_capacity/.test(s.sql));
  assert.ok(insert, "the capacity insert was never rendered");
  // Eight bound values per row, twice.
  assert.equal(insert.max, 16);
  assert.equal(insert.bound, 16);
});

test("the printer-list insert binds a whole tuple per VM, and never widens by one", async () => {
  // Same trap as the capacity insert below it: seven bound values and an eighth COLUMN filled
  // by a literal now(). A row array that grows to eight while the width stays seven binds the
  // second VM's node into the first VM's error, which is a silent data swap rather than an
  // error — until Postgres refuses the count, in production, on a live pharmacy's reading.
  const { store, seen } = recordingStore();
  await store.reportProxmoxVmPrinters([
    { vmid: 305, node: "wcn1", name: "a", printers: [], read_at: "2026-08-26T09:41:07.000Z" },
    { vmid: 306, node: "wcn1", name: "b", printers: ["X"], read_at: "2026-08-26T09:41:07.000Z" },
  ]);
  const insert = seen.find((s) => /INSERT INTO pmr_vm_printers/.test(s.sql));
  assert.ok(insert, "the printer insert was never rendered");
  assert.equal(insert.max, 14);
  assert.equal(insert.bound, 14);
});

test("a printer reading with no list binds SQL NULL, never an empty array", async () => {
  // ⛔ ABSENT IS NOT EMPTY, asserted at the last place it can still go wrong. A '{}' bound here
  // for a VM the collector never read would store "Windows lists no printers" — the alarming
  // answer — for every desktop with no guest agent in the estate.
  const { store, seen } = recordingStore();
  await store.reportProxmoxVmPrinters([
    { vmid: 305, node: "wcn1", name: "a", printers: null, read_at: null, error: "no agent" },
    { vmid: 306, node: "wcn1", name: "b", printers: [], read_at: "2026-08-26T09:41:07.000Z" },
  ]);
  const insert = seen.find((s) => /INSERT INTO pmr_vm_printers/.test(s.sql));
  assert.ok(insert, "the printer insert was never rendered");
  // Row 1 is vmid..error at offsets 0..6, row 2 at 7..13. printers is the 4th value of each.
  assert.equal(insert.params[3], null, "a VM with no reading must bind NULL");
  assert.deepEqual(insert.params[10], [], "a real empty answer must bind an empty array");
  assert.equal(insert.params[4], null, "read_at moves with the list");
});

test("a printer list arriving without a read time is not stored as a list", async () => {
  // The wire contract makes collected_at required: a reading that cannot be dated cannot be
  // aged, and the modal ages everything it draws. So the list is dropped and the reason kept.
  const { store, seen } = recordingStore();
  await store.reportProxmoxVmPrinters([
    { vmid: 305, node: "wcn1", name: "a", printers: ["Pharmacy-ETP"], read_at: null },
  ]);
  const insert = seen.find((s) => /INSERT INTO pmr_vm_printers/.test(s.sql));
  assert.equal(insert.params[3], null);
  assert.equal(insert.params[4], null);
});

test("the pharmacy reads select the whole row, so crm_site_id is never silently dropped", () => {
  // Stage 3 of the build checklist asks `hasOwnProperty(site, 'crm_site_id')`, so an
  // UNSELECTED column does not read as "this site is not pinned to a CRM record" — it reads as
  // UNKNOWN, and the checklist says in words that it cannot see the stage. Both reads are
  // whole-row today and this is the guard on that: a later refactor to a named column list
  // would take the stage out without touching anything that looks related to it.
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "shared", "store.pg.js"), "utf8");
  assert.match(src, /SELECT \* FROM pharmacies\s*\n\s*WHERE \(\$1 ~/,
    "getPharmacy no longer selects the whole pharmacies row");
  assert.match(src, /SELECT p\.\*,\s*\n\s*\(SELECT count\(\*\) FROM counters/,
    "listPharmacies no longer selects the whole pharmacies row");
  // And the column really exists to be selected.
  const schema = fs.readFileSync(path.join(__dirname, "..", "db", "schema.sql"), "utf8");
  assert.match(schema, /ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS crm_site_id text;/);
});
