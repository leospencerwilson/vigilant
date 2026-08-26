// docs/pmr-printer-contract.md, tested where it is testable without a database.
//
// ⛔ WHY THIS FILE IS SHAPED LIKE THIS. The contract exists because three owners each applied
// their own rules to one shared format and a driver name with a comma was staged, validated,
// promoted, restarted a counter's session and came back with the printer gone — while
// telemetry read converged. There are five owners now, so the FIRST group of tests below does
// not check that the server's rules are reasonable: it checks that they are CHARACTER-FOR-
// CHARACTER the rules the device already enforces, by reading the device's own files. A test
// that only exercised this side would have passed on the day of that defect.
//
// The parts that touch the database — the effective-table view, the whole-table check inside
// the write, the promote job's confirming reading — are single SQL statements precisely so
// they are atomic, and they are exercised against a real Postgres rather than mocked here.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const printerQueues = require("../src/shared/printerQueues");
const nodeCapacity = require("../src/shared/nodeCapacity");
const pmrVerbs = require("../src/shared/pmrVerbs");

const root = path.join(__dirname, "..");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const agent = read("agent/pi/vigilant-pi-agent.py");
const toolboxPriv = read("agent/pi/wcn-toolbox-priv");
const schema = read("db/schema.sql");
const contract = read("docs/pmr-printer-contract.md");

// ── ONE FORMAT, FIVE OWNERS ─────────────────────────────────────────────────

test("the queue pattern is character-for-character the one the Pi agent enforces", () => {
  // vigilant-pi-agent.py: TAB_QUEUE_RE — the pattern it refuses a whole table on.
  const m = /TAB_QUEUE_RE = re\.compile\(r"([^"]+)"\)/.exec(agent);
  assert.ok(m, "TAB_QUEUE_RE not found in the Pi agent");
  assert.equal(printerQueues.QUEUE_RE.source, m[1]);
});

test("the queue pattern is also the privileged helper's, which does the promoting", () => {
  // wcn-toolbox-priv: v_tabqueue — the check that runs at promotion time. A name this server
  // stores but that helper refuses makes the counter's WHOLE table permanently un-promotable.
  const m = /v_tabqueue\(\) \{ \[\[ "\$1" =~ (\S+) \]\]/.exec(toolboxPriv);
  assert.ok(m, "v_tabqueue not found in wcn-toolbox-priv");
  assert.equal(printerQueues.QUEUE_RE.source, m[1]);
});

test("the driver pattern is the agent's, comma carve-out included", () => {
  const m = /TAB_DRIVER_RE = re\.compile\(r"([^"]+)"\)/.exec(agent);
  assert.ok(m, "TAB_DRIVER_RE not found in the Pi agent");
  assert.equal(printerQueues.DRIVER_RE.source, m[1]);
  // And the carve-out is real, not incidental: the comma is what FreeRDP splits on.
  assert.equal(printerQueues.DRIVER_RE.test("ZDesigner ZD420-203dpi ZPL"), true);
  assert.equal(printerQueues.DRIVER_RE.test("Kyocera FS-1030D, KPDL"), false);
});

test("the 32-queue cap is ONE number in all the owners that hold one", () => {
  const inAgent = /^PRINTERS_MAX = (\d+)$/m.exec(agent);
  const inPriv = /^PRINTERS_MAX=(\d+)$/m.exec(toolboxPriv);
  assert.ok(inAgent && inPriv);
  assert.equal(printerQueues.MAX_QUEUES_PER_PI, Number(inAgent[1]));
  assert.equal(printerQueues.MAX_QUEUES_PER_PI, Number(inPriv[1]));
  // …and the contract states the same number, in words.
  assert.match(contract, /at most \*\*32\*\* queues per Pi/);
});

test("the flag set is closed, and it is the agent's set", () => {
  const m = /TAB_FLAGS = frozenset\(\("([^"]+)",\)\)/.exec(agent);
  assert.ok(m, "TAB_FLAGS not found in the Pi agent");
  assert.deepEqual([...printerQueues.QUEUE_FLAGS], [m[1]]);
});

test("the database refuses a name the kiosk would refuse — section 6, literally", () => {
  // "Enforce §2's patterns SERVER-SIDE at the point the operator types the name… A name the
  // kiosk would reject must never be storable." The CHECK constraint is the last of those
  // words: unstorable, not merely un-saveable through this API.
  assert.ok(schema.includes(`queue ~ '${printerQueues.QUEUE_RE.source}'`),
    "pmr_printer_queues.queue does not carry the contract's own pattern as a CHECK");
  // The driver's rule is spelled as three conditions rather than one class; the comma
  // carve-out is the part that matters and it must be there.
  assert.match(schema, /position\(',' in driver\) = 0/);
});

// ── section 2: the WHOLE table, or nothing ──────────────────────────────────

test("a driver with a comma refuses the WHOLE table, not just its line", () => {
  const r = printerQueues.validatePrinterTable([
    { queue: "Label-ZD421", driver: "ZDesigner ZD420-203dpi ZPL" },
    { queue: "Printer-A4", driver: "Kyocera FS-1030D, KPDL" },
  ]);
  assert.equal(r.ok, false);
  assert.equal(r.value, undefined, "a refused table must yield no partial value at all");
  assert.match(r.error, /COMMA/);
  assert.match(r.error, /refusing the whole table/);
});

test("a duplicate queue name refuses the whole table", () => {
  const r = printerQueues.validatePrinterTable([
    { queue: "Label", driver: "a" },
    { queue: "Label", driver: "b" },
  ]);
  assert.equal(r.ok, false);
  assert.match(r.error, /duplicate queue/);
});

test("two defaults are not a preference the file can express", () => {
  const r = printerQueues.validatePrinterTable([
    { queue: "A", driver: "x", flags: ["default"] },
    { queue: "B", driver: "y", flags: ["default"] },
  ]);
  assert.equal(r.ok, false);
  assert.match(r.error, /2 queues marked default/);
  // One is fine, and no default at all is fine.
  assert.equal(printerQueues.validatePrinterTable([
    { queue: "A", driver: "x", flags: ["default"] },
    { queue: "B", driver: "y" },
  ]).ok, true);
});

test("the cap is 32, and 33 refuses the table rather than truncating it", () => {
  const table = (n) => Array.from({ length: n }, (_, i) => ({ queue: `q${i}`, driver: "d" }));
  assert.equal(printerQueues.validatePrinterTable(table(32)).ok, true);
  const over = printerQueues.validatePrinterTable(table(33));
  assert.equal(over.ok, false);
  assert.match(over.error, /33 queues/);
});

test("63 characters is a queue name and 64 is not", () => {
  assert.equal(printerQueues.validateQueueName("a".repeat(63)).ok, true);
  assert.equal(printerQueues.validateQueueName("a".repeat(64)).ok, false);
  // Leading character must be alphanumeric — a name starting with '-' or '.' is refused.
  assert.equal(printerQueues.validateQueueName("-Label").ok, false);
  assert.equal(printerQueues.validateQueueName(".Label").ok, false);
  assert.equal(printerQueues.validateQueueName("Label-ZD421").ok, true);
});

test("an unknown flag is refused rather than dropped", () => {
  assert.equal(printerQueues.validateFlags(["default"]).ok, true);
  assert.equal(printerQueues.validateFlags(["preferred"]).ok, false);
  // A comma-separated string is the shape the FILE uses, so echoing a stored line back is
  // accepted — the same latitude _tab_flags() gives on the device.
  assert.deepEqual(printerQueues.validateFlags("default").value, ["default"]);
  assert.deepEqual(printerQueues.validateFlags(null).value, []);
});

test("the wire shape carries exactly the three fields section 2 names", () => {
  const r = printerQueues.validatePrinterTable([
    { queue: "Label-ZD421", driver: "ZDesigner ZD420-203dpi ZPL", flags: ["default"] },
  ]);
  assert.equal(r.ok, true);
  assert.deepEqual(Object.keys(r.value[0]).sort(), ["driver", "flags", "queue"]);
});

// ── section 3: what the Pi reports ──────────────────────────────────────────

test("'unknown' is never collapsed into 'attached, no queue'", () => {
  // Section 5: "AN UNKNOWN VALUE MUST NEVER RENDER AS A CONFIDENT ONE." CUPS being
  // unreachable and a printer having no queue are different facts, and the yellow-border
  // alarm belongs to only one of them.
  const out = printerQueues.normalizePeripheralPrinters({
    printers_attached: [
      { usb_path: "1-1.3", status: "unknown", serial: "ZD421-77J" },
      { usb_path: "1-1.4", status: "attached, no queue", serial: "BRN12345" },
    ],
  });
  assert.equal(out.printers_attached[0].status, "unknown");
  assert.deepEqual(out.printers_unqueued, ["1-1.4"]);
});

test("a status the agent never sends degrades to unknown, never to a confident one", () => {
  const out = printerQueues.normalizePeripheralPrinters({
    printers_attached: [{ usb_path: "1-1.3", status: "probably fine" }],
  });
  assert.equal(out.printers_attached[0].status, "unknown");
  assert.deepEqual(out.printers_unqueued, []);
});

test("reporting nothing about printers is not the same as reporting none", () => {
  assert.equal(printerQueues.normalizePeripheralPrinters({}), null);
  assert.equal(printerQueues.normalizePeripheralPrinters({ smartcard_reader: "present" }), null);
  const none = printerQueues.normalizePeripheralPrinters({ printers_attached: [] });
  assert.deepEqual(none.printers_attached, []);
  assert.deepEqual(none.printers_unqueued, []);
});

test("descriptor strings are escaped for display and never trusted", () => {
  // Section 3: "Descriptor strings are supplied by whoever made the device… never interpolate
  // them into SQL, a shell, or a filename, and escape them for display." A newline is the one
  // that matters most here: it is what lets a device forge a second line in a log or a second
  // field in a tab-separated file.
  const out = printerQueues.normalizePeripheralPrinters({
    printers_attached: [{
      usb_path: "1-1.3",
      manufacturer: "Zebra\nTechnologies",
      product: "ZD 421",
      status: "queued",
      queue: "Label",
    }],
  });
  const rec = out.printers_attached[0];
  assert.equal(rec.manufacturer.includes("\n"), false);
  assert.equal(rec.product, "ZD421");
  assert.match(rec.manufacturer, /^[\x20-\x7e]+$/);
});

test("a reported queue name that section 2 would refuse is not carried as a queue", () => {
  const out = printerQueues.normalizePeripheralPrinters({
    printers_attached: [{ usb_path: "1-1.3", status: "queued", queue: "not a legal name!" }],
  });
  assert.equal(out.printers_attached[0].queue, null);
});

test("a placeholder serial is not an identity", () => {
  // Whole production runs of cheap USB printers ship the same string. One of those becoming
  // the identity key would merge two physical printers into one row — the exact failure the
  // name-keyed `printers` table already has, arriving by a different door.
  assert.equal(printerQueues.usableSerial("000000"), null);
  assert.equal(printerQueues.usableSerial("n/a"), null);
  assert.equal(printerQueues.usableSerial("To be filled by O.E.M."), null);
  assert.equal(printerQueues.usableSerial("AB"), null);
  assert.equal(printerQueues.usableSerial("ZD421-77J"), "ZD421-77J");
});

test("identity falls back down the strength order, and says which it used", () => {
  // Section 1 ranks them: serial survives a rename AND a move; a bus path does not survive a
  // move; an address is the weakest and a re-address loses the link.
  assert.deepEqual(
    printerQueues.deviceIdentity({ serial: "ZD421-77J", usb_path: "1-1.3", counter_id: 7 }),
    { kind: "usb-serial", key: "usb-serial:zd421-77j", serial: "ZD421-77J" }
  );
  assert.equal(
    printerQueues.deviceIdentity({ serial: "000000", usb_path: "1-1.3", counter_id: 7 }).kind,
    "usb-path"
  );
  assert.equal(printerQueues.deviceIdentity({ address: "10.200.5.40" }).kind, "network");
  assert.equal(printerQueues.deviceIdentity({}), null);
});

// ── the assignment ──────────────────────────────────────────────────────────

test("no opinion and shared-to-nothing are different answers", () => {
  // null = no opinion: the queue keeps serving the desk it is built on. [] = shared to
  // nothing. Collapsing the two would silently un-share every printer nobody has dragged.
  assert.deepEqual(printerQueues.validateAssignedVmids(null), { ok: true, value: null });
  assert.deepEqual(printerQueues.validateAssignedVmids(undefined), { ok: true, value: null });
  assert.deepEqual(printerQueues.validateAssignedVmids([]), { ok: true, value: [] });
});

test("vmids are refused, never coerced, and are stored as a stable set", () => {
  assert.equal(printerQueues.validateAssignedVmids(["305"]).ok, false);
  assert.equal(printerQueues.validateAssignedVmids([305.5]).ok, false);
  assert.equal(printerQueues.validateAssignedVmids([99]).ok, false);
  // Sorted and deduped, so saving [306,305] and [305,306] are the same instruction and a UI
  // diffing them does not report a change that was not made.
  assert.deepEqual(printerQueues.validateAssignedVmids([306, 305, 305]).value, [305, 306]);
});

// ── section 4: the promote verb ─────────────────────────────────────────────

test("the promote verb signs a member of staff out, so it is disruptive and never converges", () => {
  const v = pmrVerbs.getVerb("counter.printing-promote");
  assert.ok(v, "counter.printing-promote is not in the allowlist");
  assert.equal(v.disruptive, true);
  assert.equal(v.converges, false);
  assert.equal(v.executor, "counter-pi");
});

test("a promotion is never re-offered — the first one already swapped the file", () => {
  // counter.session-restart may be re-handed out because "the session it would restart has
  // already gone". That argument does not hold here: the swap has happened, .prev is consumed,
  // and a second offer is a second sign-out that changes nothing.
  const v = pmrVerbs.getVerb("counter.printing-promote");
  assert.equal(v.retry_ok, false);
  assert.equal(v.max_attempts, 1);
});

test("the promote verb names a confirming reading, and both CHECKs know it", () => {
  const v = pmrVerbs.getVerb("counter.printing-promote");
  assert.equal(v.confirm, "pi-printers-promoted");
  assert.ok(pmrVerbs.CONFIRM_KINDS.includes(v.confirm));
  // The database mirrors the allowlist. A verb the allowlist admits and the CHECK refuses is
  // a job that 500s on INSERT, at midnight, on a live site.
  assert.match(schema, /pmr_jobs_verb_check CHECK \(verb IN \([^)]*'counter\.printing-promote'/);
  assert.match(schema, /pmr_jobs_confirm_kind_check CHECK \(confirm_kind IN \([^)]*'pi-printers-promoted'/);
});

test("the promote verb is honest that its confirmation is self-attested", () => {
  const v = pmrVerbs.getVerb("counter.printing-promote");
  assert.equal(v.confirm_self_attested, true);
  assert.ok(v.confirm_independent_would_be, "no independent reading is named");
  assert.ok(v.self_attested_acceptable_because);
});

test("the executor half is named as the verb the device already implements", () => {
  // wcn-toolbox-priv holds a privileged verb called `printing-promote` which validates .next,
  // keeps .prev, swaps the live file and restarts the session as one action. The server sends
  // a NAME; this is the name.
  assert.match(pmrVerbs.getVerb("counter.printing-promote").executor_note, /wcn-toolbox-priv/);
  assert.match(toolboxPriv, /printing-promote/);
});

// ── capacity, honestly ──────────────────────────────────────────────────────

const GB = nodeCapacity.GB;
const fresh = () => new Date().toISOString();

test("the measured 2026-08-25 numbers refuse the next site, and name the resource", () => {
  // wcn-zfs had 143 GB free; one site costs about 197 GB.
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "wcn-zfs-host",
    storage_name: "wcn-zfs",
    mem_total_bytes: 188 * GB,
    mem_free_bytes: 67 * GB,
    storage_total_bytes: 900 * GB,
    storage_free_bytes: 143 * GB,
    measured_at: fresh(),
  }, nodeCapacity.siteCost({ counters: 2 }));
  assert.equal(verdict.verdict, "short");
  assert.deepEqual(verdict.short.map((s) => s.resource), ["storage"]);
  assert.match(verdict.reason, /143\.0 GB free, 197\.0 GB needed/);
});

test("a site that fits is allowed, and memory is judged against the estate standard", () => {
  // 12 GB server + 6 GB per desktop.
  const need = nodeCapacity.siteCost({ counters: 2 });
  assert.equal(need.mem_bytes, 24 * GB);
  assert.equal(need.storage_bytes, 197 * GB);
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "spare", storage_name: "local-zfs",
    mem_free_bytes: 67 * GB, storage_free_bytes: 400 * GB, measured_at: fresh(),
  }, need);
  assert.equal(verdict.verdict, "fits");
});

test("a ten-counter site is short on BOTH, and both are named", () => {
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "wcn-zfs-host", storage_name: "wcn-zfs",
    mem_free_bytes: 67 * GB, storage_free_bytes: 143 * GB, measured_at: fresh(),
  }, nodeCapacity.siteCost({ counters: 10 }));
  assert.equal(verdict.verdict, "short");
  assert.deepEqual(verdict.short.map((s) => s.resource).sort(), ["memory", "storage"]);
});

test("a figure nobody measured is UNKNOWN — never zero, and never room", () => {
  // "Do not invent headroom — if the collector does not report a figure, the answer is
  // unknown, not zero."
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "quiet", storage_name: "wcn-zfs",
    mem_free_bytes: 67 * GB, storage_free_bytes: null, measured_at: fresh(),
  }, nodeCapacity.siteCost({ counters: 2 }));
  assert.equal(verdict.verdict, "unknown");
  assert.deepEqual(verdict.missing, ["storage"]);
  assert.equal(verdict.short.length, 0);
});

test("zero free IS a measurement, and it refuses", () => {
  // The other half of the same rule: 0 must not be treated as "we could not read it".
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "full", storage_name: "wcn-zfs",
    mem_free_bytes: 67 * GB, storage_free_bytes: 0, measured_at: fresh(),
  }, nodeCapacity.siteCost({ counters: 2 }));
  assert.equal(verdict.verdict, "short");
  assert.equal(verdict.short[0].free_bytes, 0);
});

test("a stale reading is unknown, not a stale yes", () => {
  const old = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString();
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "quiet", storage_name: "wcn-zfs",
    mem_free_bytes: 900 * GB, storage_free_bytes: 900 * GB, measured_at: old,
  }, nodeCapacity.siteCost({ counters: 2 }));
  assert.equal(verdict.verdict, "unknown");
  assert.match(verdict.reason, /older than/);
});

test("nothing reported at all is unknown, not fine", () => {
  const verdict = nodeCapacity.judgeNodeForSite(null, nodeCapacity.siteCost({}));
  assert.equal(verdict.verdict, "unknown");
  assert.deepEqual(verdict.missing, ["memory", "storage"]);
});

test("a known blocker beats a blind spot — short wins over unknown", () => {
  const verdict = nodeCapacity.judgeNodeForSite({
    node: "wcn-zfs-host", storage_name: "wcn-zfs",
    mem_free_bytes: null, storage_free_bytes: 143 * GB, measured_at: fresh(),
  }, nodeCapacity.siteCost({ counters: 2 }));
  assert.equal(verdict.verdict, "short");
  assert.deepEqual(verdict.missing, ["memory"]);
});

// ── §7 · WHAT WINDOWS ITSELF LISTS, END TO END ──────────────────────────────
//
// The modal's confirmations are a join between the CUPS queue name and the Windows printer
// list, and every one of them read "not checked" because nothing produced the second half.
// These tests drive the two halves that can run without a database — the ingest's cleaning of
// an untrusted list, and the read shape the modal polls — against the SAME sentences the front
// end's own contract states in src/lib/vigilantApi.js §7.
//
// ⛔ THE ONE PROPERTY EVERYTHING BELOW IS DEFENDING: absent is not empty. `null` means nobody
// has looked, which is the ORDINARY state of a desktop here and must render as unknown; `[]`
// means the guest was read and Windows lists nothing, which is a real fault. A path that
// collapses them puts a red confirmation on every desktop in the estate that has no agent.

const handlers = require("../src/ingest/handlers");

const capture = () => {
  const out = { code: null, body: null };
  return {
    out,
    res: {
      writeHead(code) { out.code = code; },
      end(buf) { out.body = JSON.parse(String(buf)); },
    },
  };
};

const desktopPrinters = async (pharmacyId, listRows) => {
  const { out, res } = capture();
  await handlers.desktopPrintersList({
    res,
    store: { listDesktopPrinters: async () => listRows },
    query: new URLSearchParams(pharmacyId === null ? "" : `pharmacy_id=${pharmacyId}`),
  });
  return out;
};

test("§7: a desktop nobody has read keeps the key, with a null list and a null time", async () => {
  const out = await desktopPrinters(3, [
    { vmid: 306, counter_id: 12, role: "thin client 2", printers: null, read_at: null,
      printer_source: null, printer_error: null, agent_ok: null },
  ]);
  assert.equal(out.code, 200);
  const d = out.body.desktops[0];
  // The key EXISTS and is null. An omitted key becomes a confident "no printers" in the UI.
  assert.ok("windows_printers" in d);
  assert.equal(d.windows_printers, null);
  assert.equal(d.collected_at, null);
});

test("§7: a guest that was read and lists nothing is [], which is a different fact", async () => {
  const out = await desktopPrinters(3, [
    { vmid: 305, printers: [], read_at: "2026-08-26T09:41:07.000Z", printer_source: "guest-agent" },
  ]);
  const d = out.body.desktops[0];
  assert.deepEqual(d.windows_printers, []);
  assert.equal(d.collected_at, "2026-08-26T09:41:07.000Z");
});

test("§7: RDP's ' (redirected N)' suffix is stripped for the join and kept for the eye", async () => {
  // MEASURED on VM 305. §1 says the queue name IS the Windows printer name and the modal joins
  // on it exactly, so with the suffix left on, all four working printers render as missing and
  // the one genuinely missing queue is indistinguishable from them.
  const out = await desktopPrinters(3, [
    { vmid: 305, printers: ["Pharmacy-ETP (redirected 2)", "Microsoft Print to PDF"],
      read_at: "2026-08-26T09:41:07.000Z", printer_source: "guest-agent" },
  ]);
  const names = out.body.desktops[0].windows_printers;
  assert.equal(names[0].name, "Pharmacy-ETP");
  assert.equal(names[0].raw_name, "Pharmacy-ETP (redirected 2)");
  assert.equal(names[0].redirected, true);
  // An undecorated name is untouched, and is not claimed to be redirected.
  assert.equal(names[1].name, "Microsoft Print to PDF");
  assert.equal(names[1].redirected, false);
});

test("§7: the server says how long its own reading may be spoken about in the present tense", async () => {
  const out = await desktopPrinters(3, []);
  // The collector's timer interval. The modal renders anything older muted and aged; polling
  // faster cannot make the reading newer, because Vigilant has no route to Proxmox.
  assert.equal(out.body.fresh_within_seconds, 900);
  assert.deepEqual(out.body.desktops, []);
});

test("§7: the freshness the endpoint vouches for is the collector's actual interval", () => {
  const timer = read("collectors/vigilant-proxmox-collector.timer");
  const m = /^OnUnitActiveSec=(\d+)min$/m.exec(timer);
  assert.ok(m, "the collector timer no longer states an interval in minutes");
  const inHandlers = /^const DESKTOP_PRINTERS_FRESH_S = (\d+);$/m
    .exec(read("src/ingest/handlers.js"));
  assert.ok(inHandlers, "DESKTOP_PRINTERS_FRESH_S not found");
  assert.equal(Number(inHandlers[1]), Number(m[1]) * 60);
});

test("§7: a bad pharmacy id is refused rather than answered for the whole estate", async () => {
  assert.equal((await desktopPrinters("nope", [])).code, 400);
  assert.equal((await desktopPrinters(null, [])).code, 400);
});

test("§7: the schema keeps the three states of a printer list apart", () => {
  // NULL-able text[] is what makes "never read" and "read, and empty" different values in the
  // column. A NOT NULL DEFAULT '{}' would erase the distinction at rest, whatever the wire did.
  assert.match(schema, /CREATE TABLE IF NOT EXISTS pmr_vm_printers \(/);
  assert.match(schema, /printers\s+text\[\],\s+-- NULL = never read/);
  assert.match(schema, /read_at\s+timestamptz,\s+-- when the GUEST was read/);
  // And nothing has quietly given the column a default that would erase the distinction.
  assert.doesNotMatch(schema, /printers\s+text\[\]\s+NOT NULL/);
});


// ── §7 · the untrusted half: a printer name is a string from inside Windows ──
//
// It is named by whoever installed the printer, it crosses an RDP redirect that decorates it,
// and it lands on a page that renders it. The ingest is the edge, so the bounding happens here
// — and these tests are the guard on it, because every rule below protects something that is
// not obviously connected to printers at all.

const proxmoxReport = async (payload) => {
  const { out, res } = capture();
  const seen = { printers: null };
  await handlers.proxmoxReport({
    res,
    // A STRING, not a Buffer: parseJsonBody returns any object it is handed as-is, so a
    // Buffer would sail past every shape check in the handler untouched.
    body: JSON.stringify(payload),
    log: { warn() {}, info() {}, error() {} },
    store: {
      reportProxmoxVms: async () => ({ vms: 0 }),
      reconcileProxmox: async () => ({ conflicts: [], linked: 0 }),
      reportProxmoxVmPrinters: async (list) => { seen.printers = list; return { printer_rows: list.length }; },
    },
  });
  return { out, seen };
};

test("§7 ingest: a name is bounded, stripped of control characters, and the list capped", async () => {
  const { seen } = await proxmoxReport({
    vms: [],
    printers: [{
      vmid: 305, node: "wcn1", name: "ipharm-cl01",
      read_at: Math.floor(Date.now() / 1000),
      printers: [
        // A bell and a NUL, which break log lines and terminals rather than the page.
        "Label-ZD\u0007 4\u000020",
        "   ",
        "x".repeat(400),
        ...Array.from({ length: 200 }, (_, i) => `p${i}`),
      ],
    }],
  });
  const names = seen.printers[0].printers;
  assert.equal(names[0], "Label-ZD 420");
  // A name that is only whitespace is not a name, and is dropped rather than stored empty.
  assert.ok(!names.includes(""));
  assert.equal(names[1].length, 120);
  assert.equal(names.length, 64);
});

test("§7 ingest: absent is not empty, in both directions", async () => {
  const { seen } = await proxmoxReport({
    vms: [],
    printers: [
      // No agent: NOTHING was read. The list must stay null all the way to the store.
      { vmid: 302, error: "QEMU guest agent is not running" },
      // Read, and Windows lists nothing. A real, alarming answer that must survive as [].
      { vmid: 305, printers: [], read_at: Math.floor(Date.now() / 1000) },
    ],
  });
  assert.equal(seen.printers[0].printers, null);
  assert.equal(seen.printers[0].read_at, null);
  assert.deepEqual(seen.printers[1].printers, []);
  assert.ok(seen.printers[1].read_at);
});

test("§7 ingest: a read time we cannot trust costs the reading, not the age", async () => {
  // A clock ahead of ours renders as permanently fresh — the one direction in which a bad
  // reading becomes a confident lie rather than a visible doubt. So the list goes, the reason
  // stays, and the modal shows unknown.
  const now = Math.floor(Date.now() / 1000);
  for (const t of [now + 3600, now - 40 * 24 * 3600, null, "not a time"]) {
    const { seen } = await proxmoxReport({
      vms: [], printers: [{ vmid: 305, printers: ["Pharmacy-ETP"], read_at: t }],
    });
    assert.equal(seen.printers[0].printers, null, `read_at ${t} should not have been trusted`);
    assert.match(seen.printers[0].error, /no usable read time/);
  }
});

test("§7 ingest: a collector that sends no printers key still reports its inventory", async () => {
  // Every deployed collector predates this key, and must keep reporting inventory.
  const { out, seen } = await proxmoxReport({ vms: [] });
  assert.equal(out.code, 200);
  assert.equal(seen.printers, null);
  // A key of the wrong shape is refused rather than guessed at.
  assert.equal((await proxmoxReport({ vms: [], printers: {} })).out.code, 400);
});
