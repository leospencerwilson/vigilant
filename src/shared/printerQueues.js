'use strict';

// Vigilant — THE SERVER'S HALF of docs/pmr-printer-contract.md. §2's wire format, §3's
// reported shape, and the four objects of §1, in one file.
//
// ⛔ READ docs/pmr-printer-contract.md BEFORE CHANGING ANYTHING HERE. That file is the single
// source of truth and this file is its server copy; every constant below is transcribed from
// it and every refusal quotes it. The contract exists because of this, in its own words:
//
//     "On 2026-08-25 three owners (the Pi agent, the kiosk launcher and the privileged helper)
//      each applied their own rules to one shared file format. The result was two blocking
//      defects: a driver name containing a comma was staged, validated, promoted, **the
//      session was restarted**, and the counter came back with that printer gone — while
//      telemetry reported it converged. Divergence between owners is the failure mode this
//      contract prevents."
//
// There are now FIVE owners of this format: vigilant-pi-agent.py (TAB_QUEUE_RE /
// TAB_DRIVER_RE / _tab_flags / render_printers_tab), wcn-toolbox-priv (v_tabqueue and the
// promote verb), wcn-kiosk (the reader), the Watchman front end
// (pages/ops/desktop/printerContract.js) and THIS FILE. All five accept and reject exactly
// the same tables.
//
// ⚠️ EXACTLY the contract, never stricter. A rule tightened here refuses a table the kiosk
// would accept, which is divergence in the other direction and the same class of bug.

// ── §2, transcribed ──────────────────────────────────────────────────────────
// | `queue` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` — max **63** characters |
// Identical to vigilant-pi-agent.py's TAB_QUEUE_RE and wcn-toolbox-priv's v_tabqueue.
const QUEUE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const QUEUE_MAX = 63;

// | `driver` | printable ASCII, 1..128, **NO COMMA** — comma is FreeRDP's own field separator
// inside `/printer:` |
//
// 0x2c is the comma, and it is the ONE printable character carved out of the range —
// character-for-character the agent's TAB_DRIVER_RE. It cannot be the queue-name class:
// every real driver name has spaces ("ZDesigner ZD420-203dpi ZPL").
const DRIVER_RE = /^[\x20-\x2b\x2d-\x7e]{1,128}$/;
const DRIVER_MAX = 128;

// | `flags` | closed set: `default` only. At most ONE queue may carry it. |
const QUEUE_FLAGS = Object.freeze(['default']);

// | count | at most **32** queues per Pi — the kiosk redirects no more |
// ONE number in all five owners: PRINTERS_MAX in vigilant-pi-agent.py, PRINTERS_MAX in
// wcn-toolbox-priv, wcn-kiosk's own cap, MAX_QUEUES_PER_PI on the front end, and this.
const MAX_QUEUES_PER_PI = 32;

// ── §3, transcribed ──────────────────────────────────────────────────────────
// | `status` | `queued` | `attached, no queue` | `unknown` (CUPS itself was unreachable —
// NOT the same as no queue) |
//
// WIRE VALUES, compared with === against what the agent sends. A paraphrase here is a silent
// mis-read rather than a visible typo, which is why they are declared once.
const STATUS_QUEUED = 'queued';
const STATUS_UNQUEUED = 'attached, no queue';
const STATUS_UNKNOWN = 'unknown';
const PRINTER_STATUSES = Object.freeze([STATUS_QUEUED, STATUS_UNQUEUED, STATUS_UNKNOWN]);

// The agent breaks out of its own loop at eight records ("A counter has two or three
// printers; anything past eight is a fault or a hub full of something else"), so a list of
// exactly this length is a LOWER BOUND on what is plugged in and nothing may conclude
// "nothing else is attached" from it.
const ATTACHED_CAP = 8;

// ── §3's untrusted strings ───────────────────────────────────────────────────
// "Descriptor strings are supplied by whoever made the device and are validated to printable
// ASCII before being reported. Treat them as untrusted on the server too: never interpolate
// them into SQL, a shell, or a filename, and escape them for display."
//
// Everything this file hands onward is bound as a query PARAMETER, never interpolated — so
// this is the DISPLAY half of that sentence, and it is applied at ingest so the bytes in the
// database are already safe for every reader (the API, the UI, a CSV export, a log line).
//
// Anything outside printable ASCII is DROPPED rather than replaced with a marker: a
// descriptor is a manufacturer's label, not a payload, and a Zebra whose product string
// carries a stray byte should read "ZD421" and not "ZD421�". A string that is nothing
// BUT unprintable characters becomes null — "we read something meaningless" and "we read
// nothing" are the same fact to every caller.
function displaySafe(value, max = 128) {
  if (typeof value !== 'string') return null;
  // Strip C0/C1 and everything above 0x7e. \t, \n and \r go with them: a newline in a
  // descriptor is what lets a device forge a second line in a log or a second field in a
  // tab-separated file.
  const cleaned = value.replace(/[^\x20-\x7e]/g, '').trim();
  if (!cleaned) return null;
  return cleaned.slice(0, max);
}

// ── §1's identities ──────────────────────────────────────────────────────────
// | Physical device | USB serial, or network MAC/serial | NOT its name. A printer keeps its
// identity across a rename and across a move to another counter. |
//
// A serial is only an identity if it actually distinguishes anything. Cheap USB printers ship
// whole production runs with the same string, and several report a placeholder, so a known-
// useless value must not become the key that merges two physical printers into one row.
const USELESS_SERIALS = new Set([
  '', '0', '00', '000', '0000', '00000', '000000',
  'none', 'null', 'n/a', 'na', 'unknown', 'serial', 'no serial', 'notset', 'not set',
  '000000000', '0123456789', '123456789', 'default_string', 'system serial number',
  'to be filled by o.e.m.', 'to be filled by o.e.m',
]);

function usableSerial(value) {
  const s = displaySafe(value, 128);
  if (!s) return null;
  if (USELESS_SERIALS.has(s.toLowerCase())) return null;
  // A serial of one or two characters is not an identity either — it collides with anything.
  if (s.length < 3) return null;
  return s;
}

// The identity key for a physical device, as ONE string, so the database can hold a single
// UNIQUE index over it instead of three partial ones — and so the server and the front end's
// deviceKeyFor() group the same devices the same way.
//
// The three kinds are ORDERED by strength, and the strongest available wins:
//   usb-serial  the device's own serial. Survives a rename AND a move to another counter,
//               which is §1's whole requirement.
//   usb-path    a serial-less USB printer, keyed by the Pi it is plugged into plus the bus
//               path. Does NOT survive a move — and says so, so the UI can too.
//   net         a network printer, by address. §1 allows MAC or serial; nothing in this
//               estate's printer feed reports either, so the address is what there is and a
//               re-address loses the link. Weakest, and labelled weakest.
function deviceIdentity(rec = {}) {
  const serial = usableSerial(rec.serial);
  if (serial) return { kind: 'usb-serial', key: `usb-serial:${serial.toLowerCase()}`, serial };
  const usbPath = displaySafe(rec.usb_path, 64);
  if (usbPath && rec.counter_id != null) {
    return { kind: 'usb-path', key: `usb-path:${rec.counter_id}:${usbPath.toLowerCase()}`, serial: null };
  }
  const address = displaySafe(rec.address, 200);
  if (address) return { kind: 'network', key: `net:${address.toLowerCase()}`, serial: null };
  return null;
}

// ── §2 validation, one line at a time ────────────────────────────────────────
// Refusals quote the contract, because the sentence the operator reads in Watchman should be
// the sentence the rule was written as.

function validateQueueName(queue) {
  if (typeof queue !== 'string' || !queue) {
    return { ok: false, error: 'a queue name is required' };
  }
  if (!QUEUE_RE.test(queue)) {
    return {
      ok: false,
      error: `queue name ${JSON.stringify(queue.slice(0, 80))} is refused — §2: `
           + '`queue` — `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` — max 63 characters. Letters, '
           + 'digits, dot, dash and underscore only, starting with a letter or a digit.',
    };
  }
  return { ok: true, value: queue };
}

function validateDriver(driver) {
  if (typeof driver !== 'string' || !driver) {
    return { ok: false, error: 'a driver name is required' };
  }
  if (!DRIVER_RE.test(driver)) {
    // The comma is named EXPLICITLY. It is the one refusal an operator hits by typing the
    // TRUE driver name off the Windows print server ("Kyocera FS-1030D, KPDL"), and
    // "not printable ASCII" sends them looking for the wrong thing entirely — the agent's
    // TAB_DRIVER_RE branch says the same thing in the same words.
    if (driver.includes(',')) {
      return {
        ok: false,
        error: `driver ${JSON.stringify(driver.slice(0, 80))} is refused because it contains a `
             + "COMMA, which is FreeRDP's own field separator inside /printer: — rename the "
             + 'driver in Windows or omit the part after the comma. §2, and the defect this '
             + 'contract exists for.',
      };
    }
    return {
      ok: false,
      error: `driver ${JSON.stringify(driver.slice(0, 80))} is refused — §2: `
           + '`driver` — printable ASCII, 1..128, NO COMMA.',
    };
  }
  return { ok: true, value: driver };
}

// A list of strings is the wire shape. A comma-separated string is accepted because it is the
// shape printers.tab itself uses and a server echoing a stored line back should not be a
// fault — the same latitude _tab_flags() gives on the device.
function validateFlags(flags) {
  if (flags === undefined || flags === null || flags === '') return { ok: true, value: [] };
  let list = flags;
  if (typeof list === 'string') list = list.split(',');
  if (!Array.isArray(list)) {
    return { ok: false, error: 'flags must be a list of strings' };
  }
  const out = new Set();
  for (const flag of list) {
    const f = typeof flag === 'string' ? flag.trim() : flag;
    if (typeof f !== 'string' || !QUEUE_FLAGS.includes(f)) {
      return {
        ok: false,
        error: `flag ${JSON.stringify(String(flag).slice(0, 40))} is refused — §2: `
             + `\`flags\` — closed set: ${QUEUE_FLAGS.join(', ')} only.`,
      };
    }
    out.add(f);
  }
  return { ok: true, value: [...out].sort() };
}

// ONE line of the table: exactly the three keys §2 puts on the wire — `queue`, `driver`,
// `flags` — and only those three are read. An extra key is DROPPED, not refused.
//
// ⚠️ THIS COMMENT USED TO CLAIM THE OPPOSITE (B3). It said unknown keys are "REFUSED rather
// than dropped, for the reason counterSettings.js states", which is a real and good rule —
// there, where a closed whitelist guards values that decide whether a pharmacist gets signed
// out, and where a typo must surface instead of appearing to save and doing nothing. It is
// simply not the rule here, and making the code match the comment would have BROKEN EVERY
// PRINTER WRITE IN THE ESTATE: siteEffectiveTables() reads pmr_counter_printer_table_v and
// carries a fourth key, `host_counter_id`, through to assertSiteTablesValid() so the caller
// can say "shared from another counter". Every save would have 409'd on it.
//
// SO THE TOLERANCE IS DELIBERATE, and it is narrow. Three things make it safe here where it
// would not be in counterSettings.js:
//
//   1. THIS IS A PROJECTION, NOT A SAVE. It returns a NEW object built from the three keys it
//      understands. Nothing a caller sends beyond them is stored, forwarded or sent to a
//      device — the value handed on is `{ queue, driver, flags }` and nothing else, so a
//      dropped key cannot silently become a setting nobody chose.
//   2. ITS INPUT IS OFTEN OURS, not an operator's. The whole-table check runs over rows this
//      server built from its own view; refusing our own enrichment would be refusing a table
//      that is correct.
//   3. THE OPERATOR-FACING PATH VALIDATES THE FIELDS SEPARATELY. printerQueueUpsert() hands
//      this a literal `{ queue, driver, flags }` assembled from named body fields, so a typo
//      an operator makes in Watchman never reaches here as an unknown key — it reaches the
//      route as an ignored body field, which is the ordinary shape of every other route.
//
// ⛔ WHAT MUST STAY STRICT is the three keys themselves: queue and driver are pattern-matched
// against §2's own regexes and flags against a closed set, all below. That is where the
// divergence-between-owners failure this contract exists to prevent actually lives.
function validateQueueLine(entry, where = 'entry') {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { ok: false, error: `${where}: expected an object` };
  }
  const q = validateQueueName(entry.queue);
  if (!q.ok) return { ok: false, error: `${where}: ${q.error}` };
  const d = validateDriver(entry.driver);
  if (!d.ok) return { ok: false, error: `${where} (${q.value}): ${d.error}` };
  const f = validateFlags(entry.flags);
  if (!f.ok) return { ok: false, error: `${where} (${q.value}): ${f.error}` };
  return { ok: true, value: { queue: q.value, driver: d.value, flags: f.value } };
}

// ── §2 validation over the WHOLE table ───────────────────────────────────────
//
// ⛔ "Send the whole effective table every tick, like `settings`. A table is a SET: refuse it
// entirely if any line is bad, never apply it partially. A partially-applied table is
// internally consistent and quietly wrong — indistinguishable from an operator who meant it."
//
// ALL OR NOTHING, and that is why this returns one error and no partial value. The three
// WHOLE-TABLE conditions — duplicate queue name, a second `default`, more than
// MAX_QUEUES_PER_PI — are refused here exactly as the two writing owners on the device refuse
// them. (wcn-kiosk, which reads a file it did not write, resolves those three PER LINE
// instead so a counter never ends up with zero printers; that leniency is unreachable by
// anything that came through this path, and it is the one deliberate asymmetry in the
// contract.)
function validatePrinterTable(entries, where = 'printer table') {
  if (!Array.isArray(entries)) {
    return { ok: false, error: `${where}: expected an array of queues` };
  }
  if (entries.length > MAX_QUEUES_PER_PI) {
    return {
      ok: false,
      error: `${where}: ${entries.length} queues, more than the ${MAX_QUEUES_PER_PI} the kiosk `
           + 'will redirect — §2: count — at most 32 queues per Pi. The whole table is refused.',
    };
  }
  const value = [];
  const seen = new Set();
  const defaults = [];
  for (let i = 0; i < entries.length; i += 1) {
    const line = validateQueueLine(entries[i], `${where} entry ${i + 1}`);
    if (!line.ok) return { ok: false, error: `${line.error} — refusing the whole table` };
    // Case-SENSITIVE, because that is what the device compares. A case-insensitive twin is a
    // trap worth warning about in the UI (the front end does), but refusing it here would
    // refuse a table the kiosk accepts.
    if (seen.has(line.value.queue)) {
      return {
        ok: false,
        error: `${where}: duplicate queue ${JSON.stringify(line.value.queue)} — §2: a duplicate `
             + 'queue name is refused for the WHOLE table. Two lines for one queue would emit '
             + 'two /printer: flags naming the same Windows printer.',
      };
    }
    seen.add(line.value.queue);
    if (line.value.flags.includes('default')) defaults.push(line.value.queue);
    value.push(line.value);
  }
  if (defaults.length > 1) {
    return {
      ok: false,
      error: `${where}: ${defaults.length} queues marked default (${defaults.join(', ')}) — §2: `
           + 'at most ONE queue may carry it. Which one the operator meant is not something '
           + 'the file can express, so the whole table is refused.',
    };
  }
  return { ok: true, value };
}

// ── the assignment (§1) ──────────────────────────────────────────────────────
// | Assignment | queue → desktop (VM) | A person drags a printer onto a desktop. This is what
// "shared to" means. |
//
// The WHOLE effective set, never a delta — the same rule §2 states for the table itself, and
// the reason the front end's setPrinterAssignments() sends every vmid every time.
//
//   null  no opinion. The queue serves its own host counter's desktop, which is what an
//         unassigned local queue has always done.
//   []    shared to nothing. A real instruction, and NOT the same as null.
//
// Bounded like every other value that reaches an executor: a vmid here selects which counter's
// effective table a queue lands in, so it is range-checked against the same 100..999999 span
// pmrVerbs.ARG_SPECS.vmid uses rather than being trusted as "a number the UI sent".
const VMID_MIN = 100;
const VMID_MAX = 999999;
const MAX_ASSIGNED_VMIDS = 32;

function validateAssignedVmids(vmids) {
  if (vmids === undefined || vmids === null) return { ok: true, value: null };
  if (!Array.isArray(vmids)) {
    return { ok: false, error: 'vmids must be an array of VM ids — send [] to share this queue to nothing, or omit the key entirely to express no opinion' };
  }
  if (vmids.length > MAX_ASSIGNED_VMIDS) {
    return { ok: false, error: `a queue cannot be shared to more than ${MAX_ASSIGNED_VMIDS} desktops` };
  }
  const out = new Set();
  for (const v of vmids) {
    // Checked AS A NUMBER and never parsed out of a string, for the reason counterSettings.js
    // gives: "24" arriving from a <select> is a UI bug, and coercing it hides the one class of
    // bug this whitelist exists to catch.
    if (typeof v !== 'number' || !Number.isInteger(v)) {
      return { ok: false, error: `vmid ${JSON.stringify(v)} must be a whole number sent as a JSON number, not a string` };
    }
    if (v < VMID_MIN || v > VMID_MAX) {
      return { ok: false, error: `vmid ${v} must be an integer between ${VMID_MIN} and ${VMID_MAX}` };
    }
    out.add(v);
  }
  // Sorted so the stored value is stable: an assignment saved as [306, 305] and one saved as
  // [305, 306] are the same instruction, and a UI diffing them must not report a change.
  return { ok: true, value: [...out].sort((a, b) => a - b) };
}

// ── §3, the reported shape ───────────────────────────────────────────────────
// What the Pi sends at peripherals.printers_attached, cleaned for storage. Every descriptor
// string goes through displaySafe(); every status is held to the three-valued vocabulary.
//
// ⚠️ 'unknown' IS NEVER COLLAPSED INTO 'attached, no queue'. §5: "AN UNKNOWN VALUE MUST NEVER
// RENDER AS A CONFIDENT ONE. 'No queue' when CUPS was simply down is a false alarm; 'queued'
// when it was not is a false all-clear. Both are worse than saying unknown." So an
// unrecognised status becomes 'unknown' — never the confident one — and a record with no
// usb_path is dropped, because usb_path is the Pi's own id for the device and the thing
// printers_unqueued lists.
function normalizeAttachedPrinter(rec) {
  if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return null;
  const usbPath = displaySafe(rec.usb_path, 64);
  if (!usbPath) return null;
  const status = PRINTER_STATUSES.includes(rec.status) ? rec.status : STATUS_UNKNOWN;
  return {
    usb_path: usbPath,
    vendor_id: displaySafe(rec.vendor_id, 16),
    product_id: displaySafe(rec.product_id, 16),
    manufacturer: displaySafe(rec.manufacturer, 128),
    product: displaySafe(rec.product, 128),
    // The RAW serial for display, and the USABLE one for identity. Both are carried: a
    // placeholder serial should still be shown to an engineer standing at the printer, it
    // just must not become the key that merges two devices.
    serial: displaySafe(rec.serial, 128),
    usable_serial: usableSerial(rec.serial),
    protocol: displaySafe(rec.protocol, 32),
    status,
    // Only meaningful when status is 'queued'. Held to §2's own pattern, because this string
    // is compared against — and may become — a managed queue name.
    queue: status === STATUS_QUEUED && QUEUE_RE.test(String(rec.queue || '')) ? rec.queue : null,
    matched_on: displaySafe(rec.matched_on, 32),
  };
}

// The whole `peripherals` block's printer half, as one bounded object.
//
// Returns null when the agent reported nothing about printers at all — which is NOT the same
// as an empty list, and is the ordinary state of every agent build predating §3.
function normalizePeripheralPrinters(peripherals) {
  if (!peripherals || typeof peripherals !== 'object' || Array.isArray(peripherals)) return null;
  const hasAttached = Array.isArray(peripherals.printers_attached);
  const hasTab = peripherals.print_tab_pending !== undefined
    || Array.isArray(peripherals.print_tab_live)
    || Array.isArray(peripherals.print_tab_next);
  if (!hasAttached && !hasTab) return null;

  const attached = [];
  if (hasAttached) {
    for (const rec of peripherals.printers_attached) {
      const clean = normalizeAttachedPrinter(rec);
      if (clean) attached.push(clean);
      // Bounded at the agent's own cap. A longer list is a bug or a hostile payload, and
      // either way the extra rows say nothing the first eight do not.
      if (attached.length >= ATTACHED_CAP) break;
    }
  }

  // The yellow-border alarm (§3). Recomputed from the cleaned records rather than trusted
  // from the wire, so it cannot disagree with the statuses stored beside it — and so
  // 'unknown' never leaks into it.
  const unqueued = attached.filter((p) => p.status === STATUS_UNQUEUED).map((p) => p.usb_path);

  const names = (list) => (Array.isArray(list)
    ? list.map((n) => displaySafe(n, QUEUE_MAX)).filter(Boolean).slice(0, 32)
    : null);

  return {
    // null when the agent said nothing about what is plugged in — distinct from [].
    printers_attached: hasAttached ? attached : null,
    printers_unqueued: hasAttached ? unqueued : null,
    // The staged table differs from the live one -> "needs a session restart at this counter".
    // Tri-state: null means the agent did not report it.
    print_tab_pending: typeof peripherals.print_tab_pending === 'boolean'
      ? peripherals.print_tab_pending : null,
    // ⚠️ BOTH ARE TRUNCATED BY THE AGENT at sixteen names (_tab_queue_names), so a count taken
    // from either is a LOWER BOUND and nothing may conclude "this counter has N queues" from
    // it. The intended table in pmr_printer_queues is the complete answer.
    print_tab_live: names(peripherals.print_tab_live),
    print_tab_next: names(peripherals.print_tab_next),
  };
}

module.exports = {
  QUEUE_RE,
  QUEUE_MAX,
  DRIVER_RE,
  DRIVER_MAX,
  QUEUE_FLAGS,
  MAX_QUEUES_PER_PI,
  STATUS_QUEUED,
  STATUS_UNQUEUED,
  STATUS_UNKNOWN,
  PRINTER_STATUSES,
  ATTACHED_CAP,
  MAX_ASSIGNED_VMIDS,
  displaySafe,
  usableSerial,
  deviceIdentity,
  validateQueueName,
  validateDriver,
  validateFlags,
  validateQueueLine,
  validatePrinterTable,
  validateAssignedVmids,
  normalizeAttachedPrinter,
  normalizePeripheralPrinters,
};
