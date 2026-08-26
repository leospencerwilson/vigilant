'use strict';

// ═══════════════════════════════════════════════════════════════════════════
// THE CAPTURE KIT'S CREDENTIALS — the ticket, the scoped token, and the three
// capabilities that are the whole of what it may do
// ═══════════════════════════════════════════════════════════════════════════
//
// ⛔ WHY THIS FILE EXISTS AT ALL. The capture kit runs on a PHARMACY'S OWN PC — a machine
// that is not ours, that we are about to image, and that will be handed back. The frontend's
// Supabase key was the obvious thing to reach for and it is the one thing that must never go
// near it: that key decodes to "role":"service_role", which BYPASSES ROW-LEVEL SECURITY
// entirely, and the env file's own comment says it must never ship in a deployed build. A kit
// that ships a long-lived credential to a pharmacy PC is a kit that has failed.
//
// So the kit carries a credential that can do exactly three things, at exactly one site, for
// a bounded time — and Vigilant queries the CRM server-side on its behalf. Same posture as
// the HMAC-signed thin-client image URL (src/shared/supportToken.js) and the per-node
// Proxmox token: the NAME and the SCOPE are properties of the SECRET, never of the request
// body.
//
// ── TWO OBJECTS, AND WHY IT IS NOT ONE ──────────────────────────────────────
//
//   THE TICKET   issued from Watchman for ONE site by a NAMED engineer, out of hours. It is
//                the kit's identity and its site binding in one object — which is precisely
//                why the site cannot be a typed string: the kit is physically unable to name
//                another pharmacy. The ticket is the thing a person handles (it is read off
//                a screen and into the kit once); it is REDEEMABLE, not usable, and the only
//                route that accepts it is POST /capture/token.
//
//   THE TOKEN    what the ticket mints: a short-lived bearer carrying the three capabilities
//                and nothing else. It is what every kit call actually presents.
//
// This is the SELF_ENROL_TOKEN -> per-device-token shape the thin-client image already uses,
// and it exists here for the same reason: the long-lived thing must not be the thing on the
// wire on every call, and the thing on the wire must be cheap to expire.
//
// ── ⚠️ THE LIFETIMES, AND THE FACT THEY ARE ARGUED AGAINST ─────────────────
// A capture takes 30–90 minutes and MAY RESUME AFTER A REBOOT — the VirtIO guest-agent
// install is the point of a human being on site and it reboots the PC. That single fact kills
// two tempting designs:
//
//   * a SINGLE-USE ticket strands the kit the moment the PC comes back up, mid-capture, at
//     one in the morning, with an engineer standing in a pharmacy;
//   * a token long enough to cover the whole visit is a bearer sitting in a file on a
//     pharmacy PC for eight hours.
//
// So the ticket is redeemable a BOUNDED number of times (REDEEM_MAX) over a bounded window,
// and each redemption mints a token that dies in TOKEN_TTL_S. A stolen ticket has a countable
// budget; a stolen token has ninety minutes.
//
// ⛔ AND THE TICKET IS HARD-BOUNDED TO THE SITE'S CLOSED WINDOW. Its expiry is
// min(now + TICKET_TTL_S, the site's next opening time), so it is arithmetically incapable of
// being alive while the pharmacy is trading. "Out of hours only" is not a check the kit makes
// and can skip — it is the shape of the credential.

const crypto = require('node:crypto');
const openingHours = require('./openingHours');

// ── the three capabilities, and there are three ─────────────────────────────
// ⛔ THIS LIST IS THE FEATURE. Adding a fourth entry here is not a refactor: it widens what a
// credential on a pharmacy PC can reach. The DB carries the same list as a CHECK constraint
// on pmr_capture_tokens.capabilities, so a token minted with anything else cannot be stored,
// and the dispatch carries it as a route table, so a token presented anywhere else is not
// even a candidate for authentication. Three enforcements, one list.
//
//   sites:list      the sites this ticket admits. Exactly one — the ticket binds it — but it
//                   is returned AS A LIST because the kit renders a picker and the engineer
//                   confirms rather than types. The kit cannot widen it.
//   slots:read      which role slots at that site are already taken, so the kit can refuse a
//                   duplicate before it spends 90 minutes producing one.
//   capture:write   register / update THIS site's capture, and be told where to upload.
//
// Note what is NOT here and must never be: creating or editing a pharmacy, reading the fleet,
// reading any other site, creating a job, touching a counter, or reading a device token.
const CAPABILITIES = Object.freeze(['sites:list', 'slots:read', 'capture:write']);
const CAPABILITY_SET = new Set(CAPABILITIES);

// ── the route table: enforcement AT THE ROUTE, not by convention ────────────
// The dispatch consults this table BEFORE it will even try to authenticate a capture bearer.
// A capture token presented to /fleet, /pharmacies, /pmr/jobs or /proxmox/report is not
// checked against a capability and found wanting — it is not a recognised credential on those
// routes at all, and falls through to the ordinary 401. The handlers then assert their own
// capability a second time (assertCapability below), so a route added to this table without a
// matching assertion still refuses.
//
// Exact method + exact path. No parameters, on purpose: a capture route that took a
// :pharmacy_id would put the site back into a string the kit chooses, which is the entire
// thing the ticket exists to prevent. Every one of these reads its site from the TOKEN.
const CAPTURE_ROUTES = Object.freeze([
  Object.freeze({ method: 'GET', path: '/capture/sites', capability: 'sites:list' }),
  Object.freeze({ method: 'GET', path: '/capture/slots', capability: 'slots:read' }),
  Object.freeze({ method: 'POST', path: '/capture/register', capability: 'capture:write' }),
]);

// The one function the dispatch asks. Returns the capability this (method, path) requires, or
// null — and null means "a capture token is not a credential here", which is a stronger
// statement than "this token lacks the capability".
function capabilityForRoute(method, pathname) {
  const m = String(method || '').toUpperCase();
  for (const r of CAPTURE_ROUTES) {
    if (r.method === m && r.path === pathname) return r.capability;
  }
  return null;
}

// Does this token row carry this capability? Defensive about the array shape because it
// arrives from Postgres as text[] and from a fixture as a plain array.
function hasCapability(token, cap) {
  if (!token || !cap) return false;
  const caps = Array.isArray(token.capabilities) ? token.capabilities : [];
  return caps.indexOf(cap) !== -1;
}

// The handler-side half of the enforcement. Belt AND braces: the dispatch already refused a
// token without the capability, and this refuses again from inside the handler, so a route
// wired up in the table but reached by some other path (a future alias, a redirect, a
// refactor that moves the auth) still cannot act.
function assertCapability(token, cap) {
  if (!CAPABILITY_SET.has(cap)) {
    return { ok: false, error: `"${cap}" is not one of the capture capabilities (${CAPABILITIES.join(', ')})` };
  }
  if (!hasCapability(token, cap)) {
    return { ok: false, error: `this capture token does not carry "${cap}"` };
  }
  return { ok: true };
}

// Minting only ever produces the full set. Kept as a function rather than a constant so a
// caller cannot mutate the exported array and widen every future token.
function fullCapabilitySet() {
  return CAPABILITIES.slice();
}

// A capability list arriving from anywhere (a stored row, a fixture) reduced to the admitted
// set. Anything unrecognised is DROPPED, never carried: a token row that somehow acquired a
// fourth string must not be able to use it.
function admittedCapabilities(list) {
  const out = [];
  for (const c of Array.isArray(list) ? list : []) {
    if (CAPABILITY_SET.has(c) && out.indexOf(c) === -1) out.push(c);
  }
  return out;
}

// ── ROLE: ONE PICKER, NOT TWO BOOLEANS ──────────────────────────────────────
// Server, or Client 01–10. Clients occupy .11–.20 on a /27 site (the derived octet is 10 + n),
// so 01–10 is exactly the addressable range and not a number somebody chose.
//
// One WIRE FIELD carries it — `role` — because two booleans (is_server / client_number) have
// a fourth state that means nothing, and the kit's UI is one dropdown.
const CLIENT_SLOT_MIN = 1;
const CLIENT_SLOT_MAX = 10;

const ROLE_VALUES = Object.freeze((() => {
  const out = ['server'];
  for (let n = CLIENT_SLOT_MIN; n <= CLIENT_SLOT_MAX; n++) out.push(`client-${String(n).padStart(2, '0')}`);
  return out;
})());

// 'server' -> { kind:'server', slot:null }; 'client-03' -> { kind:'client', slot:3 }.
// Anything else is refused, never coerced: "3" or "client-3" or "Client-03" from a kit is a
// bug in the kit, and parsing it hides the class of bug the closed list exists to catch.
function parseRole(value) {
  if (value === 'server') return { ok: true, kind: 'server', slot: null, role: 'server' };
  if (typeof value === 'string') {
    const m = /^client-(\d{2})$/.exec(value);
    if (m) {
      const slot = Number(m[1]);
      if (Number.isInteger(slot) && slot >= CLIENT_SLOT_MIN && slot <= CLIENT_SLOT_MAX) {
        return { ok: true, kind: 'client', slot, role: value };
      }
    }
  }
  return {
    ok: false,
    error: `role must be exactly one of: ${ROLE_VALUES.join(', ')}`,
  };
}

function formatRole(kind, slot) {
  if (kind === 'server') return 'server';
  if (kind === 'client' && Number.isInteger(Number(slot))) return `client-${String(Number(slot)).padStart(2, '0')}`;
  return null;
}

// The address a role will end up on, derived exactly as pharmacy_vms_v derives it: the server
// is the site's server_ip (.10 by default), a client is (10 + n) on a /27 site and (20 + n) on
// a legacy /24. Returned so the kit's picker can SHOW the address beside the slot — an
// engineer who can see ".13" against Client 03 will not mis-pick.
//
// Advisory only. Nothing is addressed from this; the import step reads the view.
function roleAddress(pharmacy, kind, slot) {
  if (!pharmacy) return null;
  if (kind === 'server') return pharmacy.server_ip || null;
  const idx = Number(pharmacy.idx);
  const n = Number(slot);
  if (!Number.isInteger(idx) || !Number.isInteger(n)) return null;
  const base = Number(pharmacy.prefix_len) >= 27 ? 10 : 20;
  return `10.200.${idx}.${base + n}`;
}

// ── image formats: a closed list, because the SERVER names the file ─────────
// The kit declares which of these it produced; the server appends the matching extension to
// the filename IT chose. The kit never composes a path.
const IMAGE_FORMATS = Object.freeze(['qcow2', 'raw', 'vmdk']);
const IMAGE_EXTENSIONS = Object.freeze({ qcow2: '.qcow2', raw: '.raw', vmdk: '.vmdk' });

// ── lifetimes ───────────────────────────────────────────────────────────────

// 90 minutes: the TOP of the stated 30–90 minute capture duration, so an ORDINARY capture
// needs exactly one token and a refresh is the exception rather than the rhythm. Short enough
// that a token left in a file on a pharmacy PC is worthless by morning.
const TOKEN_TTL_S = 90 * 60;

// 12 hours, and it is a CEILING, not the answer — see ticketExpiry(). It covers an overnight
// visit that starts at 18:00 and finishes at 06:00; the closed-window bound almost always
// makes the real expiry earlier.
const TICKET_TTL_S = 12 * 3600;

// A fresh token every 90 minutes across a 12-hour window is 8. Four more for the reboots the
// guest-agent install forces, and for a kit restarted by an engineer who closed the wrong
// window. Beyond that something is wrong and a person should reissue, which is a cheap thing
// to ask and a loud thing to notice.
const TICKET_REDEEM_MAX = 12;

// ⛔ REFUSE TO ISSUE when the site reopens sooner than this. Starting a 90-minute capture
// inside a 40-minute window strands an engineer mid-run with a dead ticket, at a pharmacy that
// is now open, with a PC that is half-imaged. The refusal is the kind thing.
const MIN_WINDOW_MIN = 90;
// Warn (but issue) below this: the run will fit, but only just.
const WARN_WINDOW_MIN = 120;

// ── secrets ─────────────────────────────────────────────────────────────────
// 32 bytes of CSPRNG, base64url. Shown ONCE, at issue, and stored only as a sha256 — the same
// contract devices.token_hash has, and for the same reason: a database read must not hand
// anybody a working credential.
function mintSecret(prefix) {
  const body = crypto.randomBytes(32).toString('base64url');
  return `${prefix}${body}`;
}

function newTicketSecret() { return mintSecret('wcncap_t_'); }
function newTokenSecret() { return mintSecret('wcncap_k_'); }

function hashSecret(s) {
  return crypto.createHash('sha256').update(String(s || '')).digest('hex');
}

// ── ⛔ THE OUT-OF-HOURS GATE, AS AN ARITHMETIC PROPERTY OF THE TICKET ───────
// Answers "may a ticket be issued for this site right now, and when must it die?".
//
// It reads the SAME signal every other gate in this platform reads —
// openingHours.gateResolved() — rather than inventing a second opinion. That is not tidiness:
// the estate fallback window fills `resolved` and `is_open` for EVERY pharmacy in the estate,
// so a gate that read those would happily declare a site closed on the strength of a guess
// nobody has ever checked, at a pharmacy that is open. This code has made that mistake three
// times (see the W1 note in openingHours.js) and it is not making it a fourth.
//
// Returns { ok, reason, message, window_closes_at, window_remaining_min, window_short }.
const WINDOW_REASONS = Object.freeze([
  'ok', 'hours-unreadable', 'hours-not-entered', 'site-open', 'no-reopen-known', 'window-too-short',
]);

function judgeCaptureWindow(state, nowMs) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const refuse = (reason, message) => ({
    ok: false, reason, message,
    window_closes_at: null, window_remaining_min: null, window_short: null,
  });

  if (!state) {
    return refuse('hours-unreadable',
      'this site\'s opening hours could not be read, so a capture ticket cannot be issued — '
      + 'a capture runs on the pharmacy\'s own PC and must not begin without knowing the site is shut.');
  }
  // ⛔ A GUESS IS NOT AN ANSWER. gateResolved() is false for a site running on the estate
  // fallback, and issuing an out-of-hours ticket off the fallback would mean telling an
  // engineer "this pharmacy is closed" on the strength of an estate default nobody checked
  // against this pharmacy.
  if (!openingHours.gateResolved(state)) {
    return refuse('hours-not-entered',
      'nobody has entered this site\'s opening hours, so Watchman is working from the estate '
      + 'fallback guess — and it will not send an engineer to image a pharmacy PC on a guess. '
      + 'Enter this site\'s hours (or import them from its VoIP time profile), then issue the ticket.');
  }
  if (state.is_open === true) {
    const until = state.next_close_at ? ` It closes at ${new Date(state.next_close_at).toISOString()}.` : '';
    return refuse('site-open',
      `that pharmacy is OPEN and dispensing right now — a capture takes the counter PC out of `
      + `service, so no ticket is issued during trading hours.${until}`);
  }
  if (state.is_open !== false) {
    return refuse('hours-unreadable',
      'this site\'s hours resolved to neither open nor closed, which is not an answer a capture '
      + 'may be started on.');
  }
  const reopen = state.next_open_at ? new Date(state.next_open_at).getTime() : NaN;
  if (!Number.isFinite(reopen)) {
    // ⛔ The bound is the whole safety property. Without a reopening time the ticket cannot be
    // made arithmetically incapable of outliving the closed window, so it is not issued.
    return refuse('no-reopen-known',
      'this site is closed but Watchman cannot tell when it next opens, so a ticket cannot be '
      + 'bounded to the closed window — and an unbounded capture credential on a pharmacy PC is '
      + 'the thing this whole design exists to prevent.');
  }
  const remainingMin = Math.floor((reopen - now) / 60000);
  const closesAt = new Date(reopen).toISOString();
  if (remainingMin < MIN_WINDOW_MIN) {
    return {
      ok: false, reason: 'window-too-short',
      message: `that pharmacy reopens in ${remainingMin} minute(s) and a capture takes up to `
             + `${MIN_WINDOW_MIN}. Starting one now leaves an engineer mid-run at an open counter, `
             + 'so the ticket is refused rather than issued short.',
      window_closes_at: closesAt,
      window_remaining_min: remainingMin,
      window_short: true,
    };
  }
  return {
    ok: true, reason: 'ok', message: null,
    window_closes_at: closesAt,
    window_remaining_min: remainingMin,
    // Issued, but the kit and the screen are told: this run will fit, but only just.
    window_short: remainingMin < WARN_WINDOW_MIN,
  };
}

// The ticket's expiry: the EARLIER of the ordinary TTL and the moment the pharmacy reopens.
// This is where "out of hours only" stops being a check and becomes arithmetic.
function ticketExpiry(nowMs, windowClosesAtIso) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const ttlEnd = now + TICKET_TTL_S * 1000;
  const windowEnd = windowClosesAtIso ? new Date(windowClosesAtIso).getTime() : NaN;
  const end = Number.isFinite(windowEnd) ? Math.min(ttlEnd, windowEnd) : ttlEnd;
  return new Date(end).toISOString();
}

// A token never outlives the ticket that minted it. A ticket bounded to 20 minutes before
// opening does not get to mint a 90-minute token.
function tokenExpiry(nowMs, ticketExpiresAt) {
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const ttlEnd = now + TOKEN_TTL_S * 1000;
  const tEnd = ticketExpiresAt ? new Date(ticketExpiresAt).getTime() : NaN;
  const end = Number.isFinite(tEnd) ? Math.min(ttlEnd, tEnd) : ttlEnd;
  return new Date(end).toISOString();
}

// ── ticket state, read rather than re-derived ───────────────────────────────
// One function decides whether a ticket row may still be redeemed, so the screen that lists
// tickets and the route that redeems one cannot disagree.
function ticketState(row, nowMs) {
  if (!row) return 'unknown';
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  if (row.revoked_at) return 'revoked';
  if (row.expires_at && new Date(row.expires_at).getTime() <= now) return 'expired';
  if (Number(row.redeem_count || 0) >= Number(row.redeem_max || 0)) return 'spent';
  return 'open';
}

// ── ⛔ THE UPLOAD DESTINATION — THE SERVER NAMES IT, ALWAYS ─────────────────
// The kit never composes a path, and there is no default it falls back to on its own.
//
// WHY VIGILANT CANNOT SIMPLY KNOW IT. Vigilant has no route to the Proxmox API — it sits on
// the DMZ VLAN with no path to the management VLAN, which is why the whole Proxmox
// integration is a collector pushing outward. So the drop directory is REPORTED BY THE NODE
// ITSELF on the reply-bearing call the collector already makes (POST /proxmox/report), stored,
// and handed back here. That makes the path ground truth from the machine that owns it rather
// than a string Vigilant guessed — and it is the same "ride the outward call" rule the job
// hand-out follows.
//
// ⛔ THE DOCUMENTED NFS SHARE IS DEAD. The working target is a drop directory on the node's
// LOCAL storage. A reported target that says it is on NFS/CIFS is refused BY NAME below —
// refused because the far end said so, not because we pattern-matched a path.
const DEAD_FS_TYPES = Object.freeze(['nfs', 'nfs3', 'nfs4', 'cifs', 'smbfs', 'smb3']);

// Head-room the node must show before we will name it as a destination. A 250 GB source disk
// shrinks to roughly 200 GB (MEASURED 2026-08-25: one site costs about 197 GB), and a transfer
// that fills the node's root filesystem takes the node down, not just the capture.
const MIN_FREE_BYTES = 220 * 1024 * 1024 * 1024;

// The filename, chosen HERE. Site code + role + an ISO-ish stamp, so two captures of the same
// role never collide and a directory listing on the node is readable by a person at 3am.
//
// ⚠️ THE PC NAME IS NOT IN IT. It is provenance only — it survives P2V, so duplicates across
// the estate are likely and a filename built from it would collide silently.
function captureFilename(code, role, format, atIso) {
  const safeCode = String(code || 'UNKNOWN').replace(/[^A-Za-z0-9._-]/g, '').slice(0, 32) || 'UNKNOWN';
  const safeRole = String(role || 'unknown').replace(/[^a-z0-9-]/g, '').slice(0, 16) || 'unknown';
  const d = atIso ? new Date(atIso) : new Date();
  const stamp = (Number.isFinite(d.getTime()) ? d : new Date()).toISOString()
    .replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const ext = IMAGE_EXTENSIONS[format] || '.img';
  return `${safeCode}-${safeRole}-${stamp}${ext}`;
}

// Turn a stored drop-target row into the contract the kit obeys — or into a NAMED REFUSAL.
// It never returns a partially-usable object: either the kit has a path it may write to, or
// it has a reason and falls back to the USB it runs from.
//
// ⛔ NEVER GUESS. A node that has not reported a drop directory produces
// { ok:false, reason:'no-target-reported' } and NOT a plausible '/var/lib/vz/dump'. A guessed
// path is how a 70 GB image lands somewhere nobody looks.
function shapeUploadTarget(target, opts) {
  const o = opts || {};
  const refuse = (reason, message) => Object.freeze({
    ok: false, reason, message, target: null,
  });

  if (!target || !target.dir) {
    return refuse('no-target-reported',
      'no Proxmox node has reported a capture drop directory yet, so Watchman will not name '
      + 'one — it has no route to the cluster and a guessed path is how an image lands where '
      + 'nobody looks. Copy the image to the USB the kit runs from; the node collector reports '
      + 'its drop directory on its next push and the destination appears here.');
  }
  if (target.read_error) {
    return refuse('target-unreadable',
      `the node reported its drop directory but could not read it: ${String(target.read_error).slice(0, 200)}`);
  }
  const fsType = String(target.fs_type || '').toLowerCase();
  if (fsType && DEAD_FS_TYPES.indexOf(fsType) !== -1) {
    // The documented NFS share is dead. This is the refusal that says so out loud, to the kit,
    // at the moment it matters — rather than a 70 GB write that stalls at 4%.
    return refuse('target-is-network-storage',
      `that node's drop directory is on ${fsType}, and the documented network share is DEAD — `
      + 'the working target is a directory on the node\'s LOCAL storage. Point the collector at '
      + 'local storage and it will be offered here.');
  }
  if (target.writable === false) {
    return refuse('target-not-writable',
      'the node reported its drop directory as not writable.');
  }
  const free = target.free_bytes == null ? null : Number(target.free_bytes);
  if (free != null && Number.isFinite(free) && free < MIN_FREE_BYTES) {
    return refuse('target-short-on-space',
      `that node's drop directory has ${Math.round(free / 1e9)} GB free and one site costs about `
      + `${Math.round(MIN_FREE_BYTES / 1e9)} GB. Free space on the node or copy to the USB the kit runs from.`);
  }

  const dir = String(target.dir).replace(/\/+$/, '');
  const filename = o.filename || captureFilename(o.code, o.role, o.format, o.startedAt);
  return Object.freeze({
    ok: true,
    reason: 'ok',
    message: null,
    target: Object.freeze({
      // A closed one-value list. The kit switches on this and must fail loudly, not silently
      // improvise, if it ever sees a kind it does not implement.
      kind: 'proxmox-drop-dir',
      node: target.node,
      storage: target.storage_name || null,
      dir,
      filename,
      // The one string the kit writes to. Composed HERE so the kit never joins a path.
      path: `${dir}/${filename}`,
      // 'node-reported' is ground truth from the machine that owns the directory.
      // 'configured' is a human naming it in Vigilant's env because that node's collector has
      // not been upgraded yet. Both are the server naming the path; the kit is told WHICH so a
      // screen can say so, and so a stale configured value is findable.
      source: target.source === 'configured' ? 'configured' : 'node-reported',
      reported_at: target.reported_at || null,
      free_bytes: free,
      min_free_bytes: MIN_FREE_BYTES,
      // ⚠️ RESUMABLE IS NOT OPTIONAL. A 70 GB transfer over a pharmacy line WILL be
      // interrupted. The kit stats the destination, resumes from its length, and reports
      // bytes_sent against the same capture record — which is why register is an UPSERT and
      // not a create.
      resumable: true,
      resume: Object.freeze({
        probe: 'stat',
        append: true,
        // Re-register with the same role and the same ticket to be handed this same path back.
        reregister: 'POST /capture/register',
      }),
      // The kit may always take this road instead, and the baseline says so: "direct, or copy
      // to the USB the kit runs from".
      usb_fallback_ok: true,
    }),
  });
}

// ── the cleaner for what a node reports about its drop directory ────────────
// Same posture as cleanNodeCapacityRow in handlers.js: a figure the collector could not
// establish arrives as null and is stored as null, NEVER as 0. "This directory is completely
// full" and "we could not read this directory" are different facts and exactly one of them
// stops a capture.
function cleanDropTargetRow(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  const text = (v, max) => (typeof v === 'string' && v.trim() ? v.trim().replace(/[^\x20-\x7e]/g, '').slice(0, max || 200) : null);
  const node = text(r.node, 200);
  const dir = text(r.dir, 512);
  if (!node || !dir) return null;
  // An absolute path or nothing. A relative path is meaningless to a kit on another machine.
  if (dir[0] !== '/') return null;
  const num = (v) => {
    if (v == null) return null;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? n : null;
  };
  return {
    node,
    storage_name: text(r.storage_name, 200),
    dir,
    fs_type: text(r.fs_type, 32) ? text(r.fs_type, 32).toLowerCase() : null,
    free_bytes: num(r.free_bytes),
    total_bytes: num(r.total_bytes),
    writable: typeof r.writable === 'boolean' ? r.writable : null,
    read_error: text(r.read_error, 500),
  };
}

// ── wire shapes, one definition each (B9) ───────────────────────────────────
// The same lesson pmr_site_captures learned the hard way: numeric(10,2) comes back from
// node-postgres as a STRING, and a kit that writes then reads back its own response gets a
// string where a checklist compares a number.

// ⛔ THE SECRET IS NEVER IN HERE. Not on issue (the handler adds it once, explicitly), not on
// list, not ever. If this function grows a secret field, every ticket list in Watchman becomes
// a credential dump.
function shapeTicket(row, nowMs) {
  if (!row) return null;
  return {
    id: row.id,
    pharmacy_id: row.pharmacy_id == null ? null : Number(row.pharmacy_id),
    state: ticketState(row, nowMs),
    issued_by: row.issued_by,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    // What the expiry was clamped to, so a screen can say "it dies when the pharmacy opens"
    // rather than showing an unexplained early time.
    window_closes_at: row.window_closes_at || null,
    redeem_max: row.redeem_max == null ? null : Number(row.redeem_max),
    redeem_count: row.redeem_count == null ? null : Number(row.redeem_count),
    last_redeemed_at: row.last_redeemed_at || null,
    revoked_at: row.revoked_at || null,
    revoked_by: row.revoked_by || null,
    note: row.note || null,
  };
}

function shapeRun(row) {
  if (!row) return null;
  return {
    role: formatRole(row.role_kind, row.role_slot),
    role_kind: row.role_kind,
    role_slot: row.role_slot == null ? null : Number(row.role_slot),
    started_at: row.started_at,
    // null while it is still running. (started_at, uploaded_at) is what separates "in
    // progress" from "held", and nothing else says it.
    uploaded_at: row.uploaded_at,
    // ⚠️ PROVENANCE ONLY, NEVER A KEY. A PC name survives P2V, so duplicates across the estate
    // are likely. Nothing joins on this, nothing addresses from it, no filename contains it.
    source_pc_name: row.source_pc_name || null,
    disk_gb: row.disk_gb == null ? null : Number(row.disk_gb),
    image_format: row.image_format || null,
    image_sha256: row.image_sha256 || null,
    bytes_total: row.bytes_total == null ? null : Number(row.bytes_total),
    bytes_sent: row.bytes_sent == null ? null : Number(row.bytes_sent),
    upload_target: row.upload_target || null,
    // ⚠️ TRI-STATE, AND IT MUST STAY TRI-STATE. null is "not established", which is NOT false.
    // A false all-clear on printers_cleared is a site imported with the pharmacy's old
    // printers still installed — the thing the capture step exists to prevent.
    guest_agent_installed: row.guest_agent_installed,
    printers_cleared: row.printers_cleared,
    slimmed: row.slimmed,
    taken_by: row.taken_by || null,
    // Decided by the SERVER from the site's own hours at the moment of the call, never taken
    // from the kit's body. A tool asserting its own compliance is not evidence of it.
    out_of_hours: row.out_of_hours,
    failed_reason: row.failed_reason || null,
    ticket_id: row.ticket_id || null,
    updated_at: row.updated_at || null,
  };
}

// ── the site roll-up, DERIVED from the runs ─────────────────────────────────
// GET /pharmacies/:id/capture predates roles and answers ONE question for a build checklist:
// "what capture does Watchman hold for this site?". Leaving it untouched while the kit wrote
// role rows would make it answer "none held" while five captures existed — a false negative,
// and this file's whole preamble is about a checklist that must never invent its own evidence.
//
// So the roll-up is recomputed from the runs on every register.
//
// ⛔ THE SAFETY FLAGS AGGREGATE PESSIMISTICALLY, IN THIS ORDER: any false -> false; else any
// null -> null; else true. "Every machine we checked was clean, and we did not check two of
// them" is NOT "the site is clean".
function rollUpFlag(values) {
  let sawNull = false;
  for (const v of values) {
    if (v === false) return false;
    if (v !== true) sawNull = true;
  }
  return sawNull ? null : true;
}

function rollUpRuns(runs) {
  const list = Array.isArray(runs) ? runs : [];
  if (!list.length) return null;
  const server = list.find((r) => r.role_kind === 'server') || null;
  const times = list.map((r) => (r.started_at ? new Date(r.started_at).getTime() : NaN)).filter(Number.isFinite);
  // ⚠️ uploaded_at is the LAST one only when EVERY run has one. A site with one run still
  // transferring is not a site whose capture is held.
  const allUploaded = list.every((r) => !!r.uploaded_at);
  const uploads = list.map((r) => (r.uploaded_at ? new Date(r.uploaded_at).getTime() : NaN)).filter(Number.isFinite);
  const disks = list.map((r) => (r.disk_gb == null ? NaN : Number(r.disk_gb))).filter(Number.isFinite);
  return {
    started_at: times.length ? new Date(Math.min(...times)).toISOString() : null,
    uploaded_at: allUploaded && uploads.length ? new Date(Math.max(...uploads)).toISOString() : null,
    // The SERVER's PC name is the site-level one when there is a server run — it is the
    // machine the site is named after. Still provenance only.
    source_hostname: (server && server.source_pc_name) || null,
    // The site's real cost on the node: every image it will host, summed. Null when nothing
    // measured one — never 0, which would read as "measured, and it costs nothing".
    disk_gb: disks.length ? Math.round(disks.reduce((a, b) => a + b, 0) * 100) / 100 : null,
    guest_agent_installed: rollUpFlag(list.map((r) => r.guest_agent_installed)),
    printers_cleared: rollUpFlag(list.map((r) => r.printers_cleared)),
    taken_by: (server && server.taken_by) || (list[0] && list[0].taken_by) || null,
    // Any run that ran during trading hours makes the site's capture an in-hours one. This is
    // the one flag where "any" rather than "all" is the honest reading.
    out_of_hours: rollUpFlag(list.map((r) => r.out_of_hours)),
  };
}

module.exports = {
  CAPABILITIES,
  CAPTURE_ROUTES,
  capabilityForRoute,
  hasCapability,
  assertCapability,
  fullCapabilitySet,
  admittedCapabilities,
  ROLE_VALUES,
  CLIENT_SLOT_MIN,
  CLIENT_SLOT_MAX,
  parseRole,
  formatRole,
  roleAddress,
  IMAGE_FORMATS,
  IMAGE_EXTENSIONS,
  TOKEN_TTL_S,
  TICKET_TTL_S,
  TICKET_REDEEM_MAX,
  MIN_WINDOW_MIN,
  WARN_WINDOW_MIN,
  MIN_FREE_BYTES,
  DEAD_FS_TYPES,
  WINDOW_REASONS,
  newTicketSecret,
  newTokenSecret,
  hashSecret,
  judgeCaptureWindow,
  ticketExpiry,
  tokenExpiry,
  ticketState,
  captureFilename,
  shapeUploadTarget,
  cleanDropTargetRow,
  shapeTicket,
  shapeRun,
  rollUpFlag,
  rollUpRuns,
};
