'use strict';

// Vigilant — CAN THIS NODE HOST ANOTHER PHARMACY? The one place that answer is computed.
//
// ⛔ THE RULE THIS FILE EXISTS TO ENFORCE: an unreported figure is UNKNOWN, never zero and
// never "fine". Nothing in the estate feed reported a Proxmox node's headroom until now, so
// every screen that talked about capacity was talking about VM disks inside guests. A missing
// number therefore has to answer "we cannot tell", because the alternative — treating absent
// as zero, or absent as room — is a site build that either never starts or starts onto a node
// that cannot hold it.
//
// THE MEASURED NUMBERS, taken 2026-08-25 and carried here so the arithmetic is auditable:
//
//   wcn-zfs free            143 GB          the pool a site would be placed on
//   one site costs about    197 GB          server + desktops, as built today
//   node RAM free            67 GB of 188
//
// Those two together are the whole point: 143 < 197, so the next site does NOT fit on wcn-zfs
// today, and Watchman must say so with the resource named rather than starting an import that
// fills a pool a live pharmacy is trading on.

const GB = 1024 * 1024 * 1024;

// ── what a site costs ────────────────────────────────────────────────────────
// The standard build, and it is a STANDARD, not a measurement of one site: a PMR server plus
// one desktop per counter.
//
// RAM is the documented estate standard (the 12 GB server / 6 GB client pair the VM screens
// check against). Storage is the MEASURED 197 GB for a whole site as built on 2026-08-25 —
// stated as one figure rather than split per VM because that is how it was measured, and
// splitting it would be inventing a breakdown nobody took.
const SERVER_MEM_BYTES = 12 * GB;
const CLIENT_MEM_BYTES = 6 * GB;
const SITE_STORAGE_BYTES = 197 * GB;

// A site with no counters registered yet still costs a server. `counters` is what the caller
// knows; when it knows nothing it should say so rather than pass 0 — hence the explicit
// default of one desktop, which is the smallest real site.
function siteCost({ counters } = {}) {
  const desktops = Number.isInteger(counters) && counters >= 0 ? counters : 1;
  return {
    counters: desktops,
    mem_bytes: SERVER_MEM_BYTES + desktops * CLIENT_MEM_BYTES,
    storage_bytes: SITE_STORAGE_BYTES,
    // Said in words next to the numbers, because a refusal that only prints bytes makes an
    // engineer do this arithmetic again on a whiteboard.
    explain: `a PMR server (${SERVER_MEM_BYTES / GB} GB) plus ${desktops} desktop`
      + `${desktops === 1 ? '' : 's'} at ${CLIENT_MEM_BYTES / GB} GB, and about `
      + `${SITE_STORAGE_BYTES / GB} GB of pool space for the whole site `
      + '(measured 2026-08-25)',
  };
}

// How old a reading may be before it stops being evidence. The Proxmox collector ticks every
// 15 minutes and its timer carries an explicit do-not-shorten warning, so this allows two
// missed ticks — the same sizing pmrVerbs uses for anything confirmed from that collector.
const CAPACITY_STALE_S = 45 * 60;

// ── the judgement ────────────────────────────────────────────────────────────
// Three verdicts and no fourth:
//
//   'fits'     every resource the site needs was MEASURED and every one has room.
//   'short'    a resource was measured and it is not enough. `short` names which, with the
//              numbers, so the refusal can be read out loud.
//   'unknown'  a resource was not measured, or the reading is stale. NOT a refusal and NOT an
//              approval — the caller must say "we cannot tell" and name what is missing.
//
// `unknown` beats `fits` and `short` beats nothing: a node that is short on a measured
// resource is short, whatever else went unread — knowing one blocker is enough to refuse.
function judgeNodeForSite(cap, need, now = Date.now()) {
  const missing = [];
  const short = [];
  if (!cap || typeof cap !== 'object') {
    return {
      verdict: 'unknown',
      short: [],
      missing: ['memory', 'storage'],
      reason: 'nothing reports this node\'s free memory or free pool space, so whether it can '
            + 'host another site cannot be established',
    };
  }

  const measuredAt = cap.measured_at ? Date.parse(cap.measured_at) : NaN;
  const stale = Number.isFinite(measuredAt)
    ? (now - measuredAt) > CAPACITY_STALE_S * 1000
    : true;

  const check = (label, free, want) => {
    // A figure the collector could not establish is null. Zero is a MEASUREMENT — "this pool
    // is completely full" — and the two must not collapse into one another.
    if (free == null || !Number.isFinite(Number(free))) { missing.push(label); return; }
    if (stale) { missing.push(label); return; }
    if (Number(free) < want) short.push({ resource: label, free_bytes: Number(free), need_bytes: want });
  };

  check('memory', cap.mem_free_bytes, need.mem_bytes);
  check('storage', cap.storage_free_bytes, need.storage_bytes);

  if (short.length) {
    const named = short
      .map((s) => `${s.resource}: ${gb(s.free_bytes)} GB free, ${gb(s.need_bytes)} GB needed`)
      .join('; ');
    return {
      verdict: 'short',
      short,
      missing,
      reason: `${cap.node || 'that node'} cannot host this site — ${named}`,
    };
  }
  if (missing.length) {
    return {
      verdict: 'unknown',
      short: [],
      missing,
      reason: stale && Number.isFinite(measuredAt)
        ? `the last capacity reading for ${cap.node || 'that node'} is older than `
          + `${Math.round(CAPACITY_STALE_S / 60)} minutes, so its headroom cannot be `
          + 'established — treat it as unknown, not as free'
        : `${cap.node || 'that node'} does not report ${missing.join(' or ')}, so whether it `
          + 'can host this site cannot be established',
    };
  }
  return {
    verdict: 'fits',
    short: [],
    missing: [],
    reason: `${cap.node || 'that node'} has room: ${gb(cap.mem_free_bytes)} GB of memory and `
          + `${gb(cap.storage_free_bytes)} GB on ${cap.storage_name || 'its pool'} free, `
          + `against ${gb(need.mem_bytes)} GB and ${gb(need.storage_bytes)} GB needed`,
  };
}

// One decimal place. A refusal that reads "143.0 GB free, 197.0 GB needed" is a sentence an
// engineer can check against `pvesh`, which a byte count is not.
function gb(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '?';
  return (n / GB).toFixed(1);
}

module.exports = {
  GB,
  SERVER_MEM_BYTES,
  CLIENT_MEM_BYTES,
  SITE_STORAGE_BYTES,
  CAPACITY_STALE_S,
  siteCost,
  judgeNodeForSite,
  gb,
};
