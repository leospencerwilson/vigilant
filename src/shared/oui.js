'use strict';

// Vigilant — MAC OUI -> vendor lookup.
//
// The ingest fills mac_hosts.vendor from the first three octets (the OUI) of each
// learned MAC. This is a deliberately small, hand-curated seed of vendors we
// actually see on Allied / Cegedim / WCN LANs (MikroTik routers, Yealink phones,
// the usual PC/printer/AP makers). It is NOT the full IEEE registry — unknown OUIs
// return null and simply leave the column blank. Keep SEED as its own const so it
// can grow without touching the lookup logic.

// OUI keys are stored in canonical upper-case colon-separated form ("AC:CF:23").
const SEED = {
  // MikroTik (routers/switches — these ARE our fleet)
  'CC:2D:E0': 'MikroTik',
  '48:8F:5A': 'MikroTik',
  'B8:69:F4': 'MikroTik',
  '64:D1:54': 'MikroTik',
  '74:4D:28': 'MikroTik',
  'DC:2C:6E': 'MikroTik',
  '2C:C8:1B': 'MikroTik',
  '4C:5E:0C': 'MikroTik',
  'E4:8D:8C': 'MikroTik',
  '6C:3B:6B': 'MikroTik',
  // Yealink (VoIP handsets — Western Communication's bread and butter)
  'AC:CF:23': 'Yealink',
  '80:5E:C0': 'Yealink',
  '24:9A:D8': 'Yealink',
  '00:15:65': 'Yealink',
  // Hewlett Packard / HP Enterprise / Aruba
  '3C:D9:2B': 'HP',
  '70:5A:0F': 'HP',
  '94:57:A5': 'HP',
  '00:1B:78': 'HP',
  'B0:5A:DA': 'HP',
  // Dell
  '00:14:22': 'Dell',
  'B8:2A:72': 'Dell',
  'F8:BC:12': 'Dell',
  '18:DB:F2': 'Dell',
  // Cisco / Cisco Meraki
  '00:1A:A1': 'Cisco',
  '00:25:45': 'Cisco',
  'F4:CF:E2': 'Cisco',
  '00:18:0A': 'Cisco Meraki',
  'E0:55:3D': 'Cisco Meraki',
  // Ubiquiti
  '24:A4:3C': 'Ubiquiti',
  'FC:EC:DA': 'Ubiquiti',
  '74:83:C2': 'Ubiquiti',
  '78:8A:20': 'Ubiquiti',
  // TP-Link (cheap APs/switches turn up on sites)
  '50:C7:BF': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  // Printers
  '00:00:48': 'Epson',
  '00:80:77': 'Brother',
  '00:26:73': 'Canon',
  '00:1E:8F': 'Canon',
  '08:00:37': 'Fuji Xerox',
  // Apple / Samsung / Intel (common endpoints + NICs)
  'AC:BC:32': 'Apple',
  'F0:18:98': 'Apple',
  '3C:5A:B4': 'Samsung',
  'B4:79:A7': 'Samsung',
  '00:1B:21': 'Intel',
  '3C:97:0E': 'Intel',
};

/**
 * Normalise the first three octets of a MAC to the canonical OUI key form,
 * e.g. "ac-cf-23-11-22-33" / "accf23112233" -> "AC:CF:23". Returns null unless at
 * least 6 hex digits (3 octets) are present. Separator- and case-insensitive.
 */
function ouiKey(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length < 6) return null;
  const up = hex.slice(0, 6).toUpperCase();
  return up.slice(0, 2) + ':' + up.slice(2, 4) + ':' + up.slice(4, 6);
}

/**
 * ouiVendor(mac) -> vendor string | null
 * Looks up the vendor for a MAC's OUI in SEED. Case- and separator-insensitive.
 * Unknown OUI (or unparseable MAC) -> null.
 */
function ouiVendor(mac) {
  const key = ouiKey(mac);
  if (key === null) return null;
  return Object.prototype.hasOwnProperty.call(SEED, key) ? SEED[key] : null;
}

// ── external OUI resolution (resolveVendor) ──────────────────────────────────────────
//
// resolveVendor(mac) resolves a MAC to a vendor in three tiers — seed -> in-process cache
// -> external API — for the admin /oui/:mac endpoint. The bulk ingest path stays on the
// synchronous ouiVendor(seed-only): we never block telemetry writes on a network call, and
// we never fan a fleet's worth of MACs out to a rate-limited free API.
//
// PRIVACY: only the 3-octet OUI prefix is ever sent to the external service, NEVER the full
// MAC. The cache is keyed by that prefix too, so the host portion never leaves the process.
//
// RATE LIMIT: api.macvendors.com is free and ~2 req/s. We cache BOTH hits and misses
// (vendor:null) so a repeated or unknown prefix never re-hits the API — that is the only
// throttle (no artificial sleeps). Cache lives for the process lifetime.
//
// FAIL SAFE: never throws and never rejects to the caller. Any timeout / network error /
// non-2xx / 404 resolves to {vendor:null, source:'none'}. A container with no outbound
// internet therefore still returns cleanly (null), it just can't enrich beyond the seed.

const OUI_API_BASE = 'https://api.macvendors.com/';
const OUI_API_TIMEOUT_MS = 3000;

// prefix -> { vendor: string|null, source: 'api', at: epochMs }. Seed/cache 'source' on a
// returned record is decided by resolveVendor; we only ever store API outcomes here.
const _cache = new Map();

// Test seam: resolveVendor calls global fetch lazily (so tests can monkeypatch global.fetch)
// and only when Node actually exposes one. Node 20+/24 ship a global fetch.

/**
 * resolveVendor(mac) -> Promise<{ mac, oui, vendor, source }>
 *   source: 'seed' | 'cache' | 'api' | 'none'
 * Resolution order: (1) local SEED; (2) in-process cache; (3) external API.
 * `mac` echoes the normalised upper-case colon form of the input (or the raw input when it
 * has no parseable OUI); `oui` is the 3-octet prefix (or null). Never throws.
 */
async function resolveVendor(mac) {
  const key = ouiKey(mac);

  // Unparseable input: nothing to resolve. Echo the input back, null everything else.
  if (key === null) {
    return { mac: typeof mac === 'string' ? mac : null, oui: null, vendor: null, source: 'none' };
  }

  // (1) seed.
  if (Object.prototype.hasOwnProperty.call(SEED, key)) {
    return { mac: ouiFull(mac, key), oui: key, vendor: SEED[key], source: 'seed' };
  }

  // (2) in-process cache (hits AND misses are cached, so an unknown prefix never re-hits).
  if (_cache.has(key)) {
    const c = _cache.get(key);
    return { mac: ouiFull(mac, key), oui: key, vendor: c.vendor, source: 'cache' };
  }

  // (3) external API — prefix only. Any failure -> null + cache the miss + source 'none'.
  const vendor = await fetchVendor(key);
  _cache.set(key, { vendor, source: 'api', at: Date.now() });
  return { mac: ouiFull(mac, key), oui: key, vendor, source: vendor === null ? 'none' : 'api' };
}

/**
 * Fetch a vendor for an OUI prefix from the external API. Returns the trimmed vendor string
 * on a 2xx with a non-empty body, or null on ANY error/timeout/404/non-2xx/empty body.
 * NEVER throws. Sends ONLY the prefix.
 */
async function fetchVendor(prefix) {
  if (typeof fetch !== 'function') return null; // no global fetch (shouldn't happen on Node 20+)
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OUI_API_TIMEOUT_MS);
  try {
    const res = await fetch(OUI_API_BASE + encodeURIComponent(prefix), {
      signal: controller.signal,
      headers: { accept: 'text/plain' },
    });
    if (!res || !res.ok) return null; // 404 (unknown OUI) and any non-2xx -> miss
    const body = await res.text();
    const vendor = typeof body === 'string' ? body.trim() : '';
    return vendor === '' ? null : vendor;
  } catch (e) {
    return null; // timeout / abort / network / DNS / offline — all fail safe to null
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Render the full MAC in canonical upper-case colon form when the input carried all 6 octets,
 * else fall back to the OUI prefix. Keeps the contract's `mac` field stable/normalised without
 * pulling in transform.js (avoids a cycle; transform.normaliseMac requires exactly 12 hex).
 */
function ouiFull(mac, key) {
  if (typeof mac !== 'string') return key;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length < 12) return key; // bare OUI (or short) -> echo the prefix
  const up = hex.slice(0, 12).toUpperCase();
  const octets = [];
  for (let i = 0; i < 12; i += 2) octets.push(up.slice(i, i + 2));
  return octets.join(':');
}

module.exports = {
  ouiVendor,
  resolveVendor,
  ouiKey,
  SEED,
  // exposed for tests to assert no-redundant-fetch behaviour / reset between cases
  _cache,
};
