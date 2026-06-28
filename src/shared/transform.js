'use strict';

// Vigilant — pure transform helpers (NO IO). The heart of the test suite.
//
// Everything here is deterministic and side-effect free so it can be unit-tested
// in isolation: the ingest handler reads state via the store, then leans on these
// functions to derive bps, classify interface roles, parse the loose values the
// agent emits, join the L2 host tables, and verify config-job checksums.

const crypto = require('node:crypto');

// ── numeric / IP parsing ─────────────────────────────────────────────
// The agent emits some numbers as bare JSON numbers, some as quoted strings,
// and some absent values as the literal string "null" or "". Coerce safely.

/**
 * parseNum(v) -> number|null
 * Accepts numbers and numeric strings ("-65", "41.5"). Treats "", "null", null,
 * undefined, NaN and any non-numeric value as null. Never throws.
 */
function parseNum(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'boolean') return null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (s === '' || s.toLowerCase() === 'null') return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/**
 * parseIp(v) -> string|null
 * Strips a CIDR /mask (e.g. "1.2.3.4/24" -> "1.2.3.4"). Maps "", "null", null,
 * undefined to null. Returns the bare address string otherwise (no validation —
 * Postgres `inet` is the final arbiter; the goal here is normalisation).
 */
function parseIp(v) {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string') return null;
  let s = v.trim();
  if (s === '' || s.toLowerCase() === 'null') return null;
  const slash = s.indexOf('/');
  if (slash !== -1) s = s.slice(0, slash);
  s = s.trim();
  if (s === '') return null;
  return s;
}

// ── throughput delta ─────────────────────────────────────────────────

/**
 * deltaBps(prevBytes, prevAtMs, curBytes, curAtMs) -> number|null
 * Bits/sec between two cumulative byte-counter samples.
 *   - null if prev is missing (prevBytes or prevAtMs null/undefined) → first tick
 *   - null if Δt <= 0 (curAt <= prevAt) → zero/negative time, can't divide
 *   - null if cur < prev → counter reset / wrap, no negative spikes
 * Otherwise (curBytes - prevBytes) * 8 / (Δt seconds), rounded to an integer
 * (interface_state.rx_bps/tx_bps are bigint).
 */
function deltaBps(prevBytes, prevAtMs, curBytes, curAtMs) {
  const prev = parseNum(prevBytes);
  const cur = parseNum(curBytes);
  const prevAt = parseNum(prevAtMs);
  const curAt = parseNum(curAtMs);
  if (prev === null || prevAt === null) return null; // missing previous sample
  if (cur === null || curAt === null) return null;
  const dtMs = curAt - prevAt;
  if (dtMs <= 0) return null; // zero or negative Δt
  if (cur < prev) return null; // counter reset / wrap guard
  const bits = (cur - prev) * 8;
  return Math.round(bits / (dtMs / 1000));
}

// ── interface role classification ────────────────────────────────────

// Interface types that are tunnels / overlays → role 'vpn'.
// NOTE: 'vlan' deliberately stays 'lan' (it is not a tunnel). Matches use either
// an exact type or a known prefix family (l2tp-*, sstp-*, ovpn-*).
// `pppoe-client` is retained (older RouterOS / agent spelling) alongside `pppoe-out`.
const VPN_TYPES = new Set([
  'pppoe-out',
  'pppoe-client',
  'l2tp-out',
  'l2tp-in',
  'sstp-out',
  'sstp-in',
  'ovpn-out',
  'ovpn-in',
  'wireguard',
  'gre',
  'eoip',
  'ipip',
  'vpls',
]);
const VPN_PREFIXES = ['l2tp-', 'sstp-', 'ovpn-'];
// Name substrings that mark a tunnel even when the agent reports a generic/empty type
// (e.g. a dynamic interface whose `type` came through blank but is named "l2tp-allied").
const VPN_NAME_SUBSTRINGS = ['l2tp', 'sstp', 'ovpn', 'gre', 'ipsec'];

function isVpnType(type) {
  if (typeof type !== 'string' || type === '') return false;
  const t = type.toLowerCase();
  if (VPN_TYPES.has(t)) return true;
  for (const p of VPN_PREFIXES) {
    if (t.startsWith(p)) return true;
  }
  return false;
}

function isVpnName(name) {
  if (typeof name !== 'string' || name === '') return false;
  const n = name.toLowerCase();
  for (const s of VPN_NAME_SUBSTRINGS) {
    if (n.includes(s)) return true;
  }
  return false;
}

/**
 * classifyRole(iface) -> 'disabled'|'wan'|'vpn'|'bridge-member'|'lan'|'unused'
 *
 * TYPE-AWARE precedence (first match wins). The ordering deliberately classifies by the
 * interface's actual TYPE before honouring the agent's `is_wan` hint, so a bridge or a
 * tunnel can never be mislabelled 'wan' just because the agent flagged it (a bridge that
 * happens to ride the WAN path, a backup VPN over a WAN, etc.):
 *   1. disabled                                              -> 'disabled'
 *   2. type 'bridge' OR name starts 'bridge'                 -> 'bridge-member'
 *   3. tunnel/overlay type OR name contains l2tp/sstp/ovpn/  -> 'vpn'   (vlan stays lan)
 *      gre/ipsec
 *   4. is_wan && type 'ether' (or 'pppoe-out')               -> 'wan'
 *   5. type 'ether' & !plugged & no bridge                   -> 'unused'
 *   6. else                                                  -> 'lan'
 */
function classifyRole(iface) {
  const i = iface || {};
  if (i.disabled === true) return 'disabled';

  const type = typeof i.type === 'string' ? i.type.toLowerCase() : i.type;
  const name = typeof i.name === 'string' ? i.name : '';
  const bridge = typeof i.bridge === 'string' ? i.bridge.trim() : i.bridge;

  // 2. A bridge itself is a bridge-member of the L2 topology (NOT a wan, even if flagged).
  if (type === 'bridge' || name.toLowerCase().startsWith('bridge')) return 'bridge-member';

  // 3. Tunnels / overlays — by type OR by a tell-tale name substring.
  if (isVpnType(type) || isVpnName(name)) return 'vpn';

  // 4. WAN only when the agent flags it AND it is an actual uplink type (ether or pppoe-out).
  if (i.is_wan === true && (type === 'ether' || type === 'pppoe-out')) return 'wan';

  // 5. An unplugged ethernet port with no bridge membership is unused.
  if (type === 'ether' && i.plugged !== true && !bridge) return 'unused';

  // A non-bridge port that is a member of a bridge is still a bridge-member.
  if (bridge) return 'bridge-member';

  return 'lan';
}

// ── MAC normalisation + L2 host join ─────────────────────────────────

/**
 * normaliseMac(s) -> 'AA:BB:CC:DD:EE:FF' | null
 * Accepts colon/dash/dot separated or bare 12-hex MACs, any case. Returns the
 * canonical upper-case colon-separated form, or null if it is not a 48-bit MAC.
 */
function normaliseMac(s) {
  if (typeof s !== 'string') return null;
  const hex = s.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length !== 12) return null;
  const up = hex.toUpperCase();
  const octets = [];
  for (let i = 0; i < 12; i += 2) octets.push(up.slice(i, i + 2));
  return octets.join(':');
}

/**
 * joinMacHosts(macHosts[], arp[]) -> [{mac, interface, ip|null}]
 * Left-join the bridge host table (mac -> physical port) with ARP (mac -> ip) by
 * normalised MAC. Hosts with no ARP match get ip: null. Rows whose mac fails to
 * normalise are dropped. `mac` in the result is the canonical form.
 */
function joinMacHosts(macHosts, arp) {
  const hosts = Array.isArray(macHosts) ? macHosts : [];
  const arps = Array.isArray(arp) ? arp : [];

  const ipByMac = new Map();
  for (const a of arps) {
    if (!a) continue;
    const m = normaliseMac(a.mac);
    if (!m) continue;
    const ip = parseIp(a.ip);
    if (!ipByMac.has(m)) ipByMac.set(m, ip); // first ARP entry wins
  }

  const out = [];
  for (const h of hosts) {
    if (!h) continue;
    const m = normaliseMac(h.mac);
    if (!m) continue;
    out.push({
      mac: m,
      interface: h.interface != null ? h.interface : null,
      ip: ipByMac.has(m) ? ipByMac.get(m) : null,
      // DHCP-derived identity (carried through from the host object when the agent attaches it).
      hostname: h.hostname != null ? h.hostname : null,
      comment: h.comment != null ? h.comment : null,
    });
  }
  return out;
}

// ── alert evaluation ─────────────────────────────────────────────────

/**
 * evaluateAlert(rule, value) -> boolean
 * Applies rule.comparator against rule.threshold.
 *   comparator 'offline' → fires when the status string `value` === 'offline'.
 *   '>','>=','<','<=','==' → numeric compare; non-numeric value never fires.
 * Unknown comparators return false (fail safe — never spuriously open an alert).
 */
function evaluateAlert(rule, value) {
  const r = rule || {};
  const cmp = r.comparator;

  if (cmp === 'offline') {
    return value === 'offline';
  }

  const v = parseNum(value);
  const t = parseNum(r.threshold);
  if (v === null || t === null) return false;

  switch (cmp) {
    case '>':
      return v > t;
    case '>=':
      return v >= t;
    case '<':
      return v < t;
    case '<=':
      return v <= t;
    case '==':
      return v === t;
    default:
      return false;
  }
}

// ── checksum ─────────────────────────────────────────────────────────

/**
 * sha256Hex(text) -> string
 * Lower-case hex SHA-256 of the UTF-8 bytes of `text`. Used to verify config-job
 * checksums (device aborts /import on mismatch). Coerces non-string input via String().
 */
function sha256Hex(text) {
  const input = typeof text === 'string' ? text : String(text);
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

module.exports = {
  deltaBps,
  classifyRole,
  parseNum,
  parseIp,
  joinMacHosts,
  normaliseMac,
  evaluateAlert,
  sha256Hex,
};
