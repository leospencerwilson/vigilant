// Vigilant — telemetry payload schema + normaliser.
//
// Source of truth for the device payload is `agent/vigilant-agent.rsc`. The agent
// emits some numbers as quoted strings and some absent values as the literal `null`
// (and as the strings "null"/""). This module's job is to be TOLERANT on the way in:
//   * unknown keys are ignored (.passthrough on nested objects, top-level stays loose),
//   * almost every field is optional / nullable,
//   * the ONLY hard requirement is `serial` (the token cross-check key),
//   * never throw on extra or missing optional keys.
//
// `normalize(raw)` validates with the schema, then coerces the messy device values
// into clean typed JS via the SHARED parsers in `transform.js` (parseNum / parseIp)
// so the ingest and the pure transform layer agree on edge cases.

const { z } = require("zod");
const transform = require("./transform.js");

// ─────────────────────────── schema ───────────────────────────
// Tolerant: most fields optional + nullable, unknown keys ignored. We deliberately
// accept loose unions (string|number|boolean|null) for fields the agent may emit in
// more than one shape, because the real coercion happens in normalize() below.

const loose = z.any();

const lteSchema = z
  .object({
    interface: z.string().optional().nullable(),
    iccid: z.string().optional().nullable(),
    imsi: z.string().optional().nullable(),
    imei: z.string().optional().nullable(),
    msisdn: z.string().optional().nullable(),
    operator: z.string().optional().nullable(),
    apn: z.string().optional().nullable(),
    registration: z.string().optional().nullable(),
    access_tech: z.string().optional().nullable(),
    band: z.string().optional().nullable(),
    earfcn: z.string().optional().nullable(),
    cell_id: z.string().optional().nullable(),
    phy_cellid: z.string().optional().nullable(),
    // signal fields arrive as STRINGS ("-65") — coerced to number|null in normalize
    rssi: loose.optional().nullable(),
    rsrp: loose.optional().nullable(),
    rsrq: loose.optional().nullable(),
    sinr: loose.optional().nullable(),
    cqi: loose.optional().nullable(),
  })
  .passthrough();

const interfaceSchema = z
  .object({
    name: z.string().optional().nullable(),
    type: z.string().optional().nullable(),
    comment: z.string().optional().nullable(),
    running: loose.optional().nullable(),
    disabled: loose.optional().nullable(),
    plugged: loose.optional().nullable(),
    speed: z.string().optional().nullable(),
    full_duplex: loose.optional().nullable(),
    bridge: z.string().optional().nullable(),
    is_wan: loose.optional().nullable(),
    mac: z.string().optional().nullable(),
    rx_byte: loose.optional().nullable(),
    tx_byte: loose.optional().nullable(),
    rx_packet: loose.optional().nullable(),
    tx_packet: loose.optional().nullable(),
    rx_error: loose.optional().nullable(),
    tx_error: loose.optional().nullable(),
    rx_drop: loose.optional().nullable(),
    tx_drop: loose.optional().nullable(),
  })
  .passthrough();

const neighborSchema = z
  .object({
    interface: z.string().optional().nullable(),
    identity: z.string().optional().nullable(),
    mac: z.string().optional().nullable(),
    address: z.string().optional().nullable(),
    platform: z.string().optional().nullable(),
    board: z.string().optional().nullable(),
    version: z.string().optional().nullable(),
  })
  .passthrough();

const macHostSchema = z
  .object({
    mac: z.string().optional().nullable(),
    interface: z.string().optional().nullable(),
  })
  .passthrough();

const arpSchema = z
  .object({
    mac: z.string().optional().nullable(),
    ip: z.string().optional().nullable(),
  })
  .passthrough();

// Top-level schema. `serial` is the ONLY required field. Everything else optional /
// nullable. `.passthrough()` keeps unknown keys (the ingest stores the full raw payload
// in device_state.raw), but normalize() only reads the keys it knows about.
const telemetrySchema = z
  .object({
    serial: z
      .string({
        required_error: "serial is required",
        invalid_type_error: "serial must be a string",
      })
      .min(1, "serial is required"),
    // optional agent-reported sample time (epoch ms or ISO string); the ingest uses it
    // for the bps delta window when present, else falls back to receive time.
    ts: loose.optional().nullable(),
    identity: z.string().optional().nullable(),
    uptime: loose.optional().nullable(),
    cpu_load: loose.optional().nullable(),
    free_memory: loose.optional().nullable(),
    total_memory: loose.optional().nullable(),
    free_hdd: loose.optional().nullable(),
    ros_version: z.string().optional().nullable(),
    temperature: loose.optional().nullable(),
    cpu_temperature: loose.optional().nullable(),
    board_temperature: loose.optional().nullable(),
    voltage: loose.optional().nullable(),
    fan1_speed: loose.optional().nullable(),
    fan2_speed: loose.optional().nullable(),
    write_sect_total: loose.optional().nullable(),
    firmware_current: z.string().optional().nullable(),
    firmware_upgrade: z.string().optional().nullable(),
    ntp_synced: loose.optional().nullable(),
    public_ip: loose.optional().nullable(),
    pppoe_running: loose.optional().nullable(),
    ppp_sessions: loose.optional().nullable(),
    dhcp_leases: loose.optional().nullable(),
    lte: lteSchema.optional().nullable(),
    interfaces: z.array(interfaceSchema).optional().nullable(),
    neighbors: z.array(neighborSchema).optional().nullable(),
    // null = "keep previous" (only present on the ~5-min slow tick)
    mac_hosts: z.array(macHostSchema).optional().nullable(),
    arp: z.array(arpSchema).optional().nullable(),
  })
  .passthrough();

// ─────────────────────────── coercion helpers ───────────────────────────

// Booleans arrive as real booleans from JSON.parse, but the agent can also emit the
// strings "true"/"false" (RouterOS prints booleans as bare words that land as JSON
// literals, but defend against quoted forms too). Returns boolean | null.
function parseBool(v) {
  if (v === true || v === false) return v;
  if (v === null || v === undefined) return null;
  if (typeof v === "number") {
    if (v === 1) return true;
    if (v === 0) return false;
    return null;
  }
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "yes" || s === "1") return true;
    if (s === "false" || s === "no" || s === "0") return false;
    return null;
  }
  return null;
}

// Pass through a free-text string, mapping empty / "null" sentinels to null. Used for
// identity/operator/etc. so downstream gets a clean string|null.
function str(v) {
  if (v === null || v === undefined) return null;
  if (typeof v !== "string") return String(v);
  const t = v.trim();
  if (t === "" || t.toLowerCase() === "null") return null;
  return v;
}

// ─────────────────────────── normalize ───────────────────────────

// normalize(raw) -> typed plain object.
//   * throws (zod error) if `serial` is absent — the only hard requirement.
//   * coerces LTE signal STRING fields to number|null via transform.parseNum.
//   * maps public_ip "null"/"" -> null and strips any CIDR /mask via transform.parseIp.
//   * passes interfaces/neighbors through with booleans/numbers coerced.
//   * leaves mac_hosts/arp as null when null (meaning "keep previous").
//   * never throws on extra / missing optional keys.
function normalize(raw) {
  const p = telemetrySchema.parse(raw); // throws only on missing/invalid `serial`

  const out = {
    serial: p.serial,
    // pass the agent-reported sample time through verbatim (number epoch ms or ISO
    // string); the handler resolves it to ms and falls back to receive time if absent.
    ts: p.ts != null ? p.ts : null,
    identity: str(p.identity),
    uptime: typeof p.uptime === "string" ? p.uptime : str(p.uptime),
    cpu_load: transform.parseNum(p.cpu_load),
    free_memory: transform.parseNum(p.free_memory),
    total_memory: transform.parseNum(p.total_memory),
    free_hdd: transform.parseNum(p.free_hdd),
    ros_version: str(p.ros_version),
    temperature: transform.parseNum(p.temperature),
    cpu_temperature: transform.parseNum(p.cpu_temperature),
    board_temperature: transform.parseNum(p.board_temperature),
    voltage: transform.parseNum(p.voltage),
    fan1_speed: transform.parseNum(p.fan1_speed),
    fan2_speed: transform.parseNum(p.fan2_speed),
    write_sect_total: transform.parseNum(p.write_sect_total),
    firmware_current: str(p.firmware_current),
    firmware_upgrade: str(p.firmware_upgrade),
    ntp_synced: parseBool(p.ntp_synced),
    // bare IP, "1.2.3.4/24" (pppoe), or "null"/"" -> null; strip /mask
    public_ip: transform.parseIp(p.public_ip),
    pppoe_running: parseBool(p.pppoe_running),
    ppp_sessions: transform.parseNum(p.ppp_sessions),
    dhcp_leases: transform.parseNum(p.dhcp_leases),
    lte: normalizeLte(p.lte),
    interfaces: normalizeInterfaces(p.interfaces),
    neighbors: normalizeNeighbors(p.neighbors),
    // null = "keep previous": preserve null vs [] distinction.
    mac_hosts: normalizeMacHosts(p.mac_hosts),
    arp: normalizeArp(p.arp),
  };

  return out;
}

function normalizeLte(lte) {
  if (lte === null || lte === undefined) return null;
  return {
    interface: str(lte.interface),
    iccid: str(lte.iccid),
    imsi: str(lte.imsi),
    imei: str(lte.imei),
    msisdn: str(lte.msisdn),
    operator: str(lte.operator),
    apn: str(lte.apn),
    registration: str(lte.registration),
    access_tech: str(lte.access_tech),
    band: str(lte.band),
    earfcn: str(lte.earfcn),
    cell_id: str(lte.cell_id),
    phy_cellid: str(lte.phy_cellid),
    // signal fields arrive as STRINGS ("-65") — coerce to number|null
    rssi: transform.parseNum(lte.rssi),
    rsrp: transform.parseNum(lte.rsrp),
    rsrq: transform.parseNum(lte.rsrq),
    sinr: transform.parseNum(lte.sinr),
    cqi: transform.parseNum(lte.cqi),
  };
}

function normalizeInterfaces(ifaces) {
  if (ifaces === null || ifaces === undefined) return [];
  return ifaces.map((i) => ({
    name: str(i.name),
    type: str(i.type),
    comment: str(i.comment),
    running: parseBool(i.running),
    disabled: parseBool(i.disabled),
    plugged: parseBool(i.plugged),
    speed: str(i.speed),
    full_duplex: parseBool(i.full_duplex),
    bridge: i.bridge === null || i.bridge === undefined ? "" : String(i.bridge),
    is_wan: parseBool(i.is_wan),
    mac: str(i.mac),
    rx_byte: transform.parseNum(i.rx_byte),
    tx_byte: transform.parseNum(i.tx_byte),
    rx_packet: transform.parseNum(i.rx_packet),
    tx_packet: transform.parseNum(i.tx_packet),
    rx_error: transform.parseNum(i.rx_error),
    tx_error: transform.parseNum(i.tx_error),
    rx_drop: transform.parseNum(i.rx_drop),
    tx_drop: transform.parseNum(i.tx_drop),
  }));
}

function normalizeNeighbors(nbrs) {
  if (nbrs === null || nbrs === undefined) return [];
  return nbrs.map((n) => ({
    interface: str(n.interface),
    identity: str(n.identity),
    mac: str(n.mac),
    address: transform.parseIp(n.address),
    platform: str(n.platform),
    board: str(n.board),
    version: str(n.version),
  }));
}

// null = "keep previous" — return null untouched. Only an array (incl. []) is processed.
function normalizeMacHosts(macHosts) {
  if (macHosts === null || macHosts === undefined) return null;
  return macHosts.map((h) => ({
    mac: str(h.mac),
    interface: str(h.interface),
  }));
}

function normalizeArp(arp) {
  if (arp === null || arp === undefined) return null;
  return arp.map((a) => ({
    mac: str(a.mac),
    ip: transform.parseIp(a.ip),
  }));
}

module.exports = { telemetrySchema, normalize };
