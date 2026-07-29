'use strict';

// Postgres implementation of the Store interface (see docs/CONTRACT.md and store.js).
//
// All methods are async and return plain objects / arrays / null. Every query is
// parameterised — no string interpolation of values. The pool (from db.js) pins
// search_path to `vigilant, public`, so table names are used bare.
//
// Conventions match the rest of the service: plain CommonJS, small focused helpers,
// no ORM. `makePgStore(pool|config)` returns the store object.

const fs = require('fs');
const path = require('path');
const { makePool } = require('./db');

// Pure threshold decision lives in transform.js (contract). Used by evaluateAndApplyAlerts.
const transform = require('./transform');

// Path to the canonical schema file applied by migrate().
const SCHEMA_PATH = path.join(__dirname, '..', '..', 'db', 'schema.sql');

// Upper bound on rows returned by a single getDeviceHistory window query, so a wide window
// (7d) on a busy multi-interface router can't return an unbounded result set to the UI.
const HISTORY_ROW_CAP = 2000;

/**
 * @param {import('pg').Pool|string|{databaseUrl?:string,connectionString?:string}} poolOrConfig
 *        An existing pg Pool, a database URL string, or a config object with
 *        databaseUrl / connectionString.
 * @returns {object} the Store
 */
function makePgStore(poolOrConfig) {
  const pool = resolvePool(poolOrConfig);

  // ── helpers ──────────────────────────────────────────────────────────────
  async function q(text, params) {
    return pool.query(text, params);
  }
  async function one(text, params) {
    const r = await q(text, params);
    return r.rows.length ? r.rows[0] : null;
  }
  async function rows(text, params) {
    const r = await q(text, params);
    return r.rows;
  }

  // Run fn inside a single transaction on one dedicated client. Retries on transient
  // serialization/deadlock errors (40P01 deadlock_detected, 40001 serialization_failure):
  // the agent fires several chunk POSTs for the same device at once (neighbours/wifi/logs/…),
  // so concurrent same-device writes can deadlock — the victim just retries and succeeds.
  async function tx(fn) {
    let lastErr;
    for (let attempt = 0; attempt < 4; attempt++) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch (_) { /* original error matters */ }
        lastErr = err;
        if (!((err.code === '40P01' || err.code === '40001') && attempt < 3)) throw err;
        await new Promise((r) => setTimeout(r, 30 * (attempt + 1)));
      } finally {
        client.release();
      }
    }
    throw lastErr;
  }

  // ── migrate ────────────────────────────────────────────────────────────────
  // Apply db/schema.sql verbatim. The file is already wrapped in BEGIN;…COMMIT; and
  // contains DO $$ … $$ blocks and function-style bodies, so we MUST NOT split on ';'.
  // node-postgres' simple query protocol happily runs a multi-statement string in one
  // call, which is exactly what we want here. The schema is idempotent (IF NOT EXISTS).
  async function migrate() {
    const sql = fs.readFileSync(SCHEMA_PATH, 'utf8');
    await q(sql);
  }

  // ── device registry / auth ──────────────────────────────────────────────────
  async function getDeviceByToken(tokenHash) {
    return one(
      // d.identity is selected so the telemetry handler can tell whether the agent's
      // reported /system identity has actually CHANGED, and skip the write when it hasn't.
      // d.kind is selected so the telemetry handler can tell a counter Pi from a router
      // without a second query — it decides whether a boot-target directive applies.
      `SELECT d.id, d.serial, d.identity, d.poll_interval_s, d.poll_until, d.agent_version,
              d.kind
         FROM enrollment_tokens t
         JOIN devices d ON d.id = t.device_id
        WHERE t.token_hash = $1
          AND t.revoked_at IS NULL`,
      [tokenHash]
    );
  }

  async function getDeviceBySerial(serial) {
    return one(
      `SELECT id, serial, identity, site_name, customer, model, ros_version, wan_type,
              tags, expected, poll_interval_s, poll_until, agent_version, enrolled_at, notes
         FROM devices
        WHERE serial = $1`,
      [serial]
    );
  }

  async function createDevice(fields) {
    const f = fields || {};
    const tags = Array.isArray(f.tags) ? f.tags : [];
    return one(
      `INSERT INTO devices
         (serial, identity, site_name, customer, model, ros_version, wan_type, tags,
          expected, poll_interval_s, poll_until, agent_version, notes, kind)
       VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7,'unknown'),
               COALESCE($8,'{}'::text[]),
               COALESCE($9,true),
               COALESCE($10,10),
               $11,$12,$13,COALESCE($14,'mikrotik'))
       ON CONFLICT (serial) DO UPDATE SET
         identity   = COALESCE(EXCLUDED.identity,  devices.identity),
         site_name  = COALESCE(EXCLUDED.site_name, devices.site_name),
         customer   = COALESCE(EXCLUDED.customer,  devices.customer),
         model      = COALESCE(EXCLUDED.model,     devices.model),
         wan_type   = EXCLUDED.wan_type,
         -- Only replace tags when the caller actually supplied some. Re-enrolling a
         -- device (our standard fix for a mis-tokened router) passes tags:[] , which
         -- used to wipe every tag it had — losing operator-set tags for good and
         -- silently dropping it out of any tag-scoped alert rule until the next sync.
         -- Clearing tags is done through setDeviceTags(), not by re-enrolling.
         tags       = CASE WHEN cardinality(EXCLUDED.tags) > 0 THEN EXCLUDED.tags ELSE devices.tags END,
         notes      = COALESCE(EXCLUDED.notes,     devices.notes),
         -- Never silently downgrade a counter-pi to a mikrotik on re-enrol: the kind
         -- gates whether RouterOS config pushes are offered for this device.
         kind       = COALESCE(EXCLUDED.kind, devices.kind)
       RETURNING id, serial, identity, site_name, customer, model, ros_version, wan_type,
                 tags, expected, poll_interval_s, poll_until, agent_version, enrolled_at, notes, kind`,
      [
        f.serial,
        f.identity || null,
        f.site_name || null,
        f.customer || null,
        f.model || null,
        f.ros_version || null,
        f.wan_type || null,
        tags,
        typeof f.expected === 'boolean' ? f.expected : null,
        typeof f.poll_interval_s === 'number' ? f.poll_interval_s : null,
        f.poll_until || null,
        f.agent_version || null,
        f.notes || null,
        f.kind || null,
      ]
    );
  }

  async function setDeviceToken(deviceId, tokenHash) {
    await q(
      `INSERT INTO enrollment_tokens (device_id, token_hash, issued_at, revoked_at)
       VALUES ($1, $2, now(), NULL)
       ON CONFLICT (device_id) DO UPDATE SET
         token_hash = EXCLUDED.token_hash,
         issued_at  = now(),
         revoked_at = NULL`,
      [deviceId, tokenHash]
    );
  }

  // ── interface delta source ────────────────────────────────────────────────
  async function getInterfaceStates(deviceId) {
    return rows(
      `SELECT name, rx_byte, tx_byte, rx_packet, tx_packet, sampled_at
         FROM interface_state
        WHERE device_id = $1`,
      [deviceId]
    );
  }

  // ── latest-snapshot upserts ─────────────────────────────────────────────────
  async function upsertDeviceState(deviceId, state) {
    const s = state || {};
    await q(
      `INSERT INTO device_state
         (device_id, status, uptime_s, cpu_load, free_memory, total_memory, free_hdd,
          temperature, voltage, public_ip, ros_version, firmware, default_route,
          pppoe_running, ppp_sessions, dhcp_leases, conn_count, lte_signal,
          cpu_temperature, board_temperature, fan1_speed, fan2_speed, write_sect_total,
          firmware_current, firmware_upgrade, ntp_synced, netwatch_down, last_seen_at, raw)
       VALUES ($1,COALESCE($2,'unknown'),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
               $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,COALESCE($28, now()),$29)
       ON CONFLICT (device_id) DO UPDATE SET
         status            = EXCLUDED.status,
         uptime_s          = EXCLUDED.uptime_s,
         cpu_load          = EXCLUDED.cpu_load,
         free_memory       = EXCLUDED.free_memory,
         total_memory      = EXCLUDED.total_memory,
         free_hdd          = EXCLUDED.free_hdd,
         temperature       = EXCLUDED.temperature,
         voltage           = EXCLUDED.voltage,
         public_ip         = EXCLUDED.public_ip,
         ros_version       = EXCLUDED.ros_version,
         firmware          = EXCLUDED.firmware,
         default_route     = EXCLUDED.default_route,
         pppoe_running     = EXCLUDED.pppoe_running,
         ppp_sessions      = EXCLUDED.ppp_sessions,
         dhcp_leases       = EXCLUDED.dhcp_leases,
         conn_count        = EXCLUDED.conn_count,
         lte_signal        = EXCLUDED.lte_signal,
         cpu_temperature   = EXCLUDED.cpu_temperature,
         board_temperature = EXCLUDED.board_temperature,
         fan1_speed        = EXCLUDED.fan1_speed,
         fan2_speed        = EXCLUDED.fan2_speed,
         write_sect_total  = EXCLUDED.write_sect_total,
         firmware_current  = EXCLUDED.firmware_current,
         firmware_upgrade  = EXCLUDED.firmware_upgrade,
         ntp_synced        = EXCLUDED.ntp_synced,
         netwatch_down     = EXCLUDED.netwatch_down,
         last_seen_at      = EXCLUDED.last_seen_at,
         raw               = EXCLUDED.raw`,
      [
        deviceId,
        s.status,
        nz(s.uptime_s),
        nz(s.cpu_load),
        nz(s.free_memory),
        nz(s.total_memory),
        nz(s.free_hdd),
        nz(s.temperature),
        nz(s.voltage),
        nz(s.public_ip),
        nz(s.ros_version),
        nz(s.firmware),
        nb(s.default_route),
        nb(s.pppoe_running),
        nz(s.ppp_sessions),
        nz(s.dhcp_leases),
        nz(s.conn_count),
        nz(s.lte_signal),
        nz(s.cpu_temperature),
        nz(s.board_temperature),
        nz(s.fan1_speed),
        nz(s.fan2_speed),
        nz(s.write_sect_total),
        nz(s.firmware_current),
        nz(s.firmware_upgrade),
        nb(s.ntp_synced),
        nz(s.netwatch_down),
        s.last_seen_at || null,
        s.raw != null ? JSON.stringify(s.raw) : null,
      ]
    );
  }

  // CHUNKED TELEMETRY: bump ONLY status + last_seen_at, leaving every system column intact.
  // Called for a detail-only chunk (interfaces/neighbors/… with no system block) so we record
  // the device is alive WITHOUT clobbering cpu_load/uptime/free_memory/etc. that a core chunk
  // wrote this tick. ON CONFLICT updates only those two columns; the INSERT branch seeds a
  // minimal 'online' row when a detail chunk races ahead of the core chunk (all system cols
  // default to NULL until the core chunk fills them).
  async function touchDeviceState(deviceId, ts) {
    await q(
      `INSERT INTO device_state (device_id, status, last_seen_at)
         VALUES ($1, 'online', COALESCE($2, now()))
       ON CONFLICT (device_id) DO UPDATE SET
         status       = 'online',
         last_seen_at = COALESCE(EXCLUDED.last_seen_at, now())`,
      [deviceId, ts || null]
    );
  }

  // ── bulk write helpers ───────────────────────────────────────────────────
  // The per-tick writes below used to issue ONE round-trip PER ROW inside a
  // transaction (a router with ~19 interfaces and ~286 mac_hosts meant ~340
  // sequential round-trips every tick, x365 devices). Postgres finished each
  // tiny statement instantly and then sat in ClientRead waiting for the next
  // one, so the cost was almost entirely round-trip latency. These helpers
  // collapse each list into a single multi-row INSERT.
  //
  // `tuple(o)` renders the VALUES tuple for one row, numbering its bind params
  // from 1-based offset `o` (so a tuple may contain SQL expressions such as
  // COALESCE($n, now()), not just bare placeholders). Postgres caps a statement
  // at 65535 bound params, so we chunk on that.
  async function bulkInsert(client, head, tail, width, rowsParams, tuple) {
    if (!rowsParams.length) return;
    const maxRows = Math.max(1, Math.floor(65000 / width));
    for (let i = 0; i < rowsParams.length; i += maxRows) {
      const chunk = rowsParams.slice(i, i + maxRows);
      const sql =
        head +
        ' VALUES ' +
        chunk.map((_, r) => tuple(r * width + 1)).join(',') +
        ' ' +
        tail;
      const params = [];
      for (const p of chunk) params.push(...p);
      await client.query(sql, params);
    }
  }

  // A tuple of `n` plain placeholders, optionally followed by literal SQL
  // (e.g. 'now()') that takes no bind param.
  function placeholders(n, trailing) {
    return (o) => {
      const ph = [];
      for (let c = 0; c < n; c++) ph.push('$' + (o + c));
      if (trailing) ph.push(trailing);
      return '(' + ph.join(',') + ')';
    };
  }

  // Composite key for the dedupe maps below. U+0000 is used as the separator
  // because it cannot appear in a RouterOS interface name, a MAC address or a
  // log line, so distinct field pairs can never collide into one key.
  function keyOf() {
    return Array.prototype.join.call(arguments, '\u0000');
  }
  // Collapse rows that share an ON CONFLICT target — a multi-row INSERT ... ON
  // CONFLICT DO UPDATE cannot touch the same row twice ("cannot affect row a
  // second time"). Last one wins, matching the previous row-at-a-time behaviour
  // where a later duplicate simply overwrote the earlier one.
  function dedupeBy(list, keyFn) {
    const byKey = new Map();
    for (const r of list) byKey.set(keyFn(r), r);
    return Array.from(byKey.values());
  }

  // Each row already has rx_bps/tx_bps/role/is_wan computed by the ingest.
  async function upsertInterfaceStates(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    const uniq = dedupeBy(list, (r) => r && r.name);
    const tuple = (o) =>
      `($${o},$${o + 1},$${o + 2},$${o + 3},$${o + 4},$${o + 5},$${o + 6},$${o + 7},` +
      `$${o + 8},$${o + 9},$${o + 10},$${o + 11},$${o + 12},COALESCE($${o + 13},false),` +
      `$${o + 14},$${o + 15},$${o + 16},$${o + 17},$${o + 18},$${o + 19},$${o + 20},$${o + 21},` +
      `$${o + 22},$${o + 23},$${o + 24},$${o + 25},$${o + 26},$${o + 27},COALESCE($${o + 28}, now()))`;
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO interface_state
             (device_id, name, type, comment, plugged, running, disabled, speed,
              full_duplex, last_link_up_at, last_link_down_at, link_downs, role, is_wan,
              bridge, poe_out_status, poe_out_power, mac, rx_bps, tx_bps, rx_byte, tx_byte,
              rx_packet, tx_packet, rx_error, tx_error, rx_drop, tx_drop, sampled_at)`,
        `ON CONFLICT (device_id, name) DO UPDATE SET
             type              = EXCLUDED.type,
             comment           = EXCLUDED.comment,
             plugged           = EXCLUDED.plugged,
             running           = EXCLUDED.running,
             disabled          = EXCLUDED.disabled,
             speed             = EXCLUDED.speed,
             full_duplex       = EXCLUDED.full_duplex,
             last_link_up_at   = COALESCE(EXCLUDED.last_link_up_at,   interface_state.last_link_up_at),
             last_link_down_at = COALESCE(EXCLUDED.last_link_down_at, interface_state.last_link_down_at),
             link_downs        = COALESCE(EXCLUDED.link_downs,        interface_state.link_downs),
             role              = EXCLUDED.role,
             is_wan            = EXCLUDED.is_wan,
             bridge            = EXCLUDED.bridge,
             poe_out_status    = EXCLUDED.poe_out_status,
             poe_out_power     = EXCLUDED.poe_out_power,
             mac               = EXCLUDED.mac,
             rx_bps            = EXCLUDED.rx_bps,
             tx_bps            = EXCLUDED.tx_bps,
             rx_byte           = EXCLUDED.rx_byte,
             tx_byte           = EXCLUDED.tx_byte,
             rx_packet         = EXCLUDED.rx_packet,
             tx_packet         = EXCLUDED.tx_packet,
             rx_error          = EXCLUDED.rx_error,
             tx_error          = EXCLUDED.tx_error,
             rx_drop           = EXCLUDED.rx_drop,
             tx_drop           = EXCLUDED.tx_drop,
             sampled_at        = EXCLUDED.sampled_at`,
        29,
        uniq.map((r) => [
          deviceId,
          r.name,
          nz(r.type),
          nz(r.comment),
          nb(r.plugged),
          nb(r.running),
          nb(r.disabled),
          nz(r.speed),
          nb(r.full_duplex),
          r.last_link_up_at || null,
          r.last_link_down_at || null,
          nz(r.link_downs),
          nz(r.role),
          nb(r.is_wan),
          nz(r.bridge),
          nz(r.poe_out_status),
          nz(r.poe_out_power),
          nz(r.mac),
          nz(r.rx_bps),
          nz(r.tx_bps),
          nz(r.rx_byte),
          nz(r.tx_byte),
          nz(r.rx_packet),
          nz(r.tx_packet),
          nz(r.rx_error),
          nz(r.tx_error),
          nz(r.rx_drop),
          nz(r.tx_drop),
          r.sampled_at || null,
        ]),
        tuple
      );
    });
  }

  async function upsertLteState(deviceId, row) {
    if (!row || !row.interface) return;
    const r = row;
    await q(
      `INSERT INTO lte_state
         (device_id, interface, iccid, imsi, imei, msisdn, operator, apn, registration,
          access_tech, band, earfcn, cell_id, phy_cellid, rssi, rsrp, rsrq, sinr, cqi,
          session_uptime_s, sampled_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
               COALESCE($21, now()))
       ON CONFLICT (device_id, interface) DO UPDATE SET
         iccid            = COALESCE(EXCLUDED.iccid,            lte_state.iccid),
         imsi             = COALESCE(EXCLUDED.imsi,             lte_state.imsi),
         imei             = COALESCE(EXCLUDED.imei,             lte_state.imei),
         msisdn           = COALESCE(EXCLUDED.msisdn,           lte_state.msisdn),
         operator         = EXCLUDED.operator,
         apn              = COALESCE(EXCLUDED.apn,              lte_state.apn),
         registration     = EXCLUDED.registration,
         access_tech      = EXCLUDED.access_tech,
         band             = EXCLUDED.band,
         earfcn           = EXCLUDED.earfcn,
         cell_id          = EXCLUDED.cell_id,
         phy_cellid       = EXCLUDED.phy_cellid,
         rssi             = EXCLUDED.rssi,
         rsrp             = EXCLUDED.rsrp,
         rsrq             = EXCLUDED.rsrq,
         sinr             = EXCLUDED.sinr,
         cqi              = EXCLUDED.cqi,
         session_uptime_s = EXCLUDED.session_uptime_s,
         sampled_at       = EXCLUDED.sampled_at`,
      [
        deviceId,
        r.interface,
        nz(r.iccid),
        nz(r.imsi),
        nz(r.imei),
        nz(r.msisdn),
        nz(r.operator),
        nz(r.apn),
        nz(r.registration),
        nz(r.access_tech),
        nz(r.band),
        nz(r.earfcn),
        nz(r.cell_id),
        nz(r.phy_cellid),
        nz(r.rssi),
        nz(r.rsrp),
        nz(r.rsrq),
        nz(r.sinr),
        nz(r.cqi),
        nz(r.session_uptime_s),
        r.sampled_at || null,
      ]
    );
  }

  // Stamps last_seen_at = now() for every neighbor row seen this tick.
  async function upsertNeighbors(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    const uniq = dedupeBy(
      list.filter((r) => r && r.interface && r.mac),
      (r) => keyOf(r.interface, r.mac)
    );
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO neighbors
             (device_id, interface, mac, identity, address, platform, board, version, last_seen_at)`,
        `ON CONFLICT (device_id, interface, mac) DO UPDATE SET
             identity     = EXCLUDED.identity,
             address      = EXCLUDED.address,
             platform     = EXCLUDED.platform,
             board        = COALESCE(EXCLUDED.board,   neighbors.board),
             version      = COALESCE(EXCLUDED.version, neighbors.version),
             last_seen_at = now()`,
        8,
        uniq.map((r) => [
          deviceId,
          r.interface,
          r.mac,
          nz(r.identity),
          nz(r.address),
          nz(r.platform),
          nz(r.board),
          nz(r.version),
        ]),
        placeholders(8, 'now()')
      );
    });
  }

  // Only called when payload.mac_hosts !== null (slow tick).
  async function upsertMacHosts(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    const uniq = dedupeBy(
      list.filter((r) => r && r.interface && r.mac),
      (r) => keyOf(r.interface, r.mac)
    );
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO mac_hosts (device_id, interface, mac, ip, hostname, comment, vendor, last_seen_at)`,
        `ON CONFLICT (device_id, interface, mac) DO UPDATE SET
             ip           = EXCLUDED.ip,
             hostname     = COALESCE(EXCLUDED.hostname, mac_hosts.hostname),
             comment      = COALESCE(EXCLUDED.comment,  mac_hosts.comment),
             vendor       = COALESCE(EXCLUDED.vendor, mac_hosts.vendor),
             last_seen_at = now()`,
        7,
        uniq.map((r) => [deviceId, r.interface, r.mac, nz(r.ip), nz(r.hostname), nz(r.comment), nz(r.vendor)]),
        placeholders(7, 'now()')
      );
    });
  }

  // WiFi config (SSIDs/channels) — FULL-SNAPSHOT replace: clear the device's WLANs then insert
  // the reported set, so a removed/renamed SSID disappears. Only called when payload.wifi !== null.
  async function upsertWifiNetworks(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    await tx(async (client) => {
      await client.query(`DELETE FROM wifi_networks WHERE device_id = $1`, [deviceId]);
      const uniq = dedupeBy(
        list.filter((r) => r && r.interface),
        (r) => r.interface
      );
      await bulkInsert(
        client,
        `INSERT INTO wifi_networks
             (device_id, interface, driver, band, ssid, passphrase, security,
              channel, frequency_mhz, width_mhz, disabled, hidden, clients, last_seen_at)`,
        `ON CONFLICT (device_id, interface) DO UPDATE SET
             driver=EXCLUDED.driver, band=EXCLUDED.band, ssid=EXCLUDED.ssid,
             passphrase=EXCLUDED.passphrase, security=EXCLUDED.security, channel=EXCLUDED.channel,
             frequency_mhz=EXCLUDED.frequency_mhz, width_mhz=EXCLUDED.width_mhz,
             disabled=EXCLUDED.disabled, hidden=EXCLUDED.hidden, clients=EXCLUDED.clients,
             last_seen_at=now()`,
        13,
        uniq.map((r) => [
          deviceId,
          r.interface,
          nz(r.driver),
          nz(r.band),
          nz(r.ssid),
          nz(r.passphrase),
          nz(r.security),
          nz(r.channel),
          nz(r.frequency_mhz),
          nz(r.width_mhz),
          nb(r.disabled),
          nb(r.hidden),
          nz(r.clients),
        ]),
        placeholders(13, 'now()')
      );
    });
  }

  // Associated WiFi stations — FULL-SNAPSHOT replace of the registration table for the device.
  // Only called when payload.wifi_clients !== null.
  async function upsertWirelessClients(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    await tx(async (client) => {
      await client.query(`DELETE FROM wireless_clients WHERE device_id = $1`, [deviceId]);
      const uniq = dedupeBy(
        list.filter((r) => r && r.interface && r.mac),
        (r) => keyOf(r.interface, r.mac)
      );
      await bulkInsert(
        client,
        `INSERT INTO wireless_clients
             (device_id, interface, mac, signal, tx_ccq, rx_rate, tx_rate, uptime_s, sampled_at)`,
        `ON CONFLICT (device_id, interface, mac) DO UPDATE SET
             signal=EXCLUDED.signal, tx_ccq=EXCLUDED.tx_ccq, rx_rate=EXCLUDED.rx_rate,
             tx_rate=EXCLUDED.tx_rate, uptime_s=EXCLUDED.uptime_s, sampled_at=now()`,
        8,
        uniq.map((r) => [
          deviceId,
          r.interface,
          r.mac,
          nz(r.signal),
          nz(r.tx_ccq),
          nz(r.rx_rate),
          nz(r.tx_rate),
          nz(r.uptime_s),
        ]),
        placeholders(8, 'now()')
      );
    });
  }

  // Append device log lines to the 30-day history. PK (device_id, log_time, message) dedups
  // the agent's overlapping re-sends — only genuinely new lines land.
  async function appendDeviceLogs(deviceId, logs) {
    const arr = Array.isArray(logs) ? logs.slice(0, 100) : [];
    if (!arr.length) return;
    const params = [];
    const seen = new Set();
    for (const l of arr) {
      const msg = l && l.message != null ? String(l.message) : '';
      if (!msg) continue;
      const logTime = l.time != null ? String(l.time) : '';
      // Same dedupe the PK would do, but done here so one multi-row INSERT can
      // carry the whole batch.
      const key = keyOf(logTime, msg);
      if (seen.has(key)) continue;
      seen.add(key);
      params.push([deviceId, logTime, l.topics != null ? String(l.topics) : null, msg]);
    }
    if (!params.length) return;
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO device_logs (device_id, log_time, topics, message)`,
        `ON CONFLICT (device_id, log_time, message) DO NOTHING`,
        4,
        params,
        placeholders(4)
      );
    });
  }
  // Filtered log read (last 30 days). q = free text in message/topics; topic = topics filter.
  async function getDeviceLogs(deviceId, opts) {
    const o = opts || {};
    const limit = Math.min(Math.max(parseInt(o.limit, 10) || 300, 1), 2000);
    const qtext = o.q != null && String(o.q).trim() !== '' ? String(o.q).trim() : null;
    const topic = o.topic != null && String(o.topic).trim() !== '' ? String(o.topic).trim() : null;
    return rows(
      `SELECT seen_at, log_time, topics, message
         FROM device_logs
        WHERE device_id = $1
          AND seen_at > now() - interval '30 days'
          AND ($2::text IS NULL OR message ILIKE '%'||$2||'%' OR topics ILIKE '%'||$2||'%')
          AND ($3::text IS NULL OR topics ILIKE '%'||$3||'%')
        ORDER BY seen_at DESC, log_time DESC
        LIMIT $4`,
      [deviceId, qtext, topic, limit]
    );
  }
  // Retention: drop log lines older than 30 days (called from the worker prune pass).
  async function pruneDeviceLogs() {
    const r = await q(`DELETE FROM device_logs WHERE seen_at < now() - interval '30 days'`, []);
    return { pruned: r.rowCount || 0 };
  }

  // ── history appends ──────────────────────────────────────────────────────
  async function appendMetricsHistory(deviceId, ts, row) {
    const r = row || {};
    await q(
      `INSERT INTO metrics_history (device_id, ts, cpu_load, free_memory, temperature, ppp_sessions, conn_count)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (device_id, ts) DO UPDATE SET
         cpu_load     = EXCLUDED.cpu_load,
         free_memory  = EXCLUDED.free_memory,
         temperature  = EXCLUDED.temperature,
         ppp_sessions = EXCLUDED.ppp_sessions,
         conn_count   = EXCLUDED.conn_count`,
      [deviceId, ts, nz(r.cpu_load), nz(r.free_memory), nz(r.temperature), nz(r.ppp_sessions), nz(r.conn_count)]
    );
  }

  async function appendInterfaceHistory(deviceId, ts, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    // ts is constant for the whole call, so the conflict key reduces to name.
    const uniq = dedupeBy(
      list.filter((r) => r && r.name),
      (r) => r.name
    );
    if (!uniq.length) return;
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO interface_history (device_id, name, ts, rx_bps, tx_bps, rx_error, tx_error)`,
        `ON CONFLICT (device_id, name, ts) DO UPDATE SET
             rx_bps   = EXCLUDED.rx_bps,
             tx_bps   = EXCLUDED.tx_bps,
             rx_error = EXCLUDED.rx_error,
             tx_error = EXCLUDED.tx_error`,
        7,
        uniq.map((r) => [deviceId, r.name, ts, nz(r.rx_bps), nz(r.tx_bps), nz(r.rx_error), nz(r.tx_error)]),
        placeholders(7)
      );
    });
  }

  async function appendLteHistory(deviceId, ts, row) {
    if (!row || !row.interface) return;
    const r = row;
    await q(
      `INSERT INTO lte_history (device_id, interface, ts, rsrp, rsrq, sinr, rssi, cell_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (device_id, interface, ts) DO UPDATE SET
         rsrp    = EXCLUDED.rsrp,
         rsrq    = EXCLUDED.rsrq,
         sinr    = EXCLUDED.sinr,
         rssi    = EXCLUDED.rssi,
         cell_id = EXCLUDED.cell_id`,
      [deviceId, r.interface, ts, nz(r.rsrp), nz(r.rsrq), nz(r.sinr), nz(r.rssi), nz(r.cell_id)]
    );
  }

  // ── poll window ────────────────────────────────────────────────────────────
  async function setPollWindow(deviceId, pollUntil, intervalS) {
    await q(
      `UPDATE devices
          SET poll_until      = $2,
              poll_interval_s = COALESCE($3, poll_interval_s)
        WHERE id = $1`,
      [deviceId, pollUntil || null, typeof intervalS === 'number' ? intervalS : null]
    );
  }

  // ── config push ──────────────────────────────────────────────────────────
  // Approved + targeted (this device directly, or via a tag on the device).
  async function getPendingConfigJob(deviceId) {
    return one(
      `SELECT j.id, j.rsc_sha256, j.confirm_window_s
         FROM config_jobs j
        WHERE j.status = 'approved'
          AND (
                j.device_id = $1
             OR (j.device_id IS NULL
                 AND j.target_tag IS NOT NULL
                 AND j.target_tag = ANY (SELECT unnest(tags) FROM devices WHERE id = $1))
              )
        ORDER BY j.approved_at ASC NULLS LAST, j.created_at ASC
        LIMIT 1`,
      [deviceId]
    );
  }

  // Verify the job targets this device AND is still in a fetchable (in-flight) status
  // before handing over the .rsc text. The serving gate must live HERE on the byte path,
  // not only in getPendingConfigJob — otherwise a device that knows/guesses a job id could
  // pull the rsc_text of a draft/cancelled/applied/rolled_back/failed job and /import it
  // onto a live router (contract non-negotiable: only approved jobs are ever served).
  // Fetchable mid-apply set: approved (initial pull), plus fetched/applying so an in-flight
  // device can retry the fetch within its confirm window. NEVER draft/cancelled/applied/
  // rolled_back/failed.
  async function getConfigJobForFetch(jobId, deviceId) {
    if (!isUuid(jobId)) return null;
    return one(
      `SELECT j.rsc_text, j.rsc_sha256
         FROM config_jobs j
        WHERE j.id = $1
          AND j.status IN ('approved','fetched','applying')
          AND (
                j.device_id = $2
             OR (j.device_id IS NULL
                 AND j.target_tag IS NOT NULL
                 AND j.target_tag = ANY (SELECT unnest(tags) FROM devices WHERE id = $2))
              )`,
      [jobId, deviceId]
    );
  }

  // The operator-confirmed job for this device, if any: a job moved to status='applied'
  // (the operator's affirmative confirm in Watchman). The telemetry response surfaces this
  // id as "confirm":"<jobid>" so the agent can cancel its dead-man's-switch rollback —
  // absence of a job must NEVER be treated as confirmation. Most recent first.
  async function getConfirmedJob(deviceId) {
    return one(
      `SELECT j.id
         FROM config_jobs j
        WHERE j.status = 'applied'
          AND (
                j.device_id = $1
             OR (j.device_id IS NULL
                 AND j.target_tag IS NOT NULL
                 AND j.target_tag = ANY (SELECT unnest(tags) FROM devices WHERE id = $1))
              )
        ORDER BY j.applied_at DESC NULLS LAST, j.created_at DESC
        LIMIT 1`,
      [deviceId]
    );
  }

  // Generic status transition; sets the timestamp/log column appropriate to the status.
  async function markConfigJob(jobId, status, fields) {
    const f = fields || {};
    await q(
      `UPDATE config_jobs
          SET status      = $2,
              fetched_at  = CASE WHEN $2 = 'fetched'
                                 THEN COALESCE($3::timestamptz, now())
                                 ELSE fetched_at END,
              applied_at  = CASE WHEN $2 IN ('applied','failed','rolled_back')
                                 THEN COALESCE($4::timestamptz, now())
                                 ELSE applied_at END,
              result_log  = COALESCE($5, result_log),
              rollback_ref = COALESCE($6, rollback_ref)
        WHERE id = $1`,
      [
        jobId,
        status,
        f.fetched_at || null,
        f.applied_at || null,
        f.result_log != null ? f.result_log : null,
        f.rollback_ref != null ? f.rollback_ref : null,
      ]
    );
  }

  // Records the device's apply result + writes pre/post config snapshots.
  async function recordConfigResult(jobId, status, resultLog, exportText) {
    await tx(async (client) => {
      // Look up the device this job targets so the snapshot is attributed correctly.
      const jr = await client.query(
        `SELECT id, device_id, target_tag, rollback_ref FROM config_jobs WHERE id = $1`,
        [jobId]
      );
      if (!jr.rows.length) return;
      const job = jr.rows[0];

      const appliedStatuses = ['applied', 'failed', 'rolled_back'];
      await client.query(
        `UPDATE config_jobs
            SET status     = $2,
                result_log = $3,
                applied_at = CASE WHEN $2 = ANY($4::text[]) THEN now() ELSE applied_at END
          WHERE id = $1`,
        [jobId, status, resultLog != null ? resultLog : null, appliedStatuses]
      );

      // Post-apply snapshot of the device config the agent exported back, if any.
      if (exportText != null && job.device_id) {
        const sha = transform.sha256Hex(String(exportText));
        await client.query(
          `INSERT INTO config_snapshots (device_id, ts, rsc_text, rsc_sha256, source)
           VALUES ($1, now(), $2, $3, 'pre-apply')`,
          [job.device_id, String(exportText), sha]
        );
      }
    });
  }

  // ── config jobs: ADMIN-facing authoring/approval (operator side) ─────────────
  // Operator counterparts to the device-side getPendingConfigJob/…Fetch above. They never
  // serve a router; the "only approved + targeted + checksum-verified" serving gate stays in
  // getPendingConfigJob / getConfigJobForFetch, so authoring/approving here cannot bypass it.

  // Create a DRAFT job (never served until approved). Computes rsc_sha256 from rsc_text when
  // not supplied. confirm_window_s/kind default at the DB level if omitted.
  async function createConfigJob(fields = {}) {
    const f = fields || {};
    const rsc = f.rsc_text != null ? String(f.rsc_text) : '';
    const sha =
      f.rsc_sha256 != null && f.rsc_sha256 !== '' ? f.rsc_sha256 : transform.sha256Hex(rsc);
    return one(
      `INSERT INTO config_jobs
         (device_id, target_tag, is_canary, kind, rsc_text, rsc_sha256, status,
          confirm_window_s, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,$8)
       RETURNING *`,
      [
        f.device_id || null,
        f.target_tag || null,
        f.is_canary === true,
        f.kind || 'snippet',
        rsc,
        sha,
        f.confirm_window_s != null ? f.confirm_window_s : 300,
        f.created_by || 'unknown',
      ]
    );
  }

  // Approve a DRAFT -> 'approved'. The WHERE status='draft' guard makes this a no-op (returns
  // null) if the job was already advanced/cancelled, so a double-approve can't reopen it.
  async function approveConfigJob(jobId, approvedBy) {
    return one(
      `UPDATE config_jobs
          SET status = 'approved', approved_by = $2, approved_at = now()
        WHERE id = $1 AND status = 'draft'
        RETURNING *`,
      [jobId, approvedBy != null ? approvedBy : null]
    );
  }

  // Cancel a not-yet-picked-up job (draft or approved) -> 'cancelled'. Returns null if the
  // job has already moved past approval (fetched/applying/applied/…), which cannot be cancelled.
  async function cancelConfigJob(jobId) {
    return one(
      `UPDATE config_jobs
          SET status = 'cancelled'
        WHERE id = $1 AND status IN ('draft','approved')
        RETURNING *`,
      [jobId]
    );
  }

  // All jobs targeting this device (directly or via a tag), newest first, capped.
  async function listConfigJobs(deviceId, limit = 50) {
    return rows(
      `SELECT *
         FROM config_jobs
        WHERE device_id = $1
           OR (device_id IS NULL
               AND target_tag IS NOT NULL
               AND target_tag = ANY (SELECT unnest(tags) FROM devices WHERE id = $1))
        ORDER BY created_at DESC
        LIMIT $2`,
      [deviceId, limit]
    );
  }

  async function getConfigJob(jobId) {
    if (!isUuid(jobId)) return null;
    return one(`SELECT * FROM config_jobs WHERE id = $1`, [jobId]);
  }

  // ── speedtest jobs ───────────────────────────────────────────────────────────
  async function createSpeedtestJob(fields = {}) {
    const f = fields || {};
    return one(
      `INSERT INTO speedtest_jobs (device_id, status, bytes_down, bytes_up, requested_by)
       VALUES ($1,'pending',$2,$3,$4)
       RETURNING *`,
      [
        f.device_id || null,
        f.bytes_down != null ? f.bytes_down : 26214400,
        f.bytes_up != null ? f.bytes_up : 8388608,
        f.requested_by || 'unknown',
      ]
    );
  }

  async function getPendingSpeedtestJob(deviceId) {
    return one(
      `SELECT * FROM speedtest_jobs
        WHERE device_id = $1 AND status = 'pending'
        ORDER BY created_at DESC LIMIT 1`,
      [deviceId]
    );
  }

  async function markSpeedtestRunning(jobId) {
    return one(
      `UPDATE speedtest_jobs
          SET status = 'running', started_at = now()
        WHERE id = $1 AND status = 'pending'
        RETURNING *`,
      [jobId]
    );
  }

  async function recordSpeedtestResult(jobId, fields = {}) {
    const f = fields || {};
    return one(
      `UPDATE speedtest_jobs
          SET down_bps    = COALESCE($2, down_bps),
              up_bps      = COALESCE($3, up_bps),
              result_log  = COALESCE($4, result_log),
              status      = COALESCE($5, status),
              finished_at = CASE WHEN $5 IN ('done','failed') THEN now() ELSE finished_at END
        WHERE id = $1
        RETURNING *`,
      [
        jobId,
        f.down_bps != null ? f.down_bps : null,
        f.up_bps != null ? f.up_bps : null,
        f.result_log != null ? f.result_log : null,
        f.status != null ? f.status : null,
      ]
    );
  }

  async function getSpeedtestJob(jobId) {
    if (!isUuid(jobId)) return null;
    return one(`SELECT * FROM speedtest_jobs WHERE id = $1`, [jobId]);
  }

  async function listSpeedtestJobs(deviceId, limit = 20) {
    return rows(
      `SELECT * FROM speedtest_jobs WHERE device_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [deviceId, limit]
    );
  }

  // ── audit ────────────────────────────────────────────────────────────────────
  async function appendAudit(actor, action, serial, details) {
    await q(
      `INSERT INTO audit_log (actor, action, serial, details) VALUES ($1,$2,$3,$4)`,
      [actor != null ? actor : 'unknown', action, serial != null ? serial : null, details != null ? details : null]
    );
  }

  // ── agent script ───────────────────────────────────────────────────────────
  async function getCurrentAgentScript() {
    const row = await one(
      `SELECT version, rsc_text
         FROM agent_scripts
        WHERE is_current = true
        ORDER BY version DESC
        LIMIT 1`,
      []
    );
    return row;
  }

  // ── read APIs ──────────────────────────────────────────────────────────────
  async function getFleet() {
    return rows(
      `SELECT id, serial, identity, site_name, customer, model, wan_type, tags,
              status, cpu_load, temperature, public_ip, ppp_sessions, last_seen_at, open_alerts
         FROM v_fleet
        ORDER BY customer NULLS LAST, site_name NULLS LAST, serial`,
      []
    );
  }

  async function getDeviceDetail(serial) {
    const device = await getDeviceBySerial(serial);
    if (!device) return null;
    const id = device.id;
    const [state, interfaces, lte, neighbors, macHosts, wifi, wifiClients] = await Promise.all([
      one(`SELECT * FROM device_state WHERE device_id = $1`, [id]),
      rows(`SELECT * FROM interface_state WHERE device_id = $1 ORDER BY name`, [id]),
      one(`SELECT * FROM lte_state WHERE device_id = $1 ORDER BY interface LIMIT 1`, [id]),
      rows(`SELECT * FROM neighbors WHERE device_id = $1 ORDER BY interface, mac`, [id]),
      rows(`SELECT * FROM mac_hosts WHERE device_id = $1 ORDER BY interface, mac`, [id]),
      rows(`SELECT * FROM wifi_networks WHERE device_id = $1 ORDER BY interface`, [id]),
      rows(`SELECT * FROM wireless_clients WHERE device_id = $1 ORDER BY interface, signal DESC NULLS LAST`, [id]),
    ]);
    // Denormalise the live connected-station count onto each WLAN row (by interface).
    const wifiWithCounts = (wifi || []).map((w) => ({
      ...w,
      clients: (wifiClients || []).filter((c) => c.interface === w.interface).length,
    }));
    return {
      device,
      state,
      interfaces,
      lte,
      neighbors,
      mac_hosts: macHosts,
      wifi: wifiWithCounts,
      wifi_clients: wifiClients || [],
    };
  }

  // ── history read APIs (dashboard charts) ─────────────────────────────────────
  // Device-level metric series since `sinceMs` (epoch ms), time-ascending. Backs the
  // dashboard CPU/memory/temperature/ppp charts (GET /devices/:serial/history). Returns []
  // for an unknown serial. ts is returned as an ISO string for the JSON contract.
  async function getMetricsHistory(serial, sinceMs) {
    const device = await getDeviceBySerial(serial);
    if (!device) return [];
    const since = new Date(typeof sinceMs === 'number' ? sinceMs : 0).toISOString();
    const r = await rows(
      `SELECT ts, cpu_load, free_memory, temperature, ppp_sessions
         FROM metrics_history
        WHERE device_id = $1 AND ts >= $2
        ORDER BY ts ASC`,
      [device.id, since]
    );
    return r.map((row) => ({
      ts: row.ts instanceof Date ? row.ts.toISOString() : String(row.ts),
      cpu_load: row.cpu_load != null ? Number(row.cpu_load) : null,
      free_memory: row.free_memory != null ? Number(row.free_memory) : null,
      temperature: row.temperature != null ? Number(row.temperature) : null,
      ppp_sessions: row.ppp_sessions != null ? Number(row.ppp_sessions) : null,
    }));
  }

  // Per-interface rx/tx bps series since `sinceMs`, grouped by interface name and
  // time-ascending within each. Backs the per-interface throughput charts.
  async function getInterfaceHistory(serial, sinceMs) {
    const device = await getDeviceBySerial(serial);
    if (!device) return [];
    const since = new Date(typeof sinceMs === 'number' ? sinceMs : 0).toISOString();
    const r = await rows(
      `SELECT name, ts, rx_bps, tx_bps
         FROM interface_history
        WHERE device_id = $1 AND ts >= $2
        ORDER BY name ASC, ts ASC`,
      [device.id, since]
    );
    const byName = new Map();
    for (const row of r) {
      if (!byName.has(row.name)) byName.set(row.name, []);
      byName.get(row.name).push({
        ts: row.ts instanceof Date ? row.ts.toISOString() : String(row.ts),
        rx_bps: row.rx_bps != null ? Number(row.rx_bps) : null,
        tx_bps: row.tx_bps != null ? Number(row.tx_bps) : null,
      });
    }
    const out = [];
    for (const [name, points] of byName) out.push({ name, points });
    return out;
  }

  // Combined device history in the HISTORY API contract shape (docs §HISTORY API):
  //   { serial, metrics:[{ts,cpu_load,free_memory,temperature,ppp_sessions}],
  //     interfaces:[{name, points:[{ts,rx_bps,tx_bps}]}] }
  // Both series cover the last `windowSeconds` (ts >= now() - window) and are time-ASCENDING.
  // Returns null for an UNKNOWN serial (route 404s) — distinct from a known device with no
  // history (empty arrays). A sane row cap (HISTORY_ROW_CAP) bounds each query so a wide
  // window on a busy multi-interface router can't return an unbounded result set; we take the
  // MOST RECENT rows (ORDER BY ts DESC LIMIT cap) then re-sort ascending for the chart. The
  // `window` label is owned by the handler.
  async function getDeviceHistory(serial, windowSeconds) {
    const device = await getDeviceBySerial(serial);
    if (!device) return null;
    const win = typeof windowSeconds === 'number' && windowSeconds > 0 ? windowSeconds : 3600;

    const mRows = await rows(
      `SELECT ts, cpu_load, free_memory, temperature, ppp_sessions
         FROM metrics_history
        WHERE device_id = $1
          AND ts >= now() - ($2 || ' seconds')::interval
        ORDER BY ts DESC
        LIMIT ${HISTORY_ROW_CAP}`,
      [device.id, String(win)]
    );
    const metrics = mRows
      .map((row) => ({
        ts: row.ts instanceof Date ? row.ts.toISOString() : String(row.ts),
        cpu_load: row.cpu_load != null ? Number(row.cpu_load) : null,
        free_memory: row.free_memory != null ? Number(row.free_memory) : null,
        temperature: row.temperature != null ? Number(row.temperature) : null,
        ppp_sessions: row.ppp_sessions != null ? Number(row.ppp_sessions) : null,
      }))
      .reverse(); // DESC fetch -> ASC for the contract

    const iRows = await rows(
      `SELECT name, ts, rx_bps, tx_bps
         FROM interface_history
        WHERE device_id = $1
          AND ts >= now() - ($2 || ' seconds')::interval
        ORDER BY ts DESC
        LIMIT ${HISTORY_ROW_CAP}`,
      [device.id, String(win)]
    );
    const byName = new Map();
    // iRows are DESC; build ascending per-interface point arrays by unshifting.
    for (const row of iRows) {
      if (!byName.has(row.name)) byName.set(row.name, []);
      byName.get(row.name).unshift({
        ts: row.ts instanceof Date ? row.ts.toISOString() : String(row.ts),
        rx_bps: row.rx_bps != null ? Number(row.rx_bps) : null,
        tx_bps: row.tx_bps != null ? Number(row.tx_bps) : null,
      });
    }
    const interfaces = [];
    for (const name of Array.from(byName.keys()).sort()) {
      interfaces.push({ name, points: byName.get(name) });
    }

    return { serial, metrics, interfaces };
  }

  // ── worker: staleness / alerts / retention ──────────────────────────────────
  // Bump device_state.status by last_seen_at age. online -> stale -> offline.
  async function markStaleDevices(staleSeconds, offlineSeconds) {
    const offline = await q(
      `UPDATE device_state
          SET status = 'offline'
        WHERE status <> 'offline'
          AND last_seen_at < now() - ($1 || ' seconds')::interval`,
      [String(offlineSeconds)]
    );
    const stale = await q(
      `UPDATE device_state
          SET status = 'stale'
        WHERE status NOT IN ('stale','offline')
          AND last_seen_at < now() - ($1 || ' seconds')::interval
          AND last_seen_at >= now() - ($2 || ' seconds')::interval`,
      [String(staleSeconds), String(offlineSeconds)]
    );
    return { stale: stale.rowCount || 0, offline: offline.rowCount || 0 };
  }

  async function getActiveAlertRules() {
    return rows(
      `SELECT id, name, metric, comparator, threshold, for_seconds, severity, scope_tag, enabled,
              notify_email, notify_teams_webhook, notify_on, neighbor_platform
         FROM alert_rules
        WHERE enabled = true`,
      []
    );
  }

  // Evaluate each enabled rule against current device_state and open/clear alerts.
  // The threshold decision itself is transform.evaluateAlert (pure, unit-tested); this
  // method only does the store reads/writes around it.
  // ── alert-rule CRUD (operator-facing; backs the Rules UI) ──────────────────────
  async function listAlertRules() {
    return rows(`SELECT * FROM alert_rules ORDER BY id`, []);
  }
  // Shared param vector for insert/update (full-object semantics — the form sends every field).
  function ruleParams(f) {
    return [
      f.name, f.metric, f.comparator || '>=', nz(f.threshold),
      f.for_seconds != null ? f.for_seconds : 0, f.severity || 'warning',
      nz(f.scope_tag), f.enabled !== false,
      nz(f.notify_email), nz(f.notify_teams_webhook), f.notify_on || 'both', nz(f.neighbor_platform),
    ];
  }
  async function createAlertRule(f) {
    return one(
      `INSERT INTO alert_rules
         (name,metric,comparator,threshold,for_seconds,severity,scope_tag,enabled,
          notify_email,notify_teams_webhook,notify_on,neighbor_platform)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      ruleParams(f)
    );
  }
  async function updateAlertRule(id, f) {
    return one(
      `UPDATE alert_rules SET
         name=$2, metric=$3, comparator=$4, threshold=$5, for_seconds=$6, severity=$7,
         scope_tag=$8, enabled=$9, notify_email=$10, notify_teams_webhook=$11,
         notify_on=$12, neighbor_platform=$13
       WHERE id=$1 RETURNING *`,
      [id, ...ruleParams(f)]
    );
  }
  async function deleteAlertRule(id) {
    const r = await q(`DELETE FROM alert_rules WHERE id=$1`, [id]);
    return (r.rowCount || 0) > 0;
  }
  // Alert history (rule hits) — newest first, with device + rule names for the UI.
  async function listAlerts(limit) {
    const n = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
    return rows(
      `SELECT a.id, a.severity, a.state, a.detail, a.opened_at, a.cleared_at, a.acked_at, a.acked_by,
              d.serial, d.site_name, d.identity,
              r.name AS rule_name, r.metric AS rule_metric
         FROM alerts a
         JOIN devices d ON d.id = a.device_id
         LEFT JOIN alert_rules r ON r.id = a.rule_id
        ORDER BY a.opened_at DESC
        LIMIT $1`,
      [n]
    );
  }

  async function evaluateAndApplyAlerts(rulesIn) {
    const rules = Array.isArray(rulesIn) ? rulesIn : await getActiveAlertRules();
    let opened = 0;
    let cleared = 0;
    const transitions = []; // open/clear events for the worker to notify on

    // Anti-flap state machine (honours rule.for_seconds, Prometheus-style `for:`): a firing
    // condition first parks as 'pending' (not counted, not notified); it only promotes to
    // 'open' (and emits an open transition) once it's been firing for for_seconds. If it stops
    // firing while pending, the pending row is dropped — so a transient blip never alarms and
    // never flaps. for_seconds=0 → opens immediately (legacy behaviour). Returns a transition
    // to notify on (open/clear) or null.
    async function applyAlertState(deviceId, rule, firing, detail, serial, siteName, value) {
      const forS = rule.for_seconds != null ? Math.max(0, Math.round(Number(rule.for_seconds))) : 0;
      const cur = await one(
        `SELECT id, state, (now() - opened_at) >= make_interval(secs => $3) AS due
           FROM alerts
          WHERE device_id = $1 AND rule_id = $2 AND state IN ('open','pending')
          ORDER BY opened_at DESC LIMIT 1`,
        [deviceId, rule.id, forS]
      );
      if (firing) {
        if (!cur) {
          const state = forS <= 0 ? 'open' : 'pending';
          await q(`INSERT INTO alerts (device_id, rule_id, severity, state, detail, opened_at) VALUES ($1,$2,$3,$4,$5, now())`,
            [deviceId, rule.id, rule.severity || 'warning', state, detail]);
          if (state === 'open') { opened += 1; return { kind: 'open', device_id: deviceId, serial, site_name: siteName, detail, value, rule }; }
          return null; // pending — not yet alarmed
        }
        if (cur.state === 'pending' && cur.due) {
          await q(`UPDATE alerts SET state='open', opened_at=now(), detail=$2 WHERE id=$1`, [cur.id, detail]);
          opened += 1;
          return { kind: 'open', device_id: deviceId, serial, site_name: siteName, detail, value, rule };
        }
        return null; // pending-not-yet-due, or already open
      }
      // not firing
      if (!cur) return null;
      if (cur.state === 'pending') { await q(`DELETE FROM alerts WHERE id=$1`, [cur.id]); return null; }
      await q(`UPDATE alerts SET state='cleared', cleared_at=now() WHERE id=$1`, [cur.id]);
      cleared += 1;
      return { kind: 'clear', device_id: deviceId, serial, site_name: siteName, detail, value, rule };
    }

    for (const rule of rules) {
      if (rule.enabled === false) continue;

      // ── neighbour-drop (e.g. a Yealink phone) — own evaluation path against the neighbors
      // table. A neighbour matching neighbor_platform that hasn't been seen for > threshold
      // seconds (but is still within the prune TTL, so it's "known but gone") counts as down.
      if (rule.metric === 'neighbor_down') {
        const thr = rule.threshold != null ? Math.round(Number(rule.threshold)) : 300;
        const devs = await rows(
          `SELECT d.id AS device_id, d.serial AS serial, d.site_name AS site_name
             FROM devices d WHERE ($1::text IS NULL OR $1 = ANY (d.tags))`,
          [rule.scope_tag || null]
        );
        for (const d of devs) {
          const dropped = await rows(
            `SELECT identity, mac::text AS mac FROM neighbors
              WHERE device_id = $1
                AND ($2::text IS NULL OR platform ILIKE '%' || $2 || '%')
                AND last_seen_at < now() - make_interval(secs => $3)
              ORDER BY last_seen_at ASC`,
            [d.device_id, rule.neighbor_platform || null, thr]
          );
          const firing = dropped.length > 0;
          const names = dropped.map((n) => n.identity || n.mac).slice(0, 5).join(', ');
          const detail = `${rule.name}: ${dropped.length} ${rule.neighbor_platform || 'neighbour'}(s) not seen >${thr}s${names ? ' — ' + names : ''}`;
          const tr = await applyAlertState(d.device_id, rule, firing, detail, d.serial, d.site_name, dropped.length);
          if (tr) transitions.push(tr);
        }
        continue; // handled — skip the device_state path for this rule
      }

      // Candidate devices: all, or only those carrying scope_tag. Pull the metric value
      // (status for 'offline', else the matching device_state column) for each.
      const metricCol = alertMetricColumn(rule.metric);
      const selectVal =
        rule.metric === 'offline'
          ? 's.status'
          : metricCol
          ? `s.${metricCol}`
          : 'NULL';

      const candidates = await rows(
        `SELECT d.id AS device_id, d.serial AS serial, d.site_name AS site_name,
                ${selectVal} AS value, s.status AS status
           FROM devices d
           JOIN device_state s ON s.device_id = d.id
          WHERE ($1::text IS NULL OR $1 = ANY (d.tags))`,
        [rule.scope_tag || null]
      );

      for (const c of candidates) {
        const value = rule.metric === 'offline' ? c.status : c.value;
        const firing = transform.evaluateAlert(rule, value);
        const detail = `${rule.name}: ${rule.metric} ${rule.comparator} ${rule.threshold == null ? '' : rule.threshold} (value=${value == null ? 'null' : value})`;
        const tr = await applyAlertState(c.device_id, rule, firing, detail, c.serial, c.site_name, value);
        if (tr) transitions.push(tr);
      }
    }

    return { opened, cleared, transitions };
  }

  // ── retention / downsample ───────────────────────────────────────────────
  // Roll raw rows older than 1h into 1-minute buckets (best-effort idempotent rollup).
  async function downsampleHistory(now) {
    const at = now ? new Date(now) : new Date();
    const cutoff = at.toISOString();

    await tx(async (client) => {
      // metrics_history: average into 1-min buckets for rows older than 1h, then delete originals.
      await client.query(
        `WITH src AS (
           SELECT device_id,
                  date_trunc('minute', ts) AS bucket,
                  avg(cpu_load)::int       AS cpu_load,
                  avg(free_memory)::bigint AS free_memory,
                  avg(temperature)         AS temperature,
                  avg(ppp_sessions)::int   AS ppp_sessions,
                  avg(conn_count)::int     AS conn_count
             FROM metrics_history
            WHERE ts < ($1::timestamptz - interval '1 hour')
              AND ts <> date_trunc('minute', ts)
            GROUP BY device_id, date_trunc('minute', ts)
         )
         INSERT INTO metrics_history (device_id, ts, cpu_load, free_memory, temperature, ppp_sessions, conn_count)
         SELECT device_id, bucket, cpu_load, free_memory, temperature, ppp_sessions, conn_count FROM src
         ON CONFLICT (device_id, ts) DO NOTHING`,
        [cutoff]
      );
      await client.query(
        `DELETE FROM metrics_history
          WHERE ts < ($1::timestamptz - interval '1 hour')
            AND ts <> date_trunc('minute', ts)`,
        [cutoff]
      );

      // interface_history: same 1-min rollup.
      await client.query(
        `WITH src AS (
           SELECT device_id, name,
                  date_trunc('minute', ts) AS bucket,
                  avg(rx_bps)::bigint AS rx_bps,
                  avg(tx_bps)::bigint AS tx_bps,
                  max(rx_error)       AS rx_error,
                  max(tx_error)       AS tx_error
             FROM interface_history
            WHERE ts < ($1::timestamptz - interval '1 hour')
              AND ts <> date_trunc('minute', ts)
            GROUP BY device_id, name, date_trunc('minute', ts)
         )
         INSERT INTO interface_history (device_id, name, ts, rx_bps, tx_bps, rx_error, tx_error)
         SELECT device_id, name, bucket, rx_bps, tx_bps, rx_error, tx_error FROM src
         ON CONFLICT (device_id, name, ts) DO NOTHING`,
        [cutoff]
      );
      await client.query(
        `DELETE FROM interface_history
          WHERE ts < ($1::timestamptz - interval '1 hour')
            AND ts <> date_trunc('minute', ts)`,
        [cutoff]
      );
    });
  }

  // Hard prune of history beyond raw retention window (default 24h via worker/config).
  async function pruneHistory(now, retentionHours) {
    const at = now ? new Date(now) : new Date();
    const hours = typeof retentionHours === 'number' ? retentionHours : 24;
    const cutoff = new Date(at.getTime() - hours * 3600 * 1000).toISOString();
    const m = await q(`DELETE FROM metrics_history WHERE ts < $1`, [cutoff]);
    const i = await q(`DELETE FROM interface_history WHERE ts < $1`, [cutoff]);
    const l = await q(`DELETE FROM lte_history WHERE ts < $1`, [cutoff]);
    return {
      metrics: m.rowCount || 0,
      interfaces: i.rowCount || 0,
      lte: l.rowCount || 0,
    };
  }

  async function pruneNeighbors(now, ttlSeconds) {
    const at = now ? new Date(now) : new Date();
    const ttl = typeof ttlSeconds === 'number' ? ttlSeconds : 86400;
    const cutoff = new Date(at.getTime() - ttl * 1000).toISOString();
    const r = await q(`DELETE FROM neighbors WHERE last_seen_at < $1`, [cutoff]);
    return { pruned: r.rowCount || 0 };
  }

  async function pruneMacHosts(now, ttlSeconds) {
    const at = now ? new Date(now) : new Date();
    const ttl = typeof ttlSeconds === 'number' ? ttlSeconds : 86400;
    const cutoff = new Date(at.getTime() - ttl * 1000).toISOString();
    const r = await q(`DELETE FROM mac_hosts WHERE last_seen_at < $1`, [cutoff]);
    return { pruned: r.rowCount || 0 };
  }

  // ── tags & smart tags ────────────────────────────────────────────────────
  // Tags are the grouping primitive the rest of the platform selects on
  // (`alert_rules.scope_tag`, `config_jobs.target_tag`). A tag is either MANUAL
  // (set here by an operator) or RULE-OWNED (recomputed by syncSmartTags from a
  // tag_rules row) — never both, so the worker can't clobber operator edits.

  // Every tag in use, with how many devices carry it and whether a rule owns it.
  // Drives the tag pickers in the UI so scoping is pick-from-list, not free text.
  async function listTags() {
    return rows(
      `SELECT t.tag,
              count(*)::int AS devices,
              EXISTS (SELECT 1 FROM tag_rules r WHERE r.tag = t.tag) AS rule_owned
         FROM (SELECT unnest(tags) AS tag FROM devices) t
        GROUP BY t.tag
        ORDER BY t.tag`,
      []
    );
  }

  // Replace a device's MANUAL tags. Rule-owned tags currently on the device are
  // preserved untouched (the worker owns those), and any rule-owned name in the
  // incoming list is ignored rather than silently reverted a tick later.
  async function setDeviceTags(serial, tagsIn) {
    const device = await getDeviceBySerial(serial);
    if (!device) return null;
    const ruleTags = new Set((await rows(`SELECT tag FROM tag_rules`, [])).map((r) => r.tag));
    const manual = (Array.isArray(tagsIn) ? tagsIn : [])
      .map((t) => String(t == null ? '' : t).trim())
      .filter(Boolean)
      .filter((t) => !ruleTags.has(t));
    const keptSmart = (device.tags || []).filter((t) => ruleTags.has(t));
    const final = Array.from(new Set([...keptSmart, ...manual])).sort();
    return one(
      `UPDATE devices SET tags = $2 WHERE serial = $1
       RETURNING serial, site_name, tags`,
      [serial, final]
    );
  }

  // The agent reports /system identity on every tick but nothing persisted it, so
  // devices.identity was empty fleet-wide and useless for grouping. Called from the
  // telemetry handler ONLY when the value has changed.
  async function setDeviceIdentity(deviceId, identity) {
    return one(
      `UPDATE devices SET identity = $2 WHERE id = $1 AND identity IS DISTINCT FROM $2
       RETURNING id, serial, identity`,
      [deviceId, identity == null ? null : String(identity)]
    );
  }

  // Operator-editable device metadata. `customer` is the one that matters: the audited
  // MikroTik→company link lives in the field app's own database, so Vigilant can only know
  // it if it is written across — which is what makes customer-scoped tag rules possible.
  async function updateDeviceMeta(serial, fields) {
    const f = fields || {};
    return one(
      `UPDATE devices SET
         customer  = COALESCE($2, customer),
         site_name = COALESCE($3, site_name),
         identity  = COALESCE($4, identity),
         model     = COALESCE($5, model),
         wan_type  = COALESCE($6, wan_type)
       WHERE serial = $1
       RETURNING serial, site_name, customer, identity, model, wan_type, tags`,
      [serial, nz(f.customer), nz(f.site_name), nz(f.identity), nz(f.model), nz(f.wan_type)]
    );
  }

  async function listTagRules() {
    return rows(
      `SELECT id, name, tag, conditions, enabled, created_at, updated_at
         FROM tag_rules ORDER BY tag`,
      []
    );
  }

  async function createTagRule(f) {
    const r = f || {};
    return one(
      `INSERT INTO tag_rules (name, tag, conditions, enabled)
       VALUES ($1,$2,COALESCE($3,'{"all":[]}'::jsonb),COALESCE($4,true))
       RETURNING id, name, tag, conditions, enabled, created_at, updated_at`,
      [String(r.name || r.tag || '').trim(), String(r.tag || '').trim(),
       r.conditions ? JSON.stringify(r.conditions) : null,
       typeof r.enabled === 'boolean' ? r.enabled : null]
    );
  }

  async function updateTagRule(id, f) {
    const r = f || {};
    return one(
      `UPDATE tag_rules SET
         name       = COALESCE($2, name),
         tag        = COALESCE($3, tag),
         conditions = COALESCE($4, conditions),
         enabled    = COALESCE($5, enabled),
         updated_at = now()
       WHERE id = $1
       RETURNING id, name, tag, conditions, enabled, created_at, updated_at`,
      [id, nz(r.name), nz(r.tag), r.conditions ? JSON.stringify(r.conditions) : null,
       typeof r.enabled === 'boolean' ? r.enabled : null]
    );
  }

  // Deleting a rule also strips its tag from every device, so a removed rule can't
  // leave orphan tags behind that look manual but nobody set.
  async function deleteTagRule(id) {
    const rule = await one(`SELECT tag FROM tag_rules WHERE id = $1`, [id]);
    if (!rule) return { deleted: 0, untagged: 0 };
    const u = await q(
      `UPDATE devices SET tags = array_remove(tags, $1) WHERE $1 = ANY(tags)`,
      [rule.tag]
    );
    const d = await q(`DELETE FROM tag_rules WHERE id = $1`, [id]);
    return { deleted: d.rowCount || 0, untagged: u.rowCount || 0 };
  }

  // How many devices a set of conditions would match, plus a sample — so the UI can
  // show the blast radius BEFORE the rule is saved.
  async function previewTagRule(conditions) {
    const c = compileTagConditions(conditions, 1);
    const n = await one(`SELECT count(*)::int AS n FROM devices d WHERE ${c.sql}`, c.params);
    // Read ros_version from device_state, same as the matcher — selecting it off `devices`
    // would show "no version" for every row and make the preview look broken.
    const sample = await rows(
      `SELECT d.serial, d.site_name, d.customer, d.model, d.wan_type,
              (SELECT s.ros_version FROM device_state s WHERE s.device_id = d.id) AS ros_version
         FROM devices d WHERE ${c.sql}
        ORDER BY d.site_name NULLS LAST LIMIT 10`,
      c.params
    );
    return { count: n ? n.n : 0, sample };
  }

  // Recompute membership for every enabled rule. Idempotent: adds the tag to devices
  // that match and don't have it, removes it from devices that have it and no longer
  // match. A rule whose conditions are empty matches nothing, so its tag is removed
  // everywhere rather than applied to the whole fleet.
  async function syncSmartTags() {
    const rules = await rows(
      `SELECT id, name, tag, conditions FROM tag_rules WHERE enabled ORDER BY id`,
      []
    );
    const out = { rules: 0, added: 0, removed: 0, errors: [] };
    for (const r of rules) {
      let c;
      try {
        c = compileTagConditions(r.conditions, 2); // $1 is the tag
      } catch (e) {
        out.errors.push({ tag: r.tag, message: e.message });
        continue;
      }
      const add = await q(
        `UPDATE devices d SET tags = array_append(d.tags, $1)
          WHERE NOT ($1 = ANY(d.tags)) AND (${c.sql})`,
        [r.tag, ...c.params]
      );
      const del = await q(
        `UPDATE devices d SET tags = array_remove(d.tags, $1)
          WHERE $1 = ANY(d.tags) AND NOT (${c.sql})`,
        [r.tag, ...c.params]
      );
      out.rules += 1;
      out.added += add.rowCount || 0;
      out.removed += del.rowCount || 0;
    }
    return out;
  }

  // ── PMR virtual desktop: pharmacies, counters, counter Pis ────────────────
  // A counter Pi is a `devices` row (kind='counter-pi'), so it inherits Vigilant's
  // token auth, telemetry, alerting and tags. These methods add only what Vigilant
  // does not already model. Derived addressing is never written — it comes from the
  // generated columns and counters_v.

  async function listPharmacies() {
    return rows(
      `SELECT p.*,
              (SELECT count(*) FROM counters c WHERE c.pharmacy_id = p.id)::int AS counters,
              (SELECT count(*) FROM counters c WHERE c.pharmacy_id = p.id
                 AND c.pi_device_id IS NOT NULL)::int AS pis_enrolled
         FROM pharmacies p ORDER BY p.idx`,
      []
    );
  }

  async function getPharmacy(idOrCode) {
    // Accept either the surrogate id or the human code, so URLs can use the code.
    return one(
      `SELECT * FROM pharmacies
        WHERE ($1 ~ '^[0-9]+$' AND id = ($1)::bigint) OR upper(code) = upper($1)`,
      [String(idOrCode)]
    );
  }

  async function createPharmacy(f) {
    const r = f || {};
    return one(
      `INSERT INTO pharmacies (code, idx, name, pmr_system, status, proxmox_node, srv_vmid, go_live_on, notes)
       VALUES ($1,$2,$3,COALESCE($4,'proscript'),COALESCE($5,'planned'),$6,$7,$8,$9)
       RETURNING *`,
      [String(r.code || '').trim().toUpperCase(), r.idx, String(r.name || '').trim(),
       nz(r.pmr_system), nz(r.status), nz(r.proxmox_node), nz(r.srv_vmid), nz(r.go_live_on), nz(r.notes)]
    );
  }

  async function updatePharmacy(id, f) {
    const r = f || {};
    // idx is deliberately NOT updatable: it derives the VLAN and every address in the
    // subnet, all of which are already live in nftables, dnsmasq and the VM configs.
    // Renumbering a pharmacy is a migration, not a field edit.
    return one(
      `UPDATE pharmacies SET
         name = COALESCE($2, name), pmr_system = COALESCE($3, pmr_system),
         status = COALESCE($4, status), proxmox_node = COALESCE($5, proxmox_node),
         srv_vmid = COALESCE($6, srv_vmid), go_live_on = COALESCE($7, go_live_on),
         notes = COALESCE($8, notes)
       WHERE id = $1 RETURNING *`,
      [id, nz(r.name), nz(r.pmr_system), nz(r.status), nz(r.proxmox_node),
       nz(r.srv_vmid), nz(r.go_live_on), nz(r.notes)]
    );
  }

  // Cascades to counters (FK ON DELETE CASCADE). The Pis' `devices` rows survive —
  // deleting a pharmacy record should not silently unenroll hardware that still exists.
  async function deletePharmacy(id) {
    const r = await q(`DELETE FROM pharmacies WHERE id = $1`, [id]);
    return { deleted: r.rowCount || 0 };
  }

  async function listCounters(pharmacyId) {
    if (pharmacyId) {
      return rows(`SELECT * FROM counters_v WHERE pharmacy_id = $1 ORDER BY n`, [pharmacyId]);
    }
    return rows(`SELECT * FROM counters_v ORDER BY pharmacy_code, n`, []);
  }

  async function getCounter(id) {
    return one(`SELECT * FROM counters_v WHERE id = $1`, [id]);
  }

  async function createCounter(f) {
    const r = f || {};
    const created = await one(
      `INSERT INTO counters (pharmacy_id, n, label, status, vmid, vm_hostname, pi_hostname, pi_model, peripherals, notes)
       VALUES ($1,$2,$3,COALESCE($4,'planned'),$5,$6,$7,$8,COALESCE($9,'{}'::jsonb),$10)
       RETURNING id`,
      [r.pharmacy_id, r.n, nz(r.label), nz(r.status), nz(r.vmid), nz(r.vm_hostname),
       nz(r.pi_hostname), nz(r.pi_model),
       r.peripherals ? JSON.stringify(r.peripherals) : null, nz(r.notes)]
    );
    return created ? getCounter(created.id) : null;
  }

  async function updateCounter(id, f) {
    const r = f || {};
    // `n` is not updatable for the same reason as pharmacy idx — it derives the VM's
    // address and the Pi's tunnel /32, both already configured on the gateway.
    const updated = await one(
      `UPDATE counters SET
         label = COALESCE($2, label), status = COALESCE($3, status),
         vmid = COALESCE($4, vmid), vm_hostname = COALESCE($5, vm_hostname),
         pi_hostname = COALESCE($6, pi_hostname), pi_model = COALESCE($7, pi_model),
         peripherals = COALESCE($8, peripherals), notes = COALESCE($9, notes)
       WHERE id = $1 RETURNING id`,
      [id, nz(r.label), nz(r.status), nz(r.vmid), nz(r.vm_hostname), nz(r.pi_hostname),
       nz(r.pi_model), r.peripherals ? JSON.stringify(r.peripherals) : null, nz(r.notes)]
    );
    return updated ? getCounter(id) : null;
  }

  async function deleteCounter(id) {
    const r = await q(`DELETE FROM counters WHERE id = $1`, [id]);
    return { deleted: r.rowCount || 0 };
  }

  // Attach an already-created Vigilant device (the Pi) to a counter. Token minting
  // stays in the handler, matching how router enrolment already works.
  async function linkCounterPi(counterId, f) {
    const r = f || {};
    const updated = await one(
      `UPDATE counters SET
         pi_device_id  = COALESCE($2, pi_device_id),
         pi_hostname   = COALESCE($3, pi_hostname),
         pi_model      = COALESCE($4, pi_model),
         pi_public_key = COALESCE($5, pi_public_key),
         pi_enrolled_at = now()
       WHERE id = $1 RETURNING id`,
      [counterId, nz(r.pi_device_id), nz(r.pi_hostname), nz(r.pi_model), nz(r.pi_public_key)]
    );
    return updated ? getCounter(counterId) : null;
  }

  // Queue a one-shot service action. Overwrites any undelivered one rather than building a
  // backlog: the operator's most recent intent is the only one that makes sense to run.
  async function setCounterAction(id, f) {
    const r = f || {};
    const updated = await one(
      `UPDATE counters SET pending_action = $2, pending_action_by = $3, pending_action_at = now()
        WHERE id = $1 RETURNING id`,
      [id, r.action, nz(r.by)]
    );
    return updated ? getCounter(id) : null;
  }

  // Hand over the pending action AND clear it in the same statement.
  //
  // The clear is the whole point: a reboot directive still pending when the Pi came back up
  // would be collected again, and the counter would reboot forever. RHS expressions see the
  // pre-UPDATE row, so last_action captures what is being handed out.
  async function takeCounterAction(deviceId) {
    return one(
      `UPDATE counters SET
         pending_action = NULL,
         last_action    = pending_action,
         last_action_by = pending_action_by,
         last_action_at = now()
       WHERE pi_device_id = $1 AND pending_action IS NOT NULL
       RETURNING last_action AS action`,
      [deviceId]
    );
  }

  // ── which VM a thin client boots into ──────────────────────────────────────
  // The operator picks a VM; the ADDRESS is resolved HERE rather than in the browser, so
  // the UI cannot push a counter at an address the platform's own numbering disagrees
  // with. Resolution follows the only two conventions the gateway actually implements:
  // the PMR server at .10 (pharmacies.server_ip), and counter desktop n at .20+n.
  //
  // A vmid matching neither is REFUSED rather than guessed at — it means the VM was
  // discovered but never registered to this pharmacy, which is the step being skipped.
  async function setCounterBootTarget(id, f) {
    const r = f || {};
    const updated = await one(
      `WITH ctx AS (
         SELECT c.id, c.pharmacy_id, p.idx, p.server_ip, p.srv_vmid
           FROM counters c JOIN pharmacies p ON p.id = c.pharmacy_id
          WHERE c.id = $1
       ), resolved AS (
         SELECT ctx.id,
                CASE WHEN ctx.srv_vmid = $2 THEN ctx.server_ip
                     WHEN sib.id IS NOT NULL THEN '10.' || ctx.idx || '.0.' || (20 + sib.n)
                END AS ip
           FROM ctx
           LEFT JOIN counters sib ON sib.pharmacy_id = ctx.pharmacy_id AND sib.vmid = $2
       )
       UPDATE counters c SET
         boot_vmid   = $2,
         boot_target = resolved.ip || ':3389',
         boot_set_by = $3,
         boot_set_at = now(),
         -- Cleared deliberately: until the Pi confirms the NEW target it has not applied it,
         -- and leaving the old timestamp would read as "already done".
         boot_applied_at = NULL
       FROM resolved
       WHERE c.id = resolved.id AND resolved.ip IS NOT NULL
       RETURNING c.id`,
      [id, r.vmid, nz(r.by)]
    );
    return updated ? getCounter(id) : null;
  }

  // What to tell this Pi on its next tick, plus the confirmation stamp.
  //
  // The stamp is computed from the state row the telemetry handler has ALREADY written, so
  // this needs nothing from the payload. Guarded on boot_applied_at IS NULL so the hot path
  // writes once per change rather than on every 30 s tick.
  //
  // Compares the CONFIGURED target, never the connected one: a Pi on the Cloudflare
  // fallback is connected to 127.0.0.1:33389, which would never match a chosen VM.
  async function getCounterBootDirective(deviceId) {
    await q(
      `UPDATE counters c SET boot_applied_at = now()
         FROM device_state ds
        WHERE ds.device_id = c.pi_device_id
          AND c.pi_device_id = $1
          AND c.boot_applied_at IS NULL
          AND c.boot_target IS NOT NULL
          AND split_part(ds.raw -> 'rdp' ->> 'configured_target', ':', 1)
              = split_part(c.boot_target, ':', 1)`,
      [deviceId]
    );
    return one(
      `SELECT boot_vmid AS vmid, boot_target AS target
         FROM counters WHERE pi_device_id = $1 AND boot_target IS NOT NULL`,
      [deviceId]
    );
  }

  // ── observed WireGuard state, reported by a collector on the hub ───────────
  async function reportWgPeers(peers) {
    const list = Array.isArray(peers) ? peers : [];
    if (!list.length) return { peers: 0 };
    // Same batching discipline as the telemetry path: one multi-row upsert, deduped on
    // the conflict key so a repeated public key in one report can't abort the statement.
    const uniq = dedupeBy(list.filter((p) => p && p.public_key), (p) => p.public_key);
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO wg_peers (public_key, allowed_ips, endpoint, latest_handshake, rx_bytes, tx_bytes, seen_at)`,
        `ON CONFLICT (public_key) DO UPDATE SET
           allowed_ips = EXCLUDED.allowed_ips, endpoint = EXCLUDED.endpoint,
           latest_handshake = EXCLUDED.latest_handshake,
           rx_bytes = EXCLUDED.rx_bytes, tx_bytes = EXCLUDED.tx_bytes, seen_at = now()`,
        6,
        uniq.map((p) => [
          p.public_key, nz(p.allowed_ips), nz(p.endpoint),
          // Accept epoch seconds (what `wg show dump` prints) or an ISO string; 0 = never.
          p.latest_handshake ? new Date(typeof p.latest_handshake === 'number'
            ? p.latest_handshake * 1000 : p.latest_handshake).toISOString() : null,
          Number(p.rx_bytes) || 0, Number(p.tx_bytes) || 0,
        ]),
        placeholders(6, 'now()')
      );
    });
    return { peers: uniq.length };
  }

  // Observed peers joined to the counter that owns them. A row with no counter is a Pi
  // on the VPN that nobody registered — worth seeing, not hiding.
  async function listWgPeers() {
    return rows(
      `SELECT w.*, c.id AS counter_id, c.n AS counter_n, p.code AS pharmacy_code,
              (w.latest_handshake IS NOT NULL
               AND w.latest_handshake > now() - interval '3 minutes') AS online
         FROM wg_peers w
         LEFT JOIN counters c   ON c.pi_public_key = w.public_key
         LEFT JOIN pharmacies p ON p.id = c.pharmacy_id
        ORDER BY w.latest_handshake DESC NULLS LAST`,
      []
    );
  }

  // ── printers ───────────────────────────────────────────────────────────────
  // Reported by an agent on the pharmacy LAN (the counter Pi), since nothing in the
  // datacentre can reach a printer on a site network.

  async function listPrinters(pharmacyId) {
    if (pharmacyId) return rows(`SELECT * FROM printers_v WHERE pharmacy_id = $1 ORDER BY name`, [pharmacyId]);
    return rows(`SELECT * FROM printers_v ORDER BY pharmacy_code, name`, []);
  }

  async function upsertPrinter(f) {
    const r = f || {};
    // Operator-set identity fields are COALESCEd so a discovery report can fill blanks
    // but never blank out something a human typed (a friendly model, the counter link).
    const saved = await one(
      `INSERT INTO printers (pharmacy_id, counter_id, name, address, make, model, serial,
                             discovered_via, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (pharmacy_id, name) DO UPDATE SET
         counter_id     = COALESCE(EXCLUDED.counter_id, printers.counter_id),
         address        = COALESCE(EXCLUDED.address,    printers.address),
         make           = COALESCE(EXCLUDED.make,       printers.make),
         model          = COALESCE(EXCLUDED.model,      printers.model),
         serial         = COALESCE(EXCLUDED.serial,     printers.serial),
         discovered_via = COALESCE(EXCLUDED.discovered_via, printers.discovered_via),
         notes          = COALESCE(EXCLUDED.notes,      printers.notes)
       RETURNING id`,
      [r.pharmacy_id, nz(r.counter_id), String(r.name || '').trim(), nz(r.address),
       nz(r.make), nz(r.model), nz(r.serial), nz(r.discovered_via), nz(r.notes)]
    );
    return saved ? one(`SELECT * FROM printers_v WHERE id = $1`, [saved.id]) : null;
  }

  async function deletePrinter(id) {
    const r = await q(`DELETE FROM printers WHERE id = $1`, [id]);
    return { deleted: r.rowCount || 0 };
  }

  // A poll report from one Pi: identity is filled in only where blank, observed state is
  // replaced wholesale. Batched into a single multi-row upsert like the telemetry path.
  async function reportPrinters(deviceId, pharmacyId, list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(arr.filter((p) => p && String(p.name || '').trim()), (p) => String(p.name).trim());
    if (!uniq.length) return { printers: 0 };
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO printers (pharmacy_id, name, address, make, model, serial, discovered_via,
                               status, state_reasons, page_count, supplies, queue_depth,
                               jobs_failed, reported_by, last_seen_at)`,
        `ON CONFLICT (pharmacy_id, name) DO UPDATE SET
           address        = COALESCE(printers.address, EXCLUDED.address),
           make           = COALESCE(printers.make,   EXCLUDED.make),
           model          = COALESCE(printers.model,  EXCLUDED.model),
           serial         = COALESCE(printers.serial, EXCLUDED.serial),
           discovered_via = COALESCE(printers.discovered_via, EXCLUDED.discovered_via),
           status         = EXCLUDED.status,
           state_reasons  = EXCLUDED.state_reasons,
           -- Lifetime page count only ever goes up; a lower value means a failed read or a
           -- replaced unit, and taking it would corrupt any usage figure derived from it.
           page_count     = GREATEST(COALESCE(printers.page_count, 0), COALESCE(EXCLUDED.page_count, 0)),
           supplies       = EXCLUDED.supplies,
           queue_depth    = EXCLUDED.queue_depth,
           jobs_failed    = EXCLUDED.jobs_failed,
           reported_by    = EXCLUDED.reported_by,
           last_seen_at   = now()`,
        14,
        uniq.map((p) => [
          pharmacyId, String(p.name).trim(), nz(p.address), nz(p.make), nz(p.model), nz(p.serial),
          nz(p.discovered_via), nz(p.status), nz(p.state_reasons),
          p.page_count == null ? null : Number(p.page_count),
          JSON.stringify(Array.isArray(p.supplies) ? p.supplies : []),
          p.queue_depth == null ? null : Number(p.queue_depth),
          p.jobs_failed == null ? null : Number(p.jobs_failed),
          nz(deviceId),
        ]),
        placeholders(14, 'now()')
      );
    });
    return { printers: uniq.length };
  }

  // ── discovered Proxmox VMs ─────────────────────────────────────────────────
  // Pushed by a collector running ON a Proxmox node (Vigilant has no route to the
  // management VLAN, and inverting the direction avoids opening one).

  async function reportProxmoxVms(list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(arr.filter((v) => v && Number.isFinite(Number(v.vmid))), (v) => Number(v.vmid));
    if (!uniq.length) return { vms: 0 };
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO proxmox_vms (vmid, node, name, status, vlan_tag, macs, cores, maxmem, maxdisk, uptime_s, template, seen_at)`,
        `ON CONFLICT (vmid) DO UPDATE SET
           node = EXCLUDED.node, name = EXCLUDED.name, status = EXCLUDED.status,
           vlan_tag = EXCLUDED.vlan_tag, macs = EXCLUDED.macs, cores = EXCLUDED.cores,
           maxmem = EXCLUDED.maxmem, maxdisk = EXCLUDED.maxdisk,
           uptime_s = EXCLUDED.uptime_s, template = EXCLUDED.template, seen_at = now()`,
        11,
        uniq.map((v) => [
          Number(v.vmid), nz(v.node), nz(v.name), nz(v.status),
          v.vlan_tag == null ? null : Number(v.vlan_tag),
          JSON.stringify(Array.isArray(v.macs) ? v.macs : []),
          v.cores == null ? null : Number(v.cores),
          v.maxmem == null ? null : Number(v.maxmem),
          v.maxdisk == null ? null : Number(v.maxdisk),
          v.uptime_s == null ? null : Number(v.uptime_s),
          v.template === true,
        ]),
        placeholders(11, 'now()')
      );
    });
    return { vms: uniq.length };
  }

  // Fill in what discovery can prove, and report what it cannot resolve.
  //
  // FILLS BLANKS ONLY. A vmid that disagrees with the discovered one is returned as a
  // conflict, never overwritten: it usually means the VM was rebuilt under a new id, and
  // silently repointing a pharmacy's records at a different VM is exactly the kind of
  // "helpful" change that loses an afternoon.
  async function reconcileProxmox() {
    const vms = await rows(
      `SELECT v.vmid, v.node, v.name, v.vlan_tag, p.id AS pharmacy_id, p.srv_vmid, p.proxmox_node
         FROM proxmox_vms v
         JOIN pharmacies p ON p.vlan = v.vlan_tag
        WHERE v.vlan_tag IS NOT NULL AND NOT v.template`,
      []
    );
    const out = { servers_linked: 0, counters_linked: 0, nodes_set: 0, conflicts: [] };

    for (const v of vms) {
      // The PMR server for the site.
      if (/-srv$/i.test(v.name || '')) {
        if (v.srv_vmid == null) {
          await q(`UPDATE pharmacies SET srv_vmid = $2 WHERE id = $1 AND srv_vmid IS NULL`, [v.pharmacy_id, v.vmid]);
          out.servers_linked += 1;
        } else if (v.srv_vmid !== v.vmid) {
          out.conflicts.push({ kind: 'pharmacy_srv_vmid', pharmacy_id: v.pharmacy_id, recorded: v.srv_vmid, discovered: v.vmid, name: v.name });
        }
        if (v.proxmox_node == null && v.node) {
          await q(`UPDATE pharmacies SET proxmox_node = $2 WHERE id = $1 AND proxmox_node IS NULL`, [v.pharmacy_id, v.node]);
          out.nodes_set += 1;
        }
        continue;
      }

      // A counter's desktop VM: pmr-<code>-cl<NN> where NN is the counter number.
      const m = /-cl0*(\d+)$/i.exec(v.name || '');
      if (!m) continue;
      const n = Number(m[1]);
      const counter = await one(`SELECT id, vmid FROM counters WHERE pharmacy_id = $1 AND n = $2`, [v.pharmacy_id, n]);
      if (!counter) {
        // A desktop VM exists for a counter nobody has recorded — worth knowing, since it
        // means the registry is behind reality rather than ahead of it.
        out.conflicts.push({ kind: 'counter_missing', pharmacy_id: v.pharmacy_id, counter_n: n, discovered: v.vmid, name: v.name });
        continue;
      }
      if (counter.vmid == null) {
        await q(`UPDATE counters SET vmid = $2, vm_hostname = COALESCE(vm_hostname, $3) WHERE id = $1`,
          [counter.id, v.vmid, v.name]);
        out.counters_linked += 1;
      } else if (counter.vmid !== v.vmid) {
        out.conflicts.push({ kind: 'counter_vmid', counter_id: counter.id, counter_n: n, recorded: counter.vmid, discovered: v.vmid, name: v.name });
      }
    }
    return out;
  }

  async function listProxmoxVms() {
    return rows(`SELECT * FROM proxmox_vms_v ORDER BY vlan_tag NULLS LAST, vmid`, []);
  }

  // Expose the pool so callers (bin/migrate, graceful shutdown) can end() it.
  async function end() {
    await pool.end();
  }

  return {
    reportProxmoxVms,
    reconcileProxmox,
    listProxmoxVms,
    listPrinters,
    upsertPrinter,
    deletePrinter,
    reportPrinters,
    listPharmacies,
    getPharmacy,
    createPharmacy,
    updatePharmacy,
    deletePharmacy,
    listCounters,
    getCounter,
    createCounter,
    updateCounter,
    deleteCounter,
    linkCounterPi,
    setCounterBootTarget,
    setCounterAction,
    takeCounterAction,
    getCounterBootDirective,
    reportWgPeers,
    listWgPeers,
    listTags,
    setDeviceTags,
    setDeviceIdentity,
    updateDeviceMeta,
    listTagRules,
    createTagRule,
    updateTagRule,
    deleteTagRule,
    previewTagRule,
    syncSmartTags,
    pool,
    migrate,
    getDeviceByToken,
    getDeviceBySerial,
    createDevice,
    setDeviceToken,
    getInterfaceStates,
    upsertDeviceState,
    touchDeviceState,
    upsertInterfaceStates,
    upsertLteState,
    upsertNeighbors,
    upsertMacHosts,
    upsertWifiNetworks,
    upsertWirelessClients,
    appendDeviceLogs,
    getDeviceLogs,
    pruneDeviceLogs,
    appendMetricsHistory,
    appendInterfaceHistory,
    appendLteHistory,
    setPollWindow,
    getPendingConfigJob,
    getConfigJobForFetch,
    getConfirmedJob,
    markConfigJob,
    recordConfigResult,
    createConfigJob,
    approveConfigJob,
    cancelConfigJob,
    listConfigJobs,
    getConfigJob,
    createSpeedtestJob,
    getPendingSpeedtestJob,
    markSpeedtestRunning,
    recordSpeedtestResult,
    getSpeedtestJob,
    listSpeedtestJobs,
    appendAudit,
    getCurrentAgentScript,
    getFleet,
    getDeviceDetail,
    getMetricsHistory,
    getInterfaceHistory,
    getDeviceHistory,
    markStaleDevices,
    getActiveAlertRules,
    listAlertRules,
    listAlerts,
    createAlertRule,
    updateAlertRule,
    deleteAlertRule,
    evaluateAndApplyAlerts,
    downsampleHistory,
    pruneHistory,
    pruneNeighbors,
    pruneMacHosts,
    end,
  };
}

// ── module-private helpers ──────────────────────────────────────────────────

// Resolve a pg Pool from an existing pool, a URL string, or a config object.
function resolvePool(poolOrConfig) {
  if (!poolOrConfig) {
    throw new Error('makePgStore: a pg Pool, database URL, or config is required');
  }
  // Duck-type an existing Pool (has .query and .connect).
  if (typeof poolOrConfig.query === 'function' && typeof poolOrConfig.connect === 'function') {
    return poolOrConfig;
  }
  if (typeof poolOrConfig === 'string') {
    return makePool(poolOrConfig);
  }
  const url = poolOrConfig.databaseUrl || poolOrConfig.connectionString;
  if (!url) {
    throw new Error('makePgStore: config must provide databaseUrl or connectionString');
  }
  return makePool(url);
}

// ── smart-tag condition compiler ────────────────────────────────────────────
// Turn a tag rule's {"all":[{field,op,value}, …]} into a parameterised WHERE fragment
// over `devices d`. Fields and operators are WHITELISTED and values are always bound —
// nothing from the rule is ever interpolated into SQL.
//
// Attributes only, by design. Live telemetry is excluded because thresholds on state are
// what alert_rules already do, and a tag that flapped with state would make scoping an
// alert rule to it circular.
// Some attributes live on `devices` (operator-set metadata) and some only arrive with
// telemetry, which lands in `device_state`. ros_version is the important one: `devices`
// .ros_version is never written by the ingest (0/363 populated as of 2026-07-29) while
// device_state.ros_version is complete and varied — so a firmware-cohort rule has to read
// the state table or it silently matches nothing/everything. Pulled via a correlated
// subquery so every call site (SELECT preview and UPDATE sync) works unchanged, and
// devices with no state row simply yield NULL rather than being dropped by a join.
const fromState = (col) => `(SELECT s.${col} FROM device_state s WHERE s.device_id = d.id)`;

const TAG_FIELDS = {
  serial: { expr: 'd.serial', kind: 'text' },
  identity: { expr: 'd.identity', kind: 'text' },
  site_name: { expr: 'd.site_name', kind: 'text' },
  customer: { expr: 'd.customer', kind: 'text' },
  model: { expr: 'd.model', kind: 'text' },
  wan_type: { expr: 'd.wan_type', kind: 'text' },
  expected: { expr: 'd.expected', kind: 'bool' },
  // Lets a smart tag group the fleet by device type, e.g. kind = 'counter-pi'.
  kind: { expr: 'd.kind', kind: 'text' },
  ros_version: { expr: fromState('ros_version'), kind: 'text' },
  firmware: { expr: fromState('firmware'), kind: 'text' },
};

// RouterOS versions must compare NUMERICALLY — plain text ordering puts '7.9' after
// '7.16', which would silently invert an "older than" rule. Pull the leading numeric-dot
// run out of values like "7.16.1 (stable)" and let Postgres compare int[] element-wise.
// substring() uses a non-capturing group so it returns the whole match, not group 1.
const versionArray = (expr) =>
  `string_to_array(COALESCE(substring(COALESCE(${expr},'') from '[0-9]+(?:\\.[0-9]+)*'), '0'), '.')::int[]`;

function tagRuleError(message) {
  const err = new Error(message);
  err.status = 400;
  return err;
}

function compileTagConditions(conditions, startIdx) {
  let parsed = conditions;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); } catch (_) { throw tagRuleError('conditions is not valid JSON'); }
  }
  const list = parsed && Array.isArray(parsed.all) ? parsed.all : [];
  const params = [];
  const parts = [];
  let i = typeof startIdx === 'number' ? startIdx : 1;

  for (const raw of list) {
    const c = raw || {};
    const field = c.field;
    const spec = TAG_FIELDS[field];
    if (!spec) {
      throw tagRuleError(`unknown condition field "${field}" (allowed: ${Object.keys(TAG_FIELDS).join(', ')})`);
    }
    const kind = spec.kind;
    const op = String(c.op || '').toLowerCase();
    const col = spec.expr;

    if (kind === 'bool') {
      if (op !== 'eq') throw tagRuleError(`field "${field}" only supports op "eq"`);
      parts.push(`${col} = $${i}::boolean`);
      params.push(c.value === true || c.value === 'true');
      i += 1;
      continue;
    }

    switch (op) {
      // Case-insensitive so "Allied" and "allied" behave the same for operators.
      case 'eq':
        parts.push(`lower(${col}) = lower($${i})`); params.push(String(c.value ?? '')); i += 1; break;
      // NULL-safe: a device with no model should satisfy "model is not X".
      case 'ne':
        parts.push(`(${col} IS NULL OR lower(${col}) <> lower($${i}))`); params.push(String(c.value ?? '')); i += 1; break;
      case 'contains':
        parts.push(`${col} ILIKE '%'||$${i}||'%'`); params.push(String(c.value ?? '')); i += 1; break;
      case 'not_contains':
        parts.push(`(${col} IS NULL OR ${col} NOT ILIKE '%'||$${i}||'%')`); params.push(String(c.value ?? '')); i += 1; break;
      case 'starts_with':
        parts.push(`${col} ILIKE $${i}||'%'`); params.push(String(c.value ?? '')); i += 1; break;
      case 'in': {
        const vals = (Array.isArray(c.value) ? c.value : String(c.value ?? '').split(','))
          .map((v) => String(v).trim()).filter(Boolean);
        if (!vals.length) throw tagRuleError(`op "in" on "${field}" needs at least one value`);
        parts.push(`lower(${col}) = ANY (SELECT lower(x) FROM unnest($${i}::text[]) x)`);
        params.push(vals); i += 1; break;
      }
      case 'is_empty':
        parts.push(`(${col} IS NULL OR ${col} = '')`); break;
      case 'is_not_empty':
        parts.push(`(${col} IS NOT NULL AND ${col} <> '')`); break;
      // Version-aware: "older than 7.16" / "at least 7.16".
      // A device with NO reported version must NOT match either way — an unknown version
      // is not an old one. Without this guard "older than 7.16" matched the entire fleet,
      // because an empty string normalises to version 0.
      case 'version_lt':
        parts.push(`(${col} IS NOT NULL AND ${col} <> '' AND ${versionArray(col)} < ${versionArray(`$${i}`)})`);
        params.push(String(c.value ?? '')); i += 1; break;
      case 'version_gte':
        parts.push(`(${col} IS NOT NULL AND ${col} <> '' AND ${versionArray(col)} >= ${versionArray(`$${i}`)})`);
        params.push(String(c.value ?? '')); i += 1; break;
      default:
        throw tagRuleError(`unknown operator "${c.op}" for field "${field}"`);
    }
  }

  // An empty rule must match NOTHING. Defaulting to TRUE here would tag the entire
  // fleet the moment someone saved a half-written rule.
  return { sql: parts.length ? parts.join(' AND ') : 'false', params };
}

// Coerce undefined -> null so parameterised queries get a clean SQL NULL.
function nz(v) {
  return v === undefined ? null : v;
}

// RFC-4122 UUID shape. Guard BEFORE binding an externally-supplied id to a `uuid` column:
// Postgres throws "invalid input syntax for type uuid" on a malformed value, and a device/
// agent that POSTs a bad job_id (observed: job_id="t" from a /speedtest/result) previously
// rejected unhandled and crash-looped the whole ingest. Callers treat a non-UUID as "not
// found" (return null), so the handler 404s instead of the query throwing.
function isUuid(v) {
  return (
    typeof v === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)
  );
}

// Coerce to boolean or null (never undefined) for nullable boolean columns.
function nb(v) {
  if (v === undefined || v === null) return null;
  return Boolean(v);
}

// Map an alert rule metric name to a device_state column we can read it from.
// Returns null for metrics that aren't a direct device_state column (e.g. rx_bps,
// which is per-interface and evaluated elsewhere) so the caller can skip them.
function alertMetricColumn(metric) {
  const allowed = new Set([
    'cpu_load',
    'temperature',
    'free_memory',
    'free_hdd',
    'voltage',
    'ppp_sessions',
    'dhcp_leases',
    'conn_count',
    'lte_signal',
    'cpu_temperature',
    'board_temperature',
    'fan1_speed',
    'fan2_speed',
    'write_sect_total',
    'netwatch_down',
    'uptime_s',
  ]);
  return allowed.has(metric) ? metric : null;
}

module.exports = { makePgStore };
