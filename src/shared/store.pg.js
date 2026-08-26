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
      // `kind` is selected for the same reason getDeviceByToken selects it: a caller that
      // resolves a device by serial has to be able to tell a RouterOS box from a thin client
      // before acting on it (the relay only works through a Pi, config-push only through a
      // router), and without it every such caller needs a second query.
      `SELECT id, serial, identity, site_name, customer, model, ros_version, wan_type,
              tags, expected, poll_interval_s, poll_until, agent_version, enrolled_at, notes,
              kind, pppoe_password
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
          firmware_current, firmware_upgrade, ntp_synced, netwatch_down, last_seen_at, raw,
          recent_logs, smartcard_stack_ok)
       VALUES ($1,COALESCE($2,'unknown'),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
               $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,COALESCE($28, now()),$29,$30,$31)
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
         raw               = EXCLUDED.raw,
         -- COALESCE, not EXCLUDED. A thin client reports every 60 s but only carries
         -- log lines when it has some; taking EXCLUDED unconditionally would blank the
         -- stored set on the very next quiet tick, which is precisely the bug this
         -- column was added to fix. Last known logs persist until newer ones arrive.
         recent_logs       = COALESCE(EXCLUDED.recent_logs, device_state.recent_logs),
         -- COALESCE for the same reason as recent_logs, plus one of its own: null here means
         -- "this agent said nothing about smartcards", which is the normal case for most of
         -- the estate. Taking EXCLUDED unconditionally would erase a counter's last known
         -- good/broken verdict on any tick that omitted the block, so the alert would flap.
         smartcard_stack_ok = COALESCE(EXCLUDED.smartcard_stack_ok, device_state.smartcard_stack_ok)`,
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
        s.recent_logs != null ? JSON.stringify(s.recent_logs) : null,
        // nz() would map 0 to null and silently turn "smartcard stack BROKEN" into "no
        // opinion", which is the one value this column exists to report.
        s.smartcard_stack_ok == null ? null : (s.smartcard_stack_ok ? 1 : 0),
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


  // ── thin-client screen thumbnails ───────────────────────────────────────────
  // One row per device, overwritten every capture. See device_screens' comment: this is
  // patient-visible screen content, so there is deliberately no history and no second copy.
  async function upsertDeviceScreen(deviceId, shot) {
    const s = shot || {};
    await q(
      `INSERT INTO device_screens (device_id, captured_at, width, height, mime, bytes)
       VALUES ($1, COALESCE($2, now()), $3, $4, COALESCE($5, 'image/jpeg'), $6)
       ON CONFLICT (device_id) DO UPDATE SET
         captured_at = EXCLUDED.captured_at,
         width       = EXCLUDED.width,
         height      = EXCLUDED.height,
         mime        = EXCLUDED.mime,
         bytes       = EXCLUDED.bytes`,
      [deviceId, s.capturedAt || null, nz(s.width), nz(s.height), s.mime || null, s.bytes]
    );
  }

  async function getDeviceScreen(deviceId) {
    return one(
      `SELECT captured_at, width, height, mime, bytes FROM device_screens WHERE device_id = $1`,
      [deviceId]
    );
  }

  // Short retention is a privacy control, not housekeeping: a thumbnail of a counter is only
  // worth keeping while it is current, and a stale one is both misleading and PHI at rest.
  async function pruneDeviceScreens() {
    const r = await q(`DELETE FROM device_screens WHERE captured_at < now() - interval '6 hours'`, []);
    return { pruned: r.rowCount || 0 };
  }

  // ── fleet-wide thin-client branding ─────────────────────────────────────────
  // One row, id = 1, for the whole estate — see branding's comment in schema.sql for why
  // there is no per-site variant. Every method below pins id = 1 rather than taking a key,
  // so no caller can invent a second row.

  // Metadata read. Deliberately does NOT select the `splash` blob: this is called on the
  // TELEMETRY PATH for every thin-client tick, and dragging up to 2 MB of PNG out of the
  // database several hundred times a minute to then throw it away is exactly the per-tick cost
  // that has saturated this service before. octet_length() is computed in the database.
  async function getBranding() {
    return one(
      `SELECT motd, issue, kiosk_message, splash_sha256, splash_width, splash_height,
              octet_length(splash) AS splash_bytes, splash_updated_at, updated_at, updated_by
         FROM branding
        WHERE id = 1`,
      []
    );
  }

  // The blob itself, for GET /branding/splash only.
  async function getBrandingSplash() {
    return one(
      `SELECT splash AS bytes, splash_sha256, splash_width, splash_height, splash_updated_at
         FROM branding
        WHERE id = 1 AND splash IS NOT NULL`,
      []
    );
  }

  /**
   * Partial text update. `fields` carries only the keys the operator actually sent, so the
   * CASE-per-column applies each one independently.
   *
   * Written as ONE upsert rather than read-modify-write on purpose: two operators saving
   * different fields from the same Watchman page would otherwise each write back the other's
   * stale value, and the loser's edit would vanish with no error anywhere.
   */
  async function updateBrandingText(fields, updatedBy) {
    const f = fields || {};
    const has = (k) => Object.prototype.hasOwnProperty.call(f, k);
    await q(
      `INSERT INTO branding (id, motd, issue, kiosk_message, updated_at, updated_by)
       VALUES (1, $1, $3, $5, now(), $7)
       ON CONFLICT (id) DO UPDATE SET
         motd          = CASE WHEN $2 THEN $1 ELSE branding.motd END,
         issue         = CASE WHEN $4 THEN $3 ELSE branding.issue END,
         kiosk_message = CASE WHEN $6 THEN $5 ELSE branding.kiosk_message END,
         updated_at    = now(),
         updated_by    = $7`,
      [
        has('motd') ? f.motd : null,
        has('motd'),
        has('issue') ? f.issue : null,
        has('issue'),
        has('kiosk_message') ? f.kiosk_message : null,
        has('kiosk_message'),
        updatedBy != null ? updatedBy : 'unknown',
      ]
    );
    return getBranding();
  }

  // Store a validated PNG. The caller has already checked the magic bytes, the size cap and
  // read the dimensions out of the IHDR chunk — the store does not re-parse the image.
  async function setBrandingSplash(shot, updatedBy) {
    const s = shot || {};
    await q(
      `INSERT INTO branding (id, splash, splash_sha256, splash_width, splash_height,
                             splash_updated_at, updated_at, updated_by)
       VALUES (1, $1, $2, $3, $4, now(), now(), $5)
       ON CONFLICT (id) DO UPDATE SET
         splash            = EXCLUDED.splash,
         splash_sha256     = EXCLUDED.splash_sha256,
         splash_width      = EXCLUDED.splash_width,
         splash_height     = EXCLUDED.splash_height,
         splash_updated_at = now(),
         updated_at        = now(),
         updated_by        = EXCLUDED.updated_by`,
      [s.bytes, s.sha256 || null, nz(s.width), nz(s.height), updatedBy != null ? updatedBy : 'unknown']
    );
    return getBranding();
  }

  // Remove the splash but keep the text branding. splash_sha256 going to NULL is the signal
  // the agent reads to put the stock theme back, so all four splash columns must clear
  // together — a stale sha with no bytes would make the agent fetch a 404 forever.
  async function clearBrandingSplash(updatedBy) {
    await q(
      `UPDATE branding
          SET splash = NULL, splash_sha256 = NULL, splash_width = NULL, splash_height = NULL,
              splash_updated_at = NULL, updated_at = now(), updated_by = $1
        WHERE id = 1`,
      [updatedBy != null ? updatedBy : 'unknown']
    );
    return getBranding();
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
      // MEASURED 2026-08-19: a telemetry POST carrying `logs` hung for >20s while the
      // byte-identical POST without it returned in 0.2s, reproducibly, alternating. Every
      // tick ships logs, so the device stopped reporting entirely and went stale — the whole
      // counter looked dead because of a log write.
      //
      // The insert itself is a single multi-row statement, so the time is spent WAITING, not
      // working: contending on the (device_id, log_time, message) primary key, whose entries
      // are whole log lines. Once one request stalls, the next tick re-sends the same lines
      // and queues behind it, which is why it never recovers on its own.
      //
      // These are per-transaction and reset on commit. A log line is the least important
      // thing this request carries: losing it is invisible, whereas blocking the transaction
      // costs the device's boot target, its settings and its liveness. So bound the wait and
      // let the rest of the tick through.
      await client.query("SET LOCAL lock_timeout = '2s'");
      await client.query("SET LOCAL statement_timeout = '5s'");
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
      // NINE values for the nine columns. created_by_credential records whether that name was
      // PROVED by an operator token or typed into the body under the shared admin token — see
      // the A6 block on the table in db/schema.sql. It defaults FALSE here for the same reason
      // it defaults false on the column: an unstated attribution is an unproved one.
      `INSERT INTO config_jobs
         (device_id, target_tag, is_canary, kind, rsc_text, rsc_sha256, status,
          confirm_window_s, created_by, created_by_credential)
       VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,$8,$9)
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
        f.created_by_credential === true,
      ]
    );
  }

  // Approve a DRAFT -> 'approved'. The WHERE status='draft' guard makes this a no-op (returns
  // null) if the job was already advanced/cancelled, so a double-approve can't reopen it.
  async function approveConfigJob(jobId, approvedBy, approvedByCredential) {
    return one(
      `UPDATE config_jobs
          SET status = 'approved', approved_by = $2, approved_at = now(),
              approved_by_credential = $3
        WHERE id = $1 AND status = 'draft'
        RETURNING *`,
      [jobId, approvedBy != null ? approvedBy : null, approvedByCredential === true]
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

  // The PPPoE password (a secret) reported on the agent's slow tick. Same write discipline as
  // setDeviceIdentity: the WHERE ... IS DISTINCT FROM makes an unchanged value a no-op, so the
  // per-tick fleet load never turns into a write storm. Stored on devices (not device_state) so
  // it stays off the Realtime publication — the caller must also keep it out of device_state.raw.
  async function setDevicePppoePassword(deviceId, pw) {
    return one(
      `UPDATE devices SET pppoe_password = $2 WHERE id = $1 AND pppoe_password IS DISTINCT FROM $2
       RETURNING id`,
      [deviceId, pw == null ? null : String(pw)]
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

  // Full removal of a device from the register. Every device-scoped table cascades from
  // the devices row (schema FKs), so one DELETE takes live state, history, the enrollment
  // token, config jobs/snapshots and alerts with it. audit_log is keyed by the serial
  // STRING, not a FK — the trail, including the delete row itself, survives. An ONLINE
  // device is refused unless force: deleting a router that is still reporting is almost
  // always a mistake, and its agent would keep POSTing into 401s afterwards.
  async function deleteDevice(serial, opts) {
    const force = !!(opts && opts.force);
    const dev = await one(
      `SELECT d.id, d.serial, d.identity, d.site_name, d.customer, d.enrolled_at,
              s.status, s.last_seen_at
         FROM devices d LEFT JOIN device_state s ON s.device_id = d.id
        WHERE d.serial = $1`,
      [serial]
    );
    if (!dev) return null;
    if (dev.status === 'online' && !force) return { blocked: 'online', device: dev };
    await q(`DELETE FROM devices WHERE id = $1`, [dev.id]);
    return { deleted: true, device: dev };
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
    // The network columns are optional: any left NULL are filled from idx by the
    // pharmacies_fill_net() trigger, so the common case still passes only code/idx/name.
    // prefix_len is NOT NULL, so COALESCE it to the /27 default rather than passing NULL.
    return one(
      `INSERT INTO pharmacies (code, idx, name, pmr_system, status, proxmox_node, srv_vmid, go_live_on, notes, crm_site_id,
                               prefix_len, gateway_ip, server_ip, dhcp_from, dhcp_to, dns_servers, domain, lease_time, ntp_server)
       VALUES ($1,$2,$3,COALESCE($4,'proscript'),COALESCE($5,'planned'),$6,$7,$8,$9,$10,
               COALESCE($11,27),$12,$13,$14,$15,$16,$17,$18,$19)
       RETURNING *`,
      [String(r.code || '').trim().toUpperCase(), r.idx, String(r.name || '').trim(),
       nz(r.pmr_system), nz(r.status), nz(r.proxmox_node), nz(r.srv_vmid), nz(r.go_live_on), nz(r.notes),
       nz(r.crm_site_id),
       nz(r.prefix_len), nz(r.gateway_ip), nz(r.server_ip), nz(r.dhcp_from), nz(r.dhcp_to),
       nz(r.dns_servers), nz(r.domain), nz(r.lease_time), nz(r.ntp_server)]
    );
  }

  async function updatePharmacy(id, f) {
    const r = f || {};
    // idx is deliberately NOT updatable: it derives the VLAN and the network address (10.idx.0.0),
    // which are baked into every counter Pi's WireGuard AllowedIPs. Renumbering a pharmacy is a
    // migration, not a field edit. prefix_len and the addressing DO update — but note that
    // changing them here only moves the REGISTRY; the gateway's live dnsmasq/nftables follow
    // from a config-push job (Phase 2), not from this write.
    const updated = await one(
      `UPDATE pharmacies SET
         name = COALESCE($2, name), pmr_system = COALESCE($3, pmr_system),
         status = COALESCE($4, status), proxmox_node = COALESCE($5, proxmox_node),
         srv_vmid = COALESCE($6, srv_vmid), go_live_on = COALESCE($7, go_live_on),
         notes = COALESCE($8, notes),
         prefix_len  = COALESCE($9, prefix_len),
         gateway_ip  = COALESCE($10, gateway_ip),
         server_ip   = COALESCE($11, server_ip),
         dhcp_from   = COALESCE($12, dhcp_from),
         dhcp_to     = COALESCE($13, dhcp_to),
         dns_servers = COALESCE($14, dns_servers),
         domain      = COALESCE($15, domain),
         lease_time  = COALESCE($16, lease_time),
         ntp_server  = COALESCE($17, ntp_server)
       WHERE id = $1 RETURNING *`,
      [id, nz(r.name), nz(r.pmr_system), nz(r.status), nz(r.proxmox_node),
       nz(r.srv_vmid), nz(r.go_live_on), nz(r.notes),
       nz(r.prefix_len), nz(r.gateway_ip), nz(r.server_ip), nz(r.dhcp_from), nz(r.dhcp_to),
       nz(r.dns_servers), nz(r.domain), nz(r.lease_time), nz(r.ntp_server)]
    );
    // The per-site counter banner is set DIRECTLY (not COALESCE) so it can be CLEARED, and only
    // when the caller actually includes it — so editing a pharmacy's name never wipes its banner.
    // An empty message clears both fields; the level is validated here.
    if (Object.prototype.hasOwnProperty.call(r, 'banner_text')) {
      const text = (r.banner_text == null || String(r.banner_text).trim() === '')
        ? null : String(r.banner_text);
      const level = ['info', 'warning', 'alert'].includes(r.banner_level)
        ? r.banner_level : (text ? 'info' : null);
      return one(
        `UPDATE pharmacies SET banner_text = $2, banner_level = $3, updated_at = now()
           WHERE id = $1 RETURNING *`,
        [id, text, level]
      );
    }
    return updated;
  }

  // The counter banner shown on a device's Pi: its pharmacy's, resolved via the counter that owns
  // the device. Returns { banner_text, banner_level } or null when the Pi is not linked to a
  // counter yet (a bench Pi, or one enrolled before its counter row was created).
  async function getSiteBanner(deviceId) {
    return one(
      `SELECT p.banner_text, p.banner_level
         FROM counters c JOIN pharmacies p ON p.id = c.pharmacy_id
        WHERE c.pi_device_id = $1`,
      [deviceId]
    );
  }

  // Cascades to counters (FK ON DELETE CASCADE). The Pis' `devices` rows survive —
  // deleting a pharmacy record should not silently unenroll hardware that still exists.
  // ⚠️ THE TYPED CONFIRMATION IS ENFORCED HERE, IN THE STATEMENT (B4). It used to be
  // enforced by a `disabled` attribute on a button, which is not a boundary: DELETE
  // /pharmacies/:id called this unconditionally, and this deleted the row — cascading every
  // counter, printer, VM registration, hours row and job for a pharmacy that may have been
  // dispensing at the time. With no user roles anywhere in Watchman, that dialog was the
  // ONLY thing standing between a mis-click and a live site, so it has to exist on the wire
  // and be checked by the server.
  //
  // Two guards, and they answer different questions:
  //   confirm  did a human deliberately name THIS site? Compared trimmed and case-folded
  //            against pharmacies.name inside the DELETE, so there is no window between the
  //            check and the delete in which the name could change.
  //   force    a LIVE site needs a second, separate act. Status is a fact about whether
  //            people are dispensing on it right now; a typed name is not consent to that.
  //
  // Returns enough for the caller to say WHICH refusal it was — 404, wrong name, or live —
  // because "nothing happened" is the answer that gets retried harder.
  async function deletePharmacy(idOrCode, opts = {}) {
    const confirm = typeof opts.confirm === 'string' ? opts.confirm : '';
    const r = await one(
      `WITH target AS (
         SELECT id, name, status FROM pharmacies
          WHERE ($1 ~ '^[0-9]+$' AND id = ($1)::bigint) OR upper(code) = upper($1)
       ), gone AS (
         DELETE FROM pharmacies p USING target t
          WHERE p.id = t.id
            AND btrim($2) <> ''
            AND lower(btrim(t.name)) = lower(btrim($2))
            AND (t.status <> 'live' OR $3::boolean)
         RETURNING p.id
       )
       SELECT (SELECT count(*) FROM target)::int AS found,
              (SELECT count(*) FROM gone)::int   AS deleted,
              (SELECT t.name   FROM target t LIMIT 1) AS name,
              (SELECT t.status FROM target t LIMIT 1) AS status`,
      [String(idOrCode), confirm, !!opts.force]
    );
    return r || { found: 0, deleted: 0, name: null, status: null };
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

  // The same boundary as deletePharmacy, for the same reason (B4). Deleting a counter drops
  // its Pi's link, its boot target, its settings and every job addressed to it.
  //
  // A counter has no single obvious name, so THREE spellings are accepted and any of them
  // counts as having named this counter deliberately: its label, "counter <n>", or
  // "<SITE CODE> counter <n>". A blank confirmation is never one of them.
  async function deleteCounter(id, opts = {}) {
    const confirm = typeof opts.confirm === 'string' ? opts.confirm : '';
    const r = await one(
      `WITH target AS (
         SELECT c.id, c.n, c.label, c.status, p.code AS site_code
           FROM counters c JOIN pharmacies p ON p.id = c.pharmacy_id
          WHERE c.id = $1
       ), gone AS (
         DELETE FROM counters c USING target t
          WHERE c.id = t.id
            AND btrim($2) <> ''
            AND lower(btrim($2)) IN (
                  lower(btrim(COALESCE(t.label, ''))),
                  lower('counter ' || t.n),
                  lower(t.site_code || ' counter ' || t.n))
            AND (t.status <> 'live' OR $3::boolean)
         RETURNING c.id
       )
       SELECT (SELECT count(*) FROM target)::int AS found,
              (SELECT count(*) FROM gone)::int   AS deleted,
              (SELECT COALESCE(NULLIF(btrim(COALESCE(t.label, '')), ''), 'counter ' || t.n)
                 FROM target t LIMIT 1) AS name,
              (SELECT t.status FROM target t LIMIT 1) AS status`,
      [id, confirm, !!opts.force]
    );
    return r || { found: 0, deleted: 0, name: null, status: null };
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

  // Printers a site's MikroTik(s) have already SEEN on the LAN, straight from mac_hosts —
  // no sweep, no Pi. The router reports its DHCP/ARP tables every slow tick and Vigilant
  // already resolves OUI vendors, so a printer is discovered the moment it gets a lease.
  //
  // A printer is identified two ways, either sufficient:
  //   * OUI vendor — the manufacturer of a printer NIC is a printer maker.
  //   * hostname prefix — vendors' factory-default network names (Brother BRN…, HP NPI…,
  //     Ricoh RNP…, Kyocera KM…, Epson/Canon by name). Catches a printer whose OUI is an
  //     embedded-NIC vendor the OUI table renders generically.
  // Kept as ONE definition so the "is it a printer" rule lives in a single place.
  const PRINTER_VENDOR_RE = '(brother|hewlett|packard|hp inc|canon|epson|lexmark|kyocera|ricoh|xerox|zebra|dymo|\\yoki\\y|konica|minolta|sharp|toshiba tec|star micronics|bixolon|pantum|develop)';
  const PRINTER_HOST_RE   = '^(brn|npi|epson|canon|km[0-9]|rnp|lex|kyo|star|bixolon|pos-?printer|hpe?[0-9])';

  async function listLanPrinters(serials) {
    const list = Array.isArray(serials) ? serials.filter(Boolean) : [];
    if (!list.length) return [];
    return rows(
      `SELECT d.serial,
              mh.mac,
              host(mh.ip)      AS ip,
              mh.hostname,
              mh.vendor,
              mh.last_seen_at,
              -- Already a monitored printer at this site? Compared by address so a LAN find
              -- and a configured queue for the same box are not shown as two things.
              EXISTS (SELECT 1 FROM printers p WHERE p.address = host(mh.ip)) AS registered
         FROM mac_hosts mh
         JOIN devices d ON d.id = mh.device_id
        WHERE d.serial = ANY($1)
          AND mh.ip IS NOT NULL
          AND (mh.vendor ~* $2 OR (mh.hostname IS NOT NULL AND mh.hostname ~* $3))
        ORDER BY d.serial, mh.ip`,
      [list, PRINTER_VENDOR_RE, PRINTER_HOST_RE]
    );
  }

  async function getPrinter(id) {
    return one(`SELECT * FROM printers WHERE id = $1`, [id]);
  }

  // Queue an action against whichever counter owns this Pi. Printers are dispatched by
  // DEVICE rather than by counter because printers.reported_by names the Pi that can reach
  // the printer, and that is the only machine on the pharmacy LAN that can print to it.
  async function setCounterActionForDevice(deviceId, f) {
    const r = f || {};
    return one(
      `UPDATE counters SET pending_action = $2, pending_action_by = $3, pending_action_at = now()
        WHERE pi_device_id = $1 RETURNING id`,
      [deviceId, r.action, nz(r.by)]
    );
  }

  // The VMs this site's thin clients may be pointed at, joined to discovered inventory so
  // the caller gets names and power state without a second query. LEFT JOIN because a VM
  // that is registered but has not been discovered yet is still a legitimate choice.
  // Thin-client Pis that have called home but are not yet adopted onto a site — a device of
  // kind 'counter-pi' that no counter points at. This is the "out of the box, phoned in,
  // waiting to be claimed" list.
  async function listUnclaimedPis() {
    return rows(
      `SELECT d.id, d.serial, d.identity, d.model, d.enrolled_at,
              ds.status, ds.last_seen_at,
              ds.raw ->> 'primary_ip' AS lan_ip
         FROM devices d
         LEFT JOIN device_state ds ON ds.device_id = d.id
        WHERE d.kind = 'counter-pi'
          AND NOT EXISTS (SELECT 1 FROM counters c WHERE c.pi_device_id = d.id)
        ORDER BY ds.last_seen_at DESC NULLS LAST`,
      []
    );
  }

  // Adopt an unclaimed Pi: create a thin-client slot on the site at the next free number and
  // link the (already self-enrolled) device to it. The device keeps the token it got at
  // self-enrol — adoption only gives it a home, it does not re-issue credentials.
  async function adoptPi(deviceId, pharmacyId, label) {
    const counter = await one(
      `INSERT INTO counters (pharmacy_id, n, label, status)
       SELECT $1, gs.n, $2, 'building'
         FROM generate_series(1, 79) AS gs(n)
        WHERE NOT EXISTS (SELECT 1 FROM counters c WHERE c.pharmacy_id = $1 AND c.n = gs.n)
        ORDER BY gs.n
        LIMIT 1
       RETURNING id`,
      [pharmacyId, nz(label)]
    );
    if (!counter) return null;   // site already has all 79 slots
    await q(
      `UPDATE counters SET pi_device_id = $2, pi_enrolled_at = now() WHERE id = $1`,
      [counter.id, deviceId]
    );
    return getCounter(counter.id);
  }

  // Reshape the flat capacity columns from listPharmacyVms into the one nested object the UI
  // consumes. Kept as a function rather than inlined because three code paths return this list
  // (list, attach, detach) and they must not drift apart.
  //
  // Postgres returns bigint and numeric as STRINGS to node-postgres — '208734650368' rather
  // than a number — so every reading is coerced here. Without it the UI compares a string
  // against a threshold and 88% full sorts below 9%.
  function shapeVmCapacity(row) {
    const {
      // ALIASED at every call site, so the row's own top-level `mem_max_bytes` — which is
      // COALESCE(capacity, the hypervisor's configured maxmem) and is therefore populated for
      // VMs with no guest agent — is NOT destructured away into the capacity block. Without a
      // top-level one the estate's 12 GB server / 6 GB desktop standard cannot be checked at
      // all on the VMs that have no agent, which is most of them.
      capacity_cores, capacity_mem_max_bytes,
      cpu_pct_1d, cpu_pct_7d, cpu_pct_30d,
      mem_bytes_1d, mem_bytes_7d, mem_bytes_30d, mem_pressure_1d,
      disk_mount, disk_used_bytes, disk_total_bytes,
      disk_used_1d, disk_used_7d, disk_used_30d, disk_source,
      capacity_rrd_error, capacity_sampled_at,
      ...vm
    } = row;
    const n = (x) => (x == null || !Number.isFinite(Number(x)) ? null : Number(x));
    // sampled_at is NOT NULL in the table, so its absence means the LEFT JOIN found no row at
    // all: this VM has never been sampled. That is a different fact from "sampled, and the
    // readings were empty", and only the first may render as "no data yet".
    if (capacity_sampled_at == null) {
      vm.capacity = null;
      return vm;
    }
    vm.capacity = {
      cores: n(capacity_cores),
      memMaxBytes: n(capacity_mem_max_bytes),
      cpu: { d1: n(cpu_pct_1d), d7: n(cpu_pct_7d), d30: n(cpu_pct_30d) },
      mem: { d1: n(mem_bytes_1d), d7: n(mem_bytes_7d), d30: n(mem_bytes_30d) },
      memPressure1d: n(mem_pressure_1d),
      // NULL, not zero, when the guest agent could not be asked. VMs 302/303/304 have no agent
      // and their disk is genuinely unknown; a 0 here would render as an empty healthy disk.
      disk: disk_source !== 'agent' ? null : {
        mount: disk_mount == null ? null : String(disk_mount),
        usedBytes: n(disk_used_bytes),
        totalBytes: n(disk_total_bytes),
        source: 'agent',
        d1: n(disk_used_1d), d7: n(disk_used_7d), d30: n(disk_used_30d),
      },
      // Additive to the agreed contract, and load-bearing: several readings above survive a
      // failed pass by COALESCE, so the UI needs to be able to see how old they are.
      sampledAt: capacity_sampled_at,
      // Why the CPU/RAM figures above are the age they are. sampledAt only advances on a pass
      // that carried an RRD reading, so a stalled sampledAt plus a populated rrdError is the
      // pair that tells an engineer the RRD path is broken rather than the VM being idle.
      rrdError: capacity_rrd_error == null ? null : String(capacity_rrd_error),
    };
    return vm;
  }

  async function listPharmacyVms(pharmacyId) {
    const list = await rows(
      // The hypervisor columns come through here because this is what the site hub reads —
      // without them the VM layer is the only one in the section with nothing observed about
      // it, and `ip` above is DERIVED from the site index rather than seen. guest_ips is the
      // only reading that reflects what Windows actually did with its address.
      //
      // ALIAS `cap`, NOT `pv`: `pv` is already proxmox_vms on the line above, and reusing it
      // raises 42712 "table name pv specified more than once", which 500s this query on all
      // three of its callers (list, attach, detach) and takes the site's VMs tab down.
      //
      // LEFT JOIN, and it must stay one: a VM with no guest agent legitimately has no capacity
      // row, and an inner join would make it VANISH from its site rather than show as unknown.
      //
      // cap.cores and cap.seen-style columns are ALIASED — an unqualified second `cores` or
      // `seen_at` in the same SELECT silently wins in the result object (node-postgres keeps
      // the last), so the UI would start reading the capacity write time as the inventory one.
      `SELECT v.vmid, v.ip, v.role, v.source, v.counter_id, v.address_overridden,
              -- The CONFIGURED memory size, from pharmacy_vms_v: the capacity pass's reading
              -- when there is one, the hypervisor's own maxmem otherwise. NULL means neither
              -- knows, which the UI must read as "not established" and never as 0.
              v.mem_max_bytes,
              pv.name, pv.status, pv.node, pv.template,
              pv.agent_enabled, pv.agent_ok, pv.agent_error, pv.agent_checked_at,
              pv.guest_os, pv.guest_ips, pv.onboot, pv.seen_at,
              cap.cores AS capacity_cores, cap.mem_max_bytes AS capacity_mem_max_bytes,
              cap.cpu_pct_1d, cap.cpu_pct_7d, cap.cpu_pct_30d,
              cap.mem_bytes_1d, cap.mem_bytes_7d, cap.mem_bytes_30d, cap.mem_pressure_1d,
              cap.disk_mount, cap.disk_used_bytes, cap.disk_total_bytes,
              cap.disk_used_1d, cap.disk_used_7d, cap.disk_used_30d, cap.disk_source,
              cap.rrd_error AS capacity_rrd_error, cap.sampled_at AS capacity_sampled_at
         FROM pharmacy_vms_v v
         LEFT JOIN proxmox_vms pv ON pv.vmid = v.vmid
         LEFT JOIN pmr_vm_capacity cap ON cap.vmid = v.vmid
        WHERE v.pharmacy_id = $1
        ORDER BY v.vmid`,
      [pharmacyId]
    );
    return list.map(shapeVmCapacity);
  }

  // Attach an extra VM to a site. ON CONFLICT so re-attaching corrects the address instead
  // of failing, which is what an operator fixing a typo expects.
  async function attachPharmacyVm(pharmacyId, f) {
    const r = f || {};
    await q(
      `INSERT INTO pharmacy_vms (pharmacy_id, vmid, ip, label)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (pharmacy_id, vmid) DO UPDATE SET ip = EXCLUDED.ip, label = EXCLUDED.label`,
      [pharmacyId, r.vmid, String(r.ip || '').trim(), nz(r.label)]
    );
    return listPharmacyVms(pharmacyId);
  }

  async function detachPharmacyVm(pharmacyId, vmid) {
    // Unified "remove from site": whatever links this VM to the site is severed. That is any
    // explicit address (override or attached row), PLUS the assignment itself if the VM is
    // the site's PMR server or a thin client's desktop. So Remove behaves the same on every
    // row — the derived rows stop being read-only.
    const del  = await q(`DELETE FROM pharmacy_vms WHERE pharmacy_id = $1 AND vmid = $2`, [pharmacyId, vmid]);
    const srv  = await q(`UPDATE pharmacies SET srv_vmid = NULL WHERE id = $1 AND srv_vmid = $2`, [pharmacyId, vmid]);
    const desk = await q(`UPDATE counters SET vmid = NULL WHERE pharmacy_id = $1 AND vmid = $2`, [pharmacyId, vmid]);
    return { detached: (del.rowCount || 0) + (srv.rowCount || 0) + (desk.rowCount || 0) };
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
         SELECT c.id, c.pharmacy_id FROM counters c WHERE c.id = $1
       ), resolved AS (
         -- Reads pharmacy_vms_v, the SAME list the picker offers, so a choice that appears
         -- in the dropdown always resolves here. A vmid outside the site's list yields no
         -- row and the UPDATE below matches nothing, which the caller reports as a refusal.
         SELECT ctx.id, v.ip
           FROM ctx
           LEFT JOIN pharmacy_vms_v v
                  ON v.pharmacy_id = ctx.pharmacy_id AND v.vmid = $2
       )
       UPDATE counters c SET
         boot_vmid   = $2,
         boot_target = resolved.ip || ':3389',
         boot_set_by = $3,
         boot_set_at = now(),
         -- Cleared deliberately: until the Pi confirms the NEW target it has not applied it,
         -- and leaving the old timestamp would read as "already done".
         boot_applied_at = NULL,
         -- ⚠️ AND ANY STAGED CHANGE IS WITHDRAWN (D2). An operator who applies a target now
         -- has superseded whatever was queued for tonight; leaving it would let the promoter
         -- overwrite their choice at 22:00 and restart the counter a second time for a
         -- decision that was already reversed.
         boot_next_pending = false,
         boot_next_vmid    = NULL
       FROM resolved
       WHERE c.id = resolved.id AND resolved.ip IS NOT NULL
       RETURNING c.id`,
      [id, r.vmid, nz(r.by)]
    );
    return updated ? getCounter(id) : null;
  }

  // Back to the default (boot the site's PMR server). Clears the RESOLVED address too, not
  // just the chosen vmid — leaving a stale boot_target would keep being pushed to the device
  // and the UI would still show it as the answer.
  async function clearCounterBootTarget(id, by) {
    const updated = await one(
      `UPDATE counters SET
         boot_vmid = NULL, boot_target = NULL, boot_set_by = $2, boot_set_at = now(),
         boot_applied_at = NULL,
         -- Supersedes anything staged, for the same reason setCounterBootTarget does.
         boot_next_pending = false, boot_next_vmid = NULL
       WHERE id = $1 RETURNING id`,
      [id, nz(by)]
    );
    return updated ? getCounter(id) : null;
  }

  // ── the STAGED boot target (D2) ───────────────────────────────────────────
  // Record the choice and push NOTHING. The live columns are untouched, so the directive on
  // the next telemetry tick still carries the OLD target and the counter is not interrupted.
  // promoteCounterBootTargets() below moves it across when the site's gate opens.
  //
  // `vmid` null means "stage a return to the site's PMR server" — the staged form of
  // clearCounterBootTarget. It is distinguished from "nothing staged" by boot_next_pending,
  // not by a sentinel vmid: see the schema comment for why a magic 0 was refused.
  //
  // ⚠️ THE VMID IS RESOLVED HERE TOO, EVEN THOUGH NOTHING IS PUSHED YET. The same B5 shape
  // setCounterBootTarget has: a vmid outside the site's registered list yields no row, the
  // UPDATE matches nothing, and the caller reports a refusal. Refusing at STAGE time is the
  // point — an operator who is told at 11:00 that the VM is not registered can fix it, while
  // one told at 22:00 by a promoter that silently skipped the row is told by nobody. The
  // address itself is resolved AGAIN at promotion, so a VM renumbered overnight cannot be
  // applied from a stale reading.
  async function stageCounterBootTarget(id, f = {}) {
    const r = f || {};
    const wantClear = r.vmid == null;
    const updated = await one(
      `WITH ctx AS (
         SELECT c.id, c.pharmacy_id FROM counters c WHERE c.id = $1
       ), resolved AS (
         SELECT ctx.id, v.ip
           FROM ctx
           LEFT JOIN pharmacy_vms_v v
                  ON v.pharmacy_id = ctx.pharmacy_id AND v.vmid = $2
       )
       UPDATE counters c SET
         boot_next_vmid    = $2,
         boot_next_pending = true,
         boot_next_by      = $3,
         boot_next_at      = now()
       FROM resolved
       WHERE c.id = resolved.id
         -- A staged CLEAR needs no VM to resolve; a staged switch does.
         AND ($4::boolean OR resolved.ip IS NOT NULL)
       RETURNING c.id`,
      [id, wantClear ? null : r.vmid, nz(r.by), wantClear]
    );
    return updated ? getCounter(id) : null;
  }

  // Withdraw a staged change. Returns the counter either way when the row exists — nothing
  // staged is not an error, it is the state the caller asked for.
  async function cancelCounterBootTargetStage(id, by) {
    const updated = await one(
      `UPDATE counters SET
         boot_next_vmid = NULL, boot_next_pending = false,
         boot_next_by = $2, boot_next_at = now()
       WHERE id = $1 RETURNING id`,
      [id, nz(by)]
    );
    return updated ? getCounter(id) : null;
  }

  // ── THE PROMOTER: one statement, the gate inside it ───────────────────────
  // Copy every staged boot target whose site's overnight window is open RIGHT NOW into the
  // live columns. From that moment the ordinary directive carries the new target on the next
  // tick and the Pi restarts the kiosk — which is the whole point, at an hour when there is
  // nobody at the counter to notice.
  //
  // ⚠️ THE GATE IS EVALUATED INSIDE THE STATEMENT, not read and then acted on. Exactly the
  // reason the job claim is written this way: the worker is not a singleton, and a
  // read-then-decide-then-write would let two passes promote (and therefore restart) the
  // same counter twice. pmr_disruptive_allowed() is the SAME function the job claim gates
  // on, so a boot target and a session restart can never disagree about when the night is.
  //
  // It runs on EVERY worker pass rather than only in the nightly claim, and that is what
  // makes a site trading until 01:00 work: at 00:30 the gate is shut and nothing moves, at
  // 01:00 it opens and the next pass promotes. Idempotent — after promotion
  // boot_next_pending is false, so a second pass matches nothing.
  //
  // A staged switch whose VM stopped being registered in the meantime resolves to no address
  // and is LEFT STAGED rather than applied or discarded: the row stays visible in Watchman
  // as pending, which is the state that gets somebody to look.
  async function promoteCounterBootTargets() {
    const promoted = await rows(
      `WITH due AS (
         SELECT c.id, c.pharmacy_id, c.boot_next_vmid,
                v.ip AS next_ip
           FROM counters c
           LEFT JOIN pharmacy_vms_v v
                  ON c.boot_next_vmid IS NOT NULL
                 AND v.pharmacy_id = c.pharmacy_id AND v.vmid = c.boot_next_vmid
          WHERE c.boot_next_pending
            AND pmr_disruptive_allowed(c.pharmacy_id, now())
            -- A staged clear (vmid NULL) needs no resolution; a staged switch does.
            AND (c.boot_next_vmid IS NULL OR v.ip IS NOT NULL)
       )
       UPDATE counters c SET
         boot_vmid   = d.boot_next_vmid,
         boot_target = CASE WHEN d.boot_next_vmid IS NULL THEN NULL
                            ELSE d.next_ip || ':3389' END,
         boot_set_by = COALESCE(c.boot_next_by, 'watchman') || ' (staged)',
         boot_set_at = now(),
         -- Cleared for the same reason setCounterBootTarget clears it: until the Pi reports
         -- the NEW target it has not applied it, and a stale stamp reads as "already done".
         boot_applied_at   = NULL,
         boot_next_pending = false,
         boot_next_vmid    = NULL
       FROM due d
        WHERE c.id = d.id
       RETURNING c.id, c.pharmacy_id, c.boot_vmid, c.boot_target`
    );
    return { promoted: promoted.length, counters: promoted };
  }

  // ── editable per-thin-client options ───────────────────────────────────────
  // MERGE (jsonb ||), never replace. The modal can save a single field, and a whole-object
  // write would silently wipe every other setting on the row — on a live site that shows up
  // as smartcards or printing "turning themselves off", with nothing in the audit trail.
  //
  // Validation is deliberately NOT here. It happens once, in shared/counterSettings.js,
  // before this is called (and again on the Pi, and again in the launcher). Callers must
  // never pass unvalidated input: this writes straight into a column the device consumes.
  // The support-session block the PI reported, straight off its last telemetry. Read from
  // device_state.raw rather than a column: it is device-reported, short-lived state, and adding
  // a column for it would mean a migration every time the agent reports one more field.
  async function getDeviceSupportVnc(deviceId) {
    const { rows } = await pool.query(
      `SELECT raw -> 'support_vnc' AS sv FROM device_state WHERE device_id = $1`, [deviceId],
    );
    return (rows[0] && rows[0].sv) || null;
  }

  // Append-only. Deliberately NOT a foreign key onto counters: the point of an audit trail is
  // that it outlives the row it describes being edited or deleted.
  async function recordSupportSession(r) {
    await pool.query(
      `INSERT INTO support_sessions (counter_id, pi_serial, pharmacy_code, actor, minutes)
       VALUES ($1, $2, $3, $4, $5)`,
      [r.counter_id || null, r.pi_serial || null, r.pharmacy_code || null, r.actor || null, r.minutes || null],
    );
  }

  async function setCounterSettings(id, settings) {
    const updated = await one(
      `UPDATE counters SET settings = counters.settings || $2::jsonb
        WHERE id = $1 RETURNING id`,
      [id, JSON.stringify(settings || {})]
    );
    return updated ? getCounter(id) : null;
  }

  // The STORED settings for whichever counter owns this Pi. Defaults are merged in by the
  // caller (server-side, one place), so this returns only what an operator has actually
  // chosen. Null for a Pi that has phoned home but is not adopted onto a counter yet —
  // which the caller treats as "all defaults" rather than as an error.
  async function getCounterSettingsForDevice(deviceId) {
    return one(`SELECT settings FROM counters WHERE pi_device_id = $1`, [deviceId]);
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
      `SELECT boot_vmid AS vmid, boot_target AS target,
              settings->>'rdp_user' AS "user", settings->>'rdp_pass' AS "pass"
         FROM counters WHERE pi_device_id = $1 AND boot_target IS NOT NULL`,
      [deviceId]
    );
  }

  // ── site LAN inventory ─────────────────────────────────────────────────────
  // Every host a site's routers have SEEN on its LAN, plus any printer a Pi registered that
  // no router reports (a printer behind a switch on a segment the MikroTik does not bridge
  // still needs to be listable). Site membership comes from site_devices_v, so this and the
  // relay allowlist can never disagree about what "this site" contains.
  //
  // DISTINCT ON (ip) because mac_hosts is keyed (device_id, interface, mac): one host that
  // roamed between two ports, or is seen by two routers, is several rows and one device. The
  // most recently seen row wins. Classification is NOT done here — it is one shared JS table
  // (shared/lanDevices.js) so the API and any future consumer share the rule.
  //
  // Capped: the busiest site in the estate reports ~1,570 hosts, so 2000 returns every real
  // site whole while a runaway L2 table cannot hand the UI an unbounded list.
  const SITE_HOSTS_CAP = 2000;

  async function listSiteHosts(siteCode) {
    const code = siteCode == null ? '' : String(siteCode);
    if (!code) return [];
    return rows(
      `WITH site AS (
         SELECT DISTINCT site_code, pharmacy_id FROM site_devices_v WHERE site_code = $1
       ), lan AS (
         SELECT DISTINCT ON (host(mh.ip))
                host(mh.ip)  AS ip,
                mh.mac::text AS mac,
                mh.hostname,
                mh.comment,
                mh.vendor,
                mh.last_seen_at,
                'mac_hosts'  AS source
           FROM mac_hosts mh
           JOIN site_devices_v sd ON sd.device_id = mh.device_id
          WHERE sd.site_code = $1
            AND mh.ip IS NOT NULL
          ORDER BY host(mh.ip), mh.last_seen_at DESC
       ), registered AS (
         -- A printer row is identity an operator or an SNMP sweep established; it is a
         -- legitimate target even when no router has ARPed it.
         SELECT pr.address AS ip,
                NULL::text AS mac,
                pr.name    AS hostname,
                pr.notes   AS comment,
                COALESCE(pr.make, 'printer') AS vendor,
                pr.last_seen_at,
                'printers' AS source
           FROM printers pr
          WHERE pr.pharmacy_id IN (SELECT pharmacy_id FROM site WHERE pharmacy_id IS NOT NULL)
            AND pr.address IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM lan WHERE lan.ip = pr.address)
       )
       SELECT * FROM lan
       UNION ALL
       SELECT * FROM registered
       LIMIT $2`,
      [code, SITE_HOSTS_CAP]
    );
  }

  // Does this site exist at all? Distinguishes "no such site" (404) from "a site with nothing
  // on its LAN yet" (200 with an empty list) — a Pi enrolled before its router reported.
  async function siteExists(siteCode) {
    const code = siteCode == null ? '' : String(siteCode);
    if (!code) return null;
    return one(
      `SELECT sd.site_code, max(sd.pharmacy_id) AS pharmacy_id, count(*) AS devices
         FROM site_devices_v sd
        WHERE sd.site_code = $1
        GROUP BY sd.site_code`,
      [code]
    );
  }

  // ── relay: allowlist ───────────────────────────────────────────────────────
  // THE gate. A target is legal only if it ALREADY appears for this Pi's own site, either as
  // a host its routers have seen (mac_hosts) or as a registered printer. Free-text addresses
  // are impossible by construction — there is no branch that trusts the caller's string.
  //
  // Returns { site_code, source } when allowed, else null. A Pi that no counter has adopted
  // has no site, so it resolves to nothing and every target is refused.
  async function findRelayTarget(deviceId, ip) {
    if (!isUuid(deviceId)) return null;
    const addr = ip == null ? '' : String(ip);
    if (!addr) return null;
    return one(
      `WITH site AS (
         -- Prefer the pharmacy link: a Pi is at its counter's site. The serial/site-name arms
         -- of the view can also match a device, so order deterministically rather than
         -- letting the planner choose which site a Pi belongs to.
         SELECT sd.site_code, sd.pharmacy_id
           FROM site_devices_v sd
          WHERE sd.device_id = $1
          ORDER BY (sd.pharmacy_id IS NULL), sd.site_code
          LIMIT 1
       ), hit AS (
         -- host(mh.ip) rather than an inet cast: the address is compared as TEXT so no
         -- malformed input can reach a cast and raise 22P02 out of the allowlist check.
         SELECT 'mac_hosts' AS source
           FROM mac_hosts mh
           JOIN site_devices_v sd ON sd.device_id = mh.device_id
           JOIN site s ON s.site_code = sd.site_code
          WHERE mh.ip IS NOT NULL AND host(mh.ip) = $2
         UNION ALL
         SELECT 'printers'
           FROM printers pr
           JOIN site s ON s.pharmacy_id = pr.pharmacy_id
          WHERE pr.address = $2
       )
       SELECT s.site_code, (SELECT source FROM hit LIMIT 1) AS source
         FROM site s`,
      [deviceId, addr]
    );
  }

  // ── relay: sessions ────────────────────────────────────────────────────────
  // Creating a session REPLACES any live one for that device, in one transaction, because the
  // partial unique index allows exactly one. Replacing rather than refusing is deliberate: an
  // engineer who reloads the panel must not be locked out for the rest of the TTL by their own
  // abandoned session.
  async function createRelaySession(f = {}) {
    return tx(async (client) => {
      await client.query(
        `UPDATE relay_sessions SET closed_at = now(), closed_reason = 'replaced'
          WHERE device_id = $1 AND closed_at IS NULL`,
        [f.device_id]
      );
      const r = await client.query(
        `INSERT INTO relay_sessions
           (device_id, site_code, target_ip, target_port, opened_by, expires_at)
         VALUES ($1,$2,$3,$4,$5, now() + make_interval(secs => $6::int))
         RETURNING id, device_id, site_code, target_ip, target_port, opened_by,
                   created_at, expires_at`,
        [f.device_id, nz(f.site_code), f.target_ip, f.target_port, nz(f.opened_by), f.ttl_s]
      );
      return r.rows[0];
    });
  }

  async function getRelaySession(id) {
    if (!isUuid(id)) return null;
    return one(
      `SELECT id, device_id, site_code, target_ip, target_port, opened_by,
              created_at, expires_at, closed_at, closed_reason, last_poll_at,
              (closed_at IS NULL AND expires_at > now()) AS live
         FROM relay_sessions WHERE id = $1`,
      [id]
    );
  }

  // What to tell this Pi on its next telemetry reply. Sent EVERY tick while the session is
  // live, exactly like the boot target and settings, and for the same reason: it is then
  // self-healing. Unlike a queued reboot this is safe to repeat — re-learning a session the Pi
  // already holds is a no-op, whereas a once-only handover lost to a dropped response would
  // strand the operator for the whole TTL.
  async function getRelayDirective(deviceId) {
    if (!isUuid(deviceId)) return null;
    return one(
      `SELECT id AS session_id, target_ip, target_port, expires_at
         FROM relay_sessions
        WHERE device_id = $1 AND closed_at IS NULL AND expires_at > now()`,
      [deviceId]
    );
  }

  async function closeRelaySession(id, reason) {
    if (!isUuid(id)) return null;
    return one(
      `UPDATE relay_sessions SET closed_at = now(), closed_reason = $2
        WHERE id = $1 AND closed_at IS NULL RETURNING id`,
      [id, nz(reason)]
    );
  }

  // Records that the Pi is actually holding the channel open. Called once per long poll (not
  // per DB poll inside it), so this is one write per 25 s per worker, not one per 150 ms.
  async function touchRelaySession(id) {
    if (!isUuid(id)) return;
    await q(`UPDATE relay_sessions SET last_poll_at = now() WHERE id = $1`, [id]);
  }

  // Housekeeping, run opportunistically when a session is created rather than from the worker:
  // the relay is used a handful of times a day, so a cron for it would be more moving parts
  // than the thing it tidies. Replies are already deleted as the browser collects them
  // (takeRelayReply), so this only mops up what a disconnected browser abandoned.
  async function pruneRelay() {
    await q(
      `UPDATE relay_sessions SET closed_at = now(), closed_reason = 'expired'
        WHERE closed_at IS NULL AND expires_at <= now()`
    );
    // 15 minutes > the 10-minute session TTL, so this can never delete a request that a live
    // session might still be answering.
    await q(`DELETE FROM relay_requests WHERE created_at < now() - interval '15 minutes'`);
    await q(`DELETE FROM relay_sessions WHERE created_at < now() - interval '7 days'`);
  }

  // ── relay: the request/reply queue ─────────────────────────────────────────
  // Enqueue only against a LIVE session: the INSERT ... SELECT returns no row for a closed or
  // expired one, which the caller turns into 410 without a second round trip (and without a
  // check-then-insert window in which the session could expire).
  async function enqueueRelayRequest(sessionId, r = {}) {
    if (!isUuid(sessionId)) return null;
    return one(
      `INSERT INTO relay_requests (session_id, method, path, headers, body_b64)
       SELECT s.id, $2, $3, $4::jsonb, $5
         FROM relay_sessions s
        WHERE s.id = $1 AND s.closed_at IS NULL AND s.expires_at > now()
       RETURNING id`,
      [sessionId, r.method, r.path, JSON.stringify(r.headers || {}), nz(r.body_b64)]
    );
  }

  // Hand the oldest queued request to whichever of the Pi's pool workers asked first.
  // FOR UPDATE SKIP LOCKED is the point: three workers claiming concurrently each get a
  // different row instead of serialising or double-fetching one.
  //
  // A claim also EXPIRES after 10 seconds, which makes delivery at-least-once for reads: a Pi
  // whose long poll died between claiming and replying (a 4G site blipping) would otherwise
  // leave one asset unanswered and the page half-rendered. 10 s is longer than any healthy LAN
  // fetch and shorter than the browser's 30 s ceiling, so a redelivery still has time to land.
  // If both attempts do answer, the second reply hits 409 — the row is already 'done'.
  //
  // GET/HEAD only, deliberately. Redelivering a POST would resubmit a form the operator sent
  // once: a printer login, or a "restart the print engine" button. A lost POST stays lost and
  // the browser is told so.
  async function claimRelayRequest(sessionId) {
    if (!isUuid(sessionId)) return null;
    return one(
      `UPDATE relay_requests r
          SET state = 'claimed', claimed_at = now()
        WHERE r.id = (
          SELECT id FROM relay_requests
           WHERE session_id = $1
             AND (state = 'queued'
                  OR (state = 'claimed'
                      AND method IN ('GET', 'HEAD')
                      AND claimed_at < now() - interval '10 seconds'))
           ORDER BY seq
           FOR UPDATE SKIP LOCKED
           LIMIT 1
        )
       RETURNING r.id AS request_id, r.method, r.path, r.headers, r.body_b64`,
      [sessionId]
    );
  }

  // Scoped by session_id as well as request id so one device's token can never answer another
  // session's request, and by state='claimed' so a reply cannot be replayed.
  async function replyRelayRequest(sessionId, requestId, f = {}) {
    if (!isUuid(sessionId) || !isUuid(requestId)) return null;
    return one(
      `UPDATE relay_requests
          SET state = 'done', replied_at = now(),
              status = $3, resp_headers = $4::jsonb, resp_body_b64 = $5
        WHERE id = $2 AND session_id = $1 AND state = 'claimed'
        RETURNING id`,
      [sessionId, requestId, f.status, JSON.stringify(f.headers || {}), nz(f.body_b64)]
    );
  }

  // DELETE ... RETURNING: the browser reads a reply exactly once, and the row is gone the
  // moment it does. That is what keeps this table at a handful of rows without a reaper, and
  // it means a proxied response body is not left sitting in the database after delivery.
  async function takeRelayReply(sessionId, requestId) {
    if (!isUuid(sessionId) || !isUuid(requestId)) return null;
    return one(
      `DELETE FROM relay_requests
        WHERE id = $2 AND session_id = $1 AND state = 'done'
        RETURNING status, resp_headers AS headers, resp_body_b64 AS body_b64`,
      [sessionId, requestId]
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

  // ── THE PRINTER MODEL (docs/pmr-printer-contract.md §1) ────────────────────
  //
  // ⛔ The four objects live in pmr_printer_devices / pmr_printer_queues /
  // pmr_printer_assignments; `printers` above is the DISCOVERY feed and is untouched by
  // everything below. See the block above those tables in db/schema.sql for why both exist.
  //
  // ⚠️ THE RULES ARE NOT RESTATED HERE. Every §2 check is src/shared/printerQueues.js's, and
  // it is handed IN to the write paths as `checkSite` so the validation and the write happen
  // inside ONE transaction. That is not ceremony: two operators saving queues on the same
  // counter at the same time would otherwise each validate a table neither of them ends up
  // with, and §2's "refuse it entirely if any line is bad" would be enforced against a
  // snapshot rather than against what the Pi is actually sent.

  // What the Pi is reporting is PLUGGED IN (§3). Written from the telemetry tick and from
  // nothing else — an operator never types one of these in.
  //
  // The identity key is computed here from fields the caller has already cleaned, because
  // the two USB kinds are mechanical:
  //   a usable serial  -> 'usb-serial:<serial>'          survives a rename AND a move
  //   no usable serial -> 'usb-path:<counter>:<path>'    does not survive a move, and says so
  // WHICH serials are usable is a JS decision (printerQueues.usableSerial) — whole production
  // runs ship the same placeholder string, and one of those becoming a key would merge two
  // physical printers into one row.
  async function reportCounterPrinters(deviceId, records) {
    if (!isUuid(deviceId)) return { printers_attached: 0 };
    const counter = await one(
      `SELECT id, pharmacy_id FROM counters WHERE pi_device_id = $1`, [deviceId]
    );
    if (!counter) return { printers_attached: 0 };
    const list = Array.isArray(records) ? records : [];
    const keyOfRec = (r) => (r.usable_serial
      ? `usb-serial:${String(r.usable_serial).toLowerCase()}`
      : `usb-path:${counter.id}:${String(r.usb_path).toLowerCase()}`);
    // Deduped on the identity the row will be stored under, so two interfaces of one device
    // cannot produce two rows and then fight over the same ON CONFLICT target inside one
    // statement — Postgres rejects that outright ("cannot affect row a second time").
    const uniq = dedupeBy(list.filter((r) => r && r.usb_path), keyOfRec);
    if (!uniq.length) return { printers_attached: 0, counter_id: counter.id };
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO pmr_printer_devices (pharmacy_id, identity_kind, identity_key,
                                          device_serial, device_usb_path, host_counter_id,
                                          vendor_id, product_id, manufacturer, product,
                                          raw_serial, protocol, status, observed_queue,
                                          last_seen_at)`,
        `ON CONFLICT (pharmacy_id, identity_key) DO UPDATE SET
           host_counter_id = EXCLUDED.host_counter_id,
           device_usb_path = EXCLUDED.device_usb_path,
           vendor_id       = COALESCE(EXCLUDED.vendor_id,    pmr_printer_devices.vendor_id),
           product_id      = COALESCE(EXCLUDED.product_id,   pmr_printer_devices.product_id),
           manufacturer    = COALESCE(EXCLUDED.manufacturer, pmr_printer_devices.manufacturer),
           product         = COALESCE(EXCLUDED.product,      pmr_printer_devices.product),
           raw_serial      = COALESCE(EXCLUDED.raw_serial,   pmr_printer_devices.raw_serial),
           protocol        = COALESCE(EXCLUDED.protocol,     pmr_printer_devices.protocol),
           status          = EXCLUDED.status,
           observed_queue  = EXCLUDED.observed_queue,
           last_seen_at    = now()`,
        14,
        uniq.map((r) => [
          counter.pharmacy_id,
          r.usable_serial ? 'usb-serial' : 'usb-path',
          keyOfRec(r),
          nz(r.usable_serial),
          String(r.usb_path),
          counter.id,
          nz(r.vendor_id), nz(r.product_id), nz(r.manufacturer), nz(r.product),
          nz(r.serial), nz(r.protocol), nz(r.status), nz(r.queue),
        ]),
        placeholders(14, 'now()')
      );
    });
    return { printers_attached: uniq.length, counter_id: counter.id };
  }

  async function listPrinterDevices(pharmacyId) {
    if (pharmacyId == null) {
      return rows(`SELECT * FROM pmr_printer_devices ORDER BY pharmacy_id, identity_key`, []);
    }
    return rows(
      `SELECT * FROM pmr_printer_devices WHERE pharmacy_id = $1 ORDER BY identity_key`,
      [pharmacyId]
    );
  }

  // The INTENDED queues for a site, with the assignment attached by the key they share.
  //
  // ⭐ (counter_id, queue) is the join, because a queue name is unique ON ONE PI and not
  // across a site — two counters may each hold a queue called `Label`, and joining on the
  // name alone would cross-share their assignments.
  async function listPrinterQueues(pharmacyId) {
    const where = pharmacyId == null ? '' : 'WHERE q.pharmacy_id = $1';
    return rows(
      `SELECT q.id, q.pharmacy_id, q.counter_id, q.device_id, q.device_serial,
              q.device_usb_path, q.device_address, q.queue, q.driver, q.flags,
              q.notes, q.set_by, q.created_at, q.updated_at,
              a.vmids AS assigned_vmids,
              c.n     AS counter_n,
              c.label AS counter_label
         FROM pmr_printer_queues q
         LEFT JOIN pmr_printer_assignments a
                ON a.counter_id = q.counter_id AND a.queue = q.queue
         LEFT JOIN counters c ON c.id = q.counter_id
         ${where}
        ORDER BY q.counter_id, q.queue`,
      pharmacyId == null ? [] : [pharmacyId]
    );
  }

  // Every counter's EFFECTIVE table at one site, as Map(counter_id -> [lines]). This is what
  // the write paths re-validate and what the tick sends; ONE definition, in
  // pmr_counter_printer_table_v.
  async function siteEffectiveTables(client, pharmacyId) {
    const r = await client.query(
      `SELECT counter_id, host_counter_id, queue, driver, flags
         FROM pmr_counter_printer_table_v
        WHERE pharmacy_id = $1
        ORDER BY counter_id, is_local DESC, queue`,
      [pharmacyId]
    );
    const byCounter = new Map();
    for (const row of r.rows) {
      if (!byCounter.has(row.counter_id)) byCounter.set(row.counter_id, []);
      byCounter.get(row.counter_id).push({
        queue: row.queue,
        driver: row.driver,
        flags: Array.isArray(row.flags) ? row.flags : [],
        host_counter_id: row.host_counter_id,
      });
    }
    return byCounter;
  }

  // WHICH COUNTERS' TABLES ACTUALLY CHANGED.
  //
  // The reason this is computed rather than assumed: promoting a table SIGNS A MEMBER OF
  // STAFF OUT (§4), so a save that changes counter 1's table must not queue a sign-out at
  // counters 2 and 3 as well. The set is taken BEFORE and AFTER the write inside the same
  // transaction and compared line for line — including the flags and the ORDER, because the
  // order sets the /printer: flag order the launcher emits and printers.tab is compared byte
  // for byte on the device.
  function tableFingerprints(byCounter) {
    const out = new Map();
    for (const [counterId, lines] of byCounter.entries()) {
      out.set(counterId, lines.map((l) => `${l.queue}\t${l.driver}\t${(l.flags || []).join(',')}`).join('\n'));
    }
    return out;
  }

  function changedCounters(before, after) {
    const changed = [];
    const ids = new Set([...before.keys(), ...after.keys()]);
    for (const id of ids) {
      if ((before.get(id) || '') !== (after.get(id) || '')) changed.push(id);
    }
    return changed.sort((a, b) => a - b);
  }

  // ⛔ THE WHOLE-TABLE CHECK, RUN OVER EVERY COUNTER AT THE SITE, INSIDE THE WRITE.
  //
  // Not just the counter being edited: a queue built on counter 1 and shared to counter 2's
  // desktop lands in counter 2's table, so a save on 1 can only be judged by looking at 2.
  // That is also the case that produces the interesting refusal — both counters holding a
  // queue called `Label` is the NORMAL pattern (§1), and sharing one onto the other's desk
  // puts two `Label` lines in one table, which §2 refuses for the whole table.
  //
  // `checkSite(counterId, lines)` is printerQueues.validatePrinterTable, passed in by the
  // caller. Throwing rolls the transaction back, so a refused table is never written.
  async function assertSiteTablesValid(client, pharmacyId, checkSite) {
    if (typeof checkSite !== 'function') return;
    const tables = await siteEffectiveTables(client, pharmacyId);
    for (const [counterId, lines] of tables.entries()) {
      const verdict = checkSite(counterId, lines);
      if (verdict && verdict.ok === false) {
        const err = new Error(verdict.error);
        err.code = 'PRINTER_TABLE_REFUSED';
        err.counter_id = counterId;
        throw err;
      }
    }
  }

  // Create or edit ONE intended queue. `id` present = edit that row; absent = upsert by the
  // key the contract gives us, (counter_id, queue).
  //
  // Returns null when the subject does not resolve — the counter does not exist, or it
  // belongs to another pharmacy. REFUSED rather than guessed at, exactly as
  // setCounterBootTarget refuses a vmid outside the site's registered list.
  async function upsertPrinterQueue(f = {}, checkSite) {
    const pharmacyId = Number(f.pharmacy_id);
    const counterId = Number(f.counter_id);
    if (!Number.isInteger(pharmacyId) || !Number.isInteger(counterId)) return null;
    return tx(async (client) => {
      const counter = (await client.query(
        `SELECT id FROM counters WHERE id = $1 AND pharmacy_id = $2`, [counterId, pharmacyId]
      )).rows[0];
      if (!counter) return null;
      const before = tableFingerprints(await siteEffectiveTables(client, pharmacyId));

      // Link the queue to the physical device when one is visible, so a rename later is a
      // rename and not a new printer. Matched on the identity columns in the order §1 ranks
      // them; a queue with no match is perfectly legal and keeps device_id NULL.
      const device = (await client.query(
        `SELECT id FROM pmr_printer_devices
          WHERE pharmacy_id = $1
            AND (($2::text IS NOT NULL AND device_serial = $2)
              OR ($3::text IS NOT NULL AND device_address = $3)
              OR ($4::text IS NOT NULL AND host_counter_id = $5 AND device_usb_path = $4))
          ORDER BY (device_serial IS NOT NULL AND device_serial = $2) DESC
          LIMIT 1`,
        [pharmacyId, nz(f.device_serial), nz(f.device_address), nz(f.device_usb_path), counterId]
      )).rows[0];

      // ELEVEN values for the eleven columns below. Counted against the placeholder list on
      // both statements — this file has twice shipped an INSERT whose bound values and $n
      // list disagreed, and both times it was a column added to one side only.
      const args = [
        pharmacyId, counterId, device ? device.id : null,
        nz(f.device_serial), nz(f.device_usb_path), nz(f.device_address),
        f.queue, f.driver, f.flags || [], nz(f.notes), nz(f.by) || 'watchman',
      ];
      // ⛔ THE COLLISION THE TABLE VALIDATOR NEVER GETS TO SEE (B1). Renaming a queue onto a
      // name already held on that counter violates UNIQUE (counter_id, queue) INSIDE the
      // UPDATE — before assertSiteTablesValid() runs, and before the duplicate could be
      // reported as the whole-table refusal it really is. Postgres raises 23505, nothing in
      // this file caught it, and an operator retyping a name got a 500.
      //
      // Turned into the SAME error shape the whole-table check throws, so both duplicates —
      // the one caught here and the one caught by §2 across a site's shared queues — reach the
      // caller as one 409 with one sentence, and the handler needs no second branch.
      //
      // 23505 is caught rather than pre-checked with a SELECT: a pre-check is a race, and this
      // path already runs inside a transaction whose whole job is to make the write and its
      // validation atomic.
      const asRefusal = (err) => {
        if (!err || err.code !== '23505') return err;
        const refusal = new Error(
          `counter ${counterId} already has a queue called ${JSON.stringify(f.queue)} — §2: a `
          + 'duplicate queue name is refused for the WHOLE table. Rename or remove the '
          + 'existing one first; two lines for one queue would emit two /printer: flags '
          + 'naming the same Windows printer.'
        );
        refusal.code = 'PRINTER_TABLE_REFUSED';
        refusal.counter_id = counterId;
        return refusal;
      };

      let saved;
      if (f.id != null && Number.isInteger(Number(f.id))) {
        // $1..$11 are `args`; $12 is the row id appended below. Twelve in, twelve bound.
        //
        // ⚠️ THIS IS THE ARM THAT CAN HIT 23505. The INSERT arm below carries ON CONFLICT
        // (counter_id, queue) DO UPDATE and therefore cannot; a RENAME has no such clause,
        // because "make this row be called X" and "merge this row into the existing X" are
        // different instructions and silently doing the second would lose a queue.
        try {
          saved = (await client.query(
            `UPDATE pmr_printer_queues SET
               counter_id = $2, device_id = $3, device_serial = $4, device_usb_path = $5,
               device_address = $6, queue = $7, driver = $8, flags = $9::text[],
               notes = $10, set_by = $11
              WHERE id = $12 AND pharmacy_id = $1
             RETURNING *`,
            [...args, Number(f.id)]
          )).rows[0];
        } catch (err) {
          throw asRefusal(err);
        }
        if (!saved) return null;
      } else {
        saved = (await client.query(
          `INSERT INTO pmr_printer_queues
             (pharmacy_id, counter_id, device_id, device_serial, device_usb_path,
              device_address, queue, driver, flags, notes, set_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text[],$10,$11)
           ON CONFLICT (counter_id, queue) DO UPDATE SET
             device_id       = EXCLUDED.device_id,
             device_serial   = EXCLUDED.device_serial,
             device_usb_path = EXCLUDED.device_usb_path,
             device_address  = EXCLUDED.device_address,
             driver          = EXCLUDED.driver,
             flags           = EXCLUDED.flags,
             notes           = COALESCE(EXCLUDED.notes, pmr_printer_queues.notes),
             set_by          = EXCLUDED.set_by
           RETURNING *`,
          args
        )).rows[0];
      }
      await assertSiteTablesValid(client, pharmacyId, checkSite);
      const after = tableFingerprints(await siteEffectiveTables(client, pharmacyId));
      return Object.assign({}, saved, { changed_counters: changedCounters(before, after) });
    });
  }

  // Removing a queue cannot introduce a duplicate or a second default, but the site's tables
  // are re-validated anyway: the check is cheap, and having exactly one place where a write
  // can leave an invalid table is worth more than skipping it here.
  async function deletePrinterQueue(id, checkSite) {
    if (!Number.isInteger(Number(id))) return { deleted: 0 };
    return tx(async (client) => {
      const row = (await client.query(
        `SELECT id, pharmacy_id FROM pmr_printer_queues WHERE id = $1`, [Number(id)]
      )).rows[0];
      if (!row) return { deleted: 0 };
      const before = tableFingerprints(await siteEffectiveTables(client, row.pharmacy_id));
      const gone = (await client.query(
        `DELETE FROM pmr_printer_queues WHERE id = $1
         RETURNING id, pharmacy_id, counter_id, queue`,
        [Number(id)]
      )).rows[0];
      if (!gone) return { deleted: 0 };

      // ⛔ AND THE ASSIGNMENT GOES WITH IT (B6). pmr_printer_assignments is keyed by
      // (counter_id, queue) with no foreign key to this row — deliberately, because §1 says a
      // NAME is not an identity and an assignment must survive the discovery row being
      // re-created. But the consequence, unhandled, was that deleting a queue left its share
      // set orphaned under the same name: re-creating a queue called `Label` on the same
      // counter silently INHERITED whatever desktops the old one had been shared to, and the
      // person creating it saw a new queue that was already on somebody's screen.
      //
      // CLEARED, NOT DOCUMENTED. The alternative was to say so in the delete response and
      // leave the row, and that is the worse of the two: an inherited share is invisible in
      // the UI at the moment it matters (creating the queue), so a sentence on a response
      // nobody reads a week earlier does not prevent it. "No opinion" is the correct state
      // after a delete, and setPrinterAssignment() already treats a missing row as exactly
      // that, so the state is reachable again the moment somebody wants it.
      //
      // Inside the same transaction as the delete: a queue that is gone and a share set that
      // survives it is precisely the half-applied state this rollback protects against.
      const orphaned = await client.query(
        `DELETE FROM pmr_printer_assignments WHERE counter_id = $1 AND queue = $2
         RETURNING vmids`,
        [gone.counter_id, gone.queue]
      );

      await assertSiteTablesValid(client, gone.pharmacy_id, checkSite);
      const after = tableFingerprints(await siteEffectiveTables(client, gone.pharmacy_id));
      return {
        deleted: 1,
        queue: gone,
        // What was cleared with it, so the response can say so rather than the operator
        // discovering it by finding the printer gone from a desktop.
        assignment_cleared: orphaned.rowCount > 0,
        assignment_was_shared_to: orphaned.rows[0] ? orphaned.rows[0].vmids : null,
        changed_counters: changedCounters(before, after),
      };
    });
  }

  // ── the assignment (§1: queue -> desktop) ─────────────────────────────────
  // Keyed by (counter_id, queue) — NOT by a printers row id, because §1 says a name is not an
  // identity and a discovery row id can name a queue that no longer exists. `printer_id` is
  // stored as a HINT when the caller happens to have one.
  //
  // vmids null CLEARS the row, which is the only way to say "no opinion" again after having
  // said something; [] is stored and means "shared to nothing". Two different instructions,
  // both reachable.
  //
  // Returns null when the counter does not resolve.
  async function setPrinterAssignment(f = {}, checkSite) {
    const counterId = Number(f.counter_id);
    if (!Number.isInteger(counterId)) return null;
    return tx(async (client) => {
      const counter = (await client.query(
        `SELECT id, pharmacy_id FROM counters WHERE id = $1`, [counterId]
      )).rows[0];
      if (!counter) return null;
      const before = tableFingerprints(await siteEffectiveTables(client, counter.pharmacy_id));

      let saved = null;
      if (f.vmids === null || f.vmids === undefined) {
        await client.query(
          `DELETE FROM pmr_printer_assignments WHERE counter_id = $1 AND queue = $2`,
          [counterId, f.queue]
        );
      } else {
        // SIX values for the six columns; set_at is the column's own default on insert and
        // now() on update.
        saved = (await client.query(
          `INSERT INTO pmr_printer_assignments
             (pharmacy_id, counter_id, queue, printer_id, vmids, set_by)
           VALUES ($1,$2,$3,$4,$5::int[],$6)
           ON CONFLICT (counter_id, queue) DO UPDATE SET
             pharmacy_id = EXCLUDED.pharmacy_id,
             printer_id  = COALESCE(EXCLUDED.printer_id, pmr_printer_assignments.printer_id),
             vmids       = EXCLUDED.vmids,
             set_by      = EXCLUDED.set_by,
             set_at      = now()
           RETURNING *`,
          [counter.pharmacy_id, counterId, f.queue,
            f.printer_id == null ? null : Number(f.printer_id),
            f.vmids, nz(f.by) || 'watchman']
        )).rows[0];
      }
      // The assignment decides which counters' tables a queue lands in, so this check matters
      // MORE here than on the queue write itself.
      await assertSiteTablesValid(client, counter.pharmacy_id, checkSite);
      const after = tableFingerprints(await siteEffectiveTables(client, counter.pharmacy_id));
      return {
        counter_id: counterId,
        pharmacy_id: counter.pharmacy_id,
        queue: f.queue,
        vmids: saved ? saved.vmids : null,
        assignment: saved,
        // The counters whose EFFECTIVE table this changed. Promotion signs a member of staff
        // out, so only these get a job — a save on counter 1 must not restart counters 2 and 3.
        changed_counters: changedCounters(before, after),
      };
    });
  }

  async function listPrinterAssignments(pharmacyId) {
    return rows(
      `SELECT * FROM pmr_printer_assignments WHERE pharmacy_id = $1 ORDER BY counter_id, queue`,
      [Number(pharmacyId)]
    );
  }

  // ── what the tick sends (§2) ──────────────────────────────────────────────
  // The EFFECTIVE table for ONE Pi. Returns [] when this device is not a counter Pi or the
  // site intends no queues for it — the CALLER decides what an empty set means on the wire,
  // and §2 is unambiguous that it must not be sent as `printers: []`.
  async function getCounterPrinterTableForDevice(deviceId) {
    if (!isUuid(deviceId)) return [];
    return rows(
      `SELECT queue, driver, flags, host_counter_id, is_local
         FROM pmr_counter_printer_table_v
        WHERE pi_device_id = $1
        ORDER BY is_local DESC, queue`,
      [deviceId]
    );
  }

  // Is a staged printer table waiting at this counter? Read from the Pi's own telemetry
  // (§3's print_tab_pending), which is what "needs a session restart at this counter" means.
  // Tri-state: null when the agent has never reported it.
  async function getCounterPrintTabState(counterId) {
    return one(
      `SELECT c.id AS counter_id, c.pharmacy_id, c.pi_device_id,
              (ds.raw -> 'peripherals' ->> 'print_tab_pending')::boolean AS print_tab_pending,
              ds.raw -> 'peripherals' -> 'print_tab_live' AS print_tab_live,
              ds.raw -> 'peripherals' -> 'print_tab_next' AS print_tab_next,
              ds.last_seen_at
         FROM counters c
         LEFT JOIN device_state ds ON ds.device_id = c.pi_device_id
        WHERE c.id = $1`,
      [Number(counterId)]
    );
  }

  // ── the site build lifecycle ──────────────────────────────────────────────
  // Both reads answer null when nothing is held, and the HANDLER always emits the key: the
  // front end does `r.capture ?? null`, so an omitted key becomes a confident "no capture
  // held" instead of "we could not tell".
  async function getSiteCapture(pharmacyId) {
    return one(`SELECT * FROM pmr_site_captures WHERE pharmacy_id = $1`, [Number(pharmacyId)]);
  }

  // NINE values for the nine columns. Every tri-state is written straight through, so a NULL
  // from the capture tool stays NULL — "we did not establish it" is not "no".
  async function setSiteCapture(pharmacyId, f = {}) {
    return one(
      `INSERT INTO pmr_site_captures
         (pharmacy_id, started_at, uploaded_at, source_hostname, disk_gb,
          guest_agent_installed, printers_cleared, taken_by, out_of_hours)
       VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (pharmacy_id) DO UPDATE SET
         started_at            = COALESCE(EXCLUDED.started_at, pmr_site_captures.started_at),
         uploaded_at           = COALESCE(EXCLUDED.uploaded_at, pmr_site_captures.uploaded_at),
         source_hostname       = COALESCE(EXCLUDED.source_hostname, pmr_site_captures.source_hostname),
         disk_gb               = COALESCE(EXCLUDED.disk_gb, pmr_site_captures.disk_gb),
         guest_agent_installed = COALESCE(EXCLUDED.guest_agent_installed, pmr_site_captures.guest_agent_installed),
         printers_cleared      = COALESCE(EXCLUDED.printers_cleared, pmr_site_captures.printers_cleared),
         taken_by              = COALESCE(EXCLUDED.taken_by, pmr_site_captures.taken_by),
         out_of_hours          = COALESCE(EXCLUDED.out_of_hours, pmr_site_captures.out_of_hours)
       RETURNING *`,
      [Number(pharmacyId), nz(f.started_at), nz(f.uploaded_at), nz(f.source_hostname),
        nz(f.disk_gb), nz(f.guest_agent_installed), nz(f.printers_cleared),
        nz(f.taken_by), nz(f.out_of_hours)]
    );
  }

  // ── the site row as a PROJECTION of the role runs ─────────────────────────
  // ⛔ WHY THIS IS NOT setSiteCapture. That one COALESCEs every field, so a tool reporting a
  // fragment cannot erase an earlier report — correct for a tool, and WRONG for a projection.
  // A roll-up that recomputes printers_cleared as "not established" MUST be able to clear a
  // stale true; otherwise pmr_site_captures keeps handing a build checklist an all-clear that
  // the runs underneath it no longer support, which is the exact false negative the tri-states
  // exist to prevent.
  //
  // started_at is still COALESCEd: it is the moment the FIRST capture at this site began, and
  // a recomputation must not move it later.
  async function setSiteCaptureRollUp(pharmacyId, f = {}) {
    return one(
      `INSERT INTO pmr_site_captures
         (pharmacy_id, started_at, uploaded_at, source_hostname, disk_gb,
          guest_agent_installed, printers_cleared, taken_by, out_of_hours)
       VALUES ($1, COALESCE($2::timestamptz, now()), $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (pharmacy_id) DO UPDATE SET
         started_at            = LEAST(pmr_site_captures.started_at,
                                       COALESCE(EXCLUDED.started_at, pmr_site_captures.started_at)),
         uploaded_at           = EXCLUDED.uploaded_at,
         source_hostname       = EXCLUDED.source_hostname,
         disk_gb               = EXCLUDED.disk_gb,
         guest_agent_installed = EXCLUDED.guest_agent_installed,
         printers_cleared      = EXCLUDED.printers_cleared,
         taken_by              = EXCLUDED.taken_by,
         out_of_hours          = EXCLUDED.out_of_hours
       RETURNING *`,
      [Number(pharmacyId), nz(f.started_at), nz(f.uploaded_at), nz(f.source_hostname),
        nz(f.disk_gb), nz(f.guest_agent_installed), nz(f.printers_cleared),
        nz(f.taken_by), nz(f.out_of_hours)]
    );
  }

  async function getSiteImport(pharmacyId) {
    return one(`SELECT * FROM pmr_site_imports WHERE pharmacy_id = $1`, [Number(pharmacyId)]);
  }

  // EIGHT values for the nine columns: last_poll_at is now() on both arms and is never taken
  // from the caller.
  //
  // ⚠️ last_poll_at IS STAMPED ON EVERY REPORT, whatever else the executor said. It is the
  // only thing separating a running import from a dead one — the executor polls OUTWARD, so
  // nothing here can ask — and an import that stopped reporting must go quiet in the data
  // rather than keep a stale "running" that looks alive.
  async function setSiteImport(pharmacyId, f = {}) {
    return one(
      `INSERT INTO pmr_site_imports
         (pharmacy_id, state, pct, node, vmid, started_at, finished_at, error, last_poll_at)
       VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, now()), $7, $8, now())
       ON CONFLICT (pharmacy_id) DO UPDATE SET
         state        = EXCLUDED.state,
         pct          = EXCLUDED.pct,
         node         = COALESCE(EXCLUDED.node, pmr_site_imports.node),
         vmid         = COALESCE(EXCLUDED.vmid, pmr_site_imports.vmid),
         started_at   = COALESCE(pmr_site_imports.started_at, EXCLUDED.started_at),
         finished_at  = CASE WHEN EXCLUDED.state IN ('done','failed')
                             THEN COALESCE(EXCLUDED.finished_at, now())
                             ELSE NULL END,
         error        = EXCLUDED.error,
         last_poll_at = now()
       RETURNING *`,
      [Number(pharmacyId), f.state, nz(f.pct), nz(f.node), nz(f.vmid),
        nz(f.started_at), nz(f.finished_at), nz(f.error)]
    );
  }


  // ══════════════════════════════════════════════════════════════════════════
  // THE CAPTURE KIT'S CREDENTIALS
  // ══════════════════════════════════════════════════════════════════════════
  //
  // ⛔ THE CAPTURE TOOL CARRIES NO SUPABASE KEY AND NO ESTATE TOKEN. It runs on a pharmacy's
  // own PC. What it carries is a short-lived scoped token with exactly three capabilities,
  // minted from a site-bound ticket, and Vigilant does every CRM read server-side on its
  // behalf. See src/shared/captureToken.js for the lifetimes and the reasoning.

  // Issue a ticket. The caller has ALREADY judged the out-of-hours window (the handler asks
  // openingHours through captureToken.judgeCaptureWindow) — this writes the decision down.
  // expires_at arrives pre-clamped to the site's closed window; it is not recomputed here,
  // because two implementations of "when does this pharmacy open" is one more than nobody can
  // get wrong.
  async function createCaptureTicket(pharmacyId, f = {}) {
    return one(
      `INSERT INTO pmr_capture_tickets
         (pharmacy_id, secret_hash, issued_by, expires_at, window_closes_at, redeem_max, note)
       VALUES ($1, $2, $3, $4::timestamptz, $5::timestamptz, COALESCE($6, 12), $7)
       RETURNING *`,
      [Number(pharmacyId), String(f.secret_hash), String(f.issued_by),
        f.expires_at, nz(f.window_closes_at), nz(f.redeem_max), nz(f.note)]
    );
  }

  async function listCaptureTickets(pharmacyId) {
    // ⛔ secret_hash IS NOT SELECTED. Not because a hash is a credential — it is not — but
    // because the moment it appears in a list payload someone will build a lookup on it, and
    // the property that makes this safe is that nothing but the redeem statement ever touches
    // it.
    return rows(
      `SELECT id, pharmacy_id, issued_by, issued_at, expires_at, window_closes_at,
              redeem_max, redeem_count, last_redeemed_at, revoked_at, revoked_by, note
         FROM pmr_capture_tickets
        WHERE pharmacy_id = $1
        ORDER BY issued_at DESC
        LIMIT 50`,
      [Number(pharmacyId)]
    );
  }

  // Revoking is the kill switch: it stops future redemptions AND kills every token the ticket
  // has already minted, in one statement. A revoke that left live tokens behind would be a
  // kill switch that does not kill anything for another ninety minutes.
  async function revokeCaptureTicket(id, by) {
    if (!isUuid(id)) return null;
    return tx(async (client) => {
      const r = await client.query(
        `UPDATE pmr_capture_tickets
            SET revoked_at = COALESCE(revoked_at, now()), revoked_by = COALESCE(revoked_by, $2)
          WHERE id = $1
          RETURNING *`,
        [id, nz(by)]
      );
      if (!r.rows.length) return null;
      await client.query(
        `UPDATE pmr_capture_tokens SET revoked_at = COALESCE(revoked_at, now())
          WHERE ticket_id = $1 AND revoked_at IS NULL`,
        [id]
      );
      return r.rows[0];
    });
  }

  // ── redeem: ticket secret -> a scoped token ───────────────────────────────
  //
  // ⛔ ONE STATEMENT DECIDES AND CLAIMS. The eligibility test (not revoked, not expired,
  // budget remaining) is INSIDE the UPDATE that spends the budget, so two kit instances
  // redeeming the same ticket at the same instant cannot both be told "you have 1 redemption
  // left". This is the same reason the PMR job claim evaluates its gate inside the claiming
  // statement rather than around it.
  //
  // ⛔ THE CAPABILITY LIST IS NOT A PARAMETER THE CALLER CHOOSES FREELY. It is bound as an
  // array and the column carries a CHECK restricting it to a subset of the three, so a caller
  // that passed a fourth string gets a constraint violation rather than a wider token.
  //
  // Returns { ticket, token } or a NAMED refusal { refused: '<reason>' } — never a bare null,
  // because "no such ticket", "revoked", "expired" and "spent" are four different things to
  // tell an engineer standing in a pharmacy at 2am.
  async function redeemCaptureTicket(secretHash, f = {}) {
    const caps = Array.isArray(f.capabilities) ? f.capabilities : [];
    return tx(async (client) => {
      const spent = await client.query(
        `UPDATE pmr_capture_tickets
            SET redeem_count = redeem_count + 1, last_redeemed_at = now()
          WHERE secret_hash = $1
            AND revoked_at IS NULL
            AND expires_at > now()
            AND redeem_count < redeem_max
          RETURNING *`,
        [String(secretHash || '')]
      );
      if (!spent.rows.length) {
        // The claim failed. Read the row (if any) purely to SAY WHY. This read cannot race
        // usefully — whatever it finds, no budget was spent — and a refusal that names the
        // reason is the difference between an engineer reissuing a ticket and an engineer
        // driving home.
        const look = await client.query(
          `SELECT revoked_at, expires_at, redeem_count, redeem_max
             FROM pmr_capture_tickets WHERE secret_hash = $1`,
          [String(secretHash || '')]
        );
        if (!look.rows.length) return { refused: 'no-such-ticket' };
        const t = look.rows[0];
        if (t.revoked_at) return { refused: 'revoked' };
        if (new Date(t.expires_at).getTime() <= Date.now()) return { refused: 'expired' };
        if (Number(t.redeem_count) >= Number(t.redeem_max)) return { refused: 'spent' };
        return { refused: 'unavailable' };
      }
      const ticket = spent.rows[0];
      // ⛔ THE TOKEN NEVER OUTLIVES THE TICKET, AND THE CLAMP IS IN THE STATEMENT. LEAST of
      // the ordinary TTL and the ticket's own expiry — computed here rather than in the
      // caller so the value tested by the auth query is the value that was written, and so a
      // ticket clamped to twenty minutes before opening cannot mint a ninety-minute token.
      // That clamp is what stops the closed-window bound leaking through a last-minute mint.
      const tok = await client.query(
        `INSERT INTO pmr_capture_tokens
           (ticket_id, pharmacy_id, token_hash, capabilities, expires_at)
         VALUES ($1, $2, $3, $4::text[],
                 LEAST(now() + make_interval(secs => $5::int), $6::timestamptz))
         RETURNING *`,
        [ticket.id, ticket.pharmacy_id, String(f.token_hash), caps,
          Number(f.token_ttl_s) > 0 ? Number(f.token_ttl_s) : 900, ticket.expires_at]
      );
      return { ticket, token: tok.rows[0] };
    });
  }

  // The hot path: authenticate one kit call. ONE lookup, and it joins the ticket so a token
  // whose ticket was revoked or has expired dies with it rather than outliving it by up to
  // ninety minutes.
  //
  // ⚠️ IT ALSO RETURNS THE PHARMACY, because every capture route resolves its site from HERE
  // and never from a request body. That is the whole point of the ticket: the kit is
  // physically unable to name another pharmacy.
  async function getCaptureTokenByHash(tokenHash) {
    return one(
      `SELECT t.id, t.ticket_id, t.pharmacy_id, t.capabilities, t.issued_at, t.expires_at,
              t.last_used_at, t.revoked_at,
              k.issued_by AS ticket_issued_by, k.expires_at AS ticket_expires_at,
              p.code AS pharmacy_code, p.name AS pharmacy_name
         FROM pmr_capture_tokens t
         JOIN pmr_capture_tickets k ON k.id = t.ticket_id
         JOIN pharmacies p          ON p.id = t.pharmacy_id
        WHERE t.token_hash = $1
          AND t.revoked_at IS NULL
          AND t.expires_at > now()
          AND k.revoked_at IS NULL
          AND k.expires_at > now()`,
      [String(tokenHash || '')]
    );
  }

  // Stamped after a call is authorised, with the capability it exercised. Failure here must
  // never fail the call it is recording, so it is fire-and-forget at the call site.
  async function touchCaptureToken(id, capability) {
    if (!isUuid(id)) return null;
    return one(
      `UPDATE pmr_capture_tokens SET last_used_at = now(), last_capability = $2
        WHERE id = $1 RETURNING id`,
      [id, nz(capability)]
    );
  }

  // ── what the kit is allowed to see ────────────────────────────────────────
  // The 'sites:list' read. Scoped to the pharmacy the TOKEN names — which is exactly one row.
  // It is a LIST because the kit renders a picker and the engineer confirms rather than types;
  // the kit cannot widen it, and no request parameter reaches this query.
  async function listCaptureSitesForToken(pharmacyId) {
    return rows(
      `SELECT p.id, p.code, p.name, p.status, p.idx, p.prefix_len, p.subnet,
              p.server_ip, p.proxmox_node, p.srv_vmid, p.pmr_system
         FROM pharmacies p
        WHERE p.id = $1`,
      [Number(pharmacyId)]
    );
  }

  // The 'slots:read' read: which role slots at this site are already spoken for, and by what.
  //
  // THREE SOURCES, because a slot is taken if ANY of them says so and a picker that showed a
  // free slot which the register call then refused would waste an engineer's night:
  //   * a capture RUN already registered for that role;
  //   * a COUNTER row (the real addressable slot — n maps to the .11–.20 band);
  //   * for the server, the site's own srv_vmid.
  async function listCaptureSlots(pharmacyId) {
    const id = Number(pharmacyId);
    const [runs, counters, ph] = await Promise.all([
      rows(
        `SELECT role_kind, role_slot, ticket_id, started_at, uploaded_at, taken_by, source_pc_name
           FROM pmr_capture_runs WHERE pharmacy_id = $1
          ORDER BY role_kind, role_slot`,
        [id]
      ),
      rows(
        `SELECT n, label, status, vmid FROM counters WHERE pharmacy_id = $1 ORDER BY n`,
        [id]
      ),
      one(`SELECT id, code, idx, prefix_len, server_ip, srv_vmid FROM pharmacies WHERE id = $1`, [id]),
    ]);
    return { runs, counters, pharmacy: ph };
  }

  async function listCaptureRuns(pharmacyId) {
    return rows(
      `SELECT * FROM pmr_capture_runs WHERE pharmacy_id = $1
        ORDER BY role_kind, role_slot NULLS FIRST`,
      [Number(pharmacyId)]
    );
  }

  // ── the 'capture:write' write ─────────────────────────────────────────────
  //
  // ⛔ IT REGISTERS A CAPTURE AGAINST A SITE THAT ALREADY EXISTS. There is no INSERT INTO
  // pharmacies anywhere on this path and there must never be one: pharmacy_id is bound from
  // the token, the FK refuses an id that is not a live site, and no column of `pharmacies` is
  // written. A kit credential that could create a pharmacy could create the site it then
  // claims to have captured.
  //
  // ⛔ AND IT REFUSES A DUPLICATE ROLE — in the database, not in a handler. The partial unique
  // indexes make (site, server) and (site, client, slot) unique, so the ON CONFLICT below is
  // an UPDATE only when the SAME TICKET is re-registering (a resume after the guest-agent
  // reboot). A DIFFERENT ticket hitting the same slot raises, and the caller turns that into a
  // 409 naming who holds it. Two engineers picking Client 03 at the same site is precisely the
  // race a SELECT-then-INSERT would lose.
  //
  // out_of_hours is passed in by the handler, decided from the SITE'S OWN HOURS server-side.
  // It is never read from the kit's body: a tool asserting its own compliance is not evidence.
  async function upsertCaptureRun(pharmacyId, f = {}) {
    const kind = f.role_kind === 'server' ? 'server' : 'client';
    const slot = kind === 'server' ? null : Number(f.role_slot);
    const conflictTarget = kind === 'server'
      ? '(pharmacy_id) WHERE role_kind = \'server\''
      : '(pharmacy_id, role_slot) WHERE role_kind = \'client\'';
    return one(
      `INSERT INTO pmr_capture_runs
         (pharmacy_id, role_kind, role_slot, ticket_id, started_at, uploaded_at,
          source_pc_name, disk_gb, image_format, image_sha256, bytes_total, bytes_sent,
          upload_target, guest_agent_installed, printers_cleared, slimmed, taken_by,
          out_of_hours, failed_reason)
       VALUES ($1, $2, $3, $4, COALESCE($5::timestamptz, now()), $6,
               $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
       ON CONFLICT ${conflictTarget} DO UPDATE SET
         -- ⛔ THE OWNERSHIP GUARD, IN THE STATEMENT. A row already owned by ANOTHER ticket is
         -- not updated: the WHERE below fails the conflict action, the statement returns no
         -- row, and the caller answers 409. Only the ticket that started this run may resume
         -- it — which is exactly what a resume after a reboot is.
         ticket_id             = COALESCE(EXCLUDED.ticket_id, pmr_capture_runs.ticket_id),
         uploaded_at           = COALESCE(EXCLUDED.uploaded_at, pmr_capture_runs.uploaded_at),
         source_pc_name        = COALESCE(EXCLUDED.source_pc_name, pmr_capture_runs.source_pc_name),
         disk_gb               = COALESCE(EXCLUDED.disk_gb, pmr_capture_runs.disk_gb),
         image_format          = COALESCE(EXCLUDED.image_format, pmr_capture_runs.image_format),
         image_sha256          = COALESCE(EXCLUDED.image_sha256, pmr_capture_runs.image_sha256),
         bytes_total           = COALESCE(EXCLUDED.bytes_total, pmr_capture_runs.bytes_total),
         -- ⚠️ PROGRESS ONLY EVER GOES FORWARD. A resumed transfer that reports its own
         -- restart offset must not make the record say less work has been done than last time.
         bytes_sent            = GREATEST(COALESCE(EXCLUDED.bytes_sent, 0),
                                          COALESCE(pmr_capture_runs.bytes_sent, 0)),
         upload_target         = COALESCE(EXCLUDED.upload_target, pmr_capture_runs.upload_target),
         -- ⚠️ TRI-STATES WRITE STRAIGHT THROUGH WHEN STATED AND ARE LEFT ALONE WHEN NOT. A
         -- NULL from the kit means "not established on this call", not "no" — so it must not
         -- overwrite a true, and a false must be able to overwrite a true (a later pass found
         -- printers after all).
         guest_agent_installed = COALESCE(EXCLUDED.guest_agent_installed, pmr_capture_runs.guest_agent_installed),
         printers_cleared      = COALESCE(EXCLUDED.printers_cleared, pmr_capture_runs.printers_cleared),
         slimmed               = COALESCE(EXCLUDED.slimmed, pmr_capture_runs.slimmed),
         taken_by              = COALESCE(EXCLUDED.taken_by, pmr_capture_runs.taken_by),
         out_of_hours          = COALESCE(EXCLUDED.out_of_hours, pmr_capture_runs.out_of_hours),
         failed_reason         = EXCLUDED.failed_reason
       WHERE pmr_capture_runs.ticket_id IS NOT DISTINCT FROM EXCLUDED.ticket_id
       RETURNING *`,
      [Number(pharmacyId), kind, slot, nz(f.ticket_id), nz(f.started_at), nz(f.uploaded_at),
        nz(f.source_pc_name), nz(f.disk_gb), nz(f.image_format), nz(f.image_sha256),
        nz(f.bytes_total), nz(f.bytes_sent), nz(f.upload_target),
        nz(f.guest_agent_installed), nz(f.printers_cleared), nz(f.slimmed), nz(f.taken_by),
        nz(f.out_of_hours), nz(f.failed_reason)]
    );
  }

  // Who holds a role slot, for the 409 that refuses a duplicate. A refusal that cannot say
  // "Client 03 was captured at 01:12 by leo.wilson" is a refusal an engineer will assume is a
  // bug and work around.
  async function getCaptureRunForRole(pharmacyId, kind, slot) {
    if (kind === 'server') {
      return one(
        `SELECT * FROM pmr_capture_runs WHERE pharmacy_id = $1 AND role_kind = 'server'`,
        [Number(pharmacyId)]
      );
    }
    return one(
      `SELECT * FROM pmr_capture_runs
        WHERE pharmacy_id = $1 AND role_kind = 'client' AND role_slot = $2`,
      [Number(pharmacyId), Number(slot)]
    );
  }

  // ── the upload destination, reported by the node that owns it ─────────────
  // Vigilant has no route to the Proxmox API, so this arrives on the reply-bearing push the
  // collector already makes. Same rule as job hand-out.
  async function reportCaptureDropTargets(list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(arr.filter((n) => n && n.node && n.dir), (n) => String(n.node));
    if (!uniq.length) return { capture_drop_targets: 0 };
    await tx(async (client) => {
      for (const t of uniq) {
        await client.query(
          `INSERT INTO pmr_capture_drop_targets
             (node, storage_name, dir, fs_type, free_bytes, total_bytes, writable, read_error, reported_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
           ON CONFLICT (node) DO UPDATE SET
             storage_name = EXCLUDED.storage_name,
             dir          = EXCLUDED.dir,
             fs_type      = EXCLUDED.fs_type,
             -- ⛔ WRITTEN AS REPORTED, INCLUDING NULL. Never COALESCEd onto the previous
             -- value: a node that has stopped being able to read its own drop directory must
             -- go quiet in the data rather than keep a stale free-space figure that looks
             -- like a current one. Same rule as proxmox_node_capacity.
             free_bytes   = EXCLUDED.free_bytes,
             total_bytes  = EXCLUDED.total_bytes,
             writable     = EXCLUDED.writable,
             read_error   = EXCLUDED.read_error,
             reported_at  = now()`,
          [t.node, nz(t.storage_name), t.dir, nz(t.fs_type), nz(t.free_bytes),
            nz(t.total_bytes), nz(t.writable), nz(t.read_error)]
        );
      }
    });
    return { capture_drop_targets: uniq.length };
  }

  async function getCaptureDropTarget(node) {
    if (!node) return null;
    return one(`SELECT * FROM pmr_capture_drop_targets WHERE node = $1`, [String(node)]);
  }

  async function listCaptureDropTargets() {
    return rows(`SELECT * FROM pmr_capture_drop_targets ORDER BY node`, []);
  }

  // ── node headroom ─────────────────────────────────────────────────────────
  // ⛔ A FIGURE THE COLLECTOR DID NOT ESTABLISH IS WRITTEN AS NULL. Never 0, and never left
  // at its previous value: "the pool is full" and "we could not read the pool" are different
  // facts, and a COALESCE here would turn the second into a confident stale first.
  async function listNodeCapacity() {
    return rows(
      `SELECT node, storage_name, mem_total_bytes, mem_free_bytes,
              storage_total_bytes, storage_free_bytes, cpu_cores, read_error, measured_at
         FROM proxmox_node_capacity
        ORDER BY node, storage_name`,
      []
    );
  }

  // EIGHT values for the nine columns: measured_at is now() and is never taken from the
  // caller — a collector's own clock deciding how fresh its reading looks is how a stale
  // number passes for a current one.
  async function reportNodeCapacity(list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(
      arr.filter((n) => n && n.node && n.storage_name),
      // ⚠️ \x00 AS AN ESCAPE, NEVER AS A LITERAL BYTE (B7). This separator was written as a
      // raw NUL in the source, which makes grep classify the WHOLE FILE as binary and return
      // NOTHING for every pattern in it — so the next person searching for a method here concludes
      // it is missing when it is four thousand lines above them. The escape is the same byte to
      // JavaScript and an ordinary text file to everything else.
      //
      // The byte itself is deliberate: it is the one character that cannot appear in a Proxmox
      // node name or a storage name, so ("wcn1","zfs-a") and ("wcn1-zfs","a") cannot collide.
      (n) => `${n.node}\x00${n.storage_name}`
    );
    if (!uniq.length) return { nodes: 0 };
    await tx(async (client) => {
      await bulkInsert(
        client,
        `INSERT INTO proxmox_node_capacity (node, storage_name, mem_total_bytes, mem_free_bytes,
                                            storage_total_bytes, storage_free_bytes, cpu_cores,
                                            read_error, measured_at)`,
        `ON CONFLICT (node, storage_name) DO UPDATE SET
           mem_total_bytes     = EXCLUDED.mem_total_bytes,
           mem_free_bytes      = EXCLUDED.mem_free_bytes,
           storage_total_bytes = EXCLUDED.storage_total_bytes,
           storage_free_bytes  = EXCLUDED.storage_free_bytes,
           cpu_cores           = EXCLUDED.cpu_cores,
           read_error          = EXCLUDED.read_error,
           measured_at         = now()`,
        8,
        uniq.map((n) => [
          String(n.node), String(n.storage_name),
          nz(n.mem_total_bytes), nz(n.mem_free_bytes),
          nz(n.storage_total_bytes), nz(n.storage_free_bytes),
          nz(n.cpu_cores), nz(n.read_error),
        ]),
        placeholders(8, 'now()')
      );
    });
    return { nodes: uniq.length };
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
        `INSERT INTO proxmox_vms (vmid, node, name, status, vlan_tag, macs, cores, maxmem, maxdisk, uptime_s, template,
                                  agent_enabled, agent_ok, agent_error, agent_checked_at, guest_os, guest_ips, onboot, seen_at)`,
        // COALESCE on everything the collector can fail to read. It reports a VM from
        // /cluster/resources even when the per-VM config call failed, and it OMITS the keys it
        // could not establish rather than sending blanks — so without COALESCE one transient
        // node hiccup overwrote a VM's stored vlan_tag with NULL and silently unlinked it from
        // its pharmacy, because the reconciler joins on vlan_tag. The identity columns that
        // always arrive (node/name/status/template) are still overwritten unconditionally.
        //
        // agent_checked_at is NOT coalesced onto now(): it is only ever set by a pass that
        // actually probed, so an un-probed tick leaves the previous timestamp in place and the
        // reading correctly ages.
        `ON CONFLICT (vmid) DO UPDATE SET
           node = EXCLUDED.node, name = EXCLUDED.name, status = EXCLUDED.status,
           vlan_tag = COALESCE(EXCLUDED.vlan_tag, proxmox_vms.vlan_tag),
           macs = CASE WHEN jsonb_array_length(EXCLUDED.macs) > 0 THEN EXCLUDED.macs ELSE proxmox_vms.macs END,
           cores = COALESCE(EXCLUDED.cores, proxmox_vms.cores),
           maxmem = COALESCE(EXCLUDED.maxmem, proxmox_vms.maxmem),
           maxdisk = COALESCE(EXCLUDED.maxdisk, proxmox_vms.maxdisk),
           uptime_s = EXCLUDED.uptime_s, template = EXCLUDED.template,
           agent_enabled = COALESCE(EXCLUDED.agent_enabled, proxmox_vms.agent_enabled),
           agent_ok = COALESCE(EXCLUDED.agent_ok, proxmox_vms.agent_ok),
           agent_error = COALESCE(EXCLUDED.agent_error, proxmox_vms.agent_error),
           agent_checked_at = COALESCE(EXCLUDED.agent_checked_at, proxmox_vms.agent_checked_at),
           guest_os = COALESCE(EXCLUDED.guest_os, proxmox_vms.guest_os),
           guest_ips = CASE WHEN jsonb_array_length(EXCLUDED.guest_ips) > 0 THEN EXCLUDED.guest_ips ELSE proxmox_vms.guest_ips END,
           onboot = COALESCE(EXCLUDED.onboot, proxmox_vms.onboot),
           seen_at = now()`,
        18,
        uniq.map((v) => [
          Number(v.vmid), nz(v.node), nz(v.name), nz(v.status),
          v.vlan_tag == null ? null : Number(v.vlan_tag),
          JSON.stringify(Array.isArray(v.macs) ? v.macs : []),
          v.cores == null ? null : Number(v.cores),
          v.maxmem == null ? null : Number(v.maxmem),
          v.maxdisk == null ? null : Number(v.maxdisk),
          v.uptime_s == null ? null : Number(v.uptime_s),
          v.template === true,
          // Tri-state all the way down: undefined (the collector could not ask) and a real
          // false are different answers, and only the second may ever render as "no".
          v.agent_enabled == null ? null : Boolean(v.agent_enabled),
          v.agent_ok == null ? null : Boolean(v.agent_ok),
          nz(v.agent_error),
          v.agent_checked_at == null ? null : new Date(Number(v.agent_checked_at) * 1000),
          nz(v.guest_os),
          JSON.stringify(Array.isArray(v.guest_ips) ? v.guest_ips : []),
          v.onboot == null ? null : Boolean(v.onboot),
        ]),
        placeholders(18, 'now()')
      );
    });
    return { vms: uniq.length };
  }

  // ── PMR VM capacity ────────────────────────────────────────────────────────
  // Written by the same collector pass, from the same POST, but kept in its own table and its
  // own call: proxmox_vms is inventory (what exists, what it is linked to) and this is a
  // reading (how full it is). They fail independently — the RRD can be readable on a VM whose
  // guest agent is dead, and vice versa.
  //
  // Called AFTER reportProxmoxVms so a capacity row is never the first thing that mentions a
  // vmid.
  async function reportProxmoxCapacity(list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(arr.filter((v) => v && Number.isFinite(Number(v.vmid))), (v) => Number(v.vmid));
    if (!uniq.length) return { capacity_rows: 0, disk_samples: 0 };

    // A row is only a DISK reading if the agent actually answered with both numbers. Anything
    // else is 'unknown' with empty columns — never 0, which would render as a healthy disk on a
    // VM nobody can see inside. (VM 305 is a live dispensing server at 88% full; the failure
    // mode being guarded here is the opposite reading.)
    const withDisk = (v) =>
      v.disk_source === 'agent' &&
      Number.isFinite(Number(v.disk_used_bytes)) &&
      Number.isFinite(Number(v.disk_total_bytes)) &&
      Number(v.disk_total_bytes) > 0 &&
      typeof v.disk_mount === 'string' && v.disk_mount.trim() !== '';
    const num = (x) => (x == null || !Number.isFinite(Number(x)) ? null : Number(x));

    const samples = uniq.filter(withDisk);
    // vmid -> the name this pass observed, for the rebuild wipe below.
    const vmids = uniq.map((v) => Number(v.vmid));
    const names = uniq.map((v) => nz(v.name));
    await tx(async (client) => {
      // PROXMOX RECYCLES VMIDS, and both tables here are keyed on vmid. A rebuilt VM 305 on a
      // fresh 100 GB disk inherits ~3,300 samples averaging 208 GB under the same vmid and the
      // same 'C:\' mountpoint, so disk_used_30d comes out ABOVE disk_total_bytes and the UI
      // paints a solid red 100% bar for five weeks on a disk that is nearly empty.
      //
      // So: a vmid observed under a DIFFERENT name is a different VM, and its inherited history
      // is dropped before anything is written. Both sides must go — the samples (which back the
      // averages) and the capacity row itself (which holds the already-computed averages, and
      // the CPU/RAM figures the upsert below COALESCEs onto).
      //
      // Guarded on both names being known: NULL on either side is "we did not observe a name",
      // which is not evidence of a rebuild and must never wipe a live VM's history.
      // Samples first, capacity second — the second statement re-reads the OLD name, which is
      // still there because only the samples have gone.
      const rebuilt =
        `SELECT cur.vmid FROM pmr_vm_capacity cur
           JOIN unnest($1::int[], $2::text[]) AS i(vmid, name) ON i.vmid = cur.vmid
          WHERE cur.name IS NOT NULL AND i.name IS NOT NULL AND cur.name <> i.name`;
      await client.query(
        `DELETE FROM pmr_vm_disk_samples s USING (${rebuilt}) r WHERE s.vmid = r.vmid`,
        [vmids, names]
      );
      await client.query(
        `DELETE FROM pmr_vm_capacity c USING (${rebuilt}) r WHERE c.vmid = r.vmid`,
        [vmids, names]
      );

      await bulkInsert(
        client,
        `INSERT INTO pmr_vm_capacity (vmid, node, name, cores, mem_max_bytes,
                                      cpu_pct_1d, cpu_pct_7d, cpu_pct_30d,
                                      mem_bytes_1d, mem_bytes_7d, mem_bytes_30d, mem_pressure_1d,
                                      disk_mount, disk_used_bytes, disk_total_bytes, disk_source,
                                      rrd_error, sampled_at, updated_at)`,
        // Two different rules in one SET list, and the difference is deliberate:
        //
        // CPU/RAM are COALESCEd, like agent_ok on proxmox_vms — a tick where the RRD read
        // failed but the agent answered must not blank a good average.
        //
        // THE DISK COLUMNS ARE NOT. They are written unconditionally, together, from the same
        // reading, so disk_source can never disagree with the numbers beside it. COALESCEing
        // them would leave last month's byte count sitting next to disk_source = 'unknown',
        // which reads as a current measurement and is a lie about a live pharmacy server.
        //
        // sampled_at is CONDITIONAL, and that is the whole point of it. The collector omits the
        // row when it established NOTHING, but a VM whose RRD path is broken while its guest
        // agent still answers sends a disk-only row every tick — and stamping now() on that
        // advanced the timestamp over CPU/RAM figures the SET list had just COALESCEd, so the
        // UI printed "sampled 2m ago" over numbers frozen since the RRD died, indefinitely.
        // It now only advances when the incoming row actually CARRIED an RRD reading, and
        // rrd_error (written unconditionally, so a repaired path clears it) says why when it
        // did not.
        `ON CONFLICT (vmid) DO UPDATE SET
           node = EXCLUDED.node, name = EXCLUDED.name,
           cores = COALESCE(EXCLUDED.cores, pmr_vm_capacity.cores),
           mem_max_bytes = COALESCE(EXCLUDED.mem_max_bytes, pmr_vm_capacity.mem_max_bytes),
           cpu_pct_1d = COALESCE(EXCLUDED.cpu_pct_1d, pmr_vm_capacity.cpu_pct_1d),
           cpu_pct_7d = COALESCE(EXCLUDED.cpu_pct_7d, pmr_vm_capacity.cpu_pct_7d),
           cpu_pct_30d = COALESCE(EXCLUDED.cpu_pct_30d, pmr_vm_capacity.cpu_pct_30d),
           mem_bytes_1d = COALESCE(EXCLUDED.mem_bytes_1d, pmr_vm_capacity.mem_bytes_1d),
           mem_bytes_7d = COALESCE(EXCLUDED.mem_bytes_7d, pmr_vm_capacity.mem_bytes_7d),
           mem_bytes_30d = COALESCE(EXCLUDED.mem_bytes_30d, pmr_vm_capacity.mem_bytes_30d),
           mem_pressure_1d = COALESCE(EXCLUDED.mem_pressure_1d, pmr_vm_capacity.mem_pressure_1d),
           disk_mount = EXCLUDED.disk_mount,
           disk_used_bytes = EXCLUDED.disk_used_bytes,
           disk_total_bytes = EXCLUDED.disk_total_bytes,
           disk_source = EXCLUDED.disk_source,
           rrd_error = EXCLUDED.rrd_error,
           sampled_at = CASE
             WHEN COALESCE(EXCLUDED.cpu_pct_1d, EXCLUDED.cpu_pct_7d, EXCLUDED.cpu_pct_30d,
                           EXCLUDED.mem_pressure_1d) IS NOT NULL
               OR COALESCE(EXCLUDED.mem_bytes_1d, EXCLUDED.mem_bytes_7d,
                           EXCLUDED.mem_bytes_30d) IS NOT NULL
             THEN now() ELSE pmr_vm_capacity.sampled_at END,
           updated_at = now()`,
        // 17 BOUND PARAMS. sampled_at and updated_at are the 18th and 19th COLUMNS but are
        // supplied as literals by the trailing argument below, so they are not counted here.
        17,
        uniq.map((v) => [
          Number(v.vmid), nz(v.node), nz(v.name),
          num(v.cores), num(v.mem_max_bytes),
          num(v.cpu_pct_1d), num(v.cpu_pct_7d), num(v.cpu_pct_30d),
          num(v.mem_bytes_1d), num(v.mem_bytes_7d), num(v.mem_bytes_30d),
          num(v.mem_pressure_1d),
          withDisk(v) ? String(v.disk_mount).trim() : null,
          withDisk(v) ? Number(v.disk_used_bytes) : null,
          withDisk(v) ? Number(v.disk_total_bytes) : null,
          // CHECK-constrained to these two values; anything else would abort the transaction.
          withDisk(v) ? 'agent' : 'unknown',
          nz(v.rrd_error),
        ]),
        // ONE string, TWO literals — placeholders() joins its parts with commas, so this
        // renders `,now(), now()` and fills both trailing columns. The count above (17) must
        // stay equal to the number of values in each .map() row: they are separate literals,
        // nothing derives one from the other, and a mismatch makes every tick 500 at bind time.
        placeholders(17, 'now(), now()')
      );

      // Our own disk history. Proxmox keeps none — its RRD `disk` is always 0 for a qemu VM —
      // so the 1d/7d/30d disk averages can only be computed from samples we accumulate here.
      // sampled_at defaults to now(), which is the TRANSACTION timestamp, so every row written
      // by one tick shares an instant and the PK cannot collide within it.
      if (samples.length) {
        await bulkInsert(
          client,
          // `name` rides along so the averages join can refuse to blend a rebuilt VM's history
          // with its predecessor's under a recycled vmid.
          `INSERT INTO pmr_vm_disk_samples (vmid, mountpoint, name, used_bytes, total_bytes)`,
          // A re-POST of the same tick must be a no-op, not a duplicate-key error that takes
          // the whole report down with it.
          `ON CONFLICT DO NOTHING`,
          5,
          samples.map((v) => [
            Number(v.vmid), String(v.disk_mount).trim(), nz(v.name),
            Number(v.disk_used_bytes), Number(v.disk_total_bytes),
          ]),
          placeholders(5)
        );
      }

      // Recompute the disk averages for exactly the VMs this report touched.
      //
      // Joined on mountpoint as well as vmid: if a VM's largest filesystem changes (a disk was
      // grown, or D: overtook C:), the average must not silently blend two different volumes.
      // Joined on NAME too, for the recycled-vmid case handled by the wipe at the top of this
      // transaction — belt and braces, so a sample that predates the wipe can never be averaged
      // into a different VM's reading. avg() over bigint returns numeric, so it is rounded back
      // to a whole byte count.
      //
      // A WINDOW THE HISTORY CANNOT COVER IS NULL, NOT AN AVERAGE OF WHAT WE HAPPEN TO HAVE.
      // Fifteen minutes after deploy every sample falls inside all three windows, so a plain
      // AVG returns d1 = d7 = d30 and the UI draws three confident equal bars — an engineer
      // reads "88% for a month, no action" off fifteen minutes of data. `first_at` is the
      // oldest sample for this (vmid, mountpoint, name), and each window is only written once
      // that sample is genuinely as old as the window is long.
      //
      // first_at is therefore taken over the UNFILTERED history and the 30-day cut moved into
      // its own FILTER: with the old `WHERE sampled_at >= now() - interval '30 days'` in place,
      // min(sampled_at) could never be 30 days old and d30 would be NULL forever. Retention
      // below keeps 35 days, which is what leaves room for the test to pass.
      await client.query(
        `UPDATE pmr_vm_capacity c
            SET disk_used_1d  = CASE WHEN s.first_at <= now() - interval '1 day'  THEN s.d1  END,
                disk_used_7d  = CASE WHEN s.first_at <= now() - interval '7 days' THEN s.d7  END,
                disk_used_30d = CASE WHEN s.first_at <= now() - interval '30 days' THEN s.d30 END,
                updated_at    = now()
           FROM (
             SELECT vmid, mountpoint, name,
                    min(sampled_at)                                                                       AS first_at,
                    round(avg(used_bytes) FILTER (WHERE sampled_at >= now() - interval '1 day'))::bigint   AS d1,
                    round(avg(used_bytes) FILTER (WHERE sampled_at >= now() - interval '7 days'))::bigint  AS d7,
                    round(avg(used_bytes) FILTER (WHERE sampled_at >= now() - interval '30 days'))::bigint AS d30
               FROM pmr_vm_disk_samples
              WHERE vmid = ANY($1::int[])
              GROUP BY vmid, mountpoint, name
           ) s
          WHERE c.vmid = s.vmid AND c.disk_mount = s.mountpoint
            AND c.name IS NOT DISTINCT FROM s.name`,
        [vmids]
      );

      // Retention. 35 days, not 30: the month window needs a full 30 days of samples behind it
      // at all times, so the table is trimmed with slack rather than exactly at the boundary.
      await client.query(
        `DELETE FROM pmr_vm_disk_samples WHERE sampled_at < now() - interval '35 days'`
      );
    });
    return { capacity_rows: uniq.length, disk_samples: samples.length };
  }

  // ── §7 · the desktop's own Windows printer list ────────────────────────────
  // Same pass, same POST, its own table and its own call — for the same reason capacity has
  // one: this is a READING and proxmox_vms is inventory, and they fail independently. A
  // desktop whose guest agent answers get-osinfo can still refuse guest-exec.
  //
  // Called AFTER reportProxmoxVms, so a printer row is never the first thing in the database
  // that mentions a vmid.
  //
  // ⛔ EVERY NAME REACHES SQL AS A BOUND PARAMETER AND AS NOTHING ELSE. These strings came out
  // of a Windows box: they are attacker-shaped input by construction. Nothing below builds SQL
  // from a name, and the ingest has already bounded their length, stripped control characters
  // and capped the list.
  async function reportProxmoxVmPrinters(list) {
    const arr = Array.isArray(list) ? list : [];
    const uniq = dedupeBy(arr.filter((v) => v && Number.isFinite(Number(v.vmid))), (v) => Number(v.vmid));
    if (!uniq.length) return { printer_rows: 0, printer_lists: 0 };

    // A row only carries a LIST if the ingest handed us an array AND a time it was read. The
    // contract makes collected_at required, so a list we cannot date is not a list we may
    // present — it is written as an error with no reading, which the UI renders as unknown.
    const withList = (v) => Array.isArray(v.printers) && v.read_at != null;
    const vmids = uniq.map((v) => Number(v.vmid));
    const names = uniq.map((v) => nz(v.name));

    await tx(async (client) => {
      // PROXMOX RECYCLES VMIDS, and this table is keyed on vmid. A rebuilt VM 305 would
      // otherwise inherit the previous machine's printer list and go on showing it, correctly
      // aged and completely wrong, until the new one is read. Same guard and same reasoning as
      // the capacity path above: both names must be known, because a NULL on either side is
      // "we did not observe a name" and is not evidence of a rebuild.
      await client.query(
        `DELETE FROM pmr_vm_printers p
           USING (SELECT cur.vmid FROM pmr_vm_printers cur
                    JOIN unnest($1::int[], $2::text[]) AS i(vmid, name) ON i.vmid = cur.vmid
                   WHERE cur.name IS NOT NULL AND i.name IS NOT NULL AND cur.name <> i.name) r
           WHERE p.vmid = r.vmid`,
        [vmids, names]
      );

      await bulkInsert(
        client,
        `INSERT INTO pmr_vm_printers (vmid, node, name, printers, read_at, source, error, updated_at)`,
        // printers and read_at MOVE TOGETHER, and both are COALESCEd. A pass that could not
        // read the guest leaves the last good list in place with its own true timestamp, so
        // the modal keeps showing what it knew and ages it honestly — rather than blanking to
        // "unknown" every time one call fails, or worse, stamping now() over a stale list.
        //
        // COALESCE is safe for the real-empty answer: '{}' is not NULL, so a guest that lists
        // no printers overwrites a previous list exactly as it should.
        //
        // `error` is NOT COALESCEd — it is written unconditionally, so a repaired path clears
        // it. `source` follows the list, because it describes the list.
        `ON CONFLICT (vmid) DO UPDATE SET
           node = EXCLUDED.node, name = EXCLUDED.name,
           printers = COALESCE(EXCLUDED.printers, pmr_vm_printers.printers),
           read_at  = COALESCE(EXCLUDED.read_at,  pmr_vm_printers.read_at),
           source   = CASE WHEN EXCLUDED.printers IS NOT NULL
                           THEN EXCLUDED.source ELSE pmr_vm_printers.source END,
           error    = EXCLUDED.error,
           updated_at = now()`,
        // 7 BOUND PARAMS. updated_at is the 8th COLUMN and is supplied as the literal now() by
        // the trailing argument below, so it is not counted here. The number must stay equal to
        // the length of every row in the .map() — nothing derives one from the other, and a
        // mismatch makes every tick 500 at bind time. That bug has shipped twice in this file.
        7,
        uniq.map((v) => [
          Number(v.vmid), nz(v.node), nz(v.name),
          // text[] binds straight from a JS array of strings. Never interpolated.
          withList(v) ? v.printers.map((s) => String(s)) : null,
          withList(v) ? v.read_at : null,
          withList(v) ? (v.source || 'guest-agent') : null,
          nz(v.error),
        ]),
        // NOT placeholders(): the two nullable non-scalar columns carry an explicit cast, the
        // same way flags::text[] and the job-args bind do above. A bare NULL parameter inside
        // the COALESCE in the SET list has no column to take its type from, and Postgres
        // answers that with "could not determine data type of parameter" — at bind time, on
        // every tick, for the one row shape that is most common (a VM with no reading).
        // updated_at is the 8th COLUMN, filled by the literal now(), and binds nothing.
        (o) => `($${o},$${o + 1},$${o + 2},$${o + 3}::text[],$${o + 4}::timestamptz,`
             + `$${o + 5},$${o + 6},now())`
      );
    });
    return { printer_rows: uniq.length, printer_lists: uniq.filter(withList).length };
  }

  // ── the per-site read the printers modal polls ─────────────────────────────
  // Every VM the site's thin clients can be pointed at, each with its printer reading or with
  // the reading's absence stated. pharmacy_vms_v rather than the desktops alone: the modal
  // looks a desktop up BY VMID, so an extra row costs nothing and a missing row is exactly the
  // failure this feed is clearing.
  //
  // LEFT JOIN, and it must stay one. A desktop with no reading has to appear WITH A NULL, not
  // vanish — an omitted key becomes a confident "no printers" in the UI.
  async function listDesktopPrinters(pharmacyId) {
    return await rows(
      `SELECT v.vmid, v.role, v.source AS vm_source, v.counter_id,
              pv.name, pv.node, pv.status, pv.agent_ok, pv.agent_error,
              pr.printers, pr.read_at, pr.source AS printer_source, pr.error AS printer_error
         FROM pharmacy_vms_v v
         LEFT JOIN proxmox_vms pv ON pv.vmid = v.vmid
         LEFT JOIN pmr_vm_printers pr ON pr.vmid = v.vmid
        WHERE v.pharmacy_id = $1
        ORDER BY v.vmid`,
      [pharmacyId]
    );
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
      const counter = await one(`SELECT id, vmid, boot_vmid FROM counters WHERE pharmacy_id = $1 AND n = $2`, [v.pharmacy_id, n]);
      if (!counter) {
        // A desktop VM exists for a counter nobody has recorded — worth knowing, since it
        // means the registry is behind reality rather than ahead of it.
        out.conflicts.push({ kind: 'counter_missing', pharmacy_id: v.pharmacy_id, counter_n: n, discovered: v.vmid, name: v.name });
        continue;
      }
      // NEVER guess against an explicit choice. This match is made on the `pmr-<code>-cl<n>`
      // NAME convention, which assumes every position owns a VM named for its own index — and
      // that is wrong wherever a position opens the site's PMR server instead. At iPharm the
      // single client VM is called cl01 but belongs to position 2, so this linked vm 306 to
      // position 1, which boots 305. The result was a phantom registration at an address
      // (.11) that no VM holds — now provable, because the guest agent reports 306 on .12.
      //
      // `boot_vmid` is the directive the platform actually pushes to the Pi. If a position has
      // one and it names a different VM, the name convention is simply wrong about this site:
      // report it and leave the record alone.
      if (counter.boot_vmid != null && counter.boot_vmid !== v.vmid) {
        out.conflicts.push({ kind: 'counter_boots_other', counter_id: counter.id, counter_n: n,
          boots: counter.boot_vmid, discovered: v.vmid, name: v.name });
      } else if (counter.vmid == null) {
        await q(`UPDATE counters SET vmid = $2, vm_hostname = COALESCE(vm_hostname, $3) WHERE id = $1`,
          [counter.id, v.vmid, v.name]);
        out.counters_linked += 1;
      } else if (counter.vmid !== v.vmid) {
        out.conflicts.push({ kind: 'counter_vmid', counter_id: counter.id, counter_n: n, recorded: counter.vmid, discovered: v.vmid, name: v.name });
      }
    }
    return out;
  }

  // The estate-wide VM Management list. Same capacity join as listPharmacyVms, and it has to be
  // here: the Desktop UI renders the capacity cell on THESE rows too, and without the join every
  // one of them read "not reported" permanently — VM 305 at 88% full included — with a tooltip
  // asserting nothing had ever sampled it. Only the per-site hub tab was ever right.
  //
  // ALIAS `cap`, NOT `pv`: `v` is the view here, and a duplicated LEFT JOIN alias in this file
  // once raised 42712 "table name pv specified more than once" and 500ed three callers. `cap` is
  // free in this query.
  //
  // cap.cores AND cap.sampled_at ARE ALIASED. proxmox_vms_v already exposes `cores` (and its own
  // `seen_at`), and node-postgres keeps the LAST column of a duplicated name — so an unaliased
  // cap.cores would silently overwrite the inventory's core count in the result object, and
  // shapeVmCapacity reads `capacity_sampled_at` by that exact name to decide whether a row was
  // ever sampled at all.
  //
  // LEFT JOIN, and it must stay one: a VM with no guest agent legitimately has no capacity row,
  // and an inner join would make it VANISH from the estate list rather than show as unknown.
  async function listProxmoxVms() {
    const list = await rows(
      `SELECT v.*,
              -- Top-level, and ALIASED below, for the reason shapeVmCapacity states: the
              -- capacity row is absent on every VM without a guest agent, and maxmem is the
              -- configured size whether or not anyone could ask the guest.
              COALESCE(cap.mem_max_bytes, v.maxmem) AS mem_max_bytes,
              cap.cores AS capacity_cores, cap.mem_max_bytes AS capacity_mem_max_bytes,
              cap.cpu_pct_1d, cap.cpu_pct_7d, cap.cpu_pct_30d,
              cap.mem_bytes_1d, cap.mem_bytes_7d, cap.mem_bytes_30d, cap.mem_pressure_1d,
              cap.disk_mount, cap.disk_used_bytes, cap.disk_total_bytes,
              cap.disk_used_1d, cap.disk_used_7d, cap.disk_used_30d, cap.disk_source,
              cap.rrd_error AS capacity_rrd_error, cap.sampled_at AS capacity_sampled_at
         FROM proxmox_vms_v v
         LEFT JOIN pmr_vm_capacity cap ON cap.vmid = v.vmid
        ORDER BY v.vlan_tag NULLS LAST, v.vmid`,
      []
    );
    return list.map(shapeVmCapacity);
  }

  // Expose the pool so callers (bin/migrate, graceful shutdown) can end() it.
  // ══════════════════════════════════════════════════════════════════════════
  // THE PMR CONTROL PLANE — opening hours, intended state, jobs
  // ══════════════════════════════════════════════════════════════════════════

  // ── opening hours ─────────────────────────────────────────────────────────
  // THE helper. "Is site X open at time T, when does it next close, when does it next
  // open, and where did those hours come from?" Everything else in this design calls it:
  // the API, the UI, the nightly scheduler, and — as pmr_disruptive_allowed() inside the
  // claim statement — the gate on every disruptive job. (site_open_at(), which this comment
  // used to name, is deleted: see the block above pmr_disruptive_allowed in db/schema.sql.)
  //
  // The decision itself is site_hours_state() in db/schema.sql, not JavaScript here. That
  // is not tidiness: the gate has to be evaluated INSIDE the statement that claims a job
  // (the ingest is a 3-worker cluster, and read-then-decide-then-claim would let two
  // workers hand out the same session restart), and opening hours are timezone-dependent,
  // so one implementation of BST/GMT is already one more than nobody can get wrong.
  // ⚠️ `resolved` is selected and must stay selected. It is what carries "we do not know"
  // out of Postgres and into the serialiser, which then OMITS openNow rather than sending
  // false — see openingHours.hoursPayload and the asymmetry note in db/schema.sql.
  //
  // ⛔ AND `gate_resolved` IS SELECTED, AND IS NOT THE SAME COLUMN (A1). `resolved` is true
  // for every pharmacy in the estate — site_hours_v hands every unknown weekday the estate
  // fallback window, and the mere existence of that row satisfies it — so a caller that reads
  // `resolved` and then decides whether to interrupt a live counter is deciding out of a
  // guess. That is exactly what requireDeliberateInterruption() was doing, which is what made
  // its unresolved arm dead code for every real counter. Anything that can sign a member of
  // staff out reads gate_resolved, through openingHours.gateResolved().
  async function getSiteHours(pharmacyId, at) {
    return one(
      `SELECT is_open, hours_source, next_open_at, next_close_at, site_timezone, resolved,
              gate_resolved
         FROM site_hours_state($1, COALESCE($2::timestamptz, now()))`,
      [pharmacyId, at || null]
    );
  }

  // "May an unattended disruptive job run at this site right now, and if not, when?"
  //
  // The same two functions the claim query and the job INSERT use, exposed as one read so a
  // caller can decide BEFORE creating work. The nightly pass asks this once per site: a
  // pharmacy that never closes has no window at all, and the right response is to record
  // that and create nothing — not to queue a restart that can only expire.
  async function siteDisruptiveWindow(pharmacyId, at) {
    return one(
      `SELECT pmr_disruptive_allowed($1, COALESCE($2::timestamptz, now()))      AS allowed_now,
              site_next_disruptive_window($1, COALESCE($2::timestamptz, now())) AS next_window_at,
              (SELECT s.resolved FROM site_hours_state($1, COALESCE($2::timestamptz, now())) s)
                AS hours_resolved,
              -- ⛔ The one the ANSWER above actually depends on (A1). hours_resolved is true
              -- for every site in the estate and explains nothing; this is why allowed_now is
              -- false and why next_window_at is null, and the UI needs it to say "nobody has
              -- entered this site's hours" instead of "it is open".
              site_hours_gate_resolved($1, COALESCE($2::timestamptz, now()))
                AS hours_gate_resolved`,
      [pharmacyId, at || null]
    );
  }

  // The effective week as the editor shows it, straight off the one view the resolver
  // reads — so the screen can never offer hours the gate would then disagree with. A site
  // with no rows of its own comes back as the estate fallback, labelled 'fallback'.
  async function listSiteHours(pharmacyId) {
    return rows(
      `SELECT wday, opens_s, closes_s, source, label
         FROM site_hours_v WHERE pharmacy_id = $1
        ORDER BY wday, opens_s`,
      [pharmacyId]
    );
  }

  // The weekdays somebody has stated the site does NOT trade. Read alongside the week
  // because the two together are the whole answer: a weekday in neither list is UNKNOWN,
  // which the view answers with the estate fallback window and the gate answers with "do
  // not disrupt". Without this list the editor cannot tell an operator which of its blank
  // days are a decision and which are a gap.
  async function listSiteClosedDays(pharmacyId) {
    return rows(
      `SELECT wday, source, created_by, created_at
         FROM pharmacy_hours_closed WHERE pharmacy_id = $1 ORDER BY wday`,
      [pharmacyId]
    );
  }

  async function listSiteHoursExceptions(pharmacyId) {
    return rows(
      `SELECT on_date, opens_s, closes_s, reason, created_by
         FROM pharmacy_hours_exceptions
        WHERE pharmacy_id = $1 AND on_date >= current_date - 30
        ORDER BY on_date`,
      [pharmacyId]
    );
  }

  // Replace a site's whole week in ONE transaction. Whole-week, never per-row: hours are
  // only correct as a set (the overlap check in openingHours.validateWeek is a property of
  // the week, not of a block), and a half-applied edit would leave a site whose Tuesday
  // came from the new plan and whose Wednesday came from the old one.
  //
  // `blocks` must already have been through openingHours.validateWeek — this writes
  // straight into a table the hours gate reads.
  async function setSiteHours(pharmacyId, blocks, f = {}) {
    const list = Array.isArray(blocks) ? blocks : [];
    const closed = Array.isArray(f.closed_wdays) ? f.closed_wdays : [];
    const source = f.source === 'voip' ? 'voip' : 'manual';
    return tx(async (client) => {
      const site = await client.query(`SELECT id FROM pharmacies WHERE id = $1`, [pharmacyId]);
      if (!site.rows.length) return null;
      // Scoped to the SOURCE being written. A VoIP import replaces the rows it owns and
      // leaves a typed override alone; a manual edit replaces the manual rows. Deleting the
      // whole site's hours on either path would make an import silently discard an
      // operator's correction, which is how two sources of truth start disagreeing.
      await client.query(
        `DELETE FROM pharmacy_hours WHERE pharmacy_id = $1 AND source = $2`,
        [pharmacyId, source]
      );
      for (const b of list) {
        await client.query(
          `INSERT INTO pharmacy_hours
             (pharmacy_id, wday, opens_s, closes_s, source, voip_rule_id, label, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (pharmacy_id, wday, opens_s) DO UPDATE SET
             closes_s = EXCLUDED.closes_s, source = EXCLUDED.source,
             voip_rule_id = EXCLUDED.voip_rule_id, label = EXCLUDED.label,
             updated_at = now(), updated_by = EXCLUDED.updated_by`,
          [pharmacyId, b.wday, b.opens_s, b.closes_s, source, nz(b.voip_rule_id), nz(b.label), nz(f.by)]
        );
      }
      // The closed weekdays go in the SAME transaction, for the same reason the blocks do:
      // "Tuesday has no rows" and "Tuesday is a day we do not trade" are different states,
      // and a half-applied edit that left the site with the first when the operator meant
      // the second would make the gate treat a closed day as unknown (harmless) or — the
      // way that matters — leave a stale closed marker on a day that now trades, which
      // makes an unattended restart legal on a trading morning.
      await client.query(
        `DELETE FROM pharmacy_hours_closed WHERE pharmacy_id = $1 AND source = $2`,
        [pharmacyId, source]
      );
      for (const wday of closed) {
        await client.query(
          `INSERT INTO pharmacy_hours_closed (pharmacy_id, wday, source, created_by)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (pharmacy_id, wday) DO UPDATE SET
             source = EXCLUDED.source, created_by = EXCLUDED.created_by, created_at = now()`,
          [pharmacyId, wday, source, nz(f.by)]
        );
      }
      return { pharmacy_id: pharmacyId, blocks: list.length, closed_wdays: closed.length, source };
    });
  }

  // A bank holiday or a one-off closure. Both times null = closed all day, which is the
  // common case and the reason this is a separate table from the weekly pattern.
  async function setSiteHoursException(pharmacyId, f = {}) {
    return one(
      `INSERT INTO pharmacy_hours_exceptions
         (pharmacy_id, on_date, opens_s, closes_s, reason, created_by)
       VALUES ($1, $2::date, $3, $4, $5, $6)
       ON CONFLICT (pharmacy_id, on_date) DO UPDATE SET
         opens_s = EXCLUDED.opens_s, closes_s = EXCLUDED.closes_s,
         reason = EXCLUDED.reason, created_by = EXCLUDED.created_by
       RETURNING pharmacy_id, on_date, opens_s, closes_s, reason`,
      [pharmacyId, f.on_date, f.opens_s == null ? null : f.opens_s,
        f.closes_s == null ? null : f.closes_s, nz(f.reason), nz(f.by)]
    );
  }

  async function deleteSiteHoursException(pharmacyId, onDate) {
    const r = await q(
      `DELETE FROM pharmacy_hours_exceptions WHERE pharmacy_id = $1 AND on_date = $2::date`,
      [pharmacyId, onDate]
    );
    return { deleted: r.rowCount || 0 };
  }

  // The estate fallback window. READ ONLY from the API on purpose: it is one fixed window
  // for the whole estate, deliberately generous, and the thing it protects is a site nobody
  // has told us the hours of. Narrowing it is a schema change with a review, not a form.
  async function getEstateHours() {
    return one(`SELECT wdays, opens_s, closes_s, updated_at, updated_by FROM estate_hours WHERE id = 1`);
  }

  // ── intended state ────────────────────────────────────────────────────────
  // What Watchman WANTS for a subject. `field` and `want` are validated by
  // pmrVerbs.validateIntent before they get here — this writes into a table a reconciler
  // acts on, so it must never see an unvalidated value.
  //
  // ⚠️ THE SUBJECT IS RESOLVED HERE, NOT TAKEN FROM THE CALLER (B5). PUT /pmr/intent used to
  // INSERT whatever vmid the body named, while POST /pmr/jobs resolved the same value
  // through pharmacy_vms_v — so the cheaper route round the back was to write an intent for
  // any vmid the cluster reports and let the reconciler turn it into a real vm.set-onboot
  // job on that VM's node. An intent is not a note; it is a standing instruction to a loop
  // that creates jobs, so it gets the same resolution the job path gets.
  //
  // The resolution is a JOIN inside the same statement, for every property createPmrVmJob
  // relies on: an unregistered vmid produces no row, the INSERT matches nothing, and the
  // caller reports the 404 the handler already tries to return — rather than a guess.
  async function setPmrIntent(f = {}) {
    return one(
      `WITH subject AS (
         SELECT p.id AS pharmacy_id,
                CASE WHEN $1 = 'vm' THEN v.vmid END       AS vmid,
                CASE WHEN $1 = 'counter' THEN c.id END    AS counter_id
           FROM pharmacies p
           -- A vm intent must name a vmid REGISTERED to this pharmacy. The join is dropped
           -- for every other subject kind by the $1 test, so a counter intent is not asked
           -- to produce a VM.
           LEFT JOIN pharmacy_vms_v v ON $1 = 'vm' AND v.pharmacy_id = p.id AND v.vmid = $4
           -- A counter intent must name a counter AT this pharmacy, for the same reason.
           LEFT JOIN counters c ON $1 = 'counter' AND c.pharmacy_id = p.id AND c.id = $3
          WHERE p.id = $2
            AND ($1 <> 'vm' OR v.vmid IS NOT NULL)
            AND ($1 <> 'counter' OR c.id IS NOT NULL)
          -- One row, always. A duplicate here would make ON CONFLICT try to affect the same
          -- intent row twice in one statement, which Postgres refuses outright.
          LIMIT 1
       )
       INSERT INTO pmr_intent
         (subject_kind, pharmacy_id, counter_id, vmid, printer_key, field, want, set_by)
       SELECT $1, sj.pharmacy_id, sj.counter_id, sj.vmid, $5, $6, $7::jsonb, $8
         FROM subject sj
       ON CONFLICT (subject_kind, pharmacy_id, COALESCE(counter_id, 0), COALESCE(vmid, 0),
                    COALESCE(printer_key, ''), field)
       DO UPDATE SET want = EXCLUDED.want, set_by = EXCLUDED.set_by, set_at = now(),
         -- Cleared on every change, for the same reason setCounterBootTarget clears
         -- boot_applied_at: until the world has been read again, the previous reading says
         -- nothing about the NEW intention, and leaving it would render as "already met".
         observed = NULL, observed_at = NULL, last_job_id = NULL
       RETURNING id, subject_kind, pharmacy_id, counter_id, vmid, printer_key, field,
                 want, observed, observed_at, set_by, set_at`,
      [f.subject_kind, f.pharmacy_id, f.counter_id == null ? null : f.counter_id,
        f.vmid == null ? null : f.vmid, nz(f.printer_key), f.field,
        JSON.stringify(f.want), nz(f.by)]
    );
  }

  async function listPmrIntent(pharmacyId) {
    return rows(
      `SELECT i.id, i.subject_kind, i.pharmacy_id, i.counter_id, i.vmid, i.printer_key,
              i.field, i.want, i.observed, i.observed_at, i.last_job_id, i.set_by, i.set_at,
              (i.observed IS NOT NULL AND i.observed = i.want) AS met
         FROM pmr_intent i
        WHERE ($1::bigint IS NULL OR i.pharmacy_id = $1)
        ORDER BY i.pharmacy_id, i.field, i.vmid NULLS FIRST, i.counter_id NULLS FIRST`,
      [pharmacyId == null ? null : pharmacyId]
    );
  }

  async function deletePmrIntent(id) {
    const r = await q(`DELETE FROM pmr_intent WHERE id = $1`, [id]);
    return { deleted: r.rowCount || 0 };
  }

  // ── creating a job ────────────────────────────────────────────────────────
  // ARGUMENTS ARE RESOLVED SERVER-SIDE, IN THE SAME STATEMENT AS THE INSERT. This is
  // setCounterBootTarget's shape and every one of its properties is load-bearing here too:
  // the caller passes an IDENTIFIER (a counter id, a pharmacy + vmid) and never an address
  // or a node name; the resolution reads the SAME view the picker offers, so a choice the
  // UI can show always resolves; an unresolvable target yields no row, the INSERT matches
  // nothing and the caller reports a REFUSAL rather than a guess; and there is no window in
  // which a resolved value could be written for a target that stopped being valid.
  //
  // The verb, its disruptive/retry flags, its confirming reading and its time limits all
  // come from the CLOSED allowlist in src/shared/pmrVerbs.js, applied by the caller. This
  // function never invents any of them, and the DB CHECKs refuse a row that carries a verb
  // or a confirm kind outside those sets.

  // A job for the Pi on one counter. Resolves the executing device AND the site whose
  // opening hours will gate it — a job with no pharmacy_id would be ungated, and
  // pmr_disruptive_allowed() answers FALSE for an unknown site precisely so that case still
  // waits. (This comment used to credit site_open_at(), which is now deleted — D8.)
  //
  // ⚠️ THE HELD JOB'S CLOCK STARTS WHEN THE GATE OPENS (S1/S12). not_before was set by NO
  // code path, and a deferred disruptive job carried a 5400-second TTL from the moment it
  // was written — so a restart raised at 11:00 was correctly held by the hours gate, and
  // then EXPIRED at 12:30, thirteen hours before the midnight the wait-reason sentence had
  // literally promised the operator. The row said one thing and the timer did another.
  //
  // Both are now computed from site_next_disruptive_window(): not_before IS the promise, and
  // the expiry is that same instant plus the verb's TTL. A job held by the gate cannot
  // expire before it was ever eligible.
  //
  // And if there is NO window — a 24-hour pharmacy — the INSERT deliberately matches nothing
  // and the caller reports a refusal. Queuing a restart that can only ever expire is how the
  // pre-opening check ends up emailing about a counter that is perfectly healthy.
  async function createPmrCounterJob(counterId, f = {}) {
    return one(
      `WITH resolved AS (
         -- The counter's own row is the resolution source. A counter with no thin client
         -- enrolled yields no row, which the caller reports as a refusal: there is nothing
         -- to send it to, and inventing a device id is how a job goes to the wrong Pi.
         SELECT c.id AS counter_id, c.pharmacy_id, c.pi_device_id
           FROM counters c
          WHERE c.id = $1 AND c.pi_device_id IS NOT NULL
       ), gated AS (
         SELECT r.*,
                CASE WHEN $4::boolean THEN pmr_disruptive_allowed(r.pharmacy_id, now())
                     ELSE true END AS allowed_now
           FROM resolved r
       ), held AS (
         SELECT g.*,
                CASE WHEN g.allowed_now THEN NULL
                     ELSE site_next_disruptive_window(g.pharmacy_id, now()) END AS hold_until
           FROM gated g
       )
       INSERT INTO pmr_jobs
         (verb, executor, pi_device_id, pharmacy_id, counter_id, args, disruptive, retry_ok,
          confirm_kind, confirm_deadline_s, not_before, expires_at, claim_ttl_s, max_attempts,
          intent_id, created_by)
       SELECT $2, 'counter-pi', h.pi_device_id, h.pharmacy_id, h.counter_id,
              $3::jsonb, $4, $5, $6, $7,
              COALESCE($8::timestamptz, h.hold_until),
              COALESCE($8::timestamptz, h.hold_until, now()) + make_interval(secs => $9),
              $10, $11, $12, $13
         FROM held h
        WHERE h.allowed_now OR h.hold_until IS NOT NULL
       RETURNING id, verb, status, disruptive, pharmacy_id, counter_id, not_before,
                 expires_at, created_at`,
      [counterId, f.verb, JSON.stringify(f.args || {}), !!f.disruptive, !!f.retry_ok,
        f.confirm_kind, f.confirm_deadline_s, f.not_before || null, f.ttl_s, f.claim_ttl_s,
        f.max_attempts == null ? 3 : f.max_attempts,
        f.intent_id == null ? null : f.intent_id, nz(f.by) || 'watchman']
    );
  }

  // A job for the Proxmox node that hosts one VM.
  //
  // TWO resolutions, and both matter. `pharmacy_vms_v` decides whether this pharmacy is
  // allowed to name this vmid at all — the same view the VM picker reads, so a VM
  // discovered on the site's VLAN but never registered to the site is REFUSED rather than
  // guessed at. `proxmox_vms` then supplies the NODE, which is what makes the job
  // deliverable: a node collects only jobs addressed to it, and the node name is never
  // taken from the caller.
  //
  // The resolved vmid and node are merged OVER the caller's args, so a caller-supplied
  // vmid can never be the one an executor acts against.
  async function createPmrVmJob(pharmacyId, vmid, f = {}) {
    return one(
      `WITH resolved AS (
         SELECT p.id AS pharmacy_id, v.vmid, pv.node
           FROM pharmacies p
           JOIN pharmacy_vms_v v ON v.pharmacy_id = p.id AND v.vmid = $2
           JOIN proxmox_vms pv   ON pv.vmid = v.vmid AND pv.node IS NOT NULL
          WHERE p.id = $1
       )
       , gated AS (
         SELECT r.*,
                CASE WHEN $5::boolean THEN pmr_disruptive_allowed(r.pharmacy_id, now())
                     ELSE true END AS allowed_now
           FROM resolved r
       ), held AS (
         SELECT g.*,
                CASE WHEN g.allowed_now THEN NULL
                     ELSE site_next_disruptive_window(g.pharmacy_id, now()) END AS hold_until
           FROM gated g
       )
       INSERT INTO pmr_jobs
         (verb, executor, node, pharmacy_id, vmid, args, disruptive, retry_ok,
          confirm_kind, confirm_deadline_s, not_before, expires_at, claim_ttl_s, max_attempts,
          intent_id, created_by)
       SELECT $3, 'proxmox-node', h.node, h.pharmacy_id, h.vmid,
              $4::jsonb || jsonb_build_object('vmid', h.vmid),
              $5, $6, $7, $8,
              COALESCE($9::timestamptz, h.hold_until),
              COALESCE($9::timestamptz, h.hold_until, now()) + make_interval(secs => $10),
              $11, $12, $13, $14
         FROM held h
        WHERE h.allowed_now OR h.hold_until IS NOT NULL
       RETURNING id, verb, status, disruptive, pharmacy_id, vmid, node, not_before,
                 expires_at, created_at`,
      [pharmacyId, vmid, f.verb, JSON.stringify(f.args || {}), !!f.disruptive, !!f.retry_ok,
        f.confirm_kind, f.confirm_deadline_s, f.not_before || null, f.ttl_s, f.claim_ttl_s,
        f.max_attempts == null ? 3 : f.max_attempts,
        f.intent_id == null ? null : f.intent_id, nz(f.by) || 'watchman']
    );
  }

  // ── claiming a job ────────────────────────────────────────────────────────
  // Handing a job out in a poll reply IS the claim, so it must be atomic with the read.
  // FOR UPDATE SKIP LOCKED, not read-then-update: the ingest runs a 3-worker cluster and
  // two of a Pi's ticks (or two nodes' pushes) can land on different processes at once.
  // claimRelayRequest is the working precedent; config_jobs has no lock because there a job
  // is claimed by being SERVED to one authenticated device, which does not hold here.
  //
  // THREE GATES, all in the one predicate:
  //   * expires_at — an unclaimed job EXPIRES rather than firing late. A session restart
  //     queued at midnight must not go off at 09:20 because a Pi came back late.
  //   * the visibility timeout — a lapsed claim is re-offered ONLY when the verb says it is
  //     re-runnable, the same idempotent/not distinction claimRelayRequest draws with
  //     method IN ('GET','HEAD'). Re-handing out a shutdown is not free.
  //   * pmr_job_wait_reason() — the hours gate, and the ONE definition of it. A disruptive
  //     job at an open site is skipped here and pmr_jobs_v reports the identical reason, so
  //     "ready" on the screen and "claimable" in the database cannot drift.
  //
  // TWO MORE GATES since, and both close a way this loop could run away:
  //   * THE ATTEMPTS CAP (B3). retry_ok says a lapsed claim MAY be re-offered; max_attempts
  //     says how often. counter.session-restart has a 120-second claim TTL inside a
  //     5400-second life, so without a cap a Pi that took a restart and never reported —
  //     the ordinary case, because restarting the session can lose the reply — was handed
  //     the same sign-out forty-five times. The cap is in the predicate AND in
  //     pmr_job_wait_reason, so the screen says why it stopped.
  //   * AN OVERRIDDEN JOB IS OFFERED ONCE (B3). override_hours is stored permanently, so
  //     after an apply-now the hours gate is off for that row FOREVER — and a re-offer
  //     under a lapsed claim would then fire INSIDE opening hours, repeatedly, which is the
  //     exact thing the operator authorised once.
  //
  // AND ONE CAPABILITY GATE (S10). Handing the job out IS the claim: there is no ack. An
  // executor that does not understand `pmr_job` therefore SWALLOWS it — pending, claimed,
  // expired — and the pre-opening check then emails "counters may not open" about a
  // perfectly healthy counter, every night, for the whole estate. The shipped Pi agent
  // reports agent_version 1 and has no pmr_job branch at all, so it must be offered NOTHING
  // until the build that implements the key reports PMR_JOB_AGENT_VERSION.
  async function claimPmrJobForDevice(deviceId, claimedBy, minAgentVersion) {
    if (!isUuid(deviceId)) return null;
    // No floor supplied is not "no floor": an unknown requirement must not become an open
    // door. The caller passes pmrVerbs.PMR_JOB_AGENT_VERSION; anything else refuses.
    const floor = Number.isInteger(minAgentVersion) && minAgentVersion > 0 ? minAgentVersion : null;
    if (floor === null) return null;
    return one(
      `UPDATE pmr_jobs j
          SET status = 'claimed', claimed_at = now(), claimed_by = $2,
              attempts = j.attempts + 1
        WHERE j.id = (
          SELECT q.id FROM pmr_jobs q
           WHERE q.executor = 'counter-pi'
             AND q.pi_device_id = $1
             AND q.expires_at > now()
             AND q.attempts < q.max_attempts
             AND NOT (q.override_hours AND q.attempts > 0)
             AND (q.status = 'pending'
                  OR (q.status = 'claimed' AND q.retry_ok
                      AND q.claimed_at < now() - make_interval(secs => q.claim_ttl_s)))
             AND pmr_job_wait_reason(q, now()) IS NULL
             -- The executor's own reported version, out of the telemetry body this device
             -- already posts. The cast is inside a CASE, never guarded by an AND: SQL does
             -- not promise left-to-right evaluation, so a regex test AND-ed with a cast
             -- can still run the cast first and error the whole claim on one malformed
             -- payload. A device that has never reported yields NULL, and NULL >= n is not
             -- true — which is the safe answer.
             AND (SELECT CASE WHEN (ds.raw ->> 'agent_version') ~ '^[0-9]{1,9}$'
                              THEN (ds.raw ->> 'agent_version')::int END
                    FROM device_state ds WHERE ds.device_id = q.pi_device_id) >= $3
           ORDER BY q.created_at
           FOR UPDATE SKIP LOCKED
           LIMIT 1
        )
        RETURNING j.id AS job_id, j.verb, j.args`,
      [deviceId, nz(claimedBy) || 'counter-pi', floor]
    );
  }

  // The node variant. Hands out SEVERAL jobs, because this executor's poll is 15 minutes
  // and its timer carries an explicit do-not-shorten warning — one job per tick would take
  // an hour to set onboot on four VMs at one site. Bounded so a backlog cannot arrive as
  // one enormous reply.
  //
  // ⚠️ AND THE SAME CAPABILITY FLOOR THE PI PATH HAS (D4). This path carried the hours gate
  // and the attempts cap but no floor at all, which made it one PROXMOX_NODE_TOKENS entry
  // away from the exact failure S10 describes: the SHIPPED collector posts
  // {"vms","capacity"} and parses no `jobs` key, so the first per-node token issued to it
  // would have made every job addressed to that node vanish — claimed on the reply, never
  // executed, never reported, expired at its deadline. On this path the vanishing verbs
  // include vm.shutdown and vm.reboot, so "claimed and silently lost" would be a live
  // pharmacy desktop believed to have been shut down.
  //
  // Handing a job out IS the claim on this executor too: it rides the reply to a push the
  // collector already makes, and there is no ack. So the floor is checked BEFORE anything is
  // selected, and a collector below it sees no jobs — the correct direction, because a job
  // never offered stays pending and shows as waiting.
  //
  // `collectorVersion` is the collector's own claim about itself, out of the body it also
  // authored. That is the same trust as the Pi's agent_version (read from device_state.raw,
  // which the agent wrote), and it is acceptable for the same reason: the failure direction
  // is "a capable collector is offered no work", never "an incapable one is". A collector
  // that lies UPWARD swallows its own jobs, which is a bug in that collector and visible as
  // jobs that expire against one node.
  async function claimPmrJobsForNode(node, limit, collectorVersion, minCollectorVersion) {
    const name = typeof node === 'string' ? node.trim() : '';
    if (!name) return [];
    // No floor supplied is not "no floor" — the same refusal claimPmrJobForDevice makes. The
    // caller passes pmrVerbs.PMR_JOB_COLLECTOR_VERSION; anything else hands out nothing.
    const floor = Number.isInteger(minCollectorVersion) && minCollectorVersion > 0
      ? minCollectorVersion : null;
    if (floor === null) return [];
    // A collector that reports NO version is pre-floor by definition. Checked as an integer
    // and never parsed out of a string, for the same reason the settings whitelist refuses
    // "24": a version arriving as text is a collector bug, and coercing it hides exactly the
    // class of mistake this floor exists to catch.
    const have = Number.isInteger(collectorVersion) ? collectorVersion : 0;
    if (have < floor) return [];
    const cap = Number.isInteger(limit) && limit > 0 && limit <= 20 ? limit : 4;
    return rows(
      `UPDATE pmr_jobs j
          SET status = 'claimed', claimed_at = now(), claimed_by = $1,
              attempts = j.attempts + 1
        WHERE j.id IN (
          SELECT q.id FROM pmr_jobs q
           WHERE q.executor = 'proxmox-node'
             AND q.node = $1
             AND q.expires_at > now()
             -- Same two loop-breakers as the Pi path (B3). The node's claim TTL is 1800s
             -- rather than 120s, so the loop is slower — a slow loop that shuts a live
             -- pharmacy desktop four times is still a loop.
             AND q.attempts < q.max_attempts
             AND NOT (q.override_hours AND q.attempts > 0)
             AND (q.status = 'pending'
                  OR (q.status = 'claimed' AND q.retry_ok
                      AND q.claimed_at < now() - make_interval(secs => q.claim_ttl_s)))
             AND pmr_job_wait_reason(q, now()) IS NULL
           ORDER BY q.created_at
           FOR UPDATE SKIP LOCKED
           LIMIT $2
        )
        RETURNING j.id AS job_id, j.verb, j.args`,
      [name, cap]
    );
  }

  // ── the executor's report ─────────────────────────────────────────────────
  // 'applied' means THE EXECUTOR SAYS IT RAN. It is not done. finished_at stays null and
  // the confirm pass decides, from a reading nothing on the executor wrote.
  //
  // Ownership is re-checked here even though the caller authenticated, exactly as
  // POST /config/result re-checks with getConfigJobForFetch and relayNext re-checks the
  // session's device: a valid token for counter B must not be able to close counter A's
  // job. Exactly one of the two scopes is supplied; the other is null and its arm cannot
  // match.
  async function recordPmrJobResult(jobId, f = {}, scope = {}) {
    if (!isUuid(jobId)) return null;
    const status = f.status === 'applied' ? 'applied' : 'failed';
    return one(
      `UPDATE pmr_jobs SET
         status      = $2,
         applied_at  = CASE WHEN $2 = 'applied' THEN now() ELSE applied_at END,
         -- A failure is over. An 'applied' job is NOT: it is waiting to be proven, and
         -- stamping finished_at here is precisely the "it exited 0, so it worked" mistake
         -- this ladder exists to make impossible.
         finished_at = CASE WHEN $2 = 'applied' THEN NULL ELSE now() END,
         result_log  = $3
       WHERE id = $1
         AND status = 'claimed'
         AND (($4::uuid IS NOT NULL AND pi_device_id = $4)
           OR ($5::text IS NOT NULL AND node = $5))
       RETURNING id, verb, status, confirm_kind, confirm_deadline_s, counter_id, pharmacy_id`,
      [jobId, status, nz(f.result_log),
        isUuid(scope.pi_device_id) ? scope.pi_device_id : null,
        typeof scope.node === 'string' && scope.node.trim() ? scope.node.trim() : null]
    );
  }

  // ── the independent observation, taken on the telemetry hot path ──────────
  // Half the proof that a counter session really signed out: the moment a thin client
  // reports its RDP client DOWN after a session-restart job was applied, stamp it.
  //
  // Computed from the state row the telemetry handler has ALREADY written this tick, so it
  // needs nothing from the payload and no cooperation from the agent — the same trick
  // getCounterBootDirective uses for its boot_applied_at stamp. Guarded on
  // session_down_at IS NULL and on there being a job in flight, so the hot path writes once
  // per restart rather than on every 30 s tick.
  async function notePmrSessionDown(deviceId) {
    if (!isUuid(deviceId)) return;
    await q(
      `UPDATE pmr_jobs j SET session_down_at = now()
         FROM device_state ds
        WHERE ds.device_id = j.pi_device_id
          AND j.pi_device_id = $1
          AND j.status = 'applied'
          -- Both counter verbs that end in a session restart. The printer promote swaps the
          -- staged table and restarts the session as ONE action (contract section 4), so the
          -- same down-then-up transition is half of its proof too.
          AND j.confirm_kind IN ('pi-session-restarted', 'pi-printers-promoted')
          AND j.session_down_at IS NULL
          AND (ds.raw -> 'rdp' ->> 'running') = 'false'`,
      [deviceId]
    );

    // ── the OTHER half of the promote's proof (B2) ─────────────────────────
    // pmrVerbs.js defends counter.printing-promote's self-attestation with "print_tab_pending
    // must be observed TRUE-then-FALSE across the moment the job was applied". The FALSE half
    // was tested; the TRUE half was never recorded anywhere, so the confirm pass could not
    // tell "the staged table was promoted" from "this counter has never had one".
    //
    // Stamped here, on the same hot path and by the same trick as session_down_at: computed
    // from the state row the telemetry handler has already written this tick, needing nothing
    // from the payload and no cooperation from the agent.
    //
    // ⚠️ NOT RESTRICTED TO status='applied'. The staged table exists from the moment the tick
    // sends it, which is BEFORE the job is claimed and long before it is applied — a promote
    // waits for the site's overnight window. Waiting for 'applied' would look for TRUE in the
    // one window where it is about to become FALSE, and would find it almost never. Every
    // status that is still going somewhere is included; a job that already finished is not,
    // so this writes once per job and not on every 30 s tick forever.
    await q(
      `UPDATE pmr_jobs j SET print_tab_staged_at = now()
         FROM device_state ds
        WHERE ds.device_id = j.pi_device_id
          AND j.pi_device_id = $1
          AND j.confirm_kind = 'pi-printers-promoted'
          AND j.status IN ('pending', 'claimed', 'applied')
          AND j.print_tab_staged_at IS NULL
          AND (ds.raw -> 'peripherals' ->> 'print_tab_pending') = 'true'`,
      [deviceId]
    );
  }

  // ── DONE MEANS PROVEN: the confirm pass ───────────────────────────────────
  // One set-based statement per confirming reading. Every one of them joins a table that
  // some OTHER collector wrote — proxmox_vms from the node's 15-minute push, device_state
  // from the Pi's own telemetry — and every one requires the reading to be NEWER than the
  // moment the job was applied. A reading taken before the job ran proves nothing, and that
  // freshness test is the whole difference between this and trusting an exit code.
  //
  // Nothing here can be reached by an executor. There is no route by which the thing that
  // ran the job can also declare it confirmed.
  async function confirmPmrJobs() {
    let confirmed = 0;

    // The counter session signed out and back in. TWO arms, either sufficient:
    //   1. the Pi reports an RDP session that STARTED after the job was applied. This is
    //      the deterministic proof and it needs one new agent-side field
    //      (rdp.session_started_at); the arm is written now so it lights up the moment that
    //      build lands, with no change here.
    //   2. the session was independently OBSERVED down (notePmrSessionDown, above) and a
    //      LATER reading shows it up again. This needs no new field and works today, but it
    //      can miss a bounce that completes inside one 30 s tick — in which case the job
    //      reaches its deadline and FAILS, which raises the counter in the pre-opening
    //      check. Failing towards "somebody look at this before the pharmacy opens" is the
    //      correct direction for the one job that must not be quietly assumed.
    //
    // The cast is inside a CASE, not guarded by an AND: SQL does not promise to evaluate
    // AND left-to-right, so a `~ '^[0-9]+$' AND ...::bigint` pair can still evaluate the
    // cast first and error the whole pass on one malformed payload.
    const sess = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = CASE
                WHEN r.started_ms IS NOT NULL THEN
                  'the thin client reports an RDP session started after this job was applied'
                ELSE
                  'the RDP session was observed down at '
                  || to_char(j.session_down_at, 'YYYY-MM-DD HH24:MI:SS')
                  || ' and up again in a later reading' END
         FROM device_state ds,
              LATERAL (SELECT CASE
                                WHEN (ds.raw -> 'rdp' ->> 'session_started_at') ~ '^[0-9]{1,19}$'
                                THEN (ds.raw -> 'rdp' ->> 'session_started_at')::bigint
                              END AS started_ms,
                              (ds.raw -> 'rdp' ->> 'running') = 'true' AS rdp_up) r
        WHERE ds.device_id = j.pi_device_id
          AND j.status = 'applied'
          AND j.confirm_kind = 'pi-session-restarted'
          AND j.applied_at IS NOT NULL
          AND ( r.started_ms > (EXTRACT(epoch FROM j.applied_at) * 1000)
             OR (j.session_down_at IS NOT NULL AND r.rdp_up
                 AND ds.last_seen_at > j.session_down_at) )`
    );
    confirmed += sess.rowCount || 0;

    // The thin client actually rebooted: it is back, and its uptime is SHORTER than the
    // time since the job was applied. Comparing uptime rather than "did it come back"
    // matters — a Pi that never rebooted at all is also online and also reporting.
    const piBoot = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = 'the thin client is back with an uptime of '
                               || ds.uptime_s || 's, shorter than the age of this job'
         FROM device_state ds
        WHERE ds.device_id = j.pi_device_id
          AND j.status = 'applied'
          AND j.confirm_kind = 'pi-uptime-reset'
          AND j.applied_at IS NOT NULL
          AND ds.last_seen_at > j.applied_at
          AND ds.uptime_s IS NOT NULL
          AND ds.uptime_s < EXTRACT(epoch FROM (ds.last_seen_at - j.applied_at)) + 60`
    );
    confirmed += piBoot.rowCount || 0;

    // THE STAGED PRINTER TABLE IS NO LONGER STAGED, and the session came back.
    //
    // print_tab_pending is the agent's own comparison of printers.tab.next against
    // printers.tab, on significant lines only. The promote verb's whole job is to make that
    // comparison equal and restart the session, so the pair (pending false, RDP up) in a
    // reading taken AFTER the job was applied is the transition that proves both halves ran.
    //
    // ⚠️ The freshness test is what stops this confirming on a counter that never had a
    // staged table at all: a reading OLDER than applied_at proves nothing, and a job is only
    // ever raised for a counter whose effective table actually changed.
    //
    // ⚠️ SELF-ATTESTED — device_state.raw is the Pi's own writing. pmrVerbs.js says so on the
    // verb, names the independent reading that would replace this (the guest agent's own
    // printer list, read by the Proxmox collector), and states why shipping it this way is
    // defensible for THIS verb.
    const printersPromoted = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = CASE
                WHEN j.session_down_at IS NOT NULL THEN
                  'the thin client reports no staged printer table remaining, and its RDP '
                  || 'session was observed down at '
                  || to_char(j.session_down_at, 'YYYY-MM-DD HH24:MI:SS')
                  || ' and up again in a later reading'
                ELSE
                  'the thin client reported a staged printer table at '
                  || to_char(j.print_tab_staged_at, 'YYYY-MM-DD HH24:MI:SS')
                  || ' and reports none remaining, with its RDP session up, in a reading '
                  || 'taken after this job was applied' END
         FROM device_state ds
        WHERE ds.device_id = j.pi_device_id
          AND j.status = 'applied'
          AND j.confirm_kind = 'pi-printers-promoted'
          AND j.applied_at IS NOT NULL
          AND ds.last_seen_at > j.applied_at
          -- ⛔ TRUE-THEN-FALSE, WHICH IS WHAT THE VERB'S DEFENCE ACTUALLY CLAIMS (B2). The
          -- FALSE half is below; this is the half that was missing. Without it "no staged
          -- table remaining" is satisfied by a counter that never had one — and since a
          -- promote job is only ever raised for a counter whose effective table changed, the
          -- freshness test alone left a real gap: a counter that lost the staged file some
          -- other way (a hand-edit, a reimage, an agent that never wrote it) would confirm a
          -- promotion that never happened, and 'confirmed' is the word this ladder exists to
          -- make mean something.
          AND j.print_tab_staged_at IS NOT NULL
          AND (ds.raw -> 'peripherals' ->> 'print_tab_pending') = 'false'
          AND (ds.raw -> 'rdp' ->> 'running') = 'true'`
    );
    confirmed += printersPromoted.rowCount || 0;

    // Proxmox reports the flag as the job asked for it, in an inventory push taken AFTER
    // the job was applied. This is the converging verb's reading, and it is what makes
    // onboot safe to reconcile unattended: the loop can see for itself that it worked.
    const onboot = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = 'proxmox reports onboot=' || (CASE WHEN v.onboot THEN '1' ELSE '0' END)
                               || ' in the inventory push at '
                               || to_char(v.seen_at, 'YYYY-MM-DD HH24:MI:SS')
         FROM proxmox_vms v
        WHERE v.vmid = j.vmid
          AND j.status = 'applied'
          AND j.confirm_kind = 'vm-onboot-matches'
          AND j.applied_at IS NOT NULL
          AND v.seen_at > j.applied_at
          AND v.onboot IS NOT NULL
          AND v.onboot = ((j.args ->> 'onboot') = '1')`
    );
    confirmed += onboot.rowCount || 0;

    // Power reached the state that was asked for. Both directions in one statement, with
    // the wanted status derived from the confirm kind rather than from the verb, so an old
    // job whose verb was later re-specified still confirms against what it was created to
    // prove.
    const power = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = 'proxmox reports status=' || v.status
                               || ' in the inventory push at '
                               || to_char(v.seen_at, 'YYYY-MM-DD HH24:MI:SS')
         FROM proxmox_vms v
        WHERE v.vmid = j.vmid
          AND j.status = 'applied'
          AND j.confirm_kind IN ('vm-status-running', 'vm-status-stopped')
          AND j.applied_at IS NOT NULL
          AND v.seen_at > j.applied_at
          AND v.status = CASE WHEN j.confirm_kind = 'vm-status-running'
                              THEN 'running' ELSE 'stopped' END`
    );
    confirmed += power.rowCount || 0;

    // The VM really restarted. Same uptime argument as the Pi: 'running' on its own is also
    // true of a VM that ignored the reboot entirely. The slack is wider (120s) because this
    // reading arrives on a 15-minute timer and seen_at is when the collector looked, not
    // when the guest came up.
    const vmBoot = await q(
      `UPDATE pmr_jobs j
          SET status = 'confirmed', confirmed_at = now(), finished_at = now(),
              confirm_detail = 'proxmox reports the VM running with an uptime of '
                               || v.uptime_s || 's, shorter than the age of this job'
         FROM proxmox_vms v
        WHERE v.vmid = j.vmid
          AND j.status = 'applied'
          AND j.confirm_kind = 'vm-uptime-reset'
          AND j.applied_at IS NOT NULL
          AND v.seen_at > j.applied_at
          AND v.status = 'running'
          AND v.uptime_s IS NOT NULL
          AND v.uptime_s < EXTRACT(epoch FROM (v.seen_at - j.applied_at)) + 120`
    );
    confirmed += vmBoot.rowCount || 0;

    // Write the confirmed reading back onto the intent it satisfied, so the UI's "wanted /
    // observed" pair moves on the SAME reading that closed the job rather than waiting for
    // the next reconcile pass.
    await q(
      `UPDATE pmr_intent i
          SET observed = i.want, observed_at = j.confirmed_at, last_job_id = j.id
         FROM pmr_jobs j
        WHERE j.intent_id = i.id AND j.status = 'confirmed'
          AND j.confirmed_at > now() - interval '5 minutes'
          AND i.observed IS DISTINCT FROM i.want`
    );
    return { confirmed };
  }

  // The other half of "done means proven": a job that was never proven must END, and it
  // must end as a FAILURE rather than drifting in 'applied' forever the way a config_job
  // stuck in 'fetched' does.
  async function expirePmrJobs() {
    const gone = await q(
      `UPDATE pmr_jobs
          SET status = 'expired', finished_at = now(),
              result_log = COALESCE(result_log || E'\\n', '')
                || 'expired: the time limit passed before an executor collected it'
        WHERE status IN ('pending', 'claimed') AND expires_at <= now()`
    );
    const unproven = await q(
      `UPDATE pmr_jobs
          SET status = 'failed', finished_at = now(),
              result_log = COALESCE(result_log || E'\\n', '')
                || 'failed: the executor reported it ran, but no independent reading '
                || 'confirmed it within ' || confirm_deadline_s || 's'
        WHERE status = 'applied'
          AND applied_at IS NOT NULL
          AND applied_at < now() - make_interval(secs => confirm_deadline_s)`
    );
    // A job that has used every attempt is finished whether or not its clock has run out.
    // Left pending it would sit on the screen looking claimable until expires_at, and — the
    // part that matters — it would NOT appear as a failure to the pre-opening check, which
    // is the one thing that gets a person to the site before it opens.
    const spent = await q(
      `UPDATE pmr_jobs
          SET status = 'failed', finished_at = now(),
              result_log = COALESCE(result_log || E'\\n', '')
                || 'failed: handed to an executor ' || attempts
                || ' times without a result, which is the cap for this verb'
        WHERE status IN ('pending', 'claimed')
          AND attempts >= max_attempts
          AND (status = 'pending'
               OR claimed_at < now() - make_interval(secs => claim_ttl_s))`
    );
    return {
      expired: gone.rowCount || 0,
      unproven: unproven.rowCount || 0,
      spent: spent.rowCount || 0,
    };
  }

  // ── the reconciler ────────────────────────────────────────────────────────
  // Refresh what has been OBSERVED about every intent from whatever collector already
  // reports the fact, then close the gaps that are allowed to close on their own.
  //
  // THE CONVERGENCE RULE, implemented: only vm.onboot converges here. It is a CONFIGURATION
  // property (it changes what the next node boot does and touches nothing running), it is
  // fully reversible, it interrupts no session, and proxmox_vms.onboot is a fresh
  // independent reading of it. A LIFECYCLE field — vm.running — is deliberately NOT
  // reconciled: power is a one-shot job with a time limit that an operator raised, and a
  // loop that powered VMs to match a stored wish would fight the engineer who just stopped
  // one. counter.boot_vmid is not reconciled either, for a different reason: the telemetry
  // reply already re-sends it on EVERY tick and is self-healing, so a second mechanism
  // pushing the same field is how a counter starts flapping.
  //
  // `verbSpec` carries the verb's timings from the one allowlist in pmrVerbs.js, so this
  // function invents none of them.
  async function reconcilePmrIntent(verbSpec = {}) {
    const observedVm = await q(
      `UPDATE pmr_intent i
          SET observed = to_jsonb(CASE WHEN v.onboot THEN 1 ELSE 0 END), observed_at = v.seen_at
         FROM proxmox_vms v
        WHERE i.field = 'vm.onboot' AND i.vmid = v.vmid AND v.onboot IS NOT NULL
          AND i.observed IS DISTINCT FROM to_jsonb(CASE WHEN v.onboot THEN 1 ELSE 0 END)`
    );
    const observedRun = await q(
      `UPDATE pmr_intent i
          SET observed = to_jsonb(CASE WHEN v.status = 'running' THEN 1 ELSE 0 END),
              observed_at = v.seen_at
         FROM proxmox_vms v
        WHERE i.field = 'vm.running' AND i.vmid = v.vmid AND v.status IS NOT NULL
          AND i.observed IS DISTINCT FROM to_jsonb(CASE WHEN v.status = 'running' THEN 1 ELSE 0 END)`
    );
    // The boot target's observation comes from the stamp the telemetry path already
    // computes out of device_state.raw — not from a second read of the payload.
    const observedBoot = await q(
      `UPDATE pmr_intent i
          SET observed = to_jsonb(c.boot_vmid), observed_at = c.boot_applied_at
         FROM counters c
        WHERE i.field = 'counter.boot_vmid' AND i.counter_id = c.id
          AND c.boot_applied_at IS NOT NULL
          AND i.observed IS DISTINCT FROM to_jsonb(c.boot_vmid)`
    );

    const created = await rows(
      `WITH gap AS (
         SELECT i.id AS intent_id, i.pharmacy_id, i.vmid,
                (i.want #>> '{}')::int AS want_onboot, v.node
           FROM pmr_intent i
           JOIN proxmox_vms v ON v.vmid = i.vmid AND v.node IS NOT NULL
          WHERE i.field = 'vm.onboot'
            AND i.observed IS DISTINCT FROM i.want
            -- One job per gap. Without this the reconciler would raise another every pass
            -- for the whole 40 minutes it takes two collector ticks to prove the first.
            AND NOT EXISTS (SELECT 1 FROM pmr_jobs j
                             WHERE j.intent_id = i.id
                               AND j.status IN ('pending', 'claimed', 'applied'))
       )
       INSERT INTO pmr_jobs
         (verb, executor, node, pharmacy_id, vmid, args, disruptive, retry_ok,
          confirm_kind, confirm_deadline_s, expires_at, claim_ttl_s, intent_id, created_by)
       SELECT 'vm.set-onboot', 'proxmox-node', g.node, g.pharmacy_id, g.vmid,
              jsonb_build_object('vmid', g.vmid, 'onboot', g.want_onboot),
              false, true, 'vm-onboot-matches', $1,
              now() + make_interval(secs => $2), $3, g.intent_id, 'reconciler'
         FROM gap g
       RETURNING id, intent_id`,
      [verbSpec.confirm_deadline_s || 2400, verbSpec.ttl_s || 86400, verbSpec.claim_ttl_s || 1800]
    );
    if (created.length) {
      await q(
        `UPDATE pmr_intent i SET last_job_id = j.id
           FROM pmr_jobs j WHERE j.id = ANY($1::uuid[]) AND j.intent_id = i.id`,
        [created.map((r) => r.id)]
      );
    }
    return {
      observed: (observedVm.rowCount || 0) + (observedRun.rowCount || 0) + (observedBoot.rowCount || 0),
      created: created.length,
    };
  }

  // ── operator actions on a job ─────────────────────────────────────────────
  async function listPmrJobs(f = {}) {
    return rows(
      `SELECT id, verb, executor, status, state, waiting_reason, disruptive, override_hours,
              override_by, override_at, pharmacy_id, site_code, site_name, counter_id, vmid,
              node, args, confirm_kind, confirm_detail, attempts, not_before, expires_at,
              created_by, created_at, claimed_at, applied_at, confirmed_at, finished_at,
              result_log
         FROM pmr_jobs_v
        WHERE ($1::bigint IS NULL OR pharmacy_id = $1)
          AND ($2::text IS NULL OR status = $2)
        ORDER BY created_at DESC
        LIMIT 200`,
      [f.pharmacy_id == null ? null : f.pharmacy_id, nz(f.status)]
    );
  }

  async function getPmrJob(id) {
    if (!isUuid(id)) return null;
    return one(`SELECT * FROM pmr_jobs_v WHERE id = $1`, [id]);
  }

  // Is there already a job of this verb in flight for this counter?
  //
  // Written for the printer path, where the SAME staged table can be saved four times in a
  // minute while an operator sets up a printer. Each save would otherwise queue another
  // sign-out for the same counter for the same night — and pmr_jobs has no uniqueness of its
  // own, deliberately, because two DIFFERENT restarts of one counter are legitimate.
  //
  // 'pending' and 'claimed' only: an 'applied' job is waiting on its confirming reading and a
  // finished one is history, and neither is a reason to refuse a NEW change made afterwards.
  async function getPendingPmrCounterJob(counterId, verb) {
    if (!Number.isInteger(Number(counterId)) || typeof verb !== 'string') return null;
    return one(
      `SELECT * FROM pmr_jobs_v
        WHERE counter_id = $1 AND verb = $2 AND status IN ('pending','claimed')
        ORDER BY created_at DESC LIMIT 1`,
      [Number(counterId), verb]
    );
  }

  // WHERE-guarded exactly as cancelConfigJob is: a job already claimed by an executor, or
  // already finished, returns null and the caller reports that it was too late — rather
  // than a silent no-op that reads as success.
  async function cancelPmrJob(id, by) {
    if (!isUuid(id)) return null;
    return one(
      `UPDATE pmr_jobs
          SET status = 'cancelled', finished_at = now(),
              result_log = COALESCE(result_log || E'\\n', '')
                           || 'cancelled by ' || COALESCE($2, 'watchman')
        WHERE id = $1 AND status IN ('pending', 'claimed')
        RETURNING id, verb, status`,
      [id, nz(by)]
    );
  }

  // "Apply it now — I know it signs the member of staff out." The ONLY way past the hours
  // gate, and it is a stored decision with a name and a time on it, because the rule this
  // suspends is that Watchman never restarts a session during opening hours ON ITS OWN.
  // Nothing here bypasses the time limit or the confirming reading.
  async function overridePmrJobHours(id, by) {
    if (!isUuid(id)) return null;
    return one(
      `UPDATE pmr_jobs
          SET override_hours = true, override_by = $2, override_at = now(),
              not_before = NULL,
              -- The job was created with an expiry computed from the overnight window it
              -- was waiting for (S1/S12). Releasing it now without touching that would be
              -- fine in the ordinary case and useless in the one that matters — an override
              -- typed minutes before the held window would expire. GREATEST only ever
              -- lengthens, so a job with hours left keeps them.
              expires_at = GREATEST(expires_at, now() + interval '15 minutes')
        WHERE id = $1 AND status = 'pending' AND disruptive
          -- Offered once, and only once. attempts is 0 for a job no executor has taken, and
          -- an override on a job that has already been handed out is the loop B3 describes.
          AND attempts = 0
        RETURNING id, verb, status, counter_id, pharmacy_id, expires_at`,
      [id, nz(by) || 'watchman']
    );
  }

  // ── the nightly restart ───────────────────────────────────────────────────
  // Claim tonight for every LIVE site whose own local clock has just passed midnight and
  // that has not already had its night run.
  //
  // The primary key on (pharmacy_id, local_date) IS the mechanism: INSERT … ON CONFLICT DO
  // NOTHING … RETURNING gives back exactly the sites this call won, so a 3-worker cluster
  // runs a night once and a worker restarted at 00:40 does not run it a second time. No
  // cron and no "when did I last run" state anywhere — the same reasoning pruneRelay uses
  // for doing its housekeeping opportunistically instead of on a timer.
  //
  // ⚠️ THE TWO GUARDS ARE DECOUPLED (S14). They used to be AND-ed: claim the night only if
  // the local clock is inside the window AND the site is closed. A 24-hour pharmacy is open
  // for the whole window, so it never satisfied both — it therefore NEVER got a nightly row,
  // which meant it never got a restart, never got a pre-opening check, and never raised an
  // alert. Silently, forever, while the comment claimed the opposite.
  //
  // Now the night is CLAIMED for every live site once per its own local date, and whether a
  // restart is possible is a SEPARATE question answered per site by siteDisruptiveWindow():
  //   * closed and inside its overnight window  -> jobs are created and run now
  //   * open until 01:00                        -> jobs are created HELD until 01:00, which
  //                                                is what not_before now means (S1/S12)
  //   * never closes                            -> NO jobs, and the row records why
  // In all three the site still has a nightly row, and the pre-opening check no longer
  // depends on one at all (S3).
  //
  // The window guard stays, and it still does its own job: it bounds how late a MISSED night
  // may be picked up, so a worker that was down until 08:00 does not schedule the estate's
  // restarts as the pharmacies open.
  async function claimPmrNightlySites(windowHours) {
    const hours = Number.isInteger(windowHours) && windowHours >= 1 && windowHours <= 6
      ? windowHours : 1;
    return rows(
      `WITH due AS (
         SELECT p.id,
                (now() AT TIME ZONE site_tz(p.timezone))::date AS local_date
           FROM pharmacies p
          WHERE p.status = 'live'
            AND (now() AT TIME ZONE site_tz(p.timezone))::time < make_time($1, 0, 0)
       ), claimed AS (
         INSERT INTO pmr_nightly_runs (pharmacy_id, local_date)
         SELECT d.id, d.local_date FROM due d
         ON CONFLICT (pharmacy_id, local_date) DO NOTHING
         RETURNING pharmacy_id, local_date
       )
       SELECT c.pharmacy_id, c.local_date, p.code AS site_code, p.name AS site_name,
              site_tz(p.timezone) AS site_timezone,
              -- Answered here so the worker makes ONE decision per site from ONE reading,
              -- rather than asking the database again per counter.
              pmr_disruptive_allowed(p.id, now())      AS restart_allowed_now,
              site_next_disruptive_window(p.id, now()) AS next_window_at
         FROM claimed c JOIN pharmacies p ON p.id = c.pharmacy_id
        ORDER BY p.code`,
      [hours]
    );
  }

  // The counters a night applies to: LIVE counters with a thin client enrolled. A counter
  // with no Pi is not a failure to report, it is a counter that has not been built yet.
  async function listSiteLiveCounters(pharmacyId) {
    return rows(
      `SELECT c.id, c.n, c.label, c.pi_device_id, d.serial AS pi_serial,
              ds.status AS pi_status, ds.last_seen_at, ds.uptime_s,
              (ds.raw -> 'rdp' ->> 'running') AS rdp_running,
              (ds.raw -> 'rdp' ->> 'configured_target') AS rdp_configured_target
         FROM counters c
         LEFT JOIN devices d ON d.id = c.pi_device_id
         LEFT JOIN device_state ds ON ds.device_id = c.pi_device_id
        WHERE c.pharmacy_id = $1 AND c.status = 'live'
        ORDER BY c.n`,
      [pharmacyId]
    );
  }

  async function recordPmrNightlyRun(pharmacyId, localDate, f = {}) {
    return one(
      `UPDATE pmr_nightly_runs
          SET counters_total = $3, jobs_created = $4, intents_promoted = $5,
              skipped_reason = $6
        WHERE pharmacy_id = $1 AND local_date = $2::date
        RETURNING pharmacy_id, local_date, counters_total, jobs_created, skipped_reason`,
      [pharmacyId, localDate, f.counters_total || 0, f.jobs_created || 0,
        f.intents_promoted || 0, nz(f.skipped_reason)]
    );
  }

  // ── the pre-opening check ─────────────────────────────────────────────────
  // Claim the verification for every LIVE site that is about to open and has not been
  // checked for its own local date yet.
  //
  // ⚠️ IT IS DRIVEN OFF THE SITE, NOT OFF THE RESTART (S3). This used to select FROM
  // pmr_nightly_runs, so it could only run for a site that HAD a nightly row — and a worker
  // down from 23:50 to 01:30 creates none. On exactly the morning when nothing was applied,
  // nothing was verified and nobody was told. The check now reads each site's own
  // next_open_at and claims into its OWN table, so it happens whether or not the restart did.
  //
  // ⚠️ THE CLAIM IS A LEASE, NOT A STAMP (S4). checked_at used to be written at CLAIM time,
  // before a verdict existed, so any failure between claiming and deciding permanently
  // destroyed that site's only alert for the night. Now the claim takes a lease a later pass
  // reclaims once it lapses, and checked_at is written by finishPmrOpeningCheck only after
  // the verdict and any email have actually landed. The failure direction is a duplicate
  // email, which is the right way round for the one message that gets somebody to a
  // pharmacy before it opens.
  //
  // The lead time is the whole point: this has to run EARLY ENOUGH TO FIX IT, not at the
  // moment the shutters go up. Everything else waits for the morning queue.
  //
  // ⚠️ AND A SITE THAT NEVER CLOSES IS STILL CHECKED (D6). The guard used to be
  // `is_open IS NOT TRUE AND next_open_at IS NOT NULL`, which a 24-hour pharmacy satisfies on
  // neither count: it is always open and it never next-opens. So it was never claimed and
  // never checked — the second half of the harm S14 named, still open after S14 fixed the
  // first half. A 24-hour site is precisely the one where nobody arrives in the morning to
  // notice a dead counter, because there is no morning.
  //
  // THE CHECK TIME CHOSEN FOR IT IS 06:00 LOCAL — pmr_night_end_s(), reused rather than
  // invented. That constant is already this schema's definition of the moment the quiet
  // hours end and the day's work starts, so a 24-hour site is verified at the instant the
  // estate already treats as the start of trading, and there is one definition of "morning"
  // in the platform instead of two. The lead window works the same way it does for everyone
  // else: the check runs in the `lead` minutes BEFORE that instant, early enough to fix it.
  const PMR_CHECK_LEASE_MIN = 10;
  async function claimPmrOpeningChecks(leadMinutes) {
    const lead = Number.isInteger(leadMinutes) && leadMinutes >= 5 && leadMinutes <= 240
      ? leadMinutes : 60;
    return rows(
      `WITH due AS (
         SELECT p.id AS pharmacy_id,
                (now() AT TIME ZONE site_tz(p.timezone))::date AS local_date,
                s.next_open_at
           FROM pharmacies p
           CROSS JOIN LATERAL site_hours_state(p.id, now()) s
          WHERE p.status = 'live'
            -- IS NOT TRUE, not = false: a site whose hours do not resolve must still be
            -- checked. "We do not know when it opens" is not a reason to stop looking at
            -- whether its counters came back.
            AND s.is_open IS NOT TRUE
            AND s.next_open_at IS NOT NULL
            AND s.next_open_at <= now() + make_interval(mins => $1)
         UNION ALL
         -- THE SITE THAT NEVER CLOSES. Identified by exactly the test
         -- site_next_disruptive_window() short-circuits on — open now, and no close anywhere
         -- in the fifteen days site_hours_state() looks ahead — so the two functions cannot
         -- disagree about which sites these are.
         --
         -- next_open_at is reported as today's local 06:00 because that is what this row
         -- MEANS to everything downstream: it is the instant the check is verifying the
         -- counters for, and it is what the alert email prints as the opening time. Sending
         -- the real answer (NULL — it never opens, it is already open) would print "unknown"
         -- on the one email whose job is to get somebody to a pharmacy in time.
         SELECT p.id,
                (now() AT TIME ZONE site_tz(p.timezone))::date,
                ((now() AT TIME ZONE site_tz(p.timezone))::date
                   + make_interval(secs => pmr_night_end_s())) AT TIME ZONE site_tz(p.timezone)
           FROM pharmacies p
           CROSS JOIN LATERAL site_hours_state(p.id, now()) s
          WHERE p.status = 'live'
            AND s.is_open IS TRUE
            AND s.next_close_at IS NULL
            -- The lead window before 06:00 local, expressed as a time-of-day band rather
            -- than as "<= now() + lead". For a site with no next_open_at there is no future
            -- instant to count back from, and comparing against today's 06:00 unbounded
            -- would make the row due for the whole rest of the day. GREATEST keeps the band
            -- inside the day even if the lead is configured longer than six hours.
            AND EXTRACT(epoch FROM (now() AT TIME ZONE site_tz(p.timezone))::time)::int
                  BETWEEN GREATEST(pmr_night_end_s() - $1::int * 60, 0) AND pmr_night_end_s()
       ), claimed AS (
         INSERT INTO pmr_opening_checks
           (pharmacy_id, local_date, next_open_at, claimed_at, lease_until, attempts)
         SELECT d.pharmacy_id, d.local_date, d.next_open_at, now(),
                now() + make_interval(mins => $2), 1
           FROM due d
         -- DO UPDATE with a WHERE, which is what makes the lease reclaimable: a row that is
         -- already finished (checked_at set) or still held by another worker (lease in the
         -- future) matches nothing and returns nothing.
         ON CONFLICT (pharmacy_id, local_date) DO UPDATE
            SET claimed_at   = now(),
                lease_until  = now() + make_interval(mins => $2),
                attempts     = pmr_opening_checks.attempts + 1,
                next_open_at = EXCLUDED.next_open_at
          WHERE pmr_opening_checks.checked_at IS NULL
            AND pmr_opening_checks.lease_until <= now()
         RETURNING pharmacy_id, local_date, next_open_at
       )
       SELECT c.pharmacy_id, c.local_date, c.next_open_at,
              p.code AS site_code, p.name AS site_name
         FROM claimed c JOIN pharmacies p ON p.id = c.pharmacy_id
        ORDER BY p.code`,
      [lead, PMR_CHECK_LEASE_MIN]
    );
  }

  // Record the verdict, and CLAIM THE ALERT in the same statement — alerted_at IS NULL is
  // what makes it one email per site per morning rather than one per worker pass.
  //
  // Deliberately does NOT set checked_at. The verdict existing is not the same as the person
  // having been told, and the whole point of S4 is that the two are separate moments.
  async function recordPmrOpeningCheck(pharmacyId, localDate, f = {}) {
    return one(
      `UPDATE pmr_opening_checks
          SET counters_ok = $3, counters_at_risk = $4,
              alerted_at = CASE WHEN $4 > 0 AND alerted_at IS NULL THEN now() ELSE alerted_at END,
              alert_detail = CASE WHEN $4 > 0 THEN $5 ELSE alert_detail END
        WHERE pharmacy_id = $1 AND local_date = $2::date AND checked_at IS NULL
        RETURNING pharmacy_id, local_date, counters_ok, counters_at_risk, alerted_at`,
      [pharmacyId, localDate, f.counters_ok || 0, f.counters_at_risk || 0, nz(f.alert_detail)]
    );
  }

  // THE ONLY WRITER OF checked_at, and it runs after the alert has landed.
  //
  // `done` false means the verdict was reached but the person was NOT told — an email send
  // that failed. Then checked_at stays null AND the alert claim is released, so the lease
  // lapses and a later pass re-runs the whole check. A site whose alert failed to send must
  // not be recorded as checked; that is precisely the state where nobody knows.
  async function finishPmrOpeningCheck(pharmacyId, localDate, f = {}) {
    return one(
      `UPDATE pmr_opening_checks
          SET checked_at = CASE WHEN $3::boolean THEN now() ELSE checked_at END,
              alerted_at = CASE WHEN $3::boolean THEN alerted_at ELSE NULL END
        WHERE pharmacy_id = $1 AND local_date = $2::date
        RETURNING pharmacy_id, local_date, checked_at, alerted_at, counters_at_risk`,
      [pharmacyId, localDate, !!f.done]
    );
  }

  // Jobs from tonight that did not reach 'confirmed' at this site — the second input to the
  // opening check, next to what the counters themselves are reporting. A restart that
  // failed or expired is exactly the case where a counter may not come back.
  // ⚠️ THE NIGHT'S OWN JOBS (S13). This used to be an 18-hour sweep of EVERYTHING at the
  // site, so any unrelated job an engineer raised yesterday afternoon — including one the
  // hours gate correctly held and then expired — counted as "tonight's restart failed", and
  // the pre-opening email said "counters may not open" about a healthy counter. That breaks
  // the one rule this channel has: it is sent ONLY when a counter will not open.
  //
  // Scoped two ways, both needed. created_by = 'nightly' is what the nightly pass stamps and
  // nothing else does, so an operator's job can never be read as the night's. The local-date
  // bound then keeps it to THIS night rather than every night since.
  async function listPmrUnfinishedNightJobs(pharmacyId, localDate) {
    return rows(
      `SELECT j.id, j.verb, j.status, j.counter_id, j.result_log, j.created_at, j.finished_at
         FROM pmr_jobs j
         JOIN pharmacies p ON p.id = j.pharmacy_id
        WHERE j.pharmacy_id = $1
          AND j.created_by = 'nightly'
          AND j.created_at >= (($2::date)::timestamp AT TIME ZONE site_tz(p.timezone))
          AND j.created_at <  ((($2::date) + 1)::timestamp AT TIME ZONE site_tz(p.timezone))
          AND j.status <> 'confirmed'
        ORDER BY j.created_at`,
      [pharmacyId, localDate]
    );
  }

  async function end() {
    await pool.end();
  }

  return {
    reportProxmoxVms,
    reportProxmoxCapacity,
    reportProxmoxVmPrinters,
    listDesktopPrinters,
    reconcileProxmox,
    listProxmoxVms,
    listPrinters,
    upsertPrinter,
    deletePrinter,
    reportPrinters,
    // ── the printer model (docs/pmr-printer-contract.md §1) ──
    reportCounterPrinters,
    listPrinterDevices,
    listPrinterQueues,
    upsertPrinterQueue,
    deletePrinterQueue,
    setPrinterAssignment,
    listPrinterAssignments,
    getCounterPrinterTableForDevice,
    getCounterPrintTabState,
    // ── the site build lifecycle ──
    getSiteCapture,
    setSiteCapture,
    setSiteCaptureRollUp,
    getSiteImport,
    setSiteImport,
    // ── the capture kit's credentials (src/shared/captureToken.js) ──
    createCaptureTicket,
    listCaptureTickets,
    revokeCaptureTicket,
    redeemCaptureTicket,
    getCaptureTokenByHash,
    touchCaptureToken,
    listCaptureSitesForToken,
    listCaptureSlots,
    listCaptureRuns,
    upsertCaptureRun,
    getCaptureRunForRole,
    reportCaptureDropTargets,
    getCaptureDropTarget,
    listCaptureDropTargets,
    // ── node headroom ──
    listNodeCapacity,
    reportNodeCapacity,
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
    listLanPrinters,
    getPrinter,
    setCounterActionForDevice,
    listUnclaimedPis,
    adoptPi,
    listPharmacyVms,
    attachPharmacyVm,
    detachPharmacyVm,
    setCounterBootTarget,
    clearCounterBootTarget,
    stageCounterBootTarget,
    cancelCounterBootTargetStage,
    promoteCounterBootTargets,
    setCounterAction,
    takeCounterAction,
    getCounterBootDirective,
    setCounterSettings,
    getDeviceSupportVnc,
    recordSupportSession,
    getCounterSettingsForDevice,
    listSiteHosts,
    siteExists,
    findRelayTarget,
    createRelaySession,
    getRelaySession,
    getRelayDirective,
    closeRelaySession,
    touchRelaySession,
    pruneRelay,
    enqueueRelayRequest,
    claimRelayRequest,
    replyRelayRequest,
    takeRelayReply,
    reportWgPeers,
    listWgPeers,
    listTags,
    setDeviceTags,
    setDeviceIdentity,
    setDevicePppoePassword,
    updateDeviceMeta,
    deleteDevice,
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
    upsertDeviceScreen,
    getDeviceScreen,
    pruneDeviceScreens,
    getBranding,
    getSiteBanner,
    getBrandingSplash,
    updateBrandingText,
    setBrandingSplash,
    clearBrandingSplash,
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

    // ── the PMR control plane ─────────────────────────────────────────────
    // Every caller reaches these through the `typeof store.X === 'function'` guard the
    // directive channel already uses, so a store that predates them (store.mem.js) still
    // loads and simply carries no control plane.
    getSiteHours,
    siteDisruptiveWindow,
    listSiteClosedDays,
    finishPmrOpeningCheck,
    listSiteHours,
    listSiteHoursExceptions,
    setSiteHours,
    setSiteHoursException,
    deleteSiteHoursException,
    getEstateHours,
    setPmrIntent,
    listPmrIntent,
    deletePmrIntent,
    createPmrCounterJob,
    createPmrVmJob,
    claimPmrJobForDevice,
    claimPmrJobsForNode,
    recordPmrJobResult,
    notePmrSessionDown,
    confirmPmrJobs,
    expirePmrJobs,
    reconcilePmrIntent,
    listPmrJobs,
    getPmrJob,
    getPendingPmrCounterJob,
    cancelPmrJob,
    overridePmrJobHours,
    claimPmrNightlySites,
    listSiteLiveCounters,
    recordPmrNightlyRun,
    claimPmrOpeningChecks,
    recordPmrOpeningCheck,
    listPmrUnfinishedNightJobs,
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
    // Counter-Pi smartcard fix stack: 1 = intact, 0 = broken, null = not applicable.
    // Write rules as `smartcard_stack_ok < 1` (comparator '<', threshold 1) — nulls are
    // ignored by evaluateAlert(), so counters without smartcards never fire.
    'smartcard_stack_ok',
  ]);
  return allowed.has(metric) ? metric : null;
}

module.exports = { makePgStore };
