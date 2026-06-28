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

  // Run fn inside a single transaction on one dedicated client.
  async function tx(fn) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch (_) {
        /* ignore rollback failure; original error is what matters */
      }
      throw err;
    } finally {
      client.release();
    }
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
      `SELECT d.id, d.serial, d.poll_interval_s, d.poll_until, d.agent_version
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
          expected, poll_interval_s, poll_until, agent_version, notes)
       VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7,'unknown'),
               COALESCE($8,'{}'::text[]),
               COALESCE($9,true),
               COALESCE($10,10),
               $11,$12,$13)
       ON CONFLICT (serial) DO UPDATE SET
         identity   = COALESCE(EXCLUDED.identity,  devices.identity),
         site_name  = COALESCE(EXCLUDED.site_name, devices.site_name),
         customer   = COALESCE(EXCLUDED.customer,  devices.customer),
         model      = COALESCE(EXCLUDED.model,     devices.model),
         wan_type   = EXCLUDED.wan_type,
         tags       = EXCLUDED.tags,
         notes      = COALESCE(EXCLUDED.notes,     devices.notes)
       RETURNING id, serial, identity, site_name, customer, model, ros_version, wan_type,
                 tags, expected, poll_interval_s, poll_until, agent_version, enrolled_at, notes`,
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

  // Each row already has rx_bps/tx_bps/role/is_wan computed by the ingest.
  async function upsertInterfaceStates(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    await tx(async (client) => {
      for (const r of list) {
        await client.query(
          `INSERT INTO interface_state
             (device_id, name, type, comment, plugged, running, disabled, speed,
              full_duplex, last_link_up_at, last_link_down_at, link_downs, role, is_wan,
              bridge, poe_out_status, poe_out_power, mac, rx_bps, tx_bps, rx_byte, tx_byte,
              rx_packet, tx_packet, rx_error, tx_error, rx_drop, tx_drop, sampled_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,COALESCE($14,false),
                   $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,COALESCE($29, now()))
           ON CONFLICT (device_id, name) DO UPDATE SET
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
          [
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
          ]
        );
      }
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
    await tx(async (client) => {
      for (const r of list) {
        if (!r || !r.interface || !r.mac) continue;
        await client.query(
          `INSERT INTO neighbors
             (device_id, interface, mac, identity, address, platform, board, version, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
           ON CONFLICT (device_id, interface, mac) DO UPDATE SET
             identity     = EXCLUDED.identity,
             address      = EXCLUDED.address,
             platform     = EXCLUDED.platform,
             board        = COALESCE(EXCLUDED.board,   neighbors.board),
             version      = COALESCE(EXCLUDED.version, neighbors.version),
             last_seen_at = now()`,
          [
            deviceId,
            r.interface,
            r.mac,
            nz(r.identity),
            nz(r.address),
            nz(r.platform),
            nz(r.board),
            nz(r.version),
          ]
        );
      }
    });
  }

  // Only called when payload.mac_hosts !== null (slow tick).
  async function upsertMacHosts(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    if (!list.length) return;
    await tx(async (client) => {
      for (const r of list) {
        if (!r || !r.interface || !r.mac) continue;
        await client.query(
          `INSERT INTO mac_hosts (device_id, interface, mac, ip, hostname, comment, vendor, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7, now())
           ON CONFLICT (device_id, interface, mac) DO UPDATE SET
             ip           = EXCLUDED.ip,
             hostname     = COALESCE(EXCLUDED.hostname, mac_hosts.hostname),
             comment      = COALESCE(EXCLUDED.comment,  mac_hosts.comment),
             vendor       = COALESCE(EXCLUDED.vendor, mac_hosts.vendor),
             last_seen_at = now()`,
          [deviceId, r.interface, r.mac, nz(r.ip), nz(r.hostname), nz(r.comment), nz(r.vendor)]
        );
      }
    });
  }

  // WiFi config (SSIDs/channels) — FULL-SNAPSHOT replace: clear the device's WLANs then insert
  // the reported set, so a removed/renamed SSID disappears. Only called when payload.wifi !== null.
  async function upsertWifiNetworks(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    await tx(async (client) => {
      await client.query(`DELETE FROM wifi_networks WHERE device_id = $1`, [deviceId]);
      for (const r of list) {
        if (!r || !r.interface) continue;
        await client.query(
          `INSERT INTO wifi_networks
             (device_id, interface, driver, band, ssid, passphrase, security,
              channel, frequency_mhz, width_mhz, disabled, hidden, clients, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())`,
          [
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
          ]
        );
      }
    });
  }

  // Associated WiFi stations — FULL-SNAPSHOT replace of the registration table for the device.
  // Only called when payload.wifi_clients !== null.
  async function upsertWirelessClients(deviceId, rowsIn) {
    const list = Array.isArray(rowsIn) ? rowsIn : [];
    await tx(async (client) => {
      await client.query(`DELETE FROM wireless_clients WHERE device_id = $1`, [deviceId]);
      for (const r of list) {
        if (!r || !r.interface || !r.mac) continue;
        await client.query(
          `INSERT INTO wireless_clients
             (device_id, interface, mac, signal, tx_ccq, rx_rate, tx_rate, uptime_s, sampled_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())`,
          [deviceId, r.interface, r.mac, nz(r.signal), nz(r.tx_ccq), nz(r.rx_rate), nz(r.tx_rate), nz(r.uptime_s)]
        );
      }
    });
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
    await tx(async (client) => {
      for (const r of list) {
        if (!r || !r.name) continue;
        await client.query(
          `INSERT INTO interface_history (device_id, name, ts, rx_bps, tx_bps, rx_error, tx_error)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (device_id, name, ts) DO UPDATE SET
             rx_bps   = EXCLUDED.rx_bps,
             tx_bps   = EXCLUDED.tx_bps,
             rx_error = EXCLUDED.rx_error,
             tx_error = EXCLUDED.tx_error`,
          [deviceId, r.name, ts, nz(r.rx_bps), nz(r.tx_bps), nz(r.rx_error), nz(r.tx_error)]
        );
      }
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
      `SELECT id, name, metric, comparator, threshold, for_seconds, severity, scope_tag, enabled
         FROM alert_rules
        WHERE enabled = true`,
      []
    );
  }

  // Evaluate each enabled rule against current device_state and open/clear alerts.
  // The threshold decision itself is transform.evaluateAlert (pure, unit-tested); this
  // method only does the store reads/writes around it.
  async function evaluateAndApplyAlerts(rulesIn) {
    const rules = Array.isArray(rulesIn) ? rulesIn : await getActiveAlertRules();
    let opened = 0;
    let cleared = 0;

    for (const rule of rules) {
      if (rule.enabled === false) continue;

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
        `SELECT d.id AS device_id, ${selectVal} AS value, s.status AS status
           FROM devices d
           JOIN device_state s ON s.device_id = d.id
          WHERE ($1::text IS NULL OR $1 = ANY (d.tags))`,
        [rule.scope_tag || null]
      );

      for (const c of candidates) {
        const value = rule.metric === 'offline' ? c.status : c.value;
        const firing = transform.evaluateAlert(rule, value);

        const openRow = await one(
          `SELECT id FROM alerts
            WHERE device_id = $1 AND rule_id = $2 AND state = 'open'
            ORDER BY opened_at DESC LIMIT 1`,
          [c.device_id, rule.id]
        );

        if (firing && !openRow) {
          await q(
            `INSERT INTO alerts (device_id, rule_id, severity, state, detail, opened_at)
             VALUES ($1, $2, $3, 'open', $4, now())`,
            [
              c.device_id,
              rule.id,
              rule.severity || 'warning',
              `${rule.name}: ${rule.metric} ${rule.comparator} ${rule.threshold == null ? '' : rule.threshold} (value=${value == null ? 'null' : value})`,
            ]
          );
          opened += 1;
        } else if (!firing && openRow) {
          const r = await q(
            `UPDATE alerts
                SET state = 'cleared', cleared_at = now()
              WHERE device_id = $1 AND rule_id = $2 AND state = 'open'`,
            [c.device_id, rule.id]
          );
          cleared += r.rowCount || 0;
        }
      }
    }

    return { opened, cleared };
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

  // Expose the pool so callers (bin/migrate, graceful shutdown) can end() it.
  async function end() {
    await pool.end();
  }

  return {
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
