'use strict';

// Vigilant — Store interface + factory.
//
// The Store is the single seam between the ingest/worker/CLIs and the datastore.
// There are two implementations behind the SAME method names:
//   * store.pg.js  — Postgres (production; self-hosted Supabase on the IaaS)
//   * store.mem.js — in-memory (tests, local dev, simulator E2E)
//
// `makeStore(kind, config)` returns the right one. Both implementations are required
// LAZILY so that 'mem' works with no `pg` driver / no database reachable, and so that
// loading this module never opens a connection as a side effect.
//
// Every method is async (returns a Promise) and returns plain objects/arrays/null —
// never driver-specific row objects — so the two implementations are interchangeable.

/**
 * A device registry row (the subset the ingest/worker care about).
 * @typedef {Object} Device
 * @property {string}   id               uuid
 * @property {string}   serial           routerboard serial (natural key)
 * @property {string=}  identity
 * @property {string=}  site_name
 * @property {string=}  customer
 * @property {string=}  model
 * @property {string=}  ros_version
 * @property {string=}  wan_type         'pppoe'|'sim'|'dhcp'|'static'|'unknown'
 * @property {string[]} tags
 * @property {boolean=} expected
 * @property {number}   poll_interval_s
 * @property {?string}  poll_until       ISO timestamp | null (temporary fast-poll window)
 * @property {?string}  agent_version
 */

/**
 * One interface_state row, as needed for delta math on the next tick.
 * @typedef {Object} InterfaceSample
 * @property {string}  name
 * @property {?number} rx_byte
 * @property {?number} tx_byte
 * @property {?number} rx_packet
 * @property {?number} tx_packet
 * @property {string}  sampled_at       ISO timestamp the row was last written
 */

/**
 * Descriptor for a pending, APPROVED config job served to a device.
 * @typedef {Object} PendingConfigJob
 * @property {string} id                 uuid
 * @property {string} rsc_sha256
 * @property {number} confirm_window_s
 */

/**
 * The Vigilant store interface. Both `makePgStore` and `makeMemStore` implement every
 * method here, verbatim by name and signature, so they are drop-in interchangeable.
 *
 * @typedef {Object} Store
 *
 * @property {() => Promise<void>} migrate
 *   pg: apply db/schema.sql idempotently (split on ';' safely). mem: no-op.
 *
 * @property {(tokenHash: string) => Promise<?Device>} getDeviceByToken
 *   Look up a device by the sha256 of its bearer token. null if no live token matches.
 *   Returns at least {id,serial,poll_interval_s,poll_until,agent_version}.
 *
 * @property {(serial: string) => Promise<?Device>} getDeviceBySerial
 *
 * @property {(fields: Object) => Promise<Device>} createDevice
 *   fields: {serial, site_name, customer, wan_type, tags, ...}. Returns the new device.
 *
 * @property {(deviceId: string, tokenHash: string) => Promise<void>} setDeviceToken
 *   Issue/replace the device's enrolment token (stores the hash, never the token).
 *
 * @property {(deviceId: string) => Promise<InterfaceSample[]>} getInterfaceStates
 *   Latest per-port counters + sampled_at, for computing bps deltas on the next tick.
 *
 * @property {(deviceId: string, state: Object) => Promise<void>} upsertDeviceState
 *   Full device_state row (already-derived values), keyed by device_id.
 *
 * @property {(deviceId: string, rows: Object[]) => Promise<void>} upsertInterfaceStates
 *   Each row already has rx_bps/tx_bps/role/is_wan computed by the handler.
 *
 * @property {(deviceId: string, row: Object) => Promise<void>} upsertLteState
 *
 * @property {(deviceId: string, rows: Object[]) => Promise<void>} upsertNeighbors
 *   Also stamps last_seen_at = now().
 *
 * @property {(deviceId: string, rows: Object[]) => Promise<void>} upsertMacHosts
 *   Only called when payload.mac_hosts !== null.
 *
 * @property {(deviceId: string, rows: Object[]) => Promise<void>} upsertWifiNetworks
 *   WiFi SSID/channel config. FULL-SNAPSHOT: replaces the device's WLAN set. Only called
 *   when payload.wifi !== null.
 * @property {(deviceId: string, rows: Object[]) => Promise<void>} upsertWirelessClients
 *   Associated WiFi stations (registration table). FULL-SNAPSHOT: replaces the device's
 *   client set. Only called when payload.wifi_clients !== null.
 *
 * @property {(deviceId: string, ts: string, row: Object) => Promise<void>} appendMetricsHistory
 * @property {(deviceId: string, ts: string, rows: Object[]) => Promise<void>} appendInterfaceHistory
 * @property {(deviceId: string, ts: string, row: Object) => Promise<void>} appendLteHistory
 *
 * @property {(deviceId: string, pollUntil: ?string, intervalS: number) => Promise<void>} setPollWindow
 *
 * @property {(deviceId: string) => Promise<?PendingConfigJob>} getPendingConfigJob
 *   status='approved' job matching this device or one of its tags; else null.
 *
 * @property {(jobId: string, deviceId: string) => Promise<?{rsc_text: string, rsc_sha256: string}>} getConfigJobForFetch
 *   Verifies the job targets this device before returning the rsc text.
 *
 * @property {(jobId: string, status: string, fields?: Object) => Promise<void>} markConfigJob
 *   Sets status + the timestamp/field appropriate to it
 *   (fetched_at/applied_at/result_log/rollback_ref).
 *
 * @property {(jobId: string, status: string, resultLog: string, exportText?: string) => Promise<void>} recordConfigResult
 *   Records the apply outcome and, when exportText is given, inserts a config_snapshots row.
 *
 * @property {(fields: Object) => Promise<Object>} createConfigJob
 *   Operator side: insert a DRAFT job (never served until approved). Computes rsc_sha256 from
 *   rsc_text when not supplied. Returns the new row.
 *
 * @property {(jobId: string, approvedBy: string) => Promise<?Object>} approveConfigJob
 *   Draft -> approved (guarded: no-op/null if not a draft). Returns the updated row.
 *
 * @property {(jobId: string) => Promise<?Object>} cancelConfigJob
 *   draft|approved -> cancelled (null if past pickup). Returns the updated row.
 *
 * @property {(deviceId: string, limit?: number) => Promise<Object[]>} listConfigJobs
 *   Jobs targeting this device (directly or via a tag), newest first, capped.
 *
 * @property {(jobId: string) => Promise<?Object>} getConfigJob
 *   Full config_jobs row by id, or null.
 *
 * @property {(actor: string, action: string, serial: ?string, details: ?string) => Promise<void>} appendAudit
 *   Append one audit_log row (actor + action + serial + details).
 *
 * @property {() => Promise<?{version: number, rsc_text: string}>} getCurrentAgentScript
 *   The agent_scripts row where is_current; null if none published yet.
 *
 * @property {() => Promise<Object[]>} getFleet
 *   v_fleet rows (read API for frontends).
 *
 * @property {(serial: string) => Promise<?Object>} getDeviceDetail
 *   {device, state, interfaces[], lte, neighbors[], mac_hosts[]} | null.
 *
 * @property {(staleSeconds: number, offlineSeconds: number) => Promise<{stale: number, offline: number}>} markStaleDevices
 *   Bumps device_state.status by last_seen_at age.
 *
 * @property {() => Promise<Object[]>} getActiveAlertRules
 *
 * @property {(rules: Object[]) => Promise<{opened: number, cleared: number}>} evaluateAndApplyAlerts
 *   Threshold decision itself lives in transform.evaluateAlert; this reads state and
 *   opens/clears alert rows.
 *
 * @property {(now: number|Date) => Promise<void>} downsampleHistory
 * @property {(now: number|Date) => Promise<void>} pruneHistory
 * @property {(now: number|Date, ttlSeconds: number) => Promise<void>} pruneNeighbors
 * @property {(now: number|Date, ttlSeconds: number) => Promise<void>} pruneMacHosts
 */

/**
 * Build the configured Store. Implementations are required lazily so 'mem' has no
 * dependency on `pg` or a reachable database.
 *
 * @param {('pg'|'mem')} kind
 * @param {Object} [config]  the typed config object (used by the pg store for databaseUrl)
 * @returns {Store}
 */
function makeStore(kind, config) {
  if (kind === 'mem') {
    const { makeMemStore } = require('./store.mem');
    return makeMemStore(config);
  }
  if (kind === 'pg') {
    const { makePgStore } = require('./store.pg');
    return makePgStore(config);
  }
  throw new Error(`makeStore: unknown store kind '${kind}' (expected 'pg' or 'mem')`);
}

module.exports = { makeStore };
