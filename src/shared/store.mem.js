'use strict';

// Vigilant — in-memory Store.
//
// Backs the unit/e2e tests, local dev, and the simulator E2E. It implements EVERY method
// of the Store interface (see store.js) with the SAME names/signatures as store.pg.js, so
// the ingest server and worker run unmodified against it.
//
// It must be correct enough that:
//   * the SECOND telemetry POST can compute a real positive bps from the first — so we
//     persist the full interface rows (incl. raw counters + sampled_at) and hand them back
//     from getInterfaceStates() for the handler's delta math;
//   * config jobs and their status transitions are tracked end-to-end
//     (draft→approved→fetched→applying→applied/failed/rolled_back);
//   * device lookups by token-hash and by serial work, plus createDevice/setDeviceToken.
//
// No external dependencies — uses node:crypto only for uuids.

const { randomUUID } = require('crypto');

/** Coerce a "now" arg (Date | epoch ms | undefined) to epoch ms. */
function nowMs(now) {
  if (now == null) return Date.now();
  if (now instanceof Date) return now.getTime();
  if (typeof now === 'number') return now;
  const t = new Date(now).getTime();
  return Number.isNaN(t) ? Date.now() : t;
}

/** ISO string for a timestamp arg, defaulting to now. */
function iso(ts) {
  if (ts == null) return new Date().toISOString();
  if (ts instanceof Date) return ts.toISOString();
  if (typeof ts === 'number') return new Date(ts).toISOString();
  return String(ts);
}

/** Age in seconds between two ISO/epoch timestamps. */
function ageSeconds(thenIso, nowAtMs) {
  const t = new Date(thenIso).getTime();
  if (Number.isNaN(t)) return Infinity;
  return (nowAtMs - t) / 1000;
}

/**
 * Construct a fresh in-memory store. Each call is fully isolated (its own Maps), so tests
 * never bleed into each other.
 *
 * @param {Object} [_config]  accepted for parity with makePgStore(config); unused here.
 * @returns {import('./store').Store}
 */
function makeMemStore(_config) {
  // ── tables ──────────────────────────────────────────────────────────────
  /** deviceId -> device row */
  const devices = new Map();
  /** serial -> deviceId */
  const serialIndex = new Map();
  /** tokenHash -> deviceId (only live, non-revoked tokens) */
  const tokenIndex = new Map();

  /** deviceId -> device_state row */
  const deviceState = new Map();
  /** deviceId -> Map<name, interface_state row> */
  const interfaceState = new Map();
  /** deviceId -> Map<interface, lte_state row> */
  const lteState = new Map();
  /** deviceId -> Map<`${interface}|${mac}`, neighbor row> */
  const neighbors = new Map();
  /** deviceId -> Map<`${interface}|${mac}`, mac_host row> */
  const macHosts = new Map();
  /** deviceId -> Map<interface, wifi_network row> */
  const wifiNetworks = new Map();
  /** deviceId -> Map<`${interface}|${mac}`, wireless_client row> */
  const wirelessClients = new Map();

  /** append-only history */
  const metricsHistory = []; // {device_id, ts, ...}
  const interfaceHistory = []; // {device_id, name, ts, ...}
  const lteHistory = []; // {device_id, interface, ts, ...}

  /** jobId -> config_jobs row */
  const configJobs = new Map();
  const configSnapshots = []; // {id, device_id, ts, rsc_text, rsc_sha256, source}
  let snapshotSeq = 0;

  /** version -> agent_scripts row */
  const agentScripts = new Map();

  /** alert_rules + alerts */
  const alertRules = []; // {id, name, metric, comparator, threshold, for_seconds, severity, scope_tag, enabled}
  const alerts = []; // {id, device_id, rule_id, severity, state, detail, opened_at, cleared_at}
  let alertSeq = 0;

  /** append-only audit trail (actor + action + serial + details) */
  const auditLog = []; // {id, ts, actor, action, serial, details}

  /** jobId -> speedtest_jobs row */
  const speedtestJobs = new Map();

  // ── helpers ─────────────────────────────────────────────────────────────
  function deviceTags(deviceId) {
    const d = devices.get(deviceId);
    return (d && Array.isArray(d.tags)) ? d.tags : [];
  }

  // ── registry ──────────────────────────────────────────────────────────────
  async function migrate() {
    // No schema to apply for the in-memory store.
  }

  async function getDeviceByToken(tokenHash) {
    const id = tokenIndex.get(tokenHash);
    if (!id) return null;
    const d = devices.get(id);
    return d ? { ...d } : null;
  }

  async function getDeviceBySerial(serial) {
    const id = serialIndex.get(serial);
    if (!id) return null;
    const d = devices.get(id);
    return d ? { ...d } : null;
  }

  async function createDevice(fields = {}) {
    if (!fields.serial) throw new Error('createDevice: serial is required');
    const existing = serialIndex.get(fields.serial);
    if (existing) throw new Error(`createDevice: serial '${fields.serial}' already exists`);
    const id = fields.id || randomUUID();
    const device = {
      id,
      serial: fields.serial,
      identity: fields.identity != null ? fields.identity : null,
      site_name: fields.site_name != null ? fields.site_name : null,
      customer: fields.customer != null ? fields.customer : null,
      model: fields.model != null ? fields.model : null,
      ros_version: fields.ros_version != null ? fields.ros_version : null,
      wan_type: fields.wan_type != null ? fields.wan_type : 'unknown',
      tags: Array.isArray(fields.tags) ? fields.tags.slice() : [],
      expected: fields.expected != null ? fields.expected : true,
      poll_interval_s: fields.poll_interval_s != null ? fields.poll_interval_s : 10,
      poll_until: fields.poll_until != null ? fields.poll_until : null,
      agent_version: fields.agent_version != null ? fields.agent_version : null,
      enrolled_at: iso(fields.enrolled_at),
      notes: fields.notes != null ? fields.notes : null,
    };
    devices.set(id, device);
    serialIndex.set(device.serial, id);
    return { ...device };
  }

  async function setDeviceToken(deviceId, tokenHash) {
    const d = devices.get(deviceId);
    if (!d) throw new Error(`setDeviceToken: no device ${deviceId}`);
    // Drop any previous token pointing at this device (one live token per device).
    for (const [hash, id] of tokenIndex) {
      if (id === deviceId) tokenIndex.delete(hash);
    }
    tokenIndex.set(tokenHash, deviceId);
  }

  // ── live state upserts ─────────────────────────────────────────────────────
  async function getInterfaceStates(deviceId) {
    const m = interfaceState.get(deviceId);
    if (!m) return [];
    // Return the fields the handler needs for delta math, including sampled_at.
    return Array.from(m.values()).map((r) => ({
      name: r.name,
      rx_byte: r.rx_byte != null ? r.rx_byte : null,
      tx_byte: r.tx_byte != null ? r.tx_byte : null,
      rx_packet: r.rx_packet != null ? r.rx_packet : null,
      tx_packet: r.tx_packet != null ? r.tx_packet : null,
      sampled_at: r.sampled_at,
    }));
  }

  async function upsertDeviceState(deviceId, state) {
    const prev = deviceState.get(deviceId) || {};
    const row = {
      ...prev,
      ...state,
      device_id: deviceId,
      last_seen_at: state && state.last_seen_at != null ? state.last_seen_at : iso(),
    };
    deviceState.set(deviceId, row);
  }

  // CHUNKED TELEMETRY: bump only last_seen_at (+ keep status 'online') WITHOUT touching the
  // system columns. Used when a detail-only chunk arrives (interfaces/neighbors/… but no
  // system block): we must record the device is alive without nulling cpu_load/uptime/etc.
  // that an earlier core chunk wrote this tick. If no device_state row exists yet (a detail
  // chunk raced ahead of the core chunk), seed a minimal online row so the device still shows.
  async function touchDeviceState(deviceId, ts) {
    const prev = deviceState.get(deviceId);
    const stamp = ts != null ? ts : iso();
    if (!prev) {
      deviceState.set(deviceId, { device_id: deviceId, status: 'online', last_seen_at: stamp });
      return;
    }
    prev.status = 'online';
    prev.last_seen_at = stamp;
  }

  async function upsertInterfaceStates(deviceId, rows) {
    if (!Array.isArray(rows)) return;
    let m = interfaceState.get(deviceId);
    if (!m) {
      m = new Map();
      interfaceState.set(deviceId, m);
    }
    for (const r of rows) {
      if (!r || r.name == null) continue;
      const prev = m.get(r.name) || {};
      const row = {
        ...prev,
        ...r,
        device_id: deviceId,
        name: r.name,
        sampled_at: r.sampled_at != null ? r.sampled_at : iso(),
      };
      m.set(r.name, row);
    }
  }

  async function upsertLteState(deviceId, row) {
    if (!row || row.interface == null) return;
    let m = lteState.get(deviceId);
    if (!m) {
      m = new Map();
      lteState.set(deviceId, m);
    }
    const prev = m.get(row.interface) || {};
    m.set(row.interface, {
      ...prev,
      ...row,
      device_id: deviceId,
      sampled_at: row.sampled_at != null ? row.sampled_at : iso(),
    });
  }

  async function upsertNeighbors(deviceId, rows) {
    if (!Array.isArray(rows)) return;
    let m = neighbors.get(deviceId);
    if (!m) {
      m = new Map();
      neighbors.set(deviceId, m);
    }
    const stamp = iso();
    for (const r of rows) {
      if (!r || r.interface == null || r.mac == null) continue;
      const key = `${r.interface}|${r.mac}`;
      const prev = m.get(key) || {};
      m.set(key, {
        ...prev,
        ...r,
        device_id: deviceId,
        last_seen_at: stamp,
      });
    }
  }

  async function upsertMacHosts(deviceId, rows) {
    if (!Array.isArray(rows)) return;
    let m = macHosts.get(deviceId);
    if (!m) {
      m = new Map();
      macHosts.set(deviceId, m);
    }
    const stamp = iso();
    for (const r of rows) {
      if (!r || r.interface == null || r.mac == null) continue;
      const key = `${r.interface}|${r.mac}`;
      const prev = m.get(key) || {};
      m.set(key, {
        ...prev,
        ...r,
        device_id: deviceId,
        last_seen_at: stamp,
      });
    }
  }

  // WiFi config + associated stations use FULL-SNAPSHOT semantics: each report REPLACES the
  // device's set (a removed SSID / departed station disappears). The handler only calls these
  // when the payload carried the array (null/absent = keep previous), so a chunk omitting wifi
  // never wipes it.
  async function upsertWifiNetworks(deviceId, rows) {
    if (!Array.isArray(rows)) return;
    const m = new Map();
    const stamp = iso();
    for (const r of rows) {
      if (!r || r.interface == null) continue;
      m.set(r.interface, { ...r, device_id: deviceId, interface: r.interface, last_seen_at: stamp });
    }
    wifiNetworks.set(deviceId, m);
  }

  async function upsertWirelessClients(deviceId, rows) {
    if (!Array.isArray(rows)) return;
    const m = new Map();
    const stamp = iso();
    for (const r of rows) {
      if (!r || r.interface == null || r.mac == null) continue;
      m.set(`${r.interface}|${r.mac}`, {
        ...r,
        device_id: deviceId,
        interface: r.interface,
        mac: r.mac,
        sampled_at: stamp,
      });
    }
    wirelessClients.set(deviceId, m);
  }

  // ── history (append-only) ──────────────────────────────────────────────────
  async function appendMetricsHistory(deviceId, ts, row) {
    metricsHistory.push({ ...(row || {}), device_id: deviceId, ts: iso(ts) });
  }

  async function appendInterfaceHistory(deviceId, ts, rows) {
    if (!Array.isArray(rows)) return;
    const stamp = iso(ts);
    for (const r of rows) {
      if (!r || r.name == null) continue;
      interfaceHistory.push({ ...r, device_id: deviceId, name: r.name, ts: stamp });
    }
  }

  async function appendLteHistory(deviceId, ts, row) {
    if (!row || row.interface == null) return;
    lteHistory.push({ ...row, device_id: deviceId, ts: iso(ts) });
  }

  // ── poll window ────────────────────────────────────────────────────────────
  async function setPollWindow(deviceId, pollUntil, intervalS) {
    const d = devices.get(deviceId);
    if (!d) return;
    d.poll_until = pollUntil != null ? iso(pollUntil) : null;
    if (intervalS != null) d.poll_interval_s = intervalS;
  }

  // ── config jobs ────────────────────────────────────────────────────────────
  /** True if a job targets this device directly, or via one of the device's tags. */
  function jobTargetsDevice(job, deviceId) {
    if (job.device_id && job.device_id === deviceId) return true;
    if (job.target_tag) return deviceTags(deviceId).includes(job.target_tag);
    return false;
  }

  async function getPendingConfigJob(deviceId) {
    for (const job of configJobs.values()) {
      if (job.status !== 'approved') continue;
      if (!jobTargetsDevice(job, deviceId)) continue;
      return {
        id: job.id,
        rsc_sha256: job.rsc_sha256,
        confirm_window_s: job.confirm_window_s,
      };
    }
    return null;
  }

  // Serving gate lives HERE on the byte path, not just in getPendingConfigJob: only a job
  // in an in-flight status may yield its bytes, so a device can never pull a draft/cancelled/
  // applied/rolled_back/failed job's rsc_text and /import it onto a live router. Fetchable
  // set: approved (initial pull) + fetched/applying (mid-apply retry within confirm window).
  const FETCHABLE_STATUSES = new Set(['approved', 'fetched', 'applying']);

  async function getConfigJobForFetch(jobId, deviceId) {
    const job = configJobs.get(jobId);
    if (!job) return null;
    if (!FETCHABLE_STATUSES.has(job.status)) return null;
    if (!jobTargetsDevice(job, deviceId)) return null;
    return { rsc_text: job.rsc_text, rsc_sha256: job.rsc_sha256 };
  }

  // The operator-confirmed job for this device (status='applied'), if any. Surfaced in the
  // telemetry response as "confirm":"<jobid>" so the agent cancels its dead-man rollback.
  // Absence of a job is NEVER confirmation — only an affirmative 'applied' job confirms.
  async function getConfirmedJob(deviceId) {
    let best = null;
    for (const job of configJobs.values()) {
      if (job.status !== 'applied') continue;
      if (!jobTargetsDevice(job, deviceId)) continue;
      const at = new Date(job.applied_at || job.created_at || 0).getTime();
      if (!best || at >= best.at) best = { id: job.id, at };
    }
    return best ? { id: best.id } : null;
  }

  async function markConfigJob(jobId, status, fields = {}) {
    const job = configJobs.get(jobId);
    if (!job) throw new Error(`markConfigJob: no job ${jobId}`);
    job.status = status;
    // Stamp the timestamp/field appropriate to the new status.
    if (status === 'fetched') job.fetched_at = fields.fetched_at != null ? iso(fields.fetched_at) : iso();
    if (status === 'applied') job.applied_at = fields.applied_at != null ? iso(fields.applied_at) : iso();
    if (fields.result_log != null) job.result_log = fields.result_log;
    if (fields.rollback_ref != null) job.rollback_ref = fields.rollback_ref;
    if (fields.fetched_at != null) job.fetched_at = iso(fields.fetched_at);
    if (fields.applied_at != null) job.applied_at = iso(fields.applied_at);
  }

  async function recordConfigResult(jobId, status, resultLog, exportText) {
    const job = configJobs.get(jobId);
    if (!job) throw new Error(`recordConfigResult: no job ${jobId}`);
    job.status = status;
    job.result_log = resultLog != null ? resultLog : null;
    if (status === 'applied') job.applied_at = iso();
    if (status === 'rolled_back' && !job.rollback_ref) {
      job.rollback_ref = `snapshot:${job.id}`;
    }
    if (exportText != null && job.device_id) {
      configSnapshots.push({
        id: ++snapshotSeq,
        device_id: job.device_id,
        ts: iso(),
        rsc_text: exportText,
        rsc_sha256: '', // checksum computed by callers/transform.sha256Hex when needed
        // The agent only ever POSTs the PRE-change export on the apply tick (see
        // agent/vigilant-agent.rsc step 5), so this is always a pre-apply snapshot.
        // Must match store.pg.js, which hard-codes 'pre-apply' — keep pg/mem parity.
        source: 'pre-apply',
      });
    }
  }

  // ── config jobs: ADMIN-facing authoring/approval (operator side) ─────────────
  // These are the operator counterparts to the device-side getPendingConfigJob/…Fetch above.
  // They never serve a router — they let the dashboard author a draft, approve it (two-person),
  // cancel it, and list a device's jobs. The serving gate stays in getPendingConfigJob /
  // getConfigJobForFetch, so creating/approving here can never bypass the "only approved +
  // targeted + checksum-verified" contract.

  // Create a DRAFT job (status='draft' — never served until approved). Computes rsc_sha256
  // from rsc_text when the caller doesn't supply one. Mirrors createConfigJob in store.pg.js.
  async function createConfigJob(fields = {}) {
    const f = fields || {};
    const rsc = f.rsc_text != null ? String(f.rsc_text) : '';
    const sha =
      f.rsc_sha256 != null && f.rsc_sha256 !== ''
        ? f.rsc_sha256
        : require('./transform').sha256Hex(rsc);
    return _test.addConfigJob({ ...f, rsc_text: rsc, rsc_sha256: sha, status: 'draft' });
  }

  // Approve a DRAFT -> 'approved' (the only status a device will pull). Returns the updated
  // row, or null if the job doesn't exist; throws if it isn't a draft (the caller checks
  // status + the two-person rule first, but defend the transition here too).
  async function approveConfigJob(jobId, approvedBy) {
    const job = configJobs.get(jobId);
    if (!job) return null;
    if (job.status !== 'draft') {
      throw new Error(`approveConfigJob: job ${jobId} is '${job.status}', not 'draft'`);
    }
    job.status = 'approved';
    job.approved_by = approvedBy != null ? approvedBy : null;
    job.approved_at = iso();
    return { ...job };
  }

  // Cancel a job that has not yet been picked up (draft or approved) -> 'cancelled'.
  async function cancelConfigJob(jobId) {
    const job = configJobs.get(jobId);
    if (!job) return null;
    if (job.status !== 'draft' && job.status !== 'approved') {
      throw new Error(`cancelConfigJob: job ${jobId} is '${job.status}', cannot cancel`);
    }
    job.status = 'cancelled';
    return { ...job };
  }

  // All jobs targeting this device (directly or via a tag), newest first, capped.
  async function listConfigJobs(deviceId, limit = 50) {
    const out = [];
    for (const job of configJobs.values()) {
      if (!jobTargetsDevice(job, deviceId)) continue;
      out.push({ ...job });
    }
    out.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return out.slice(0, Math.max(0, limit));
  }

  async function getConfigJob(jobId) {
    const j = configJobs.get(jobId);
    return j ? { ...j } : null;
  }

  // ── speedtest jobs ───────────────────────────────────────────────────────────
  async function createSpeedtestJob(fields = {}) {
    const f = fields || {};
    const id = f.id || randomUUID();
    const row = {
      id,
      device_id: f.device_id != null ? f.device_id : null,
      status: 'pending',
      bytes_down: f.bytes_down != null ? f.bytes_down : 26214400,
      bytes_up: f.bytes_up != null ? f.bytes_up : 8388608,
      down_bps: null,
      up_bps: null,
      requested_by: f.requested_by || 'unknown',
      result_log: null,
      created_at: iso(f.created_at),
      started_at: null,
      finished_at: null,
    };
    speedtestJobs.set(id, row);
    return { ...row };
  }

  // Most-recent pending job for this device (the one the agent should run next), or null.
  async function getPendingSpeedtestJob(deviceId) {
    let best = null;
    for (const j of speedtestJobs.values()) {
      if (j.device_id !== deviceId || j.status !== 'pending') continue;
      const at = new Date(j.created_at).getTime();
      if (!best || at >= best.at) best = { job: j, at };
    }
    return best ? { ...best.job } : null;
  }

  async function markSpeedtestRunning(jobId) {
    const j = speedtestJobs.get(jobId);
    if (!j) return null;
    if (j.status === 'pending') { j.status = 'running'; j.started_at = iso(); }
    return { ...j };
  }

  // Record a measured leg (down or up). The handler computes bps from its own transfer timing
  // and calls this per leg; finishing (status done/failed) is set explicitly via fields.status.
  async function recordSpeedtestResult(jobId, fields = {}) {
    const j = speedtestJobs.get(jobId);
    if (!j) return null;
    const f = fields || {};
    if (f.down_bps != null) j.down_bps = f.down_bps;
    if (f.up_bps != null) j.up_bps = f.up_bps;
    if (f.result_log != null) j.result_log = f.result_log;
    if (f.status != null) j.status = f.status;
    if (f.status === 'done' || f.status === 'failed') j.finished_at = iso();
    return { ...j };
  }

  async function getSpeedtestJob(jobId) {
    const j = speedtestJobs.get(jobId);
    return j ? { ...j } : null;
  }

  async function listSpeedtestJobs(deviceId, limit = 20) {
    const out = [];
    for (const j of speedtestJobs.values()) if (j.device_id === deviceId) out.push({ ...j });
    out.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return out.slice(0, Math.max(0, limit));
  }

  // ── audit ────────────────────────────────────────────────────────────────────
  async function appendAudit(actor, action, serial, details) {
    auditLog.push({
      id: auditLog.length + 1,
      ts: iso(),
      actor: actor != null ? actor : 'unknown',
      action,
      serial: serial != null ? serial : null,
      details: details != null ? details : null,
    });
  }

  // ── agent script ───────────────────────────────────────────────────────────
  async function getCurrentAgentScript() {
    for (const s of agentScripts.values()) {
      if (s.is_current) return { version: s.version, rsc_text: s.rsc_text };
    }
    return null;
  }

  // ── read APIs ──────────────────────────────────────────────────────────────
  async function getFleet() {
    const rows = [];
    for (const d of devices.values()) {
      const s = deviceState.get(d.id) || {};
      const openAlerts = alerts.filter((a) => a.device_id === d.id && a.state === 'open').length;
      rows.push({
        id: d.id,
        serial: d.serial,
        identity: d.identity != null ? d.identity : null,
        site_name: d.site_name != null ? d.site_name : null,
        customer: d.customer != null ? d.customer : null,
        model: d.model != null ? d.model : null,
        wan_type: d.wan_type,
        tags: d.tags.slice(),
        status: s.status != null ? s.status : null,
        cpu_load: s.cpu_load != null ? s.cpu_load : null,
        temperature: s.temperature != null ? s.temperature : null,
        public_ip: s.public_ip != null ? s.public_ip : null,
        ppp_sessions: s.ppp_sessions != null ? s.ppp_sessions : null,
        last_seen_at: s.last_seen_at != null ? s.last_seen_at : null,
        open_alerts: openAlerts,
      });
    }
    return rows;
  }

  async function getDeviceDetail(serial) {
    const id = serialIndex.get(serial);
    if (!id) return null;
    const d = devices.get(id);
    const state = deviceState.get(id) || null;
    const ifMap = interfaceState.get(id);
    const lteMap = lteState.get(id);
    const nbrMap = neighbors.get(id);
    const macMap = macHosts.get(id);
    const wifiMap = wifiNetworks.get(id);
    const wcMap = wirelessClients.get(id);
    const wifiClients = wcMap ? Array.from(wcMap.values()).map((r) => ({ ...r })) : [];
    // Denormalise the connected-station count onto each WLAN row (counted by interface) so the
    // UI/grid can show "N clients" without a second pass.
    const wifi = wifiMap
      ? Array.from(wifiMap.values()).map((r) => ({
          ...r,
          clients: wifiClients.filter((c) => c.interface === r.interface).length,
        }))
      : [];
    return {
      device: { ...d },
      state: state ? { ...state } : null,
      interfaces: ifMap ? Array.from(ifMap.values()).map((r) => ({ ...r })) : [],
      lte: lteMap ? Array.from(lteMap.values()).map((r) => ({ ...r })) : [],
      neighbors: nbrMap ? Array.from(nbrMap.values()).map((r) => ({ ...r })) : [],
      mac_hosts: macMap ? Array.from(macMap.values()).map((r) => ({ ...r })) : [],
      wifi,
      wifi_clients: wifiClients,
    };
  }

  // ── history read APIs (dashboard charts) ────────────────────────────────────
  // Time-ascending device-level metric points since `sinceMs` (epoch ms). Mirrors
  // store.pg.getMetricsHistory: the dashboard's CPU/memory/temperature/ppp charts read
  // from here. Returns [] for an unknown serial (the route layer 404s on unknown serials
  // via getDeviceDetail, so this never has to distinguish "no device" from "no points").
  async function getMetricsHistory(serial, sinceMs) {
    const id = serialIndex.get(serial);
    if (!id) return [];
    const since = typeof sinceMs === 'number' ? sinceMs : 0;
    return metricsHistory
      .filter((r) => r.device_id === id && new Date(r.ts).getTime() >= since)
      .map((r) => ({
        ts: iso(r.ts),
        cpu_load: r.cpu_load != null ? r.cpu_load : null,
        free_memory: r.free_memory != null ? r.free_memory : null,
        temperature: r.temperature != null ? r.temperature : null,
        ppp_sessions: r.ppp_sessions != null ? r.ppp_sessions : null,
      }))
      .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  }

  // Time-ascending per-interface rx/tx bps points since `sinceMs`, grouped by interface
  // name. Mirrors store.pg.getInterfaceHistory. Each interface gets its own points array.
  async function getInterfaceHistory(serial, sinceMs) {
    const id = serialIndex.get(serial);
    if (!id) return [];
    const since = typeof sinceMs === 'number' ? sinceMs : 0;
    const byName = new Map();
    for (const r of interfaceHistory) {
      if (r.device_id !== id) continue;
      if (new Date(r.ts).getTime() < since) continue;
      if (!byName.has(r.name)) byName.set(r.name, []);
      byName.get(r.name).push({
        ts: iso(r.ts),
        rx_bps: r.rx_bps != null ? r.rx_bps : null,
        tx_bps: r.tx_bps != null ? r.tx_bps : null,
      });
    }
    const out = [];
    for (const [name, points] of byName) {
      points.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
      out.push({ name, points });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }

  // Combined device history in the HISTORY API contract shape (docs §HISTORY API):
  //   { serial, metrics:[{ts,cpu_load,free_memory,temperature,ppp_sessions}],
  //     interfaces:[{name, points:[{ts,rx_bps,tx_bps}]}] }
  // window is `windowSeconds` back from now; both series are time-ASCENDING. Returns null
  // for an UNKNOWN serial so the route layer can 404 (distinct from a known device with no
  // history, which yields empty arrays). Mirrors store.pg.getDeviceHistory so mem/pg stay
  // interchangeable. The `window` label itself is owned by the handler.
  async function getDeviceHistory(serial, windowSeconds) {
    const id = serialIndex.get(serial);
    if (!id) return null;
    const win = typeof windowSeconds === 'number' && windowSeconds > 0 ? windowSeconds : 3600;
    const sinceMs = Date.now() - win * 1000;
    const metrics = await getMetricsHistory(serial, sinceMs);
    const interfaces = await getInterfaceHistory(serial, sinceMs);
    return { serial, metrics, interfaces };
  }

  // ── worker ─────────────────────────────────────────────────────────────────
  async function markStaleDevices(staleSeconds, offlineSeconds) {
    const at = Date.now();
    for (const s of deviceState.values()) {
      const age = ageSeconds(s.last_seen_at, at);
      if (age >= offlineSeconds) s.status = 'offline';
      else if (age >= staleSeconds) s.status = 'stale';
      else s.status = 'online';
    }
    // Report the live population of stale/offline devices after the pass.
    let stale = 0;
    let offline = 0;
    for (const s of deviceState.values()) {
      if (s.status === 'stale') stale += 1;
      else if (s.status === 'offline') offline += 1;
    }
    return { stale, offline };
  }

  async function getActiveAlertRules() {
    return alertRules.filter((r) => r.enabled !== false).map((r) => ({ ...r }));
  }

  // ── alert-rule CRUD (operator-facing; backs the Rules UI) ──
  async function listAlertRules() {
    return alertRules.map((r) => ({ ...r }));
  }
  async function listAlerts(limit) {
    const n = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
    return [...alerts]
      .sort((a, b) => new Date(b.opened_at) - new Date(a.opened_at))
      .slice(0, n)
      .map((a) => {
        const d = devices.get(a.device_id) || {};
        const r = alertRules.find((x) => x.id === a.rule_id) || {};
        return { ...a, serial: d.serial, site_name: d.site_name, identity: d.identity, rule_name: r.name, rule_metric: r.metric };
      });
  }
  async function createAlertRule(f) {
    return _test.addAlertRule(f || {});
  }
  function buildRuleRow(id, u) {
    return {
      id,
      name: u.name || `rule-${id}`,
      metric: u.metric,
      comparator: u.comparator || '>=',
      threshold: u.threshold != null ? u.threshold : null,
      for_seconds: u.for_seconds != null ? u.for_seconds : 0,
      severity: u.severity || 'warning',
      scope_tag: u.scope_tag != null ? u.scope_tag : null,
      enabled: u.enabled !== false,
      notify_email: u.notify_email != null ? u.notify_email : null,
      notify_teams_webhook: u.notify_teams_webhook != null ? u.notify_teams_webhook : null,
      notify_on: u.notify_on != null ? u.notify_on : 'both',
      neighbor_platform: u.neighbor_platform != null ? u.neighbor_platform : null,
    };
  }
  async function updateAlertRule(id, f) {
    const i = alertRules.findIndex((x) => String(x.id) === String(id));
    if (i < 0) return null;
    alertRules[i] = buildRuleRow(alertRules[i].id, f || {});
    return { ...alertRules[i] };
  }
  async function deleteAlertRule(id) {
    const i = alertRules.findIndex((x) => String(x.id) === String(id));
    if (i < 0) return false;
    alertRules.splice(i, 1);
    return true;
  }

  /**
   * Evaluate each active rule against current device_state and open/clear alerts.
   * The threshold decision lives in transform.evaluateAlert — required lazily so this
   * module has no hard dependency back on transform for non-alert use.
   *
   * @param {Object[]} rules
   * @returns {Promise<{opened: number, cleared: number}>}
   */
  async function evaluateAndApplyAlerts(rules) {
    const { evaluateAlert } = require('./transform');
    let opened = 0;
    let cleared = 0;
    const transitions = []; // open/clear events for the worker to notify on
    const ruleList = Array.isArray(rules) ? rules : [];

    // Anti-flap (honours rule.for_seconds): a firing condition parks as 'pending' until it has
    // held for for_seconds, then promotes to 'open' (notify); if it stops firing while pending
    // it's dropped (no alarm, no flap). for_seconds=0 → open immediately. Returns a transition.
    function applyAlertState(deviceId, rule, firing, detail, dev, value) {
      const forS = rule.for_seconds != null ? Math.max(0, Math.round(Number(rule.for_seconds))) : 0;
      const cur = alerts.find(
        (a) => a.device_id === deviceId && a.rule_id === rule.id && (a.state === 'open' || a.state === 'pending')
      );
      if (firing) {
        if (!cur) {
          const state = forS <= 0 ? 'open' : 'pending';
          alerts.push({ id: ++alertSeq, device_id: deviceId, rule_id: rule.id, severity: rule.severity || 'warning', state, detail, opened_at: iso(), cleared_at: null });
          if (state === 'open') { opened += 1; return { kind: 'open', device_id: deviceId, serial: dev.serial, site_name: dev.site_name, detail, value, rule }; }
          return null;
        }
        if (cur.state === 'pending' && ageSeconds(cur.opened_at, Date.now()) >= forS) {
          cur.state = 'open'; cur.opened_at = iso(); cur.detail = detail; opened += 1;
          return { kind: 'open', device_id: deviceId, serial: dev.serial, site_name: dev.site_name, detail, value, rule };
        }
        return null;
      }
      if (!cur) return null;
      if (cur.state === 'pending') { const i = alerts.indexOf(cur); if (i >= 0) alerts.splice(i, 1); return null; }
      cur.state = 'cleared'; cur.cleared_at = iso(); cleared += 1;
      return { kind: 'clear', device_id: deviceId, serial: dev.serial, site_name: dev.site_name, detail, value, rule };
    }

    for (const [deviceId, s] of deviceState) {
      const tags = deviceTags(deviceId);
      const dev = devices.get(deviceId) || {};
      for (const rule of ruleList) {
        if (rule.enabled === false) continue;
        if (rule.scope_tag && !tags.includes(rule.scope_tag)) continue;

        let value;
        let firing;
        let detail;
        if (rule.metric === 'neighbor_down') {
          // A matching neighbour (e.g. Yealink) not seen for > threshold seconds = dropped.
          const thr = rule.threshold != null ? Math.round(Number(rule.threshold)) : 300;
          const nm = neighbors.get(deviceId);
          const dropped = nm
            ? Array.from(nm.values()).filter((n) => {
                if (rule.neighbor_platform && !String(n.platform || '').toLowerCase().includes(String(rule.neighbor_platform).toLowerCase())) return false;
                return ageSeconds(n.last_seen_at, Date.now()) > thr;
              })
            : [];
          firing = dropped.length > 0;
          value = dropped.length;
          const names = dropped.map((n) => n.identity || n.mac).slice(0, 5).join(', ');
          detail = `${rule.name ? rule.name + ': ' : ''}${dropped.length} ${rule.neighbor_platform || 'neighbour'}(s) not seen >${thr}s${names ? ' — ' + names : ''}`;
        } else {
          value = rule.metric === 'offline' ? s.status : s[rule.metric];
          firing = evaluateAlert(rule, value);
          detail = `${rule.name ? rule.name + ': ' : ''}${rule.metric} ${rule.comparator} ${rule.threshold != null ? rule.threshold : ''} (value=${value == null ? 'null' : value})`.trim();
        }
        const tr = applyAlertState(deviceId, rule, firing, detail, dev, value);
        if (tr) transitions.push(tr);
      }
    }
    return { opened, cleared, transitions };
  }

  async function downsampleHistory(_now) {
    // In-memory store keeps raw rows only; downsampling is a no-op (parity with pg).
  }

  async function pruneHistory(now) {
    const at = nowMs(now);
    const cfg = _config || {};
    const retentionH = cfg.historyRawRetentionH != null ? cfg.historyRawRetentionH : 24;
    const cutoff = at - retentionH * 3600 * 1000;
    const keep = (arr) => {
      for (let i = arr.length - 1; i >= 0; i -= 1) {
        if (new Date(arr[i].ts).getTime() < cutoff) arr.splice(i, 1);
      }
    };
    keep(metricsHistory);
    keep(interfaceHistory);
    keep(lteHistory);
  }

  async function pruneNeighbors(now, ttlSeconds) {
    const at = nowMs(now);
    for (const m of neighbors.values()) {
      for (const [key, r] of m) {
        if (ageSeconds(r.last_seen_at, at) > ttlSeconds) m.delete(key);
      }
    }
  }

  async function pruneMacHosts(now, ttlSeconds) {
    const at = nowMs(now);
    for (const m of macHosts.values()) {
      for (const [key, r] of m) {
        if (ageSeconds(r.last_seen_at, at) > ttlSeconds) m.delete(key);
      }
    }
  }

  // ── test/seed helpers (in addition to the Store interface) ──────────────────
  // Not part of the Store interface — exposed so tests can stand up fixtures directly
  // (e.g. push an approved config job, publish an agent script, define an alert rule)
  // without a SQL round-trip.
  const _test = {
    addConfigJob(job) {
      const id = job.id || randomUUID();
      const row = {
        id,
        device_id: job.device_id != null ? job.device_id : null,
        target_tag: job.target_tag != null ? job.target_tag : null,
        is_canary: job.is_canary === true,
        kind: job.kind || 'snippet',
        rsc_text: job.rsc_text != null ? job.rsc_text : '',
        rsc_sha256: job.rsc_sha256 != null ? job.rsc_sha256 : '',
        status: job.status || 'draft',
        confirm_window_s: job.confirm_window_s != null ? job.confirm_window_s : 300,
        created_by: job.created_by || 'test',
        approved_by: job.approved_by != null ? job.approved_by : null,
        created_at: iso(job.created_at),
        approved_at: job.approved_at != null ? iso(job.approved_at) : null,
        fetched_at: null,
        applied_at: null,
        result_log: null,
        rollback_ref: null,
      };
      configJobs.set(id, row);
      return { ...row };
    },
    getConfigJob(jobId) {
      const j = configJobs.get(jobId);
      return j ? { ...j } : null;
    },
    setAgentScript(script) {
      const version = script.version != null ? script.version : 1;
      if (script.is_current) {
        for (const s of agentScripts.values()) s.is_current = false;
      }
      agentScripts.set(version, {
        version,
        rsc_text: script.rsc_text != null ? script.rsc_text : '',
        rsc_sha256: script.rsc_sha256 != null ? script.rsc_sha256 : '',
        notes: script.notes != null ? script.notes : null,
        is_current: script.is_current === true,
      });
    },
    addAlertRule(rule) {
      const id = rule.id != null ? rule.id : alertRules.length + 1;
      const row = {
        id,
        name: rule.name || `rule-${id}`,
        metric: rule.metric,
        comparator: rule.comparator,
        threshold: rule.threshold != null ? rule.threshold : null,
        for_seconds: rule.for_seconds != null ? rule.for_seconds : 0,
        severity: rule.severity || 'warning',
        scope_tag: rule.scope_tag != null ? rule.scope_tag : null,
        enabled: rule.enabled !== false,
        notify_email: rule.notify_email != null ? rule.notify_email : null,
        notify_teams_webhook: rule.notify_teams_webhook != null ? rule.notify_teams_webhook : null,
        notify_on: rule.notify_on != null ? rule.notify_on : 'both',
        neighbor_platform: rule.neighbor_platform != null ? rule.neighbor_platform : null,
      };
      alertRules.push(row);
      return { ...row };
    },
    listAlerts() {
      return alerts.map((a) => ({ ...a }));
    },
    listConfigSnapshots() {
      return configSnapshots.map((s) => ({ ...s }));
    },
    // Raw table handles for assertions in tests that want to peek.
    _tables: {
      devices,
      deviceState,
      interfaceState,
      lteState,
      neighbors,
      macHosts,
      wifiNetworks,
      wirelessClients,
      metricsHistory,
      interfaceHistory,
      lteHistory,
      configJobs,
      configSnapshots,
      agentScripts,
      alertRules,
      alerts,
      auditLog,
      speedtestJobs,
    },
  };

  return {
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
    // Test/seed convenience (not part of the Store interface): insert a config_jobs row
    // directly so config.test.js can stand up draft/approved jobs without SQL. Returns the
    // row (incl. its id). Mirrors seedDevice.
    seedConfigJob: (fields) => _test.addConfigJob(fields || {}),
    _test,
  };
}

/**
 * Test convenience: create a device and (optionally) attach a token hash in one call.
 * Mirrors the enrol flow (createDevice → setDeviceToken) so the e2e/config tests can stand
 * up an authenticatable device without going through the /enroll route.
 *
 * @param {import('./store').Store} store   a mem store from makeMemStore()
 * @param {{serial: string, tokenHash?: string, site_name?: string, customer?: string,
 *          wan_type?: string, tags?: string[]}} opts
 * @returns {Promise<import('./store').Device>}  the created device
 */
async function seedDevice(store, opts = {}) {
  if (!opts.serial) throw new Error('seedDevice: serial is required');
  const device = await store.createDevice({
    serial: opts.serial,
    site_name: opts.site_name,
    customer: opts.customer,
    wan_type: opts.wan_type,
    tags: opts.tags,
  });
  if (opts.tokenHash) {
    await store.setDeviceToken(device.id, opts.tokenHash);
  }
  return device;
}

module.exports = { makeMemStore, seedDevice };
