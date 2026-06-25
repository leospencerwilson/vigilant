'use strict';

// Vigilant ingest — request handlers (one async fn per route).
//
// Each handler receives a `ctx` built by server.js:
//   { req, res, store, config, log, body, query, params, device }
// where `body` is the raw request body STRING (handlers parse it themselves so a
// malformed payload returns 400 rather than crashing the router), `device` is the
// authenticated device row for device routes (null for admin routes), `query` is a
// URLSearchParams, and `params` holds matched path params (e.g. {id} or {serial}).
//
// Handlers are pure-ish wrappers around the store + transform helpers — the business
// logic lives in transform.js (pure) and the store (IO). Nothing here logs the raw
// bearer token.

const crypto = require('node:crypto');

const transform = require('../shared/transform');
const telemetry = require('../shared/telemetry');
const oui = require('../shared/oui');

// Statuses a DEVICE may legitimately report via POST /config/result. A subset of the
// config_jobs.status CHECK set — the server-only states ('draft','approved','cancelled')
// are never device-reportable. Reject anything else at the handler so a malformed body
// can't violate the DB CHECK and 500 the service.
const DEVICE_REPORTABLE_STATUSES = new Set([
  'fetched',
  'applying',
  'applied',
  'failed',
  'rolled_back',
]);

// ── small response helpers ───────────────────────────────────────────
function json(res, code, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': buf.length });
  res.end(buf);
}

function text(res, code, body, headers) {
  const buf = Buffer.from(body == null ? '' : String(body));
  res.writeHead(code, Object.assign({ 'content-type': 'text/plain', 'content-length': buf.length }, headers || {}));
  res.end(buf);
}

function nowMs() {
  return Date.now();
}

// Parse a sampled_at value (Date | string | number) to epoch ms, or null.
function toMs(v) {
  if (v == null) return null;
  if (v instanceof Date) return v.getTime();
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  const t = Date.parse(String(v));
  return Number.isNaN(t) ? null : t;
}

// Parse a RouterOS uptime string ('1w2d3h4m5s', '4m5s', '1d', '30s', …) to whole
// seconds, or null when absent / unparseable. ROS uses w/d/h/m/s tokens; any subset may
// appear, always in descending order. We sum the components we recognise. A bare number
// (or numeric string) is treated as a seconds count. transform.js (owned by another
// agent) does not export parseUptime and the contract's transform signature list omits
// it, so the parse lives here inline rather than calling an undefined contract function.
function parseRosUptime(v) {
  if (v == null) return null;
  if (typeof v === 'number') return Number.isFinite(v) ? Math.round(v) : null;
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  if (s === '' || s === 'null') return null;
  // Plain seconds count (e.g. "300").
  if (/^\d+$/.test(s)) return Number(s);
  const units = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
  const re = /(\d+)([wdhms])/g;
  let total = 0;
  let matched = false;
  let m;
  while ((m = re.exec(s)) !== null) {
    matched = true;
    total += Number(m[1]) * units[m[2]];
  }
  return matched ? total : null;
}

// ── GET /healthz ─────────────────────────────────────────────────────
async function healthz(ctx) {
  text(ctx.res, 200, 'ok');
}

// ── GET / — admin onboarding UI (static HTML; actions inside require the admin token) ──
let _adminHtml = null;
function adminUi(ctx) {
  const { res } = ctx;
  if (_adminHtml == null) {
    try {
      _adminHtml = require('node:fs').readFileSync(
        require('node:path').join(__dirname, 'admin.html'), 'utf8');
    } catch (e) {
      _adminHtml = '<!doctype html><meta charset="utf-8"><title>Vigilant</title>' +
        '<body style="font-family:sans-serif;background:#0b0f14;color:#e6edf3;padding:40px">' +
        '<h1>Vigilant</h1><p>Admin UI asset missing; API is up. Use POST /enroll directly.</p>';
    }
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(_adminHtml);
}

// ── POST /telemetry ──────────────────────────────────────────────────
// Implements the 11-step algorithm from the contract verbatim.
async function telemetryIngest(ctx) {
  const { res, store, config, log, device, body } = ctx;

  // 1. auth → device (already done by the server's auth helper; device is set).
  if (!device) {
    return json(res, 401, { ok: false, error: 'unauthorized' });
  }

  // 2. parse JSON — fail safe (400), never crash the service.
  let raw;
  try {
    raw = JSON.parse(body || '');
  } catch (e) {
    log.warn('telemetry: bad json', { device: device.id });
    return json(res, 400, { ok: false, error: 'bad json' });
  }

  // 3. normalize → typed payload (coerces strings, maps "null"/"" → null, strips CIDR).
  let payload;
  try {
    payload = telemetry.normalize(raw);
  } catch (e) {
    log.warn('telemetry: normalize failed', { device: device.id });
    return json(res, 400, { ok: false, error: 'invalid payload' });
  }

  // 4. cross-check the payload serial against the token's device.
  if (payload.serial !== device.serial) {
    log.warn('telemetry: serial mismatch', { device: device.id });
    return json(res, 409, { ok: false, error: 'serial mismatch' });
  }

  // Sample time: prefer the agent-reported tick time (payload.ts, epoch ms) so the bps
  // delta is computed over the device's own inter-tick interval rather than HTTP
  // round-trip latency; fall back to receive time when the agent omits it.
  const reportedMs = toMs(payload.ts);
  const curMs = reportedMs != null ? reportedMs : Date.now();
  const ts = new Date(curMs);

  // 5. per-interface deltaBps (match previous sample by name) + classifyRole.
  const prev = (await store.getInterfaceStates(device.id)) || [];
  const prevByName = new Map();
  for (const p of prev) prevByName.set(p.name, p);

  const ifaceRows = [];
  const ifaceHistRows = [];
  for (const iface of payload.interfaces) {
    const p = prevByName.get(iface.name);
    const prevAt = p ? toMs(p.sampled_at) : null;
    const rxBps = transform.deltaBps(p ? p.rx_byte : null, prevAt, iface.rx_byte, curMs);
    const txBps = transform.deltaBps(p ? p.tx_byte : null, prevAt, iface.tx_byte, curMs);
    const role = transform.classifyRole(iface);
    const row = {
      name: iface.name,
      type: iface.type,
      running: iface.running,
      disabled: iface.disabled,
      plugged: iface.plugged,
      speed: iface.speed,
      full_duplex: iface.full_duplex,
      bridge: iface.bridge || null,
      is_wan: !!iface.is_wan,
      role,
      rx_bps: rxBps,
      tx_bps: txBps,
      rx_byte: iface.rx_byte,
      tx_byte: iface.tx_byte,
      rx_packet: iface.rx_packet,
      tx_packet: iface.tx_packet,
      sampled_at: ts,
    };
    ifaceRows.push(row);
    ifaceHistRows.push({ name: iface.name, rx_bps: rxBps, tx_bps: txBps, rx_error: null, tx_error: null });
  }

  // 6. parse LTE signal strings → numbers.
  let lteRow = null;
  if (payload.lte) {
    const l = payload.lte;
    lteRow = {
      interface: l.interface,
      iccid: l.iccid,
      imsi: l.imsi,
      imei: l.imei,
      msisdn: l.msisdn,
      operator: l.operator,
      registration: l.registration,
      access_tech: l.access_tech,
      band: l.band,
      cell_id: l.cell_id,
      rssi: transform.parseNum(l.rssi),
      rsrp: transform.parseNum(l.rsrp),
      rsrq: transform.parseNum(l.rsrq),
      sinr: transform.parseNum(l.sinr),
    };
  }

  // 7. mac_hosts !== null → join with arp + OUI vendor lookup (slow tick only).
  let macHostRows = null;
  if (payload.mac_hosts !== null && payload.mac_hosts !== undefined) {
    const joined = transform.joinMacHosts(payload.mac_hosts, payload.arp || []);
    macHostRows = joined.map((h) => ({
      interface: h.interface,
      mac: h.mac,
      ip: h.ip,
      vendor: oui.ouiVendor(h.mac),
    }));
  }

  // ── CHUNKED-TELEMETRY contract (see docs/CONTRACT.md §chunked telemetry) ──────────────
  // RouterOS /tool fetch caps the size of the http-data argument the script can hand the
  // fetch subsystem, so a multi-interface router cannot POST its whole rich body in one
  // request. The agent therefore splits a tick across several SMALLER POSTs, and EVERY POST
  // to /telemetry is treated as an IDEMPOTENT PARTIAL UPSERT of whatever it carries:
  //   * device_state (the system block + status:'online' + metrics-history row) is written
  //     ONLY for a CORE chunk — one whose raw body carried at least one system field
  //     (payload.has_core). A DETAIL chunk (interfaces/neighbors/lte/mac_hosts only, or
  //     partial:true) must NOT overwrite device_state with nulls; it only bumps last_seen_at
  //     via store.touchDeviceState so the device still shows 'online' between core ticks.
  //   * interface_state is upserted per (device, name) for whatever interfaces are present;
  //     a chunk carrying a SUBSET leaves the others untouched (the store upserts, never
  //     replaces). bps is per-interface and matched by name against the prior sample, so it
  //     is computed correctly across chunked calls regardless of which chunk a port rode in.
  //   * lte / neighbors / mac_hosts are independently upserted only when present (mac_hosts
  //     null still means "keep previous"), so a chunk omitting any of them loses no data.
  // A single full payload (no partial flag, system block present) keeps the EXACT prior
  // behaviour — has_core is true, so this is byte-for-byte the original code path.
  const hasCore = payload.has_core !== false; // default true unless normalize flagged a detail chunk

  if (hasCore) {
    // 8. one logical transaction: upsert state + neighbors + lte + (mac_hosts) + history.
    //
    // NUMERIC COERCION (defence in depth): telemetry.normalize() already coerces every health
    // numeric via transform.parseNum, but the agent emits some of these as QUOTED strings
    // ('41.5') and absent values as the literal string 'null', while device_state's columns are
    // numeric (int/bigint/numeric). Re-coerce here through transform.parseNum so the stored
    // device_state is ALWAYS number|null regardless of which layer fed `payload` ('null' -> null,
    // '41.5' -> 41.5), and a stray string can never slip into a numeric column.
    const num = transform.parseNum;
    const deviceState = {
      status: 'online',
      uptime_s: parseRosUptime(payload.uptime),
      cpu_load: num(payload.cpu_load),
      free_memory: num(payload.free_memory),
      total_memory: num(payload.total_memory),
      free_hdd: num(payload.free_hdd),
      temperature: num(payload.temperature),
      voltage: num(payload.voltage),
      public_ip: payload.public_ip,
      ros_version: payload.ros_version,
      firmware: payload.firmware_current,
      pppoe_running: payload.pppoe_running,
      ppp_sessions: num(payload.ppp_sessions),
      dhcp_leases: num(payload.dhcp_leases),
      cpu_temperature: num(payload.cpu_temperature),
      board_temperature: num(payload.board_temperature),
      fan1_speed: num(payload.fan1_speed),
      write_sect_total: num(payload.write_sect_total),
      firmware_current: payload.firmware_current,
      firmware_upgrade: payload.firmware_upgrade,
      ntp_synced: payload.ntp_synced,
      // Single-number signal for the bounded overview grid (schema device_state.lte_signal,
      // RSRP/dBm). Mirrors the richer lte_state row; null when no SIM or no RSRP this tick.
      lte_signal: lteRow && lteRow.rsrp != null ? Math.round(lteRow.rsrp) : null,
      last_seen_at: ts,
      raw,
    };
    await store.upsertDeviceState(device.id, deviceState);
  } else if (typeof store.touchDeviceState === 'function') {
    // DETAIL chunk: don't clobber the system columns; just keep the device 'online'. Guarded
    // so a store predating touchDeviceState still loads (it simply won't bump last_seen here).
    await store.touchDeviceState(device.id, ts);
  }

  await store.upsertInterfaceStates(device.id, ifaceRows);
  if (lteRow) await store.upsertLteState(device.id, lteRow);
  await store.upsertNeighbors(device.id, payload.neighbors || []);
  if (macHostRows !== null) await store.upsertMacHosts(device.id, macHostRows);

  // Metrics history is a snapshot of the system block — only meaningful for a CORE chunk.
  // Skip it for a detail chunk so we never append an all-null metrics row that would dilute
  // the history series and the downsample/rollup averages.
  if (hasCore) {
    await store.appendMetricsHistory(device.id, ts, {
      cpu_load: payload.cpu_load,
      free_memory: payload.free_memory,
      temperature: payload.temperature,
      ppp_sessions: payload.ppp_sessions,
      conn_count: null,
    });
  }
  await store.appendInterfaceHistory(device.id, ts, ifaceHistRows);
  if (lteRow) {
    await store.appendLteHistory(device.id, ts, {
      interface: lteRow.interface,
      rsrp: lteRow.rsrp,
      rsrq: lteRow.rsrq,
      sinr: lteRow.sinr,
      rssi: lteRow.rssi,
      cell_id: lteRow.cell_id,
    });
  }

  // 9. compute poll_interval_s — fast while poll_until is in the future, else default.
  const pollUntilMs = toMs(device.poll_until);
  let pollIntervalS = config.defaultPollS;
  if (pollUntilMs !== null && pollUntilMs > nowMs()) {
    pollIntervalS = config.fastPollS;
  }

  // 10. pending approved config job for this device (or its tag).
  let job = null;
  const pending = await store.getPendingConfigJob(device.id);
  if (pending) {
    job = {
      id: pending.id,
      sha256: pending.rsc_sha256,
      url: `${config.publicBaseUrl}/config/${pending.id}.rsc`,
      confirm_window_s: pending.confirm_window_s,
    };
  }

  // 10b. AFFIRMATIVE confirm signal. When the operator has confirmed a just-applied change
  // (job moved to status='applied'), surface its id so the agent cancels its dead-man's
  // switch rollback. This is the ONLY signal that cancels rollback — the agent must never
  // treat the mere ABSENCE of a job as confirmation (a transient/garbled telemetry response
  // after a half-broken WAN change would otherwise look like a confirm). Guarded so stores
  // that predate this method still load.
  let confirm = null;
  if (typeof store.getConfirmedJob === 'function') {
    const confirmed = await store.getConfirmedJob(device.id);
    if (confirmed && confirmed.id) confirm = confirmed.id;
  }

  // 11. respond with the documented control shape. agent_version is the CURRENT
  // server-side script version (so a device on an older version self-updates via the
  // bootstrap); fall back to config then to the device's recorded version.
  const current = await store.getCurrentAgentScript();
  const agentVersion =
    current && current.version != null
      ? current.version
      : config.agentVersion != null
        ? config.agentVersion
        : device.agent_version != null
          ? device.agent_version
          : null;

  const response = {
    ok: true,
    poll_interval_s: pollIntervalS,
    agent_version: agentVersion,
    job,
  };
  // Only include "confirm" when there IS an affirmative server confirmation, so the agent's
  // string-extracting parser never finds a spurious key.
  if (confirm) response.confirm = confirm;
  return json(res, 200, response);
}

// ── GET /agent/script?serial= ────────────────────────────────────────
async function agentScript(ctx) {
  const { res, store, config, device } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });

  let scriptText = null;
  const current = await store.getCurrentAgentScript();
  if (current && current.rsc_text) {
    scriptText = current.rsc_text;
  } else {
    // Fallback to the bundled agent script file.
    try {
      scriptText = require('node:fs').readFileSync(config.agentScriptPath, 'utf8');
    } catch (e) {
      scriptText = null;
    }
  }
  if (scriptText == null) return json(res, 404, { ok: false, error: 'no agent script' });
  return text(res, 200, scriptText, { 'content-type': 'text/plain' });
}

// ── GET /config/pending?serial= ──────────────────────────────────────
async function configPending(ctx) {
  const { res, store, config, device } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });

  const pending = await store.getPendingConfigJob(device.id);
  if (!pending) {
    ctx.res.writeHead(204);
    return ctx.res.end();
  }
  return json(res, 200, {
    id: pending.id,
    sha256: pending.rsc_sha256,
    url: `${config.publicBaseUrl}/config/${pending.id}.rsc`,
    confirm_window_s: pending.confirm_window_s,
  });
}

// ── GET /config/:id.rsc ──────────────────────────────────────────────
// Serve the job's rsc_text only if the job targets THIS device; checksum in header.
async function configScript(ctx) {
  const { res, store, log, device, params } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });

  const jobId = params.id;
  const job = await store.getConfigJobForFetch(jobId, device.id);
  if (!job) return json(res, 404, { ok: false, error: 'not found' });

  // Advance the job to 'fetched' (RUNBOOK-config-push §2.3): the device has now pulled the
  // bytes, so getPendingConfigJob stops re-offering it on every subsequent tick (which would
  // otherwise let a device re-import the same change repeatedly), and the operator UI can
  // distinguish pending vs in-flight. Best-effort: serving the bytes is the contract, so a
  // transition failure must not turn a successful fetch into an error to the device.
  try {
    await store.markConfigJob(jobId, 'fetched');
  } catch (e) {
    log.warn('config/script: markConfigJob(fetched) failed', { device: device.id });
  }

  return text(res, 200, job.rsc_text, {
    'content-type': 'text/plain',
    'x-vigilant-sha256': job.rsc_sha256,
  });
}

// ── POST /config/result ──────────────────────────────────────────────
async function configResult(ctx) {
  const { res, store, log, device, body } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });

  let parsed;
  try {
    parsed = JSON.parse(body || '');
  } catch (e) {
    log.warn('config/result: bad json', { device: device.id });
    return json(res, 400, { ok: false, error: 'bad json' });
  }

  const jobId = parsed && parsed.job_id;
  const status = parsed && parsed.status;
  if (!jobId || !status) {
    return json(res, 400, { ok: false, error: 'job_id and status required' });
  }

  // Validate the device-reported status against the set a device may legitimately report,
  // BEFORE it reaches the DB. config_jobs.status carries a CHECK constraint; an unknown
  // value would otherwise violate it and surface as a 500 — a malformed body from one
  // device must never 500 the service (contract non-negotiable: fail safe on bad input).
  if (!DEVICE_REPORTABLE_STATUSES.has(status)) {
    log.warn('config/result: invalid status', { device: device.id });
    return json(res, 400, { ok: false, error: 'invalid status' });
  }

  // The job must target this device — getConfigJobForFetch verifies ownership.
  const job = await store.getConfigJobForFetch(jobId, device.id);
  if (!job) return json(res, 404, { ok: false, error: 'not found' });

  await store.recordConfigResult(jobId, status, parsed.result_log || null, parsed.export || null);
  return json(res, 200, { ok: true });
}

// ── POST /enroll (admin) ─────────────────────────────────────────────
// Create a device + per-device bearer token. Returns {token, bootstrap}; bootstrap is
// the two :global lines the router pastes once. We store only sha256(token), never the
// raw token.
async function enroll(ctx) {
  const { res, store, config, log, body } = ctx;

  let parsed;
  try {
    parsed = JSON.parse(body || '');
  } catch (e) {
    log.warn('enroll: bad json');
    return json(res, 400, { ok: false, error: 'bad json' });
  }

  const serial = parsed && parsed.serial;
  if (!serial || typeof serial !== 'string') {
    return json(res, 400, { ok: false, error: 'serial required' });
  }

  const device = await store.createDevice({
    serial,
    site_name: parsed.site_name || null,
    customer: parsed.customer || null,
    wan_type: parsed.wan_type || 'unknown',
    tags: Array.isArray(parsed.tags) ? parsed.tags : [],
  });

  // Generate a random opaque bearer; store only its sha256 hash.
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await store.setDeviceToken(device.id, tokenHash);

  // Build the FULL, reboot-safe install block from the bootstrap.rsc template (single
  // source of truth — same file the agent docs ship), substituting the real URL + token.
  // Falls back to the minimal two-liner if the template can't be read.
  let install;
  try {
    const fs = require('node:fs');
    const path = require('node:path');
    const dir = path.dirname(config.agentScriptPath || './agent/vigilant-agent.rsc');
    const tmpl = fs.readFileSync(path.join(dir, 'bootstrap.rsc'), 'utf8');
    install = tmpl
      .split('<VIGILANT_URL>').join(config.publicBaseUrl)
      .split('<VIGILANT_TOKEN>').join(token);
  } catch (e) {
    install =
      `:global vigilantUrl "${config.publicBaseUrl}"\n` +
      `:global vigilantToken "${token}"`;
    log.warn('enroll: bootstrap template unreadable, returned minimal snippet', { msg: e && e.message });
  }

  log.info('enroll: device created', { serial });
  // `bootstrap` kept as an alias of `install` for backward compatibility.
  return json(res, 200, { token, serial, install, bootstrap: install });
}

// ── GET /fleet (admin) ───────────────────────────────────────────────
async function fleet(ctx) {
  const { res, store } = ctx;
  const rows = await store.getFleet();
  return json(res, 200, { devices: rows || [] });
}

// ── GET /devices/:serial (admin) ─────────────────────────────────────
async function deviceDetail(ctx) {
  const { res, store, params } = ctx;
  const detail = await store.getDeviceDetail(params.serial);
  if (!detail) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, detail);
}

// ── GET /devices/:serial/history?window=1h (admin) ───────────────────
// Time-series for the dashboard throughput/health charts. Returns device-level metric
// points (cpu/memory/temperature/ppp) and per-interface rx/tx bps series, both
// time-ascending, for the requested window. 404 when the serial is unknown so the UI can
// distinguish a typo'd/deleted device from a device with no history yet.
const HISTORY_WINDOWS = {
  '1h': 3600,
  '6h': 6 * 3600,
  '24h': 24 * 3600,
  '7d': 7 * 24 * 3600,
};

async function deviceHistory(ctx) {
  const { res, store, query, params } = ctx;

  // Validate the window; default to 1h on anything unrecognised (fail soft — a bad query
  // param should still return a useful chart, not an error).
  const requested = query && query.get('window');
  const windowKey = Object.prototype.hasOwnProperty.call(HISTORY_WINDOWS, requested)
    ? requested
    : '1h';
  const windowSeconds = HISTORY_WINDOWS[windowKey];

  // Prefer the single combined store reader getDeviceHistory(serial, windowSeconds) (the
  // HISTORY API contract method): it returns null for an unknown serial, does its own
  // ts >= now()-window filtering, and (pg) caps the row count. Fall back to getDeviceDetail
  // for existence + the split getMetricsHistory/getInterfaceHistory readers only when a store
  // predates getDeviceHistory, so the route never 500s on an older store.
  if (typeof store.getDeviceHistory === 'function') {
    const hist = await store.getDeviceHistory(params.serial, windowSeconds);
    if (!hist) return json(res, 404, { ok: false, error: 'not found' });
    return json(res, 200, {
      serial: hist.serial != null ? hist.serial : params.serial,
      window: windowKey,
      metrics: hist.metrics || [],
      interfaces: hist.interfaces || [],
    });
  }

  // ── fallback path (store predating getDeviceHistory) ──
  const sinceMs = Date.now() - windowSeconds * 1000;
  // 404 if the serial is unknown (mirrors deviceDetail). getDeviceDetail is the cheapest
  // existence check that both stores already implement.
  const detail = await store.getDeviceDetail(params.serial);
  if (!detail) return json(res, 404, { ok: false, error: 'not found' });

  const metrics =
    typeof store.getMetricsHistory === 'function'
      ? await store.getMetricsHistory(params.serial, sinceMs)
      : [];
  const interfaces =
    typeof store.getInterfaceHistory === 'function'
      ? await store.getInterfaceHistory(params.serial, sinceMs)
      : [];

  return json(res, 200, {
    serial: params.serial,
    window: windowKey,
    metrics: metrics || [],
    interfaces: interfaces || [],
  });
}

// ── GET /oui/:mac (admin) ────────────────────────────────────────────
// Resolve a MAC's OUI to a vendor for the dashboard's neighbours / mac_hosts enrichment.
// Tiered: seed -> in-process cache -> external API (prefix only). Never 500s — a clearly
// invalid mac is 400, everything else (incl. an unreachable API) returns the contract shape
// with vendor:null source:'none'. The :mac may be colon/hyphen/dot-separated or bare hex.
async function ouiLookup(ctx) {
  const { res, params } = ctx;
  const raw = params && params.mac;

  // A clearly-invalid MAC has no resolvable 3-octet OUI prefix -> 400 (not a server fault).
  if (oui.ouiKey(raw) === null) {
    return json(res, 400, { ok: false, error: 'invalid mac' });
  }

  // resolveVendor never throws; it returns the full contract shape directly.
  const result = await oui.resolveVendor(raw);
  return json(res, 200, {
    mac: result.mac,
    oui: result.oui,
    vendor: result.vendor,
    source: result.source,
  });
}

// ── admin config-push management (author + two-person approve) ───────
// Operator-facing side of the review-gated config push (docs/RUNBOOK-config-push.md): list a
// device's jobs, author a DRAFT, approve it (two-person), or cancel a not-yet-picked-up job.
// None of these touch a router — a device only ever PULLS an approved job on its own tick. All
// are admin-token gated by the server, and every state change is written to audit_log.
const CONFIG_JOB_KINDS = new Set(['snippet', 'full']);

// GET /devices/:serial/config-jobs — recent jobs targeting this device (newest first).
async function configJobsList(ctx) {
  const { res, store, params } = ctx;
  const device = await store.getDeviceBySerial(params.serial);
  if (!device) return json(res, 404, { ok: false, error: 'not found' });
  const jobs =
    typeof store.listConfigJobs === 'function' ? await store.listConfigJobs(device.id, 50) : [];
  return json(res, 200, { ok: true, serial: device.serial, jobs: jobs || [] });
}

// POST /devices/:serial/config-jobs — author a DRAFT job. A draft is NEVER served to a device;
// it must be approved by a second operator first (configJobApprove).
async function configJobCreate(ctx) {
  const { res, store, log, params, body } = ctx;
  const device = await store.getDeviceBySerial(params.serial);
  if (!device) return json(res, 404, { ok: false, error: 'not found' });

  let parsed;
  try {
    parsed = JSON.parse(body || '');
  } catch (e) {
    return json(res, 400, { ok: false, error: 'bad json' });
  }

  const rscText = parsed && typeof parsed.rsc_text === 'string' ? parsed.rsc_text : '';
  const createdBy =
    parsed && typeof parsed.created_by === 'string' ? parsed.created_by.trim() : '';
  const kind = parsed && parsed.kind ? String(parsed.kind) : 'snippet';
  if (!rscText.trim()) return json(res, 400, { ok: false, error: 'rsc_text required' });
  if (!createdBy) return json(res, 400, { ok: false, error: 'created_by required' });
  if (!CONFIG_JOB_KINDS.has(kind)) return json(res, 400, { ok: false, error: 'invalid kind' });

  if (typeof store.createConfigJob !== 'function') {
    return json(res, 501, { ok: false, error: 'config push not supported by this store' });
  }

  // Clamp the dead-man confirm window to a 30s floor so an operator can't disarm the auto-
  // rollback by setting it to 0. Default 300s (RUNBOOK §2.1).
  let confirmWindow = transform.parseNum(parsed && parsed.confirm_window_s);
  confirmWindow = confirmWindow == null ? 300 : Math.max(30, Math.round(confirmWindow));

  const job = await store.createConfigJob({
    device_id: device.id,
    kind,
    rsc_text: rscText,
    confirm_window_s: confirmWindow,
    is_canary: !!(parsed && parsed.is_canary === true),
    created_by: createdBy,
  });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(
      createdBy,
      'config.draft',
      device.serial,
      `job=${job.id} kind=${kind} sha=${job.rsc_sha256}`
    );
  }
  log.info('config: draft created', { serial: device.serial, job: job.id });
  return json(res, 201, { ok: true, job });
}

// POST /config-jobs/:id/approve — second-person approval. Enforces the two-person rule
// (approver must differ from the author) and that the job is still a DRAFT.
async function configJobApprove(ctx) {
  const { res, store, log, params, body } = ctx;
  let parsed;
  try {
    parsed = JSON.parse(body || '');
  } catch (e) {
    return json(res, 400, { ok: false, error: 'bad json' });
  }
  const approvedBy =
    parsed && typeof parsed.approved_by === 'string' ? parsed.approved_by.trim() : '';
  if (!approvedBy) return json(res, 400, { ok: false, error: 'approved_by required' });

  if (typeof store.getConfigJob !== 'function' || typeof store.approveConfigJob !== 'function') {
    return json(res, 501, { ok: false, error: 'config push not supported by this store' });
  }
  const job = await store.getConfigJob(params.id);
  if (!job) return json(res, 404, { ok: false, error: 'not found' });
  if (job.status !== 'draft') {
    return json(res, 409, { ok: false, error: `job is '${job.status}', not 'draft'` });
  }
  // Two-person rule (RUNBOOK §0): the approver must not be the author.
  if (job.created_by && approvedBy.toLowerCase() === String(job.created_by).toLowerCase()) {
    return json(res, 409, { ok: false, error: 'two-person rule: approver must differ from author' });
  }
  const updated = await store.approveConfigJob(params.id, approvedBy);
  if (!updated) return json(res, 409, { ok: false, error: 'could not approve (status changed?)' });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(approvedBy, 'config.approve', null, `job=${params.id} author=${job.created_by}`);
  }
  log.info('config: job approved', { job: params.id });
  return json(res, 200, { ok: true, job: updated });
}

// POST /config-jobs/:id/cancel — cancel a draft or a not-yet-picked-up approved job.
async function configJobCancel(ctx) {
  const { res, store, log, params, body } = ctx;
  let parsed = {};
  try {
    parsed = body ? JSON.parse(body) : {};
  } catch (e) {
    parsed = {};
  }
  const actor =
    parsed && typeof parsed.actor === 'string' && parsed.actor.trim() ? parsed.actor.trim() : 'operator';

  if (typeof store.getConfigJob !== 'function' || typeof store.cancelConfigJob !== 'function') {
    return json(res, 501, { ok: false, error: 'config push not supported by this store' });
  }
  const job = await store.getConfigJob(params.id);
  if (!job) return json(res, 404, { ok: false, error: 'not found' });
  if (job.status !== 'draft' && job.status !== 'approved') {
    return json(res, 409, { ok: false, error: `job is '${job.status}', cannot cancel` });
  }
  const updated = await store.cancelConfigJob(params.id);
  if (!updated) return json(res, 409, { ok: false, error: 'could not cancel (status changed?)' });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(actor, 'config.cancel', null, `job=${params.id}`);
  }
  log.info('config: job cancelled', { job: params.id });
  return json(res, 200, { ok: true, job: updated });
}

// ── active speedtest (server-timed; HTTP to the Vigilant server) ─────
// An operator requests a test (admin route); the DEVICE pulls it (GET /speedtest/pending),
// downloads bytes_down from GET /speedtest/down and uploads bytes_up to POST /speedtest/up.
// The SERVER times each transfer (wall-clock to stream the bytes ≈ throughput) and stores
// down_bps/up_bps — so the agent needs no sub-second clock. ⚠️ An active test deliberately
// saturates the WAN; it is operator-gated + audit-logged and capped server-side.
const SPEEDTEST_MAX_BYTES = 64 * 1024 * 1024; // hard cap per leg (defence in depth)
const SPEEDTEST_CHUNK = 64 * 1024;
const SPEEDTEST_ZEROS = Buffer.alloc(SPEEDTEST_CHUNK);

// GET /speedtest/pending (device) — hand the device its next pending test (and mark it running
// so it isn't re-offered every tick). 200 with {job} when there is one, else 200 {ok:true}.
async function speedtestPending(ctx) {
  const { res, store, config, device } = ctx;
  if (typeof store.getPendingSpeedtestJob !== 'function') return json(res, 200, { ok: true });
  const job = await store.getPendingSpeedtestJob(device.id);
  if (!job) return json(res, 200, { ok: true });
  await store.markSpeedtestRunning(job.id);
  const base = config.publicBaseUrl || '';
  return json(res, 200, {
    ok: true,
    job: {
      id: job.id,
      bytes_down: job.bytes_down,
      bytes_up: job.bytes_up,
      down_url: `${base}/speedtest/down?job=${job.id}&bytes=${job.bytes_down}`,
      up_url: `${base}/speedtest/up?job=${job.id}`,
    },
  });
}

// GET /speedtest/down?job=&bytes= (device) — stream N zero bytes with backpressure; time from
// first write to flush and store down_bps. Honours backpressure so send time ≈ the device's
// receive rate (true download throughput) for payloads larger than the socket buffer.
async function speedtestDown(ctx) {
  const { res, store, device, query } = ctx;
  const jobId = query.get('job');
  const job = jobId && typeof store.getSpeedtestJob === 'function' ? await store.getSpeedtestJob(jobId) : null;
  if (!job || job.device_id !== device.id) return json(res, 404, { ok: false, error: 'not found' });
  let n = parseInt(query.get('bytes') || String(job.bytes_down || 0), 10);
  if (!Number.isFinite(n) || n < 0) n = 0;
  n = Math.min(SPEEDTEST_MAX_BYTES, n);

  res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(n), 'cache-control': 'no-store' });
  let sent = 0;
  const t0 = process.hrtime.bigint();
  res.on('finish', () => {
    const secs = Number(process.hrtime.bigint() - t0) / 1e9;
    const bps = secs > 0 ? Math.round((n * 8) / secs) : null;
    Promise.resolve(store.recordSpeedtestResult(jobId, { down_bps: bps })).catch(() => {});
  });
  const pump = () => {
    while (sent < n) {
      const len = Math.min(SPEEDTEST_CHUNK, n - sent);
      const buf = len === SPEEDTEST_CHUNK ? SPEEDTEST_ZEROS : SPEEDTEST_ZEROS.subarray(0, len);
      sent += len;
      if (!res.write(buf)) { res.once('drain', pump); return; }
    }
    res.end();
  };
  pump();
}

// POST /speedtest/up?job= (device) — consume + discard the body, counting bytes and timing from
// the first byte; store up_bps and mark the job done. Streamed (server.js does NOT pre-buffer
// this route) so timing reflects the device's upload rate.
async function speedtestUp(ctx) {
  const { req, res, store, device, query } = ctx;
  const jobId = query.get('job');
  const job = jobId && typeof store.getSpeedtestJob === 'function' ? await store.getSpeedtestJob(jobId) : null;
  if (!job || job.device_id !== device.id) return json(res, 404, { ok: false, error: 'not found' });
  let bytes = 0;
  let t0 = null;
  req.on('data', (c) => { if (t0 === null) t0 = process.hrtime.bigint(); bytes += c.length; });
  req.on('end', () => {
    const secs = t0 !== null ? Number(process.hrtime.bigint() - t0) / 1e9 : 0;
    const bps = secs > 0 ? Math.round((bytes * 8) / secs) : null;
    Promise.resolve(store.recordSpeedtestResult(jobId, { up_bps: bps, status: 'done', result_log: 'down+up measured' })).catch(() => {});
    json(res, 200, { ok: true, bytes });
  });
  req.on('error', () => { try { json(res, 400, { ok: false, error: 'upload error' }); } catch (e) { /* sent */ } });
}

// POST /speedtest/result (device) — optional finaliser the agent posts after its run, e.g. to
// mark the job failed (download error) or done when no upload leg ran. Body {job_id,status,result_log}.
async function speedtestResult(ctx) {
  const { res, store, device, body } = ctx;
  let p;
  try { p = JSON.parse(body || ''); } catch (e) { return json(res, 400, { ok: false, error: 'bad json' }); }
  const jobId = p && p.job_id;
  if (!jobId) return json(res, 400, { ok: false, error: 'job_id required' });
  const job = typeof store.getSpeedtestJob === 'function' ? await store.getSpeedtestJob(jobId) : null;
  if (!job || job.device_id !== device.id) return json(res, 404, { ok: false, error: 'not found' });
  const status = p.status === 'failed' ? 'failed' : 'done';
  await store.recordSpeedtestResult(jobId, { status, result_log: p.result_log != null ? p.result_log : null });
  return json(res, 200, { ok: true });
}

// POST /devices/:serial/speedtests (admin) — request a test. Caps byte counts server-side.
async function speedtestCreate(ctx) {
  const { res, store, log, params, body } = ctx;
  const device = await store.getDeviceBySerial(params.serial);
  if (!device) return json(res, 404, { ok: false, error: 'not found' });
  let p = {};
  try { p = body ? JSON.parse(body) : {}; } catch (e) { return json(res, 400, { ok: false, error: 'bad json' }); }
  const by = p && typeof p.requested_by === 'string' ? p.requested_by.trim() : '';
  if (!by) return json(res, 400, { ok: false, error: 'requested_by required' });
  if (typeof store.createSpeedtestJob !== 'function') return json(res, 501, { ok: false, error: 'speedtest not supported by this store' });
  const num = transform.parseNum;
  let bd = num(p.bytes_down); bd = bd == null ? 26214400 : Math.max(1048576, Math.min(SPEEDTEST_MAX_BYTES, Math.round(bd)));
  let bu = num(p.bytes_up); bu = bu == null ? 8388608 : Math.max(0, Math.min(SPEEDTEST_MAX_BYTES, Math.round(bu)));
  const job = await store.createSpeedtestJob({ device_id: device.id, bytes_down: bd, bytes_up: bu, requested_by: by });
  if (typeof store.appendAudit === 'function') await store.appendAudit(by, 'speedtest.request', device.serial, `job=${job.id} down=${bd} up=${bu}`);
  log.info('speedtest: requested', { serial: device.serial, job: job.id });
  return json(res, 201, { ok: true, job });
}

// GET /devices/:serial/speedtests (admin) — recent tests for this device.
async function speedtestList(ctx) {
  const { res, store, params } = ctx;
  const device = await store.getDeviceBySerial(params.serial);
  if (!device) return json(res, 404, { ok: false, error: 'not found' });
  const jobs = typeof store.listSpeedtestJobs === 'function' ? await store.listSpeedtestJobs(device.id, 20) : [];
  return json(res, 200, { ok: true, serial: device.serial, jobs: jobs || [] });
}

module.exports = {
  healthz,
  adminUi,
  telemetry: telemetryIngest,
  agentScript,
  configPending,
  configScript,
  configResult,
  enroll,
  fleet,
  deviceDetail,
  deviceHistory,
  ouiLookup,
  configJobsList,
  configJobCreate,
  configJobApprove,
  configJobCancel,
  speedtestPending,
  speedtestDown,
  speedtestUp,
  speedtestResult,
  speedtestCreate,
  speedtestList,
};
