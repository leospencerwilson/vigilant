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

  // 8. one logical transaction: upsert state + neighbors + lte + (mac_hosts) + history.
  const deviceState = {
    status: 'online',
    uptime_s: parseRosUptime(payload.uptime),
    cpu_load: payload.cpu_load,
    free_memory: payload.free_memory,
    total_memory: payload.total_memory,
    free_hdd: payload.free_hdd,
    temperature: payload.temperature,
    voltage: payload.voltage,
    public_ip: payload.public_ip,
    ros_version: payload.ros_version,
    firmware: payload.firmware_current,
    pppoe_running: payload.pppoe_running,
    ppp_sessions: payload.ppp_sessions,
    dhcp_leases: payload.dhcp_leases,
    cpu_temperature: payload.cpu_temperature,
    board_temperature: payload.board_temperature,
    fan1_speed: payload.fan1_speed,
    write_sect_total: payload.write_sect_total,
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
  await store.upsertInterfaceStates(device.id, ifaceRows);
  if (lteRow) await store.upsertLteState(device.id, lteRow);
  await store.upsertNeighbors(device.id, payload.neighbors || []);
  if (macHostRows !== null) await store.upsertMacHosts(device.id, macHostRows);

  await store.appendMetricsHistory(device.id, ts, {
    cpu_load: payload.cpu_load,
    free_memory: payload.free_memory,
    temperature: payload.temperature,
    ppp_sessions: payload.ppp_sessions,
    conn_count: null,
  });
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

module.exports = {
  healthz,
  telemetry: telemetryIngest,
  agentScript,
  configPending,
  configScript,
  configResult,
  enroll,
  fleet,
  deviceDetail,
};
