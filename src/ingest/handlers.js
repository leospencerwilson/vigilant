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
// The one validator + the one copy of the per-thin-client defaults. Both the save path and
// the telemetry push go through this module so the UI, the server and the Pi cannot drift.
const { validateCounterSettings, effectiveCounterSettings } = require('../shared/counterSettings');
// The capability the browser presents to the noVNC bridge on the hub. Mirrors
// /etc/wcn/wcn_vnc_token.py there — change one, change both.
const { mintSupportToken } = require('../shared/supportToken');
const notify = require('../worker/notify');
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
  // Stamp the real build SHA into the bottom-left badge when the platform provides it
  // (Coolify/CI set one of these), so the badge tracks what's actually deployed. Falls back
  // to the literal short SHA baked into admin.html. Replaces the 7-char default everywhere it
  // appears (badge text + the GitHub commit link).
  const sha = (process.env.BUILD_SHA || process.env.SOURCE_COMMIT || process.env.COMMIT_SHA || '').trim();
  const html = sha ? _adminHtml.split('40d2d3f').join(sha.slice(0, 7)) : _adminHtml;
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

// ── POST /realtime/config (admin) ────────────────────────────────────
// The dashboard is gated by ENROLL_TOKEN, not a Supabase session — so to use Supabase
// Realtime it asks here (after the server has already verified the admin token) for the bits
// it needs: the Supabase URL, the anon key, and a SHORT-LIVED `authenticated` JWT the ingest
// mints by signing with SUPABASE_JWT_SECRET. RLS then lets that token read; anon gets nothing.
// 501 when Realtime isn't configured (no URL/anon/secret) → the dashboard stays on polling.
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Mint an HS256 JWT { role:'authenticated', aud:'authenticated', sub, iat, exp } — the minimal
// claim set PostgREST/Realtime need to apply the `authenticated` RLS policies. ttlS default 1h.
function mintSupabaseJwt(secret, ttlS) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    role: 'authenticated',
    aud: 'authenticated',
    sub: crypto.randomUUID(),
    iat: now,
    exp: now + (ttlS || 3600),
  };
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', secret).update(signingInput).digest());
  return { token: signingInput + '.' + sig, expiresAt: payload.exp };
}

async function realtimeConfig(ctx) {
  const { res, config } = ctx;
  if (!config.supabaseUrl || !config.supabaseAnonKey || !config.supabaseJwtSecret) {
    return json(res, 501, { ok: false, error: 'realtime not configured' });
  }
  const minted = mintSupabaseJwt(config.supabaseJwtSecret, 3600);
  return json(res, 200, {
    ok: true,
    url: config.supabaseUrl,
    anonKey: config.supabaseAnonKey,
    token: minted.token,
    expiresAt: minted.expiresAt,
    schema: 'vigilant',
  });
}

// Postgres cannot store a NUL byte in `text` OR a \u0000 escape in `jsonb` — the INSERT
// throws "unsupported Unicode escape sequence". A counter Pi ships kiosk log lines verbatim
// and FreeRDP writes raw control bytes into that log (MEASURED 2026-08-19: 29,845 NUL-bearing
// lines on the pilot), so telemetry POSTs intermittently carried one and the whole tick died
// at the DB — taking last_seen_at with it, so a healthy counter read as "7 minutes ago".
//
// Strip at the boundary rather than at each write: the same body reaches device_state.raw
// (jsonb), device_state.recent_logs (jsonb) and device_logs.message (text), and a guard on
// only one of them just moves the failure. A NUL is never meaningful payload — it is console
// noise — so dropping it loses nothing a reader would want.
function stripNuls(v) {
  if (typeof v === 'string') return v.indexOf('\u0000') === -1 ? v : v.replace(/\u0000/g, '');
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) v[i] = stripNuls(v[i]);
    return v;
  }
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) v[k] = stripNuls(v[k]);
    return v;
  }
  return v;
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
    raw = stripNuls(JSON.parse(body || ''));
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

  // Keep devices.identity fresh from telemetry. The agent reports /system identity on every
  // tick but nothing ever persisted it, so the column was empty fleet-wide (0/363) and
  // useless for grouping or smart tags.
  //
  // Write ONLY when the value actually changes: the fleet posts several hundred times a
  // second, so an unconditional UPDATE here would add a write per tick per device — the
  // exact kind of per-tick cost that had this service saturated. Identity changes ~never.
  const reportedIdentity = typeof payload.identity === 'string' ? payload.identity.trim() : '';
  if (reportedIdentity && reportedIdentity !== (device.identity || '') && typeof store.setDeviceIdentity === 'function') {
    try {
      await store.setDeviceIdentity(device.id, reportedIdentity);
    } catch (err) {
      // Never fail an ingest over a metadata refresh.
      log.warn('telemetry: identity refresh failed', { device: device.id, msg: err && err.message });
    }
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
      hostname: h.hostname,   // DHCP host-name — the real device identity
      comment: h.comment,     // operator-labelled DHCP lease comment, if any
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
      // Same fallback as the history append below, so the live column and the graph can
      // never disagree about a thin client's temperature.
      temperature: num(payload.temperature) != null ? num(payload.temperature) : num(payload.cpu_temperature),
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
      // Kiosk + agent log lines from a thin client (routers carry their own via device_logs).
      // Array-only: the column is a jsonb list and the UI iterates it, so a string or object
      // here would render as garbage rather than fail loudly. Bounded because this is a
      // latest-snapshot column — an agent bug that shipped thousands of lines would otherwise
      // bloat one row on every tick, forever.
      recent_logs: Array.isArray(payload.logs) ? payload.logs.slice(-200) : null,
      // Smartcard fix stack roll-up, flattened to 1/0 so an alert rule can read it (rules can
      // only see device_state COLUMNS, never raw). Deliberately null — not 0 — when the agent
      // does not report it, so an older agent or a counter that was never set up for
      // smartcards cannot raise a permanent false alarm: evaluateAlert() ignores nulls.
      smartcard_stack_ok:
        payload.smartcard_stack && typeof payload.smartcard_stack.ok === 'boolean'
          ? (payload.smartcard_stack.ok ? 1 : 0)
          : null,
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

  // WiFi config + associated stations. null = "keep previous" (a chunk that omitted them);
  // an array (incl. []) is a full snapshot that REPLACES the device's set. Guarded so a store
  // predating these methods still loads.
  if (payload.wifi != null && typeof store.upsertWifiNetworks === 'function') {
    await store.upsertWifiNetworks(device.id, payload.wifi);
  }
  if (payload.wifi_clients != null && typeof store.upsertWirelessClients === 'function') {
    await store.upsertWirelessClients(device.id, payload.wifi_clients);
  }
  // Device log lines (agent already strips its own fetch noise). Append to 30-day history.
  if (payload.logs != null && typeof store.appendDeviceLogs === 'function') {
    log.info('telemetry: logs partial', { serial: device.serial, n: Array.isArray(payload.logs) ? payload.logs.length : 0 });
    // Never let a log write decide whether this device gets a reply. MEASURED 2026-08-19: a
    // POST carrying `logs` hung >20s while the identical POST without it answered in 0.2s,
    // and because every tick ships logs the counter stopped reporting altogether and went
    // stale. A device that looks dead because of a log insert is the worst trade this
    // service makes: the reply carries the boot target, the settings and the liveness stamp,
    // and a dropped log line is invisible by comparison.
    //
    // The store now bounds the statement itself (lock_timeout/statement_timeout); this catch
    // is the second half of the same decision — if it fails anyway, log it and answer.
    try {
      await store.appendDeviceLogs(device.id, payload.logs);
    } catch (e) {
      log.warn('telemetry: log append failed, continuing', { serial: device.serial, err: String((e && e.message) || e) });
    }
  }

  // Metrics history is a snapshot of the system block — only meaningful for a CORE chunk.
  // Skip it for a detail chunk so we never append an all-null metrics row that would dilute
  // the history series and the downsample/rollup averages.
  if (hasCore) {
    await store.appendMetricsHistory(device.id, ts, {
      cpu_load: payload.cpu_load,
      free_memory: payload.free_memory,
      // Fall back to cpu_temperature. metrics_history has ONE temperature column, RouterOS
      // fills it from a board sensor, and a Pi has no board sensor - it reports only
      // cpu_temperature. Reading payload.temperature alone graphed an empty series for every
      // thin client, which looked like a broken chart rather than an unpopulated column.
      temperature: payload.temperature != null ? payload.temperature : payload.cpu_temperature,
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

  // 10c. which VM this thin client should boot into. Only counter Pis carry one, so the
  // lookup stays off the router hot path entirely. The desired target is sent on EVERY
  // tick rather than only on change: that makes it self-healing, so a launcher edited by
  // hand on the device is corrected back to what Watchman says.
  let boot = null;
  if (device.kind === 'counter-pi' && typeof store.getCounterBootDirective === 'function') {
    const want = await store.getCounterBootDirective(device.id);
    if (want && want.target) boot = { target: want.target, vmid: want.vmid };
  }

  // 10d. a one-shot service action, if the operator queued one. Collected at most once —
  // see takeCounterAction for why a surviving reboot directive would be a loop.
  let action = null;
  if (device.kind === 'counter-pi' && typeof store.takeCounterAction === 'function') {
    const taken = await store.takeCounterAction(device.id);
    if (taken && taken.action) action = taken.action;
  }

  // 10e. the EFFECTIVE per-thin-client options: the operator's stored values merged over
  // the server-side defaults. Counter Pis only, so the router hot path is untouched.
  //
  // Sent on EVERY tick rather than only on change, exactly like the boot target and for the
  // same reason: it is then self-healing, so a kiosk.conf hand-edited on the device is put
  // back to what Watchman says. The agent decides only whether the RENDERED FILE changed —
  // it must not restart a pharmacy counter's session every 30 s.
  //
  // Defaults are merged HERE, server-side, so the agent carries no default of its own and
  // cannot drift from the UI.
  //
  // The reverse direction needs no code: the agent reports what it has ACTUALLY applied as
  // `settings_applied`, and the whole raw body is already persisted to device_state.raw
  // above — counters_v surfaces it as pi_settings_applied for the UI's drift display. A
  // payload WITHOUT the key is still perfectly valid and is never rejected.
  let settings = null;
  if (device.kind === 'counter-pi' && typeof store.getCounterSettingsForDevice === 'function') {
    const row = await store.getCounterSettingsForDevice(device.id);
    settings = effectiveCounterSettings(row && row.settings);
  }

  // 10f. an open LAN-relay session, if an operator has asked for one. This is why the relay
  // needs no second poller: the directive rides the reply the Pi is already collecting.
  //
  // Sent on EVERY tick while the session is live, like the boot target — and unlike the
  // one-shot action, which is cleared on delivery. Repeating this is safe (a Pi that already
  // holds the session ignores it), whereas an at-most-once handover lost to a dropped response
  // would strand the operator for the whole TTL.
  //
  // The target is named HERE so the Pi can enforce the allowlist again from what it was given:
  // a compromised server that omits or alters it cannot make the Pi fetch something no session
  // authorised.
  let relay = null;
  if (device.kind === 'counter-pi' && typeof store.getRelayDirective === 'function') {
    const want = await store.getRelayDirective(device.id);
    if (want) {
      const lanDevices = require('../shared/lanDevices');
      relay = {
        session_id: want.session_id,
        target_ip: want.target_ip,
        target_port: want.target_port,
        // Derived from the port, not configured — 443/8443 is TLS, and these devices all ship
        // self-signed certs, which is why the agent must not verify them.
        scheme: lanDevices.schemeForPort(want.target_port),
        expires_at: want.expires_at,
      };
    }
  }

  // 10g. fleet-wide branding — one set for the whole estate, so this is a keyless read of a
  // single row (no per-site resolution exists). Counter Pis only: a router has no boot splash,
  // no console banner and no kiosk.
  //
  // Only a SHA plus the small text bodies ride here. The splash's bytes must NEVER be inlined:
  // the request that carries this reply has its whole raw body persisted to device_state.raw on
  // every tick, so an image on the telemetry path would be re-stored several hundred times a
  // minute, forever. The agent compares `sha`, and fetches GET /branding/splash with its own
  // device token only when splash_sha256 differs from what it has on disk.
  let branding = null;
  if (device.kind === 'counter-pi' && typeof store.getBranding === 'function') {
    try {
      branding = brandingDirective(await store.getBranding());
    } catch (err) {
      // A cosmetic lookup must NEVER kill a telemetry tick. This same reply carries the boot
      // target, the queued service action and the relay handover — losing those to a failed
      // branding read would cost an engineer a site visit for the sake of a logo.
      log.warn('telemetry: branding lookup failed', { device: device.id, msg: err && err.message });
      branding = null;
    }
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
  // Same reasoning as "confirm": absent rather than null, so the agent's parser cannot
  // read a spurious key.
  if (boot) response.boot = boot;
  if (action) response.action = action;
  // Counter Pis only — a router has no kiosk, and its agent parses this response with a
  // string scanner, so an irrelevant key is not free.
  if (settings) response.settings = settings;
  // Absent unless there is a live session, same reasoning as "boot" and "action".
  if (relay) response.relay = relay;
  // Absent until the estate has ANY branding configured — brandingDirective() returns null for
  // an empty record precisely so a fleet nobody has branded yet pays nothing per tick.
  if (branding) response.branding = branding;
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
  return text(res, 200, minifyAgentScript(scriptText), { 'content-type': 'text/plain' });
}

// Strip full-line comments and blank lines before serving the agent. The source carries heavy
// documentation (~half its bytes); RouterOS re-parses the whole agent every tick, and very
// large `/system script` sources are slower (and closer to platform limits) to install. We
// only drop lines that are blank or whose first non-space char is `#` (a RouterOS line
// comment) — never code lines (those never start with `#`, even ones with a trailing inline
// comment), so behaviour is unchanged. A one-line marker is prepended for provenance.
function minifyAgentScript(src) {
  if (typeof src !== 'string') return src;
  const out = [];
  for (const line of src.split('\n')) {
    const t = line.trim();
    if (t === '' || t.charAt(0) === '#') continue;
    out.push(line);
  }
  return '# vigilant-agent (comments stripped on serve)\n' + out.join('\n') + '\n';
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

// ── alert-rule CRUD (admin) — backs the Rules UI ─────────────────────
const ALERT_COMPARATORS = new Set(['>', '>=', '<', '<=', '==', 'offline']);
const NOTIFY_ON = new Set(['open', 'clear', 'both']);

function parseRuleBody(body) {
  try { return JSON.parse(body || ''); } catch (e) { return null; }
}
function validateRule(r) {
  if (!r || typeof r.name !== 'string' || !r.name.trim()) return 'name required';
  if (typeof r.metric !== 'string' || !r.metric.trim()) return 'metric required';
  if (r.comparator != null && !ALERT_COMPARATORS.has(r.comparator)) return 'invalid comparator';
  if (r.notify_on != null && !NOTIFY_ON.has(r.notify_on)) return 'invalid notify_on';
  return null;
}

async function alertRulesList(ctx) {
  const { res, store } = ctx;
  const rules = typeof store.listAlertRules === 'function' ? await store.listAlertRules() : [];
  return json(res, 200, { ok: true, rules: rules || [] });
}
// GET /alerts — recent alert history (every rule hit, open + cleared), newest first.
async function alertHistory(ctx) {
  const { res, store, query } = ctx;
  const limit = query && typeof query.get === 'function' ? query.get('limit') : undefined;
  const alerts = typeof store.listAlerts === 'function' ? await store.listAlerts(limit) : [];
  return json(res, 200, { ok: true, alerts: alerts || [] });
}
async function alertRuleCreate(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.createAlertRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const r = parseRuleBody(body);
  if (!r) return json(res, 400, { ok: false, error: 'bad json' });
  const err = validateRule(r);
  if (err) return json(res, 400, { ok: false, error: err });
  const created = await store.createAlertRule(r);
  return json(res, 201, { ok: true, rule: created });
}
async function alertRuleUpdate(ctx) {
  const { res, store, body, params } = ctx;
  if (typeof store.updateAlertRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const r = parseRuleBody(body);
  if (!r) return json(res, 400, { ok: false, error: 'bad json' });
  const err = validateRule(r);
  if (err) return json(res, 400, { ok: false, error: err });
  const updated = await store.updateAlertRule(params.id, r);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, rule: updated });
}
async function alertRuleDelete(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.deleteAlertRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const ok = await store.deleteAlertRule(params.id);
  return ok ? json(res, 200, { ok: true }) : json(res, 404, { ok: false, error: 'not found' });
}

// POST /alert-rules/test — fire a TEST notification through the channels in the body (the
// Rules form's current values), so an operator can verify email/Teams BEFORE saving. Returns
// per-channel results so the UI can show a ✓/✗ against each. Sends regardless of notify_on.
async function alertRuleTest(ctx) {
  const { res, config, body } = ctx;
  const r = parseRuleBody(body);
  if (!r) return json(res, 400, { ok: false, error: 'bad json' });
  if (!r.notify_email && !r.notify_teams_webhook) {
    return json(res, 400, { ok: false, error: 'set an email and/or Teams webhook to test' });
  }
  const transition = {
    kind: 'open',
    site_name: '(test)',
    serial: '(test)',
    value: 'test',
    detail: 'Test notification from Vigilant — this channel is wired correctly.',
    rule: {
      name: (r.name && r.name.trim()) || 'Test rule',
      severity: r.severity || 'info',
      notify_email: r.notify_email || null,
      notify_teams_webhook: r.notify_teams_webhook || null,
      notify_on: 'both',
    },
  };
  const out = await notify.dispatchAlert(transition, { config, logger: ctx.log });
  return json(res, 200, { ok: true, results: (out && out.results) || {} });
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
// POST /screen — a thin client uploads its current screen thumbnail.
// Device-authenticated with the token it already uses for telemetry; counter-pi only, because
// a router has no screen and should not be able to write image rows.
// Kept OFF the telemetry path so it never enters device_state.raw, which is stored wholesale
// and would grow by the size of an image on every single tick.
async function postScreen(ctx) {
  const { res, store, device, body, log } = ctx;
  if (!device || device.kind !== 'counter-pi') {
    return json(res, 403, { ok: false, error: 'this endpoint serves counter-pi devices only' });
  }
  let p;
  try { p = JSON.parse(body || '{}'); } catch (e) { return json(res, 400, { ok: false, error: 'invalid json' }); }
  const b64 = typeof p.image_b64 === 'string' ? p.image_b64 : '';
  // ~300 KB decoded. A thumbnail is ~8 KB; anything near this cap is a bug or an abuse, and
  // the row is overwritten per tick so an unbounded one would be paid for forever.
  if (!b64 || b64.length > 400000) {
    return json(res, 400, { ok: false, error: 'image_b64 missing or too large' });
  }
  let buf;
  try { buf = Buffer.from(b64, 'base64'); } catch (e) { return json(res, 400, { ok: false, error: 'bad base64' }); }
  // Magic-byte check: only ever store something that really is a JPEG, so the read endpoint
  // cannot be turned into a way to serve arbitrary bytes under an image content-type.
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) {
    return json(res, 400, { ok: false, error: 'not a jpeg' });
  }
  if (typeof store.upsertDeviceScreen !== 'function') {
    return json(res, 501, { ok: false, error: 'screen storage not available' });
  }
  await store.upsertDeviceScreen(device.id, {
    bytes: buf,
    width: p.width,
    height: p.height,
    mime: 'image/jpeg',
    capturedAt: p.captured_at || null,
  });
  log.info('screen: thumbnail stored', { serial: device.serial, bytes: buf.length });
  return json(res, 200, { ok: true, bytes: buf.length });
}

// GET /devices/:serial/screen — the thumbnail, as an image.
// Returns 404 when there is none, which is what lets the UI skip a view column change: it just
// asks for every row's thumbnail and renders a placeholder for the ones that 404.
async function deviceScreen(ctx) {
  const { res, store, params } = ctx;
  const dev = await store.getDeviceBySerial(params.serial);
  if (!dev) return json(res, 404, { ok: false, error: 'not found' });
  const row = typeof store.getDeviceScreen === 'function' ? await store.getDeviceScreen(dev.id) : null;
  if (!row || !row.bytes) return json(res, 404, { ok: false, error: 'no screen captured' });
  res.writeHead(200, {
    'content-type': row.mime || 'image/jpeg',
    'content-length': row.bytes.length,
    // PHI: must not sit in a proxy, a shared cache, or the browser's disk cache.
    'cache-control': 'no-store, private',
    'x-captured-at': new Date(row.captured_at).toISOString(),
    'x-screen-size': `${row.width || '?'}x${row.height || '?'}`,
  });
  return res.end(row.bytes);
}

// ════════════════════════════════════════════════════════════════════════════
// FLEET-WIDE THIN-CLIENT BRANDING
// ════════════════════════════════════════════════════════════════════════════
//
// One set of branding for EVERY thin client — boot splash, console MOTD/issue art, and the
// kiosk pre-connect line. There is no per-site override anywhere in here by decision, which is
// why nothing below takes a serial or a site code.
//
// WHAT THE AGENT CAN ACTUALLY WRITE, AND WHY THAT SHAPES THIS:
// the agent's systemd unit runs ProtectSystem=full, which mounts /etc AND /boot READ-ONLY
// inside its namespace. The unit therefore needs a surgical, OPTIONAL grant — and only for the
// three paths branding touches:
//     ReadWritePaths=-/etc/motd
//     ReadWritePaths=-/etc/issue
//     ReadWritePaths=-/usr/share/plymouth/themes/pix
// The leading "-" is load-bearing, not tidiness: a NON-optional ReadWritePaths naming a path
// that does not exist FAILS THE UNIT, and a failed unit is a dead monitoring agent restarting
// every 10 s. Pi OS Lite may not have plymouth installed at all, so a missing splash theme has
// to degrade to "no splash", never to "no agent". (Lives in agent/pi/build-image.sh and the
// live drop-in — outside this module, but it is the reason a splash push is allowed to be a
// no-op on a device and must never be treated as an error here.)
//
// AND WHAT IS NOT HERE: /boot/firmware/cmdline.txt. `quiet` and `logo.nologo` are set ONCE at
// image bake time. That file is the only one on a Pi with no remote recovery — a typo means it
// never boots, so no SSH, no agent, no tunnel, and an engineer drives to a pharmacy with an SD
// card reader. No endpoint, column or settings key below can reach it.

// Per-field caps. These are a BANDWIDTH budget, not a storage one: the text bodies ride inline
// in the telemetry reply of every thin client on every tick (~354 devices), so the whole set
// has to stay small. The splash never rides telemetry for exactly this reason — only its sha
// does, and the agent fetches the bytes once, when that sha changes.
const BRANDING_TEXT_LIMITS = {
  // /etc/motd and /etc/issue are ASCII art banners printed on a console. 4 KB is several
  // screens' worth; more than that scrolls the login prompt off the top and is a mistake.
  motd: 4096,
  issue: 4096,
  // One line on the kiosk's pre-connect screen. It is read at arm's length by a pharmacist.
  kiosk_message: 1024,
};
const BRANDING_TEXT_FIELDS = Object.keys(BRANDING_TEXT_LIMITS);

// Hard cap on a decoded splash: 2 MB. A 1080p PNG logo is tens of KB, so this is generous — it
// exists so a mis-picked camera photo cannot be pushed to 354 devices over site DSL.
const BRANDING_SPLASH_MAX_BYTES = 2 * 1024 * 1024;
// Pre-check on the base64 STRING before decoding, so a hostile body is refused without first
// materialising it as a Buffer. base64 is 4 bytes per 3, plus slack for any newlines a client
// wrapped it at.
const BRANDING_SPLASH_MAX_B64 = Math.ceil(BRANDING_SPLASH_MAX_BYTES / 3) * 4 + 4096;

// The 8-byte PNG signature. The brief's check is the first four (89 50 4E 47); we verify all
// eight because the trailing 0D 0A 1A 0A is precisely what a text-mode/CRLF-mangling transfer
// destroys — the same corruption base64-in-JSON exists to prevent. Cheap, and it turns a
// silently broken splash into a 400 at upload time.
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

// Read width/height out of a PNG's IHDR chunk. IHDR is mandated by the spec to be the FIRST
// chunk, so its layout is fixed: 8-byte signature, 4-byte length, "IHDR", then width and height
// as big-endian uint32. Returns nulls for anything that does not match rather than throwing —
// the dimensions are display metadata for the editor, not a validity gate.
function pngDimensions(buf) {
  if (!buf || buf.length < 24) return { width: null, height: null };
  if (buf.toString('ascii', 12, 16) !== 'IHDR') return { width: null, height: null };
  const width = buf.readUInt32BE(16);
  const height = buf.readUInt32BE(20);
  // A zero dimension is illegal per the spec; treat it as unknown rather than reporting 0x0.
  return { width: width > 0 ? width : null, height: height > 0 ? height : null };
}

// The operator's name for the audit trail and branding.updated_by. Same convention as the
// counter action/boot-target handlers: the UI sends it, and 'watchman' is the honest fallback
// when it does not (the admin token identifies the estate, not a person).
function brandingActor(parsed) {
  const v = parsed && typeof parsed.by === 'string' ? parsed.by.trim() : '';
  return v || 'watchman';
}

// The GET /branding response body. Built from a metadata row that does NOT carry the blob, so
// this is safe to call on any path. A null row (nothing configured yet, or the mem store)
// renders as an all-null record with splash.present false — the editor then shows empty fields
// instead of erroring, which is the correct state for a fleet that has never been branded.
function brandingShape(row) {
  const r = row || {};
  return {
    motd: r.motd != null ? r.motd : null,
    issue: r.issue != null ? r.issue : null,
    kiosk_message: r.kiosk_message != null ? r.kiosk_message : null,
    splash: {
      present: !!r.splash_sha256,
      bytes: r.splash_bytes != null ? Number(r.splash_bytes) : null,
      width: r.splash_width != null ? r.splash_width : null,
      height: r.splash_height != null ? r.splash_height : null,
      sha256: r.splash_sha256 != null ? r.splash_sha256 : null,
      updated_at: r.splash_updated_at ? new Date(r.splash_updated_at).toISOString() : null,
    },
    updated_at: r.updated_at ? new Date(r.updated_at).toISOString() : null,
    updated_by: r.updated_by != null ? r.updated_by : null,
  };
}

// The compact object carried in the telemetry reply, or null when there is nothing to say.
//
// `sha` covers the WHOLE set (all three texts plus the splash's own sha), so the agent can skip
// every branding comparison with one string equality on the overwhelming majority of ticks.
// It is derived from a JSON array, not a concatenation: JSON.stringify quotes and escapes each
// member, so "ab"+"c" and "a"+"bc" cannot collide into the same digest.
//
// A text field is null when it has never been set, and that is NOT the same as "". null means
// "no opinion — leave the device's file alone"; "" means "write it empty". Blanking a working
// /etc/issue because Watchman has never been filled in would be a regression on every device.
function brandingSha(row) {
  const r = row || {};
  const canonical = JSON.stringify([
    r.motd != null ? r.motd : null,
    r.issue != null ? r.issue : null,
    r.kiosk_message != null ? r.kiosk_message : null,
    r.splash_sha256 != null ? r.splash_sha256 : null,
  ]);
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function brandingDirective(row) {
  if (!row) return null;
  const hasAnything =
    row.motd != null || row.issue != null || row.kiosk_message != null || row.splash_sha256 != null;
  // Absent rather than null-and-empty, exactly like `relay` and `boot`: the agent parses this
  // reply with a string scanner, so a key that says nothing is not free.
  if (!hasAnything) return null;
  return {
    sha: brandingSha(row),
    motd: row.motd != null ? row.motd : null,
    issue: row.issue != null ? row.issue : null,
    kiosk_message: row.kiosk_message != null ? row.kiosk_message : null,
    // Hex or null. The ONLY splash signal on the telemetry path — the bytes are fetched
    // out-of-band from GET /branding/splash, because device_state.raw stores the whole reply's
    // sibling request wholesale on every tick and an image there would be paid for forever.
    splash_sha256: row.splash_sha256 != null ? row.splash_sha256 : null,
  };
}

// GET /branding (field) — the whole record for the Watchman editor. authField, not authAdmin:
// this is a read of cosmetic estate config, and it is the same credential the editor already
// holds for the splash preview.
async function brandingGet(ctx) {
  const { res, store } = ctx;
  if (typeof store.getBranding !== 'function') {
    return json(res, 501, { ok: false, error: 'branding storage not available' });
  }
  const row = await store.getBranding();
  return json(res, 200, { ok: true, branding: brandingShape(row) });
}

// PUT /branding (admin) — body { motd?, issue?, kiosk_message?, by? }.
// Only the keys PRESENT in the body are written, so the editor can save one field without
// having to round-trip the others (and without racing another operator's save).
async function brandingPutText(ctx) {
  const { res, store, body, log } = ctx;
  if (typeof store.updateBrandingText !== 'function') {
    return json(res, 501, { ok: false, error: 'branding storage not available' });
  }
  let p;
  try { p = JSON.parse(body || '{}'); } catch (e) { return json(res, 400, { ok: false, error: 'invalid json' }); }
  if (!p || typeof p !== 'object' || Array.isArray(p)) {
    return json(res, 400, { ok: false, error: 'body must be an object' });
  }

  const fields = {};
  for (const k of BRANDING_TEXT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(p, k)) continue;
    const v = p[k];
    // null is a first-class value here: it CLEARS the field back to "no opinion", which is what
    // makes the field's absence on the device recoverable from the UI.
    if (v === null) { fields[k] = null; continue; }
    if (typeof v !== 'string') {
      return json(res, 400, { ok: false, error: `${k} must be a string or null` });
    }
    if (v.length > BRANDING_TEXT_LIMITS[k]) {
      return json(res, 400, { ok: false, error: `${k} exceeds ${BRANDING_TEXT_LIMITS[k]} bytes` });
    }
    // Postgres `text` cannot hold a NUL byte — it would 500 on the INSERT rather than fail
    // usefully. Nothing legitimate in a console banner contains one.
    if (v.indexOf('\u0000') !== -1) {
      return json(res, 400, { ok: false, error: `${k} must not contain NUL bytes` });
    }
    fields[k] = v;
  }
  if (!Object.keys(fields).length) {
    return json(res, 400, { ok: false, error: `nothing to update (expected one of: ${BRANDING_TEXT_FIELDS.join(', ')})` });
  }

  const by = brandingActor(p);
  const row = await store.updateBrandingText(fields, by);
  if (typeof store.appendAudit === 'function') {
    // Name the fields, not their contents: a MOTD is several KB of art and the audit trail is
    // for answering "who changed the branding, when", which the field list already does.
    await store.appendAudit(by, 'branding.text', null, `fields=${Object.keys(fields).join(',')}`);
  }
  log.warn('branding: text updated', { by, fields: Object.keys(fields) });
  return json(res, 200, { ok: true, branding: brandingShape(row) });
}

// PUT /branding/splash (admin) — body { image_b64, by? }.
// base64 in JSON, not a raw binary PUT, because readBody() accumulates the request into a
// STRING: raw PNG bytes would be corrupted by that before any handler saw them. Same transport
// as POST /screen and the relay bodies, for the same reason.
async function brandingPutSplash(ctx) {
  const { res, store, body, log } = ctx;
  if (typeof store.setBrandingSplash !== 'function') {
    return json(res, 501, { ok: false, error: 'branding storage not available' });
  }
  let p;
  try { p = JSON.parse(body || '{}'); } catch (e) { return json(res, 400, { ok: false, error: 'invalid json' }); }
  const b64 = p && typeof p.image_b64 === 'string' ? p.image_b64 : '';
  if (!b64) return json(res, 400, { ok: false, error: 'image_b64 missing' });
  if (b64.length > BRANDING_SPLASH_MAX_B64) {
    return json(res, 413, { ok: false, error: `image too large (max ${BRANDING_SPLASH_MAX_BYTES} bytes decoded)` });
  }
  let buf;
  try { buf = Buffer.from(b64, 'base64'); } catch (e) { return json(res, 400, { ok: false, error: 'bad base64' }); }
  // Check the DECODED length too — the b64 pre-check above is a cheap guard, this is the cap.
  if (!buf.length) return json(res, 400, { ok: false, error: 'bad base64' });
  if (buf.length > BRANDING_SPLASH_MAX_BYTES) {
    return json(res, 413, { ok: false, error: `image too large (max ${BRANDING_SPLASH_MAX_BYTES} bytes decoded)` });
  }
  // Magic bytes: only ever store something that really is a PNG, so GET /branding/splash cannot
  // be turned into a way to serve arbitrary bytes under an image content-type — and so plymouth
  // is never handed a file it will refuse (a bad theme file shows no splash, which is invisible
  // until somebody reboots a counter).
  if (buf.length < PNG_SIGNATURE.length || !buf.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    return json(res, 400, { ok: false, error: 'not a png' });
  }

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const { width, height } = pngDimensions(buf);
  const by = brandingActor(p);
  await store.setBrandingSplash({ bytes: buf, sha256, width, height }, by);
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(by, 'branding.splash.set', null, `bytes=${buf.length} sha256=${sha256} dim=${width || '?'}x${height || '?'}`);
  }
  log.warn('branding: splash uploaded', { by, bytes: buf.length, sha256, width, height });
  return json(res, 200, { ok: true, bytes: buf.length, sha256 });
}

// DELETE /branding/splash (admin) — drop the image, keep the text. The agent sees
// splash_sha256 go null on its next tick and restores the stock theme.
async function brandingDeleteSplash(ctx) {
  const { res, store, log } = ctx;
  if (typeof store.clearBrandingSplash !== 'function') {
    return json(res, 501, { ok: false, error: 'branding storage not available' });
  }
  // A DELETE carries no body by convention, so there is no `by` to read — the actor falls back
  // to 'watchman', same as the relay's audit row.
  const by = brandingActor(null);
  await store.clearBrandingSplash(by);
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(by, 'branding.splash.clear', null, null);
  }
  log.warn('branding: splash cleared', { by });
  return json(res, 200, { ok: true });
}

// GET /branding/splash (field) — the PNG bytes.
// Serves TWO callers with one route: the editor's preview (field token) and every thin-client
// agent fetching a changed splash (its own DEVICE token). authField in server.js covers the
// first; the device case is routed there too, see the comment on the route.
async function brandingGetSplash(ctx) {
  const { req, res, store } = ctx;
  const row = typeof store.getBrandingSplash === 'function' ? await store.getBrandingSplash() : null;
  if (!row || !row.bytes) return json(res, 404, { ok: false, error: 'no splash uploaded' });
  // The content sha IS the ETag. Not PHI (it is a company logo), so unlike /devices/:serial/screen
  // this may be revalidated rather than no-store'd: 354 agents that already hold the current
  // image get a 304 instead of up to 2 MB each. no-cache (not no-store) means "you may keep it,
  // but ask every time" — so a splash change still reaches a device on its next fetch.
  const etag = `"${row.splash_sha256 || ''}"`;
  const inm = req.headers['if-none-match'];
  if (row.splash_sha256 && inm && String(inm).split(',').some((t) => t.trim() === etag)) {
    res.writeHead(304, { etag, 'cache-control': 'no-cache' });
    return res.end();
  }
  res.writeHead(200, {
    'content-type': 'image/png',
    'content-length': row.bytes.length,
    'cache-control': 'no-cache',
    etag,
    'x-splash-sha256': row.splash_sha256 || '',
    'x-splash-size': `${row.splash_width || '?'}x${row.splash_height || '?'}`,
  });
  return res.end(row.bytes);
}

// GET /devices/:serial/logs?q=&topic=&limit= — filtered 30-day log history for the device view.
async function deviceLogs(ctx) {
  const { res, store, params, query } = ctx;
  const dev = await store.getDeviceBySerial(params.serial);
  if (!dev) return json(res, 404, { ok: false, error: 'not found' });
  const g = k => (query && typeof query.get === 'function' ? query.get(k) : undefined);
  const logs = typeof store.getDeviceLogs === 'function'
    ? await store.getDeviceLogs(dev.id, { q: g('q'), topic: g('topic'), limit: g('limit') })
    : [];
  return json(res, 200, { ok: true, serial: params.serial, logs: logs || [] });
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
    // Distinguish "upload measured" from "request arrived but carried no body" (the agent's
    // file upload didn't attach data) so a blank up_bps is explainable rather than silent.
    const log = bytes > 0 ? 'down+up measured' : 'upload: no body received from device';
    Promise.resolve(store.recordSpeedtestResult(jobId, { up_bps: bps, status: 'done', result_log: log })).catch(() => {});
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

// POST /admin/migrate (admin) — apply the bundled, idempotent db/schema.sql. This exists so
// schema changes can be applied over the tunnel (the ingest container can reach the DB; an
// office machine can't). It runs ONLY the schema.sql baked into this image — never arbitrary
// SQL — and every statement is CREATE … IF NOT EXISTS / CREATE OR REPLACE, so it's safe to
// re-run. Admin-token gated like the other admin routes.
async function adminMigrate(ctx) {
  const { res, store, log } = ctx;
  if (typeof store.migrate !== 'function') return json(res, 501, { ok: false, error: 'migrate not supported' });
  try {
    await store.migrate();
    log.info('admin: schema migrate applied');
    return json(res, 200, { ok: true, migrated: true });
  } catch (e) {
    // Surface the DB error detail (admin-gated route) so a schema problem can be diagnosed
    // over the API without shell access to the server logs.
    log.error('admin: migrate failed', { msg: e && e.message });
    return json(res, 500, {
      ok: false,
      error: 'migrate failed',
      detail: e && e.message ? e.message : String(e),
      code: e && e.code ? e.code : null,
      position: e && e.position ? e.position : null,
    });
  }
}

// ── tags & smart tags ───────────────────────────────────────────────────────
// Tags are what alert_rules.scope_tag and config_jobs.target_tag select on, so these
// routes are what makes tag-scoped alerting usable at all.

function parseJsonBody(body) {
  if (body == null || body === '') return {};
  if (typeof body === 'object') return body;
  try { return JSON.parse(body); } catch (_) { return null; }
}

// GET /tags — every tag in use, device counts, and whether a rule owns it.
async function tagsList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listTags !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, tags: await store.listTags() });
}

// PATCH /devices/:serial/tags  { tags: [...] } — replaces the device's MANUAL tags.
// Rule-owned tags are preserved by the store; sending one is ignored rather than
// reverted a tick later by the worker.
async function deviceTagsSet(ctx) {
  const { res, store, body, params } = ctx;
  if (typeof store.setDeviceTags !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body);
  if (!parsed) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(parsed.tags)) return json(res, 400, { ok: false, error: 'tags must be an array' });
  if (parsed.tags.length > 50) return json(res, 400, { ok: false, error: 'too many tags (max 50)' });
  const bad = parsed.tags.find((t) => String(t == null ? '' : t).length > 64);
  if (bad !== undefined) return json(res, 400, { ok: false, error: 'tag too long (max 64 chars)' });
  const updated = await store.setDeviceTags(params.serial, parsed.tags);
  if (!updated) return json(res, 404, { ok: false, error: 'device not found' });
  return json(res, 200, { ok: true, device: updated });
}

// ── PMR virtual desktop: pharmacies, counters, counter Pis ──────────────────
// A counter Pi is enrolled as a Vigilant device (kind='counter-pi'), so it reuses the
// same token auth, telemetry ingest, alerting and tags as a router. These handlers add
// only the pharmacy/counter layer on top.

const PMR_SYSTEMS = ['proscript', 'pharmacy_manager', 'nexphase', 'analyst', 'titan', 'rxweb', 'other'];
const PMR_STATUSES = ['planned', 'building', 'live', 'suspended', 'decommissioned'];

async function pharmaciesList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listPharmacies !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, pharmacies: await store.listPharmacies() });
}

async function pharmacyGet(ctx) {
  const { res, store, params } = ctx;
  const p = await store.getPharmacy(params.id);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const counters = typeof store.listCounters === 'function' ? await store.listCounters(p.id) : [];
  return json(res, 200, { ok: true, pharmacy: p, counters });
}

async function pharmacyCreate(ctx) {
  const { res, store, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!String(p.code || '').trim()) return json(res, 400, { ok: false, error: 'code is required' });
  if (!String(p.name || '').trim()) return json(res, 400, { ok: false, error: 'name is required' });
  // idx drives the VLAN and every address in the subnet, so it must be a sane integer
  // up front — the DB CHECK would otherwise surface as a 500.
  const idx = Number(p.idx);
  if (!Number.isInteger(idx) || idx < 1 || idx > 154) {
    return json(res, 400, { ok: false, error: 'idx must be an integer 1–154 (it derives vlan 100+idx and 10.idx.0.0/24)' });
  }
  if (p.pmr_system && !PMR_SYSTEMS.includes(p.pmr_system)) return json(res, 400, { ok: false, error: `pmr_system must be one of ${PMR_SYSTEMS.join(', ')}` });
  if (p.status && !PMR_STATUSES.includes(p.status)) return json(res, 400, { ok: false, error: `status must be one of ${PMR_STATUSES.join(', ')}` });
  try {
    return json(res, 201, { ok: true, pharmacy: await store.createPharmacy({ ...p, idx }) });
  } catch (e) {
    // code and idx are both UNIQUE — a clash is the caller's problem, not a 500.
    if (e && e.code === '23505') return json(res, 409, { ok: false, error: 'a pharmacy already uses that code, index, or CRM site' });
    throw e;
  }
}

async function pharmacyUpdate(ctx) {
  const { res, store, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (p.idx !== undefined) {
    return json(res, 400, { ok: false, error: 'idx cannot be changed — it derives the VLAN and every address already live in nftables/dnsmasq and the VM configs' });
  }
  if (p.pmr_system && !PMR_SYSTEMS.includes(p.pmr_system)) return json(res, 400, { ok: false, error: `pmr_system must be one of ${PMR_SYSTEMS.join(', ')}` });
  if (p.status && !PMR_STATUSES.includes(p.status)) return json(res, 400, { ok: false, error: `status must be one of ${PMR_STATUSES.join(', ')}` });
  const updated = await store.updatePharmacy(params.id, p);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, pharmacy: updated });
}

async function pharmacyDelete(ctx) {
  const { res, store, params } = ctx;
  const r = await store.deletePharmacy(params.id);
  if (!r || !r.deleted) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, ...r });
}

async function countersList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listCounters !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const pid = query && query.get('pharmacy_id');
  return json(res, 200, { ok: true, counters: await store.listCounters(pid || null) });
}

async function counterCreate(ctx) {
  const { res, store, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!p.pharmacy_id) return json(res, 400, { ok: false, error: 'pharmacy_id is required' });
  const n = Number(p.n);
  if (!Number.isInteger(n) || n < 1 || n > 79) {
    return json(res, 400, { ok: false, error: 'n must be an integer 1–79 (it derives the VM address 10.x.0.(20+n) and the Pi tunnel 10.255.x.n)' });
  }
  if (p.status && !PMR_STATUSES.includes(p.status)) return json(res, 400, { ok: false, error: `status must be one of ${PMR_STATUSES.join(', ')}` });
  // Settings on create go through the SAME validator as the edit path — a bad key here must
  // be a 400 rather than a silently ignored field, which is the failure mode the closed
  // whitelist exists to prevent. Omitting settings entirely is the normal case: a new thin
  // client starts at '{}', which the server reads as "all defaults".
  let newSettings = null;
  if (p.settings !== undefined) {
    const checked = validateCounterSettings(p.settings);
    if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });
    newSettings = checked.value;
  }
  try {
    const created = await store.createCounter({ ...p, n });
    // Applied as a merge onto the row's '{}' default, so there is only ONE code path that
    // ever writes this column and only one place the merge semantics live.
    if (created && newSettings && Object.keys(newSettings).length && typeof store.setCounterSettings === 'function') {
      const withSettings = await store.setCounterSettings(created.id, newSettings);
      if (withSettings) return json(res, 201, { ok: true, counter: withSettings });
    }
    return json(res, 201, { ok: true, counter: created });
  } catch (e) {
    if (e && e.code === '23505') return json(res, 409, { ok: false, error: 'that counter number already exists for this pharmacy' });
    if (e && e.code === '23503') return json(res, 400, { ok: false, error: 'unknown pharmacy_id' });
    throw e;
  }
}

async function counterUpdate(ctx) {
  const { res, store, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (p.n !== undefined) {
    return json(res, 400, { ok: false, error: 'n cannot be changed — it derives the VM address and the Pi tunnel /32 already configured on the gateway' });
  }
  if (p.status && !PMR_STATUSES.includes(p.status)) return json(res, 400, { ok: false, error: `status must be one of ${PMR_STATUSES.join(', ')}` });

  // Per-thin-client options ride on the EXISTING update route rather than getting one of
  // their own, so the edit modal still saves everything in a single request.
  //
  // Validated BEFORE anything is written: a body carrying one bad setting must change
  // nothing at all rather than half-applying. An unknown key or an out-of-range value is a
  // 400 naming the key — never coerced, never dropped (see shared/counterSettings.js for
  // why nothing unchecked may reach this column).
  let settings = null;
  if (p.settings !== undefined) {
    if (typeof store.setCounterSettings !== 'function') {
      return json(res, 501, { ok: false, error: 'thin-client settings are not supported by this store' });
    }
    const checked = validateCounterSettings(p.settings);
    if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });
    settings = checked.value;
  }

  const updated = await store.updateCounter(params.id, p);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  // MERGED, not replaced (see setCounterSettings): saving one field must leave the rest
  // alone. Skipped for an empty object so a no-op save does not touch the row.
  if (settings && Object.keys(settings).length) {
    const merged = await store.setCounterSettings(params.id, settings);
    if (merged) return json(res, 200, { ok: true, counter: merged });
  }
  return json(res, 200, { ok: true, counter: updated });
}

// GET /pharmacies/:id/vms — what this site's thin clients may be pointed at.
async function pharmacyVmsList(ctx) {
  const { res, store, params } = ctx;
  const ph = await store.getPharmacy(params.id);
  if (!ph) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  return json(res, 200, { ok: true, vms: await store.listPharmacyVms(ph.id) });
}

// POST /pharmacies/:id/vms  { vmid, ip, label? }
// Attaches an EXTRA VM. The PMR server and counter desktops are already included by
// derivation, so this is only for the rest.
async function pharmacyVmAttach(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const vmid = Number(p.vmid);
  if (!Number.isInteger(vmid) || vmid <= 0) {
    return json(res, 400, { ok: false, error: 'vmid must be a positive integer' });
  }
  // Validated to a bare IPv4 for the same reason the agent does it: this value ends up in
  // the kiosk's connection target, so it is an allowlist rather than free text.
  const ip = String(p.ip || '').trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) {
    return json(res, 400, { ok: false, error: 'ip must be a bare IPv4 address, e.g. 10.1.0.30' });
  }
  const ph = await store.getPharmacy(params.id);
  if (!ph) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  const vms = await store.attachPharmacyVm(ph.id, { vmid, ip, label: p.label });
  log.info('pmr: vm attached to site', { pharmacy: ph.code, vmid, ip });
  return json(res, 200, { ok: true, vms });
}

// DELETE /pharmacies/:id/vms/:vmid
async function pharmacyVmDetach(ctx) {
  const { res, store, params } = ctx;
  const ph = await store.getPharmacy(params.id);
  if (!ph) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  const r = await store.detachPharmacyVm(ph.id, Number(params.vmid));
  if (!r.detached) {
    return json(res, 404, { ok: false, error: 'that VM is not linked to this site' });
  }
  return json(res, 200, { ok: true, vms: await store.listPharmacyVms(ph.id) });
}

// POST /printers/:id/test-print
// Sends a test page from the Pi that reported the printer. Nothing in the datacentre can
// reach a printer on a pharmacy LAN, so this is dispatched to that device rather than
// attempted here — and if no Pi has reported the printer, there is no route to it at all.
// GET /printers/lan?serials=a,b,c
// Printers seen on the LAN by the given MikroTik serials (Tier-1 discovery from mac_hosts).
// The caller resolves which serials belong to a site — this endpoint just reports what those
// routers have seen, so it stays a pure Vigilant read with no CRM knowledge.
async function lanPrinters(ctx) {
  const { res, store, query } = ctx;
  const raw = ((query && query.get('serials')) || '').trim();
  if (!raw) return json(res, 400, { ok: false, error: 'serials query param required (comma-separated)' });
  const serials = raw.split(',').map((s) => s.trim()).filter(Boolean).slice(0, 200);
  if (!serials.length) return json(res, 400, { ok: false, error: 'no valid serials' });
  const printers = await store.listLanPrinters(serials);
  return json(res, 200, { ok: true, printers });
}

async function printerTestPrint(ctx) {
  const { res, store, log, params } = ctx;
  const printer = await store.getPrinter(params.id);
  if (!printer) return json(res, 404, { ok: false, error: 'printer not found' });
  if (!printer.reported_by) {
    return json(res, 409, { ok: false, error: 'no thin client has reported this printer, so there is no machine on the pharmacy LAN to print from' });
  }
  // The queue name is carried in the action string and ends up as an argv element on the
  // device. Restricted to what CUPS itself permits in a queue name so it cannot smuggle
  // anything into the command, on top of the agent's own allowlist.
  const queue = String(printer.name || '').trim();
  if (!/^[A-Za-z0-9_.-]+$/.test(queue)) {
    return json(res, 400, { ok: false, error: `printer name ${JSON.stringify(queue)} is not a usable CUPS queue name, so a test print cannot be addressed to it` });
  }
  const queued = await store.setCounterActionForDevice(printer.reported_by, {
    action: `test-print:${queue}`,
    by: 'watchman',
  });
  if (!queued) {
    return json(res, 409, { ok: false, error: 'the thin client that reported this printer is no longer linked to a counter' });
  }
  log.warn('pmr: test print queued', { printer: printer.id, queue, device: printer.reported_by });
  return json(res, 200, { ok: true, queued: queue });
}

// POST /enrol/self  { serial, model?, identity? }   (auth: SELF_ENROL_TOKEN, checked in server.js)
// A fresh Pi from the base image calls this on first boot to register itself and be issued a
// per-device token. It lands as an UNCLAIMED counter-pi device (no counter points at it) and
// shows up on the Thin Clients page for an operator to adopt onto a site.
async function selfEnrol(ctx) {
  const { res, store, config, log, body } = ctx;
  const p = parseJsonBody(body) || {};
  const serial = String(p.serial || '').trim();
  if (!serial) return json(res, 400, { ok: false, error: 'serial required' });

  const device = await store.createDevice({
    serial,
    kind: 'counter-pi',
    identity: p.identity || null,
    model: p.model || null,
    // 'unclaimed' makes the waiting-to-be-adopted fleet filterable; adoption is the real
    // state change (a counter starts pointing at it), the tag is just a convenience.
    tags: ['counter-pi', 'unclaimed'],
  });

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await store.setDeviceToken(device.id, tokenHash);

  log.info('pmr: thin client self-enrolled', { serial, device: device.id });
  return json(res, 201, {
    ok: true,
    token,
    serial: device.serial,
    telemetry_url: `${config.publicBaseUrl}/telemetry`,
  });
}

// GET /pis/unclaimed — self-enrolled Pis waiting to be adopted onto a site.
async function unclaimedPisList(ctx) {
  const { res, store } = ctx;
  return json(res, 200, { ok: true, pis: await store.listUnclaimedPis() });
}

// POST /pis/:id/adopt  { pharmacy_id, label? } — claim a Pi onto a site as a new thin client.
async function adoptPi(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!p.pharmacy_id) return json(res, 400, { ok: false, error: 'pharmacy_id required' });
  const label = typeof p.label === 'string' && p.label.trim() ? p.label.trim() : null;
  try {
    const counter = await store.adoptPi(params.id, p.pharmacy_id, label);
    if (!counter) return json(res, 409, { ok: false, error: 'that site already has all 79 thin-client slots' });
    log.info('pmr: thin client adopted', { device: params.id, pharmacy: p.pharmacy_id, counter: counter.id });
    return json(res, 200, { ok: true, counter });
  } catch (e) {
    if (e && e.code === '23503') return json(res, 400, { ok: false, error: 'unknown pharmacy_id or device' });
    throw e;
  }
}

// GET /agent/pi-script — the current counter-pi agent, served to the DEVICE.
// Authenticated with the device's own bearer token (the same one it uses for telemetry), so
// no new secret and nothing is public. Restricted to counter-pi devices: a router has no use
// for it and should not be able to pull it.
async function piAgentScript(ctx) {
  const { res, device, log } = ctx;
  if (!device || device.kind !== 'counter-pi') {
    return json(res, 403, { ok: false, error: 'this endpoint serves counter-pi devices only' });
  }
  let body;
  try {
    // Inline require matches this file's existing style (see the admin-html and agent-script readers).
    body = require('node:fs').readFileSync('/app/agent/pi/vigilant-pi-agent.py', 'utf8');
  } catch (e) {
    // Named explicitly: in the container the repo is mounted at /app, and a missing file here
    // means the image was built without the agent rather than a caller error.
    return json(res, 500, { ok: false, error: 'agent script not present in this build' });
  }
  log.info('agent: pi script fetched', { serial: device.serial, bytes: body.length });
  return text(res, 200, body, {
    'content-type': 'text/x-python; charset=utf-8',
    'x-vigilant-sha256': crypto.createHash('sha256').update(body).digest('hex'),
  });
}

// The actions a thin client will carry out. An allowlist, not a command channel: the server
// sends a NAME and the agent maps it to a command locally, so nothing here can ever become
// arbitrary execution on a pharmacy counter.
const PI_ACTIONS = ['reboot', 'restart-kiosk', 'restart-agent'];
// 'test-print:<queue>' is generated server-side (never accepted from a caller), so the
// operator-facing allowlist above stays exact-match only.

// POST /counters/:id/action  { action }
async function counterAction(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const action = typeof p.action === 'string' ? p.action.trim() : '';
  if (!PI_ACTIONS.includes(action)) {
    return json(res, 400, { ok: false, error: `action must be one of ${PI_ACTIONS.join(', ')}` });
  }
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });
  if (!counter.pi_device_id) {
    return json(res, 409, { ok: false, error: 'this counter has no thin client enrolled, so there is nothing to send the action to' });
  }
  const by = typeof p.by === 'string' && p.by.trim() ? p.by.trim() : 'watchman';
  const updated = await store.setCounterAction(params.id, { action, by });
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  log.warn('pmr: service action queued for thin client', { counter: params.id, action, by });
  return json(res, 200, { ok: true, counter: updated });
}

// ── support screen sharing ───────────────────────────────────────────────────
// POST /counters/:id/support  { minutes }   — 0 ends it early
//
// Writes the setting and returns. Deliberately does NOT return a viewer URL: the Pi has not
// started x11vnc yet and will not until its next telemetry tick (<=30 s), so there is no
// server to connect to and no session password to hand out. The UI polls GET and opens the
// viewer when the DEVICE says it is up. Returning a URL that fails for half a minute is how a
// working feature gets reported as broken.
async function counterSupportStart(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const minutes = Number.isInteger(p.minutes) ? p.minutes : 15;
  // Through the ONE validator rather than straight into jsonb, so this route cannot become a
  // second way to put an out-of-range value in the settings column.
  const checked = validateCounterSettings({ support_vnc_min: minutes });
  if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });

  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });
  if (!counter.pi_device_id) {
    return json(res, 409, { ok: false, error: 'this counter has no thin client enrolled, so there is nothing to share' });
  }

  const updated = await store.setCounterSettings(params.id, checked.value);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });

  const by = typeof p.by === 'string' && p.by.trim() ? p.by.trim() : 'watchman';
  // Audited BEFORE the session can possibly be live, so a crash between here and the viewer
  // opening still leaves the record that someone asked. Only when actually starting one:
  // minutes=0 is an operator closing a window, not an access event.
  if (checked.value.support_vnc_min > 0 && typeof store.recordSupportSession === 'function') {
    await store.recordSupportSession({
      counter_id: params.id,
      pi_serial: counter.pi_serial || null,
      pharmacy_code: counter.pharmacy_code || null,
      actor: by,
      minutes: checked.value.support_vnc_min,
    });
  }
  log.warn('pmr: support screen sharing requested', {
    counter: params.id, minutes: checked.value.support_vnc_min, by,
  });
  return json(res, 200, { ok: true, minutes: checked.value.support_vnc_min, starting: checked.value.support_vnc_min > 0 });
}

// GET /counters/:id/support
// Is the device sharing yet, and if so how do we connect? The password is generated ON THE PI
// and arrives in telemetry — it is never pushed down, because the settings channel is a closed
// bool/int whitelist and a secret would be the first free-text value in a channel whose safety
// rests on there being none.
async function counterSupportStatus(ctx) {
  const { res, store, params } = ctx;
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });

  const requested = (counter.settings && counter.settings.support_vnc_min) || 0;
  let sv = null;
  if (counter.pi_device_id && typeof store.getDeviceSupportVnc === 'function') {
    sv = await store.getDeviceSupportVnc(counter.pi_device_id);
  }
  if (!sv || !sv.active) return json(res, 200, { ok: true, active: false, requested });

  // OBSERVED tunnel address, never derived. A previous version of this estate computed
  // 10.255.<idx>.<n> and displayed an address no device had — see the counters_v comment. The
  // column is a CIDR from the hub, so strip the prefix length.
  const raw = counter.pi_tunnel_ip || '';
  const host = String(raw).split(',')[0].trim().split('/')[0];
  if (!host) return json(res, 409, { ok: false, error: 'this thin client has no tunnel address yet (has its VPN peer ever handshaked?)' });

  let minted;
  try {
    minted = mintSupportToken({ host, port: sv.port || 5900 });
  } catch (e) {
    // A missing secret must be loud: minting unsigned tokens would silently make the bridge's
    // whole authorisation model a no-op.
    return json(res, 500, { ok: false, error: e.message });
  }
  const base = (process.env.SUPPORT_VNC_BASE || '').replace(/\/$/, '');
  if (!base) return json(res, 500, { ok: false, error: 'SUPPORT_VNC_BASE is not configured' });

  return json(res, 200, {
    ok: true,
    active: true,
    requested,
    expires_in_s: sv.expires_in_s || null,
    token_expires_at: minted.expires_at,
    // The inner "?" MUST be percent-encoded or it terminates the outer query string and noVNC
    // never sees the token.
    url: `${base}/vnc.html?autoconnect=1&resize=scale&path=websockify%3Ftoken%3D${encodeURIComponent(minted.token)}`,
    password: sv.password || null,
  });
}

// POST /counters/:id/boot-target  { vmid }
// Which VM this counter's thin client boots into, chosen in Watchman instead of by editing
// the kiosk launcher on the device. The address is resolved server-side from the vmid; an
// unregistered VM is refused rather than guessed at.
async function counterSetBootTarget(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });

  const by = typeof p.by === 'string' && p.by.trim() ? p.by.trim() : 'watchman';

  // An EXPLICIT null (or empty string) means "back to the default" — boot the site's PMR
  // server. Distinguished from a malformed vmid, which is still a 400: Number(null) is 0, so
  // without this the UI's "PMR server (default)" option could never be saved.
  if (p.vmid === null || p.vmid === '' || typeof p.vmid === 'undefined') {
    if (typeof store.clearCounterBootTarget !== 'function') {
      return json(res, 501, { ok: false, error: 'clearing a boot target is not supported by this store' });
    }
    const cleared = await store.clearCounterBootTarget(params.id, by);
    if (!cleared) return json(res, 404, { ok: false, error: 'not found' });
    log.info('pmr: boot target cleared', { counter: params.id, by });
    return json(res, 200, { ok: true, counter: cleared });
  }

  const vmid = Number(p.vmid);
  if (!Number.isInteger(vmid) || vmid <= 0) {
    return json(res, 400, { ok: false, error: 'vmid must be a positive integer, or null to boot the PMR server' });
  }
  const updated = await store.setCounterBootTarget(params.id, { vmid, by });
  if (!updated) {
    return json(res, 409, {
      ok: false,
      error: `vm ${vmid} is not registered to ${counter.pharmacy_code} as either its PMR server or one of its counter desktops, so its address is unknown — register it first`,
    });
  }
  if (!updated.pi_device_id) {
    // Worth saying out loud: the choice is stored, but nothing will collect it yet.
    log.info('pmr: boot target set on a counter with no Pi enrolled', { counter: params.id, vmid });
  }
  log.info('pmr: boot target set', { counter: params.id, vmid, target: updated.boot_target });
  return json(res, 200, { ok: true, counter: updated });
}

async function counterDelete(ctx) {
  const { res, store, params } = ctx;
  const r = await store.deleteCounter(params.id);
  if (!r || !r.deleted) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, ...r });
}

// POST /counters/:id/enrol-pi  { serial?, pi_hostname?, pi_model?, pi_public_key? }
// Creates the Pi as a Vigilant device (kind='counter-pi'), mints its bearer token and
// links it to the counter — one action, because a Pi with no device row can't report and
// a device row with no counter is orphaned. The plaintext token is returned ONCE.
async function counterEnrolPi(ctx) {
  const { res, store, config, log, body, params } = ctx;
  const p = parseJsonBody(body) || {};
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });
  if (counter.pi_device_id && !p.replace) {
    // Re-enrolling silently would strand the old token; make the caller be explicit.
    return json(res, 409, { ok: false, error: 'this counter already has a Pi enrolled — pass {"replace":true} to issue a new token' });
  }

  // Prefer the Pi's real hardware serial; fall back to a deterministic one derived from
  // the site so the device row is still uniquely identifiable without it.
  const serial = String(p.serial || `PI-${counter.pharmacy_code}-${counter.n}`).trim();

  const device = await store.createDevice({
    serial,
    kind: 'counter-pi',
    site_name: `${counter.pharmacy_code} counter ${counter.n}`,
    customer: counter.pharmacy_name || null,
    model: p.pi_model || null,
    // Tag it so the Pi fleet is filterable and alert rules can scope to it out of the box.
    tags: ['counter-pi'],
  });

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await store.setDeviceToken(device.id, tokenHash);

  const linked = await store.linkCounterPi(params.id, {
    pi_device_id: device.id,
    pi_hostname: p.pi_hostname || null,
    pi_model: p.pi_model || null,
    pi_public_key: p.pi_public_key || null,
  });

  log.info('pmr: counter Pi enrolled', { counter: params.id, serial, device: device.id });
  return json(res, 201, {
    ok: true,
    counter: linked,
    device: { id: device.id, serial: device.serial, kind: 'counter-pi' },
    // Shown once and never recoverable — same contract as router enrolment.
    token,
    telemetry_url: `${config.publicBaseUrl}/telemetry`,
  });
}

async function printersList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listPrinters !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const pid = query && query.get('pharmacy_id');
  return json(res, 200, { ok: true, printers: await store.listPrinters(pid || null) });
}

async function printerUpsert(ctx) {
  const { res, store, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!p.pharmacy_id) return json(res, 400, { ok: false, error: 'pharmacy_id is required' });
  if (!String(p.name || '').trim()) return json(res, 400, { ok: false, error: 'name is required' });
  if (p.discovered_via && !['snmp', 'ipp', 'cups', 'manual', 'probe'].includes(p.discovered_via)) {
    return json(res, 400, { ok: false, error: 'discovered_via must be snmp, ipp, cups, manual or probe' });
  }
  try {
    return json(res, 200, { ok: true, printer: await store.upsertPrinter(p) });
  } catch (e) {
    if (e && e.code === '23503') return json(res, 400, { ok: false, error: 'unknown pharmacy_id or counter_id' });
    throw e;
  }
}

async function printerDelete(ctx) {
  const { res, store, params } = ctx;
  const r = await store.deletePrinter(params.id);
  if (!r || !r.deleted) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, ...r });
}

// POST /printers/report — a DEVICE route: the counter Pi posts what it polled on the
// pharmacy LAN. Authenticated as the device, and the pharmacy is resolved from the
// counter that owns that Pi, so a Pi can never write printers into another site.
async function printersReport(ctx) {
  const { res, store, device, body } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(p.printers)) return json(res, 400, { ok: false, error: 'printers must be an array' });
  const counters = await store.listCounters();
  const mine = (counters || []).find((c) => c.pi_device_id === device.id);
  if (!mine) return json(res, 409, { ok: false, error: 'this device is not linked to a counter, so its pharmacy is unknown' });
  return json(res, 200, { ok: true, ...(await store.reportPrinters(device.id, mine.pharmacy_id, p.printers)) });
}

// POST /wg-peers/report — the hub's collector posts `wg show dump`.
async function wgPeersReport(ctx) {
  const { res, store, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(p.peers)) return json(res, 400, { ok: false, error: 'peers must be an array' });
  return json(res, 200, { ok: true, ...(await store.reportWgPeers(p.peers)) });
}

async function wgPeersList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listWgPeers !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, peers: await store.listWgPeers() });
}

// ── Proxmox discovery ───────────────────────────────────────────────────────
// A collector on a Proxmox node pushes the cluster's VM inventory here. Vigilant cannot
// pull it: it sits on the DMZ VLAN with no route to the management VLAN, and inverting the
// direction avoids having to open one.
async function proxmoxReport(ctx) {
  const { res, store, body, log } = ctx;
  if (typeof store.reportProxmoxVms !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(p.vms)) return json(res, 400, { ok: false, error: 'vms must be an array' });
  const stored = await store.reportProxmoxVms(p.vms);
  // Reconcile immediately so a freshly-provisioned pharmacy is linked up on the first
  // report rather than after some later pass.
  const linked = await store.reconcileProxmox();
  if (linked.conflicts.length) {
    log.warn('proxmox: discovery conflicts', { count: linked.conflicts.length });
  }
  return json(res, 200, { ok: true, ...stored, ...linked });
}

async function proxmoxList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listProxmoxVms !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, vms: await store.listProxmoxVms() });
}

// PATCH /devices/:serial  { customer?, site_name?, identity?, model?, wan_type? }
// Operator-editable metadata. Its main job is letting the field app write across the
// audited MikroTik→company link, since Vigilant cannot see that database — and a populated
// `customer` is what makes customer-scoped tag rules possible.
const WAN_TYPES = ['pppoe', 'sim', 'dhcp', 'static', 'unknown'];
async function deviceMetaSet(ctx) {
  const { res, store, body, params } = ctx;
  if (typeof store.updateDeviceMeta !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body);
  if (!parsed) return json(res, 400, { ok: false, error: 'bad json' });
  const allowed = ['customer', 'site_name', 'identity', 'model', 'wan_type'];
  const patch = {};
  for (const k of allowed) if (parsed[k] !== undefined && parsed[k] !== null) patch[k] = String(parsed[k]).trim();
  if (!Object.keys(patch).length) return json(res, 400, { ok: false, error: `nothing to update (allowed: ${allowed.join(', ')})` });
  for (const [k, v] of Object.entries(patch)) {
    if (v.length > 200) return json(res, 400, { ok: false, error: `${k} too long (max 200 chars)` });
  }
  // wan_type is CHECK-constrained in the schema; reject it here for a clean 400 rather
  // than letting the constraint raise a 500.
  if (patch.wan_type && !WAN_TYPES.includes(patch.wan_type)) {
    return json(res, 400, { ok: false, error: `wan_type must be one of ${WAN_TYPES.join(', ')}` });
  }
  const updated = await store.updateDeviceMeta(params.serial, patch);
  if (!updated) return json(res, 404, { ok: false, error: 'device not found' });
  return json(res, 200, { ok: true, device: updated });
}

function validateTagRule(r, { partial } = {}) {
  if (!partial || r.tag !== undefined) {
    const tag = String(r.tag == null ? '' : r.tag).trim();
    if (!tag) return 'tag is required';
    if (tag.length > 64) return 'tag too long (max 64 chars)';
    // Keep tags shell/URL-friendly: they end up in scope_tag, target_tag and query strings.
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(tag)) return 'tag may contain letters, digits, dot, dash and underscore only';
  }
  if (!partial || r.name !== undefined) {
    if (!String(r.name == null ? '' : r.name).trim()) return 'name is required';
  }
  if (r.conditions !== undefined) {
    const c = r.conditions;
    if (!c || typeof c !== 'object' || !Array.isArray(c.all)) return 'conditions must be {"all":[…]}';
    if (c.all.length > 20) return 'too many conditions (max 20)';
  }
  return null;
}

async function tagRulesList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listTagRules !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, rules: await store.listTagRules() });
}

// POST /tag-rules/preview { conditions } — blast radius BEFORE saving.
async function tagRulePreview(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.previewTagRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body);
  if (!parsed) return json(res, 400, { ok: false, error: 'bad json' });
  try {
    return json(res, 200, { ok: true, ...(await store.previewTagRule(parsed.conditions)) });
  } catch (e) {
    // The compiler raises 400s for unknown fields/operators — surface them as such.
    return json(res, e && e.status === 400 ? 400 : 500, { ok: false, error: e.message });
  }
}

async function tagRuleCreate(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.createTagRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body);
  if (!parsed) return json(res, 400, { ok: false, error: 'bad json' });
  const err = validateTagRule(parsed);
  if (err) return json(res, 400, { ok: false, error: err });
  // Reject conditions that don't compile, so a rule can never be saved in a state the
  // worker will just log an error about every tick.
  try { await store.previewTagRule(parsed.conditions || { all: [] }); }
  catch (e) { return json(res, 400, { ok: false, error: e.message }); }
  try {
    const created = await store.createTagRule(parsed);
    return json(res, 201, { ok: true, rule: created });
  } catch (e) {
    // tag is UNIQUE — one rule owns one tag.
    if (e && e.code === '23505') return json(res, 409, { ok: false, error: 'a rule already owns that tag' });
    throw e;
  }
}

async function tagRuleUpdate(ctx) {
  const { res, store, body, params } = ctx;
  if (typeof store.updateTagRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body);
  if (!parsed) return json(res, 400, { ok: false, error: 'bad json' });
  const err = validateTagRule(parsed, { partial: true });
  if (err) return json(res, 400, { ok: false, error: err });
  if (parsed.conditions !== undefined) {
    try { await store.previewTagRule(parsed.conditions); }
    catch (e) { return json(res, 400, { ok: false, error: e.message }); }
  }
  try {
    const updated = await store.updateTagRule(params.id, parsed);
    if (!updated) return json(res, 404, { ok: false, error: 'not found' });
    return json(res, 200, { ok: true, rule: updated });
  } catch (e) {
    if (e && e.code === '23505') return json(res, 409, { ok: false, error: 'a rule already owns that tag' });
    throw e;
  }
}

// Deleting a rule also strips its tag from every device (store does this), so nothing is
// left looking like a manual tag that nobody set.
async function tagRuleDelete(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.deleteTagRule !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const r = await store.deleteTagRule(params.id);
  if (!r || !r.deleted) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, ...r });
}

// POST /tag-rules/sync — apply rules now instead of waiting for the worker's next pass,
// so the UI can show the result immediately after a rule is saved.
async function tagRulesSync(ctx) {
  const { res, store } = ctx;
  if (typeof store.syncSmartTags !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  return json(res, 200, { ok: true, ...(await store.syncSmartTags()) });
}

// ── GET /sites/:pharmacy_code/devices ───────────────────────────────────────
// What is ON a site's LAN, from telemetry the site already sends: the routers' bridge-host /
// ARP / DHCP tables (mac_hosts), plus any printer a thin client registered that no router has
// ARPed. Classification is shared/lanDevices.js so the kind shown here is the kind the relay
// reasons about.
//
// The :pharmacy_code segment is resolved by site_devices_v, which accepts EITHER a
// pharmacies.code or a MikroTik's serial — the ~348 monitored sites have no pharmacies row,
// and a site does not need a Pi to be VISIBLE, only to be reached. A code that matches nothing
// is a 404; a real site whose routers have reported nothing yet is a 200 with an empty list,
// because those mean different things to whoever is looking.
async function siteDevices(ctx) {
  const { res, store, params } = ctx;
  const lanDevices = require('../shared/lanDevices');
  if (typeof store.listSiteHosts !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const site = typeof store.siteExists === 'function' ? await store.siteExists(params.code) : null;
  if (!site) return json(res, 404, { ok: false, error: 'no such site' });

  const hosts = await store.listSiteHosts(params.code);
  const devices = hosts.map((h) => {
    const kind = lanDevices.classifyHost(h);
    return {
      mac: h.mac,
      ip: h.ip,
      hostname: h.hostname,
      vendor: h.vendor,
      kind,
      last_seen_at: h.last_seen_at,
      ports: lanDevices.portsForKind(kind),
      // Which table the row came from, so the UI can say why an address is offerable when a
      // router has never seen it (a Pi-registered printer).
      source: h.source,
    };
  });
  // Sorted by address, numerically per octet — a text sort puts .10 before .9 and an engineer
  // reading down a site's LAN notices that immediately.
  devices.sort((a, b) => compareIpish(a.ip, b.ip));
  return json(res, 200, { ok: true, site: site.site_code, devices });
}

// Compare two addresses octet-wise, falling back to a string compare for anything that is not
// a dotted quad (printers.address may hold a hostname).
function compareIpish(a, b) {
  const pa = /^\d+\.\d+\.\d+\.\d+$/.test(String(a || '')) ? String(a).split('.').map(Number) : null;
  const pb = /^\d+\.\d+\.\d+\.\d+$/.test(String(b || '')) ? String(b).split('.').map(Number) : null;
  if (!pa || !pb) return String(a || '').localeCompare(String(b || ''));
  for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// LAN RELAY — a long-poll reverse channel through a site's thin client
// ════════════════════════════════════════════════════════════════════════════
//
// WHY IT IS SHAPED LIKE THIS — measured constraints, not preference:
//   * Nothing in the datacentre can open a connection TOWARDS a Pi. The hub's forward chain is
//     policy-drop with one exception (WireGuard → RDP), so the Pi must dial OUT. It already
//     does, every tick, for telemetry — which is why the session directive rides that reply
//     instead of a second poller.
//   * Vigilant is published through a Cloudflare Tunnel, which passes HTTP only: no raw TCP and
//     no assumed WebSocket.
//   * A queue-per-poll relay would make every asset on a printer's admin page wait a whole poll
//     cycle, so the Pi's collector request is HELD OPEN (/next) instead.
//
// It is a PROXY, not a tunnel. A session names exactly ONE address and port, both validated
// against inventory the site itself reported, and every hop is an ordinary HTTP request this
// server can see, log and refuse.

// 10 minutes: long enough to read a toner page or change a phone's dial plan, short enough that
// a forgotten browser tab is not a standing hole into a pharmacy LAN.
const RELAY_TTL_S = 600;

// How long GET /next is held open. 25 s is under every timeout in the path (Cloudflare's ~100 s
// origin read, Node's 60 s headers timeout) with room for a slow reply to finish first.
const RELAY_NEXT_HOLD_MS = 25000;
// Queue→claim latency is added to EVERY asset on a page, so it has to be well below the
// threshold a human notices. 150 ms x 3 Pi workers is ~20 queries/s per session, against an
// ingest already absorbing hundreds of telemetry writes a second.
const RELAY_NEXT_POLL_MS = 150;
// Re-read the session every ~3 s while holding, so closing a session (or its TTL running out)
// surfaces as 410 promptly instead of a 204 twenty-five seconds later.
const RELAY_LIVENESS_EVERY = 20;

// The browser's ceiling. A device admin UI that has not answered in 30 s is not going to.
const RELAY_PROXY_WAIT_MS = 30000;
const RELAY_PROXY_POLL_MS = 120;

// Per-PROCESS cap on concurrent /next holds for one session. The Pi is specified to run a pool
// of 3; 6 leaves room for a worker whose previous hold has not yet been torn down, and stops a
// buggy or hostile agent from parking hundreds of DB-polling requests on the ingest. The ingest
// is a 3-worker cluster, so the real ceiling is 18 — still bounded, still cheap.
const RELAY_MAX_HOLDS = 6;
const relayHolds = new Map();

// Bodies are base64 in JSON (readBody accumulates a STRING and would corrupt binary), so these
// are limits on the ENCODED length. 1 MB in covers any form or config post an embedded UI makes;
// 12 MB out covers a firmware page's images without letting a device stream the DB full.
const RELAY_MAX_REQ_B64 = 1 * 1024 * 1024;
const RELAY_MAX_RESP_B64 = 12 * 1024 * 1024;

// Never forwarded to the device. Beyond the hop-by-hop set:
//   authorization / cookie-less auth — the caller's Vigilant bearer must NEVER reach a printer.
//   accept-encoding — forced to identity: the Pi is stdlib-only and does not inflate, and a
//     content-encoding the body does not actually have renders as binary soup.
//   x-forwarded-* / cf-* — Cloudflare tunnel plumbing, meaningless to a phone and needless
//     detail about our infrastructure.
// `authorization` is deliberately NOT in this set. It used to be stripped because it carried
// OUR field key on /p/*, which must never reach a printer. The session id is now the only
// credential on that path, so this header carries nothing of ours and belongs to the DEVICE:
// forwarding it is what lets a browser answer a printer's WWW-Authenticate: Basic challenge.
const RELAY_STRIP_REQUEST = new Set([
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
  'accept-encoding',
  ]);

// Stripped from the device's response. content-length is recomputed from the decoded body;
// x-frame-options and a frame-ancestors CSP are removed because printer and phone UIs send
// SAMEORIGIN and would otherwise refuse to render inside the Watchman iframe.
const RELAY_STRIP_RESPONSE = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
  'x-frame-options',
]);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Strict dotted-quad only. No hostnames, no CIDR, no IPv6: the allowlist compares this string
// against host(mac_hosts.ip) and printers.address, and anything looser would let two spellings
// of one address disagree about whether it is allowed.
function isIpv4(v) {
  const s = String(v == null ? '' : v).trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((o) => Number(o) <= 255 && String(Number(o)) === o);
}

// POST /relay/sessions  { serial, target_ip, target_port, opened_by? }
// Validates the target against the site's own inventory, records the session, and writes the
// audit row. The Pi learns of it on its next telemetry reply.
//
// opened_by is optional rather than required (unlike config-push, which demands created_by):
// the relay contract fixes the request body, so the audit actor falls back to 'watchman' — the
// same label the test-print path uses when the UI does not name a person.
async function relaySessionCreate(ctx) {
  const { res, store, config, log, body } = ctx;
  const lanDevices = require('../shared/lanDevices');
  if (typeof store.createRelaySession !== 'function' || typeof store.findRelayTarget !== 'function') {
    return json(res, 501, { ok: false, error: 'relay not supported by this store' });
  }
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const serial = String(p.serial || '').trim();
  if (!serial) return json(res, 400, { ok: false, error: 'serial required' });
  const device = await store.getDeviceBySerial(serial);
  if (!device) return json(res, 404, { ok: false, error: 'device not found' });
  // Only a thin client can serve a relay — it is the agent that dials out and fetches. A
  // MikroTik would silently never collect the directive.
  if (device.kind !== 'counter-pi') {
    return json(res, 400, { ok: false, error: 'only a thin client can relay — this device is a ' + device.kind });
  }

  if (!isIpv4(p.target_ip)) {
    return json(res, 400, { ok: false, error: 'target_ip must be an IPv4 address' });
  }
  const port = Number(p.target_port);
  if (!Number.isInteger(port)) return json(res, 400, { ok: false, error: 'target_port must be an integer' });
  // A port outside the set is a policy refusal, not a typo — same 403 as an off-site address.
  if (!lanDevices.isRelayPort(port)) {
    return json(res, 403, { ok: false, error: `target_port must be one of ${lanDevices.RELAY_PORTS.join(', ')}` });
  }

  // THE gate. Allowed only if this Pi's own site already reports the address.
  const allowed = await store.findRelayTarget(device.id, p.target_ip);
  if (!allowed || !allowed.source) {
    log.warn('relay: target refused', { serial: device.serial, target: p.target_ip, port });
    return json(res, 403, {
      ok: false,
      error: 'target is not on this site\'s reported inventory (vigilant.mac_hosts / vigilant.printers)',
    });
  }

  const openedBy = String(p.opened_by || '').trim() || 'watchman';
  const session = await store.createRelaySession({
    device_id: device.id,
    site_code: allowed.site_code,
    target_ip: String(p.target_ip).trim(),
    target_port: port,
    opened_by: openedBy,
    ttl_s: RELAY_TTL_S,
  });

  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(
      openedBy,
      'relay.open',
      device.serial,
      `session=${session.id} target=${session.target_ip}:${session.target_port} site=${allowed.site_code} via=${allowed.source}`
    );
  }
  // Opportunistic housekeeping — see pruneRelay. Never let tidying fail the operator's action.
  if (typeof store.pruneRelay === 'function') {
    store.pruneRelay().catch((e) => log.warn('relay: prune failed', { msg: e && e.message }));
  }
  log.warn('relay: session opened', {
    serial: device.serial,
    session: session.id,
    target: `${session.target_ip}:${session.target_port}`,
    by: openedBy,
  });

  return json(res, 201, {
    ok: true,
    session_id: session.id,
    expires_at: session.expires_at,
    proxy_base: `${config.publicBaseUrl}/relay/${session.id}/p`,
    target_ip: session.target_ip,
    target_port: session.target_port,
    scheme: lanDevices.schemeForPort(session.target_port),
    site: allowed.site_code,
  });
}

// Shared session lookup for the three device/browser-facing relay routes. Returns the session
// or writes the refusal itself, so each route reads as one line of policy.
async function relayLoadSession(ctx, { requireLive }) {
  const { res, store, params } = ctx;
  if (typeof store.getRelaySession !== 'function') {
    json(res, 501, { ok: false, error: 'relay not supported by this store' });
    return null;
  }
  const s = await store.getRelaySession(params.id);
  if (!s) {
    json(res, 404, { ok: false, error: 'no such relay session' });
    return null;
  }
  if (requireLive && !s.live) {
    // 410, not 404: the contract makes this the Pi's signal to STOP reconnecting.
    json(res, 410, { ok: false, error: 'relay session is over' });
    return null;
  }
  return s;
}

// GET /relay/:session_id/next  (device bearer)
// Held open up to RELAY_NEXT_HOLD_MS waiting for a browser request. 200 with work, 204 to
// reconnect, 410 when the session is over.
async function relayNext(ctx) {
  const { req, res, store, log, device } = ctx;
  const s = await relayLoadSession(ctx, { requireLive: true });
  if (!s) return undefined;
  // A session belongs to ONE device. Checked even though the bearer authenticated: a valid
  // token for device B must not be able to drain device A's queue.
  if (s.device_id !== device.id) return json(res, 403, { ok: false, error: 'not your session' });

  const held = relayHolds.get(s.id) || 0;
  if (held >= RELAY_MAX_HOLDS) {
    log.warn('relay: too many concurrent collectors', { session: s.id, held });
    return json(res, 429, { ok: false, error: 'too many concurrent collectors for this session' });
  }
  relayHolds.set(s.id, held + 1);

  // If the agent walks away mid-hold, stop polling the database for it.
  let gone = false;
  const onClose = () => {
    gone = true;
  };
  req.on('close', onClose);

  try {
    if (typeof store.touchRelaySession === 'function') await store.touchRelaySession(s.id);
    const deadline = Date.now() + RELAY_NEXT_HOLD_MS;
    for (let i = 0; !gone; i++) {
      const claimed = await store.claimRelayRequest(s.id);
      if (claimed) {
        return json(res, 200, {
          ok: true,
          request_id: claimed.request_id,
          method: claimed.method,
          path: claimed.path,
          headers: claimed.headers || {},
          body_b64: claimed.body_b64 || null,
        });
      }
      if (Date.now() >= deadline) {
        // 204 — nothing queued, reconnect. No body: a 204 that carries one is malformed.
        res.writeHead(204);
        return res.end();
      }
      if (i > 0 && i % RELAY_LIVENESS_EVERY === 0) {
        const fresh = await store.getRelaySession(s.id);
        if (!fresh || !fresh.live) return json(res, 410, { ok: false, error: 'relay session is over' });
      }
      await sleep(RELAY_NEXT_POLL_MS);
    }
    return undefined; // client disconnected; nothing to answer
  } finally {
    req.removeListener('close', onClose);
    const n = (relayHolds.get(s.id) || 1) - 1;
    if (n <= 0) relayHolds.delete(s.id);
    else relayHolds.set(s.id, n);
  }
}

// POST /relay/:session_id/reply  (device bearer)
//   { request_id, status, headers, body_b64 }
// Liveness is deliberately NOT required: a request claimed a second before the TTL expired
// still has a browser waiting for it, and throwing the answer away would show the operator a
// 504 for work the Pi actually did.
async function relayReply(ctx) {
  const { res, store, device, body } = ctx;
  const s = await relayLoadSession(ctx, { requireLive: false });
  if (!s) return undefined;
  if (s.device_id !== device.id) return json(res, 403, { ok: false, error: 'not your session' });

  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const status = Number(p.status);
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    return json(res, 400, { ok: false, error: 'status must be an HTTP status code' });
  }
  const bodyB64 = p.body_b64 == null ? null : String(p.body_b64);
  if (bodyB64 && bodyB64.length > RELAY_MAX_RESP_B64) {
    return json(res, 413, { ok: false, error: 'response too large to relay' });
  }
  const headers = p.headers && typeof p.headers === 'object' ? p.headers : {};

  const done = await store.replyRelayRequest(s.id, String(p.request_id || ''), {
    status,
    headers,
    body_b64: bodyB64,
  });
  // 409 rather than 404: the request id may well have existed and been answered already (or
  // abandoned by the browser and pruned), and a retrying agent should not treat that as fatal.
  if (!done) return json(res, 409, { ok: false, error: 'no such claimed request for this session' });
  return json(res, 200, { ok: true });
}

// Build the header map forwarded to the device.
function relayRequestHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw || {})) {
    const key = String(k).toLowerCase();
    if (RELAY_STRIP_REQUEST.has(key)) continue;
    // Cloudflare and any proxy in front of us add these; a printer has no use for them.
    if (key.startsWith('x-forwarded-') || key.startsWith('cf-')) continue;
    out[key] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  // Force identity so what the Pi fetches is what we hand back undecoded.
  out['accept-encoding'] = 'identity';
  return out;
}

// Remove ONLY the frame-ancestors directive from a CSP, keeping the rest of the policy intact —
// script-src and friends are the device's own protection and none of our business. Returns null
// when nothing is left to send.
function stripFrameAncestors(value) {
  const kept = String(value)
    .split(';')
    .map((d) => d.trim())
    .filter((d) => d && !/^frame-ancestors\b/i.test(d));
  return kept.length ? kept.join('; ') : null;
}

// Rewrite a redirect so it stays inside the proxy. A device that 302s to '/login' would
// otherwise send the iframe to Vigilant's own root, and the operator would see a 404 instead of
// the login page. An absolute URL to somewhere OTHER than the session's target is left alone —
// following it is not ours to authorise.
function rewriteRelayLocation(value, session, base) {
  const v = String(value);
  if (v.startsWith('/')) return base + v;
  const m = /^https?:\/\/([^/:]+)(?::(\d+))?(\/.*)?$/i.exec(v);
  if (m && m[1] === session.target_ip) return base + (m[3] || '/');
  return v;
}

// GET|POST /relay/:session_id/p/*  (field/admin)
// Queues the request for the Pi's next /next and answers when the reply lands. 504 on timeout.
async function relayProxy(ctx) {
  const { req, res, store, log, params, query } = ctx;
  const s = await relayLoadSession(ctx, { requireLive: true });
  if (!s) return undefined;
  if (typeof store.enqueueRelayRequest !== 'function') {
    return json(res, 501, { ok: false, error: 'relay not supported by this store' });
  }

  // The token may arrive in the query string because a subresource or iframe load cannot carry
  // an Authorization header (RFC 6750 §2.3). Drop it here so it is never forwarded to the
  // device or written into its logs.
  const q = new URLSearchParams(query ? query.toString() : '');
  q.delete('access_token');
  const qs = q.toString();
  const path = (params.path || '/') + (qs ? `?${qs}` : '');

  // readBody() gave us a string, so this is only sound for text payloads (form posts, JSON) —
  // the same limitation the base64 wire contract exists to work around in the other direction.
  const bodyB64 = ctx.body ? Buffer.from(ctx.body, 'utf8').toString('base64') : null;
  if (bodyB64 && bodyB64.length > RELAY_MAX_REQ_B64) {
    return json(res, 413, { ok: false, error: 'request too large to relay' });
  }

  const queued = await store.enqueueRelayRequest(s.id, {
    method: req.method || 'GET',
    path,
    headers: relayRequestHeaders(req.headers),
    body_b64: bodyB64,
  });
  if (!queued) return json(res, 410, { ok: false, error: 'relay session is over' });

  let gone = false;
  const onClose = () => {
    gone = true;
  };
  req.on('close', onClose);
  try {
    const deadline = Date.now() + RELAY_PROXY_WAIT_MS;
    while (!gone) {
      const reply = await store.takeRelayReply(s.id, queued.id);
      if (reply) return writeRelayResponse(ctx, s, reply);
      if (Date.now() >= deadline) {
        log.warn('relay: no answer from thin client', { session: s.id, path });
        return json(res, 504, { ok: false, error: 'the thin client did not answer in time' });
      }
      await sleep(RELAY_PROXY_POLL_MS);
    }
    // Browser navigated away. The queued row is left for pruneRelay rather than deleted here:
    // the Pi may already be fetching it, and a reply to a missing row is a harmless 409.
    return undefined;
  } finally {
    req.removeListener('close', onClose);
  }
}

// Write the device's response back to the browser, stripped of the headers that would stop it
// rendering in the panel. Body goes out as bytes with res.end(buffer) — json()/text() would
// mangle an image.
// Point root-absolute urls in a relayed HTML body at the proxy path.
//
// A device page saying href="/general/status.html" resolves against OUR origin and asks Vigilant
// for /general/status.html, which answers {"ok":false,"error":"not found"}. Rewriting them to
// /relay/<id>/p/general/status.html keeps navigation, stylesheets and form posts inside the
// session. Relative urls never needed this and are untouched.
//
// A single leading "/" only: "//host/x" is protocol-relative and belongs to another origin, so
// prefixing it would aim an off-device request at the printer.
function rewriteRelayHtml(buf, base) {
  let html;
  try {
    html = buf.toString('utf8');
  } catch (e) {
    return buf; // not decodable as text — hand it back untouched
  }
  const rewritten = html.replace(
    /(\s(?:src|href|action|poster|formaction|data-src)\s*=\s*["'])\/(?!\/)/gi,
    `$1${base}/`,
  // CSS url(/x) inside <style> blocks and style attributes, same single-slash rule.
  ).replace(
    /(url\(\s*["']?)\/(?!\/)/gi,
    `$1${base}/`,
  );
  return Buffer.from(rewritten, 'utf8');
}

function writeRelayResponse(ctx, session, reply) {
  const { res, params } = ctx;
  const base = `/relay/${params.id}/p`;
  const out = {};
  for (const [k, v] of Object.entries(reply.headers || {})) {
    const key = String(k).toLowerCase();
    if (RELAY_STRIP_RESPONSE.has(key)) continue;
    let value = Array.isArray(v) ? v : String(v);
    if (key === 'content-security-policy' || key === 'content-security-policy-report-only') {
      const kept = stripFrameAncestors(Array.isArray(value) ? value.join('; ') : value);
      if (!kept) continue;
      value = kept;
    } else if (key === 'location') {
      value = rewriteRelayLocation(Array.isArray(value) ? value[0] : value, session, base);
    } else if (key === 'set-cookie') {
      // Strip any Domain attribute so a device cannot widen its cookie beyond this origin.
      // Path is left as the device set it: embedded UIs almost all use Path=/ and rewriting it
      // breaks their login, and the session is one operator's, for ten minutes.
      const list = (Array.isArray(value) ? value : [value]).map((c) =>
        String(c)
          .split(';')
          .filter((part) => !/^\s*domain=/i.test(part))
          .join(';')
      );
      out['set-cookie'] = list;
      continue;
    }
    out[key] = value;
  }
  // `let`, not `const`: the HTML rewrite below replaces this buffer.
  let buf = reply.body_b64 ? Buffer.from(String(reply.body_b64), 'base64') : Buffer.alloc(0);
  // text/html only, and BEFORE content-length is taken, so the length always describes the
  // bytes actually sent — a stale length truncates the page in the browser.
  if (buf.length && /text\/html/i.test(String(out['content-type'] || ''))) {
    buf = rewriteRelayHtml(buf, base);
  }
  out['content-length'] = buf.length;
  const status = Number(reply.status);
  res.writeHead(Number.isInteger(status) && status >= 100 && status <= 599 ? status : 502, out);
  return res.end(buf);
}

module.exports = {
  siteDevices,
  relaySessionCreate,
  relayNext,
  relayReply,
  relayProxy,
  healthz,
  adminUi,
  adminMigrate,
  realtimeConfig,
  tagsList,
  deviceTagsSet,
  deviceMetaSet,
  pharmaciesList,
  pharmacyGet,
  pharmacyCreate,
  pharmacyUpdate,
  pharmacyDelete,
  countersList,
  counterCreate,
  counterUpdate,
  lanPrinters,
  printerTestPrint,
  piAgentScript,
  postScreen,
  deviceScreen,
  brandingGet,
  brandingPutText,
  brandingPutSplash,
  brandingDeleteSplash,
  brandingGetSplash,
  selfEnrol,
  unclaimedPisList,
  adoptPi,
  pharmacyVmsList,
  pharmacyVmAttach,
  pharmacyVmDetach,
  counterSetBootTarget,
  counterAction,
  counterSupportStart,
  counterSupportStatus,
  counterDelete,
  counterEnrolPi,
  wgPeersReport,
  wgPeersList,
  printersList,
  printerUpsert,
  printerDelete,
  printersReport,
  proxmoxReport,
  proxmoxList,
  tagRulesList,
  tagRulePreview,
  tagRuleCreate,
  tagRuleUpdate,
  tagRuleDelete,
  tagRulesSync,
  alertRulesList,
  alertHistory,
  alertRuleCreate,
  alertRuleUpdate,
  alertRuleDelete,
  alertRuleTest,
  telemetry: telemetryIngest,
  agentScript,
  configPending,
  configScript,
  configResult,
  enroll,
  fleet,
  deviceDetail,
  deviceHistory,
  deviceLogs,
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
