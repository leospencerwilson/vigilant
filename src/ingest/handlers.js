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
// Renders a pharmacy's editable network settings into the dnsmasq drop-in the gateway applies.
const pmrGateway = require('../shared/pmrGateway');
// The one validator + the one copy of the per-thin-client defaults. Both the save path and
// the telemetry push go through this module so the UI, the server and the Pi cannot drift.
const {
  validateCounterSettings, effectiveCounterSettings, interruptingSettingChanges,
  COUNTER_SETTINGS_DEFAULTS,
} = require('../shared/counterSettings');
// The capability the browser presents to the noVNC bridge on the hub. Mirrors
// /etc/wcn/wcn_vnc_token.py there — change one, change both.
const { mintSupportToken } = require('../shared/supportToken');
const notify = require('../worker/notify');
const oui = require('../shared/oui');
// The PMR control plane's CLOSED verb allowlist, the per-verb argument specs and the intent
// field table. Nothing in this file invents a verb, a timing or an argument bound — a
// handler that did would be a second place the allowlist could drift from.
const pmrVerbs = require('../shared/pmrVerbs');
// The one validator for an hours block and the one sentence describing an hours state.
const openingHours = require('../shared/openingHours');
// The capture kit's credential model: the three capabilities, the ticket lifetimes, the role
// picker, and the upload-destination contract. Pure — no DB, no HTTP — so the rules can be
// tested without either.
const captureToken = require('../shared/captureToken');
// docs/pmr-printer-contract.md, server-side: the queue-name pattern, the driver's no-comma
// rule, one `default`, no duplicate on a Pi, at most 32 queues — and §3's untrusted-descriptor
// escaping. Nothing in this file restates one of those rules; it quotes that file.
const printerQueues = require('../shared/printerQueues');
// What a site costs and whether a node can hold one. The measured numbers live there, next to
// the arithmetic, so a refusal can name the resource and the figure it was judged against.
const nodeCapacity = require('../shared/nodeCapacity');

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

  // 4b. WHAT THIS EXECUTOR CLAIMS TO BE RUNNING (A4). Read from `raw` and not from `payload`:
  // telemetry.normalize() does not carry agent_version, and `raw` is byte-for-byte what is
  // persisted to device_state.raw — which is where claimPmrJobForDevice() reads the same
  // number back out inside the claim statement. One value, one parse, so the four directive
  // channels below and the job claim cannot disagree about this Pi's capabilities.
  //
  // An absent, malformed or non-integer version is null, and null meets no floor: a device
  // that has not said what it runs is offered nothing that could restart a kiosk. That is the
  // safe direction and it self-corrects on the first tick that reports one.
  const agentVersionClaimed = pmrVerbs.reportedAgentVersion(raw && raw.agent_version);

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

  // PPPoE password (a secret; sent only on the agent's slow tick). It must NEVER reach
  // device_state — that table is Realtime-published and its `raw` column would broadcast the
  // secret — so we persist it to devices (unpublished, ungranted) and DELETE it from `raw`
  // before device_state is written below. Read from `raw` (the parsed body) rather than
  // `payload`, since normalize() does not carry this field through.
  if (raw && typeof raw === 'object' && 'pppoe_password' in raw) {
    const reportedPppoePw = typeof raw.pppoe_password === 'string' && raw.pppoe_password !== '' ? raw.pppoe_password : null;
    delete raw.pppoe_password; // keep the secret out of device_state.raw / the Realtime broadcast
    if (reportedPppoePw != null && typeof store.setDevicePppoePassword === 'function') {
      try {
        await store.setDevicePppoePassword(device.id, reportedPppoePw);
      } catch (err) {
        log.warn('telemetry: pppoe secret refresh failed', { device: device.id, msg: err && err.message });
      }
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

  // §3 of docs/pmr-printer-contract.md: what the Pi says is PLUGGED IN, at
  // peripherals.printers_attached. Lifted out of device_state.raw into real rows so a
  // physical printer has an identity that survives a rename — which is the whole of §1 and
  // the thing the name-keyed `printers` table cannot do.
  //
  // Counter Pis only, so the router hot path is untouched, and wrapped for the same reason
  // the log append is: this reply also carries the boot target, the settings and the printer
  // table, and a printer-inventory write must never cost a counter those.
  if (device.kind === 'counter-pi' && payload.peripheral_printers
      && Array.isArray(payload.peripheral_printers.printers_attached)
      && typeof store.reportCounterPrinters === 'function') {
    try {
      await store.reportCounterPrinters(device.id, payload.peripheral_printers.printers_attached);
    } catch (err) {
      log.warn('telemetry: printer inventory write failed, continuing',
        { serial: device.serial, err: String((err && err.message) || err) });
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
  //
  // ⛔ AND IT IS BEHIND THE CAPABILITY FLOOR (A4). Applying a boot target restarts the kiosk
  // session, so it is one of the three directives on this reply that can sign a member of
  // staff out. The floor and the reasoning per channel are in
  // pmrVerbs.COUNTER_CHANNEL_AGENT_FLOOR; `agentVersionClaimed` is the device's own claim out
  // of the body it has just posted — the SAME value claimPmrJobForDevice() reads back out of
  // device_state.raw, so the four channels cannot disagree about what this Pi is running.
  let boot = null;
  if (device.kind === 'counter-pi' && pmrVerbs.agentMeetsFloor(agentVersionClaimed, 'boot')
      && typeof store.getCounterBootDirective === 'function') {
    const want = await store.getCounterBootDirective(device.id);
    if (want && want.target) boot = { target: want.target, vmid: want.vmid, user: want.user || null, pass: want.pass || null };
  }

  // 10d. a one-shot service action, if the operator queued one. Collected at most once —
  // see takeCounterAction for why a surviving reboot directive would be a loop.
  //
  // ⛔ THE FLOOR IS TESTED BEFORE THE TAKE, NEVER AFTER (A4). takeCounterAction() CLEARS
  // pending_action as it reads it, so this channel is at-most-once in exactly the way pmr_job
  // is — an agent that cannot run `action` does not ignore a queued reboot, it SWALLOWS it,
  // and the operator sees a counter that was never restarted and no reason why. Checking the
  // floor after the take would make the floor itself the thing that discarded the action.
  let action = null;
  if (device.kind === 'counter-pi' && pmrVerbs.agentMeetsFloor(agentVersionClaimed, 'action')
      && typeof store.takeCounterAction === 'function') {
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
  //
  // ⛔ ABSENT MUST BE ABSENT (A3). This read used to be
  // `effectiveCounterSettings(row && row.settings)`, and that erased the difference between
  // the two answers getCounterSettingsForDevice() can give:
  //
  //   a row       — this Pi IS linked to a counter, and these are the operator's values.
  //   NULL        — the counter row was DELETED, or this Pi is no longer linked to one.
  //                 Nobody has an opinion about this device at all.
  //
  // effectiveCounterSettings(null) returns the FULL DEFAULT SET, which is truthy, so the
  // second answer went out on the wire as `settings` and the agent applied it. A counter that
  // had been deleted was therefore indistinguishable from an operator who had just chosen
  // every default — and if that counter ran any non-default session value (colour depth,
  // resolution), the Pi rendered a changed kiosk.conf and RESTARTED THE KIOSK. Deleting a
  // row in Watchman signed a member of staff out, with no gate, no credential and no record.
  //
  // So the key is omitted entirely for an unlinked Pi. That is this channel's own documented
  // convention — the same reason `boot`, `action`, `relay`, `branding` and `printers` are all
  // absent rather than null — and it is the only shape that means "the server has no opinion;
  // do nothing" instead of "the server's opinion is the defaults".
  //
  // ⛔ AND BEHIND THE SAME CAPABILITY FLOOR AS `boot` (A4) — a settings push that changes a
  // session value restarts the kiosk, which is the whole reason PATCH /counters/:id has to
  // climb requireDeliberateInterruption() before it can write one.
  let settings = null;
  if (device.kind === 'counter-pi' && pmrVerbs.agentMeetsFloor(agentVersionClaimed, 'settings')
      && typeof store.getCounterSettingsForDevice === 'function') {
    const row = await store.getCounterSettingsForDevice(device.id);
    if (row) settings = effectiveCounterSettings(row.settings);
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
  if (device.kind === 'counter-pi') {
    try {
      const row = (typeof store.getBranding === 'function') ? (await store.getBranding()) || {} : {};
      // Per-site banner OVERRIDES the fleet-wide kiosk_message (estate owner's call 2026-08-19):
      // a message set on this Pi's pharmacy in the Site Configurator shows on every counter Pi at
      // the site. Format is "<level>\n<text>", which the counter's wcn-banner parses into a
      // severity colour + message. brandingDirective() re-hashes the MERGED row, so the agent
      // re-applies the moment the site message changes.
      if (typeof store.getSiteBanner === 'function') {
        const site = await store.getSiteBanner(device.id);
        if (site && site.banner_text) {
          const level = ['info', 'warning', 'alert'].includes(site.banner_level) ? site.banner_level : 'info';
          row.kiosk_message = `${level}\n${site.banner_text}`;
        }
      }
      branding = brandingDirective(row);
    } catch (err) {
      // A cosmetic lookup must NEVER kill a telemetry tick. This same reply carries the boot
      // target, the queued service action and the relay handover — losing those to a failed
      // branding read would cost an engineer a site visit for the sake of a logo.
      log.warn('telemetry: branding lookup failed', { device: device.id, msg: err && err.message });
      branding = null;
    }
  }

  // 10h. a PMR control-plane job for this counter. Rides this same reply for the same
  // reason every other directive does: there is no second poller, and nothing can dial in
  // to a Pi. What makes it a JOB rather than another `action` is that it has a ladder — it
  // is claimed atomically by being handed out here, the executor reports whether it ran,
  // and it is only DONE when an independent reading proves it. `action` has none of those.
  //
  // Two things happen here and the order matters:
  //   * notePmrSessionDown FIRST, because it is an OBSERVATION of the tick that has just
  //     been written — the moment a thin client reports its RDP client down after a
  //     restart job was applied. Taking it before a new job is handed out keeps the
  //     reading attached to the job it actually proves.
  //   * then the claim. claimPmrJobForDevice applies all three gates in ONE statement:
  //     the time limit, the visibility timeout, and pmr_job_wait_reason() — which is where
  //     the OPENING HOURS gate lives. A disruptive job at a site that is open is simply
  //     not selected, so it stays pending and pmr_jobs_v tells the operator it is waiting.
  //     Watchman cannot restart a session during opening hours by this path at all.
  //
  // Sent AT MOST ONCE per claim, unlike boot/settings/relay: handing it out IS the claim.
  // A verb whose claim may lapse and be re-offered says so with retry_ok, and that decision
  // is made in the claim statement, never here.
  let pmrJob = null;
  if (device.kind === 'counter-pi' && typeof store.claimPmrJobForDevice === 'function') {
    try {
      if (typeof store.notePmrSessionDown === 'function') await store.notePmrSessionDown(device.id);
      // ⚠️ THE CAPABILITY FLOOR (S10). Handing the job out IS the claim, so an executor
      // that cannot parse `pmr_job` does not ignore it — it SWALLOWS it, and the job goes
      // pending -> claimed -> expired with nothing having happened. The shipped Pi agent
      // reports agent_version 1 and has no pmr_job branch at all, so with the control plane
      // switched on today every nightly restart at every live site would be lost that way,
      // and the pre-opening check would email "counters may not open" for the WHOLE estate,
      // every night, on the one channel reserved for real outages.
      //
      // The floor is passed from the allowlist, never defaulted here: the store refuses to
      // claim at all without one, so forgetting this argument fails closed.
      const claimed = await store.claimPmrJobForDevice(
        device.id, device.serial || 'counter-pi', pmrVerbs.PMR_JOB_AGENT_VERSION
      );
      // Only ever a NAME plus the server-resolved arguments. There is no command line in
      // this object and there must never be one — the Pi looks the name up in its own
      // table, exactly as ACTIONS does for the one-shot verbs.
      if (claimed && claimed.job_id) {
        pmrJob = { id: claimed.job_id, verb: claimed.verb, args: claimed.args || {} };
      }
    } catch (err) {
      // Same guard as branding, and it matters more here: this reply also carries the boot
      // target and the relay handover, and a failed job claim must not cost a counter those.
      log.warn('telemetry: pmr job claim failed', { device: device.id, msg: err && err.message });
      pmrJob = null;
    }
  }

  // 10i. THE PRINTER TABLE (§2 of docs/pmr-printer-contract.md).
  //
  // "Send the whole effective table every tick, like `settings`." Same channel, same
  // self-healing reason as the boot target and the settings: a printers.tab.next edited by
  // hand on the device is put back to what Watchman says, and the agent decides only whether
  // the RENDERED FILE changed. Nothing on this path touches a live session — the agent writes
  // .next and stops; `counter.printing-promote` is the verb that swaps it live.
  //
  // ⛔ THE SERVER RE-RUNS §2 OVER THE WHOLE RESULTING TABLE, AND THIS IS NOT A DUPLICATE OF
  // THE UI'S CHECK. The front end validates what an operator is typing, from telemetry that
  // TRUNCATES (print_tab_live/next stop at sixteen names, printer_names at six), so it cannot
  // see the whole table and its queue counts are lower bounds. This check sees the complete
  // effective set — including queues hosted on ANOTHER counter and shared onto this desktop,
  // which is exactly where a duplicate name appears, because two counters each holding a
  // queue called `Label` is the NORMAL pattern (§1). It is the only complete one.
  //
  // ⛔ AND IT REFUSES THE WHOLE TABLE. "A table is a SET: refuse it entirely if any line is
  // bad, never apply it partially. A partially-applied table is internally consistent and
  // quietly wrong — indistinguishable from an operator who meant it."
  //
  // ⛔ ABSENT-NOT-NULL, and the two absences mean different things:
  //   * a table that FAILED validation is sent as NOTHING. "`printers` ABSENT means the
  //     server has no opinion; do nothing" — so the counter keeps the last good staged file
  //     while a person is told which line is at fault, which is the only safe direction.
  //   * an EMPTY effective set is also sent as nothing. §2 allows `printers: []` and defines
  //     it as "leave the staged file alone", so sending it would be a no-op with a cost; what
  //     it must NEVER be taken to mean is "no printers here", because "the launcher's
  //     fallback turns a file with no valid lines back into a derived set". Not sending the
  //     key says the same thing and cannot be misread.
  let printers = null;
  if (device.kind === 'counter-pi' && typeof store.getCounterPrinterTableForDevice === 'function') {
    try {
      const table = await store.getCounterPrinterTableForDevice(device.id);
      if (Array.isArray(table) && table.length) {
        // Only the three keys §2 puts on the wire. host_counter_id and `local` are ours, for
        // the UI's "shared from another counter" line, and have no business on the device.
        const wire = table.map((r) => ({
          queue: r.queue,
          driver: r.driver,
          flags: Array.isArray(r.flags) ? r.flags : [],
        }));
        const checked = printerQueues.validatePrinterTable(wire, 'effective printer table');
        if (checked.ok) {
          printers = checked.value;
        } else {
          // warn, not info: a site whose table cannot be sent is a site whose printer changes
          // are silently not arriving, and the operator's only clue is a queue that never
          // appears. Named loudly enough to be found without knowing to look.
          log.warn('printers: the effective table for this counter is REFUSED, so nothing is sent',
            { device: device.id, serial: device.serial, why: checked.error });
        }
      }
    } catch (err) {
      log.warn('telemetry: printer table lookup failed', { device: device.id, msg: err && err.message });
      printers = null;
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
  // Absent on every tick that has no job, which is nearly all of them: a counter takes one
  // job a night. Same reasoning as "action", plus one specific to this key — the reply read
  // is bounded at 64000 bytes on the device and a reply clipped mid-JSON loses EVERY
  // directive in it, so a key that would be null 2,879 ticks out of 2,880 is not free.
  if (pmrJob) response.pmr_job = pmrJob;
  // ABSENT unless there is a valid, non-empty table — see 10i. `printers` absent is the
  // contract's own "the server has no opinion", and it is what a refused table sends too.
  if (printers) response.printers = printers;
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
  // ⚠️ THE CREDENTIAL WINS, AND THE ROW REMEMBERS WHICH IT WAS (A6). An operator token names
  // a person; `created_by` in the body is a string the browser chose. Both are accepted —
  // authoring a draft serves no router and blocking the shared token here would only push
  // people off the review path entirely — but they are NOT recorded as the same kind of fact,
  // because the two-person rule downstream compares this name against the approver's and can
  // only be a real rule if both were proved.
  const createdBy = ctx.actor
    || (parsed && typeof parsed.created_by === 'string' ? parsed.created_by.trim() : '');
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
    created_by_credential: !!ctx.actor,
  });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(
      createdBy,
      'config.draft',
      device.serial,
      `job=${job.id} kind=${kind} sha=${job.rsc_sha256} author=${ctx.actor ? 'credential' : 'self-declared'}`
    );
  }
  log.info('config: draft created', { serial: device.serial, job: job.id, author_proved: !!ctx.actor });
  return json(res, 201, {
    ok: true,
    job,
    // So the UI can say, at the point the draft is made, whether the approval that follows
    // will be able to be a real two-person one.
    author_attribution: ctx.actor ? 'credential' : 'self-declared',
  });
}

// POST /config-jobs/:id/approve — the second-person approval.
//
// ⛔ WHAT THIS CHECK ACTUALLY PROVES, WHICH IS NOT WHAT IT USED TO SAY (A6). Both names came
// out of a request body carrying the shared admin token, so "the approver must differ from
// the author" compared two strings the SAME caller had supplied. One person could author as
// "leo", approve as "jake", and the RUNBOOK's two-person guarantee was a naming convention.
//
// THE CHOICE: the approver is taken from a CREDENTIAL when one is presented, and when one is
// not, this stops calling itself a two-person rule — in the response, in the audit line and
// in the log — rather than refusing outright, because the shared-token path is what the
// browser has today and a refusal would push the estate off the review path onto SSH, where
// there is no record at all. So both halves of the finding are closed: the rule is real when
// it can be, and honest when it cannot.
//
// `two_person` on the response is TRUE only when BOTH names were proved by a credential and
// they differ. That is the only combination in which a second secret was actually held.
async function configJobApprove(ctx) {
  const { res, store, log, params, body } = ctx;
  let parsed;
  try {
    parsed = JSON.parse(body || '');
  } catch (e) {
    return json(res, 400, { ok: false, error: 'bad json' });
  }
  // The credential wins over the body, always — a name the browser chose can never override
  // a name a secret proved.
  const approvedBy = ctx.actor
    || (parsed && typeof parsed.approved_by === 'string' ? parsed.approved_by.trim() : '');
  if (!approvedBy) return json(res, 400, { ok: false, error: 'approved_by required' });

  if (typeof store.getConfigJob !== 'function' || typeof store.approveConfigJob !== 'function') {
    return json(res, 501, { ok: false, error: 'config push not supported by this store' });
  }
  const job = await store.getConfigJob(params.id);
  if (!job) return json(res, 404, { ok: false, error: 'not found' });
  if (job.status !== 'draft') {
    return json(res, 409, { ok: false, error: `job is '${job.status}', not 'draft'` });
  }
  // The names must differ. This holds whichever way each was established: two different
  // credentials are two people, and two different self-declared names are at least two
  // different claims on the record.
  if (job.created_by && approvedBy.toLowerCase() === String(job.created_by).toLowerCase()) {
    return json(res, 409, {
      ok: false,
      error: 'the approver must differ from the author',
    });
  }
  // ⛔ AND THIS IS THE PART THAT MAKES IT A RULE RATHER THAN A CONVENTION. A second SECRET was
  // held only if both names came from credentials. Anything less is provenance, and is
  // reported as provenance.
  const approverProved = !!ctx.actor;
  const authorProved = job.created_by_credential === true;
  const twoPerson = approverProved && authorProved;

  const updated = await store.approveConfigJob(params.id, approvedBy, approverProved);
  if (!updated) return json(res, 409, { ok: false, error: 'could not approve (status changed?)' });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(approvedBy, 'config.approve', null,
      `job=${params.id} author=${job.created_by} two_person=${twoPerson}`
      + ` author_attribution=${authorProved ? 'credential' : 'self-declared'}`
      + ` approver_attribution=${approverProved ? 'credential' : 'self-declared'}`);
  }
  log.info('config: job approved', { job: params.id, two_person: twoPerson });
  return json(res, 200, {
    ok: true,
    job: updated,
    // ⚠️ THE HONEST ANSWER, and the UI must render it. false does NOT mean the approval
    // failed — it means the two names were typed under one shared token, so this is a record
    // of who said they did it and not proof that two people did.
    two_person: twoPerson,
    author_attribution: authorProved ? 'credential' : 'self-declared',
    approver_attribution: approverProved ? 'credential' : 'self-declared',
    note: twoPerson
      ? 'author and approver each proved a separate operator credential'
      : 'both names were supplied under the shared admin token, so this records who says they '
        + 'authored and approved it — it does not prove two people were involved. Use '
        + 'PMR_OPERATOR_TOKENS on both calls for a two-person approval.',
  });
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

// The Authorization bearer, for the one handler that has to look at a credential itself:
// POST /capture/token authenticates a TICKET, and a ticket is not any of the credential kinds
// the dispatch knows how to check. Everywhere else the dispatch has already decided.
function bearerFromRequest(req) {
  const h = (req && req.headers && req.headers['authorization']) || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : '';
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

// The states a change is still GOING to happen in. 'confirmed' is done, and the four
// terminal failures are history — neither belongs in a panel headed "pending".
const PMR_PENDING_STATES = new Set(['pending', 'waiting', 'claimed', 'applied']);

// ── GET /pharmacies/:id (admin) ─────────────────────────────────────────────
// ⚠️ hours AND pendingChanges ARE COMPOSED HERE (B7/S11). Nothing server-side emitted either
// of them, so the site page's hours pill read "hours unknown" forever and its pending-changes
// panel never rendered — the two pieces of UI whose whole job is to tell an operator that
// something is queued against a live pharmacy and when it will land.
//
//   hours           from the SAME site_hours_state() the job gate reads, through the ONE
//                   serialiser (openingHours.hoursPayload) — so `openNow` is OMITTED, never
//                   false, when the site's hours do not resolve (S6). The screen must be
//                   able to say "unknown"; it must never say "closed" because a lookup came
//                   back empty.
//   pendingChanges  from the job list, carrying waitingReason and appliesAt so the panel can
//                   say WHY something has not run and WHEN it will. appliesAt is not_before,
//                   which since S1/S12 is a real stored instant rather than the word
//                   "midnight" in a sentence.
//
// Both are best-effort: a failed hours read must not cost the page its counters.
async function pharmacyGet(ctx) {
  const { res, store, log, params } = ctx;
  const p = await store.getPharmacy(params.id);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const counters = typeof store.listCounters === 'function' ? await store.listCounters(p.id) : [];

  let hours = null;
  let pendingChanges = [];
  try {
    if (typeof store.getSiteHours === 'function') {
      hours = openingHours.hoursPayload(await store.getSiteHours(p.id, null));
    }
  } catch (err) {
    log.warn('pmr: hours lookup failed for the site page', { pharmacy: p.id, msg: err && err.message });
    // null, not a fabricated "closed". The serialiser's own unresolved shape is the right
    // answer to "we could not find out".
    hours = openingHours.hoursPayload(null);
  }
  try {
    if (typeof store.listPmrJobs === 'function') {
      const jobs = await store.listPmrJobs({ pharmacy_id: p.id, status: null });
      pendingChanges = jobs
        .filter((j) => PMR_PENDING_STATES.has(j.state || j.status))
        .map((j) => ({
          id: j.id,
          verb: j.verb,
          state: j.state || j.status,
          disruptive: !!j.disruptive,
          counterId: j.counter_id,
          vmid: j.vmid,
          // Why it has not run. Null when nothing is holding it.
          waitingReason: j.waiting_reason || null,
          // When it WILL run, as an instant. Null means "as soon as an executor polls".
          appliesAt: j.not_before || null,
          expiresAt: j.expires_at || null,
          overrideHours: !!j.override_hours,
          overrideBy: j.override_by || null,
          by: j.created_by,
          createdAt: j.created_at,
        }));
    }
  } catch (err) {
    log.warn('pmr: job list failed for the site page', { pharmacy: p.id, msg: err && err.message });
    pendingChanges = [];
  }
  return json(res, 200, { ok: true, pharmacy: p, counters, hours, pendingChanges });
}

// Validate the editable network settings before they reach the DB. Format + range + pool
// ordering are checked here; subnet-containment against the site's own net is enforced in the
// UI (which knows the index). `idx` is passed on create so the last octet can be range-checked
// against the prefix; on update it is omitted (idx is immutable) and containment is skipped.
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const lastOctet = (ip) => Number(String(ip).split('.').pop());
function validateNetFields(p, { idx } = {}) {
  let prefix = null;
  if (p.prefix_len !== undefined && p.prefix_len !== null && p.prefix_len !== '') {
    prefix = Number(p.prefix_len);
    if (!Number.isInteger(prefix) || prefix < 24 || prefix > 30) return 'prefix_len must be an integer 24–30';
  }
  const single = { gateway_ip: 'gateway_ip', server_ip: 'server_ip', dhcp_from: 'dhcp_from', dhcp_to: 'dhcp_to', ntp_server: 'ntp_server' };
  for (const key of Object.keys(single)) {
    const v = p[key];
    if (v === undefined || v === null || v === '') continue;
    if (!IPV4.test(String(v).trim())) return `${key} must be a valid IPv4 address`;
  }
  if (p.dns_servers !== undefined && p.dns_servers !== null && String(p.dns_servers).trim() !== '') {
    const parts = String(p.dns_servers).split(',').map((s) => s.trim()).filter(Boolean);
    if (!parts.length || parts.some((s) => !IPV4.test(s))) return 'dns_servers must be a comma-separated list of IPv4 addresses';
  }
  // Pool ordering and, when we can, containment in the /prefix.
  const from = p.dhcp_from, to = p.dhcp_to;
  if (from && to && IPV4.test(String(from)) && IPV4.test(String(to))) {
    if (lastOctet(from) > lastOctet(to)) return 'dhcp_from must not be above dhcp_to';
    if (prefix != null && idx != null) {
      const max = Math.pow(2, 32 - prefix) - 1; // last usable octet within 10.200.idx.0/prefix
      for (const [k, v] of [['dhcp_from', from], ['dhcp_to', to]]) {
        if (String(v).startsWith(`10.200.${idx}.`) && lastOctet(v) > max) return `${k} (${v}) is outside 10.200.${idx}.0/${prefix}`;
      }
    }
  }
  return null;
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
    return json(res, 400, { ok: false, error: 'idx must be an integer 1–154 (it derives vlan 100+idx and 10.200.idx.0/27)' });
  }
  if (p.pmr_system && !PMR_SYSTEMS.includes(p.pmr_system)) return json(res, 400, { ok: false, error: `pmr_system must be one of ${PMR_SYSTEMS.join(', ')}` });
  if (p.status && !PMR_STATUSES.includes(p.status)) return json(res, 400, { ok: false, error: `status must be one of ${PMR_STATUSES.join(', ')}` });
  const netErr = validateNetFields(p, { idx });
  if (netErr) return json(res, 400, { ok: false, error: netErr });
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
  const netErr = validateNetFields(p, {});
  if (netErr) return json(res, 400, { ok: false, error: netErr });
  const updated = await store.updatePharmacy(params.id, p);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  return json(res, 200, { ok: true, pharmacy: updated });
}

// ── DELETE /pharmacies/:id (admin) ──────────────────────────────────────────
// ⚠️ THE CONFIRMATION IS PART OF THE REQUEST, AND THE SERVER CHECKS IT (B4).
//
// It used to be enforced by a `disabled` attribute on a button in the browser: type the site
// name to enable Delete. This handler then called store.deletePharmacy(id) unconditionally —
// no name, no force, no check on whether the pharmacy was dispensing — and the row went,
// cascading its counters, printers, VM registrations, opening hours and jobs. Anything that
// reached the route with a valid token deleted a live site: a stale tab, a scripted call, a
// mis-click on a page that had already lost the dialog's state.
//
// Watchman has no user roles — everyone gets everything — so that dialog was the ONLY
// boundary in front of this. A boundary that lives in the browser is not one.
//
// THE CONTRACT: { "confirm": "<the site's name, exactly>", "force": true (live sites only) }
// `confirm` may also arrive as ?confirm= for a client that cannot send a DELETE body. The
// comparison is trimmed and case-folded, and it happens INSIDE the delete statement, so
// there is no window between checking the name and removing the row.
function deleteConfirmation(ctx) {
  const p = ctx.body ? parseJsonBody(ctx.body) : null;
  const fromBody = p && typeof p.confirm === 'string' ? p.confirm : '';
  const fromQuery = ctx.query ? String(ctx.query.get('confirm') || '') : '';
  const force = !!(p && p.force === true) || String((ctx.query && ctx.query.get('force')) || '') === 'true';
  return { confirm: (fromBody || fromQuery).slice(0, 200), force };
}

async function pharmacyDelete(ctx) {
  const { res, store, log, params } = ctx;
  const { confirm, force } = deleteConfirmation(ctx);
  const r = await store.deletePharmacy(params.id, { confirm, force });
  if (!r || !r.found) return json(res, 404, { ok: false, error: 'not found' });
  if (!r.deleted) {
    // Two different refusals, said differently, because an operator who gets "nothing
    // happened" tries again harder and an operator who gets the reason stops.
    if (r.status === 'live' && !force) {
      return json(res, 409, {
        ok: false,
        error: 'that pharmacy is LIVE — its counters may be dispensing right now. Send '
             + '"force": true as well as the typed name if you really mean to delete it.',
        status: r.status,
      });
    }
    return json(res, 400, {
      ok: false,
      error: 'type the pharmacy\'s name exactly to confirm — this also deletes its '
           + 'counters, printers, VM registrations, opening hours and jobs',
      expects: 'confirm',
    });
  }
  log.warn('pmr: a pharmacy was deleted', { pharmacy: params.id, name: r.name, was: r.status });
  return json(res, 200, { ok: true, deleted: r.deleted, name: r.name });
}

// GET /pharmacies/:id/gateway-config — render (read-only) the dnsmasq drop-in this site's
// current network settings produce. This is the exact file a config-push job would write to
// /etc/dnsmasq.d on the gateway, so an operator can preview it, diff it, or apply it by hand
// before the automated push path is trusted for a given site.
async function pharmacyGatewayConfig(ctx) {
  const { res, store, params } = ctx;
  const p = await store.getPharmacy(params.id);
  if (!p) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  let config;
  try {
    config = pmrGateway.renderSiteDnsmasq(p);
  } catch (e) {
    // A planned site can legitimately lack addressing; say so rather than 500.
    return json(res, 409, { ok: false, error: `cannot render config: ${e.message}` });
  }
  return json(res, 200, {
    ok: true,
    filename: pmrGateway.siteDnsmasqFilename(p.code),
    config,
    sha256: transform.sha256Hex(config),
  });
}

// GET /gateway/dnsmasq — the whole fleet's dnsmasq drop-ins, for the gateway agent on VM 300 to
// write into /etc/dnsmasq.d and reload. Each file carries its own sha256 so the agent only
// rewrites+reloads on change; `skipped` names any site that could not render (so a half-set-up
// site is visible, not silently missing) and `manifest_sha256` covers the whole set for a quick
// "anything changed?" check.
async function gatewayDnsmasqManifest(ctx) {
  const { res, store } = ctx;
  if (typeof store.listPharmacies !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const pharmacies = await store.listPharmacies();
  const { files, skipped } = pmrGateway.renderAllSites(pharmacies);
  const withSha = files.map((f) => ({ ...f, sha256: transform.sha256Hex(f.config) }));
  const manifestSha = transform.sha256Hex(withSha.map((f) => `${f.filename}:${f.sha256}`).join('\n'));
  return json(res, 200, { ok: true, prefix: 'pmr-', manifest_sha256: manifestSha, files: withSha, skipped });
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
    return json(res, 400, { ok: false, error: 'n must be an integer 1–79 (it derives the VM address 10.200.x.(10+n) and the Pi tunnel 10.255.x.n)' });
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
  const { res, store, log, body, params } = ctx;
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

  // ⚠️ A SESSION SETTING CHANGE SIGNS A MEMBER OF STAFF OUT (D3). The Pi writes the kiosk
  // conf and then restarts the kiosk once — folded together with a boot target arriving on
  // the same tick so the counter is interrupted once and not twice
  // (agent/pi/vigilant-pi-agent.py:1720-1726). THE FOLDING IS RIGHT AND STAYS. What was
  // missing is any gate on the WRITE: saving `bpp` from the edit modal at 11:00 on a trading
  // Tuesday restarted that counter's session about thirty seconds later.
  //
  // Gated on the CHANGE, not on the key being mentioned. The modal saves the whole form, so
  // every save carries all five session options; demanding a typed pharmacy name to alter
  // the printer poll cadence would teach people to type it without reading. See
  // counterSettings.interruptingSettingChanges — it compares effective values, so a no-op
  // save and an agent-only save pass straight through.
  //
  // NOT stageable, unlike the boot target. There is one settings column and the server's
  // contract is to push the whole EFFECTIVE set on every tick, so a "pending" copy would be
  // a second value the device could be handed — and a settings channel whose safety rests on
  // there being exactly one validated value is not the place to add a second. An operator
  // who does not need it now waits for the nightly restart to pick it up, or raises a
  // counter.session-restart job.
  let interrupting = [];
  let counterRow = null;
  if (settings && Object.keys(settings).length && typeof store.getCounter === 'function') {
    counterRow = await store.getCounter(params.id);
    if (!counterRow) return json(res, 404, { ok: false, error: 'counter not found' });
    interrupting = interruptingSettingChanges(counterRow.settings, settings);
    // A counter with no thin client enrolled cannot be interrupted — there is nothing there
    // to restart — so the gate would only be theatre.
    if (interrupting.length && counterRow.pi_device_id) {
      const gate = await requireDeliberateInterruption(ctx, counterRow, p, {
        effect: `changing ${interrupting.join(', ')} restarts the kiosk session and signs the `
              + 'member of staff at that counter out when it lands',
        instead: 'Every other setting on this form saves without interrupting anybody. To '
               + 'change these at a quiet hour instead, save them tonight or raise a '
               + 'counter.session-restart job (POST /pmr/jobs) and let the nightly window '
               + 'apply them.',
      });
      if (!gate.ok) return;
    }
  }

  const updated = await store.updateCounter(params.id, p);
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  // MERGED, not replaced (see setCounterSettings): saving one field must leave the rest
  // alone. Skipped for an empty object so a no-op save does not touch the row.
  if (settings && Object.keys(settings).length) {
    const merged = await store.setCounterSettings(params.id, settings);
    if (merged) {
      if (interrupting.length) {
        log.warn('pmr: a live counter will be interrupted by a settings change', {
          counter: params.id, keys: interrupting, by: ctx.actor || null,
          pharmacy: counterRow && counterRow.pharmacy_id,
        });
      }
      return json(res, 200, {
        ok: true,
        counter: merged,
        // THE UI'S SENTENCE, computed server-side so the browser cannot get it wrong: which
        // keys in this save will interrupt the counter when the device picks them up.
        interrupts: interrupting.length > 0,
        interrupting_settings: interrupting,
        warning: interrupting.length
          ? 'the thin client will restart its kiosk session on its next tick — this signs '
            + 'the member of staff at that counter out'
          : null,
      });
    }
  }
  return json(res, 200, { ok: true, counter: updated, interrupts: false, interrupting_settings: [] });
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

// POST /printers/adopt (admin) — { pharmacy_id, printer_id, as:'new'|'merge', into_printer_id?,
// into_device_serial? }. 'new' makes the row its own printer; 'merge' records it as another
// address-form of one already listed (kept as evidence, never deleted).
async function printerAdopt(ctx) {
  const { res, store, log, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!p.pharmacy_id || !p.printer_id) return json(res, 400, { ok: false, error: 'pharmacy_id and printer_id required' });
  if (p.as && p.as !== 'new' && p.as !== 'merge') return json(res, 400, { ok: false, error: "as must be 'new' or 'merge'" });
  const r = await store.adoptPrinter(p.pharmacy_id, {
    printer_id: p.printer_id,
    as: p.as || 'new',
    into_printer_id: p.into_printer_id || null,
    into_device_serial: p.into_device_serial || null,
  });
  if (r && r.error) return json(res, 409, { ok: false, error: r.error });
  log.warn('pmr: printer adopted', { pharmacy_id: p.pharmacy_id, printer_id: p.printer_id, as: p.as || 'new' });
  return json(res, 200, { ok: true, ...r });
}

// POST /printers/identify (admin) — { pharmacy_id, printer_id, counter_id? }. Queues a Pi to read
// what is at the printer's address; it reports back on its next tick.
async function printerIdentify(ctx) {
  const { res, store, log, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!p.pharmacy_id || !p.printer_id) return json(res, 400, { ok: false, error: 'pharmacy_id and printer_id required' });
  const r = await store.identifyPrinter(p.pharmacy_id, { printer_id: p.printer_id, counter_id: p.counter_id || null });
  if (r && r.error) return json(res, 409, { ok: false, error: r.error });
  log.warn('pmr: printer identify queued', { pharmacy_id: p.pharmacy_id, printer_id: p.printer_id, counter_id: r.counter_id });
  return json(res, 200, { ok: true, ...r });
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

// GET /agent/pi-toolbox and /agent/pi-toolbox-priv — the on-console support toolbox scripts,
// served to the DEVICE on the SAME device-token + sha256 contract as the agent above, so all
// three (agent, toolbox, priv helper) update through one channel and one trust boundary rather
// than only arriving with a reimage. `which` is chosen by the ROUTE, never by the caller, and is
// checked against a two-entry allowlist, so this can never be steered to read an arbitrary path.
const TOOLBOX_FILES = {
  'wcn-toolbox':      'text/x-shellscript; charset=utf-8',
  'wcn-toolbox-priv': 'text/x-shellscript; charset=utf-8',
  'wcn-kiosk':        'text/x-shellscript; charset=utf-8',
};
async function piToolboxScript(ctx, which) {
  const { res, device, log } = ctx;
  if (!device || device.kind !== 'counter-pi') {
    return json(res, 403, { ok: false, error: 'this endpoint serves counter-pi devices only' });
  }
  if (!Object.prototype.hasOwnProperty.call(TOOLBOX_FILES, which)) {
    return json(res, 404, { ok: false, error: 'unknown toolbox file' });
  }
  let body;
  try {
    body = require('node:fs').readFileSync(`/app/agent/pi/${which}`, 'utf8');
  } catch (e) {
    return json(res, 500, { ok: false, error: 'toolbox script not present in this build' });
  }
  log.info('agent: toolbox script fetched', { serial: device.serial, which, bytes: body.length });
  return text(res, 200, body, {
    'content-type': TOOLBOX_FILES[which],
    'x-vigilant-sha256': crypto.createHash('sha256').update(body).digest('hex'),
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// INTERRUPTING A LIVE COUNTER IS A DELIBERATE, ATTRIBUTED ACT (D1/D2/D3)
// ══════════════════════════════════════════════════════════════════════════════
// The job ladder grew a careful hours gate, an attempts cap, a named operator credential and
// a typed site name — and all of it guarded ONE door, POST /pmr/jobs/:id/apply-now. Three
// older routes could still sign a member of staff out of a live dispensing session with none
// of it:
//
//   POST /counters/:id/action  {"restart-kiosk"|"reboot"}   admin token, `by` from the body
//   PUT  /counters/:id/boot-target                          admin token, no gate at all
//   PATCH /counters/:id        {"settings":{…session…}}      admin token, no gate at all
//
// ⚠️ THE FIX IS NOT TO BLOCK THEM. A support engineer on the phone to a pharmacy legitimately
// restarts a counter at 11:00 on a Tuesday, and a platform that makes that impossible gets
// worked around with SSH, where there is no record at all. The goal is that interrupting a
// live counter is always DELIBERATE and ATTRIBUTED — never incidental, never anonymous.
//
// So all three now come through here, and it is the same ladder apply-now climbs:
//
//   1. A NAMED OPERATOR CREDENTIAL, and the actor comes from the CREDENTIAL. ctx.actor is
//      set by the dispatch in server.js from PMR_OPERATOR_TOKENS. It is never read from the
//      body: the browser holds the shared admin token, so a name in `by` is a string the
//      browser chose, and "watchman signed a pharmacist out" records nothing.
//   2. THE TYPED SITE NAME, ON THE WIRE, when the site is OPEN or its hours are UNRESOLVED.
//      A confirmation dialog that lives only in the browser is not a boundary.
//   3. THE UNKNOWN COUNTS AS OPEN. This is a gate, and a gate's unknown is "do not disrupt",
//      the same asymmetry pmr_disruptive_allowed() carries.
//
// It deliberately does NOT hold the action back to the overnight window. That is what the
// job ladder is for, and each caller's refusal message names the deferred route instead.
//
// ── ⛔ THE TYPED NAME IS ONE FIELD WITH ONE SPELLING, AND THE REFUSAL SAYS SO (W3) ──────
// Every route in this file that can sign a member of staff out asks for the SAME field, in
// the same place, with the same comparison — `confirm`, a string in the JSON request body,
// trimmed and case-folded against the site's name (its code is accepted when it has no name).
//
// ⚠️ WHY THE VERDICT IS THREE-VALUED RATHER THAN A BOOLEAN. The four callers on the other
// side of this contract currently send NO confirm at all, and a refusal that says only "type
// the site's name" is indistinguishable, to the person writing that caller, from "you typed
// it wrong". Those are different bugs with different fixes: one is a missing field in the
// request, the other is a mismatched value. A gate whose refusal cannot be acted on gets
// worked around, and the way this gate gets worked around is SSH, where there is no record
// at all. So the field is NAMED in the refusal and the two cases are said differently.
//
//   'ok'        the name matches.
//   'missing'   no `confirm` key, or it is not a string, or it is blank after trimming.
//   'mismatch'  a name was typed and it is not this site's.
//
// `expect` empty — a site with neither a name nor a code — is 'mismatch', never 'ok': an
// empty expectation must not become a gate that anything satisfies.
//
// ── EVERY ROUTE THAT CAN DEMAND IT, AND THE EXACT BODY EACH ONE NEEDS ────────
// `confirm` is required ONLY in the conditions named; sending it when it is not required is
// harmless and ignored, so a caller may always include it. It is a JSON body field on every
// route below, including the DELETE — a confirmation that lives only in the browser is not a
// boundary, so it has to travel on the wire.
//
//   POST /counters/:id/action
//     { "action": "reboot"|"restart-kiosk"|"restart-agent"|"clear-failed", "confirm"?: "<site name>" }
//     confirm required for reboot and restart-kiosk when the site is OPEN or its hours are
//     not a FACT. The other two actions never require it. Operator token needed for the
//     first two; the shared admin token still drives the other two.
//
//   PUT|PATCH /counters/:id
//     { …counter fields…, "settings": {…}, "confirm"?: "<site name>" }
//     confirm required only when `settings` actually CHANGES one of the session-interrupting
//     options (counterSettings.interruptingSettingChanges) AND the counter has a Pi enrolled.
//     A save that changes nothing interrupting needs nothing.
//
//   PUT|POST /counters/:id/boot-target
//     { "vmid": <int>|null, "when": "overnight"|"now", "confirm"?: "<site name>" }
//     confirm required only for when:"now" — the default, "overnight", stages and interrupts
//     nobody.
//
//   POST /counters/:id/printing-promote
//     { "now"?: true, "confirm"?: "<site name>" }
//     confirm required only when now:true. Without `now` the promotion is staged to the
//     site's own overnight window and needs no override.
//
//   POST /pmr/jobs/:id/apply-now
//     { "confirm"?: "<site name>" }
//     confirm required when the job is `disruptive` and the site is OPEN or its hours are not
//     a FACT. Operator token ALWAYS required on this route, whatever the body.
//
//   PUT|POST /pharmacies/:id/hours          { "blocks": [...], "closed_wdays": [...], "confirm"?: … }
//   PUT|POST /pharmacies/:id/hours/exception { "on_date": "YYYY-MM-DD", …, "confirm"?: … }
//   DELETE   /pharmacies/:id/hours/exception?on_date=YYYY-MM-DD   { "confirm"?: … }
//     confirm required only when the edit would NEWLY arm the nightly restart on a day that
//     currently forbids it (openingHours.newlyPermittedWdays / dayNewlyPermitted). The
//     refusal names the affected weekdays. Operator token always required for these writes.
//
// The name to type is the SITE's, resolved as `name || code`, and every refusal returns it in
// `site` along with a ready-made `body` — so no caller has to guess the spelling.
function confirmVerdict(parsed, expect) {
  const raw = parsed && typeof parsed.confirm === 'string' ? parsed.confirm.trim() : '';
  const want = String(expect || '').trim();
  if (!raw) return 'missing';
  if (!want || raw.toLowerCase() !== want.toLowerCase()) return 'mismatch';
  return 'ok';
}

// The two halves of the refusal body that every confirm-requiring route shares, so a dialog
// written against one route works against all of them. `expects` has always been here;
// `needs`, `field` and `body` are new and are what make the refusal actionable.
function confirmRefusal(verdict, expect) {
  return {
    // Unchanged, and still the key a caller may switch on.
    expects: 'confirm',
    // What kind of thing is missing, in the same vocabulary requireDeliberateInterruption
    // uses for the credential refusal ('operator-credential').
    needs: 'typed-site-name',
    // ⚠️ THE FIELD, BY NAME, ON THE WIRE. Not "the site's name" in prose — the JSON key.
    field: 'confirm',
    // Which of the two failures this is, so a caller can tell "I never sent the field" from
    // "the operator typed the wrong thing".
    confirm_error: verdict,           // 'missing' | 'mismatch'
    // The exact string the operator has to type, and the exact body that carries it.
    site: String(expect || '').trim() || null,
    body: { confirm: String(expect || '').trim() || '<the site\'s name, exactly>' },
  };
}

// Returns { ok: true, actor, siteOpen } — or writes the refusal and returns { ok: false }.
async function requireDeliberateInterruption(ctx, counter, parsed, what) {
  const { res, store, log } = ctx;
  const effect = (what && what.effect) || 'this interrupts the live session at that counter';
  const instead = (what && what.instead) || '';

  // ⚠️ FROM THE CREDENTIAL, NEVER FROM THE BODY. server.js accepts either an operator token
  // or the shared admin token on these routes — the admin token still drives everything
  // NON-interrupting on them — so reaching here with no actor means a caller held only the
  // shared secret and is asking for the one thing it does not buy.
  if (!ctx.actor) {
    // ⚠️ WRITE THE REFUSAL, THEN RETURN THE VERDICT (A5). This was `return json(...)`
    // followed by an unreachable `return { ok: false }`. json() returns undefined, so the
    // caller's `if (!gate.ok)` dereferenced undefined and threw — after the 401 was already
    // on the wire. Closed, but noisy in exactly the way that gets a real refusal "fixed".
    json(res, 401, {
      ok: false,
      error: `${effect}, so it needs a named operator credential (PMR_OPERATOR_TOKENS), `
           + 'not the shared admin token — the interruption is recorded against a person'
           + (instead ? `. ${instead}` : ''),
      needs: 'operator-credential',
    });
    return { ok: false };
  }

  let siteState = null;
  if (typeof store.getSiteHours === 'function' && counter.pharmacy_id != null) {
    try {
      siteState = await store.getSiteHours(counter.pharmacy_id, null);
    } catch (err) {
      // A lookup that THREW is not a lookup that said "closed". Left null, which falls into
      // the unresolved arm below and asks for the typed name.
      log.warn('pmr: hours lookup failed on an interrupting route', {
        counter: counter.id, msg: err && err.message,
      });
      siteState = null;
    }
  }
  // ⛔ gateResolved(), NEVER `resolved` (A1). This arm used to test `siteState.resolved`, and
  // that made it DEAD CODE for every counter that exists: counters.pharmacy_id is NOT NULL,
  // site_hours_v inner-joins pharmacies and emits the estate fallback window for every
  // weekday nobody has entered, so `resolved` came back true for all 348 sites. The typed
  // site name was therefore being skipped at 03:00 for a site whose hours are entirely
  // unknown, on the grounds that the fallback said it was shut.
  //
  // openingHours.gateResolved() reads the column Postgres computes from the site's OWN rows
  // for the days that decide this, and an absent column reads as unresolved — so this arm is
  // reachable again, and it is reachable for exactly the sites it was written for.
  const gateKnown = openingHours.gateResolved(siteState);
  const unresolved = !gateKnown
    || siteState.is_open === null || siteState.is_open === undefined;
  const siteOpen = unresolved ? null : siteState.is_open === true;
  // Only for the refusal sentence. "Nobody has told us this site's hours" and "the lookup
  // failed" both refuse, and an operator can act on the first one.
  const guessing = !!siteState && !gateKnown;

  if (unresolved || siteOpen) {
    const expect = String(counter.pharmacy_name || counter.pharmacy_code || '').trim();
    const verdict = confirmVerdict(parsed, expect);
    if (verdict !== 'ok') {
      // WHY the name is being asked for, then WHAT is missing. The second clause names the
      // JSON field rather than describing it, because the caller that has to be fixed is a
      // program (W3) and the operator reading the dialog is served by the first clause.
      const why = unresolved
        ? (guessing
          ? `nobody has entered this site's opening hours, so what Watchman shows for it is `
            + `the estate fallback GUESS and not a fact — it must be treated as open`
          : `this site's opening hours could not be read, so it must be treated as open`)
        : 'that site is OPEN';
      const how = verdict === 'missing'
        ? `send "confirm" in the JSON body, set to the site's name exactly ("${expect || '?'}")`
        : `"confirm" does not match this site's name ("${expect || '?'}") — it is compared `
          + 'trimmed and case-insensitively, and nothing else is accepted';
      json(res, 400, {
        ok: false,
        error: `${why}. ${how}: ${effect}`,
        ...confirmRefusal(verdict, expect),
        warning: effect,
        // Which of the two unresolved cases this is, so the dialog can offer "enter this
        // site's hours" for the first and only "try again" for the second.
        hours_unknown: guessing,
        // So the dialog can offer the alternative rather than only the refusal.
        instead: instead || null,
      });
      // ⚠️ A SEPARATE STATEMENT, not `return json(...)` (A5). json() returns undefined, so
      // returning its value handed the caller `undefined` and `if (!gate.ok)` threw a
      // TypeError AFTER the 400 had already been written. It still failed closed, but every
      // refusal was logged as an unhandled request error — which is how a working refusal
      // gets mistaken for a bug and "fixed".
      return { ok: false };
    }
  }
  return { ok: true, actor: ctx.actor, siteOpen, gateResolved: gateKnown };
}

// The actions a thin client will carry out. An allowlist, not a command channel: the server
// sends a NAME and the agent maps it to a command locally, so nothing here can ever become
// arbitrary execution on a pharmacy counter.
// 'clear-failed' takes no argument on purpose: the DEVICE decides which units it means, from
// its own `systemctl --failed`. Keeping it a bare name is what stops this becoming a way for
// the server to start an arbitrary unit on a pharmacy counter.
const PI_ACTIONS = ['reboot', 'restart-kiosk', 'restart-agent', 'clear-failed'];
// 'test-print:<queue>' is generated server-side (never accepted from a caller), so the
// operator-facing allowlist above stays exact-match only.

// ⚠️ WHICH OF THOSE FOUR SIGNS A MEMBER OF STAFF OUT (D1). Answered here, once, and
// pessimistically — the same rule pmrVerbs applies to `disruptive`, and for the same reason:
// an action marked harmless by mistake is a pharmacist signed out mid-consultation.
//
//   reboot         takes the whole thin client down. Obviously interrupting.
//   restart-kiosk  restarts the kiosk session, so the RDP session signs out and back in.
//                  This is the SAME effect as the counter.session-restart verb, which the
//                  job ladder treats as its most dangerous act — it cannot be casual here.
//   restart-agent  restarts the monitoring agent only. The kiosk keeps running and nobody at
//                  the counter sees anything; telemetry pauses for a few seconds.
//   clear-failed   `systemctl reset-failed` on the device's own choice of units. Touches no
//                  session.
//
// The two that interrupt now need the same operator credential and typed site name the job
// ladder's apply-now needs. The two that do not are unchanged and still take the shared
// admin token, because dragging them through a pharmacy-name dialog would train people to
// type it without reading.
const PI_ACTIONS_INTERRUPTING = ['reboot', 'restart-kiosk'];

// The corresponding verb on the job ladder, named in the refusal so an operator who does NOT
// need it to happen this second is told where the overnight route is instead of being left
// with a "no".
const PI_ACTION_DEFERRED_VERB = {
  'reboot': 'counter.reboot',
  'restart-kiosk': 'counter.session-restart',
};

// POST /counters/:id/action  { action, confirm? }
//
// Auth is DUAL and the dispatch does not choose: server.js accepts an operator token or the
// shared admin token and sets ctx.actor only for the former, because which credential is
// required depends on the ACTION, which is in the body. Same two-credential shape as
// POST /proxmox/report, where the master token authenticates but identifies nobody.
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

  const interrupting = PI_ACTIONS_INTERRUPTING.includes(action);
  let by;
  let siteOpen = null;
  if (interrupting) {
    const gate = await requireDeliberateInterruption(ctx, counter, p, {
      effect: action === 'reboot'
        ? 'this reboots the thin client and signs the member of staff at that counter out'
        : 'this restarts the kiosk session and signs the member of staff at that counter out',
      instead: `To have it happen in this site's overnight window instead, raise a `
             + `${PI_ACTION_DEFERRED_VERB[action]} job (POST /pmr/jobs) — that path waits `
             + 'for the gate and needs no override.',
    });
    if (!gate.ok) return;
    // ⚠️ THE ACTOR IS THE CREDENTIAL'S NAME. `by` used to be read straight out of the
    // request body, so the caller named themselves on the record of a pharmacist being
    // signed out. It is not read from the body on this branch at all.
    by = gate.actor;
    siteOpen = gate.siteOpen;
  } else {
    // Unchanged for the non-interrupting actions: routine provenance on a row nobody is
    // authenticating, exactly as pmrActor() is used elsewhere. ctx.actor still wins when an
    // operator token was used, so a named person is never downgraded to a typed string.
    by = ctx.actor || (typeof p.by === 'string' && p.by.trim() ? p.by.trim() : 'watchman');
  }

  const updated = await store.setCounterAction(params.id, { action, by });
  if (!updated) return json(res, 404, { ok: false, error: 'not found' });
  if (interrupting) {
    // warn, and with the site's state on it: this is the record of a live counter being
    // interrupted on purpose, and it should be findable in the log without knowing to look.
    log.warn('pmr: a live counter was interrupted on purpose', {
      counter: params.id, action, by, pharmacy: counter.pharmacy_id, site_open: siteOpen,
    });
  } else {
    log.info('pmr: service action queued for thin client', { counter: params.id, action, by });
  }
  return json(res, 200, {
    ok: true,
    counter: updated,
    by,
    interrupts: interrupting,
    warning: interrupting ? 'this signs the member of staff at that counter out' : null,
  });
}

// ── support screen sharing ───────────────────────────────────────────────────
// Cadence a counter reports at while a support session is open. 10 is the validator's floor for
// report_interval_s. The agent's own floor is 3 (MIN_POLL_S) and applies to poll_interval_s, so
// once an agent that prefers the FASTER of the two is rolled out, the poll_until window opened
// below takes this the rest of the way down to config.fastPollS.
const SUPPORT_FAST_REPORT_S = 10;

// POST /counters/:id/support  { minutes }   — 0 ends it early
//
// Writes the setting and returns. Deliberately does NOT return a viewer URL: the Pi has not
// started x11vnc yet and will not until its next telemetry tick, so there is no server to
// connect to and no session password to hand out. The UI polls GET and opens the viewer when
// the DEVICE says it is up. Returning a URL that fails for half a minute is how a working
// feature gets reported as broken.
//
// That tick used to be up to 30s, which is how this got reported as broken anyway. It is now
// seconds - see the cadence block inside the handler.
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

  // ── make the click land in SECONDS, not on the Pi's next ordinary tick ──────────────────
  // support_vnc_tick() runs on EVERY agent tick, so the entire delay an operator feels is the
  // telemetry cadence - 30s by default, which reads as "the button did nothing" and is exactly
  // how this feature got reported as broken. TWO things are needed; either alone does nothing:
  //   1. open the server's fast-poll window (poll_until), so telemetry answers with fastPollS;
  //   2. lower THIS counter's report_interval_s, because the agent treats a per-device
  //      report_interval_s as a deliberate choice for that device and returns it BEFORE it ever
  //      looks at poll_interval_s. That key's DEFAULT (30) is always present in the merged
  //      settings, so it silently defeated fast-poll for every thin client in the estate.
  // Both are wound back when the session is turned off, so no counter stays chatty forever.
  const starting = checked.value.support_vnc_min > 0;
  // Bump the request id on every START, so the agent can tell "the operator asked again" from
  // "this setting has not changed". Without it a repeat request of the same duration after an
  // expiry is discarded by the agent's re-arm guard and the counter never shares again.
  const prevSeq = Number((counter.settings && counter.settings.support_vnc_seq) || 0);
  const cadence = validateCounterSettings(Object.assign({
    report_interval_s: starting ? SUPPORT_FAST_REPORT_S : COUNTER_SETTINGS_DEFAULTS.report_interval_s,
  }, starting ? { support_vnc_seq: (prevSeq + 1) % 1000000 } : {}));
  if (cadence.ok) await store.setCounterSettings(params.id, cadence.value);
  if (typeof store.setPollWindow === 'function') {
    // Bounded by the session itself, plus slack so a STOP is picked up quickly too. It closes on
    // its own even if nothing ever calls stop - the same reasoning as the Pi's local expiry.
    const secs = starting ? checked.value.support_vnc_min * 60 + 60 : 60;
    await store.setPollWindow(counter.pi_device_id, new Date(Date.now() + secs * 1000).toISOString(), null);
  }

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

// PUT/POST /counters/:id/boot-target  { vmid, when?, confirm? }
// Which VM this counter's thin client boots into, chosen in Watchman instead of by editing
// the kiosk launcher on the device. The address is resolved server-side from the vmid; an
// unregistered VM is refused rather than guessed at.
//
// ⚠️ WRITING THE LIVE COLUMN IS APPLYING IT, AND APPLYING IT SIGNS SOMEBODY OUT (D2). The
// boot directive rides the telemetry reply on EVERY tick — deliberately, so a launcher
// edited by hand is corrected back — and the Pi restarts the kiosk the moment the target it
// holds differs (agent/pi/vigilant-pi-agent.py:2662 says so, :2722 does it). So this route
// used to interrupt a live dispensing session about thirty seconds after a save, with no
// hours gate, nothing attributed and nothing confirmed.
//
// It is a CONFIGURATION change whose APPLICATION interrupts — a different shape from
// POST /counters/:id/action, which is an interruption and nothing else. So it is STAGEABLE,
// which is what the job ladder is for, and `when` chooses:
//
//   when: "overnight"  (THE DEFAULT) the choice is recorded and NOTHING is pushed. The
//                      promoter moves it into the live columns when the site's own overnight
//                      window opens — the same pmr_disruptive_allowed() gate a session
//                      restart waits for. No credential beyond the admin token, no typed
//                      name, because nobody is interrupted.
//   when: "now"        the apply-now escape hatch, and it climbs the same ladder apply-now
//                      climbs: a named operator credential, the actor taken from that
//                      credential, and the site's name typed when it is open or unresolved.
//
// The default is deliberately the SAFE one. A caller that says nothing gets the staged path,
// so the way to interrupt a pharmacy is to ask for it in words.
const BOOT_TARGET_WHEN = ['overnight', 'now'];

async function counterSetBootTarget(ctx) {
  const { res, store, log, body, params } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });

  const when = typeof p.when === 'string' && p.when.trim() ? p.when.trim() : 'overnight';
  if (!BOOT_TARGET_WHEN.includes(when)) {
    return json(res, 400, { ok: false, error: `"when" must be one of ${BOOT_TARGET_WHEN.join(', ')}` });
  }

  // An EXPLICIT null (or empty string) means "back to the default" — boot the site's PMR
  // server. Distinguished from a malformed vmid, which is still a 400: Number(null) is 0, so
  // without this the UI's "PMR server (default)" option could never be saved.
  const wantClear = p.vmid === null || p.vmid === '' || typeof p.vmid === 'undefined';
  let vmid = null;
  if (!wantClear) {
    vmid = Number(p.vmid);
    if (!Number.isInteger(vmid) || vmid <= 0) {
      return json(res, 400, { ok: false, error: 'vmid must be a positive integer, or null to boot the PMR server' });
    }
  }

  const notRegistered = `vm ${vmid} is not registered to ${counter.pharmacy_code} as either `
    + 'its PMR server or one of its counter desktops, so its address is unknown — register '
    + 'it first';

  // ── the staged path ───────────────────────────────────────────────────────
  if (when === 'overnight') {
    if (typeof store.stageCounterBootTarget !== 'function') {
      return json(res, 501, { ok: false, error: 'staging a boot target is not supported by this store' });
    }
    // ⚠️ REFUSED HERE RATHER THAN QUEUED, for the same reason a disruptive job at a 24-hour
    // pharmacy is refused rather than queued: a staged change that can only ever sit there
    // is worse than a refusal, because Watchman would show it as "applies overnight" at a
    // site that has no overnight. The operator is told to use when:"now" at a time somebody
    // has agreed with the pharmacy.
    if (typeof store.siteDisruptiveWindow === 'function' && counter.pharmacy_id != null) {
      const w = await store.siteDisruptiveWindow(counter.pharmacy_id, null);
      if (w && !w.allowed_now && !w.next_window_at) {
        // ⚠️ THREE ANSWERS, NOT TWO (Z1). This arm used to be
        // `w.hours_resolved ? "it never closes" : "hours do not resolve"`, and hours_resolved
        // is site_hours_state().resolved — TRUE for all 348 sites, because site_hours_v gives
        // every unstated weekday the estate fallback window. So a pharmacy whose hours nobody
        // has typed was told "that site has no overnight window — it never closes": a
        // confident claim about a business's trading pattern, produced by a guess, sending an
        // operator to negotiate a maintenance slot over a missing row. The rule is
        // openingHours.describeNoOvernightWindow() and it is shared with pmrNoJobReason() and
        // the nightly worker, so there is one definition and no sentence to keep in step.
        return json(res, 409, {
          ok: false,
          error: openingHours.describeNoOvernightWindow(w, {
            subject: 'a boot target',
            remedy: 'send when:"now" with a named operator',
          }),
          // The machine-readable half, so a dialog can offer "enter this site's hours"
          // instead of parsing the sentence back apart.
          hours_reason: openingHours.noOvernightWindowReason(w),
        });
      }
    }
    const by = ctx.actor || (typeof p.by === 'string' && p.by.trim() ? p.by.trim() : 'watchman');
    const staged = await store.stageCounterBootTarget(params.id, { vmid, by });
    if (!staged) return json(res, 409, { ok: false, error: notRegistered });
    let appliesAt = null;
    if (typeof store.siteDisruptiveWindow === 'function' && counter.pharmacy_id != null) {
      const w = await store.siteDisruptiveWindow(counter.pharmacy_id, null);
      // allowed_now means the window is open THIS SECOND — the next worker pass promotes it,
      // so the honest answer is "now", not the next window after this one.
      appliesAt = w && w.allowed_now ? new Date().toISOString() : (w && w.next_window_at) || null;
    }
    log.info('pmr: boot target staged for the overnight window', {
      counter: params.id, vmid, by, applies_at: appliesAt,
    });
    return json(res, 200, {
      ok: true,
      counter: staged,
      staged: true,
      by,
      // The stored gate instant, so the UI's "switches overnight" line and the promoter are
      // the same value rather than the word "midnight" in a sentence.
      applies_at: appliesAt,
      note: 'nothing has been pushed to the thin client — this applies in the site\'s own '
          + 'overnight window, when the counter is not in use',
    });
  }

  // ── the apply-now path ────────────────────────────────────────────────────
  const gate = await requireDeliberateInterruption(ctx, counter, p, {
    effect: 'applying a boot target restarts the kiosk session and signs the member of staff '
          + 'at that counter out',
    instead: 'Send when:"overnight" (the default) to have it applied in this site\'s own '
           + 'overnight window instead — that path needs no override.',
  });
  if (!gate.ok) return;
  const by = gate.actor;

  if (wantClear) {
    if (typeof store.clearCounterBootTarget !== 'function') {
      return json(res, 501, { ok: false, error: 'clearing a boot target is not supported by this store' });
    }
    const cleared = await store.clearCounterBootTarget(params.id, by);
    if (!cleared) return json(res, 404, { ok: false, error: 'not found' });
    log.warn('pmr: a live counter was interrupted on purpose — boot target cleared', {
      counter: params.id, by, pharmacy: counter.pharmacy_id, site_open: gate.siteOpen,
    });
    return json(res, 200, {
      ok: true, counter: cleared, by, staged: false, interrupts: true,
      warning: 'this signs the member of staff at that counter out',
    });
  }

  const updated = await store.setCounterBootTarget(params.id, { vmid, by });
  if (!updated) return json(res, 409, { ok: false, error: notRegistered });
  if (!updated.pi_device_id) {
    // Worth saying out loud: the choice is stored, but nothing will collect it yet.
    log.info('pmr: boot target set on a counter with no Pi enrolled', { counter: params.id, vmid });
  }
  log.warn('pmr: a live counter was interrupted on purpose — boot target applied now', {
    counter: params.id, vmid, target: updated.boot_target, by,
    pharmacy: counter.pharmacy_id, site_open: gate.siteOpen,
  });
  return json(res, 200, {
    ok: true, counter: updated, by, staged: false, interrupts: true,
    warning: 'this signs the member of staff at that counter out',
  });
}

// DELETE /counters/:id/boot-target/staged — withdraw a staged change.
// Interrupts nothing (it un-schedules something that has not happened), so the shared admin
// token is enough and no typed name is asked for.
async function counterCancelBootTargetStage(ctx) {
  const { res, store, log, params } = ctx;
  if (typeof store.cancelCounterBootTargetStage !== 'function') {
    return json(res, 501, { ok: false, error: 'staging a boot target is not supported by this store' });
  }
  const by = ctx.actor || (ctx.query ? String(ctx.query.get('by') || '').trim() : '') || 'watchman';
  const updated = await store.cancelCounterBootTargetStage(params.id, by);
  if (!updated) return json(res, 404, { ok: false, error: 'counter not found' });
  log.info('pmr: staged boot target withdrawn', { counter: params.id, by });
  return json(res, 200, { ok: true, counter: updated, staged: false });
}

// ── DELETE /counters/:id (admin) ────────────────────────────────────────────
// The same boundary as the pharmacy delete and for the same reason (B4). Any of three
// spellings counts as naming the counter deliberately: its label, "counter <n>", or
// "<SITE CODE> counter <n>". A live counter needs "force": true as well.
async function counterDelete(ctx) {
  const { res, store, log, params } = ctx;
  const { confirm, force } = deleteConfirmation(ctx);
  const r = await store.deleteCounter(params.id, { confirm, force });
  if (!r || !r.found) return json(res, 404, { ok: false, error: 'not found' });
  if (!r.deleted) {
    if (r.status === 'live' && !force) {
      return json(res, 409, {
        ok: false,
        error: 'that counter is LIVE — somebody may be dispensing on it. Send "force": true '
             + 'as well as the typed name if you really mean to delete it.',
        status: r.status,
      });
    }
    return json(res, 400, {
      ok: false,
      error: 'type the counter\'s name exactly to confirm — its label, "counter N", or '
           + '"<SITE> counter N"',
      expects: 'confirm',
    });
  }
  log.warn('pmr: a counter was deleted', { counter: params.id, name: r.name, was: r.status });
  return json(res, 200, { ok: true, deleted: r.deleted, name: r.name });
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
  // The page that owns the parked drawer asks for hidden rows; nothing else has to know they
  // exist. Same spelling as the 'force' flag elsewhere in this file.
  const includeHidden = String((query && query.get('include_hidden')) || '') === 'true';
  return json(res, 200, { ok: true, printers: await store.listPrinters(pid || null, { includeHidden }) });
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

// A SIBLING COUNTER PI IS NOT A PRINTER. discover_printers() sweeps the pharmacy LAN and
// files anything answering a printer port as a row named after its address -- and at a site
// built the normal way the thing answering 631 on the next desk is ANOTHER COUNTER PI, whose
// CUPS answers IPP perfectly happily. It then lands in 'printers' as a printer nobody owns.
//
// It is masked at iPharm today by an accident: the sweep skips addresses already known from
// CUPS queues, and each Pi holds a remote queue pointing at the other, so each hides the
// other from its own sweep. Remove one share, or add a third Pi that shares nothing, and the
// sibling lands as a printer immediately. This is preventative, not corrective.
//
// THE TWO-PART TEST IS THE WHOLE SAFETY OF IT. Filtering on address alone would delete live
// queues: ipharm-02 legitimately reports Label-GK420d with address 192.168.55.17 because the
// Zebra is cabled to ipharm-01. Only SWEEP FINDS are eligible, and the sweep sets both tells
// -- unconfigured:true, and a name that IS the address (agent: "THE NAME STAYS THE ADDRESS").
// A configured queue sets neither, whatever address it points at.
//
// This is the platform doing what cups_queue_roles() says it should: the PLATFORM decides, by
// matching a host against the addresses of the site's own counters. Applied to the discovery
// feed rather than to a queue role. No agent change, so not a fleet event.
//
// RESIDUAL GAP, deliberately not closed here: counters_v.pi_lan_ip is device_state.raw
// 'primary_ip' -- the PRIMARY address only. ipharm-01 is dual-homed (eth0 192.168.55.17 stored,
// wlan0 10.10.2.75 stored nowhere) and sweeps both subnets, so a sibling reached at a
// non-primary address still slips through. Closing that needs the agent to report all LAN
// addresses, which is a fleet event; it is not exploitable today (ipharm-02 has only eth0).
function isSiblingCounterPi(rec, piAddresses) {
  if (!rec || !piAddresses.size) return false;
  const addr = String(rec.address == null ? '' : rec.address).trim();
  if (!addr || !piAddresses.has(addr)) return false;
  const name = String(rec.name == null ? '' : rec.name).trim();
  // The sweep sets both. A configured queue sets neither, whatever address it points at.
  return rec.unconfigured === true || name === addr;
}

// POST /printers/report — a DEVICE route: the counter Pi posts what it polled on the
// pharmacy LAN. Authenticated as the device, and the pharmacy is resolved from the
// counter that owns that Pi, so a Pi can never write printers into another site.
async function printersReport(ctx) {
  const { res, store, device, body, log } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(p.printers)) return json(res, 400, { ok: false, error: 'printers must be an array' });
  const counters = await store.listCounters();
  const mine = (counters || []).find((c) => c.pi_device_id === device.id);
  if (!mine) return json(res, 409, { ok: false, error: 'this device is not linked to a counter, so its pharmacy is unknown' });
  // The whole counter list is already loaded to find 'mine'; the rest of it is what says
  // which addresses at this site are Pis rather than printers. It was being thrown away.
  const site = String(mine.pharmacy_id);
  const piAddresses = new Set(
    (counters || [])
      .filter((c) => c && String(c.pharmacy_id) === site && c.pi_lan_ip)
      .map((c) => String(c.pi_lan_ip).trim())
      .filter(Boolean)
  );
  const kept = p.printers.filter((rec) => !isSiblingCounterPi(rec, piAddresses));
  if (log && kept.length !== p.printers.length) {
    log.info('printers: dropped sibling counter Pi sweep hits', {
      serial: device.serial, pharmacy_id: mine.pharmacy_id,
      dropped: p.printers.length - kept.length,
    });
  }
  return json(res, 200, { ok: true, ...(await store.reportPrinters(device.id, mine.pharmacy_id, kept)) });
}

// ═══════════════════════════════════════════════════════════════════════════
// THE PRINTER MODEL — docs/pmr-printer-contract.md
// ═══════════════════════════════════════════════════════════════════════════
//
// ⛔ READ THAT FILE. Every rule applied below is quoted from it and implemented once, in
// src/shared/printerQueues.js. Nothing in this section restates a rule from memory — that is
// the failure mode the contract was written after, and it has already produced two blocking
// defects on live counters.
//
// The routes here are the server half of the action names the Watchman front end already
// calls (src/lib/vigilantApi.js): printer-queues, printer-queue-upsert, printer-queue-delete,
// printer-queue-test-print, printer-assign and printing-promote.

// ⛔ §2 OVER THE WHOLE RESULTING TABLE, FOR EVERY COUNTER AT THE SITE, INSIDE THE WRITE.
//
// Handed to the store so the check and the write share one transaction. It is NOT a duplicate
// of the front end's field checks: those run on what an operator is typing, from telemetry
// that TRUNCATES (print_tab_live/next stop at sixteen names, printer_names at six), so they
// count queues off an incomplete list. This sees the complete effective set of every counter,
// including queues hosted elsewhere and shared onto a desktop here — which is precisely where
// a duplicate name appears, because two counters each holding a queue called `Label` is the
// normal pattern (§1).
const siteTableCheck = (counterId, lines) => printerQueues.validatePrinterTable(
  lines, `counter ${counterId}'s effective printer table`
);

// A refusal from that check comes back as a thrown error so the transaction rolls back.
// Turned into a 409 with the contract's own sentence — never a 500, and never a partial save.
function printerTableRefused(res, err) {
  if (err && err.code === 'PRINTER_TABLE_REFUSED') {
    return json(res, 409, {
      ok: false,
      error: err.message,
      // Which counter's table it was. A refusal caused by ANOTHER counter's queue is the
      // confusing case, and it is the common one once a printer is shared across desks.
      counter_id: err.counter_id != null ? err.counter_id : null,
      refused: 'whole-table',
    });
  }
  return null;
}

// ── staging a promotion ─────────────────────────────────────────────────────
// §4: "Building or sharing a CUPS queue reaches the counter AT ONCE and interrupts nobody.
// Adding or removing a **Windows** printer needs a session restart, which signs the user out.
// So: a printer change stages, and Watchman shows 'applies at midnight' with an apply-now
// button that states it signs the member of staff out."
//
// So every write above STAGES: it changes what the tick sends, the agent renders that to
// printers.tab.next, and nothing restarts. This raises the job that will do the restart, on
// the EXISTING job ladder — the hours gate, the attempts cap, the confirming reading and the
// apply-now override all come from there, and none of it is re-implemented here.
//
// ⚠️ ONLY FOR THE COUNTERS WHOSE TABLE ACTUALLY CHANGED. The store computes that set inside
// the same transaction. Promotion signs a member of staff out, so a save that changed counter
// 1's table must not queue a sign-out at counters 2 and 3.
//
// ⚠️ AND ONE JOB PER COUNTER. Setting a printer up is four or five saves in a minute; without
// this each would queue another sign-out of the same counter for the same night.
// ⚠️ EVERY ENTRY CARRIES `subject` AND `summary` (B4). The hub's waiting-to-apply list is a
// mixed list — a boot target here, a session restart there, a printer promotion next to them —
// and it renders each row from those two fields. Without them it falls back to a generic
// sentence, so three different pending changes at one site all read the same and an operator
// cannot tell which counter is waiting for what.
//
// `subject` names the THING ("counter 2 at IPHARM"), `summary` says what will happen to it in
// one sentence that already contains the consequence. Both are built server-side, here, so the
// job list, the save response and the promote response cannot word the same pending change
// three different ways.
async function promotionSubject(store, counterId) {
  let counter = null;
  try {
    counter = typeof store.getCounter === 'function' ? await store.getCounter(counterId) : null;
  } catch (err) {
    counter = null;
  }
  if (!counter) return `counter ${counterId}`;
  const site = counter.pharmacy_name || counter.pharmacy_code;
  const which = counter.label || `counter ${counter.n != null ? counter.n : counterId}`;
  return site ? `${which} at ${site}` : which;
}

async function stagePrinterPromotions(ctx, pharmacyId, counterIds, by) {
  const { store, log } = ctx;
  const out = [];
  if (!Array.isArray(counterIds) || !counterIds.length) return out;
  if (typeof store.createPmrCounterJob !== 'function') return out;
  const spec = pmrVerbs.getVerb('counter.printing-promote');
  for (const counterId of counterIds) {
    const subject = await promotionSubject(store, counterId);
    const summary = 'apply the staged printer table and restart the session, which signs out '
                  + `whoever is signed in at ${subject}`;
    try {
      const existing = typeof store.getPendingPmrCounterJob === 'function'
        ? await store.getPendingPmrCounterJob(counterId, 'counter.printing-promote')
        : null;
      if (existing) {
        out.push({
          counter_id: counterId,
          subject,
          summary,
          job_id: existing.id,
          applies_at: existing.not_before || null,
          waiting_reason: existing.waiting_reason || null,
          already_staged: true,
        });
        continue;
      }
      // Everything about how the job runs comes from the verb's own entry in the ONE
      // allowlist — spread from a single place so a verb whose timings change cannot leave a
      // stale copy behind in this handler.
      const job = await store.createPmrCounterJob(counterId, {
        verb: 'counter.printing-promote',
        args: {},
        disruptive: spec.disruptive,
        retry_ok: spec.retry_ok,
        confirm_kind: spec.confirm,
        confirm_deadline_s: spec.confirm_deadline_s,
        ttl_s: spec.ttl_s,
        claim_ttl_s: spec.claim_ttl_s,
        max_attempts: spec.max_attempts,
        by: by || 'watchman',
      });
      if (!job) {
        // No row means the hours gate found no overnight window at all — a 24-hour pharmacy —
        // or the counter has no thin client. The printer change is STILL SAVED and still goes
        // out on the tick; what cannot be scheduled is the restart that makes it appear
        // inside Windows. Said in words rather than swallowed, because a queue that never
        // shows up is otherwise a mystery.
        out.push({
          counter_id: counterId,
          subject,
          summary,
          job_id: null,
          applies_at: null,
          waiting_reason: await pmrNoJobReason(store, spec, { counter_id: counterId }),
          already_staged: false,
        });
        continue;
      }
      const full = typeof store.getPmrJob === 'function' ? await store.getPmrJob(job.id) : null;
      out.push({
        counter_id: counterId,
        subject,
        summary,
        job_id: job.id,
        applies_at: job.not_before || null,
        waiting_reason: full ? (full.waiting_reason || null) : null,
        already_staged: false,
      });
    } catch (err) {
      // A failure to SCHEDULE the restart must not undo a printer change that is already
      // written and already on its way to the Pi. Reported per counter instead.
      log.warn('printers: could not stage a promotion for this counter', {
        counter: counterId, pharmacy: pharmacyId, msg: err && err.message,
      });
      out.push({ counter_id: counterId, subject, summary, job_id: null, applies_at: null,
        waiting_reason: 'the promotion could not be scheduled — raise it from the counter', already_staged: false });
    }
  }
  return out;
}

// ── GET /printer-devices?pharmacy_id= (admin) ──────────────────────────────
// §1's PHYSICAL DEVICES: one row per printer that has actually been seen plugged in or on the
// network, keyed by USB serial / USB path / network address — the identity a rename cannot
// orphan. A DIFFERENT object from both /printers (the name-keyed discovery feed) and
// /printer-queues (what Watchman INTENDS a counter to have).
//
// ⛔ WHY THIS ROUTE EXISTS (B10). store.listPrinterDevices() was implemented, exported, and
// had no HTTP route at all — so §3's three-valued `status`, which the telemetry tick writes on
// every counter check-in, was WRITE-ONLY. The whole point of that third value is that
// 'unknown' means CUPS itself was unreachable and must never render as 'attached, no queue'
// (§5: "AN UNKNOWN VALUE MUST NEVER RENDER AS A CONFIDENT ONE") — and no reader could see it.
// Routed rather than deleted: it is the only view of a printer's identity across a rename, and
// the queue editor needs it to offer "this is the Zebra you already have" instead of a blank
// serial field.
async function printerDevicesList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listPrinterDevices !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const raw = query.get('pharmacy_id');
  const pid = raw == null || raw === '' ? null : Number(raw);
  if (pid !== null && !Number.isInteger(pid)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  const list = await store.listPrinterDevices(pid);
  return json(res, 200, {
    ok: true,
    // ALWAYS THE KEY, even when empty — a site with nothing plugged in is a real answer.
    devices: (list || []).map((d) => ({
      id: d.id,
      pharmacy_id: d.pharmacy_id,
      // §1's identity, and the reason this table exists. `identity_kind` says how strong it
      // is: a usb-serial survives a move to another counter, a usb-path does not.
      identity_kind: d.identity_kind,
      identity_key: d.identity_key,
      device_serial: d.device_serial,
      device_usb_path: d.device_usb_path,
      device_address: d.device_address,
      // NULL for a network printer, and that null is meaningful (§1): it has no host Pi.
      host_counter_id: d.host_counter_id,
      vendor_id: d.vendor_id,
      product_id: d.product_id,
      manufacturer: d.manufacturer,
      product: d.product,
      protocol: d.protocol,
      // ⚠️ THREE-VALUED, AND IT MUST REACH THE UI AS THREE VALUES. 'unknown' is "CUPS was
      // unreachable", not "no queue" — collapsing them is the confident-rendering-of-an-
      // unknown §5 forbids. null here means the device has never been reported with one.
      status: d.status == null ? null : d.status,
      observed_queue: d.observed_queue,
      first_seen_at: d.first_seen_at,
      last_seen_at: d.last_seen_at,
    })),
  });
}

// ── GET /printer-queues?pharmacy_id= (admin) ───────────────────────────────
// The queues Watchman INTENDS a counter to have — a DIFFERENT object from the `printers`
// discovery table, and the difference is the whole of §1. These are keyed by the physical
// device, so a rename is a rename and not a new printer.
async function printerQueuesList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listPrinterQueues !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const raw = query.get('pharmacy_id');
  const pid = raw == null || raw === '' ? null : Number(raw);
  if (pid !== null && !Number.isInteger(pid)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  const queues = await store.listPrinterQueues(pid);
  return json(res, 200, {
    ok: true,
    // ALWAYS THE KEY, even when empty. The front end does `r.queues || []`, and a site with no
    // managed queues is a real answer.
    queues: queues.map((q) => ({
      id: q.id,
      pharmacy_id: q.pharmacy_id,
      // ⭐ The Pi the queue is BUILT ON — the host, in §1's words. Never null, including for a
      // network printer: a network printer has no host DEVICE, but its queue still lives in
      // one Pi's CUPS and that Pi is what redirects it.
      counter_id: q.counter_id,
      counter_n: q.counter_n,
      device_serial: q.device_serial,
      device_usb_path: q.device_usb_path,
      device_address: q.device_address,
      queue: q.queue,
      driver: q.driver,
      flags: Array.isArray(q.flags) ? q.flags : [],
      // Not in the shape the UI asked for, and included anyway: it is the same fact the
      // discovery row carries, read off the row that is actually keyed by (counter, queue).
      // NULL = no opinion, [] = shared to nothing.
      assigned_vmids: q.assigned_vmids === undefined ? null : q.assigned_vmids,
      updated_at: q.updated_at,
    })),
  });
}

// ── GET /pmr/desktop-printers?pharmacy_id= (admin) ─────────────────────────
// §7 of docs/pmr-printer-contract.md: what each DESKTOP says is in its Windows printer list.
// The printers modal polls this every few seconds and ages the reading on screen.
//
// ⛔ POLLING FASTER DOES NOT MAKE THE READING NEWER, and this endpoint says so in its own
// answer. Vigilant has no route to the Proxmox API, so the only writer is the collector's
// outward push every 15 minutes. `fresh_within_seconds` is this server licensing how long its
// reading may be spoken about in the present tense; the modal renders anything older muted and
// stamped with its age. Nothing here reaches out to a node.
//
// ⛔ ALWAYS EMIT THE KEY. `windows_printers` is tri-state on the wire and the absent case is
// the COMMON one: null means nobody has looked, [] means the guest was read and Windows lists
// nothing. An omitted key becomes a confident "no printers" in the UI, which is the exact
// failure this whole feed is clearing, so every desktop at the site appears in `desktops` even
// when there is no reading at all for it.
const DESKTOP_PRINTERS_FRESH_S = 900;

// RDP names a redirected printer after the queue and then decorates it: VM 305 lists
// "Pharmacy-ETP (redirected 2)" for the CUPS queue "Pharmacy-ETP". §1 says the queue name IS
// the Windows printer name, and the modal joins on it EXACTLY — so with the decoration left on,
// every redirected printer at every site renders as missing and the one genuinely missing queue
// (Label-ZD421, absent from both iPharm desktops) is indistinguishable from the four that are
// working.
//
// So the decoration is removed HERE, on the read path, in one place, and the guest's literal
// string is carried beside it as `raw_name`. It is never removed on the way in: the stored
// column is what the machine said. Nothing else is normalised — no case folding, no prettifying,
// no mapping to what Watchman intended.
const RDP_REDIRECT_SUFFIX_RE = /\s*\(redirected\s+\d+\)\s*$/i;

async function desktopPrintersList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listDesktopPrinters !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const raw = query.get('pharmacy_id');
  const pid = raw == null || raw === '' ? null : Number(raw);
  if (!Number.isInteger(pid)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });

  const list = await store.listDesktopPrinters(pid);
  return json(res, 200, {
    ok: true,
    fresh_within_seconds: DESKTOP_PRINTERS_FRESH_S,
    desktops: list.map((d) => {
      // Array.isArray, never a truthiness test: [] is the real "Windows lists nothing" answer
      // and it must survive to the wire as [].
      const stored = Array.isArray(d.printers) ? d.printers : null;
      return {
        vmid: d.vmid,
        counter_id: d.counter_id ?? null,
        role: d.role ?? null,
        name: d.name ?? null,
        node: d.node ?? null,
        // ⛔ NULL WHEN THERE IS NO READING, and the store's LEFT JOIN is what makes that
        // reachable. read_at is NULL exactly when printers is, so these two never disagree.
        collected_at: d.read_at ?? null,
        source: d.printer_source ?? null,
        windows_printers: stored === null ? null : stored.map((n) => {
          const literal = String(n ?? '');
          return {
            // What the join matches on.
            name: literal.replace(RDP_REDIRECT_SUFFIX_RE, ''),
            // What the guest actually said, kept so the screen can show the real string and
            // so nobody has to trust this transformation to audit it.
            raw_name: literal,
            redirected: RDP_REDIRECT_SUFFIX_RE.test(literal),
          };
        }),
        // Why the last refresh failed, or null. Carried ALONGSIDE a list, not instead of one:
        // a capped or partly-unreadable list is still evidence for the printers in it.
        error: d.printer_error ?? null,
        // What is known about the channel the reading comes from, so a desktop with no reading
        // can say WHY rather than just being blank. A VM with no guest agent is the ordinary
        // reason and it is not a fault of this feed.
        agent_ok: d.agent_ok === undefined ? null : d.agent_ok,
        agent_error: d.agent_error ?? null,
        status: d.status ?? null,
      };
    }),
  });
}

// ── POST /printer-queues (admin) ───────────────────────────────────────────
// Create or edit ONE intended queue. §6: "Enforce §2's patterns SERVER-SIDE at the point the
// operator types the name, so the refusal is visible in Watchman. A name the kiosk would
// reject must never be storable."
async function printerQueueUpsert(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.upsertPrinterQueue !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const pharmacyId = Number(p.pharmacy_id);
  const counterId = Number(p.counter_id);
  if (!Number.isInteger(pharmacyId)) return json(res, 400, { ok: false, error: 'pharmacy_id required' });
  if (!Number.isInteger(counterId)) {
    return json(res, 400, {
      ok: false,
      error: 'counter_id required — it is the Pi the queue is BUILT ON, and it is never null, '
           + 'including for a network printer',
    });
  }
  // The line's own three fields, through the ONE validator.
  const line = printerQueues.validateQueueLine(
    { queue: p.queue, driver: p.driver, flags: p.flags }, 'this queue'
  );
  if (!line.ok) return json(res, 400, { ok: false, error: line.error });

  // §1's identity columns. Escaped for display at the boundary, like every other descriptor
  // string that came off a device — these reach the database as bound parameters and are
  // interpolated into nothing.
  const f = {
    id: p.id,
    pharmacy_id: pharmacyId,
    counter_id: counterId,
    device_serial: printerQueues.displaySafe(p.device_serial, 128),
    device_usb_path: printerQueues.displaySafe(p.device_usb_path, 64),
    device_address: printerQueues.displaySafe(p.device_address, 200),
    queue: line.value.queue,
    driver: line.value.driver,
    flags: line.value.flags,
    notes: printerQueues.displaySafe(p.notes, 500),
    by: pmrActor(p, ctx) || 'watchman',
  };

  let saved;
  try {
    saved = await store.upsertPrinterQueue(f, siteTableCheck);
  } catch (err) {
    const refusal = printerTableRefused(res, err);
    if (refusal) return refusal;
    throw err;
  }
  if (!saved) {
    return json(res, 404, {
      ok: false,
      error: 'that counter does not belong to that pharmacy, or the queue row does not exist',
    });
  }
  const staged = await stagePrinterPromotions(ctx, pharmacyId, saved.changed_counters, f.by);
  return json(res, 200, {
    ok: true,
    queue: saved,
    // §4, said back to the caller: the queue is built at the counter and can be test-printed
    // straight away; it does not appear INSIDE Windows until the session restarts.
    staged: true,
    promotions: staged,
    note: 'the queue is staged — the thin client writes it to printers.tab.next and nothing '
        + 'restarts. It appears inside Windows when the promotion runs, which signs the '
        + 'member of staff at that counter out.',
  });
}

// ── POST /printer-queues/:id/delete (admin) ────────────────────────────────
async function printerQueueDelete(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.deletePrinterQueue !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad queue id' });
  let gone;
  try {
    gone = await store.deletePrinterQueue(id, siteTableCheck);
  } catch (err) {
    const refusal = printerTableRefused(res, err);
    if (refusal) return refusal;
    throw err;
  }
  if (!gone.deleted) return json(res, 404, { ok: false, error: 'not found' });
  const staged = await stagePrinterPromotions(
    ctx, gone.queue.pharmacy_id, gone.changed_counters, pmrActor(null, ctx) || 'watchman'
  );
  return json(res, 200, {
    ok: true,
    deleted: gone.deleted,
    promotions: staged,
    // ⚠️ THE SHARE SET WENT WITH IT (B6). pmr_printer_assignments has no FK to the queue row,
    // so this had to be an explicit delete — and it has to be an explicit line on the
    // response, because the alternative is that re-creating a queue of the same name on the
    // same counter would have silently inherited these desktops.
    assignment_cleared: !!gone.assignment_cleared,
    assignment_was_shared_to: gone.assignment_was_shared_to || null,
    assignment_note: gone.assignment_cleared
      ? 'the desktops this queue was shared to were cleared with it — re-creating a queue of '
        + 'the same name on this counter starts with no sharing, and has to be shared again'
      : 'this queue was not shared to any desktop',
    // ⛔ The one thing this does NOT do, stated so nobody expects it. §2: "`printers: []`
    // means leave the staged file alone — an empty file cannot mean 'no printers here',
    // because the launcher's fallback turns a file with no valid lines back into a derived
    // set." So removing the LAST managed queue at a counter stops the server having an
    // opinion; it does not remove anything from the thin client.
    note: gone.changed_counters && gone.changed_counters.length
      ? 'the queue is removed from what this counter will be sent'
      : 'nothing this counter is sent has changed',
  });
}

// ── POST /printer-queues/test-print (admin) ────────────────────────────────
// §6: "Every queue gets a test-print button — printing from it and reading the paper is the
// only way to learn which tray a queue selects."
//
// Addressed by (counter, queue) rather than by a discovery row id, for the queue that has no
// discovery row yet. Where one DOES exist, POST /printers/:id/test-print is unchanged and is
// what the UI uses — one verb per situation, not two spellings of one.
//
// Interrupts nobody: printing a page is not a session change, so this takes the shared admin
// token like the existing test print.
async function printerQueueTestPrint(ctx) {
  const { res, store, log, body } = ctx;
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const counterId = Number(p.counter_id);
  if (!Number.isInteger(counterId)) return json(res, 400, { ok: false, error: 'counter_id required' });
  // §2's own pattern, again, because THIS is the value that becomes an argument on the
  // device. The agent re-validates it a third time before it becomes argv — the same
  // belt-and-braces the relay applies to its session target.
  const name = printerQueues.validateQueueName(p.queue);
  if (!name.ok) return json(res, 400, { ok: false, error: name.error });

  const counter = await store.getCounter(counterId);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });
  if (!counter.pi_device_id) {
    return json(res, 409, {
      ok: false,
      error: 'this counter has no thin client enrolled, so there is no machine on the '
           + 'pharmacy LAN to print from',
    });
  }
  const queued = await store.setCounterActionForDevice(counter.pi_device_id, {
    action: `test-print:${name.value}`,
    by: pmrActor(p, ctx) || 'watchman',
  });
  if (!queued) return json(res, 409, { ok: false, error: 'that thin client is no longer linked to a counter' });
  log.warn('printers: queue test print queued', { counter: counter.id, queue: name.value });
  return json(res, 200, { ok: true, queued: true, counter_id: counter.id, queue: name.value });
}

// ── POST /printers/assign (admin) ──────────────────────────────────────────
// §1: "Assignment | queue -> desktop (VM) | A person drags a printer onto a desktop. This is
// what 'shared to' means."
//
// ⭐ KEYED BY (counter_id, queue), NEVER BY A printers ROW ID. §1: "Physical device | USB
// serial, or network MAC/serial | NOT its name." The discovery table is keyed by NAME, so a
// rename orphans the old row — at iPharm one Zebra sits in it three times under three retired
// names — and a row id can therefore name a queue that no longer exists. `printer_id` is
// stored alongside as a hint when the caller happens to have one; it is never the identity.
//
// ⛔ THIS STAGES AND NOTHING ELSE. It writes what the tick will send and raises the promotion
// job; it does not reach the counter, and it cannot restart a session. Applying is the
// promote verb.
async function printerAssign(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.setPrinterAssignment !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const counterId = Number(p.counter_id);
  if (!Number.isInteger(counterId)) return json(res, 400, { ok: false, error: 'counter_id required' });
  const name = printerQueues.validateQueueName(p.queue);
  if (!name.ok) return json(res, 400, { ok: false, error: name.error });
  // THE WHOLE EFFECTIVE SET, never a delta — the same rule §2 states for the table itself.
  // null clears the row (back to "no opinion"); [] is stored and means "shared to nothing".
  const vmids = printerQueues.validateAssignedVmids(p.vmids);
  if (!vmids.ok) return json(res, 400, { ok: false, error: vmids.error });

  let saved;
  try {
    saved = await store.setPrinterAssignment({
      counter_id: counterId,
      queue: name.value,
      printer_id: p.printer_id == null ? null : p.printer_id,
      vmids: vmids.value,
      by: pmrActor(p, ctx) || 'watchman',
    }, siteTableCheck);
  } catch (err) {
    const refusal = printerTableRefused(res, err);
    if (refusal) return refusal;
    throw err;
  }
  if (!saved) return json(res, 404, { ok: false, error: 'counter not found' });

  const staged = await stagePrinterPromotions(
    ctx, saved.pharmacy_id, saved.changed_counters, pmrActor(p, ctx) || 'watchman'
  );
  return json(res, 200, {
    ok: true,
    counter_id: saved.counter_id,
    queue: saved.queue,
    // ⚠️ THE SHAPE THE HUB'S WAITING-TO-APPLY LIST DECLARED (B4). It renders each pending
    // change from `subject` + `summary`; without them this response fell back to a generic
    // sentence, so an assignment change, a queue rename and a boot target all read alike in a
    // list whose entire job is telling them apart. Built from the counters whose EFFECTIVE
    // table this actually changed — which may be counters OTHER than the one edited, because
    // sharing a queue lands it on somebody else's desktop, and that is exactly the case an
    // operator needs named.
    subject: staged.length
      ? staged.map((e) => e.subject).join(', ')
      : await promotionSubject(store, saved.counter_id),
    summary: staged.length
      ? `${JSON.stringify(saved.queue)} is staged for `
        + `${staged.map((e) => e.subject).join(', ')} — it appears inside Windows when the `
        + 'promotion runs, which signs out whoever is signed in at the time'
      : `${JSON.stringify(saved.queue)} is saved; no counter's effective printer table changed, `
        + 'so nothing is waiting to apply',
    // Echoed back so the caller can see what was STORED rather than what it sent — a set,
    // sorted and deduped. null means the assignment was cleared.
    assigned_vmids: saved.vmids === undefined ? null : saved.vmids,
    staged: true,
    promotions: staged,
    note: 'staged — nothing has been sent to the counter beyond the table it stages. The '
        + 'printer appears inside Windows when the promotion runs, which signs the member of '
        + 'staff at that counter out.',
  });
}

// ── POST /counters/:id/printing-promote (admin | OPERATOR) ─────────────────
// §4: "`printing-promote` is the named verb that swaps the staged table live and restarts the
// session as ONE action."
//
// The device already has this verb: wcn-toolbox-priv implements `printing-promote`, which
// re-validates printers.tab.next against the same §2 rules, keeps .prev, swaps the live file
// and restarts the session. This route is how Watchman reaches it, and it goes through the
// job ladder rather than the one-shot action channel because it needs the hours gate, an ack,
// a time limit and a confirming reading.
//
// TWO OUTCOMES, and both are honest:
//   * by default it STAGES — the job is created and held to the site's own overnight window,
//     and the response says when. §4: "Never issue a session-interrupting job unattended
//     during a site's opening hours."
//   * with `now: true`, a named operator credential and the site's name typed into `confirm`,
//     the SAME job is released immediately through the same override the apply-now route
//     uses. The rule being suspended — that Watchman never restarts a session during opening
//     hours on its own — is recorded against a person, exactly as it is there.
async function printingPromote(ctx) {
  const { res, store, log, params, body } = ctx;
  if (typeof store.createPmrCounterJob !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = body ? parseJsonBody(body) : null;
  const counter = await store.getCounter(params.id);
  if (!counter) return json(res, 404, { ok: false, error: 'counter not found' });
  if (!counter.pi_device_id) {
    return json(res, 409, {
      ok: false,
      error: 'this counter has no thin client enrolled, so there is nothing to promote',
    });
  }

  // Is there anything to promote? The Pi's own print_tab_pending answers it (§3: "the staged
  // table differs from the live one -> needs a session restart at this counter"). Tri-state,
  // and an UNKNOWN never blocks: a counter that has not reported it may still have a table
  // waiting, and refusing on "we cannot tell" would strand it.
  let tab = null;
  if (typeof store.getCounterPrintTabState === 'function') {
    try { tab = await store.getCounterPrintTabState(counter.id); } catch (err) {
      log.warn('printers: print-tab state lookup failed', { counter: counter.id, msg: err && err.message });
    }
  }
  if (tab && tab.print_tab_pending === false) {
    // ⚠️ THE ORDINARY WAY TO HIT THIS is saving a queue and pressing promote within the same
    // tick: the table is written here, but the Pi has not collected it yet, so its last
    // reading still says nothing is staged. The refusal is still the right answer — signing a
    // pharmacist out for a change the counter has not received would achieve nothing — so the
    // reading's own timestamp is returned rather than left as a mystery.
    return json(res, 409, {
      ok: false,
      error: 'that counter reports no staged printer table, so there is nothing to promote — '
           + 'promoting anyway would sign the member of staff out for no change. If a printer '
           + 'change was just saved, wait for the counter\'s next check-in and try again.',
      print_tab_pending: false,
      reported_at: tab.last_seen_at || null,
    });
  }

  // ⚠️ THE CREDENTIAL WINS OVER THE BODY here too. On the `now` path this row records a
  // member of staff being signed out on purpose, and pmrActor() reads a name the browser
  // chose. ctx.actor is set by the dispatch only when an operator token was presented.
  const by = ctx.actor || pmrActor(p, ctx) || 'watchman';
  const staged = await stagePrinterPromotions(ctx, counter.pharmacy_id, [counter.id], by);
  const entry = staged[0] || { job_id: null, waiting_reason: null, applies_at: null };
  if (!entry.job_id) {
    return json(res, 409, { ok: false, error: entry.waiting_reason || 'that promotion could not be scheduled' });
  }

  // The apply-now half. Deliberately the SAME gate the other interrupting counter routes use
  // — an operator credential, plus the site's name typed when the site is open or its hours
  // do not resolve — and the SAME store call the apply-now route makes, so there is one
  // override mechanism and one audit shape.
  if (p && p.now === true) {
    const gate = await requireDeliberateInterruption(ctx, counter, p, {
      effect: 'this swaps the staged printer table live and restarts the session, which signs '
            + 'the member of staff at that counter out',
      instead: 'Leave `now` off and the same promotion applies in this site\'s own overnight '
             + 'window, with no override and nobody signed out.',
    });
    if (!gate.ok) return;
    // ⛔ NO SILENT FALL-THROUGH (B5). This used to be `if (typeof store.overridePmrJobHours
    // === 'function') { … }` with nothing after it, so a store without the method dropped out
    // of the branch and returned the ordinary staged 200 — `applied_now: false`, "applies at
    // midnight" — to an operator who had just typed the pharmacy's name to make it happen NOW.
    // The one path in this service whose entire purpose is to be unambiguous answered
    // ambiguously. A store that cannot override says so.
    if (typeof store.overridePmrJobHours !== 'function') {
      return json(res, 501, {
        ok: false,
        error: 'this store cannot release a held job, so `now` cannot be honoured — the '
             + 'promotion is staged and will apply in this site\'s overnight window',
        job_id: entry.job_id,
        applies_at: entry.applies_at,
      });
    }
    const done = await store.overridePmrJobHours(entry.job_id, gate.actor);
    if (!done) {
      return json(res, 409, {
        ok: false,
        error: 'that promotion is not a pending job that has never been handed out — there '
             + 'is nothing to override',
        job_id: entry.job_id,
      });
    }
    log.warn('pmr: hours override — a printer promotion was released during opening hours', {
      job: entry.job_id, counter: counter.id, pharmacy: counter.pharmacy_id, by: gate.actor,
    });
    return json(res, 200, {
      ok: true,
      job_id: entry.job_id,
      applied_now: true,
      by: gate.actor,
      subject: entry.subject,
      summary: entry.summary,
      warning: 'this signs the member of staff at that counter out',
      note: 'this override releases the job once; it is not re-offered if the thin client '
          + 'does not report',
    });
  }

  return json(res, 200, {
    ok: true,
    job_id: entry.job_id,
    applied_now: false,
    already_staged: !!entry.already_staged,
    subject: entry.subject,
    summary: entry.summary,
    // WHEN, as an instant rather than as the word "midnight" in a sentence — the stored
    // not_before the claim query actually gates on.
    applies_at: entry.applies_at,
    waiting_reason: entry.waiting_reason,
    warning: 'when this runs it signs the member of staff at that counter out',
    // ⚠️ THE APPLY-NOW HALF, DESCRIBED ON THE WIRE (B5). It was unreachable in practice: it
    // needs {now:true, confirm:"<site name>"} in the body plus an operator token, and the
    // front end's helper takes no argument, so nothing ever sent either. A route whose
    // override exists only in the server's source is an override nobody has.
    //
    // Advertised here so the dialog can be built from the response instead of from memory.
    // The site name is the string that must be typed back; `needs` is the credential.
    apply_now: {
      method: 'POST',
      path: `/counters/${counter.id}/printing-promote`,
      body: { now: true, confirm: counter.pharmacy_name || counter.pharmacy_code || null },
      needs: 'operator-credential',
      effect: 'releases this promotion immediately and signs the member of staff at that '
            + 'counter out',
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// THE SITE BUILD LIFECYCLE — capture, import, and node headroom
// ═══════════════════════════════════════════════════════════════════════════
//
// ⛔ EVERY READ BELOW ALWAYS EMITS ITS KEY, even as null. The front end does
// `r.capture ?? null` and `r.import ?? null`, so an OMITTED key becomes a confident "no
// capture held" instead of "we could not tell" — and a build checklist that invents its own
// evidence sends an engineer home from a site that is not finished.

// Shared subject resolution: these routes take an id OR a code, like GET /pharmacies/:id.
async function pharmacyForLifecycle(ctx) {
  const { store, params } = ctx;
  if (typeof store.getPharmacy !== 'function') return null;
  return store.getPharmacy(params.id);
}

// ── GET /pharmacies/:id/capture (admin) ────────────────────────────────────
async function siteCaptureGet(ctx) {
  const { res, store } = ctx;
  if (typeof store.getSiteCapture !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const row = await store.getSiteCapture(p.id);
  return json(res, 200, {
    ok: true,
    // ALWAYS PRESENT. null means Watchman holds no capture for this site — a real answer, and
    // different from the call failing, which means nobody can tell.
    capture: shapeCapture(row),
  });
}

// ── ⛔ ONE SHAPE, READ OR WRITE (B9) ────────────────────────────────────────
// The GETs shaped their row and the POSTs returned the RAW database row, and those are not
// the same object. The difference that bites is disk_gb: it is numeric(10,2), and
// node-postgres returns numeric as a STRING because a JS number cannot hold every numeric —
// so GET gave 197 and POST gave "197.00" for the same row. A caller that writes and then
// reads back its own response (which the capture tool does, to show what it recorded) got a
// string where the build checklist compares a number, and `197.00 >= threshold` is a string
// comparison that is wrong roughly half the time.
//
// So both directions go through these two functions. Everything the shape decides — the
// numeric coercion, the tri-states that must NOT be coerced, which columns are exposed at all
// — is decided once.
function shapeCapture(row) {
  if (!row) return null;
  return {
    started_at: row.started_at,
    // null while it is still running.
    uploaded_at: row.uploaded_at,
    source_hostname: row.source_hostname,
    // The size of the shrunk image: the real cost of this site. Number, never the string
    // node-postgres hands back for a numeric column.
    disk_gb: row.disk_gb == null ? null : Number(row.disk_gb),
    // ⚠️ TRI-STATE, and it must stay tri-state through here. null is "not established",
    // which is NOT false: a false all-clear on printers_cleared is a site imported with the
    // pharmacy's old printers still installed.
    guest_agent_installed: row.guest_agent_installed,
    printers_cleared: row.printers_cleared,
    taken_by: row.taken_by,
    out_of_hours: row.out_of_hours,
  };
}

function shapeImport(row) {
  if (!row) return null;
  return {
    state: row.state,
    // 0-100 or null. The executor polls outward, so this is its LAST report and not a live
    // reading — null means it has not reported one, never "nothing has happened yet".
    pct: row.pct == null ? null : Number(row.pct),
    node: row.node,
    vmid: row.vmid == null ? null : Number(row.vmid),
    started_at: row.started_at,
    finished_at: row.finished_at,
    error: row.error,
    // ⚠️ LOAD-BEARING. The executor polls OUTWARD, so this is the only thing separating a
    // running import from a dead one: an import whose last poll is hours old is not
    // "running", it is lost, and the UI has to be able to tell those apart.
    last_poll_at: row.last_poll_at,
  };
}

// ── POST /pharmacies/:id/capture (admin) ───────────────────────────────────
// The capture tool reporting what it took. Without this the read above is null forever.
//
// ⚠️ THE CAPTURE TOOL MUST NOT CARRY A SUPABASE KEY OR ANY OTHER ESTATE CREDENTIAL beyond the
// admin token this route already needs — it runs on a pharmacy PC that is not ours.
async function siteCaptureSet(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.setSiteCapture !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const b = parseJsonBody(body);
  if (!b) return json(res, 400, { ok: false, error: 'bad json' });
  const tri = (v) => (typeof v === 'boolean' ? v : null);
  const num = (v) => (v == null || !Number.isFinite(Number(v)) ? null : Number(v));
  const saved = await store.setSiteCapture(p.id, {
    started_at: b.started_at || null,
    uploaded_at: b.uploaded_at || null,
    // A hostname off a pharmacy PC is a descriptor string like any other: escaped for display,
    // bound as a parameter, interpolated into nothing.
    source_hostname: printerQueues.displaySafe(b.source_hostname, 200),
    disk_gb: num(b.disk_gb),
    // Anything that is not a real boolean stays NULL. "We did not establish it" is not "no",
    // and coercing a missing reading to false is the false all-clear this whole record exists
    // to prevent.
    guest_agent_installed: tri(b.guest_agent_installed),
    printers_cleared: tri(b.printers_cleared),
    taken_by: printerQueues.displaySafe(b.taken_by, 120),
    out_of_hours: tri(b.out_of_hours),
  });
  // THE SAME SHAPE THE GET RETURNS (B9) — see shapeCapture(). The raw row's disk_gb is the
  // string node-postgres produces for numeric(10,2).
  return json(res, 200, { ok: true, capture: shapeCapture(saved) });
}

// ── GET /pharmacies/:id/import (admin) ─────────────────────────────────────
async function siteImportGet(ctx) {
  const { res, store } = ctx;
  if (typeof store.getSiteImport !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const row = await store.getSiteImport(p.id);
  return json(res, 200, { ok: true, import: shapeImport(row) });
}

// ── POST /pharmacies/:id/import (admin) ────────────────────────────────────
// The import executor reporting progress. Every report stamps last_poll_at server-side.
//
// ⛔ AND THIS IS WHERE A SITE BUILD IS REFUSED. A build is placed on a node at the moment it
// is QUEUED, so that is the moment to ask whether the node can hold it — see
// src/shared/nodeCapacity.js for the measured numbers. 'unknown' is not a refusal and not an
// approval: it is reported alongside so nobody reads silence as headroom.
async function siteImportSet(ctx) {
  const { res, store, log, body } = ctx;
  if (typeof store.setSiteImport !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const b = parseJsonBody(body);
  if (!b) return json(res, 400, { ok: false, error: 'bad json' });
  const states = ['queued', 'running', 'done', 'failed'];
  if (!states.includes(b.state)) {
    return json(res, 400, { ok: false, error: `state must be one of ${states.join(', ')}` });
  }
  let pct = null;
  if (b.pct != null) {
    if (typeof b.pct !== 'number' || !Number.isInteger(b.pct) || b.pct < 0 || b.pct > 100) {
      return json(res, 400, { ok: false, error: 'pct must be a whole number between 0 and 100, or omitted' });
    }
    pct = b.pct;
  }

  // THE REFUSAL. Only on the transition INTO 'queued' — a run already under way is reported
  // on, never blocked, because stopping the reports would only make it invisible.
  //
  // `force: true` overrides it, deliberately and openly: this judgement rests on one
  // collector's reading of a pool, and a person standing in front of the cluster who knows
  // something we do not must not be locked out by our own arithmetic. The override is logged
  // and the verdict is still computed, so "it was queued anyway" is a fact on the record
  // rather than a silence.
  if (b.state === 'queued' && b.force !== true) {
    const verdict = await judgeSiteFits(ctx, p, b.node || p.proxmox_node);
    if (verdict && verdict.verdict === 'short') {
      log.warn('pmr: a site build was refused for capacity', {
        pharmacy: p.id, node: verdict.node, short: verdict.short,
      });
      return json(res, 409, {
        ok: false,
        error: verdict.reason,
        // Named, so the answer is "wcn-zfs is 54 GB short" and not "no".
        short: verdict.short,
        node: verdict.node,
        needs: verdict.need,
      });
    }
    if (verdict && verdict.verdict === 'unknown') {
      // NOT a refusal. An unmeasured node is unknown, and a build that a person has decided
      // to run must not be blocked by our own blind spot — but the answer is carried onto the
      // record so nobody later reads it as "we checked and it was fine".
      log.warn('pmr: a site build was queued without a capacity answer', {
        pharmacy: p.id, node: verdict.node, missing: verdict.missing,
      });
    }
  }

  const saved = await store.setSiteImport(p.id, {
    state: b.state,
    pct,
    node: printerQueues.displaySafe(b.node, 200),
    vmid: Number.isInteger(b.vmid) ? b.vmid : null,
    started_at: b.started_at || null,
    finished_at: b.finished_at || null,
    error: printerQueues.displaySafe(b.error, 2000),
  });
  // THE SAME SHAPE THE GET RETURNS (B9). An import executor that reads back its own progress
  // report must not get a different type for pct than the poller does.
  return json(res, 200, { ok: true, import: shapeImport(saved) });
}

// Can this node hold this site? One answer, from one place.
//
// Returns null when nothing can be judged at all (no node named, no store support) — which
// the caller treats as unknown, never as approval.
async function judgeSiteFits(ctx, pharmacy, nodeName) {
  const { store } = ctx;
  if (typeof store.listNodeCapacity !== 'function') return null;
  const node = typeof nodeName === 'string' && nodeName.trim() ? nodeName.trim() : null;
  if (!node) return null;
  const counters = typeof store.listCounters === 'function'
    ? (await store.listCounters(pharmacy.id)) : [];
  const need = nodeCapacity.siteCost({ counters: counters.length });
  const all = await store.listNodeCapacity();
  // `node` must match pharmacies.proxmox_node — that is the whole point of the column, and a
  // site whose node is not in the capacity feed is UNKNOWN rather than fine.
  const rowsForNode = all.filter((r) => r.node === node);
  if (!rowsForNode.length) {
    return { verdict: 'unknown', node, need, short: [], missing: ['memory', 'storage'],
      reason: `nothing reports headroom for ${node}, so whether it can host this site cannot `
            + 'be established' };
  }
  // The best pool on the node: a site is placed on ONE pool, so the question is whether ANY
  // pool has room, not whether the total does. Judged against the most free one.
  let best = null;
  for (const row of rowsForNode) {
    const verdict = nodeCapacity.judgeNodeForSite(row, need);
    if (!best) { best = { ...verdict, node, need, storage_name: row.storage_name }; continue; }
    const rank = { fits: 0, unknown: 1, short: 2 };
    if (rank[verdict.verdict] < rank[best.verdict]) {
      best = { ...verdict, node, need, storage_name: row.storage_name };
    }
  }
  return best;
}

// ═══════════════════════════════════════════════════════════════════════════
// THE CAPTURE KIT — a ticket, a scoped token, and three capabilities
// ═══════════════════════════════════════════════════════════════════════════
//
// ⛔ THE CREDENTIAL RULE, RESTATED HERE BECAUSE THIS IS WHERE IT IS KEPT. The capture tool
// runs on a PHARMACY'S OWN PC and MUST NEVER CARRY A SUPABASE KEY. The key in the frontend's
// env decodes to "role":"service_role" and BYPASSES ROW-LEVEL SECURITY entirely; that file's
// own comment says it must never ship in a deployed build. Nor does the kit carry the estate
// master token, the operator token, or a per-node token. It carries a short-lived token with
// exactly three capabilities — list sites, read a site's taken role slots, register a capture
// — and Vigilant does every CRM read server-side on its behalf. Same posture as the
// HMAC-signed thin-client image URL.
//
// The shapes, the lifetimes and the reasoning live in src/shared/captureToken.js. What lives
// here is the enforcement.

// ── POST /pharmacies/:id/capture-ticket (OPERATOR) ─────────────────────────
// Issue the kit's ticket for one site.
//
// ⛔ A NAMED PERSON ISSUES IT, AND THE SHARED ADMIN TOKEN IS NOT ENOUGH. Same rule as
// apply-now, for a related reason: this hands out a credential that will run on a machine we
// do not own, and a row recording "watchman issued it" records nothing. server.js refuses the
// route outright when no per-operator token matched, so ctx.actor here is always a person.
//
// ⛔ OUT OF HOURS ONLY, AND THE REFUSAL IS THE SHAPE OF THE CREDENTIAL. The gate is judged
// from the SITE'S OWN hours through the same gateResolved() every other gate in this platform
// reads — never from the estate fallback guess — and the ticket's expiry is then clamped to
// the moment the pharmacy reopens. A ticket is therefore arithmetically incapable of being
// alive during trading hours, which is a stronger thing than a check the kit performs.
async function captureTicketIssue(ctx) {
  const { res, store, body, log, actor } = ctx;
  if (typeof store.createCaptureTicket !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const b = parseJsonBody(body);
  if (!b) return json(res, 400, { ok: false, error: 'bad json' });

  // ⛔ A CAPTURE IS FOR A SITE THAT IS BEING BUILT. Issuing one against a 'live' pharmacy
  // would point an engineer at a dispensing counter's PC. Overridable only by a person who
  // types the site's own code — the same confirm-by-name device the hours write and the
  // printing promote use, because "are you sure" is a button and typing RX54554 is a decision.
  if (p.status === 'live' && String(b.confirm || '').trim().toUpperCase() !== String(p.code).toUpperCase()) {
    return json(res, 409, {
      ok: false,
      error: `${p.code} is LIVE and dispensing. A capture takes a counter PC out of service. `
           + `If this site really is being re-captured, send confirm:"${p.code}".`,
      needs_confirm: p.code,
    });
  }

  // The hours judgement, from the site's own rows.
  let hoursState = null;
  if (typeof store.getSiteHours === 'function') {
    try { hoursState = await store.getSiteHours(p.id, null); } catch (e) { hoursState = null; }
  }
  const window = captureToken.judgeCaptureWindow(hoursState, Date.now());
  if (!window.ok) {
    log.warn('capture: ticket refused', { pharmacy: p.id, reason: window.reason, by: actor });
    return json(res, 409, {
      ok: false,
      error: window.message,
      // Named, so the screen can say WHICH refusal this is instead of showing a paragraph.
      reason: window.reason,
      window_closes_at: window.window_closes_at,
      window_remaining_min: window.window_remaining_min,
      hours: openingHours.hoursPayload(hoursState),
    });
  }

  const secret = captureToken.newTicketSecret();
  const expiresAt = captureToken.ticketExpiry(Date.now(), window.window_closes_at);
  let row;
  try {
    row = await store.createCaptureTicket(p.id, {
      secret_hash: captureToken.hashSecret(secret),
      issued_by: actor,
      expires_at: expiresAt,
      window_closes_at: window.window_closes_at,
      redeem_max: captureToken.TICKET_REDEEM_MAX,
      note: printerQueues.displaySafe(b.note, 500),
    });
  } catch (err) {
    log.warn('capture: ticket insert failed', { pharmacy: p.id, msg: err && err.message });
    return json(res, 500, { ok: false, error: 'could not issue a capture ticket' });
  }
  if (!row) return json(res, 500, { ok: false, error: 'could not issue a capture ticket' });

  log.info('capture: ticket issued', {
    pharmacy: p.id, code: p.code, by: actor, ticket: row.id, expires_at: row.expires_at,
  });

  return json(res, 201, {
    ok: true,
    // ⛔ THE ONE AND ONLY TIME THE SECRET IS RETURNED. Only a sha256 is stored, so it cannot
    // be recovered from the database or from any list route — a lost ticket is reissued, never
    // looked up. shapeTicket() does not carry it and must never learn to.
    secret,
    ticket: captureToken.shapeTicket(row, Date.now()),
    // What the kit will be able to do once it redeems this. Stated at issue so the person
    // handing it over can see the whole of it on one screen.
    capabilities: captureToken.fullCapabilitySet(),
    redeem: { method: 'POST', path: '/capture/token' },
    site: { id: p.id, code: p.code, name: p.name },
    // Issued, but only just: the run will fit inside the closed window with little to spare.
    window_short: window.window_short,
    window_remaining_min: window.window_remaining_min,
    hours: openingHours.hoursPayload(hoursState),
  });
}

// ── GET /pharmacies/:id/capture-ticket (admin) ─────────────────────────────
// The tickets held for this site. Never a secret — see listCaptureTickets in store.pg.js.
async function captureTicketList(ctx) {
  const { res, store } = ctx;
  if (typeof store.listCaptureTickets !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const p = await pharmacyForLifecycle(ctx);
  if (!p) return json(res, 404, { ok: false, error: 'not found' });
  const now = Date.now();
  const list = await store.listCaptureTickets(p.id);
  return json(res, 200, {
    ok: true,
    // ALWAYS PRESENT, even as []. The build checklist reads this and an omitted key would
    // become a confident "no ticket outstanding".
    tickets: (list || []).map((r) => captureToken.shapeTicket(r, now)),
  });
}

// ── DELETE /capture-tickets/:id (admin) ────────────────────────────────────
// The kill switch. It stops future redemptions AND revokes every token the ticket already
// minted, in one transaction — a revoke that left live tokens behind would not kill anything
// for another ninety minutes.
async function captureTicketRevoke(ctx) {
  const { res, store, params, log, actor } = ctx;
  if (typeof store.revokeCaptureTicket !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const row = await store.revokeCaptureTicket(params.id, actor || 'watchman');
  if (!row) return json(res, 404, { ok: false, error: 'not found' });
  log.info('capture: ticket revoked', { ticket: params.id, by: actor || 'watchman' });
  return json(res, 200, { ok: true, ticket: captureToken.shapeTicket(row, Date.now()) });
}

// ── POST /capture/token (TICKET) ───────────────────────────────────────────
// The ONE route the ticket secret works on. It exchanges the ticket for a short-lived token
// carrying the three capabilities, and it is what the kit calls again after the guest-agent
// reboot — which is why the ticket is redeemable a bounded number of times rather than once.
//
// The refusals are NAMED. "no-such-ticket", "revoked", "expired" and "spent" are four
// different things to tell an engineer standing in a pharmacy at two in the morning, and a
// flat 401 would send them home.
async function captureTokenMint(ctx) {
  const { res, store, req, log } = ctx;
  if (typeof store.redeemCaptureTicket !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const presented = bearerFromRequest(req);
  if (!presented) return json(res, 401, { ok: false, error: 'present the capture ticket as a bearer token' });

  const now = Date.now();
  const secret = captureToken.newTokenSecret();
  let out;
  try {
    out = await store.redeemCaptureTicket(captureToken.hashSecret(presented), {
      token_hash: captureToken.hashSecret(secret),
      // ⛔ ALWAYS THE FULL THREE, NEVER A SET THE CALLER CHOSE. There is no request field that
      // widens or narrows this, and the column's CHECK constraint refuses anything outside the
      // three even if this line were wrong.
      capabilities: captureToken.fullCapabilitySet(),
      // The store computes the expiry inside the same transaction, as LEAST(now + this TTL,
      // the ticket's own expiry) — so a token can never outlive the ticket, and the
      // closed-window bound cannot leak through a token minted at the last minute.
      token_ttl_s: captureToken.TOKEN_TTL_S,
    });
  } catch (err) {
    log.warn('capture: redeem failed', { msg: err && err.message });
    return json(res, 500, { ok: false, error: 'could not mint a capture token' });
  }
  if (!out || out.refused) {
    const reason = (out && out.refused) || 'unavailable';
    const said = {
      'no-such-ticket': 'that capture ticket is not recognised',
      revoked: 'that capture ticket has been revoked from Watchman',
      expired: 'that capture ticket has expired — it is bounded to the site\'s closed window, '
             + 'so it dies when the pharmacy opens. Ask for a new one out of hours.',
      spent: 'that capture ticket has been redeemed its maximum number of times. Ask for a new one.',
      unavailable: 'that capture ticket cannot be redeemed',
    }[reason];
    // Deliberately the same 401 for all of them at the HTTP level — this route is reachable by
    // anybody who can post to it — but the body names the reason, because the caller is an
    // engineer we sent, not an attacker who learns anything new from "expired".
    return json(res, 401, { ok: false, error: said, reason });
  }

  // ⚠️ THE ROW'S OWN EXPIRY GOES ON THE WIRE, never a value recomputed here. The store clamped
  // it to the ticket inside the transaction; a second computation in JS could disagree with the
  // column the auth query actually tests, and then a kit would believe it had time it does not.
  const rowExpiry = (out.token && out.token.expires_at)
    || captureToken.tokenExpiry(now, out.ticket.expires_at);

  log.info('capture: token minted', {
    pharmacy: out.ticket.pharmacy_id, ticket: out.ticket.id,
    redeem: `${out.ticket.redeem_count}/${out.ticket.redeem_max}`,
  });

  return json(res, 200, {
    ok: true,
    token: secret,
    expires_at: rowExpiry,
    // ⛔ THE WHOLE OF WHAT THIS TOKEN MAY DO, on the wire, by name. The kit does not infer its
    // permissions from which calls happen to succeed.
    capabilities: captureToken.admittedCapabilities(out.token && out.token.capabilities),
    // The bounded budget, so the kit can say "2 redemptions left" instead of discovering it.
    redeem_count: Number(out.ticket.redeem_count),
    redeem_max: Number(out.ticket.redeem_max),
    ticket_expires_at: out.ticket.expires_at,
    // The three routes, named by the server. The kit does not compose these either.
    endpoints: {
      'sites:list': { method: 'GET', path: '/capture/sites' },
      'slots:read': { method: 'GET', path: '/capture/slots' },
      'capture:write': { method: 'POST', path: '/capture/register' },
    },
  });
}

// The capability assertion every capture handler makes for itself. The dispatch has ALREADY
// refused a token that lacks it — this is the second lock, so a route wired into the table
// without a matching assertion, or reached through some future alias, still cannot act.
function captureCapOk(ctx, cap) {
  const check = captureToken.assertCapability(ctx.capture, cap);
  if (check.ok) return null;
  return json(ctx.res, 403, { ok: false, error: check.error, capabilities: captureToken.CAPABILITIES });
}

// ── GET /capture/sites  (capability: sites:list) ───────────────────────────
// The sites this ticket admits.
//
// ⛔ THERE IS NO SITE PARAMETER, AND THAT IS THE POINT. The pharmacy comes from the TOKEN.
// "Site picked from a live Watchman list, never typed" is enforced by the kit being physically
// unable to name another pharmacy: there is no field in which to name one.
//
// It is a LIST — exactly one row — because the kit renders a picker and the engineer confirms
// what Watchman already decided, rather than typing a code that could be wrong.
async function captureSitesList(ctx) {
  const { res, store, capture: tok } = ctx;
  const refused = captureCapOk(ctx, 'sites:list');
  if (refused) return refused;
  if (typeof store.listCaptureSitesForToken !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const list = await store.listCaptureSitesForToken(tok.pharmacy_id);
  const sites = (list || []).map((p) => ({
    id: Number(p.id),
    code: p.code,
    name: p.name,
    status: p.status,
    subnet: p.subnet,
    server_ip: p.server_ip,
    pmr_system: p.pmr_system,
    proxmox_node: p.proxmox_node,
  }));
  return json(res, 200, {
    ok: true,
    // ALWAYS PRESENT, even as []. A missing key would let a kit conclude "no sites" from a
    // call that failed.
    sites,
    // Said out loud so nobody reads the single row as a truncated list.
    scoped_to_ticket: true,
  });
}

// ── GET /capture/slots  (capability: slots:read) ───────────────────────────
// Which role slots at this site are already taken, so the kit can refuse a duplicate BEFORE
// somebody spends ninety minutes producing one.
//
// ROLE IS ONE PICKER: 'server', or 'client-01' … 'client-10'. Clients occupy .11–.20 on a /27
// site (the derived octet is 10 + n), so 01–10 is exactly the addressable range.
async function captureSlotsRead(ctx) {
  const { res, store, capture: tok } = ctx;
  const refused = captureCapOk(ctx, 'slots:read');
  if (refused) return refused;
  if (typeof store.listCaptureSlots !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const data = await store.listCaptureSlots(tok.pharmacy_id);
  const p = (data && data.pharmacy) || null;
  const runs = (data && data.runs) || [];
  const counters = (data && data.counters) || [];

  const runFor = (kind, slot) => runs.find(
    (r) => r.role_kind === kind && (kind === 'server' ? true : Number(r.role_slot) === slot)
  ) || null;

  const slots = captureToken.ROLE_VALUES.map((role) => {
    const parsed = captureToken.parseRole(role);
    const run = runFor(parsed.kind, parsed.slot);
    const counter = parsed.kind === 'client'
      ? counters.find((c) => Number(c.n) === parsed.slot) || null
      : null;
    // THREE SOURCES OF "TAKEN", because a picker that offered a slot the register call then
    // refused would waste an engineer's night. A capture already registered; a counter row
    // (the real addressable slot); and, for the server, the site's own srv_vmid.
    const takenBy = [];
    if (run) takenBy.push('capture');
    if (counter) takenBy.push('counter');
    if (parsed.kind === 'server' && p && p.srv_vmid != null) takenBy.push('vm');
    return {
      role,
      kind: parsed.kind,
      slot: parsed.slot,
      // Advisory: the address this role will end up on, so the picker can show ".13" beside
      // Client 03 and an engineer cannot mis-pick silently.
      address: captureToken.roleAddress(p, parsed.kind, parsed.slot),
      taken: takenBy.length > 0,
      taken_by: takenBy,
      // ⚠️ ALWAYS PRESENT, null when nothing holds it. An omitted key reads as "free".
      capture: captureToken.shapeRun(run),
      counter_label: counter ? (counter.label || null) : null,
    };
  });

  return json(res, 200, {
    ok: true,
    site: p ? { id: Number(p.id), code: p.code } : null,
    slots,
    // Named on the wire so the kit's picker cannot invent an eleventh client.
    roles: captureToken.ROLE_VALUES,
  });
}

// Coerce a tri-state from the kit. ⚠️ ANYTHING THAT IS NOT A REAL BOOLEAN STAYS NULL. "We did
// not establish it" is not "no", and coercing a missing reading to false is the false
// all-clear the whole capture record exists to prevent — a site imported with the pharmacy's
// old printers still installed, or a VM with no guest agent that everyone believes has one.
function captureTri(v) {
  return typeof v === 'boolean' ? v : null;
}

function captureNum(v) {
  if (v == null) return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

// ── POST /capture/register  (capability: capture:write) ────────────────────
// The kit reporting what it is taking / has taken, and being told where to put it.
//
// ⛔ IT CANNOT CREATE OR MODIFY A PHARMACY. pharmacy_id is read from the TOKEN, the row is
// written into pmr_capture_runs against a foreign key, and nothing on this path writes a
// column of `pharmacies` or creates a counter. A capture registers against a site that already
// exists; a credential that could create the site would be able to invent the thing it then
// claims to have captured.
//
// ⛔ IT REFUSES A DUPLICATE ROLE — in the database. The partial unique indexes make (site,
// server) and (site, client, slot) unique, and the upsert only updates a row owned by THE SAME
// TICKET. That makes a resume after the guest-agent reboot an update, and a second engineer on
// the same slot a 409 naming who holds it.
//
// ⛔ out_of_hours IS DECIDED HERE, from the site's own hours, and is never read from the body.
// A tool asserting its own compliance is not evidence of it.
async function captureRegister(ctx) {
  const { res, store, body, log, capture: tok } = ctx;
  const refused = captureCapOk(ctx, 'capture:write');
  if (refused) return refused;
  if (typeof store.upsertCaptureRun !== 'function') {
    return json(res, 501, { ok: false, error: 'not supported by this store' });
  }
  const b = parseJsonBody(body);
  if (!b) return json(res, 400, { ok: false, error: 'bad json' });

  // ⚠️ THE SITE IS NOT IN THE BODY AND A BODY THAT NAMES ONE IS AN ERROR, NOT A PREFERENCE.
  // Same rule as the Proxmox collector naming a node it does not hold a token for: a kit
  // sending pharmacy_id is either misconfigured or a token being used from the wrong place,
  // and both need a person rather than a silent choice between two answers.
  for (const forbidden of ['pharmacy_id', 'pharmacy_code', 'site', 'site_code']) {
    if (b[forbidden] !== undefined) {
      return json(res, 400, {
        ok: false,
        error: `a capture registration must not name its site — "${forbidden}" is not accepted. `
             + 'The site is a property of the ticket this token was minted from.',
      });
    }
  }

  const parsed = captureToken.parseRole(b.role);
  if (!parsed.ok) return json(res, 400, { ok: false, error: parsed.error, roles: captureToken.ROLE_VALUES });

  if (b.image_format != null && !captureToken.IMAGE_FORMATS.includes(b.image_format)) {
    return json(res, 400, {
      ok: false,
      error: `image_format must be one of ${captureToken.IMAGE_FORMATS.join(', ')}, or omitted`,
    });
  }

  // The site still has to exist, and it has to be the one the token names. This read is also
  // what the upload filename and the address preview are built from.
  const sites = typeof store.listCaptureSitesForToken === 'function'
    ? await store.listCaptureSitesForToken(tok.pharmacy_id) : [];
  const p = (sites && sites[0]) || null;
  if (!p) {
    return json(res, 409, {
      ok: false,
      error: 'the site this ticket was issued for no longer exists in Watchman. A capture '
           + 'registers against a site that already exists; it cannot create one.',
    });
  }

  // ⛔ THE COMPLIANCE FACT, DECIDED SERVER-SIDE. gateResolved() is the same signal every other
  // gate reads, so a site running on the estate fallback yields null — "we could not establish
  // it" — rather than a confident true off a guess nobody checked.
  let outOfHours = null;
  if (typeof store.getSiteHours === 'function') {
    try {
      const st = await store.getSiteHours(tok.pharmacy_id, null);
      if (st && openingHours.gateResolved(st) && typeof st.is_open === 'boolean') {
        outOfHours = st.is_open === false;
      }
    } catch (e) { outOfHours = null; }
  }

  // Where it goes. Asked BEFORE the write so the answer can be recorded on the row, and so a
  // resumed run is handed the very same path back.
  const upload = await resolveCaptureUpload(ctx, p, parsed.role, b.image_format, b.started_at);

  let saved;
  try {
    saved = await store.upsertCaptureRun(tok.pharmacy_id, {
      role_kind: parsed.kind,
      role_slot: parsed.slot,
      ticket_id: tok.ticket_id,
      started_at: b.started_at || null,
      uploaded_at: b.uploaded_at || null,
      // ⚠️ PROVENANCE ONLY, NEVER A KEY. A PC name survives P2V, so duplicates across the
      // estate are likely. It is escaped for display, bound as a parameter, and interpolated
      // into nothing — a hostname off a pharmacy PC is a descriptor string like any other.
      source_pc_name: printerQueues.displaySafe(b.pc_name, 200),
      disk_gb: captureNum(b.disk_gb),
      image_format: b.image_format || null,
      image_sha256: printerQueues.displaySafe(b.image_sha256, 64),
      bytes_total: captureNum(b.bytes_total),
      bytes_sent: captureNum(b.bytes_sent),
      upload_target: upload.ok ? upload.target.path : null,
      guest_agent_installed: captureTri(b.guest_agent_installed),
      printers_cleared: captureTri(b.printers_cleared),
      slimmed: captureTri(b.slimmed),
      taken_by: printerQueues.displaySafe(b.taken_by, 120) || tok.ticket_issued_by || null,
      out_of_hours: outOfHours,
      failed_reason: printerQueues.displaySafe(b.failed_reason, 500),
    });
  } catch (err) {
    log.warn('capture: register failed', { pharmacy: tok.pharmacy_id, role: parsed.role, msg: err && err.message });
    return json(res, 500, { ok: false, error: 'could not record this capture' });
  }

  if (!saved) {
    // The upsert's ownership guard refused: this slot belongs to a DIFFERENT ticket. Name who
    // holds it — a refusal an engineer cannot explain is a refusal they will work around.
    let holder = null;
    if (typeof store.getCaptureRunForRole === 'function') {
      holder = await store.getCaptureRunForRole(tok.pharmacy_id, parsed.kind, parsed.slot);
    }
    const shaped = captureToken.shapeRun(holder);
    return json(res, 409, {
      ok: false,
      error: shaped
        ? `${p.code} ${parsed.role} is already registered${shaped.taken_by ? ` by ${shaped.taken_by}` : ''}`
          + `${shaped.started_at ? ` at ${shaped.started_at}` : ''}, under a different capture ticket. `
          + 'Pick another slot, or have that capture withdrawn in Watchman.'
        : `${p.code} ${parsed.role} is already registered under a different capture ticket.`,
      role: parsed.role,
      capture: shaped,
    });
  }

  log.info('capture: registered', {
    pharmacy: tok.pharmacy_id, code: p.code, role: parsed.role,
    ticket: tok.ticket_id, uploaded: !!saved.uploaded_at,
  });

  // ⛔ KEEP THE SITE-LEVEL ROLL-UP TRUE. GET /pharmacies/:id/capture predates roles and is
  // read by a build checklist that must never invent its own evidence. Leaving it untouched
  // while the kit wrote role rows would make it answer "no capture held" while five captures
  // existed — a false negative, which sends an engineer home from a site that is not finished.
  await rollUpSiteCapture(ctx, tok.pharmacy_id);

  return json(res, 200, {
    ok: true,
    capture: captureToken.shapeRun(saved),
    // ⛔ THE SERVER NAMES THE DESTINATION. The kit never hardcodes a path, and when there is no
    // destination it is told WHY by name rather than being handed a plausible guess — a
    // guessed path is how a 70 GB image lands where nobody looks.
    upload: upload.ok ? upload.target : null,
    upload_refused: upload.ok ? null : { reason: upload.reason, message: upload.message },
  });
}

// Where does this site's image go? Vigilant has NO ROUTE TO THE PROXMOX API, so it cannot ask
// — the directory is reported by the node itself on the reply-bearing push the collector
// already makes (POST /proxmox/report), and handed back here.
//
// CAPTURE_DROP_DIR / CAPTURE_DROP_NODE are the escape hatch for a node whose collector has not
// been upgraded yet: a HUMAN naming the path in Vigilant's env is still the server naming it,
// and the answer carries source:'configured' so a screen can tell the two apart and a stale
// configured value is findable.
async function resolveCaptureUpload(ctx, pharmacy, role, format, startedAt) {
  const { store } = ctx;
  const node = (pharmacy && pharmacy.proxmox_node) || null;
  let target = null;
  if (node && typeof store.getCaptureDropTarget === 'function') {
    try { target = await store.getCaptureDropTarget(node); } catch (e) { target = null; }
  }
  if (!target) {
    const dir = (process.env.CAPTURE_DROP_DIR || '').trim();
    const forNode = (process.env.CAPTURE_DROP_NODE || '').trim();
    // Only when the env names THIS node, or names no node at all. A configured directory that
    // belongs to temeraire must not be offered for a site placed on another node.
    if (dir && dir[0] === '/' && (!forNode || !node || forNode === node)) {
      target = {
        node: node || forNode || null,
        storage_name: null,
        dir,
        fs_type: null,
        free_bytes: null,
        writable: null,
        read_error: null,
        source: 'configured',
        reported_at: null,
      };
    }
  }
  return captureToken.shapeUploadTarget(target, {
    code: pharmacy && pharmacy.code,
    role,
    format,
    startedAt,
  });
}

// Recompute pmr_site_captures from the role runs. One projection, one direction: the runs are
// the record and this is derived from them, so the two cannot drift.
//
// ⛔ THE SAFETY FLAGS AGGREGATE PESSIMISTICALLY — any false wins, else any null wins, else
// true. "Every machine we checked was clean, and we did not check two of them" is NOT "the
// site is clean". See captureToken.rollUpFlag.
async function rollUpSiteCapture(ctx, pharmacyId) {
  const { store, log } = ctx;
  if (typeof store.listCaptureRuns !== 'function' || typeof store.setSiteCaptureRollUp !== 'function') return;
  try {
    const runs = await store.listCaptureRuns(pharmacyId);
    const roll = captureToken.rollUpRuns(runs);
    if (!roll) return;
    // ⛔ setSiteCaptureRollUp, NOT setSiteCapture. The ordinary write COALESCEs every field so
    // a partial report cannot erase an earlier one — correct for a tool reporting fragments,
    // and WRONG for a projection: a roll-up that recomputes printers_cleared as "not
    // established" must be able to clear a stale true, or the site row keeps handing out an
    // all-clear the runs no longer support.
    await store.setSiteCaptureRollUp(pharmacyId, roll);
  } catch (err) {
    // A failed roll-up must not fail the registration it follows: the run row IS the record,
    // and losing the derived summary is recoverable on the next register. Said out loud so a
    // stale site-level row is diagnosable rather than mysterious.
    log.warn('capture: site roll-up failed', { pharmacy: pharmacyId, msg: err && err.message });
  }
}

// ── GET /proxmox-node-capacity (admin) ─────────────────────────────────────
// The figure nothing in this estate reported until now. Without it, "Watchman refuses a site
// it cannot host and names the resource short" is not implementable at all.
async function proxmoxNodeCapacity(ctx) {
  const { res, store } = ctx;
  if (typeof store.listNodeCapacity !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const list = await store.listNodeCapacity();
  const need = nodeCapacity.siteCost({});
  return json(res, 200, {
    ok: true,
    // ALWAYS THE KEY. `r.nodes || []` on the far side, and an empty list means the collector
    // has not reported — which the caller must read as unknown, not as a cluster with no room
    // and not as one with plenty.
    nodes: list.map((r) => ({
      // Matches pharmacies.proxmox_node. That is what makes this joinable to a site at all.
      node: r.node,
      mem_total_bytes: r.mem_total_bytes == null ? null : Number(r.mem_total_bytes),
      // FREE = what a new VM could actually claim. Never derived from total minus something
      // we did not measure.
      mem_free_bytes: r.mem_free_bytes == null ? null : Number(r.mem_free_bytes),
      storage_name: r.storage_name,
      storage_total_bytes: r.storage_total_bytes == null ? null : Number(r.storage_total_bytes),
      storage_free_bytes: r.storage_free_bytes == null ? null : Number(r.storage_free_bytes),
      measured_at: r.measured_at,
      // Ours, not in the shape the UI asked for: why a read failed, and the verdict for a
      // standard site, so the refusal sentence is computed in one place rather than in every
      // screen that wants to show it.
      read_error: r.read_error || null,
      verdict: nodeCapacity.judgeNodeForSite(r, need),
    })),
    // What a standard site costs, with the arithmetic said in words. Sent so the caller never
    // has to hardcode 197 GB anywhere.
    site_cost: need,
  });
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

// ════════════════════════════════════════════════════════════════════════════
// THE PMR CONTROL PLANE — opening hours, intended state, jobs
// ════════════════════════════════════════════════════════════════════════════

// WHO did this. There are NO user roles in Watchman — everyone gets everything — so a name
// on a row is not an authorisation check and must never be mistaken for one. It is
// PROVENANCE: the audit trail for a change a person made, in the same spirit as
// config_jobs.created_by, which the config path likewise takes from the caller.
//
// Returns null when nobody was named, so a caller that REQUIRES a name (the hours override,
// which suspends a safety rule) can insist on one while routine edits fall back.
function pmrActor(parsed, ctx) {
  const fromBody = parsed && typeof parsed.by === 'string' ? parsed.by.trim() : '';
  const fromQuery = ctx && ctx.query ? String(ctx.query.get('by') || '').trim() : '';
  return (fromBody || fromQuery).slice(0, 80) || null;
}

// ── GET /pharmacies/:id/hours (admin) ───────────────────────────────────────
// The effective week, the exceptions, the estate fallback, and the state RIGHT NOW —
// including which of the three sources answered. All four come off the same view and the
// same function the job gate uses, so the screen cannot show hours the gate disagrees with.
async function siteHoursGet(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.listSiteHours !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  const [week, exceptions, estate, state, closed, window] = await Promise.all([
    store.listSiteHours(id),
    store.listSiteHoursExceptions(id),
    store.getEstateHours(),
    store.getSiteHours(id, null),
    typeof store.listSiteClosedDays === 'function' ? store.listSiteClosedDays(id) : [],
    typeof store.siteDisruptiveWindow === 'function' ? store.siteDisruptiveWindow(id, null) : null,
  ]);
  // Which weekdays are answered by the estate fallback, i.e. which ones NOBODY has told us
  // about. Derived from the same view the gate reads rather than recomputed, and surfaced
  // because it is the difference between "we do not trade on Sunday" and "Sunday's rules
  // were never imported" — and the second one is what the Crossbar 50-row truncation
  // produces.
  const unknownWdays = Array.from(new Set(
    (week || []).filter((b) => b.source === 'fallback').map((b) => b.wday)
  )).sort((a, b) => a - b);
  return json(res, 200, {
    ok: true,
    week,
    exceptions,
    // The weekdays somebody has STATED the site does not trade.
    closed_wdays: (closed || []).map((c) => c.wday),
    // The weekdays nothing is known about. Not the same list, and not the same meaning.
    unknown_wdays: unknownWdays,
    estate_fallback: estate,
    state,
    // Whether a disruptive job could run right now, and when it next could. The job list's
    // "applies at" and this answer come from the same two functions.
    disruptive_window: window,
    // The serialised shape the site page uses, so the hours pill on the site page and this
    // editor cannot disagree — openNow OMITTED, never false, when nothing resolved.
    hours: openingHours.hoursPayload(state),
    // The sentence the UI prints, rendered server-side so the site page, the job list and
    // the API all say the same thing about the same state.
    describes: openingHours.describeHoursState(state),
  });
}

// ── ⛔ THE HOURS WRITE PATH IS ITSELF A GATE (A2) ────────────────────────────
// Shared by the three writes below. Two jobs, and the second is the interesting one:
//
//   1. THE ACTOR COMES FROM THE CREDENTIAL. These tables decide what every
//      pmr_disruptive_allowed() in the platform will permit, so a change to them is at least
//      as consequential as releasing one job with apply-now, and it is recorded the same way:
//      a named operator token, never the shared admin token, and never a `by` the browser
//      chose. `by` in the body is not read on this path at all.
//
//   2. AN EDIT THAT NEWLY ARMS THE NIGHTLY RESTART NEEDS THE TYPED SITE NAME. Not every edit
//      — openingHours.newlyPermittedWdays() answers which ones, and it answers in one
//      direction only, so correcting hours to be MORE protective is friction-free. What is
//      caught is the edit that takes a weekday the gate currently refuses to act on and hands
//      it over: filling in a site whose hours were never entered (its estate-fallback
//      protection disappears the moment it has any facts), or marking a night-trading day
//      closed.
//
// Returns { ok:true, actor } — or writes the refusal and returns { ok:false }. The refusal is
// WRITTEN and the verdict RETURNED as two statements, never `return json(...)`: json()
// returns undefined and the caller would dereference it (A5).
function requireHoursCredential(ctx, what) {
  const { res } = ctx;
  if (!ctx.actor) {
    json(res, 401, {
      ok: false,
      error: `${what} decides when this platform may restart a counter unattended, so it `
           + 'needs a named operator credential (PMR_OPERATOR_TOKENS), not the shared admin '
           + 'token — the change is recorded against a person. Reading the hours is '
           + 'unchanged and still takes the admin token.',
      needs: 'operator-credential',
    });
    return { ok: false };
  }
  return { ok: true, actor: ctx.actor };
}

// The site's OWN weekly blocks, i.e. site_hours_v with the estate fallback rows dropped.
// ⚠️ The fallback rows MUST be dropped here. They are the guess; counting them as current
// hours would make every first-time entry look like a change to an already-known week, which
// is precisely the comparison that must come out the other way.
function ownBlocksFrom(week) {
  return (Array.isArray(week) ? week : [])
    .filter((b) => b && b.source !== 'fallback')
    .map((b) => ({ wday: b.wday, opens_s: b.opens_s, closes_s: b.closes_s }));
}

// The typed-site-name step, in the shape the interrupting counter routes already use, so a
// dialog written for one works for the other.
function requireTypedSiteName(ctx, parsed, pharmacy, why) {
  const { res } = ctx;
  const expect = String((pharmacy && (pharmacy.name || pharmacy.code)) || '').trim();
  const verdict = confirmVerdict(parsed, expect);
  if (verdict !== 'ok') {
    const how = verdict === 'missing'
      ? `send "confirm" in the JSON body, set to the site's name exactly ("${expect || '?'}")`
      : `"confirm" does not match this site's name ("${expect || '?'}")`;
    json(res, 400, {
      ok: false,
      error: `${why}. ${how}`,
      ...confirmRefusal(verdict, expect),
      warning: 'after this change, Watchman may restart this site\'s counters unattended on '
             + 'the affected days, which signs out whoever is signed in at the time',
    });
    return { ok: false };
  }
  return { ok: true };
}

// ── PUT /pharmacies/:id/hours (OPERATOR) ────────────────────────────────────
// Replace a site's whole week. Whole-week and never per-row, because the overlap check is
// a property of the WEEK: two blocks are only valid with reference to each other.
async function siteHoursSet(ctx) {
  const { res, store, body, params, log } = ctx;
  if (typeof store.setSiteHours !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const cred = requireHoursCredential(ctx, "a site's opening hours");
  if (!cred.ok) return;

  // Through the ONE validator, exactly as counterSupportStart routes even a single integer
  // through validateCounterSettings — so this route cannot become a second way to put an
  // out-of-range or overlapping block into the table the hours gate reads.
  const checked = openingHours.validateWeek(p.blocks);
  if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });

  // ⚠️ A WEEKDAY WITH NO BLOCKS IS NOT "CLOSED" — it is UNKNOWN, and the resolver answers it
  // with the estate fallback window (B1). Saying "we do not trade on Sunday" is therefore a
  // POSITIVE statement the editor has to send, and it is what stops a site whose Saturday
  // rules were truncated away from reading as shut all Saturday.
  const closed = openingHours.validateClosedDays(p.closed_wdays, checked.value);
  if (!closed.ok) return json(res, 400, { ok: false, error: closed.error });

  // ⛔ WOULD THIS EDIT NEWLY ARM THE NIGHTLY RESTART? Answered BEFORE anything is written, by
  // comparing the site's own current rows with the proposal. The current week is read from
  // the same view the gate resolves from, with the estate fallback rows dropped — they are
  // the guess, and counting them as current hours would hide the single most consequential
  // edit there is: the first time a site's hours are entered at all, which is the moment its
  // fallback protection ends and the nightly restart becomes legal there.
  const pharmacy = typeof store.getPharmacy === 'function' ? await store.getPharmacy(id) : null;
  const currentWeek = typeof store.listSiteHours === 'function' ? await store.listSiteHours(id) : [];
  const currentClosed = typeof store.listSiteClosedDays === 'function'
    ? (await store.listSiteClosedDays(id)).map((c) => c.wday) : [];
  const newlyPermitted = openingHours.newlyPermittedWdays(
    { blocks: ownBlocksFrom(currentWeek), closed_wdays: currentClosed },
    { blocks: checked.value, closed_wdays: closed.value }
  );
  if (newlyPermitted.length) {
    const days = newlyPermitted.map((w) => openingHours.WDAY_SHORT[w]).join(', ');
    const typedOk = requireTypedSiteName(ctx, p, pharmacy,
      `this change lets Watchman restart this site's counters unattended overnight on ${days}, `
      + 'which it may not do today');
    if (!typedOk.ok) return;
  }

  // 'voip' is reserved for the importer, which owns the rows it writes and replaces them on
  // the next run. A human editing in Watchman is always 'manual', whatever the body claims —
  // otherwise an operator's correction would be silently overwritten by the next import and
  // nobody could tell the two apart.
  //
  // ⚠️ `by` IS THE CREDENTIAL'S NAME (A2). pmrActor() reads the request body, and a name the
  // browser chose is not a person — the same argument apply-now makes. The row's updated_by
  // and updated_at columns are the record of who armed this site and when.
  const saved = await store.setSiteHours(id, checked.value, {
    source: 'manual', closed_wdays: closed.value, by: cred.actor,
  });
  if (!saved) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  // A second, immutable record next to the row's own updated_by: the row keeps only the LAST
  // writer, and "who changed it and when" is a history question.
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(cred.actor, 'hours.set', (pharmacy && pharmacy.code) || String(id),
      `blocks=${checked.value.length} closed_wdays=${closed.value.join('|') || 'none'}`
      + ` newly_permitted=${newlyPermitted.join('|') || 'none'}`);
  }
  if (newlyPermitted.length) {
    log.warn('pmr: a site\'s hours now permit an unattended overnight restart on days they did not',
      { pharmacy: id, wdays: newlyPermitted, by: cred.actor });
  }
  return json(res, 200, {
    ok: true,
    ...saved,
    by: cred.actor,
    // Said back, so the UI can show what the edit actually changed about the platform's
    // permission to interrupt this site — not only what it changed about the times.
    newly_permitted_wdays: newlyPermitted,
  });
}

// ── PUT /pharmacies/:id/hours/exception (OPERATOR) ──────────────────────────
// A bank holiday or a one-off closure. Both times omitted = closed all day, which is the
// common case and the reason this is not folded into the weekly pattern.
//
// ⚠️ AND IT IS THE SHARPEST VERSION OF THE A2 PROBLEM. "Closed all day on the 26th" is one
// short request that makes an unattended restart legal on a date the weekly pattern says the
// site trades through the night — so it climbs the same ladder as the weekly write.
async function siteHoursExceptionSet(ctx) {
  const { res, store, body, params, log } = ctx;
  if (typeof store.setSiteHoursException !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  const checked = openingHours.validateException(p);
  if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });

  const cred = requireHoursCredential(ctx, 'a one-off opening-hours day');
  if (!cred.ok) return;

  const pharmacy = typeof store.getPharmacy === 'function' ? await store.getPharmacy(id) : null;
  const before = await hoursDayState(store, id, checked.value.on_date);
  const after = {
    known: true,
    blocks: checked.value.opens_s == null ? []
      : [{ wday: null, opens_s: checked.value.opens_s, closes_s: checked.value.closes_s }],
  };
  if (openingHours.dayNewlyPermitted(before, after)) {
    const typedOk = requireTypedSiteName(ctx, p, pharmacy,
      `on ${checked.value.on_date} this site currently trades through the hours Watchman uses `
      + 'for unattended restarts; this change opens that window');
    if (!typedOk.ok) return;
  }

  const saved = await store.setSiteHoursException(id, { ...checked.value, by: cred.actor });
  if (!saved) return json(res, 404, { ok: false, error: 'pharmacy not found' });
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(cred.actor, 'hours.exception.set', (pharmacy && pharmacy.code) || String(id),
      `on_date=${checked.value.on_date} opens_s=${checked.value.opens_s == null ? 'closed' : checked.value.opens_s}`);
  }
  log.info('pmr: a one-off opening-hours day was set', { pharmacy: id, on_date: checked.value.on_date, by: cred.actor });
  return json(res, 200, { ok: true, exception: saved, by: cred.actor });
}

// ── DELETE /pharmacies/:id/hours/exception?on_date= (OPERATOR) ──────────────
// ⚠️ DELETING ONE IS A CHANGE IN THE SAME DIRECTION AS SETTING ONE. Removing a "we are open
// late on the 24th" row hands that date back to the weekly pattern, which may be night-quiet
// — so the same before/after comparison decides whether this needs the typed name, and the
// answer is computed from the row being removed rather than assumed.
async function siteHoursExceptionDelete(ctx) {
  const { res, store, params, query, body, log } = ctx;
  if (typeof store.deleteSiteHoursException !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  const onDate = query.get('on_date');
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(onDate || '')) return json(res, 400, { ok: false, error: 'on_date must be YYYY-MM-DD' });
  const p = body ? parseJsonBody(body) : null;

  const cred = requireHoursCredential(ctx, 'a one-off opening-hours day');
  if (!cred.ok) return;

  const pharmacy = typeof store.getPharmacy === 'function' ? await store.getPharmacy(id) : null;
  const before = await hoursDayState(store, id, onDate);
  // What that date falls back to once the exception is gone: the weekly pattern for its
  // weekday, which may state nothing at all — and "nothing" is protected, never permitted.
  const after = await hoursDayState(store, id, onDate, { ignoreException: true });
  if (openingHours.dayNewlyPermitted(before, after)) {
    const typedOk = requireTypedSiteName(ctx, p, pharmacy,
      `removing the one-off day for ${onDate} opens this site's overnight restart window on `
      + 'that date');
    if (!typedOk.ok) return;
  }

  const done = await store.deleteSiteHoursException(id, onDate);
  if (typeof store.appendAudit === 'function') {
    await store.appendAudit(cred.actor, 'hours.exception.delete', (pharmacy && pharmacy.code) || String(id),
      `on_date=${onDate} deleted=${done.deleted}`);
  }
  log.info('pmr: a one-off opening-hours day was removed', { pharmacy: id, on_date: onDate, by: cred.actor });
  return json(res, 200, { ok: true, ...done, by: cred.actor });
}

// What answers ONE local date at this site today: the exception row if there is one,
// otherwise the weekly pattern for that weekday, otherwise nothing at all.
//
// ⚠️ `known:false` IS A REAL ANSWER and it is the protective one — a date nothing states is a
// date site_hours_gate_resolved() refuses, exactly like an unknown weekday. The estate
// fallback rows are dropped for the same reason ownBlocksFrom() drops them: they are the
// guess, not a statement about this site.
async function hoursDayState(store, pharmacyId, onDate, opts = {}) {
  const wday = new Date(`${onDate}T00:00:00Z`).getUTCDay();
  if (!opts.ignoreException && typeof store.listSiteHoursExceptions === 'function') {
    const list = await store.listSiteHoursExceptions(pharmacyId);
    const hit = (list || []).find((x) => String(x.on_date).slice(0, 10) === onDate);
    if (hit) {
      return {
        known: true,
        blocks: hit.opens_s == null ? [] : [{ wday, opens_s: hit.opens_s, closes_s: hit.closes_s }],
      };
    }
  }
  const week = typeof store.listSiteHours === 'function' ? await store.listSiteHours(pharmacyId) : [];
  const closed = typeof store.listSiteClosedDays === 'function'
    ? (await store.listSiteClosedDays(pharmacyId)).map((c) => c.wday) : [];
  const blocks = ownBlocksFrom(week).filter((b) => b.wday === wday);
  if (!blocks.length && !closed.includes(wday)) return { known: false, blocks: [] };
  return { known: true, blocks };
}

// ── intended state (admin) ──────────────────────────────────────────────────
async function pmrIntentList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listPmrIntent !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const raw = query.get('pharmacy_id');
  const id = raw == null || raw === '' ? null : Number(raw);
  if (id !== null && !Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  return json(res, 200, { ok: true, intent: await store.listPmrIntent(id), fields: pmrVerbs.INTENT_FIELDS });
}

// What Watchman WANTS. Validated against the closed field table before it is stored,
// because a reconciler acts on this row: an unvalidated value here becomes an argument to
// a verb later, and the whole point of resolving arguments server-side is that no value a
// caller typed ever reaches an executor unchecked.
async function pmrIntentSet(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.setPmrIntent !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const field = p.field;
  const checked = pmrVerbs.validateIntent(field, p.want);
  if (!checked.ok) return json(res, 400, { ok: false, error: checked.error });
  const spec = pmrVerbs.INTENT_FIELDS[field];

  // The SUBJECT is derived from the field's own table, never taken from the body: a field
  // declared as being about a VM cannot be filed against a counter.
  const subject = spec.subject;
  const pharmacyId = Number(p.pharmacy_id);
  if (!Number.isInteger(pharmacyId)) return json(res, 400, { ok: false, error: 'pharmacy_id required' });
  const counterId = subject === 'counter' ? Number(p.counter_id) : null;
  const vmid = subject === 'vm' ? Number(p.vmid) : null;
  if (subject === 'counter' && !Number.isInteger(counterId)) return json(res, 400, { ok: false, error: 'counter_id required for a counter intent' });
  if (subject === 'vm' && !Number.isInteger(vmid)) return json(res, 400, { ok: false, error: 'vmid required for a vm intent' });

  const saved = await store.setPmrIntent({
    subject_kind: subject, pharmacy_id: pharmacyId, counter_id: counterId, vmid,
    printer_key: null, field, want: checked.value, by: pmrActor(p, ctx) || 'watchman',
  });
  // No row means the SUBJECT did not resolve — the pharmacy does not exist, or the vmid is
  // not registered to it, or the counter belongs to another site. Resolved in the same
  // statement as the INSERT (B5), exactly as createPmrVmJob resolves a job's vmid, because
  // an intent is a standing instruction to a loop that creates real jobs on real nodes.
  if (!saved) {
    return json(res, 404, {
      ok: false,
      error: subject === 'vm'
        ? 'that VM is not registered to that pharmacy — register it on the site first'
        : subject === 'counter'
          ? 'that counter does not belong to that pharmacy'
          : 'subject not found',
    });
  }
  return json(res, 200, { ok: true, intent: saved, converges: !!spec.converges, via: spec.via });
}

async function pmrIntentDelete(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.deletePmrIntent !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const id = Number(params.id);
  if (!Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad intent id' });
  return json(res, 200, { ok: true, ...(await store.deletePmrIntent(id)) });
}

// ── jobs (admin) ────────────────────────────────────────────────────────────
async function pmrJobsList(ctx) {
  const { res, store, query } = ctx;
  if (typeof store.listPmrJobs !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const raw = query.get('pharmacy_id');
  const id = raw == null || raw === '' ? null : Number(raw);
  if (id !== null && !Number.isInteger(id)) return json(res, 400, { ok: false, error: 'bad pharmacy id' });
  return json(res, 200, { ok: true, jobs: await store.listPmrJobs({ pharmacy_id: id, status: query.get('status') }) });
}

// ── POST /pmr/jobs (admin) ──────────────────────────────────────────────────
// Create a job. The caller names a VERB and a SUBJECT — a counter id, or a pharmacy and a
// vmid — and NOTHING ELSE about how it will run: the disruptive flag, the confirming
// reading, the time limit and the visibility timeout all come from the verb's entry in the
// one allowlist, and the executable arguments are resolved server-side inside the INSERT.
//
// A caller cannot make a disruptive job non-disruptive, cannot lengthen its time limit, and
// cannot choose what will count as proof that it worked.
async function pmrJobCreate(ctx) {
  const { res, store, body } = ctx;
  if (typeof store.createPmrCounterJob !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });

  const verb = p.verb;
  if (!pmrVerbs.isVerb(verb)) {
    // Exact match only, and the refusal names the admitted set — the same shape
    // counterAction uses for PI_ACTIONS.
    return json(res, 400, { ok: false, error: `unknown verb "${verb}" — allowed verbs are ${pmrVerbs.VERB_NAMES.join(', ')}` });
  }
  const spec = pmrVerbs.getVerb(verb);
  const args = pmrVerbs.validateVerbArgs(verb, p.args);
  if (!args.ok) return json(res, 400, { ok: false, error: args.error });

  // The verb's own entry decides everything about how the job runs. Spread from ONE place
  // so a verb whose timings change cannot leave a stale copy behind in this handler.
  const fromVerb = {
    verb,
    args: args.value,
    disruptive: spec.disruptive,
    retry_ok: spec.retry_ok,
    confirm_kind: spec.confirm,
    confirm_deadline_s: spec.confirm_deadline_s,
    ttl_s: spec.ttl_s,
    claim_ttl_s: spec.claim_ttl_s,
    // The loop-breaker, from the same one place as everything else about this verb (B3).
    max_attempts: spec.max_attempts,
    by: pmrActor(p, ctx) || 'watchman',
  };

  let job = null;
  if (spec.executor === 'counter-pi') {
    const counterId = Number(p.counter_id);
    if (!Number.isInteger(counterId)) return json(res, 400, { ok: false, error: 'counter_id required' });
    job = await store.createPmrCounterJob(counterId, fromVerb);
    // No row means the resolution found nothing — the counter does not exist, or it has no
    // thin client enrolled. REFUSED rather than guessed at, exactly as setCounterBootTarget
    // refuses a vmid outside the site's registered list: inventing a device id is how a job
    // goes to the wrong Pi.
    if (!job) {
      // Two reasons produce no row, and only one of them is about the counter. A disruptive
      // verb at a site with NO overnight window at all — a 24-hour pharmacy — is refused
      // here rather than queued, because a job that can only expire is worse than a refusal:
      // it later reads to the pre-opening check as a restart that failed (S1/S12, S14).
      const why = await pmrNoJobReason(store, spec, { counter_id: counterId });
      return json(res, 409, { ok: false, error: why });
    }
  } else {
    const pharmacyId = Number(p.pharmacy_id);
    const vmid = Number(p.vmid);
    if (!Number.isInteger(pharmacyId) || !Number.isInteger(vmid)) {
      return json(res, 400, { ok: false, error: 'pharmacy_id and vmid required' });
    }
    job = await store.createPmrVmJob(pharmacyId, vmid, fromVerb);
    if (!job) {
      const why = await pmrNoJobReason(store, spec, { pharmacy_id: pharmacyId });
      return json(res, 409, {
        ok: false,
        error: why === PMR_NO_SUBJECT
          ? 'that VM is not registered to that pharmacy, or its node is not known yet'
          : why,
      });
    }
  }

  // Tell the caller, in the same breath, whether this will actually go anywhere yet. A
  // disruptive job raised while the site is open is CREATED and then WAITS — it does not
  // fire and it does not fail — and the UI's "ready — applies at midnight" line is built
  // from exactly this.
  let waiting = null;
  if (typeof store.getPmrJob === 'function') {
    const full = await store.getPmrJob(job.id);
    if (full) waiting = full.waiting_reason || null;
  }
  return json(res, 201, {
    ok: true,
    job,
    waiting_reason: waiting,
    disruptive: spec.disruptive,
    // WHEN, as an instant rather than as the word "midnight" in a sentence. This is the
    // stored not_before the claim query actually gates on, so the promise and the timer are
    // the same value (S1/S12).
    applies_at: job.not_before || null,
    expires_at: job.expires_at || null,
  });
}

// Why did the INSERT match nothing? The statement is deliberately all-or-nothing — it
// resolves the subject and applies the hours gate in one shot — so the caller has to ask
// afterwards which of the two refused. Read-only, and only ever on the failure path.
const PMR_NO_SUBJECT = 'no-subject';
async function pmrNoJobReason(store, spec, subject) {
  if (!spec.disruptive || typeof store.siteDisruptiveWindow !== 'function') return PMR_NO_SUBJECT;
  let pharmacyId = subject.pharmacy_id;
  if (pharmacyId == null && subject.counter_id != null && typeof store.getCounter === 'function') {
    const c = await store.getCounter(subject.counter_id);
    if (!c) return 'no thin client is enrolled on that counter, so there is nothing to send this to';
    pharmacyId = c.pharmacy_id;
  }
  if (pharmacyId == null) return PMR_NO_SUBJECT;
  const w = await store.siteDisruptiveWindow(pharmacyId, null);
  if (w && !w.allowed_now && !w.next_window_at) {
    // ⚠️ THREE ANSWERS, NOT TWO (A1), AND THE RULE LIVES IN ONE PLACE NOW (Z1/Z2).
    // `hours_resolved` is true for every pharmacy in the estate — site_hours_v hands every
    // unknown weekday the estate fallback — so a two-way split sends every unentered site
    // down the "it never closes" arm and tells an operator to argue a time with a pharmacy
    // that in fact just has no hours on file. The gate's own resolution is what separates
    // them, and it is the sentence most sites will see until their hours are imported.
    //
    // This arm was already three-way, and it still had the hole the other two had: the
    // `hours_resolved` ternary underneath it was reached whenever hours_gate_resolved was
    // ABSENT rather than false — an older store, a lookup that answered without the column —
    // and it then announced "it never closes" on the strength of the fallback. Absent is
    // unknown, and openingHours.noOvernightWindowReason() is where that is decided.
    return openingHours.describeNoOvernightWindow(w, {
      subject: 'this',
      remedy: 'use apply-now with a named operator',
    });
  }
  return subject.counter_id != null
    ? 'no thin client is enrolled on that counter, so there is nothing to send this to'
    : PMR_NO_SUBJECT;
}

async function pmrJobCancel(ctx) {
  const { res, store, params } = ctx;
  if (typeof store.cancelPmrJob !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const cancelled = await store.cancelPmrJob(params.id, pmrActor(null, ctx) || 'watchman');
  // WHERE-guarded in the store: a job an executor has already collected, or one that has
  // finished, returns null. Reported as a refusal rather than a silent no-op that reads as
  // success — the operator needs to know the thing is already in flight.
  if (!cancelled) return json(res, 409, { ok: false, error: 'too late — that job is already with an executor or already finished' });
  return json(res, 200, { ok: true, job: cancelled });
}

// ── POST /pmr/jobs/:id/apply-now (admin) ────────────────────────────────────
// "Apply it now — I know it signs the member of staff out." The ONLY way past the hours
// gate, and it is deliberately a stored fact with a name and a time on it: the rule being
// suspended is that Watchman never restarts a session during opening hours ON ITS OWN, so
// when one does happen the row has to record which person decided that.
//
// Nothing here touches the time limit or the confirming reading. Overriding the hours does
// not make a job done, and it does not make it provable by any weaker standard.
async function pmrJobApplyNow(ctx) {
  const { res, store, log, params, body, actor } = ctx;
  if (typeof store.overridePmrJobHours !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });

  // ⚠️ THE ACTOR COMES FROM THE DISPATCH, WHICH GOT IT FROM A CREDENTIAL (B6/S7). It is NOT
  // read from the body and it is NOT read from ?by=. pmrActor() exists for routine
  // provenance — a name on a row nobody is authenticating — and this route is the one place
  // where that is not good enough: the browser holds the shared admin token, so a browser
  // that can call this could put any name it liked on the record of a pharmacist being
  // signed out. server.js refuses the request outright when no per-operator token matched,
  // so reaching here means a person was identified.
  if (!actor) {
    return json(res, 401, {
      ok: false,
      error: 'apply-now needs a named operator credential — the override is recorded '
           + 'against a person, not against "watchman"',
    });
  }

  const job = typeof store.getPmrJob === 'function' ? await store.getPmrJob(params.id) : null;
  if (!job) return json(res, 404, { ok: false, error: 'not found' });

  // ⚠️ THE TYPED CONFIRMATION, ON THE WIRE, WHEN IT MATTERS MOST (B4). The dialog that makes
  // an operator type the site's name is enforced here for the same reason the deletes
  // enforce theirs: it lived in the browser, and a boundary in the browser is not one.
  //
  // Required whenever the site is OPEN or its hours are UNRESOLVED — the two states in which
  // pressing this signs somebody out of a live session. A site that is already shut needs no
  // typed name, because then this is only asking for the job to run a little sooner.
  let siteState = null;
  if (typeof store.getSiteHours === 'function' && job.pharmacy_id != null) {
    try {
      siteState = await store.getSiteHours(job.pharmacy_id, null);
    } catch (err) {
      log.warn('pmr: hours lookup failed on apply-now', { job: job.id, msg: err && err.message });
      siteState = null;
    }
  }
  // Unknown counts AS OPEN here, deliberately. This is a gate, and the gate's unknown is
  // "do not disrupt" — so an unresolved site asks for the confirmation rather than skipping
  // it. Same direction pmr_disruptive_allowed() takes: unknown means refuse to act.
  //
  // ⛔ gateResolved(), NEVER `resolved` (A1, and this route was MISSED when the other four
  // were fixed). `resolved` is true for every pharmacy in the estate — site_hours_v emits the
  // estate fallback window for every weekday nobody has entered, and the mere existence of
  // that row satisfies it — so at 00:30 the fallback said "shut", `unresolved` came out
  // false, `needsConfirm` came out false, and the ONE route whose entire purpose is to record
  // a person deciding to sign a pharmacist out released the job with no typed name at all.
  // The same defect, in the same shape, on the door the other four were built to match.
  const gateKnown = openingHours.gateResolved(siteState);
  const unresolved = !gateKnown
    || siteState.is_open === null || siteState.is_open === undefined;
  // Only for the refusal sentence: "nobody has entered this site's hours" and "the lookup
  // failed" both refuse, and an operator can act on the first.
  const guessing = !!siteState && !gateKnown;
  const needsConfirm = job.disruptive && (unresolved || siteState.is_open === true);
  if (needsConfirm) {
    const p = body ? parseJsonBody(body) : null;
    const expect = String(job.site_name || job.site_code || '').trim();
    const verdict = confirmVerdict(p, expect);
    if (verdict !== 'ok') {
      const why = unresolved
        ? (guessing
          ? 'nobody has entered this site\'s opening hours, so what Watchman shows for it is '
            + 'the estate fallback GUESS and not a fact — it must be treated as open'
          : 'this site\'s opening hours could not be read, so it must be treated as open')
        : 'that site is OPEN';
      const how = verdict === 'missing'
        ? `send "confirm" in the JSON body, set to the site's name exactly ("${expect || '?'}")`
        : `"confirm" does not match this site's name ("${expect || '?'}")`;
      return json(res, 400, {
        ok: false,
        error: `${why}. ${how}, confirming that you are signing a member of staff out`,
        ...confirmRefusal(verdict, expect),
        // Same key the counter routes emit, so one dialog serves both.
        hours_unknown: guessing,
      });
    }
  }

  const done = await store.overridePmrJobHours(params.id, actor);
  if (!done) {
    return json(res, 409, {
      ok: false,
      error: 'that job is not a pending disruptive job that has never been handed out — '
           + 'there is nothing to override',
    });
  }
  // warn, not info: this is the record of a safety rule being deliberately suspended on a
  // live pharmacy counter, and it should be findable in the log without knowing to look.
  log.warn('pmr: hours override — a disruptive job was released during opening hours', {
    job: done.id, verb: done.verb, counter: done.counter_id, pharmacy: done.pharmacy_id,
    by: actor, site_open: siteState ? siteState.is_open : null,
  });
  return json(res, 200, {
    ok: true,
    job: done,
    by: actor,
    // Said back verbatim so the confirmation dialog and the audit trail carry the same
    // sentence the operator agreed to.
    warning: 'this signs the member of staff at that counter out',
    // Offered ONCE. If the executor never reports, the job does not come round again — the
    // override is not a standing permission to restart this counter in hours (B3).
    note: 'this override releases the job once; it is not re-offered if the executor does not report',
  });
}

// ── POST /pmr/job-result (device) ───────────────────────────────────────────
// The counter Pi reporting what it did. 'applied' means THE EXECUTOR SAYS IT RAN — it is
// not done, finished_at stays null, and a reading nothing on the executor wrote decides.
//
// Ownership is re-checked in the store even though the bearer authenticated, exactly as
// POST /config/result re-checks with getConfigJobForFetch and relayNext re-checks the
// session's device: a valid token for counter B must not close counter A's job.
async function pmrJobResult(ctx) {
  const { res, store, log, device, body } = ctx;
  if (!device) return json(res, 401, { ok: false, error: 'unauthorized' });
  if (typeof store.recordPmrJobResult !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });

  const p = parseJsonBody(body);
  if (!p) {
    log.warn('pmr/job-result: bad json', { device: device.id });
    return json(res, 400, { ok: false, error: 'bad json' });
  }
  const jobId = p.job_id;
  const status = p.status;
  if (!jobId || !status) return json(res, 400, { ok: false, error: 'job_id and status required' });

  // The closed set an EXECUTOR may report, checked BEFORE it reaches the DB so a malformed
  // body cannot violate the CHECK constraint and 500 the service. The important word is the
  // one that is NOT in the set: 'confirmed'. An executor can say it ran the thing; it can
  // never say the thing is true.
  if (!pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has(status)) {
    log.warn('pmr/job-result: invalid status', { device: device.id, status });
    return json(res, 400, { ok: false, error: `status must be one of ${[...pmrVerbs.EXECUTOR_REPORTABLE_STATUSES].join(', ')}` });
  }

  const done = await store.recordPmrJobResult(jobId, { status, result_log: p.result_log },
    { pi_device_id: device.id });
  if (!done) return json(res, 404, { ok: false, error: 'not found' });
  // Deliberately does NOT say "ok, done". The job is waiting to be proven, and telling an
  // executor otherwise is the "it exited 0, so it worked" mistake this ladder exists to
  // make impossible.
  return json(res, 200, {
    ok: true,
    status: done.status,
    awaiting_confirmation: done.status === 'applied',
    confirmed_by: done.status === 'applied' ? done.confirm_kind : null,
  });
}

// ── Proxmox discovery ───────────────────────────────────────────────────────
// Every numeric field of a capacity row. Listed once so the coercion below cannot drift from
// the columns the store binds.
const CAPACITY_NUMERIC_FIELDS = [
  'cores', 'mem_max_bytes',
  'cpu_pct_1d', 'cpu_pct_7d', 'cpu_pct_30d',
  'mem_bytes_1d', 'mem_bytes_7d', 'mem_bytes_30d', 'mem_pressure_1d',
  'disk_used_bytes', 'disk_total_bytes',
];

// Range guard for the fields whose column has a fixed precision. Coercing to a number is not
// enough: cpu_pct_* is numeric(5,2) and mem_pressure_1d is numeric(6,3), so a single value past
// their precision raises 22003 "numeric field overflow", which aborts the WHOLE capacity
// transaction — one bad reading from one VM destroys every VM's capacity row for that pass.
//
// Measured on the real cluster (VM 305, day timeframe, 1439 rows, no gaps): cpu ran 0.344..0.902
// as a FRACTION (x100 for percent) and every pressure series read 0.000, so nothing observed is
// anywhere near the limit. This is defensive, not a fix for something seen — but the cost of
// being wrong is the entire estate's capacity, so both are pinned to the 0..100 they are defined
// as. Anything outside that is not a bigger reading, it is a broken one.
const CAPACITY_CLAMPED_FIELDS = {
  cpu_pct_1d: [0, 100], cpu_pct_7d: [0, 100], cpu_pct_30d: [0, 100],
  mem_pressure_1d: [0, 100],
};

// One capacity row, cleaned. Returns null for a row that must be DROPPED.
//
// This is the only gate in front of the capacity write: the VM branch above hands p.vms
// straight to the store, and that was survivable while every column was nullable text. It stops
// being survivable here because disk_source is CHECK-constrained — one junk value would abort
// the whole transaction, so a single malformed row would take every VM's capacity with it.
// One node/pool headroom row off the collector, cleaned.
//
// (node, storage_name) is the primary key and the join back to pharmacies.proxmox_node, so a
// row missing either has nothing to attach to and is dropped rather than guessed at.
//
// ⛔ EVERY NUMBER IS null-OR-A-NUMBER, NEVER COERCED TO 0. A pool the collector could not read
// must stay unreadable in the data: judgeNodeForSite() answers 'unknown' for a null, and
// 'unknown' is neither a refusal nor an approval. A 0 here would read as "completely full",
// which is a different and much louder claim than the one the collector made.
function cleanNodeCapacityRow(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  const text = (v) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 200) : null);
  const node = text(r.node);
  const storage = text(r.storage_name);
  if (!node || !storage) return null;
  const num = (v) => {
    if (v == null) return null;
    const n = Number(v);
    // Negative free space is not a reading, it is a bug at the far end. Refused rather than
    // clamped to 0, which would be inventing the most alarming possible answer.
    return Number.isFinite(n) && n >= 0 ? n : null;
  };
  return {
    node,
    storage_name: storage,
    mem_total_bytes: num(r.mem_total_bytes),
    mem_free_bytes: num(r.mem_free_bytes),
    storage_total_bytes: num(r.storage_total_bytes),
    storage_free_bytes: num(r.storage_free_bytes),
    cpu_cores: num(r.cpu_cores),
    read_error: text(r.read_error),
  };
}

function cleanCapacityRow(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  // vmid is the primary key and the join back to proxmox_vms. A row without a real one has
  // nothing to attach to, so it is dropped rather than guessed at.
  const vmid = Number(r.vmid);
  if (!Number.isInteger(vmid) || vmid <= 0) return null;

  const text = (v) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 200) : null);
  const out = {
    vmid,
    node: text(r.node),
    name: text(r.name),
    disk_mount: text(r.disk_mount),
    // Tri-state collapsed to the CHECK's two legal values. Only an explicit 'agent' from a
    // successful get-fsinfo counts as a disk reading; everything else — absent, misspelled, a
    // number — is 'unknown', and the store then writes NULL bytes rather than 0.
    disk_source: r.disk_source === 'agent' ? 'agent' : 'unknown',
    // Why the RRD read failed on this pass, or null when it worked. The collector used to throw
    // this away, which is what made a permanently broken RRD path indistinguishable from a quiet
    // VM. The store writes it unconditionally, so a repaired path clears it.
    rrd_error: text(r.rrd_error),
    proscript: (r.proscript === 'running' || r.proscript === 'stopped' || r.proscript === 'unknown') ? r.proscript : null,
    vm_sql: (r.vm_sql === 'running' || r.vm_sql === 'stopped' || r.vm_sql === 'unknown') ? r.vm_sql : null,
    vm_scardsvr: (r.vm_scardsvr === 'running' || r.vm_scardsvr === 'stopped' || r.vm_scardsvr === 'unknown') ? r.vm_scardsvr : null,
    health_error: text(r.health_error),
    last_backup_at: (Number.isFinite(Number(r.last_backup_at)) && Number(r.last_backup_at) > 0) ? Number(r.last_backup_at) : null,
    backup_error: text(r.backup_error),
  };
  for (const k of CAPACITY_NUMERIC_FIELDS) {
    const n = Number(r[k]);
    // A field the collector could not establish is omitted, not zeroed, and must stay that way
    // through here: null means "not measured", 0 would mean "measured, and idle/empty".
    if (r[k] == null || !Number.isFinite(n)) { out[k] = null; continue; }
    const range = CAPACITY_CLAMPED_FIELDS[k];
    out[k] = range ? Math.min(range[1], Math.max(range[0], n)) : n;
  }
  return out;
}

// ── §7 · the Windows printer list, on the way IN ────────────────────────────
// ⚠️ A PRINTER NAME IS A STRING FROM INSIDE A WINDOWS BOX. It is named by whoever installed the
// printer, it travels through an RDP redirect that decorates it, and it lands on a page that
// renders it. So it is bounded here, at the edge, before anything stores or shows it: control
// characters out (they break log lines and terminals), length bounded, list capped. The store
// binds every one as a parameter and builds no SQL from any of them.
const PRINTER_NAME_MAX = 120;
// Far beyond the five queues a kiosk redirects, so this is a runaway guard rather than a
// filter — but the collector caps too, and a capped list is reported AS capped so the modal
// never reads a name's absence from one as evidence.
const PRINTER_LIST_CAP = 64;
// eslint-disable-next-line no-control-regex
const PRINTER_CTRL_RE = /[\u0000-\u001f\u007f-\u009f]/g;
// How far out of step with our own clock a collector's read time may be before it is unusable.
// The FUTURE bound is the one that matters: `collected_at` is what the modal ages the reading
// by, so a timestamp ahead of now renders as permanently fresh — the one direction in which a
// bad clock produces a confident lie rather than a visible doubt. A little slack for ordinary
// drift between a node and this server.
const PRINTER_READ_AHEAD_MS = 5 * 60 * 1000;
// And a floor. A reading a week old is not a reading; it is a row from a collector that has
// been failing since, and the honest answer for it is "nobody has looked recently".
const PRINTER_READ_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function cleanPrinterName(v) {
  if (typeof v !== 'string') return null;
  const s = v.replace(PRINTER_CTRL_RE, '').trim();
  return s ? s.slice(0, PRINTER_NAME_MAX) : null;
}

// One printer reading off the collector, cleaned. Returns null for a row that must be DROPPED.
//
// ⛔ ABSENT IS NOT EMPTY, AND THIS IS THE LAST PLACE THAT CAN GET IT WRONG. `printers: null`
// means the guest was not read; `printers: []` means it WAS read and Windows lists nothing.
// Anything that turns the first into the second — a `|| []`, a filter that empties a list, a
// missing key defaulted — puts a red fault on every desktop nobody has looked at yet.
//
// A list that arrives WITHOUT a usable read time is therefore demoted to no list at all, with
// the reason attached. The wire contract makes collected_at required for exactly this reason:
// a reading that cannot be dated cannot be aged, and a reading that cannot be aged must not be
// presented as one.
function cleanVmPrintersRow(r, nowMs) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return null;
  const vmid = Number(r.vmid);
  if (!Number.isInteger(vmid) || vmid <= 0) return null;

  const text = (v) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, 200) : null);
  const out = {
    vmid,
    node: text(r.node),
    name: text(r.name),
    printers: null,
    read_at: null,
    source: null,
    error: text(r.error),
  };

  // NOT `if (r.printers)` — [] is falsy and is the one answer that must survive.
  if (!Array.isArray(r.printers)) return out;

  // Epoch seconds from the collector; an ISO string is accepted too so a future producer is
  // not forced through a second format.
  let readMs = null;
  if (typeof r.read_at === 'number' && Number.isFinite(r.read_at)) {
    readMs = r.read_at * 1000;
  } else if (typeof r.read_at === 'string' && r.read_at.trim()) {
    const parsed = Date.parse(r.read_at);
    if (Number.isFinite(parsed)) readMs = parsed;
  }
  if (readMs === null || readMs > nowMs + PRINTER_READ_AHEAD_MS
      || readMs < nowMs - PRINTER_READ_MAX_AGE_MS) {
    // The list is dropped, deliberately, and the row still goes so the reason is stored.
    out.error = out.error
      || 'the collector reported a printer list with no usable read time, so it was not stored';
    return out;
  }

  const names = [];
  for (const entry of r.printers) {
    // Bare strings today. An object with a `name` is accepted so the collector can carry the
    // driver or the default flag later without this having to change.
    const raw = typeof entry === 'string' ? entry
      : (entry && typeof entry === 'object' && !Array.isArray(entry) ? entry.name : null);
    const name = cleanPrinterName(raw);
    if (name === null) continue;
    names.push(name);
    if (names.length >= PRINTER_LIST_CAP) break;
  }
  // ⛔ NOT demoted to null when every entry was unusable and the guest said there were some —
  // that judgement belongs to the collector, which knows how many the guest declared and says
  // so in `error`. Here, an array that arrived IS an answer that the guest was read.
  out.printers = names;
  out.read_at = new Date(readMs).toISOString();
  out.source = r.source === 'session-agent' ? 'session-agent' : 'guest-agent';
  return out;
}

// A collector on a Proxmox node pushes the cluster's VM inventory here, plus a `capacity`
// array of CPU/RAM/disk readings. Vigilant cannot pull either: it sits on the DMZ VLAN with no
// route to the management VLAN, and inverting the direction avoids having to open one.
async function proxmoxReport(ctx) {
  const { res, store, body, log } = ctx;
  if (typeof store.reportProxmoxVms !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const p = parseJsonBody(body);
  if (!p) return json(res, 400, { ok: false, error: 'bad json' });
  if (!Array.isArray(p.vms)) return json(res, 400, { ok: false, error: 'vms must be an array' });
  // Optional: an older collector sends no capacity at all, and must keep reporting inventory.
  if (p.capacity !== undefined && !Array.isArray(p.capacity)) {
    return json(res, 400, { ok: false, error: 'capacity must be an array' });
  }
  const stored = await store.reportProxmoxVms(p.vms);

  // Capacity AFTER the inventory, in its own call: a capacity row must never be the first
  // thing in the database that mentions a vmid.
  const capIn = Array.isArray(p.capacity) ? p.capacity : [];
  const capacity = capIn.map(cleanCapacityRow).filter(Boolean);
  const rejected = capIn.length - capacity.length;
  if (rejected) {
    // Surfaced rather than swallowed — a collector shipping rows we silently discard looks
    // exactly like a collector that is not running.
    log.warn('proxmox: capacity rows rejected', { rejected, received: capIn.length });
  }
  let capStored = {};
  if (capacity.length && typeof store.reportProxmoxCapacity === 'function') {
    capStored = await store.reportProxmoxCapacity(capacity);
  }

  // ── §7 · WHAT WINDOWS ITSELF LISTS ────────────────────────────────────────
  // The reading the printers modal joins its confirmations against, and the ONLY channel it
  // can arrive on. Vigilant has no route to the Proxmox API — no inbound hole, no API token —
  // so there is no on-demand read to add and this is not a cache in front of one: it is the
  // reading. The modal polls the READ path below and ages what it finds.
  //
  // OPTIONAL, like `capacity` and `nodes`: every deployed collector predates this key, and one
  // that sends none must keep reporting inventory.
  //
  // ⛔ A VM THE COLLECTOR DID NOT READ SENDS NO ROW. Not an empty list — an empty list is a
  // claim about Windows, and the collector is not entitled to make it about a desktop it never
  // asked. Nothing here manufactures one either.
  let printersStored = {};
  if (p.printers !== undefined && !Array.isArray(p.printers)) {
    return json(res, 400, { ok: false, error: 'printers must be an array' });
  }
  const printersIn = Array.isArray(p.printers) ? p.printers : [];
  const nowMs = Date.now();
  const printerRows = printersIn.map((r) => cleanVmPrintersRow(r, nowMs)).filter(Boolean);
  if (printersIn.length !== printerRows.length) {
    // Surfaced rather than swallowed, exactly as the capacity rejections are: a collector
    // shipping rows we silently discard looks identical to a collector that is not running.
    log.warn('proxmox: printer rows rejected',
      { rejected: printersIn.length - printerRows.length, received: printersIn.length });
  }
  if (printerRows.length && typeof store.reportProxmoxVmPrinters === 'function') {
    printersStored = await store.reportProxmoxVmPrinters(printerRows);
  }

  // ── NODE HEADROOM ─────────────────────────────────────────────────────────
  // A different question from `capacity` above: that one asks "is this pharmacy's SERVER
  // running out of room?", this one asks "can this NODE host another pharmacy at all?".
  // Nothing reported it until now, which is why a site build could not be refused with the
  // resource named.
  //
  // OPTIONAL, like `capacity`: a collector that sends no `nodes` key must keep reporting
  // inventory, and every deployed collector predates this.
  //
  // ⛔ A FIGURE THE COLLECTOR COULD NOT ESTABLISH ARRIVES AS null AND IS STORED AS null.
  // Never 0. "This pool is full" and "we could not read this pool" are different facts and
  // exactly one of them is an emergency.
  let nodesStored = {};
  if (p.nodes !== undefined && !Array.isArray(p.nodes)) {
    return json(res, 400, { ok: false, error: 'nodes must be an array' });
  }
  const nodesIn = Array.isArray(p.nodes) ? p.nodes : [];
  const nodeRows = nodesIn.map(cleanNodeCapacityRow).filter(Boolean);
  if (nodesIn.length !== nodeRows.length) {
    // Surfaced rather than swallowed, exactly as the capacity rejections are: a collector
    // shipping rows we silently discard looks identical to a collector that is not running.
    log.warn('proxmox: node capacity rows rejected',
      { rejected: nodesIn.length - nodeRows.length, received: nodesIn.length });
  }
  if (nodeRows.length && typeof store.reportNodeCapacity === 'function') {
    nodesStored = await store.reportNodeCapacity(nodeRows);
  }

  // ── WHERE A 70 GB CAPTURE IS ALLOWED TO LAND ──────────────────────────────
  // ⛔ VIGILANT HAS NO ROUTE TO THE PROXMOX API, so it cannot ask a node where its capture
  // drop directory is — the whole integration is this outward push, which is also why job
  // hand-out rides this reply. The node therefore REPORTS the directory here, and the capture
  // kit is handed it back by name. The path is then ground truth from the machine that owns
  // it, rather than a string Vigilant guessed; a guessed path is how an image lands where
  // nobody looks.
  //
  // ⛔ AND ONLY A CREDENTIALED NODE MAY NAME ONE. `p.capture_drop.node` would be a string in
  // a body authenticated by an estate master token that all three nodes share — the same
  // weakness `p.node` had for job hand-out. The node name is taken from ctx.executorNode and
  // from nothing else, so a master-token collector's inventory still lands and its drop
  // directory is ignored.
  //
  // OPTIONAL, like `capacity` and `nodes`: every deployed collector predates this key.
  let dropStored = {};
  if (p.capture_drop !== undefined && (typeof p.capture_drop !== 'object' || Array.isArray(p.capture_drop))) {
    return json(res, 400, { ok: false, error: 'capture_drop must be an object' });
  }

  // Reconcile immediately so a freshly-provisioned pharmacy is linked up on the first
  // report rather than after some later pass.
  const linked = await store.reconcileProxmox();
  if (linked.conflicts.length) {
    log.warn('proxmox: discovery conflicts', { count: linked.conflicts.length });
  }

  const dropNode = typeof ctx.executorNode === 'string' ? ctx.executorNode : '';
  if (p.capture_drop && dropNode && typeof store.reportCaptureDropTargets === 'function') {
    // The node is overwritten with the credentialed one, whatever the body said. Not merged,
    // not preferred — overwritten, because the body's opinion of which node it is has no
    // standing here at all.
    const cleaned = captureToken.cleanDropTargetRow({ ...p.capture_drop, node: dropNode });
    if (cleaned) {
      dropStored = await store.reportCaptureDropTargets([cleaned]);
    } else {
      // Said out loud rather than swallowed: a collector shipping a drop directory we
      // silently discard looks exactly like a collector that never reported one, and the
      // symptom lands ninety minutes later on an engineer with a finished image and nowhere
      // to put it.
      log.warn('proxmox: capture drop target rejected', { node: dropNode });
    }
  }

  const response = { ok: true, ...stored, ...capStored, capacity_rejected: rejected,
    ...printersStored, ...nodesStored, ...dropStored, ...linked };

  // ── the control plane rides this reply ────────────────────────────────────
  // WHICH NODE IS ASKING. The rows in `vms` carry a per-row node name, but that is data
  // ABOUT VMs — it is not this caller's claim about who it is, and one node's push legally
  // contains rows for the whole cluster. So the node names ITSELF, top level, and jobs are
  // selected for THAT name only.
  //
  // The same check relayNext makes at the device level and for the same reason: three nodes
  // share one admin bearer, so without this each of them would drain every other node's
  // queue and act on VMs it does not host.
  //
  // ⚠️ AND IT NAMES ITSELF WITH A CREDENTIAL, NOT WITH A STRING (S9). `p.node` was the
  // executor's own claim about who it was, carried in the body it also authored, on a route
  // authenticated by an estate master token that all three nodes share. That token also buys
  // job creation, apply-now at any site and intent writes, so "which node is this" was the
  // weakest link in the strongest credential. ctx.executorNode is derived by the dispatch
  // from a per-node token; it is the only identity trusted here.
  //
  // A master-token caller keeps its inventory write and gets NO jobs and NO result recording:
  // it is authenticated but anonymous, and neither of those may be done anonymously.
  const node = typeof ctx.executorNode === 'string' ? ctx.executorNode : '';
  const claimedNode = typeof p.node === 'string' ? p.node.trim() : '';
  // A body that names a DIFFERENT node than the credential is not a mistake worth guessing
  // about — it is either a misconfigured collector or a token being used from the wrong box,
  // and both need a person, not a silent preference for one of the two answers.
  if (node && claimedNode && claimedNode !== node) {
    log.warn('proxmox: body names a different node than the credential', { credential: node, body: claimedNode });
    return json(res, 400, {
      ok: false,
      error: 'this credential belongs to node "' + node + '" but the report names "'
           + claimedNode + '"',
    });
  }

  // RESULTS FIRST, then new work. Reported on the push the collector already makes rather
  // than through a route of their own — cheaper, and it needs nothing inbound. Applied in
  // their own store call AFTER the inventory, for the same reason capacity is: one failing
  // must not roll back the other.
  //
  // Note what a result CANNOT say. 'applied' means the executor ran it; the confirm pass
  // decides whether it worked, from proxmox_vms rows this very push just wrote.
  const resultsIn = Array.isArray(p.job_results) ? p.job_results : [];
  if (resultsIn.length && node && typeof store.recordPmrJobResult === 'function') {
    let recorded = 0;
    for (const r of resultsIn.slice(0, 50)) {
      if (!r || typeof r !== 'object') continue;
      if (!r.job_id || !pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has(r.status)) continue;
      try {
        // Scoped to the reporting node inside the statement, so a node cannot close a job
        // that belongs to another node.
        const done = await store.recordPmrJobResult(r.job_id,
          { status: r.status, result_log: r.result_log }, { node });
        if (done) recorded += 1;
      } catch (err) {
        log.warn('proxmox: job result rejected', { node, job: r.job_id, msg: err && err.message });
      }
    }
    response.job_results_recorded = recorded;
  }

  // NEW WORK. SEVERAL jobs, not one: this executor's poll is 15 minutes and its timer
  // carries an explicit do-not-shorten warning, so one job per tick would take an hour to
  // set onboot on four VMs at one site. Bounded in the store so a backlog cannot arrive as
  // one enormous reply.
  //
  // Handing them out IS the claim, and the claim statement applies the same three gates the
  // Pi path gets — the time limit, the visibility timeout, and the opening-hours gate on a
  // disruptive verb. A vm.shutdown at a trading pharmacy is not selected here.
  //
  // ⚠️ AND THE COLLECTOR MUST UNDERSTAND `jobs` BEFORE IT IS OFFERED ANY (D4). The shipped
  // collector posts {"vms","capacity"} and reads no `jobs` key, so a token issued to it would
  // have made these jobs disappear on the reply — claimed, never run, expired — and two of
  // the four verbs on this path take a live pharmacy desktop down. The floor is the same
  // mechanism the Pi path got, with the version read from the top level of this body.
  const collectorVersion = Number.isInteger(p.collector_version) ? p.collector_version : 0;
  if (node && typeof store.claimPmrJobsForNode === 'function') {
    try {
      const jobs = await store.claimPmrJobsForNode(
        node, 4, collectorVersion, pmrVerbs.PMR_JOB_COLLECTOR_VERSION
      );
      // Absent rather than empty when there is nothing to do, exactly as the Pi reply omits
      // a directive it has no work for: an older collector that never learned to parse this
      // key is unaffected, and the common idle reply costs nothing.
      if (jobs.length) {
        response.jobs = jobs.map((j) => ({ id: j.job_id, verb: j.verb, args: j.args || {} }));
      }
    } catch (err) {
      // A failed claim must not cost this push its inventory write, which is the thing the
      // whole estate's VM view depends on.
      log.warn('proxmox: job claim failed', { node, msg: err && err.message });
    }
  } else if (!node) {
    // Said out loud rather than silently skipped: a collector authenticating with the shared
    // master token looks exactly like a collector with no work, and that is a difference an
    // operator wondering why onboot never converges needs to be able to see.
    response.jobs_skipped =
      'this collector authenticated with the estate master token, which names no node — '
      + 'issue it a per-node token (PROXMOX_NODE_TOKENS) to receive jobs';
  }
  // Said out loud for the SECOND reason a node gets no work, and it must be a different
  // sentence from the one above: "I have a token and still get nothing" is precisely the
  // symptom that would otherwise be diagnosed as a broken queue rather than an un-upgraded
  // collector. Reported whether or not jobs were handed out, so it is visible on the very
  // first push after a token is issued.
  if (node && collectorVersion < pmrVerbs.PMR_JOB_COLLECTOR_VERSION) {
    response.jobs_skipped =
      `this collector reports collector_version ${collectorVersion || 'none'}, below the `
      + `${pmrVerbs.PMR_JOB_COLLECTOR_VERSION} that implements the "jobs" key — it is offered `
      + 'no jobs until it does, because handing one out IS the claim and a collector that '
      + 'cannot read the key would swallow it';
  }

  return json(res, 200, response);
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

// DELETE /devices/:serial  { by?, force? }
// Full removal from the register — the cascade takes live state, history, the enrollment
// token (revoked-by-deletion; the plaintext is unrecoverable, so a returning router needs
// a full re-enrol), config jobs/snapshots and alerts. An ONLINE device is refused without
// {"force":true}. The audit row records who asked; 'watchman' is the honest fallback when
// the UI does not say (same convention as brandingActor — the admin token identifies the
// estate, not a person).
async function deviceDelete(ctx) {
  const { res, store, body, params } = ctx;
  if (typeof store.deleteDevice !== 'function') return json(res, 501, { ok: false, error: 'not supported by this store' });
  const parsed = parseJsonBody(body) || {};
  const by = typeof parsed.by === 'string' && parsed.by.trim() ? parsed.by.trim() : 'watchman';
  const force = parsed.force === true;
  const r = await store.deleteDevice(params.serial, { force });
  if (!r) return json(res, 404, { ok: false, error: 'device not found' });
  if (r.blocked === 'online') {
    return json(res, 409, {
      ok: false,
      error: 'device is online — it is still reporting; pass {"force":true} to remove it anyway',
      device: r.device,
    });
  }
  await store.appendAudit(by, 'device.delete', params.serial,
    `identity=${r.device.identity || '?'} site=${r.device.site_name || '?'} last_status=${r.device.status || 'unknown'} forced=${force}`);
  return json(res, 200, { ok: true, deleted: true, device: r.device });
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
  deviceDelete,
  pharmaciesList,
  pharmacyGet,
  pharmacyCreate,
  pharmacyUpdate,
  pharmacyDelete,
  pharmacyGatewayConfig,
  gatewayDnsmasqManifest,
  countersList,
  counterCreate,
  counterUpdate,
  lanPrinters,
  printerTestPrint,
  printerAdopt,
  printerIdentify,
  piAgentScript,
  piToolboxScript,
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
  counterCancelBootTargetStage,
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
  // ── the printer model (docs/pmr-printer-contract.md) ──
  printerDevicesList,
  printerQueuesList,
  desktopPrintersList,
  printerQueueUpsert,
  printerQueueDelete,
  printerQueueTestPrint,
  printerAssign,
  printingPromote,
  // ── the site build lifecycle ──
  siteCaptureGet,
  siteCaptureSet,
  // ── the capture kit ──
  captureTicketIssue,
  captureTicketList,
  captureTicketRevoke,
  captureTokenMint,
  captureSitesList,
  captureSlotsRead,
  captureRegister,
  siteImportGet,
  siteImportSet,
  proxmoxNodeCapacity,
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

  // ── the PMR control plane ─────────────────────────────────────────────────
  siteHoursGet,
  siteHoursSet,
  siteHoursExceptionSet,
  siteHoursExceptionDelete,
  pmrIntentList,
  pmrIntentSet,
  pmrIntentDelete,
  pmrJobsList,
  pmrJobCreate,
  pmrJobCancel,
  pmrJobApplyNow,
  pmrJobResult,
};
