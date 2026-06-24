# Vigilant — build contract (authoritative)

This pins the interfaces so the ingest service, worker, CLIs, tests, and agent all line
up. **Source of truth for DB columns = `db/schema.sql`. Source of truth for the device
payload = `agent/vigilant-agent.rsc`.** This file pins the JavaScript architecture.

Stack: **Node 20+, plain CommonJS JS** (matches `provisioner/server.js`), HTTP via the
stdlib `http` module, Postgres via `pg`, validation via `zod`, env via `dotenv`. Tests via
the built-in `node:test` runner. No TypeScript, no Express. Target Postgres is the
self-hosted Supabase DB on the IaaS, schema `vigilant`.

## File layout

```
vigilant/
  package.json            # one manifest for the whole service; scripts below
  .env.example
  .dockerignore
  Dockerfile
  docker-compose.yml
  src/
    shared/
      config.js           # loads env (dotenv), exports typed config object + validation
      log.js              # tiny structured logger: log.info/warn/error(msg, meta?)
      store.js            # the Store INTERFACE (jsdoc) + factory makeStore(kind)
      store.pg.js         # Postgres Store (uses db.js) + migrate()
      store.mem.js        # in-memory Store (tests + local dev + simulator E2E)
      db.js               # pg Pool factory from config.databaseUrl
      telemetry.js        # zod schema + normalize(raw) -> typed payload
      transform.js        # PURE functions (no IO): deltas, role, joins, parsing
      oui.js              # MAC OUI -> vendor lookup (seed map + lookup fn)
    ingest/
      server.js           # createServer({store, config}) -> http.Server ; routing+auth
      handlers.js         # one fn per route (telemetry, agentScript, config*, fleet…)
    worker/
      worker.js           # runWorker({store, config}) ; runOnce() for tests
    bin/
      migrate.js          # node src/bin/migrate.js  -> store.migrate()
      enroll.js           # node src/bin/enroll.js --serial … --site …  -> device + token
      simulate.js         # node src/bin/simulate.js --url … --token …  -> POSTs telemetry
  test/
      transform.test.js
      telemetry.test.js
      oui.test.js
      ingest.e2e.test.js  # createServer(memStore) + a real POST + assert store writes
      config.test.js
  db/schema.sql           # EXISTING — migrate() runs this verbatim
  agent/*.rsc             # EXISTING — finalized by the agent task
  docs/*.md
```

`package.json` scripts: `start` (ingest), `start:worker`, `migrate`, `enroll`,
`simulate`, `test` (= `node --test`). Dependencies: `pg`, `zod`, `dotenv`. No dev deps.

## Telemetry payload (POST /telemetry body)

Exactly what `agent/vigilant-agent.rsc` emits. The ingest MUST be tolerant: unknown keys
ignored, missing keys → null, and the agent emits some numbers as quoted strings and some
absent values as the literal `null`. `normalize()` in `telemetry.js` coerces.

```jsonc
{
  "serial": "HGT0A023T6C",          // string, REQUIRED — used only to cross-check the token's device
  "identity": "AlliedHuddersfield",
  "uptime": "1w2d3h4m5s",           // ROS uptime string
  "cpu_load": 7,                    // number
  "free_memory": 123456, "total_memory": 268435456, "free_hdd": 100000000,
  "ros_version": "7.15.3",
  "temperature": 41.5, "cpu_temperature": null, "board_temperature": null,
  "voltage": 24.1, "fan1_speed": null,        // number | null
  "write_sect_total": 123456,
  "firmware_current": "7.15.3", "firmware_upgrade": "7.15.3",
  "ntp_synced": true,
  "public_ip": "84.247.33.71",      // bare IP (from /ip cloud) OR "1.2.3.4/24" (pppoe) OR "null"/"" -> null; strip /mask
  "pppoe_running": true, "ppp_sessions": 12, "dhcp_leases": 30,
  "lte": null | {                    // null when no LTE iface
    "interface":"lte1","iccid":"…","imsi":"…","imei":"…","msisdn":"",
    "operator":"23410","registration":"registered","access_tech":"lte",
    "band":"3","cell_id":"…","rssi":"-65","rsrp":"-95","rsrq":"-10","sinr":"12"  // signal as STRINGS -> parse to number|null
  },
  "interfaces": [                    // array, may be large
    { "name":"ether1","type":"ether","running":true,"disabled":false,"plugged":true,
      "speed":"1Gbps","full_duplex":true,"bridge":"","is_wan":true,
      "rx_byte":999,"tx_byte":888,"rx_packet":10,"tx_packet":9 }
  ],
  "neighbors": [ {"interface":"ether3","identity":"phone-1","mac":"AA:BB:…","address":"10.0.0.5","platform":"Yealink"} ],
  "mac_hosts": null | [ {"mac":"AA:BB:…","interface":"ether4"} ],   // null on fast ticks = "keep previous"; only on ~5-min slow tick
  "arp": null | [ {"mac":"AA:BB:…","ip":"10.0.0.9"} ]              // join to mac_hosts by mac
}
```

Free-text fields (`identity`, `neighbors[].identity`, `neighbors[].platform`,
`lte.operator`, interface `comment`) are vendor-supplied. **The agent task must add
sanitisation** (strip `"` `\` and control chars, replacing with space) so the JSON is
always valid; **the ingest must also fail safe** — on `JSON.parse` error return `400` and
log, never crash.

## TELEMETRY RESPONSE (200)

```jsonc
{
  "ok": true,
  "poll_interval_s": 10,            // device obeys this; lowered to FAST_POLL_S when poll_until is in the future
  "agent_version": 3,              // current agent script version; if device's is older, bootstrap re-fetches
  "job": null | {                   // present only if an APPROVED config job is pending for this device
    "id":"uuid","sha256":"…","url":"https://…/config/<id>.rsc","confirm_window_s":300
  }
}
```

## Store interface (`store.js`)

All methods async, return plain objects/arrays/null. `store.pg.js` and `store.mem.js` both
implement this; the e2e test uses mem; production uses pg. `makeStore(kind, config)` →
returns the right one.

```
migrate()                                      // pg: apply db/schema.sql idempotently (split on ; safely)
getDeviceByToken(tokenHash)  -> {id,serial,poll_interval_s,poll_until,agent_version} | null
getDeviceBySerial(serial)    -> device | null
createDevice(fields)         -> device         // {serial,site_name,customer,wan_type,tags,...}
setDeviceToken(deviceId, tokenHash)
getInterfaceStates(deviceId) -> [{name,rx_byte,tx_byte,rx_packet,tx_packet,sampled_at}]   // for delta math
upsertDeviceState(deviceId, state)             // full device_state row (already-derived values)
upsertInterfaceStates(deviceId, rows[])        // each row already has rx_bps/tx_bps/role/is_wan computed
upsertLteState(deviceId, row)
upsertNeighbors(deviceId, rows[])              // also stamps last_seen_at = now()
upsertMacHosts(deviceId, rows[])               // only called when payload.mac_hosts !== null
appendMetricsHistory(deviceId, ts, row)
appendInterfaceHistory(deviceId, ts, rows[])
appendLteHistory(deviceId, ts, row)
setPollWindow(deviceId, pollUntil, intervalS)
getPendingConfigJob(deviceId) -> {id,rsc_sha256,confirm_window_s} | null   // status='approved', matches device or its tag
getConfigJobForFetch(jobId, deviceId) -> {rsc_text, rsc_sha256} | null     // verifies the job targets this device
markConfigJob(jobId, status, fields?)          // fetched_at/applied_at/result_log/rollback_ref by status
recordConfigResult(jobId, status, resultLog, exportText?)                  // + insert config_snapshots(pre/post)
getCurrentAgentScript() -> {version, rsc_text} | null                      // agent_scripts where is_current
getFleet() -> [v_fleet rows]                   // read API
getDeviceDetail(serial) -> {device, state, interfaces[], lte, neighbors[], mac_hosts[]} | null
// worker:
markStaleDevices(staleSeconds, offlineSeconds) -> {stale:n, offline:n}     // bump device_state.status by last_seen_at
getActiveAlertRules() -> rules[]
evaluateAndApplyAlerts(rules) -> {opened:n, cleared:n}    // may live in worker using primitive store reads; see note
downsampleHistory(now) / pruneHistory(now)
pruneNeighbors(now, ttlSeconds) / pruneMacHosts(now, ttlSeconds)
```

> Note: alert evaluation logic is pure where possible (`transform.evaluateAlert(rule,
> stateRow)`); the worker reads state via the store and calls store open/clear helpers. If
> a single `evaluateAndApplyAlerts` is simpler for mem/pg parity, that's acceptable as long
> as the threshold decision itself lives in `transform.js` and is unit-tested.

## `transform.js` — PURE functions (no IO; the heart of the test suite)

```
deltaBps(prevBytes, prevAtMs, curBytes, curAtMs) -> number|null
   // bits/sec. null if prev missing, curAt<=prevAt, or cur<prev (counter reset/wrap guard — no negative spikes).
classifyRole(iface) -> 'disabled'|'wan'|'vpn'|'bridge-member'|'lan'|'unused'
   // precedence: disabled -> 'disabled'; is_wan -> 'wan';
   //   type in {pppoe-out,pppoe-client,l2tp-*,sstp-*,ovpn-*,wireguard,gre,eoip,vlan?} -> 'vpn' (tunnels; vlan stays lan);
   //   bridge set -> 'bridge-member'; type 'ether' & !plugged & no bridge -> 'unused'; else 'lan'.
parseNum(v) -> number|null            // handles "", "null", null, "-65", 42 ; non-numeric -> null
parseIp(v) -> string|null             // strip CIDR /mask; "null"/""/null -> null
joinMacHosts(macHosts[], arp[]) -> [{mac, interface, ip|null}]   // left-join by normalised mac (upper, ':' sep)
normaliseMac(s) -> 'AA:BB:CC:DD:EE:FF' | null
evaluateAlert(rule, value) -> boolean // applies rule.comparator/threshold; 'offline' compares status string
sha256Hex(text) -> string             // node:crypto; used to verify config job checksums
```

## API routes (ingest `server.js` + `handlers.js`)

Auth: `Authorization: Bearer <token>`. Device routes hash the bearer (sha256) and look it
up via `getDeviceByToken`; mismatch → 401. Admin routes (`/enroll`) require
`Bearer ${config.enrollToken}`. `/healthz` is open.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/healthz` | none | "ok" |
| POST | `/telemetry` | device | validate→normalize→derive (bps/role/join)→upsert all→append history→return control+job |
| GET  | `/agent/script?serial=` | device | current agent script text (from `getCurrentAgentScript`, fallback to `agent/vigilant-agent.rsc` file) |
| GET  | `/config/pending?serial=` | device | approved job descriptor or `204` |
| GET  | `/config/:id.rsc` | device | the job's rsc_text (verify job targets this device; checksum in header `X-Vigilant-Sha256`) |
| POST | `/config/result` | device | `{job_id,status,result_log,export?}` → recordConfigResult |
| POST | `/enroll` | admin | `{serial,site_name,customer,wan_type,tags?}` → create device + token → `{token, bootstrap}` |
| GET  | `/fleet` | admin | read API for frontends (Realtime is primary; this is convenience) |
| GET  | `/devices/:serial` | admin | device detail |

POST /telemetry algorithm (in `handlers.telemetry`):
1. auth → device. 2. parse JSON (fail→400). 3. `telemetry.normalize(raw)`. 4. cross-check
`payload.serial === device.serial` (mismatch→409, log). 5. `getInterfaceStates` →
`deltaBps` per port (match by name, Δt from sampled_at) + `classifyRole`. 6. parse lte
signal strings → numbers. 7. if `mac_hosts`!=null → `joinMacHosts` + `ouiVendor`. 8. one
logical transaction: upsert device_state, interface_state, lte_state, neighbors,
(mac_hosts), append *_history. 9. compute poll_interval_s from device.poll_until. 10.
`getPendingConfigJob`. 11. respond.

### Chunked telemetry (partial upserts)

RouterOS `/tool fetch` caps the size of the `http-data` argument a script can hand the fetch
subsystem (the script→tool message bus has a low-tens-of-KiB ceiling, surfacing as
`maximum message size exceeded`). A multi-interface router's full rich body (per-interface
counters for every bridge/VLAN/pppoe/lte/wifi + neighbours + mac_hosts) overflows it, so the
POST is rejected before a byte leaves the box. This is an **undocumented platform constraint**
— keep every `/tool fetch` body in the single-KB range.

To stay under the cap the agent MAY split one tick across several smaller POSTs to `/telemetry`.
Every POST is an **idempotent partial upsert** of whatever it carries — a chunk must NEVER wipe
data it does not carry:

- **CORE chunk** — carries the system block (`cpu_load`/`uptime`/`free_memory`/`lte`/… any of
  the device_state fields). This is the ONLY chunk that writes `device_state` (status `online` +
  metrics-history row + `lte_signal` mirror), and where the agent reads back the control fields
  (`poll_interval_s`/`agent_version`/`job`/`confirm`). It carries no interfaces.
- **DETAIL chunk** — carries only interfaces (in small batches) / neighbors / mac_hosts / arp,
  and SHOULD set `"partial": true`. It does NOT overwrite the system columns; the server only
  bumps `last_seen_at` (`store.touchDeviceState`) so the device stays `online` between core
  ticks. Per-interface `bps` is matched by name against the prior sample, so it is computed
  correctly across chunked calls regardless of which chunk a port rode in. An interface/neighbor
  not present in a chunk is left untouched (upsert, never replace). `mac_hosts:null` still means
  "keep previous".

Detection: the server treats a payload as a DETAIL chunk when it carries no system field
(`telemetry.normalize` → `has_core:false`) OR when `partial:true` is set; otherwise it is a CORE
sample and the existing full-payload path runs byte-for-byte unchanged. A single full payload
(system block + interfaces + neighbors in one body) keeps the original behaviour exactly.

## Env (`config.js` + `.env.example`)

```
VIGILANT_DB_URL=postgresql://vigilant:CHANGEME@10.10.30.10:5432/postgres   # ?options=-csearch_path=vigilant or set in db.js
PORT=9100
ENROLL_TOKEN=<admin bearer for /enroll>
AGENT_SCRIPT_PATH=./agent/vigilant-agent.rsc      # fallback when agent_scripts table empty
PUBLIC_BASE_URL=https://vigilant.western-communication.com   # for building config job URLs
FAST_POLL_S=3
DEFAULT_POLL_S=10
STALE_AFTER_S=45         # 3 missed 10s ticks -> stale
OFFLINE_AFTER_S=120
HISTORY_RAW_RETENTION_H=24
NEIGHBOR_TTL_S=86400
STORE_KIND=pg            # 'pg' | 'mem'
```

## Tests (must pass under `node --test`, NO external Postgres)

- `transform.test.js` — deltaBps (normal, reset cur<prev → null, zero/negative Δt → null,
  missing prev → null); classifyRole all branches; parseNum/parseIp edge cases;
  normaliseMac; joinMacHosts (match, no-arp-match→ip null); evaluateAlert; sha256Hex known
  vector.
- `telemetry.test.js` — normalize() accepts the full sample above, coerces string signals
  to numbers, maps `"null"`/`""` public_ip to null, strips CIDR, tolerates extra keys,
  rejects missing `serial`.
- `oui.test.js` — known OUI → vendor; unknown → null; case/sep-insensitive.
- `config.test.js` — pending job served only when approved+targeted; checksum match;
  result transitions status; rollback path fields.
- `ingest.e2e.test.js` — `createServer({store: memStore, config})`; POST a payload twice;
  assert: device_state upserted, interface bps == 0 on first POST (no prev) and a correct
  positive number on the second POST (bytes advanced over known Δt), neighbors stored,
  mac_hosts only stored when provided, and the response shape matches. Use the generator
  from `simulate.js` (export it) so the simulator and the test share one payload factory.

Verification gate: `npm install` succeeds, `node --test` is green, `node -e
"require('./src/ingest/server.js')"` and the worker load without throwing.

## Worker (`worker/worker.js`)

`runOnce({store,config,now})` does, in order: `markStaleDevices` → evaluate alert rules →
`downsampleHistory`/`pruneHistory` → `pruneNeighbors`/`pruneMacHosts`. `runWorker` calls
`runOnce` on an interval (default 30s). `runOnce` is exported and unit-tested against
memStore. Nightly config snapshot: worker flags devices whose last snapshot is >24h and
enqueues a read-only `/export` job (kind='snippet', a no-op export request) — keep this
behind a config flag `ENABLE_NIGHTLY_SNAPSHOT` default false for v1.

## Non-negotiables

- **Never log secrets** (tokens, db password). Hash tokens before compare/store.
- **Config push stays review-gated**: ingest only ever serves `status='approved'` jobs,
  only to the targeted device, only after checksum verify. No auto-apply server-side.
- **Fail safe on bad input** — a malformed payload from one device must not 500 the service
  or affect others.
- Match `provisioner/server.js` conventions (CJS, stdlib http, small modules).
