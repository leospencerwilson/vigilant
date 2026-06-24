# Vigilant — architecture & design

> Realtime MikroTik telemetry + safe config-push engine for the WCN estate.
> Lives on the WCN Cloud IaaS, backed by self-hosted Supabase.
> **Watchman** (the existing web UI) and the WCN Cloud **console** are *frontends* that
> consume Vigilant — Vigilant itself is the collector, ingest API, datastore, and
> config-push orchestrator.

Status: **design / scaffold**. Nothing here is deployed. All RouterOS artifacts are
DRAFTs and must be reviewed before they touch a live router (see `../CLAUDE.md` of the
parent workspace and `server project/CLAUDE.md` — the WCN MikroTik estate is live
production).

---

## 1. Why this exists

Today a RouterOS scheduler script on each router hand-builds a JSON blob and `POST`s it
to `https://84.247.33.71:8443/api/metrics` with a static `X-API-Key`, **once every 6
minutes**. Problems with that:

- **Too slow for alerting.** A circuit can be down for ~6 min before anything notices.
- **No throughput data.** It sends interface *running* booleans — not rx/tx rates, not
  byte counters, not errors/drops. You cannot draw a port-utilisation graph from it.
- **Thin payload.** No CPU/memory/temperature/voltage, no PPP session list, no wireless
  registration table, no DHCP leases, no firewall connection count.
- **Hard to evolve.** Adding a metric means editing the scheduler script on every one of
  ~250 routers.
- **Leaks secrets.** The current payload includes the **PPPoE password** in clear text,
  and the same `X-API-Key` is baked into every router's config. (Fix both — see §7.)
- **No config path.** There is no way to push a config change back down; everything is
  manual Winbox/SSH per site.

Vigilant replaces this with a fast, rich, two-way channel.

## 2. Constraints that shape the design

1. **Devices dial home — we cannot reliably reach them inbound.** Some sites are on
   4G/SIM (CGNAT), some on dynamic-IP PPPoE. So **central polling is off the table** for
   a chunk of the estate. Everything device-side is *device-initiated*: the router pushes
   telemetry out, and the router *pulls* its pending config jobs. This is the one
   non-negotiable architectural fact.
2. **The routers are live production** carrying SSTP/L2TP for ~250 Allied/Cegedim/WCN
   sites + HSCN. Config push is **review-gated**, applied under **Safe Mode**, with an
   automatic dead-man's-switch rollback. Never auto-apply.
3. **Vigilant runs on the IaaS** (the Coolify + self-hosted Supabase VM, `10.10.30.10`,
   deployed via Coolify alongside the console). Public reachability for device ingest is
   via the existing Cloudflare Tunnel / ingress, not a raw `:8443` with a self-signed
   cert.
4. **Reuse the IaaS stack:** Next.js 16, `@supabase/ssr`, `pg`, self-hosted Supabase,
   Coolify deploys. Don't invent a new toolchain.

## 3. Shape of the system

```
   ~250 MikroTiks (live)                Vigilant (on the IaaS)                 Frontends
 ┌────────────────────────┐      ┌──────────────────────────────────┐   ┌────────────────┐
 │ bootstrap scheduler     │      │  Ingest API  (Next.js route or   │   │  Watchman UI   │
 │  └ fetches current      │ ───▶ │   small Node svc behind CF       │   │  (existing)    │
 │    agent script daily   │ push │   Tunnel)                        │   │                │
 │ agent script (every Ns):│ tele │   • auth: per-device bearer      │   │  WCN console   │
 │  • system/health        │ metry│   • validates, computes bps      │   │  (existing)    │
 │  • per-iface counters   │      │     deltas, writes Supabase      │   └───────┬────────┘
 │  • ppp / wifi / dhcp    │      │                                  │           │ Supabase
 │  • checks for config job│ ◀─── │  Supabase Postgres + Realtime    │ ◀─────────┘ Realtime
 │  • applies under SafeMode│ pull │   • device_state / interfaces    │   (browser subscribes,
 │    + dead-man rollback   │ job  │   • *_history (graphs)           │    no polling)
 └────────────────────────┘      │   • config_jobs / snapshots      │
                                  │   • alerts / alert_rules         │
                                  │  Collector worker (cron):        │
                                  │   • staleness → offline alerts   │
                                  │   • threshold rules → alerts     │
                                  │   • history downsample/retention │
                                  └──────────────────────────────────┘
```

Three deployable pieces, one repo:

| Piece | What | Where |
|---|---|---|
| **Ingest API** | Receives device telemetry, authenticates per-device, computes throughput from counter deltas, upserts live state + appends history. Serves the device its pending config job and accepts job results. | Next.js route handlers (or a tiny standalone Node svc like `provisioner/`) on the IaaS, public via Cloudflare Tunnel. |
| **Collector worker** | Background cron: marks devices stale/offline when telemetry stops, evaluates alert rules, downsamples + prunes history, requests nightly config snapshots. | Node worker on the IaaS (Coolify scheduled service / systemd timer). |
| **Data + Realtime** | Supabase Postgres schema (`db/schema.sql`) + Supabase Realtime publication so Watchman/console get live pushes. | Self-hosted Supabase on the IaaS. |

The **frontend is not in this repo** — Watchman already exists and the console already
exists. Vigilant exposes (a) Supabase tables/Realtime channels they subscribe to, and
(b) a small REST surface for actions (create/approve config job, ack alert).

## 4. Collection model (device push)

### 4.1 Bootstrap + agent split (solves "edit 250 routers")

Each router runs **two** scheduler entries:

- **`vigilant-bootstrap`** (daily): `/tool fetch` the current agent script from Vigilant
  (`GET /agent/script?serial=…`, authenticated), verify it, and replace the local
  `vigilant-agent` script. This means **you change what's collected in one place** —
  update the script in Vigilant, and routers self-update within a day. (Optionally the
  agent can hot-pull a new version if Vigilant signals one in the telemetry response.)
- **`vigilant-agent`** (every *N* seconds, default 10s): collect, push telemetry, then
  check for and apply a pending config job.

### 4.2 What the agent collects each tick

- **System / health:** uptime, CPU load, free/total memory, free HDD, board temperature,
  voltage, ROS version, firmware, identity, serial.
- **Per-interface (the big win):** for every interface — `rx-byte`/`tx-byte` (cumulative
  64-bit counters), `rx-packet`/`tx-packet`, `rx-error`/`tx-error`, `rx-drop`/`tx-drop`,
  running, link speed, MAC, type, comment. **The agent sends cumulative counters; the
  ingest computes bps.** (Don't compute rates on the router — counters are robust across
  reboots and let us re-derive rate if a sample is missed.)
- **WAN:** PPPoE up/down, public IP (no password — see §7), default-route present, LTE
  signal/RSRP where SIM present.
- **PPP:** active session count + list (relevant to the SSTP/L2TP concentrator role).
- **Wireless:** registration table — per-client signal, CCQ, tx/rx rate, uptime. (Directly
  useful to the Yealink AX83H / DFS stabilisation project.)
- **DHCP:** active lease count. **Firewall:** connection-tracking count.

A device sends one JSON document per tick. The ingest is schema-tolerant (unknown fields
ignored, missing fields null) so the agent script can grow without breaking ingest.

### 4.3 Cadence & "instant" feel

- Overview grid: every device pushes on its `poll_interval_s` (default **10s**).
- Drilldown: when an operator opens a device in Watchman, the UI flips that device's
  `poll_interval_s` down (e.g. **3–5s**) via a control row the agent reads back in the
  telemetry response; it reverts after a TTL. So the device you're staring at is
  near-instant, without hammering all 250 at 3s.
- The browser never polls Vigilant — it subscribes to **Supabase Realtime** on
  `device_state` and `interface_state`, so writes appear as live pushes.

### 4.4 Throughput math (server-side)

On each interface row the ingest keeps `rx_byte`/`tx_byte` + `sampled_at`. On the next
sample: `bps = (Δbytes * 8) / Δseconds`. Guard against counter reset (reboot/wrap): if
`new < old`, treat as reset and emit null for that tick rather than a negative spike.

## 5. Config push (review-gated, Safe Mode, dead-man rollback)

Because devices aren't reachable inbound, push is really **device-pull of an approved
job**:

1. **Author** in Watchman: upload a `.rsc` snippet (or full config) and target one device,
   a group/tag, or "canary then all". Stored in `config_jobs` as `status='draft'`.
2. **Approve:** a second person (or the same, per policy) sets `status='approved'`. Until
   then it is never served. (Audit who authored / who approved.)
3. **Pickup:** on its next agent tick the target device sees the job in its telemetry
   response (or a dedicated `GET /config/pending?serial=…`), `/tool fetch`es the `.rsc`,
   and Vigilant marks it `fetched`.
4. **Apply safely** on the device:
   - take `/export` + `/system backup` first (stored back to Vigilant as a rollback point);
   - arm a **dead-man's switch**: schedule a rollback (`/system reset` to backup, or
     re-import the pre-snapshot) in *T* minutes;
   - `/import` the new `.rsc` (equivalent of running under **Safe Mode** — if the session
     drops or import errors, changes revert);
   - the device then re-checks in. If it checks in healthy and the operator *confirms* in
     Watchman within *T*, Vigilant tells it to cancel the rollback timer (`status='applied'`).
     If it doesn't, the dead-man's switch fires and the device self-recovers
     (`status='rolled_back'`).
5. **Report:** apply log + final `/export` diff stored in `config_jobs.result_log` and a
   new row in `config_snapshots`.

Staged rollout: a job can target `canary` (1 device) and only auto-promote to the rest of
its group after the canary reports `applied` + healthy for *T* minutes.

Bonus that falls out of this: **nightly config snapshots** (`/export` pushed up) give you
free per-device config history + diffing + drift detection.

## 6. Data model (Supabase)

Full DDL in `db/schema.sql`. Summary:

| Table | Grain | Purpose | Realtime? |
|---|---|---|---|
| `devices` | 1 / router | Registry: serial (natural key), identity, site, model, ROS ver, WAN type, tags, enrolment, `poll_interval_s`, `expected`. | — |
| `device_state` | 1 / router (upsert) | Latest snapshot: uptime, cpu, mem, temp, voltage, public_ip, ppp count, status (online/stale/offline), `last_seen_at`. Drives grid tiles. | ✅ |
| `interface_state` | 1 / router·iface (upsert) | Latest per port: `rx_bps`/`tx_bps`, cumulative bytes, errors/drops, running, speed. Drives port view. | ✅ |
| `metrics_history` | append, downsampled | Time-series for device-level graphs (cpu/mem/temp). Retention + rollup. | — |
| `interface_history` | append, downsampled | Time-series for throughput graphs. Retention + rollup. | — |
| `wireless_clients` | 1 / router·iface·mac | Wi-Fi registration table (signal, CCQ, rates). Feeds Yealink work. | optional |
| `config_jobs` | 1 / job | Config push lifecycle (draft→approved→fetched→applying→applied/failed/rolled_back). | ✅ |
| `config_snapshots` | append | `/export` history per device for diff/rollback/drift. | — |
| `alerts` / `alert_rules` | — | Open/cleared alerts + threshold definitions. | ✅ (alerts) |
| `enrollment_tokens` | 1 / device | Per-device bearer for ingest auth (replaces the shared `X-API-Key`). | — |
| `agent_scripts` | versioned | The centrally-managed agent script the bootstrap fetches. | — |
| `audit_log` | append | Who did what (mirrors the ops-DB pattern). | — |

Write-volume note for "all sites, instant": at 10s × ~250 devices that's ~25 device
upserts/s plus per-port rows. `device_state`/`interface_state` are **upserts** (bounded
row count — they don't grow), so the live panel stays cheap. Growth is only in the
`*_history` tables, which the collector downsamples (e.g. raw for 24h → 1-min for 7d →
5-min for 90d) and prunes. Consider a separate Supabase schema (`vigilant`) and, if
volume bites, partition history by day.

## 7. Security (fix what the current script does wrong)

- **Per-device enrolment token**, not a shared key. Each router authenticates ingest with
  its own bearer (`enrollment_tokens`), revocable per device. Enrol once during onboarding.
- **Never put secrets in telemetry.** Drop the PPPoE password the current payload sends.
  If credential inventory is genuinely needed, it belongs in the ops DB, set during
  provisioning — not pushed every 6 minutes from the field.
- **TLS to a real hostname** via Cloudflare Tunnel/ingress, not `https://<ip>:8443` with a
  self-signed cert and `check-certificate=no` on the router.
- **Config jobs are signed/approved** and target by serial; a device only ever fetches a
  job addressed to its own serial and verifies a checksum before importing.
- **Least privilege:** ingest uses a scoped Postgres role / Supabase service path, not the
  console's keys. Don't reuse `SUPABASE_SERVICE_ROLE_KEY` in the field.

## 8. Repo layout

```
vigilant/
├── docs/
│   └── ARCHITECTURE.md        ← this file
├── db/
│   └── schema.sql             ← Supabase schema (devices, *_state, *_history, config_jobs, …)
├── agent/
│   ├── bootstrap.rsc          ← DRAFT: daily self-update scheduler for the router
│   └── vigilant-agent.rsc     ← DRAFT: the collector + config-apply agent
├── README.md
└── (later) ingest/ , worker/  ← Next.js route handlers / Node worker, when we build them
```

## 9. Build order (suggested)

1. **Schema** into a `vigilant` schema on the IaaS Supabase; enable Realtime on
   `device_state`, `interface_state`, `config_jobs`, `alerts`.
2. **Ingest API** (`POST /telemetry`) — auth, delta→bps, upsert state, append history.
   Stand it up behind the Cloudflare Tunnel.
3. **Rewrite the agent** (`agent/vigilant-agent.rsc`) to push the rich snapshot; pilot on
   **one** lab/non-critical router first (Safe Mode, reviewed).
4. **Realtime panel** — point Watchman at the new tables/channels.
5. **Collector worker** — staleness/offline + threshold alerts + history rollup.
6. **Config push** — `config_jobs` lifecycle + agent apply path; canary-first; nightly
   snapshots.
7. **Enrolment & secrets** — per-device tokens, retire the shared `X-API-Key`, stop
   sending the PPPoE password.

## 10. Open questions / decisions still to make

- **Ingest host:** Next.js route handler inside the console app, or a standalone Node
  service mirroring `provisioner/server.js`? (Standalone keeps device traffic off the
  console; route handler is less to operate.) — *recommend standalone svc.*
- **History store:** plain Postgres partitions vs. adding TimescaleDB/Influx. Start with
  partitioned Postgres; revisit only if write volume hurts.
- **Confirm-to-keep window** *T* for the dead-man's switch (suggest 5 min).
- **Who can approve config jobs** (single-operator vs two-person rule).
```
