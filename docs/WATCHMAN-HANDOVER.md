# Watchman ↔ Vigilant — frontend handover

One self-contained brief for building the **Watchman** UI (Vite SPA on Vercel, public)
against the **Vigilant** backend. Covers: architecture & auth, the live/read path (Supabase
direct), the REST API + full schema/types, the Vercel proxy for admin actions, and
device-specific gotchas (Chateau AC/AX WiFi, blank temperature).

Verified against `src/ingest/server.js`, `src/ingest/handlers.js`, `src/shared/store.mem.js`,
`db/schema.sql`, and `agent/vigilant-agent.rsc`.

- **Vigilant API base URL:** `https://vigilant.internal.western-communication.com`
  (externally reachable — the `internal` is just part of the subdomain name).
- **Supabase:** public hostname (same self-hosted instance Vigilant writes to). Vigilant's
  tables live in the **`vigilant` schema**, not `public`.

---

## 1. Architecture & auth

A RouterOS agent pushes telemetry → Vigilant's ingest writes it into Supabase
(`vigilant` schema) → Watchman renders it. Watchman uses **two data paths**:

| Watchman needs | Path | Auth |
|---|---|---|
| Live/read views — fleet grid, drilldown, alerts, config-job status, charts | **Supabase directly** from the SPA (Realtime + `.select()`) | the logged-in user's Supabase session (RLS) |
| **Actions** — author/approve/cancel config-push, request speedtest, OUI lookup | **Vercel Function proxy** → Vigilant ingest | proxy swaps the user's JWT for Vigilant's admin bearer, server-side |

Why the split: Vigilant's admin endpoints are guarded by a single bearer (`ENROLL_TOKEN`)
that **must never ship in a Vite bundle** (every `VITE_` var is public). Live/read data
doesn't need it — the browser reads Supabase under the user's own auth. Only the action
endpoints (which do server-side validation: two-person rule, sha256, audit log) must go
through the ingest API, so those are proxied.

```
                 ┌─ live/read ─▶ Supabase (public)  ◀── ingest writes here
browser (SPA) ───┤
                 └─ actions ───▶ /api/vigilant/*  (Vercel Fn) ──▶ Vigilant ingest (admin bearer)
```

---

## 2. Environment variables

### Browser (Vite — public, baked into the bundle; `VITE_` prefix)
```sh
VITE_SUPABASE_URL=https://<supabase-host>
VITE_SUPABASE_ANON_KEY=<anon key>     # public by design; RLS guards the data
```

### Vercel Functions (server-side only — NO `VITE_` prefix)
```sh
VIGILANT_API_URL=https://vigilant.internal.western-communication.com
VIGILANT_ADMIN_TOKEN=<ENROLL_TOKEN>   # Vigilant's admin bearer
SUPABASE_URL=https://<supabase-host>  # to verify the caller's JWT
SUPABASE_ANON_KEY=<anon key>
# Optional — only if Vigilant's hostname is behind Cloudflare Access:
CF_ACCESS_CLIENT_ID=<service-token id>
CF_ACCESS_CLIENT_SECRET=<service-token secret>
```

On Vercel: Framework Preset = **Vite**, build `npm run build`, output `dist`. SPA rewrite
that does **not** swallow `/api/*` (`vercel.json`):
```json
{ "rewrites": [{ "source": "/((?!api/).*)", "destination": "/index.html" }] }
```

> Hand the secrets (`ENROLL_TOKEN`, Supabase keys) over a secure channel — never in the repo.
> To check whether the API host is Access-gated: `curl -s https://vigilant.internal.western-communication.com/healthz`
> from off-VPN. `ok` → bearer alone is enough; only works on VPN → set the `CF_ACCESS_*` vars.

---

## 3. Live / read path — Supabase directly

### 3.1 Realtime tables (in the `vigilant` schema)

| Table | Grain | Drives |
|---|---|---|
| `device_state` | 1 row / device (upsert) | Overview grid: status, cpu, temp, public_ip, ppp_sessions, last_seen_at |
| `interface_state` | 1 row / device·port | Port view: `rx_bps`/`tx_bps` (server-derived), role, link |
| `lte_state` | 1 row / device·lte iface | SIM/signal panel |
| `neighbors` | 1 row / device·iface·mac | "What's plugged into each port" (LLDP/CDP/MNDP) |
| `config_jobs` | 1 row / job | Config-push timeline (status transitions) |
| `alerts` | 1 row / alert | Alert banner/list |

Not Realtime (query on demand): `metrics_history`, `interface_history`, `lte_history`
(charts), `mac_hosts` (large). `wireless_clients` exists but is **not populated** — see §6.

### 3.2 Client (singleton, pinned to the `vigilant` schema)
```ts
// src/lib/vigilant/client.ts
import { createClient } from "@supabase/supabase-js";
export const vigilant = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
  { db: { schema: "vigilant" } }
);
```

### 3.3 First paint (direct query) + live (subscribe)
```ts
import { vigilant } from "@/lib/vigilant/client";

// Fleet grid — the v_fleet view (device + state + open-alert count)
const { data: fleet } = await vigilant.from("v_fleet").select("*");

// One device's drilldown
async function loadDevice(deviceId: string) {
  const [state, interfaces, lte, neighbors] = await Promise.all([
    vigilant.from("device_state").select("*").eq("device_id", deviceId).maybeSingle(),
    vigilant.from("interface_state").select("*").eq("device_id", deviceId).order("name"),
    vigilant.from("lte_state").select("*").eq("device_id", deviceId),       // 0..n rows
    vigilant.from("neighbors").select("*").eq("device_id", deviceId),
  ]);
  return { state: state.data, interfaces: interfaces.data ?? [],
           lte: lte.data ?? [], neighbors: neighbors.data ?? [] };
}

// resolve a /device/:serial route → id
const { data: dev } = await vigilant
  .from("devices").select("id, serial, site_name, tags").eq("serial", serial).maybeSingle();
```

```ts
// Live overview grid
const channel = vigilant
  .channel("vigilant:device_state")
  .on("postgres_changes",
    { event: "*", schema: "vigilant", table: "device_state" },
    (payload) => applyDeviceState(payload.new))   // upserted DeviceState row
  .subscribe();

// Drilldown — one device's ports only
const portChannel = vigilant
  .channel(`vigilant:interface_state:${deviceId}`)
  .on("postgres_changes",
    { event: "*", schema: "vigilant", table: "interface_state", filter: `device_id=eq.${deviceId}` },
    (payload) => applyInterfaceState(payload.new))
  .subscribe();

// cleanup
vigilant.removeChannel(channel);
```
Same pattern for `lte_state`, `neighbors`, `config_jobs`, `alerts`.

> **RLS / grants required.** These tables are in a non-`public` schema. The role Watchman's
> users authenticate as needs `SELECT` grants + RLS policies on `v_fleet`, `devices`, and the
> six Realtime tables — without them both queries *and* subscriptions silently return nothing.
> If a subscription is silent, also confirm the table is in the `supabase_realtime`
> publication (re-run `npm run migrate`).

### 3.4 Recommended wiring
| View | Initial fetch | Live source |
|---|---|---|
| Overview grid | `from("v_fleet")` | `device_state` (+ `alerts` for badges) |
| Device drilldown | `device_state`/`interface_state`/`lte_state`/`neighbors` by `device_id` | same, filtered `device_id=eq.<id>` |
| Config-push timeline | `from("config_jobs")` | `config_jobs` |
| Alerts | `from("alerts").eq("state","open")` | `alerts` |
| Charts | `GET /devices/:serial/history` (via proxy) or query `*_history` | not Realtime |

---

## 4. REST API & schema (admin endpoints, via the proxy)

Base: `VIGILANT_API_URL`. All require `Authorization: Bearer <ENROLL_TOKEN>` — so call them
through the proxy (§5), never from the browser directly. JSON in/out. Non-2xx →
`{ ok:false, error }`. Unknown serial/job → `404`.

> Live/read views should prefer Supabase (§3). Use these for actions and (optionally)
> server-assembled reads like the pre-joined drilldown and history charts.

### `GET /fleet` → `{ devices: FleetDevice[] }`  *(note the envelope — not a bare array)*

### `GET /devices/:serial` → `DeviceDetail`
`{ device, state|null, interfaces[], lte[], neighbors[], mac_hosts[] }`.
`lte` is an **array** (one per LTE iface, `[]` if no SIM); `state` is `null` if never reported.

### `GET /devices/:serial/history?window=1h|6h|24h|7d` → `DeviceHistory`
`{ serial, window, metrics[], interfaces:[{name, points[]}] }`. Unknown window → `1h`.

### Config-push (review-gated; status `draft→approved→fetched→applying→applied|failed|rolled_back|cancelled`)
| Method & path | Body | Success |
|---|---|---|
| `GET /devices/:serial/config-jobs` | — | `{ ok, serial, jobs: ConfigJob[] }` (newest first, ≤50) |
| `POST /devices/:serial/config-jobs` | `{ rsc_text, created_by, kind?:"snippet"\|"full", confirm_window_s?, is_canary? }` | `201 { ok, job }` (status `draft`) |
| `POST /config-jobs/:id/approve` | `{ approved_by }` | `{ ok, job }` — `409` if not draft or approver==author |
| `POST /config-jobs/:id/cancel` | `{ actor? }` | `{ ok, job }` — only draft/approved cancellable |

`confirm_window_s` floored to 30, default 300. The device only ever *pulls* an approved job
on its own tick — none of these touch a router. **UI must render this lifecycle and gate
approve/apply as deliberate, audited actions — never one-click auto-apply** (the MikroTik
estate is live production).

### Active speedtest (operator-gated; saturates the WAN)
| Method & path | Body | Success |
|---|---|---|
| `GET /devices/:serial/speedtests` | — | `{ ok, serial, jobs: SpeedtestJob[] }` (≤20) |
| `POST /devices/:serial/speedtests` | `{ requested_by, bytes_down?, bytes_up? }` | `201 { ok, job }` (status `pending`) |
Bytes capped server-side (≤64 MiB/leg; down default 25 MiB, up 8 MiB). Poll the list (or
watch `speedtest_jobs`) for `down_bps`/`up_bps` to fill in.

### `GET /oui/:mac` → `{ mac, oui, vendor|null, source }`  (invalid MAC → 400)

### Not for the dashboard (listed so they aren't wired by mistake)
`POST /enroll`, `POST /admin/migrate` (admin lifecycle); `GET /healthz` (open). All
`/telemetry`, `/agent/script`, `/config/*`, `/speedtest/{pending,down,up,result}` routes are
**device** routes (per-device bearer) — the frontend never calls them.

### TypeScript types
```ts
export type DeviceStatus = "online" | "stale" | "offline" | "unknown";
export type WanType = "pppoe" | "sim" | "dhcp" | "static" | "unknown";

export interface FleetResponse { devices: FleetDevice[]; }
export interface FleetDevice {
  id: string; serial: string; identity: string | null;
  site_name: string | null; customer: string | null; model: string | null;
  wan_type: WanType; tags: string[];
  status: DeviceStatus | null; cpu_load: number | null; temperature: number | null;
  public_ip: string | null; ppp_sessions: number | null;
  last_seen_at: string | null; open_alerts: number;
}

export interface Device {
  id: string; serial: string; identity: string | null;
  site_name: string | null; customer: string | null; model: string | null;
  ros_version: string | null; wan_type: WanType; tags: string[];
  expected: boolean; poll_interval_s: number; poll_until: string | null;
  agent_version: string | null; enrolled_at: string; notes: string | null;
}

export interface DeviceState {
  device_id: string; status: DeviceStatus;
  uptime_s: number | null; cpu_load: number | null;
  free_memory: number | null; total_memory: number | null; free_hdd: number | null;
  temperature: number | null;      // often null on Chateau — see §6
  voltage: number | null; public_ip: string | null;
  ros_version: string | null; firmware: string | null;
  default_route: boolean | null; pppoe_running: boolean | null;
  ppp_sessions: number | null; dhcp_leases: number | null; conn_count: number | null;
  lte_signal: number | null;       // RSRP/dBm
  cpu_temperature: number | null; board_temperature: number | null;
  fan1_speed: number | null; fan2_speed: number | null;
  firmware_current: string | null; firmware_upgrade: string | null;
  ntp_synced: boolean | null; netwatch_down: number | null;
  last_seen_at: string; raw?: unknown;
}

export interface InterfaceState {
  device_id?: string; name: string; type: string | null; comment: string | null;
  plugged: boolean | null; running: boolean | null; disabled: boolean | null;
  speed: string | null; full_duplex: boolean | null;
  last_link_up_at: string | null; last_link_down_at: string | null; link_downs: number | null;
  role: "wan"|"lan"|"bridge-member"|"trunk"|"vpn"|"unused"|"disabled"|null;
  is_wan: boolean; bridge: string | null;
  poe_out_status: string | null; poe_out_power: number | null; mac: string | null;
  rx_bps: number | null; tx_bps: number | null;     // derived
  rx_byte: number | null; tx_byte: number | null;
  rx_packet: number | null; tx_packet: number | null;
  sampled_at: string;
}

export interface LteState {
  device_id?: string; interface: string;
  iccid: string|null; imsi: string|null; imei: string|null; msisdn: string|null;
  operator: string|null; apn: string|null;
  registration: string|null; access_tech: string|null; band: string|null; earfcn: string|null;
  cell_id: string|null; phy_cellid: string|null;
  rssi: number|null; rsrp: number|null; rsrq: number|null; sinr: number|null; cqi: number|null;
  session_uptime_s: number|null; sampled_at: string;
}

export interface Neighbor {
  device_id?: string; interface: string; mac: string;
  identity: string|null; address: string|null; platform: string|null;
  board: string|null; version: string|null; last_seen_at: string;
}

export interface MacHost { interface: string; mac: string; ip: string|null; vendor: string|null; }

export interface DeviceDetail {
  device: Device; state: DeviceState | null;
  interfaces: InterfaceState[]; lte: LteState[];
  neighbors: Neighbor[]; mac_hosts: MacHost[];
}

export type HistoryWindow = "1h" | "6h" | "24h" | "7d";
export interface DeviceHistory {
  serial: string; window: HistoryWindow;
  metrics: Array<{ ts: string; cpu_load: number|null; free_memory: number|null; temperature: number|null; ppp_sessions: number|null }>;
  interfaces: Array<{ name: string; points: Array<{ ts: string; rx_bps: number|null; tx_bps: number|null }> }>;
}

export type ConfigJobStatus = "draft"|"approved"|"fetched"|"applying"|"applied"|"failed"|"rolled_back"|"cancelled";
export interface ConfigJob {
  id: string; device_id: string|null; target_tag: string|null; is_canary: boolean;
  kind: "snippet"|"full"; rsc_text: string; rsc_sha256: string; status: ConfigJobStatus;
  confirm_window_s: number; created_by: string; approved_by: string|null;
  created_at: string; approved_at: string|null; fetched_at: string|null;
  applied_at: string|null; result_log: string|null;
}
export interface ConfigJobsResponse { ok: true; serial: string; jobs: ConfigJob[]; }

export type SpeedtestStatus = "pending"|"running"|"done"|"failed";
export interface SpeedtestJob {
  id: string; device_id: string|null; status: SpeedtestStatus;
  bytes_down: number; bytes_up: number; down_bps: number|null; up_bps: number|null;
  requested_by: string; result_log: string|null;
  created_at: string; started_at: string|null; finished_at: string|null;
}
export interface SpeedtestsResponse { ok: true; serial: string; jobs: SpeedtestJob[]; }

export type AlertSeverity = "info"|"warning"|"critical";
export type AlertState = "open"|"acked"|"cleared";
export interface Alert {
  id: number; device_id: string; rule_id: number|null;
  severity: AlertSeverity; state: AlertState; detail: string|null;
  opened_at: string; acked_at: string|null; acked_by: string|null; cleared_at: string|null;
}

export interface OuiResult { mac: string; oui: string; vendor: string|null; source: "seed"|"cache"|"api"|"none"; }
export interface ApiError { ok: false; error: string; [k: string]: unknown; }
```

### Typed client (points at the proxy; bearer = user's Supabase token)
```ts
// src/lib/vigilant/api.ts
export function createVigilantApi(baseUrl: string, token?: string) {
  async function call<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(`${baseUrl}${path}`, {
      ...init,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
    if (!res.ok) {
      const b = await res.json().catch(() => ({}));
      throw new Error(`Vigilant ${init?.method ?? "GET"} ${path} → ${res.status}: ${(b as any).error ?? res.statusText}`);
    }
    return res.json() as Promise<T>;
  }
  return {
    fleet: () => call<FleetResponse>("/fleet"),
    device: (s: string) => call<DeviceDetail>(`/devices/${encodeURIComponent(s)}`),
    history: (s: string, w: HistoryWindow = "1h") => call<DeviceHistory>(`/devices/${encodeURIComponent(s)}/history?window=${w}`),
    listConfigJobs: (s: string) => call<ConfigJobsResponse>(`/devices/${encodeURIComponent(s)}/config-jobs`),
    createConfigJob: (s: string, b: { rsc_text: string; created_by: string; kind?: "snippet"|"full"; confirm_window_s?: number; is_canary?: boolean }) =>
      call<{ ok: true; job: ConfigJob }>(`/devices/${encodeURIComponent(s)}/config-jobs`, { method: "POST", body: JSON.stringify(b) }),
    approveConfigJob: (id: string, approved_by: string) =>
      call<{ ok: true; job: ConfigJob }>(`/config-jobs/${id}/approve`, { method: "POST", body: JSON.stringify({ approved_by }) }),
    cancelConfigJob: (id: string, actor?: string) =>
      call<{ ok: true; job: ConfigJob }>(`/config-jobs/${id}/cancel`, { method: "POST", body: JSON.stringify({ actor }) }),
    listSpeedtests: (s: string) => call<SpeedtestsResponse>(`/devices/${encodeURIComponent(s)}/speedtests`),
    requestSpeedtest: (s: string, b: { requested_by: string; bytes_down?: number; bytes_up?: number }) =>
      call<{ ok: true; job: SpeedtestJob }>(`/devices/${encodeURIComponent(s)}/speedtests`, { method: "POST", body: JSON.stringify(b) }),
    oui: (mac: string) => call<OuiResult>(`/oui/${encodeURIComponent(mac)}`),
  };
}
```

---

## 5. Vercel Function proxy (for §4 actions)

Copy `api/vigilant/[...path].ts` into the Watchman repo root (the ready file is in
`docs/watchman-proxy/`). It: rebuilds the Vigilant path, **allowlists** method+path (only the
10 frontend endpoints — `/enroll`, `/admin/migrate`, device routes → `403`), verifies the
caller's Supabase JWT, then forwards with the admin bearer (+ optional Cloudflare Access
service-token headers). Needs `@vercel/node` in devDeps (`npm i -D @vercel/node`).

```ts
import type { VercelRequest, VercelResponse } from "@vercel/node";

const SERIAL = "[^/]+", ID = "[^/]+";
const ALLOW: Array<{ method: string; re: RegExp }> = [
  { method: "GET",  re: new RegExp(`^/fleet$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/history$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/config-jobs$`) },
  { method: "POST", re: new RegExp(`^/devices/${SERIAL}/config-jobs$`) },
  { method: "POST", re: new RegExp(`^/config-jobs/${ID}/approve$`) },
  { method: "POST", re: new RegExp(`^/config-jobs/${ID}/cancel$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/speedtests$`) },
  { method: "POST", re: new RegExp(`^/devices/${SERIAL}/speedtests$`) },
  { method: "GET",  re: new RegExp(`^/oui/${ID}$`) },
];
const isAllowed = (m: string, p: string) => ALLOW.some((a) => a.method === m && a.re.test(p));

async function verifyUser(accessToken: string): Promise<string | null> {
  const base = process.env.SUPABASE_URL, anon = process.env.SUPABASE_ANON_KEY;
  if (!base || !anon) return null;
  try {
    const r = await fetch(`${base}/auth/v1/user`, { headers: { apikey: anon, Authorization: `Bearer ${accessToken}` } });
    if (!r.ok) return null;
    const u = (await r.json()) as { id?: string };
    return u?.id ?? null;
  } catch { return null; }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const method = (req.method || "GET").toUpperCase();
  const segs = req.query.path;
  const parts = Array.isArray(segs) ? segs : segs ? [segs] : [];
  const path = "/" + parts.map(encodeURIComponent).join("/");

  if (!isAllowed(method, path)) return res.status(403).json({ ok: false, error: "forbidden path" });

  const auth = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(Array.isArray(auth) ? auth[0] : auth);
  const userId = m ? await verifyUser(m[1].trim()) : null;
  if (!userId) return res.status(401).json({ ok: false, error: "unauthorized" });

  const targetBase = process.env.VIGILANT_API_URL, adminToken = process.env.VIGILANT_ADMIN_TOKEN;
  if (!targetBase || !adminToken) return res.status(500).json({ ok: false, error: "proxy not configured" });

  const qs = req.url && req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  const targetUrl = `${targetBase.replace(/\/$/, "")}${path}${qs}`;
  const headers: Record<string, string> = { Authorization: `Bearer ${adminToken}` };
  if (process.env.CF_ACCESS_CLIENT_ID && process.env.CF_ACCESS_CLIENT_SECRET) {
    headers["CF-Access-Client-Id"] = process.env.CF_ACCESS_CLIENT_ID;
    headers["CF-Access-Client-Secret"] = process.env.CF_ACCESS_CLIENT_SECRET;
  }
  let body: string | undefined;
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
    headers["Content-Type"] = "application/json";
  }
  try {
    const upstream = await fetch(targetUrl, { method, headers, body });
    const text = await upstream.text();
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type"); if (ct) res.setHeader("content-type", ct);
    return res.send(text);
  } catch (e: any) {
    return res.status(502).json({ ok: false, error: "upstream unreachable", detail: e?.message ?? String(e) });
  }
}
```

Wire the client to the proxy with the user's Supabase token:
```ts
async function vigilantApi() {
  const { data } = await supabase.auth.getSession();
  return createVigilantApi("/api/vigilant", data.session?.access_token);
}
const api = await vigilantApi();
const { devices } = await api.fleet();
```

---

## 6. Device-specific notes (Chateau AC/AX, temperature)

The estate includes MikroTik **Chateau AC and AX** models. Two things the frontend must
account for:

### WiFi client monitoring is not available yet
- The agent collects only per-interface **throughput/link** for the `wifi` interface — it
  shows up in `interface_state` like any other port (rx/tx bps, running, role). So you can
  chart WiFi *throughput* per device today.
- **Per-client WiFi data (connected stations, signal, CCQ) is NOT collected.** The
  `wireless_clients` table exists in the schema but **nothing writes to it** — treat it as
  empty/future. Don't build a "WiFi clients" panel expecting data; gate it behind a
  "coming soon"/empty state, or omit it for v1.
- When it *is* added, it's chip-specific and the API/shape may differ per model: **AC** uses
  the legacy `/interface/wireless` driver (`…/registration-table`); **AX** uses wifiwave2
  `/interface/wifi` (`…/registration-table`). The agent will need to branch per driver, so
  expect a `driver`/`band` discriminator on future wifi-client rows. Design the UI so a
  WiFi-clients view can be slotted in later without reshaping the device drilldown.

### Temperature is often blank
- `device_state.temperature` (and `cpu_temperature`, `board_temperature`, `voltage`, fans)
  come from `/system/health`, which is **board-dependent**. Chateaus frequently don't expose
  a `temperature` row, so the field arrives **`null`** — that's the blank you're seeing, not
  a bug in the pipeline.
- **UI rule:** render `null` temp as "—" / "n/a", never "0 °C", and don't colour-threshold a
  null. Same for any health metric: `null` = "not reported by this board", distinct from a
  real low value. The same applies in the fleet grid temp column and the drilldown health
  panel.

---

## 7. What to build first (suggested order)
1. Supabase client + RLS verified → fleet grid (`v_fleet` + `device_state` Realtime).
2. Device drilldown (direct queries + filtered subscriptions). Handle `null` temp; `lte` is an array.
3. Alerts list/badges (`alerts`).
4. Charts (`/devices/:serial/history` via proxy, or `*_history` queries).
5. Proxy + config-push timeline (render lifecycle; gate approve/apply).
6. Speedtest request/list.
7. (Later) WiFi-clients view once agent collection lands.

> Source of truth for every contract here: Vigilant's `db/schema.sql`, `src/ingest/*`, and
> `agent/vigilant-agent.rsc`. If anything disagrees, the code wins — flag it back.
