# Vigilant — API & schema reference (for the Watchman frontend)

Everything needed to build a frontend against Vigilant: the HTTP endpoints, their exact
request/response shapes, and TypeScript types. Verified against `src/ingest/server.js`,
`src/ingest/handlers.js`, `src/shared/store.mem.js`, and `db/schema.sql`.

- **Base URL:** `https://vigilant.western-communication.com`
- **Content type:** JSON in, JSON out (some routes return `text/plain` — noted).
- **Errors:** non-2xx bodies are `{ "ok": false, "error": "<message>" }` (sometimes with
  extra fields). `404` for unknown serial/job id.

## Auth — read this first

All frontend-facing endpoints below are **admin routes**: they require
`Authorization: Bearer <ENROLL_TOKEN>` (the single admin token from Vigilant's `.env`).

The other routes in the service (`POST /telemetry`, `/agent/script`, `/config/pending`,
`/config/:id.rsc`, `/config/result`, `/speedtest/{pending,down,up,result}`) are **device**
routes — each router authenticates with its own per-device bearer. The frontend never calls
these; they're listed only so you don't wire them by mistake.

> ⚠️ **The admin token can't live in a Vite/SPA bundle** (every `VITE_` var ships to the
> browser). Call these endpoints from a **server-side proxy** — e.g. a Vercel Function that
> holds `VIGILANT_ADMIN_TOKEN`, authenticates the logged-in user, and forwards to Vigilant.
> The browser hits same-origin `/api/...`; the token stays on the server. (Alternatively,
> for the live/read views, skip the API and subscribe to Supabase Realtime directly under
> the user's RLS — see `WATCHMAN-IMPORT-GUIDE.md`. This doc is the REST surface.)

---

## Endpoint reference

### `GET /fleet` — overview grid

One row per device (registry + latest state + open-alert count).

**Response 200**
```jsonc
{
  "devices": [
    {
      "id": "uuid", "serial": "HGT0A023T6C", "identity": "AlliedHuddersfield",
      "site_name": "Allied Huddersfield", "customer": "Allied", "model": "RB5009",
      "wan_type": "pppoe", "tags": ["allied","pharmacy"],
      "status": "online", "cpu_load": 7, "temperature": 41.5,
      "public_ip": "84.247.33.71", "ppp_sessions": 12,
      "last_seen_at": "2026-06-24T10:00:00Z", "open_alerts": 0
    }
  ]
}
```
> Note the `{ devices: [...] }` envelope — it is **not** a bare array.

---

### `GET /devices/:serial` — device drilldown

Full detail for one device. **404** if the serial is unknown.

**Response 200**
```jsonc
{
  "device":    { "id":"uuid","serial":"HGT0A023T6C","identity":"…","site_name":"…","customer":"Allied","model":"…","ros_version":"7.19.4","wan_type":"pppoe","tags":[],"expected":true,"poll_interval_s":10,"poll_until":null,"agent_version":"…","enrolled_at":"…","notes":null },
  "state":     { /* DeviceState row, or null if never reported — see types */ },
  "interfaces":[ { "name":"ether1","type":"ether","role":"wan","is_wan":true,"running":true,"rx_bps":1234567,"tx_bps":234567, /* …InterfaceState */ } ],
  "lte":       [ /* LteState rows — ARRAY (one per lte iface), [] when no SIM */ ],
  "neighbors": [ { "interface":"ether3","mac":"AA:BB:CC:DD:EE:FF","identity":"phone-1","platform":"Yealink", /* …Neighbor */ } ],
  "mac_hosts": [ { "interface":"ether4","mac":"AA:BB:…","ip":"10.0.0.9","vendor":"…" } ]
}
```
> `lte` is an **array**, not a single object. `state` can be `null` for a freshly-enrolled
> device that hasn't reported yet.

---

### `GET /devices/:serial/history?window=1h|6h|24h|7d` — chart series

Time-ascending series for CPU/mem/temp/ppp and per-interface throughput. Unknown `window`
falls back to `1h`; unknown serial → **404**.

**Response 200**
```jsonc
{
  "serial": "HGT0A023T6C",
  "window": "1h",
  "metrics": [
    { "ts":"2026-06-24T10:00:00Z","cpu_load":7,"free_memory":123456789,"temperature":41.5,"ppp_sessions":12 }
  ],
  "interfaces": [
    { "name":"ether1","points":[ { "ts":"2026-06-24T10:00:00Z","rx_bps":1234567,"tx_bps":234567 } ] }
  ]
}
```

---

### Config-push (review-gated) — `config_jobs` lifecycle

Status flow: `draft → approved → fetched → applying → applied | failed | rolled_back | cancelled`.
The device only ever *pulls* an **approved** job on its own tick — none of these admin calls
touch a router. Two-person rule: the approver must differ from the author.

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `GET /devices/:serial/config-jobs` | — | `200 { ok, serial, jobs: ConfigJob[] }` (newest first, max 50) | `404` unknown serial |
| `POST /devices/:serial/config-jobs` | `{ rsc_text, created_by, kind?: "snippet"\|"full", confirm_window_s?, is_canary? }` | `201 { ok, job: ConfigJob }` (status `draft`) | `kind` default `snippet`; `confirm_window_s` floored to 30, default 300 |
| `POST /config-jobs/:id/approve` | `{ approved_by }` | `200 { ok, job }` | `409` if not a draft or approver == author |
| `POST /config-jobs/:id/cancel` | `{ actor? }` | `200 { ok, job }` | only `draft`/`approved` cancellable |

> The UI should **render** this lifecycle and gate approve/apply as deliberate, audited
> actions. Never one-click auto-apply — the MikroTik estate is live production. See
> `RUNBOOK-config-push.md`.

---

### Active speedtest (operator-gated; saturates the WAN)

| Method & path | Body | Success | Notes |
|---|---|---|---|
| `GET /devices/:serial/speedtests` | — | `200 { ok, serial, jobs: SpeedtestJob[] }` (max 20) | recent tests |
| `POST /devices/:serial/speedtests` | `{ requested_by, bytes_down?, bytes_up? }` | `201 { ok, job: SpeedtestJob }` (status `pending`) | bytes capped server-side (≤64 MiB/leg; down default 25 MiB, up 8 MiB) |

The device runs the test on its next tick; poll `GET …/speedtests` (or watch the
`speedtest_jobs` table via Realtime) for `down_bps`/`up_bps` to fill in.

---

### `GET /oui/:mac` — vendor lookup

Resolve a MAC's OUI to a vendor (for neighbour/mac-host enrichment). `:mac` may be
colon/hyphen/dot-separated or bare hex. Clearly invalid MAC → **400**.

**Response 200** `{ "mac":"AA:BB:CC:DD:EE:FF", "oui":"AABBCC", "vendor":"MikroTik", "source":"seed|cache|api|none" }`

---

### Admin lifecycle (not usually wired into the dashboard)

| Method & path | Body | Success |
|---|---|---|
| `POST /enroll` | `{ serial, site_name?, customer?, wan_type?, tags? }` | `200 { token, serial, install, bootstrap }` — `token` shown **once** |
| `POST /admin/migrate` | — | `200 { ok, migrated: true }` — applies bundled `schema.sql` |
| `GET /healthz` | — | `200 "ok"` (open, no auth) |

---

## TypeScript types

Source of truth: `db/schema.sql` + the store readers. `numeric` columns arrive as JS
numbers; `bigint` byte counters can be large but the derived `rx_bps`/`tx_bps` are safe.

```ts
// vigilant.ts — types for the Vigilant API responses
export type DeviceStatus = "online" | "stale" | "offline" | "unknown";
export type WanType = "pppoe" | "sim" | "dhcp" | "static" | "unknown";

// GET /fleet  →  { devices: FleetDevice[] }
export interface FleetResponse { devices: FleetDevice[]; }
export interface FleetDevice {
  id: string;
  serial: string;
  identity: string | null;
  site_name: string | null;
  customer: string | null;
  model: string | null;
  wan_type: WanType;
  tags: string[];
  status: DeviceStatus | null;
  cpu_load: number | null;        // percent
  temperature: number | null;
  public_ip: string | null;
  ppp_sessions: number | null;
  last_seen_at: string | null;    // ISO
  open_alerts: number;
}

// Device registry row (devices table) — `device` in the drilldown
export interface Device {
  id: string;
  serial: string;
  identity: string | null;
  site_name: string | null;
  customer: string | null;
  model: string | null;
  ros_version: string | null;
  wan_type: WanType;
  tags: string[];
  expected: boolean;
  poll_interval_s: number;
  poll_until: string | null;
  agent_version: string | null;
  enrolled_at: string;
  notes: string | null;
}

export interface DeviceState {
  device_id: string;
  status: DeviceStatus;
  uptime_s: number | null;
  cpu_load: number | null;          // percent
  free_memory: number | null;
  total_memory: number | null;
  free_hdd: number | null;
  temperature: number | null;
  voltage: number | null;
  public_ip: string | null;
  ros_version: string | null;
  firmware: string | null;
  default_route: boolean | null;
  pppoe_running: boolean | null;
  ppp_sessions: number | null;      // active PPP/SSTP/L2TP sessions
  dhcp_leases: number | null;
  conn_count: number | null;
  lte_signal: number | null;        // RSRP/dBm (also in LteState)
  cpu_temperature: number | null;
  board_temperature: number | null;
  fan1_speed: number | null;
  fan2_speed: number | null;
  firmware_current: string | null;
  firmware_upgrade: string | null;  // != current → firmware-behind
  ntp_synced: boolean | null;
  netwatch_down: number | null;
  last_seen_at: string;
  raw?: unknown;                     // full last payload (jsonb)
}

export interface InterfaceState {
  device_id?: string;
  name: string;
  type: string | null;              // ether / bridge / vlan / pppoe-out / lte / …
  comment: string | null;
  plugged: boolean | null;          // cable in + link up
  running: boolean | null;
  disabled: boolean | null;
  speed: string | null;             // e.g. "1Gbps"
  full_duplex: boolean | null;
  last_link_up_at: string | null;
  last_link_down_at: string | null;
  link_downs: number | null;        // flap counter — high = dodgy cable/port
  role: "wan" | "lan" | "bridge-member" | "trunk" | "vpn" | "unused" | "disabled" | null;
  is_wan: boolean;
  bridge: string | null;
  poe_out_status: string | null;
  poe_out_power: number | null;
  mac: string | null;
  rx_bps: number | null;            // derived server-side
  tx_bps: number | null;            // derived server-side
  rx_byte: number | null;           // cumulative
  tx_byte: number | null;
  rx_packet: number | null;
  tx_packet: number | null;
  sampled_at: string;
}

export interface LteState {
  device_id?: string;
  interface: string;
  iccid: string | null;
  imsi: string | null;
  imei: string | null;
  msisdn: string | null;
  operator: string | null;
  apn: string | null;
  registration: string | null;      // registered / searching / denied
  access_tech: string | null;       // lte / lte-a / 5g-nsa
  band: string | null;
  earfcn: string | null;
  cell_id: string | null;
  phy_cellid: string | null;
  rssi: number | null;
  rsrp: number | null;
  rsrq: number | null;
  sinr: number | null;
  cqi: number | null;
  session_uptime_s: number | null;
  sampled_at: string;
}

export interface Neighbor {
  device_id?: string;
  interface: string;                 // local port the neighbor was seen on
  mac: string;
  identity: string | null;
  address: string | null;
  platform: string | null;           // "MikroTik" / "Yealink" / switch vendor
  board: string | null;
  version: string | null;
  last_seen_at: string;
}

export interface MacHost {
  interface: string;
  mac: string;
  ip: string | null;
  vendor: string | null;
}

// GET /devices/:serial
export interface DeviceDetail {
  device: Device;
  state: DeviceState | null;
  interfaces: InterfaceState[];
  lte: LteState[];                    // ARRAY (one per lte iface), [] when no SIM
  neighbors: Neighbor[];
  mac_hosts: MacHost[];
}

// GET /devices/:serial/history
export type HistoryWindow = "1h" | "6h" | "24h" | "7d";
export interface DeviceHistory {
  serial: string;
  window: HistoryWindow;
  metrics: Array<{
    ts: string; cpu_load: number | null; free_memory: number | null;
    temperature: number | null; ppp_sessions: number | null;
  }>;
  interfaces: Array<{
    name: string;
    points: Array<{ ts: string; rx_bps: number | null; tx_bps: number | null }>;
  }>;
}

// config_jobs
export type ConfigJobStatus =
  | "draft" | "approved" | "fetched" | "applying"
  | "applied" | "failed" | "rolled_back" | "cancelled";
export interface ConfigJob {
  id: string;
  device_id: string | null;          // null = group job
  target_tag: string | null;
  is_canary: boolean;
  kind: "snippet" | "full";
  rsc_text: string;
  rsc_sha256: string;
  status: ConfigJobStatus;
  confirm_window_s: number;          // dead-man's-switch keep-window (≥30)
  created_by: string;
  approved_by: string | null;
  created_at: string;
  approved_at: string | null;
  fetched_at: string | null;
  applied_at: string | null;
  result_log: string | null;
}
export interface ConfigJobsResponse { ok: true; serial: string; jobs: ConfigJob[]; }

// speedtest_jobs
export type SpeedtestStatus = "pending" | "running" | "done" | "failed";
export interface SpeedtestJob {
  id: string;
  device_id: string | null;
  status: SpeedtestStatus;
  bytes_down: number;
  bytes_up: number;
  down_bps: number | null;           // filled once measured
  up_bps: number | null;
  requested_by: string;
  result_log: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}
export interface SpeedtestsResponse { ok: true; serial: string; jobs: SpeedtestJob[]; }

// alerts (read via Supabase / future list endpoint)
export type AlertSeverity = "info" | "warning" | "critical";
export type AlertState = "open" | "acked" | "cleared";
export interface Alert {
  id: number;
  device_id: string;
  rule_id: number | null;
  severity: AlertSeverity;
  state: AlertState;
  detail: string | null;
  opened_at: string;
  acked_at: string | null;
  acked_by: string | null;
  cleared_at: string | null;
}

export interface OuiResult {
  mac: string; oui: string; vendor: string | null;
  source: "seed" | "cache" | "api" | "none";
}

export interface ApiError { ok: false; error: string; [k: string]: unknown; }
```

---

## A typed client (drop-in)

Point `baseUrl` at your **server-side proxy** (which injects the bearer), or at Vigilant
directly from server code. Don't embed the token in browser-shipped source.

```ts
// vigilantApi.ts
import type {
  FleetResponse, DeviceDetail, DeviceHistory, HistoryWindow,
  ConfigJobsResponse, ConfigJob, SpeedtestsResponse, SpeedtestJob, OuiResult,
} from "./vigilant";

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
      const body = await res.json().catch(() => ({}));
      throw new Error(`Vigilant ${init?.method ?? "GET"} ${path} → ${res.status}: ${(body as any).error ?? res.statusText}`);
    }
    return res.json() as Promise<T>;
  }

  return {
    fleet: () => call<FleetResponse>("/fleet"),
    device: (serial: string) => call<DeviceDetail>(`/devices/${encodeURIComponent(serial)}`),
    history: (serial: string, window: HistoryWindow = "1h") =>
      call<DeviceHistory>(`/devices/${encodeURIComponent(serial)}/history?window=${window}`),

    listConfigJobs: (serial: string) =>
      call<ConfigJobsResponse>(`/devices/${encodeURIComponent(serial)}/config-jobs`),
    createConfigJob: (serial: string, b: { rsc_text: string; created_by: string; kind?: "snippet" | "full"; confirm_window_s?: number; is_canary?: boolean }) =>
      call<{ ok: true; job: ConfigJob }>(`/devices/${encodeURIComponent(serial)}/config-jobs`, { method: "POST", body: JSON.stringify(b) }),
    approveConfigJob: (id: string, approved_by: string) =>
      call<{ ok: true; job: ConfigJob }>(`/config-jobs/${id}/approve`, { method: "POST", body: JSON.stringify({ approved_by }) }),
    cancelConfigJob: (id: string, actor?: string) =>
      call<{ ok: true; job: ConfigJob }>(`/config-jobs/${id}/cancel`, { method: "POST", body: JSON.stringify({ actor }) }),

    listSpeedtests: (serial: string) =>
      call<SpeedtestsResponse>(`/devices/${encodeURIComponent(serial)}/speedtests`),
    requestSpeedtest: (serial: string, b: { requested_by: string; bytes_down?: number; bytes_up?: number }) =>
      call<{ ok: true; job: SpeedtestJob }>(`/devices/${encodeURIComponent(serial)}/speedtests`, { method: "POST", body: JSON.stringify(b) }),

    oui: (mac: string) => call<OuiResult>(`/oui/${encodeURIComponent(mac)}`),
  };
}
```
