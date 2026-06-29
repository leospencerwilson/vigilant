# wc_field — Router stats API (Vigilant)

Everything wc_field needs to **list routers and show a router's live stats** when an engineer
taps into one. Read-only; called **directly from the page** (CORS is enabled on Vigilant).
Verified against `src/ingest/handlers.js` + `src/shared/store.*` + `db/schema.sql`.

- **Base URL:** `https://vigilant.internal.western-communication.com`
- **Auth:** `Authorization: Bearer <FIELD_ENROLL_TOKEN>` on every call (the `vfk_…` scoped key —
  **not** the master `ven_…` token). Put it in `VITE_VIGILANT_FIELD_KEY`.
- **CORS:** Vigilant answers the preflight and allows the wc_field origin (`CORS_ALLOW_ORIGINS`).
- **Content:** JSON out. Non-2xx bodies are `{ "ok": false, "error": "…" }`. Unknown serial → `404`.

### What the scoped key CAN and CANNOT do
| Allowed (read-only + enrol) | Denied (master token only → `401`) |
|---|---|
| `GET /fleet`, `GET /devices/:serial`, `GET /devices/:serial/history`, `GET /oui/:mac`, `POST /enroll` | config-push (`/devices/:serial/config-jobs`, `/config-jobs/*`), speedtests, `/admin/migrate`, `/realtime/config` |

> ⚠️ `GET /devices/:serial` includes WiFi **passphrases** (`wifi[].passphrase`) — treat the
> response as sensitive in the UI (mask the PSK, reveal on tap). Anyone holding the field key
> can read any device's detail, so keep it out of public builds and lock `CORS_ALLOW_ORIGINS`.

---

## Endpoints

### 1. `GET /fleet` — the router list
One row per enrolled device (registry + latest state + open-alert count). Use it to populate
the "pick a router" list; poll every ~10–15s if you keep it on screen.

```
GET /fleet      Authorization: Bearer <FIELD_ENROLL_TOKEN>
```
**200** → `{ "devices": FleetDevice[] }` *(note the envelope — not a bare array)*:
```jsonc
{ "devices": [
  { "id":"…uuid…","serial":"HGT0A023T6C","identity":"AlliedHuddersfield",
    "site_name":"Allied Huddersfield","customer":"Allied","model":"RB5009",
    "wan_type":"pppoe","tags":["allied","pharmacy"],
    "status":"online","cpu_load":7,"temperature":41.5,
    "public_ip":"84.247.33.71","ppp_sessions":12,
    "last_seen_at":"2026-06-29T10:00:00Z","open_alerts":0 }
] }
```
`status` ∈ `online | stale | offline | unknown`. `temperature` is often `null` on Chateaus
(board doesn't report it) — render `null` as "—", not 0.

### 2. `GET /devices/:serial` — the router stats (the main "click-in" view)
Full live detail for one device. **404** if the serial is unknown.
```
GET /devices/HGT0A023T6C      Authorization: Bearer <FIELD_ENROLL_TOKEN>
```
**200** → `DeviceDetail`:
```jsonc
{
  "device":    { "id":"…","serial":"…","identity":"…","site_name":"…","customer":"Allied",
                 "model":"…","ros_version":"7.16.1","wan_type":"pppoe","tags":[],
                 "poll_interval_s":10,"enrolled_at":"…" },
  "state":     { "status":"online","cpu_load":7,"temperature":41.5,"uptime_s":864000,
                 "free_memory":123456789,"total_memory":268435456,"public_ip":"84.247.33.71",
                 "pppoe_running":true,"ppp_sessions":12,"dhcp_leases":30,"lte_signal":-95,
                 "firmware_current":"7.16.1","firmware_upgrade":"7.16.1","ntp_synced":true,
                 "last_seen_at":"…" },                       // null if never reported
  "interfaces":[ { "name":"ether1","type":"ether","role":"wan","is_wan":true,"running":true,
                   "plugged":true,"speed":"1Gbps","rx_bps":1234567,"tx_bps":234567,
                   "link_downs":0,"mac":"…" } ],
  "lte":       [ { "interface":"lte1","operator":"…","registration":"registered","band":"3",
                   "rsrp":-95,"rsrq":-10,"sinr":12,"rssi":-65,"iccid":"…","cell_id":"…" } ],  // [] if no SIM
  "neighbors": [ { "interface":"ether3","identity":"phone-1","mac":"AA:BB:CC:DD:EE:FF",
                   "platform":"Yealink","address":"10.0.0.12" } ],
  "mac_hosts": [ { "interface":"ether4","mac":"AA:BB:…","ip":"10.0.0.9",
                   "hostname":"RECEPTION-PC","vendor":"Hewlett Packard" } ],
  "wifi":      [ { "interface":"wifi1","driver":"ax","ssid":"Pharmacy Wifi",
                   "passphrase":"… (sensitive)","security":"wpa2-psk","channel":"5180/ax",
                   "clients":3 } ],
  "wifi_clients":[ { "interface":"wifi1","mac":"…","signal":-57,"rx_rate":"130Mbps","tx_rate":"144Mbps" } ]
}
```
`lte` and `wifi*` are **arrays** (`[]` when none). `state` can be `null` for a freshly-enrolled
device that hasn't reported yet. Poll every ~2–5s while the view is open for live cpu/throughput.

### 3. `GET /devices/:serial/history?window=1h|6h|24h|7d` — charts
Time-ascending series for CPU/mem/temp/ppp and per-interface throughput.
```
GET /devices/HGT0A023T6C/history?window=1h
```
**200** →
```jsonc
{ "serial":"HGT0A023T6C","window":"1h",
  "metrics":[ { "ts":"…","cpu_load":7,"free_memory":123456789,"temperature":41.5,"ppp_sessions":12 } ],
  "interfaces":[ { "name":"ether1","points":[ { "ts":"…","rx_bps":1234567,"tx_bps":234567 } ] } ] }
```
Unknown `window` → defaults to `1h`. Poll ~5–10s (it's downsampled; no need to hammer).

### 4. `GET /oui/:mac` — manufacturer for a MAC
For labelling neighbours / hosts the agent didn't already vendor-stamp. `:mac` may be
colon/dash/dot-separated or bare hex.
```
GET /oui/AABBCCDDEEFF
```
**200** → `{ "mac":"AA:BB:CC:DD:EE:FF","oui":"AABBCC","vendor":"MikroTik","source":"db|seed|api|none" }`.
Invalid MAC → `400`. Dedupe + cache client-side by the 3-octet prefix (one lookup per vendor).

---

## TypeScript types
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
  id: string; serial: string; identity: string | null; site_name: string | null;
  customer: string | null; model: string | null; ros_version: string | null;
  wan_type: WanType; tags: string[]; poll_interval_s: number; enrolled_at: string;
  notes: string | null;
}
export interface DeviceState {
  device_id: string; status: DeviceStatus; uptime_s: number | null;
  cpu_load: number | null; free_memory: number | null; total_memory: number | null;
  temperature: number | null; cpu_temperature: number | null; board_temperature: number | null;
  voltage: number | null; public_ip: string | null; ros_version: string | null;
  pppoe_running: boolean | null; ppp_sessions: number | null; dhcp_leases: number | null;
  conn_count: number | null; lte_signal: number | null; netwatch_down: number | null;
  firmware_current: string | null; firmware_upgrade: string | null; ntp_synced: boolean | null;
  last_seen_at: string;
}
export interface InterfaceState {
  name: string; type: string | null; role: "wan"|"lan"|"bridge-member"|"trunk"|"vpn"|"unused"|"disabled"|null;
  is_wan: boolean; running: boolean | null; plugged: boolean | null; disabled: boolean | null;
  speed: string | null; link_downs: number | null; bridge: string | null; mac: string | null;
  rx_bps: number | null; tx_bps: number | null; rx_byte: number | null; tx_byte: number | null;
  sampled_at: string;
}
export interface LteState {
  interface: string; operator: string | null; registration: string | null; access_tech: string | null;
  band: string | null; cell_id: string | null; rsrp: number | null; rsrq: number | null;
  sinr: number | null; rssi: number | null; iccid: string | null; imsi: string | null;
  imei: string | null; sampled_at: string;
}
export interface Neighbor {
  interface: string; mac: string; identity: string | null; address: string | null;
  platform: string | null; board: string | null; version: string | null; last_seen_at: string;
}
export interface MacHost {
  interface: string; mac: string; ip: string | null;
  hostname: string | null; comment: string | null; vendor: string | null;
}
export interface WifiNetwork {
  interface: string; driver: "ax" | "ac" | null; ssid: string | null;
  passphrase: string | null;            // ⚠️ sensitive — mask in the UI
  security: string | null; channel: string | null; band: string | null;
  disabled: boolean | null; hidden: boolean | null; clients: number | null;
}
export interface WirelessClient {
  interface: string; mac: string; signal: number | null;     // dBm
  rx_rate: string | null; tx_rate: string | null; uptime_s: number | null;
}
export interface DeviceDetail {
  device: Device; state: DeviceState | null;
  interfaces: InterfaceState[]; lte: LteState[];
  neighbors: Neighbor[]; mac_hosts: MacHost[];
  wifi: WifiNetwork[]; wifi_clients: WirelessClient[];
}
export type HistoryWindow = "1h" | "6h" | "24h" | "7d";
export interface DeviceHistory {
  serial: string; window: HistoryWindow;
  metrics: Array<{ ts: string; cpu_load: number|null; free_memory: number|null; temperature: number|null; ppp_sessions: number|null }>;
  interfaces: Array<{ name: string; points: Array<{ ts: string; rx_bps: number|null; tx_bps: number|null }> }>;
}
export interface OuiResult { mac: string; oui: string; vendor: string|null; source: "db"|"seed"|"api"|"none"; }
```

---

## Minimal client
```ts
const BASE = "https://vigilant.internal.western-communication.com";
const KEY  = import.meta.env.VITE_VIGILANT_FIELD_KEY;
const H = { Authorization: `Bearer ${KEY}` };

export const vigilant = {
  fleet:   ()             => fetch(`${BASE}/fleet`, { headers: H }).then(r => r.json()) as Promise<FleetResponse>,
  device:  (s: string)    => fetch(`${BASE}/devices/${encodeURIComponent(s)}`, { headers: H }).then(r => r.json()) as Promise<DeviceDetail>,
  history: (s: string, w: HistoryWindow = "1h") =>
                              fetch(`${BASE}/devices/${encodeURIComponent(s)}/history?window=${w}`, { headers: H }).then(r => r.json()) as Promise<DeviceHistory>,
  oui:     (mac: string)  => fetch(`${BASE}/oui/${encodeURIComponent(mac)}`, { headers: H }).then(r => r.json()) as Promise<OuiResult>,
};
```

## Wiring the per-router screen
| Panel | Source | Refresh |
|---|---|---|
| Header (name/model/ROS/uptime/status) | `device.device` + `device.state` | on open + ~5s |
| Tiles (CPU/mem/temp/PPP/DHCP/firmware) | `device.state` | ~2–5s |
| Ports (role/link/speed/RX/TX) | `device.interfaces` | ~2–5s |
| WAN throughput | `interfaces` where `is_wan`/`role==='wan'` → `rx_bps`/`tx_bps` | ~2–5s |
| LTE/SIM | `device.lte[0]` | ~5s |
| WiFi (SSID/PSK/security/channel + clients/signal) | `device.wifi` + `device.wifi_clients` | ~5–10s |
| Neighbours / Hosts | `device.neighbors` / `device.mac_hosts` (+ `/oui` for blanks) | ~30s (changes rarely) |
| Charts (cpu/mem/throughput) | `GET …/history?window=` | ~5–10s |

**Rendering rules:** treat `null` as "—" (never 0 — esp. temperature); `lte`/`wifi*` are arrays
(may be empty); a device with no WiFi clients connected shows an empty client list (not a bug);
**mask the WiFi passphrase** and reveal on explicit tap.

> Source of truth: Vigilant `src/ingest/handlers.js`, `db/schema.sql`. For the live-update
> in-place rendering approach, the admin dashboard (`src/ingest/admin.html`) is a working
> reference. The richer Watchman doc (`docs/WATCHMAN-API-AND-SCHEMA.md`) covers the same shapes.
