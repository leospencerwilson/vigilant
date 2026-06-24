# Vigilant — frontend integration (Watchman + WCN console)

Vigilant is the backend/engine. The **Watchman** UI and the WCN Cloud **console** are the
frontends. They consume Vigilant two ways:

1. **Supabase Realtime (primary)** — subscribe to the live tables and render pushes. The
   browser never polls Vigilant; writes from the ingest appear as live row changes.
2. **A small convenience read API** (`GET /fleet`, `GET /devices/:serial`) — for the
   initial server-side render / non-Realtime fetches. Realtime is the source of truth for
   "live"; these endpoints are for first paint and one-off reads.

> All Realtime tables live in the `vigilant` schema and are added to the
> `supabase_realtime` publication by `db/schema.sql`. If a subscription is silent, confirm
> the publication includes the table (the schema's `DO $$ … $$` block does this; re-apply
> `npm run migrate` if Realtime was enabled after the tables were created).

---

## 1. Realtime tables / channels

These six tables are published for Realtime (see `db/schema.sql`). Subscribe to the ones
each view needs:

| Table | Grain | Drives | Notes |
|---|---|---|---|
| `device_state` | 1 row / device (upsert) | Overview grid tiles: status, cpu, temp, public_ip, ppp_sessions, last_seen_at | Bounded row count — cheap. Status: `online`/`stale`/`offline`/`unknown`. Events are mostly `UPDATE`. |
| `interface_state` | 1 row / device·interface (upsert) | Port view: `rx_bps`/`tx_bps` (server-derived), role, is_wan, link state | Filter by `device_id` on the drilldown. |
| `lte_state` | 1 row / device·lte iface (upsert) | SIM/signal panel: rsrp/rsrq/sinr/rssi, operator, registration, band, cell_id | Identifiers (iccid/imsi/imei) update rarely; signal updates fast. |
| `neighbors` | 1 row / device·iface·mac | "What's plugged into each port" (LLDP/CDP/MNDP) | `last_seen_at` stamped on upsert; worker prunes stale rows. |
| `config_jobs` | 1 row / job | Config-push lifecycle UI: `draft → approved → fetched → applying → applied/failed/rolled_back/cancelled` | Watch status transitions to drive the push timeline. See `RUNBOOK-config-push.md`. |
| `alerts` | 1 row / alert | Alert banner / list: open/acked/cleared, severity, detail | Index on open alerts; `v_fleet.open_alerts` gives per-device counts. |

Not Realtime (query on demand): `metrics_history`, `interface_history`, `lte_history`
(charts), `config_snapshots`, `audit_log`, `mac_hosts` (L2 fallback table — large; read
via `GET /devices/:serial`).

The `v_fleet` view (used by `GET /fleet`) joins `devices` + `device_state` + open-alert
count. Subscribe to the underlying `device_state` for live grid updates and use the view
for the initial list.

---

## 2. Subscription snippet (`@supabase/ssr`)

The console/Watchman already create a Supabase browser client with `@supabase/ssr`. Set
the client's schema to `vigilant` (or qualify per-channel) and subscribe with
`postgres_changes`. Example overview-grid hook:

```ts
// uses the existing @supabase/ssr browser client
import { createBrowserClient } from "@supabase/ssr";

const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  { db: { schema: "vigilant" } } // Vigilant lives in its own schema
);

// Live overview grid: one row per device in device_state.
const channel = supabase
  .channel("vigilant:device_state")
  .on(
    "postgres_changes",
    { event: "*", schema: "vigilant", table: "device_state" },
    (payload) => {
      // payload.new is the upserted row: { device_id, status, cpu_load, temperature,
      //   public_ip, ppp_sessions, last_seen_at, ... }
      applyDeviceState(payload.new);
    }
  )
  .subscribe();

// Drilldown: only the ports for the open device.
const portChannel = supabase
  .channel(`vigilant:interface_state:${deviceId}`)
  .on(
    "postgres_changes",
    {
      event: "*",
      schema: "vigilant",
      table: "interface_state",
      filter: `device_id=eq.${deviceId}`,
    },
    (payload) => applyInterfaceState(payload.new) // { name, rx_bps, tx_bps, role, is_wan, ... }
  )
  .subscribe();

// later
supabase.removeChannel(channel);
supabase.removeChannel(portChannel);
```

Same pattern for `lte_state`, `neighbors`, `config_jobs`, and `alerts` — change the
`table` (and `filter` to `device_id=eq.<id>` where you want one device's rows).

> RLS: these tables are in a non-`public` schema served to authenticated console/Watchman
> users. Ensure the Realtime-published tables have appropriate RLS / grants for the role
> the frontends use (the console's auth model). The ingest writes via `pg` with its own
> scoped role and does not use the frontend keys.

---

## 3. Convenience read API

Realtime is primary; these admin endpoints exist for initial render and scripted reads.
Both require the admin bearer (`Authorization: Bearer ${ENROLL_TOKEN}`) and are served by
the ingest service.

### `GET /fleet`

Returns the `v_fleet` rows — one per device with latest state + open-alert count. Use it
for the first paint of the overview grid, then let `device_state` Realtime keep it live.

```bash
curl -s https://vigilant.western-communication.com/fleet \
  -H "Authorization: Bearer $ENROLL_TOKEN"
```

```jsonc
[
  {
    "id": "…uuid…", "serial": "HGT0A023T6C", "identity": "AlliedHuddersfield",
    "site_name": "Allied Huddersfield", "customer": "Allied", "model": "…",
    "wan_type": "pppoe", "tags": ["allied","pharmacy"],
    "status": "online", "cpu_load": 7, "temperature": 41.5,
    "public_ip": "84.247.33.71", "ppp_sessions": 12,
    "last_seen_at": "2026-06-24T10:00:00Z", "open_alerts": 0
  }
]
```

### `GET /devices/:serial`

Returns one device's full detail: registry row, latest `device_state`, all
`interface_state` rows, `lte_state`, `neighbors`, and `mac_hosts`. Use it for the
drilldown's initial render; then subscribe to `interface_state` / `lte_state` /
`neighbors` filtered by `device_id` for live updates.

```bash
curl -s https://vigilant.western-communication.com/devices/HGT0A023T6C \
  -H "Authorization: Bearer $ENROLL_TOKEN"
```

```jsonc
{
  "device":    { "id": "…", "serial": "HGT0A023T6C", "site_name": "Allied Huddersfield", "tags": [] },
  "state":     { "status": "online", "cpu_load": 7, "public_ip": "84.247.33.71", "last_seen_at": "…" },
  "interfaces":[ { "name": "ether1", "role": "wan", "is_wan": true, "rx_bps": 1234567, "tx_bps": 234567, "running": true } ],
  "lte":       null,
  "neighbors": [ { "interface": "ether3", "identity": "phone-1", "mac": "AA:BB:CC:DD:EE:FF", "platform": "Yealink" } ],
  "mac_hosts": [ { "interface": "ether4", "mac": "AA:BB:…", "ip": "10.0.0.9", "vendor": "…" } ]
}
```

Unknown serial → `404`.

---

## 4. Recommended wiring

| View | Initial fetch | Live source |
|---|---|---|
| Overview grid | `GET /fleet` | Realtime `device_state` (+ `alerts` for badges) |
| Device drilldown | `GET /devices/:serial` | Realtime `interface_state`, `lte_state`, `neighbors` filtered by `device_id` |
| Config push timeline | (list jobs) | Realtime `config_jobs` (status transitions) |
| Alerts | (list open) | Realtime `alerts` |
| Charts (cpu/throughput/signal) | query `*_history` tables on demand | not Realtime — these are downsampled time-series |

To make a device "near-instant" on drilldown, lower its poll cadence: the agent reads
`poll_interval_s` back from the telemetry response and Vigilant drops it to `FAST_POLL_S`
while `poll_until` is in the future (set via the device's poll window). The browser still
just watches Realtime — no client polling.
