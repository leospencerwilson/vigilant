# Importing Vigilant into Watchman

A self-contained guide for wiring the **Watchman** web UI (Vite SPA on Vercel) to the
**Vigilant** backend. Copy this file into the Watchman repo (e.g. `docs/vigilant.md`) and
follow it top to bottom.

Vigilant is the engine: a RouterOS agent pushes telemetry → the ingest service writes it
into a self-hosted Supabase (`vigilant` schema) → Watchman renders it. Watchman consumes
Vigilant via **Supabase Realtime + direct supabase-js queries**:

1. **Supabase Realtime (primary, "live")** — subscribe to `vigilant.*` tables, render row
   changes as they land. No client polling.
2. **First paint** — a direct supabase-js `.select()` against the `vigilant` tables/views
   under the user's auth (RLS). No admin token in the browser.

> **Why not Vigilant's `GET /fleet` read API?** That endpoint exists for SSR frameworks and
> requires an admin bearer (`ENROLL_TOKEN`). In a **Vite SPA every env var is baked into the
> public bundle at build time** — you cannot keep a bearer secret client-side. So Watchman
> reads the same data straight from Supabase under the logged-in user's RLS instead. If you
> ever truly need the read API, proxy it through a Vercel serverless function — see §5b.

---

## 0. Prerequisites

- Vigilant deployed (schema applied via `npm run migrate`). Default public origin:
  `https://vigilant.western-communication.com`.
- The `vigilant` schema's six Realtime tables are in the `supabase_realtime` publication
  (the schema's `DO $$…$$` block handles this; re-run `migrate` if Realtime was enabled
  after the tables existed).
- Watchman has `@supabase/supabase-js` installed (the SPA client — not `@supabase/ssr`,
  which is for server frameworks).

---

## 1. Environment variables

Vite only exposes vars prefixed `VITE_` to client code, via `import.meta.env`. These are
**public** — baked into the bundle at build time. The Supabase anon key is designed to be
public (RLS guards the data), so this is fine. Add to `.env` locally and to the Vercel
project's **Environment Variables** (all environments):

```sh
# Supabase — same self-hosted instance Vigilant writes to. Both are public (RLS-guarded).
VITE_SUPABASE_URL=https://<your-supabase-host>
VITE_SUPABASE_ANON_KEY=<anon key>
```

> ⚠️ **Never** put `ENROLL_TOKEN` / any admin secret behind a `VITE_` var — it would ship to
> every visitor. If you add the optional read-API proxy (§5b), that token is a *Vercel
> Function* env var (no `VITE_` prefix) and stays server-side.

On Vercel, set the project's **Framework Preset** to *Vite*; build `npm run build`, output
`dist`. SPA routing rewrite (`vercel.json`):

```json
{ "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }] }
```

---

## 2. Realtime tables

Six tables are published for Realtime. Subscribe only to what a view needs:

| Table | Grain | Drives | Notes |
|---|---|---|---|
| `device_state` | 1 row / device (upsert) | Overview grid tiles | Bounded, cheap. Status: `online`/`stale`/`offline`/`unknown`. Mostly `UPDATE`. |
| `interface_state` | 1 row / device·port (upsert) | Port view: `rx_bps`/`tx_bps` (server-derived), role, link | Filter by `device_id` on drilldown. |
| `lte_state` | 1 row / device·lte iface | SIM/signal panel: rsrp/rsrq/sinr/rssi, operator, band, cell | Signal updates fast; identifiers rarely. |
| `neighbors` | 1 row / device·iface·mac | "What's plugged into each port" (LLDP/CDP/MNDP) | Worker prunes stale rows. |
| `config_jobs` | 1 row / job | Config-push timeline: `draft → approved → fetched → applying → applied/failed/rolled_back/cancelled` | Watch status transitions. |
| `alerts` | 1 row / alert | Alert banner/list: `open`/`acked`/`cleared`, severity, detail | `v_fleet.open_alerts` gives per-device counts. |

**Not Realtime** (query on demand): `metrics_history`, `interface_history`, `lte_history`
(charts), `config_snapshots`, `audit_log`, `mac_hosts` (large — read via `GET /devices/:serial`).

The `v_fleet` view (used by `GET /fleet`) joins `devices` + `device_state` + open-alert count.
Use it for the initial list; subscribe to `device_state` for live updates.

---

## 3. Supabase client — point it at the `vigilant` schema

Vigilant lives in its own schema. Create one shared client (a singleton — don't call
`createClient` per render):

```ts
// src/lib/vigilant/client.ts
import { createClient } from "@supabase/supabase-js";

export const vigilant = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
  { db: { schema: "vigilant" } } // Vigilant runs in its own schema, not `public`
);
```

> If Watchman already has a `public`-schema Supabase client for auth/other data, keep it and
> add this second one for Vigilant — a client is pinned to one schema via `db.schema`.
> (Auth/session is shared across clients on the same URL, so the user's JWT still applies.)

---

## 4. Realtime subscriptions

### 4a. Live overview grid (`device_state`)

```ts
import { vigilant } from "@/lib/vigilant/client";

const channel = vigilant
  .channel("vigilant:device_state")
  .on(
    "postgres_changes",
    { event: "*", schema: "vigilant", table: "device_state" },
    (payload) => {
      // payload.new = the upserted DeviceState row (see types below)
      applyDeviceState(payload.new as DeviceState);
    }
  )
  .subscribe();

// cleanup
vigilant.removeChannel(channel);
```

### 4b. Device drilldown — ports for one device only

```ts
const portChannel = vigilant
  .channel(`vigilant:interface_state:${deviceId}`)
  .on(
    "postgres_changes",
    {
      event: "*",
      schema: "vigilant",
      table: "interface_state",
      filter: `device_id=eq.${deviceId}`,
    },
    (payload) => applyInterfaceState(payload.new as InterfaceState)
  )
  .subscribe();
```

Same pattern for `lte_state`, `neighbors`, `config_jobs`, `alerts` — swap `table`, and add
`filter: \`device_id=eq.${deviceId}\`` where you want a single device's rows.

> **RLS / grants — now provided.** Apply **`docs/VIGILANT-RLS.sql`** (also embedded in
> `db/schema.sql`) once as the postgres superuser. It grants the Supabase **`authenticated`**
> role `SELECT` + adds RLS `SELECT` policies on `v_fleet`, `devices`, and the live tables —
> so a logged-in Watchman user (anon key + their user JWT) can read and subscribe, while the
> public **`anon`** role gets **nothing**. The ingest still writes via its own scoped `pg` role.
>
> ⚠️ **WiFi passphrase:** `wifi_networks.passphrase` is withheld by a column-level grant and
> the table is **not** in the Realtime publication — so a `select('*')` won't return the PSK
> and it's never broadcast. Read SSID/channel/clients via Supabase as normal; fetch the **PSK
> only through the Vercel proxy** (`GET /devices/:serial`, admin-gated) when a user reveals it.
> For multi-tenant scoping, see the per-customer policy note at the bottom of `VIGILANT-RLS.sql`.

### 4c. React hook — first paint + live, in one place

For a SPA the cleanest pattern is: query once for the initial rows, then subscribe for live
updates. Both go through the same `vigilant` client (RLS applies under the user's session).

```ts
// src/hooks/useFleet.ts
import { useEffect, useState } from "react";
import { vigilant } from "@/lib/vigilant/client";
import type { FleetRow, DeviceState } from "@/lib/vigilant/types";

export function useFleet() {
  const [byId, setById] = useState<Map<string, FleetRow>>(new Map());

  useEffect(() => {
    let alive = true;

    // First paint: query the v_fleet view directly (no admin token needed).
    vigilant
      .from("v_fleet")
      .select("*")
      .then(({ data, error }) => {
        if (error) { console.error("[vigilant] fleet load", error); return; }
        if (alive && data) setById(new Map(data.map((d: FleetRow) => [d.id, d])));
      });

    // Live: device_state upserts. Merge onto the matching fleet row by device id.
    const channel = vigilant
      .channel("vigilant:device_state")
      .on(
        "postgres_changes",
        { event: "*", schema: "vigilant", table: "device_state" },
        (payload) => {
          const row = (payload.new ?? payload.old) as DeviceState;
          setById((m) => {
            const next = new Map(m);
            const existing = next.get(row.device_id);
            if (existing) next.set(row.device_id, { ...existing, ...row });
            return next;
          });
        }
      )
      .subscribe();

    return () => { alive = false; vigilant.removeChannel(channel); };
  }, []);

  return [...byId.values()];
}
```

> `v_fleet`'s primary key is the device `id`; `device_state` keys on `device_id` — they're
> the same uuid, which is why the merge above works. If you'd rather drive the grid purely
> off `device_state` (no view), query `device_state` for first paint instead and join device
> registry fields separately.

---

## 5. First paint — read directly from Supabase

In a SPA you don't need Vigilant's admin read API; query the same tables/views with the
`vigilant` client under the user's RLS.

### 5a. Direct queries (the default)

```ts
// Fleet (overview grid) — the v_fleet view: device + state + open-alert count
const { data: fleet } = await vigilant.from("v_fleet").select("*");

// One device's drilldown — fetch state, ports, lte, neighbors in parallel by device id
async function loadDevice(deviceId: string) {
  const [state, interfaces, lte, neighbors] = await Promise.all([
    vigilant.from("device_state").select("*").eq("device_id", deviceId).maybeSingle(),
    vigilant.from("interface_state").select("*").eq("device_id", deviceId).order("name"),
    vigilant.from("lte_state").select("*").eq("device_id", deviceId).maybeSingle(),
    vigilant.from("neighbors").select("*").eq("device_id", deviceId),
  ]);
  return {
    state: state.data, interfaces: interfaces.data ?? [],
    lte: lte.data, neighbors: neighbors.data ?? [],
  };
}

// To resolve a route like /device/:serial → id, look it up in the devices registry:
const { data: dev } = await vigilant
  .from("devices").select("id, serial, site_name, tags").eq("serial", serial).maybeSingle();
```

> This needs `SELECT` grants + RLS policies on `v_fleet`, `devices`, and the five state
> tables for the role Watchman's users authenticate as. See §0 and the RLS note in §4b.
> `mac_hosts` is large — only query it when a drilldown panel actually needs it.

### 5b. Optional: proxy Vigilant's read API through a Vercel Function

Only if you specifically want Vigilant's pre-joined `GET /devices/:serial` payload (state +
interfaces + lte + neighbors + mac_hosts in one response) rather than assembling it client-
side. The admin bearer stays server-side as a **Vercel Function** env var (no `VITE_`).

Set in Vercel project env (Functions, not exposed to client):
`VIGILANT_API_URL`, `VIGILANT_ADMIN_TOKEN` (= Vigilant's `ENROLL_TOKEN`).

```ts
// api/device/[serial].ts  — a Vercel Serverless Function (Node runtime)
export default async function handler(req: any, res: any) {
  // TODO: authenticate the caller (verify the user's Supabase JWT) before proxying.
  const r = await fetch(
    `${process.env.VIGILANT_API_URL}/devices/${encodeURIComponent(req.query.serial)}`,
    { headers: { Authorization: `Bearer ${process.env.VIGILANT_ADMIN_TOKEN}` } }
  );
  res.status(r.status).json(await r.json());
}
```

The browser then calls `/api/device/HGT0A023T6C` (same-origin, no secret). Vigilant's
`GET /devices/:serial` returns `device`, `state`, `interfaces`, `lte`, `neighbors`,
`mac_hosts`; unknown serial → `404`. `GET /fleet` returns `v_fleet` rows. Shapes match the
`DeviceDetail` / `FleetRow` types in §7.

---

## 6. Recommended wiring (per view)

| View | Initial fetch (`.select()`) | Live source (Realtime) |
|---|---|---|
| Overview grid | `from("v_fleet")` | `device_state` (+ `alerts` for badges) |
| Device drilldown | `device_state` / `interface_state` / `lte_state` / `neighbors` by `device_id` | same tables, filtered `device_id=eq.<id>` |
| Config-push timeline | `from("config_jobs")` | `config_jobs` (status transitions) |
| Alerts | `from("alerts").eq("state","open")` | `alerts` |
| Charts (cpu / throughput / signal) | `from("metrics_history"/"interface_history"/"lte_history")` | not Realtime — downsampled time-series |

**Fast drilldown:** to make a device near-instant, lower its poll cadence — the agent reads
`poll_interval_s` back from the telemetry response and Vigilant drops it to `FAST_POLL_S`
while `poll_until` is in the future. The browser still just watches Realtime.

---

## 7. TypeScript types

Generated from `db/schema.sql`. Numeric DB columns (`numeric`) arrive as JS numbers via
supabase-js; `bigint` columns can exceed `Number.MAX_SAFE_INTEGER` only for lifetime byte
counters — the derived `rx_bps`/`tx_bps` are safe.

```ts
// lib/vigilant/types.ts
export type DeviceStatus = "online" | "stale" | "offline" | "unknown";
export type WanType = "pppoe" | "sim" | "dhcp" | "static" | "unknown";

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
  lte_signal: number | null;        // RSRP/dBm
  cpu_temperature: number | null;
  board_temperature: number | null;
  fan1_speed: number | null;
  fan2_speed: number | null;
  firmware_current: string | null;
  firmware_upgrade: string | null;  // if != current → firmware-behind
  ntp_synced: boolean | null;
  netwatch_down: number | null;
  last_seen_at: string;             // ISO timestamp
  raw: unknown;                     // full last payload (jsonb)
}

export interface InterfaceState {
  device_id: string;
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
  rx_error: number | null;
  tx_error: number | null;
  rx_drop: number | null;
  tx_drop: number | null;
  sampled_at: string;
}

export interface LteState {
  device_id: string;
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
  device_id: string;
  interface: string;                // local port
  mac: string;
  identity: string | null;
  address: string | null;
  platform: string | null;          // "MikroTik" / "Yealink" / switch vendor
  board: string | null;
  version: string | null;
  last_seen_at: string;
}

export type ConfigJobStatus =
  | "draft" | "approved" | "fetched" | "applying"
  | "applied" | "failed" | "rolled_back" | "cancelled";

export interface ConfigJob {
  id: string;
  device_id: string | null;         // null = group job
  target_tag: string | null;
  is_canary: boolean;
  kind: "snippet" | "full";
  rsc_text: string;
  rsc_sha256: string;
  status: ConfigJobStatus;
  confirm_window_s: number;         // dead-man's-switch keep-window
  created_by: string;
  approved_by: string | null;
  created_at: string;
  approved_at: string | null;
  fetched_at: string | null;
  applied_at: string | null;
  result_log: string | null;
}

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

// GET /fleet row (v_fleet view: devices + device_state + open-alert count)
export interface FleetRow {
  id: string;
  serial: string;
  identity: string | null;
  site_name: string | null;
  customer: string | null;
  model: string | null;
  wan_type: WanType;
  tags: string[];
  status: DeviceStatus;
  cpu_load: number | null;
  temperature: number | null;
  public_ip: string | null;
  ppp_sessions: number | null;
  last_seen_at: string;
  open_alerts: number;
}

// GET /devices/:serial
export interface DeviceDetail {
  device: { id: string; serial: string; site_name: string | null; tags: string[]; [k: string]: unknown };
  state: DeviceState | null;
  interfaces: InterfaceState[];
  lte: LteState | null;
  neighbors: Neighbor[];
  mac_hosts: Array<{ interface: string; mac: string; ip: string | null; vendor: string | null }>;
}
```

---

## 8. Config push — read-only in the UI

Config jobs are **review-gated** and applied under Safe Mode with a dead-man's-switch
rollback. Watchman should **render** the `config_jobs` lifecycle (timeline of status
transitions) but treat apply/approve as deliberate, audited actions — see Vigilant's
`docs/RUNBOOK-config-push.md`. Never wire a one-click auto-apply: the WCN MikroTik estate is
live production.

---

## 9. Checklist

- [ ] `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY` set locally **and** in Vercel (all envs).
- [ ] No admin/`ENROLL_TOKEN` behind any `VITE_` var (it would ship to every visitor).
- [ ] `vercel.json` SPA rewrite in place; Vercel preset = Vite, output = `dist`.
- [ ] Single `vigilant` supabase-js client created with `{ db: { schema: "vigilant" } }`.
- [ ] Overview grid: `from("v_fleet")` first paint → subscribe `device_state`.
- [ ] Drilldown: parallel `.select()` by `device_id` → subscribe `interface_state`/`lte_state`/`neighbors` filtered by `device_id`.
- [ ] Alerts + config_jobs subscriptions wired.
- [ ] RLS/grants verified for the Watchman auth role on `v_fleet`, `devices`, and the six `vigilant` Realtime tables (without these, queries + subscriptions return nothing).
- [ ] Confirmed a silent subscription isn't a missing `supabase_realtime` publication (re-run `migrate`).
- [ ] (Optional) Vercel Function proxy added only if you need Vigilant's pre-joined read API — token as a Function env var, with caller auth.

> Source of truth for these contracts: Vigilant's `db/schema.sql`, `docs/CONTRACT.md`, and
> `docs/FRONTEND-INTEGRATION.md`. If a field here disagrees with the schema, the schema wins.
