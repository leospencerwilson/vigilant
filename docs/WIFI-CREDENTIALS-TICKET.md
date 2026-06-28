# Ticket — WiFi visibility: SSID, passphrase, channel & connected clients (Chateau AC/AX)

**Goal:** in Watchman, per device show:
1. WiFi network **name (SSID)** and **password (PSK)** — gated, for NOC/support.
2. The **channel** each radio is on (frequency, width, band).
3. **Connected devices** on each channel/SSID, each with a **signal bar** (RSSI → bars).

Backend (agent + ingest + schema) work, then the frontend view.

**Status:** not started. Today the agent collects only per-interface WiFi *throughput*; no
SSID, no passphrase, no channel, and `wireless_clients` is unpopulated.

---

## ⚠️ Security — decide this first

Displaying a passphrase means the plaintext PSK lands in Supabase and is served to a
browser. This is **customer network credentials** (Allied pharmacy estate etc.). Risks:
DB backups, anyone with Supabase/SQL access, any Watchman user, request logs, screenshots.

Pick a posture before building (the schema/agent below support all three):

| Option | How | Trade-off |
|---|---|---|
| **A. Store + mask (recommended baseline)** | PSK stored in `vigilant.wifi_networks`; API returns it only to a privileged role; UI masks with an **audited "reveal"** click | Simple; plaintext at rest. Mitigate with column-level RLS + DB-at-rest encryption + restricted backups. |
| **B. Store encrypted** | Encrypt PSK with a key held only by the ingest/proxy (pgcrypto or app-side); decrypt on authorized read | No plaintext at rest; key management overhead |
| **C. On-demand, never stored** | Don't store the PSK; a privileged Watchman action triggers a one-off agent fetch returned through the proxy and shown once | Lowest exposure; needs an agent command channel + is only as live as the fetch |

Non-negotiables regardless of option:
- **SSID is fine to store/show broadly; the passphrase is gated** to an explicit role/permission.
- **Never log the passphrase** (agent, ingest, proxy, worker) — same rule as the bearer tokens.
- **Audit every reveal/read** of a passphrase (who, which device, when) in `audit_log`.
- Mask by default in the UI; reveal is a deliberate, logged action.

> Recommend **A** for v1 (with RLS + reveal audit), with **B** as a fast-follow if a security
> review wants no plaintext at rest. Confirm the posture before merging the schema.

---

## RouterOS collection — AC vs AX differ

Two different driver trees. The agent must detect which is present and branch. **Verify the
exact field names on real firmware** before shipping (ROS health/wifi fields are
version-dependent); read defensively with `:do {…} on-error={}` like the existing health block.

### AC — legacy `wireless` package (`/interface/wireless`)
- SSID per WLAN: `/interface/wireless print` → `ssid` (also `disabled`, `band`, `mode`).
- PSK lives in the **security profile** referenced by the WLAN's `security-profile`:
  ```
  :foreach w in=[/interface/wireless find] do={
    :local if  [/interface/wireless get $w name]
    :local ssid [/interface/wireless get $w ssid]
    :local sp   [/interface/wireless get $w security-profile]
    :local psk  ""
    :do { :set psk [/interface/wireless/security-profiles get [find name=$sp] wpa2-pre-shared-key] } on-error={}
    :if ($psk = "") do={ :do { :set psk [/interface/wireless/security-profiles get [find name=$sp] wpa-pre-shared-key] } on-error={} }
    # emit { interface=$if, driver="ac", ssid=$ssid, passphrase=$psk, security_profile=$sp }
  }
  ```
  (auth type from the profile's `authentication-types` / `mode`.)

### AX — wifiwave2 `wifi` package (`/interface/wifi`)
- SSID may be inline or via a named configuration; passphrase inline or via a `security`
  profile. Read both:
  ```
  :foreach w in=[/interface/wifi find] do={
    :local if   [/interface/wifi get $w name]
    :local ssid ""
    :do { :set ssid [/interface/wifi get $w ssid] } on-error={}
    :if ($ssid = "") do={ :do { :set ssid [/interface/wifi get $w configuration.ssid] } on-error={} }
    :local psk ""
    :do { :set psk [/interface/wifi get $w security.passphrase] } on-error={}
    # if a named security profile is used, resolve it:
    :if ($psk = "") do={ :do {
      :local sec [/interface/wifi get $w security]
      :set psk [/interface/wifi/security get [find name=$sec] passphrase]
    } on-error={} }
    # emit { interface=$if, driver="ax", ssid=$ssid, passphrase=$psk }
  }
  ```
- A Chateau may also expose a guest/second SSID and a separate 2.4/5 GHz radio — emit one
  row per WLAN interface; include `band` where readable.

### Channel (operating frequency/width) — per radio
Read the *actual* operating channel (what it's really on, incl. after DFS/auto), not just
the configured one — this is the existing Yealink-on-Allied DFS work's blind spot.
- **AC:** `/interface/wireless monitor <if> once` → `channel` (e.g. `5180/20/ac`),
  `frequency`, `band`, plus `noise-floor`, `overall-tx-ccq`. Configured fallback:
  `/interface/wireless get <if> channel-width` / `frequency`.
  ```
  :do { :set chan [/interface/wireless monitor $if once as-value] } on-error={}
  # chan->channel, chan->frequency, chan->"noise-floor"
  ```
- **AX:** `/interface/wifi monitor <if> once as-value` → `channel` (freq/width/band), or
  `/interface/wifi/radio print` for the radio's current channel. Configured fallback:
  `/interface/wifi get <if> channel.frequency` / `channel.width`.
- Emit `channel`, `frequency_mhz`, `width_mhz`, `band` on each wifi row.

### Connected clients (registration table) — per WLAN, with signal
One row per associated station. **AC and AX use different trees** (verify fields on firmware):
- **AC:** `/interface/wireless/registration-table print` → `mac-address`,
  `signal-strength` (dBm, e.g. `-67@…`), `tx-rate`, `rx-rate`, `tx-ccq`, `uptime`, `interface`.
- **AX:** `/interface/wifi/registration-table print` → `mac-address`, `signal` (dBm),
  `tx-rate`, `rx-rate`, `uptime`, `interface`.
- Parse `signal-strength` to a plain dBm int (strip the `@rate` suffix on AC).
- Enrich `mac` → vendor via the existing OUI lookup server-side (don't make the agent do it).
- Cadence: **medium** (clients come and go) — faster than the SSID/PSK slow tick but not the
  fast system tick; e.g. every 2–3 ticks. Worker prunes by `sampled_at` like neighbours.

### Notes
- **CAPsMAN:** if any site centralises WiFi via CAPsMAN, live SSID/PSK and the registration
  table are on the controller, not the AP — out of scope for v1, flag per-site.
- Collect SSID/PSK + channel config on the **slow tick** (changes rarely); the registration
  table on the **medium** cadence above.
- JSON-string quoting: emit passphrase as a quoted string and escape `"` / `\` (PSKs can
  contain specials) — reuse the agent's existing string-escaping for telemetry values.

---

## Telemetry payload addition

Add an optional `wifi` array to the slow-tick chunk (omit on fast ticks → "keep previous",
same convention as `mac_hosts`):

```jsonc
"wifi": [
  { "interface": "wifi1", "driver": "ax", "band": "5ghz", "ssid": "Allied-Staff",
    "passphrase": "…", "security": "wpa2-psk", "disabled": false, "hidden": false }
]
```

`telemetry.normalize` (`src/shared/telemetry.js`): add a `wifi` zod schema (all fields
optional/nullable; `driver` ∈ `ac|ax`), and **make sure the passphrase is never logged** in
any warn/debug path.

---

## Schema (`db/schema.sql`)

New table — one row per (device, interface). (For option B, store `passphrase_enc bytea`
instead of/alongside `passphrase`.)

```sql
CREATE TABLE IF NOT EXISTS wifi_networks (
    device_id    uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface    text        NOT NULL,
    driver       text,                       -- 'ac' | 'ax'
    band         text,                       -- '2ghz' | '5ghz' | etc.
    ssid         text,
    passphrase   text,                       -- ⚠️ sensitive (option A); or NULL if using passphrase_enc
    -- passphrase_enc bytea,                 -- option B: app/pgcrypto-encrypted
    security     text,                       -- 'wpa2-psk' | 'wpa3' | 'open' | …
    disabled     boolean,
    hidden       boolean,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface)
);
CREATE INDEX IF NOT EXISTS wifi_networks_device_idx ON wifi_networks (device_id);
```

**Realtime/RLS:** Do **not** blanket-add `passphrase` to the broad frontend grants. Either
(a) keep `wifi_networks` out of the general SELECT grant and only expose the passphrase via
the gated proxy endpoint below, or (b) use column/row RLS so the passphrase column is
readable only by a privileged role. SSID can be in the normal read set.

---

## Ingest / store

- `store.pg.js` / `store.mem.js`: add `upsertWifiNetworks(deviceId, rows)` (upsert by
  `(device_id, interface)`, stamp `last_seen_at`), and include wifi rows in
  `getDeviceDetail` (SSID always; passphrase only for the privileged path — see API).
- `handlers.js` telemetry step: `if (payload.wifi) await store.upsertWifiNetworks(...)`.
  Worker: prune wifi rows not seen within `NEIGHBOR_TTL_S` (same as neighbours).

---

## API exposure

- `GET /devices/:serial` → add `wifi: WifiNetwork[]` to `DeviceDetail`. **By default return
  SSID + metadata but `passphrase: null`** (so the normal drilldown never carries PSKs).
- New gated read for the actual secret, e.g. **`GET /devices/:serial/wifi/secrets`** (admin):
  returns `[{ interface, ssid, passphrase }]`, **writes an `audit_log` entry on every call**.
  Add it to the proxy allowlist behind a stricter check (a privileged Watchman role claim,
  not just any logged-in user).

```ts
export interface WifiNetwork {
  interface: string; driver: "ac" | "ax" | null; band: string | null;
  ssid: string | null; passphrase: string | null;   // null unless the gated secrets read
  security: string | null; disabled: boolean | null; hidden: boolean | null;
  last_seen_at: string;
}
```

---

## Frontend (Watchman)

- Device drilldown: a **WiFi** panel listing each SSID with band, security, enabled/hidden.
- Passphrase: render `••••••••` with a **Reveal** button. Reveal calls the gated
  `…/wifi/secrets` endpoint (not the general detail), shows the value transiently, and the
  call is audited server-side. Hide on blur/navigation; offer copy-to-clipboard.
- Gate the Reveal control behind the privileged role; hide it entirely for others.
- Handle empty/`null` (no WiFi, CAPsMAN-managed, or not yet collected) gracefully.

---

## Acceptance
- AC and AX Chateaus both report SSID + passphrase (verified on one of each).
- Normal drilldown payload contains **no** passphrase; only the gated endpoint does.
- Every passphrase reveal is in `audit_log` (actor, serial, ts).
- Passphrase never appears in any log line (agent/ingest/worker/proxy).
- UI masks by default; reveal is role-gated and audited.

## Out of scope (v1)
- CAPsMAN-centralised sites (controller-held config).
- Per-client WiFi stats (`wireless_clients`) — separate ticket; AC `/interface/wireless/registration-table` vs AX `/interface/wifi/registration-table`.
- Editing SSID/PSK from Watchman (that would be a config-push job, review-gated).
