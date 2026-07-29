-- Vigilant — realtime MikroTik telemetry + config-push datastore.
-- Self-hosted Supabase (Postgres >= 15) on the WCN Cloud IaaS.
-- Isolated in its own schema so it never collides with the ops DB or Supabase internals.
--
-- Apply:  psql "$VIGILANT_DB_URL" -f db/schema.sql
-- Idempotent. DRAFT — review before applying.

BEGIN;

CREATE SCHEMA IF NOT EXISTS vigilant;
SET search_path = vigilant, public;

-- ─────────────────────────── devices (registry) ───────────────────────────
-- Natural key is the routerboard serial — stable across reboots, IP changes,
-- and re-homing onto a different circuit. We never key on IP (dynamic / CGNAT).
CREATE TABLE IF NOT EXISTS devices (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    serial          text        NOT NULL UNIQUE,
    identity        text,                       -- /system identity
    site_name       text,                       -- human label, e.g. "Allied Huddersfield"
    customer        text,                       -- grouping (Allied / Cegedim / WCN / HSCN)
    model           text,
    ros_version     text,
    wan_type        text        CHECK (wan_type IN ('pppoe','sim','dhcp','static','unknown'))
                                DEFAULT 'unknown',
    tags            text[]      NOT NULL DEFAULT '{}',
    expected        boolean     NOT NULL DEFAULT true,   -- should this device be online?
    poll_interval_s int         NOT NULL DEFAULT 10,     -- agent tick; UI lowers this on drilldown
    poll_until      timestamptz,                -- temporary fast-poll window (drilldown), then revert
    agent_version   text,
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    notes           text
);

-- ─────────────────────────── device_state (latest snapshot) ───────────────
-- One row per device, UPSERTed every tick. Bounded row count → cheap live panel.
-- This is the table the overview grid subscribes to via Supabase Realtime.
CREATE TABLE IF NOT EXISTS device_state (
    device_id        uuid        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    status           text        NOT NULL DEFAULT 'unknown'
                                 CHECK (status IN ('online','stale','offline','unknown')),
    uptime_s         bigint,
    cpu_load         int,                       -- percent
    free_memory      bigint,
    total_memory     bigint,
    free_hdd         bigint,
    temperature      numeric,                   -- /system health, where supported
    voltage          numeric,
    public_ip        inet,
    ros_version      text,
    firmware         text,
    default_route    boolean,
    pppoe_running    boolean,
    ppp_sessions     int,                       -- active PPP/SSTP/L2TP sessions (concentrators)
    dhcp_leases      int,
    conn_count       int,                       -- firewall connection-tracking entries
    lte_signal       int,                       -- RSRP/dBm where SIM present (also in lte_state)
    cpu_temperature  numeric,
    board_temperature numeric,
    fan1_speed       int,
    fan2_speed       int,
    write_sect_total bigint,                     -- flash-wear trend
    firmware_current text,
    firmware_upgrade text,                       -- if != current → firmware-behind
    ntp_synced       boolean,
    netwatch_down    int,                        -- count of monitored hosts currently down
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    raw              jsonb                       -- full last payload, for fields not yet promoted to columns
);
CREATE INDEX IF NOT EXISTS device_state_status_idx   ON device_state (status);
CREATE INDEX IF NOT EXISTS device_state_lastseen_idx ON device_state (last_seen_at);

-- ─────────────────────────── interface_state (latest per port) ────────────
-- One row per (device, interface), UPSERTed every tick. rx_bps/tx_bps are
-- computed server-side from the delta of the cumulative byte counters.
CREATE TABLE IF NOT EXISTS interface_state (
    device_id    uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         text        NOT NULL,
    type         text,                           -- ether / bridge / vlan / pppoe-out / lte / ...
    comment      text,
    -- physical / link
    plugged      boolean,                        -- cable in + link up (ethernet status=link-ok)
    running      boolean,
    disabled     boolean,
    speed        text,                           -- negotiated rate, e.g. "1Gbps"
    full_duplex  boolean,
    last_link_up_at   timestamptz,
    last_link_down_at timestamptz,
    link_downs   int,                            -- flap counter — high = dodgy cable/port
    -- role / topology
    role         text,                           -- 'wan' | 'lan' | 'bridge-member' | 'trunk' | 'vpn' | 'unused' | 'disabled'
    is_wan       boolean     NOT NULL DEFAULT false,
    bridge       text,                           -- bridge this port belongs to, if any
    poe_out_status text,                         -- powered device status, where PoE
    poe_out_power  numeric,
    mac          macaddr,
    rx_bps       bigint,                         -- derived
    tx_bps       bigint,                         -- derived
    rx_byte      bigint,                         -- cumulative, as sent by agent
    tx_byte      bigint,
    rx_packet    bigint,
    tx_packet    bigint,
    rx_error     bigint,
    tx_error     bigint,
    rx_drop      bigint,
    tx_drop      bigint,
    sampled_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, name)
);
CREATE INDEX IF NOT EXISTS interface_state_device_idx ON interface_state (device_id);

-- ─────────────────────────── neighbors (what's on the other end) ──────────
-- LLDP/CDP/MNDP discovery — tells you the device plugged into each port (where it
-- advertises). For dumb endpoints that don't, fall back to the bridge host MAC table.
-- UPSERTed per (device, interface, neighbor mac); collector prunes rows not seen recently.
CREATE TABLE IF NOT EXISTS neighbors (
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface   text        NOT NULL,            -- local port the neighbor was seen on
    mac         macaddr     NOT NULL,
    identity    text,                            -- neighbor's /system identity
    address     inet,
    platform    text,                            -- e.g. "MikroTik", "Yealink", a switch vendor
    board       text,
    version     text,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface, mac)
);
CREATE INDEX IF NOT EXISTS neighbors_device_idx ON neighbors (device_id);

-- ─────────────────────────── mac_hosts (L2 fallback) ──────────────────────
-- For endpoints that don't advertise LLDP/CDP (PCs, printers, phones). Built from the
-- bridge host MAC table (mac → physical port) joined with ARP (mac → ip) by the ingest.
-- Collected on a SLOW cadence (these tables can be large on a busy LAN). The collector
-- prunes rows not seen for a while. `vendor` is an optional OUI lookup the ingest fills.
CREATE TABLE IF NOT EXISTS mac_hosts (
    device_id    uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface    text        NOT NULL,            -- physical port the MAC was learned on
    mac          macaddr     NOT NULL,
    ip           inet,                            -- from ARP, where known
    hostname     text,                            -- DHCP lease host-name — the real device identity
    comment      text,                            -- DHCP lease comment (operator label), where set
    vendor       text,                            -- OUI lookup (ingest-side), optional
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface, mac)
);
CREATE INDEX IF NOT EXISTS mac_hosts_device_idx ON mac_hosts (device_id);
-- Existing deployments: add the identity columns idempotently (CREATE TABLE above is a no-op
-- once the table exists, so new columns need an explicit ALTER).
ALTER TABLE mac_hosts ADD COLUMN IF NOT EXISTS hostname text;
ALTER TABLE mac_hosts ADD COLUMN IF NOT EXISTS comment  text;

-- ─────────────────────────── lte_state (SIM + cell + signal) ──────────────
-- One row per (device, lte interface), UPSERTed. Identifiers (iccid/imsi/imei/
-- msisdn) are static — the agent sends them on bootstrap/on-change only, not every
-- tick (querying them via AT can disrupt the data session). Signal fields update fast.
CREATE TABLE IF NOT EXISTS lte_state (
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface     text        NOT NULL,
    -- static identifiers
    iccid         text,                          -- /interface/lte/info -> uicc (the SIM number)
    imsi          text,
    imei          text,                          -- modem IMEI
    msisdn        text,                          -- phone number (subscriber-number), often blank
    operator      text,                          -- current-operator (MCC+MNC) / name
    apn           text,
    -- live state
    registration  text,                          -- registered / searching / denied
    access_tech   text,                          -- lte / lte-a / 5g-nsa
    band          text,
    earfcn        text,
    cell_id       text,                          -- current-cellid (eNB+cell)
    phy_cellid    text,
    rssi          numeric,
    rsrp          numeric,
    rsrq          numeric,
    sinr          numeric,
    cqi           int,
    session_uptime_s bigint,
    sampled_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface)
);
CREATE INDEX IF NOT EXISTS lte_state_iccid_idx ON lte_state (iccid);

CREATE TABLE IF NOT EXISTS lte_history (
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface   text        NOT NULL,
    ts          timestamptz NOT NULL,
    rsrp        numeric,
    rsrq        numeric,
    sinr        numeric,
    rssi        numeric,
    cell_id     text,
    PRIMARY KEY (device_id, interface, ts)
);
CREATE INDEX IF NOT EXISTS lte_history_ts_idx ON lte_history (ts);

-- ─────────────────────────── history (time-series, downsampled) ───────────
-- Append-only. The collector worker rolls these up (raw 24h → 1-min 7d → 5-min 90d)
-- and prunes. Partition by day if volume bites. Not Realtime — charts query on demand.
CREATE TABLE IF NOT EXISTS metrics_history (
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL,
    cpu_load    int,
    free_memory bigint,
    temperature numeric,
    ppp_sessions int,
    conn_count  int,
    PRIMARY KEY (device_id, ts)
);
CREATE INDEX IF NOT EXISTS metrics_history_ts_idx ON metrics_history (ts);

CREATE TABLE IF NOT EXISTS interface_history (
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    ts          timestamptz NOT NULL,
    rx_bps      bigint,
    tx_bps      bigint,
    rx_error    bigint,
    tx_error    bigint,
    PRIMARY KEY (device_id, name, ts)
);
CREATE INDEX IF NOT EXISTS interface_history_ts_idx ON interface_history (ts);

-- ─────────────────────────── wireless (Yealink / Wi-Fi work) ──────────────
-- WiFi RADIOS / SSIDs configured on the device. One row per WLAN interface. Populated from
-- the agent's slow tick. Works for BOTH driver stacks on the Chateau estate:
--   * AC  → legacy `wireless` package  (/interface/wireless + /interface/wireless/security-profiles)
--   * AX  → wifiwave2 `wifi` package    (/interface/wifi   + /interface/wifi/security)
-- `driver` records which stack the row came from. Full snapshot semantics: each report
-- REPLACES the device's WLAN set, so a removed/renamed SSID disappears.
-- ⚠️ `passphrase` is the plaintext PSK — sensitive. It is served only on the admin-gated
-- device-detail API and masked-by-default in the UI (revealed on an explicit click). Never log it.
CREATE TABLE IF NOT EXISTS wifi_networks (
    device_id    uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface    text        NOT NULL,
    driver       text,                           -- 'ac' | 'ax'
    band         text,                           -- '2ghz' | '5ghz' | free-form from ROS
    ssid         text,
    passphrase   text,                           -- ⚠️ plaintext PSK (WPA2/WPA3 pre-shared key)
    security     text,                           -- 'wpa2-psk' | 'wpa3' | 'open' | profile name
    channel      text,                           -- operating channel string, e.g. '5180/20/ac'
    frequency_mhz int,                           -- centre frequency in MHz
    width_mhz    int,                            -- channel width in MHz
    disabled     boolean,
    hidden       boolean,                         -- SSID hidden / not broadcast
    clients      int,                             -- connected-station count (denormalised for the grid)
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface)
);
CREATE INDEX IF NOT EXISTS wifi_networks_device_idx ON wifi_networks (device_id);

-- Currently-ASSOCIATED WiFi stations (the registration table), with signal for the UI bars.
-- AC  → /interface/wireless/registration-table   AX → /interface/wifi/registration-table.
-- Full snapshot semantics: each report REPLACES the device's client set, so a station that
-- has roamed/left disappears immediately (no stale TTL needed).
CREATE TABLE IF NOT EXISTS wireless_clients (
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface   text        NOT NULL,
    mac         macaddr     NOT NULL,
    signal      int,                            -- dBm
    tx_ccq      int,
    rx_rate     text,
    tx_rate     text,
    uptime_s    bigint,
    sampled_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, interface, mac)
);
CREATE INDEX IF NOT EXISTS wireless_clients_device_idx ON wireless_clients (device_id);

-- ─────────────────────────── alerts ───────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id          bigserial   PRIMARY KEY,
    name        text        NOT NULL,
    metric      text        NOT NULL,           -- e.g. 'cpu_load','offline','temperature','rx_bps'
    comparator  text        NOT NULL CHECK (comparator IN ('>','>=','<','<=','==','offline')),
    threshold   numeric,
    for_seconds int         NOT NULL DEFAULT 0, -- sustained-for before firing
    severity    text        NOT NULL DEFAULT 'warning'
                            CHECK (severity IN ('info','warning','critical')),
    scope_tag   text,                           -- null = all devices, else only devices with this tag
    enabled     boolean     NOT NULL DEFAULT true,
    -- Notification targets for this rule (dispatched by the worker on open/clear).
    notify_email         text,                  -- comma-separated recipients (via Resend)
    notify_teams_webhook text,                  -- MS Teams incoming-webhook URL
    notify_on            text NOT NULL DEFAULT 'both'   -- 'open' | 'clear' | 'both'
                         CHECK (notify_on IN ('open','clear','both')),
    -- For metric='neighbor_down' (a device/phone behind a router dropping off LLDP/CDP/MNDP):
    -- optional case-insensitive substring the neighbour's platform must match (e.g. 'Yealink');
    -- null = any neighbour. `threshold` is the seconds-not-seen that counts as "dropped".
    neighbor_platform    text
);
-- Existing deployments: add the new columns idempotently.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS notify_email         text;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS notify_teams_webhook text;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS notify_on            text NOT NULL DEFAULT 'both';
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS neighbor_platform    text;

-- ─────────────────────────────────────────────────────────────────────────────
-- SMART TAGS
--
-- Tags are what `alert_rules.scope_tag` and `config_jobs.target_tag` select on, so a tag
-- is really a *live group*: "every SIM-WAN router", "everything below RouterOS 7.16". A
-- tag_rule owns exactly one tag and declares which devices carry it; the worker
-- re-evaluates membership each pass and adds/removes that tag on `devices.tags`.
--
-- A tag is therefore either RULE-OWNED (managed here) or MANUAL (edited in the UI) and
-- never both — otherwise the worker would overwrite an operator's edits on every tick.
-- `tag` is UNIQUE to enforce exactly that.
--
-- `conditions` is {"all":[{field,op,value}, …]} over DEVICE ATTRIBUTES only
-- (serial/identity/site_name/customer/model/ros_version/wan_type/expected). Live
-- telemetry is deliberately excluded: thresholds on state are what alert_rules already
-- do, and a tag that flapped with device state would make alert scoping circular.
-- An empty condition list matches NOTHING (never the whole fleet).
CREATE TABLE IF NOT EXISTS tag_rules (
    id          bigserial   PRIMARY KEY,
    name        text        NOT NULL,
    tag         text        NOT NULL UNIQUE,
    conditions  jsonb       NOT NULL DEFAULT '{"all":[]}'::jsonb,
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
-- devices.tags is membership-tested on every smart-tag sync and on every scope_tag /
-- target_tag lookup, so give the array an index.
CREATE INDEX IF NOT EXISTS devices_tags_gin ON devices USING gin (tags);

-- ═════════════════════════════════════════════════════════════════════════════
-- PMR VIRTUAL DESKTOP — pharmacies, counters, and their Raspberry Pi thin clients
--
-- The counter Pis need exactly what Vigilant already provides for MikroTiks: a
-- per-device enrolment token, a telemetry ingest, device_state, alert rules and
-- tags. So a Pi IS a `devices` row and reuses all of it, rather than a second
-- service growing its own copy. `pharmacies`/`counters` add only the things
-- Vigilant does not already model.
--
-- `devices.kind` is the discriminator that makes this safe. Everything existing
-- assumes RouterOS — the agent-script route serves a .rsc, config_jobs push
-- RouterOS config, and alert metrics read RouterOS fields. Without a kind, the
-- config-push path would happily target a Raspberry Pi.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'mikrotik';
DO $$ BEGIN
    ALTER TABLE devices ADD CONSTRAINT devices_kind_check
        CHECK (kind IN ('mikrotik', 'counter-pi'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS devices_kind_idx ON devices (kind);

-- ── pharmacies ───────────────────────────────────────────────────────────────
-- ADDRESSING IS DERIVED, NEVER TYPED. From systems/pmr-vpn/network-design.md, a
-- pharmacy index N gives: vlan 100+N, subnet 10.N.0.0/24, gateway 10.N.0.1,
-- PMR server 10.N.0.10, counter VM 10.N.0.(20+n), counter Pi 10.255.N.n/32.
-- Storing those would let them drift from the scheme the gateway's nftables and
-- dnsmasq config — and the provisioning scripts — already assume.
CREATE TABLE IF NOT EXISTS pharmacies (
    id           bigserial   PRIMARY KEY,
    code         text        NOT NULL UNIQUE,          -- NHS/site code, e.g. 'RX54554'
    -- Bounded because N is both the VLAN offset (100+N) and an octet in 10.255.N.n.
    idx          int         NOT NULL UNIQUE CHECK (idx BETWEEN 1 AND 154),
    name         text        NOT NULL,
    pmr_system   text        NOT NULL DEFAULT 'proscript'
                             CHECK (pmr_system IN ('proscript', 'titan', 'other')),
    status       text        NOT NULL DEFAULT 'planned'
                             CHECK (status IN ('planned', 'building', 'live', 'suspended', 'decommissioned')),
    proxmox_node text,
    srv_vmid     int,                                  -- Proxmox VMID of the PMR server VM
    go_live_on   date,
    notes        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    vlan       int  GENERATED ALWAYS AS (100 + idx) STORED,
    subnet     text GENERATED ALWAYS AS ('10.' || idx || '.0.0/24') STORED,
    gateway_ip text GENERATED ALWAYS AS ('10.' || idx || '.0.1') STORED,
    server_ip  text GENERATED ALWAYS AS ('10.' || idx || '.0.10') STORED,
    dhcp_from  text GENERATED ALWAYS AS ('10.' || idx || '.0.100') STORED,
    dhcp_to    text GENERATED ALWAYS AS ('10.' || idx || '.0.149') STORED
);

-- ── counters ─────────────────────────────────────────────────────────────────
-- One counter = one Windows desktop VM + one Pi thin client on its own WireGuard
-- tunnel. One row because they are provisioned, replaced and retired together.
CREATE TABLE IF NOT EXISTS counters (
    id            bigserial   PRIMARY KEY,
    pharmacy_id   bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    -- Bounded so the derived VM octet (20+n) stays inside the .20–.99 counter band.
    n             int         NOT NULL CHECK (n BETWEEN 1 AND 79),
    label         text,
    status        text        NOT NULL DEFAULT 'planned'
                              CHECK (status IN ('planned', 'building', 'live', 'suspended', 'decommissioned')),
    vmid          int,                                 -- Proxmox VMID of the desktop VM
    vm_hostname   text,
    -- The Pi as a Vigilant device: this is what gives it a token, telemetry,
    -- alerting and tags for free. SET NULL on delete so retiring a Pi's device row
    -- leaves the counter (and its VM) intact.
    pi_device_id  uuid        UNIQUE REFERENCES devices(id) ON DELETE SET NULL,
    pi_hostname   text,
    pi_model      text,
    -- WireGuard identity, UNIQUE so one key cannot be enrolled twice and observed
    -- peers can be joined back to the counter that owns them.
    pi_public_key text        UNIQUE,
    pi_enrolled_at timestamptz,
    -- {"smartcard":"untested","printer":"ok","scanner":null} — the peripheral set
    -- differs per site, and NHS smartcard over the tunnel is still the open
    -- go/no-go for the whole counter model.
    peripherals   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    notes         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pharmacy_id, n)
);
CREATE INDEX IF NOT EXISTS counters_pharmacy_idx ON counters (pharmacy_id);

-- ── observed WireGuard peer state on the hub (VM 300) ────────────────────────
-- Kept separate from `counters` so live telemetry never overwrites intended
-- configuration, and so a peer that is connected but NOT registered still shows
-- up — an unknown Pi on the VPN is precisely what you want surfaced.
CREATE TABLE IF NOT EXISTS wg_peers (
    public_key       text        PRIMARY KEY,
    allowed_ips      text,
    endpoint         text,
    latest_handshake timestamptz,
    rx_bytes         bigint,
    tx_bytes         bigint,
    seen_at          timestamptz NOT NULL DEFAULT now()
);

-- The view the Desktop UI reads: intent joined to observed state, with the derived
-- addresses (which need the pharmacy's index, so they cannot be generated columns
-- on `counters`). `pi_online` uses a 3-minute handshake window — WireGuard is
-- silent when idle, but a Pi holding an RDP session handshakes well inside that,
-- so a longer window would mask a Pi that has genuinely dropped.
CREATE OR REPLACE VIEW counters_v AS
SELECT c.id, c.pharmacy_id,
       p.code AS pharmacy_code, p.name AS pharmacy_name, p.idx AS pharmacy_idx, p.vlan,
       c.n, c.label, c.status, c.vmid, c.vm_hostname,
       '10.' || p.idx || '.0.' || (20 + c.n)     AS vm_ip,
       '10.255.' || p.idx || '.' || c.n || '/32' AS pi_tunnel_ip,
       c.pi_device_id, c.pi_hostname, c.pi_model, c.pi_public_key, c.pi_enrolled_at,
       c.peripherals, c.notes,
       d.serial       AS pi_serial,
       ds.status      AS pi_agent_status,      -- from the Pi's Vigilant telemetry
       ds.last_seen_at AS pi_last_seen_at,
       w.endpoint     AS pi_endpoint,
       w.latest_handshake AS pi_last_handshake,
       w.rx_bytes AS pi_rx_bytes, w.tx_bytes AS pi_tx_bytes,
       (w.latest_handshake IS NOT NULL
        AND w.latest_handshake > now() - interval '3 minutes') AS pi_tunnel_up
  FROM counters c
  JOIN pharmacies p   ON p.id = c.pharmacy_id
  LEFT JOIN devices d ON d.id = c.pi_device_id
  LEFT JOIN device_state ds ON ds.device_id = c.pi_device_id
  LEFT JOIN wg_peers w ON w.public_key = c.pi_public_key;

-- Keep updated_at honest on the PMR tables. Without this the column exists but never
-- moves, which is worse than not having it — it reads as "nothing has changed since
-- creation" on rows that have been edited repeatedly.
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pharmacies_touch ON pharmacies;
CREATE TRIGGER pharmacies_touch BEFORE UPDATE ON pharmacies
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
DROP TRIGGER IF EXISTS counters_touch ON counters;
CREATE TRIGGER counters_touch BEFORE UPDATE ON counters
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── printers ─────────────────────────────────────────────────────────────────
-- Pharmacy printing is part of whether a counter can actually dispense, so printer
-- health belongs next to the counters rather than in a separate tool.
--
-- Stats come from an agent ON THE PHARMACY LAN (the counter Pi), because nothing in
-- the datacentre can reach a printer on a site network:
--   SNMP Printer MIB (RFC 3805) — prtMarkerLifeCount (lifetime pages),
--     prtMarkerSuppliesLevel/MaxCapacity (toner/drum), prtAlertDescription (jams)
--   IPP                          — marker-levels / printer-state-reasons on newer kit
--   CUPS (local queue)           — queue depth and failed jobs, which SNMP cannot see
--
-- `printers` therefore mixes IDENTITY (stable, may be operator-set) with OBSERVED
-- state (overwritten by each report), and records which device reported it so a stale
-- row can be traced to a Pi that has stopped polling.
CREATE TABLE IF NOT EXISTS printers (
    id             bigserial   PRIMARY KEY,
    pharmacy_id    bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    -- Which counter it serves, when that is known. SET NULL so retiring a counter does
    -- not delete a printer that is still on the wall.
    counter_id     bigint      REFERENCES counters(id) ON DELETE SET NULL,
    -- CUPS queue name or the operator's label. Unique per site so repeated reports
    -- update one row rather than growing duplicates.
    name           text        NOT NULL,
    address        text,                              -- IP/hostname on the pharmacy LAN
    make           text,
    model          text,
    serial         text,
    discovered_via text        CHECK (discovered_via IN ('snmp', 'ipp', 'cups', 'manual')),
    notes          text,
    -- ── observed ──
    status         text,                              -- idle | printing | stopped | unreachable
    state_reasons  text,                              -- 'media-jam', 'toner-low', …
    page_count     bigint,                            -- lifetime pages (counter, not a rate)
    -- [{name,type,level,max_capacity,pct}] — level/max kept raw as reported, because a
    -- percentage alone loses the difference between "unknown" and "empty".
    supplies       jsonb       NOT NULL DEFAULT '[]'::jsonb,
    queue_depth    int,
    jobs_failed    int,
    reported_by    uuid        REFERENCES devices(id) ON DELETE SET NULL,
    last_seen_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (pharmacy_id, name)
);
CREATE INDEX IF NOT EXISTS printers_pharmacy_idx ON printers (pharmacy_id);

DROP TRIGGER IF EXISTS printers_touch ON printers;
CREATE TRIGGER printers_touch BEFORE UPDATE ON printers
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- Adds the derived bits the UI needs: the lowest supply level (what you actually alert a
-- human on) and whether the report has gone stale. `stale` is 15 minutes because printer
-- polling is deliberately infrequent — toner does not move fast, and hammering a printer's
-- SNMP agent can wedge older devices.
CREATE OR REPLACE VIEW printers_v AS
SELECT pr.*,
       ph.code AS pharmacy_code,
       ph.name AS pharmacy_name,
       c.n     AS counter_n,
       (SELECT min((s->>'pct')::numeric)
          FROM jsonb_array_elements(pr.supplies) s
         WHERE (s->>'pct') ~ '^[0-9.]+$')            AS min_supply_pct,
       (pr.last_seen_at IS NULL
        OR pr.last_seen_at < now() - interval '15 minutes') AS stale
  FROM printers pr
  JOIN pharmacies ph ON ph.id = pr.pharmacy_id
  LEFT JOIN counters c ON c.id = pr.counter_id;

-- Recent device log lines (agent-collected, fetch-noise stripped) for the device view.
ALTER TABLE device_state ADD COLUMN IF NOT EXISTS recent_logs jsonb;

-- Per-device log HISTORY (agent-collected, fetch-noise stripped). 30-day retention (worker
-- prune). The agent re-sends its recent window each slow tick, so the PK dedups overlap;
-- genuinely new lines accumulate. log_time defaults '' so it can sit in the PK.
CREATE TABLE IF NOT EXISTS device_logs (
    device_id  uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    seen_at    timestamptz NOT NULL DEFAULT now(),
    log_time   text        NOT NULL DEFAULT '',
    topics     text,
    message    text        NOT NULL,
    PRIMARY KEY (device_id, log_time, message)
);
CREATE INDEX IF NOT EXISTS device_logs_device_seen_idx ON device_logs (device_id, seen_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id          bigserial   PRIMARY KEY,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id     bigint      REFERENCES alert_rules(id),
    severity    text        NOT NULL,
    -- 'pending' = condition firing but not yet held for the rule's for_seconds (anti-flap; not
    -- counted as open, not notified). Promotes to 'open' once sustained; reset to gone if it
    -- stops firing first.
    state       text        NOT NULL DEFAULT 'open' CHECK (state IN ('open','acked','cleared','pending')),
    detail      text,
    opened_at   timestamptz NOT NULL DEFAULT now(),  -- while pending, this is the firing-since time
    acked_at    timestamptz,
    acked_by    text,
    cleared_at  timestamptz
);
CREATE INDEX IF NOT EXISTS alerts_open_idx ON alerts (device_id, state) WHERE state = 'open';
-- Existing deployments: widen the state CHECK to allow 'pending'.
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_state_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_state_check CHECK (state IN ('open','acked','cleared','pending'));

-- ─────────────────────────── config push ───────────────────────────
CREATE TABLE IF NOT EXISTS config_jobs (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id      uuid        REFERENCES devices(id) ON DELETE CASCADE, -- null = group job
    target_tag     text,                          -- group target (with canary promotion)
    is_canary      boolean     NOT NULL DEFAULT false,
    kind           text        NOT NULL CHECK (kind IN ('snippet','full')),
    rsc_text       text        NOT NULL,
    rsc_sha256     text        NOT NULL,           -- device verifies before /import
    status         text        NOT NULL DEFAULT 'draft'
                               CHECK (status IN ('draft','approved','fetched','applying',
                                                 'applied','failed','rolled_back','cancelled')),
    confirm_window_s int       NOT NULL DEFAULT 300,   -- dead-man's-switch keep-window
    created_by     text        NOT NULL,
    approved_by    text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    approved_at    timestamptz,
    fetched_at     timestamptz,
    applied_at     timestamptz,
    result_log     text,
    rollback_ref   text                            -- snapshot taken pre-apply
);
CREATE INDEX IF NOT EXISTS config_jobs_pickup_idx ON config_jobs (device_id, status)
    WHERE status = 'approved';

CREATE TABLE IF NOT EXISTS config_snapshots (
    id          bigserial   PRIMARY KEY,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL DEFAULT now(),
    rsc_text    text        NOT NULL,
    rsc_sha256  text        NOT NULL,
    source      text        NOT NULL DEFAULT 'nightly'  -- 'nightly' | 'pre-apply' | 'manual'
);
CREATE INDEX IF NOT EXISTS config_snapshots_device_idx ON config_snapshots (device_id, ts DESC);

-- ─────────────────────────── speedtest jobs ───────────────────────────
-- Operator-triggered, device-pulled active bandwidth test. The DEVICE pulls a pending job
-- (GET /speedtest/pending), downloads bytes_down from GET /speedtest/down and uploads
-- bytes_up to POST /speedtest/up; the SERVER times each transfer (wall-clock to stream the
-- bytes ≈ throughput) and writes down_bps/up_bps — so the agent needs no sub-second clock.
-- ⚠️ An active test deliberately saturates the WAN; it is operator-gated + audit-logged.
CREATE TABLE IF NOT EXISTS speedtest_jobs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status        text        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','running','done','failed','cancelled')),
    bytes_down    bigint      NOT NULL DEFAULT 26214400,   -- 25 MiB
    bytes_up      bigint      NOT NULL DEFAULT 8388608,     -- 8 MiB
    down_bps      bigint,                                   -- server-measured
    up_bps        bigint,                                   -- server-measured
    requested_by  text        NOT NULL,
    result_log    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);
CREATE INDEX IF NOT EXISTS speedtest_jobs_pickup_idx ON speedtest_jobs (device_id, status)
    WHERE status = 'pending';

-- ─────────────────────────── enrolment / secrets ───────────────────────────
-- Per-device bearer for ingest auth — replaces the single shared X-API-Key.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    device_id   uuid        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    token_hash  text        NOT NULL,            -- store a hash, compare on ingest
    issued_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

-- Centrally-managed agent script that the router bootstrap fetches.
CREATE TABLE IF NOT EXISTS agent_scripts (
    version     int         PRIMARY KEY,
    rsc_text    text        NOT NULL,
    rsc_sha256  text        NOT NULL,
    notes       text,
    published_at timestamptz NOT NULL DEFAULT now(),
    is_current  boolean     NOT NULL DEFAULT false
);

-- ─────────────────────────── audit ───────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id      bigserial   PRIMARY KEY,
    ts      timestamptz NOT NULL DEFAULT now(),
    actor   text        NOT NULL,
    action  text        NOT NULL,
    serial  text,
    details text
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);

-- ─────────────────────────── views ───────────────────────────
CREATE OR REPLACE VIEW v_fleet AS
  SELECT d.id, d.serial, d.identity, d.site_name, d.customer, d.model, d.wan_type, d.tags,
         s.status, s.cpu_load, s.temperature, s.public_ip, s.ppp_sessions, s.last_seen_at,
         (SELECT count(*) FROM alerts a WHERE a.device_id = d.id AND a.state = 'open') AS open_alerts
  FROM devices d
  LEFT JOIN device_state s ON s.device_id = d.id;

-- Realtime: add the live tables to the supabase_realtime publication so the
-- existing Watchman frontend / console get pushed changes without polling.
-- (Run once; ignore "already member" errors on re-apply.)
DO $$
DECLARE t text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    -- NB: wifi_networks is intentionally NOT published — it holds the plaintext PSK, which
    -- must never be broadcast over Realtime. Frontends read WiFi config via select (the PSK
    -- column is withheld by a column-level grant) and the PSK itself via the admin REST path.
    FOREACH t IN ARRAY ARRAY['device_state','interface_state','lte_state','neighbors','config_jobs','alerts','wireless_clients'] LOOP
      -- Per-table sub-block so one failure (already a member, or no privilege to alter
      -- the publication) never aborts the others or the outer transaction.
      BEGIN
        EXECUTE format('ALTER PUBLICATION supabase_realtime ADD TABLE vigilant.%I', t);
      EXCEPTION
        -- Swallow ANY failure here (already a member, no privilege, or the publication is
        -- defined FOR ALL TABLES — which raises a non-duplicate error). Realtime wiring is
        -- best-effort and must NEVER abort the migration transaction (this aborted the whole
        -- schema apply, so new tables like speedtest_jobs were never created).
        WHEN OTHERS THEN
          RAISE NOTICE 'vigilant: could not add vigilant.% to supabase_realtime (%) — skipping', t, SQLERRM;
      END;
    END LOOP;
  END IF;
END $$;

-- ─────────────── Row-Level Security + grants for frontend reads ───────────────
-- Live/read frontends read these tables directly (select + Realtime) as the Supabase
-- `authenticated` role — the admin dashboard via a short-lived JWT the ingest mints after
-- checking the admin token (POST /realtime/config), and Watchman via the logged-in user's
-- Supabase session. The public `anon` role is granted NOTHING: a leaked anon key on its own
-- cannot read any device data.
-- ⚠️ wifi_networks.passphrase (plaintext PSK) is withheld via a COLUMN-level grant, and the
-- table is kept OUT of the Realtime publication (above) — the PSK only ever travels the
-- admin-gated REST path, never a select* or a broadcast.
-- Wrapped so a non-Supabase database (no `authenticated` role — e.g. a bare test pg) doesn't
-- abort the migration; it just logs and skips.
DO $$
DECLARE t text;
BEGIN
  EXECUTE 'GRANT USAGE ON SCHEMA vigilant TO authenticated';

  FOREACH t IN ARRAY ARRAY[
    'devices','device_state','interface_state','lte_state','neighbors','mac_hosts',
    'wireless_clients','config_jobs','alerts','metrics_history','interface_history',
    'lte_history','speedtest_jobs'
  ] LOOP
    EXECUTE format('ALTER TABLE vigilant.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('GRANT SELECT ON vigilant.%I TO authenticated', t);
    -- Drop+recreate so re-running migrate is idempotent.
    EXECUTE format('DROP POLICY IF EXISTS %I ON vigilant.%I', t || '_sel_authed', t);
    EXECUTE format('CREATE POLICY %I ON vigilant.%I FOR SELECT TO authenticated USING (true)', t || '_sel_authed', t);
  END LOOP;

  -- wifi_networks: RLS + column-level SELECT that OMITS passphrase (and the raw comment).
  EXECUTE 'ALTER TABLE vigilant.wifi_networks ENABLE ROW LEVEL SECURITY';
  EXECUTE 'GRANT SELECT (device_id, interface, driver, band, ssid, security, channel, frequency_mhz, width_mhz, disabled, hidden, clients, last_seen_at) ON vigilant.wifi_networks TO authenticated';
  EXECUTE 'DROP POLICY IF EXISTS wifi_networks_sel_authed ON vigilant.wifi_networks';
  EXECUTE 'CREATE POLICY wifi_networks_sel_authed ON vigilant.wifi_networks FOR SELECT TO authenticated USING (true)';

  -- v_fleet view (RLS lives on the underlying tables; the view just needs a grant).
  EXECUTE 'GRANT SELECT ON vigilant.v_fleet TO authenticated';
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'vigilant: RLS/grants step skipped (%) — apply manually on the Supabase DB if needed', SQLERRM;
END $$;

COMMIT;
