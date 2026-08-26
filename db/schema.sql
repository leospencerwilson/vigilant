-- Vigilant — realtime MikroTik telemetry + config-push datastore.
-- Self-hosted Supabase (Postgres >= 15) on the WCN Cloud IaaS.
-- Isolated in its own schema so it never collides with the ops DB or Supabase internals.
--
-- Apply:  psql "$VIGILANT_DB_URL" -f db/schema.sql
-- Idempotent. DRAFT — review before applying.
--
-- ── ⛔ BEFORE APPLYING: THE DROP VIEW CHECK (B8) ─────────────────────────────
-- This file REDEFINES several views by dropping and recreating them, and the drops carry no
-- CASCADE on purpose. A bare DROP VIEW fails if anything depends on the view, and because the
-- whole file runs inside one transaction, that failure aborts the ENTIRE migration — on this
-- deployment that means the ingest crash-loops on a fresh container.
--
-- No CASCADE is the right default: cascading would silently delete somebody else's view or
-- materialised view, and finding out afterwards that a report stopped working is worse than a
-- migration that refuses to start. The cost is that the check has to happen HERE, before the
-- apply, rather than being papered over in the DDL.
--
-- Nothing in this repository depends on any of them. What this cannot see is a view, matview,
-- or RLS policy created OUTSIDE it — by hand in psql, by Supabase Studio, or by the reporting
-- work — so run this first and expect ZERO rows:
--
--   SELECT dependent_ns.nspname || '.' || dependent.relname AS dependent_object,
--          source.relname                                   AS depends_on
--     FROM pg_depend d
--     JOIN pg_rewrite r          ON r.oid = d.objid
--     JOIN pg_class  dependent   ON dependent.oid = r.ev_class
--     JOIN pg_namespace dependent_ns ON dependent_ns.oid = dependent.relnamespace
--     JOIN pg_class  source      ON source.oid = d.refobjid
--    WHERE d.classid = 'pg_rewrite'::regclass
--      AND source.relnamespace = 'vigilant'::regnamespace
--      AND source.relname IN ('printers_v', 'pharmacy_vms_v', 'counters_v', 'proxmox_vms_v',
--                             'site_hours_v', 'pmr_jobs_v')
--      AND dependent.oid <> source.oid;
--
-- A row means that object must be dropped and recreated around this apply. Do NOT "fix" it by
-- adding CASCADE to the drop below — that turns a refusal into a silent deletion of the very
-- object the query just found.

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

-- ⚠️ The PPPoE password — a SECRET. The agent historically stopped sending it; it is now
-- collected again (on request) so support can read it without a second system. It lives HERE,
-- on devices, DELIBERATELY and not on device_state, because device_state is in the
-- supabase_realtime publication (see below) and devices is not — so the secret never rides a
-- Realtime broadcast. The ingest also strips it from device_state.raw for the same reason.
-- ⛔ devices IS granted to `authenticated` (see the RLS/grants block below), so this column is
-- protected the same way the WiFi PSK is: by a COLUMN-LEVEL grant that omits it. A table-level
-- `GRANT SELECT ON devices` would expose every site's PPPoE password in plaintext to any logged-in
-- dashboard user. If you add a column to devices, add it to that column list too — a column added
-- without being listed is simply unreadable by the dashboard, which fails safe.
-- It is served only through the ingest API's device-detail endpoint, masked by default.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS pppoe_password text;

-- ── pharmacies ───────────────────────────────────────────────────────────────
-- ADDRESSING IS DERIVED-BY-DEFAULT, and OVERRIDABLE. From systems/pmr-vpn/network-design.md,
-- a pharmacy index N gives: vlan 100+N, subnet 10.200.N.0/<prefix>, gateway 10.200.N.1,
-- PMR server 10.200.N.10, counter VM 10.200.N.(base+n), counter Pi 10.255.N.n/32.
-- The pharmacy LAN lives in 10.200.0.0/16 (index in the THIRD octet) so it can never collide
-- with the 10.10.x.x VLAN/NHS space or the 10.255.x tunnel transit.
-- vlan and the network address (10.200.N.0) still follow mechanically from the index and
-- cannot be edited — they are baked into every counter Pi's WireGuard AllowedIPs. Everything
-- else (subnet size, gateway, server, DHCP pool, DNS, domain, lease, NTP) is filled from the
-- index by the pharmacies_fill_net() trigger but can be set per-site, so a site can diverge
-- from the default plan without the schema pretending it never happens.
--
-- The default prefix is /27 (30 usable hosts) — a pharmacy LAN never reaches the ~25-device
-- ceiling, so a whole /24 was 8x wasted space. Every site is /27: nothing is in production on
-- the virtual desktops yet, so the netmig block below moves existing rows to /27 outright rather
-- than preserving a legacy /24. A site can still be widened per-row (prefix_len is editable).
CREATE TABLE IF NOT EXISTS pharmacies (
    id           bigserial   PRIMARY KEY,
    code         text        NOT NULL UNIQUE,          -- NHS/site code, e.g. 'RX54554'
    -- Bounded because N is both the VLAN offset (100+N) and an octet in 10.255.N.n.
    idx          int         NOT NULL UNIQUE CHECK (idx BETWEEN 1 AND 154),
    name         text        NOT NULL,
    pmr_system   text        NOT NULL DEFAULT 'proscript'
                             CHECK (pmr_system IN ('proscript', 'pharmacy_manager', 'nexphase', 'analyst', 'titan', 'rxweb', 'other')),
    status       text        NOT NULL DEFAULT 'planned'
                             CHECK (status IN ('planned', 'building', 'live', 'suspended', 'decommissioned')),
    proxmox_node text,
    srv_vmid     int,                                  -- Proxmox VMID of the PMR server VM
    go_live_on   date,
    notes        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    -- prefix sizes the subnet; the network address is always 10.200.idx.0, so shrinking the
    -- prefix only tightens how much of that /24-worth of space is in-network. /27 = .0–.31.
    prefix_len  int  NOT NULL DEFAULT 27 CHECK (prefix_len BETWEEN 24 AND 30),
    vlan        int  GENERATED ALWAYS AS (100 + idx) STORED,
    subnet      text GENERATED ALWAYS AS ('10.200.' || idx || '.0/' || prefix_len) STORED,
    -- Plain columns, filled from idx by pharmacies_fill_net() when left NULL (see below).
    -- Editable so a site can override any single value; NULL them to fall back to the default.
    gateway_ip  text,                                 -- .1 by default
    server_ip   text,                                 -- .10 by default (PMR server)
    dhcp_from   text,                                 -- /27 default .21
    dhcp_to     text,                                 -- /27 default .30
    dns_servers text,                                 -- comma-separated; DHCP option 6. Default: the gateway (dnsmasq resolves+forwards)
    domain      text DEFAULT 'pmr.local',             -- DHCP option 15 / dnsmasq local domain, so pmr-<code>-srv resolves unqualified
    lease_time  text DEFAULT '12h',                   -- dnsmasq dhcp-range lease
    ntp_server  text,                                 -- DHCP option 42. Default: the gateway
    -- Per-site counter banner (set in the Site Configurator). Shown on every counter Pi at this
    -- site by wcn-banner, OVERRIDING any fleet-wide kiosk_message. Empty text = no site banner;
    -- level (info|warning|alert) is validated in the app, not the DB, so an ALTER on an existing
    -- deployment stays a plain ADD COLUMN.
    banner_text  text,
    banner_level text
);

-- Existing deployments: add the banner columns idempotently (the CREATE TABLE above is a no-op
-- once the table exists).
ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS banner_text  text;
ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS banner_level text;



-- ── editable per-VLAN network settings + /27 everywhere (2026-08 migration) ──
-- Turn the once-derived addressing into "derived default, editable override", and move the
-- subnet from /24 to /27 for EVERY site. Nothing is in production on the virtual desktops yet,
-- so there is no live gateway to keep in step and no reason to preserve a legacy /24 — existing
-- rows are re-planned to /27 outright. Guarded on prefix_len so it runs exactly once; a fresh
-- install already has the new shape from CREATE TABLE and skips the whole block.
DO $netmig$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'vigilant' AND table_name = 'pharmacies' AND column_name = 'prefix_len'
  ) THEN
    -- server_ip (and vlan) are referenced by these views, so DROP COLUMN would be refused while
    -- they exist. Drop them here and let the CREATE OR REPLACE VIEW statements later in this file
    -- rebuild them against the new columns. Nothing nests on them, so no CASCADE is needed.
    DROP VIEW IF EXISTS pharmacy_vms_v;
    DROP VIEW IF EXISTS counters_v;

    -- NOT NULL DEFAULT 27 backfills every existing row to /27 in one shot.
    ALTER TABLE pharmacies ADD COLUMN prefix_len int NOT NULL DEFAULT 27;
    ALTER TABLE pharmacies ADD CONSTRAINT pharmacies_prefix_len_check CHECK (prefix_len BETWEEN 24 AND 30);

    -- subnet was GENERATED off a hard-coded /24; re-derive it from prefix_len.
    ALTER TABLE pharmacies DROP COLUMN subnet;
    ALTER TABLE pharmacies ADD  COLUMN subnet text
      GENERATED ALWAYS AS ('10.200.' || idx || '.0/' || prefix_len) STORED;

    -- the addressing columns were GENERATED (read-only); re-add as plain so they can be edited.
    ALTER TABLE pharmacies DROP COLUMN gateway_ip; ALTER TABLE pharmacies ADD COLUMN gateway_ip text;
    ALTER TABLE pharmacies DROP COLUMN server_ip;  ALTER TABLE pharmacies ADD COLUMN server_ip  text;
    ALTER TABLE pharmacies DROP COLUMN dhcp_from;  ALTER TABLE pharmacies ADD COLUMN dhcp_from  text;
    ALTER TABLE pharmacies DROP COLUMN dhcp_to;    ALTER TABLE pharmacies ADD COLUMN dhcp_to    text;

    ALTER TABLE pharmacies ADD COLUMN dns_servers text;
    ALTER TABLE pharmacies ADD COLUMN domain      text DEFAULT 'pmr.local';
    ALTER TABLE pharmacies ADD COLUMN lease_time  text DEFAULT '12h';
    ALTER TABLE pharmacies ADD COLUMN ntp_server  text;

    -- /27 plan for every existing row: gw .1, server .10, DHCP .21–.30.
    UPDATE pharmacies SET
      gateway_ip  = '10.200.' || idx || '.1',
      server_ip   = '10.200.' || idx || '.10',
      dhcp_from   = '10.200.' || idx || '.21',
      dhcp_to     = '10.200.' || idx || '.30',
      dns_servers = COALESCE(dns_servers, '10.200.' || idx || '.1'),
      domain      = COALESCE(domain, 'pmr.local'),
      lease_time  = COALESCE(lease_time, '12h'),
      ntp_server  = COALESCE(ntp_server, '10.200.' || idx || '.1');
  END IF;
END $netmig$;

-- Fill the editable addressing from the index whenever a value is left NULL — on INSERT and on
-- UPDATE, so clearing a field back to NULL resets it to the /27 default. A value that is set
-- survives untouched. This is the one place the default plan lives on the DB side; the UI's
-- planFrom() mirrors it for the live preview.
CREATE OR REPLACE FUNCTION pharmacies_fill_net() RETURNS trigger AS $fn$
BEGIN
  NEW.gateway_ip  := COALESCE(NEW.gateway_ip,  '10.200.' || NEW.idx || '.1');
  NEW.server_ip   := COALESCE(NEW.server_ip,   '10.200.' || NEW.idx || '.10');
  NEW.dhcp_from   := COALESCE(NEW.dhcp_from,   '10.200.' || NEW.idx || '.21');
  NEW.dhcp_to     := COALESCE(NEW.dhcp_to,     '10.200.' || NEW.idx || '.30');
  NEW.dns_servers := COALESCE(NEW.dns_servers, '10.200.' || NEW.idx || '.1');
  NEW.ntp_server  := COALESCE(NEW.ntp_server,  '10.200.' || NEW.idx || '.1');
  NEW.domain      := COALESCE(NEW.domain, 'pmr.local');
  NEW.lease_time  := COALESCE(NEW.lease_time, '12h');
  RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pharmacies_fill_net_trg ON pharmacies;
CREATE TRIGGER pharmacies_fill_net_trg BEFORE INSERT OR UPDATE ON pharmacies
  FOR EACH ROW EXECUTE FUNCTION pharmacies_fill_net();


-- pmr_system vocabulary refresh: widen to the major UK community-pharmacy PMR systems. The inline CHECK
-- only applies to fresh installs, so the live constraint is rebuilt here. Safe to
-- re-run: DROP IF EXISTS then ADD lands on the same constraint each time.
ALTER TABLE pharmacies DROP CONSTRAINT IF EXISTS pharmacies_pmr_system_check;
ALTER TABLE pharmacies ADD CONSTRAINT pharmacies_pmr_system_check CHECK (pmr_system IN ('proscript', 'pharmacy_manager', 'nexphase', 'analyst', 'titan', 'rxweb', 'other'));

-- ── counters ─────────────────────────────────────────────────────────────────
-- One counter = one Windows desktop VM + one Pi thin client on its own WireGuard
-- tunnel. One row because they are provisioned, replaced and retired together.
-- ── link to the CRM site this pharmacy IS ────────────────────────────────────
-- The configurator lists every site in the CRM and offers to create the ones that have no
-- Vigilant record yet, which needs an explicit link rather than matching on name: sites get
-- renamed, and two branches of one group can share a name. Nullable because pharmacies
-- created before this existed have no link, and inventing one by guessing would be worse
-- than admitting it is unknown.
--
-- Not a foreign key: the CRM lives in a different database (Supabase), so this is a soft
-- reference. UNIQUE so one site cannot be built twice.
ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS crm_site_id text;
CREATE UNIQUE INDEX IF NOT EXISTS pharmacies_crm_site_idx ON pharmacies (crm_site_id)
    WHERE crm_site_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS counters (
    id            bigserial   PRIMARY KEY,
    pharmacy_id   bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    -- Bounded so the derived VM octet stays inside the counter band: 20+n (.21–.99) on a /24
    -- site, 10+n (.11–.20) on a /27 site. The /27 band only has room for 10, but the DB cap
    -- stays 79 for the /24 sites still in service; the UI caps per-site to what the prefix fits.
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

-- ── which VMs a site's thin clients may use ──────────────────────────────────
-- Extra VMs attached to a site by hand. Most sites need none: the PMR server and each
-- counter's desktop are already known, and their addresses follow the platform's numbering.
-- This table is for anything else a site legitimately exposes.
--
-- `ip` is stored rather than derived because Proxmox discovery cannot see VM addresses — it
-- reports vmid, node, VLAN tag and MACs, and nothing more. Guessing an address for an
-- arbitrary VM would put a counter in front of whatever happens to answer on it.
CREATE TABLE IF NOT EXISTS pharmacy_vms (
    pharmacy_id bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    vmid        int         NOT NULL,
    ip          text        NOT NULL,
    label       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pharmacy_id, vmid)
);

-- THE definition of what a site's thin clients can be pointed at. Both the picker in
-- Watchman and the server-side resolver read this one view, so the dropdown cannot offer a
-- choice the server would then refuse — which it previously did, listing every VM on the
-- site's VLAN while accepting only the registered ones.
-- DROP then CREATE for the same idempotency reason printers_v carries above: the foot of
-- this file appends mem_max_bytes to this view, and a CREATE OR REPLACE here on the next
-- run would try to drop that column and abort the migration. The append has to live down
-- there because it reads pmr_vm_capacity and proxmox_vms, which are created BELOW this
-- point — and a view that forward-references a table fails the whole file.
-- ⚠️ NO CASCADE, ON PURPOSE, AND THE CHECK FOR IT IS IN THE DEPLOY NOTE AT THE TOP OF THIS
-- FILE (B8). Nothing in this repository depends on this view; a view built on it OUTSIDE
-- the repo would make this bare DROP fail and abort the whole single-transaction
-- migration. Adding CASCADE would turn that refusal into a silent deletion of somebody
-- else's object, which is the worse failure — so the dependency query runs before the
-- apply instead.
DROP VIEW IF EXISTS pharmacy_vms_v;
CREATE VIEW pharmacy_vms_v AS
-- Every VM a site's thin clients can be pointed at. A pharmacy_vms row overrides the DERIVED
-- address for the same vmid, so the server (.10) and counter (20+n on /24, 10+n on /27) octets
-- are defaults, not fixed. 'source' records how the
-- VM is linked (server / desktop / attached) so the UI can unassign any of them uniformly.
-- Leading columns (pharmacy_id, vmid, ip, role) are unchanged so CREATE OR REPLACE accepts
-- the appended source / counter_id / address_overridden.
SELECT p.id AS pharmacy_id, p.srv_vmid AS vmid,
       COALESCE(o.ip, p.server_ip) AS ip,
       'PMR server' AS role,
       'server' AS source,
       NULL::bigint AS counter_id,
       (o.ip IS NOT NULL) AS address_overridden
  FROM pharmacies p
  LEFT JOIN pharmacy_vms o ON o.pharmacy_id = p.id AND o.vmid = p.srv_vmid
 WHERE p.srv_vmid IS NOT NULL
UNION ALL
SELECT c.pharmacy_id, c.vmid,
       COALESCE(o.ip, '10.200.' || p.idx || '.' || ((CASE WHEN p.prefix_len >= 27 THEN 10 ELSE 20 END) + c.n)),
       'thin client ' || c.n,
       'desktop',
       c.id,
       (o.ip IS NOT NULL)
  FROM counters c
  JOIN pharmacies p ON p.id = c.pharmacy_id
  LEFT JOIN pharmacy_vms o ON o.pharmacy_id = c.pharmacy_id AND o.vmid = c.vmid
 WHERE c.vmid IS NOT NULL
UNION ALL
-- extra attached VMs = pharmacy_vms rows that are NOT overrides of the server/a desktop
SELECT v.pharmacy_id, v.vmid, v.ip, COALESCE(v.label, 'attached'),
       'attached', NULL::bigint, false
  FROM pharmacy_vms v
  JOIN pharmacies p ON p.id = v.pharmacy_id
 WHERE v.vmid IS DISTINCT FROM p.srv_vmid
   AND NOT EXISTS (SELECT 1 FROM counters c WHERE c.pharmacy_id = v.pharmacy_id AND c.vmid = v.vmid);

-- 'probe' provenance: the Pi found something listening on a printer port during a LAN
-- sweep but could not identify it. Deliberately distinct from snmp/ipp, which mean the
-- device actually answered a printer protocol.
DO $$ BEGIN
  ALTER TABLE printers DROP CONSTRAINT IF EXISTS printers_discovered_via_check;
  ALTER TABLE printers ADD CONSTRAINT printers_discovered_via_check
    CHECK (discovered_via IN ('snmp', 'ipp', 'cups', 'manual', 'probe'));
END $$;

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
-- ── one-shot service actions for a thin client ───────────────────────────────
-- Reboot and friends, requested from Watchman and collected on the Pi's next tick.
--
-- Delivery is AT-MOST-ONCE by design: pending_action is cleared the instant it is handed
-- to the device, before the device acts on it. A reboot directive that survived delivery
-- would be collected again by the Pi as it came back up, and the counter would reboot in a
-- loop forever. Losing an action to a dropped response is recoverable by clicking again;
-- a reboot loop on a pharmacy counter is not.
ALTER TABLE counters ADD COLUMN IF NOT EXISTS pending_action     text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS pending_action_by  text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS pending_action_at  timestamptz;
-- last_* is the audit trail: what was sent, and when it was picked up.
ALTER TABLE counters ADD COLUMN IF NOT EXISTS last_action        text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS last_action_by     text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS last_action_at     timestamptz;

-- ── which VM a thin client boots into ────────────────────────────────────────
-- Chosen in Watchman and pushed to the Pi, instead of being baked into the kiosk
-- launcher where changing it meant editing a file on the device.
--
-- Two columns rather than one: `boot_vmid` is the operator's CHOICE (the VM they picked
-- out of discovered Proxmox inventory) and `boot_target` is the ADDRESS actually pushed.
-- Keeping both means a VM that is rebuilt or renumbered surfaces as a disagreement,
-- rather than silently sending a counter to whatever now answers on that address.
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_vmid       int;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_target     text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_set_by     text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_set_at     timestamptz;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_applied_at timestamptz;

-- ── THE STAGED boot target: the same choice, made now, applied at the window (D2) ─────
-- ⚠️ WRITING boot_target IS APPLYING IT. The telemetry reply carries the boot directive on
-- EVERY tick — deliberately, so a launcher edited by hand is corrected back — and the Pi
-- restarts the kiosk the moment the target it holds differs from the one it is sent
-- (agent/pi/vigilant-pi-agent.py:2662 says so and :2722 does it). So a boot target saved at
-- 11:00 on a trading Tuesday signed a member of staff out roughly thirty seconds later,
-- with no hours gate, no attribution and no confirmation.
--
-- That is a CONFIGURATION change whose application happens to interrupt — which is exactly
-- the shape the job ladder exists for. So it is STAGEABLE: the intent is recorded here now,
-- nothing is pushed, and one set-based promoter (store.pg.js promoteCounterBootTargets)
-- copies it into the live columns when pmr_disruptive_allowed() opens for that site. The
-- apply-now escape hatch is still there — PUT …/boot-target {"when":"now"} — and it climbs
-- the same operator-credential + typed-site-name ladder apply-now climbs.
--
-- WHY NOT A pmr_intent ROW: the intent table already carries counter.boot_vmid, but its
-- value spec is a bounded vmid and "back to the site's PMR server" is the ABSENCE of one.
-- Expressing that would have meant a magic 0 inside a closed whitelist whose whole purpose
-- is that it holds no magic values. Two columns say it without a sentinel:
--   boot_next_pending = false            nothing is staged
--   true,  boot_next_vmid = <n>          stage a switch to VM n
--   true,  boot_next_vmid = NULL         stage a return to the PMR server default
-- pmr_intent keeps its job: it is where the OBSERVED value is reconciled against the wish.
--
-- ⚠️ THERE IS STILL EXACTLY ONE MECHANISM PUSHING boot_target. The promoter writes the live
-- column; the directive then re-sends that column every tick and self-heals it. They act on
-- different fields and never race — which is the thing the pmr_intent comment warns about.
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_next_vmid    int;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_next_pending boolean NOT NULL DEFAULT false;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_next_by      text;
ALTER TABLE counters ADD COLUMN IF NOT EXISTS boot_next_at      timestamptz;
-- Partial: the promoter sweeps only the handful of counters that have something staged, and
-- the estate is 348 sites of counters that mostly do not.
CREATE INDEX IF NOT EXISTS counters_boot_next_idx ON counters (pharmacy_id)
    WHERE boot_next_pending;

-- ── editable per-thin-client options ────────────────────────────────────────
-- The persistent settings channel: session options the kiosk launcher reads (smartcard,
-- printer redirection, clipboard, colour depth, screen blanking) and agent options the
-- agent applies to its own loop (report interval, printer/discovery cadence).
--
-- jsonb rather than a column each because the set is expected to grow, and because the
-- server merges (`settings || $new`) so saving one field cannot wipe the others.
--
-- ONLY stored values live here — NOT the defaults. The effective value is computed
-- server-side in src/shared/counterSettings.js and pushed on every telemetry tick, so an
-- empty '{}' means "all defaults" and there is exactly one place a default is written down.
-- The keys are a CLOSED whitelist validated before anything is stored: these values end up
-- in a file the Pi's kiosk launcher sources and in xfreerdp argv, so no free text exists in
-- this version at all.
ALTER TABLE counters ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}'::jsonb;

-- The smartcard fix stack on a counter Pi, as a single alertable number (1 = intact,
-- 0 = broken). Added 2026-08-17 with the NHS smartcard fix.
--
-- WHY A COLUMN AND NOT JUST raw->'smartcard_stack': alert_rules can only read device_state
-- COLUMNS (see alertMetricColumn in store.pg.js), and this is the one thin-client fact whose
-- silent regression closes a pharmacy counter. The fix is a shim library plus one exported
-- environment variable on the kiosk process; an apt upgrade, an edited launcher or a rebuilt
-- image removes it with no error anywhere — pcscd still runs, the reader is still detected,
-- the session still connects, and the failure only surfaces as a pharmacist unable to log in.
-- A boolean would have been the natural type, but every other alertable health value here is
-- numeric and evaluateAlert() compares numerically, so 1/0 keeps rules writable as
-- `smartcard_stack_ok < 1`.
--
-- NULL means "not applicable / not known" (a counter with no smartcard redirection, or an
-- agent too old to report it) and must NEVER read as a fault: evaluateAlert() returns false
-- on a null value, which is the behaviour we want.
ALTER TABLE device_state ADD COLUMN IF NOT EXISTS smartcard_stack_ok int;
-- NOTE ON ORDER: this ALTER must stay ABOVE counters_v, which selects the column below.
-- schema.sql is applied top-to-bottom in one pass, so a column added after the view that
-- reads it fails the whole migration with "column ds.smartcard_stack_ok does not exist" —
-- and on this deployment that means the ingest crash-loops on a fresh container.

CREATE OR REPLACE VIEW counters_v AS
SELECT c.id, c.pharmacy_id,
       p.code AS pharmacy_code, p.name AS pharmacy_name, p.idx AS pharmacy_idx, p.vlan,
       c.n, c.label, c.status, c.vmid, c.vm_hostname,
       '10.200.' || p.idx || '.' || ((CASE WHEN p.prefix_len >= 27 THEN 10 ELSE 20 END) + c.n)     AS vm_ip,
       -- OBSERVED from the WireGuard hub, not derived. This was previously computed as
       -- 10.255.<pharmacy idx>.<counter n>, a convention the estate does not actually
       -- follow: the pilot Pi answers on 10.255.0.10/32 while that formula produced
       -- 10.255.1.2/32, and because nothing compared the two, the UI displayed an address
       -- no device had. NULL when the peer has never handshaked, which is the honest
       -- answer for a client that is not on the VPN yet.
       w.allowed_ips AS pi_tunnel_ip,
       c.pi_device_id, c.pi_hostname, c.pi_model, c.pi_public_key, c.pi_enrolled_at,
       c.peripherals, c.notes,
       d.serial       AS pi_serial,
       ds.status      AS pi_agent_status,      -- from the Pi's Vigilant telemetry
       ds.last_seen_at AS pi_last_seen_at,
       w.endpoint     AS pi_endpoint,
       w.latest_handshake AS pi_last_handshake,
       w.rx_bytes AS pi_rx_bytes, w.tx_bytes AS pi_tx_bytes,
       (w.latest_handshake IS NOT NULL
        AND w.latest_handshake > now() - interval '3 minutes') AS pi_tunnel_up,
       -- ── appended, and it must stay appended ──────────────────────────────
       -- CREATE OR REPLACE VIEW can only ADD columns at the END. Inserting one mid-list
       -- fails with "cannot change name of view column", so new columns go here even
       -- when they would read better next to related ones.
       --
       -- Which PMR system this counter works against and where it lives in Proxmox: the
       -- desktop VM is only a shell that RDPs into the PMR server, so the server is the
       -- meaningful target.
       p.pmr_system,
       p.server_ip AS pmr_server_ip,
       p.srv_vmid  AS pmr_srv_vmid,
       -- What the Pi's kiosk is ACTUALLY connected to, read from the running FreeRDP
       -- process. Compared against pmr_server_ip: a Pi pointed at another pharmacy's PMR
       -- server is a serious misconfiguration nothing else in the stack would notice.
       ds.raw -> 'rdp' ->> 'target' AS pi_rdp_target,
       -- The Pi's real address on the site LAN, as opposed to its tunnel /32.
       ds.raw ->> 'primary_ip' AS pi_lan_ip,
       -- Peripherals the agent actually found, kept separate from the operator's
       -- `peripherals` column so a detection gap never silently overwrites a human's
       -- assessment (and vice versa).
       ds.raw -> 'peripherals' AS pi_peripherals_detected,
       -- Which VM this thin client is told to boot into, and whether the Pi has taken it.
       -- Deliberately NOT joined to proxmox_vms for the VM's name: that table is created
       -- later in this file, so a fresh bootstrap would fail on the forward reference.
       -- The caller already loads discovered inventory for the picker and maps vmid->name.
       c.boot_vmid, c.boot_target, c.boot_set_by, c.boot_set_at, c.boot_applied_at,
       -- The Pi reports the target it is CONFIGURED with separately from the one it is
       -- currently CONNECTED to, because those legitimately differ: on the Cloudflare
       -- fallback the live target is 127.0.0.1:33389, so comparing the connected address
       -- against the desired VM would show a permanent false mismatch on any site whose
       -- WireGuard path is down.
       ds.raw -> 'rdp' ->> 'configured_target' AS pi_configured_target,
       CASE
         WHEN c.boot_target IS NULL THEN 'unset'
         WHEN ds.raw -> 'rdp' ->> 'configured_target' IS NULL THEN 'pending'
         WHEN split_part(ds.raw -> 'rdp' ->> 'configured_target', ':', 1)
              = split_part(c.boot_target, ':', 1) THEN 'applied'
         ELSE 'pending'
       END AS boot_state,
       -- Appended for the same reason as everything above it: CREATE OR REPLACE VIEW can
       -- only ADD columns at the END, so placing these next to the boot columns they relate
       -- to fails with "cannot change name of view column".
       c.pending_action, c.pending_action_by, c.pending_action_at,
       c.last_action, c.last_action_by, c.last_action_at,
       -- Appended, and it must stay appended (see the note above): CREATE OR REPLACE VIEW
       -- can only ADD columns at the END.
       --
       -- The STORED per-thin-client options only. Defaults are NOT merged in here: they
       -- live once, server-side, in src/shared/counterSettings.js, and merging them in SQL
       -- too would be a second copy to keep in step.
       c.settings,
       -- What the agent says it has ACTUALLY applied, straight from its telemetry. Kept
       -- separate from c.settings for the same reason as pi_peripherals_detected: the
       -- difference between the two IS the interesting signal (a thin client that has not
       -- picked up a change, or a kiosk still running the old session options).
       ds.raw -> 'settings_applied' AS pi_settings_applied,
       -- ── health signals, appended (CREATE OR REPLACE VIEW cannot insert mid-list) ──
       -- Populated for thin clients only once temperature fell back to cpu_temperature: a Pi
       -- has no board sensor, so the RouterOS-shaped `temperature` was always null here.
       ds.temperature                             AS pi_temp_c,
       -- Undervoltage/throttling LATCHES until reboot, so the since-boot flags are as
       -- important as the current ones — a counter that browned out earlier has a PSU fault
       -- that will recur, and only the latched bit still shows it.
       (ds.raw -> 'throttling' ->> 'undervoltage_now')::boolean        AS pi_undervolt_now,
       (ds.raw -> 'throttling' ->> 'undervoltage_since_boot')::boolean AS pi_undervolt_ever,
       (ds.raw -> 'throttling' ->> 'throttled_now')::boolean           AS pi_throttled_now,
       -- How an SD card actually fails: a rising error count first, read-only at the end.
       (ds.raw -> 'storage_errors' ->> 'count')::int                   AS pi_sd_errors,
       (ds.raw ->> 'rootfs_readonly')::boolean                         AS pi_rootfs_ro,
       ds.raw -> 'failed_units'                                        AS pi_failed_units,
       ds.raw -> 'storage'                                             AS pi_storage,
       ds.raw -> 'wifi_link'                                           AS pi_wifi_link,
       -- The smartcard fix stack (2026-08-17). Appended at the END of the select list because
       -- CREATE OR REPLACE VIEW can only add columns, never insert mid-list — the same
       -- constraint noted three times above. The roll-up is also carried as a real column
       -- (device_state.smartcard_stack_ok) so alert_rules can read it; this jsonb is for the
       -- UI, which needs to say WHICH part broke, not merely that something did.
       ds.raw -> 'smartcard_stack'                                     AS pi_smartcard_stack,
       ds.smartcard_stack_ok                                           AS pi_smartcard_ok,
       -- ── the STAGED boot target (D2), appended for the reason stated three times above:
       -- CREATE OR REPLACE VIEW can only add columns at the END.
       --
       -- The UI needs all four to say the true sentence. "Counter 2 will switch to VM 305
       -- overnight" is boot_next_pending + boot_next_vmid, and boot_next_by / boot_next_at
       -- are who decided and when. Without them a staged change is invisible, and the next
       -- person makes it again — this time reaching for the apply-now hatch because nothing
       -- on the screen said it was already coming.
       c.boot_next_pending, c.boot_next_vmid, c.boot_next_by, c.boot_next_at
       -- ⚠️ WHEN it will land is deliberately NOT a column here. It comes from
       -- site_next_disruptive_window(), which is defined far below this view — schema.sql is
       -- applied top-to-bottom in one pass and a view referencing a function declared later
       -- fails the whole migration, the same forward-reference trap noted above for
       -- ds.smartcard_stack_ok. It is also a property of the SITE, not of one counter, so it
       -- belongs where the site's hours are already served: siteDisruptiveWindow(), returned
       -- by GET /pharmacies/:id/hours and echoed as `applies_at` on the staging response.
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
-- DROP then CREATE, not CREATE OR REPLACE, and the reason is IDEMPOTENCY rather than
-- style. This file is applied top-to-bottom on every migrate, and the foot of it rebuilds
-- printers_v with `assigned_vmids` and three more columns. CREATE OR REPLACE may only
-- APPEND columns, never drop them, so on the SECOND run this statement would try to
-- narrow the wider view back to eight columns and fail with "cannot drop columns from
-- view" — taking the whole migration with it. Nothing nests on this view (the only
-- readers are listPrinters/upsertPrinter in store.pg.js), so dropping is safe.
-- ⚠️ NO CASCADE, ON PURPOSE, AND THE CHECK FOR IT IS IN THE DEPLOY NOTE AT THE TOP OF THIS
-- FILE (B8). Nothing in this repository depends on this view; a view built on it OUTSIDE
-- the repo would make this bare DROP fail and abort the whole single-transaction
-- migration. Adding CASCADE would turn that refusal into a silent deletion of somebody
-- else's object, which is the worse failure — so the dependency query runs before the
-- apply instead.
DROP VIEW IF EXISTS printers_v;
CREATE VIEW printers_v AS
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

-- ── discovered Proxmox VMs ───────────────────────────────────────────────────
-- Observed cluster inventory, so a pharmacy's VMIDs and hostnames stop being hand-typed.
--
-- Collected BY A PROXMOX NODE and pushed here, not pulled: Vigilant sits on the DMZ VLAN
-- and has no route to the Proxmox API on the management VLAN. Inverting the direction
-- keeps it that way — no DMZ-to-management hole, and no API token, because a collector
-- running on a node uses `pvesh` locally as root.
--
-- Matching is mechanical rather than configured: a VM's VLAN tag IS the pharmacy
-- (tag = 100 + index), and the naming convention identifies its role
-- (pmr-<code>-srv = PMR server, pmr-<code>-cl<NN> = counter NN's desktop).
--
-- Kept separate from `pharmacies`/`counters` for the same reason as wg_peers: discovery
-- fills gaps and reports disagreement, but never silently overwrites what an operator set.
CREATE TABLE IF NOT EXISTS proxmox_vms (
    vmid        int         PRIMARY KEY,
    node        text,
    name        text,
    status      text,
    vlan_tag    int,                                -- from netN tag=, the pharmacy key
    macs        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    cores       int,
    maxmem      bigint,
    maxdisk     bigint,
    uptime_s    bigint,
    template    boolean     NOT NULL DEFAULT false,
    seen_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS proxmox_vms_vlan_idx ON proxmox_vms (vlan_tag);

-- Guest-agent and boot state, from the collector. Existing deployments need these explicitly:
-- CREATE TABLE above is a no-op once the table exists.
--
-- agent_enabled and agent_ok are DIFFERENT FACTS and both are three-state. `agent_enabled` is
-- whether Proxmox is configured to talk to a guest agent — every Windows VM in this estate
-- reads true, so on its own it answers nothing. `agent_ok` is whether the agent actually
-- ANSWERED from inside the guest, which is the question people are really asking. NULL on both
-- means "not established" — a stopped VM, an unreachable node, a config we could not read — and
-- must never be rendered as "not installed". agent_checked_at is what makes agent_ok perishable
-- rather than permanent: the gateway's agent died mid-session once, so a stale true is a lie.
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS agent_enabled    boolean;
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS agent_ok         boolean;
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS agent_error      text;
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS agent_checked_at timestamptz;
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS guest_os         text;
-- The address Windows ACTUALLY holds, as opposed to the one the platform derives from the site
-- index. Everything else compares one derivation against another, so they agree by construction
-- — which is how a VM whose NIC was on the wrong address blocked a live counter with every
-- screen green. This is the only observed reading in the VM layer.
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS guest_ips        jsonb NOT NULL DEFAULT '[]'::jsonb;
-- 0 on every Windows desktop in the estate today, including both a live pharmacy trades on: a
-- node reboot leaves that site with a gateway and no desktops. Nothing has ever surfaced it.
ALTER TABLE proxmox_vms ADD COLUMN IF NOT EXISTS onboot           boolean;

-- ── PMR VM capacity ─────────────────────────────────────────────────────────
-- "Is this pharmacy's server running out of room?" — the one question the VM layer could not
-- answer. One row per VM, overwritten in place by the collector; this is a CURRENT-STATE table,
-- not a history, which is why it is keyed on vmid alone.
--
-- CPU and RAM averages come FREE from Proxmox RRD (the node already keeps them), so they are
-- stored as computed numbers and nothing here has to accumulate them.
--
-- DISK HAS NO RRD SOURCE. rrddata's `disk` is ALWAYS 0 for a qemu VM — Proxmox cannot see
-- inside the guest filesystem — and proxmox_vms.maxdisk is only the nominal virtual disk size
-- (238GiB for VM 305, which is really 88% full). The only true reading is the guest agent's
-- get-fsinfo, so disk_used_bytes/disk_total_bytes may be written from THAT AND NOTHING ELSE,
-- and the 1d/7d/30d disk averages are computed by us from pmr_vm_disk_samples below.
--
-- disk_source is the tri-state. 'unknown' means the agent was absent, dead or unreadable on the
-- pass that wrote this row (VMs 302/303/304 have no agent at all) and the disk numbers are NULL.
-- It must never degrade to 0: "0 bytes used" and "we could not ask" are different facts, and
-- one of them puts a false all-clear on a live dispensing server.
CREATE TABLE IF NOT EXISTS pmr_vm_capacity (
    vmid              int         PRIMARY KEY,
    node              text,
    name              text,
    sampled_at        timestamptz NOT NULL DEFAULT now(),
    cores             int,
    mem_max_bytes     bigint,
    cpu_pct_1d        numeric(5,2),               -- RRD `cpu` is a FRACTION 0..1, stored x100
    cpu_pct_7d        numeric(5,2),
    cpu_pct_30d       numeric(5,2),
    mem_bytes_1d      bigint,
    mem_bytes_7d      bigint,
    mem_bytes_30d     bigint,
    mem_pressure_1d   numeric(6,3),               -- RRD pressurememorysome, day timeframe
    disk_mount        text,                       -- the largest real filesystem, e.g. 'C:\'
    disk_used_bytes   bigint,
    disk_total_bytes  bigint,
    disk_used_1d      bigint,                     -- NULL until the history actually covers 1d
    disk_used_7d      bigint,                     -- NULL until the history actually covers 7d
    disk_used_30d     bigint,                     -- NULL until the history actually covers 30d
    disk_source       text        CHECK (disk_source IN ('agent','unknown')),
    rrd_error         text,                       -- why the RRD read failed, or NULL when it worked
    updated_at        timestamptz NOT NULL DEFAULT now()
);
-- Existing deployments: CREATE TABLE above is a no-op once the table exists.
--
-- The three disk_used_* windows are NULL-when-uncovered, NOT "computed from whatever history
-- exists". Fifteen minutes after deploy a plain AVG makes d1 = d7 = d30 and the UI draws three
-- confident equal bars, so an engineer reads "VM 305 has been 88% for a month, no action" when
-- the truth is "there is no history". A window is only written once the oldest sample behind it
-- is genuinely that old.
--
-- rrd_error was previously DISCARDED by the collector. Without it a permanently broken RRD path
-- is invisible: sampled_at kept advancing (the guest agent was still answering) while CPU/RAM
-- were COALESCEd, so the UI printed "sampled 2m ago" over numbers frozen weeks ago. sampled_at
-- now only advances on a pass that actually carried an RRD reading, and this says why when it
-- did not.
ALTER TABLE pmr_vm_capacity ADD COLUMN IF NOT EXISTS rrd_error text;

-- Our own disk history, because Proxmox keeps none (see above). One row per VM per mountpoint
-- per collection tick; the 1d/7d/30d columns on pmr_vm_capacity are AVGs over this table.
-- Pruned to 35 days on every collection — 30 days of window plus a few days of slack, so the
-- 30-day average is never computed from a window that was silently trimmed underneath it.
CREATE TABLE IF NOT EXISTS pmr_vm_disk_samples (
    vmid        int         NOT NULL,
    mountpoint  text        NOT NULL,
    sampled_at  timestamptz NOT NULL DEFAULT now(),
    used_bytes  bigint,
    total_bytes bigint,
    PRIMARY KEY (vmid, mountpoint, sampled_at)
);
-- The retention DELETE and all three window AVGs filter on sampled_at alone.
CREATE INDEX IF NOT EXISTS pmr_vm_disk_samples_age_idx ON pmr_vm_disk_samples (sampled_at);

-- The VM NAME the sample was taken from. Existing deployments need this explicitly.
--
-- PROXMOX RECYCLES VMIDS, and this table is keyed on vmid alone. A rebuilt VM 305 on a fresh
-- 100 GB disk would otherwise inherit ~3,300 rows averaging 208 GB under the same vmid and the
-- same 'C:\' mountpoint, so disk_used_30d (208 GB) exceeds disk_total_bytes (100 GB) and the UI
-- clamps it to a solid red 100% bar for five weeks. Carrying the name means the averages join
-- can refuse to blend two different VMs, and the write path wipes both this table and the
-- capacity row the moment a vmid is observed under a changed name.
ALTER TABLE pmr_vm_disk_samples ADD COLUMN IF NOT EXISTS name text;
-- Backfill, once: the averages join matches on name, so rows written before the column existed
-- would never match their capacity row again and every window would sit NULL for 35 days. The
-- current name is the right answer for them — a rebuild between then and now is exactly what the
-- write path's wipe deletes, so anything still here belongs to the VM that is there today.
UPDATE pmr_vm_disk_samples s SET name = c.name
  FROM pmr_vm_capacity c WHERE c.vmid = s.vmid AND s.name IS NULL AND c.name IS NOT NULL;

-- ── §7 · WHAT WINDOWS ITSELF LISTS ──────────────────────────────────────────
-- The printer list a PMR desktop actually holds, as the guest reported it. The printers modal
-- joins it against the CUPS queue names to draw a confirmation per printer, and without it
-- every confirmation on that modal reads 'not checked'.
--
-- ⛔ THE ONLY WRITER IS THE PROXMOX COLLECTOR'S OUTWARD PUSH. Vigilant has no route to the
-- Proxmox API — no inbound hole, no API token — so there is no on-demand read and no way to
-- refresh a row except by waiting for the next 15-minute pass. read_at is therefore what the
-- whole feed is presented through: the UI ages this reading on screen rather than pretending
-- it is current.
--
-- ⛔ THE THREE STATES OF `printers`, AND THEY ARE NOT INTERCHANGEABLE:
--   NULL   nobody has looked. The ordinary state of a VM with no guest agent, a VM on a node
--          whose collector is not installed, or a site that has not had a pass yet. It must
--          render as UNKNOWN and never as a finding.
--   '{}'   the guest WAS read and Windows lists no printers at all. A real, alarming fact.
--   {…}    the names as the guest gave them, RDP's ' (redirected N)' suffix included. The
--          suffix is stripped on the READ path, in one documented place, never here: this
--          column is what the machine said.
-- An endpoint or a write path that collapses the first two is the bug this table exists to
-- make impossible, so read_at is NULL exactly when printers is NULL and they move together.
--
-- `error` is written on EVERY pass that tried, including successful ones (as NULL), so a
-- repaired path clears it — the same discipline as pmr_vm_capacity.rrd_error. A pass that
-- failed leaves printers and read_at untouched and updates only this, so the last good list
-- stays on screen with its true age beside the reason the refresh failed.
CREATE TABLE IF NOT EXISTS pmr_vm_printers (
    vmid       int         PRIMARY KEY,
    node       text,
    name       text,                       -- the VM name this reading was taken from
    printers   text[],                     -- NULL = never read. '{}' = read, and empty.
    read_at    timestamptz,                -- when the GUEST was read, not when we received it
    source     text        CHECK (source IN ('guest-agent', 'session-agent')),
    error      text,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Discovered VMs joined to whatever they were matched to, plus the disagreements. A VM
-- whose vmid differs from the one recorded on the counter is surfaced rather than
-- corrected: it usually means the VM was rebuilt, and a human should decide.
-- DROPPED, not replaced. The view is `SELECT v.*`, so its column list was fixed at creation
-- time; once the ALTERs above add columns to proxmox_vms, CREATE OR REPLACE fails outright
-- ("cannot change name of view column"). Nothing else depends on it — the only reader is
-- listProxmoxVms in store.pg.js — so dropping and recreating is safe and idempotent.
DROP VIEW IF EXISTS proxmox_vms_v;

-- Discovered VMs joined to whatever they were matched to, plus the disagreements. A VM
-- whose vmid differs from the one recorded on the counter is surfaced rather than
-- corrected: it usually means the VM was rebuilt, and a human should decide.
CREATE VIEW proxmox_vms_v AS
SELECT v.*,
       p.code AS pharmacy_code,
       c.id   AS counter_id,
       c.n    AS counter_n,
       CASE
         WHEN p.id IS NULL THEN 'unmatched'
         WHEN v.name ~ '-srv$' AND p.srv_vmid IS NULL THEN 'fillable'
         WHEN v.name ~ '-srv$' AND p.srv_vmid <> v.vmid THEN 'conflict'
         WHEN c.id IS NOT NULL AND c.vmid IS NULL THEN 'fillable'
         WHEN c.id IS NOT NULL AND c.vmid <> v.vmid THEN 'conflict'
         WHEN c.id IS NOT NULL OR p.srv_vmid = v.vmid THEN 'linked'
         ELSE 'unmatched'
       END AS match_state,
       (v.seen_at < now() - interval '30 minutes') AS stale
  FROM proxmox_vms v
  LEFT JOIN pharmacies p ON p.vlan = v.vlan_tag
  -- substring() with a capture group yields NULL when the pattern does not match, so the
  -- cast is safe. regexp_replace returns the ORIGINAL string on no-match, and casting
  -- 'pmr-desktop-gateway' to int aborts the entire view.
  LEFT JOIN counters  c ON c.pharmacy_id = p.id
                       AND c.n = (substring(v.name from '-cl0*([0-9]+)$'))::int;

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

-- ── ⛔ WAS THE NAME ON THIS ROW PROVED, OR TYPED (A6) ────────────────────────
-- The two-person rule compares config_jobs.created_by with the approver, and BOTH used to be
-- strings out of a request body carrying the shared admin token — so "the approver must
-- differ from the author" compared two names the same caller had chosen, and one person could
-- author as "leo" and approve as "jake" without holding a second credential.
--
-- These two columns record HOW each name was established, so the rule can say what it
-- actually proved instead of asserting what it hoped:
--   true   the name came from a PMR_OPERATOR_TOKENS credential. A different name here really
--          is a different secret, and therefore really is a second person.
--   false  the name was typed into the request body under the shared admin token. Still
--          useful provenance; NOT a second person, and nothing may call it one.
-- A job with either flag false is approved with `two_person: false` on the response and in
-- the audit line, and the RUNBOOK's guarantee holds only for the ones where both are true.
ALTER TABLE config_jobs ADD COLUMN IF NOT EXISTS created_by_credential  boolean NOT NULL DEFAULT false;
ALTER TABLE config_jobs ADD COLUMN IF NOT EXISTS approved_by_credential boolean NOT NULL DEFAULT false;

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

  -- ⛔ 'devices' is deliberately NOT in this list — it holds pppoe_password. It is granted
  -- column-by-column below, exactly like wifi_networks. Do not add it back here.
  FOREACH t IN ARRAY ARRAY[
    'device_state','interface_state','lte_state','neighbors','mac_hosts',
    'wireless_clients','config_jobs','alerts','metrics_history','interface_history',
    'lte_history','speedtest_jobs'
  ] LOOP
    EXECUTE format('ALTER TABLE vigilant.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('GRANT SELECT ON vigilant.%I TO authenticated', t);
    -- Drop+recreate so re-running migrate is idempotent.
    EXECUTE format('DROP POLICY IF EXISTS %I ON vigilant.%I', t || '_sel_authed', t);
    EXECUTE format('CREATE POLICY %I ON vigilant.%I FOR SELECT TO authenticated USING (true)', t || '_sel_authed', t);
  END LOOP;

  -- devices: RLS + column-level SELECT that OMITS pppoe_password.
  -- The REVOKE is REQUIRED, not defensive: a column-level grant does NOT supersede an existing
  -- table-level grant, so a database that ran an earlier migrate would keep full read access.
  EXECUTE 'ALTER TABLE vigilant.devices ENABLE ROW LEVEL SECURITY';
  EXECUTE 'REVOKE SELECT ON vigilant.devices FROM authenticated';
  EXECUTE 'GRANT SELECT (id, serial, identity, site_name, customer, model, ros_version, wan_type, tags, expected, poll_interval_s, poll_until, agent_version, enrolled_at, notes, kind) ON vigilant.devices TO authenticated';
  EXECUTE 'DROP POLICY IF EXISTS devices_sel_authed ON vigilant.devices';
  EXECUTE 'CREATE POLICY devices_sel_authed ON vigilant.devices FOR SELECT TO authenticated USING (true)';

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

-- Deliberately NOT added to the grant loop above and NOT published to Realtime: relay_requests
-- holds the base64 bodies of whatever an engineer proxied, and site_devices_v/relay_sessions
-- are the allowlist itself. Both are reachable only through the token-gated API, never by a
-- frontend select.

-- ══════════════════════════════════════════════════════════════════════════════
-- SITE LAN INVENTORY + THE RELAY REVERSE CHANNEL
-- ══════════════════════════════════════════════════════════════════════════════

-- ── which Vigilant devices belong to a site ───────────────────────────────────
-- ONE definition, read by the inventory API (GET /sites/:code/devices) AND by the relay's
-- allowlist, so a target the picker can offer is exactly a target the server will accept.
-- Previously each caller passed its own list of serials (see /printers/lan?serials=), which
-- means the client decides what "this site" is — unusable for an allowlist.
--
-- Three links, because these are the only ones that genuinely exist today:
--   thin-client  a pharmacy's counters name their Pi's devices row (counters.pi_device_id).
--   site-name    a MikroTik whose site_name CONTAINS the site code. strpos(), never LIKE:
--                a code must never be interpretable as a wildcard pattern.
--   serial       the ~348 monitored sites that have NO pharmacies row. There the router IS
--                the site, keyed by its own serial. Inventory has to work for those — a Pi
--                is what a site needs to be REACHED, not to be seen.
CREATE OR REPLACE VIEW site_devices_v AS
SELECT p.code       AS site_code,
       p.id         AS pharmacy_id,
       c.pi_device_id AS device_id,
       'thin-client' AS link
  FROM pharmacies p
  JOIN counters c ON c.pharmacy_id = p.id
 WHERE c.pi_device_id IS NOT NULL
UNION
SELECT p.code, p.id, d.id, 'site-name'
  FROM pharmacies p
  JOIN devices d ON d.site_name IS NOT NULL
                AND strpos(lower(d.site_name), lower(p.code)) > 0
 -- Routers only. A site's own Pis are already the thin-client arm, and their site_name
 -- ("RX54554 counter 1") contains the code too, which would list every Pi twice.
 WHERE d.kind = 'mikrotik'
UNION
SELECT d.serial, NULL::bigint, d.id, 'serial'
  FROM devices d
 WHERE d.kind = 'mikrotik';

-- ── relay sessions ───────────────────────────────────────────────────────────
-- A time-boxed permission for ONE Pi to proxy HTTP to ONE address:port on its own site LAN.
-- Nothing here can be reached from the datacentre: the hub's forward chain is policy-drop
-- except WireGuard→RDP, so the Pi dials out and this row is what it is allowed to fetch.
--
-- The row is the authority the Pi is handed, and the Pi re-checks the target against it, so a
-- compromised server still cannot aim a Pi at an address no session named.
CREATE TABLE IF NOT EXISTS relay_sessions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- Resolved from site_devices_v at creation and RECORDED, not re-derived: the audit trail
    -- must say which site this was authorised against even after inventory changes.
    site_code     text,
    target_ip     text        NOT NULL,
    target_port   int         NOT NULL,
    opened_by     text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    closed_at     timestamptz,
    closed_reason text,
    -- Last time the Pi actually held a long poll open, so a UI can tell "no Pi is listening"
    -- from "the Pi is listening and the printer is not answering".
    last_poll_at  timestamptz
);
-- One live session per device, enforced STRUCTURALLY rather than by a check-then-insert:
-- creating a second session closes the first, and two operators clicking at once would
-- otherwise both pass the check and leave two live sessions on one Pi.
CREATE UNIQUE INDEX IF NOT EXISTS relay_sessions_one_live_idx
    ON relay_sessions (device_id) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS relay_sessions_expiry_idx ON relay_sessions (expires_at)
    WHERE closed_at IS NULL;

-- ── the queued requests that cross the channel ───────────────────────────────
-- WHY A TABLE AND NOT PROCESS MEMORY: the ingest runs as a 3-worker cluster sharing one
-- listening socket (docker-compose.override.yml, INGEST_WORKERS=3). The browser's GET and the
-- Pi's long poll therefore land on DIFFERENT processes about two thirds of the time, and an
-- in-process queue would silently 504 most page loads. Postgres is the only state the cluster
-- shares.
--
-- Bodies are base64 TEXT because readBody() accumulates a string and would corrupt binary —
-- the same reason the wire contract is base64 — so the bytes are never decoded server-side.
CREATE TABLE IF NOT EXISTS relay_requests (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    uuid        NOT NULL REFERENCES relay_sessions(id) ON DELETE CASCADE,
    -- FIFO across the Pi's pool of workers. A page's assets are queued in the order the
    -- browser asked for them; serving them out of order would delay the document itself.
    seq           bigserial   NOT NULL,
    method        text        NOT NULL,
    path          text        NOT NULL,
    headers       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    body_b64      text,
    state         text        NOT NULL DEFAULT 'queued'
                              CHECK (state IN ('queued', 'claimed', 'done')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    claimed_at    timestamptz,
    replied_at    timestamptz,
    status        int,
    resp_headers  jsonb,
    resp_body_b64 text
);
-- The claim query is the hot one: the oldest unanswered row for this session, SKIP LOCKED so
-- the Pi's three workers never collide. Partial on "not answered yet", which is both states the
-- claim can select — 'queued', and a 'claimed' read whose 10 s visibility window has lapsed
-- (see claimRelayRequest). Dropped and recreated rather than CREATE IF NOT EXISTS so a database
-- carrying the earlier queued-only definition converges on this one.
DROP INDEX IF EXISTS relay_requests_claim_idx;
CREATE INDEX IF NOT EXISTS relay_requests_claim_idx
    ON relay_requests (session_id, seq) WHERE state <> 'done';
CREATE INDEX IF NOT EXISTS relay_requests_created_idx ON relay_requests (created_at);

-- ── thin-client branding (FLEET-WIDE, exactly one row) ───────────────────────
-- The boot splash, the console MOTD/issue art and the kiosk pre-connect line, for EVERY thin
-- client in the estate. There is deliberately no device_id and no site column: branding was
-- decided fleet-wide with NO per-site override, which is what keeps this one flat row instead
-- of a resolution order with a precedence bug waiting in it.
--
-- `id` is pinned to 1 by the CHECK so a second row is impossible rather than merely unlikely —
-- every writer upserts ON CONFLICT (id) and every reader selects WHERE id = 1, so a stray
-- second row would silently split the fleet's branding in two.
--
-- The splash is `bytea`, not a file on disk: the ingest runs as a 3-worker cluster sharing one
-- listening socket (see relay_requests for the same constraint), so a PNG written to a
-- container filesystem by one worker is invisible to the other two. Postgres is the only state
-- they share. Uploads arrive as base64 in JSON for the same reason relay bodies do — readBody()
-- accumulates the request into a STRING, which mangles raw PNG bytes.
--
-- WHAT IS DELIBERATELY ABSENT: there is no column here for kernel verbosity (`quiet`,
-- `logo.nologo`) or anything else in /boot/firmware/cmdline.txt. That file is the one thing on a
-- Pi with NO remote recovery — a typo means the device does not boot, so no SSH, no agent, no
-- tunnel, and somebody drives to a pharmacy with an SD card reader. It is written ONCE at image
-- bake time (agent/pi/build-image.sh) and must never become a pushable setting.
CREATE TABLE IF NOT EXISTS branding (
    id            smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- exactly one row, fleet-wide
    motd          text,
    issue         text,
    kiosk_message text,
    splash        bytea,
    splash_sha256 text,
    splash_width  int,
    splash_height int,
    -- Separate from the row's updated_at ON PURPOSE. updated_at moves whenever ANY field
    -- changes, so reusing it for the splash would tell the editor "the image changed" every
    -- time an operator only fixed a typo in the MOTD. The contract's splash.updated_at has to
    -- mean the image, so it gets its own stamp. NULL when no splash has ever been uploaded.
    splash_updated_at timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    text
);
-- Converge a database that received an earlier revision of this table (the column was added
-- after the first cut of the DDL). ADD COLUMN IF NOT EXISTS keeps the file re-runnable.
ALTER TABLE branding ADD COLUMN IF NOT EXISTS splash_updated_at timestamptz;


-- ══════════════════════════════════════════════════════════════════════════════
-- THE PMR CONTROL PLANE: OPENING HOURS, INTENDED STATE, AND JOBS
-- ══════════════════════════════════════════════════════════════════════════════
-- Watchman holds INTENDED STATE. A reconciler turns a gap between intent and the last
-- observed reading into a JOB: a verb NAME plus arguments the SERVER resolved from rows it
-- already holds. Executors PULL jobs on the reply to a call they already make outward — the
-- Pi's /telemetry post and the Proxmox collector's /proxmox/report post. Nothing new dials
-- IN, and in particular Vigilant still has no route to Proxmox (see proxmoxReport).
--
-- THREE RULES THIS SCHEMA EXISTS TO ENFORCE, all of them decisions and none of them
-- negotiable in a later revision:
--   1. THE VERB RULE. `verb` is a NAME from a closed allowlist and `args` are bounded values.
--      There is no column anywhere here that can hold a command line, and adding one would
--      turn a mistaken or compromised server into arbitrary execution on a pharmacy counter.
--   2. DONE MEANS PROVEN. 'applied' is only the executor's word for it. 'confirmed' is a
--      SEPARATE reading of the world, taken from a table some other collector wrote. A job
--      that reaches its confirm deadline without that reading FAILS — it is never quietly
--      counted as done because a command exited 0.
--   3. NOTHING DISRUPTIVE IN HOURS, UNATTENDED. `disruptive` says a job signs a member of
--      staff out. pmr_job_wait_reason() is the ONE gate, read by the claim query and by the
--      UI view, so "why has this not run" has exactly one answer.

-- ── the timezone opening hours are expressed in ──────────────────────────────
-- The first timezone anywhere in this schema, and it has to exist: opening hours are the
-- first concept in this system that is absolute wall-clock rather than a duration the
-- executing machine measures on its own clock (see counterSettings.js support_vnc_min for
-- the rule this is the exception to). Defaulting to the SERVER's timezone is the classic way
-- this breaks in October, so it is a stored per-site value with a real default.
ALTER TABLE pharmacies ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT 'Europe/London';

-- ⚠️ A TIMEZONE THAT DOES NOT EXIST MUST NOT BE ABLE TO STOP THE ESTATE'S NIGHT (S5).
-- `timestamp AT TIME ZONE 'Europe/Londn'` does not return null, it RAISES. Every hours
-- query below is set-based across all 348 sites, so ONE typo in ONE row aborts the whole
-- nightly pass for every other pharmacy. Two defences, and both are needed:
--
--   site_tz()    the READ path. Never raises: an unknown or empty zone name resolves to the
--                estate default, so a bad row costs that ONE site its own hours and nothing
--                else. Every AT TIME ZONE in this file goes through it.
--   the trigger  the WRITE path, so a bad value cannot get in at all. The read path is
--                still not allowed to trust it: rows predate the trigger, and an OS tzdata
--                update can retire a zone name that was valid when it was written.
CREATE OR REPLACE FUNCTION site_tz(p_tz text) RETURNS text
LANGUAGE plpgsql STABLE AS $fn$
DECLARE t text := NULLIF(btrim(p_tz), '');
BEGIN
  IF t IS NULL THEN RETURN 'Europe/London'; END IF;
  -- The cheapest total test there is: ask Postgres to use it, and catch the refusal.
  PERFORM now() AT TIME ZONE t;
  RETURN t;
EXCEPTION WHEN OTHERS THEN
  RETURN 'Europe/London';
END;
$fn$;

CREATE OR REPLACE FUNCTION pharmacies_check_timezone() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
  IF NEW.timezone IS NULL OR btrim(NEW.timezone) = '' THEN
    NEW.timezone := 'Europe/London';
  ELSIF site_tz(NEW.timezone) <> NEW.timezone THEN
    RAISE EXCEPTION 'timezone "%" is not a zone name this server knows (see pg_timezone_names)',
      NEW.timezone USING ERRCODE = 'invalid_parameter_value';
  END IF;
  RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS pharmacies_check_timezone_trg ON pharmacies;
CREATE TRIGGER pharmacies_check_timezone_trg
  BEFORE INSERT OR UPDATE OF timezone ON pharmacies
  FOR EACH ROW EXECUTE FUNCTION pharmacies_check_timezone();

-- Repair anything that got in before the trigger existed. A silent correction is right here
-- and only here: the alternative is a site whose hours never resolve at all.
UPDATE pharmacies SET timezone = 'Europe/London' WHERE site_tz(timezone) <> timezone;

-- ── per-site weekly opening hours ────────────────────────────────────────────
-- ONE ROW PER CONTIGUOUS OPEN BLOCK PER WEEKDAY. Not open_time/close_time columns on
-- pharmacies: the estate already violates that shape. A Saturday with different hours is its
-- own rows, and a lunchtime close is two rows for that weekday.
--
-- Times are SECONDS FROM MIDNIGHT, which is not an arbitrary choice: it is exactly what
-- Kazoo temporal_rules already store (time_window_start 32400 = 09:00), so a row here maps
-- 1:1 onto a VoIP time profile with no conversion and no rounding.
--
-- wday is 0=Sunday..6=Saturday to match EXTRACT(dow), because the hours functions below
-- join on it; the Kazoo importer converts its wdays[] names into these integers.
--
-- `source` records where the row came from so the UI can say which it used — the estate
-- owner's decision is that VoIP time profiles are the import source and a manual row is an
-- override somebody typed. See the import note at the foot of this block.
CREATE TABLE IF NOT EXISTS pharmacy_hours (
    id           bigserial   PRIMARY KEY,
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    wday         int         NOT NULL CHECK (wday BETWEEN 0 AND 6),   -- 0 = Sunday (EXTRACT(dow))
    opens_s      int         NOT NULL CHECK (opens_s  BETWEEN 0 AND 86400),
    closes_s     int         NOT NULL CHECK (closes_s BETWEEN 0 AND 86400),
    -- A block that ends before it starts is not a midnight-crossing block, it is a typo. A
    -- genuine site trading past midnight is two rows, which is also how Kazoo models it.
    CHECK (closes_s > opens_s),
    source       text        NOT NULL DEFAULT 'manual' CHECK (source IN ('voip','manual')),
    -- The Kazoo temporal_rule this row was imported from, so a re-import can update in place
    -- instead of duplicating. Soft reference: Kazoo is a different database on a different box.
    voip_rule_id text,
    label        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   text,
    UNIQUE (pharmacy_id, wday, opens_s)
);
CREATE INDEX IF NOT EXISTS pharmacy_hours_site_idx ON pharmacy_hours (pharmacy_id, wday);

-- ── one-off days ─────────────────────────────────────────────────────────────
-- Bank holidays and one-off closures, DELIBERATELY a separate table. Kazoo models these as
-- separate temporal_rules for the same reason: mixing recurring and one-off rows into one
-- shape is what makes hours logic go wrong, and it goes wrong on the day it matters most.
--
-- A row REPLACES the weekly pattern for that date. Both times NULL = closed all day, which
-- is the common case.
CREATE TABLE IF NOT EXISTS pharmacy_hours_exceptions (
    pharmacy_id bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    on_date     date        NOT NULL,
    opens_s     int         CHECK (opens_s  BETWEEN 0 AND 86400),
    closes_s    int         CHECK (closes_s BETWEEN 0 AND 86400),
    CHECK ((opens_s IS NULL) = (closes_s IS NULL)),
    CHECK (closes_s IS NULL OR closes_s > opens_s),
    reason      text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text,
    PRIMARY KEY (pharmacy_id, on_date)
);

-- ── weekdays a site is KNOWN to be closed ────────────────────────────────────
-- The other half of the per-weekday fallback below, and the reason it needs a table of its
-- own. Once the fallback is per WEEKDAY, "this site has no Saturday rows" means two
-- entirely different things and absence cannot tell them apart:
--
--   the site does not trade on Saturday                  -> CLOSED. Restarting a counter
--                                                           then is safe.
--   Saturday's rows were never imported, or were lost    -> UNKNOWN. It is NOT.
--
-- So "closed on this weekday" is written down EXPLICITLY, and a weekday with neither an
-- open block nor a row here is UNKNOWN — which site_hours_v answers with the estate
-- fallback window, and which pmr_disruptive_allowed() therefore answers FALSE for during it
-- (the gate refuses to act on an unknown; see the asymmetry block below).
--
-- The loss is not hypothetical. Crossbar caps a list response at 50 rows and signals more
-- with next_start_key; temporal_rules is one of the endpoints found truncated in production
-- (50 of 67). A site that lost its Saturday rule that way used to read as "closed all day
-- Saturday", and an unattended reboot fired at 10:30 on a trading day.
CREATE TABLE IF NOT EXISTS pharmacy_hours_closed (
    pharmacy_id bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    wday        int         NOT NULL CHECK (wday BETWEEN 0 AND 6),
    source      text        NOT NULL DEFAULT 'manual' CHECK (source IN ('voip','manual')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text,
    PRIMARY KEY (pharmacy_id, wday)
);

-- ── the estate fallback window (FLEET-WIDE, exactly one row) ─────────────────
-- Used for a site that has no hours of its own — no VoIP account, or a VoIP account with no
-- time profile. The branding table is the precedent for the shape: one flat row pinned to
-- id = 1 by the CHECK, because a second row would silently split the estate's fallback in
-- two, and there is deliberately no per-site override here (a site that needs one has
-- pharmacy_hours rows instead).
--
-- ⚠️ THE DEFAULT IS DELIBERATELY GENEROUS — every day, 07:00 to 21:00. Guessing narrow
-- (Mon-Fri 09:00-18:00) would put a Saturday morning outside the window.
--
-- ⛔ AND IT IS A GUESS, WHICH IS ALL IT IS. This block used to end "guessing wide costs
-- nothing: the nightly restart happens at local midnight, which is inside 21:00-07:00 either
-- way" — and that sentence was wrong for exactly the sites the gate is most dangerous at. A
-- pharmacy trading until 23:00, or round the clock, is INSIDE 21:00-07:00 at midnight and
-- open for business, and the gate read the guess as a fact and signed the counter out (A1).
--
-- So this window is no longer load-bearing for the gate at all. It is what the SCREEN shows
-- for a weekday nobody has told us about, labelled 'fallback' so an operator can see that
-- nobody has. The gate reads site_hours_gate_resolved(), which does not look at this table,
-- and refuses to act unattended on any day this row is answering for.
CREATE TABLE IF NOT EXISTS estate_hours (
    id         smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    wdays      int[]       NOT NULL DEFAULT '{0,1,2,3,4,5,6}',
    opens_s    int         NOT NULL DEFAULT 25200 CHECK (opens_s  BETWEEN 0 AND 86400),  -- 07:00
    closes_s   int         NOT NULL DEFAULT 75600 CHECK (closes_s BETWEEN 0 AND 86400),  -- 21:00
    CHECK (closes_s > opens_s),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text
);
INSERT INTO estate_hours (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- The row must be there, and a migration that leaves it missing is worth failing on: it is
-- the window the editor shows and the number an operator would change.
--
-- It is NOT, however, what makes the platform fail safe. site_hours_v carries the same
-- window as literals via COALESCE, and pmr_disruptive_allowed() answers FALSE for a site
-- that resolves to no hours at all, so DELETING this row cannot open the gate on a trading
-- pharmacy. That is the point of B2: the fail-safe is a property of the FUNCTION, never of a
-- row somebody can remove.
DO $estate$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM estate_hours WHERE id = 1) THEN
    RAISE EXCEPTION 'estate_hours has no id=1 row — the estate fallback window is missing';
  END IF;
END
$estate$;

-- THE definition of a site's effective hours. Both the editor in Watchman and the
-- server-side resolver read this ONE view, exactly as pharmacy_vms_v is the one definition
-- of what a thin client may be pointed at — so the screen can never show hours the gate
-- would then disagree with.
--
-- ⚠️ THE FALLBACK IS PER WEEKDAY, NOT PER SITE (B1). The previous shape attached the estate
-- window only WHERE NOT EXISTS any pharmacy_hours row for the site, which is all-or-nothing:
-- a site that lost its Saturday rule to the Crossbar 50-row cap kept its Mon-Fri rows, had
-- ZERO Saturday blocks, and therefore read as closed for the whole of Saturday. The gate
-- read that absence as "shut" and an unattended reboot fired at 10:30 on a trading day.
--
-- Now a weekday resolves in one of three ways, and the third is the one that matters:
--   an open block          -> the site's own hours for that weekday
--   a pharmacy_hours_closed row -> KNOWN closed. Nothing is emitted for that weekday.
--   neither                -> UNKNOWN, and the estate fallback window is emitted for it.
--
-- ⚠️ AND THE FALLBACK WINDOW IS NOT A ROW THIS DEPENDS ON (B2). The old arm was a CROSS JOIN
-- against estate_hours, which yields ZERO ROWS against an empty table — silently, for every
-- site, because no site has pharmacy_hours rows today. The window is now COALESCEd against
-- the same literals the table defaults to, so deleting the estate row narrows nothing.
DROP VIEW IF EXISTS site_hours_v;
CREATE VIEW site_hours_v AS
SELECT p.id   AS pharmacy_id,
       p.code AS site_code,
       site_tz(p.timezone) AS timezone,
       h.wday, h.opens_s, h.closes_s,
       h.source,
       h.label
  FROM pharmacies p
  JOIN pharmacy_hours h ON h.pharmacy_id = p.id
UNION ALL
SELECT p.id, p.code,
       site_tz(p.timezone),
       w.wday,
       COALESCE(e.opens_s, 25200),    -- 07:00, the same default the table carries
       COALESCE(e.closes_s, 75600),   -- 21:00
       'fallback',
       'estate fallback window — nothing is known about this weekday at this site'
  FROM pharmacies p
  CROSS JOIN generate_series(0, 6) AS w(wday)
  -- LEFT, not CROSS: an empty estate_hours must not delete the fallback (B2).
  LEFT JOIN estate_hours e ON e.id = 1
 WHERE NOT EXISTS (SELECT 1 FROM pharmacy_hours ph
                    WHERE ph.pharmacy_id = p.id AND ph.wday = w.wday)
   AND NOT EXISTS (SELECT 1 FROM pharmacy_hours_closed pc
                    WHERE pc.pharmacy_id = p.id AND pc.wday = w.wday)
   AND w.wday = ANY (COALESCE(e.wdays, '{0,1,2,3,4,5,6}'::int[]));

-- ── ⛔ A GUESS MUST NOT BE INDISTINGUISHABLE FROM A FACT (A1) ────────────────
-- The two functions below exist because the per-weekday fallback ABOVE defeated the safety
-- property the whole feature was built to create, and it did it silently.
--
-- WHAT WENT WRONG. site_hours_v emits an estate-fallback row for every weekday nobody has
-- told us about, and site_hours_state()'s `known` CTE is satisfied by the mere EXISTENCE of
-- a site_hours_v row. pharmacies is inner-joined, so EVERY pharmacy that exists has seven
-- fallback rows, so `resolved` was TRUE for every site in the estate however little was
-- known about it. The gate then read `resolved AND is_open IS FALSE` and got a confident
-- answer built entirely out of a guess.
--
-- WHAT THAT COSTS, concretely. A 24-hour or late-trading pharmacy whose hours were never
-- imported sits at 00:30 local with resolved=true and is_open=false FROM THE GUESS (the
-- fallback window is 07:00-21:00), inside the night band, with the next guessed opening more
-- than an hour away. pmr_disruptive_allowed() returned TRUE and the unattended nightly
-- restart signed a TRADING counter out.
--
-- THE ASSUMPTION THAT FAILED is written a few lines above, in this file: "guessing wide costs
-- nothing: the nightly restart happens at local midnight, which is inside 21:00-07:00 either
-- way". That is true of a site that shuts in the evening and false of exactly the sites this
-- gate is most dangerous at — the ones trading past 21:00.
--
-- THE FIX IS PROVENANCE, NOT A NARROWER GUESS. The fallback stays exactly as it is for the
-- SCREEN: an operator looking at a site with no imported hours should still see a window and
-- the word 'fallback' next to it, and site_hours_state().resolved keeps its present meaning
-- so the UI's tri-state is unchanged. What changes is that the GATE now asks a different and
-- stricter question — "is the answer for the days that decide this made of FACTS?" — and
-- these two functions are the one place that question is answered.
--
-- They read pharmacy_hours / pharmacy_hours_closed / pharmacy_hours_exceptions DIRECTLY and
-- never site_hours_v, which is the whole point: site_hours_v is where the guess is mixed in,
-- so a gate that reads it cannot tell the two apart.
CREATE OR REPLACE FUNCTION site_hours_day_known(p_pharmacy_id bigint, p_local_date date)
RETURNS boolean LANGUAGE sql STABLE AS $fn$
  -- Is this site's state on this LOCAL CALENDAR DATE a recorded fact? Three ways to be one,
  -- and they are the same three site_hours_state() resolves a day from:
  --   a one-off day for that date   — replaces the weekly pattern, including with nothing
  --   an open block for that weekday
  --   an explicit "we do not trade on this weekday" marker
  -- A weekday with none of them is the case pharmacy_hours_closed was created to separate
  -- out: not "closed", UNKNOWN. The estate fallback answers it on the screen and, from here
  -- on, answers it with FALSE at the gate.
  SELECT EXISTS (SELECT 1 FROM pharmacy_hours_exceptions x
                  WHERE x.pharmacy_id = p_pharmacy_id AND x.on_date = p_local_date)
      OR EXISTS (SELECT 1 FROM pharmacy_hours h
                  WHERE h.pharmacy_id = p_pharmacy_id
                    AND h.wday = EXTRACT(dow FROM p_local_date)::int)
      OR EXISTS (SELECT 1 FROM pharmacy_hours_closed c
                  WHERE c.pharmacy_id = p_pharmacy_id
                    AND c.wday = EXTRACT(dow FROM p_local_date)::int);
$fn$;

-- MAY THE GATE ACT ON THIS SITE AT THIS INSTANT AT ALL — before asking what the hours say.
--
-- ⚠️ TWO LOCAL DAYS, AND EXACTLY TWO. Which days can bear on the gate's answer is not a
-- matter of taste, it falls out of what the gate asks:
--
--   TODAY (site-local) decides "is it shut right now". Nothing earlier can: closes_s is
--        capped at 86400, so a block cannot outlive its own local midnight, and the gate's
--        own test is close_at > p_at. Yesterday's rows are therefore never live.
--   TOMORROW decides "is it about to open". The gate refuses inside pmr_min_closed_s() of
--        the next opening, and at 23:30 the next opening can be tomorrow's — a site that
--        trades from 00:00 opens thirty minutes later while the 07:00 guess says seven
--        hours. That is the A1 failure moved one day along, so tomorrow must be a fact too.
--
-- Requiring MORE days than these would refuse the gate three nights a week over one missing
-- Sunday marker, for no safety gained; requiring fewer re-opens the hole. A site whose whole
-- week is known is unaffected — which is the state every site should be in, and the state
-- the editor's unknown_wdays list exists to drive sites towards.
CREATE OR REPLACE FUNCTION site_hours_gate_resolved(p_pharmacy_id bigint,
                                                    p_at timestamptz DEFAULT now())
RETURNS boolean LANGUAGE sql STABLE AS $fn$
  -- COALESCE to false, so a pharmacy_id naming no row is a refusal and not a NULL that a
  -- caller might read as "no objection". Same direction as pmr_disruptive_allowed() itself.
  SELECT COALESCE((
    SELECT site_hours_day_known(p.id, (p_at AT TIME ZONE site_tz(p.timezone))::date)
       AND site_hours_day_known(p.id, ((p_at AT TIME ZONE site_tz(p.timezone))::date + 1))
      FROM pharmacies p WHERE p.id = p_pharmacy_id
  ), false);
$fn$;

-- ── THE hours helper ─────────────────────────────────────────────────────────
-- "Is site X open at time T, when does it next close, and when does it next open?"
--
-- IT LIVES IN POSTGRES, not in JavaScript and not on a Pi, for one reason that decides it:
-- the gate on a disruptive job has to be evaluated INSIDE the statement that claims the job,
-- because the ingest is a 3-worker cluster and a read-then-decide-then-claim would let two
-- workers hand out the same session-restart. Everything else — the API, the UI, the worker —
-- reads this same function, so there is one answer to "is it open" in the whole platform.
--
-- ⚠️ THE DELIBERATE ASYMMETRY, and it is the load-bearing decision in this whole feature:
--
--     site_hours_state()       answers a SCREEN. Unknown must be NULL — say "unknown",
--                              never claim "closed", because the frontend renders a false
--                              `openNow` as fact and an operator acts on it.
--     pmr_disruptive_allowed() answers a GATE.   Unknown must be FALSE — do not disrupt,
--                              because the cost of being wrong is a pharmacist signed out
--                              of a live dispensing session by a data gap.
--
-- Same question, opposite failure directions, because the two answers are used for opposite
-- things. TWO columns carry the distinction across the boundary, and they are NOT the same
-- column wearing two hats — that conflation is what A1 was:
--
--     resolved       "can this site be described at all" — the SCREEN's word. A fallback
--                    weekday counts, because the screen shows the fallback window and says
--                    so. Its meaning is unchanged and the UI's tri-state is unchanged.
--     gate_resolved  "is the answer for the days that decide a disruption made of FACTS" —
--                    the GATE's word, from site_hours_gate_resolved() above. A fallback
--                    weekday does NOT count. This is the one the gate reads.
--
-- resolved is therefore true for every pharmacy that exists, and that is fine; gate_resolved
-- is true only for a site somebody has actually told us about.
--
-- ⚠️ THE GATE HALF USED TO BE NAMED HERE AS site_open_at(), AND THAT FUNCTION IS GONE (D8).
-- It answered "is the site open this second", with TRUE for unknown — the right polarity for
-- a gate, but the wrong QUESTION: "shut this second" made a lunchtime close a restart window
-- (S2). Every gate in the platform now reads pmr_disruptive_allowed(), which asks "is
-- anybody likely at the counter" and answers only for the site's own overnight window.
-- site_open_at() had no caller left in db/ or src/ while three comments — this one included —
-- still presented it as the safety mechanism. A dead function the comments call the gate is
-- how the next person gets it wrong, so it is DROPPED below rather than left to be read.
--
-- DST is handled by `timestamp AT TIME ZONE tz`, which is why the local calendar date is
-- computed first and the seconds-from-midnight added to it as a LOCAL timestamp: 09:00 on a
-- transition Sunday is 09:00 local, whatever that is in UTC that day.
--
-- DROP then CREATE, not CREATE OR REPLACE: `resolved` and now `gate_resolved` are OUT columns
-- added after the fact, and a replace may only append to the record type in some versions —
-- dropping is unambiguous. No view depends on this function, so nothing cascades.
DROP FUNCTION IF EXISTS site_hours_state(bigint, timestamptz);
CREATE FUNCTION site_hours_state(p_pharmacy_id bigint, p_at timestamptz DEFAULT now())
RETURNS TABLE (is_open boolean, hours_source text, next_open_at timestamptz,
               next_close_at timestamptz, site_timezone text, resolved boolean,
               gate_resolved boolean)
LANGUAGE sql STABLE AS $fn$
  WITH site AS (
      SELECT p.id, site_tz(p.timezone) AS tz
        FROM pharmacies p WHERE p.id = p_pharmacy_id
  ),
  -- Does this site resolve to ANY statement about its hours? An open block, a fallback
  -- weekday, an explicit closed weekday or a one-off day all count. A pharmacy_id that names
  -- no row — or a site that resolves to nothing whatever — is UNRESOLVED, and every answer
  -- below is then NULL rather than false.
  known AS (
      SELECT (EXISTS (SELECT 1 FROM site) AND (
                 EXISTS (SELECT 1 FROM site_hours_v h WHERE h.pharmacy_id = p_pharmacy_id)
              OR EXISTS (SELECT 1 FROM pharmacy_hours_closed c WHERE c.pharmacy_id = p_pharmacy_id)
              OR EXISTS (SELECT 1 FROM pharmacy_hours_exceptions x WHERE x.pharmacy_id = p_pharmacy_id)
             )) AS ok
  ),
  -- Local calendar dates either side of the instant. -1 day so a block that opened
  -- yesterday and has not closed yet is still seen; +14 so a site that opens one day a week
  -- still yields a "next open" rather than a null the UI has to explain.
  days AS (
      SELECT s.tz, g.d::date AS local_date
        FROM site s,
             generate_series(((p_at AT TIME ZONE s.tz)::date - 1)::timestamp,
                             ((p_at AT TIME ZONE s.tz)::date + 14)::timestamp,
                             interval '1 day') AS g(d)
  ),
  -- One row per concrete open block in absolute time. An exception day REPLACES the weekly
  -- pattern for its date — including replacing it with nothing, which is a closed day.
  blocks AS (
      SELECT (dy.local_date + (x.opens_s  * interval '1 second')) AT TIME ZONE dy.tz AS open_at,
             (dy.local_date + (x.closes_s * interval '1 second')) AT TIME ZONE dy.tz AS close_at
        FROM days dy
        JOIN pharmacy_hours_exceptions x
          ON x.pharmacy_id = p_pharmacy_id AND x.on_date = dy.local_date
       WHERE x.opens_s IS NOT NULL AND x.closes_s IS NOT NULL
      UNION ALL
      SELECT (dy.local_date + (h.opens_s  * interval '1 second')) AT TIME ZONE dy.tz,
             (dy.local_date + (h.closes_s * interval '1 second')) AT TIME ZONE dy.tz
        FROM days dy
        JOIN site_hours_v h
          ON h.pharmacy_id = p_pharmacy_id
         AND h.wday = EXTRACT(dow FROM dy.local_date)::int
       WHERE NOT EXISTS (SELECT 1 FROM pharmacy_hours_exceptions x
                          WHERE x.pharmacy_id = p_pharmacy_id AND x.on_date = dy.local_date)
  ),
  -- Which of the three sources the answer came from. A site with any imported row reads
  -- 'voip' even if somebody has since typed one override, because the import is what will
  -- overwrite it next time and the UI has to say so. Closed weekdays are counted too: a
  -- site whose whole week is "we do not trade" has a real, human-set answer.
  src AS (
      SELECT CASE WHEN bool_or(u.source = 'voip')   THEN 'voip'
                  WHEN bool_or(u.source = 'manual') THEN 'manual'
                  ELSE 'fallback' END AS source
        FROM (SELECT h.source FROM site_hours_v h WHERE h.pharmacy_id = p_pharmacy_id
              UNION ALL
              SELECT c.source FROM pharmacy_hours_closed c WHERE c.pharmacy_id = p_pharmacy_id) u
  )
  SELECT CASE WHEN (SELECT ok FROM known)
              THEN EXISTS (SELECT 1 FROM blocks b WHERE b.open_at <= p_at AND b.close_at > p_at)
         END,
         CASE WHEN (SELECT ok FROM known)
              THEN COALESCE((SELECT source FROM src), 'fallback')
         END,
         (SELECT min(b.open_at)  FROM blocks b WHERE b.open_at  > p_at),
         (SELECT min(b.close_at) FROM blocks b WHERE b.close_at > p_at AND b.open_at <= p_at),
         COALESCE((SELECT tz FROM site), 'Europe/London'),
         (SELECT ok FROM known),
         -- ⛔ NOT `known`. This is the GATE's resolution and it is deliberately a different
         -- and stricter question — see the A1 block above site_hours_day_known(). Surfaced
         -- here as well as inside pmr_disruptive_allowed() so that the API, the site page and
         -- the interrupting routes in handlers.js all read the same fact from the same place,
         -- rather than each deciding for itself what "we do not really know" means.
         site_hours_gate_resolved(p_pharmacy_id, p_at);
$fn$;

-- ── site_open_at() IS DELETED, ON PURPOSE (D8) ───────────────────────────────
-- It was the original gate: "is this site open at time T", TRUE for unknown. The polarity
-- was right and the question was wrong — "shut this second" turned a lunchtime close into a
-- restart window and signed out the dispenser at the bench over lunch (S2). It was replaced
-- by pmr_disruptive_allowed() below, which asks "is anybody likely at the counter" and
-- answers TRUE only inside the site's own overnight window.
--
-- By the time this drop was written NOTHING called it — no query in db/, no statement in
-- src/, no view — while three separate comments still described it as the mechanism that
-- keeps a pharmacist from being signed out. That is the dangerous state: the next person to
-- add a gate reads the comments, finds a function that does exactly what they need, calls
-- it, and ships an intraday restart window. Dropping it is what makes the comments and the
-- code agree.
--
-- IF YOU ARE LOOKING FOR IT: the three questions it used to answer now have three answers.
--   "is the site open right now, for a SCREEN"      -> site_hours_state().is_open
--   "may an unattended disruptive job run NOW"      -> pmr_disruptive_allowed()
--   "when may one next run"                         -> site_next_disruptive_window()
--
-- IF NOT EXISTS so a fresh bootstrap, where it was never created, applies this cleanly.
DROP FUNCTION IF EXISTS site_open_at(bigint, timestamptz);

-- ── WHEN AN UNATTENDED DISRUPTIVE JOB MAY RUN ────────────────────────────────
-- "The site is shut this second" is NOT the question, and treating it as one is how a
-- lunchtime close became a restart window: at 13:00:00 the gate flipped and the dispenser
-- at the bench over lunch was signed out of the session they were coming back to (S2).
--
-- The question is "is anybody likely at the counter", and the answer this platform commits
-- to is the NIGHT. An unattended disruptive job runs in the site's own overnight window and
-- at no other time — never in an intraday gap, however long. A half-day, a lunchtime close,
-- a staff-training afternoon and a bank holiday morning are all times when somebody is
-- behind the counter with the shutters down, and none of them is a maintenance window.
--
-- The alternative considered was "closed AND stays closed for N hours", which is rejected:
-- a Saturday half-day closing at 13:00 and reopening Monday satisfies any N, and 13:00
-- Saturday is exactly the moment a dispenser is still finishing the morning's scripts. The
-- night window has no such edge, and the one thing it costs — an operator who genuinely
-- wants a restart at 14:00 — is already served by apply-now, which is attributed, recorded,
-- and confirms the sentence "this signs the member of staff at that counter out".
--
-- Seconds from LOCAL midnight, as functions rather than literals so the gate and the
-- "when will this run" answer cannot drift apart.
CREATE OR REPLACE FUNCTION pmr_night_start_s() RETURNS int LANGUAGE sql IMMUTABLE AS $fn$ SELECT 79200 $fn$;  -- 22:00
CREATE OR REPLACE FUNCTION pmr_night_end_s()   RETURNS int LANGUAGE sql IMMUTABLE AS $fn$ SELECT 21600 $fn$;  -- 06:00
-- How far from the next opening the job must still be. Stops a restart at 05:55 for a site
-- that opens at 06:00 and has not finished coming back up.
CREATE OR REPLACE FUNCTION pmr_min_closed_s() RETURNS int LANGUAGE sql IMMUTABLE AS $fn$ SELECT 3600 $fn$;

-- THE gate. TRUE only when every one of these is POSITIVELY known:
--   the site exists, its hours resolve FROM ITS OWN RECORDED ROWS, it is shut right now, its
--   own local clock is inside the night window, and it is not about to open.
--
-- ⛔ IT GATES ON gate_resolved, NEVER ON resolved (A1). `resolved` is true for every pharmacy
-- in the estate, because site_hours_v hands every unknown weekday the estate fallback window
-- and the mere existence of that row satisfied the old test. Reading it here meant the gate
-- was answering out of a 07:00-21:00 GUESS: a 24-hour pharmacy nobody had entered hours for
-- read as "shut, in the night band, opens in seven hours", and the nightly restart signed a
-- trading counter out. gate_resolved is FALSE for exactly that site, and the job waits.
-- Anything unknown is FALSE — the job waits. THIS IS THE ONLY GATE. It is the sole reader of
-- "may we interrupt" in the platform: the job claim, the job INSERT, the nightly pass, the
-- boot-target promoter and the three counter routes in handlers.js all call this one
-- function, so a lunchtime close, a data gap and a bank-holiday morning get the same answer
-- everywhere. (site_open_at(), which used to share this job with the opposite polarity, is
-- dropped above.)
CREATE OR REPLACE FUNCTION pmr_disruptive_allowed(p_pharmacy_id bigint, p_at timestamptz DEFAULT now())
RETURNS boolean LANGUAGE sql STABLE AS $fn$
  SELECT COALESCE((
    SELECT s.gate_resolved
       -- Still IS FALSE and not "NOT is_open": gate_resolved TRUE implies resolved TRUE (a
       -- known day is a pharmacy_hours, pharmacy_hours_closed or exception row, and any of
       -- the three satisfies `known`), so is_open cannot be NULL here — but the strict test
       -- costs nothing and keeps this readable as "positively shut".
       AND s.is_open IS FALSE
       AND (EXTRACT(epoch FROM (p_at AT TIME ZONE s.site_timezone)::time)::int >= pmr_night_start_s()
         OR EXTRACT(epoch FROM (p_at AT TIME ZONE s.site_timezone)::time)::int <  pmr_night_end_s())
       AND (s.next_open_at IS NULL
         OR s.next_open_at > p_at + make_interval(secs => pmr_min_closed_s()))
      FROM site_hours_state(p_pharmacy_id, p_at) s
  ), false);
$fn$;

-- WHEN the gate will next open, in absolute time. This is the value that turns "it applies
-- at midnight" from a sentence in a wait-reason into a stored fact on the row (S1/S12): the
-- job's not_before AND its expiry are both computed from it, so a 90-minute TTL and a
-- promise of midnight can no longer both be true of the same job.
--
-- It probes the SAME predicate the claim query gates on rather than re-deriving the rule, so
-- the time an operator is promised and the time the job is actually released are one
-- calculation. Probes are half-hourly and only inside the night window, so the common answer
-- — tonight's 22:00 — costs one evaluation.
--
-- NULL means "never, as far as the next eight days can see": a 24-hour pharmacy. That is a
-- real answer and the caller must handle it by NOT creating the job, not by picking a time.
CREATE OR REPLACE FUNCTION site_next_disruptive_window(p_pharmacy_id bigint,
                                                       p_at timestamptz DEFAULT now())
RETURNS timestamptz LANGUAGE plpgsql STABLE AS $fn$
DECLARE
  v_tz       text;
  v_open     boolean;
  v_close    timestamptz;
  v_resolved boolean;
  probe      timestamptz;
  secs       int;
  i          int := 0;
BEGIN
  IF p_pharmacy_id IS NULL THEN RETURN NULL; END IF;
  SELECT site_tz(p.timezone) INTO v_tz FROM pharmacies p WHERE p.id = p_pharmacy_id;
  IF v_tz IS NULL THEN RETURN NULL; END IF;

  SELECT s.is_open, s.next_close_at, s.resolved
    INTO v_open, v_close, v_resolved
    FROM site_hours_state(p_pharmacy_id, p_at) s;
  -- Unknown hours never produce a window. A job at such a site waits indefinitely, which is
  -- the correct direction: nothing may be applied unattended to a site nobody has told us
  -- the hours of.
  IF v_resolved IS NOT TRUE THEN RETURN NULL; END IF;

  -- ⛔ AND A SITE WITH NO HOURS FACTS OF ITS OWN HAS NO WINDOW AT ALL (A1). Since the
  -- fallback made `resolved` true for every pharmacy, the test above stopped excluding
  -- anything; without this the loop below would run 400 probes per site per pass, every one
  -- of them refused by pmr_disruptive_allowed()'s gate_resolved term, and return NULL after
  -- doing 348 sites' worth of work to reach the answer this one EXISTS test gives.
  --
  -- It is deliberately the WEAKEST form of the question — "has anybody said anything about
  -- this site" — not site_hours_gate_resolved(p_at). A site whose Monday is known and whose
  -- Sunday is not still has real windows later in the week, and the loop is what finds them;
  -- short-circuiting on today's answer would refuse those too.
  IF NOT EXISTS (SELECT 1 FROM pharmacy_hours h WHERE h.pharmacy_id = p_pharmacy_id)
     AND NOT EXISTS (SELECT 1 FROM pharmacy_hours_closed c WHERE c.pharmacy_id = p_pharmacy_id)
     AND NOT EXISTS (SELECT 1 FROM pharmacy_hours_exceptions x WHERE x.pharmacy_id = p_pharmacy_id)
  THEN
    RETURN NULL;
  END IF;
  -- Open now with no close anywhere in the next fifteen days is a site that does not shut.
  -- Short-circuited rather than discovered by 400 probes, because the nightly pass asks this
  -- of every 24-hour site every night.
  IF v_open AND v_close IS NULL THEN RETURN NULL; END IF;

  probe := date_trunc('hour', p_at);
  WHILE i < 400 LOOP          -- 400 half-hours ≈ 8 days
    IF probe > p_at THEN
      secs := EXTRACT(epoch FROM (probe AT TIME ZONE v_tz)::time)::int;
      -- The cheap test first, so the expensive one runs ~16 times a day and not 48.
      IF (secs >= pmr_night_start_s() OR secs < pmr_night_end_s())
         AND pmr_disruptive_allowed(p_pharmacy_id, probe) THEN
        RETURN probe;
      END IF;
    END IF;
    probe := probe + interval '30 minutes';
    i := i + 1;
  END LOOP;
  RETURN NULL;
END;
$fn$;

-- ── INTENDED STATE ───────────────────────────────────────────────────────────
-- What Watchman WANTS for a subject, next to what was last OBSERVED about it. One row per
-- (subject, field). The reconciler compares the two and, when they differ, writes a job.
--
-- There is no `converges` column: whether a field may converge unattended is a property of
-- the FIELD, not of one site's row, so it lives in the closed whitelist in
-- src/shared/pmrVerbs.js next to the verb that changes it — the same reason per-thin-client
-- settings keep their specs in counterSettings.js and only their values in the database.
--
-- `observed` is written by the reconciler from whatever collector already reports the fact
-- (proxmox_vms for a VM, device_state.raw for a counter). It is never written by whatever
-- executed the job: that is the difference between 'applied' and 'confirmed'.
CREATE TABLE IF NOT EXISTS pmr_intent (
    id           bigserial   PRIMARY KEY,
    subject_kind text        NOT NULL CHECK (subject_kind IN ('site','vm','counter','printer')),
    -- Every intent belongs to a site, including a VM's: it is what the hours gate reads.
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    counter_id   bigint      REFERENCES counters(id) ON DELETE CASCADE,
    -- Soft refs: a VM has no devices row and proxmox_vms is keyed on vmid alone, and a
    -- printer is discovered rather than registered.
    vmid         int,
    printer_key  text,
    field        text        NOT NULL,   -- validated against INTENT_FIELDS before insert
    want         jsonb       NOT NULL,
    observed     jsonb,
    observed_at  timestamptz,
    last_job_id  uuid,
    set_by       text,
    set_at       timestamptz NOT NULL DEFAULT now()
);
-- COALESCE rather than a plain UNIQUE: NULLs are DISTINCT in a unique index, so two
-- site-scoped rows for the same field (both with counter_id null) would both be accepted and
-- the reconciler would fight itself. NULLS NOT DISTINCT would do it on 15+, but this form
-- works on every version this schema claims to support.
CREATE UNIQUE INDEX IF NOT EXISTS pmr_intent_subject_idx ON pmr_intent
    (subject_kind, pharmacy_id, COALESCE(counter_id, 0), COALESCE(vmid, 0),
     COALESCE(printer_key, ''), field);
CREATE INDEX IF NOT EXISTS pmr_intent_site_idx ON pmr_intent (pharmacy_id);

-- ── JOBS ─────────────────────────────────────────────────────────────────────
-- Modelled on config_jobs — the two-stage ladder, the WHERE-guarded transitions that make a
-- double-approve and a late-cancel no-ops, the partial pickup index, result_log — and
-- deliberately NOT the same table. config_jobs is RouterOS by every column: kind
-- ('snippet','full'), rsc_text, and a sha that exists only because the device fetches BYTES
-- over a second request. A PMR job has no byte path at all, so a sha here would be ceremony.
--
-- THE STATUS LADDER
--   pending ──claimed on the reply to a poll──> claimed ──executor reports──> applied
--           └─ expires_at lapses ─> expired          └─ executor reports ──> failed
--   applied ──an INDEPENDENT reading agrees──> confirmed        <-- the only DONE
--   applied ──confirm deadline lapses, no reading──> failed
--   pending|claimed ──operator──> cancelled
-- 'applied' is the executor's word. 'confirmed' is the world's. Nothing marks a job
-- confirmed except the reconciler reading a table some other collector wrote.
--
-- 'waiting' is deliberately NOT a stored status: it is what pmr_job_wait_reason() says about
-- a row that is still 'pending', computed by the same expression the claim query gates on.
-- A stored waiting status would have to be written and unwritten as a site opens and closes,
-- which is a write every worker pass for every held job and a lie in between.
CREATE TABLE IF NOT EXISTS pmr_jobs (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- A NAME the executor looks up in its OWN table. Never a command line. The CHECK mirrors
    -- VERBS in src/shared/pmrVerbs.js, which is where the allowlist is authored — this is
    -- defence in depth for a row inserted by hand, not the primary gate.
    verb         text        NOT NULL CHECK (verb IN (
                                 'counter.session-restart', 'counter.reboot',
                                 'vm.set-onboot', 'vm.start', 'vm.shutdown', 'vm.reboot')),
    executor     text        NOT NULL CHECK (executor IN ('counter-pi','proxmox-node')),

    -- WHO runs it. Exactly one of these is set, matching `executor`.
    pi_device_id uuid        REFERENCES devices(id) ON DELETE CASCADE,
    node         text,                       -- soft ref: a Proxmox node has no devices row

    -- WHAT it is about. Real FKs where a real row exists; vmid stays soft because a VM is
    -- discovered, not registered, and proxmox_vms is keyed on vmid alone.
    pharmacy_id  bigint      REFERENCES pharmacies(id) ON DELETE CASCADE,
    counter_id   bigint      REFERENCES counters(id) ON DELETE CASCADE,
    vmid         int,

    -- Arguments the SERVER resolved, never values a caller supplied. Every value is bounded
    -- by the verb's own spec in pmrVerbs.js (a bool, an enum, or a range-checked integer) —
    -- the same closed-whitelist treatment counterSettings.js gives per-thin-client options,
    -- and for the same reason: these end up as argv on a machine in a pharmacy.
    args         jsonb       NOT NULL DEFAULT '{}'::jsonb,

    -- Does executing this interrupt a session? The single input to the hours gate.
    disruptive   boolean     NOT NULL,
    -- May a lapsed claim be handed out again? The idempotent/non-idempotent distinction
    -- claimRelayRequest makes with method IN ('GET','HEAD'), recorded per job because it is
    -- a property of the verb. Re-handing out a shutdown is not free.
    retry_ok     boolean     NOT NULL DEFAULT false,

    intent_id    bigint      REFERENCES pmr_intent(id) ON DELETE SET NULL,

    status       text        NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending','claimed','applied','confirmed',
                                               'failed','expired','cancelled')),

    -- WHAT INDEPENDENT READING PROVES IT WORKED. Recorded on the row rather than looked up
    -- from the verb at confirm time, so a verb retired or re-specified later still leaves an
    -- old job able to explain what would have proved it.
    confirm_kind text        NOT NULL CHECK (confirm_kind IN (
                                 'pi-session-restarted', 'pi-uptime-reset',
                                 'vm-onboot-matches', 'vm-status-running',
                                 'vm-status-stopped', 'vm-uptime-reset')),
    confirm_deadline_s int   NOT NULL DEFAULT 900,
    confirm_detail text,                     -- the reading itself, in words, for the UI
    -- Set when a counter's RDP session was independently OBSERVED down after this job was
    -- applied. Half of the session-restart proof; see the confirm pass in store.pg.js.
    session_down_at timestamptz,

    -- TIME LIMITS. An unclaimed job EXPIRES rather than firing late: a session restart that
    -- has been sitting in the queue since midnight must not go off at 09:20 because a Pi
    -- came back late.
    not_before   timestamptz,
    expires_at   timestamptz NOT NULL,
    claim_ttl_s  int         NOT NULL DEFAULT 120,
    attempts     int         NOT NULL DEFAULT 0,

    -- "Apply it now, and I know it signs the member of staff out." The ONLY way a disruptive
    -- job runs inside a site's opening hours, and it is deliberately a stored fact with a
    -- name and a time on it rather than a transient flag in a request: what Watchman must
    -- never do is restart a session during opening hours ON ITS OWN, so when one happens the
    -- row has to say which person decided that.
    override_hours boolean   NOT NULL DEFAULT false,
    override_by  text,
    override_at  timestamptz,

    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    claimed_by   text,
    claimed_at   timestamptz,
    applied_at   timestamptz,
    confirmed_at timestamptz,
    finished_at  timestamptz,
    result_log   text
);
-- Partial on the two statuses the claim query can select, exactly as config_jobs_pickup_idx
-- is partial on the one status its device path selects.
CREATE INDEX IF NOT EXISTS pmr_jobs_pi_pickup_idx  ON pmr_jobs (pi_device_id, created_at)
    WHERE status IN ('pending','claimed');
CREATE INDEX IF NOT EXISTS pmr_jobs_node_pickup_idx ON pmr_jobs (node, created_at)
    WHERE status IN ('pending','claimed');
-- The confirm pass sweeps this one every worker tick.
CREATE INDEX IF NOT EXISTS pmr_jobs_confirm_idx ON pmr_jobs (confirm_kind, applied_at)
    WHERE status = 'applied';
CREATE INDEX IF NOT EXISTS pmr_jobs_site_idx ON pmr_jobs (pharmacy_id, created_at DESC);

-- ── HOW MANY TIMES A JOB MAY BE HANDED OUT ───────────────────────────────────
-- counter.session-restart is retry_ok with a 120-second claim TTL inside a 5400-second life,
-- and nothing bounded the retries. An executor that took the job and never reported — a Pi
-- that restarted its session and lost the reply, the ordinary case — was re-offered the same
-- restart every 120 seconds for ninety minutes: forty-five sign-outs, which is a repeating
-- sign-out loop and not a retry (B3).
--
-- Bounded on the ROW rather than only in the claim query, so the reason a job stopped being
-- offered is visible next to the job in pmr_jobs_v instead of being a predicate nobody can
-- see from the screen.
ALTER TABLE pmr_jobs ADD COLUMN IF NOT EXISTS max_attempts int NOT NULL DEFAULT 3;
ALTER TABLE pmr_jobs DROP CONSTRAINT IF EXISTS pmr_jobs_max_attempts_check;
ALTER TABLE pmr_jobs ADD  CONSTRAINT pmr_jobs_max_attempts_check
    CHECK (max_attempts BETWEEN 1 AND 20);

-- ── THE ONE GATE ─────────────────────────────────────────────────────────────
-- Why this job is not being handed out, or NULL if nothing is holding it. Read by the claim
-- query AND by pmr_jobs_v, so the UI's "waiting because…" and the server's decision cannot
-- drift — the failure mode being avoided is a screen that says a job is ready while the
-- claim query silently keeps skipping it.
--
-- Status is NOT tested here on purpose: the claim query also re-offers a 'claimed' row whose
-- visibility window lapsed, and that re-offer has to pass the same hours gate as the first
-- one. A site that opened while an executor was away must not get its session restarted on
-- the retry.
--
-- FIVE arms now, and the order is the order the claim query must apply them in.
--   1. the time limit
--   2. the attempts cap (B3) — the loop-breaker
--   3. an apply-now job that has already been offered once (B3). override_hours is set
--      PERMANENTLY by the operator, so without this arm the override keeps re-releasing the
--      job every claim_ttl_s — INSIDE opening hours, which is the one thing the override was
--      supposed to authorise exactly once.
--   4. not_before, which since S1/S12 is a real stored time and not a promise nobody kept
--   5. the hours gate itself, now pmr_disruptive_allowed() rather than "the site is shut
--      this second" — see the block above it for why an intraday gap is not a window.
CREATE OR REPLACE FUNCTION pmr_job_wait_reason(p_job pmr_jobs, p_at timestamptz DEFAULT now())
RETURNS text LANGUAGE sql STABLE AS $fn$
  SELECT CASE
    WHEN p_job.expires_at <= p_at
      THEN 'expired — the time limit passed before an executor collected it'
    WHEN p_job.attempts >= p_job.max_attempts
      THEN 'given up — handed to an executor ' || p_job.attempts
           || ' times and never reported back'
    WHEN p_job.override_hours AND p_job.attempts > 0
      THEN 'an apply-now override releases a job ONCE — this one has already been handed '
           || 'to an executor, so it will not be offered again'
    WHEN p_job.not_before IS NOT NULL AND p_job.not_before > p_at
      THEN 'held until ' || to_char(p_job.not_before AT TIME ZONE
             COALESCE((SELECT s.site_timezone FROM site_hours_state(p_job.pharmacy_id, p_at) s),
                      'Europe/London'), 'YYYY-MM-DD HH24:MI')
           || ' local — this signs a member of staff out, so it waits for the site''s own '
           || 'overnight window'
    -- ⚠️ THE TWO REASONS A DISRUPTIVE JOB WAITS ARE NOT THE SAME REASON (A1), and after the
    -- provenance fix the second one is the COMMON one: every site whose hours have never been
    -- entered now holds its jobs forever, correctly, and "the site is not safely shut" would
    -- send somebody looking at a clock instead of at the hours editor. Named separately so the
    -- job list tells an operator what to actually do about it.
    WHEN p_job.disruptive AND NOT p_job.override_hours
         AND NOT site_hours_gate_resolved(p_job.pharmacy_id, p_at)
      THEN 'nobody has entered this site''s opening hours, so Watchman is guessing them — and '
           || 'it will not sign a member of staff out on a guess. Enter the hours for this '
           || 'site (or import them from its VoIP time profile) and this will run in its own '
           || 'overnight window; an operator can also apply it now.'
    WHEN p_job.disruptive AND NOT p_job.override_hours
         AND NOT pmr_disruptive_allowed(p_job.pharmacy_id, p_at)
      THEN 'the site is not safely shut — this signs a member of staff out, so it waits for '
           || 'the site''s own overnight window unless an operator applies it now'
    ELSE NULL
  END;
$fn$;

-- ── ⛔ THE TRANSITION THE PROMOTE VERB'S DEFENCE CLAIMS (B2) ─────────────────
-- src/shared/pmrVerbs.js defends counter.printing-promote's self-attested reading with a
-- specific sentence: "print_tab_pending must be observed TRUE-then-FALSE across the moment
-- the job was applied". The confirm pass tested only that it is FALSE now, and nothing
-- anywhere recorded that it had ever been TRUE — so the defence described a check the code
-- did not implement, which is worse than a weak check, because it stops anybody looking.
--
-- This column is the missing half. It is stamped on the telemetry hot path the FIRST time a
-- counter with a promote job in flight reports a staged table, and the confirm pass now
-- requires it — so 'confirmed' means the staged table was seen to exist and then seen to be
-- gone, and not merely that the counter has nothing staged today.
--
-- ⚠️ A PROMOTE THAT CANNOT BE PROVEN FAILS, and that is the intended direction: the verb's own
-- entry says so, and a failed counter job raises that counter in the pre-opening check, which
-- puts a person in front of it before the pharmacy opens. In practice the observation is
-- cheap to make — the table is staged on one tick and the job waits for the overnight window,
-- so print_tab_pending is TRUE for hundreds of ticks before the promote ever runs.
ALTER TABLE pmr_jobs ADD COLUMN IF NOT EXISTS print_tab_staged_at timestamptz;

-- What the UI reads. `waiting_reason` is only meaningful while a job is still pending, and
-- `state` is the word to put on the screen: the stored ladder plus the one derived state.
--
-- DROP then CREATE, not CREATE OR REPLACE: this selects j.*, so the first ALTER that adds a
-- column to pmr_jobs would make a replace fail outright (a replace may only APPEND columns,
-- and a new pmr_jobs column lands in the middle). proxmox_vms_v carries the same note for
-- the same reason.
DROP VIEW IF EXISTS pmr_jobs_v;
CREATE VIEW pmr_jobs_v AS
SELECT j.*,
       p.code AS site_code,
       p.name AS site_name,
       CASE WHEN j.status = 'pending' THEN pmr_job_wait_reason(j, now()) END AS waiting_reason,
       CASE WHEN j.status = 'pending' AND pmr_job_wait_reason(j, now()) IS NOT NULL
            THEN 'waiting' ELSE j.status END AS state
  FROM pmr_jobs j
  LEFT JOIN pharmacies p ON p.id = j.pharmacy_id;

-- ── the nightly restart ledger ───────────────────────────────────────────────
-- One row per site per LOCAL date. The primary key is the whole mechanism: the scheduler
-- claims a night by INSERT … ON CONFLICT DO NOTHING … RETURNING, so a 3-worker cluster runs
-- the night exactly once, and a worker restarted at 00:40 does not run it a second time.
--
-- Local date, not UTC date: a site's night belongs to its own calendar.
CREATE TABLE IF NOT EXISTS pmr_nightly_runs (
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    local_date   date        NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    counters_total   int     NOT NULL DEFAULT 0,
    jobs_created     int     NOT NULL DEFAULT 0,
    intents_promoted int     NOT NULL DEFAULT 0,
    skipped_reason   text,
    -- The pre-opening verification, claimed the same way so one site raises one alert.
    checked_at   timestamptz,
    counters_ok  int,
    counters_at_risk int,
    alerted_at   timestamptz,
    alert_detail text,
    PRIMARY KEY (pharmacy_id, local_date)
);
CREATE INDEX IF NOT EXISTS pmr_nightly_runs_check_idx ON pmr_nightly_runs (started_at)
    WHERE checked_at IS NULL;

-- ── the pre-opening check ledger (ITS OWN TABLE) ─────────────────────────────
-- The verification used to be four columns on pmr_nightly_runs, which meant it could only
-- happen for a site that HAD a nightly row — and a worker down from 23:50 to 01:30 creates
-- no nightly rows. So on exactly the morning when nothing was applied, nothing was checked
-- and nobody was told (S3). The check is not a footnote to the restart; it is the thing that
-- protects the morning, and it has to run whether or not the restart did.
--
-- Keyed on (pharmacy_id, LOCAL date) for the same reason the nightly ledger is: a site's
-- morning belongs to its own calendar.
--
-- THE LEASE, not a stamp (S4). checked_at used to be written at CLAIM time, before the
-- verdict existed — so any failure between claiming and deciding permanently destroyed that
-- site's only alert for the night, silently, on the morning it mattered. Now a claim takes a
-- LEASE that a later pass reclaims when it lapses, and checked_at is written only once the
-- verdict and the alert have actually landed. The failure direction is a duplicate email,
-- which is the right way round.
CREATE TABLE IF NOT EXISTS pmr_opening_checks (
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    local_date   date        NOT NULL,
    next_open_at timestamptz,
    claimed_at   timestamptz NOT NULL DEFAULT now(),
    -- While this is in the future the check belongs to whichever worker holds it. Once it
    -- lapses with checked_at still null, another pass may take it.
    lease_until  timestamptz NOT NULL DEFAULT now(),
    attempts     int         NOT NULL DEFAULT 0,
    -- DONE. Written only by recordPmrOpeningCheck, after the verdict and any alert.
    checked_at   timestamptz,
    counters_ok  int,
    counters_at_risk int,
    alerted_at   timestamptz,
    alert_detail text,
    PRIMARY KEY (pharmacy_id, local_date)
);
CREATE INDEX IF NOT EXISTS pmr_opening_checks_open_idx ON pmr_opening_checks (lease_until)
    WHERE checked_at IS NULL;

-- ── WHAT A VoIP IMPORT WOULD NEED (not built here; no external API is called) ──
-- The estate ALREADY holds per-site opening hours, in Kazoo, as temporal_rules. This block
-- is the destination for them, not a second hand-maintained copy — two copies of a
-- pharmacy's opening hours is a defect waiting for a bank holiday.
--
-- 1. THE MAPPING IS THE MISSING PIECE, and it is bigger than the API client. pharmacy →
--    Kazoo account is a three-hop join across two databases today: pharmacies.crm_site_id →
--    CRM site → company → voip_accounts.kazoo_account_id, and voip_accounts lives in
--    Supabase. The cheap answer is a soft pharmacies.kazoo_account_id column with the same
--    partial UNIQUE index crm_site_id has.
-- 2. THE READER PUSHES OUTWARD, from kazoo-core. Vigilant sits on the DMZ VLAN and Crossbar
--    is bound to 127.0.0.1:8090 on kazoo-core, so Vigilant cannot pull; and the voice
--    bridge authenticates a Supabase USER JWT, which a machine caller does not have. The
--    shape that fits the estate is a small collector ON kazoo-core, modelled on
--    vigilant-proxmox-collector.py, holding the master credential where the VoIP security
--    rule requires it and POSTing rules to an admin endpoint here on a timer.
-- 3. TWO TRAPS ARE ALREADY DOCUMENTED — do not rediscover them. Crossbar caps list
--    responses at 50 and signals more with next_start_key; temporal_rules is one of the
--    endpoints found truncated in production (50 of 67). And the token must be cached
--    (~50 min) with one transparent refresh on 401, or /user_auth trips a Kazoo lockout.
-- 4. THE CONVERSION IS 1:1 AND LOSSLESS. A temporal_rule's time_window_start/stop ARE
--    opens_s/closes_s; its wdays[] names expand to one pharmacy_hours row each; its rule id
--    goes in voip_rule_id so a re-import updates in place. Rows land with source='voip'.
--    ⚠️ Only the rules a callflow's temporal_route lists as OPEN branches are hours — the
--    `_` branch is the closed branch and there is no "closed rule", so importing every
--    temporal_rule in an account would invert some sites.
-- 5. DIRECTION IS ONE-WAY. Kazoo is authoritative, this table is derived. Writing hours
--    BACK to Kazoo means rewriting temporal_route.data.rules and its child branches, which
--    is live call routing for pharmacies, and is a separate explicitly-approved piece of
--    work — not a side effect of a control-plane feature.

-- ═══════════════════════════════════════════════════════════════════════════
-- THE PRINTER MODEL — docs/pmr-printer-contract.md §1, in tables
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ⛔ READ docs/pmr-printer-contract.md IN FULL BEFORE CHANGING ANYTHING BELOW. It is the one
-- source of truth for this format and there are five owners of it; the server's half of §2
-- lives in src/shared/printerQueues.js and quotes the file rather than restating it.
--
-- WHY THESE TABLES EXIST AT ALL. `printers` above mixes CUPS queues with network-sweep hits
-- and is KEYED BY NAME (UNIQUE (pharmacy_id, name)), so renaming a queue ORPHANS the old row:
-- at iPharm one Zebra sits in it three times under three retired names. §1 answers that —
-- "Physical device | USB serial, or network MAC/serial | NOT its name. A printer keeps its
-- identity across a rename and across a move to another counter."
--
-- ⚠️ `printers` IS NOT DELETED, REPLACED OR REWRITTEN. It is the DISCOVERY feed — SNMP/IPP
-- sweeps and CUPS polls — and desktopPrinters.js's shelve()/identified() helpers exist to cope
-- with exactly its mess. These four objects are ADOPTED ALONGSIDE it, and printers_v is
-- re-created further down to carry `assigned_vmids` so the flow graph reads assignment from
-- the discovery row it already renders.
--
-- The four objects, in §1's own words:
--   Physical device | USB serial, or network MAC/serial   -> pmr_printer_devices
--   Queue           | (device, tray label)                -> pmr_printer_queues
--   Host            | the Pi with the USB connection      -> pmr_printer_queues.counter_id
--                                                            (+ devices.host_counter_id)
--   Assignment      | queue -> desktop (VM)               -> pmr_printer_assignments

-- ── 1 · THE PHYSICAL DEVICE ─────────────────────────────────────────────────
-- Observed, not registered: rows are written from peripherals.printers_attached on the
-- telemetry tick (§3) and from nothing else. An operator never types one of these in.
--
-- `identity_key` is the whole point of the table and is computed server-side by
-- printerQueues.deviceIdentity(), which orders the three kinds by strength:
--
--   usb-serial:<serial>            the device's own serial. Survives a rename AND a move to
--                                  another counter — §1's actual requirement.
--   usb-path:<counter>:<usb_path>  a serial-less USB printer. Does NOT survive a move, and
--                                  identity_kind says so rather than pretending otherwise.
--   net:<address>                  a network printer. §1 allows MAC or serial; nothing in
--                                  this estate's printer feed reports either, so the address
--                                  is what there is and a re-address loses the link.
--
-- A placeholder serial is NOT an identity. Whole production runs of cheap USB printers ship
-- the same string, so printerQueues.usableSerial() refuses the known-useless values before
-- one of them becomes the key that merges two physical printers into one row.
CREATE TABLE IF NOT EXISTS pmr_printer_devices (
    id             bigserial   PRIMARY KEY,
    pharmacy_id    bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    identity_kind  text        NOT NULL CHECK (identity_kind IN ('usb-serial','usb-path','network')),
    identity_key   text        NOT NULL,
    -- The identity values themselves, kept as columns so a human can read the row and so a
    -- queue can name its device without joining.
    device_serial  text,                              -- the USABLE serial, or NULL
    device_usb_path text,
    device_address text,                              -- a network printer's address
    -- ⚠️ THE HOST (§1): "the Pi with the USB connection. Other Pis reach the device through
    -- it. A network printer has NO host." So this is NULL for a network printer and that NULL
    -- is meaningful — it is not a gap to be filled in later.
    host_counter_id bigint     REFERENCES counters(id) ON DELETE SET NULL,
    -- ── descriptor strings ──
    -- ⚠️ SUPPLIED BY WHOEVER MADE THE DEVICE (§3). Every one of these is passed through
    -- printerQueues.displaySafe() at ingest — printable ASCII only, bounded — so the bytes in
    -- this table are already safe for every reader. They are bound as query PARAMETERS
    -- everywhere and interpolated into nothing, ever.
    vendor_id      text,
    product_id     text,
    manufacturer   text,
    product        text,
    raw_serial     text,                              -- what the device claims, even if useless
    protocol       text,
    -- ── last observed (§3) ──
    -- THREE-VALUED, and the third value is load-bearing: 'unknown' means CUPS itself was
    -- unreachable and MUST NOT be collapsed into 'attached, no queue'. §5: "AN UNKNOWN VALUE
    -- MUST NEVER RENDER AS A CONFIDENT ONE."
    status         text        CHECK (status IN ('queued','attached, no queue','unknown')),
    observed_queue text,                              -- the CUPS queue CUPS says points at it
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    -- One physical printer per site, whatever it has been called. THIS is the row a rename
    -- cannot orphan.
    UNIQUE (pharmacy_id, identity_key)
);
CREATE INDEX IF NOT EXISTS pmr_printer_devices_site_idx ON pmr_printer_devices (pharmacy_id);
CREATE INDEX IF NOT EXISTS pmr_printer_devices_host_idx ON pmr_printer_devices (host_counter_id);
DROP TRIGGER IF EXISTS pmr_printer_devices_touch ON pmr_printer_devices;
CREATE TRIGGER pmr_printer_devices_touch BEFORE UPDATE ON pmr_printer_devices
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── 2 · THE QUEUE ───────────────────────────────────────────────────────────
-- §1: "Queue | (device, tray label) | One physical device may carry several queues — a
-- Brother needs plain paper and ETP tokens from different trays. Some sites need more than
-- two."
--
-- This is the INTENDED set: the table the server renders into the `printers` key on the
-- telemetry reply, which the agent writes to /var/lib/wcn/printers.tab.next and nothing else.
--
-- ⭐ THE UNIQUENESS RULE, and it is the one most likely to be got wrong. §1: "A queue name is
-- unique ON ONE PI, not across a site. Two counters may each hold a queue called `Label`
-- pointing at their own printer — that is the normal pattern, and it is what lets ProScript
-- hold the same setting on every desktop." So the UNIQUE is (counter_id, queue) and NOT
-- (pharmacy_id, queue). A site-wide unique index here would refuse the estate's normal
-- arrangement, which is precisely the divergence this contract exists to prevent.
--
-- counter_id is NOT NULL and is the HOST — "the Pi the queue is BUILT ON", never null, "and
-- that includes a network printer". A network printer has no host DEVICE (§1), but its queue
-- is still built in one Pi's CUPS, and that Pi is what has to redirect it.
--
-- device_id is nullable and ON DELETE SET NULL: a queue an operator created before the
-- printer was ever seen is a real state, and so is a device row swept away with a site.
CREATE TABLE IF NOT EXISTS pmr_printer_queues (
    id             bigserial   PRIMARY KEY,
    pharmacy_id    bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    counter_id     bigint      NOT NULL REFERENCES counters(id) ON DELETE CASCADE,
    device_id      bigint      REFERENCES pmr_printer_devices(id) ON DELETE SET NULL,
    -- Denormalised from the device on purpose: these three are what the UI asks for on the
    -- printer-queues row, and a queue whose device row has been swept away must still be able
    -- to say which printer it was built for.
    device_serial  text,
    device_usb_path text,
    device_address text,
    -- ⚠️ §2's own pattern, enforced in the DATABASE as well as in printerQueues.js. §6:
    -- "Enforce §2's patterns SERVER-SIDE at the point the operator types the name... A name
    -- the kiosk would reject must never be storable." This CHECK is the last of those words —
    -- literally unstorable — and it is character-for-character TAB_QUEUE_RE in
    -- vigilant-pi-agent.py and v_tabqueue in wcn-toolbox-priv.
    queue          text        NOT NULL CHECK (queue ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
    -- Printable ASCII, 1..128, NO COMMA. The comma is FreeRDP's own field separator inside
    -- /printer:<queue>,<driver>, and a driver name containing one is the defect the contract
    -- was written after: it staged, validated, promoted, restarted the session, and the
    -- counter came back with that printer gone while telemetry reported it converged.
    -- Written as three conditions rather than as one class with the comma carved out of it
    -- (which is how the agent's TAB_DRIVER_RE spells the same rule): the carve-out is the part
    -- that matters, and a constraint whose reason can be read off it is a constraint the next
    -- person will not "simplify".
    driver         text        NOT NULL
                               CHECK (length(driver) BETWEEN 1 AND 128
                                  AND driver ~ '^[\x20-\x7e]+$'
                                  AND position(',' in driver) = 0),
    -- The closed set, currently `default` only. At most ONE queue may carry it — that is a
    -- WHOLE-TABLE condition, so it is enforced in printerQueues.validatePrinterTable() over
    -- the counter's resulting table rather than by a constraint on one row.
    flags          text[]      NOT NULL DEFAULT '{}'::text[]
                               CHECK (flags <@ ARRAY['default']::text[]),
    notes          text,
    set_by         text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (counter_id, queue)
);
CREATE INDEX IF NOT EXISTS pmr_printer_queues_site_idx   ON pmr_printer_queues (pharmacy_id);
CREATE INDEX IF NOT EXISTS pmr_printer_queues_device_idx ON pmr_printer_queues (device_id);
DROP TRIGGER IF EXISTS pmr_printer_queues_touch ON pmr_printer_queues;
CREATE TRIGGER pmr_printer_queues_touch BEFORE UPDATE ON pmr_printer_queues
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── 3 · THE ASSIGNMENT ──────────────────────────────────────────────────────
-- §1: "Assignment | queue -> desktop (VM) | A person drags a printer onto a desktop. This is
-- what 'shared to' means."
--
-- ⭐ ITS OWN TABLE, and keyed by (counter_id, queue) rather than by a pmr_printer_queues id.
-- The reason is that an assignment must be recordable for a queue that EXISTS ON THE PI but
-- has no intended-queue row yet — the ordinary case when an engineer built a queue at the
-- counter and Watchman is catching up — and a foreign key to a row that may not exist cannot
-- express that. (counter_id, queue) is the same key printer-assign is called with and the same
-- key pmr_printer_queues is unique on, so the two always address the same queue.
--
-- vmids is the WHOLE EFFECTIVE SET, never a delta — the same rule §2 states for the table
-- itself, and the reason the front end sends every vmid on every save.
--
--   no row    NO OPINION. The queue serves its own host counter's desktop, which is what an
--             unassigned local queue has always done; taking a working printer away because
--             nobody has dragged it anywhere would be a change nobody asked for.
--   {}        shared to NOTHING. A real instruction, and NOT the same as no row.
--
-- int[] rather than a row per vmid because the value is always REPLACED wholesale: a child
-- table would add a delete-then-insert dance around a set that is never edited in part.
CREATE TABLE IF NOT EXISTS pmr_printer_assignments (
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    counter_id   bigint      NOT NULL REFERENCES counters(id) ON DELETE CASCADE,
    queue        text        NOT NULL CHECK (queue ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
    -- The discovery row this was dragged from, when there was one. A HINT for reconciliation
    -- and never the identity: §1 says a name is not an identity, and a printers row id can
    -- name a queue that no longer exists.
    printer_id   bigint      REFERENCES printers(id) ON DELETE SET NULL,
    vmids        int[]       NOT NULL DEFAULT '{}'::int[],
    set_by       text,
    set_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (counter_id, queue)
);
CREATE INDEX IF NOT EXISTS pmr_printer_assignments_site_idx ON pmr_printer_assignments (pharmacy_id);

-- ── the discovery view, re-created to carry the assignment ──────────────────
-- DROPPED and re-created rather than CREATE OR REPLACE: the view is `SELECT pr.*`, so its
-- column list was fixed at creation time and a replace may only APPEND. The same note
-- proxmox_vms_v and pmr_jobs_v carry, for the same reason. Nothing else depends on it — the
-- only readers are listPrinters/upsertPrinter in store.pg.js.
--
-- ⚠️ EVERY EXISTING COLUMN IS UNCHANGED. desktopPrinters.js's shelve()/identified() helpers
-- read this feed and must keep working; this adds columns and removes none.
--
-- assigned_vmids is THE field the flow graph reads (`row.assigned_vmids ?? row.assignedVmids`
-- in desktopGraph.js) and it is deliberately three-valued:
--   NULL  no opinion — no assignment row for (this counter, this name). NOT "shared to
--         nothing", and the difference is the whole reason it is nullable.
--   {}    shared to nothing.
--   {…}   the desktops this queue serves.
--
-- The join is BY (counter, name), because that is what an assignment is keyed on and because
-- ⭐ a queue name is unique on ONE PI. The counter is resolved as the printer's own
-- counter_id, falling back to the counter that owns the Pi which REPORTED it — a discovery row
-- filled in by a CUPS poll carries reported_by and often no counter_id at all.
DROP VIEW IF EXISTS printers_v;
CREATE VIEW printers_v AS
SELECT pr.*,
       ph.code AS pharmacy_code,
       ph.name AS pharmacy_name,
       c.n     AS counter_n,
       (SELECT min((s->>'pct')::numeric)
          FROM jsonb_array_elements(pr.supplies) s
         WHERE (s->>'pct') ~ '^[0-9.]+$')            AS min_supply_pct,
       (pr.last_seen_at IS NULL
        OR pr.last_seen_at < now() - interval '15 minutes') AS stale,
       -- ── appended below this line ──
       -- Which Pi this row's queue would live on, resolved the same way the assignment lookup
       -- resolves it. Surfaced because "we could not work out which counter this printer is
       -- on" and "this printer is assigned to nothing" are different answers.
       COALESCE(pr.counter_id, rc.id)                AS host_counter_id,
       a.vmids                                       AS assigned_vmids,
       a.set_by                                      AS assigned_by,
       a.set_at                                      AS assigned_at
  FROM printers pr
  JOIN pharmacies ph ON ph.id = pr.pharmacy_id
  LEFT JOIN counters c  ON c.id = pr.counter_id
  LEFT JOIN counters rc ON rc.pi_device_id = pr.reported_by
  LEFT JOIN pmr_printer_assignments a
         ON a.counter_id = COALESCE(pr.counter_id, rc.id)
        AND a.queue = pr.name;

-- ── THE EFFECTIVE TABLE FOR ONE PI ──────────────────────────────────────────
-- What the telemetry reply sends as `printers`, computed once, here, so the tick, the UI's
-- preview and the promote job's confirmation all read one definition.
--
-- §2: "Send the whole effective table every tick, like `settings`." EFFECTIVE is the word that
-- does the work, and it means more than "the queues built on this Pi":
--
--   * a queue hosted on this Pi with NO assignment row serves this Pi's own desktop — what an
--     unassigned local queue has always done. Dropping it would silently un-share a printer
--     that is working today.
--   * a queue hosted on ANY Pi at the site whose assignment names THIS Pi's desktop VM is in
--     this Pi's table too. That is §5's "shared from another counter", and it is the only way
--     a person dragging a printer onto another desk can have any effect.
--   * a queue whose assignment is {} is shared to nothing and appears in NO table.
--
-- The desktop a Pi connects to is COALESCE(boot_vmid, vmid): the pushed boot target if there
-- is one, otherwise the counter's registered desktop.
--
-- ⚠️ THIS VIEW MAY LEGITIMATELY PRODUCE A TABLE §2 REFUSES. Two counters may each host a
-- queue called `Label` (that is the normal pattern), and sharing one of them onto the other's
-- desktop puts two `Label` lines in one Pi's table. That is a genuine conflict an operator has
-- to resolve, so it is NOT deduplicated here — it is refused whole by
-- printerQueues.validatePrinterTable() before the tick sends anything, which is exactly what
-- "refuse it entirely if any line is bad" means.
CREATE OR REPLACE VIEW pmr_counter_printer_table_v AS
SELECT tgt.id                AS counter_id,
       tgt.pharmacy_id,
       tgt.pi_device_id,
       q.id                  AS queue_id,
       q.counter_id          AS host_counter_id,
       q.queue,
       q.driver,
       q.flags,
       a.vmids               AS assigned_vmids,
       (q.counter_id = tgt.id) AS is_local
  FROM counters tgt
  JOIN pmr_printer_queues q ON q.pharmacy_id = tgt.pharmacy_id
  LEFT JOIN pmr_printer_assignments a
         ON a.counter_id = q.counter_id AND a.queue = q.queue
 WHERE (
         -- no opinion: it serves the desk it is built on
         (a.vmids IS NULL AND q.counter_id = tgt.id)
         -- assigned: it serves whichever desktops it names, wherever it is hosted
      OR (a.vmids IS NOT NULL AND COALESCE(tgt.boot_vmid, tgt.vmid) = ANY (a.vmids))
       )
 ORDER BY tgt.id, q.counter_id = tgt.id DESC, q.queue;

-- ── the promote job's confirming reading ────────────────────────────────────
-- The verb is counter.printing-promote in src/shared/pmrVerbs.js and its confirm kind is
-- 'pi-printers-promoted'. Both CHECKs below are widened for it — they mirror the allowlist,
-- which is where the verbs are authored; this is defence in depth for a row inserted by hand.
ALTER TABLE pmr_jobs DROP CONSTRAINT IF EXISTS pmr_jobs_verb_check;
ALTER TABLE pmr_jobs ADD  CONSTRAINT pmr_jobs_verb_check CHECK (verb IN (
    'counter.session-restart', 'counter.reboot', 'counter.printing-promote',
    'vm.set-onboot', 'vm.start', 'vm.shutdown', 'vm.reboot'));
ALTER TABLE pmr_jobs DROP CONSTRAINT IF EXISTS pmr_jobs_confirm_kind_check;
ALTER TABLE pmr_jobs ADD  CONSTRAINT pmr_jobs_confirm_kind_check CHECK (confirm_kind IN (
    'pi-session-restarted', 'pi-uptime-reset', 'pi-printers-promoted',
    'vm-onboot-matches', 'vm-status-running', 'vm-status-stopped', 'vm-uptime-reset'));

-- ═══════════════════════════════════════════════════════════════════════════
-- THE SITE BUILD LIFECYCLE — what Watchman holds about a capture and an import
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Both of these are READ by a build checklist that must never invent its own evidence: a
-- false "done" sends an engineer home from a site that is not finished. So both reads answer
-- with an explicit null when nothing is held, and the API ALWAYS emits the key — the front
-- end does `r.capture ?? null`, so an OMITTED key becomes a confident "no capture held"
-- instead of "we could not tell".

-- ── the capture ─────────────────────────────────────────────────────────────
-- One per site, overwritten in place: this is CURRENT STATE ("what capture does Watchman hold
-- for this site"), not a history of every attempt.
--
-- guest_agent_installed and printers_cleared are TRI-STATE and must stay that way. NULL means
-- the capture tool did not establish it — not "no". A false all-clear on either one is a site
-- imported with the pharmacy's old printers still installed, which is the thing the capture
-- step exists to prevent.
CREATE TABLE IF NOT EXISTS pmr_site_captures (
    pharmacy_id           bigint      PRIMARY KEY REFERENCES pharmacies(id) ON DELETE CASCADE,
    started_at            timestamptz NOT NULL DEFAULT now(),
    -- NULL while the capture is still running. The pair (started_at, uploaded_at) is what
    -- separates "in progress" from "held", and nothing else says it.
    uploaded_at           timestamptz,
    source_hostname       text,                       -- the pharmacy PC it was taken from
    disk_gb               numeric(10,2),              -- the shrunk image: the real cost of this site
    guest_agent_installed boolean,
    printers_cleared      boolean,
    taken_by              text,
    -- Whether it ran outside the site's opening hours. Recorded because a capture during
    -- trading hours is a decision somebody made, and the site's own hours are what judge it.
    out_of_hours          boolean,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS pmr_site_captures_touch ON pmr_site_captures;
CREATE TRIGGER pmr_site_captures_touch BEFORE UPDATE ON pmr_site_captures
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── the import ──────────────────────────────────────────────────────────────
-- ⚠️ last_poll_at IS LOAD-BEARING. The executor polls OUTWARD — nothing here can reach into
-- the cluster and ask — so this stamp is the ONLY thing separating a running import from a
-- dead one. An import whose last poll is hours old is not "running", it is lost, and a screen
-- that cannot tell those apart will show a progress bar for a job nobody is doing.
--
-- pct is nullable for the same reason every capacity figure is: an executor that has not
-- reported a percentage has not reported one, and 0 would mean "measured, and nothing done".
CREATE TABLE IF NOT EXISTS pmr_site_imports (
    pharmacy_id  bigint      PRIMARY KEY REFERENCES pharmacies(id) ON DELETE CASCADE,
    state        text        NOT NULL CHECK (state IN ('queued','running','done','failed')),
    pct          int         CHECK (pct IS NULL OR (pct BETWEEN 0 AND 100)),
    node         text,
    vmid         int,
    started_at   timestamptz,
    finished_at  timestamptz,
    error        text,
    last_poll_at timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS pmr_site_imports_touch ON pmr_site_imports;
CREATE TRIGGER pmr_site_imports_touch BEFORE UPDATE ON pmr_site_imports
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ═══════════════════════════════════════════════════════════════════════════
-- NODE HEADROOM — the figure nothing in this estate reported
-- ═══════════════════════════════════════════════════════════════════════════
--
-- pmr_vm_capacity above answers "is this pharmacy's SERVER running out of room?". This answers
-- the different question "can this NODE host another pharmacy at all?", and until now nothing
-- did — which is why "Watchman refuses a site it cannot host and names the resource short" was
-- not implementable from anything on the wire.
--
-- MEASURED 2026-08-25: wcn-zfs had 143 GB free and one site costs about 197 GB, with 67 GB of
-- 188 GB RAM free. So the honest answer for the next site on that pool is NO, and the arithmetic
-- lives in src/shared/nodeCapacity.js.
--
-- ⛔ A FIGURE THAT WAS NOT MEASURED IS NULL, NEVER 0. "This pool is completely full" and "the
-- collector could not read this pool" are different facts and exactly one of them is an
-- emergency. judgeNodeForSite() answers 'unknown' for a NULL and for a stale row, and 'unknown'
-- is neither a refusal nor an approval.
--
-- One row per (node, storage): a node may hold several pools and the site is placed on ONE of
-- them, so the pool has to be named rather than summed.
CREATE TABLE IF NOT EXISTS proxmox_node_capacity (
    node                 text        NOT NULL,
    -- The pool Watchman would place a site on, e.g. 'wcn-zfs'.
    storage_name         text        NOT NULL,
    mem_total_bytes      bigint,
    -- FREE, not "unused": what a new VM could actually claim.
    mem_free_bytes       bigint,
    storage_total_bytes  bigint,
    storage_free_bytes   bigint,
    cpu_cores            int,
    -- Why the read failed, or NULL when it worked. Carried for the reason pmr_vm_capacity
    -- carries rrd_error: a permanently broken read is otherwise indistinguishable from a
    -- cluster where nothing changed.
    read_error           text,
    measured_at          timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node, storage_name)
);
DROP TRIGGER IF EXISTS proxmox_node_capacity_touch ON proxmox_node_capacity;
CREATE TRIGGER proxmox_node_capacity_touch BEFORE UPDATE ON proxmox_node_capacity
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── the VM memory standard, on the view that judges it ──────────────────────
-- Appended to pharmacy_vms_v: without a configured memory size on these rows the estate's
-- 12 GB server / 6 GB desktop standard cannot be checked AT ALL, and the VM screen was reduced
-- to saying so in words.
--
-- APPENDED, and it must stay appended — CREATE OR REPLACE VIEW may only ADD columns at the
-- end, which is the note this view already carries about source/counter_id/address_overridden.
--
-- pmr_vm_capacity first, proxmox_vms.maxmem second: both are the CONFIGURED maximum, the
-- collector's capacity pass is the more recent reading of it, and a VM the capacity pass has
-- never covered still has an inventory row. NULL when neither knows — which the UI must read
-- as "not established", never as 0.
CREATE OR REPLACE VIEW pharmacy_vms_v AS
SELECT p.id AS pharmacy_id, p.srv_vmid AS vmid,
       COALESCE(o.ip, p.server_ip) AS ip,
       'PMR server' AS role,
       'server' AS source,
       NULL::bigint AS counter_id,
       (o.ip IS NOT NULL) AS address_overridden,
       COALESCE(cap.mem_max_bytes, pv.maxmem) AS mem_max_bytes
  FROM pharmacies p
  LEFT JOIN pharmacy_vms o ON o.pharmacy_id = p.id AND o.vmid = p.srv_vmid
  LEFT JOIN pmr_vm_capacity cap ON cap.vmid = p.srv_vmid
  LEFT JOIN proxmox_vms pv ON pv.vmid = p.srv_vmid
 WHERE p.srv_vmid IS NOT NULL
UNION ALL
SELECT c.pharmacy_id, c.vmid,
       COALESCE(o.ip, '10.200.' || p.idx || '.' || ((CASE WHEN p.prefix_len >= 27 THEN 10 ELSE 20 END) + c.n)),
       'thin client ' || c.n,
       'desktop',
       c.id,
       (o.ip IS NOT NULL),
       COALESCE(cap.mem_max_bytes, pv.maxmem)
  FROM counters c
  JOIN pharmacies p ON p.id = c.pharmacy_id
  LEFT JOIN pharmacy_vms o ON o.pharmacy_id = c.pharmacy_id AND o.vmid = c.vmid
  LEFT JOIN pmr_vm_capacity cap ON cap.vmid = c.vmid
  LEFT JOIN proxmox_vms pv ON pv.vmid = c.vmid
 WHERE c.vmid IS NOT NULL
UNION ALL
SELECT v.pharmacy_id, v.vmid, v.ip, COALESCE(v.label, 'attached'),
       'attached', NULL::bigint, false,
       COALESCE(cap.mem_max_bytes, pv.maxmem)
  FROM pharmacy_vms v
  JOIN pharmacies p ON p.id = v.pharmacy_id
  LEFT JOIN pmr_vm_capacity cap ON cap.vmid = v.vmid
  LEFT JOIN proxmox_vms pv ON pv.vmid = v.vmid
 WHERE v.vmid IS DISTINCT FROM p.srv_vmid
   AND NOT EXISTS (SELECT 1 FROM counters c WHERE c.pharmacy_id = v.pharmacy_id AND c.vmid = v.vmid);



-- ═══════════════════════════════════════════════════════════════════════════
-- THE CAPTURE KIT'S CREDENTIALS — the ticket, the scoped token, the runs, and
-- the one place a 70 GB image is allowed to land
-- ═══════════════════════════════════════════════════════════════════════════
--
-- ⛔ WHY THERE IS A CREDENTIAL MODEL HERE AT ALL. The capture kit runs on a PHARMACY'S OWN PC.
-- The obvious thing to hand it was the frontend's Supabase key, and that key decodes to
-- "role":"service_role" — it BYPASSES ROW-LEVEL SECURITY entirely, and the env file's own
-- comment says it must never ship in a deployed build. A kit that carries a long-lived estate
-- credential to a pharmacy PC is a kit that has failed. So: a short-lived scoped token with
-- exactly three capabilities, minted from a site-bound ticket, and Vigilant queries the CRM
-- server-side on the kit's behalf.
--
-- The rules the shapes below encode, and none of them are conventions:
--   * the SITE is a property of the ticket, so the kit cannot name another pharmacy;
--   * the ticket's expiry is clamped to the site's closed window, so "out of hours only" is
--     arithmetic rather than a check the kit could skip;
--   * the token's capability list is CHECK-constrained to the three, so a fourth cannot be
--     stored even by a bug;
--   * a role slot is UNIQUE per site, so "refuse a duplicate" is a database guarantee and not
--     a check-then-write race between two engineers at 2am.
--
-- See src/shared/captureToken.js for the lifetimes and why each one is the number it is.

-- ── the ticket ──────────────────────────────────────────────────────────────
-- Issued from Watchman, for ONE site, by a NAMED engineer. It is the kit's identity and its
-- site binding in one object. It is REDEEMABLE, not usable: the only route that accepts it is
-- POST /capture/token, which exchanges it for a short-lived scoped token.
--
-- ⚠️ REDEEMABLE MORE THAN ONCE, DELIBERATELY. The VirtIO guest-agent install — the point of a
-- human being on site — reboots the PC mid-capture. A single-use ticket would strand the kit
-- the moment it came back up. The budget (redeem_max) is what keeps that from being a licence:
-- a stolen ticket has a countable number of tokens left in it, and the count is visible.
CREATE TABLE IF NOT EXISTS pmr_capture_tickets (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- ⛔ THE SITE BINDING. Not a column the kit sends — a column the ticket IS. Every capture
    -- route reads its pharmacy from here and never from a request body.
    pharmacy_id   bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    -- sha256 only, exactly as devices.token_hash. A database read must never hand anybody a
    -- working credential; the secret is shown ONCE, at issue, and is unrecoverable after.
    secret_hash   text        NOT NULL UNIQUE,
    -- The person, from a per-operator credential (PMR_OPERATOR_TOKENS) — never a name typed
    -- into a body. "watchman issued it" records nothing.
    issued_by     text        NOT NULL,
    issued_at     timestamptz NOT NULL DEFAULT now(),
    -- The EARLIER of the ordinary TTL and window_closes_at. This is where out-of-hours stops
    -- being a policy and becomes a property.
    expires_at    timestamptz NOT NULL,
    -- When the pharmacy next opens, recorded so a screen can explain an early expiry instead
    -- of showing an unexplained time.
    window_closes_at timestamptz,
    redeem_max    int         NOT NULL DEFAULT 12 CHECK (redeem_max BETWEEN 1 AND 64),
    redeem_count  int         NOT NULL DEFAULT 0  CHECK (redeem_count >= 0),
    last_redeemed_at timestamptz,
    revoked_at    timestamptz,
    revoked_by    text,
    note          text
);
CREATE INDEX IF NOT EXISTS pmr_capture_tickets_pharmacy_idx ON pmr_capture_tickets (pharmacy_id, issued_at DESC);

-- ── the scoped token ────────────────────────────────────────────────────────
-- What the ticket mints and what every kit call actually presents. Short-lived, so a bearer
-- left in a file on a pharmacy PC is worthless by morning.
--
-- ⛔ THE CHECK BELOW IS THE FEATURE. `capabilities` may only ever be a subset of the three.
-- The dispatch enforces the same list as a route table and the handlers assert it a second
-- time, but this is the enforcement that survives a bug in both: a token minted with
-- 'pharmacy:write' cannot be written down, so it cannot exist to be presented.
CREATE TABLE IF NOT EXISTS pmr_capture_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id    uuid        NOT NULL REFERENCES pmr_capture_tickets(id) ON DELETE CASCADE,
    -- Carried alongside the ticket's, so the hot path (authenticate a kit call) is ONE lookup
    -- and cannot resolve a site by joining through a ticket that was meanwhile revoked.
    -- Revocation is checked explicitly instead; see redeem/auth in store.pg.js.
    pharmacy_id  bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    token_hash   text        NOT NULL UNIQUE,
    capabilities text[]      NOT NULL,
    issued_at    timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    -- Which capability it last exercised. Cheap, and it is what turns "a token was used" into
    -- "a token listed sites at 02:14 and registered a capture at 03:40".
    last_capability text,
    revoked_at   timestamptz,
    CONSTRAINT pmr_capture_tokens_caps_check CHECK (
        capabilities <@ ARRAY['sites:list','slots:read','capture:write']::text[]
        AND array_length(capabilities, 1) BETWEEN 1 AND 3
    )
);
CREATE INDEX IF NOT EXISTS pmr_capture_tokens_ticket_idx ON pmr_capture_tokens (ticket_id, issued_at DESC);

-- ── the capture runs ────────────────────────────────────────────────────────
-- ONE ROW PER (SITE, ROLE). pmr_site_captures above is one row per SITE and predates roles;
-- a site is a PMR server plus up to ten counters, and each of those is its own 30–90 minute
-- capture of its own physical PC. A single row per site could not hold them.
--
-- ROLE IS ONE PICKER, NOT TWO BOOLEANS: role_kind='server' (no slot) or role_kind='client'
-- with a slot 1–10. Clients occupy .11–.20 on a /27 site — the derived octet is 10 + n — so
-- 1–10 is exactly the addressable range and not a number somebody chose. The CHECK below
-- makes the illegal fourth state (a server with a slot, a client without one) unstorable.
--
-- ⛔ THE PARTIAL UNIQUE INDEXES ARE HOW A DUPLICATE IS REFUSED. Not a SELECT-then-INSERT in
-- the handler: two engineers picking Client 03 at the same site within the same second is
-- exactly the race that check would lose, and the loser's 90 minutes of work would overwrite
-- the winner's.
CREATE TABLE IF NOT EXISTS pmr_capture_runs (
    id             bigserial   PRIMARY KEY,
    pharmacy_id    bigint      NOT NULL REFERENCES pharmacies(id) ON DELETE CASCADE,
    role_kind      text        NOT NULL CHECK (role_kind IN ('server','client')),
    role_slot      int         CHECK (role_slot IS NULL OR role_slot BETWEEN 1 AND 10),
    -- Which ticket registered it. SET NULL rather than CASCADE: a ticket expiring or being
    -- cleaned up must never delete the record of a capture that was actually taken.
    ticket_id      uuid        REFERENCES pmr_capture_tickets(id) ON DELETE SET NULL,
    started_at     timestamptz NOT NULL DEFAULT now(),
    -- NULL while the transfer is still running.
    uploaded_at    timestamptz,
    -- ⚠️ PROVENANCE ONLY, NEVER A KEY. A PC name SURVIVES P2V, so duplicates across the estate
    -- are likely — two pharmacies both running a machine called RECEPTION is the normal case,
    -- not the exception. Nothing joins on this, nothing is addressed from it, and no filename
    -- contains it.
    source_pc_name text,
    -- The size of the SHRUNK image: the real cost of this machine on the node. Slimming is
    -- aggressive by decision — Windows features and preinstalled apps stripped, free space
    -- zeroed, and the partition AND the virtual disk shrunk — because we cannot keep hosting
    -- 250 GB drives.
    disk_gb        numeric(10,2),
    image_format   text        CHECK (image_format IS NULL OR image_format IN ('qcow2','raw','vmdk')),
    image_sha256   text,
    -- ⚠️ RESUMABLE IS NOT A NICETY. A 70 GB transfer over a pharmacy line WILL be interrupted.
    -- These two are what let a resumed run report against the same record instead of starting
    -- a second one, which is why register is an UPSERT.
    bytes_total    bigint      CHECK (bytes_total IS NULL OR bytes_total >= 0),
    bytes_sent     bigint      CHECK (bytes_sent  IS NULL OR bytes_sent  >= 0),
    -- The destination the SERVER named for this run, recorded so a resume is handed the same
    -- answer and an audit can see where the image went.
    upload_target  text,
    -- ⚠️ TRI-STATE, AND THEY MUST STAY TRI-STATE. NULL is "the kit did not establish it",
    -- which is NOT false. A false all-clear on printers_cleared is a site imported with the
    -- pharmacy's old printers still installed, which is the thing the capture step exists to
    -- prevent. guest_agent_installed is the one that needs a human: the VirtIO trust prompt
    -- must be answered, which is exactly why a silent install fails and why three existing VMs
    -- have no agent.
    guest_agent_installed boolean,
    printers_cleared      boolean,
    slimmed               boolean,
    taken_by       text,
    -- ⛔ DECIDED BY THE SERVER from the site's own hours at the moment of the call, never taken
    -- from the kit's body. A tool asserting its own compliance is not evidence of it.
    out_of_hours   boolean,
    failed_reason  text,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pmr_capture_runs_role_shape CHECK (
        (role_kind = 'server' AND role_slot IS NULL)
     OR (role_kind = 'client' AND role_slot IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS pmr_capture_runs_server_uq
    ON pmr_capture_runs (pharmacy_id) WHERE role_kind = 'server';
CREATE UNIQUE INDEX IF NOT EXISTS pmr_capture_runs_client_uq
    ON pmr_capture_runs (pharmacy_id, role_slot) WHERE role_kind = 'client';
DROP TRIGGER IF EXISTS pmr_capture_runs_touch ON pmr_capture_runs;
CREATE TRIGGER pmr_capture_runs_touch BEFORE UPDATE ON pmr_capture_runs
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── where a 70 GB image is allowed to land ──────────────────────────────────
-- ⛔ VIGILANT HAS NO ROUTE TO THE PROXMOX API. It sits on the DMZ VLAN with no path to the
-- management VLAN — which is why the entire Proxmox integration is a collector pushing
-- OUTWARD, and why job hand-out rides the reply to that push. The same rule applies here: a
-- node REPORTS its drop directory on POST /proxmox/report, and Vigilant hands that back to the
-- kit. The path is then ground truth from the machine that owns it, rather than a string
-- Vigilant guessed.
--
-- ⛔ THE DOCUMENTED NFS SHARE IS DEAD. The working target is a directory on the node's LOCAL
-- storage. fs_type is carried so a target that reports itself as nfs/cifs can be refused BY
-- NAME — refused because the far end said so, not because we pattern-matched a path.
--
-- ⛔ A FIGURE THE COLLECTOR COULD NOT ESTABLISH IS NULL, NEVER 0, for the reason every other
-- capacity column in this file is: "this directory is completely full" and "we could not read
-- this directory" are different facts and exactly one of them stops a capture.
CREATE TABLE IF NOT EXISTS pmr_capture_drop_targets (
    node         text        PRIMARY KEY,
    storage_name text,
    dir          text        NOT NULL,
    fs_type      text,
    free_bytes   bigint,
    total_bytes  bigint,
    writable     boolean,
    read_error   text,
    reported_at  timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
DROP TRIGGER IF EXISTS pmr_capture_drop_targets_touch ON pmr_capture_drop_targets;
CREATE TRIGGER pmr_capture_drop_targets_touch BEFORE UPDATE ON pmr_capture_drop_targets
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


COMMIT;
