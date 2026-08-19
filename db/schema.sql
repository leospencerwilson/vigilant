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
CREATE OR REPLACE VIEW pharmacy_vms_v AS
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
       ds.smartcard_stack_ok                                           AS pi_smartcard_ok
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

-- Discovered VMs joined to whatever they were matched to, plus the disagreements. A VM
-- whose vmid differs from the one recorded on the counter is surfaced rather than
-- corrected: it usually means the VM was rebuilt, and a human should decide.
CREATE OR REPLACE VIEW proxmox_vms_v AS
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

COMMIT;
