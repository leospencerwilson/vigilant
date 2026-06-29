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

CREATE TABLE IF NOT EXISTS alerts (
    id          bigserial   PRIMARY KEY,
    device_id   uuid        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id     bigint      REFERENCES alert_rules(id),
    severity    text        NOT NULL,
    state       text        NOT NULL DEFAULT 'open' CHECK (state IN ('open','acked','cleared')),
    detail      text,
    opened_at   timestamptz NOT NULL DEFAULT now(),
    acked_at    timestamptz,
    acked_by    text,
    cleared_at  timestamptz
);
CREATE INDEX IF NOT EXISTS alerts_open_idx ON alerts (device_id, state) WHERE state = 'open';

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
