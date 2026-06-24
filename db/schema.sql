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
    lte_signal       int,                       -- RSRP/dBm where SIM present
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
    type         text,
    comment      text,
    running      boolean,
    speed        text,                           -- e.g. "1Gbps"
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
    enabled     boolean     NOT NULL DEFAULT true
);

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
BEGIN
  PERFORM 1 FROM pg_publication WHERE pubname = 'supabase_realtime';
  IF FOUND THEN
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE vigilant.device_state';
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE vigilant.interface_state';
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE vigilant.config_jobs';
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE vigilant.alerts';
  END IF;
EXCEPTION WHEN duplicate_object THEN
  NULL;
END $$;

COMMIT;
