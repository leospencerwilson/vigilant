-- Vigilant — Row-Level Security + grants for FRONTEND reads (Watchman + the admin dashboard).
--
-- Apply once against the self-hosted Supabase DB AS THE postgres SUPERUSER (the runtime
-- `vigilant` pooler role can't run DDL):
--     psql "$SUPERUSER_DB_URL" -f docs/VIGILANT-RLS.sql
-- It is also embedded (identically) in db/schema.sql, so `npm run migrate` applies it too —
-- this standalone copy is for the Watchman team / a quick re-apply.
--
-- Model: frontends read the live tables as the Supabase `authenticated` role —
--   * Watchman: the logged-in user's own Supabase session (anon key + user JWT), and
--   * the Vigilant admin dashboard: a short-lived JWT the ingest mints (POST /realtime/config).
-- The public `anon` role is granted NOTHING — a leaked anon key alone cannot read device data.
--
-- ⚠️ wifi_networks.passphrase (plaintext PSK) is withheld via a COLUMN-level grant and the
-- table is NOT in the Realtime publication. The PSK travels only the admin-gated REST path
-- (GET /devices/:serial in Vigilant; the Vercel proxy in Watchman) — never select* / Realtime.

SET search_path = vigilant, public;

DO $$
DECLARE t text;
BEGIN
  GRANT USAGE ON SCHEMA vigilant TO authenticated;

  FOREACH t IN ARRAY ARRAY[
    'devices','device_state','interface_state','lte_state','neighbors','mac_hosts',
    'wireless_clients','config_jobs','alerts','metrics_history','interface_history',
    'lte_history','speedtest_jobs'
  ] LOOP
    EXECUTE format('ALTER TABLE vigilant.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('GRANT SELECT ON vigilant.%I TO authenticated', t);
    EXECUTE format('DROP POLICY IF EXISTS %I ON vigilant.%I', t || '_sel_authed', t);
    EXECUTE format('CREATE POLICY %I ON vigilant.%I FOR SELECT TO authenticated USING (true)', t || '_sel_authed', t);
  END LOOP;

  -- wifi_networks: RLS + column-level SELECT that OMITS the plaintext passphrase.
  ALTER TABLE vigilant.wifi_networks ENABLE ROW LEVEL SECURITY;
  GRANT SELECT (device_id, interface, driver, band, ssid, security, channel,
                frequency_mhz, width_mhz, disabled, hidden, clients, last_seen_at)
    ON vigilant.wifi_networks TO authenticated;
  DROP POLICY IF EXISTS wifi_networks_sel_authed ON vigilant.wifi_networks;
  CREATE POLICY wifi_networks_sel_authed ON vigilant.wifi_networks
    FOR SELECT TO authenticated USING (true);

  GRANT SELECT ON vigilant.v_fleet TO authenticated;
END $$;

-- TIGHTENING (optional, recommended for multi-tenant Watchman): replace the `USING (true)`
-- policies with a per-customer predicate so each user sees only their estate, e.g.
--   USING (device_id IN (SELECT id FROM vigilant.devices
--                         WHERE customer = (auth.jwt() ->> 'customer')))
-- once the app issues JWTs carrying a `customer` claim.
