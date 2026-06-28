// Vigilant — config loader.
// Reads env (via dotenv), coerces types, validates, and exports ONE frozen config
// object consumed across the ingest, worker, and CLIs. No npm deps beyond dotenv.
//
// Env var names are pinned by docs/CONTRACT.md §Env — keep them verbatim.

require("dotenv").config();

// Parse a possibly-undefined env string into a number, falling back to a default.
// Empty / non-numeric values fall back rather than producing NaN.
function num(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

// Parse a boolean env flag. Truthy = '1'|'true'|'yes'|'on' (case-insensitive).
function bool(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

const storeKind = (process.env.STORE_KIND || "pg").trim().toLowerCase();
const databaseUrl = process.env.VIGILANT_DB_URL || "";

// A Postgres store with no connection string is unrecoverable. We do NOT throw at
// module-load time, though: simply REQUIRING config (which server.js / worker.js / the
// CLIs do at load) must never crash a process that is about to run with STORE_KIND='mem'
// — e.g. the test suite, which requires server.js (→ config.js) before it has a chance to
// set STORE_KIND. The loud-fail still happens, but at the point a pg store is actually
// built: makePgStore()/resolvePool() throws when given a config with no databaseUrl. The
// `assertUsable()` helper below lets entrypoints opt into the early check explicitly.
function assertUsable() {
  if (storeKind === "pg" && !databaseUrl) {
    throw new Error(
      "VIGILANT_DB_URL is not set but STORE_KIND='pg' — set the Postgres connection " +
        "string or use STORE_KIND='mem' for tests/local dev.",
    );
  }
}

const config = Object.freeze({
  databaseUrl,
  port: num(process.env.PORT, 9100),
  enrollToken: process.env.ENROLL_TOKEN || "",
  agentScriptPath: process.env.AGENT_SCRIPT_PATH || "./agent/vigilant-agent.rsc",
  publicBaseUrl: process.env.PUBLIC_BASE_URL || "https://vigilant.western-communication.com",
  fastPollS: num(process.env.FAST_POLL_S, 3),
  defaultPollS: num(process.env.DEFAULT_POLL_S, 10),
  staleAfterS: num(process.env.STALE_AFTER_S, 45),
  offlineAfterS: num(process.env.OFFLINE_AFTER_S, 120),
  historyRawRetentionH: num(process.env.HISTORY_RAW_RETENTION_H, 24),
  neighborTtlS: num(process.env.NEIGHBOR_TTL_S, 86400),
  storeKind,
  enableNightlySnapshot: bool(process.env.ENABLE_NIGHTLY_SNAPSHOT, false),
  // Supabase Realtime for the dashboard. The admin page is gated by ENROLL_TOKEN (not a
  // Supabase session), so the ingest mints a short-lived `authenticated` JWT (signed with the
  // Supabase JWT secret) after validating the admin token — the browser uses that + the anon
  // key to subscribe. RLS (db/schema.sql) lets `authenticated` read; `anon` gets nothing.
  // All optional: if unset, the dashboard silently stays on its (now in-place) polling path.
  supabaseUrl: process.env.SUPABASE_URL || "",
  supabaseAnonKey: process.env.SUPABASE_ANON_KEY || "",
  supabaseJwtSecret: process.env.SUPABASE_JWT_SECRET || "",
  // Opt-in early validation for entrypoints (server/worker startup); no-op for tests.
  assertUsable,
});

module.exports = config;
