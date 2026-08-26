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

// Parse a NAME:SECRET credential list into [{ name, secret }].
//
// ⚠️ THIS IS HOW AN IDENTITY STOPS BEING A STRING IN A REQUEST BODY. Two callers used to
// assert who they were and be believed: a Proxmox collector named its node in `p.node`, and
// an operator applying a disruptive job during opening hours typed their name into `by`.
// Neither was a credential, and both bought real power — jobs addressed to a node, and the
// suspension of the rule that Watchman never signs a pharmacist out on its own. Here the
// NAME is a property of the SECRET, so it cannot be chosen by the caller.
//
// The name is bounded and pattern-checked because it lands in a query and in an audit
// column. Split on the FIRST colon only: a secret may legally contain one.
function credentialList(value, pattern) {
  const out = [];
  for (const entry of String(value || "").split(",")) {
    const raw = entry.trim();
    if (!raw) continue;
    const at = raw.indexOf(":");
    if (at <= 0 || at === raw.length - 1) continue;   // no name, or no secret — dropped
    const name = raw.slice(0, at).trim();
    const secret = raw.slice(at + 1).trim();
    if (!name || !secret || !pattern.test(name)) continue;
    out.push(Object.freeze({ name, secret }));
  }
  return Object.freeze(out);
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
  // Scoped key for browser frontends (wc_field) — authorises ONLY enrol + single-device read,
  // never bulk fleet reads or config-push. Lets the field app carry a key WITHOUT the estate
  // master token. Leave unset to disable. A leaked field key can at most create device rows /
  // read a device's detail.
  fieldEnrollToken: process.env.FIELD_ENROLL_TOKEN || "",
  // Shared secret baked into the thin-client base image. Lets a fresh Pi REGISTER
  // itself (POST /enrol/self) and be issued a per-device token. It can only create an
  // UNCLAIMED counter-pi device — which does nothing until an operator adopts it onto a
  // site — so a leak of this token cannot reach any existing device or site. Rotate
  // independently of the estate master token.
  selfEnrolToken: process.env.SELF_ENROL_TOKEN || "",
  // Scoped read token for the PMR desktop gateway (VM 300). The gateway agent carries this to
  // pull the rendered dnsmasq drop-ins (GET /gateway/dnsmasq). Read-only and single-purpose, so
  // it can sit on the gateway without handing it the estate master token. The master admin token
  // also authenticates the endpoint. Rotate independently.
  gatewayPullToken: process.env.GATEWAY_PULL_TOKEN || "",
  // CORS allow-list for browser callers. '*' (default) echoes any origin (safe here: auth is a
  // bearer token, not cookies). Set a comma-separated list to lock it to the wc_field origin(s).
  corsAllowOrigins: process.env.CORS_ALLOW_ORIGINS || "*",
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
  // Alert notifications (worker dispatches on alert open/clear). Email via Resend; Teams via a
  // per-rule incoming-webhook URL (no global key needed). All optional — unset = no email sent.
  resendApiKey: process.env.RESEND_API_KEY || "",
  alertEmailFrom: process.env.ALERT_EMAIL_FROM || "Vigilant <vigilant@western-communication.com>",
  // ── the PMR control plane ─────────────────────────────────────────────────
  // Off by default. The nightly pass SIGNS PHARMACY STAFF OUT AND RESTARTS COUNTERS, so it
  // does not begin happening merely because this code was deployed — it is switched on
  // deliberately, per environment.
  enablePmrControlPlane: bool(process.env.ENABLE_PMR_CONTROL_PLANE, false),
  // The shared support inbox for the ONE alert this feature raises: a counter that will not
  // open. Unset = no email is sent and the worker says so in the log; see
  // notify.dispatchOpeningAlert, which is the single integration point.
  pmrSupportInbox: process.env.PMR_SUPPORT_INBOX || "",
  // How long after a site's LOCAL midnight a missed night may still be run. It bounds the
  // damage from a worker that was down: at 1 hour, a worker back at 08:00 does NOT restart
  // every counter in the estate as the pharmacies open — it skips the night instead, and
  // the pre-opening check reports whatever it finds.
  pmrNightlyWindowH: num(process.env.PMR_NIGHTLY_WINDOW_H, 1),
  // How long BEFORE a site opens the verification runs. The point is to be early enough to
  // fix it, not to observe the failure as the shutters go up.
  pmrOpeningLeadMin: num(process.env.PMR_OPENING_LEAD_MIN, 60),
  // ── who a caller IS, as opposed to who it says it is ──────────────────────
  // PROXMOX_NODE_TOKENS = "temeraire:<secret>,node2:<secret>"
  // A per-node credential for POST /proxmox/report. The estate MASTER token still
  // authenticates that route for inventory — three nodes have shared it for a long time —
  // but it identifies nobody, and job hand-out now requires a credential that does: a node
  // only ever receives the jobs addressed to the name its own token carries. Without this,
  // one leaked master token drains every node's queue and acts on VMs it does not host, and
  // the only thing deciding which node a job went to was a string in the request body.
  // Unset = no node receives jobs (inventory still works).
  proxmoxNodeTokens: credentialList(process.env.PROXMOX_NODE_TOKENS, /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/),
  // PMR_OPERATOR_TOKENS = "leo.wilson:<secret>,someone.else:<secret>"
  // The named-person credential for the ONE route that suspends a safety rule: apply-now,
  // which releases a disruptive job during opening hours and signs a member of staff out.
  // The master admin token is NOT sufficient there and that is the point — it is shared, it
  // is in the browser, and a row that records "watchman did it" records nothing. Unset =
  // apply-now is refused outright, which is the correct direction for a route whose effect
  // is a pharmacist signed out mid-consultation.
  pmrOperatorTokens: credentialList(process.env.PMR_OPERATOR_TOKENS, /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,79}$/),
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
