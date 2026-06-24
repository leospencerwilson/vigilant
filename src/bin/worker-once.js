#!/usr/bin/env node
// Vigilant — one-shot worker pass, for cron scheduling.
//
// The WCN Cloud platform schedules tasks via POST /apps/{id}/cron, which runs a COMMAND
// inside the app container on a cron schedule (not an always-on process). So instead of
// deploying the always-on runWorker() loop as a second web app (which the platform would
// health-check on an HTTP port it doesn't have), we schedule THIS: a single runOnce()
// pass against the pg store, then exit. Schedule it e.g. every minute.
//
// Runs in the ingest container, so it inherits the same env (VIGILANT_DB_URL, …).

const { runOnce } = require("../worker/worker");
const log = require("../shared/log");

async function main() {
  const config = require("../shared/config");
  const { makeStore } = require("../shared/store");
  if (typeof config.assertUsable === "function") config.assertUsable();
  const store = makeStore(config.storeKind || process.env.STORE_KIND || "pg", config);
  const summary = await runOnce({ store, config, now: new Date() });
  log.info("worker-once pass complete", summary);
  // Release the pg pool if the store exposes a closer, so the process exits promptly.
  if (store && typeof store.close === "function") {
    try { await store.close(); } catch (e) { /* ignore */ }
  }
  process.exit(0);
}

main().catch((e) => {
  log.error("worker-once failed", { error: e.message });
  process.exit(1);
});
