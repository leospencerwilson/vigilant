#!/usr/bin/env node
// Vigilant — collector worker.
// Background cron that runs on the IaaS (Coolify scheduled service / systemd timer).
// Each pass (runOnce) does, in order:
//   1. markStaleDevices  — bump device_state.status by last_seen_at (online→stale→offline)
//   2. evaluate alert rules — threshold decision lives in transform.evaluateAlert; the
//      worker reads device state via the store and opens/clears alerts through store helpers
//   3. downsampleHistory + pruneHistory — roll up + age out the *_history tables
//   4. pruneNeighbors + pruneMacHosts — age out discovery rows past the TTL
// Optionally (behind ENABLE_NIGHTLY_SNAPSHOT, default false) requests nightly config
// snapshots for devices whose last snapshot is >24h old.
//
// runOnce({store, config, now}) is pure orchestration — no IO of its own beyond the
// store — so it is safe to call repeatedly against the in-memory store in tests.
// runWorker({store, config}) drives runOnce on a setInterval. The require.main bootstrap
// builds the pg store from config and starts the loop.

const transform = require("../shared/transform");
const log = require("../shared/log");
const notify = require("./notify");

// Resolve the worker's tunables from the typed config object, tolerating either camelCase
// (config.js) or the raw env var names, with the contract defaults as the floor. This
// keeps runOnce callable with a minimal/partial config in tests.
function resolveConfig(config = {}) {
  const num = (...vals) => {
    for (const v of vals) {
      if (v === undefined || v === null || v === "") continue;
      const n = Number(v);
      if (Number.isFinite(n)) return n;
    }
    return undefined;
  };
  const bool = (...vals) => {
    for (const v of vals) {
      if (v === undefined || v === null) continue;
      if (typeof v === "boolean") return v;
      const s = String(v).trim().toLowerCase();
      if (s === "true" || s === "1" || s === "yes") return true;
      if (s === "false" || s === "0" || s === "no" || s === "") return false;
    }
    return undefined;
  };
  return {
    staleAfterS: num(config.staleAfterS, process.env.STALE_AFTER_S) ?? 45,
    offlineAfterS: num(config.offlineAfterS, process.env.OFFLINE_AFTER_S) ?? 120,
    neighborTtlS: num(config.neighborTtlS, process.env.NEIGHBOR_TTL_S) ?? 86400,
    workerIntervalS: num(config.workerIntervalS, process.env.WORKER_INTERVAL_S) ?? 30,
    enableNightlySnapshot:
      bool(config.enableNightlySnapshot, process.env.ENABLE_NIGHTLY_SNAPSHOT) ?? false,
  };
}

// Map an alert_rules.metric to the value we compare against on a device's live state.
// `state` is a device_state row (already-derived columns). Returns null when the metric
// is unknown or not present — evaluateAlert treats a non-'offline' rule with a null value
// as "no data, do not fire".
function metricValue(rule, state) {
  if (!state) return null;
  const metric = rule.metric;
  // 'offline' rules compare the status string, not a number.
  if (metric === "offline" || rule.comparator === "offline") {
    return state.status;
  }
  const v = state[metric];
  return v === undefined ? null : v;
}

// Build a short human detail string for an opened alert.
function alertDetail(rule, value) {
  if (rule.comparator === "offline" || rule.metric === "offline") {
    return `${rule.metric} is ${value}`;
  }
  return `${rule.metric}=${value} ${rule.comparator} ${rule.threshold}`;
}

// Does this rule apply to this device? scope_tag null = all devices, else the device
// must carry that tag.
function ruleTargetsDevice(rule, device) {
  if (!rule.scope_tag) return true;
  const tags = Array.isArray(device.tags) ? device.tags : [];
  return tags.includes(rule.scope_tag);
}

// Evaluate every active rule against every in-scope device and open/clear alerts.
// The THRESHOLD decision itself stays in transform.evaluateAlert; the worker only does
// the IO (read state, open/clear). Returns {opened, cleared}.
async function evaluateAlerts({ store, now }) {
  let opened = 0;
  let cleared = 0;
  const transitions = [];

  // Parity escape hatch: if the store implements a single evaluateAndApplyAlerts that
  // internally uses transform.evaluateAlert, defer to it (keeps mem/pg behaviour identical).
  const rules = (await store.getActiveAlertRules()) || [];
  if (rules.length === 0) return { opened, cleared, transitions };

  if (typeof store.evaluateAndApplyAlerts === "function") {
    const res = (await store.evaluateAndApplyAlerts(rules)) || {};
    return { opened: res.opened || 0, cleared: res.cleared || 0, transitions: res.transitions || [] };
  }

  // Primitive-read path: pull the fleet once, then evaluate each rule per device.
  const devices = (await store.getDeviceStates()) || [];
  for (const rule of rules) {
    for (const device of devices) {
      if (!ruleTargetsDevice(rule, device)) continue;
      const value = metricValue(rule, device);
      const firing = transform.evaluateAlert(rule, value);
      if (firing) {
        const wasOpened = await store.openAlert(device.device_id || device.id, rule, {
          severity: rule.severity,
          detail: alertDetail(rule, value),
          now,
        });
        if (wasOpened) opened += 1;
      } else {
        const wasCleared = await store.clearAlert(device.device_id || device.id, rule, { now });
        if (wasCleared) cleared += 1;
      }
    }
  }
  return { opened, cleared, transitions };
}

// Dispatch notifications (email/Teams) for the alert transitions from this pass. Best-effort:
// a failed send is logged and never breaks the worker loop or other notifications.
async function dispatchNotifications(transitions, config) {
  const list = Array.isArray(transitions) ? transitions : [];
  let sent = 0;
  for (const t of list) {
    try {
      const r = await notify.dispatchAlert(t, { config, logger: log });
      if (r && r.sent) sent += 1;
    } catch (e) {
      log.warn("worker: notify dispatch error", { msg: e && e.message });
    }
  }
  return { sent };
}

// Flag devices whose newest config_snapshot is older than 24h and enqueue a read-only
// export job. Behind config.enableNightlySnapshot (default false) — the apply path runs
// against LIVE config, so this stays opt-in for v1.
async function maybeNightlySnapshots({ store, now }) {
  if (typeof store.enqueueNightlySnapshots !== "function") return { enqueued: 0 };
  const res = (await store.enqueueNightlySnapshots(now)) || {};
  return { enqueued: res.enqueued || 0 };
}

// One full collector pass. Order matters: staleness first (so alert rules see the freshly
// updated status), then alerts, then history rollup/prune, then discovery-table prune.
// `now` is injectable for deterministic tests; defaults to wall clock.
async function runOnce({ store, config, now }) {
  const at = now || new Date();
  const cfg = resolveConfig(config);
  const summary = {};

  // 1. staleness → status transitions
  summary.stale = await store.markStaleDevices(cfg.staleAfterS, cfg.offlineAfterS);

  // 2. alert rules (threshold decision in transform.evaluateAlert)
  summary.alerts = await evaluateAlerts({ store, now: at });
  // 2b. notify (email/Teams) on the open/clear transitions — pass the FULL config (Resend key).
  summary.notified = await dispatchNotifications(summary.alerts.transitions, config);

  // 3. history downsample + prune
  await store.downsampleHistory(at);
  await store.pruneHistory(at);

  // 4. discovery-table prune (neighbors + L2 mac hosts share the neighbor TTL)
  await store.pruneNeighbors(at, cfg.neighborTtlS);
  await store.pruneMacHosts(at, cfg.neighborTtlS);

  // 5. optional nightly config snapshots
  if (cfg.enableNightlySnapshot) {
    summary.snapshots = await maybeNightlySnapshots({ store, now: at });
  }

  return summary;
}

// Drive runOnce on a fixed interval. Passes never overlap: we await the current pass
// before scheduling the next tick, and we never throw out of the loop (a transient store
// error must not kill the worker). Returns a handle with stop().
function runWorker({ store, config }) {
  const cfg = resolveConfig(config);
  const intervalMs = cfg.workerIntervalS * 1000;
  let running = false;
  let stopped = false;

  async function tick() {
    if (running || stopped) return;
    running = true;
    try {
      const summary = await runOnce({ store, config, now: new Date() });
      log.info("worker pass complete", summary);
    } catch (e) {
      log.error("worker pass failed", { error: e.message });
    } finally {
      running = false;
    }
  }

  const timer = setInterval(tick, intervalMs);
  if (typeof timer.unref === "function") timer.unref();
  // Kick off an immediate first pass rather than waiting a full interval.
  tick();

  log.info("worker started", { intervalS: cfg.workerIntervalS });

  return {
    stop() {
      stopped = true;
      clearInterval(timer);
      log.info("worker stopped");
    },
  };
}

// Bootstrap: build the pg store from config and start the loop.
async function main() {
  const config = require("../shared/config");
  const { makeStore } = require("../shared/store");
  // Fail loud if a pg store is configured without a connection string (deferred from
  // config load so that merely requiring config never crashes mem/test processes).
  if (typeof config.assertUsable === "function") config.assertUsable();
  // pg in production; STORE_KIND=mem for local dry-runs. We do NOT migrate here — that is
  // bin/migrate.js's job; the worker only reads/rolls-up existing data.
  const store = makeStore(config.storeKind || process.env.STORE_KIND || "pg", config);
  runWorker({ store, config });
}

if (require.main === module) {
  main().catch((e) => {
    log.error("worker bootstrap failed", { error: e.message });
    process.exit(1);
  });
}

module.exports = { runOnce, runWorker, evaluateAlerts };
