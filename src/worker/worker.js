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
// Optionally (behind ENABLE_PMR_CONTROL_PLANE, default false) runs the PMR control plane:
//   6. confirm applied jobs from independent readings, expire what was never proven,
//      reconcile the converging intents, run each site's nightly counter restart at its own
//      local midnight, and verify before opening that every counter came back.
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
    // Off unless switched on deliberately: this pass signs pharmacy staff out and restarts
    // counters, so it must not begin happening merely because the code was deployed.
    enablePmrControlPlane:
      bool(config.enablePmrControlPlane, process.env.ENABLE_PMR_CONTROL_PLANE) ?? false,
    pmrNightlyWindowH: num(config.pmrNightlyWindowH, process.env.PMR_NIGHTLY_WINDOW_H) ?? 1,
    pmrOpeningLeadMin: num(config.pmrOpeningLeadMin, process.env.PMR_OPENING_LEAD_MIN) ?? 60,
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

// ════════════════════════════════════════════════════════════════════════════
// THE PMR CONTROL PLANE PASS
// ════════════════════════════════════════════════════════════════════════════
// Five steps, and their ORDER is the design:
//
//   1. CONFIRM  — prove what has been applied, from readings nothing on an executor wrote.
//   2. EXPIRE   — end what was never proven. STRICTLY AFTER confirm, or this pass would
//                 fail a job on the very tick the reading that proves it arrived.
//   3. RECONCILE— close the gaps that are allowed to close unattended. Only a CONFIGURATION
//                 property that is reversible, interrupts nothing and has a fresh
//                 independent reading qualifies; the rule is enforced in pmrVerbs.js and in
//                 the store's reconcile statement, not here.
//   4. NIGHTLY  — at each site's own local midnight, restart every counter session.
//   5. OPENING  — before each site opens, verify the counters came back, and raise ONE
//                 alert per site if one will not.
//
// There is no cron anywhere in this. Every step is idempotent and claims its own work in
// the database, so the 3-worker cluster runs each night once and a worker restarted at
// 00:40 does not run it a second time — the same reasoning pruneRelay uses for doing its
// housekeeping opportunistically rather than on a timer.
const pmrVerbs = require('../shared/pmrVerbs');
// The three-way "why has this site no overnight window" rule, shared with the two routes that
// refuse for the same reason. Not re-worded here — see describeNoOvernightWindow().
const openingHours = require('../shared/openingHours');

// The nightly restart, per site whose local clock has just passed midnight.
//
// EVERY COUNTER, EVERY NIGHT, whether or not a change is pending. That is the decision, and
// the reason is that the restart does two jobs: it applies whatever is pending, and it
// clears session state that has leaked over a trading day. A restart that only ran when
// something was pending would leave the second job undone on exactly the quiet sites where
// nobody would notice.
async function runNightlyRestarts({ store, cfg }) {
  if (typeof store.claimPmrNightlySites !== 'function') return { sites: 0 };
  const sites = await store.claimPmrNightlySites(cfg.pmrNightlyWindowH);
  if (!sites.length) return { sites: 0 };

  // The verb decides its own timings. Read once, from the one allowlist.
  const spec = pmrVerbs.getVerb('counter.session-restart');
  let created = 0;
  let skipped = 0;
  let noWindow = 0;

  for (const site of sites) {
    try {
      // ⚠️ CAN THIS SITE HAVE AN UNATTENDED RESTART AT ALL? Asked per site, once, because
      // the answer is a property of the site's hours and not of any one counter. Three
      // outcomes, and the third is the one S14 exposed:
      //   allowed now        -> the jobs run on the next telemetry tick
      //   a window later     -> the jobs are created HELD until it, by not_before
      //   no window at all   -> a 24-hour pharmacy. NOTHING is created, and the row says so.
      // Queuing a restart at a site that never closes produces a job that can only expire,
      // and an expired nightly job is what makes the pre-opening check email about a counter
      // that is perfectly healthy.
      const window = typeof store.siteDisruptiveWindow === 'function'
        ? await store.siteDisruptiveWindow(site.pharmacy_id, null)
        : { allowed_now: site.restart_allowed_now, next_window_at: site.next_window_at };
      const canRestart = !!(window && (window.allowed_now || window.next_window_at));

      const counters = await store.listSiteLiveCounters(site.pharmacy_id);
      let siteCreated = 0;
      if (canRestart) {
        for (const c of counters) {
          // A counter with no thin client enrolled is not a failure to report — it is a
          // counter that has not been built yet. Skipped silently, and NOT counted as at
          // risk later either.
          if (!c.pi_device_id) { skipped += 1; continue; }
          const job = await store.createPmrCounterJob(c.id, {
            verb: 'counter.session-restart',
            args: {},
            disruptive: spec.disruptive,
            retry_ok: spec.retry_ok,
            confirm_kind: spec.confirm,
            confirm_deadline_s: spec.confirm_deadline_s,
            // The time limit is what stops a queued restart firing late — but it is measured
            // from the moment the hours gate OPENS, not from now (S1/S12). A job held until
            // 22:00 gets its ninety minutes from 22:00; it can no longer expire at 12:30 on
            // the strength of a promise that it would apply overnight.
            ttl_s: spec.ttl_s,
            claim_ttl_s: spec.claim_ttl_s,
            // The loop-breaker. Without it, retry_ok plus a 120-second claim TTL is
            // forty-five sign-outs at one counter (B3).
            max_attempts: spec.max_attempts,
            // ⚠️ 'nightly' is not decoration: it is what scopes the pre-opening check to the
            // night's OWN jobs, so an operator's unrelated expired job cannot be read as a
            // failed restart (S13). Do not change this string without changing
            // listPmrUnfinishedNightJobs with it.
            by: 'nightly',
          });
          if (job) siteCreated += 1;
        }
      } else {
        noWindow += 1;
      }
      created += siteCreated;
      // intents_promoted is left at its default, and the reason has NARROWED (D2). It used
      // to read "the restart IS the promotion: pending settings and boot target are already
      // on the device". That was only ever true of SETTINGS — the effective set is pushed
      // every tick and the kiosk restart is what makes a session option take effect. It was
      // never true of the boot target, which the Pi applies the moment it arrives, restart
      // and all, at whatever hour it was saved. That is now staged instead, and promoted by
      // its own step in runPmrControlPlane (see 3b) rather than here: the promoter has to be
      // re-asked every pass, not once just after midnight, or a site trading until 01:00
      // would wait a day for its gate. The column still belongs to the reconciler's intent
      // rows, which close on their own schedule.
      await store.recordPmrNightlyRun(site.pharmacy_id, site.local_date, {
        counters_total: counters.length,
        jobs_created: siteCreated,
        // ⚠️ THE ROW HAS TO SAY WHICH OF THE THREE IT WAS (Z2). This sentence used to be
        // "it never closes, OR its hours do not resolve" — a stored record that declines to
        // distinguish a 24-hour pharmacy from one nobody has entered hours for, written every
        // night for most of the estate and read the next morning by a person deciding whether
        // anything is wrong. `window` carries hours_gate_resolved and this line ignored it.
        // Same rule as the two refusal routes, from the same function, so the nightly record
        // and the API refusal cannot describe one site two ways.
        skipped_reason: !canRestart
          ? openingHours.describeNoOvernightWindow(window, {
            subject: 'a restart',
            remedy: 'use apply-now with a named operator',
          })
          : (siteCreated ? null : 'no counter at this site has a thin client enrolled'),
      });
      log.info('pmr: nightly restart queued', {
        site: site.site_code, counters: counters.length, jobs: siteCreated,
        window: canRestart ? (window.allowed_now ? 'now' : window.next_window_at) : 'none',
      });
    } catch (err) {
      // One site's failure must not stop the rest of the estate getting its night. The row
      // is already claimed, so this site simply gets no jobs and the pre-opening check will
      // find whatever state its counters are actually in.
      log.error('pmr: nightly restart failed for a site (continuing)', {
        site: site.site_code, msg: err && err.message,
      });
    }
  }
  return {
    sites: sites.length, jobs: created,
    counters_without_pi: skipped, sites_without_window: noWindow,
  };
}

// Decide whether ONE counter will open, and say why not in words an engineer can act on.
// Returns null when the counter is fine.
//
// Read from what the counter itself is reporting, plus whatever happened to its jobs
// tonight. Both matter and neither is sufficient: a job can succeed against a Pi that has
// since fallen over, and a job can fail against a counter that recovered on its own.
function counterOpeningRisk(c, jobsByCounter, at) {
  if (!c.pi_device_id) return null;   // not built yet — see runNightlyRestarts
  const seenMs = c.last_seen_at ? new Date(c.last_seen_at).getTime() : 0;
  // Ten minutes: the thin client reports every 30 s by default, so a counter that has said
  // nothing for twenty ticks is not merely between reports.
  if (!seenMs || at.getTime() - seenMs > 10 * 60 * 1000) {
    return c.last_seen_at
      ? `the thin client has not reported since ${new Date(c.last_seen_at).toISOString()}`
      : 'the thin client has never reported';
  }
  // The counter is up, but the thing a pharmacist actually uses is not. This is the case
  // the whole nightly check exists for: the Pi came back and the desktop did not.
  if (c.rdp_running !== 'true') {
    return 'the thin client is online but its remote desktop session is not running';
  }
  const failed = (jobsByCounter.get(c.id) || []).filter(
    (j) => j.status === 'failed' || j.status === 'expired'
  );
  if (failed.length) {
    const j = failed[0];
    return `tonight's ${j.verb} ${j.status} — ${j.result_log || 'no detail recorded'}`;
  }
  return null;
}

// The pre-opening check. Runs early enough to fix the problem, not at the moment the
// shutters go up, and raises ONE alert per site listing every counter at risk.
//
// The claim and the alert are both stamped in the database (claimPmrOpeningChecks takes the
// check, recordPmrOpeningCheck stamps alerted_at), so a 3-worker cluster sends one email.
async function runOpeningChecks({ store, config, cfg, now }) {
  if (typeof store.claimPmrOpeningChecks !== 'function') return { sites: 0 };
  const due = await store.claimPmrOpeningChecks(cfg.pmrOpeningLeadMin);
  if (!due.length) return { sites: 0 };

  let alerted = 0;
  for (const site of due) {
    // Whether the check may be marked DONE. It stays false until either there was nothing
    // to say, or somebody was actually told — see finishPmrOpeningCheck. A check that threw
    // halfway, or whose email failed, releases its lease and is retried by a later pass
    // instead of being lost the way a claim-time stamp lost it (S4).
    let done = false;
    try {
      const [counters, jobs] = await Promise.all([
        store.listSiteLiveCounters(site.pharmacy_id),
        // Scoped to the NIGHT'S OWN jobs at this site, not an 18-hour sweep (S13).
        store.listPmrUnfinishedNightJobs(site.pharmacy_id, site.local_date),
      ]);
      const jobsByCounter = new Map();
      for (const j of jobs) {
        if (j.counter_id == null) continue;
        const list = jobsByCounter.get(j.counter_id) || [];
        list.push(j);
        jobsByCounter.set(j.counter_id, list);
      }

      const atRisk = [];
      let ok = 0;
      for (const c of counters) {
        const reason = counterOpeningRisk(c, jobsByCounter, now);
        if (reason) atRisk.push({ label: c.label || `counter ${c.n}`, reason });
        else if (c.pi_device_id) ok += 1;
      }

      const recorded = await store.recordPmrOpeningCheck(site.pharmacy_id, site.local_date, {
        counters_ok: ok,
        counters_at_risk: atRisk.length,
        alert_detail: atRisk.map((c) => `${c.label}: ${c.reason}`).join('; ') || null,
      });

      // ONLY when a counter will not open. Everything else waits for the morning queue —
      // and the store only stamps alerted_at when there is something to alert about, so
      // `alerted_at` being freshly set is the signal that THIS pass owns the email.
      if (!atRisk.length) {
        // Nothing to say is a finished check.
        done = true;
      } else if (recorded && recorded.alerted_at) {
        const sent = await notify.dispatchOpeningAlert(site, atRisk, { config, logger: log });
        if (sent.sent) alerted += 1;
        // ⚠️ A FAILED SEND IS NOT A COMPLETED CHECK. If nobody was told, the lease must
        // lapse and a later pass must try again — recording it as checked is exactly how a
        // site's only alert for the morning disappears.
        done = !!sent.sent;
        log.warn('pmr: counters may not open', {
          site: site.site_code, at_risk: atRisk.length, ok, emailed: !!sent.sent,
        });
      } else {
        // Another worker already owns this site's email for today; nothing left to do here.
        done = true;
      }
    } catch (err) {
      log.error('pmr: opening check failed for a site (continuing)', {
        site: site.site_code, msg: err && err.message,
      });
    }
    try {
      if (typeof store.finishPmrOpeningCheck === 'function') {
        await store.finishPmrOpeningCheck(site.pharmacy_id, site.local_date, { done });
      }
    } catch (err) {
      log.error('pmr: could not close out an opening check (it will be retried)', {
        site: site.site_code, msg: err && err.message,
      });
    }
  }
  return { sites: due.length, alerted };
}

// The whole control-plane pass. Wrapped by the caller so a failure here never stops the
// fleet's own staleness/alert/prune work.
//
// ⚠️ EVERY STEP GETS ITS OWN try/catch, and that is not defensive tidiness (S5). These steps
// share one input nobody validated for years: pharmacies.timezone is free text with a NOT
// NULL default and no constraint, and `now() AT TIME ZONE p.timezone` does not return null
// on a bad value — it RAISES. Every hours query here is set-based across all 348 sites, so
// ONE malformed string used to abort the whole pass: the nightly restart AND the pre-opening
// check, for every other pharmacy in the estate, silently, on the same tick.
//
// The value is now constrained at the write path and defused at the read path (site_tz in
// db/schema.sql), and these boundaries are the third layer: whatever else one step manages to
// throw, the pre-opening check — the only thing that gets a person to a pharmacy before it
// opens — still runs.
async function step(out, name, fn) {
  try {
    const r = await fn();
    if (r && typeof r === 'object') Object.assign(out, r);
  } catch (err) {
    log.error('pmr: control-plane step failed (continuing)', { step: name, msg: err && err.message });
    out.errors = out.errors || {};
    out.errors[name] = err && err.message;
  }
}

async function runPmrControlPlane({ store, config, cfg, now }) {
  const out = {};
  // 1 & 2 — prove, THEN end what was not proven. Never the other way round.
  await step(out, 'confirm', async () => (typeof store.confirmPmrJobs === 'function'
    ? { confirmed: (await store.confirmPmrJobs()).confirmed } : null));
  await step(out, 'expire', async () => (typeof store.expirePmrJobs === 'function'
    ? await store.expirePmrJobs() : null));
  // 3 — the converging fields only.
  await step(out, 'reconcile', async () => {
    if (typeof store.reconcilePmrIntent !== 'function') return null;
    const spec = pmrVerbs.getVerb('vm.set-onboot');
    const r = await store.reconcilePmrIntent({
      confirm_deadline_s: spec.confirm_deadline_s, ttl_s: spec.ttl_s, claim_ttl_s: spec.claim_ttl_s,
    });
    return { observed: r.observed, reconciled: r.created };
  });
  // 3b — the STAGED boot targets (D2). Writing counters.boot_target IS applying it: the
  // directive rides every telemetry reply and the Pi restarts the kiosk the moment the
  // target changes. So a boot target chosen in Watchman is now recorded and NOT pushed, and
  // this is the one thing that pushes it — when the site's own overnight window is open.
  //
  // ⚠️ IT RUNS ON EVERY PASS, not inside the nightly claim, and that is what makes a site
  // trading until 01:00 work: the nightly claim fires once just after local midnight, when
  // that site's gate is still SHUT, so a promotion tied to it would wait a whole day. Here
  // the gate is re-asked every pass and the change lands the hour it opens.
  //
  // The gate is evaluated INSIDE the promoting statement — pmr_disruptive_allowed(), the
  // same function the job claim uses — because this worker is not a singleton and a
  // read-then-write would let two passes restart the same counter twice.
  await step(out, 'boot-targets', async () => {
    if (typeof store.promoteCounterBootTargets !== 'function') return null;
    const r = await store.promoteCounterBootTargets();
    if (r && r.promoted) {
      log.info('pmr: staged boot targets promoted into their overnight window', {
        counters: r.promoted,
      });
    }
    return { bootTargetsPromoted: (r && r.promoted) || 0 };
  });
  // 4 & 5 — and 5 must run even when 4 threw. It is the step that protects the morning.
  await step(out, 'nightly', async () => ({ nightly: await runNightlyRestarts({ store, cfg }) }));
  await step(out, 'opening', async () => ({ opening: await runOpeningChecks({ store, config, cfg, now }) }));
  return out;
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

  // 1b. smart tags — recompute which devices carry each rule-owned tag. Runs BEFORE the
  // alert pass on purpose: alert_rules.scope_tag selects on devices.tags, so a device that
  // has just started matching a rule is scoped correctly in this same tick rather than the
  // next one. A failure here must not stop alerting, hence the try/catch.
  if (typeof store.syncSmartTags === 'function') {
    try {
      summary.smartTags = await store.syncSmartTags();
      const st = summary.smartTags;
      if (st && (st.added || st.removed || (st.errors && st.errors.length))) {
        log.info('worker: smart tags synced', st);
      }
    } catch (err) {
      log.error('worker: smart tag sync failed (continuing)', { msg: err && err.message });
      summary.smartTags = { error: err && err.message };
    }
  }

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
  // 4b. device log history — 30-day retention
  if (typeof store.pruneDeviceLogs === 'function') await store.pruneDeviceLogs();
  // Screen thumbnails expire far sooner than logs — see pruneDeviceScreens.
  if (typeof store.pruneDeviceScreens === 'function') await store.pruneDeviceScreens();

  // 5. optional nightly config snapshots
  if (cfg.enableNightlySnapshot) {
    summary.snapshots = await maybeNightlySnapshots({ store, now: at });
  }

  // 6. the PMR control plane — confirm, expire, reconcile, the nightly restart and the
  // pre-opening check. Behind its own flag (default off) and inside its own try/catch: a
  // failure in it must never stop the fleet's staleness, alerting and pruning work, which
  // is what every router in the estate depends on.
  if (cfg.enablePmrControlPlane) {
    try {
      summary.pmr = await runPmrControlPlane({ store, config, cfg, now: at });
    } catch (err) {
      log.error('worker: pmr control plane pass failed (continuing)', { msg: err && err.message });
      summary.pmr = { error: err && err.message };
    }
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

// runNightlyRestarts is exported for the same reason counterOpeningRisk is: what it WRITES
// into pmr_nightly_runs.skipped_reason is read by a person the next morning, and that
// sentence is testable without a database (see hours-gate.test.js, Z2).
module.exports = {
  runOnce, runWorker, evaluateAlerts, runPmrControlPlane, counterOpeningRisk,
  runNightlyRestarts,
};
