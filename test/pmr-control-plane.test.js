// The PMR control plane's pure decisions: the verb allowlist, the argument whitelist, the
// intent field table, the hours validators, and the pre-opening risk call.
//
// Everything covered here is deliberately pure — the parts that touch the database (the
// claim, the hours gate, the confirm pass) are single SQL statements precisely so they are
// atomic, and they are exercised against a real Postgres rather than mocked here.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const pmrVerbs = require("../src/shared/pmrVerbs");
const openingHours = require("../src/shared/openingHours");
const counterSettings = require("../src/shared/counterSettings");
const { counterOpeningRisk } = require("../src/worker/worker");
const notify = require("../src/worker/notify");

// ── the verb allowlist ──────────────────────────────────────────────────────

test("every verb names a confirming reading, and the DB CHECK knows all of them", () => {
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    assert.ok(v.confirm, `${name} has no confirming reading`);
    assert.ok(pmrVerbs.CONFIRM_KINDS.includes(v.confirm));
    assert.ok(pmrVerbs.EXECUTORS.includes(v.executor));
  }
});

test("a verb that converges is never disruptive — the convergence rule", () => {
  // "A field converges unattended ONLY if it is a CONFIGURATION property, is fully
  // reversible, interrupts no session…" — a converging verb that interrupted a session
  // would let a reconciler sign a pharmacist out with nobody watching.
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    if (v.converges) assert.equal(v.disruptive, false, `${name} converges but is disruptive`);
  }
});

test("power is a lifecycle property and never converges", () => {
  assert.equal(pmrVerbs.getVerb("vm.start").converges, false);
  assert.equal(pmrVerbs.getVerb("vm.shutdown").converges, false);
  assert.equal(pmrVerbs.INTENT_FIELDS["vm.running"].converges, false);
  // onboot is the one that does.
  assert.equal(pmrVerbs.INTENT_FIELDS["vm.onboot"].converges, true);
});

test("a non-idempotent verb may not be re-offered after its claim lapses", () => {
  // Re-handing out a shutdown or a reboot is not free.
  assert.equal(pmrVerbs.getVerb("vm.shutdown").retry_ok, false);
  assert.equal(pmrVerbs.getVerb("vm.reboot").retry_ok, false);
  assert.equal(pmrVerbs.getVerb("counter.reboot").retry_ok, false);
});

test("an unknown verb is refused and the refusal names the admitted set", () => {
  assert.equal(pmrVerbs.isVerb("vm.destroy"), false);
  assert.equal(pmrVerbs.isVerb("counter.session-restart"), true);
  const r = pmrVerbs.validateVerbArgs("vm.destroy", {});
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown verb/);
  assert.match(r.error, /vm\.set-onboot/);
});

test("a verb with no confirming reading is defined but NOT admitted", () => {
  // Kept named, with the reading that would admit it, so it cannot be quietly added later
  // with "returned 0" for proof.
  assert.ok(pmrVerbs.UNADMITTED_VERBS["vm.session-logoff"]);
  assert.equal(pmrVerbs.isVerb("vm.session-logoff"), false);
  assert.ok(pmrVerbs.UNADMITTED_VERBS["vm.session-logoff"].would_be_admitted_by);
});

// ── arguments are DATA, and bounded data ────────────────────────────────────

test("arguments are refused, never coerced", () => {
  // "1" from a <select> is a UI bug; parsing it hides the class of bug the whitelist exists
  // to catch.
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { onboot: "1" }).ok, false);
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { onboot: 1.5 }).ok, false);
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { onboot: 2 }).ok, false);
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { onboot: 1 }).ok, true);
});

test("an unknown argument key is an error, prototype keys included", () => {
  const r = pmrVerbs.validateVerbArgs("vm.set-onboot", { onboot: 1, shell: 1 });
  assert.equal(r.ok, false);
  // hasOwnProperty, not truthiness — 'constructor' resolves through Object.prototype and is
  // exactly how a closed whitelist stops being closed.
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { constructor: 1 }).ok, false);
  assert.equal(pmrVerbs.validateVerbArgs("vm.set-onboot", { toString: 1 }).ok, false);
});

test("a server-resolved argument is accepted and then DISCARDED", () => {
  // The caller sends the vmid it picked in the UI; the server resolves the real one and
  // overwrites it. Keeping the caller's value would make the browser the authority on what
  // an executor acts against.
  const r = pmrVerbs.validateVerbArgs("vm.set-onboot", { vmid: 305, onboot: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.value.vmid, undefined, "the caller's vmid must not survive validation");
  assert.equal(r.value.onboot, 1);
});

test("a verb that takes no arguments refuses one", () => {
  assert.equal(pmrVerbs.validateVerbArgs("counter.session-restart", {}).ok, true);
  const r = pmrVerbs.validateVerbArgs("counter.session-restart", { force: 1 });
  assert.equal(r.ok, false);
  assert.match(r.error, /takes no arguments/);
});

test("an executor may report applied or failed — never confirmed", () => {
  // An executor can say it ran the thing; it can never say the thing is true.
  assert.ok(pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has("applied"));
  assert.ok(pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has("failed"));
  assert.equal(pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has("confirmed"), false);
  assert.equal(pmrVerbs.EXECUTOR_REPORTABLE_STATUSES.has("expired"), false);
});

test("an intent field is closed and its value bounded", () => {
  assert.equal(pmrVerbs.validateIntent("vm.onboot", 1).ok, true);
  assert.equal(pmrVerbs.validateIntent("vm.onboot", 7).ok, false);
  assert.equal(pmrVerbs.validateIntent("vm.rm", 1).ok, false);
  assert.equal(pmrVerbs.validateIntent("vm.onboot", "1").ok, false);
});

// ── opening hours ───────────────────────────────────────────────────────────

test("a block that ends before it starts is a typo, not a midnight crossing", () => {
  const r = openingHours.validateHoursBlock({ wday: 1, opens_s: 64800, closes_s: 32400 });
  assert.equal(r.ok, false);
  assert.match(r.error, /past midnight is two blocks/);
});

test("overlapping blocks in a week are refused rather than merged", () => {
  // Two overlapping blocks do not break "is it open", but they do break "when does it next
  // close" — and the UI would tell an operator the site shuts at 13:00 when it trades to 18:00.
  const r = openingHours.validateWeek([
    { wday: 1, opens_s: 32400, closes_s: 46800 },
    { wday: 1, opens_s: 43200, closes_s: 64800 },
  ]);
  assert.equal(r.ok, false);
  assert.match(r.error, /overlapping/);
});

test("a lunchtime close is two blocks that do not touch, and is accepted", () => {
  const r = openingHours.validateWeek([
    { wday: 1, opens_s: 32400, closes_s: 46800 },
    { wday: 1, opens_s: 50400, closes_s: 64800 },
  ]);
  assert.equal(r.ok, true);
  assert.equal(r.value.length, 2);
});

test("seconds-from-midnight maps 1:1 onto a Kazoo temporal rule", () => {
  // 32400 = 09:00 is exactly what a temporal_rule stores, so the import is a copy.
  assert.equal(openingHours.hhmmToSeconds("09:00"), 32400);
  assert.equal(openingHours.hhmm(64800), "18:00");
  const r = openingHours.blocksFromTemporalRule({
    name: "Mon-Fri 9-6",
    wdays: ["monday", "friday"],
    time_window_start: 32400,
    time_window_stop: 64800,
  });
  assert.equal(r.ok, true);
  // One rule, one block PER WEEKDAY it names — a Saturday with different hours is its own
  // rule, which is exactly how the estate already models it in Kazoo.
  assert.equal(r.value.length, 2);
  assert.deepEqual(r.value.map((b) => b.wday).sort(), [1, 5]);
  assert.equal(r.value[0].opens_s, 32400);
  assert.equal(r.value[0].label, "Mon-Fri 9-6");
});

test("a Kazoo holiday rule is refused, not flattened into the weekly pattern", () => {
  // Monthly/yearly cycles are how Kazoo expresses a holiday, and a holiday is an exception
  // row. Mixing recurring and one-off rows in one shape is what makes hours logic go wrong
  // on the day it matters.
  const r = openingHours.blocksFromTemporalRule({
    cycle: "yearly", wdays: ["monday"], time_window_start: 32400, time_window_stop: 64800,
  });
  assert.equal(r.ok, false);
  assert.match(r.error, /pharmacy_hours_exceptions/);
});

test("a disabled temporal rule contributes no open hours", () => {
  const r = openingHours.blocksFromTemporalRule({ enabled: false, wdays: ["monday"] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, []);
});

test("an exception is a full closure or a whole short day, never half of one", () => {
  assert.equal(openingHours.validateException({ on_date: "2026-12-25" }).ok, true);
  assert.equal(openingHours.validateException({ on_date: "2026-12-25", opens_s: 32400 }).ok, false);
  assert.equal(
    openingHours.validateException({ on_date: "2026-12-24", opens_s: 32400, closes_s: 46800 }).ok,
    true
  );
  // Refused rather than parsed: Date.parse would read "25/12/2026" as a day nobody meant.
  assert.equal(openingHours.validateException({ on_date: "25/12/2026" }).ok, false);
});

test("the hours state names its source and never softens the fallback", () => {
  const fell = openingHours.describeHoursState({ is_open: false, hours_source: "fallback" });
  assert.match(fell, /estate fallback/);
  assert.match(openingHours.describeHoursState({ is_open: true, hours_source: "voip" }), /VoIP/);
});

// ── the pre-opening check ───────────────────────────────────────────────────

const NOW = new Date("2026-08-26T07:00:00Z");
const seenAt = (minsAgo) => new Date(NOW.getTime() - minsAgo * 60000).toISOString();

test("a counter with no thin client is not built yet, and is not at risk", () => {
  assert.equal(counterOpeningRisk({ id: 1, pi_device_id: null }, new Map(), NOW), null);
});

test("a healthy counter raises nothing", () => {
  const c = { id: 1, pi_device_id: "d", last_seen_at: seenAt(1), rdp_running: "true" };
  assert.equal(counterOpeningRisk(c, new Map(), NOW), null);
});

test("a thin client that stopped reporting will not open", () => {
  const c = { id: 1, pi_device_id: "d", last_seen_at: seenAt(45), rdp_running: "true" };
  assert.match(counterOpeningRisk(c, new Map(), NOW), /has not reported since/);
  const never = { id: 2, pi_device_id: "d", last_seen_at: null };
  assert.match(counterOpeningRisk(never, new Map(), NOW), /never reported/);
});

test("the Pi came back but the desktop did not — the case the check exists for", () => {
  const c = { id: 1, pi_device_id: "d", last_seen_at: seenAt(1), rdp_running: "false" };
  assert.match(counterOpeningRisk(c, new Map(), NOW), /remote desktop session is not running/);
});

test("a restart that failed or expired raises the counter even though it looks healthy", () => {
  const c = { id: 7, pi_device_id: "d", last_seen_at: seenAt(1), rdp_running: "true" };
  const jobs = new Map([[7, [
    { verb: "counter.session-restart", status: "expired", result_log: "the time limit passed" },
  ]]]);
  const risk = counterOpeningRisk(c, jobs, NOW);
  assert.match(risk, /counter\.session-restart expired/);
  // A job that reached 'confirmed' is proof, not a risk.
  const done = new Map([[7, [{ verb: "counter.session-restart", status: "confirmed" }]]]);
  assert.equal(counterOpeningRisk(c, done, NOW), null);
});

// ── the alert ───────────────────────────────────────────────────────────────

test("nothing at risk is not an alert", async () => {
  const r = await notify.dispatchOpeningAlert({ site_code: "RX54554" }, [], { config: {} });
  assert.equal(r.sent, false);
  assert.equal(r.skipped, "nothing-at-risk");
});

test("an unconfigured inbox is reported loudly, not silently dropped", async () => {
  const warned = [];
  const r = await notify.dispatchOpeningAlert(
    { site_code: "RX54554" },
    [{ label: "counter 1", reason: "did not report" }],
    { config: {}, logger: { warn: (m, meta) => warned.push({ m, meta }), info() {}, error() {} } }
  );
  assert.equal(r.sent, false);
  assert.equal(r.skipped, "no-inbox");
  // An estate with no inbox configured must not look like an estate with no problems.
  assert.equal(warned.length, 1);
  assert.match(warned[0].m, /PMR_SUPPORT_INBOX is unset/);
});

test("one email per site, listing every counter at risk", async () => {
  const orig = global.fetch;
  const calls = [];
  global.fetch = async (url, opts) => { calls.push({ url: String(url), opts }); return { ok: true, status: 200 }; };
  try {
    const r = await notify.dispatchOpeningAlert(
      { site_code: "RX54554", site_name: "Sharief", next_open_at: "2026-08-26T08:00:00Z" },
      [
        { label: "counter 1", reason: "the thin client has not reported since 06:15" },
        { label: "counter 3", reason: "its remote desktop session is not running" },
      ],
      { config: { resendApiKey: "k", alertEmailFrom: "v@x", pmrSupportInbox: "support@x" } }
    );
    assert.equal(r.sent, true);
    assert.equal(calls.length, 1, "one email, not one per counter");
    const body = JSON.parse(calls[0].opts.body);
    assert.deepEqual(body.to, ["support@x"]);
    assert.match(body.subject, /2 counters may not open/);
    assert.match(body.text, /counter 1/);
    assert.match(body.text, /counter 3/);
  } finally {
    if (orig === undefined) delete global.fetch; else global.fetch = orig;
  }
});

// ════════════════════════════════════════════════════════════════════════════
// THE FAIL-SAFE DIRECTION
// ════════════════════════════════════════════════════════════════════════════
// For a job that INTERRUPTS A SESSION, "closed" is the PERMISSIVE state. Every failure in
// the hours path — missing data, a partial import, an empty fallback table, an unknown site,
// a bad timezone — must resolve to "treat as OPEN", never to "closed". These tests pin the
// half of that rule that is expressible without a database; the other half is the SQL in
// db/schema.sql (site_open_at COALESCEs to true; site_hours_v falls back per WEEKDAY).

test("an unresolved site is 'unknown', never 'closed'", () => {
  // The sentence an operator reads must not assert a pharmacy is shut because a lookup came
  // back empty. Four shapes of "we do not know", all of which used to render as closed.
  for (const state of [null, undefined, {}, { resolved: false }, { is_open: null, hours_source: null }]) {
    const said = openingHours.describeHoursState(state);
    assert.match(said, /not known/, `${JSON.stringify(state)} should read as unknown`);
    assert.doesNotMatch(said, /^closed/);
  }
});

test("the serialiser OMITS openNow when nothing resolved — it never sends false", () => {
  // S6. `false` is read by the frontend as a fact about a pharmacy. An ABSENT key is the
  // only way to say "we do not know" in a shape whose other states are true and false.
  const unknown = openingHours.hoursPayload({ is_open: null, resolved: false, site_timezone: 'Europe/London' });
  assert.equal('openNow' in unknown, false, 'openNow must be absent, not false');
  assert.equal(unknown.certainty, 'unknown');
  // Z3: `resolved` is gone from the wire — it was `certainty !== 'unknown'` restated, and no
  // consumer anywhere read it. `certainty` above is the assertion that carries this meaning.
  assert.equal('resolved' in unknown, false, '`resolved` must not be emitted at all');
  assert.equal(unknown.source, null);
  assert.equal('guess' in unknown, false, 'an unresolved site has no guess either');
  // …and it is present, as a real boolean, whenever the site's OWN rows answered.
  const shut = openingHours.hoursPayload({ is_open: false, resolved: true, hours_source: 'voip' });
  assert.equal(shut.certainty, 'fact');
  assert.equal(shut.openNow, false);
  assert.equal(shut.source, 'voip');
  // W1: the estate fallback is NOT the site's own rows, so it does not get openNow. Its
  // answer travels under `guess`, where it cannot be mistaken for a fact about the pharmacy.
  const guessed = openingHours.hoursPayload({ is_open: true, resolved: true, hours_source: 'fallback' });
  assert.equal(guessed.certainty, 'guess');
  assert.equal('openNow' in guessed, false);
  assert.equal(guessed.guess.openNow, true);
});

test("a weekday with no hours is UNKNOWN unless somebody said it is closed", () => {
  // B1. "We do not trade on Sunday" is a POSITIVE statement, because absence now means the
  // estate fallback window applies — which is what stops a site whose Saturday rules were
  // lost to the Crossbar 50-row cap from reading as shut all Saturday.
  const week = [{ wday: 1, opens_s: 32400, closes_s: 64800 }];
  const ok = openingHours.validateClosedDays([0, 6], week);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.value, [0, 6]);
  // A day cannot be both traded and closed — that is a contradiction the resolver would have
  // to guess about.
  const clash = openingHours.validateClosedDays([1], week);
  assert.equal(clash.ok, false);
  assert.match(clash.error, /both closed and have opening hours/);
  // Refused, never coerced — same rule as every other value in this feature.
  assert.equal(openingHours.validateClosedDays(['0'], week).ok, false);
  assert.equal(openingHours.validateClosedDays([7], week).ok, false);
  // Omitted is not the same as "closed on nothing said" — it is simply no change.
  assert.deepEqual(openingHours.validateClosedDays(undefined, week).value, []);
});

// ── the loop-breakers ───────────────────────────────────────────────────────

test("every verb bounds how many times it may be handed out", () => {
  // B3. retry_ok says a lapsed claim MAY be re-offered; max_attempts says how often. Without
  // a cap, counter.session-restart's 120s claim TTL inside a 5400s life is forty-five
  // sign-outs at one counter.
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    assert.ok(Number.isInteger(v.max_attempts), `${name} has no max_attempts`);
    assert.ok(v.max_attempts >= 1 && v.max_attempts <= 20, `${name} max_attempts out of range`);
    // A verb that must not be re-run gets exactly one go.
    if (!v.retry_ok) assert.equal(v.max_attempts, 1, `${name} is not re-runnable but may be attempted more than once`);
  }
});

test("a verb's claim TTL times its attempts cap cannot outlast its own life", () => {
  // The arithmetic that made the loop possible: 5400 / 120 = 45 re-offers inside one job's
  // lifetime. Capped, the worst case is bounded and small.
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    assert.ok(v.max_attempts * v.claim_ttl_s <= v.ttl_s + v.claim_ttl_s,
      `${name} can be re-offered ${v.max_attempts} times, which its TTL does not bound`);
  }
});

// ── the executor must understand the job before it is given one ─────────────

test("the agent-version floor is a real number above what the shipped agent reports", () => {
  // S10. Handing the job out IS the claim, so an executor that cannot parse `pmr_job`
  // swallows it. The shipped Pi agent reports agent_version 1.
  assert.ok(Number.isInteger(pmrVerbs.PMR_JOB_AGENT_VERSION));
  assert.ok(pmrVerbs.PMR_JOB_AGENT_VERSION > 1,
    'the floor must exclude the shipped agent, which has no pmr_job branch');
});

test("the collector-version floor is a real number above what the shipped collector reports", () => {
  // D4, the node-path twin of the test above. The shipped Proxmox collector posts
  // {"vms","capacity"} and sends no collector_version at all, which the server reads as 0.
  assert.ok(Number.isInteger(pmrVerbs.PMR_JOB_COLLECTOR_VERSION));
  assert.ok(pmrVerbs.PMR_JOB_COLLECTOR_VERSION > 1,
    'the floor must exclude the shipped collector, which has no jobs branch');
});

test("both executors have a capability floor — neither path may be the ungated one", () => {
  // The point of D4 is not the number, it is that there is no executor without one. Handing
  // a job out IS the claim on BOTH paths, so an executor that cannot parse its key swallows
  // the job on either.
  const floors = {
    'counter-pi': pmrVerbs.PMR_JOB_AGENT_VERSION,
    'proxmox-node': pmrVerbs.PMR_JOB_COLLECTOR_VERSION,
  };
  for (const ex of pmrVerbs.EXECUTORS) {
    assert.ok(Number.isInteger(floors[ex]) && floors[ex] > 1,
      `executor "${ex}" has no capability floor, so an un-upgraded one would swallow jobs`);
  }
});

// ── say plainly what the confirmation is worth ──────────────────────────────

test("EVERY verb is confirmed by its own executor, and every one of them says so", () => {
  // ⚠️ THIS TEST USED TO ASSERT THE OPPOSITE FOR THE FOUR PROXMOX VERBS, and the assertion
  // was untrue (D5). confirmPmrJobs() proves vm.set-onboot / vm.start / vm.shutdown /
  // vm.reboot by reading proxmox_vms, which is written by POST /proxmox/report — the SAME
  // request, from the SAME collector process, on the SAME node, that received the job and
  // posted its result. Even the freshness test 'v.seen_at > j.applied_at' compares two
  // timestamps that node authored.
  //
  // The definition of 'independent' is NOT widened to make the code pass. The test applied
  // here is the one in pmrVerbs.SELF_ATTESTATION.independence_test: could the machine that
  // executed the job produce this reading without the world having changed? For all six, yes.
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    assert.equal(v.confirm_self_attested, true,
      `${name} is confirmed from a table its own executor wrote and must say so`);
  }
});

test("a self-attested verb names the reading that would make it independent", () => {
  // The flag on its own is an admission. What stops it becoming permanent is that each verb
  // carries a buildable specification for removing it, and a plain answer to whether shipping
  // it self-attested is defensible for THAT verb.
  for (const name of pmrVerbs.VERB_NAMES) {
    const v = pmrVerbs.getVerb(name);
    assert.equal(typeof v.confirm_independent_would_be, 'string');
    assert.ok(v.confirm_independent_would_be.length > 40,
      `${name} does not say what an independent confirmation would be`);
    assert.equal(typeof v.self_attested_acceptable_because, 'string');
    assert.ok(v.self_attested_acceptable_because.length > 40,
      `${name} does not say whether self-attestation is acceptable for it`);
  }
});

test("the power verbs do not lean on their confirmation, because it is the weakest", () => {
  // vm.shutdown says outright that self-attestation is NOT acceptable on its own merits. What
  // makes it shippable is structural, and this is the structure: a job that is never proven
  // ENDS rather than being re-offered. If either of these flipped, an unproven shutdown would
  // be re-handed to the node that already claimed to have done it.
  for (const name of ['vm.shutdown', 'vm.reboot', 'counter.reboot']) {
    const v = pmrVerbs.getVerb(name);
    assert.equal(v.retry_ok, false, `${name} is self-attested and must not be re-offered`);
    assert.equal(v.max_attempts, 1, `${name} is self-attested and must be offered once`);
  }
});

// ── the three older paths that can interrupt a live counter (D1/D2/D3) ──────
// The parts of those fixes that are a DECISION rather than a query: which counter actions
// interrupt, and which setting changes do. The credential and the typed site name are
// enforced in handlers.js against a real store and are exercised there.

test("every interrupting counter setting is a session setting, and no agent setting is", () => {
  // D3. The Pi restarts the kiosk when the kiosk conf file's CONTENT changes, and the conf
  // file holds exactly the session options. An agent option is picked up by the agent's own
  // loop and interrupts nobody — dragging those through a typed-pharmacy-name dialog would
  // teach people to type it without reading.
  const SESSION = ['smartcard', 'printer_redirect', 'clipboard', 'bpp', 'blank_after_min'];
  assert.deepEqual([...counterSettings.INTERRUPTING_SETTING_KEYS].sort(), [...SESSION].sort());
  for (const k of counterSettings.COUNTER_SETTING_KEYS) {
    if (SESSION.includes(k)) continue;
    assert.ok(!counterSettings.INTERRUPTING_SETTING_KEYS.includes(k),
      `${k} is applied live by the agent and must not be gated as an interruption`);
  }
});

test("the settings gate fires on a CHANGED value, not on a mentioned key", () => {
  // The edit modal saves the whole form, so every save carries all five session options.
  // Gating on "the body mentions bpp" would demand a pharmacy name to alter a poll interval.
  const changes = counterSettings.interruptingSettingChanges;
  // A whole-form save that changes nothing.
  assert.deepEqual(changes({ bpp: 24 }, { bpp: 24, smartcard: true, clipboard: true }), []);
  // Agent options only.
  assert.deepEqual(changes({}, { report_interval_s: 60, screenshot_every: 0 }), []);
  // A real change.
  assert.deepEqual(changes({ bpp: 24 }, { bpp: 32 }), ['bpp']);
  // Two at once, reported in SPECS order so the sentence reads the same way every time.
  assert.deepEqual(changes({}, { smartcard: false, bpp: 32 }), ['smartcard', 'bpp']);
});

test("a first-ever save of a value the device already runs is not an interruption", () => {
  // The settings column holds only what somebody set; the defaults live in
  // counterSettings.js and are merged server-side. Comparing the patch against `undefined`
  // rather than against the effective value would make the first save of smartcard:true read
  // as a change on a counter that has had smartcards on since it was built — and restart it
  // for nothing.
  const changes = counterSettings.interruptingSettingChanges;
  const defaults = counterSettings.COUNTER_SETTINGS_DEFAULTS;
  for (const k of counterSettings.INTERRUPTING_SETTING_KEYS) {
    assert.deepEqual(changes({}, { [k]: defaults[k] }), [],
      `saving ${k} at its documented default must not restart the session`);
  }
});

test("the interrupting keys are derived from SPECS, not written out a second time", () => {
  // A new session option added without the flag would be a change that signs staff out with
  // no gate — the exact hole D3 closed. Deriving the list is what makes forgetting impossible
  // rather than merely unlikely, and this asserts the derivation still holds.
  const spec = counterSettings.COUNTER_SETTINGS_DEFAULTS;
  for (const k of counterSettings.INTERRUPTING_SETTING_KEYS) {
    assert.ok(Object.prototype.hasOwnProperty.call(spec, k),
      `${k} is gated as interrupting but is not a real setting`);
  }
});

// ── A4: the capability floor, on every channel that can restart a kiosk ─────

test("A4: every counter channel that can restart a kiosk has a floor", () => {
  // The floor used to protect `pmr_job` alone, while the boot directive, the settings push and
  // the one-shot action were all honoured by the shipped agent_version 1 agent with none. The
  // table is what makes "which channels are floored" a decision somebody made rather than a
  // list somebody happened to write, so it is asserted to cover exactly the three plus the job.
  const floor = pmrVerbs.COUNTER_CHANNEL_AGENT_FLOOR;
  assert.deepEqual(Object.keys(floor).sort(), ["action", "boot", "pmr_job", "settings"]);
  // pmr_job's floor is the one that says "no shipped build implements this key"; the other
  // three are implemented by the shipped agent, so their floor is the version that ships them.
  assert.equal(floor.pmr_job, pmrVerbs.PMR_JOB_AGENT_VERSION);
  assert.ok(floor.pmr_job > floor.boot, "pmr_job needs a HIGHER floor — no agent parses it yet");
  for (const ch of ["boot", "settings", "action"]) assert.equal(floor[ch], 1);
});

test("A4: an executor that has not said what it runs is offered nothing", () => {
  // The whole direction of the floor: "a capable agent is offered no work" is recoverable on
  // the next tick, "an incapable one is handed a session restart" is a pharmacist signed out.
  for (const v of [undefined, null, "", "v1", "1.2", -1, {}, [], NaN]) {
    assert.equal(pmrVerbs.agentMeetsFloor(v, "settings"), false,
      `${JSON.stringify(v)} is not a version and must meet no floor`);
  }
  // The shipped agent reports the integer 1 and implements all three, so the estate is
  // unaffected — this is the assertion that would catch a floor raised without a build.
  for (const ch of ["boot", "settings", "action"]) {
    assert.equal(pmrVerbs.agentMeetsFloor(1, ch), true, `the SHIPPED agent must still get ${ch}`);
    assert.equal(pmrVerbs.agentMeetsFloor("1", ch), true, "a JSON string version is still a version");
  }
  assert.equal(pmrVerbs.agentMeetsFloor(1, "pmr_job"), false,
    "the shipped agent has no pmr_job branch and must be offered no jobs");
  assert.equal(pmrVerbs.agentMeetsFloor(2, "pmr_job"), true);
});

test("A4: a channel nobody has decided about is refused, not waved through", () => {
  // Closed whitelist, same as every other table in pmrVerbs.js. A sixth directive added to the
  // telemetry reply without a row here gets nothing until somebody chooses.
  assert.equal(pmrVerbs.agentMeetsFloor(99, "relay"), false);
  assert.equal(pmrVerbs.agentMeetsFloor(99, "constructor"), false);
});

// ── A2: which hours edits newly arm the nightly restart ────────────────────

const MON = 1;
const TUE = 2;

test("A2: filling in a site that had NO hours newly arms the nightly restart", () => {
  // The most consequential edit there is, and the one that looks most routine. Before: nothing
  // is stated, so site_hours_gate_resolved() is false and the gate refuses every night. After:
  // the site has facts, the gate resolves, and the nightly restart becomes legal there.
  const before = { blocks: [], closed_wdays: [] };
  const after = {
    blocks: [{ wday: MON, opens_s: 32400, closes_s: 64800 }],
    closed_wdays: [TUE],
  };
  assert.deepEqual(openingHours.newlyPermittedWdays(before, after), [MON, TUE]);
});

test("A2: marking a NIGHT-TRADING weekday closed newly arms it", () => {
  // "This site does not trade on Tuesdays" typed onto a site that trades Tuesday 07:00-23:30
  // is exactly the stale-closed-marker harm store.pg.js names, arriving as a fresh edit.
  const before = { blocks: [{ wday: TUE, opens_s: 25200, closes_s: 84600 }], closed_wdays: [] };
  const after = { blocks: [], closed_wdays: [TUE] };
  assert.deepEqual(openingHours.newlyPermittedWdays(before, after), [TUE]);
});

test("A2: an ordinary daytime correction needs no ceremony", () => {
  // 09:00-17:00 becoming 08:30-18:00 changes nothing about the night, and asking for the
  // pharmacy's name here is how people learn to type it without reading.
  const before = { blocks: [{ wday: MON, opens_s: 32400, closes_s: 61200 }], closed_wdays: [] };
  const after = { blocks: [{ wday: MON, opens_s: 30600, closes_s: 64800 }], closed_wdays: [] };
  assert.deepEqual(openingHours.newlyPermittedWdays(before, after), []);
});

test("A2: an edit that ADDS protection is never challenged", () => {
  // Extending trading into the night narrows what the gate may do. One direction only.
  const before = { blocks: [{ wday: MON, opens_s: 32400, closes_s: 61200 }], closed_wdays: [] };
  const after = { blocks: [{ wday: MON, opens_s: 32400, closes_s: 84600 }], closed_wdays: [] };
  assert.deepEqual(openingHours.newlyPermittedWdays(before, after), []);
  // …and the reverse of that same edit IS challenged.
  assert.deepEqual(openingHours.newlyPermittedWdays(after, before), [MON]);
});

test("A2: a 24-hour weekday is night-protected, and losing that is the edit that matters", () => {
  const roundTheClock = [{ wday: MON, opens_s: 0, closes_s: 86400 }];
  assert.ok(openingHours.nightProtectedWdays(roundTheClock, []).has(MON));
  // Every weekday nobody has stated is protected too — that is A1's fallback protection,
  // expressed on the write path.
  const stated = openingHours.nightProtectedWdays(roundTheClock, []);
  assert.equal(stated.size, 7, "six unstated weekdays plus the night-trading Monday");
});

test("A2: a one-off day is judged the same way, and an unstated date is protected", () => {
  const trading = { known: true, blocks: [{ opens_s: 25200, closes_s: 84600 }] };
  const closedAllDay = { known: true, blocks: [] };
  const nothingStated = { known: false, blocks: [] };
  assert.equal(openingHours.dayNewlyPermitted(trading, closedAllDay), true);
  assert.equal(openingHours.dayNewlyPermitted(nothingStated, closedAllDay), true);
  assert.equal(openingHours.dayNewlyPermitted(closedAllDay, trading), false,
    "declaring a closure into a trading day removes permission, it does not grant it");
  assert.equal(openingHours.dayNewlyPermitted(closedAllDay, closedAllDay), false);
});

// ── A3: absent must be absent on the settings channel ──────────────────────

test("A3: the full default set is TRUTHY, which is why the null row had to be caught", () => {
  // This is the shape of the bug, held so nobody "simplifies" the guard back out. The telemetry
  // handler asks the store for the counter row and used to pass `row && row.settings` straight
  // into the merge — and for a DELETED counter (row null) that produced the complete default
  // set, which is truthy, so the reply carried `settings` and the agent applied it. A counter
  // that had been deleted was indistinguishable from one where every default was chosen.
  const full = counterSettings.effectiveCounterSettings(null);
  assert.ok(full && typeof full === "object");
  assert.ok(Object.keys(full).length > 0, "the merge of nothing is the FULL default set");
  assert.ok(!!full, "…and it is truthy, so `if (settings)` cannot be the absence test");
  // The handler must therefore branch on the ROW, never on the merged value.
  const src = fs.readFileSync(path.join(__dirname, "..", "src", "ingest", "handlers.js"), "utf8");
  assert.match(src, /if \(row\) settings = effectiveCounterSettings\(row\.settings\);/,
    "the settings directive must be built only when a counter row actually exists");
});
