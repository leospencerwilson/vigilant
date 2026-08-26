// ⛔ THE PROPERTY A1 WAS ABOUT: A GUESS IS NOT A FACT.
//
// A site whose opening hours have never been entered must not be disruptable unattended, and
// must not be treated as "closed, therefore safe" by anything that can sign a member of staff
// out of a live dispensing session.
//
// WHY THIS FILE EXISTS SEPARATELY. The property was created deliberately (unknown fails safe),
// and then destroyed by a change that looked like an improvement: making the estate fallback
// PER WEEKDAY meant site_hours_v emitted a 07:00-21:00 guess for every weekday of every site
// with no hours rows, and site_hours_state()'s `known` CTE is satisfied by the mere EXISTENCE
// of a row. `resolved` therefore became TRUE for every pharmacy in the estate, and the gate —
// which had been written to refuse an unknown — started answering out of the guess. Nothing
// failed. No test broke. The only visible symptom would have been a pharmacist at a 24-hour
// counter signed out at 00:30.
//
// So the property is PINNED here rather than left as a comment: at the JS boundary that can
// actually be executed without a database, and structurally over the SQL that holds the rest.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const openingHours = require("../src/shared/openingHours");
const handlers = require("../src/ingest/handlers");

const SCHEMA = fs.readFileSync(path.join(__dirname, "..", "db", "schema.sql"), "utf8");

// The state Postgres returns for a pharmacy that exists and has NO hours rows of its own, at
// 00:30 local. Every field here is what site_hours_state() actually produced before the fix:
// the fallback window says the site is shut, the source names it as a fallback, and `resolved`
// is true because a fallback row exists.
function stateFromPureGuess(extra) {
  return Object.assign({
    is_open: false,
    hours_source: "fallback",
    next_open_at: "2026-08-27T06:00:00.000Z",   // the guessed 07:00 local, hours away
    next_close_at: null,
    site_timezone: "Europe/London",
    resolved: true,
    // ⚠️ FALSE is the whole fix. Postgres computes it from the site's OWN rows for the days
    // that decide a disruption; a site with no rows has none, so the gate has nothing to act
    // on. Before the fix this column did not exist and `resolved` was read in its place.
    gate_resolved: false,
  }, extra || {});
}

// A site somebody HAS entered hours for, shut for the night. The control case: the fix must
// not make ordinary overnight maintenance impossible.
function stateFromRealHours(extra) {
  return Object.assign({
    is_open: false,
    hours_source: "manual",
    next_open_at: "2026-08-27T08:00:00.000Z",
    next_close_at: null,
    site_timezone: "Europe/London",
    resolved: true,
    gate_resolved: true,
  }, extra || {});
}

// ── the executable half: the route that can interrupt a live counter ────────

// A response object shaped just enough for handlers.json() — it writes a head and ends with a
// Buffer, and nothing here needs a socket.
function captureRes() {
  const out = { status: null, body: null };
  return {
    out,
    writeHead(code) { out.status = code; },
    end(buf) { out.body = buf ? JSON.parse(String(buf)) : null; },
  };
}

const COUNTER = {
  id: 7,
  pharmacy_id: 3,
  pharmacy_name: "iPharm Colne",
  pharmacy_code: "IPHARM",
  pi_device_id: "11111111-2222-3333-4444-555555555555",
};

function stubCtx(siteState, bodyObj) {
  const queued = [];
  const res = captureRes();
  return {
    queued,
    res,
    ctx: {
      res,
      log: { info() {}, warn() {}, error() {} },
      params: { id: 7 },
      body: JSON.stringify(bodyObj),
      // A NAMED OPERATOR. The credential half of the ladder is satisfied on purpose, so what
      // this test measures is the HOURS half and nothing else.
      actor: "leo",
      store: {
        async getCounter() { return COUNTER; },
        async getSiteHours() { return siteState; },
        async setCounterAction(id, f) { queued.push({ id, ...f }); return { id, ...f }; },
      },
    },
  };
}

test("A1: a site with no hours rows is NOT disruptable without the typed site name", async () => {
  // The failure this pins, in full: iPharm's hours were never imported. It is 00:30. The
  // estate fallback says 07:00-21:00, so site_hours_state() reports is_open=false with
  // resolved=true, and requireDeliberateInterruption() reads `resolved`, concludes the site is
  // KNOWN SHUT, and lets a reboot through with no confirmation at all.
  //
  // Against the pre-fix code this assertion FAILS: the status is 200 and the reboot is queued.
  const { ctx, res, queued } = stubCtx(stateFromPureGuess(), { action: "reboot" });
  await handlers.counterAction(ctx);

  assert.equal(res.out.status, 400, "a guessed 'closed' must not authorise a reboot on its own");
  assert.equal(res.out.body.expects, "confirm");
  assert.equal(res.out.body.hours_unknown, true,
    "the refusal must say WHY — nobody has entered this site's hours");
  assert.equal(queued.length, 0, "nothing may be queued for a site whose hours are a guess");
});

test("A1: the typed site name still gets it through — this is a gate, not a wall", async () => {
  // The rule the whole feature is built on: interrupting a live counter must be DELIBERATE and
  // ATTRIBUTED, never impossible. A support engineer on the phone to the pharmacy types the
  // site's name and it proceeds, against a named credential.
  const { ctx, res, queued } = stubCtx(stateFromPureGuess(), {
    action: "reboot", confirm: "iPharm Colne",
  });
  await handlers.counterAction(ctx);

  assert.equal(res.out.status, 200);
  assert.equal(queued.length, 1);
  assert.equal(queued[0].by, "leo", "the record names the credential, never the body");
});

test("A1: a site whose hours ARE entered and shut is disruptable as before", async () => {
  // The control. If this went red the fix would have bought safety by breaking overnight
  // maintenance for the whole estate, which is not a trade worth making.
  const { ctx, res, queued } = stubCtx(stateFromRealHours(), { action: "reboot" });
  await handlers.counterAction(ctx);

  assert.equal(res.out.status, 200, "a KNOWN-shut site needs no typed name");
  assert.equal(queued.length, 1);
});

test("A1: an OPEN site needs the typed name whether or not its hours are known", async () => {
  const { ctx, res, queued } = stubCtx(stateFromRealHours({ is_open: true }), { action: "reboot" });
  await handlers.counterAction(ctx);
  assert.equal(res.out.status, 400);
  assert.equal(res.out.body.hours_unknown, false, "this site's hours ARE known — it is just open");
  assert.equal(queued.length, 0);
});

test("A1: a lookup that threw is not a lookup that said 'closed'", async () => {
  // siteState null — getSiteHours failed and the handler left it null. Unknown is unknown
  // however it arose, and the refusal must not claim the hours are missing when they may
  // simply be unreadable.
  const { ctx, res, queued } = stubCtx(null, { action: "restart-kiosk" });
  await handlers.counterAction(ctx);
  assert.equal(res.out.status, 400);
  assert.equal(res.out.body.hours_unknown, false);
  assert.equal(queued.length, 0);
});

// ── the serialiser: what the screen and the gate each get told ──────────────

test("A1/W1: a GUESS never reaches the screen wearing openNow", () => {
  // ⛔ THE CONTRACT CHANGED HERE, ON PURPOSE, AND THIS IS THE ASSERTION THAT SAYS WHY.
  // The first fix made the BACKEND read the guess correctly and left the SCREEN deriving
  // "are these hours known" for itself, from `typeof h.openNow === 'boolean'` — and this
  // payload filled openNow with a real boolean for a site nobody has entered hours for. So
  // the server refused the job while the pill beside the button said "closed now" as a fact.
  //
  // Top-level `openNow` now means one thing only: this pharmacy is open, and that is a FACT
  // about this pharmacy. The estate default still travels, under a name that cannot be read
  // as one.
  const guess = openingHours.hoursPayload(stateFromPureGuess());
  assert.equal(guess.certainty, "guess");
  assert.equal("openNow" in guess, false,
    "a fallback-only site must not report openNow at top level — that is the whole defect");
  assert.equal(guess.guess.openNow, false, "the estate default is still carried, but named");
  assert.equal(guess.guess.nextOpen, "2026-08-27T06:00:00.000Z");
  // The screen can still DESCRIBE it — but it reads `certainty` to know that, not a second
  // key saying the same thing. Z3: `resolved` was `certainty !== 'unknown'` and nothing more,
  // and it is no longer emitted. An absent key is asserted rather than a falsy one, because
  // `guess.resolved === undefined` would also pass on the day somebody re-added it as null.
  assert.equal("resolved" in guess, false,
    "`resolved` is a projection of `certainty` with no reader — it must not be on the wire");
  assert.notEqual(guess.certainty, "unknown", "…and `certainty` is what carries that meaning");
  assert.equal(guess.source, "fallback");
  // A different fact again: nothing will be applied here unattended.
  assert.equal(guess.gateResolved, false);
  assert.match(guess.describes, /GUESS/,
    "the sentence must name the guess, not bury it in a parenthesis");
  assert.doesNotMatch(guess.describes, /^closed/,
    "a guess must not lead with the confident state word");

  const known = openingHours.hoursPayload(stateFromRealHours());
  assert.equal(known.certainty, "fact");
  assert.equal(known.openNow, false);
  assert.equal("guess" in known, false);
  assert.equal(known.gateResolved, true);
});

test("W1: certainty and gateResolved are different questions, and both are true statements", () => {
  // A site with a REAL VoIP profile that has a gap on some weekday: Postgres says the gate
  // cannot act (today or tomorrow is not fully stated), but the answer for RIGHT NOW is still
  // made of this pharmacy's own rows. Collapsing the two would either hide a fact the screen
  // has, or let the gate act on a day nobody stated.
  const gapped = openingHours.hoursPayload(
    stateFromRealHours({ hours_source: "voip", gate_resolved: false })
  );
  assert.equal(gapped.certainty, "fact", "we DO know whether it is open right now");
  assert.equal(gapped.openNow, false);
  assert.equal(gapped.gateResolved, false, "…and the nightly restart still may not fire");
});

test("A1: gateResolved fails closed on every shape that cannot answer", () => {
  // The four ways a caller can arrive without the column, all of which mean "we cannot tell".
  assert.equal(openingHours.gateResolved(null), false);
  assert.equal(openingHours.gateResolved({}), false);
  // A store that predates the column: `resolved` alone must NEVER stand in for it.
  assert.equal(openingHours.gateResolved({ resolved: true, is_open: false }), false);
  // Belt-and-braces: a hand-built row claiming both cannot smuggle a fallback answer past.
  assert.equal(
    openingHours.gateResolved({ gate_resolved: true, hours_source: "fallback" }), false
  );
  assert.equal(
    openingHours.gateResolved({ gate_resolved: true, hours_source: "voip" }), true
  );
});

// ── the SQL half, held structurally ─────────────────────────────────────────
// The gate itself is one predicate inside the statement that claims a job, so it cannot be
// exercised without Postgres. What CAN be held here is the shape that made the bug possible:
// the gate reading the column that the fallback inflates.

function sqlBody(name) {
  // Everything between the CREATE and the closing $fn$ of that function.
  const re = new RegExp(`CREATE (?:OR REPLACE )?FUNCTION ${name}\\b[\\s\\S]*?\\$fn\\$([\\s\\S]*?)\\$fn\\$`);
  const m = re.exec(SCHEMA);
  assert.ok(m, `${name} is not defined in db/schema.sql`);
  return m[1];
}

test("A1: the gate reads gate_resolved and never `resolved`", () => {
  const gate = sqlBody("pmr_disruptive_allowed");
  assert.match(gate, /s\.gate_resolved/,
    "pmr_disruptive_allowed must gate on the FACTS column");
  assert.ok(!/\bs\.resolved\b/.test(gate),
    "pmr_disruptive_allowed must not read `resolved` — it is true for every pharmacy in the "
    + "estate, because site_hours_v emits the estate fallback for every unknown weekday");
});

test("A1: the gate's resolution never reads the view the guess is mixed into", () => {
  // site_hours_v is where a fallback row is indistinguishable from a real one. A resolution
  // function that reads it cannot tell a fact from a guess, which is the entire bug.
  for (const fn of ["site_hours_day_known", "site_hours_gate_resolved"]) {
    assert.ok(!/site_hours_v/.test(sqlBody(fn)),
      `${fn} must read pharmacy_hours / pharmacy_hours_closed / pharmacy_hours_exceptions `
      + "directly, never site_hours_v");
  }
  // And it must consult all three, or a day stated only one of those ways reads as unknown.
  const day = sqlBody("site_hours_day_known");
  for (const table of ["pharmacy_hours_exceptions", "pharmacy_hours_closed", "pharmacy_hours"]) {
    assert.match(day, new RegExp(table), `site_hours_day_known ignores ${table}`);
  }
});

test("A1: the gate's resolution covers today AND tomorrow, local", () => {
  // Today decides "is it shut now"; tomorrow decides "is it about to open" — a site trading
  // from 00:00 opens thirty minutes after a 23:30 probe while the 07:00 guess says seven
  // hours. Dropping either day re-opens the hole one step along.
  const body = sqlBody("site_hours_gate_resolved");
  const calls = body.match(/site_hours_day_known\(/g) || [];
  assert.equal(calls.length, 2, "exactly two local days decide the gate");
  assert.match(body, /\+ 1\)/, "the second day must be tomorrow");
  assert.match(body, /COALESCE\(/, "a pharmacy_id naming no row must be a refusal, not NULL");
});

test("A1: site_hours_state still hands the SCREEN its own, unchanged answer", () => {
  // The fix must not have been bought by making the UI say "unknown" for the whole estate.
  assert.match(SCHEMA, /RETURNS TABLE \(is_open boolean[\s\S]*?resolved boolean,\s*\n\s*gate_resolved boolean\)/,
    "site_hours_state must return BOTH columns — they answer different questions");
});

// ── A2's copied constants ───────────────────────────────────────────────────

test("A2: the night band in JavaScript matches the one the gate uses", () => {
  // openingHours.NIGHT_START_S / NIGHT_END_S are a COPY, needed because the write-path check
  // runs on a proposal that is not in the database yet. A copy that drifts would classify the
  // wrong edits as safe, so it is compared against the SQL literal here.
  const start = /pmr_night_start_s\(\) RETURNS int[^$]*\$fn\$ SELECT (\d+) \$fn\$/.exec(SCHEMA);
  const end = /pmr_night_end_s\(\)\s+RETURNS int[^$]*\$fn\$ SELECT (\d+) \$fn\$/.exec(SCHEMA);
  assert.ok(start && end, "the night band literals are not where this test looks for them");
  assert.equal(openingHours.NIGHT_START_S, Number(start[1]));
  assert.equal(openingHours.NIGHT_END_S, Number(end[1]));
});

// ════════════════════════════════════════════════════════════════════════════
// Z1/Z2 · "NO OVERNIGHT WINDOW" HAS THREE ANSWERS, AND ONE DEFINITION OF THEM
// ════════════════════════════════════════════════════════════════════════════
// The same defect as A1, one field over and three call sites wide. When
// siteDisruptiveWindow() reports allowed_now=false AND next_window_at=null, somebody has to
// be told why — and three places wrote `w.hours_resolved ? "it never closes" : "hours do not
// resolve"`. `hours_resolved` is site_hours_state().resolved, TRUE for all 348 sites because
// site_hours_v hands every unstated weekday the estate fallback. So a pharmacy whose hours
// nobody has typed was told, confidently, that it never closes.

// The window row for a site nobody has entered hours for: the fallback makes hours_resolved
// true, and the GATE — which reads the site's own rows — says false.
const WINDOW_NO_HOURS = {
  allowed_now: false, next_window_at: null,
  hours_resolved: true, hours_gate_resolved: false,
};
// A genuine 24-hour pharmacy: real hours, gate resolves, and still no window.
const WINDOW_24H = {
  allowed_now: false, next_window_at: null,
  hours_resolved: true, hours_gate_resolved: true,
};

test("Z1: an unentered site is NOT told 'it never closes'", () => {
  assert.equal(openingHours.noOvernightWindowReason(WINDOW_NO_HOURS), "hours-not-entered");
  const said = openingHours.describeNoOvernightWindow(WINDOW_NO_HOURS,
    { subject: "a boot target", remedy: 'send when:"now" with a named operator' });
  assert.doesNotMatch(said, /never closes/,
    "this is the claim about a pharmacy's trading pattern that was derived from a guess");
  assert.match(said, /nobody has entered this site's opening hours/);
  // …and the remedy offered is data entry, not a phone call to negotiate a slot.
  assert.match(said, /Enter this site's hours/);
});

test("Z1: a real 24-hour pharmacy still gets the 24-hour sentence", () => {
  // The fix must not have been bought by making every refusal say "no hours on file". S14's
  // site that genuinely never shuts is a real answer and keeps its own words.
  assert.equal(openingHours.noOvernightWindowReason(WINDOW_24H), "never-closes");
  const said = openingHours.describeNoOvernightWindow(WINDOW_24H, { subject: "a restart" });
  assert.match(said, /never closes/);
  assert.match(said, /a restart cannot be applied/);
});

test("Z1: an ABSENT gate column is 'we cannot tell', never 'it never closes'", () => {
  // The hole that survived inside the arm that was ALREADY three-way: the ternary underneath
  // `if (w.hours_gate_resolved === false)` was reached whenever the column was absent — an
  // older store, a lookup that answered without it — and then announced "it never closes" on
  // the strength of the fallback's hours_resolved. Same rule as gateResolved(): absent is
  // unknown.
  const shapes = [
    null,
    {},
    { allowed_now: false, next_window_at: null, hours_resolved: true },
    { allowed_now: false, next_window_at: null, hours_resolved: false },
    { allowed_now: false, next_window_at: null, hours_gate_resolved: true },
  ];
  for (const w of shapes) {
    assert.equal(openingHours.noOvernightWindowReason(w), "hours-unreadable",
      `${JSON.stringify(w)} must not claim to know which of the two reasons it is`);
    assert.doesNotMatch(openingHours.describeNoOvernightWindow(w), /never closes/);
  }
});

test("Z1: the three reasons are a closed set, and every one has a sentence", () => {
  assert.deepEqual(openingHours.NO_WINDOW_REASONS.slice().sort(),
    ["hours-not-entered", "hours-unreadable", "never-closes"]);
  const said = new Set();
  for (const w of [WINDOW_NO_HOURS, WINDOW_24H, null]) {
    const s = openingHours.describeNoOvernightWindow(w, { subject: "this" });
    assert.equal(typeof s, "string");
    assert.ok(s.length > 40, "a refusal an operator can act on is more than a code");
    said.add(s);
  }
  assert.equal(said.size, 3, "the three reasons must not collapse into fewer sentences");
});

// ── the three call sites read that rule rather than re-writing it ───────────

test("Z1/Z2: the boot-target, job and worker refusals share ONE definition", () => {
  // Structural, because the point of the fix is that the sentence exists once. A call site
  // that goes back to `hours_resolved ?` is what this catches.
  const handlersSrc = fs.readFileSync(
    path.join(__dirname, "..", "src", "ingest", "handlers.js"), "utf8");
  const workerSrc = fs.readFileSync(
    path.join(__dirname, "..", "src", "worker", "worker.js"), "utf8");
  for (const [name, raw] of [["handlers.js", handlersSrc], ["worker.js", workerSrc]]) {
    // Comments are stripped first: these files EXPLAIN the old two-way split at length, and a
    // test that cannot tell an explanation from a decision would forbid writing the history
    // down — which is most of what stops this recurring.
    const src = raw.replace(/^\s*\/\/.*$/gm, "");
    assert.ok(!/\bw(indow)?\s*\??\.\s*hours_resolved/.test(src),
      `${name} decides a refusal from hours_resolved, which is true for all 348 sites`);
    assert.ok(!/never closes/.test(src),
      `${name} still spells the "it never closes" sentence itself instead of calling `
      + "openingHours.describeNoOvernightWindow()");
    assert.match(src, /describeNoOvernightWindow\(/,
      `${name} must call the one shared rule`);
  }
});

test("Z2: the boot-target staged refusal names the reason on the wire", async () => {
  // The route Z1 names, driven end to end: a counter at a site with no hours on file, asked
  // to stage a boot target. Before the fix the 409 said "it never closes".
  const res = captureRes();
  const ctx = {
    res,
    log: { info() {}, warn() {}, error() {} },
    params: { id: 7 },
    body: JSON.stringify({ vmid: 305 }),
    actor: "leo",
    store: {
      async getCounter() { return COUNTER; },
      async siteDisruptiveWindow() { return WINDOW_NO_HOURS; },
      async stageCounterBootTarget() {
        throw new Error("nothing may be staged at a site with no overnight window");
      },
    },
  };
  await handlers.counterSetBootTarget(ctx);
  assert.equal(res.out.status, 409);
  assert.equal(res.out.body.hours_reason, "hours-not-entered");
  assert.doesNotMatch(res.out.body.error, /never closes/);
  assert.match(res.out.body.error, /nobody has entered this site's opening hours/);
});

test("Z2: the nightly run RECORDS which of the three it was", async () => {
  // The third reader, and the one nobody was looking for: worker.js wrote
  // "it never closes, or its hours do not resolve" into pmr_nightly_runs.skipped_reason —
  // every night, for most of the estate — and that row is what a person reads the next
  // morning when deciding whether a pharmacy needs visiting. It had hours_gate_resolved in
  // hand and used neither field.
  const worker = require("../src/worker/worker");
  const recorded = [];
  const store = {
    async claimPmrNightlySites() {
      return [{ pharmacy_id: 3, site_code: "IPHARM", local_date: "2026-08-26" }];
    },
    async siteDisruptiveWindow() { return WINDOW_NO_HOURS; },
    async listSiteLiveCounters() { return []; },
    async recordPmrNightlyRun(pharmacyId, localDate, f) { recorded.push(f); },
  };
  const out = await worker.runNightlyRestarts({ store, cfg: { pmrNightlyWindowH: 2 } });
  assert.equal(out.sites_without_window, 1);
  assert.equal(recorded.length, 1);
  assert.doesNotMatch(recorded[0].skipped_reason, /never closes/,
    "the stored record must not tell tomorrow morning's reader that this pharmacy is 24-hour");
  assert.match(recorded[0].skipped_reason, /nobody has entered this site's opening hours/);
  // …and the genuine 24-hour site still records the answer that IS true of it.
  recorded.length = 0;
  store.siteDisruptiveWindow = async () => WINDOW_24H;
  await worker.runNightlyRestarts({ store, cfg: { pmrNightlyWindowH: 2 } });
  assert.match(recorded[0].skipped_reason, /never closes/);
});

// ── Z2 · describeHoursState reads the tri-state, it does not re-derive it ───

test("Z2: the sentence's gate clause comes from gate_resolved, not from the source", () => {
  // describeHoursState() answered "is this describable" and "is this a fact" for itself, from
  // the same two fields hoursCertainty() reads — a second definition of a question this
  // module already answers once. Worse, its "nothing will be applied to it unattended" clause
  // was inferred from the PROVENANCE, so the one arm that never carried it was the fact arm:
  // a site with real VoIP hours and an unstated overnight weekday read "closed — opens 09:00
  // (from the VoIP time profile)" and an operator would take that as "tonight's restart will
  // run". It will not.
  const gapped = openingHours.describeHoursState(
    stateFromRealHours({ hours_source: "voip", gate_resolved: false }));
  assert.match(gapped, /^closed/, "the hours themselves are still this pharmacy's own");
  assert.match(gapped, /not fully stated/);
  assert.match(gapped, /nothing will be applied to it overnight/);
  // A site whose gate DOES resolve makes no such claim, because it would be false.
  const fine = openingHours.describeHoursState(stateFromRealHours());
  assert.doesNotMatch(fine, /nothing will be applied/);
  // And the two cautious arms take their clause from the same field rather than the source.
  assert.match(openingHours.describeHoursState(stateFromPureGuess()),
    /nothing will be applied to it unattended/);
  assert.match(openingHours.describeHoursState(null),
    /nothing may be applied to it unattended/);
});

test("Z2: describeHoursState and hoursPayload cannot disagree about certainty", () => {
  // One definition, exercised from both ends: the sentence and the wire key are now the same
  // decision. An unrecognised source is a GUESS on both, which is the case a denylist of
  // 'fallback' would have got wrong in opposite directions on the two sides.
  const odd = { is_open: true, hours_source: "imported-2027", resolved: true,
    gate_resolved: true, site_timezone: "Europe/London" };
  assert.equal(openingHours.hoursCertainty(odd), "guess");
  assert.match(openingHours.describeHoursState(odd), /GUESS/,
    "the sentence must treat an unrecognised source exactly as the wire key does");
});
