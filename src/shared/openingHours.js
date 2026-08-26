'use strict';

// Vigilant — opening hours: the vocabulary, the ONE validator for an hours block, and the
// conversions the VoIP import needs. Every layer that writes a pharmacy_hours row goes
// through this file.
//
// WHERE THE DECISION ITSELF LIVES: not here. "Is site X open at time T" is answered by
// site_hours_state() and pmr_disruptive_allowed() in db/schema.sql, and this module never
// re-implements them. That is deliberate and it is the load-bearing choice in this feature:
//
//   * the gate on a disruptive job has to be evaluated INSIDE the statement that claims the
//     job, because the ingest is a 3-worker cluster and a read-then-decide-then-claim would
//     let two workers hand out the same session restart;
//   * opening hours are the first concept in this system that is absolute wall-clock rather
//     than a duration measured on the executing machine's own clock (counterSettings.js
//     support_vnc_min states that rule), so they are timezone-dependent, so BST/GMT decides
//     them twice a year — and one implementation of that is exactly one too few to get
//     wrong. Postgres has AT TIME ZONE and a tzdata that is patched with the OS.
//
// So the server-side helper the rest of the design calls is store.getSiteHours(pharmacyId,
// at), which wraps site_hours_state(). What lives HERE is everything that is not the
// decision: the vocabulary, the write-path validation, and the formatting.

// 0 = Sunday, matching EXTRACT(dow) in Postgres and pharmacy_hours.wday. The Kazoo names are
// the ones a temporal_rule's `wdays` array uses, so the import is an index lookup and not a
// table of special cases.
const WDAY_NAMES = [
  'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
];

const WDAY_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

// Where a site's hours came from. Recorded per row so the UI can say which it used, and so a
// re-import knows which rows it owns.
//   voip      imported from the customer's Kazoo temporal rules — the estate owner's chosen
//             source of truth, and the one that will overwrite this row next time.
//   manual    typed into Watchman for a site the import cannot reach.
//   fallback  not a stored row at all: the single estate window, used for a site with no
//             hours of its own. Emitted by site_hours_v, never inserted.
const HOURS_SOURCES = ['voip', 'manual', 'fallback'];

const SECONDS_PER_DAY = 86400;

// ── the ONE validator for an hours block ─────────────────────────────────────
// Same shape and the same strictness as counterSettings.validateCounterSettings, and for a
// related reason: these values decide whether a pharmacist gets signed out mid-consultation.
// A string that looks like a number is REFUSED rather than parsed — "09:00" arriving where
// seconds were expected is a UI bug, and coercing it hides the one class of bug this
// whitelist exists to catch.
//
// Returns { ok:true, value } with only whitelisted keys, or { ok:false, error } naming the
// offending one.
const BLOCK_SPECS = {
  wday:     { type: 'int', min: 0, max: 6 },
  opens_s:  { type: 'int', min: 0, max: SECONDS_PER_DAY },
  closes_s: { type: 'int', min: 0, max: SECONDS_PER_DAY },
  // Free text, and the only free text in this module — it is a display label that never
  // reaches a shell, an argv or a file a script sources. Bounded in length so a paste
  // accident cannot fill the column.
  label:    { type: 'text', max: 80 },
};
const BLOCK_KEYS = Object.keys(BLOCK_SPECS);

function validateHoursBlock(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'an opening-hours block must be a JSON object' };
  }
  const value = {};
  for (const key of Object.keys(input)) {
    // hasOwnProperty, NOT BLOCK_SPECS[key]: 'constructor' resolves through Object.prototype
    // and would sail past a truthiness check, which is how a closed whitelist stops being
    // closed. Same guard as counterSettings.js.
    if (!Object.prototype.hasOwnProperty.call(BLOCK_SPECS, key)) {
      return { ok: false, error: `unknown field "${key}" — allowed fields are ${BLOCK_KEYS.join(', ')}` };
    }
    const spec = BLOCK_SPECS[key];
    const v = input[key];
    if (spec.type === 'text') {
      if (v === null || v === undefined) continue;
      if (typeof v !== 'string') return { ok: false, error: `"${key}" must be a string` };
      const t = v.trim();
      if (t.length > spec.max) return { ok: false, error: `"${key}" must be ${spec.max} characters or fewer` };
      value[key] = t || null;
      continue;
    }
    if (typeof v !== 'number' || !Number.isInteger(v)) {
      return { ok: false, error: `"${key}" must be a whole number of seconds sent as a JSON number, not a string` };
    }
    if (v < spec.min || v > spec.max) {
      return { ok: false, error: `"${key}" must be between ${spec.min} and ${spec.max}` };
    }
    value[key] = v;
  }
  for (const required of ['wday', 'opens_s', 'closes_s']) {
    if (value[required] === undefined) return { ok: false, error: `"${required}" is required` };
  }
  // The DB carries this CHECK too. It is repeated here so the operator gets a sentence
  // instead of a constraint-violation 500, and because a block that ends before it starts is
  // not a midnight-crossing block — it is a typo. A site genuinely trading past midnight is
  // two blocks, which is also how Kazoo models it.
  if (value.closes_s <= value.opens_s) {
    return { ok: false, error: 'the closing time must be after the opening time — a block that runs past midnight is two blocks' };
  }
  return { ok: true, value };
}

// Validate a WHOLE week at once, which is the only way to catch the error that matters:
// blocks that OVERLAP. Two overlapping blocks do not break "is it open", but they do break
// "when does it next close" — the earlier close wins and the UI tells an operator the site
// shuts at 13:00 when it trades until 18:00. Refused rather than merged, because merging
// would silently accept the typo that produced them.
function validateWeek(blocks) {
  if (!Array.isArray(blocks)) return { ok: false, error: 'hours must be an array of blocks' };
  const out = [];
  for (const raw of blocks) {
    const checked = validateHoursBlock(raw);
    if (!checked.ok) return checked;
    out.push(checked.value);
  }
  const byDay = new Map();
  for (const b of out) {
    const list = byDay.get(b.wday) || [];
    list.push(b);
    byDay.set(b.wday, list);
  }
  for (const [wday, list] of byDay) {
    list.sort((a, b) => a.opens_s - b.opens_s);
    for (let i = 1; i < list.length; i += 1) {
      if (list[i].opens_s < list[i - 1].closes_s) {
        return {
          ok: false,
          error: `${WDAY_SHORT[wday]} has overlapping blocks (${hhmm(list[i - 1].opens_s)}-${hhmm(list[i - 1].closes_s)} and ${hhmm(list[i].opens_s)}-${hhmm(list[i].closes_s)}) — a lunchtime close is two blocks that do not touch`,
        };
      }
    }
  }
  return { ok: true, value: out };
}

// ── one-off days ─────────────────────────────────────────────────────────────
// A bank holiday or a one-off closure, validated the same way and kept deliberately
// SEPARATE from the weekly pattern. Kazoo models these as their own temporal_rules grouped
// by a set, and mixing recurring and one-off rows into one shape is what makes hours logic
// go wrong: a Christmas Day row has no weekday, and a weekly row has no date.
//
// BOTH TIMES OMITTED MEANS CLOSED ALL DAY, and that is the common case — it is why this is
// a table with nullable times rather than a `closed boolean`. A half-day (opens_s and
// closes_s both present) is the other case; one without the other is a typo and is refused.
const EXCEPTION_KEYS = ['on_date', 'opens_s', 'closes_s', 'reason'];

function validateException(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'an opening-hours exception must be a JSON object' };
  }
  for (const key of Object.keys(input)) {
    // Same closed-whitelist guard as validateHoursBlock, and the same reason for
    // hasOwnProperty over a truthiness check.
    if (!Object.prototype.hasOwnProperty.call({ on_date: 1, opens_s: 1, closes_s: 1, reason: 1 }, key)) {
      return { ok: false, error: `unknown field "${key}" — allowed fields are ${EXCEPTION_KEYS.join(', ')}` };
    }
  }
  const onDate = input.on_date;
  // Pinned to an unambiguous ISO date rather than parsed: Date.parse would accept
  // "25/12/2026" and read it as a day in 2026 that is not the one anybody meant, and this
  // value decides whether a pharmacy's counters get restarted.
  if (typeof onDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(onDate)) {
    return { ok: false, error: '"on_date" must be a date in YYYY-MM-DD form' };
  }
  const value = { on_date: onDate, opens_s: null, closes_s: null, reason: null };

  const hasOpen = input.opens_s !== undefined && input.opens_s !== null;
  const hasClose = input.closes_s !== undefined && input.closes_s !== null;
  if (hasOpen !== hasClose) {
    return { ok: false, error: 'give both "opens_s" and "closes_s" for a short day, or neither for a full closure' };
  }
  if (hasOpen) {
    for (const key of ['opens_s', 'closes_s']) {
      const v = input[key];
      if (typeof v !== 'number' || !Number.isInteger(v)) {
        return { ok: false, error: `"${key}" must be a whole number of seconds sent as a JSON number, not a string` };
      }
      if (v < 0 || v > SECONDS_PER_DAY) {
        return { ok: false, error: `"${key}" must be between 0 and ${SECONDS_PER_DAY}` };
      }
      value[key] = v;
    }
    if (value.closes_s <= value.opens_s) {
      return { ok: false, error: 'the closing time must be after the opening time' };
    }
  }
  if (input.reason !== undefined && input.reason !== null) {
    if (typeof input.reason !== 'string') return { ok: false, error: '"reason" must be a string' };
    const t = input.reason.trim();
    if (t.length > 120) return { ok: false, error: '"reason" must be 120 characters or fewer' };
    value.reason = t || null;
  }
  return { ok: true, value };
}

// ── conversions ──────────────────────────────────────────────────────────────
// Seconds from midnight is the stored form because it is exactly what a Kazoo temporal_rule
// stores (time_window_start 32400 = 09:00), so the VoIP import is a copy and not a
// conversion. These two are for humans and for the UI only.

// 32400 -> "09:00". Never used to compute anything; a display helper.
function hhmm(seconds) {
  const s = Math.max(0, Math.min(SECONDS_PER_DAY, Number(seconds) || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

// "09:00" -> 32400, or null if it is not a plain HH:MM. Returns null rather than guessing:
// the caller reports a refusal, exactly as the addressing resolver does for a vmid it cannot
// place. "9am", "09.00" and "0900" are all refusals.
function hhmmToSeconds(text) {
  if (typeof text !== 'string') return null;
  const m = /^([01]\d|2[0-4]):([0-5]\d)$/.exec(text.trim());
  if (!m) return null;
  const s = Number(m[1]) * 3600 + Number(m[2]) * 60;
  return s > SECONDS_PER_DAY ? null : s;
}

// A Kazoo temporal_rule -> the pharmacy_hours rows it means. ONE rule becomes one row per
// weekday it names, which is what makes "is it open" a single indexed join instead of an
// array scan, and reconstructing the rule is a GROUP BY.
//
// This is a PURE conversion and is all that a VoIP import needs from this module — it calls
// no API. What the import still needs is described at the foot of the schema block: the
// pharmacy -> Kazoo account mapping (the genuinely missing piece), a reader that pushes
// outward from kazoo-core, and the paging every Crossbar list needs.
//
// ⚠️ Only rules a callflow's temporal_route lists as OPEN branches are hours. Kazoo has no
// "closed rule" — the `_` branch is the closed branch — so handing this every temporal_rule
// in an account would invert some sites.
function blocksFromTemporalRule(rule) {
  if (!rule || typeof rule !== 'object') return { ok: false, error: 'not a temporal rule' };
  if (rule.enabled === false) return { ok: true, value: [] };
  if (rule.cycle && rule.cycle !== 'weekly') {
    // Monthly/yearly cycles are how Kazoo expresses a holiday, and a holiday is a
    // pharmacy_hours_exceptions row, not a weekly one. Refused rather than flattened into a
    // recurring block, because mixing recurring and one-off rows in one shape is precisely
    // what makes hours logic go wrong on the day it matters.
    return { ok: false, error: `cycle "${rule.cycle}" is a one-off rule and belongs in pharmacy_hours_exceptions, not the weekly pattern` };
  }
  const opens = Number(rule.time_window_start);
  const closes = Number(rule.time_window_stop);
  if (!Number.isInteger(opens) || !Number.isInteger(closes)) {
    return { ok: false, error: 'time_window_start/stop must be whole seconds from midnight' };
  }
  const wdays = Array.isArray(rule.wdays) ? rule.wdays : [];
  const value = [];
  for (const name of wdays) {
    const wday = WDAY_NAMES.indexOf(String(name || '').trim().toLowerCase());
    if (wday < 0) return { ok: false, error: `unknown weekday "${name}" in the rule's wdays` };
    const checked = validateHoursBlock({
      wday, opens_s: opens, closes_s: closes,
      label: typeof rule.name === 'string' ? rule.name : null,
    });
    if (!checked.ok) return checked;
    value.push(checked.value);
  }
  return { ok: true, value };
}

// ── formatting the helper's answer ───────────────────────────────────────────
// Turn one site_hours_state() row into the sentence Watchman puts on the screen. Kept here
// so the API, the job list and the site page all say the same thing about the same state.
//
// `source` is surfaced verbatim and never softened: an operator looking at a site whose
// hours came from the estate fallback needs to know that nobody has told us when it opens.
// ⛔ IT DOES NOT RE-DERIVE THE TRI-STATE, AND IT DOES NOT DERIVE THE GATE FROM THE SOURCE
// (Z2). This function used to answer BOTH of those questions for itself, from the same two
// fields hoursCertainty() reads, in the same shape:
//
//     if (!state || state.resolved === false || state.is_open == null)      -> unknown
//     if (state.hours_source !== 'voip' && state.hours_source !== 'manual') -> guess
//
// Both were correct on the day they were written, and both were a SECOND definition of a
// question this module already answers once. That is the shape of every defect in this
// feature: `resolved` was read here and in hoursCertainty(), and a change to one would have
// moved the sentence and the wire apart without failing anything.
//
// ⚠️ AND THE GATE CLAUSE IS THE GATE'S OWN FIELD NOW. The two cautious arms below end with
// "nothing will be applied to it unattended" — a statement about pmr_disruptive_allowed() —
// and that statement used to be inferred from the PROVENANCE. It is inferred from nothing
// now: gateResolved() answers it, so this sentence and the gate cannot disagree. The 'fact'
// arm gained the clause it never had, which is the case that mattered: a site with real VoIP
// hours whose overnight weekday is not stated reads "closed — opens 09:00 (from the VoIP
// time profile)", and an operator would reasonably take that as "the restart will run
// tonight". It will not.
function describeHoursState(state) {
  const certainty = hoursCertainty(state);
  // ONE definition of "may an unattended job act here", read, never re-derived.
  const gateOk = gateResolved(state);
  // The one clause that states the CONSEQUENCE, in the two arms that need it. Empty when the
  // gate does resolve, because then the claim would be false — and a false reassurance in
  // either direction is the whole reason this feature keeps going wrong.
  const unattended = gateOk ? '' : ' — nothing will be applied to it unattended';

  // ⚠️ UNRESOLVED IS ITS OWN ANSWER, and it is NOT "closed". site_hours_state() returns
  // is_open NULL for a site whose hours do not resolve at all, precisely so that this
  // sentence — and the pill the frontend builds from it — says "unknown" instead of
  // claiming a pharmacy is shut. See the asymmetry note in db/schema.sql: the GATE reads
  // that same unknown as "treat it as open, do not disrupt".
  if (certainty === 'unknown') {
    return `opening hours are not known for this site${
      gateOk ? '' : ' — nothing may be applied to it unattended'}`;
  }
  // ⚠️ A GUESS DOES NOT GET THE OPEN/CLOSED WORD FIRST (A1 / W1). It used to read
  // "closed — opens 07:00 (the estate fallback window — …GUESS…)", and a sentence that
  // OPENS with a confident state word is read as a confident state word; the parenthesis at
  // the end is a caveat nobody reaches. The order is inverted so the first clause is the one
  // that decides what the operator may do, matching `certainty: 'guess'` on the wire.
  if (certainty === 'guess') {
    const window = state.is_open
      ? (state.next_close_at ? `would be open until ${new Date(state.next_close_at).toISOString()}` : 'would be open')
      : (state.next_open_at ? `would be shut until ${new Date(state.next_open_at).toISOString()}` : 'would be shut');
    return 'nobody has entered this site\'s opening hours — the one estate fallback window '
         + `is being shown instead, and it is a GUESS, not this pharmacy's hours (it ${window}). `
         + `Treat the site as OPEN${unattended}`;
  }
  const src = state.hours_source === 'voip' ? 'from the VoIP time profile' : 'set in Watchman';
  // The gate clause on the FACT arm names the reason, because here the hours themselves are
  // this pharmacy's own and "we do not know" would be untrue: what is missing is a weekday.
  const gap = gateOk
    ? ''
    : ' — but the weekdays that decide an unattended job are not fully stated, so nothing '
      + 'will be applied to it overnight';
  if (state.is_open) {
    const until = state.next_close_at ? ` until ${new Date(state.next_close_at).toISOString()}` : '';
    return `open${until} (${src})${gap}`;
  }
  const opens = state.next_open_at ? ` — opens ${new Date(state.next_open_at).toISOString()}` : '';
  return `closed${opens} (${src})${gap}`;
}

// ── ⛔ WHY DOES THIS SITE HAVE NO OVERNIGHT WINDOW (Z1 / Z2) ─────────────────
// siteDisruptiveWindow() answers "may an unattended job run here now, and if not when". When
// BOTH are no — allowed_now false and next_window_at null — something has to tell a person
// why, and there are THREE reasons, not two.
//
// ⛔ THE TWO-WAY SPLIT WAS A CONFIDENT CLAIM ABOUT A PHARMACY DERIVED FROM A GUESS. Three
// call sites wrote `w.hours_resolved ? "it never closes" : "hours do not resolve"`, and
// `hours_resolved` is site_hours_state().resolved, which is TRUE for all 348 sites because
// site_hours_v hands every unstated weekday the estate fallback window. So a pharmacy whose
// hours nobody has typed was told "that site has no overnight window — it never closes", and
// an operator was sent to argue a maintenance slot with a pharmacy that in fact just has no
// hours on file. One of those is a fact about a business; the other is a missing row.
//
// So the rule is written ONCE, here, and the three call sites call it. A fourth caller
// cannot get it wrong, and there is no sentence to keep in step across files.
//
//   'hours-not-entered'  the GATE says this site's own rows do not answer the days that
//                        decide a disruption. Nobody has entered its hours. The remedy is
//                        data entry, and this is most of the estate.
//   'never-closes'       the gate DOES resolve, the hours DO resolve, and there is still no
//                        window: a genuine 24-hour pharmacy. The remedy is a conversation.
//   'hours-unreadable'   we cannot tell which of the two it is — the lookup failed, the row
//                        predates hours_gate_resolved, or a store answered without the
//                        columns. Never spoken as either of the other two.
//
// ⚠️ AN ABSENT COLUMN IS 'hours-unreadable', NEVER 'never-closes'. Same rule, same reason, as
// gateResolved() above: a store that predates the column, a lookup that threw, an older row
// shape — all of them mean we cannot tell, and the cautious answer is the one that does not
// make a claim about a pharmacy's trading pattern.
const NO_WINDOW_REASONS = ['hours-not-entered', 'never-closes', 'hours-unreadable'];

function noOvernightWindowReason(w) {
  if (!w) return 'hours-unreadable';
  if (w.hours_gate_resolved === false) return 'hours-not-entered';
  if (w.hours_gate_resolved === true && w.hours_resolved === true) return 'never-closes';
  return 'hours-unreadable';
}

// The sentence for a person, built from that reason. The two things that differ between call
// sites are parameters rather than three copies of the paragraph:
//
//   subject  what cannot be applied, as a noun phrase ("this", "a boot target", "a restart").
//   remedy   the escape hatch THIS caller offers, lower case, no full stop
//            ("use apply-now with a named operator", 'send when:"now" with a named operator').
function describeNoOvernightWindow(w, opts) {
  const subject = (opts && opts.subject) || 'this';
  const remedy = (opts && opts.remedy) || 'use apply-now with a named operator';
  switch (noOvernightWindowReason(w)) {
    case 'hours-not-entered':
      return 'nobody has entered this site\'s opening hours, so Watchman is working from the '
           + 'estate fallback guess — and it will not sign a member of staff out on a guess. '
           + 'Enter this site\'s hours (or import them from its VoIP time profile), then '
           + `${subject} will schedule itself into the site's own overnight window.`;
    case 'never-closes':
      return `that site has no overnight window — it never closes, so ${subject} cannot be `
           + `applied to it unattended. Raise it and ${remedy}, at a time somebody has agreed `
           + 'with the pharmacy.';
    default:
      return `that site's opening hours could not be read, so ${subject} cannot be applied to `
           + `it unattended. Check its hours in Watchman, or ${remedy}.`;
  }
}

// ── ⛔ WOULD THIS EDIT NEWLY ARM THE NIGHTLY RESTART (A2) ────────────────────
// The write path's half of the safety story, and the one this whole file's validators were
// missing. PUT /pharmacies/:id/hours is the ONE write that decides what every gate in the
// platform will permit, and it had the shared admin token, an actor from the request body and
// no confirmation of any kind. store.pg.js names the exact harm in its own comment: a stale
// 'closed' weekday marker on a day that now trades "makes an unattended restart legal on a
// trading morning". Every interruption path was hardened; its input was not.
//
// So an edit is classified before it is applied: does it take a weekday on which an
// unattended disruptive job CANNOT run today and turn it into one on which it CAN? That edit
// gets the typed site name, exactly like apply-now. An edit that only narrows what is
// permitted — or leaves it alone — does not, because training people to type a pharmacy's
// name for routine edits is how they stop reading the dialog.
//
// ⚠️ THE NIGHT BAND IS DUPLICATED HERE AND THAT IS A DEBT, NOT A DESIGN. The authority is
// pmr_night_start_s() / pmr_night_end_s() in db/schema.sql, because the gate is evaluated
// inside the claim statement. These two constants are a copy for a check that runs before any
// row is written, on a proposal that is not in the database yet and cannot be asked about.
// test/pmr-control-plane.test.js asserts the two agree by reading the SQL literals, so the
// copy cannot drift silently.
const NIGHT_START_S = 79200;   // 22:00 — pmr_night_start_s()
const NIGHT_END_S = 21600;     // 06:00 — pmr_night_end_s()

// Does this block cover any part of the night band? The band is two pieces of one local day
// ([22:00,24:00) and [00:00,06:00)), so a block trading at either end protects that weekday.
function touchesNight(block) {
  if (!block) return false;
  return Number(block.opens_s) < NIGHT_END_S || Number(block.closes_s) > NIGHT_START_S;
}

// The weekdays on which the gate CANNOT release an unattended disruptive job, given a
// proposed week. Two reasons, and both are refusals rather than permissions:
//
//   UNKNOWN   the weekday has neither an open block nor a closed marker, so
//             site_hours_gate_resolved() is false for it and the gate refuses outright.
//             This is the protection A1 restored, and it is the one an edit removes just by
//             filling the day in.
//   TRADING   the site trades into or out of the night band on that weekday, so the gate is
//             shut for the hours it would otherwise fire in.
//
// Returns a Set of weekday numbers.
function nightProtectedWdays(blocks, closedWdays) {
  const list = Array.isArray(blocks) ? blocks : [];
  const closed = new Set((Array.isArray(closedWdays) ? closedWdays : []).map(Number));
  const stated = new Set(closed);
  const trading = new Set();
  for (const b of list) {
    if (!b || !Number.isInteger(Number(b.wday))) continue;
    stated.add(Number(b.wday));
    if (touchesNight(b)) trading.add(Number(b.wday));
  }
  const out = new Set();
  for (let wday = 0; wday <= 6; wday += 1) {
    if (!stated.has(wday) || trading.has(wday)) out.add(wday);
  }
  return out;
}

// The weekdays this edit would NEWLY hand to the nightly restart: protected before, not
// protected after. Sorted, so the refusal names them in a stable order.
//
// ⚠️ ONE DIRECTION ONLY. An edit that ADDS protection needs no ceremony — that is somebody
// making the estate safer, and refusing it would be perverse.
function newlyPermittedWdays(before, after) {
  const wasProtected = nightProtectedWdays(before && before.blocks, before && before.closed_wdays);
  const nowProtected = nightProtectedWdays(after && after.blocks, after && after.closed_wdays);
  const out = [];
  for (const wday of wasProtected) if (!nowProtected.has(wday)) out.push(wday);
  return out.sort((a, b) => a - b);
}

// The same question for ONE calendar date, which is what an exception row changes. An
// exception REPLACES the weekly pattern for its date, so the comparison is between whatever
// answers that date now and whatever would answer it after.
//
// `day` is { known, blocks } — `known` false meaning nothing states that date at all, which
// is protected for the same reason an unknown weekday is.
function dayNewlyPermitted(before, after) {
  const protectedNow = !before || before.known !== true
    || (Array.isArray(before.blocks) && before.blocks.some(touchesNight));
  const protectedAfter = !after || after.known !== true
    || (Array.isArray(after.blocks) && after.blocks.some(touchesNight));
  return protectedNow && !protectedAfter;
}

// ── ⛔ MAY THIS STATE BE ACTED ON WITHOUT A PERSON WATCHING (A1) ─────────────
// The JavaScript side of the provenance split described above site_hours_day_known() in
// db/schema.sql, and the ONE place any JS asks the question. Everything that can interrupt a
// live counter — requireDeliberateInterruption() and the routes behind it — reads this and
// nothing else.
//
// ⚠️ IT DOES NOT RE-DERIVE THE ANSWER. `gate_resolved` is computed in Postgres, in the same
// function the claim statement gates on, and re-implementing "which weekdays are facts" here
// is precisely the second implementation of BST/GMT this module's header refuses to have.
// This reads the column.
//
// ⚠️ AND AN ABSENT COLUMN IS UNRESOLVED, NOT RESOLVED. A store that predates the column, a
// lookup that threw and left null, an older row shape — all of them arrive here as "no
// gate_resolved key", and every one of them means we cannot tell. The gate's unknown is
// "treat it as open", so the answer is false and the caller asks for the typed site name.
//
// The `hours_source` test is belt-and-braces and cannot fire on a consistent row (a site with
// any fact of its own reads 'voip' or 'manual', and a site with none cannot be gate-resolved);
// it is here so that a hand-built or partially-selected state cannot smuggle a fallback
// answer past the gate.
function gateResolved(state) {
  if (!state || state.gate_resolved !== true) return false;
  if (state.hours_source === 'fallback') return false;
  return true;
}

// ── THE WIRE CONTRACT FOR OPENING HOURS (S6 / A1 / W1 / W2) ──────────────────
// One site_hours_state() row -> the `hours` object the site page renders. It exists so that
// exactly ONE piece of code decides what an unresolved site looks like on the wire, and so
// that decision is testable without a database.
//
// ⛔ WHY THIS SHAPE CHANGED, AND IT IS THE THIRD TIME THIS EXACT THING HAPPENED. The backend
// was made correct on its own terms — site_hours_gate_resolved() reads the three base tables
// and pmr_disruptive_allowed() gates on it — and the SCREEN was left deriving the same
// question for itself, from a different signal. desktopChanges.readHours() decided "are this
// site's hours known" with `typeof h.openNow === 'boolean'`, and the estate fallback fills
// openNow with a real boolean. So the server refused a disruptive job on the grounds that
// nobody has told us this site's hours, while the pill beside the button said "closed now"
// as a fact. Two implementations of one question, and they disagreed in the direction that
// makes an apply-now button look safe at 11am.
//
// The remedy is the one this codebase already uses for the printer table: ONE definition,
// carried across the wire, READ BY NAME. Nothing downstream may infer "is this known" from
// the presence, the type or the truthiness of another field.
//
//   certainty   the named tri-state, and the ONLY field any consumer may use to decide how
//               much to trust the rest. It answers a question about PROVENANCE:
//
//                 'fact'     the open/closed answer came from this pharmacy's OWN rows —
//                            its VoIP time profile or hours somebody typed. Trustworthy.
//                 'guess'    the answer came from the single estate fallback window. Nobody
//                            has told us this site's hours. It is not a claim about this
//                            pharmacy at all; it is the estate default evaluated at this
//                            instant.
//                 'unknown'  nothing resolved — no rows, no fallback reached it, or the
//                            lookup failed. We cannot say anything.
//
//   openNow     whether the site is open, and it is a SEPARATE fact from certainty. Present
//               ONLY when certainty === 'fact'. See the decision below.
//
//   gateResolved   whether an unattended disruptive job may act on this site. NOT the same
//               question as certainty and deliberately kept apart: a site with a real VoIP
//               profile that has a gap on one weekday is certainty 'fact' (we know whether
//               it is open right now) and gateResolved false (the gate will not fire near
//               that gap). Both are true statements and neither implies the other.
//
// ⚠️ THE DECISION W1 ASKED FOR, STATED: A FALLBACK-ONLY SITE DOES NOT REPORT `openNow`.
// Top-level `openNow` now means, in every shape it can arrive in, "this pharmacy is open,
// and that is a fact about this pharmacy". It used to also mean "the estate default window
// happens to be shut at this instant", and the two are not the same sentence — the whole
// defect above is what happens when one key carries both.
//
// The guessed answer is NOT thrown away, because it is genuinely useful and because losing
// it would make "nobody entered this site's hours" indistinguishable from "the lookup threw",
// which have different remedies. It moves to `guess`, a sub-object whose name cannot be
// mistaken for a fact:
//
//   guess: { openNow, nextOpen, nextClose }
//
// So the failure mode of a consumer that reads this payload NAIVELY — takes openNow and
// ignores certainty — is now CAUTION rather than false confidence, which is the direction
// every other unknown in this feature already fails in. That is the point of the change: the
// contract stops depending on the reader remembering a rule.
//
// ⚠️ AND `openNow` IS STILL OMITTED, NEVER FALSE, WHEN NOTHING RESOLVED. An absent key is
// the only way to say "we do not know" in a shape whose other states are true and false. Do
// not "simplify" any of this into `openNow: !!state.is_open`.
//
// ⚠️ THE KEY SPELLINGS ARE THE FRONTEND'S (W2). This used to emit timezone / nextOpenAt /
// nextCloseAt while desktopChanges.readHours() read timeZone / nextOpen / nextClose — zero
// hits for nextOpenAt anywhere in the frontend — so the "opens 09:00" clause silently never
// rendered and the pill's next-event suffix was dead. The server moved to the reader's
// spelling rather than the reverse, because the reader's names are also Intl's own
// (`timeZone`) and there are four call sites on that side. test/hours-wire-contract.test.js
// reads BOTH files and fails if the two lists ever diverge again.
const HOURS_CERTAINTY = ['fact', 'guess', 'unknown'];

// Every key hoursPayload can emit, split by which shape emits it. Exported because the
// cross-side contract test enumerates them against the frontend's reader — a test that only
// exercised this side would pass on the day the two diverge, which is exactly what happened.
const HOURS_WIRE_KEYS = {
  // Emitted in all three shapes, always, so a consumer never has to test for presence.
  always: ['certainty', 'source', 'gateResolved', 'timeZone', 'nextOpen',
    'nextClose', 'describes'],
  // certainty === 'fact' only.
  fact: ['openNow'],
  // certainty === 'guess' only.
  guess: ['guess'],
  // The keys inside the `guess` sub-object.
  guessInner: ['openNow', 'nextOpen', 'nextClose'],
  // ⛔ THE ONLY WAY TO EMIT A KEY NOBODY READS, AND IT COSTS A WRITTEN REASON (Z3 / Z4).
  // key -> why it is still on the wire and what removes it. The cross-side contract test
  // FAILS on any emitted key that no consumer reads unless it is declared here, and fails on
  // any entry here whose reason is empty or whose key is not actually emitted any more.
  //
  // ⚠️ WHAT USED TO BE IN THIS SLOT, AND WHY IT IS EMPTY. It was `optional: ['resolved']`,
  // an exemption with no reason attached, justified in a comment that said the hours EDITOR
  // showed `resolved`. That reader did not exist: the frontend's ONLY reader of this payload
  // is readHours() in desktopChanges.jsx, which computes its own `described` from
  // `certainty`, and no screen calls GET /pharmacies/:id/hours at all. So the one key the
  // contract test was told to skip was the one key nothing read — the exemption and the
  // defect were the same line. `resolved` was a pure projection of `certainty !== 'unknown'`
  // carrying no information, and it is no longer emitted. An exemption now has to name a
  // consumer or a date, in writing, where the next person will read it.
  deprecated: {},
};

// The named tri-state, computed in ONE place. `hours_source` is the provenance Postgres
// already computes from the three base tables; this does not re-derive it.
function hoursCertainty(state) {
  const describable = !!state && state.resolved !== false
    && state.is_open !== null && state.is_open !== undefined;
  if (!describable) return 'unknown';
  // ⚠️ AN ALLOWLIST, NOT A DENYLIST OF 'fallback'. Only the two sources that are statements
  // about THIS pharmacy earn 'fact'; the estate window and anything unrecognised or absent
  // are a guess. A new source appearing in Postgres must arrive here as a guess and be
  // promoted deliberately, not be trusted by default.
  return (state.hours_source === 'voip' || state.hours_source === 'manual') ? 'fact' : 'guess';
}

function hoursPayload(state) {
  const certainty = hoursCertainty(state);
  const known = certainty !== 'unknown';
  const out = {
    // ⛔ READ THIS, NOT THE TYPE OF ANY OTHER FIELD. 'fact' | 'guess' | 'unknown'.
    certainty,
    // Present in every shape: 'voip' | 'manual' | 'fallback' | null when unresolved.
    source: known ? (state.hours_source || null) : null,
    // ⛔ `resolved` IS NOT EMITTED (Z3). It was `certainty !== 'unknown'` and nothing else —
    // a projection of a key travelling beside it, carrying no fact of its own, kept alive on
    // the strength of a reader (the hours editor) that does not exist. A consumer that wants
    // "can this site be described at all" computes it from `certainty` the way readHours()
    // already does; a consumer that wants "may this be acted on" reads `gateResolved`. Two
    // spellings of one question is how the last three defects in this feature survived, and
    // the second spelling was this one.
    // ⛔ ALWAYS PRESENT, AND NOT THE SAME FACT AS EITHER OF THE OTHER TWO (A1). This says an
    // unattended job may act on this site: its own rows answer today AND tomorrow. False for
    // every site whose hours have never been entered — most of the estate — and the UI
    // should read it as "nothing will be applied here overnight until somebody fills these
    // in", NOT as an error.
    gateResolved: known && gateResolved(state),
    // The site's own zone, needed to render every instant below in the terms the staff will
    // experience. Present even when certainty is 'guess', because the zone is a property of
    // the pharmacy and not of its hours.
    timeZone: (state && state.site_timezone) || null,
    // ⚠️ FACT-ONLY INSTANTS. Null unless certainty === 'fact', because "opens at 07:00" is a
    // claim about this pharmacy and the fallback's 07:00 is not one. The guessed pair lives
    // under `guess`.
    nextOpen: certainty === 'fact' ? ((state && state.next_open_at) || null) : null,
    nextClose: certainty === 'fact' ? ((state && state.next_close_at) || null) : null,
    describes: describeHoursState(state),
  };
  // The whole point of the function.
  if (certainty === 'fact') out.openNow = !!state.is_open;
  if (certainty === 'guess') {
    // The estate default, evaluated at this instant, under a name that cannot be read as a
    // fact about this pharmacy. Render it labelled as a default or not at all — never in the
    // same voice as `openNow`.
    out.guess = {
      openNow: !!state.is_open,
      nextOpen: (state && state.next_open_at) || null,
      nextClose: (state && state.next_close_at) || null,
    };
  }
  return out;
}

// ── weekdays a site is KNOWN not to trade ────────────────────────────────────
// The write-path validator for the closed markers site_hours_v reads. Deliberately its own
// list rather than a `closed: true` flag on an hours block: a closed weekday has no times,
// and a block with times is not closed. Same closed-whitelist treatment as everything else
// here — an out-of-range day is refused, not clamped.
//
// Refuses a weekday that also carries an open block, because the two together are a
// contradiction the resolver would have to guess about, and guessing is what this whole
// module exists to avoid.
function validateClosedDays(input, blocks) {
  if (input === undefined || input === null) return { ok: true, value: [] };
  if (!Array.isArray(input)) return { ok: false, error: 'closed_wdays must be an array of weekday numbers' };
  const open = new Set((Array.isArray(blocks) ? blocks : []).map((b) => b && b.wday));
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'number' || !Number.isInteger(raw)) {
      return { ok: false, error: 'closed_wdays must be whole numbers sent as JSON numbers, not strings' };
    }
    if (raw < 0 || raw > 6) return { ok: false, error: 'each closed weekday must be between 0 (Sunday) and 6' };
    if (open.has(raw)) {
      return { ok: false, error: `${WDAY_SHORT[raw]} cannot be both closed and have opening hours` };
    }
    if (!out.includes(raw)) out.push(raw);
  }
  return { ok: true, value: out.sort((a, b) => a - b) };
}

module.exports = {
  WDAY_NAMES,
  WDAY_SHORT,
  HOURS_SOURCES,
  SECONDS_PER_DAY,
  validateHoursBlock,
  validateWeek,
  validateException,
  hhmm,
  hhmmToSeconds,
  blocksFromTemporalRule,
  describeHoursState,
  gateResolved,
  NO_WINDOW_REASONS,
  noOvernightWindowReason,
  describeNoOvernightWindow,
  NIGHT_START_S,
  NIGHT_END_S,
  touchesNight,
  nightProtectedWdays,
  newlyPermittedWdays,
  dayNewlyPermitted,
  hoursPayload,
  hoursCertainty,
  HOURS_CERTAINTY,
  HOURS_WIRE_KEYS,
  validateClosedDays,
};
