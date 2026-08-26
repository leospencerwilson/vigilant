// ⛔ THE OPENING-HOURS WIRE CONTRACT, HELD FROM BOTH ENDS (W4).
//
// WHY THIS FILE EXISTS, AND IT IS THE THIRD TIME. Three times now a fix on one side of this
// contract has broken the other side's assumption, and every time the tests stayed green:
//
//   1. the estate fallback was made per-weekday, which made site_hours_state().resolved true
//      for all 348 sites and quietly turned the gate's "unknown" into a guess it acted on;
//   2. the gate was then fixed to read site_hours_gate_resolved(), and the SCREEN was left
//      deciding "are these hours known" for itself with `typeof h.openNow === 'boolean'` —
//      so the server refused a disruptive job while the pill beside the button said the site
//      was safely closed;
//   3. the server emitted timezone / nextOpenAt / nextCloseAt while the screen read
//      timeZone / nextOpen / nextClose. Zero hits for nextOpenAt anywhere in the frontend.
//      The "opens at 09:00" clause simply never rendered, and nothing failed.
//
// Every one of those is the same defect: ONE question with TWO implementations, or ONE value
// with TWO spellings, and a test suite that only ever exercised one side. So this file does
// what test/printer-contract.test.js does for the printer table — it reads the OTHER OWNER'S
// SOURCE and compares, rather than checking that our own rules are reasonable.
//
// ⚠️ IT DOES NOT SKIP WHEN THE FRONTEND IS NOT THERE. A contract test that silently disables
// itself is worth less than no test, because the suite still reads green on the day the two
// sides diverge — which is precisely the failure mode above. If the sibling checkout is
// somewhere else, point WC_FIELD_SRC at it.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const openingHours = require("../src/shared/openingHours");

// The frontend's reader lives in its own repo. Default is the sibling checkout Leo has;
// WC_FIELD_SRC overrides the `src` root for anyone whose layout differs.
const WC_FIELD_SRC = process.env.WC_FIELD_SRC
  || path.join(__dirname, "..", "..", "wcn-infrastructure-docs", "frontend", "wc-field", "src");
const READER_PATH = path.join(WC_FIELD_SRC, "pages", "ops", "desktopChanges.jsx");

const reader = (() => {
  try {
    return fs.readFileSync(READER_PATH, "utf8");
  } catch (err) {
    assert.fail(
      `the frontend's hours reader was not readable at ${READER_PATH} (${err.code}). This test `
      + "compares the two sides of the opening-hours wire contract and must not skip: set "
      + "WC_FIELD_SRC to the wc-field src directory, or check the frontend out beside this repo."
    );
    return "";
  }
})();

// readHours() is the ONE function on the frontend that touches the wire shape. Everything
// else there (HoursPill, hoursSentence, SiteTabs, SiteHub, SiteFlow, Printers) consumes the
// NORMALISED object readHours returns, so this is the whole boundary.
function readerBody() {
  const start = reader.indexOf("export function readHours");
  assert.notEqual(start, -1,
    "readHours() is gone from desktopChanges.jsx — it is the frontend's only reader of the "
    + "hours payload, and this contract has to be re-pointed if it moved");
  // To the first closing brace in the first column after the signature.
  const end = reader.indexOf("\n}", start);
  assert.notEqual(end, -1, "could not find the end of readHours()");
  return reader.slice(start, end + 2);
}

// Every `h.<key>` the reader takes off the payload object. The frontend names its local
// binding for the wire object `h`; the contract is that keys are read BY NAME off it, which
// is also what stops the next person inferring a fact from the type of a field.
function keysReadByFrontend(body) {
  const found = new Set();
  // `h.key` and `h?.key` alike — optional chaining is a style choice, not a different read.
  for (const m of body.matchAll(/\bh\s*\??\s*\.\s*([A-Za-z_$][\w$]*)/g)) found.add(m[1]);
  return found;
}

// The same question one level down. readHours() binds the `guess` sub-object to `g`, so the
// keys INSIDE it are read as `g.openNow` and not `h.openNow` — and without this the three
// guessInner keys were emitted into a scan that could not see them, which is the identical
// blind spot `resolved` sat in.
function innerKeysReadByFrontend(body) {
  const found = new Set();
  for (const m of body.matchAll(/\bg\s*\??\s*\.\s*([A-Za-z_$][\w$]*)/g)) found.add(m[1]);
  return found;
}

const ALWAYS = openingHours.HOURS_WIRE_KEYS.always;
const FACT = openingHours.HOURS_WIRE_KEYS.fact;
const GUESS = openingHours.HOURS_WIRE_KEYS.guess;
const GUESS_INNER = openingHours.HOURS_WIRE_KEYS.guessInner;
// ⛔ key -> written reason. The ONLY exemption from "everything emitted is read", and it
// costs a sentence naming a consumer or a removal date. See the block above `deprecated` in
// openingHours.js for what used to be here and what it hid.
const DEPRECATED = openingHours.HOURS_WIRE_KEYS.deprecated;
const EMITTED = new Set([...ALWAYS, ...FACT, ...GUESS]);
const MUST_BE_READ = [...EMITTED].filter((k) => !Object.hasOwn(DEPRECATED, k));

// ── the declared contract is the code's actual behaviour ────────────────────

test("HOURS_WIRE_KEYS is what hoursPayload actually emits, in all three shapes", () => {
  // The list the cross-side comparison is made against has to be the truth, or the
  // comparison proves nothing. So it is checked against real output first.
  const fact = openingHours.hoursPayload({
    is_open: true, hours_source: "voip", resolved: true, gate_resolved: true,
    site_timezone: "Europe/London", next_close_at: "2026-08-26T20:00:00.000Z",
  });
  const guess = openingHours.hoursPayload({
    is_open: false, hours_source: "fallback", resolved: true, gate_resolved: false,
    site_timezone: "Europe/London", next_open_at: "2026-08-27T06:00:00.000Z",
  });
  const unknown = openingHours.hoursPayload(null);

  assert.deepEqual(Object.keys(fact).sort(), [...ALWAYS, ...FACT].sort());
  assert.deepEqual(Object.keys(guess).sort(), [...ALWAYS, ...GUESS].sort());
  assert.deepEqual(Object.keys(unknown).sort(), [...ALWAYS].sort());
  assert.deepEqual(Object.keys(guess.guess).sort(),
    [...openingHours.HOURS_WIRE_KEYS.guessInner].sort());

  // The three shapes are exactly the three values of the named tri-state, and nothing else.
  assert.equal(fact.certainty, "fact");
  assert.equal(guess.certainty, "guess");
  assert.equal(unknown.certainty, "unknown");
  assert.deepEqual(openingHours.HOURS_CERTAINTY.slice().sort(),
    ["fact", "guess", "unknown"]);
});

// ── server -> frontend: nothing we emit is unread ───────────────────────────

test("every key the server emits is a key the frontend actually reads", () => {
  const body = readerBody();
  const read = keysReadByFrontend(body);
  const unread = MUST_BE_READ.filter((k) => !read.has(k));
  assert.deepEqual(unread, [],
    `hoursPayload emits ${unread.join(", ")}, and readHours() in desktopChanges.jsx never `
    + "reads them off the payload. Either the frontend has to read them by name, or the "
    + "server must stop sending them — a key that travels and is never read is a key that is "
    + "about to be spelled two ways.");
});

test("every key inside the `guess` sub-object is read too", () => {
  // Z4. The scan used to look only at `h.<key>`, so the three keys the frontend takes off the
  // `g` binding were exempt by accident rather than by decision — the same blind spot that
  // let `resolved` travel unread for three fixes. There is no deprecation list for these:
  // the sub-object exists to carry exactly what a dialog renders.
  const body = readerBody();
  const readInner = innerKeysReadByFrontend(body);
  const unread = GUESS_INNER.filter((k) => !readInner.has(k));
  assert.deepEqual(unread, [],
    `hoursPayload emits guess.${unread.join(", guess.")} and readHours() never reads `
    + "it off the guess sub-object");
});

// ── ⛔ AN UNREAD KEY FAILS THIS TEST UNLESS SOMEBODY WROTE DOWN WHY (Z4) ─────
// The exemption that let this file miss `resolved` was `optional: ['resolved']` — a list with
// no reason attached, justified in a comment that named the hours EDITOR as its reader. That
// reader does not exist. So the one key nothing read was the one key this test was told to
// skip: the exemption and the defect were the same line.
//
// The list is now a MAP of key -> written reason, and these two tests make it expensive
// enough to be deliberate: an entry must name a real emitted key and must carry a real
// sentence. An empty map is the healthy state and is what ships today.
test("the deprecation list is a map of real emitted keys to written reasons", () => {
  assert.equal(typeof DEPRECATED, "object");
  assert.ok(DEPRECATED && !Array.isArray(DEPRECATED),
    "`deprecated` must be a key -> reason map. A bare list is what `optional` was, and a list "
    + "cannot hold the reason that makes the exemption reviewable.");
  assert.equal(openingHours.HOURS_WIRE_KEYS.optional, undefined,
    "the old reason-free `optional` escape hatch must not come back alongside `deprecated`");
  for (const [key, reason] of Object.entries(DEPRECATED)) {
    assert.ok(EMITTED.has(key),
      `"${key}" is declared deprecated but hoursPayload does not emit it — delete the entry`);
    assert.equal(typeof reason, "string");
    assert.ok(reason.trim().length >= 30,
      `the reason for keeping "${key}" on the wire has to say who still reads it, or when it `
      + `goes. Got: ${JSON.stringify(reason)}`);
  }
});

test("a key that no consumer reads FAILS, and only a written deprecation excuses it", () => {
  // The rule itself, exercised rather than described: an emitted key absent from BOTH the
  // frontend's reads and the deprecation map is a failure. Simulated against this suite's own
  // comparison so the rule is proven without waiting for somebody to add such a key.
  const read = keysReadByFrontend(readerBody());
  const phantom = "hoursKnownProbably";
  const emitted = new Set([...EMITTED, phantom]);
  const unread = [...emitted].filter((k) => !read.has(k) && !Object.hasOwn(DEPRECATED, k));
  assert.deepEqual(unread, [phantom],
    "the comparison must catch an emitted key nobody reads — that is the whole point of Z4");
  // …and declaring it, with a reason, is what makes it pass.
  const excused = { ...DEPRECATED, [phantom]: "kept for the 2026-09 Watchman release only" };
  assert.deepEqual(
    [...emitted].filter((k) => !read.has(k) && !Object.hasOwn(excused, k)), []);
});

// ── frontend -> server: nothing it reads is unsent ──────────────────────────

test("every key the frontend reads is a key the server actually emits", () => {
  const body = readerBody();
  const unsent = [...keysReadByFrontend(body)].filter((k) => !EMITTED.has(k)).sort();
  assert.deepEqual(unsent, [],
    `readHours() reads ${unsent.join(", ")} off the hours payload and hoursPayload() never `
    + "emits it. This is exactly how nextOpenAt/nextOpen happened: the clause never rendered "
    + "and nothing failed.");
});

// ── the specific defects, pinned by name so they cannot come back ───────────

test("the frontend decides 'known' from the NAMED tri-state, not the type of another field", () => {
  const body = readerBody();
  // The line whose own comment called it the single most important in the file, and which
  // was wrong: `typeof h.openNow === 'boolean'` asks the payload to prove a fact by the
  // shape of a different field, and the estate fallback satisfied it.
  assert.doesNotMatch(body, /typeof\s+h\s*\??\s*\.\s*openNow/,
    "readHours() must not test the TYPE of openNow. That test is the shape of the derivation "
    + "that caused the defect, and it is no longer needed for anything: openNow is now emitted "
    + "ONLY when certainty === 'fact', so `h.openNow ?? null` carries it and `h.certainty` "
    + "answers whether it is a fact — one field, computed once, in Postgres");
  assert.match(body, /\bh\s*\??\s*\.\s*certainty\b/,
    "readHours() must read h.certainty by name");
});

test("the old key spellings are gone from BOTH sides", () => {
  // W2. Three keys, two spellings each, and the mismatch was invisible because the missing
  // value simply rendered as "not stated".
  const serverSrc = fs.readFileSync(
    path.join(__dirname, "..", "src", "shared", "openingHours.js"), "utf8");
  const payload = serverSrc.slice(serverSrc.indexOf("function hoursPayload"));
  for (const dead of ["nextOpenAt", "nextCloseAt"]) {
    assert.ok(!payload.includes(`${dead}:`), `hoursPayload still emits ${dead}`);
    assert.ok(!reader.includes(dead), `the frontend still mentions ${dead}`);
  }
  assert.ok(!/\btimezone\s*:/.test(payload), "hoursPayload still emits lower-case `timezone`");
  assert.ok(!/\bh\s*\??\s*\.\s*timezone\b/.test(reader), "the frontend still reads h.timezone");
});

test("a fallback-only site carries its guess under a name that is not openNow", () => {
  // The W1 decision, stated as an assertion: top-level openNow means "this pharmacy is open,
  // and that is a fact about this pharmacy" in EVERY shape it can arrive in. A consumer that
  // reads openNow and ignores certainty now fails safe — it sees nothing — instead of
  // rendering the estate default as this pharmacy's own hours.
  const guess = openingHours.hoursPayload({
    is_open: false, hours_source: "fallback", resolved: true, gate_resolved: false,
    site_timezone: "Europe/London", next_open_at: "2026-08-27T06:00:00.000Z",
  });
  assert.equal("openNow" in guess, false);
  assert.equal(guess.guess.openNow, false);
  assert.equal(guess.nextOpen, null, "a guessed instant is not a fact-shaped key");
  assert.equal(guess.guess.nextOpen, "2026-08-27T06:00:00.000Z");
  // …and the guess is never presented as gate-resolved, whatever a hand-built row claims.
  assert.equal(
    openingHours.hoursPayload({
      is_open: false, hours_source: "fallback", resolved: true, gate_resolved: true,
    }).gateResolved,
    false
  );
});
