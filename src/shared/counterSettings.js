'use strict';

// Vigilant — per-thin-client settings: the CLOSED whitelist, the DEFAULTS, and the ONE
// validator. Every layer that touches these values goes through this file.
//
// WHY it is this strict: these values start life in a BROWSER, are stored as jsonb, are
// pushed to the Pi on /telemetry, and end up (a) as KEY=VALUE lines in a file a shell
// script SOURCES on the device and (b) as xfreerdp argv. Anything that reaches there and
// is not a plain number or 1|0 is a command-injection surface. So this version has NO
// free-text settings at all: every value is a boolean, or an integer in a stated
// range/enum, and anything else is REFUSED rather than coerced into range. The refusal is
// what makes the file safe to write — not the quoting at the far end.
//
// The whitelist is CLOSED: an unknown key is an ERROR, not a silently dropped field, so a
// typo in the UI surfaces at once instead of appearing to save and doing nothing.

const SPECS = {
  // ── session options — read by the kiosk launcher; a change needs a kiosk restart ──
  smartcard:         { type: 'bool', default: true },                     // FreeRDP /smartcard
  printer_redirect:  { type: 'bool', default: true },                     // FreeRDP /printer:...
  clipboard:         { type: 'bool', default: true },                     // FreeRDP +clipboard
  bpp:               { type: 'enum', default: 16, values: [16, 24, 32] }, // FreeRDP /bpp:N
  // 0 does NOT mean "off" here, it means NEVER blank (xset s off -dpms noblank). A counter
  // that blanks mid-consultation is a support call, so never-blank is the default.
  blank_after_min:   { type: 'int',  default: 0,  min: 0,  max: 120 },

  // ── agent options — applied live by the agent's own loop, no restart ──
  report_interval_s: { type: 'int',  default: 30, min: 10, max: 900 },
  // For these two, 0 DISABLES the poll entirely, which is why the floor is 0 rather than
  // the smallest useful cadence.
  printer_every:     { type: 'int',  default: 15, min: 0,  max: 240 },
  discover_every:    { type: 'int',  default: 8,  min: 0,  max: 240 },
  // Screen thumbnail cadence for the thin-client list, in ticks. 0 DISABLES capture, and that
  // is the important value: a counter screen shows patient data, so a site that has not agreed
  // to it must be able to guarantee no frame is ever taken. Resolution is NOT settable from
  // here by design - the agent fixes it at 1/8 scale so text is illegible, so the server can
  // stop capture but cannot ask for a sharper picture of a patient record.
  screenshot_every:  { type: 'int',  default: 10, min: 0,  max: 240 },

  // ── support screen sharing ──
  // Minutes x11vnc stays up on the thin client, mirroring the LIVE display. 0 = off, and 0 is
  // the default: a counter shares its screen only because an operator just asked it to.
  //
  // READ THE screenshot_every NOTE ABOVE FIRST. It says the server may stop capture but must
  // not "ask for a sharper picture of a patient record". This key is the deliberate exception
  // to that — full resolution, live, interactive — added knowingly (2026-08-03) with four
  // controls that are the reason it is defensible, none of them decorative:
  //   1. the SHARED display: the pharmacist sees the same pixels, so support is never covert;
  //   2. the Pi expires the session on its OWN clock, so "it stopped" is a fact not a promise;
  //   3. an audit row per session (support_sessions), because full control from the first click
  //      makes "who was driving" a question a dispensing-error investigation may ask;
  //   4. a confirm step in the UI, because the thumbnail this opens from renders on every fleet
  //      row and a misclick must not open a live clinical session.
  // Removing any of those means removing this key too.
  //
  // A DURATION, not a deadline: it keeps this file's "bounded numbers only, no free text"
  // invariant, and the Pi computes expiry from its own clock — so a device whose NTP has
  // drifted cannot be handed a timestamp already past (never opens) or hours ahead (never
  // closes). Capped at 60: a ceiling is what makes "we turned that off" true, and a longer job
  // means clicking again, which is one more audit row, which is the point.
  support_vnc_min:   { type: 'int',  default: 0,  min: 0,  max: 60 },
};

const COUNTER_SETTING_KEYS = Object.keys(SPECS);

const COUNTER_SETTINGS_DEFAULTS = Object.freeze(
  COUNTER_SETTING_KEYS.reduce((acc, k) => { acc[k] = SPECS[k].default; return acc; }, {})
);

// The ONLY validator. Takes an arbitrary object (straight off the wire) and returns either
// { ok: true, value } — a new object holding only whitelisted, correctly typed, in-range
// keys — or { ok: false, error } naming the offending key.
//
// Note there is deliberately no "reset to default" sentinel (null/""): storage is
// merge-only, and saving a key back to its documented default is indistinguishable from
// never having set it, so a sentinel would add a second way to say the same thing and a
// second value shape to defend against.
function validateCounterSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'settings must be a JSON object' };
  }
  const value = {};
  for (const key of Object.keys(input)) {
    // hasOwnProperty, NOT `SPECS[key]`: a key of 'constructor' or 'toString' resolves
    // through Object.prototype and would sail past a truthiness check, which is exactly
    // how a closed whitelist stops being closed.
    if (!Object.prototype.hasOwnProperty.call(SPECS, key)) {
      return { ok: false, error: `unknown setting "${key}" — allowed keys are ${COUNTER_SETTING_KEYS.join(', ')}` };
    }
    const spec = SPECS[key];
    const v = input[key];

    if (spec.type === 'bool') {
      // A REAL boolean only. "yes", "true", 1 and 0 are refused rather than interpreted:
      // this becomes RDP_SMARTCARD=1|0 in a sourced file, and guessing what the caller
      // meant is how a wrong-but-plausible value gets written to a live counter.
      if (typeof v !== 'boolean') {
        return { ok: false, error: `"${key}" must be a boolean true or false` };
      }
      value[key] = v;
      continue;
    }

    // Integers are checked AS NUMBERS and never parsed out of a string: "24" arriving from
    // a <select> is a UI bug, and coercing it would hide the one class of bug this
    // whitelist exists to catch. Number.isInteger also rejects NaN/Infinity/24.5.
    if (typeof v !== 'number' || !Number.isInteger(v)) {
      return { ok: false, error: `"${key}" must be a whole number sent as a JSON number, not a string` };
    }
    if (spec.type === 'enum') {
      if (!spec.values.includes(v)) {
        return { ok: false, error: `"${key}" must be one of ${spec.values.join(', ')}` };
      }
    } else if (v < spec.min || v > spec.max) {
      return { ok: false, error: `"${key}" must be an integer between ${spec.min} and ${spec.max}` };
    }
    value[key] = v;
  }
  return { ok: true, value };
}

// The EFFECTIVE settings for a device: stored values merged over the defaults above. This
// is the single place the defaults are applied, so the agent ships none of its own and
// cannot drift from what the UI shows.
//
// Stored keys are re-validated ONE AT A TIME rather than as a block: the column could hold
// a value written before a range was tightened, or edited by hand in psql, and a single bad
// key must not discard the seven good ones. An unusable stored value silently falls back to
// its default — the device is never handed a value that would fail validation.
function effectiveCounterSettings(stored) {
  const out = Object.assign({}, COUNTER_SETTINGS_DEFAULTS);
  if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
    for (const key of Object.keys(stored)) {
      const checked = validateCounterSettings({ [key]: stored[key] });
      if (checked.ok) out[key] = checked.value[key];
    }
  }
  return out;
}

module.exports = {
  COUNTER_SETTING_KEYS,
  COUNTER_SETTINGS_DEFAULTS,
  validateCounterSettings,
  effectiveCounterSettings,
};
