// Alert notification senders + dispatch gating. No real network: global.fetch is stubbed.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const notify = require("../src/worker/notify");

// Run fn with a stubbed global.fetch that records calls; restore after.
function withFetch(stub, fn) {
  const orig = global.fetch;
  const calls = [];
  global.fetch = async (url, opts) => {
    calls.push({ url: String(url), opts });
    return stub ? stub(url, opts) : { ok: true, status: 200 };
  };
  return Promise.resolve()
    .then(() => fn(calls))
    .finally(() => { if (orig === undefined) delete global.fetch; else global.fetch = orig; });
}

const CONFIG = { resendApiKey: "re_test", alertEmailFrom: "Vigilant <v@wcn>" };
const RULE = {
  name: "CPU high", severity: "critical", notify_on: "both",
  notify_email: "noc@wcn, ops@wcn", notify_teams_webhook: "https://teams.example/webhook/abc",
};
const OPEN = { kind: "open", device_id: "d1", serial: "RB-1", site_name: "Allied X", detail: "cpu_load > 90 (value=95)", rule: RULE };

test("dispatchAlert(open): sends BOTH email (Resend) and Teams", async () => {
  await withFetch(null, async (calls) => {
    const r = await notify.dispatchAlert(OPEN, { config: CONFIG });
    assert.equal(r.sent, true);
    const email = calls.find((c) => c.url === "https://api.resend.com/emails");
    const teams = calls.find((c) => c.url === "https://teams.example/webhook/abc");
    assert.ok(email, "email POSTed to Resend");
    assert.match(email.opts.headers.Authorization, /^Bearer re_test$/);
    const eb = JSON.parse(email.opts.body);
    assert.deepEqual(eb.to, ["noc@wcn", "ops@wcn"], "recipients split");
    assert.match(eb.subject, /CRITICAL OPENED/);
    assert.match(eb.subject, /Allied X/);
    assert.ok(teams, "Teams POSTed to the webhook");
    const tb = JSON.parse(teams.opts.body);
    assert.equal(tb["@type"], "MessageCard");
    assert.match(tb.text, /cpu_load > 90/);
  });
});

test("dispatchAlert respects notify_on: clear-only rule does NOT fire on open", async () => {
  await withFetch(null, async (calls) => {
    const rule = { ...RULE, notify_on: "clear" };
    const r = await notify.dispatchAlert({ ...OPEN, rule }, { config: CONFIG });
    assert.equal(r.sent, false);
    assert.equal(r.skipped, "notify_on");
    assert.equal(calls.length, 0, "no sends for a suppressed transition");
  });
});

test("dispatchAlert: no targets configured → nothing sent", async () => {
  await withFetch(null, async (calls) => {
    const rule = { name: "x", notify_on: "both" };
    const r = await notify.dispatchAlert({ ...OPEN, rule }, { config: CONFIG });
    assert.equal(r.sent, false);
    assert.equal(calls.length, 0);
  });
});

test("dispatchAlert: email skipped when RESEND_API_KEY absent, Teams still sends", async () => {
  await withFetch(null, async (calls) => {
    const r = await notify.dispatchAlert(OPEN, { config: { alertEmailFrom: "v@wcn" } }); // no resendApiKey
    assert.equal(r.sent, true);
    assert.ok(!calls.some((c) => c.url.includes("resend.com")), "no email without API key");
    assert.ok(calls.some((c) => c.url.includes("teams.example")), "Teams still sent");
  });
});

test("senders never throw on a network error", async () => {
  await withFetch(() => { throw new Error("offline"); }, async () => {
    const e = await notify.sendEmail({ apiKey: "k", from: "f", to: "t@x", subject: "s", text: "b" });
    const t = await notify.sendTeams({ webhook: "https://x", title: "s", text: "b" });
    assert.equal(e.ok, false);
    assert.equal(t.ok, false);
  });
});
