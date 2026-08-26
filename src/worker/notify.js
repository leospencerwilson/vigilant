'use strict';

// Vigilant — alert notification senders (email via Resend, MS Teams via incoming webhook).
//
// The worker calls dispatchAlert() for each alert transition (open/clear) returned by the
// store's evaluateAndApplyAlerts. Senders are fire-and-forget and NEVER throw — a failed
// notification must never break a worker pass or block other alerts. Both use the global
// fetch (Node 20+); tests monkeypatch global.fetch.

const log = require('../shared/log');

const RESEND_URL = 'https://api.resend.com/emails';
const HTTP_TIMEOUT_MS = 5000;

// POST with a timeout; resolve {ok, status} on any outcome, never throw.
async function post(url, headers, body) {
  if (typeof fetch !== 'function') return { ok: false, status: 0 };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { method: 'POST', headers, body, signal: controller.signal });
    return { ok: !!(res && res.ok), status: res ? res.status : 0 };
  } catch (e) {
    return { ok: false, status: 0, error: e && e.message };
  } finally {
    clearTimeout(timer);
  }
}

// Send an email via Resend. `to` may be a comma/semicolon-separated string or an array.
async function sendEmail({ apiKey, from, to, subject, text }) {
  if (!apiKey || !from || !to) return { ok: false, skipped: true };
  const recipients = Array.isArray(to)
    ? to
    : String(to).split(/[,;]/).map((s) => s.trim()).filter(Boolean);
  if (!recipients.length) return { ok: false, skipped: true };
  return post(
    RESEND_URL,
    { Authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    JSON.stringify({ from, to: recipients, subject, text })
  );
}

// POST a FLAT JSON payload to a Teams notifier (a Power Automate "When an HTTP request is
// received" flow). Deliberately flat — single-level object, all string values, NO nested
// objects/arrays — so the flow's request schema maps each field straight into the Teams
// message / Adaptive Card. `payload` is the flat object (see the schema in the notify docs).
async function sendTeams({ webhook, payload }) {
  if (!webhook) return { ok: false, skipped: true };
  return post(webhook, { 'content-type': 'application/json' }, JSON.stringify(payload));
}

// Dispatch one alert transition to whichever channels the rule configured.
//   t = { kind:'open'|'clear', device_id, serial?, site_name?, detail, value,
//         rule:{ name, severity, notify_email, notify_teams_webhook, notify_on } }
// Honours rule.notify_on ('open'|'clear'|'both'). Returns a small result for logging/tests.
async function dispatchAlert(t, { config, logger } = {}) {
  const lg = logger || log;
  const rule = (t && t.rule) || {};
  const on = rule.notify_on || 'both';
  if (on !== 'both' && on !== t.kind) return { sent: false, skipped: 'notify_on' };
  if (!rule.notify_email && !rule.notify_teams_webhook) return { sent: false, skipped: 'no-targets' };

  const where = t.site_name || t.serial || t.device_id || 'device';
  const verb = t.kind === 'open' ? 'OPENED' : 'CLEARED';
  const subject = `[Vigilant] ${String(rule.severity || 'warning').toUpperCase()} ${verb} — ${rule.name || 'alert'} @ ${where}`;
  const lines = [
    `${rule.name || 'alert'} ${verb}`,
    `Site:   ${where}`,
    t.serial ? `Serial: ${t.serial}` : null,
    `Detail: ${t.detail || ''}`,
    `When:   ${new Date().toISOString()}`,
  ].filter(Boolean);
  const text = lines.join('\n');

  const results = {};
  if (rule.notify_email && config && config.resendApiKey) {
    results.email = await sendEmail({
      apiKey: config.resendApiKey, from: config.alertEmailFrom,
      to: rule.notify_email, subject, text,
    });
    if (!results.email.ok && !results.email.skipped) lg.warn('notify: email send failed', { rule: rule.name, status: results.email.status });
  }
  if (rule.notify_teams_webhook) {
    // FLAT payload for the Power Automate flow — no nested objects/arrays.
    const payload = {
      title: subject,
      severity: String(rule.severity || 'warning'),
      state: t.kind,                                   // 'open' | 'clear'
      rule: rule.name || 'alert',
      site: where,
      serial: t.serial || '',
      detail: t.detail || '',
      value: t.value == null ? '' : String(t.value),
      timestamp: new Date().toISOString(),
    };
    results.teams = await sendTeams({ webhook: rule.notify_teams_webhook, payload });
    if (!results.teams.ok && !results.teams.skipped) lg.warn('notify: teams send failed', { rule: rule.name, status: results.teams.status });
  }
  return { sent: true, results };
}

// ── THE PMR PRE-OPENING ALERT ───────────────────────────────────────────────
// ⚠️ THE SINGLE INTEGRATION POINT for the control plane's alerting. Everything the estate
// owner decided about this is expressed here, so there is one place to change it:
//
//   * IT GOES TO A SHARED SUPPORT INBOX, not to a per-rule recipient. `alert_rules` is
//     where recipients live for the fleet's threshold alerts, and its rows are per-RULE —
//     there is no per-pharmacy or per-customer recipient anywhere in this schema, and
//     `pharmacies` has no contact column at all. So this reads ONE address from config
//     (PMR_SUPPORT_INBOX) and that is deliberate rather than a gap left open.
//   * IT FIRES ONLY WHEN A COUNTER WILL NOT OPEN. Everything else waits for the morning
//     queue. The claim that makes it at-most-once per site per night is in the store
//     (recordPmrOpeningCheck stamps alerted_at in the same statement that records the
//     verdict), NOT here — a formatter cannot deduplicate across three worker processes.
//   * ONE EMAIL PER SITE, listing every counter at risk, because the person reading it goes
//     to the site once.
//
// dispatchAlert is NOT reused: its subject and body are hard-coded to the alert vocabulary
// ([Vigilant] SEVERITY OPENED/CLEARED — rule @ site) and it requires a `rule` object, which
// this has no equivalent of. The SENDERS are reused as-is, which is the part worth sharing.
//
// Fire-and-forget and never throws, exactly like dispatchAlert: a failed email must not
// break the worker pass that is still checking the rest of the estate.
//
// `site` = { site_code, site_name, next_open_at }
// `counters` = [{ label, reason }] — one entry per counter that will not open.
async function dispatchOpeningAlert(site, counters, { config, logger } = {}) {
  const lg = logger || log;
  const list = Array.isArray(counters) ? counters : [];
  // Nothing at risk is not an alert. The whole rule is "only when a counter will not open".
  if (!list.length) return { sent: false, skipped: 'nothing-at-risk' };

  const cfg = config || {};
  const to = cfg.pmrSupportInbox || '';
  if (!to) {
    // Said out loud, once per site, rather than silently dropped: an estate with no inbox
    // configured must not look like an estate with no problems. This is the log line that
    // tells an operator the integration point above has never been filled in.
    lg.warn('notify: a counter will not open, but PMR_SUPPORT_INBOX is unset — nobody was told', {
      site: site && site.site_code, counters: list.length,
    });
    return { sent: false, skipped: 'no-inbox' };
  }

  const where = (site && (site.site_name || site.site_code)) || 'site';
  const opensAt = site && site.next_open_at ? new Date(site.next_open_at).toISOString() : 'unknown';
  // The subject carries the site and the count, because it is read on a phone at 07:00 and
  // the decision it drives is "do I have to go there before they open".
  const subject = `[Vigilant] ${list.length} counter${list.length === 1 ? '' : 's'} may not open — ${where}`;
  const lines = [
    `${list.length} counter${list.length === 1 ? '' : 's'} at ${where} did not come back after the nightly restart.`,
    '',
    `Site:  ${site && site.site_code ? site.site_code : ''} ${where}`.trim(),
    `Opens: ${opensAt}`,
    '',
    'Counters:',
    ...list.map((c) => `  - ${c.label || 'counter'}: ${c.reason || 'did not report'}`),
    '',
    'This was raised before opening so it can be fixed in time. Nothing else about this',
    'site is being reported — everything that is not "a counter will not open" waits for',
    'the morning queue.',
    `When:  ${new Date().toISOString()}`,
  ];
  const text = lines.join('\n');

  const result = await sendEmail({
    apiKey: cfg.resendApiKey, from: cfg.alertEmailFrom, to, subject, text,
  });
  if (!result.ok && !result.skipped) {
    lg.warn('notify: pre-opening email send failed', { site: site && site.site_code, status: result.status });
  }
  // Teams is available (sendTeams above) and takes a flat payload, but no webhook is
  // configured for this path and inventing a second channel nobody asked for is not free.
  // If one is wanted later it goes HERE, next to the email, not in a new module.
  return { sent: !!result.ok, result };
}

module.exports = { sendEmail, sendTeams, dispatchAlert, dispatchOpeningAlert };
