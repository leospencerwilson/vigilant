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

// Send a Microsoft Teams message via an incoming webhook (legacy MessageCard — widely
// supported by the classic "Incoming Webhook" connector). `themeColor` tints the card.
async function sendTeams({ webhook, title, text, themeColor }) {
  if (!webhook) return { ok: false, skipped: true };
  const card = {
    '@type': 'MessageCard',
    '@context': 'https://schema.org/extensions',
    themeColor: themeColor || '0078D7',
    summary: title || 'Vigilant alert',
    title: title || 'Vigilant alert',
    text: text || '',
  };
  return post(webhook, { 'content-type': 'application/json' }, JSON.stringify(card));
}

// Map alert severity → a Teams card colour.
function severityColor(sev) {
  if (sev === 'critical') return 'D13438';
  if (sev === 'warning') return 'F2A900';
  return '0078D7';
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
    results.teams = await sendTeams({
      webhook: rule.notify_teams_webhook, title: subject,
      text: text.replace(/\n/g, '  \n'), themeColor: severityColor(rule.severity),
    });
    if (!results.teams.ok && !results.teams.skipped) lg.warn('notify: teams send failed', { rule: rule.name, status: results.teams.status });
  }
  return { sent: true, results };
}

module.exports = { sendEmail, sendTeams, dispatchAlert, severityColor };
