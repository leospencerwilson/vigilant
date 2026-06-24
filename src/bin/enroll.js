#!/usr/bin/env node
'use strict';

// node src/bin/enroll.js --serial HGT0A023T6C --site "Allied Huddersfield" \
//     --customer Allied --wan-type pppoe --tags allied,pharmacy
//
// Creates a device row, mints a per-device bearer token, stores ONLY its sha256
// hash, and prints the plaintext token + a ready-to-paste RouterOS bootstrap
// snippet exactly ONCE. The plaintext is never persisted or logged.

const crypto = require('crypto');
const config = require('../shared/config');
const log = require('../shared/log');
const { makeStore } = require('../shared/store');

// wan_type is constrained by the schema CHECK; map a couple of friendly aliases.
const WAN_TYPES = ['pppoe', 'sim', 'dhcp', 'static', 'unknown'];
const WAN_ALIASES = { lte: 'sim', '4g': 'sim', '5g': 'sim', sim: 'sim' };

function parseArgs(argv) {
  // Supports `--flag value` and `--flag=value`.
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    let key = a.slice(2);
    let val;
    const eq = key.indexOf('=');
    if (eq !== -1) {
      val = key.slice(eq + 1);
      key = key.slice(0, eq);
    } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
      val = argv[++i];
    } else {
      val = true; // bare boolean flag
    }
    out[key] = val;
  }
  return out;
}

function usage() {
  return [
    'Usage: node src/bin/enroll.js --serial <serial> --site <site name> \\',
    '         --customer <customer> --wan-type <pppoe|sim|dhcp|static|unknown> [--tags a,b,c]',
  ].join('\n');
}

// sha256 hex of the bearer — identical scheme to the ingest token lookup, so the
// device's plaintext bearer hashes to this value on every /telemetry request.
function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// Build the RouterOS snippet the operator pastes once at enrolment. Fills in the
// two globals the agent/bootstrap scripts expect.
function bootstrapSnippet(publicBaseUrl, token) {
  return [
    '# Vigilant enrolment — paste ONCE on this device (RouterOS 7.x). REVIEW before applying.',
    '# Sets the two globals the vigilant-agent / vigilant-bootstrap scripts read.',
    `:global vigilantUrl   "${publicBaseUrl}"`,
    `:global vigilantToken "${token}"`,
    '# Persist the globals across reboot so the scheduler can read them:',
    '/system script add name=vigilant-env dont-require-permissions=no \\',
    `    source=":global vigilantUrl \\"${publicBaseUrl}\\"; :global vigilantToken \\"${token}\\""`,
    '/system scheduler add name=vigilant-env start-time=startup \\',
    '    on-event="/system script run vigilant-env" comment="Vigilant: load enrolment globals at boot"',
    '# Then run the daily self-update bootstrap (see agent/bootstrap.rsc) to pull the current agent.',
  ].join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const serial = args.serial != null && args.serial !== true ? String(args.serial).trim() : '';
  const siteName = args.site != null && args.site !== true ? String(args.site) : null;
  const customer = args.customer != null && args.customer !== true ? String(args.customer) : null;

  let wanType = args['wan-type'] != null && args['wan-type'] !== true
    ? String(args['wan-type']).toLowerCase().trim()
    : 'unknown';
  if (WAN_ALIASES[wanType]) wanType = WAN_ALIASES[wanType];
  if (!WAN_TYPES.includes(wanType)) {
    throw new Error(`invalid --wan-type "${wanType}"; expected one of ${WAN_TYPES.join(', ')}`);
  }

  const tags = args.tags != null && args.tags !== true
    ? String(args.tags)
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
    : [];

  if (!serial) {
    throw new Error(`--serial is required\n\n${usage()}`);
  }

  const store = makeStore('pg', config);

  // Create the device first so we have its id to attach the token to.
  const device = await store.createDevice({
    serial,
    site_name: siteName,
    customer,
    wan_type: wanType,
    tags,
  });

  // Mint the bearer: 32 random bytes -> 64 hex chars. Store ONLY the hash.
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = sha256Hex(token);
  await store.setDeviceToken(device.id, tokenHash);

  // Release the pool so the process can exit cleanly. The pg store exposes end();
  // tolerate close() too for forward-compat.
  if (typeof store.end === 'function') {
    await store.end();
  } else if (typeof store.close === 'function') {
    await store.close();
  }

  // Log the enrolment WITHOUT the secret.
  log.info('enroll: device enrolled', {
    serial,
    deviceId: device.id,
    site: siteName,
    customer,
    wan_type: wanType,
    tags,
  });

  // Print the plaintext token + paste snippet ONCE, to stdout, never to the log.
  const snippet = bootstrapSnippet(config.publicBaseUrl, token);
  process.stdout.write(
    [
      '',
      '============================================================',
      ` Device enrolled: ${serial}  (id ${device.id})`,
      '============================================================',
      '',
      ' Per-device bearer token (shown ONCE — store it now, it is not recoverable):',
      '',
      `   ${token}`,
      '',
      ' ---- RouterOS bootstrap (paste once on the device) ----',
      '',
      snippet,
      '',
      '============================================================',
      '',
    ].join('\n')
  );
}

main().then(
  () => process.exit(0),
  (err) => {
    log.error('enroll: failed', { error: err && err.message ? err.message : String(err) });
    process.exit(1);
  }
);
