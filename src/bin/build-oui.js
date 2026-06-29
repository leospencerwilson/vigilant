#!/usr/bin/env node
'use strict';

// Build src/shared/oui-db.json from the IEEE OUI registry. Run where there IS outbound
// internet (a dev box or the Docker build):
//
//     npm run build:oui
//
// The output ({ "AC:CF:23": "Yealink Inc.", … }) is loaded by src/shared/oui.js and gives
// the ingest OFFLINE, near-complete vendor coverage — so MAC→vendor no longer depends on the
// rate-limited public api.macvendors.com. If this never runs, oui.js falls back to the small
// hand-curated SEED (no crash).
//
// Source: the IEEE registry TEXT file (oui.txt). Each assignment has a line like:
//     00-22-72   (hex)		American Micro-Fuel Device Corp.
// We parse exactly those "(hex)" lines: 3 hyphen-separated octets, "(hex)", then the vendor.

const fs = require('node:fs');
const path = require('node:path');

const SOURCE = process.env.OUI_URL || 'https://standards-oui.ieee.org/oui/oui.txt';

// Match a "(hex)" assignment line → [ouiKey, vendor], or null. Separator between fields is
// whitespace (spaces then tabs); vendor is the trailing free text.
const HEX_LINE = /^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$/;

function parseLine(line) {
  const m = HEX_LINE.exec(line);
  if (!m) return null;
  const key = (m[1] + ':' + m[2] + ':' + m[3]).toUpperCase();
  const vendor = m[4].trim();
  if (!vendor) return null;
  return [key, vendor];
}

async function main() {
  if (typeof fetch !== 'function') {
    console.error('build-oui: needs Node 20+ with a global fetch');
    process.exit(1);
  }
  process.stdout.write(`build-oui: fetching ${SOURCE} …\n`);
  // IEEE returns 403 to requests without a browser-ish User-Agent — set one explicitly.
  const res = await fetch(SOURCE, {
    headers: { 'User-Agent': 'Mozilla/5.0 (vigilant-oui-build)', Accept: 'text/plain,*/*' },
  });
  if (!res.ok) {
    console.error(`build-oui: fetch failed (HTTP ${res.status})`);
    process.exit(1);
  }
  const txt = await res.text();

  const out = {};
  for (const line of txt.split(/\r?\n/)) {
    const parsed = parseLine(line);
    if (!parsed) continue;
    out[parsed[0]] = parsed[1]; // last write wins (entries are unique anyway)
  }

  const count = Object.keys(out).length;
  // Sanity gate: the real registry has ~35k assignments. A tiny count means the format moved
  // and our parse is wrong — fail rather than ship a near-empty DB that looks "fixed".
  if (count < 10000) {
    console.error(`build-oui: parsed only ${count} OUIs — aborting (oui.txt format changed?)`);
    process.exit(1);
  }

  const dest = path.join(__dirname, '..', 'shared', 'oui-db.json');
  fs.writeFileSync(dest, JSON.stringify(out));
  process.stdout.write(`build-oui: wrote ${count} OUIs -> ${dest}\n`);
}

main().catch((e) => {
  console.error(`build-oui: ${e && e.message ? e.message : String(e)}`);
  process.exit(1);
});
