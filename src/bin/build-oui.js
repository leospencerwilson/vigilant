#!/usr/bin/env node
'use strict';

// Build src/shared/oui-db.json from the IEEE OUI registry. Run where there IS outbound
// internet (a dev box or the Docker build):
//
//     npm run build:oui
//
// The output ({ "AC:CF:23": "Yealink Inc.", … }) is loaded by src/shared/oui.js and gives
// the ingest OFFLINE, near-complete vendor coverage — so MAC→vendor no longer depends on the
// rate-limited public api.macvendors.com (which is why coverage was ~5%). If this never runs,
// oui.js falls back to the small hand-curated SEED (no crash).
//
// Source: the IEEE "MA-L" registry CSV (one assignment per /24 OUI block). Columns:
//   Registry,Assignment,Organization Name,Organization Address
// Assignment is bare 6-hex (e.g. "AccF23"); Organization Name is quoted and may contain
// commas and ""-escaped quotes — so we parse fields rather than naive comma-splitting.

const fs = require('node:fs');
const path = require('node:path');

const SOURCE = process.env.OUI_CSV_URL || 'https://standards-oui.ieee.org/oui/oui.csv';

// Parse one CSV line: return [registry, assignment, organizationName] or null.
function parseLine(line) {
  const c1 = line.indexOf(',');
  if (c1 < 0) return null;
  const c2 = line.indexOf(',', c1 + 1);
  if (c2 < 0) return null;
  const registry = line.slice(0, c1).trim();
  const assignment = line.slice(c1 + 1, c2).trim();
  const rest = line.slice(c2 + 1);
  let name;
  if (rest[0] === '"') {
    // Quoted field: consume until an unescaped closing quote ("" is a literal quote).
    let buf = '';
    let j = 1;
    while (j < rest.length) {
      const ch = rest[j];
      if (ch === '"') {
        if (rest[j + 1] === '"') { buf += '"'; j += 2; continue; }
        break;
      }
      buf += ch;
      j += 1;
    }
    name = buf;
  } else {
    const c3 = rest.indexOf(',');
    name = c3 < 0 ? rest : rest.slice(0, c3);
  }
  return [registry, assignment, name.trim()];
}

async function main() {
  if (typeof fetch !== 'function') {
    console.error('build-oui: needs Node 20+ with a global fetch');
    process.exit(1);
  }
  process.stdout.write(`build-oui: fetching ${SOURCE} …\n`);
  const res = await fetch(SOURCE);
  if (!res.ok) {
    console.error(`build-oui: fetch failed (HTTP ${res.status})`);
    process.exit(1);
  }
  const csv = await res.text();
  const lines = csv.split(/\r?\n/);

  const out = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const parsed = parseLine(line);
    if (!parsed) continue;
    const [, assignment, name] = parsed;
    if (!/^[0-9A-Fa-f]{6}$/.test(assignment) || !name) continue;
    const hex = assignment.toUpperCase();
    const key = hex.slice(0, 2) + ':' + hex.slice(2, 4) + ':' + hex.slice(4, 6);
    out[key] = name;
  }

  const count = Object.keys(out).length;
  // Sanity gate: the real registry has ~35k assignments. A tiny count means the format moved
  // and our parse is wrong — fail rather than ship a near-empty DB that looks "fixed".
  if (count < 10000) {
    console.error(`build-oui: parsed only ${count} OUIs — aborting (CSV format changed?)`);
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
