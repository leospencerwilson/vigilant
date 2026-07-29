// Printer stats: HTTP end-to-end against a THROWAWAY database.
// The parts worth proving: a Pi can only write printers into ITS OWN pharmacy, the
// lifetime page counter never goes backwards, and identity typed by a human is not
// blanked out by a discovery report.
'use strict';
const http = require('node:http');
const { createServer } = require('/app/src/ingest/server.js');
const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');

const TOKEN = 'printer-test-token';
let fails = 0;
const check = (n, c, e) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${e !== undefined ? '  (' + e + ')' : ''}`); if (!c) fails++; };

function req(port, method, path, body, bearer = TOKEN) {
  return new Promise((resolve, reject) => {
    const p = body === undefined ? null : JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: {
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      ...(p ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(p) } : {}) } },
      (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (_) {} resolve({ s: res.statusCode, j }); }); });
    r.on('error', reject); if (p) r.write(p); r.end();
  });
}

(async () => {
  const pool = makePool(process.env.VIGILANT_DB_URL);
  const store = makePgStore(pool);
  await store.migrate();
  const cfg = { storeKind: 'pg', port: 0, enrollToken: TOKEN, defaultPollS: 30, fastPollS: 3, publicBaseUrl: 'http://vig.test' };
  const server = createServer({ store, config: cfg });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // two pharmacies, each with a counter + enrolled Pi
  const mk = async (code, idx) => {
    const ph = (await req(port, 'POST', '/pharmacies', { code, idx, name: `${code} site` })).j.pharmacy;
    const c = (await req(port, 'POST', '/counters', { pharmacy_id: ph.id, n: 1 })).j.counter;
    const e = (await req(port, 'POST', `/counters/${c.id}/enrol-pi`, {})).j;
    return { ph, c, token: e.token };
  };
  const A = await mk('AAA111', 1);
  const B = await mk('BBB222', 2);

  // ── the Pi reports what it polled on its site LAN
  let r = await req(port, 'POST', '/printers/report', { printers: [{
    name: 'brother-counter', address: '192.168.1.50', make: 'Brother', model: 'HL-L2350DW',
    discovered_via: 'snmp', status: 'idle', page_count: 12000, queue_depth: 0, jobs_failed: 0,
    supplies: [{ name: 'Black Toner', type: 'toner', level: 1200, max_capacity: 3000, pct: 40 },
               { name: 'Drum', type: 'opc', level: 8000, max_capacity: 12000, pct: 66.7 }],
  }] }, A.token);
  check('Pi reports printers with its own token → 200', r.s === 200 && r.j.printers === 1, JSON.stringify(r.j));

  r = await req(port, 'GET', '/printers');
  let p = (r.j.printers || [])[0];
  check('printer stored against the Pi\'s pharmacy', p && p.pharmacy_code === 'AAA111', p && p.pharmacy_code);
  check('supplies retained with raw level + max', p && p.supplies.length === 2 && p.supplies[0].max_capacity === 3000);
  // min_supply_pct is what a human actually reacts to — lowest consumable, not an average.
  check('min_supply_pct derived from the lowest consumable', p && Number(p.min_supply_pct) === 40, p && p.min_supply_pct);
  check('fresh report is not stale', p && p.stale === false);
  check('reported_by records which Pi polled it', p && !!p.reported_by);

  // ── a Pi must not be able to write into another site
  r = await req(port, 'POST', '/printers/report', { printers: [{ name: 'intruder' }] }, B.token);
  check('second Pi writes into ITS OWN pharmacy only', r.s === 200);
  r = await req(port, 'GET', '/printers');
  const intruder = (r.j.printers || []).find((x) => x.name === 'intruder');
  check('the other site\'s printer landed under BBB222, not AAA111', intruder && intruder.pharmacy_code === 'BBB222', intruder && intruder.pharmacy_code);
  check('AAA111 still has exactly one printer', (r.j.printers || []).filter((x) => x.pharmacy_code === 'AAA111').length === 1);

  // ── unlinked device cannot report (its pharmacy is unknowable)
  const lone = (await req(port, 'POST', '/enroll', { serial: 'LONE-ROUTER' })).j;
  r = await req(port, 'POST', '/printers/report', { printers: [{ name: 'x' }] }, lone.token);
  check('device not linked to a counter → 409', r.s === 409, `got ${r.s}: ${r.j && r.j.error}`);

  // ── page count must never go backwards (failed read / swapped unit)
  await req(port, 'POST', '/printers/report', { printers: [{ name: 'brother-counter', page_count: 12500 }] }, A.token);
  r = await req(port, 'GET', '/printers');
  p = (r.j.printers || []).find((x) => x.name === 'brother-counter');
  check('page count advances', Number(p.page_count) === 12500, p.page_count);
  await req(port, 'POST', '/printers/report', { printers: [{ name: 'brother-counter', page_count: 3 }] }, A.token);
  r = await req(port, 'GET', '/printers');
  p = (r.j.printers || []).find((x) => x.name === 'brother-counter');
  check('a LOWER page count is ignored, not taken', Number(p.page_count) === 12500, p.page_count);

  // ── a discovery report must not blank out operator-set identity
  await req(port, 'POST', '/printers', { pharmacy_id: A.ph.id, name: 'brother-counter', model: 'HL-L2350DW (dispensary)', counter_id: A.c.id, notes: 'behind the counter' });
  await req(port, 'POST', '/printers/report', { printers: [{ name: 'brother-counter', status: 'printing' }] }, A.token);
  r = await req(port, 'GET', '/printers');
  p = (r.j.printers || []).find((x) => x.name === 'brother-counter');
  check('operator model survives a later report', p.model === 'HL-L2350DW (dispensary)', p.model);
  check('operator notes survive', p.notes === 'behind the counter', p.notes);
  check('counter link survives', p.counter_id === A.c.id);
  check('observed status IS refreshed', p.status === 'printing', p.status);

  // ── validation + cleanup
  r = await req(port, 'POST', '/printers', { pharmacy_id: A.ph.id, name: 'bad', discovered_via: 'telepathy' });
  check('invalid discovered_via → 400', r.s === 400, `got ${r.s}`);
  r = await req(port, 'DELETE', `/printers/${p.id}`);
  check('delete printer → 200', r.s === 200);
  // deleting the pharmacy takes its printers with it
  await req(port, 'POST', '/printers/report', { printers: [{ name: 'temp' }] }, A.token);
  await req(port, 'POST', `/pharmacies/${A.ph.id}`.replace('/pharmacies/', '/pharmacies/'), undefined); // no-op guard
  r = await req(port, 'DELETE', `/pharmacies/${A.ph.id}`);
  check('delete pharmacy → 200', r.s === 200);
  r = await req(port, 'GET', '/printers');
  check('printers cascade with the pharmacy', !(r.j.printers || []).some((x) => x.pharmacy_code === 'AAA111'), JSON.stringify((r.j.printers || []).map((x) => x.pharmacy_code)));

  await new Promise((x) => server.close(x));
  await pool.end();
  console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL PRINTER CHECKS PASSED');
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('\nTEST ERROR:', e.message, '\n', e.stack); process.exit(2); });
