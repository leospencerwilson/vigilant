// Validation for DELETE /devices/:serial (handlers.deviceDelete + store.deleteDevice).
// Runs against a THROWAWAY database (never the live one) — the caller passes
// VIGILANT_DB_URL pointing at it. Proves: 404 unknown; 409 online-without-force
// (device untouched); force delete cascades and writes a surviving audit row;
// offline and never-reported devices delete without force; actor falls back to
// 'watchman' when the UI does not say who asked.
'use strict';

const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');
const handlers = require('/app/src/ingest/handlers.js');

const URL = process.env.VIGILANT_DB_URL;
let failures = 0;
function check(name, cond, extra) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  (' + extra + ')' : ''}`);
  if (!cond) failures++;
}

function fakeRes() {
  const r = { code: null, json: null };
  r.writeHead = (c) => { r.code = c; };
  r.end = (buf) => { r.json = buf && buf.length ? JSON.parse(buf.toString()) : null; };
  return r;
}

async function callDelete(store, serial, body) {
  const res = fakeRes();
  await handlers.deviceDelete({
    res, store,
    params: { serial },
    body: body == null ? '' : JSON.stringify(body),
  });
  return res;
}

(async () => {
  const pool = makePool(URL);
  const store = makePgStore(pool);

  console.log('-- applying schema --');
  if (!process.env.SKIP_MIGRATE) await store.migrate();

  // 404 on unknown serial
  let r = await callDelete(store, 'NOSUCHSERIAL', { by: 'test-op' });
  check('unknown serial -> 404', r.code === 404, 'code=' + r.code);

  // online device without force -> 409, device untouched
  const dev = await store.createDevice({ serial: 'DELTEST01', site_name: 'del test', identity: 'DelTest' });
  await pool.query(
    `INSERT INTO device_state (device_id, status, last_seen_at) VALUES ($1, 'online', now())`, [dev.id]);
  await store.upsertInterfaceStates(dev.id, [{ name: 'ether1', rx_bps: 1 }, { name: 'ether2', rx_bps: 2 }]);
  r = await callDelete(store, 'DELTEST01', { by: 'test-op' });
  check('online without force -> 409', r.code === 409, 'code=' + r.code);
  let n = (await pool.query(`SELECT count(*)::int n FROM devices WHERE serial='DELTEST01'`)).rows[0].n;
  check('409 leaves the device in place', n === 1, 'rows=' + n);

  // online WITH force -> 200, cascade, audit row survives
  r = await callDelete(store, 'DELTEST01', { by: 'test-op', force: true });
  check('online with force -> 200 deleted', r.code === 200 && r.json && r.json.deleted === true, 'code=' + r.code);
  n = (await pool.query(`SELECT count(*)::int n FROM devices WHERE serial='DELTEST01'`)).rows[0].n;
  check('device row gone', n === 0, 'rows=' + n);
  n = (await pool.query(`SELECT count(*)::int n FROM interface_state WHERE device_id=$1`, [dev.id])).rows[0].n;
  check('interface_state cascaded', n === 0, 'rows=' + n);
  n = (await pool.query(`SELECT count(*)::int n FROM device_state WHERE device_id=$1`, [dev.id])).rows[0].n;
  check('device_state cascaded', n === 0, 'rows=' + n);
  const audit = (await pool.query(
    `SELECT actor, action, details FROM audit_log WHERE serial='DELTEST01' AND action='device.delete'`)).rows;
  check('audit row written and survives the delete', audit.length === 1 && audit[0].actor === 'test-op',
    JSON.stringify(audit[0] || null));
  check('audit details record the force', audit.length === 1 && /forced=true/.test(audit[0].details || ''),
    audit[0] && audit[0].details);

  // offline device deletes without force
  const dev2 = await store.createDevice({ serial: 'DELTEST02', site_name: 'del test 2' });
  await pool.query(
    `INSERT INTO device_state (device_id, status, last_seen_at) VALUES ($1, 'offline', now())`, [dev2.id]);
  r = await callDelete(store, 'DELTEST02', { by: 'test-op' });
  check('offline without force -> 200 deleted', r.code === 200 && r.json && r.json.deleted === true, 'code=' + r.code);

  // never-reported device (no device_state row) deletes without force; actor falls back
  await store.createDevice({ serial: 'DELTEST03' });
  r = await callDelete(store, 'DELTEST03', {});
  check('never-reported device deletes without force', r.code === 200, 'code=' + r.code);
  const a3 = (await pool.query(`SELECT actor FROM audit_log WHERE serial='DELTEST03'`)).rows[0];
  check("missing 'by' falls back to watchman", !!a3 && a3.actor === 'watchman', a3 && a3.actor);

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL PASS');
  await pool.end();
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
