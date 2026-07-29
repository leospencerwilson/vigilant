// Validation for the batched (multi-row) writes in store.pg.js.
// Runs against a THROWAWAY database (never the live one) — the caller passes
// VIGILANT_DB_URL pointing at it. Proves the three things the rewrite could break:
//   1. intra-batch ON CONFLICT dedupe  (a multi-row upsert must not touch a row twice)
//   2. chunking past Postgres's 65535 bound-parameter ceiling
//   3. upsert semantics unchanged (second write updates, doesn't duplicate)
'use strict';

const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');

const URL = process.env.VIGILANT_DB_URL;
let failures = 0;
function check(name, cond, extra) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  (' + extra + ')' : ''}`);
  if (!cond) failures++;
}

(async () => {
  const pool = makePool(URL);
  const store = makePgStore(pool);

  console.log('-- applying schema --');
  await store.migrate();

  const dev = await store.createDevice({ serial: 'BATCHTEST01', site_name: 'batch test' });
  const id = dev.id;
  console.log('-- device', id, '--');

  const cnt = async (t, where) =>
    (await pool.query(`SELECT count(*)::int n FROM ${t} WHERE device_id=$1 ${where || ''}`, [id])).rows[0].n;

  // ---- 1. interface_state: duplicate conflict key (same name twice) in ONE batch
  await store.upsertInterfaceStates(id, [
    { name: 'ether1', rx_bps: 1, comment: 'first' },
    { name: 'ether2', rx_bps: 2 },
    { name: 'ether1', rx_bps: 999, comment: 'last-wins' }, // duplicate PK within the batch
  ]);
  check('interface_state dedupes duplicate name in one batch', (await cnt('interface_state')) === 2, 'rows=' + (await cnt('interface_state')));
  const e1 = (await pool.query('SELECT rx_bps, comment FROM interface_state WHERE device_id=$1 AND name=$2', [id, 'ether1'])).rows[0];
  check('interface_state last-wins on intra-batch dupe', String(e1.rx_bps) === '999' && e1.comment === 'last-wins', `rx_bps=${e1.rx_bps} comment=${e1.comment}`);

  // ---- upsert on a SECOND call must update, not duplicate
  await store.upsertInterfaceStates(id, [{ name: 'ether1', rx_bps: 5 }]);
  check('interface_state re-upsert updates in place', (await cnt('interface_state')) === 2, 'rows=' + (await cnt('interface_state')));

  // ---- 2. mac_hosts: the big one. dupes + volume past the param ceiling.
  // 7 params/row -> chunk size 9285, so 12000 rows forces >1 chunk.
  // NB: the mac columns are Postgres `macaddr`, so these must be real MACs.
  const hx = (n) => n.toString(16).padStart(2, '0');
  const mac = (i) => `02:00:00:00:${hx((i >> 8) & 0xff)}:${hx(i & 0xff)}`;
  const macs = [];
  for (let i = 0; i < 12000; i++) {
    macs.push({ interface: 'bridge', mac: mac(i), ip: '10.0.0.1', hostname: 'h' + i });
  }
  macs.push({ interface: 'bridge', mac: mac(0), ip: '10.9.9.9', hostname: 'dupe-last-wins' });
  const t0 = Date.now();
  await store.upsertMacHosts(id, macs);
  const ms = Date.now() - t0;
  check('mac_hosts 12000 rows inserted across chunks', (await cnt('mac_hosts')) === 12000, 'rows=' + (await cnt('mac_hosts')) + ` in ${ms}ms`);
  const m0 = (await pool.query('SELECT ip, hostname FROM mac_hosts WHERE device_id=$1 AND mac=$2', [id, mac(0)])).rows[0];
  check('mac_hosts intra-batch dupe collapsed, last wins', m0.hostname === 'dupe-last-wins', 'hostname=' + m0.hostname);

  // ---- 3. neighbors: rows missing interface/mac must be skipped (as before)
  await store.upsertNeighbors(id, [
    { interface: 'ether1', mac: '02:00:00:aa:00:01', identity: 'n1' },
    { interface: null, mac: '02:00:00:aa:00:02' }, // skipped
    { mac: null, interface: 'ether1' }, // skipped
    { interface: 'ether1', mac: '02:00:00:aa:00:01', identity: 'n1-updated' }, // dupe
  ]);
  check('neighbors skips invalid + dedupes', (await cnt('neighbors')) === 1, 'rows=' + (await cnt('neighbors')));
  const nb = (await pool.query('SELECT identity FROM neighbors WHERE device_id=$1', [id])).rows[0];
  check('neighbors last-wins', nb.identity === 'n1-updated', 'identity=' + nb.identity);

  // ---- 4. interface_history: conflict key is (device_id,name,ts)
  const ts = new Date(Date.UTC(2026, 0, 1, 12, 0, 0)).toISOString();
  await store.appendInterfaceHistory(id, ts, [
    { name: 'ether1', rx_bps: 10, tx_bps: 20 },
    { name: 'ether2', rx_bps: 30, tx_bps: 40 },
    { name: 'ether1', rx_bps: 111, tx_bps: 222 }, // dupe within batch
  ]);
  check('interface_history dedupes name within one ts', (await cnt('interface_history')) === 2, 'rows=' + (await cnt('interface_history')));
  const h = (await pool.query('SELECT rx_bps FROM interface_history WHERE device_id=$1 AND name=$2', [id, 'ether1'])).rows[0];
  check('interface_history last-wins', String(h.rx_bps) === '111', 'rx_bps=' + h.rx_bps);

  // ---- 5. full-snapshot tables: DELETE-then-insert must still replace the set
  await store.upsertWirelessClients(id, [
    { interface: 'wlan1', mac: '02:00:00:bb:00:01', signal: -50 },
    { interface: 'wlan1', mac: '02:00:00:bb:00:02', signal: -60 },
    { interface: 'wlan1', mac: '02:00:00:bb:00:01', signal: -70 }, // dupe
  ]);
  check('wireless_clients dedupes', (await cnt('wireless_clients')) === 2, 'rows=' + (await cnt('wireless_clients')));
  await store.upsertWirelessClients(id, [{ interface: 'wlan1', mac: '02:00:00:bb:00:03', signal: -55 }]);
  check('wireless_clients full-snapshot replaces set', (await cnt('wireless_clients')) === 1, 'rows=' + (await cnt('wireless_clients')));

  await store.upsertWifiNetworks(id, [
    { interface: 'wlan1', ssid: 'A' },
    { interface: 'wlan1', ssid: 'B' }, // dupe on (device,interface)
    { interface: 'wlan2', ssid: 'C' },
  ]);
  check('wifi_networks dedupes interface', (await cnt('wifi_networks')) === 2, 'rows=' + (await cnt('wifi_networks')));

  // ---- 6. device_logs: DO NOTHING + identical lines in one batch
  await store.appendDeviceLogs(id, [
    { time: '10:00:00', topics: 'info', message: 'one' },
    { time: '10:00:00', topics: 'info', message: 'one' }, // exact dupe
    { time: '10:00:01', topics: 'info', message: 'two' },
    { message: '' }, // skipped
  ]);
  check('device_logs dedupes identical lines', (await cnt('device_logs')) === 2, 'rows=' + (await cnt('device_logs')));

  // ---- 7. empty input must be a no-op, not a crash
  await store.upsertMacHosts(id, []);
  await store.upsertNeighbors(id, []);
  await store.appendInterfaceHistory(id, ts, []);
  await store.appendDeviceLogs(id, []);
  check('empty lists are no-ops', true);

  await pool.end();
  console.log(failures ? `\n${failures} CHECK(S) FAILED` : '\nALL CHECKS PASSED');
  process.exit(failures ? 1 : 0);
})().catch((e) => {
  console.error('\nTEST ERROR:', e.message);
  process.exit(2);
});
