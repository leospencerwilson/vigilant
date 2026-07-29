// End-to-end HTTP test for the PMR virtual-desktop API against a THROWAWAY database.
// The interesting parts: derived addressing, the immutability of idx/n, and the Pi
// enrolment flow that turns a counter into a real Vigilant device.
'use strict';

const http = require('node:http');
const { createServer } = require('/app/src/ingest/server.js');
const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');

const TOKEN = 'pmr-test-token';
let fails = 0;
const check = (name, cond, extra) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  (' + extra + ')' : ''}`);
  if (!cond) fails++;
};

function req(port, method, path, body, auth = true) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: {
      ...(auth ? { authorization: `Bearer ${TOKEN}` } : {}),
      ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
    } }, (res) => {
      let d = ''; res.on('data', (c) => (d += c));
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (_) {} resolve({ status: res.statusCode, body: j }); });
    });
    r.on('error', reject); if (payload) r.write(payload); r.end();
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

  // ── auth
  let r = await req(port, 'GET', '/pharmacies', undefined, false);
  check('GET /pharmacies unauthenticated → 401', r.status === 401, `got ${r.status}`);

  // ── create the real pilot pharmacy: RX54554, index 1
  r = await req(port, 'POST', '/pharmacies', { code: 'rx54554', idx: 1, name: 'RX54554 (pilot)', pmr_system: 'proscript', status: 'building', proxmox_node: 'temeraire', srv_vmid: 301 });
  check('create pharmacy → 201', r.status === 201, `got ${r.status}: ${r.body && r.body.error}`);
  const ph = r.body && r.body.pharmacy;
  check('code is upper-cased', ph && ph.code === 'RX54554', ph && ph.code);
  // The whole point of the generated columns — these must match the documented estate.
  check('derived vlan = 101', ph && ph.vlan === 101, ph && ph.vlan);
  check('derived subnet = 10.1.0.0/24', ph && ph.subnet === '10.1.0.0/24', ph && ph.subnet);
  check('derived gateway = 10.1.0.1', ph && ph.gateway_ip === '10.1.0.1', ph && ph.gateway_ip);
  check('derived PMR server = 10.1.0.10', ph && ph.server_ip === '10.1.0.10', ph && ph.server_ip);
  check('derived DHCP pool = .100–.149', ph && ph.dhcp_from === '10.1.0.100' && ph.dhcp_to === '10.1.0.149', ph && `${ph.dhcp_from}-${ph.dhcp_to}`);

  // ── uniqueness + validation
  r = await req(port, 'POST', '/pharmacies', { code: 'OTHER', idx: 1, name: 'Clashing index' });
  check('duplicate idx → 409', r.status === 409, `got ${r.status}`);
  r = await req(port, 'POST', '/pharmacies', { code: 'RX54554', idx: 2, name: 'Clashing code' });
  check('duplicate code → 409', r.status === 409, `got ${r.status}`);
  r = await req(port, 'POST', '/pharmacies', { code: 'BAD', idx: 999, name: 'Out of range' });
  check('idx out of range → 400 (not a 500 from the CHECK)', r.status === 400, `got ${r.status}`);
  r = await req(port, 'PATCH', `/pharmacies/${ph.id}`, { idx: 5 });
  check('idx is immutable → 400', r.status === 400, r.body && r.body.error);

  // ── counter 2 (there is no counter 1 at this site — the octet tracks the counter no.)
  r = await req(port, 'POST', '/counters', { pharmacy_id: ph.id, n: 2, label: 'Counter 2', status: 'building', vmid: 302, vm_hostname: 'pmr-rx54554-cl02', peripherals: { smartcard: 'untested' } });
  check('create counter → 201', r.status === 201, `got ${r.status}: ${r.body && r.body.error}`);
  const c = r.body && r.body.counter;
  check('derived VM ip = 10.1.0.22 (20 + n)', c && c.vm_ip === '10.1.0.22', c && c.vm_ip);
  check('derived Pi tunnel = 10.255.1.2/32', c && c.pi_tunnel_ip === '10.255.1.2/32', c && c.pi_tunnel_ip);
  check('peripherals stored', c && c.peripherals && c.peripherals.smartcard === 'untested', JSON.stringify(c && c.peripherals));
  r = await req(port, 'POST', '/counters', { pharmacy_id: ph.id, n: 2, label: 'dupe' });
  check('duplicate counter n → 409', r.status === 409, `got ${r.status}`);
  r = await req(port, 'PATCH', `/counters/${c.id}`, { n: 3 });
  check('counter n is immutable → 400', r.status === 400, r.body && r.body.error);
  r = await req(port, 'POST', '/counters', { pharmacy_id: 999999, n: 1 });
  check('unknown pharmacy_id → 400', r.status === 400, `got ${r.status}`);

  // ── enrol the Pi: becomes a Vigilant device and gets a bearer token
  r = await req(port, 'POST', `/counters/${c.id}/enrol-pi`, { pi_hostname: 'pi-rx54554-2', pi_model: 'Raspberry Pi 5', pi_public_key: 'TESTKEY123=' });
  check('enrol Pi → 201', r.status === 201, `got ${r.status}: ${r.body && r.body.error}`);
  const enrol = r.body || {};
  check('token returned once', typeof enrol.token === 'string' && enrol.token.length === 64, enrol.token && enrol.token.length);
  check('device created with kind=counter-pi', enrol.device && enrol.device.kind === 'counter-pi', JSON.stringify(enrol.device));
  check('device serial defaults from the site', enrol.device && enrol.device.serial === 'PI-RX54554-2', enrol.device && enrol.device.serial);
  check('counter now linked to the device', enrol.counter && enrol.counter.pi_device_id === enrol.device.id);
  check('telemetry url handed back', enrol.telemetry_url === 'http://vig.test/telemetry', enrol.telemetry_url);
  r = await req(port, 'POST', `/counters/${c.id}/enrol-pi`, {});
  check('re-enrol without replace → 409 (would strand the old token)', r.status === 409, `got ${r.status}`);

  // the Pi must be a first-class device: auto-tagged, and visible in the fleet
  r = await req(port, 'GET', '/tags');
  const piTag = (r.body.tags || []).find((t) => t.tag === 'counter-pi');
  check('Pi auto-tagged counter-pi', !!piTag && piTag.devices === 1, JSON.stringify(piTag));
  // and a smart tag can group the Pi fleet by kind
  r = await req(port, 'POST', '/tag-rules/preview', { conditions: { all: [{ field: 'kind', op: 'eq', value: 'counter-pi' }] } });
  check('smart tag can match on kind=counter-pi', r.status === 200 && r.body.count === 1, `count=${r.body && r.body.count}`);

  // ── the Pi can actually authenticate and post telemetry, like a router
  const piPost = await new Promise((resolve) => {
    const payload = JSON.stringify({ serial: 'PI-RX54554-2', identity: 'pi-rx54554-2', uptime: '1d2h', cpu_load: '4' });
    const rq = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/telemetry', headers: {
      authorization: `Bearer ${enrol.token}`, 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } },
      (res) => { let d = ''; res.on('data', (x) => (d += x)); res.on('end', () => resolve({ status: res.statusCode, d })); });
    rq.on('error', () => resolve({ status: 0, d: '' })); rq.write(payload); rq.end();
  });
  check('Pi posts telemetry with its token → 200', piPost.status === 200, `got ${piPost.status}: ${piPost.d.slice(0, 90)}`);

  // ── observed WireGuard state
  r = await req(port, 'POST', '/wg-peers/report', { peers: [
    { public_key: 'TESTKEY123=', allowed_ips: '10.255.1.2/32', endpoint: '1.2.3.4:51820', latest_handshake: Math.floor(Date.now() / 1000), rx_bytes: 100, tx_bytes: 200 },
    { public_key: 'UNKNOWNKEY=', allowed_ips: '10.255.0.10/32', endpoint: '5.6.7.8:51820', latest_handshake: Math.floor(Date.now() / 1000), rx_bytes: 5, tx_bytes: 6 },
  ] });
  check('wg report → 200, 2 peers', r.status === 200 && r.body.peers === 2, JSON.stringify(r.body));
  r = await req(port, 'GET', '/wg-peers');
  const peers = r.body.peers || [];
  const known = peers.find((x) => x.public_key === 'TESTKEY123=');
  const unknown = peers.find((x) => x.public_key === 'UNKNOWNKEY=');
  check('registered peer joins to its counter', known && known.counter_id === c.id && known.pharmacy_code === 'RX54554', JSON.stringify(known && { c: known.counter_id, p: known.pharmacy_code }));
  check('UNREGISTERED peer still listed (unknown Pi on the VPN)', unknown && unknown.counter_id === null, JSON.stringify(unknown && { c: unknown.counter_id }));
  check('peers marked online from a fresh handshake', known && known.online === true);

  // counters_v surfaces tunnel state and agent state as separate facts
  r = await req(port, 'GET', `/pharmacies/RX54554`);
  const cv = (r.body.counters || [])[0];
  check('lookup pharmacy by CODE works', r.status === 200 && r.body.pharmacy.code === 'RX54554');
  check('counter shows tunnel up', cv && cv.pi_tunnel_up === true, cv && String(cv.pi_tunnel_up));
  check('counter also shows the Pi agent status separately', cv && cv.pi_agent_status !== undefined, cv && String(cv.pi_agent_status));

  // ── cascade + orphan behaviour
  r = await req(port, 'DELETE', `/pharmacies/${ph.id}`);
  check('delete pharmacy → 200', r.status === 200);
  r = await req(port, 'GET', '/counters');
  check('counters cascade-deleted with the pharmacy', (r.body.counters || []).length === 0, `${(r.body.counters || []).length} left`);
  const dev = await store.getDeviceBySerial('PI-RX54554-2');
  check("the Pi's device row SURVIVES (hardware still exists)", !!dev, dev && dev.serial);

  await new Promise((x) => server.close(x));
  await pool.end();
  console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL PMR CHECKS PASSED');
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('\nTEST ERROR:', e.message, '\n', e.stack); process.exit(2); });
