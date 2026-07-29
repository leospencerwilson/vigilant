// End-to-end HTTP test for the tag / smart-tag routes: real requests through
// createServer() against a THROWAWAY database. Validates routing, admin auth,
// validation and status codes — the store logic is covered by test-tags.cjs.
'use strict';

const http = require('node:http');
const { createServer } = require('/app/src/ingest/server.js');
const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');

const TOKEN = 'route-test-token';
let fails = 0;
function check(name, cond, extra) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  (' + extra + ')' : ''}`);
  if (!cond) fails++;
}

function req(port, method, path, { body, auth = true } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const r = http.request(
      { host: '127.0.0.1', port, method, path,
        headers: {
          ...(auth ? { authorization: `Bearer ${TOKEN}` } : {}),
          ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
        } },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => {
          let j = null;
          try { j = JSON.parse(d); } catch (_) { /* non-json */ }
          resolve({ status: res.statusCode, body: j, raw: d });
        });
      }
    );
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

(async () => {
  const pool = makePool(process.env.VIGILANT_DB_URL);
  const store = makePgStore(pool);
  await store.migrate();
  await store.createDevice({ serial: 'R-ONE', site_name: 'Route One', customer: 'Allied', model: 'hAP ac2', ros_version: '7.9', wan_type: 'sim' });
  await store.createDevice({ serial: 'R-TWO', site_name: 'Route Two', customer: 'WCN', model: 'RB5009', ros_version: '7.20', wan_type: 'pppoe' });

  const cfg = { storeKind: 'pg', port: 0, enrollToken: TOKEN, defaultPollS: 30, fastPollS: 3, publicBaseUrl: 'http://test' };
  const server = createServer({ store, config: cfg });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  console.log('-- server on', port, '--');

  // ── auth is enforced
  let r = await req(port, 'GET', '/tags', { auth: false });
  check('GET /tags without auth → 401', r.status === 401, `got ${r.status}`);
  r = await req(port, 'GET', '/tags');
  check('GET /tags with auth → 200', r.status === 200 && Array.isArray(r.body.tags), `got ${r.status}`);

  // ── manual tags on a device
  r = await req(port, 'PATCH', '/devices/R-TWO/tags', { body: { tags: ['vip', 'survey'] } });
  check('PATCH device tags → 200', r.status === 200 && r.body.device.tags.includes('vip'), JSON.stringify(r.body && r.body.device));
  r = await req(port, 'PATCH', '/devices/NOPE/tags', { body: { tags: ['x'] } });
  check('PATCH unknown device → 404', r.status === 404, `got ${r.status}`);
  r = await req(port, 'PATCH', '/devices/R-TWO/tags', { body: { tags: 'not-an-array' } });
  check('PATCH non-array tags → 400', r.status === 400, `got ${r.status}`);
  r = await req(port, 'PATCH', '/devices/R-TWO/tags', { body: { tags: ['x'.repeat(65)] } });
  check('PATCH over-long tag → 400', r.status === 400, `got ${r.status}`);

  // ── operator metadata (this is what "confirm customers" writes across)
  r = await req(port, 'PATCH', '/devices/R-ONE', { body: { customer: 'Allied Pharmacy Group' } });
  check('PATCH device customer → 200', r.status === 200 && r.body.device.customer === 'Allied Pharmacy Group', JSON.stringify(r.body && r.body.device && r.body.device.customer));
  r = await req(port, 'PATCH', '/devices/R-ONE', { body: {} });
  check('PATCH with no fields → 400', r.status === 400, `got ${r.status}`);
  r = await req(port, 'PATCH', '/devices/R-ONE', { body: { wan_type: 'carrier-pigeon' } });
  check('PATCH invalid wan_type → 400 (not a 500 from the CHECK)', r.status === 400, `got ${r.status}`);
  r = await req(port, 'PATCH', '/devices/NOPE', { body: { customer: 'x' } });
  check('PATCH unknown device → 404', r.status === 404, `got ${r.status}`);
  // a customer-scoped rule can now actually match something
  r = await req(port, 'POST', '/tag-rules/preview', { body: { conditions: { all: [{ field: 'customer', op: 'contains', value: 'allied' }] } } });
  check('customer-scoped condition matches the patched device', r.status === 200 && r.body.count === 1, `count=${r.body && r.body.count}`);

  // ── preview before saving
  r = await req(port, 'POST', '/tag-rules/preview', { body: { conditions: { all: [{ field: 'wan_type', op: 'eq', value: 'sim' }] } } });
  check('preview returns a count', r.status === 200 && r.body.count === 1, JSON.stringify(r.body && { c: r.body.count }));
  r = await req(port, 'POST', '/tag-rules/preview', { body: { conditions: { all: [{ field: 'bogus', op: 'eq', value: 'x' }] } } });
  check('preview with unknown field → 400', r.status === 400, `got ${r.status}: ${r.body && r.body.error}`);

  // ── create / duplicate / validation
  r = await req(port, 'POST', '/tag-rules', { body: { name: 'SIM WAN', tag: 'sim-wan', conditions: { all: [{ field: 'wan_type', op: 'eq', value: 'sim' }] } } });
  check('create rule → 201', r.status === 201 && r.body.rule.tag === 'sim-wan', `got ${r.status}`);
  const ruleId = r.body && r.body.rule && r.body.rule.id;
  r = await req(port, 'POST', '/tag-rules', { body: { name: 'Dup', tag: 'sim-wan', conditions: { all: [] } } });
  check('duplicate tag → 409', r.status === 409, `got ${r.status}: ${r.body && r.body.error}`);
  r = await req(port, 'POST', '/tag-rules', { body: { name: 'Bad tag', tag: 'has spaces!', conditions: { all: [] } } });
  check('invalid tag name → 400', r.status === 400, `got ${r.status}: ${r.body && r.body.error}`);
  r = await req(port, 'POST', '/tag-rules', { body: { name: 'Bad cond', tag: 'ok-tag', conditions: { all: [{ field: 'site_name', op: 'wat', value: 'x' }] } } });
  check('rule with uncompilable conditions → 400', r.status === 400, `got ${r.status}: ${r.body && r.body.error}`);

  // ── sync applies it
  r = await req(port, 'POST', '/tag-rules/sync');
  check('sync → 200 and applied 1', r.status === 200 && r.body.added === 1, JSON.stringify(r.body));
  r = await req(port, 'GET', '/tags');
  const simTag = (r.body.tags || []).find((t) => t.tag === 'sim-wan');
  check('GET /tags shows the rule-owned tag', simTag && simTag.rule_owned === true && simTag.devices === 1, JSON.stringify(simTag));
  const vipTag = (r.body.tags || []).find((t) => t.tag === 'vip');
  check('GET /tags shows the manual tag as not rule-owned', vipTag && vipTag.rule_owned === false, JSON.stringify(vipTag));

  // ── update
  r = await req(port, 'PATCH', `/tag-rules/${ruleId}`, { body: { enabled: false } });
  check('update rule → 200', r.status === 200 && r.body.rule.enabled === false, `got ${r.status}`);
  r = await req(port, 'PATCH', '/tag-rules/999999', { body: { enabled: false } });
  check('update missing rule → 404', r.status === 404, `got ${r.status}`);

  // ── delete strips the tag
  r = await req(port, 'DELETE', `/tag-rules/${ruleId}`);
  check('delete rule → 200 and untagged 1', r.status === 200 && r.body.untagged === 1, JSON.stringify(r.body));
  r = await req(port, 'GET', '/tags');
  check('tag gone after delete', !(r.body.tags || []).some((t) => t.tag === 'sim-wan'), JSON.stringify(r.body.tags));
  check('manual tag survived the rule delete', (r.body.tags || []).some((t) => t.tag === 'vip'));

  await new Promise((r2) => server.close(r2));
  await pool.end();
  console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL ROUTE CHECKS PASSED');
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('\nTEST ERROR:', e.message, '\n', e.stack); process.exit(2); });
