// Validation for smart tags. Runs against a THROWAWAY database (caller sets
// VIGILANT_DB_URL). Covers the risky parts: generated SQL, version-aware comparison,
// the empty-rule guard, and manual/rule-owned tag separation.
'use strict';

const { makePgStore } = require('/app/src/shared/store.pg.js');
const { makePool } = require('/app/src/shared/db.js');

let fails = 0;
function check(name, cond, extra) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  (' + extra + ')' : ''}`);
  if (!cond) fails++;
}
const tagsOf = async (store, serial) => ((await store.getDeviceBySerial(serial)) || {}).tags || [];

(async () => {
  const pool = makePool(process.env.VIGILANT_DB_URL);
  const store = makePgStore(pool);
  await store.migrate();
  console.log('-- schema applied --');

  // A small fleet spanning the attributes rules can test.
  const fleet = [
    { serial: 'T-SIM-OLD', site_name: 'Sim Old', customer: 'Allied', model: 'hAP ac2', ros_version: '7.9.2 (stable)', wan_type: 'sim' },
    { serial: 'T-SIM-NEW', site_name: 'Sim New', customer: 'Allied', model: 'hAP ax3', ros_version: '7.16.1 (stable)', wan_type: 'sim' },
    { serial: 'T-PPP-OLD', site_name: 'Pppoe Old', customer: 'Cegedim', model: 'hAP ac2', ros_version: '7.10', wan_type: 'pppoe' },
    { serial: 'T-PPP-NEW', site_name: 'Pppoe New', customer: 'WCN', model: 'RB5009', ros_version: '7.20.0', wan_type: 'pppoe' },
    { serial: 'T-NOVER', site_name: 'No Version', customer: 'WCN', model: null, ros_version: null, wan_type: 'dhcp' },
  ];
  const ids = {};
  for (const d of fleet) ids[d.serial] = (await store.createDevice(d)).id;
  // ros_version is read from device_state (the ingest never writes devices.ros_version),
  // so the version tests must seed telemetry. T-NOVER deliberately gets NO state row.
  for (const d of fleet) {
    if (d.serial === 'T-NOVER' || !d.ros_version) continue;
    await store.upsertDeviceState(ids[d.serial], { status: 'online', ros_version: d.ros_version });
  }
  console.log(`-- ${fleet.length} devices seeded (4 with telemetry) --`);

  // ── 1. attribute equality
  let r = await store.createTagRule({ name: 'SIM WAN', tag: 'sim-wan', conditions: { all: [{ field: 'wan_type', op: 'eq', value: 'sim' }] } });
  let s = await store.syncSmartTags();
  check('eq: sim-wan applied to 2 devices', s.added === 2, `added=${s.added} removed=${s.removed}`);
  check('eq: tag present on T-SIM-OLD', (await tagsOf(store, 'T-SIM-OLD')).includes('sim-wan'));
  check('eq: tag absent on T-PPP-OLD', !(await tagsOf(store, 'T-PPP-OLD')).includes('sim-wan'));

  // ── 2. sync is idempotent (a second pass must be a no-op)
  s = await store.syncSmartTags();
  check('sync is idempotent', s.added === 0 && s.removed === 0, `added=${s.added} removed=${s.removed}`);

  // ── 3. THE version trap: text ordering would put '7.9' after '7.16'
  await store.createTagRule({ name: 'Old firmware', tag: 'old-firmware', conditions: { all: [{ field: 'ros_version', op: 'version_lt', value: '7.16' }] } });
  await store.syncSmartTags();
  const old = await tagsOf(store, 'T-SIM-OLD'), oldPpp = await tagsOf(store, 'T-PPP-OLD');
  const newSim = await tagsOf(store, 'T-SIM-NEW'), newPpp = await tagsOf(store, 'T-PPP-NEW');
  check('version_lt: 7.9.2 counts as older than 7.16', old.includes('old-firmware'));
  check('version_lt: 7.10 counts as older than 7.16', oldPpp.includes('old-firmware'));
  check('version_lt: 7.16.1 is NOT older than 7.16', !newSim.includes('old-firmware'));
  check('version_lt: 7.20.0 is NOT older than 7.16', !newPpp.includes('old-firmware'));
  // An unknown version must match NEITHER direction — otherwise "older than 7.16" tags the
  // whole fleet on an estate where the version column isn't populated (exactly what
  // happened live: 363/363 matched before this guard).
  check('version_lt: a device with NO reported version does NOT match', !(await tagsOf(store, 'T-NOVER')).includes('old-firmware'));
  const gte = await store.previewTagRule({ all: [{ field: 'ros_version', op: 'version_gte', value: '7.16' }] });
  check('version_gte: matches only the two new ones', gte.count === 2, `count=${gte.count}`);
  const lt = await store.previewTagRule({ all: [{ field: 'ros_version', op: 'version_lt', value: '7.16' }] });
  check('version_lt: matches only the two old ones', lt.count === 2, `count=${lt.count}`);

  // ── 4. multiple conditions AND together
  await store.createTagRule({ name: 'Allied SIM', tag: 'allied-sim', conditions: { all: [
    { field: 'customer', op: 'eq', value: 'allied' },       // case-insensitive
    { field: 'wan_type', op: 'eq', value: 'sim' },
  ] } });
  await store.syncSmartTags();
  const c = await store.previewTagRule({ all: [{ field: 'customer', op: 'eq', value: 'allied' }, { field: 'wan_type', op: 'eq', value: 'sim' }] });
  check('AND of two conditions matches 2', c.count === 2, `count=${c.count}`);

  // ── 5. rule membership follows the data: flip a device's WAN and it loses the tag
  await store.createDevice({ serial: 'T-SIM-OLD', wan_type: 'pppoe' });   // upsert changes wan_type
  s = await store.syncSmartTags();
  check('tag removed when the device stops matching', !(await tagsOf(store, 'T-SIM-OLD')).includes('sim-wan'), `removed=${s.removed}`);

  // ── 6. THE dangerous default: an empty rule must match nothing, not everything
  const empty = await store.createTagRule({ name: 'Half written', tag: 'half-written', conditions: { all: [] } });
  await store.syncSmartTags();
  const p = await store.previewTagRule({ all: [] });
  check('empty conditions match NOTHING', p.count === 0, `count=${p.count}`);
  const anyHalf = (await Promise.all(fleet.map((d) => tagsOf(store, d.serial)))).some((t) => t.includes('half-written'));
  check('empty rule tagged no device', !anyHalf);
  await store.deleteTagRule(empty.id);

  // ── 7. manual tags coexist with rule-owned ones and survive a sync
  await store.setDeviceTags('T-PPP-NEW', ['vip', 'site-survey']);
  let t = await tagsOf(store, 'T-PPP-NEW');
  check('manual tags stored', t.includes('vip') && t.includes('site-survey'), t.join(','));
  await store.syncSmartTags();
  t = await tagsOf(store, 'T-PPP-NEW');
  check('manual tags survive a smart-tag sync', t.includes('vip') && t.includes('site-survey'), t.join(','));

  // ── 8. a rule-owned tag cannot be set (or dropped) by hand
  await store.setDeviceTags('T-SIM-NEW', ['sim-wan', 'manual-one']);
  t = await tagsOf(store, 'T-SIM-NEW');
  check('rule-owned name ignored in manual set', t.filter((x) => x === 'sim-wan').length <= 1, t.join(','));
  check('manual tag alongside rule-owned kept', t.includes('manual-one'), t.join(','));
  await store.setDeviceTags('T-SIM-NEW', []);           // try to clear everything
  t = await tagsOf(store, 'T-SIM-NEW');
  check('clearing manual tags preserves rule-owned tag', t.includes('sim-wan'), t.join(','));
  check('clearing manual tags drops the manual one', !t.includes('manual-one'), t.join(','));

  // ── 9. deleting a rule strips its tag everywhere
  const rules = await store.listTagRules();
  const simRule = rules.find((x) => x.tag === 'sim-wan');
  const del = await store.deleteTagRule(simRule.id);
  check('deleting a rule untags its devices', del.untagged >= 1, `untagged=${del.untagged}`);
  check('tag gone from device', !(await tagsOf(store, 'T-SIM-NEW')).includes('sim-wan'));

  // ── 10. listTags reports counts + ownership
  const list = await store.listTags();
  const oldF = list.find((x) => x.tag === 'old-firmware');
  const vip = list.find((x) => x.tag === 'vip');
  check('listTags marks a rule-owned tag', oldF && oldF.rule_owned === true, JSON.stringify(oldF));
  check('listTags marks a manual tag as not rule-owned', vip && vip.rule_owned === false, JSON.stringify(vip));

  // ── 11. injection / whitelist guards
  for (const bad of [
    { all: [{ field: 'tags; DROP TABLE devices; --', op: 'eq', value: 'x' }] },
    { all: [{ field: 'site_name', op: 'nonsense', value: 'x' }] },
    { all: [{ field: 'expected', op: 'contains', value: 'x' }] },
  ]) {
    let threw = false;
    try { await store.previewTagRule(bad); } catch (e) { threw = e.status === 400; }
    check(`rejects ${JSON.stringify(bad.all[0]).slice(0, 52)}…`, threw);
  }
  const stillThere = await one_(pool, `SELECT count(*)::int n FROM devices`);
  check('devices table intact after injection attempts', stillThere.n === fleet.length, `n=${stillThere.n}`);

  // ── 11b. re-enrolling a device must NOT wipe its tags (we re-enrol routinely to fix
  // mis-tokened routers; that used to silently drop the device out of tag-scoped rules)
  await store.setDeviceTags('T-PPP-OLD', ['keep-me']);
  await store.createDevice({ serial: 'T-PPP-OLD', site_name: 'Pppoe Old' }); // re-enrol, no tags
  t = await tagsOf(store, 'T-PPP-OLD');
  check('re-enrol preserves manual tags', t.includes('keep-me'), t.join(','));
  check('re-enrol preserves rule-owned tags', t.includes('old-firmware'), t.join(','));
  await store.createDevice({ serial: 'T-PPP-OLD', tags: ['replaced'] });     // explicit tags DO replace
  t = await tagsOf(store, 'T-PPP-OLD');
  check('explicit tags on enrol still replace', t.includes('replaced') && !t.includes('keep-me'), t.join(','));

  // ── 12. other operators
  await store.createTagRule({ name: 'Pharmacy sites', tag: 'pharmacy', conditions: { all: [{ field: 'site_name', op: 'contains', value: 'old' }] } });
  await store.createTagRule({ name: 'Not WCN', tag: 'not-wcn', conditions: { all: [{ field: 'customer', op: 'ne', value: 'WCN' }] } });
  await store.createTagRule({ name: 'Model set', tag: 'has-model', conditions: { all: [{ field: 'model', op: 'is_not_empty' }] } });
  await store.createTagRule({ name: 'AC2 or 5009', tag: 'ac2-5009', conditions: { all: [{ field: 'model', op: 'in', value: ['hAP ac2', 'RB5009'] }] } });
  await store.syncSmartTags();
  check('contains matched', (await store.previewTagRule({ all: [{ field: 'site_name', op: 'contains', value: 'old' }] })).count === 2);
  check('ne is NULL-safe (T-NOVER has no model but customer WCN excluded)', !(await tagsOf(store, 'T-NOVER')).includes('not-wcn'));
  check('is_not_empty excludes the null model', !(await tagsOf(store, 'T-NOVER')).includes('has-model'));
  check('in matched 3 devices', (await store.previewTagRule({ all: [{ field: 'model', op: 'in', value: ['hAP ac2', 'RB5009'] }] })).count === 3);

  await pool.end();
  console.log(fails ? `\n${fails} CHECK(S) FAILED` : '\nALL CHECKS PASSED');
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('\nTEST ERROR:', e.message, '\n', e.stack); process.exit(2); });

async function one_(pool, sql) { const r = await pool.query(sql); return r.rows[0]; }
