'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { prefixToNetmask, siteDnsmasqFilename, dnsList, renderSiteDnsmasq, renderAllSites } = require('../src/shared/pmrGateway.js');

test('prefixToNetmask: common prefixes', () => {
  assert.strictEqual(prefixToNetmask(24), '255.255.255.0');
  assert.strictEqual(prefixToNetmask(27), '255.255.255.224');
  assert.strictEqual(prefixToNetmask(26), '255.255.255.192');
  assert.strictEqual(prefixToNetmask(30), '255.255.255.252');
  assert.strictEqual(prefixToNetmask(32), '255.255.255.255');
});

test('prefixToNetmask: rejects nonsense', () => {
  assert.throws(() => prefixToNetmask(33));
  assert.throws(() => prefixToNetmask('x'));
});

test('siteDnsmasqFilename: lower-cased, stable', () => {
  assert.strictEqual(siteDnsmasqFilename('RX54554'), 'pmr-rx54554.conf');
  assert.strictEqual(siteDnsmasqFilename(' rx32163 '), 'pmr-rx32163.conf');
});

test('dnsList: splits and trims, falls back', () => {
  assert.deepStrictEqual(dnsList('10.7.0.1, 8.8.8.8'), ['10.7.0.1', '8.8.8.8']);
  assert.deepStrictEqual(dnsList('', '10.7.0.1'), ['10.7.0.1']);
  assert.deepStrictEqual(dnsList(null, '10.7.0.1'), ['10.7.0.1']);
});

// A new /27 site as the trigger/UI would produce it (base 10.200.<idx>).
const site27 = {
  idx: 7, code: 'RX70000', name: 'Boots Hull', vlan: 107, prefix_len: 27,
  gateway_ip: '10.200.7.1', server_ip: '10.200.7.10', dhcp_from: '10.200.7.21', dhcp_to: '10.200.7.30',
  dns_servers: '10.200.7.1', domain: 'pmr.local', lease_time: '12h', ntp_server: '10.200.7.1',
};

test('renderSiteDnsmasq: /27 site renders the expected dnsmasq lines', () => {
  const out = renderSiteDnsmasq(site27);
  assert.match(out, /dhcp-range=set:pmr7,10\.200\.7\.21,10\.200\.7\.30,255\.255\.255\.224,12h/);
  assert.match(out, /dhcp-option=tag:pmr7,option:router,10\.200\.7\.1/);
  assert.match(out, /dhcp-option=tag:pmr7,option:dns-server,10\.200\.7\.1/);
  assert.match(out, /dhcp-option=tag:pmr7,option:domain-name,pmr\.local/);
  assert.match(out, /domain=pmr\.local,10\.200\.7\.0\/27/);
  assert.match(out, /dhcp-option=tag:pmr7,option:ntp-server,10\.200\.7\.1/);
  assert.match(out, /address=\/pmr-rx70000-srv\/10\.200\.7\.10/);
  assert.ok(out.endsWith('\n'));
});

test('renderSiteDnsmasq: a widened /24 site gets the /24 mask under the same base', () => {
  const out = renderSiteDnsmasq({
    idx: 1, code: 'RX54554', vlan: 101, prefix_len: 24,
    gateway_ip: '10.200.1.1', server_ip: '10.200.1.10', dhcp_from: '10.200.1.100', dhcp_to: '10.200.1.254',
    dns_servers: '10.200.1.1', domain: 'pmr.local', lease_time: '12h', ntp_server: '10.200.1.1',
  });
  assert.match(out, /dhcp-range=set:pmr1,10\.200\.1\.100,10\.200\.1\.254,255\.255\.255\.0,12h/);
  assert.match(out, /domain=pmr\.local,10\.200\.1\.0\/24/);
});

test('renderSiteDnsmasq: multiple DNS servers are comma-joined', () => {
  const out = renderSiteDnsmasq({ ...site27, dns_servers: '10.200.7.1, 8.8.8.8' });
  assert.match(out, /option:dns-server,10\.200\.7\.1,8\.8\.8\.8/);
});

test('renderSiteDnsmasq: optional fields omitted when blank', () => {
  const out = renderSiteDnsmasq({ ...site27, domain: '', ntp_server: '', server_ip: '' });
  assert.doesNotMatch(out, /domain=/);
  assert.doesNotMatch(out, /option:domain-name/);
  assert.doesNotMatch(out, /option:ntp-server/);
  assert.doesNotMatch(out, /address=\//);
});

test('renderAllSites: renders servable sites in filename order, reports skips', () => {
  const { files, skipped } = renderAllSites([
    { ...site27, idx: 9, code: 'RX90000' },
    { ...site27, idx: 2, code: 'RX20000' },
    { idx: 3, code: 'RX30000', status: 'decommissioned' },   // skipped: decommissioned
    { idx: 4, code: 'RX40000' },                              // skipped: no dhcp pool → cannot render
  ]);
  assert.deepStrictEqual(files.map((f) => f.filename), ['pmr-rx20000.conf', 'pmr-rx90000.conf']);
  assert.ok(files.every((f) => typeof f.config === 'string' && f.config.length));
  assert.strictEqual(skipped.length, 2);
  assert.ok(skipped.some((s) => s.code === 'RX30000' && s.reason === 'decommissioned'));
  assert.ok(skipped.some((s) => s.code === 'RX40000'));
});

test('renderSiteDnsmasq: requires idx, code, and the DHCP pool', () => {
  assert.throws(() => renderSiteDnsmasq({ code: 'X', dhcp_from: '10.7.0.21', dhcp_to: '10.7.0.30' }));
  assert.throws(() => renderSiteDnsmasq({ idx: 7, dhcp_from: '10.7.0.21', dhcp_to: '10.7.0.30' }));
  assert.throws(() => renderSiteDnsmasq({ idx: 7, code: 'X' }));
});
