#!/usr/bin/env node
'use strict';

// node src/bin/simulate.js --url http://localhost:9100 --token <bearer> [--ticks N] [--interval 1000]
//
// Drives the ingest with synthetic-but-contract-valid telemetry so a human can
// watch data flow without a real router. Each tick the per-interface CUMULATIVE
// byte/packet counters advance by a KNOWN amount, so the server-derived bps is
// deterministic and testable.
//
// `makeTelemetry({serial, tick, prev})` is exported and is the SINGLE payload
// factory shared with ingest.e2e.test.js — the test and the simulator must agree
// on the byte-advance so the bps assertion is exact.

const http = require('http');
const https = require('https');
const { URL } = require('url');

// Known per-tick advance for each interface's counters. The e2e test relies on
// these being constant so it can predict the bps after a fixed Δt.
const BYTES_PER_TICK = {
  rx: 1000000, // 1,000,000 bytes rx per tick
  tx: 500000, //   500,000 bytes tx per tick
};
const PACKETS_PER_TICK = {
  rx: 1000,
  tx: 500,
};

// The fixed interface set the simulator emits. ether1 is the WAN uplink.
const IFACE_TEMPLATES = [
  { name: 'ether1', type: 'ether', bridge: '', is_wan: true, plugged: true, running: true, disabled: false, speed: '1Gbps', full_duplex: true },
  { name: 'ether2', type: 'ether', bridge: 'bridge1', is_wan: false, plugged: true, running: true, disabled: false, speed: '1Gbps', full_duplex: true },
  { name: 'ether3', type: 'ether', bridge: 'bridge1', is_wan: false, plugged: true, running: true, disabled: false, speed: '1Gbps', full_duplex: true },
  { name: 'bridge1', type: 'bridge', bridge: '', is_wan: false, plugged: true, running: true, disabled: false, speed: '', full_duplex: true },
];

// Index a previous payload's interfaces by name for counter carry-over.
function indexPrevInterfaces(prev) {
  const map = {};
  if (prev && Array.isArray(prev.interfaces)) {
    for (const i of prev.interfaces) {
      if (i && i.name != null) map[i.name] = i;
    }
  }
  return map;
}

/**
 * Build one synthetic telemetry payload matching agent/vigilant-agent.rsc.
 *
 * This is the SINGLE payload factory shared by the simulator CLI and ingest.e2e.test.js.
 * It supports two complementary modes:
 *
 *   * SYNTHETIC (CLI): pass {serial, tick, prev}. The fixed interface set advances its
 *     cumulative counters by BYTES_PER_TICK/PACKETS_PER_TICK each tick (carried over from
 *     `prev` when supplied), and mac_hosts/arp populate on the ~5-min slow tick (tick%30).
 *   * EXPLICIT (e2e): pass any of {interfaces, neighbors, mac_hosts, arp, now} to override
 *     the synthetic values verbatim. This lets the test pin exact byte counters so it can
 *     predict the server-derived bps. An explicitly-passed `mac_hosts`/`arp` key is honoured
 *     even when its value is null (null = "keep previous" to the ingest).
 *
 * @param {object} opts
 * @param {string} [opts.serial='SIM00000001'] device serial (echoed in payload.serial)
 * @param {number} [opts.tick=1]   1-based tick counter; mac_hosts/arp populate when tick % 30 === 0
 * @param {object} [opts.prev]     the previous payload returned by makeTelemetry; its
 *                                 per-interface byte/packet counters are advanced by
 *                                 BYTES_PER_TICK/PACKETS_PER_TICK. If omitted, counters are
 *                                 seeded from `tick` so a standalone call is still monotonic.
 * @param {number} [opts.now]      epoch ms (e2e); used only to derive a plausible uptime.
 * @param {object[]} [opts.interfaces] override interface set verbatim.
 * @param {object[]} [opts.neighbors]  override neighbor set verbatim.
 * @param {?object[]} [opts.mac_hosts] override mac_hosts (null = keep previous).
 * @param {?object[]} [opts.arp]       override arp (null = keep previous).
 * @returns {object} a contract-valid POST /telemetry body
 */
function makeTelemetry(opts) {
  const o = opts || {};
  const serial = o.serial != null ? o.serial : 'SIM00000001';
  const tick = o.tick != null ? o.tick : 1;
  const prev = o.prev || null;
  const prevIf = indexPrevInterfaces(prev);

  // Interfaces: explicit override (e2e) wins; otherwise advance the synthetic set.
  const interfaces = Array.isArray(o.interfaces)
    ? o.interfaces
    : IFACE_TEMPLATES.map((t) => {
        const p = prevIf[t.name];
        const baseRxByte = p && typeof p.rx_byte === 'number' ? p.rx_byte : (tick - 1) * BYTES_PER_TICK.rx;
        const baseTxByte = p && typeof p.tx_byte === 'number' ? p.tx_byte : (tick - 1) * BYTES_PER_TICK.tx;
        const baseRxPkt = p && typeof p.rx_packet === 'number' ? p.rx_packet : (tick - 1) * PACKETS_PER_TICK.rx;
        const baseTxPkt = p && typeof p.tx_packet === 'number' ? p.tx_packet : (tick - 1) * PACKETS_PER_TICK.tx;
        return {
          name: t.name,
          type: t.type,
          running: t.running,
          disabled: t.disabled,
          plugged: t.plugged,
          speed: t.speed,
          full_duplex: t.full_duplex,
          bridge: t.bridge,
          is_wan: t.is_wan,
          rx_byte: baseRxByte + BYTES_PER_TICK.rx,
          tx_byte: baseTxByte + BYTES_PER_TICK.tx,
          rx_packet: baseRxPkt + PACKETS_PER_TICK.rx,
          tx_packet: baseTxPkt + PACKETS_PER_TICK.tx,
        };
      });

  // Heavy L2 tables only on the ~5-min slow tick (every 30th), matching the agent.
  // null on fast ticks means "keep previous" to the ingest. An explicit override
  // (including an explicit null) takes precedence over the synthetic cadence.
  const isSlow = tick % 30 === 0;
  const macHosts = 'mac_hosts' in o
    ? o.mac_hosts
    : isSlow
      ? [
          { mac: 'AA:BB:CC:00:00:01', interface: 'ether2' },
          { mac: 'AA:BB:CC:00:00:02', interface: 'ether3' },
        ]
      : null;
  const arp = 'arp' in o
    ? o.arp
    : isSlow
      ? [
          { mac: 'AA:BB:CC:00:00:01', ip: '10.0.0.11' },
          { mac: 'AA:BB:CC:00:00:02', ip: '10.0.0.12' },
        ]
      : null;

  // Neighbors: explicit override (e2e) wins; otherwise the default one-phone set.
  const neighbors = Array.isArray(o.neighbors)
    ? o.neighbors
    : [
        { interface: 'ether3', identity: 'phone-1', mac: 'AA:BB:CC:00:00:02', address: '10.0.0.12', platform: 'Yealink' },
      ];

  // WiFi: SSIDs/channels are config (slow tick; also tick 1 so a short demo run shows them),
  // associated stations report every tick so the signal bars move. Explicit overrides win.
  const wifiSlow = isSlow || tick === 1;
  const wifi = 'wifi' in o
    ? o.wifi
    : wifiSlow
      ? [
          { interface: 'wifi1', driver: 'ax', band: '5ghz', ssid: 'Allied-Staff', passphrase: 'pharmacy-wifi-2026', security: 'wpa2-psk', channel: '5180/20/ax', frequency_mhz: 5180, width_mhz: 20, disabled: false, hidden: false },
          { interface: 'wifi2', driver: 'ax', band: '2ghz', ssid: 'Allied-Guest', passphrase: 'guestpass123', security: 'wpa2-psk', channel: '2412/20/ax', frequency_mhz: 2412, width_mhz: 20, disabled: false, hidden: false },
        ]
      : null;
  const wifiClients = 'wifi_clients' in o
    ? o.wifi_clients
    : [
        // signal arrives as the AC "-NN@rate" form to exercise the parser; it jitters per tick.
        { interface: 'wifi1', mac: 'AA:BB:CC:00:00:02', signal: `${-55 - (tick % 18)}@6mbps`, rx_rate: '130Mbps', tx_rate: '144Mbps', uptime_s: tick * 10 },
        { interface: 'wifi1', mac: 'AA:BB:CC:00:00:03', signal: -72, rx_rate: '58Mbps', tx_rate: '65Mbps', uptime_s: tick * 7 },
        { interface: 'wifi2', mac: 'AA:BB:CC:00:00:04', signal: -83, rx_rate: '24Mbps', tx_rate: '24Mbps', uptime_s: tick * 3 },
      ];

  // uptime advances 10s/tick to look plausible (agent default poll = 10s).
  const uptimeS = tick * 10;

  // Agent-reported sample time (epoch ms). When the caller supplies `now` (the e2e does,
  // to pin a deterministic Δt), thread it through so the server computes bps over that
  // exact window instead of HTTP round-trip latency. Omitted by the CLI -> server uses
  // receive time, which is correct for real interval-spaced ticks.
  const ts = o.now != null ? o.now : undefined;

  return {
    serial,
    ...(ts != null ? { ts } : {}),
    identity: 'SimRouter',
    uptime: `${uptimeS}s`,
    cpu_load: 5 + (tick % 10),
    free_memory: 123456000,
    total_memory: 268435456,
    free_hdd: 100000000,
    ros_version: '7.15.3',
    temperature: 41.5,
    cpu_temperature: null,
    board_temperature: null,
    voltage: 24.1,
    fan1_speed: null,
    write_sect_total: 123456 + tick,
    firmware_current: '7.15.3',
    firmware_upgrade: '7.15.3',
    ntp_synced: true,
    public_ip: '84.247.33.71',
    pppoe_running: true,
    ppp_sessions: 12,
    dhcp_leases: 30,
    lte: {
      interface: 'lte1',
      iccid: '8944000000000000000',
      imsi: '234100000000000',
      imei: '350000000000000',
      msisdn: '',
      operator: '23410',
      registration: 'registered',
      access_tech: 'lte',
      band: '3',
      cell_id: '1A2B3C',
      // signal fields are STRINGS, as the agent emits them
      rssi: '-65',
      rsrp: '-95',
      rsrq: '-10',
      sinr: '12',
    },
    interfaces,
    neighbors,
    mac_hosts: macHosts,
    arp,
    wifi,
    wifi_clients: wifiClients,
  };
}

// ── CLI: POST makeTelemetry() to <url>/telemetry on an interval ──────────────

function parseArgs(argv) {
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
      val = true;
    }
    out[key] = val;
  }
  return out;
}

function postTelemetry(baseUrl, token, body) {
  return new Promise((resolve, reject) => {
    const u = new URL('/telemetry', baseUrl);
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length,
          Authorization: `Bearer ${token}`,
        },
      },
      (res) => {
        let chunks = '';
        res.setEncoding('utf8');
        res.on('data', (c) => {
          chunks += c;
        });
        res.on('end', () => resolve({ status: res.statusCode, body: chunks }));
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runCli() {
  const args = parseArgs(process.argv.slice(2));
  const url = args.url != null && args.url !== true ? String(args.url) : '';
  const token = args.token != null && args.token !== true ? String(args.token) : '';
  const ticks = args.ticks != null && args.ticks !== true ? parseInt(args.ticks, 10) : 0; // 0 = forever
  const interval = args.interval != null && args.interval !== true ? parseInt(args.interval, 10) : 1000;
  const serial = args.serial != null && args.serial !== true ? String(args.serial) : 'SIM00000001';

  if (!url || !token) {
    process.stderr.write('Usage: node src/bin/simulate.js --url <baseUrl> --token <bearer> [--ticks N] [--interval ms] [--serial S]\n');
    process.exit(1);
    return;
  }

  let prev = null;
  let tick = 0;
  // Mask the token in logs (never print the secret).
  process.stdout.write(`simulate: POSTing telemetry for ${serial} -> ${url}/telemetry every ${interval}ms\n`);

  for (;;) {
    tick += 1;
    const payload = makeTelemetry({ serial, tick, prev });
    try {
      const res = await postTelemetry(url, token, payload);
      const wan = payload.interfaces.find((i) => i.is_wan) || payload.interfaces[0];
      process.stdout.write(
        `tick ${tick}: HTTP ${res.status}  rx_byte(ether1)=${wan.rx_byte}  resp=${res.body}\n`
      );
    } catch (err) {
      process.stderr.write(`tick ${tick}: POST failed: ${err && err.message ? err.message : String(err)}\n`);
    }
    prev = payload; // carry counters forward for monotonic deltas
    if (ticks > 0 && tick >= ticks) break;
    await sleep(interval);
  }
}

module.exports = { makeTelemetry, BYTES_PER_TICK, PACKETS_PER_TICK };

// Run the CLI only when invoked directly, not when required by the test suite.
if (require.main === module) {
  runCli().then(
    () => process.exit(0),
    (err) => {
      process.stderr.write(`simulate: ${err && err.message ? err.message : String(err)}\n`);
      process.exit(1);
    }
  );
}
