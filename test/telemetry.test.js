// Tests for telemetry.normalize(raw) -> typed payload (docs/CONTRACT.md §Telemetry payload).
// The ingest must be tolerant: unknown keys ignored, missing keys -> null, agent emits some
// numbers as quoted strings and some absent values as the literal "null".
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const telemetry = require("../src/shared/telemetry");

// The full sample payload exactly as documented in the contract / emitted by the agent.
function sample() {
  return {
    serial: "HGT0A023T6C",
    identity: "AlliedHuddersfield",
    uptime: "1w2d3h4m5s",
    cpu_load: 7,
    free_memory: 123456,
    total_memory: 268435456,
    free_hdd: 100000000,
    ros_version: "7.15.3",
    temperature: 41.5,
    cpu_temperature: null,
    board_temperature: null,
    voltage: 24.1,
    fan1_speed: null,
    write_sect_total: 123456,
    firmware_current: "7.15.3",
    firmware_upgrade: "7.15.3",
    ntp_synced: true,
    public_ip: "84.247.33.71",
    pppoe_running: true,
    ppp_sessions: 12,
    dhcp_leases: 30,
    lte: {
      interface: "lte1",
      iccid: "8944000000000000000",
      imsi: "234100000000000",
      imei: "350000000000000",
      msisdn: "",
      operator: "23410",
      registration: "registered",
      access_tech: "lte",
      band: "3",
      cell_id: "12345",
      rssi: "-65",
      rsrp: "-95",
      rsrq: "-10",
      sinr: "12",
    },
    interfaces: [
      {
        name: "ether1",
        type: "ether",
        running: true,
        disabled: false,
        plugged: true,
        speed: "1Gbps",
        full_duplex: true,
        bridge: "",
        is_wan: true,
        rx_byte: 999,
        tx_byte: 888,
        rx_packet: 10,
        tx_packet: 9,
      },
    ],
    neighbors: [
      {
        interface: "ether3",
        identity: "phone-1",
        mac: "AA:BB:CC:DD:EE:01",
        address: "10.0.0.5",
        platform: "Yealink",
      },
    ],
    mac_hosts: [{ mac: "AA:BB:CC:DD:EE:02", interface: "ether4" }],
    arp: [{ mac: "AA:BB:CC:DD:EE:02", ip: "10.0.0.9" }],
  };
}

test("normalize: accepts the full sample payload", () => {
  const out = telemetry.normalize(sample());
  assert.equal(out.serial, "HGT0A023T6C");
  assert.equal(out.identity, "AlliedHuddersfield");
  assert.equal(out.cpu_load, 7);
  assert.ok(Array.isArray(out.interfaces));
  assert.equal(out.interfaces.length, 1);
  assert.equal(out.interfaces[0].name, "ether1");
  assert.equal(out.interfaces[0].rx_byte, 999);
  assert.ok(Array.isArray(out.neighbors));
  assert.equal(out.neighbors[0].mac, "AA:BB:CC:DD:EE:01");
});

test("normalize: coerces lte signal strings to numbers", () => {
  const out = telemetry.normalize(sample());
  assert.ok(out.lte, "lte object present");
  assert.equal(out.lte.rssi, -65);
  assert.equal(out.lte.rsrp, -95);
  assert.equal(out.lte.rsrq, -10);
  assert.equal(out.lte.sinr, 12);
  assert.equal(typeof out.lte.rssi, "number");
  assert.equal(typeof out.lte.sinr, "number");
  // identifiers stay as-is (strings)
  assert.equal(out.lte.iccid, "8944000000000000000");
  assert.equal(out.lte.interface, "lte1");
});

test("normalize: lte null stays null", () => {
  const raw = sample();
  raw.lte = null;
  const out = telemetry.normalize(raw);
  assert.equal(out.lte, null);
});

test("normalize: public_ip 'null' -> null", () => {
  const raw = sample();
  raw.public_ip = "null";
  const out = telemetry.normalize(raw);
  assert.equal(out.public_ip, null);
});

test("normalize: public_ip '' -> null", () => {
  const raw = sample();
  raw.public_ip = "";
  const out = telemetry.normalize(raw);
  assert.equal(out.public_ip, null);
});

test("normalize: public_ip with CIDR mask is stripped", () => {
  const raw = sample();
  raw.public_ip = "1.2.3.4/24";
  const out = telemetry.normalize(raw);
  assert.equal(out.public_ip, "1.2.3.4");
});

test("normalize: tolerates unknown / extra keys (ignored, no throw)", () => {
  const raw = sample();
  raw.some_future_field = "whatever";
  raw.another = { nested: [1, 2, 3] };
  raw.interfaces[0].some_new_counter = 42;
  const out = telemetry.normalize(raw);
  assert.equal(out.serial, "HGT0A023T6C");
  // extra keys must not appear on the typed payload
  assert.equal(out.some_future_field, undefined);
});

test("normalize: mac_hosts null is preserved (means 'keep previous')", () => {
  const raw = sample();
  raw.mac_hosts = null;
  raw.arp = null;
  const out = telemetry.normalize(raw);
  assert.equal(out.mac_hosts, null);
});

test("normalize: rejects missing serial", () => {
  const raw = sample();
  delete raw.serial;
  assert.throws(() => telemetry.normalize(raw));
});

// ── NUMERIC COERCION: the agent emits health numerics both as QUOTED strings and as the
// literal 'null'. normalize() must coerce every one to number|null (docs/CONTRACT.md). ──
test("normalize: quoted-string health numerics coerce to numbers; 'null' -> null", () => {
  const raw = sample();
  // Agent emits these as QUOTED strings.
  raw.cpu_load = "23";
  raw.free_memory = "123456789";
  raw.total_memory = "268435456";
  raw.free_hdd = "100000000";
  raw.temperature = "41.5";
  raw.voltage = "24.1";
  raw.write_sect_total = "987654";
  raw.ppp_sessions = "7";
  raw.dhcp_leases = "30";
  // Agent emits these absent values as the literal string 'null'.
  raw.cpu_temperature = "null";
  raw.board_temperature = "null";
  raw.fan1_speed = "null";

  const out = telemetry.normalize(raw);

  assert.equal(out.cpu_load, 23);
  assert.equal(typeof out.cpu_load, "number");
  assert.equal(out.free_memory, 123456789);
  assert.equal(out.total_memory, 268435456);
  assert.equal(out.free_hdd, 100000000);
  assert.equal(out.temperature, 41.5);
  assert.equal(typeof out.temperature, "number");
  assert.equal(out.voltage, 24.1);
  assert.equal(out.write_sect_total, 987654);
  assert.equal(out.ppp_sessions, 7);
  assert.equal(out.dhcp_leases, 30);
  // 'null' string -> real null
  assert.equal(out.cpu_temperature, null);
  assert.equal(out.board_temperature, null);
  assert.equal(out.fan1_speed, null);
});
