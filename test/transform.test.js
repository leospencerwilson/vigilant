// Unit tests for the PURE transform helpers (no IO).
// These pin transform.js to the contract (docs/CONTRACT.md §transform.js).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const transform = require("../src/shared/transform");

// ── deltaBps(prevBytes, prevAtMs, curBytes, curAtMs) -> number|null ─────────
test("deltaBps: normal positive delta -> bits/sec", () => {
  // 1000 bytes over 1s = 8000 bits/sec.
  const t0 = 1_700_000_000_000;
  const t1 = t0 + 1000; // +1 second
  assert.equal(transform.deltaBps(0, t0, 1000, t1), 8000);
});

test("deltaBps: 1.25 MB over 10s -> 1,000,000 bps", () => {
  const t0 = 1_700_000_000_000;
  const t1 = t0 + 10_000; // +10 seconds
  // (1_250_000 bytes * 8) / 10s = 1_000_000 bps
  assert.equal(transform.deltaBps(0, t0, 1_250_000, t1), 1_000_000);
});

test("deltaBps: counter reset / wrap (cur < prev) -> null (no negative spike)", () => {
  const t0 = 1_700_000_000_000;
  const t1 = t0 + 1000;
  assert.equal(transform.deltaBps(5000, t0, 100, t1), null);
});

test("deltaBps: zero Δt -> null", () => {
  const t0 = 1_700_000_000_000;
  assert.equal(transform.deltaBps(0, t0, 1000, t0), null);
});

test("deltaBps: negative Δt (curAt < prevAt) -> null", () => {
  const t0 = 1_700_000_000_000;
  const t1 = t0 - 1000;
  assert.equal(transform.deltaBps(0, t0, 1000, t1), null);
});

test("deltaBps: missing prev bytes -> null", () => {
  const t1 = 1_700_000_000_000;
  assert.equal(transform.deltaBps(null, null, 1000, t1), null);
  assert.equal(transform.deltaBps(undefined, undefined, 1000, t1), null);
});

// ── classifyRole(iface) -> role ─────────────────────────────────────────────
test("classifyRole: disabled wins over everything (precedence)", () => {
  // even though is_wan true and bridge set, disabled takes precedence.
  assert.equal(
    transform.classifyRole({ disabled: true, is_wan: true, bridge: "br1", type: "ether" }),
    "disabled",
  );
});

test("classifyRole: is_wan -> 'wan' (beats bridge/type)", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "br1", type: "ether" }),
    "wan",
  );
});

test("classifyRole: tunnel/vpn types -> 'vpn'", () => {
  for (const type of [
    "pppoe-out",
    "pppoe-client",
    "l2tp-out",
    "l2tp-in",
    "sstp-out",
    "ovpn-out",
    "wireguard",
    "gre",
    "eoip",
  ]) {
    assert.equal(
      transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type }),
      "vpn",
      `type ${type} should classify as vpn`,
    );
  }
});

test("classifyRole: vlan stays lan (not vpn)", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type: "vlan", plugged: true }),
    "lan",
  );
});

test("classifyRole: bridge set -> 'bridge-member'", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: false, bridge: "bridge1", type: "ether" }),
    "bridge-member",
  );
});

test("classifyRole: ether + not plugged + no bridge -> 'unused'", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type: "ether", plugged: false }),
    "unused",
  );
});

test("classifyRole: ether + plugged + no bridge -> 'lan'", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type: "ether", plugged: true }),
    "lan",
  );
});

test("classifyRole: non-ether, no bridge, not wan/vpn (e.g. vlan) -> 'lan'", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type: "vlan", plugged: true }),
    "lan",
  );
});

// ── type-aware classification: a TYPE/name never mislabelled 'wan' (precedence) ─────────
test("classifyRole: a bridge with is_wan=true -> 'bridge-member' (type beats the wan flag)", () => {
  // Even though the agent flagged is_wan:true, a bridge interface must be a bridge-member,
  // never a 'wan' — the bridge type takes precedence over the hint.
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "", type: "bridge", plugged: true }),
    "bridge-member",
  );
  // also by name (type came through blank but it is named "bridge-lan").
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "", type: "", name: "bridge-lan", plugged: true }),
    "bridge-member",
  );
});

test("classifyRole: an l2tp-out with is_wan=true -> 'vpn' (tunnel type beats the wan flag)", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "", type: "l2tp-out", plugged: true }),
    "vpn",
  );
  // also by tell-tale name when the type is generic/blank.
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "", type: "", name: "sstp-allied", plugged: true }),
    "vpn",
  );
});

test("classifyRole: a plugged ether with is_wan=true -> 'wan'", () => {
  assert.equal(
    transform.classifyRole({ disabled: false, is_wan: true, bridge: "", type: "ether", plugged: true }),
    "wan",
  );
});

test("classifyRole: extra VPN types (ipip, vpls, sstp-in, ovpn-out) -> 'vpn'", () => {
  for (const type of ["ipip", "vpls", "sstp-in", "ovpn-out"]) {
    assert.equal(
      transform.classifyRole({ disabled: false, is_wan: false, bridge: "", type }),
      "vpn",
      `type ${type} should classify as vpn`,
    );
  }
});

// ── parseNum(v) -> number|null ──────────────────────────────────────────────
test("parseNum: numbers and numeric strings", () => {
  assert.equal(transform.parseNum(42), 42);
  assert.equal(transform.parseNum("-65"), -65);
  assert.equal(transform.parseNum("0"), 0);
  assert.equal(transform.parseNum("41.5"), 41.5);
});

test("parseNum: empty/null/'null'/non-numeric -> null", () => {
  assert.equal(transform.parseNum(""), null);
  assert.equal(transform.parseNum("null"), null);
  assert.equal(transform.parseNum(null), null);
  assert.equal(transform.parseNum(undefined), null);
  assert.equal(transform.parseNum("abc"), null);
});

// ── parseIp(v) -> string|null ───────────────────────────────────────────────
test("parseIp: strips CIDR mask", () => {
  assert.equal(transform.parseIp("1.2.3.4/24"), "1.2.3.4");
  assert.equal(transform.parseIp("84.247.33.71"), "84.247.33.71");
});

test("parseIp: 'null'/''/null -> null", () => {
  assert.equal(transform.parseIp("null"), null);
  assert.equal(transform.parseIp(""), null);
  assert.equal(transform.parseIp(null), null);
  assert.equal(transform.parseIp(undefined), null);
});

// ── normaliseMac(s) -> 'AA:BB:CC:DD:EE:FF' | null ───────────────────────────
test("normaliseMac: uppercases and colon-separates", () => {
  assert.equal(transform.normaliseMac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF");
  assert.equal(transform.normaliseMac("AA-BB-CC-DD-EE-FF"), "AA:BB:CC:DD:EE:FF");
  assert.equal(transform.normaliseMac("aabb.ccdd.eeff"), "AA:BB:CC:DD:EE:FF");
  assert.equal(transform.normaliseMac("AABBCCDDEEFF"), "AA:BB:CC:DD:EE:FF");
});

test("normaliseMac: invalid/empty -> null", () => {
  assert.equal(transform.normaliseMac(""), null);
  assert.equal(transform.normaliseMac(null), null);
  assert.equal(transform.normaliseMac("not-a-mac"), null);
});

// ── joinMacHosts(macHosts[], arp[]) -> [{mac, interface, ip|null}] ──────────
test("joinMacHosts: left-joins arp by normalised mac", () => {
  const macHosts = [
    { mac: "aa:bb:cc:dd:ee:ff", interface: "ether4" },
    { mac: "11:22:33:44:55:66", interface: "ether5" },
  ];
  const arp = [{ mac: "AA-BB-CC-DD-EE-FF", ip: "10.0.0.9" }];
  const out = transform.joinMacHosts(macHosts, arp);

  const byMac = Object.fromEntries(out.map((r) => [r.mac, r]));
  // matched host gets its ip
  assert.equal(byMac["AA:BB:CC:DD:EE:FF"].interface, "ether4");
  assert.equal(byMac["AA:BB:CC:DD:EE:FF"].ip, "10.0.0.9");
  // no arp match -> ip null
  assert.equal(byMac["11:22:33:44:55:66"].interface, "ether5");
  assert.equal(byMac["11:22:33:44:55:66"].ip, null);
});

test("joinMacHosts: no arp at all -> all ips null", () => {
  const macHosts = [{ mac: "aa:bb:cc:dd:ee:ff", interface: "ether4" }];
  const out = transform.joinMacHosts(macHosts, []);
  assert.equal(out.length, 1);
  assert.equal(out[0].ip, null);
  assert.equal(out[0].mac, "AA:BB:CC:DD:EE:FF");
});

// ── evaluateAlert(rule, value) -> boolean ───────────────────────────────────
test("evaluateAlert: '>' comparator", () => {
  assert.equal(transform.evaluateAlert({ comparator: ">", threshold: 80 }, 90), true);
  assert.equal(transform.evaluateAlert({ comparator: ">", threshold: 80 }, 80), false);
  assert.equal(transform.evaluateAlert({ comparator: ">", threshold: 80 }, 70), false);
});

test("evaluateAlert: '>=' comparator", () => {
  assert.equal(transform.evaluateAlert({ comparator: ">=", threshold: 80 }, 80), true);
  assert.equal(transform.evaluateAlert({ comparator: ">=", threshold: 80 }, 79), false);
});

test("evaluateAlert: 'offline' compares status string", () => {
  assert.equal(transform.evaluateAlert({ comparator: "offline" }, "offline"), true);
  assert.equal(transform.evaluateAlert({ comparator: "offline" }, "online"), false);
  assert.equal(transform.evaluateAlert({ comparator: "offline" }, "stale"), false);
});

// ── sha256Hex(text) -> string ───────────────────────────────────────────────
test("sha256Hex: known vector for 'abc'", () => {
  assert.equal(
    transform.sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("sha256Hex: known vector for empty string", () => {
  assert.equal(
    transform.sha256Hex(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
});
