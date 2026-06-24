// Tests for the OUI -> vendor lookup (docs/CONTRACT.md §oui.js: "seed map + lookup fn").
// The ingest fills mac_hosts.vendor from this. Lookup must be case/separator-insensitive
// over the first three octets (the OUI).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const oui = require("../src/shared/oui");

// MikroTik is the whole fleet here, so its OUI is the safest "known" seed entry.
// 4C:5E:0C is a registered MikroTik / Routerboard.com prefix.
const MIKROTIK_OUI = "4C:5E:0C";

test("ouiVendor: known OUI -> a vendor string", () => {
  const v = oui.ouiVendor(MIKROTIK_OUI + ":11:22:33");
  assert.equal(typeof v, "string");
  assert.ok(v.length > 0, "vendor should be a non-empty string");
  assert.match(v.toLowerCase(), /mikrotik/);
});

test("ouiVendor: unknown OUI -> null", () => {
  // Locally-administered / unassigned prefix that no real vendor seed would contain.
  assert.equal(oui.ouiVendor("02:00:00:DE:AD:BE"), null);
});

test("ouiVendor: case-insensitive", () => {
  const upper = oui.ouiVendor("4C:5E:0C:AA:BB:CC");
  const lower = oui.ouiVendor("4c:5e:0c:aa:bb:cc");
  assert.equal(lower, upper);
  assert.ok(upper, "uppercase form should resolve");
});

test("ouiVendor: separator-insensitive (colon / dash / dot / none)", () => {
  const expected = oui.ouiVendor("4C:5E:0C:AA:BB:CC");
  assert.equal(oui.ouiVendor("4C-5E-0C-AA-BB-CC"), expected);
  assert.equal(oui.ouiVendor("4c5e.0caa.bbcc"), expected);
  assert.equal(oui.ouiVendor("4C5E0CAABBCC"), expected);
});

test("ouiVendor: bare 3-octet OUI also resolves", () => {
  assert.match(String(oui.ouiVendor("4C:5E:0C")).toLowerCase(), /mikrotik/);
});

test("ouiVendor: empty / invalid input -> null", () => {
  assert.equal(oui.ouiVendor(""), null);
  assert.equal(oui.ouiVendor(null), null);
  assert.equal(oui.ouiVendor(undefined), null);
});
