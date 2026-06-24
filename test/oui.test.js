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

// ── resolveVendor (seed -> cache -> external API), per OUI LOOKUP API CONTRACT ───────────
// These tests NEVER hit the real network: the only external call (resolveVendor's third tier)
// is exercised by monkeypatching global.fetch within the test and restoring it after.

// An OUI we know the seed does NOT contain, so resolveVendor falls through to the API tier.
// 02:* is locally-administered and not in SEED.
const UNKNOWN_OUI = "02:AB:CD";

// Restore global.fetch + clear the module cache after each API-touching test so cases don't
// leak a stub or a cached prefix into one another.
function withStubbedFetch(stub, fn) {
  const original = global.fetch;
  oui._cache.clear();
  global.fetch = stub;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (original === undefined) delete global.fetch;
      else global.fetch = original;
      oui._cache.clear();
    });
}

test("resolveVendor: normalises mac to upper-case colon form (seed hit)", async () => {
  // lower-case, hyphen-separated, but a known MikroTik prefix -> seed hit + canonical mac.
  const r = await oui.resolveVendor("4c-5e-0c-aa-bb-cc");
  assert.equal(r.mac, "4C:5E:0C:AA:BB:CC");
  assert.equal(r.oui, "4C:5E:0C");
  assert.match(String(r.vendor).toLowerCase(), /mikrotik/);
  assert.equal(r.source, "seed");
});

test("resolveVendor: seed hit returns source 'seed' and never calls fetch", async () => {
  let called = false;
  await withStubbedFetch(
    async () => {
      called = true;
      throw new Error("fetch must NOT be called for a seed hit");
    },
    async () => {
      const r = await oui.resolveVendor(MIKROTIK_OUI + ":11:22:33");
      assert.equal(r.source, "seed");
      assert.match(String(r.vendor).toLowerCase(), /mikrotik/);
      assert.equal(called, false, "seed tier must short-circuit before the API");
    }
  );
});

test("resolveVendor: unknown prefix hits stubbed API (source 'api'); second call is 'cache' with NO second fetch", async () => {
  let fetchCount = 0;
  await withStubbedFetch(
    async (url) => {
      fetchCount += 1;
      // PRIVACY: only the 3-octet prefix may be sent — never the full MAC's host octets.
      assert.ok(
        String(url).endsWith(encodeURIComponent(UNKNOWN_OUI)),
        `external URL must carry ONLY the OUI prefix, got: ${url}`
      );
      return { ok: true, status: 200, async text() { return "Acme Networks\n"; } };
    },
    async () => {
      const first = await oui.resolveVendor(UNKNOWN_OUI + ":DE:AD:BE");
      assert.equal(first.vendor, "Acme Networks");
      assert.equal(first.source, "api");
      assert.equal(first.oui, UNKNOWN_OUI);
      assert.equal(fetchCount, 1);

      // A second lookup of the SAME prefix (different host octets) must come from cache.
      const second = await oui.resolveVendor(UNKNOWN_OUI + ":99:88:77");
      assert.equal(second.vendor, "Acme Networks");
      assert.equal(second.source, "cache");
      assert.equal(fetchCount, 1, "second call must NOT re-hit the API (rate-limit respect)");
    }
  );
});

test("resolveVendor: a stubbed 404 caches the miss as vendor:null source:'none'", async () => {
  let fetchCount = 0;
  await withStubbedFetch(
    async () => {
      fetchCount += 1;
      return { ok: false, status: 404, async text() { return ""; } };
    },
    async () => {
      const first = await oui.resolveVendor(UNKNOWN_OUI + ":01:02:03");
      assert.equal(first.vendor, null);
      assert.equal(first.source, "none");

      // The MISS is cached too, so an unknown prefix never re-hits the rate-limited API.
      const second = await oui.resolveVendor(UNKNOWN_OUI + ":04:05:06");
      assert.equal(second.vendor, null);
      assert.equal(second.source, "cache");
      assert.equal(fetchCount, 1, "a cached miss must not re-fetch");
    }
  );
});

test("resolveVendor: fetch throwing (network error/timeout) -> vendor:null source:'none', never throws", async () => {
  await withStubbedFetch(
    async () => {
      // Simulate an aborted/timed-out or offline fetch by rejecting.
      const err = new Error("The operation was aborted");
      err.name = "AbortError";
      throw err;
    },
    async () => {
      const r = await oui.resolveVendor(UNKNOWN_OUI + ":AA:BB:CC");
      assert.equal(r.vendor, null);
      assert.equal(r.source, "none");
      assert.equal(r.oui, UNKNOWN_OUI);
    }
  );
});

test("resolveVendor: invalid mac (no resolvable OUI) -> source 'none', oui null", async () => {
  const r = await oui.resolveVendor("xyz");
  assert.equal(r.oui, null);
  assert.equal(r.vendor, null);
  assert.equal(r.source, "none");
});
