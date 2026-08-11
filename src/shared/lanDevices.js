'use strict';

// Vigilant — what a host ON A SITE LAN is, and which ports it is administered on.
//
// ONE definition, required from both the inventory API (GET /sites/:code/devices) and the
// relay's target validation, because "a printer" in the picker and "a printer" the server
// will proxy to must be the same rule. Pure functions, no IO, no deps.
//
// The input is a vigilant.mac_hosts row: `vendor` is the OUI-registry registrant string the
// ingest already resolved ("Brother Industries, LTD.", "HEWLETT PACKARD"), and `hostname` is
// the DHCP lease host-name. Vendor is authoritative — an OUI is burned into the NIC, whereas
// a hostname is whatever DHCP happened to record — so vendor is matched FIRST and hostname is
// only a fallback for kit whose OUI belongs to a generic embedded-NIC maker.

// Substrings of the registrant name, lower-cased, NOT exact values: the registry writes the
// same company a dozen ways ("HP Inc.", "Hewlett Packard", "Hewlett-Packard Company").
//
// 'hp' alone is deliberately absent — a two-letter substring collides with unrelated
// registrants — so HP is matched by the forms the registry actually uses.
const PRINTER_VENDOR_SUBSTRINGS = [
  'brother',
  'hewlett',
  'packard',
  'hp inc',
  'kyocera',
  'ricoh',
  'canon',
  'epson',
  'seiko epson',
  'lexmark',
  'xerox',
  'sharp',
  'konica',
  'minolta',
];

// Checked BEFORE the phone list: Meraki registers under "Cisco Meraki", and the whole line is
// access points, switches and cameras — never a handset. 7 rows in the estate today and growing
// with every WiFi refresh, so it is worth naming rather than tolerating.
const NOT_PHONE_VENDOR_SUBSTRINGS = ['meraki'];

// NB: 'cisco' matches Cisco SWITCHES as well as Cisco phones, and 'panasonic' matches
// Panasonic anything. That is accepted rather than fixed: `kind` only decides which admin
// ports we suggest, and every candidate port is inside the relay's fixed port allowlist, so
// a mis-labelled switch cannot be reached anywhere a phone could not.
const PHONE_VENDOR_SUBSTRINGS = [
  'yealink',
  'polycom',
  'grandstream',
  'snom',
  'fanvil',
  'gigaset',
  'cisco',
  'avaya',
  'mitel',
  'panasonic',
];

// Factory-default DHCP host-names. Anchored at the start because these are PREFIXES the
// vendor's firmware generates (Brother BRN30055C…, HP NPI…, Ricoh RNP…, Kyocera KM…), and an
// unanchored match on two or three letters would sweep up half a LAN.
const PRINTER_HOSTNAME_RE =
  /^(brn|bru|npi|nph|rnp|km[0-9]|kyo|lex|epson|canon|brother|ricoh|xerox|sharp|konica|star|bixolon|pos-?print)/;
// Substring (not prefix) match for names an operator or the firmware spells out in full.
const PRINTER_HOSTNAME_CONTAINS = /(printer|mfp|laserjet|officejet|deskjet|imagerunner|-prn|prn-)/;

const PHONE_HOSTNAME_RE = /^(yealink|snom|fanvil|grandstream|gxp|gxv|polycom|spip|cp-[0-9]|sep[0-9a-f]{12})/;
// 'phone' needs a preceding non-letter. Every DHCP lease named "iPhone" on a site's guest WiFi
// matched a bare /phone/ — 7 of 29 hosts at the first site checked — which would have filled the
// picker's phone category with mobiles nobody administers.
const PHONE_HOSTNAME_CONTAINS = /(handset|deskphone|voip|-sip|sip-|(?:^|[^a-z])phone)/;

// The ONLY ports a relay session may target. Deliberately tiny: an embedded admin UI lives on
// one of these four, and anything wider turns the Pi into a port scanner with a web front end.
const RELAY_PORTS = Object.freeze([80, 443, 8080, 8443]);

// Candidate admin ports per kind, in PROBE ORDER — the UI offers the first and falls back.
// Phones lead with 443 because current Yealink/Fanvil/Grandstream firmware ships HTTPS-only
// and 80 either refuses or 301s straight to it; printers' embedded servers are still
// overwhelmingly plain 80. Every entry is a member of RELAY_PORTS, checked by the test below,
// so the ports a UI offers can never drift from the ports the relay accepts.
const PORTS_BY_KIND = Object.freeze({
  printer: Object.freeze([80, 443, 8080, 8443]),
  phone: Object.freeze([443, 80, 8443, 8080]),
  other: Object.freeze([80, 443, 8080, 8443]),
});

function lower(v) {
  return v == null ? '' : String(v).toLowerCase();
}

function hasAny(haystack, needles) {
  for (const n of needles) if (haystack.includes(n)) return true;
  return false;
}

/**
 * Classify one LAN host into 'printer' | 'phone' | 'other'.
 * @param {{vendor?: ?string, hostname?: ?string, comment?: ?string}} host  a mac_hosts row
 * @returns {'printer'|'phone'|'other'}
 */
function classifyHost(host) {
  const h = host || {};
  const vendor = lower(h.vendor);
  if (vendor) {
    if (hasAny(vendor, PRINTER_VENDOR_SUBSTRINGS)) return 'printer';
    if (!hasAny(vendor, NOT_PHONE_VENDOR_SUBSTRINGS) && hasAny(vendor, PHONE_VENDOR_SUBSTRINGS)) {
      return 'phone';
    }
  }
  // Hostname fallback, for a device whose OUI belongs to the embedded-NIC maker rather than
  // the brand on the case. The operator's DHCP comment is searched too — on these sites it is
  // where a human has written "counter printer" — but only for the spelled-out forms, never
  // the vendor prefixes, which are meaningless in free text.
  const name = lower(h.hostname);
  if (name) {
    if (PRINTER_HOSTNAME_RE.test(name) || PRINTER_HOSTNAME_CONTAINS.test(name)) return 'printer';
    if (PHONE_HOSTNAME_RE.test(name) || PHONE_HOSTNAME_CONTAINS.test(name)) return 'phone';
  }
  const comment = lower(h.comment);
  if (comment) {
    if (PRINTER_HOSTNAME_CONTAINS.test(comment)) return 'printer';
    if (PHONE_HOSTNAME_CONTAINS.test(comment)) return 'phone';
  }
  return 'other';
}

/**
 * Candidate admin ports for a kind, in probe order.
 * @param {string} kind
 * @returns {number[]}
 */
function portsForKind(kind) {
  const list = PORTS_BY_KIND[kind] || PORTS_BY_KIND.other;
  return list.slice();
}

/**
 * Is this a port the relay may open a session to?
 * @param {*} port
 * @returns {boolean}
 */
function isRelayPort(port) {
  const n = Number(port);
  return Number.isInteger(n) && RELAY_PORTS.includes(n);
}

// The Pi fetches the target with this scheme. Derived from the port rather than configured:
// an admin UI on 443/8443 is TLS (self-signed, which is why the Pi must not verify), and one
// on 80/8080 is not. Keeping the derivation here means the server's session record, the
// directive it hands the Pi and any future consumer agree.
function schemeForPort(port) {
  const n = Number(port);
  return n === 443 || n === 8443 ? 'https' : 'http';
}

module.exports = {
  RELAY_PORTS,
  PORTS_BY_KIND,
  classifyHost,
  portsForKind,
  isRelayPort,
  schemeForPort,
};
