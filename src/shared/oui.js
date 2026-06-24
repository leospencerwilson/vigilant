'use strict';

// Vigilant — MAC OUI -> vendor lookup.
//
// The ingest fills mac_hosts.vendor from the first three octets (the OUI) of each
// learned MAC. This is a deliberately small, hand-curated seed of vendors we
// actually see on Allied / Cegedim / WCN LANs (MikroTik routers, Yealink phones,
// the usual PC/printer/AP makers). It is NOT the full IEEE registry — unknown OUIs
// return null and simply leave the column blank. Keep SEED as its own const so it
// can grow without touching the lookup logic.

// OUI keys are stored in canonical upper-case colon-separated form ("AC:CF:23").
const SEED = {
  // MikroTik (routers/switches — these ARE our fleet)
  'CC:2D:E0': 'MikroTik',
  '48:8F:5A': 'MikroTik',
  'B8:69:F4': 'MikroTik',
  '64:D1:54': 'MikroTik',
  '74:4D:28': 'MikroTik',
  'DC:2C:6E': 'MikroTik',
  '2C:C8:1B': 'MikroTik',
  '4C:5E:0C': 'MikroTik',
  'E4:8D:8C': 'MikroTik',
  '6C:3B:6B': 'MikroTik',
  // Yealink (VoIP handsets — Western Communication's bread and butter)
  'AC:CF:23': 'Yealink',
  '80:5E:C0': 'Yealink',
  '24:9A:D8': 'Yealink',
  '00:15:65': 'Yealink',
  // Hewlett Packard / HP Enterprise / Aruba
  '3C:D9:2B': 'HP',
  '70:5A:0F': 'HP',
  '94:57:A5': 'HP',
  '00:1B:78': 'HP',
  'B0:5A:DA': 'HP',
  // Dell
  '00:14:22': 'Dell',
  'B8:2A:72': 'Dell',
  'F8:BC:12': 'Dell',
  '18:DB:F2': 'Dell',
  // Cisco / Cisco Meraki
  '00:1A:A1': 'Cisco',
  '00:25:45': 'Cisco',
  'F4:CF:E2': 'Cisco',
  '00:18:0A': 'Cisco Meraki',
  'E0:55:3D': 'Cisco Meraki',
  // Ubiquiti
  '24:A4:3C': 'Ubiquiti',
  'FC:EC:DA': 'Ubiquiti',
  '74:83:C2': 'Ubiquiti',
  '78:8A:20': 'Ubiquiti',
  // TP-Link (cheap APs/switches turn up on sites)
  '50:C7:BF': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  // Printers
  '00:00:48': 'Epson',
  '00:80:77': 'Brother',
  '00:26:73': 'Canon',
  '00:1E:8F': 'Canon',
  '08:00:37': 'Fuji Xerox',
  // Apple / Samsung / Intel (common endpoints + NICs)
  'AC:BC:32': 'Apple',
  'F0:18:98': 'Apple',
  '3C:5A:B4': 'Samsung',
  'B4:79:A7': 'Samsung',
  '00:1B:21': 'Intel',
  '3C:97:0E': 'Intel',
};

/**
 * Normalise the first three octets of a MAC to the canonical OUI key form,
 * e.g. "ac-cf-23-11-22-33" / "accf23112233" -> "AC:CF:23". Returns null unless at
 * least 6 hex digits (3 octets) are present. Separator- and case-insensitive.
 */
function ouiKey(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length < 6) return null;
  const up = hex.slice(0, 6).toUpperCase();
  return up.slice(0, 2) + ':' + up.slice(2, 4) + ':' + up.slice(4, 6);
}

/**
 * ouiVendor(mac) -> vendor string | null
 * Looks up the vendor for a MAC's OUI in SEED. Case- and separator-insensitive.
 * Unknown OUI (or unparseable MAC) -> null.
 */
function ouiVendor(mac) {
  const key = ouiKey(mac);
  if (key === null) return null;
  return Object.prototype.hasOwnProperty.call(SEED, key) ? SEED[key] : null;
}

module.exports = {
  ouiVendor,
  SEED,
};
