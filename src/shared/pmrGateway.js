'use strict';

// Render the dnsmasq drop-in for ONE pharmacy leg on the PMR desktop gateway (VM 300) from its
// Site Configurator registry row. Pure and deterministic: the same row always produces the same
// bytes, so a checksum over the output is a stable identity for a config-push job.
//
// The gateway (VM 300) is a Debian box running one dnsmasq that serves every pharmacy leg. Each
// site gets its own file at /etc/dnsmasq.d/pmr-<code>.conf; dnsmasq matches each dhcp-range to
// the interface whose subnet it falls in, so listing every site's range in one dnsmasq is safe.
//
// What this does NOT emit: dhcp-host (MAC reservations) — the registry does not hold device MACs,
// and the counter desktops are statically addressed in-guest, not by DHCP. It also does not touch
// nftables or interface addresses; those are the leg's structural setup, owned by the provisioning
// runbook, not by an editable-settings push.

// prefix (0–32) → dotted-quad netmask. /27 → 255.255.255.224.
function prefixToNetmask(prefix) {
  const p = Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > 32) throw new Error(`bad prefix: ${prefix}`);
  const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
  return [24, 16, 8, 0].map((s) => (mask >>> s) & 0xff).join('.');
}

// The per-site drop-in filename. Lower-cased code so the path is stable regardless of how the
// operator typed it.
function siteDnsmasqFilename(code) {
  return `pmr-${String(code || '').trim().toLowerCase()}.conf`;
}

// Split a comma-separated DNS list into clean entries.
function dnsList(value, fallback) {
  const parts = String(value == null || value === '' ? (fallback || '') : value)
    .split(',').map((s) => s.trim()).filter(Boolean);
  return parts;
}

// Render the dnsmasq drop-in text for one pharmacy. Throws if the row is missing the addressing
// the file cannot be written without — the caller surfaces that rather than pushing a half-file.
function renderSiteDnsmasq(pharmacy) {
  const p = pharmacy || {};
  const idx = Number(p.idx);
  const code = String(p.code || '').trim();
  if (!Number.isInteger(idx) || idx < 1) throw new Error('pharmacy.idx is required');
  if (!code) throw new Error('pharmacy.code is required');

  const prefix = Number(p.prefix_len) || 24;
  const netmask = prefixToNetmask(prefix);
  const tag = `pmr${idx}`;
  const network = `10.200.${idx}.0`;
  const gateway = String(p.gateway_ip || `10.200.${idx}.1`).trim();
  const from = String(p.dhcp_from || '').trim();
  const to = String(p.dhcp_to || '').trim();
  if (!from || !to) throw new Error('pharmacy dhcp_from/dhcp_to are required');
  const lease = String(p.lease_time || '12h').trim();
  const domain = String(p.domain || '').trim();
  const ntp = String(p.ntp_server || '').trim();
  const server = String(p.server_ip || '').trim();
  const dns = dnsList(p.dns_servers, gateway);

  const lines = [];
  lines.push(`# Vigilant-managed — pharmacy ${code}${p.name ? ` (${p.name})` : ''}, idx ${idx}, vlan ${p.vlan || 100 + idx}.`);
  lines.push('# DO NOT EDIT BY HAND — source of truth is the Site Configurator; applied by pmr-gateway-agent.');
  lines.push('');
  lines.push(`dhcp-range=set:${tag},${from},${to},${netmask},${lease}`);
  lines.push(`dhcp-option=tag:${tag},option:router,${gateway}`);
  if (dns.length) lines.push(`dhcp-option=tag:${tag},option:dns-server,${dns.join(',')}`);
  if (domain) {
    lines.push(`dhcp-option=tag:${tag},option:domain-name,${domain}`);
    // Scope the local domain to this leg's subnet so pmr-<code>-srv resolves unqualified.
    lines.push(`domain=${domain},${network}/${prefix}`);
  }
  if (ntp) lines.push(`dhcp-option=tag:${tag},option:ntp-server,${ntp}`);
  if (server) lines.push(`address=/pmr-${code.toLowerCase()}-srv/${server}`);
  return lines.join('\n') + '\n';
}

// Render every site into a manifest of drop-in files for the gateway agent to write. Skips
// decommissioned sites (their file should be removed) and any row that cannot render (missing
// addressing) — those are reported in `skipped` rather than aborting the whole manifest, so one
// half-set-up site never blocks a push for all the others.
function renderAllSites(pharmacies) {
  const files = [];
  const skipped = [];
  for (const p of pharmacies || []) {
    if (p && p.status === 'decommissioned') { skipped.push({ code: p.code, reason: 'decommissioned' }); continue; }
    try {
      files.push({ code: p.code, filename: siteDnsmasqFilename(p.code), config: renderSiteDnsmasq(p) });
    } catch (e) {
      skipped.push({ code: p && p.code, reason: e.message });
    }
  }
  // Deterministic order so a checksum over the manifest is stable.
  files.sort((a, b) => a.filename.localeCompare(b.filename));
  return { files, skipped };
}

module.exports = { prefixToNetmask, siteDnsmasqFilename, dnsList, renderSiteDnsmasq, renderAllSites };
