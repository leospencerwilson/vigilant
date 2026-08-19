# PMR desktop gateway agent

Applies the pharmacy network settings from the **Site Configurator** to the real dnsmasq on
**VM 300 (`pmr-desktop-gateway`)**. This is the "push" end of the editable per-VLAN settings: an
operator edits DNS / DHCP / domain / lease / NTP / subnet in Watchman, and this agent renders
those into `/etc/dnsmasq.d/pmr-<code>.conf` on the gateway and reloads dnsmasq.

## How it works

```
Site Configurator (registry)  ──►  GET /gateway/dnsmasq  ──►  pmr-gateway-agent.sh on VM 300
   (pharmacies table)              (rendered drop-ins,          writes /etc/dnsmasq.d/pmr-*.conf
                                    one per site, + sha256)      dnsmasq --test → reload
```

- **Pull, not push.** The gateway polls Vigilant on a 2-minute timer. Nothing outside VM 300 can
  write to it.
- **Idempotent.** Files are only rewritten when their bytes change; dnsmasq is only reloaded when
  something actually changed.
- **Fail-safe.** A rendered set is applied to a staging copy and validated with `dnsmasq --test`
  before reload. If it fails, the previous files are restored and dnsmasq is left untouched — a
  bad edit can never take DNS/DHCP down. (Nothing is in production on the virtual desktops yet, so
  this is belt-and-braces rather than protecting live dispensing — but it costs nothing.)
- **Scoped.** It owns only files matching `pmr-*.conf`; anything else in `/etc/dnsmasq.d` is left
  alone. Sites deleted from the registry have their drop-in removed.

## Addressing it renders

Each pharmacy index `N` → `10.200.N.0/<prefix>` (default `/27`): gateway `.1`, PMR server `.10`,
counter desktops `.(10+n)`, DHCP pool `.21–.30`. The `10.200.0.0/16` block keeps pharmacy LANs
clear of the `10.10.x` VLAN/NHS space and the `10.255.x` WireGuard transit.

## Install on VM 300

1. **Mint a scoped pull token** and set it in Vigilant's environment, then redeploy ingest:
   ```
   GATEWAY_PULL_TOKEN=<a long random hex string>
   ```
   (The estate master `ENROLL_TOKEN` also authenticates the endpoint, but use the scoped one so
   the gateway never holds the master key.)

2. **On VM 300**, install deps and the agent:
   ```bash
   apt-get install -y curl jq          # dnsmasq is already present
   install -m 0755 pmr-gateway-agent.sh /usr/local/sbin/pmr-gateway-agent.sh
   install -m 0644 pmr-gateway-agent.service /etc/systemd/system/
   install -m 0644 pmr-gateway-agent.timer   /etc/systemd/system/
   ```

3. **Write `/etc/pmr-gateway-agent.env`** (root-only, `chmod 600`):
   ```
   VIGILANT_URL=https://vigilant.western-communication.com
   GATEWAY_PULL_TOKEN=<the same token as step 1>
   ```

4. **Ensure dnsmasq reads the drop-in dir.** `/etc/dnsmasq.conf` must contain
   `conf-dir=/etc/dnsmasq.d,*.conf` (Debian's default). The per-site files rely on dnsmasq
   matching each `dhcp-range` to the interface whose subnet it belongs to, so no `interface=`
   line is emitted per site.

5. **Dry-run once, then enable the timer:**
   ```bash
   /usr/local/sbin/pmr-gateway-agent.sh      # first run: writes files, dnsmasq --test, reload
   systemctl daemon-reload
   systemctl enable --now pmr-gateway-agent.timer
   journalctl -u pmr-gateway-agent.service -f
   ```

## Preview without applying

The Site Configurator's edit pane has a **"Show gateway config"** button (per site), and the API
exposes it directly:

```
GET /pharmacies/<id-or-code>/gateway-config     # one site, admin-authed
GET /gateway/dnsmasq                            # whole fleet manifest, gateway-token-authed
```

Both render the exact bytes the agent writes, so you can diff before enabling the timer.

## Scope / not included

This agent owns **dnsmasq** (DHCP + DNS + options) only. Interface addresses, VLAN sub-interfaces
and the **nftables** ruleset are the leg's structural setup and remain owned by the
provisioning runbook — they are not driven by the editable-settings push.
