# Vigilant — telemetry catalogue (what we can pull from RouterOS 7)

Everything below is read-only and safe to poll. Grouped by subsystem, with the exact
ROS7 command and the fields worth storing. Cadence column: **fast** = every agent tick
(~10s), **slow** = every few minutes, **rare** = daily / on-change (static identifiers).

The current 6-min script pulls maybe 5% of this (interface `running` booleans + a few
strings). The big wins are **per-port byte/error counters**, **LTE/SIM + signal**,
**PPP session detail**, **conntrack/firewall counters**, and **hardware health**.

---

## 1. System & hardware

| Source (ROS7) | Fields | Cadence |
|---|---|---|
| `/system/resource print` | `uptime`, `version`, `cpu-load`, `free-memory`/`total-memory`, `free-hdd-space`/`total-hdd-space`, `cpu`, `cpu-count`, `cpu-frequency`, `architecture-name`, `board-name`, `write-sect-total` (flash wear), `bad-blocks` | fast (load), rare (static) |
| `/system/resource/cpu print` | per-core `load`, `irq`, `disk` | slow |
| `/system/health print` | `temperature`, `cpu-temperature`, `board-temperature`, `voltage`, `fan1-speed`/`fan2-speed`, PSU state — **board-dependent, iterate the rows** | fast |
| `/system/routerboard print` | `model`, `serial-number`, `revision`, `current-firmware`, `factory-firmware`, `upgrade-firmware` (→ firmware-behind alert) | rare |
| `/system/clock print` | `time`, `date`, `time-zone-name` (clock drift / wrong-TZ detection) | slow |
| `/system/ntp/client print` | `status`, `synced-server`, `system-offset` (NTP sync health) | slow |
| `/system/package print` | installed packages + versions; scheduled to up/downgrade | rare |
| `/system/package/update check-for-updates` | `latest-version` vs `installed-version` | rare |
| `/system/license print` | `level`, `nlevel` (level-0/demo expiry risk) | rare |
| `/system/scheduler print` / `/system/script print` | `run-count`, `last-started`, failed scripts | slow |
| `/system/ups print` / `monitor` | on-line/on-battery, charge %, runtime, load (if a UPS is wired) | slow |

## 2. Interfaces — counters & link (the throughput win)

| Source | Fields | Cadence |
|---|---|---|
| `/interface print stats` (or `get` per iface) | `rx-byte`/`tx-byte`, `rx-packet`/`tx-packet`, `rx-error`/`tx-error`, `rx-drop`/`tx-drop`, `running`, `last-link-up-time`, `last-link-down-time`, `link-downs` | **fast** (cumulative counters → server derives bps) |
| `/interface/monitor-traffic <if> once` | `rx-bits-per-second`, `tx-bits-per-second`, `rx-packets-per-second`, `tx-packets-per-second` (live rate without delta math — handy for the drilldown view) | fast (drilldown only) |
| `/interface/ethernet/monitor <if> once` | `status`, `rate` (negotiated speed), `full-duplex`, `auto-negotiation`, `sfp-temperature`, `sfp-rx-power`, `sfp-tx-power`, `sfp-vendor-name`, `sfp-wavelength` (fibre diagnostics!) | slow |
| `/interface/ethernet/poe/monitor <if> once` | `poe-out-status`, `poe-out-voltage`, `poe-out-current`, `poe-out-power` (powered devices / phones) | slow |
| `/interface/bridge/host print` | MAC table — which MAC on which port | slow |

**Why counters not rates:** send cumulative `rx-byte`/`tx-byte`; the ingest computes
`bps = Δbytes·8 / Δt`. Robust across missed samples and reboots (reset guard).

## 3. LTE / SIM  ← your specific ask

**Yes — SIM identifiers and live cell/signal are all pullable.**

| Source | Fields | Cadence |
|---|---|---|
| `/interface/lte/info <if> once as-value` | `imei` (modem), `imsi` (subscriber), **`uicc` = ICCID — the long number printed on the SIM**, `subscriber-number` = MSISDN (the *phone number*, if the carrier wrote it to the SIM — often blank), `pin-status`, `registration-status`, `functionality`, `manufacturer`/`model`/`revision`, `current-operator` (MCC+MNC), `access-technology` (lte / lte-a / 5g-nsa), `session-uptime` | identifiers **rare**, signal below **fast** |
| ↑ same call, signal fields | `rssi`, `rsrp`, `rsrq`, `sinr`, `cqi`, `ri`, `earfcn`, `band`, `phy-cellid`, `lac`, `current-cellid` (eNB+cell), `sector-id` | **fast** |
| `/interface/lte print detail` | APN, `apn-profiles`, `pin`, data session state | slow |

**If `/interface/lte/info` doesn't expose a field on a given modem** (varies by Quectel
/ Telit / etc.), fall back to raw AT commands via `/interface/lte/at-chat`:

| AT command | Returns |
|---|---|
| `/interface/lte/at-chat <if> input="AT+CGSN"` | IMEI |
| `/interface/lte/at-chat <if> input="AT+CIMI"` | IMSI |
| `/interface/lte/at-chat <if> input="AT+CCID"` (or `AT+QCCID` Quectel / `AT+ICCID`) | **ICCID (SIM number)** |
| `/interface/lte/at-chat <if> input="AT+CNUM"` | MSISDN (phone number) |
| `/interface/lte/at-chat <if> input="AT+CSQ"` | signal quality |
| `/interface/lte/at-chat <if> input="AT+COPS?"` | registered operator name |

**Important cadence rule:** ICCID / IMSI / IMEI / MSISDN are *static* — collect them on
the daily bootstrap (or on-change), **not** every 10s. Hammering `at-chat` every tick can
disrupt the data session on some modems. Signal (rsrp/rsrq/sinr/rssi) is what changes —
poll that fast via `lte/info` (which is non-disruptive).

Scripting shape:
```routeros
:if ([:len [/interface/lte find]] > 0) do={
    :local li [/interface/lte/info [find] once as-value]
    :local rsrp  ($li->"rsrp");  :local rsrq ($li->"rsrq")
    :local sinr  ($li->"sinr");  :local rssi ($li->"rssi")
    :local iccid ($li->"uicc");  :local imsi ($li->"imsi")
    :local imei  ($li->"imei");  :local msisdn ($li->"subscriber-number")
    :local oper  ($li->"current-operator")
    :local cell  ($li->"current-cellid")
}
```

## 4. PPP / VPN concentrator (relevant to the SSTP/L2TP role)

| Source | Fields | Cadence |
|---|---|---|
| `/ppp/active print` | per session: `name`, `service` (sstp/l2tp/pppoe), `caller-id`, `address`, `uptime`, `encoding`, `session-id` + **total count** | fast (count), slow (list) |
| `/interface/sstp-server`, `/interface/l2tp-server` monitor | per-tunnel rx/tx, state | slow |
| `/ppp/secret print` | configured accounts, `last-logged-out`, `last-caller-id` (who hasn't dialled in) | rare |
| `/interface/pppoe-client monitor <if> once` | `status`, `uptime`, `local-address`, `remote-address`, `service-name` | fast |

## 5. Firewall / connections

| Source | Fields | Cadence |
|---|---|---|
| `/ip/firewall/connection print count-only` | live conntrack count (load/abuse signal) | fast |
| `/ip/firewall/connection/tracking print` | `total-entries`, `max-entries`, tcp state counts | slow |
| `/ip/firewall/filter print stats` (and `mangle`, `raw`, `nat`) | per-rule `bytes`/`packets` (spot a rule being hammered) | slow |
| `/ip/firewall/address-list print count-only` | dynamic list size (e.g. HSCN, EMIS lists) | slow |

## 6. DHCP / addressing / discovery

| Source | Fields | Cadence |
|---|---|---|
| `/ip/dhcp-server/lease print` | count + per-lease `address`, `mac-address`, `host-name`, `status`, `expires-after`, `last-seen` | slow |
| `/ip/pool/used print` | pool utilisation (exhaustion alert) | slow |
| `/ip/arp print count-only`, `/ip/neighbor print` | ARP count; **LLDP/CDP/MNDP neighbours → topology discovery** (what's plugged into what) | slow |
| `/ip/dns/cache print count-only` | DNS cache size | slow |
| `/ip/cloud print` | **public IP as MikroTik sees it** (great for dynamic-IP sites — authoritative WAN IP without parsing pppoe) | slow |

## 7. Routing & reachability (SLA signals)

| Source | Fields | Cadence |
|---|---|---|
| `/ip/route print count-only where active` | active route count; **default-route present?** | fast |
| `/tool/netwatch print` | up/down + latency of monitored hosts (e.g. NHS Spine, HSCN gateways) — per-target SLA | fast |
| `/routing/bgp/session print`, `/routing/ospf/neighbor print` | neighbour state, prefix counts (where dynamic routing used) | slow |
| `/tool/ping … as-value` (scripted) | RTT / loss to a target (synthetic probe from the device's vantage) | fast |

## 8. Queues / QoS

| Source | Fields | Cadence |
|---|---|---|
| `/queue/simple print stats` | per-target `bytes`, `rate`, `packet-rate`, drops | slow |
| `/queue/tree print stats` | hierarchical queue bytes/rates | slow |

## 9. Storage, certs, logs (operational health)

| Source | Fields | Cadence |
|---|---|---|
| `/disk print` | usage, SMART, temperature (if disk attached) | slow |
| `/certificate print detail` | `invalid-after` → **cert-expiry alert** (matters for SSTP server certs) | rare |
| `/log print where topics~"error\|critical"` | recent errors/criticals → surface in panel | slow |
| `/system/resource print` `write-sect-total` | flash write wear trend | rare |

## 10. Flow export (optional, heavier)

- `/ip/traffic-flow` — NetFlow/IPFIX export to a collector for per-flow top-talkers.
- `/tool/torch` — realtime top talkers (interactive; scriptable snapshot).
- `/tool/graphing` — built-in RRD graphs (lighter alternative if we ever want on-box).

---

## Recommended additions to Vigilant (priority order)

1. **Per-interface counters** — already in v1 agent. Foundation for all throughput graphs.
2. **LTE/SIM block** — signal fast, identifiers (ICCID/IMSI/IMEI/MSISDN) on bootstrap. New
   `lte_state` table (see `db/schema.sql`).
3. **Hardware health** — temperature/voltage/fan, flash wear. Cheap, high diagnostic value.
4. **PPP session count + conntrack count** — load/health of the concentrator routers.
5. **`/ip/cloud` public IP + default-route-present + netwatch** — SLA / WAN-up signals,
   especially for dynamic-IP and SIM sites.
6. **SFP/PoE diagnostics, cert expiry, firmware-behind, NTP sync** — slow-cadence
   operational alerts.

Cadence discipline keeps the load sane: most of the value is **fast** counters + signal;
the static identifiers and heavy prints run **slow/rare**.
