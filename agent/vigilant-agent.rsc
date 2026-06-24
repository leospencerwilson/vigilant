# Vigilant agent — DRAFT. REVIEW BEFORE APPLYING TO ANY LIVE ROUTER.
# RouterOS 7.x. This is the rewritten replacement for the current 6-minute push script.
#
# What it does each tick (default every 10s, driven by the scheduler):
#   1. Collect a rich snapshot: system/health, per-interface CUMULATIVE counters
#      (the server computes bps from deltas — we do NOT compute rates here),
#      WAN/PPP/Wi-Fi/DHCP state.
#   2. POST it to Vigilant ingest with this device's OWN bearer token.
#   3. Read the response for control (fast-poll window) and a pending config job.
#   4. If a config job is present + approved + checksum matches: apply it SAFELY
#      (pre-snapshot + dead-man's-switch rollback + Safe-Mode import), then report.
#
# IMPORTANT changes vs the old script:
#   * NO secrets in the payload. The old script sent the PPPoE password — removed.
#   * Per-device token, not a shared X-API-Key.
#   * Real per-port byte/packet/error/drop counters → enables throughput graphs.
#
# Globals (set once at enrolment by bootstrap / provisioning):
#   :global vigilantUrl   "https://vigilant.western-communication.com"
#   :global vigilantToken "<PER-DEVICE-ENROLMENT-TOKEN>"

:global vigilantUrl
:global vigilantToken

# Tick counter — lets us run heavy/large collections on a slower cadence than the
# 10s fast tick. The MAC/ARP host tables can be large on a busy LAN, so we only
# gather them every ~30 ticks (~5 min). Survives between runs as a global.
:global vigilantTick
:if ([:typeof $vigilantTick] = "nothing") do={ :set vigilantTick 0 }
:set vigilantTick ($vigilantTick + 1)
:local doSlow false
:if (($vigilantTick % 30) = 0) do={ :set doSlow true }

# ── identity / system ───────────────────────────────────────────────
:local serial    "unknown"; :do { :set serial    [/system routerboard get serial-number] } on-error={}
:local identity  "unknown"; :do { :set identity  [/system identity get name] } on-error={}
:local uptime    "0";       :do { :set uptime    [/system resource get uptime] } on-error={}
:local cpuLoad   "0";       :do { :set cpuLoad   [/system resource get cpu-load] } on-error={}
:local freeMem   "0";       :do { :set freeMem   [/system resource get free-memory] } on-error={}
:local totMem    "0";       :do { :set totMem    [/system resource get total-memory] } on-error={}
:local freeHdd   "0";       :do { :set freeHdd   [/system resource get free-hdd-space] } on-error={}
:local rosVer    "0";       :do { :set rosVer    [/system resource get version] } on-error={}

# Health — board-dependent; guard each. (Iterating /system/health rows also works.)
:local temp     "null"; :do { :set temp     [/system health get [find name="temperature"] value] } on-error={}
:local cpuTemp  "null"; :do { :set cpuTemp  [/system health get [find name="cpu-temperature"] value] } on-error={}
:local brdTemp  "null"; :do { :set brdTemp  [/system health get [find name="board-temperature"] value] } on-error={}
:local volt     "null"; :do { :set volt     [/system health get [find name="voltage"] value] } on-error={}
:local fan1     "null"; :do { :set fan1     [/system health get [find name="fan1-speed"] value] } on-error={}
:local writeSect "0";   :do { :set writeSect [/system resource get write-sect-total] } on-error={}

# Firmware-behind + NTP sync (cheap operational signals)
:local fwCur "null"; :do { :set fwCur [/system routerboard get current-firmware] } on-error={}
:local fwUpg "null"; :do { :set fwUpg [/system routerboard get upgrade-firmware] } on-error={}
:local ntpSynced "false"; :do { :if ([/system ntp client get status] = "synchronized") do={ :set ntpSynced "true" } } on-error={}

# ── LTE / SIM (only if an LTE interface exists) ──────────────────────
# Signal fields update every tick. Identifiers (ICCID/IMSI/IMEI/MSISDN) are STATIC —
# we read them via lte/info here, but if missing fall back to at-chat sparingly (see
# docs/TELEMETRY-CATALOGUE.md §3 — at-chat every tick can disrupt the data session).
:local lteJson "null"
:if ([:len [/interface/lte find]] > 0) do={
    :do {
        :local lif [/interface/lte find]
        :local ln  [/interface/lte get [:pick $lif 0] name]
        :local li  [/interface/lte/info $ln once as-value]
        :local g do={ :local v ($1->$2); :if ([:typeof $v] = "nothing") do={ :return "" }; :return $v }
        :set lteJson ("{\"interface\":\"" . $ln . "\"" . \
            ",\"iccid\":\"" .  [$g $li "uicc"] . "\"" . \
            ",\"imsi\":\"" .   [$g $li "imsi"] . "\"" . \
            ",\"imei\":\"" .   [$g $li "imei"] . "\"" . \
            ",\"msisdn\":\"" . [$g $li "subscriber-number"] . "\"" . \
            ",\"operator\":\"" . [$g $li "current-operator"] . "\"" . \
            ",\"registration\":\"" . [$g $li "registration-status"] . "\"" . \
            ",\"access_tech\":\"" . [$g $li "access-technology"] . "\"" . \
            ",\"band\":\"" .  [$g $li "band"] . "\"" . \
            ",\"cell_id\":\"" . [$g $li "current-cellid"] . "\"" . \
            ",\"rssi\":\"" .  [$g $li "rssi"] . "\"" . \
            ",\"rsrp\":\"" .  [$g $li "rsrp"] . "\"" . \
            ",\"rsrq\":\"" .  [$g $li "rsrq"] . "\"" . \
            ",\"sinr\":\"" .  [$g $li "sinr"] . "\"}")
    } on-error={ :log warning "vigilant-agent: lte/info read failed" }
}

# WAN / routing (public IP only — NEVER the password)
:local publicIp "null"
:do { :local ic [/ip cloud get public-address]; :if ([:len $ic] > 0) do={ :set publicIp $ic } } on-error={}
:if ($publicIp = "null") do={
    :local pe [/ip address find interface="pppoe-out1"]
    :if ([:len $pe] > 0) do={ :set publicIp [/ip address get [:pick $pe 0] address] }
}
:local pppoeUp "false"
:if ([:len [/interface find name="pppoe-out1"]] > 0) do={ :set pppoeUp [/interface get [find name="pppoe-out1"] running] }
:local pppSessions [:len [/ppp active find]]
:local dhcpLeases  [:len [/ip dhcp-server lease find]]

# ── WAN detection ────────────────────────────────────────────────────
# A port is WAN if: it's the physical interface a pppoe-client dials over, OR it
# carries the active default route, OR it's a dhcp-client iface that adds a default
# route. Names are space-wrapped so the membership test can't false-match (ether1/ether10).
:local wanList " "
:foreach p in=[/interface pppoe-client find] do={
    :do { :set wanList ($wanList . [/interface pppoe-client get $p interface] . " " . [/interface pppoe-client get $p name] . " ") } on-error={}
}
:foreach r in=[/ip route find dst-address="0.0.0.0/0" active=yes] do={
    :do {
        :local gi [/ip route get $r immediate-gw]
        :if ([:typeof [:find $gi "%"]] != "nothing") do={ :set wanList ($wanList . [:pick $gi ([:find $gi "%"]+1) [:len $gi]] . " ") }
    } on-error={}
}
:foreach d in=[/ip dhcp-client find] do={
    :do { :if ([/ip dhcp-client get $d add-default-route] = "yes") do={ :set wanList ($wanList . [/ip dhcp-client get $d interface] . " ") } } on-error={}
}

# ── per-interface: counters + link + role + bridge membership ─────────
# Cumulative counters (ingest derives bps); plugged/speed/duplex from ethernet/monitor;
# bridge membership; is_wan from the list above. The ingest classifies `role`.
:local ifaces "["
:local first true
:foreach i in=[/interface find] do={
    :local nm  [/interface get $i name]
    :local tp  [/interface get $i type]
    :local run "false"; :do { :set run [/interface get $i running] } on-error={}
    :local dis "false"; :do { :set dis [/interface get $i disabled] } on-error={}
    :local rb 0; :local tb 0; :local rp 0; :local tp2 0
    :do { :set rb [/interface get $i rx-byte] }   on-error={}
    :do { :set tb [/interface get $i tx-byte] }   on-error={}
    :do { :set rp [/interface get $i rx-packet] } on-error={}
    :do { :set tp2 [/interface get $i tx-packet] } on-error={}
    # bridge membership
    :local br ""
    :do { :local bp [/interface bridge port find interface=$nm]; :if ([:len $bp] > 0) do={ :set br [/interface bridge port get [:pick $bp 0] bridge] } } on-error={}
    # physical link details (ethernet only)
    :local plugged $run
    :local rate ""
    :local fd "null"
    :if ($tp = "ether") do={
        :do {
            :local em [/interface ethernet monitor $nm once as-value]
            :set plugged (($em->"status") = "link-ok")
            :set rate ($em->"rate")
            :if ([:typeof ($em->"full-duplex")] != "nothing") do={ :set fd ($em->"full-duplex") }
        } on-error={}
    }
    # WAN?
    :local isWan false
    :if ([:typeof [:find $wanList (" " . $nm . " ")]] != "nothing") do={ :set isWan true }
    :if (!$first) do={ :set ifaces ($ifaces . ",") }
    :set first false
    :set ifaces ($ifaces . "{\"name\":\"" . $nm . "\",\"type\":\"" . $tp . \
        "\",\"running\":" . $run . ",\"disabled\":" . $dis . ",\"plugged\":" . $plugged . \
        ",\"speed\":\"" . $rate . "\",\"full_duplex\":" . $fd . ",\"bridge\":\"" . $br . "\"" . \
        ",\"is_wan\":" . $isWan . ",\"rx_byte\":" . $rb . ",\"tx_byte\":" . $tb . \
        ",\"rx_packet\":" . $rp . ",\"tx_packet\":" . $tp2 . "}")
}

# ── neighbours (what's plugged into each port, where it advertises) ──
# LLDP/CDP/MNDP. For endpoints that don't advertise, the ingest can fall back to the
# bridge host MAC table. NOTE: identity/platform are vendor-supplied free text — the
# INGEST must JSON-escape these defensively (a stray quote here would break the doc).
:local nbrs "["
:local nf true
:foreach n in=[/ip neighbor find] do={
    :do {
        :local nif [/ip neighbor get $n interface]
        :local nid [/ip neighbor get $n identity]
        :local nmac [/ip neighbor get $n mac-address]
        :local nip [/ip neighbor get $n address]
        :local npl [/ip neighbor get $n platform]
        :if (!$nf) do={ :set nbrs ($nbrs . ",") }
        :set nf false
        :set nbrs ($nbrs . "{\"interface\":\"" . $nif . "\",\"identity\":\"" . $nid . \
            "\",\"mac\":\"" . $nmac . "\",\"address\":\"" . $nip . "\",\"platform\":\"" . $npl . "\"}")
    } on-error={}
}
:set nbrs ($nbrs . "]")

# ── L2 host fallback (slow cadence) ──────────────────────────────────
# Endpoints that don't advertise LLDP/CDP still show up here: the bridge host table
# maps a MAC to the physical port it was learned on; ARP adds the IP. The ingest joins
# them by MAC and does the OUI→vendor lookup. `null` on fast ticks = "keep previous".
:local macHosts "null"
:local arpList  "null"
:if ($doSlow) do={
    :set macHosts "["
    :local mf true
    :do {
        :foreach h in=[/interface bridge host find local=no] do={
            :do {
                :local hm [/interface bridge host get $h mac-address]
                :local hi [/interface bridge host get $h interface]
                :if (!$mf) do={ :set macHosts ($macHosts . ",") }
                :set mf false
                :set macHosts ($macHosts . "{\"mac\":\"" . $hm . "\",\"interface\":\"" . $hi . "\"}")
            } on-error={}
        }
    } on-error={}
    :set macHosts ($macHosts . "]")
    :set arpList "["
    :local af true
    :do {
        :foreach a in=[/ip arp find] do={
            :do {
                :local am [/ip arp get $a mac-address]
                :local aa [/ip arp get $a address]
                :if (([:len $am] > 0) && ([:len $aa] > 0)) do={
                    :if (!$af) do={ :set arpList ($arpList . ",") }
                    :set af false
                    :set arpList ($arpList . "{\"mac\":\"" . $am . "\",\"ip\":\"" . $aa . "\"}")
                }
            } on-error={}
        }
    } on-error={}
    :set arpList ($arpList . "]")
}
:set ifaces ($ifaces . "]")

# ── assemble payload ─────────────────────────────────────────────────
:local body "{\
\"serial\":\"$serial\",\"identity\":\"$identity\",\"uptime\":\"$uptime\",\
\"cpu_load\":$cpuLoad,\"free_memory\":$freeMem,\"total_memory\":$totMem,\"free_hdd\":$freeHdd,\
\"ros_version\":\"$rosVer\",\"temperature\":$temp,\"cpu_temperature\":$cpuTemp,\
\"board_temperature\":$brdTemp,\"voltage\":$volt,\"fan1_speed\":$fan1,\
\"write_sect_total\":$writeSect,\"firmware_current\":\"$fwCur\",\"firmware_upgrade\":\"$fwUpg\",\
\"ntp_synced\":$ntpSynced,\"public_ip\":\"$publicIp\",\"pppoe_running\":$pppoeUp,\
\"ppp_sessions\":$pppSessions,\"dhcp_leases\":$dhcpLeases,\
\"lte\":$lteJson,\"interfaces\":$ifaces,\"neighbors\":$nbrs,\
\"mac_hosts\":$macHosts,\"arp\":$arpList}"

# ── push, and read back control + pending job ────────────────────────
:local resp ""
:do {
    :set resp [/tool fetch http-method=post mode=https \
        url=("$vigilantUrl/telemetry") \
        http-header-field=("Authorization: Bearer " . $vigilantToken . ",Content-Type: application/json") \
        http-data=$body output=user as-value]
} on-error={ :log warning "vigilant-agent: telemetry POST failed" }

# The ingest response MAY contain a pending, approved config job for this serial:
#   {"job":{"id":"…","sha256":"…","url":"…/config/<id>.rsc","confirm_window_s":300}}
# Applying it is gated server-side (only approved jobs are ever served) and locally
# (checksum verify + pre-snapshot + dead-man's-switch). Pseudocode of the apply path:
#
#   1. /export file=vigilant-pre-<jobid>           ;# pre-change snapshot (also POSTed back)
#   2. /system scheduler add name=vigilant-rollback interval=<window> \
#        on-event="/import vigilant-pre-<jobid>.rsc; /system scheduler remove vigilant-rollback"
#                                                  ;# dead-man's switch: auto-revert unless cancelled
#   3. /tool fetch the job .rsc; verify sha256 == job.sha256 (abort if mismatch)
#   4. /import <job>.rsc                            ;# behaves like Safe Mode: error/disconnect reverts
#   5. POST result + new /export to Vigilant; operator confirms healthy within the window
#   6. on confirm → /system scheduler remove vigilant-rollback   (status=applied)
#      no confirm → rollback fires                                (status=rolled_back)
#
# Left as commented pseudocode deliberately — the apply path runs against LIVE config and
# must be reviewed and piloted on a non-critical router before being enabled.
