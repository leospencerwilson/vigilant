# Vigilant agent — DRAFT. REVIEW BEFORE APPLYING TO ANY LIVE ROUTER.
# RouterOS 7.x. This is the rewritten replacement for the current 6-minute push script.
#
# What it does each tick (every 1s, driven by the vigilant-agent scheduler):
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

# TLS verification mode for every /tool fetch below. Set by vigilant-env (see
# bootstrap.rsc). RouterOS 7 trusts no public CA by default, so default to "no" (skip
# verification — still TLS-encrypted) unless the operator has imported the CA and set
# vigilantTlsCheck to a verifying mode. Declared once; visible to the fetches below.
:global vigilantTlsCheck
:local vigilantCC "no"
:if ($vigilantTlsCheck = "yes-without-crl") do={ :set vigilantCC "yes-without-crl" }
:if ($vigilantTlsCheck = "yes") do={ :set vigilantCC "yes" }

# ── JSON free-text sanitiser ─────────────────────────────────────────
# Vendor-supplied free text (identity, neighbour identity/platform, LTE operator,
# interface comments) can contain characters that would BREAK the JSON document we
# hand-build below: a double-quote ends a string early, a backslash starts an escape
# the parser won't expect, and raw control chars (CR/LF/TAB/etc.) are illegal inside a
# JSON string. We do NOT try to *escape* them (RouterOS string handling makes that
# fiddly and error-prone) — we simply REPLACE each dangerous byte with a single space.
# The server treats these as display-only labels, so lossy-but-safe is the right call.
#
# Implementation: walk the string one character at a time with :pick and copy through
# every character UNLESS it is one we must neutralise. The characters that can break the
# JSON doc and that actually occur in RouterOS string values are: the double-quote (")
# and backslash (\) structural chars, plus the control chars TAB, LF and CR. RouterOS
# has no per-char codepoint function, so rather than test "codepoint < 32" we compare
# each char against this explicit set; any match is replaced with a single space, and
# everything else passes through unchanged. (The other ASCII control chars do not appear
# in identity / neighbour / operator strings, and the ingest fails safe on a bad parse.)
:global vigilantClean do={
    :local s [:tostr $1]
    :local out ""
    :local n [:len $s]
    :local i 0
    # Pre-build the control characters we want to strip (TAB, LF, CR) as 1-char strings.
    :local tab [:pick "\09" 0 1]
    :local lf  [:pick "\0A" 0 1]
    :local cr  [:pick "\0D" 0 1]
    :while ($i < $n) do={
        :local c [:pick $s $i ($i + 1)]
        # Replace double-quote, backslash and control chars (TAB/LF/CR) with a space.
        :if (($c = "\"") || ($c = "\\") || ($c = $tab) || ($c = $lf) || ($c = $cr)) do={
            :set out ($out . " ")
        } else={
            :set out ($out . $c)
        }
        :set i ($i + 1)
    }
    :return $out
}

# Tick counter — lets us run heavy/large collections on a slower cadence than the
# 10s fast tick. The MAC/ARP host tables can be large on a busy LAN, so we only
# gather them every ~30 ticks (~5 min). Survives between runs as a global.
:global vigilantTick
:if ([:typeof $vigilantTick] = "nothing") do={ :set vigilantTick 0 }
:set vigilantTick ($vigilantTick + 1)
:local doSlow false
:if (($vigilantTick % 30) = 0) do={ :set doSlow true }

# ── identity / system ───────────────────────────────────────────────
:global vigilantClean
:local serial    "unknown"; :do { :set serial    [/system routerboard get serial-number] } on-error={}
:local identity  "unknown"; :do { :set identity  [$vigilantClean [/system identity get name]] } on-error={}
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
            ",\"operator\":\"" . [$vigilantClean [$g $li "current-operator"]] . "\"" . \
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

# ── L2TP management tunnels (l2tp-CLIENT only) ───────────────────────
# Emit each OUTBOUND l2tp tunnel this router dials as {name,address,running}. address is the
# local IP RouterOS assigned the tunnel, looked up in /ip address (same technique as the
# pppoe-out public-ip fallback above) — it may carry a /mask, the server/UI strips it.
# DELIBERATELY only l2tp-CLIENT interfaces: a VPN concentrator can hold HUNDREDS of dynamic
# l2tp-IN server sessions, which we must never enumerate here (it would blow the CORE chunk
# size). Outbound management tunnels are a bounded handful, so this stays small. On any error
# the array degrades to "[]" rather than breaking the core POST.
:local l2tpJson "[]"
:do {
    :local arr ""
    :local sep ""
    :foreach lc in=[/interface l2tp-client find] do={
        :local lname [/interface l2tp-client get $lc name]
        :local lrun  [/interface l2tp-client get $lc running]
        :local laddr "null"
        :local pa [/ip address find interface=$lname]
        :if ([:len $pa] > 0) do={ :set laddr [/ip address get [:pick $pa 0] address] }
        :set arr ($arr . $sep . ("{\"name\":\"" . $lname . "\",\"address\":\"" . $laddr . "\",\"running\":" . $lrun . "}"))
        :set sep ","
    }
    :set l2tpJson ("[" . $arr . "]")
} on-error={ :set l2tpJson "[]" }

# ── WAN detection (CONSERVATIVE) ──────────────────────────────────────
# is_wan must be TRUE ONLY for a genuine internet uplink. On a VPN-concentrator router
# (this box has bridge_HSCN, bridge_L2TP, l2tp-out1, ether2-5, …) the naive "egress of any
# default route is WAN" rule wrongly flags ~24/25 interfaces, because every tunnel/bridge
# that carries a default route looked like WAN. We therefore only ever add:
#   (a) the PHYSICAL interface a pppoe-client dials over, PLUS the pppoe-out interface
#       itself (the dialled session) — these are unambiguously the internet uplink; and
#   (b) the egress interface of the ACTIVE default route, but ONLY IF that egress is a
#       physical 'ether' or a 'pppoe-out'. A bridge / l2tp / sstp / gre / ipsec / vlan
#       egress is an overlay or LAN-side path, NOT an internet uplink, so it is EXCLUDED.
# We deliberately DROP the old "dhcp-client add-default-route => WAN" rule: only a route
# whose egress passes the ether/pppoe-out type check qualifies, and a DHCP-WAN port's
# default route is already covered by (b) when its egress is an ether.
# Names are space-wrapped (" name ") so the membership test can't false-match (ether1 vs
# ether10). A helper de-dupes so the same port is never added twice.
:local wanList " "
# Add " $nm " to $wanList only if it is not already present (dedupe on the space-wrapped name).
:local wanAdd do={
    :local lst [:tostr $1]
    :local nm  [:tostr $2]
    :if ([:len $nm] = 0) do={ :return $lst }
    :if ([:typeof [:find $lst (" " . $nm . " ")]] != "nothing") do={ :return $lst }
    :return ($lst . $nm . " ")
}
# (a) pppoe-client: the physical interface it dials over + the pppoe-out session itself.
:foreach p in=[/interface pppoe-client find] do={
    :do {
        :set wanList [$wanAdd $wanList [/interface pppoe-client get $p interface]]
        :set wanList [$wanAdd $wanList [/interface pppoe-client get $p name]]
    } on-error={}
}
# (b) active default route egress — ONLY when the egress interface is a physical 'ether'
#     or a 'pppoe-out'. Read the route's egress interface name, then check its type before
#     adding. NOT a bridge, NOT an l2tp/sstp/gre/ipsec/eoip/vlan tunnel.
:foreach r in=[/ip route find dst-address="0.0.0.0/0" active=yes] do={
    :do {
        # immediate-gw is "<gw-ip>%<iface>" (or "%<iface>"). On an ECMP / dual-WAN default
        # route it is a COMMA-separated LIST of those segments, e.g.
        #   "1.2.3.4%ether1,5.6.7.8%pppoe-out1"
        # so we MUST split on comma and process each segment independently. Taking everything
        # after the FIRST '%' would yield a mangled "ether1,5.6.7.8%pppoe-out1" that matches no
        # interface, silently flagging NEITHER real WAN egress on a load-balanced site.
        # Walk $gi one comma-delimited segment at a time; per segment, pull the iface name
        # after that segment's '%' and apply the unchanged ether/pppoe-out type gate.
        :local gi [/ip route get $r immediate-gw]
        :local glen [:len $gi]
        :local segStart 0
        :while ($segStart <= $glen) do={
            # Find the next comma at/after segStart; the segment is [segStart, comma).
            :local rel [:find [:pick $gi $segStart $glen] ","]
            :local segEnd $glen
            :if ([:typeof $rel] != "nothing") do={ :set segEnd ($segStart + $rel) }
            :local seg [:pick $gi $segStart $segEnd]
            # Within this ONE segment, split on '%' to get the egress interface name.
            :local pos [:find $seg "%"]
            :if ([:typeof $pos] != "nothing") do={
                :local egN [:pick $seg ($pos + 1) [:len $seg]]
                :if ([:len $egN] > 0) do={
                    # Look up the egress interface's TYPE; only ether / pppoe-out qualify as WAN.
                    :local egT ""
                    :do { :set egT [/interface get [find name=$egN] type] } on-error={}
                    :if (($egT = "ether") || ($egT = "pppoe-out")) do={ :set wanList [$wanAdd $wanList $egN] }
                }
            }
            # Advance past this segment and its trailing comma. If there was no comma we are
            # done (jump past glen so the :while exits); otherwise resume after the comma.
            :if ([:typeof $rel] = "nothing") do={ :set segStart ($glen + 1) } else={ :set segStart ($segEnd + 1) }
        }
    } on-error={}
}

# ── per-interface: counters + link + role + bridge membership ─────────
# Cumulative counters (ingest derives bps); plugged/speed/duplex from ethernet/monitor;
# bridge membership; is_wan from the list above. The ingest classifies `role`.
#
# CHUNKING: we collect each interface as its OWN small JSON object string into an ARRAY
# ($ifaceArr) rather than concatenating one giant "[...]" string. The send section below
# then POSTs these objects in SMALL BATCHES so no single /tool fetch http-data argument
# exceeds RouterOS's message-bus cap (see the header comment in the send section). Each
# element is a self-contained {...} object; the batch loop wraps a slice in [ ... ].
:local ifaceArr [:toarray ""]
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
    # One self-contained interface object (explicit "." concatenation per line — survives
    # the fetch->script-add->run reformat that breaks backslash-continued literals).
    :local ifObj "{"
    :set ifObj ($ifObj . "\"name\":\"" . $nm . "\",\"type\":\"" . $tp . "\",")
    :set ifObj ($ifObj . "\"running\":" . $run . ",\"disabled\":" . $dis . ",\"plugged\":" . $plugged . ",")
    :set ifObj ($ifObj . "\"speed\":\"" . $rate . "\",\"full_duplex\":" . $fd . ",\"bridge\":\"" . $br . "\",")
    :set ifObj ($ifObj . "\"is_wan\":" . $isWan . ",\"rx_byte\":" . $rb . ",\"tx_byte\":" . $tb . ",")
    :set ifObj ($ifObj . "\"rx_packet\":" . $rp . ",\"tx_packet\":" . $tp2 . "}")
    :set ifaceArr ($ifaceArr , $ifObj)
}

# ── neighbours (what's plugged into each port, where it advertises) ──
# LLDP/CDP/MNDP. For endpoints that don't advertise, the ingest can fall back to the
# bridge host MAC table. NOTE: identity/platform are vendor-supplied free text — we run
# them through $vigilantClean before interpolating so a stray quote/backslash/control
# char can't break the JSON doc. (The ingest also fails safe on a bad parse — belt+braces.)
#
# CHUNKING: collect each neighbour as its own small object into $nbrArr; the send section
# POSTs them in small batches the same way as interfaces.
:local nbrArr [:toarray ""]
:foreach n in=[/ip neighbor find] do={
    :do {
        :local nif [/ip neighbor get $n interface]
        :local nid [$vigilantClean [/ip neighbor get $n identity]]
        :local nmac [/ip neighbor get $n mac-address]
        :local nip [/ip neighbor get $n address]
        :local npl [$vigilantClean [/ip neighbor get $n platform]]
        :local nObj "{"
        :set nObj ($nObj . "\"interface\":\"" . $nif . "\",\"identity\":\"" . $nid . "\",")
        :set nObj ($nObj . "\"mac\":\"" . $nmac . "\",\"address\":\"" . $nip . "\",\"platform\":\"" . $npl . "\"}")
        :set nbrArr ($nbrArr , $nObj)
    } on-error={}
}

# ── L2 host fallback (slow cadence) ──────────────────────────────────
# Endpoints that don't advertise LLDP/CDP still show up here: the bridge host table
# maps a MAC to the physical port it was learned on; ARP adds the IP. The ingest joins
# them by MAC and does the OUI→vendor lookup. We only collect this on the SLOW tick;
# on a fast tick we send NO mac_hosts POST at all, which the server reads as
# "keep previous" (mac_hosts null/absent === keep previous — handlers.js step 7).
#
# CHUNKING + the mac↔arp JOIN: the server joins mac_hosts to arp BY MAC *within a single
# POST body* (transform.joinMacHosts builds ipByMac from that body's arp array). So a
# batch's mac_hosts and its matching arp entries MUST ride in the SAME POST or the IP
# won't attach. We therefore resolve each host's IP from ARP HERE, and store mac, the
# port it was learned on, and that IP together in one array element ($hostArr). The send
# loop emits, per batch, BOTH a mac_hosts slice and a matching arp slice from the same
# elements — keeping every batch self-joining and small.
:local hostArr [:toarray ""]
:if ($doSlow) do={
    # Build a mac->ip lookup from ARP once, then attach the IP to each bridge host.
    :local arpIp [:toarray ""]
    :do {
        :foreach a in=[/ip arp find] do={
            :do {
                :local am [/ip arp get $a mac-address]
                :local aa [/ip arp get $a address]
                :if (([:len $am] > 0) && ([:len $aa] > 0)) do={ :set ($arpIp->$am) $aa }
            } on-error={}
        }
    } on-error={}
    # Build a mac->host-name lookup from the DHCP leases. This is the BEST device identity we
    # have (e.g. "Galaxy-S21", "RECEPTION-PC", "HP-LaserJet") — far better than an OUI vendor
    # guess. host-names are DNS labels (no ';'), so they're tuple-safe; JSON-cleaned on send.
    :local dhcpHost [:toarray ""]
    :do {
        :foreach l in=[/ip dhcp-server lease find] do={
            :do {
                :local lm [/ip dhcp-server lease get $l mac-address]
                :local lh ""
                :do { :set lh [/ip dhcp-server lease get $l host-name] } on-error={}
                :if (([:len $lm] > 0) && ([:len $lh] > 0)) do={ :set ($dhcpHost->$lm) $lh }
            } on-error={}
        }
    } on-error={}
    :do {
        :foreach h in=[/interface bridge host find local=no] do={
            :do {
                :local hm [/interface bridge host get $h mac-address]
                :local hi [/interface bridge host get $h interface]
                :local hip ($arpIp->$hm)
                :if ([:typeof $hip] = "nothing") do={ :set hip "" }
                :local hh ($dhcpHost->$hm)
                :if ([:typeof $hh] = "nothing") do={ :set hh "" }
                # Store the fields as a ";"-delimited tuple; the send loop splits it back into
                # the mac_hosts object (mac;interface;ip;host-name) and the matching arp object.
                :set hostArr ($hostArr , ($hm . ";" . $hi . ";" . $hip . ";" . $hh))
            } on-error={}
        }
    } on-error={}
}

# ── WiFi: SSID / passphrase + associated stations (driver-safe via :parse) ───────────
# Two driver stacks exist across the estate and a box has only ONE:
#   * AX → wifiwave2:      /interface/wifi[/registration-table]
#   * AC → legacy wireless: /interface/wireless[/security-profiles][/registration-table]
# RouterOS resolves command paths at COMPILE time, so naming the menu a box lacks anywhere in
# the agent is a syntax error that kills the WHOLE script (on-error can't guard a compile error).
# FIX: keep each driver's collector in a STRING and compile it only at RUNTIME with :parse —
# wrapped in on-error, so the absent driver (or a wrong field name, or an escaping slip) just
# throws at runtime and is swallowed → WORST CASE is "no WiFi data", never a broken agent. The
# collectors fill flat globals (no JSON inside the string = minimal escaping); the JSON is built
# below in normally-compiled code that names no driver menu. AX is tried first, AC as fallback.
# ⚠️ passphrase is the PLAINTEXT PSK (NOC view) — masked-by-default in the dashboard; never logged.
:global vWN; :global vWS; :global vWP; :global vWDrv
:global vCI; :global vCM; :global vCG; :global vCR; :global vCT
:set vWN [:toarray ""]; :set vWS [:toarray ""]; :set vWP [:toarray ""]; :set vWDrv [:toarray ""]
:set vCI [:toarray ""]; :set vCM [:toarray ""]; :set vCG [:toarray ""]; :set vCR [:toarray ""]; :set vCT [:toarray ""]

:local axSrc ":global vWN; :global vWS; :global vWP; :global vWDrv; :global vCI; :global vCM; :global vCG; :global vCR; :global vCT; :foreach w in=[/interface/wifi find] do={ :local nm [/interface/wifi get \$w name]; :local ss \"\"; :do { :set ss [/interface/wifi get \$w ssid] } on-error={}; :local pk \"\"; :do { :set pk [/interface/wifi get \$w security.passphrase] } on-error={}; :set vWN (\$vWN,\$nm); :set vWS (\$vWS,\$ss); :set vWP (\$vWP,\$pk); :set vWDrv (\$vWDrv,\"ax\") }; :foreach r in=[/interface/wifi/registration-table find] do={ :local sg \"\"; :do { :set sg [/interface/wifi/registration-table get \$r signal] } on-error={}; :set vCI (\$vCI,[/interface/wifi/registration-table get \$r interface]); :set vCM (\$vCM,[/interface/wifi/registration-table get \$r mac-address]); :set vCG (\$vCG,\$sg); :set vCR (\$vCR,\"\"); :set vCT (\$vCT,\"\") }"
:local acSrc ":global vWN; :global vWS; :global vWP; :global vWDrv; :global vCI; :global vCM; :global vCG; :global vCR; :global vCT; :foreach w in=[/interface/wireless find] do={ :local nm [/interface/wireless get \$w name]; :local ss \"\"; :do { :set ss [/interface/wireless get \$w ssid] } on-error={}; :local sp \"\"; :do { :set sp [/interface/wireless get \$w security-profile] } on-error={}; :local pk \"\"; :do { :local sid [/interface/wireless/security-profiles find name=\$sp]; :if ([:len \$sid]>0) do={ :set pk [/interface/wireless/security-profiles get \$sid wpa2-pre-shared-key] } } on-error={}; :set vWN (\$vWN,\$nm); :set vWS (\$vWS,\$ss); :set vWP (\$vWP,\$pk); :set vWDrv (\$vWDrv,\"ac\") }; :foreach r in=[/interface/wireless/registration-table find] do={ :local sg \"\"; :do { :set sg [/interface/wireless/registration-table get \$r signal-strength] } on-error={}; :local rr \"\"; :do { :set rr [/interface/wireless/registration-table get \$r rx-rate] } on-error={}; :local tt \"\"; :do { :set tt [/interface/wireless/registration-table get \$r tx-rate] } on-error={}; :set vCI (\$vCI,[/interface/wireless/registration-table get \$r interface]); :set vCM (\$vCM,[/interface/wireless/registration-table get \$r mac-address]); :set vCG (\$vCG,\$sg); :set vCR (\$vCR,\$rr); :set vCT (\$vCT,\$tt) }"

:do { :local axF [:parse $axSrc]; $axF } on-error={}
:if (([:len $vWN] = 0) && ([:len $vCI] = 0)) do={ :do { :local acF [:parse $acSrc]; $acF } on-error={} }

# Build the JSON arrays here (normal compiled code — names no driver menu, so always parses).
:local wifiArr [:toarray ""]
:local iW 0
:while ($iW < [:len $vWN]) do={
    :local o ("{\"interface\":\"" . ($vWN->$iW) . "\",\"driver\":\"" . ($vWDrv->$iW) . "\",\"ssid\":\"" . [$vigilantClean ($vWS->$iW)] . "\",\"passphrase\":\"" . [$vigilantClean ($vWP->$iW)] . "\"}")
    :set wifiArr ($wifiArr , $o)
    :set iW ($iW + 1)
}
:local wcArr [:toarray ""]
:local iC 0
:while ($iC < [:len $vCI]) do={
    :local o ("{\"interface\":\"" . ($vCI->$iC) . "\",\"mac\":\"" . ($vCM->$iC) . "\",\"signal\":\"" . ($vCG->$iC) . "\",\"rx_rate\":\"" . ($vCR->$iC) . "\",\"tx_rate\":\"" . ($vCT->$iC) . "\"}")
    :set wcArr ($wcArr , $o)
    :set iC ($iC + 1)
}
:local hasWifi false
:if (([:len $wifiArr] > 0) || ([:len $wcArr] > 0)) do={ :set hasWifi true }

# ── push telemetry in SMALL CHUNKS ───────────────────────────────────
# WHY CHUNKED: RouterOS /tool fetch serialises the WHOLE command — including the entire
# `http-data` string — into ONE message on the scripting↔tool message bus, which has a
# hard size cap. A multi-interface router's full rich telemetry body (per-interface
# counters for every bridge + VLAN + pppoe-out1 + lte1 + wifi, plus neighbours + system +
# the slow-tick host/arp tables) is tens of KB and OVERFLOWS that cap → the fetch is
# rejected before a byte leaves the box ("maximum message size exceeded"). output=none
# does NOT help: that governs the RESPONSE coming back, not the OUTBOUND http-data arg.
# Fix: split each tick into several SMALL POSTs, each well under ~1500 bytes, that the
# server treats as idempotent partial upserts (see docs/CONTRACT.md §chunked telemetry):
#   * CORE  — serial + identity + system/health + WAN/ppp/dhcp + lte. NO arrays.
#             This is the chunk that writes device_state + marks the device 'online'.
#   * DETAIL (partial:true) — interfaces in small batches; neighbours in small batches;
#             slow-tick mac_hosts+arp in small batches. Each carries ONLY its subset, so
#             it never clobbers device_state and a dropped batch only ages out its subset.
# NOTE on headers: send ONLY the Authorization header. RouterOS /tool fetch does not
# reliably split a comma-joined http-header-field into multiple headers — a trailing
# ",Content-Type: …" gets folded into the bearer value (401). The ingest parses JSON
# regardless of Content-Type, so the header is unnecessary.
# NOTE on $body length: log it from the OUTER scope (computed before the fetch). The old
# "[:len $body]" inside the :onerror handler could not see the outer body and reported a
# misleading constant (the "body-bytes=32" scope artifact) — never use that pattern.

# Reusable single-POST helper: POST $1 (a body string) to /telemetry, fire-and-forget
# (output=none), single Authorization header, TLS mode $3, concise failure log that
# includes the TRUE outbound size. $2 is a short label for the log line.
#   We capture the error into a function-scope variable INSIDE the :onerror and log it
#   AFTERWARDS, in the function body — NOT from inside the :onerror do={} block. The old
#   code logged "[:len $body]" from inside the handler, where the outer body string was
#   not reliably bound, yielding the misleading "body-bytes=32" scope artifact. Computing
#   blen and reading the captured error out here avoids that trap entirely.
:global vigilantPost do={
    :global vigilantUrl
    :global vigilantToken
    :local cc  $3
    :local b   [:tostr $1]
    :local lbl [:tostr $2]
    :local blen [:len $b]
    :local failMsg ""
    :onerror perr in={
        /tool fetch http-method=post mode=https check-certificate=$cc \
            url=("$vigilantUrl/telemetry") \
            http-header-field=("Authorization: Bearer " . $vigilantToken) \
            http-data=$b output=none
    } do={
        :set failMsg $perr
    }
    :if ([:len $failMsg] > 0) do={
        :log warning ("vigilant-agent: " . $lbl . " POST failed: " . $failMsg . " | body-bytes=" . $blen)
    }
}
:global vigilantPost

# ── 1) CORE chunk — system/health + WAN + ppp + lte. Small + bounded. ──
# This is the ONLY chunk carrying the system block, so it is the one that writes
# device_state and flips the device 'online'. No arrays → size is independent of how
# many interfaces/neighbours/hosts the router has.
#
# NUMERIC SAFETY — health metrics are emitted as QUOTED STRINGS, not bare JSON numbers.
# /system health values are board-dependent free-form fields: a sensor can report a
# non-numeric token (e.g. "24.5C", "no-sensor", or a stray space) and the defaults here
# are the literal token "null". Interpolated UNQUOTED that would produce invalid JSON
# (e.g. {"temperature":24.5C} or {"temperature":null,...} with a missing value) and 400
# the ENTIRE core POST — taking the device offline for that tick. Quoting them
# ("temperature":"41.5" / "temperature":"null" / "cpu_load":"3") keeps the body valid
# JSON unconditionally; the server's telemetry.normalize parseNum-coerces each string to
# number|null (so "24.5C"→null, "41.5"→41.5, "null"→null). Fields kept as QUOTED STRINGS:
#   cpu_load, free_memory, total_memory, free_hdd, temperature, cpu_temperature,
#   board_temperature, voltage, fan1_speed, write_sect_total (the health/resource numerics),
#   plus ros_version / uptime / identity / public_ip / firmware_current / firmware_upgrade.
# Kept as UNQUOTED booleans: ntp_synced, pppoe_running. Kept as UNQUOTED integers:
#   ppp_sessions, dhcp_leases (both from [:len …] — reliably whole numbers).
# (Interface counters rx_byte/tx_byte/rx_packet/tx_packet stay UNQUOTED integers in the
#  DETAIL chunk: they come straight from /interface get and are reliably numeric.)
:local core "{"
:set core ($core . "\"serial\":\"" . $serial . "\",\"identity\":\"" . $identity . "\",\"uptime\":\"" . $uptime . "\",")
:set core ($core . "\"cpu_load\":\"" . $cpuLoad . "\",\"free_memory\":\"" . $freeMem . "\",\"total_memory\":\"" . $totMem . "\",\"free_hdd\":\"" . $freeHdd . "\",")
:set core ($core . "\"ros_version\":\"" . $rosVer . "\",\"temperature\":\"" . $temp . "\",\"cpu_temperature\":\"" . $cpuTemp . "\",\"board_temperature\":\"" . $brdTemp . "\",")
:set core ($core . "\"voltage\":\"" . $volt . "\",\"fan1_speed\":\"" . $fan1 . "\",\"write_sect_total\":\"" . $writeSect . "\",")
:set core ($core . "\"firmware_current\":\"" . $fwCur . "\",\"firmware_upgrade\":\"" . $fwUpg . "\",\"ntp_synced\":" . $ntpSynced . ",")
:set core ($core . "\"public_ip\":\"" . $publicIp . "\",\"pppoe_running\":" . $pppoeUp . ",\"ppp_sessions\":" . $pppSessions . ",\"dhcp_leases\":" . $dhcpLeases . ",")
:set core ($core . "\"l2tp_tunnels\":" . $l2tpJson . ",")
:set core ($core . "\"lte\":" . $lteJson . "}")
[$vigilantPost $core "telemetry-core" $vigilantCC]

# ── 2) INTERFACE detail in small BATCHES (partial:true) ──
# 3 interfaces per POST keeps each body in the few-hundred-bytes range even with long
# 10-13 digit counters. Each batch carries ONLY {serial,partial,interfaces[...]} — no
# system fields — so the server upserts just those ports and never touches device_state.
# We deliberately send NO `ts`: the server then stamps each interface with that chunk's
# receive time, and per-interface bps is computed against the SAME port's prior sample
# (matched by name), so the delta window stays correct across ticks regardless of which
# batch a port rode in (the single-payload path also omitted ts and relied on this).
:local ifBatch 3
:local ifN [:len $ifaceArr]
:local ifI 0
:while ($ifI < $ifN) do={
    :local body ("{\"serial\":\"" . $serial . "\",\"partial\":true,\"interfaces\":[")
    :local j 0
    :local sep ""
    :while (($j < $ifBatch) && (($ifI + $j) < $ifN)) do={
        :set body ($body . $sep . ($ifaceArr->($ifI + $j)))
        :set sep ","
        :set j ($j + 1)
    }
    :set body ($body . "]}")
    [$vigilantPost $body "telemetry-ifaces" $vigilantCC]
    :set ifI ($ifI + $ifBatch)
}

# ── 3) NEIGHBOUR detail in small BATCHES (partial:true) ──
:local nbBatch 4
:local nbN [:len $nbrArr]
:local nbI 0
:while ($nbI < $nbN) do={
    :local body ("{\"serial\":\"" . $serial . "\",\"partial\":true,\"neighbors\":[")
    :local j 0
    :local sep ""
    :while (($j < $nbBatch) && (($nbI + $j) < $nbN)) do={
        :set body ($body . $sep . ($nbrArr->($nbI + $j)))
        :set sep ","
        :set j ($j + 1)
    }
    :set body ($body . "]}")
    [$vigilantPost $body "telemetry-neighbors" $vigilantCC]
    :set nbI ($nbI + $nbBatch)
}

# ── 4) SLOW-TICK mac_hosts + arp in small BATCHES (partial:true) ──
# Only runs on the slow tick (otherwise $hostArr is empty → no POST → server keeps the
# previous host table). Each batch emits BOTH a mac_hosts slice and the MATCHING arp
# slice from the same elements, so transform.joinMacHosts attaches each IP within the
# batch. We send mac_hosts even when a host has no ARP IP (arp entry omitted for it) —
# the server left-joins, leaving ip:null, which is the intended "MAC seen, no IP" row.
:if ([:len $hostArr] > 0) do={
    :local hBatch 4
    :local hN [:len $hostArr]
    :local hI 0
    :while ($hI < $hN) do={
        :local hosts ""
        :local arps  ""
        :local j 0
        :local hsep ""
        :local asep ""
        :while (($j < $hBatch) && (($hI + $j) < $hN)) do={
            :local tuple ($hostArr->($hI + $j))
            # Split "mac;interface;ip;host-name" back into fields.
            :local p1 [:find $tuple ";"]
            :local hm [:pick $tuple 0 $p1]
            :local rest [:pick $tuple ($p1 + 1) [:len $tuple]]
            :local p2 [:find $rest ";"]
            :local hi [:pick $rest 0 $p2]
            :local rest2 [:pick $rest ($p2 + 1) [:len $rest]]
            :local p3 [:find $rest2 ";"]
            :local hip [:pick $rest2 0 $p3]
            :local hh [:pick $rest2 ($p3 + 1) [:len $rest2]]
            # host-name is free text — JSON-clean it before interpolating.
            :local hostObj ("{\"mac\":\"" . $hm . "\",\"interface\":\"" . $hi . "\"")
            :if ([:len $hh] > 0) do={ :set hostObj ($hostObj . ",\"hostname\":\"" . [$vigilantClean $hh] . "\"") }
            :set hostObj ($hostObj . "}")
            :set hosts ($hosts . $hsep . $hostObj)
            :set hsep ","
            :if ([:len $hip] > 0) do={
                :set arps ($arps . $asep . "{\"mac\":\"" . $hm . "\",\"ip\":\"" . $hip . "\"}")
                :set asep ","
            }
            :set j ($j + 1)
        }
        :local body ("{\"serial\":\"" . $serial . "\",\"partial\":true,\"mac_hosts\":[" . $hosts . "],\"arp\":[" . $arps . "]}")
        [$vigilantPost $body "telemetry-hosts" $vigilantCC]
        :set hI ($hI + $hBatch)
    }
}

# ── 5) WiFi config (slow tick) — one POST; few WLANs, well under the size cap ──
# Snapshot semantics server-side: this REPLACES the device's WLAN set, so a removed SSID
# disappears. Only sent when a WLAN was actually read.
:if ([:len $wifiArr] > 0) do={
    :local body ("{\"serial\":\"" . $serial . "\",\"partial\":true,\"wifi\":[")
    :local j 0
    :local sep ""
    :while ($j < [:len $wifiArr]) do={
        :set body ($body . $sep . ($wifiArr->$j))
        :set sep ","
        :set j ($j + 1)
    }
    :set body ($body . "]}")
    [$vigilantPost $body "telemetry-wifi" $vigilantCC]
}

# ── 6) WiFi associated stations (EVERY tick when the device has WiFi) ──
# Sent even when EMPTY so the server's snapshot replace clears stations that have left
# (that's how the live "connected devices + signal bars" stay accurate).
# ONE POST: the server REPLACES the whole client set per POST, so the registration table
# must ride in a single body (chunking it would make each batch wipe the previous one).
# Chateau APs carry few stations, so the body stays small; if a future high-density AP ever
# overflows the fetch cap, add an explicit "first chunk replaces, rest append" flag instead.
:if ($hasWifi) do={
    :local body ("{\"serial\":\"" . $serial . "\",\"partial\":true,\"wifi_clients\":[")
    :local j 0
    :local sep ""
    :while ($j < [:len $wcArr]) do={
        :set body ($body . $sep . ($wcArr->$j))
        :set sep ","
        :set j ($j + 1)
    }
    :set body ($body . "]}")
    [$vigilantPost $body "telemetry-wifi-clients" $vigilantCC]
}

# NOTE: telemetry is now FIRE-AND-FORGET across all chunks (output=none everywhere), so we
# never capture a telemetry response. $resp therefore stays empty and the DRAFT config-apply
# block below — which extracts its job fields from $resp->"data" — cleanly finds NO job and
# no-ops (it is also gated off by $vigilantApplyEnabled=false by default). This matches the
# old behaviour: the previous single POST also used output=none, leaving $resp empty. When
# the apply path is taken live it must source the pending job from GET /config/pending (see
# handlers.js configPending) rather than a telemetry response — out of scope for this change.
:local resp ""

# ─────────────────────────────────────────────────────────────────────
# CONFIG-JOB APPLY PATH  —  DRAFT / REVIEW-BEFORE-LIVE
# ─────────────────────────────────────────────────────────────────────
# !! This block runs against LIVE router configuration. It is written to be SAFE
# !! (checksum gate, pre-snapshot, dead-man's-switch rollback, server-confirmed cancel)
# !! but MUST be reviewed line-by-line and piloted on a NON-CRITICAL router (Safe Mode,
# !! Ctrl-X) before it is enabled across the estate. Until signed off, leave the master
# !! switch `$vigilantApplyEnabled` unset/false so this whole block no-ops.
#
# The ingest telemetry response MAY contain a pending, APPROVED job for THIS serial:
#   {"ok":true,"poll_interval_s":10,"agent_version":3,
#    "job":{"id":"<uuid>","sha256":"<hex>","url":"https://…/config/<id>.rsc","confirm_window_s":300}}
# The server only ever serves approved jobs, only to the targeted device. We add the
# device-side guarantees: verify the checksum, snapshot first, arm an auto-rollback, and
# only cancel that rollback when the SERVER confirms the change is good.
#
# Two separate ticks are involved:
#   TICK A — a `job` is present and we have not started it yet  → run the APPLY sequence
#            (snapshot → arm dead-man → import → report "applying"/"failed").
#   TICK B — the server has confirmed the applied change (no job, "confirm":"<jobid>" in
#            the response, or the job is simply gone) → CANCEL the dead-man scheduler and
#            report "applied". If we never reach TICK B in time, the dead-man fires and the
#            device self-recovers (status becomes rolled_back when it next reports in).

# Master safety switch. Set to true ONLY after this path has been reviewed + piloted.
:global vigilantApplyEnabled
:if ([:typeof $vigilantApplyEnabled] = "nothing") do={ :set vigilantApplyEnabled false }

# Remember which job we are mid-applying across ticks (survives between runs).
:global vigilantPendingJob
:if ([:typeof $vigilantPendingJob] = "nothing") do={ :set vigilantPendingJob "" }

:global vigilantClean

# Pull the job fields out of the telemetry response body. $resp->"data" is the raw body
# string (output=user as-value). We extract by hand to avoid a JSON parser dependency;
# the values are server-generated and well-formed (uuid / hex / url / integer).
:local respBody ""
:do { :set respBody ($resp->"data") } on-error={}

# Tiny helper: pull the string value of a top-level JSON field "key":"value" from $1
# (the body) given $2 (the key). Returns "" if absent. Quote-delimited values only.
:global vigilantJsonStr do={
    :local b [:tostr $1]; :local k [:tostr $2]
    :local pat ("\"" . $k . "\":\"")
    :local p [:find $b $pat]
    :if ([:typeof $p] = "nothing") do={ :return "" }
    :local s ($p + [:len $pat])
    :local e [:find $b "\"" $s]
    :if ([:typeof $e] = "nothing") do={ :return "" }
    :return [:pick $b $s $e]
}
# And the numeric confirm_window (unquoted integer): "confirm_window_s":300
:global vigilantJsonNum do={
    :local b [:tostr $1]; :local k [:tostr $2]
    :local pat ("\"" . $k . "\":")
    :local p [:find $b $pat]
    :if ([:typeof $p] = "nothing") do={ :return 0 }
    :local s ($p + [:len $pat]); :local i $s
    :while (($i < [:len $b]) && ([:pick $b $i ($i+1)] ~ "[0-9]")) do={ :set i ($i + 1) }
    :if ($i = $s) do={ :return 0 }
    :return [:tonum [:pick $b $s $i]]
}
:global vigilantJsonStr
:global vigilantJsonNum

:local jobId    [$vigilantJsonStr $respBody "id"]
:local jobSha   [$vigilantJsonStr $respBody "sha256"]
:local jobUrl   [$vigilantJsonStr $respBody "url"]
:local jobWin   [$vigilantJsonNum $respBody "confirm_window_s"]
:if ($jobWin <= 0) do={ :set jobWin 300 }
:local confirmedJob [$vigilantJsonStr $respBody "confirm"]

# ── TICK B: server confirmed → cancel the dead-man's switch, mark applied ──
# Cancelling the rollback scheduler is the ONLY thing that prevents the auto-revert, so we
# must do it ONLY on an AFFIRMATIVE server confirmation: the telemetry response carries
# "confirm":"<jobid>" for the job we are mid-applying, set once the operator confirms the
# change is healthy (job → status='applied' server-side). The mere ABSENCE of a job is NOT
# confirmation — a transient error body, an empty/garbled response after a config change
# that half-broke the WAN, or a different job appearing must NEVER cancel the dead-man. If
# no affirmative confirm arrives within confirm_window_s, the dead-man fires and the device
# self-recovers (the intended safe default — exactly the failure this switch exists to catch).
:if (($vigilantApplyEnabled) && ([:len $vigilantPendingJob] > 0)) do={
    :local serverConfirms false
    :if (([:len $confirmedJob] > 0) && ($confirmedJob = $vigilantPendingJob)) do={ :set serverConfirms true }
    :if ($serverConfirms) do={
        :do {
            :if ([:len [/system scheduler find name="vigilant-rollback"]] > 0) do={
                /system scheduler remove [find name="vigilant-rollback"]
            }
        } on-error={ :log warning "vigilant-agent: failed to remove rollback scheduler" }
        # Report applied (best-effort; server already considers it confirmed).
        :do {
            :local rb ("{\"job_id\":\"" . $vigilantPendingJob . "\",\"status\":\"applied\"," . \
                "\"result_log\":\"rollback cancelled on server confirm\"}")
            /tool fetch http-method=post mode=https check-certificate=$vigilantCC url=("$vigilantUrl/config/result") \
                http-header-field=("Authorization: Bearer " . $vigilantToken) \
                http-data=$rb output=none
        } on-error={ :log warning "vigilant-agent: applied-result POST failed" }
        :log info ("vigilant-agent: config job " . $vigilantPendingJob . " confirmed applied")
        :set vigilantPendingJob ""
    }
}

# ── TICK A: a new approved job is offered → APPLY IT SAFELY ──
:if (($vigilantApplyEnabled) && ([:len $jobId] > 0) && ($jobId != $vigilantPendingJob)) do={
    # Filenames derived from the (server-generated, uuid) job id — sanitise defensively.
    :local jid   [$vigilantClean $jobId]
    :local preFn ("vigilant-pre-" . $jid . ".rsc")     ;# pre-change export (rollback source)
    :local preBk ("vigilant-pre-" . $jid)              ;# pre-change binary backup
    :local jobFn ("vigilant-job-" . $jid . ".rsc")     ;# the new config to import
    :local resultStatus "failed"
    :local resultLog ""

    :do {
        # 1) PRE-SNAPSHOT first — both a text /export (used as the rollback source AND
        #    POSTed back to the server) and a binary /system backup (belt + braces).
        :do { /file remove [find name=$preFn] } on-error={}
        /export file=$preFn
        /system backup save name=$preBk
        :delay 1s

        # 2) ARM THE DEAD-MAN'S SWITCH *before* importing anything. If the import breaks
        #    management access (so we never reach TICK B to cancel it), this scheduler
        #    fires after the confirm window, re-imports the pre-change export, and removes
        #    itself. interval=<window>s means it runs once after the window elapses
        #    (we remove it on confirm long before then).
        :do {
            :if ([:len [/system scheduler find name="vigilant-rollback"]] > 0) do={
                /system scheduler remove [find name="vigilant-rollback"]
            }
        } on-error={}
        /system scheduler add name=vigilant-rollback \
            interval=[:totime ($jobWin . "s")] \
            comment="Vigilant dead-man rollback - auto-removed on server confirm" \
            on-event=(":log warning \"vigilant-agent: dead-man rollback firing for job " . $jid . "\"; " . \
                      "/import file-name=" . $preFn . "; " . \
                      "/system scheduler remove [find name=\"vigilant-rollback\"]")

        # 3) FETCH the new .rsc to a file and CHECKSUM-GATE it. Nothing is imported unless
        #    the sha256 of the fetched bytes matches BOTH the sha256 the server put in the
        #    telemetry job object AND (where present) the X-Vigilant-Sha256 response header.
        :do { /file remove [find name=$jobFn] } on-error={}
        :local fr [/tool fetch http-method=get mode=https check-certificate=$vigilantCC url=$jobUrl \
            http-header-field=("Authorization: Bearer " . $vigilantToken) \
            dst-path=$jobFn as-value]
        :delay 1s

        # Optional secondary check: the response header (ROS7 exposes received headers in
        # the as-value result under "header-fields" on versions that support it).
        :local hdrSha ""
        :do {
            :local hf ($fr->"header-fields")
            :if ([:typeof $hf] != "nothing") do={
                :foreach hk,hv in=$hf do={
                    :if (($hk = "X-Vigilant-Sha256") || ($hk = "x-vigilant-sha256")) do={ :set hdrSha [:tostr $hv] }
                }
            }
        } on-error={}

        # Compute sha256 of the fetched file's bytes. RouterOS v7 exposes a per-file
        # sha256 via the file menu; if the build doesn't, $gotSha stays "" and we rely on
        # the X-Vigilant-Sha256 response header instead. We must have at least ONE source
        # of a computed checksum to compare, or we refuse to import (fail safe).
        :local gotSha ""
        :do { :set gotSha [/file get [find name=$jobFn] sha256] } on-error={}

        # GATE: only import when we can prove the bytes match the server's expected sha256.
        :local shaOk true
        :if ([:len $jobSha] = 0) do={ :set shaOk false }                               ;# no expected sha => never apply
        :if (([:len $gotSha] = 0) && ([:len $hdrSha] = 0)) do={ :set shaOk false }      ;# nothing to verify against => never apply
        :if (([:len $gotSha] > 0) && ($gotSha != $jobSha)) do={ :set shaOk false }      ;# file hash disagrees
        :if (([:len $hdrSha] > 0) && ($hdrSha != $jobSha)) do={ :set shaOk false }      ;# header disagrees

        :if (!$shaOk) do={
            :set resultLog ("checksum mismatch: expected=" . $jobSha . " file=" . $gotSha . " header=" . $hdrSha)
            :log warning ("vigilant-agent: ABORT import - " . $resultLog)
            # Abort cleanly: tear down the dead-man (nothing was imported) and the files.
            :do { /system scheduler remove [find name="vigilant-rollback"] } on-error={}
            :do { /file remove [find name=$jobFn] } on-error={}
            :error "checksum-mismatch"
        }

        # 4) IMPORT under Safe-Mode semantics. /import stops on the first error; combined
        #    with the dead-man's switch this gives us auto-revert if the change is bad or
        #    drops our session. We do NOT confirm here — only the SERVER cancels rollback.
        /import file-name=$jobFn
        :set resultStatus "applying"
        :set resultLog ("imported " . $jobFn . "; dead-man armed for " . $jobWin . "s; awaiting server confirm")
        :set vigilantPendingJob $jobId
        :log info ("vigilant-agent: applied config job " . $jid . " - awaiting confirm")
    } on-error={
        :set resultStatus "failed"
        :if ([:len $resultLog] = 0) do={ :set resultLog "apply path error (see /log) - Safe Mode / dead-man will recover" }
        :log warning ("vigilant-agent: config apply failed for job " . $jobId)
    }

    # 5) REPORT the outcome of this tick. Include the pre-change export so the server can
    #    store it as the rollback point (config_snapshots, source='pre-apply'). result_log
    #    is sanitised free text. The export body is read from the file we wrote in step 1.
    :do {
        :local exp ""
        :do { :set exp [/file get [find name=$preFn] contents] } on-error={}
        :local rl  [$vigilantClean $resultLog]
        :local ex  [$vigilantClean $exp]
        :local rb ("{\"job_id\":\"" . $jobId . "\",\"status\":\"" . $resultStatus . "\"," . \
            "\"result_log\":\"" . $rl . "\",\"export\":\"" . $ex . "\"}")
        /tool fetch http-method=post mode=https check-certificate=$vigilantCC url=("$vigilantUrl/config/result") \
            http-header-field=("Authorization: Bearer " . $vigilantToken) \
            http-data=$rb output=none
    } on-error={ :log warning "vigilant-agent: config result POST failed" }
}
# ── end config-job apply path (DRAFT / REVIEW-BEFORE-LIVE) ───────────────

# ── ACTIVE SPEEDTEST (server-timed) ──────────────────────────────────────
# Checked at most every 5th tick (so it is NOT a per-second poll). When the operator has
# requested a test, the server hands us a descriptor via GET /speedtest/pending; we DOWNLOAD
# bytes_down to a temp file (the server times its own send → download Mbps) and re-UPLOAD that
# file to /speedtest/up (the server times its own receive → upload Mbps), then POST a result.
# The SERVER does all the timing/maths, so we need no sub-second clock here. ⚠️ This deliberately
# saturates the WAN for the test's duration — it only runs when an operator has requested one,
# and the server caps the byte counts. Uses the $vigilantJsonStr helper defined above.
:if (($vigilantTick % 5) = 0) do={
    :do {
        :local sp [/tool fetch url=("$vigilantUrl/speedtest/pending") http-method=get mode=https \
            check-certificate=$vigilantCC http-header-field=("Authorization: Bearer " . $vigilantToken) \
            output=user as-value]
        :local sb ""; :do { :set sb ($sp->"data") } on-error={}
        :local sjid [$vigilantJsonStr $sb "id"]
        :if ([:len $sjid] > 0) do={
            :local durl [$vigilantJsonStr $sb "down_url"]
            :local uurl [$vigilantJsonStr $sb "up_url"]
            :local dlok false
            :local ulok false
            :do { /file remove [find name="vigilant-speedtest.bin"] } on-error={}
            # DOWNLOAD leg → temp file (the server times its own SEND → down_bps, so this works
            # even if the file save is imperfect). dlok is set from the FILE actually landing,
            # not from fetch not-throwing — otherwise we'd try to upload a missing file.
            :if ([:len $durl] > 0) do={
                :do {
                    /tool fetch url=$durl http-method=get mode=https check-certificate=$vigilantCC \
                        http-header-field=("Authorization: Bearer " . $vigilantToken) \
                        dst-path="vigilant-speedtest.bin"
                } on-error={}
            }
            :if ([:len [/file find name="vigilant-speedtest.bin"]] > 0) do={ :set dlok true }
            # UPLOAD leg → POST the file back (server times its RECEIVE → up_bps). Do NOT set
            # http-method=post: `upload=yes` already POSTs the file, and on several ROS builds the
            # two together error ("post needs http-data"). Capture the REAL error so a failure is
            # diagnosable in the log rather than a silent ul=false.
            # NB: NO `output=none` here — RouterOS rejects it on an upload ("'output' option can
            # only be used for download"), which is exactly what made the upload throw (ul=false).
            # `upload=yes` already POSTs the file; we just don't capture a response body.
            :if (($dlok) && ([:len $uurl] > 0)) do={
                :local uerr ""
                :onerror perr in={
                    /tool fetch url=$uurl mode=https check-certificate=$vigilantCC \
                        http-header-field=("Authorization: Bearer " . $vigilantToken) \
                        src-path="vigilant-speedtest.bin" upload=yes
                    :set ulok true
                } do={ :set uerr $perr }
                :if ([:len $uerr] > 0) do={ :log warning ("vigilant-agent: speedtest upload failed: " . $uerr) }
            }
            :do { /file remove [find name="vigilant-speedtest.bin"] } on-error={}
            :local sst "done"
            :if (!$dlok) do={ :set sst "failed" }
            # Tell the server WHY there's no upload figure so the dashboard can label it rather
            # than show a blank. Many RouterOS builds only support [s]ftp upload via /tool fetch,
            # so an HTTP active-upload test isn't possible — download-only is expected there.
            :local rlog ""
            :if (($dlok) && (!$ulok)) do={ :set rlog "download measured; HTTP upload not supported on this RouterOS build" }
            :do {
                /tool fetch url=("$vigilantUrl/speedtest/result") http-method=post mode=https \
                    check-certificate=$vigilantCC http-header-field=("Authorization: Bearer " . $vigilantToken) \
                    http-data=("{\"job_id\":\"" . $sjid . "\",\"status\":\"" . $sst . "\",\"result_log\":\"" . $rlog . "\"}") output=none
            } on-error={}
            :log info ("vigilant-agent: speedtest " . $sjid . " " . $sst . " (dl=" . $dlok . " ul=" . $ulok . ")")
        }
    } on-error={ :log warning "vigilant-agent: speedtest check failed" }
}
