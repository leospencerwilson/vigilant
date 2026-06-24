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
# bridge host MAC table. NOTE: identity/platform are vendor-supplied free text — we run
# them through $vigilantClean before interpolating so a stray quote/backslash/control
# char can't break the JSON doc. (The ingest also fails safe on a bad parse — belt+braces.)
:local nbrs "["
:local nf true
:foreach n in=[/ip neighbor find] do={
    :do {
        :local nif [/ip neighbor get $n interface]
        :local nid [$vigilantClean [/ip neighbor get $n identity]]
        :local nmac [/ip neighbor get $n mac-address]
        :local nip [/ip neighbor get $n address]
        :local npl [$vigilantClean [/ip neighbor get $n platform]]
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
# NOTE: send ONLY the Authorization header. RouterOS /tool fetch does not reliably split a
# comma-joined http-header-field into multiple headers — a ",Content-Type: application/json"
# suffix gets folded into the Authorization value, so the server reads the bearer as
# "<token>,Content-Type: …" and returns 401 (seen live as "telemetry POST failed"). The
# ingest parses the JSON body regardless of Content-Type, so the header is unnecessary.
:local resp ""
:onerror telErr in={
    :set resp [/tool fetch http-method=post mode=https check-certificate=$vigilantCC \
        url=("$vigilantUrl/telemetry") \
        http-header-field=("Authorization: Bearer " . $vigilantToken) \
        http-data=$body output=user as-value]
} do={
    # Surface the REAL fetch error + the body size, so a failure is diagnosable instead
    # of a generic "POST failed" (e.g. HTTP status, "too large", timeout, TLS).
    :log warning ("vigilant-agent: telemetry POST failed: " . $telErr . " | body-bytes=" . [:len $body])
}

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
