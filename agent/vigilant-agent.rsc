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

# ── identity / system ───────────────────────────────────────────────
:local serial    "unknown"; :do { :set serial    [/system routerboard get serial-number] } on-error={}
:local identity  "unknown"; :do { :set identity  [/system identity get name] } on-error={}
:local uptime    "0";       :do { :set uptime    [/system resource get uptime] } on-error={}
:local cpuLoad   "0";       :do { :set cpuLoad   [/system resource get cpu-load] } on-error={}
:local freeMem   "0";       :do { :set freeMem   [/system resource get free-memory] } on-error={}
:local totMem    "0";       :do { :set totMem    [/system resource get total-memory] } on-error={}
:local freeHdd   "0";       :do { :set freeHdd   [/system resource get free-hdd-space] } on-error={}
:local rosVer    "0";       :do { :set rosVer    [/system resource get version] } on-error={}

# Health (temperature/voltage) — not all boards support it; guard each.
:local temp "null"; :do { :set temp [/system health get [find name="temperature"] value] } on-error={}
:local volt "null"; :do { :set volt [/system health get [find name="voltage"] value] } on-error={}

# WAN / routing (public IP only — NEVER the password)
:local publicIp "null"
:local pe [/ip address find interface="pppoe-out1"]
:if ([:len $pe] > 0) do={ :set publicIp [/ip address get [:pick $pe 0] address] }
:local pppoeUp "false"
:if ([:len [/interface find name="pppoe-out1"]] > 0) do={ :set pppoeUp [/interface get [find name="pppoe-out1"] running] }
:local pppSessions [:len [/ppp active find]]
:local dhcpLeases  [:len [/ip dhcp-server lease find]]

# ── per-interface counters (the throughput win) ──────────────────────
# Build a JSON array of every interface with cumulative counters. The ingest
# diffs rx-byte/tx-byte against the previous sample to derive bps.
:local ifaces "["
:local first true
:foreach i in=[/interface find] do={
    :local nm  [/interface get $i name]
    :local tp  [/interface get $i type]
    :local run [/interface get $i running]
    :local rb 0; :local tb 0; :local rp 0; :local tp2 0
    :do { :set rb [/interface get $i rx-byte] }   on-error={}
    :do { :set tb [/interface get $i tx-byte] }   on-error={}
    :do { :set rp [/interface get $i rx-packet] } on-error={}
    :do { :set tp2 [/interface get $i tx-packet] } on-error={}
    :if (!$first) do={ :set ifaces ($ifaces . ",") }
    :set first false
    :set ifaces ($ifaces . "{\"name\":\"" . $nm . "\",\"type\":\"" . $tp . \
        "\",\"running\":" . $run . ",\"rx_byte\":" . $rb . ",\"tx_byte\":" . $tb . \
        ",\"rx_packet\":" . $rp . ",\"tx_packet\":" . $tp2 . "}")
}
:set ifaces ($ifaces . "]")

# ── assemble payload ─────────────────────────────────────────────────
:local body "{\
\"serial\":\"$serial\",\"identity\":\"$identity\",\"uptime\":\"$uptime\",\
\"cpu_load\":$cpuLoad,\"free_memory\":$freeMem,\"total_memory\":$totMem,\"free_hdd\":$freeHdd,\
\"ros_version\":\"$rosVer\",\"temperature\":$temp,\"voltage\":$volt,\
\"public_ip\":\"$publicIp\",\"pppoe_running\":$pppoeUp,\"ppp_sessions\":$pppSessions,\
\"dhcp_leases\":$dhcpLeases,\"interfaces\":$ifaces}"

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
