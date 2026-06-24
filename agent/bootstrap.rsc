# Vigilant install/bootstrap — DRAFT. REVIEW BEFORE APPLYING TO ANY LIVE ROUTER.
# RouterOS 7.x. Paste under Safe Mode (Ctrl-X / F4).
#
# This is the COMPLETE per-device installer (telemetry-only; config-apply is OFF).
# The Vigilant /enroll endpoint serves a copy of this with <VIGILANT_URL> and
# <VIGILANT_TOKEN> already substituted — so the admin UI / API hand you a ready block.
#
# It establishes four things, all reboot-safe:
#   1. vigilant-env       — a script that (re)declares the globals, re-run on every boot
#                           via a start-time=startup scheduler (RouterOS globals are wiped
#                           on reboot — this is how url/token/flags survive).
#   2. vigilant-bootstrap — fetches the CURRENT agent script from Vigilant once a day, so
#                           the whole estate self-updates from one place.
#   3. vigilant-agent     — the collector script itself (fetched by the bootstrap).
#   4. vigilant-agent scheduler — runs the collector every 10s (the telemetry tick).
#
# TLS: RouterOS 7 does NOT trust public CAs by default, so a plain mode=https fetch to a
# Cloudflare-fronted host FAILS. vigilantTlsCheck controls /tool fetch check-certificate:
#   "no"               -> skip verification (pragmatic pilot default; still TLS-encrypted)
#   "yes-without-crl"  -> verify the chain (do this once you've imported the CA — secure)
#
# Config-apply: vigilantApplyEnabled=false keeps the device telemetry-only. It will NOT
# change anything on the router until you deliberately flip this to true later.

# ── 1) Persistent globals (survive reboot) ───────────────────────────
/system script remove [find name="vigilant-env"]
/system script add name=vigilant-env dont-require-permissions=no source={
    :global vigilantUrl "<VIGILANT_URL>"
    :global vigilantToken "<VIGILANT_TOKEN>"
    :global vigilantTlsCheck "no"
    :global vigilantApplyEnabled false
}
/system scheduler remove [find name="vigilant-env"]
/system scheduler add name=vigilant-env start-time=startup interval=0 \
    on-event="/system script run vigilant-env" \
    comment="Vigilant: re-declare globals on boot"
# Set them now, this session.
/system script run vigilant-env

# ── 2) Daily self-updater: fetch the current agent script from Vigilant ──
/system script remove [find name="vigilant-bootstrap"]
/system script add name=vigilant-bootstrap dont-require-permissions=no source={
    :global vigilantUrl
    :global vigilantToken
    :global vigilantTlsCheck
    :local cc "yes-without-crl"
    :if ($vigilantTlsCheck = "no") do={ :set cc "no" }
    :local serial [/system routerboard get serial-number]
    :do {
        /tool fetch http-method=get \
            url=("$vigilantUrl/agent/script?serial=" . $serial) \
            http-header-field=("Authorization: Bearer " . $vigilantToken) \
            mode=https check-certificate=$cc dst-path="vigilant-agent.rsc"
        :delay 2s
        :if ([:len [/system script find name="vigilant-agent"]] > 0) do={
            /system script remove [find name="vigilant-agent"]
        }
        /system script add name=vigilant-agent dont-require-permissions=no \
            source=[/file get [find name="vigilant-agent.rsc"] contents]
    } on-error={
        :log warning "vigilant-bootstrap: agent self-update failed (check TLS/token/URL)"
    }
}
/system scheduler remove [find name="vigilant-bootstrap"]
/system scheduler add name=vigilant-bootstrap interval=1d \
    on-event="/system script run vigilant-bootstrap" \
    comment="Vigilant: daily agent self-update"

# ── 3) Fetch the agent NOW (creates the vigilant-agent script) ───────
/system script run vigilant-bootstrap
:delay 3s

# ── 4) Telemetry tick: run the collector every 10s ───────────────────
/system scheduler remove [find name="vigilant-agent"]
/system scheduler add name=vigilant-agent interval=10s \
    on-event="/system script run vigilant-agent" \
    comment="Vigilant: telemetry tick"

:log info "vigilant: install complete (telemetry-only; apply disabled)"
