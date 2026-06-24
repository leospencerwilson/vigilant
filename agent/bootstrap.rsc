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
# TLS: vigilantTlsCheck controls /tool fetch check-certificate. RouterOS 7.12+ ships a
# builtin trust store containing the public roots, so a validating fetch to the
# Cloudflare-fronted host works with NO CA import on a healthy box (correct clock + trust
# store on). Two things break it on a fresh board: a wrong clock (1970 RTC -> "cert not yet
# valid") and a disabled trust store — fix both before install (see ONBOARDING-A-SITE.md §2).
#   "yes-without-crl"  -> validate the chain via the builtin trust store (default; secure)
#   "yes"              -> validate incl. CRL
#   "no"               -> skip verification (fallback only; still TLS-encrypted but unverified)
#
# Config-apply: vigilantApplyEnabled=false keeps the device telemetry-only. It will NOT
# change anything on the router until you deliberately flip this to true later.

# ── 1) Persistent globals (survive reboot) ───────────────────────────
/system script remove [find name="vigilant-env"]
/system script add name=vigilant-env dont-require-permissions=no source={
    :global vigilantUrl "<VIGILANT_URL>"
    :global vigilantToken "<VIGILANT_TOKEN>"
    # "yes-without-crl" = validate the TLS chain (RouterOS 7.12+ ships a builtin trust
    # store that contains the public root behind the Cloudflare edge, so no CA import is
    # needed on a healthy box with a correct clock). Set to "no" ONLY as a fallback if a
    # validating fetch fails after fixing the clock + trust store (see ONBOARDING-A-SITE.md).
    :global vigilantTlsCheck "yes-without-crl"
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
