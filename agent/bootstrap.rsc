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
# TLS: vigilantTlsCheck controls /tool fetch check-certificate. NOTE: real estate boxes
# (e.g. a 7.18 unit) returned "SSL: no trusted CA certificate found" on a validating fetch —
# RouterOS's builtin trust store is often empty/disabled, so validation FAILS out of the box.
# So the default is "no" (skip verification; still TLS-encrypted) for reliable onboarding.
# To harden a site: import the Cloudflare-edge CA (/certificate import) or populate+enable
# the builtin trust store, then set vigilantTlsCheck to a validating mode.
#   "no"               -> skip verification (DEFAULT; still TLS-encrypted but unverified)
#   "yes-without-crl"  -> validate the chain (needs a CA imported / trust store populated)
#   "yes"              -> validate incl. CRL
#
# Config-apply: vigilantApplyEnabled=false keeps the device telemetry-only. It will NOT
# change anything on the router until you deliberately flip this to true later.

# ── 1) Persistent globals (survive reboot) ───────────────────────────
/system script remove [find name="vigilant-env"]
/system script add name=vigilant-env dont-require-permissions=no source={
    :global vigilantUrl "<VIGILANT_URL>"
    :global vigilantToken "<VIGILANT_TOKEN>"
    # TLS verification for /tool fetch. Default "no" (skip verification — still TLS-
    # encrypted) because real estate boxes were observed with an empty/disabled trust store
    # ("SSL: no trusted CA certificate found"), which makes a validating fetch fail. To
    # HARDEN a site, import the Cloudflare-edge CA (/certificate import) or enable a
    # populated builtin trust store, then set this to "yes-without-crl". Note: with "no",
    # the per-device bearer is sent over unverified TLS — fine for a pilot; for estate-wide
    # rollout, harden so the token can't be captured by a path MITM.
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
