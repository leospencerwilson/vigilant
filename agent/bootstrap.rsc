# Vigilant bootstrap — DRAFT. REVIEW BEFORE APPLYING TO ANY LIVE ROUTER.
# RouterOS 7.x.
#
# Purpose: keep the data-collection agent centrally managed. This tiny scheduler
# fetches the *current* agent script from Vigilant once a day and replaces the local
# `vigilant-agent` script. So you change what's collected in ONE place (Vigilant) and
# the whole estate self-updates — you never hand-edit 250 routers again.
#
# One-time per device (done at enrolment, with the device's own token):
#   :global vigilantUrl   "https://vigilant.western-communication.com"
#   :global vigilantToken "<PER-DEVICE-ENROLMENT-TOKEN>"   ;# NOT a shared key
#
# Safety: review the fetched script's checksum server-side; this only swaps the
# collector script, it does NOT apply router config. Config changes go through the
# review-gated config-job path in vigilant-agent.rsc.

/system script
add name=vigilant-bootstrap dont-require-permissions=no source={
    :global vigilantUrl
    :global vigilantToken
    :local serial [/system routerboard get serial-number]
    :do {
        # Fetch the current agent script body into a file, then load it as a script.
        /tool fetch http-method=get \
            url=("$vigilantUrl/agent/script?serial=" . $serial) \
            http-header-field=("Authorization: Bearer " . $vigilantToken) \
            mode=https dst-path="vigilant-agent.rsc"
        :delay 2s
        # Replace the agent script with the freshly fetched body.
        :if ([:len [/system script find name="vigilant-agent"]] > 0) do={
            /system script remove [find name="vigilant-agent"]
        }
        /system script add name=vigilant-agent dont-require-permissions=no \
            source=[/file get [find name="vigilant-agent.rsc"] contents]
    } on-error={
        :log warning "vigilant-bootstrap: agent self-update failed"
    }
}

/system scheduler
add name=vigilant-bootstrap interval=1d on-event="/system script run vigilant-bootstrap" \
    comment="Vigilant: daily agent self-update"
