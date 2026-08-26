# WcnTicket.ps1 — the ONLY way a credential enters this kit.
#
# ⛔ THE RULE: no long-lived credential ever ships to a pharmacy PC. Specifically and by name,
# the Supabase key from the frontend's env must never come near this kit — it decodes to
# "role":"service_role" and bypasses row-level security for the whole estate, and the file it
# lives in says so itself. A kit that ships a long-lived credential to a pharmacy PC has failed.
#
# ⭐ TWO OBJECTS, NOT ONE. This mirrors src/shared/captureToken.js exactly, and the reasoning is
# that file's:
#
#   THE TICKET   `wcncap_t_…`. Issued in Watchman by a NAMED operator, for ONE site, out of
#                hours. It is REDEEMABLE, not usable: the only route that accepts it is
#                POST /capture/token. It is what a person handles — read off a screen, into
#                the kit, once.
#
#   THE TOKEN    `wcncap_k_…`. What a redemption mints: a 90-minute bearer carrying the three
#                capabilities. It is what every other call presents.
#
# WHY NOT ONE OBJECT. A capture takes 30–90 minutes AND resumes across a reboot (the guest-agent
# install restarts the PC). A single-use ticket would strand the kit the moment the machine came
# back up, at one in the morning, mid-capture. A single credential long enough to cover the
# visit would be an eight-hour bearer sitting in a file on a pharmacy PC. So: a ticket with a
# countable redemption budget, each redemption minting a token that dies in ninety minutes.
# A stolen ticket has a budget; a stolen token has ninety minutes.
#
# ⛔ THE SITE IS A PROPERTY OF THE TICKET. There is no site field anywhere in this kit and no
# route that accepts one — POST /capture/register rejects a body carrying `pharmacy_id`,
# `site`, or `site_code` outright. "Never a typed site code" is not a validation the kit
# performs and could skip; the kit is physically unable to name another pharmacy.
#
# ⛔ AND "OUT OF HOURS ONLY" IS ARITHMETIC, NOT A CHECK. The ticket's expiry is
# min(issue + 12 h, the site's next opening time), so it is incapable of being alive while the
# pharmacy is trading. The kit cannot skip that rule because the kit does not implement it.

Set-StrictMode -Version 2.0

# MUST match captureToken.CAPABILITIES. Three, and there are three.
#   sites:list      the one site this ticket admits (returned as a list so the kit renders a
#                   picker and the engineer CONFIRMS rather than types)
#   slots:read      which role slots are already taken, so a duplicate is refused before
#                   ninety minutes are spent producing one
#   capture:write   register/resume THIS site's capture, and be told where to upload
$script:WcnRequiredCaps = @('sites:list', 'slots:read', 'capture:write')

# A ticket secret looks like this. Checked so that pasting an admin token, a device token or a
# Supabase JWT into the ticket file fails HERE, with a sentence, rather than as a puzzling 401.
$script:WcnTicketSecretPattern = '^wcncap_t_[A-Za-z0-9_-]{20,}$'

function Get-WcnProp {
    # PS 5.1's ConvertFrom-Json yields PSCustomObject, and reading a missing property under
    # Set-StrictMode throws. Every read of untrusted server or ticket content goes through here,
    # so malformed content becomes a refusal with a sentence rather than a PropertyNotFound.
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if (-not $p) { return $Default }
    if ($null -eq $p.Value) { return $Default }
    return $p.Value
}

function Read-WcnTicket {
    <#
      Load the ticket file. NEVER throws on bad content — it returns .Ok = $false with .Error
      set, because every one of these is a refusal the table has to render in one voice.

      The file is small on purpose. It holds where to go and the redeemable secret, and NOTHING
      about the site: the kit learns which pharmacy it is at by asking, using the ticket.

          {
            "v": 1,
            "kind": "wcn.pmr.capture-ticket",
            "api": "https://watchman.example",
            "ticket": "wcncap_t_…",
            "issued_to": "leo.wilson@westerncommunication.co.uk",
            "expires_at": "2026-08-27T06:00:00Z"
          }

      `issued_to` and `expires_at` are DISPLAY ONLY and explicitly untrusted — the server holds
      the authoritative copies and hands them back on redemption. They exist so an engineer can
      see whose ticket it is without spending a redemption.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $bad = { param($msg) [pscustomobject]@{ Ok = $false; Error = $msg; Path = $Path } }

    if (-not (Test-Path -LiteralPath $Path)) { return (& $bad "no ticket at $Path") }

    $raw = $null
    try { $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
    catch { return (& $bad ("the ticket file could not be read: {0}" -f $_.Exception.Message)) }
    if ([string]::IsNullOrWhiteSpace($raw)) { return (& $bad 'the ticket file is empty') }

    $t = $null
    try { $t = $raw | ConvertFrom-Json -ErrorAction Stop }
    catch { return (& $bad 'the ticket is not valid JSON — re-issue it from Watchman rather than editing it') }

    $kind = [string](Get-WcnProp $t 'kind')
    if ($kind -ne 'wcn.pmr.capture-ticket') {
        return (& $bad ("this is not a capture ticket (kind='{0}') — a credential for something else must not be used here" -f $kind))
    }
    $v = Get-WcnProp $t 'v'
    if ([string]$v -ne '1') { return (& $bad ("ticket schema v{0} is not understood by this kit — update the kit or re-issue the ticket" -f $v)) }

    $api = [string](Get-WcnProp $t 'api')
    if ([string]::IsNullOrWhiteSpace($api)) { return (& $bad 'the ticket names no Watchman URL') }
    # http:// is refused outright: the ticket is a bearer credential and it is about to cross a
    # pharmacy's own network.
    if ($api -notmatch '^https://') { return (& $bad ("the ticket's api must be an https:// URL, not '{0}'" -f $api)) }

    $secret = [string](Get-WcnProp $t 'ticket')
    if ([string]::IsNullOrWhiteSpace($secret)) { return (& $bad 'the ticket file carries no ticket secret') }

    # ⭐ THE GUARD THAT MATTERS MOST HERE. A capture ticket has a recognisable shape. Anything
    # else in this field is somebody substituting a credential they had to hand — and the
    # realistic path for that is not an attack, it is a tired engineer at 11pm whose ticket
    # expired, who has the estate admin token in a password manager because it works for
    # everything else. It does not work here, and the message says why.
    if ($secret -notmatch $script:WcnTicketSecretPattern) {
        return (& $bad ('that is not a capture ticket secret (a capture ticket starts "wcncap_t_"). ' +
                        'Do NOT substitute an admin, operator, device or Supabase key: this kit will not ' +
                        'carry a credential broader than its job, and a pharmacy PC is not a place to put one.'))
    }

    return [pscustomobject]@{
        Ok         = $true
        Error      = $null
        Path       = $Path
        Api        = $api.TrimEnd('/')
        Secret     = $secret
        # ⚠️ DISPLAY ONLY, AND UNVERIFIED. The server's copies are authoritative and arrive on
        # redemption. Never gate on these.
        IssuedTo   = [string](Get-WcnProp $t 'issued_to' '')
        ExpiresHint = [string](Get-WcnProp $t 'expires_at' '')
    }
}

function Test-WcnCapabilities {
    <#
      Compare what the server SAID this token may do against what this kit is allowed to hold.

      ⭐ The kit refuses a credential BROADER than its job, even though a broader one would work
      perfectly and would make the operator's immediate problem go away. A control that only
      stops adversaries stops nobody on the night it is actually needed.

      Reads the `capabilities` array the mint response puts on the wire by name — the kit does
      not infer its permissions from which calls happen to succeed.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Capabilities)
    $have    = @($Capabilities)
    $extra   = @($have | Where-Object { $script:WcnRequiredCaps -notcontains $_ })
    $missing = @($script:WcnRequiredCaps | Where-Object { $have -notcontains $_ })
    return [pscustomobject]@{
        Extra   = $extra
        Missing = $missing
        Ok      = ($extra.Count -eq 0 -and $missing.Count -eq 0)
        Required = $script:WcnRequiredCaps
    }
}

function Remove-WcnTicket {
    <#
      Destroy the ticket at the end of the run, whatever the outcome.

      Overwritten before deletion — not because forensic recovery is in the threat model, but
      because the realistic exposure is the USB stick going into the next PC and somebody
      reading what is on it. Never fatal: failing a completed capture over a file permission
      would be absurd.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $true }
        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -gt 0) {
            $junk = New-Object byte[] $len
            (New-Object System.Random).NextBytes($junk)
            [System.IO.File]::WriteAllBytes($Path, $junk)
        }
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        return $true
    } catch { return $false }
}
