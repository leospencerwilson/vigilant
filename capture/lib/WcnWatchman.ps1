# WcnWatchman.ps1 — the kit's entire connection to the platform. One redeem, three calls.
#
# The old kit had NO connection to the platform at all: grepping watchman|vigilant|api across
# every script returned nothing. The site was a typed string, so a fat-fingered RX99999 produced
# a valid capture of a real pharmacy filed against a site that does not exist — an association
# nothing downstream can correct, because a P2V image carries no proof of where it came from.
# Nothing registered a capture either, so a site mid-build existed only in somebody's head.
#
# ⛔ CONNECTIVITY IS REQUIRED, and there is no offline path. An offline capture is precisely the
# capture that cannot confirm the site, cannot see which slots are taken, cannot be bounded to
# the closed window and cannot tell anyone it is happening — that is, the capture with every
# safeguard disabled at once. An --offline switch would not be a convenience; it would be a
# single bypass for all of them, and it would get used.
#
# THE WIRE, mirroring src/shared/captureToken.js and src/ingest/server.js:
#
#   POST /capture/token      ← the TICKET secret. The only route it works on. Mints a token.
#   GET  /capture/sites      cap sites:list     the one site this ticket admits
#   GET  /capture/slots      cap slots:read     which roles are taken
#   POST /capture/register   cap capture:write  register/resume, and be told where to upload
#
# ⚠️ NOTE WHAT IS NOT IN ANY OF THOSE PATHS: a site. Not a path parameter, not a query string,
# not a body field — POST /capture/register REFUSES a body carrying pharmacy_id, site or
# site_code with a 400. The pharmacy is read from the token server-side.

Set-StrictMode -Version 2.0

# Windows PowerShell 5.1 on an un-patched pharmacy build still defaults to SSL3/TLS1.0 on
# .NET 4.5, and the failure is an opaque "underlying connection was closed" that names no
# protocol. Force TLS 1.2 once, here.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ── the session: a ticket, and the token currently minted from it ────────────────────────────
# ⛔ THE TOKEN LIVES ONLY IN MEMORY. It is never written to the state file and never to the log.
# Across the reboot the kit re-reads the TICKET from the USB and redeems again, which is exactly
# what the ticket's redemption budget is for.
function New-WcnSession {
    param([Parameter(Mandatory)]$Ticket)
    return [pscustomobject]@{
        Ticket           = $Ticket
        Api              = $Ticket.Api
        Token            = $null
        TokenExpiresAt   = $null
        Capabilities     = @()
        RedeemCount      = $null
        RedeemMax        = $null
        TicketExpiresAt  = $null
        Endpoints        = $null
    }
}

function Invoke-WcnRedeem {
    <#
      Spend one redemption and mint a 90-minute token.

      Called at the start, after the reboot, and any time a call comes back 401 — a capture can
      outlive a 90-minute token, and the budget (12) exists precisely to cover that plus the
      reboots the guest-agent install forces.

      The refusal reasons are the server's own, and they are worth reading verbatim to the
      operator: 'expired' on a capture ticket does not mean "you were slow", it means THE
      PHARMACY HAS OPENED — the ticket is bounded to the closed window by arithmetic.
    #>
    param([Parameter(Mandatory)]$Session)

    $uri = ("{0}/capture/token" -f $Session.Api)
    $headers = @{ Authorization = ("Bearer {0}" -f $Session.Ticket.Secret); Accept = 'application/json' }
    try {
        $r = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
    } catch {
        $status = 0; $reason = $null; $said = $null
        try {
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $rd = New-Object System.IO.StreamReader($stream)
                    $text = $rd.ReadToEnd(); $rd.Close()
                    if ($text) {
                        try {
                            $parsed = $text | ConvertFrom-Json -ErrorAction Stop
                            $said   = [string](Get-WcnProp $parsed 'error')
                            $reason = [string](Get-WcnProp $parsed 'reason')
                        } catch { $said = $text.Substring(0, [Math]::Min(300, $text.Length)) }
                    }
                }
            }
        } catch { }
        if (-not $said) { $said = $_.Exception.Message }
        return [pscustomobject]@{ Ok = $false; Error = $said; Reason = $reason; Status = $status }
    }

    $caps = @(@(Get-WcnProp $r 'capabilities' @()) | ForEach-Object { [string]$_ })
    $Session.Token           = [string](Get-WcnProp $r 'token')
    $Session.TokenExpiresAt  = [string](Get-WcnProp $r 'expires_at')
    $Session.Capabilities    = $caps
    $Session.RedeemCount     = Get-WcnProp $r 'redeem_count'
    $Session.RedeemMax       = Get-WcnProp $r 'redeem_max'
    $Session.TicketExpiresAt = [string](Get-WcnProp $r 'ticket_expires_at')
    # The server names its own three routes. The kit does not compose them either — it only
    # records them, so a mismatch between kit and server is visible rather than a 404.
    $Session.Endpoints       = Get-WcnProp $r 'endpoints'

    if (-not $Session.Token) { return [pscustomobject]@{ Ok = $false; Error = 'Watchman returned no token'; Reason = $null; Status = 200 } }
    return [pscustomobject]@{ Ok = $true; Error = $null; Reason = $null; Status = 200 }
}

function Invoke-WcnEnsureToken {
    <#
      Redeem ONLY if we do not hold a usable token. The refusal table runs at three gates and
      calls this at each one; redeeming every time would burn a third of the ticket's budget
      (12) on checks alone and leave nothing for the reboot and the long transfer.

      ⭐ AND SKIPPING THE REDEEM DOES NOT WEAKEN THE OUT-OF-HOURS GATE. A token's expiry is
      clamped to LEAST(now + 90 min, the ticket's expiry), and the ticket's expiry is clamped to
      the site's next opening time. So a token that is still valid is itself proof that the
      pharmacy has not opened — the property is arithmetic, and re-asking for it would only be
      asking the same arithmetic again.

      The 10-minute floor stops a token expiring in the middle of the very call it was checked for.
    #>
    param([Parameter(Mandatory)]$Session, [int]$MinRemainingMinutes = 10)
    if ($Session.Token -and $Session.TokenExpiresAt) {
        try {
            $left = ([datetime]$Session.TokenExpiresAt).ToUniversalTime() - [DateTime]::UtcNow
            if ($left.TotalMinutes -ge $MinRemainingMinutes) {
                return [pscustomobject]@{ Ok = $true; Error = $null; Reason = $null; Status = 200; Reused = $true }
            }
        } catch { }
    }
    $r = Invoke-WcnRedeem -Session $Session
    return [pscustomobject]@{ Ok = $r.Ok; Error = $r.Error; Reason = $r.Reason; Status = $r.Status; Reused = $false }
}

function Invoke-WcnApi {
    <#
      One authenticated call. Returns @{ Ok; Status; Data; Error }. NEVER throws: every caller
      feeds a refusal table, and a table that renders "Watchman refused the ticket" is useful
      where a stack trace is not.

      ⭐ A 401 IS AUTOMATICALLY RE-REDEEMED, ONCE. A token lives 90 minutes and a capture can
      take longer; without this the run would die at the compress step having done all the work.
      Once, not in a loop: a token that is refused immediately after a fresh mint means
      something is wrong that spending the rest of the budget will not fix.
    #>
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body = $null,
        [int]$TimeoutSec = 30,
        [switch]$NoRefresh
    )
    if (-not $Session.Token) {
        $mint = Invoke-WcnRedeem -Session $Session
        if (-not $mint.Ok) { return [pscustomobject]@{ Ok = $false; Status = 401; Data = $null; Error = $mint.Error; Reason = $mint.Reason } }
    }

    $uri = ("{0}{1}" -f $Session.Api, $Path)
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $headers = @{ Authorization = ("Bearer {0}" -f $Session.Token); Accept = 'application/json' }
        try {
            $args = @{ Uri = $uri; Method = $Method; Headers = $headers; TimeoutSec = $TimeoutSec
                       UseBasicParsing = $true; ErrorAction = 'Stop' }
            if ($null -ne $Body) {
                $args.ContentType = 'application/json'
                $args.Body = ($Body | ConvertTo-Json -Depth 8 -Compress)
            }
            $resp = Invoke-RestMethod @args
            return [pscustomobject]@{ Ok = $true; Status = 200; Data = $resp; Error = $null; Reason = $null }
        } catch {
            $status = 0; $said = $null; $data = $null
            try {
                if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                    $status = [int]$_.Exception.Response.StatusCode
                    $stream = $_.Exception.Response.GetResponseStream()
                    if ($stream) {
                        $rd = New-Object System.IO.StreamReader($stream)
                        $text = $rd.ReadToEnd(); $rd.Close()
                        if ($text) {
                            try { $data = $text | ConvertFrom-Json -ErrorAction Stop
                                  $said = [string](Get-WcnProp $data 'error') }
                            catch { $said = $text.Substring(0, [Math]::Min(300, $text.Length)) }
                        }
                    }
                }
            } catch { }
            if (-not $said) { $said = $_.Exception.Message }

            if ($status -eq 401 -and $attempt -eq 1 -and -not $NoRefresh) {
                # The token aged out mid-run. Spend a redemption and try once more.
                $mint = Invoke-WcnRedeem -Session $Session
                if (-not $mint.Ok) {
                    return [pscustomobject]@{ Ok = $false; Status = 401; Data = $null; Error = $mint.Error; Reason = $mint.Reason }
                }
                continue
            }
            return [pscustomobject]@{ Ok = $false; Status = $status; Data = $data; Error = $said
                                      Reason = [string](Get-WcnProp $data 'reason') }
        }
    }
    return [pscustomobject]@{ Ok = $false; Status = 0; Data = $null; Error = 'unreachable'; Reason = $null }
}

function Get-WcnCaptureSite {
    <#
      CAPABILITY 1 of 3 — sites:list.

      Returns the ONE site this ticket admits. It arrives as a list because the kit renders a
      picker and the engineer CONFIRMS what Watchman already decided, rather than typing a code
      that could be wrong. The kit cannot widen it: there is no site parameter on this route.
    #>
    param([Parameter(Mandatory)]$Session)
    $r = Invoke-WcnApi -Session $Session -Method GET -Path '/capture/sites'
    if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Sites = @(); Error = $r.Error; Reason = $r.Reason } }
    return [pscustomobject]@{
        Ok    = $true
        Error = $null
        Sites = @(Get-WcnProp $r.Data 'sites' @())
        ScopedToTicket = [bool](Get-WcnProp $r.Data 'scoped_to_ticket' $false)
    }
}

function Get-WcnCaptureSlots {
    <#
      CAPABILITY 2 of 3 — slots:read.

      Every role at this site with whether it is taken and BY WHAT. The server counts three
      sources of "taken" — an existing capture run, a counter row, and (for the server) the
      site's own srv_vmid — so the picker cannot offer a slot the register call would then
      refuse, which is how an engineer's night gets wasted.

      `roles` comes back on the wire so the picker cannot invent an eleventh client. Ten,
      because a /27 site addresses its desktops at .11-.20 and that is exactly the addressable
      range; each slot also carries the `address` it would land on, so ".13" is visible beside
      Client 03 and a mis-pick is not silent.
    #>
    param([Parameter(Mandatory)]$Session)
    $r = Invoke-WcnApi -Session $Session -Method GET -Path '/capture/slots'
    if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Error = $r.Error; Reason = $r.Reason } }
    return [pscustomobject]@{
        Ok    = $true
        Error = $null
        Site  = Get-WcnProp $r.Data 'site'
        Slots = @(Get-WcnProp $r.Data 'slots' @())
        Roles = @(Get-WcnProp $r.Data 'roles' @())
    }
}

function Register-WcnCapture {
    <#
      CAPABILITY 3 of 3 — capture:write. An UPSERT, which is what makes a resume work: the same
      ticket registering the same role again updates its own row and is handed the SAME upload
      path back, so a broken 70 GB transfer continues instead of restarting.

      ⛔ THE BODY MUST NOT NAME A SITE. pharmacy_id / pharmacy_code / site / site_code are all
      rejected with a 400 by the server — deliberately an error rather than an ignored field,
      because a kit sending one is either misconfigured or a token being used from somewhere it
      should not be, and both need a person.

      ⛔ out_of_hours IS NOT SENT. The server decides it from the site's own hours at the moment
      of the call. A tool asserting its own compliance is not evidence of it.

      ⚠️ THE TRI-STATES GO UP AS $true / $false / $null AND MUST NOT BE COERCED. $null means
      "this run did not establish it", which is NOT false — captureTri() on the far end keeps
      anything that is not a real boolean as null for the same reason. A false all-clear on
      printers_cleared is a site imported with the pharmacy's old printers still installed.
    #>
    param(
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)][string]$Role,        # 'server' | 'client-01' … 'client-10'
        [Parameter(Mandatory)]$Machine,
        [string]$StartedAt,
        [string]$UploadedAt,
        $DiskGB = $null,
        [string]$ImageFormat,
        [string]$ImageSha256,
        $BytesTotal = $null,
        $BytesSent = $null,
        $GuestAgentInstalled = $null,
        $PrintersCleared = $null,
        $Slimmed = $null,
        [string]$FailedReason
    )
    $body = @{
        role = $Role
        # ⚠️ PROVENANCE ONLY, NEVER A KEY — and the server treats it the same way. A PC name
        # survives P2V, so duplicates across this estate are expected, and no filename the
        # server composes contains it.
        pc_name               = $Machine.Hostname
        started_at            = $StartedAt
        uploaded_at           = $UploadedAt
        disk_gb               = $DiskGB
        image_format          = $ImageFormat
        image_sha256          = $ImageSha256
        bytes_total           = $BytesTotal
        bytes_sent            = $BytesSent
        guest_agent_installed = $GuestAgentInstalled
        printers_cleared      = $PrintersCleared
        slimmed               = $Slimmed
        failed_reason         = $FailedReason
    }
    # Strip only the keys we genuinely have nothing to say about. The tri-states are NOT
    # stripped: an explicit null is the fact "not established" and must reach the server.
    foreach ($k in @('started_at', 'uploaded_at', 'image_format', 'image_sha256', 'failed_reason')) {
        if (-not $body[$k]) { $body.Remove($k) }
    }

    $r = Invoke-WcnApi -Session $Session -Method POST -Path '/capture/register' -Body $body -TimeoutSec 60
    if (-not $r.Ok) {
        return [pscustomobject]@{
            Ok = $false; Status = $r.Status; Error = $r.Error
            # A 409 names who holds the slot, which is what stops a refusal an engineer cannot
            # explain from becoming a refusal they work around.
            Conflict = $(if ($r.Status -eq 409) { Get-WcnProp $r.Data 'capture' } else { $null })
            Capture = $null; Upload = $null; UploadRefused = $null
        }
    }
    return [pscustomobject]@{
        Ok            = $true
        Status        = 200
        Error         = $null
        Conflict      = $null
        Capture       = Get-WcnProp $r.Data 'capture'
        # ⛔ THE SERVER NAMES THE DESTINATION, per registration. Null is a real answer and the
        # kit honours it by falling back to the USB — never by inventing a plausible path.
        Upload        = Get-WcnProp $r.Data 'upload'
        # And when there is none, WHY, by name: 'no-target-reported', 'target-is-network-storage'
        # (the documented NFS share is dead), 'target-short-on-space', …
        UploadRefused = Get-WcnProp $r.Data 'upload_refused'
    }
}
