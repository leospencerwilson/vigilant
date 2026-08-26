# PMR site capture kit

The tool a WCN engineer runs on a pharmacy PC, out of hours, to turn it into a virtual desktop
image the platform can host.

It lives here rather than in the documentation tree because it is **code**, and because Watchman
serves it: the kit is versioned with the server it talks to, and a kit that has drifted from the
API it calls is a kit that fails at a counter at midnight.

```powershell
.\Invoke-PmrCapture.ps1 -Ticket D:\ticket.json            # start
.\Invoke-PmrCapture.ps1 -Resume                           # continue after the reboot
.\Invoke-PmrCapture.ps1 -Ticket D:\ticket.json -DryRun    # every check, nothing changed
```

---

## What is in here

```
Invoke-PmrCapture.ps1        THE orchestrator. There is one.
lib/
  WcnUi.ps1                  output, logging, and the ONE redaction point
  WcnMachine.ps1             SMBIOS + volume fingerprint — "am I still on the same PC?"
  WcnTicket.ps1              the only way a credential enters this kit
  WcnWatchman.ps1            redeem, then the three capability calls, and nothing else
  WcnSql.ps1                 DBCC, with three verdicts instead of two
  WcnRefuse.ps1              EVERY refusal, in one place, re-run at every gate
stages/
  Stage-Printers.ps1         record every printer, then delete every printer
  Stage-GuestAgent.ps1       virtio guest tools — required, and verified running
  Stage-Shrink.ps1           shrink the partition; a failure is a reported outcome
  Stage-Capture.ps1          disk2vhd -> qcow2 (zstd) -> verify -> sha256
  Stage-Upload.ps1           resumable, to a destination the server names
vendor/
  Remove-Bloat.ps1           verbatim. Its $NEVER list is why slimming is safe.
  Strip-PmrImage.ps1         verbatim.
  README.md                  hashes, and why two switches are promotions not skips
docs/
  CAPTURE-TOKEN-CONTRACT.md  the wire as the kit speaks it, and three open gaps
```

**Stage on the USB alongside it:** `disk2vhd.exe`, **`qemu-img.exe`** (without it the kit falls
back to the old `.vhdx.zst`, which the platform cannot record as a format), `sdelete.exe`,
`zstd.exe`, and ideally `virtio-win-guest-tools.exe` (so a pharmacy line is not downloading
60 MB at midnight).

---

## The refusal table

Every one of these is checked in `lib/WcnRefuse.ps1`, and the table is re-run at **three** gates:
`pre` (before anything), `resume` (after the reboot) and `destructive` (the last moment stopping
is free). The whole reason to re-run it is that the world moves while a machine reboots.

| id | refuses when | why it is a refusal and not a warning |
|---|---|---|
| `NOT_ADMIN` | not elevated | every stage needs it |
| `TICKET_MISSING` | no ticket file, unreadable, or not a `wcncap_t_…` secret | there is no other way in — and this is where an admin/Supabase key pasted in as a workaround is refused |
| `TICKET_EXPIRED` | Watchman will not redeem it: expired | ⭐ on a capture ticket this usually means **the pharmacy has opened**. The expiry is clamped to the site's next opening time, so out-of-hours is arithmetic, not a check |
| `TICKET_SPENT` | the 12 redemptions are used up | |
| `TICKET_REVOKED` | somebody revoked it in Watchman | find out why before asking for another |
| `TICKET_UNKNOWN` / `TICKET_REFUSED` | Watchman does not recognise it | |
| `NO_CONNECTIVITY` | Watchman unreachable | there is no offline path — offline is the run with every check below disabled |
| `TOKEN_OVERSCOPED` | the minted token carries anything beyond the three capabilities | ⭐ the kit refuses to hold a credential broader than its job |
| `WINDOW_TOO_SHORT` | < 90 min of ticket left, at `pre` only | a capture takes that long; starting now strands an engineer mid-run at a counter that has opened |
| `FINGERPRINT_UNAVAILABLE` | this PC cannot be identified at all | the resume gate would have nothing to compare |
| `MACHINE_MISMATCH` | this is not the PC the run was started on | ⭐ catches the USB walked to another counter mid-run — otherwise this image is filed under the other machine's slot and nothing downstream can tell |
| `SITE_UNREADABLE` | the slot list could not be read | a duplicate capture cannot be ruled out |
| `ROLE_TAKEN` | that slot is occupied (`pre` gate only) | files this image where another PC's already is. At `resume` the slot is *expected* to be held — by us |
| `SQL_UNPROVEN` | DBCC is dirty, **or NO-CONNECT, or ERR, or no instance for a `server` role** | ⭐ unreadable is not clean. See below |
| `SCRATCH_TOO_SMALL` | scratch < used(C:) × 1.3, or scratch is on C: | running out happens 50 minutes in, after the PC has already been changed |

**There is no override.** No `-Force`, no `-Yes`, no `-SkipChecks`. Every one of these exists
because the alternative cost a site something real, and an override gets reached for on exactly
the night when the check was right. Where a human genuinely knows better — a site whose hours
Watchman has wrong — the fix is to correct the fact in Watchman, which is also the only fix that
helps the next engineer.

### The SQL one, specifically

`Strip-PmrImage.ps1` records `Errors = 'NO-CONNECT'` when the instance will not answer, then
gates on `$_.Errors -is [int] -and $_.Errors -gt 0`. A string is not `[int]`. **An unreadable
database printed "SQL check PASSED" in green and the capture proceeded.**

`lib/WcnSql.ps1` has three verdicts — `clean` / `dirty` / `unproven` — and only `clean`
continues. Role-aware: a `server` with no SQL instance is a refusal (the engine should be there);
a `client` with none passes, because a counter PC has no dispensing database — but if an instance
*is* present it still has to check clean.

---

## The ticket and the token

The kit ships with **nothing**. No key, no URL, no destination. It is handed a ticket at the
counter:

```
ticket file  →  { api, ticket: "wcncap_t_…", issued_to, expires_at }
POST /capture/token  ←  the ticket secret. The only route it works on.
                     →  { token: "wcncap_k_…", expires_at, capabilities, redeem_count/max }
```

**Two objects, not one.** The ticket is issued in Watchman by a named operator, for **one site**,
out of hours; it is *redeemable*, not usable, up to 12 times. Each redemption mints a 90-minute
token, and the token is what every other call presents. A capture takes 30–90 minutes and resumes
across a reboot, so a single-use ticket would strand the kit at 1am, and a credential long enough
to cover the visit would be an eight-hour bearer sitting on a pharmacy PC. A stolen ticket has a
countable budget; a stolen token has ninety minutes.

Three capabilities, exactly — `sites:list`, `slots:read`, `capture:write`. It cannot read pharmacy
data, cannot reach the CRM (Vigilant queries that server-side), cannot touch another site, cannot
create one, and does nothing once it expires.

**Two baseline rules the kit cannot break, because it cannot express them:**

* *Never a typed site.* No capture route accepts a site, and `POST /capture/register` **rejects**
  a body naming one. There is no field in which to type a wrong code.
* *Out of hours only.* The ticket's expiry is `min(issue + 12 h, the site's next opening time)`.
  It is arithmetically incapable of being alive while the pharmacy trades — which is why
  `TICKET_EXPIRED` above says the pharmacy has probably opened.

**Neither secret is ever written to disk by the kit.** The state file records the ticket's *path*;
the resume re-reads it from the USB and redeems again, which is what the budget is for. Logs go
through `Protect-WcnSecret`, which redacts at the single point every line passes through. The
ticket file is shredded at the end of the run, whatever the outcome.

⛔ **No Supabase key. Ever.** The frontend's key decodes to `"role":"service_role"` and bypasses
row-level security for the whole estate; its own file says it must not ship in a deployed build.
The ticket-shape and capability guards refuse it — aimed less at attackers than at the 11pm
workaround.

Wire detail and **three open gaps between kit and server**:
**`docs/CAPTURE-TOKEN-CONTRACT.md`**. The most important is that the upload target names no
transport credential yet, so every capture currently comes home on a USB stick.

---

## What can be tested where

`-DryRun` runs every refusal and every read-only measurement, then **stops before registering**
— a registration is server state (it marks the site mid-build and consumes the role slot), so a
rehearsal must not create one. It reports what it would do: the printers it would delete, and a
deliberately pessimistic shrink projection. Nothing is changed, on the PC or in Watchman.

The individual stages can also be exercised on their own by dot-sourcing them, which is how to
test the destructive ones in a VM without driving the whole pipeline:

```powershell
. .\lib\WcnUi.ps1 ; . .\stages\Stage-Printers.ps1
Invoke-WcnPrinterPurge -ProvenanceDir C:\temp -DryRun
```

### A VM can exercise

| stage | notes |
|---|---|
| the whole refusal table | including `ROLE_TAKEN`, `TOKEN_OVERSCOPED`, `WINDOW_TOO_SHORT` — point it at a staging Watchman. The out-of-hours rule is exercised by asking a staging Watchman for a ticket during a site's open hours: it refuses to ISSUE one |
| ticket parse, scope guard, expiry, shredding | no server needed for the malformed/expired/over-scoped cases |
| machine fingerprint | a VM has SMBIOS and a volume serial like anything else |
| SQL integrity, all three verdicts | install SQL Express; stop the service to produce a genuine `unproven` |
| printer record + purge | add a few fake printers first; the tri-state and the provenance file are fully exercisable |
| strip + debloat | as they always were |
| partition shrink | **including the failure path** — put an unmovable file near the end of the volume |
| zero free space | |
| upload | the USB path fully; the sftp path only once the server names a transport credential (gap 3.1). Resume is testable by killing the transfer half way |
| redeem, register, re-register, report | against a staging Watchman. The upsert/resume behaviour is exercisable by registering the same role twice on one ticket |

### Needs a physical PC

| stage | why |
|---|---|
| **the virtio driver-trust prompt** | this is the point of a human being there. In a VM already running virtio, the guest agent is present and the stage short-circuits — the prompt, and the dismissal that produced three agent-less sites, only appears on hardware that has never seen the driver |
| **disk2vhd against real hardware** | it is a GUI-subsystem tool that hangs headless, and its behaviour against a physical disk with real bad sectors, OEM recovery partitions and vendor block drivers is the thing being proven |
| **a real shrink outcome** | a clean VM disk shrinks easily. The immovable-file path that matters happens on a five-year-old pharmacy PC |
| **honest size numbers** | the 159 GB → 72 GB figure came from real hardware; a VM's disk compresses very differently |
| **the upload over a pharmacy line** | interruption is the property being tested, and a lab link does not interrupt |

---

## Syntax verification status

⚠️ **The PowerShell syntax in this kit is UNVERIFIED.** There is no `pwsh` on the machine it was
written on (macOS, `which pwsh` → not found), so
`[System.Management.Automation.Language.Parser]::ParseFile(...)` could not be run against any of
these files. What *was* checked is a delimiter-balance and structural pass (`tools/lint.py`),
which catches gross imbalance but is not a parser and does not prove the files parse.

**Before this touches a pharmacy PC**, on any Windows box or anything with PowerShell installed:

```powershell
Get-ChildItem -Recurse -Filter *.ps1 | ForEach-Object {
  $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$e)
  if ($e) { Write-Host $_.Name -Fore Red; $e | ForEach-Object { "  $($_.Extent.StartLineNumber): $($_.Message)" } }
}
```

Then run `-DryRun` in a VM. Then read the log.

---

## Superseded

These files under `~/Desktop/western documentation/Virtual Desktop/2-build/image-prep/` are
replaced by this kit and should not be run any more. They have **not** been edited or deleted —
that tree is documentation and is somebody else's to prune.

| superseded | by | because |
|---|---|---|
| `Start-PmrOnboard.ps1` | `Invoke-PmrCapture.ps1` | `-Site` was a typed string; `-Unattended` answered its own prompts; no platform connection at all |
| `Invoke-PmrImagePrep.ps1` | `Invoke-PmrCapture.ps1` | the second orchestrator — two of them means two places for a safety rule to be almost right |
| `Capture-Compress-Upload.ps1` | `stages/Stage-Capture.ps1` + `stages/Stage-Upload.ps1` | the pipeline is carried forward unchanged; the compiled-in `wcn-dreadnaught:` target, `teleport` proxy jump and `wcn_upload` key file are not |

**Still current, and reused verbatim:** `Remove-Bloat.ps1` and `Strip-PmrImage.ps1` (see
`vendor/README.md`). `Inventory-PC.ps1` is untouched and still useful for a pre-visit survey.
`import-pmr-image.sh` is the host-side import and is out of scope here.
