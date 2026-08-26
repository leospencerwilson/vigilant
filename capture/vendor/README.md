# vendor/ — carried forward, byte-for-byte

These two scripts are **verbatim copies** of the originals under
`~/Desktop/western documentation/Virtual Desktop/2-build/image-prep/`. Not forks. Not
"mostly the same". Identical files, so a fix in either place is a fix in one place.

| file | sha256 of the source, at the moment it was copied (2026-08-26) |
|---|---|
| `Remove-Bloat.ps1`   | `2af7e776abf85aed92bad191526640550ed5d3190855836e621055260eb1e7ed` |
| `Strip-PmrImage.ps1` | `73518d8c38087258d280fe9b481261edcb8d773a846a821798d50b6c7deca78d` |

Verify at any time with:

```bash
shasum -a 256 vendor/Remove-Bloat.ps1 vendor/Strip-PmrImage.ps1
```

## Why they were not rewritten

`Remove-Bloat.ps1` is the most valuable single asset in the whole kit, and the reason is its
two protection lists:

* `$NEVER` — a version- and instance-agnostic pattern protecting ProScript, EMIS, RxSystems, the
  SQL **engine** and its connectivity layers (but deliberately not SSMS), the NHS Spine smartcard
  stack in all four vendor spellings (`oberthur|gemalto|idemia|classic client`), Identity Agent,
  virtio/QEMU, and the .NET and VC++ runtimes.
* `$PROTECT_PATH` — the ProScript and EMIS data directories, any `MSSQL<ver>.<INSTANCE>\DATA`
  whatever the version or instance name, and `*.bak` anywhere.

That list is what makes aggressive slimming safe, and the baseline makes it **load-bearing**:
"strip Windows features and preinstalled apps, zero free space, and shrink the partition and the
virtual disk" is only a defensible instruction because these patterns stand between it and a
pharmacy's dispensing data. It was built from a real whole-PC classification pass on RX54554 and
it encodes a lot of specific knowledge — `sra-pin-*`, `quovadx`, `drugcomparison`, `rx scheduler`
— that nobody would reconstruct from memory correctly.

`Strip-PmrImage.ps1` is ~500 lines of proven behaviour: the Appx debloat with its per-package
try/catch (some packages throw a *terminating* error that `-EA SilentlyContinue` does not
suppress), `DISM /ResetBase`, the profile purge with its `takeown`/`icacls`/`rd` escalation, the
pagefile and hibernation removal that later makes the partition shrink possible.

## How they are called, and the two switches

The orchestrator invokes them as:

```powershell
& vendor\Strip-PmrImage.ps1 -SkipGuestTools -SkipSqlCheck
& vendor\Remove-Bloat.ps1 -Execute
```

Both switches are **promotions, not skips**. The two things this script did weakly are now done
properly upstream of it, where their failure is a refusal instead of a warning:

* **`-SkipGuestTools`** → `stages/Stage-GuestAgent.ps1`. The vendor A0 stage installs
  virtio-win-guest-tools correctly (Red Hat / WHQL-signed, so EDR does not flag it) but ends in
  `catch { Write-Host "guest-tools install skipped/failed" -ForegroundColor Yellow }`. That catch
  block is why three VMs in this estate have no guest agent, and each one costs an engineer visit
  to fix. The new stage installs it, **waits for the service**, and refuses the run if it is not
  `Running`.

* **`-SkipSqlCheck`** → `lib/WcnSql.ps1`. The vendor check records `Errors = 'NO-CONNECT'` when
  the instance will not answer and `'ERR'` when the check throws, then gates on
  `$_.Errors -is [int] -and $_.Errors -gt 0`. A string is not `[int]`, so **an unreadable
  database printed "SQL check PASSED" in green and the capture proceeded**. The new module has
  three verdicts — clean / dirty / *unproven* — and only `clean` continues.

Everything else in both scripts runs exactly as written.

## If you change either file

Change it in the documentation tree, copy it here, and update the hash table above. Do not edit
the copy in place: a silent divergence between the two is precisely the failure mode the printer
contract describes, where three owners each applied their own version of one shared format.
