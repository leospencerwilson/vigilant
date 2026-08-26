# The wire, as the kit speaks it — and three gaps

The server side is **built**: `src/shared/captureToken.js`, `authCaptureToken` in
`src/ingest/server.js`, and the four handlers in `src/ingest/handlers.js`. This kit is written
against that code, not against a proposal. This document records what the kit sends and expects,
and names the places where the two halves do not yet meet.

---

## 1 · Two objects, and the kit holds nothing

```
TICKET   wcncap_t_…   issued in Watchman by a NAMED operator, for ONE site, out of hours.
                      REDEEMABLE, not usable. The only route that accepts it is
                      POST /capture/token. Up to TICKET_REDEEM_MAX (12) redemptions.
TOKEN    wcncap_k_…   what a redemption mints. 90 minutes. Carries the three capabilities.
                      Never written to disk by the kit — memory only.
```

The kit ships with no key, no URL and no destination. The ticket file is the sole input:

```json
{ "v": 1, "kind": "wcn.pmr.capture-ticket",
  "api": "https://watchman.example",
  "ticket": "wcncap_t_…",
  "issued_to": "leo.wilson@westerncommunication.co.uk",
  "expires_at": "2026-08-27T06:00:00Z" }
```

`issued_to` and `expires_at` are **display only and explicitly untrusted** — the server holds the
authoritative copies and returns them on redemption. `api` must be `https://`; the kit refuses
`http://`. The file is shredded at the end of the run, whatever the outcome.

### Two rules the kit cannot break because it cannot express them

* **Never a typed site.** No capture route takes a site — not as a path parameter, not as a query
  string. `POST /capture/register` *rejects* a body carrying `pharmacy_id`, `pharmacy_code`,
  `site` or `site_code` with a 400. The kit is physically unable to name another pharmacy.
* **Out of hours only.** The ticket's expiry is `min(issue + 12 h, the site's next opening time)`.
  It cannot be alive while the pharmacy is trading. The kit does not implement this rule, so the
  kit cannot skip it.

The kit's `TICKET_EXPIRED` refusal therefore says, in as many words, that the pharmacy has
probably opened — because on a capture ticket that is what expiry usually means.

### The capability guard

`Test-WcnCapabilities` refuses a minted token whose `capabilities` are not exactly
`sites:list`, `slots:read`, `capture:write`. `Read-WcnTicket` refuses a ticket secret that does
not match `^wcncap_t_…`.

Neither guard is aimed at attackers. Both are aimed at the tired engineer at 11pm whose ticket
expired, who has the estate admin token in a password manager because it works for everything
else, and who has no reason to think it would not work here. It does not, and the message says
why. ⛔ The Supabase `service_role` key — which bypasses row-level security for the whole estate,
and whose own env file says it must never ship in a deployed build — is refused by the same guard.

---

## 2 · The calls

| call | capability | kit function |
|---|---|---|
| `POST /capture/token` | *(the ticket secret)* | `Invoke-WcnRedeem` / `Invoke-WcnEnsureToken` |
| `GET /capture/sites` | `sites:list` | `Get-WcnCaptureSite` |
| `GET /capture/slots` | `slots:read` | `Get-WcnCaptureSlots` |
| `POST /capture/register` | `capture:write` | `Register-WcnCapture` |

**Token refresh.** A capture can outrun a 90-minute token, so `Invoke-WcnApi` re-redeems once on
a 401 and retries. `Invoke-WcnEnsureToken` reuses a token with more than 10 minutes left rather
than spending a redemption at every gate — which does **not** weaken the hours rule, because a
token's expiry is clamped to the ticket's and the ticket's to the opening time, so a live token
is itself proof the pharmacy has not opened.

**`GET /capture/sites`** returns one row (`scoped_to_ticket: true`). The kit renders it as a
picker so a human *confirms* the pharmacy before a destructive run — not so they can choose.

**`GET /capture/slots`** returns every role with `taken`, `taken_by`, `address` and the held
`capture`. The kit's picker uses the server's own `roles` list, so it cannot invent an eleventh
client, and shows `address` beside each slot so a mis-pick is not silent.

**`POST /capture/register`** is an **upsert**, which is what makes the resume work: the same
ticket registering the same role updates its own row and is handed the same `upload.path` back.
The kit calls it three times — at start (to make the site visibly mid-build and bind the
machine), after the capture (to record the image and refresh the destination), and at the end
(to report the outcome). It sends:

`role` · `pc_name` · `started_at` · `uploaded_at` · `disk_gb` · `image_format` · `image_sha256`
· `bytes_total` · `bytes_sent` · `guest_agent_installed` · `printers_cleared` · `slimmed` ·
`failed_reason`

> ⚠️ **The tri-states go up as `$true` / `$false` / `$null` and are never coerced.** `$null` means
> "this run did not establish it", which is not `false` — `captureTri()` keeps it that way on the
> far end for the same reason. The kit reports `$null` from a dry run and from any run where the
> spooler could not be re-read. A false all-clear on `printers_cleared` is a site imported with
> the pharmacy's old printers still installed.

> ⚠️ **`out_of_hours` is not sent.** The server derives it from the site's own hours at the moment
> of the call. A tool asserting its own compliance is not evidence of it.

---

## 3 · Three gaps between the halves

### ⭐ 3.1 The upload target names no transport (blocking)

`shapeUploadTarget()` returns `kind` · `node` · `storage` · `dir` · `filename` · `path` ·
`resumable` · `resume` · `usb_fallback_ok`. There is **no `host`, no `user` and no credential**,
so a kit holding that object knows *where* the file goes and has no way to send it.

`Invoke-WcnUploadSftp` is written against `host` / `user` / `credential` / `host_key` /
`proxy_jump` and **refuses cleanly when they are absent** — it does not guess a username, derive
a hostname from the node name, or fall back to whatever key an agent happens to have loaded.
The kit then takes the USB road (`usb_fallback_ok` is `true`) and reports `uploaded_at: null`,
which is honest: an image on a stick in an engineer's bag is not an image Watchman holds.

**To close it,** add to the object `shapeUploadTarget` returns:

```js
host: …, user: …, host_key: …,       // pinned; the kit refuses to connect without it
credential: …, credential_expires_at: …,   // short-lived, per registration
proxy_jump: …                        // optional
```

Until then every capture comes home on a USB stick.

### 3.2 `printers_removed` has nowhere to go

The kit records **every printer** — name, port, host address, driver, share, and which was
default — **before the first deletion**, because this stage deletes the site's printer
configuration with no undo and the recorded set is the only answer to "what did this pharmacy
actually have?". `pmr_capture_runs` has no column for it, so a server that accepts the key drops
it.

The kit does not depend on that: the set is written to `C:\wcn-imageprep\printers-removed.json`
and copied beside the artefact as `<code>-<role>.printers.json`, so it travels with the image.
But it should be stored — it is what the printer queues get rebuilt from, and it is gone from the
source PC the moment the strip runs.

Additive, if the owner of `db/` agrees:

```sql
ALTER TABLE pmr_capture_runs ADD COLUMN IF NOT EXISTS printers_removed jsonb;
```

### 3.3 `IMAGE_FORMATS` has no place for the proven pipeline

`IMAGE_FORMATS` is `qcow2 | raw | vmdk`. The old kit produced `.vhdx.zst` — disk2vhd then
`zstd --ultra -22 --long=31`, measured 159 GB → 72 GB.

The kit's **default is now qcow2**: `qemu-img convert -O qcow2 -c -o compression_type=zstd`. It
is in the server's list, and it stays compressed at rest, so Proxmox boots it directly with no
decompress step and no window where an import needs twice the disk it will finally use. The cost
is honest — qcow2's per-cluster zstd does not reach what a 2 GB window reached over the whole
image — and a slightly larger file that imports by itself beats a smaller one that needs an
engineer.

The old pipeline remains as a **fallback** when `qemu-img.exe` is not staged on the USB. It is
loud about it and registers with **no** `image_format` rather than mislabelling the artefact as
something the far end would then try to import. **Stage `qemu-img.exe` on the kit.**

---

## 4 · What the kit never does

* never holds a credential it did not receive at runtime from a ticket;
* never holds one broader than the three capabilities — it refuses it;
* never writes the ticket secret or the minted token to its state file or its log
  (`Protect-WcnSecret` redacts at the single point every line passes through);
* never queries the CRM — Vigilant does that server-side;
* never has an offline path, because offline is the run with every check disabled;
* never composes an upload path, and has no default destination to fall back on.
