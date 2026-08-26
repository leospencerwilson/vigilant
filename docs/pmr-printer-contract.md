# PMR printer contract — ONE source of truth

Every owner below reads THIS FILE. Do not restate a rule from memory; quote this file.

⛔ WHY THIS FILE EXISTS. On 2026-08-25 three owners (the Pi agent, the kiosk launcher and the
privileged helper) each applied their own rules to one shared file format. The result was two
blocking defects: a driver name containing a comma was staged, validated, promoted, **the session
was restarted**, and the counter came back with that printer gone — while telemetry reported it
converged. Divergence between owners is the failure mode this contract prevents.

## 1 · The four objects

| Object | Identity | Notes |
|---|---|---|
| **Physical device** | USB serial, or network MAC/serial | NOT its name. A printer keeps its identity across a rename and across a move to another counter. |
| **Queue** | (device, tray label) | One physical device may carry several queues — a Brother needs plain paper and ETP tokens from different trays. Some sites need more than two. |
| **Host** | the Pi with the USB connection | Other Pis reach the device through it. A network printer has NO host. |
| **Assignment** | queue → desktop (VM) | A person drags a printer onto a desktop. This is what "shared to" means. |

⭐ **The queue name IS the Windows printer name.** RDP names a redirected printer after the CUPS
queue, and ProScript stores that name in its report mapping. A rename breaks dispensing.

⭐ **A queue name is unique ON ONE PI, not across a site.** Two counters may each hold a queue
called `Label` pointing at their own printer — that is the normal pattern, and it is what lets
ProScript hold the same setting on every desktop.

## 2 · The wire format the Pi already implements

The agent consumes `printers` on the telemetry reply and renders `/var/lib/wcn/printers.tab.next`.
It is ALREADY BUILT and its validation is ALREADY FIXED. The server must match it exactly.

```
"printers": [ { "queue": "Label-ZD421", "driver": "ZDesigner ZD420-203dpi ZPL", "flags": ["default"] } ]
```

| Field | Rule |
|---|---|
| `queue` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` — max **63** characters |
| `driver` | printable ASCII, 1..128, **NO COMMA** — comma is FreeRDP's own field separator inside `/printer:` |
| `flags` | closed set: `default` only. At most ONE queue may carry it. |
| count | at most **32** queues per Pi — the kiosk redirects no more |
| duplicates | a duplicate queue name is refused for the WHOLE table |

⛔ Send the whole effective table every tick, like `settings`. A table is a SET: refuse it entirely
if any line is bad, never apply it partially. A partially-applied table is internally consistent
and quietly wrong — indistinguishable from an operator who meant it.

⛔ `printers` ABSENT means the server has no opinion; do nothing. `printers: []` means leave the
staged file alone — an empty file cannot mean "no printers here", because the launcher's fallback
turns a file with no valid lines back into a derived set.

## 3 · What the Pi reports back

At `peripherals.printers_attached` (deliberately nested — a top-level key the ingest does not
allowlist would 400 the WHOLE telemetry POST and silently stop the counter reporting):

| Field | Meaning |
|---|---|
| `printers_attached[]` | every USB printer, with `usb_path`, `vendor_id`, `product_id`, `manufacturer`, `product`, `serial`, `status`, `queue` |
| `status` | `queued` \| `attached, no queue` \| `unknown` (CUPS itself was unreachable — NOT the same as no queue) |
| `printers_unqueued[]` | the `usb_path` list — **this is the yellow-border alarm** |
| `print_tab_pending` | the staged table differs from the live one → "needs a session restart at this counter" |

⚠️ Descriptor strings are supplied by whoever made the device and are validated to printable ASCII
before being reported. Treat them as untrusted on the server too: never interpolate them into SQL,
a shell, or a filename, and escape them for display.

## 4 · Applying

Building or sharing a CUPS queue reaches the counter AT ONCE and interrupts nobody.
Adding or removing a **Windows** printer needs a session restart, which signs the user out.

So: a printer change stages, and Watchman shows "applies at midnight" with an apply-now button that
states it signs the member of staff out. `printing-promote` is the named verb that swaps the staged
table live and restarts the session as ONE action.

⛔ Never issue a session-interrupting job unattended during a site's opening hours.

## 5 · The states the UI must render

| State | Rendering |
|---|---|
| Connected, no queue | **Yellow border**, "connected, not set up". One click begins setup. |
| Set up, assigned | A line from the printer to each desktop it serves. |
| Shared from another counter | A line to the host counter, so the dependency is visible. |
| Host counter off | The printer and every line from it read unavailable. |
| CUPS unreachable | "unknown" — NEVER "no queue". |

⛔ AN UNKNOWN VALUE MUST NEVER RENDER AS A CONFIDENT ONE. "No queue" when CUPS was simply down is a
false alarm; "queued" when it was not is a false all-clear. Both are worse than saying unknown.

## 6 · Naming

The operator names the printer; Watchman SUGGESTS one from the model (`Label-ZD421`, `Printer-A4`).
A tray label makes the rest of the name (`Printer-ETP`, `Printer-Test`). Every queue gets a
**test-print button** — printing from it and reading the paper is the only way to learn which tray
a queue selects.

⚠️ Enforce §2's patterns SERVER-SIDE at the point the operator types the name, so the refusal is
visible in Watchman. A name the kiosk would reject must never be storable.
