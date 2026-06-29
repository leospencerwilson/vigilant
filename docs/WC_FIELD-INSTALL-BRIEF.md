# wc_field — "Install Vigilant on this router" flow (build brief)

A spec for the wc_field app team to add a guided flow that enrols a MikroTik into **Vigilant**
(the WCN telemetry backend) and installs its agent. The goal: a field engineer standing at a
site can get a router reporting into Vigilant in ~2 minutes, with no hand-typed tokens and no
way to fat-finger it onto the wrong device.

> ⚠️ The WCN MikroTik estate is **live production**. The install is **telemetry-only** (config
> apply is OFF by default) and only ever *adds* scripts/schedulers + sets globals — it never
> changes routing/firewall. Still: the engineer pastes it under **Safe Mode (Ctrl-X)** and the
> UI must make that instruction unmissable.

---

## 1. What "install" actually is

Vigilant enrolment is a 2-touch flow because the app can't reach the router directly (CGNAT /
dynamic IP) and needs the router's own serial + identity:

1. **Probe** — engineer runs a tiny read-only snippet in the router terminal; it prints the
   **serial** and **identity**.
2. **Enrol** — wc_field sends the serial (+ identity as site name) to Vigilant's `POST /enroll`;
   Vigilant returns a **per-device token** and a ready-to-paste **install block** (the bootstrap
   `.rsc` with the URL + token already substituted).
3. **Install** — engineer pastes the install block into the router (Safe Mode). The router then
   self-fetches the agent and starts pushing telemetry every ~10s.
4. **Verify** — wc_field polls Vigilant until the device shows **online**.

The router never needs an inbound connection; it always dials out to
`https://vigilant.internal.western-communication.com`.

---

## 2. Connection (CHOSEN: direct call from the page, scoped key)

wc_field calls Vigilant's `/enroll` **directly from the logged-in page** — no edge function, no
backend. Vigilant now sends **CORS** headers so the browser call isn't blocked, and accepts a
**scoped `FIELD_ENROLL_TOKEN`** that authorises ONLY enrol + single-device read (never bulk
fleet reads or config-push).

```ts
const BASE = "https://vigilant.internal.western-communication.com";
const KEY  = import.meta.env.VITE_VIGILANT_FIELD_KEY;   // FIELD_ENROLL_TOKEN
const r = await fetch(`${BASE}/enroll`, {
  method: "POST",
  headers: { Authorization: `Bearer ${KEY}`, "content-type": "application/json" },
  body: JSON.stringify({ serial, site_name, customer, wan_type, tags }),
});
const out = await r.json();   // { token, serial, install, bootstrap }
// verify: GET `${BASE}/devices/${serial}` with the same key → state.status === "online"
```

⚠️ **Use the scoped `FIELD_ENROLL_TOKEN`, NOT the master `ENROLL_TOKEN`.** The page is behind a
login, but a Vite bundle ships its env to the browser, so any logged-in engineer can read the
key from DevTools. The scoped key limits the blast radius to "can create device rows / read a
device" — the master key can read the whole estate and push config to live routers, so it must
never be in the SPA. Set `CORS_ALLOW_ORIGINS` on Vigilant to the wc_field origin(s) to stop
other sites using the key from a browser.

> (The earlier Edge-Function / server-proxy pattern below is the stronger option if you ever
> want zero key in the browser — kept for reference, not required for the chosen approach.)

## 2b. (Reference) Auth via a server proxy — keep the token fully server-side

`POST /enroll` is gated by Vigilant's single **admin token** (`ENROLL_TOKEN`). wc_field is behind
a login, so it can hold the token in **env** — but it must be read by wc_field's **server / API
routes only**, never exposed to the browser. The flow:

```
wc_field UI ──(engineer's wc_field login/session)──▶ wc_field API route ──(ENROLL_TOKEN from env)──▶ Vigilant /enroll
```

- ✅ Server-side env (e.g. a Next.js API route / server action): `VIGILANT_API_URL`,
  `VIGILANT_ADMIN_TOKEN=<ENROLL_TOKEN>`. The browser calls the API route; the token stays on the
  server. This is simpler than a standalone proxy — it's just one authed route.
- ❌ Do **not** put it in a client-exposed var (`NEXT_PUBLIC_*` / `VITE_*`) even behind the login:
  that bakes it into the JS bundle and any logged-in user (or anyone who pulls the bundle) gets it.
- ⚠️ This token is the **estate master key** — it can enrol AND read *every* device. The login
  population should be people you'd trust with that. (If wc_field's users are broader than Vigilant
  admins, consider a scoped enrol-only token — a Vigilant change; flag it.)
- The API route should **require the engineer's authenticated session** before forwarding, so the
  endpoint can't be hit anonymously.

---

## 3. Screen-by-screen

### Screen A — "Probe the router"
- Show **step 1 copy block** (one tap to copy) and instruct: *New Terminal in Winbox/WebFig (or SSH), paste, press Enter.*
  ```
  :put ("VIGILANT serial=" . [/system routerboard get serial-number]); :put ("VIGILANT identity=" . [/system identity get name])
  ```
- A **multiline paste field**: "Paste the router's output here."
- Parse it live (regex below). Show a green confirmation: `✓ serial HGT0A023T6C · identity "Allied Huddersfield"`.
- Optional editable fields (pre-filled from parse / engineer choice): **Site name** (default = identity), **Customer** (Allied / Cegedim / WCN / HSCN), **WAN type** (`pppoe | sim | dhcp | static | unknown`), **Tags** (chips, e.g. `allied,pharmacy`).
- **[Enrol]** button (disabled until a serial is parsed).

Parse:
```
serial   = /serial\s*=\s*([^\r\n]+)/i
identity = /identity\s*=\s*([^\r\n]+)/i   // → default site_name
```

### Screen B — "Install block" (after enrol succeeds)
- **Per-device token** in a copy box with a one-time warning: *"Shown once — stored only as a hash server-side. It's already baked into the install block below; you don't need to copy it separately."*
- **Install block** (the big `.rsc`) in a copy box with the headline instruction:
  **"Enable Safe Mode (Ctrl-X), paste this into the router terminal, press Enter."**
- A note: *"Telemetry-only — config apply is disabled. TLS verification off by default (see runbook to harden)."*
- **[Done — verify]** button → Screen C.

### Screen C — "Verify"
- Poll Vigilant for the device every ~3s for up to ~60s; show a live status chip
  (`unknown → online`). On **online**: ✓ "Reporting to Vigilant" + show cpu/last-seen.
- If it doesn't go online in 60s: show troubleshooting (TLS/token/URL; did the block paste
  cleanly?; is `/log` showing `vigilant-bootstrap` errors?) and a **[Re-check]** button.

---

## 4. API (wc_field backend → Vigilant)

All requests carry `Authorization: Bearer <ENROLL_TOKEN>` (added by the backend).

### Enrol — `POST /enroll`
Request:
```jsonc
{ "serial": "HGT0A023T6C", "site_name": "Allied Huddersfield",
  "customer": "Allied", "wan_type": "pppoe", "tags": ["allied","pharmacy"] }
```
Response `200`:
```jsonc
{
  "token":  "<PER-DEVICE-BEARER — shown once>",
  "serial": "HGT0A023T6C",
  "install": "<full RouterOS .rsc install block, URL + token already substituted>",
  "bootstrap": "<alias of install, kept for back-compat>"
}
```
- `serial` is the only required field. `400` if missing. Re-enrolling an existing serial
  currently errors — see §6.
- **Render `install` verbatim** in the copy box. Do not modify it.

### Verify — `GET /devices/:serial`
Returns the device detail; check `state.status` (`online` once telemetry lands) and
`state.last_seen_at`. `404` until the first telemetry tick creates state — treat 404 as
"not reporting yet," keep polling.
(Or `GET /fleet` → find the row by `serial`; `status` + `last_seen_at`.)

---

## 5. Field UX requirements (don't skip)
- **Safe Mode banner** on Screen B — the single most important instruction.
- **One-tap copy** on every code block; never expect the engineer to type.
- **Don't display the per-device token as a required manual step** — it's already inside the
  install block. (Showing it is fine for records, but the engineer shouldn't have to handle it.)
- Works on a **phone** (engineers are on Winbox mobile / a laptop on site).
- **Offline-tolerant:** if the backend/Vigilant is unreachable, fail clearly ("couldn't reach
  Vigilant — check your connection") and let them retry without re-probing.
- **Idempotent feel:** if enrol fails after the engineer already pasted a block, re-running
  verify should still work.

---

## 6. Edge cases / for the backend
- **Already enrolled:** `POST /enroll` rejects a duplicate serial today. wc_field backend should
  detect this (or pre-check `GET /devices/:serial`) and offer "already enrolled — just verify"
  rather than erroring. (If re-issuing a token is needed, that's a Vigilant change — flag it.)
- **TLS:** the install block defaults to `check-certificate=no` (still TLS-encrypted) because
  many estate boxes have an empty trust store. Fine for rollout; hardening is per-site later.
- **Verification 404 vs error:** 404 = no telemetry yet (keep polling); non-2xx/again = backend
  or auth problem (surface it).
- **Reboot-safe:** the install sets persistent globals + a startup scheduler, so it survives
  reboots — no need to revisit the box.

---

## 7. Acceptance
- Engineer completes probe → enrol → install → **online** without typing a token or any RouterOS.
- The admin token never reaches the device/app bundle (only the wc_field backend holds it).
- A device that doesn't come online within 60s shows actionable troubleshooting, not a spinner.
- Re-opening the flow for an already-enrolled serial doesn't dead-end.

> Source of truth for the API + install: Vigilant `src/ingest/handlers.js` (`enroll`),
> `agent/bootstrap.rsc`, and `docs/DEPLOYMENT.md` §4 (enrol). Base URL:
> `https://vigilant.internal.western-communication.com`.
