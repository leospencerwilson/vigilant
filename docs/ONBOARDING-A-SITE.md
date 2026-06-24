# Onboarding a Site to Vigilant — Operator Runbook

> **Read this first.** This runbook onboards **one real MikroTik test site** to the
> **LIVE** Vigilant deployment at `https://vigilant.internal.western-communication.com`.
>
> - **The estate is live production.** Every device carries SSTP/L2TP for ~250
>   Allied/Cegedim/WCN sites plus HSCN. The reference fleet box is the WCN CCR2116 on
>   **RouterOS 7.19.4**. Any config change is high-impact.
> - **Pilot on a NON-CRITICAL router first.** Never a hub / HSCN router.
> - **The agent and bootstrap `.rsc` are reviewed-DRAFT** (`agent/vigilant-agent.rsc`,
>   `agent/bootstrap.rsc` — both headers say *REVIEW BEFORE APPLYING TO ANY LIVE ROUTER*).
>   Treat every snippet as draft: review it line-by-line before paste.
> - **Every step that touches the router MUST be pasted under Safe Mode (`Ctrl-X`).**
>   Per `server project/CLAUDE.md`: never paste blind, always Safe Mode, always have a
>   rollback path, flag to Jake via `/system note`.
> - **This onboarding enables TELEMETRY ONLY. Config-push stays OFF** for the entire
>   pilot (see §1 and §9).

Source files this runbook is built from (read-only repo analysis — do **not** call the
live API except the explicit curl/fetch commands below):

- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/agent/vigilant-agent.rsc`
- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/agent/bootstrap.rsc`
- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/src/ingest/server.js`
- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/src/ingest/handlers.js`
- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/src/bin/enroll.js`
- `C:/Users/LeoWilson/claude/server project/IaaS/vigilant/src/shared/config.js`

---

## 1. Overview — what we are doing

We register one test MikroTik with Vigilant, mint its **per-device bearer token**, install
the collector + self-update + persistence machinery on the router, and confirm it is
reporting telemetry into Watchman. **Telemetry only.** Config-push is a separate, gated
phase deferred to §9.

### How Vigilant works (so the steps make sense)

There are **two completely separate paths**. Onboarding enables only the first.

- **Telemetry collection** — the `vigilant-agent` script runs on a ~10s scheduler. Each
  tick it reads system/health/resource, per-interface **cumulative** byte/packet counters
  (the *server* derives bps from deltas — the agent does **not** compute rates), WAN/PPP/
  Wi-Fi/DHCP/LTE state, LLDP/CDP/MNDP neighbours, and on every ~30th tick (~5 min) the
  bridge-host + ARP tables. It hand-builds a JSON body and `POST`s it to `/telemetry` with
  the per-device bearer. **Read + push-out only. It writes nothing to router config.** No
  secrets are sent (the old script's PPPoE password was removed).
- **Config-apply** — the device fetches an approved `.rsc` job and `/import`s it. **This
  writes live config.** It is DRAFT, gated behind the master switch `vigilantApplyEnabled`
  (defaults to `false` when unset), and is deferred to §9.

The **`bootstrap.rsc`** script is a `vigilant-bootstrap` script + a `1d` scheduler: once a
day it `GET`s `/agent/script?serial=…`, writes it to `vigilant-agent.rsc`, removes the old
`vigilant-agent` script, and recreates it from the fetched file. This is how you change
collection once (server-side, `agent_scripts.is_current=true`) and the estate self-updates
— no per-router edits.

### Three blocking facts the shipped scripts get wrong (you fix these here)

These are the reasons "paste both files as-is" does **not** work. Each is handled in the
steps below; do not skip them.

1. **TLS must validate before any data flows.** Every `/tool fetch` uses `mode=https` with
   full validation (no `check-certificate=` override). The host is **Cloudflare-fronted**,
   so its edge cert chains to a **public root that RouterOS 7's `builtin-trust-store`
   already contains** — on a healthy 7.19.4 box validation just works, with **no CA
   import**. The two things that break it on a fresh box are a **disabled trust store** and
   a **wrong clock** (cert-not-yet-valid on a 1970 RTC looks exactly like a missing CA). The
   agent **swallows the error** (`on-error={ :log warning … }`), so the router looks healthy
   locally while sending **zero** telemetry, and the daily bootstrap self-update never runs.
   → Fix the clock + trust store and prove a validating `/healthz` fetch **before** enrolment
   (§2.2). **Never** hand-add `check-certificate=no` to the scripts (it is overwritten by the
   daily self-update) and **never** fetch a CA from the ingest (no such route exists).
2. **`:global` variables are wiped on every reboot.** `vigilantUrl` and `vigilantToken`
   vanish on a power cut; the agent then fetches an empty base URL with an empty bearer
   (401 / malformed) and the bootstrap fetch has no host. Neither script ships a startup
   scheduler. → You add a `start-time=startup` scheduler that re-declares the per-device
   globals (§5).
3. **Neither file creates the collector scheduler.** `bootstrap.rsc` only adds the daily
   `vigilant-bootstrap` scheduler; the agent script has no timer of its own. Pasted as-is,
   `vigilant-agent` never runs on a schedule, so no telemetry is sent. → You add the 10s
   `vigilant-agent` scheduler by hand (§5), **with a `Vigilant` comment** so the back-out
   in §8 can find it.

### A trap to avoid: the wrong hostname

Both `.rsc` draft files hardcode the **OLD** host
`https://vigilant.western-communication.com` in their comments. The **LIVE** ingest is at
`https://vigilant.internal.western-communication.com` (the `.internal` subdomain). An
operator transcribing from the script comment points the router at the wrong (likely
non-resolving) host. **Always paste the `vigilantUrl` that `/enroll` returns** in its
`bootstrap` field — it is built from `config.publicBaseUrl` (`handlers.js` `enroll()`),
which is `PUBLIC_BASE_URL` in Coolify, and is also used to build the `config/<id>.rsc` job
URL. Treat the URLs in the `.rsc` drafts as stale placeholders; update them before they
ship estate-wide.

> **But the `/enroll` `bootstrap` is only authoritative if `PUBLIC_BASE_URL` is set.**
> `config.publicBaseUrl` **defaults to the OLD `.internal`-less host** when `PUBLIC_BASE_URL`
> is unset (`src/shared/config.js` line 47), so a misconfigured Coolify env makes `/enroll`
> hand you the **wrong** host in both the `bootstrap` globals and the config-job URL. §4.0
> makes you confirm `PUBLIC_BASE_URL` before enrolling, and §4.2 makes you assert the
> returned host is the `.internal` one and **abort** if not.

---

## 2. Prerequisites (on the pilot router)

> All commands in this section are RouterOS 7 syntax. Do them **inside Safe Mode**
> (§3) on a **non-critical pilot router**.

### 2.1 Confirm RouterOS version and `/tool fetch`

```routeros
/system resource print
```

Read the `version:` line — you need **7.x** (estate baseline is `7.19.4`). The agent uses
ROS7-only features (`/interface/lte/info … as-value`, `/tool fetch … as-value`, `:onerror`
/ `:do … on-error`), so a v6 box must be upgraded first.

`/tool fetch` is part of the built-in `system` package and is on every standard install.
Confirm it is callable (this just prints the parameter list, it transfers nothing):

```routeros
/tool fetch
```

If the menu responds with its parameter list, fetch is available. (`/system package print`
matters only if someone has *disabled* core packages.)

### 2.2 The TLS decision for `/tool fetch` over HTTPS — DECIDE THIS BEFORE ENROLMENT

Vigilant ingest is HTTPS at `https://vigilant.internal.western-communication.com`. By
default `/tool fetch mode=https` **validates the server cert against the router's trust
store**. The host is **Cloudflare-fronted** (public exposure is via Cloudflare Tunnel — see
`server project/CLAUDE.md` and this runbook's own note in §1), so the edge cert chains to a
**public root that RouterOS 7's `builtin-trust-store` already contains**. On a stock 7.19.4
box with the built-in trust store enabled, a plain `mode=https` fetch **validates with no
import and no `check-certificate=` override** — which is exactly what the shipped agent
does. **This is the supported path.** Do not import anything unless you have a genuine
private-CA pinning requirement (see the note at the end of this section).

The production agent (`vigilant-agent.rsc`, telemetry POST ~line 274) and the bootstrap
self-updater (`bootstrap.rsc`, ~line 50) both fetch `mode=https` with full validation. The
agent **swallows fetch errors** (`on-error={ :log warning … }`), so if validation fails the
device looks alive locally while sending **zero** telemetry. So the whole job here is: make
the box validate the public-root chain cleanly **before** enrolment. Two things break that
on a fresh box — an off trust store, and a wrong clock — fix both first.

#### Step 0 — Clock gate (do this BEFORE any HTTPS fetch)

RouterOS cert-validity checks fail on **clock skew**. A freshly-booted board with no RTC can
sit at `jan/02/1970`; the first validating fetch then fails with **`certificate is not yet
valid` / verification failed**, which looks **identical to a missing-CA error** and sends
you down a CA-import rabbit hole that is the wrong fix. Confirm the clock and NTP first:

```routeros
/system clock print          ;# confirm the YEAR is current (2026), NOT 1970
/system ntp client print     ;# status must read 'synchronized' before the first https fetch
```

If the year is wrong or NTP is not configured/synced, set a server and enable the client,
then re-check until `status: synchronized`:

```routeros
/system ntp client set enabled=yes
/system ntp client servers add address=time.cloudflare.com   ;# or your estate NTP source
/system ntp client print     ;# repeat until status: synchronized, then re-check /system clock print
```

> A "certificate is not yet valid / verification failed" error while `/system clock print`
> still shows 1970 is **clock skew, not a CA problem.** Fix the clock; do not import a CA.

#### Step 1 — Confirm the built-in trust store is on

```routeros
/certificate/settings print     ;# builtin-trust-store must be 'yes' (the default)
```

If it reads `no`, turn it back on so the public root that signs the Cloudflare edge cert is
trusted:

```routeros
/certificate/settings set builtin-trust-store=yes
```

#### Step 2 — Prove it with a validating `/healthz` fetch (NO override flag)

This is the canonical test and matches what the agent does. It must return `ok` with **no**
`check-certificate=` override:

```routeros
/tool fetch url="https://vigilant.internal.western-communication.com/healthz" \
    mode=https output=user as-value
```

If this returns the `/healthz` body cleanly, TLS is sorted — **nothing to import**, the
shipped agent's full-validation fetch will work as-is, and you can proceed to enrolment.

If it still fails **after** the clock is correct (Step 0) and the trust store is on
(Step 1), do **not** reach for `check-certificate=no` and do **not** try to fetch a CA from
the ingest — **there is no `/ca.pem` route on the server** (`server.js` routes only
`/healthz`, `/`, `/telemetry`, `/agent/script`, `/config/pending`, `/config/:id.rsc`,
`/config/result`, `/enroll`, `/fleet`, `/devices/:serial`; anything else returns
`404 {ok:false,error:'not found'}`). Fetching `/ca.pem` would just write a 36-byte JSON 404
body to a file and the import would fail to parse it.

> **If — and only if — you have a genuine private-CA pinning requirement** (e.g. the origin
> is later moved behind a private CA rather than the public Cloudflare edge), obtain the CA
> PEM **out-of-band** (export it from the origin, or from the Cloudflare dashboard) and
> **SFTP it onto the router**, then `/certificate import file-name=<the-pem> trusted=yes`
> and `/certificate print` to confirm exactly one trusted entry landed. **Never fetch a CA
> from the ingest** — the route does not exist. For the Cloudflare-fronted public-root setup
> this runbook targets, you do not need this at all. If you do import a private CA, you MUST
> also remove it in the §8 back-out (it adds a persistent trust change to a live router).

Either way, prove the decision with the validating `/healthz` fetch returning `ok` before
proceeding. **Do not hand-edit the agent's fetch mode** — the agent body is centrally
managed and re-fetched every 24h (§5.2/§5.3), so any local edit is silently overwritten on
the next daily bootstrap tick. Make the box validate the public-root chain instead.

### 2.3 User account / policy

Adding scripts, adding a scheduler, importing config, and running fetch require a user whose
group carries the right policies. The scripts are added `dont-require-permissions=no` (the
secure default — the script is bound by its own policy set, inherited from the scheduler's
group). **Do not flip that to `yes` as a shortcut.**

For the **telemetry-only pilot**, the scheduler/scripts need:

- **read** — all `/system … get`, `/interface get`, `/ip neighbor/arp/route`, `/interface bridge host` reads.
- **write** — `/system script add/remove`, `/system scheduler add/remove`, `/file remove`.
- **test** — `/interface ethernet monitor … once`, `/interface/lte/info … once`, ping-style probes.
- **fetch** — every `/tool fetch`. **Without `fetch`, the POST/GET silently fails** (then logged as a warning by the `on-error`).
- **sensitive** — needed to read `/system routerboard get serial-number`, `/export`, `/system backup save`. Without it `/export` may omit data and the serial read can be restricted on some builds.

So for the pilot grant the scheduler group: **`read,write,test,sensitive,fetch`** — **no
`reboot`, no `policy`**. Those two are only needed when you enable the apply path (§9), and
only if config jobs reboot or install users/scripts. A too-narrow policy is a failure that
**only surfaces when a config job is dispatched** (the simple telemetry fetch works), so get
it right now even though the extra bits are unused during the pilot.

```routeros
/user/group print                       ;# confirm your group's policy list
# If creating a dedicated automation user/group for the pilot:
/user/group add name=vigilant-ops policy=read,write,test,sensitive,ftp,winbox,ssh
/user add name=vigilant group=vigilant-ops password="<strong>" address=<mgmt-cidr>
```

> **LTE / at-chat note:** the LTE block only runs when `/interface/lte find` is non-empty;
> it reads identifiers via `/interface/lte/info … once` (needs **test**). The script
> deliberately does **not** use the `at-chat` ICCID/IMSI fallback — `at-chat` every tick can
> disrupt the data session. Do **not** add at-chat without per-hardware validation (some
> Quectel modems on RouterOS don't expose it); if you ever do, it needs `test`+`sensitive`.

---

## 3. Pre-flight safety (BEFORE touching the device)

### 3.1 Confirm out-of-band access exists

You must be able to reach the device by a path that does **not** depend on the link you
might break — Winbox/SSH via the mgmt path (e.g. `192.168.100.240` for the WCN router), or
LTE/console. **If the only path in is the WAN you're about to risk, STOP.**

### 3.2 Take a text export AND a binary backup, named and dated, and PULL THEM OFF

This is your manual rollback, independent of Vigilant's own dead-man switch. An on-device
backup you can't reach is useless if the change cuts your access.

```routeros
# On the device (Winbox terminal / SSH). ISO date.
/export file=preflight-vigilant-20260624
/system backup save name=preflight-vigilant-20260624
/file print
```

Pull **both** off the box (drag out of Winbox **Files**, or `scp`). Store alongside the
estate's existing rollback artifacts (cf. `pre-dread-backup-20260430.{rsc,backup}`). The
`.rsc` is human-readable/diffable; the `.backup` is the byte-exact restore.

### 3.3 Enter Safe Mode — non-negotiable on this estate

Safe Mode records every change in the session and **auto-reverts all of them** if your
management session drops before you exit cleanly. The enrolment snippet only *adds*
scripts/schedulers/globals, but a fat-fingered or partial paste over SSH can still wedge a
session on a live HSCN/SSTP box — so Safe Mode is **mandatory**, not optional.

- **Winbox / WebFig:** click the **Safe Mode** button (top-left) — it turns red.
- **Terminal (SSH or Winbox terminal):** press **`Ctrl-X`** to enter; the prompt gains a
  `<SAFE>` marker. Press **`Ctrl-X`** again to **exit and commit**. (`F4` is the legacy
  toggle in some Winbox builds.)
- If the session is interrupted in Safe Mode, the router rolls back everything done this
  session and you reconnect to the pre-change state.

Safe Mode protects you **while connected**; it does **not** survive a reboot or persist
globals — that is what the startup scheduler in §5 is for.

### 3.4 Flag to Jake

Per `server project/CLAUDE.md`, flag the work via `/system note` so the on-call engineer
knows the pilot router is being touched.

---

## 4. Enrol the site — `POST /enroll` (admin)

Enrolment is **admin-only**: the server compares the bearer to `config.enrollToken` in
constant time (`server.js` `authAdmin`). **Only Leo holds the admin `ENROLL_TOKEN`**, so
**Leo runs the enrol** — or asks Claude to run it for him, in which case **Claude needs only
the router's serial** (plus optional metadata). Claude must never be handed the admin token
to keep; the request is one-shot. Use `$VIGILANT_ENROLL_TOKEN` **only** for enrol/verify
calls; the per-device token goes **only** on the router. Using the wrong bearer returns
`401`.

Get the router's real serial from the device itself:

```routeros
/system routerboard get serial-number
```

### 4.0 Pre-enrol gate — confirm `PUBLIC_BASE_URL` is the `.internal` host (MANDATORY)

`enroll()` interpolates `config.publicBaseUrl` **verbatim** into BOTH the returned
`bootstrap` globals (`handlers.js` lines 448–450) **and** the `config/<id>.rsc` job URL
(`handlers.js` line 271). But `config.publicBaseUrl` **defaults to the OLD host**
`https://vigilant.western-communication.com` when `PUBLIC_BASE_URL` is unset
(`src/shared/config.js` line 47). So if `PUBLIC_BASE_URL` is missing/wrong in Coolify,
`/enroll` silently hands you a `bootstrap` pointing the router at a **likely-non-resolving**
host — and the same wrong host poisons every future config-job fetch.

**Before enrolling**, confirm on the **Vigilant Coolify app** that
`PUBLIC_BASE_URL=https://vigilant.internal.western-communication.com` is set (env tab /
`docker exec … printenv PUBLIC_BASE_URL`). Do not enrol until it is.

### 4.1 The request

```bash
curl -sS -X POST https://vigilant.internal.western-communication.com/enroll \
  -H "Authorization: Bearer $VIGILANT_ENROLL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "serial": "<SERIAL>",
    "site_name": "<SITE NAME>",
    "customer": "<CUSTOMER>",
    "wan_type": "pppoe",
    "tags": ["<tag>", "<tag>"]
  }'
```

Body fields (handled in `handlers.js` `enroll`):

| Field | Required | Notes |
|---|---|---|
| `serial` | **Yes** | Non-empty string or `400 {"error":"serial required"}`. Use the value from `/system routerboard get serial-number`. |
| `site_name` | No | Defaults to `null`. |
| `customer` | No | Defaults to `null`. |
| `wan_type` | No | Defaults to `"unknown"`. DB CHECK accepts `pppoe`/`sim`/`dhcp`/`static`/`unknown`. The raw HTTP handler stores the string **as-is** — it does **NOT** apply the CLI's `lte`/`4g`/`5g` → `sim` aliasing. **For LTE/SIM sites over HTTP send `"wan_type":"sim"`** (use `bin/enroll.js` if you want the friendly aliasing). |
| `tags` | No | Must be an array, else coerced to `[]`. |

### 4.2 The response — `200 {token, bootstrap}`

```json
{
  "token": "<64 hex chars — crypto.randomBytes(32).toString('hex')>",
  "bootstrap": ":global vigilantUrl \"https://vigilant.internal.western-communication.com\"\n:global vigilantToken \"<token>\""
}
```

- The `token` is the **per-device** opaque bearer. The server stores **only
  `sha256(token)`** (`store.setDeviceToken`); the plaintext is **returned once in this
  response and never again**. **Capture it now — it is not recoverable. If lost, re-enrol**
  the device to mint a new one.
- The `bootstrap` field is **exactly two `:global` lines** (newline-separated), built
  verbatim from `config.publicBaseUrl` and the token. **This is the correct `vigilantUrl`**
  — paste from here, not from the `.rsc` comments.
- **HARD CHECK — assert the returned host before doing anything else.** Because the
  `bootstrap` is built verbatim from `config.publicBaseUrl`, a misconfigured `PUBLIC_BASE_URL`
  silently returns the WRONG host (see §4.0). **Confirm the `bootstrap` string contains
  exactly `https://vigilant.internal.western-communication.com` and ABORT if it does not** —
  a returned `https://vigilant.western-communication.com` (no `.internal`) means
  `PUBLIC_BASE_URL` is unset/wrong in Coolify; fix it there and re-enrol rather than pasting
  a router pointed at a non-resolving host. A quick guard when scripting the enrol:
  ```bash
  resp=$(curl -sS -X POST https://vigilant.internal.western-communication.com/enroll \
    -H "Authorization: Bearer $VIGILANT_ENROLL_TOKEN" \
    -H "Content-Type: application/json" -d '{ "serial": "<SERIAL>" }')
  echo "$resp" | grep -q '"vigilantUrl \\"https://vigilant.internal.western-communication.com\\""' \
    && echo "$resp" \
    || { echo "ABORT: /enroll returned wrong host — check PUBLIC_BASE_URL in Coolify"; }
  ```
- **The HTTP `bootstrap` field is ONLY the two bare globals — it does NOT include
  reboot-persistence.** After a reboot the globals are lost and the scheduler can't
  authenticate. You add persistence yourself in §5 (or run `bin/enroll.js`, whose CLI prints
  a richer snippet with a `vigilant-env` persisted script + startup scheduler).

> **Claude:** if running the enrol on Leo's behalf, return the `token` and `bootstrap`
> to Leo immediately and do not retain the admin token.

---

## 5. Install on the router (telemetry only; config-apply DISABLED)

> **Safe Mode on (§3.3). Review each block before paste.** Prefer the `.rsc` + `/import`
> route for multi-line scripts (see §5.5). Paste the **exact** url+token from the §4
> `bootstrap`/`token` — `vigilantUrl` must be
> `https://vigilant.internal.western-communication.com` and the token must be **this**
> device's.

### 5.1 Persist the per-device globals across reboot (fixes blocking-fact #2)

CLI-declared `:global` vars are session-scoped and wiped on reboot. The fix is a
`start-time=startup` scheduler that re-declares them on each boot.

```routeros
# (a) A persisted script holding THIS device's globals. Paste the EXACT url+token
#     returned by /enroll for THIS device.
/system script add name=vigilant-env policy=read,write,test \
    comment="Vigilant: per-device globals" \
    source={
        :global vigilantUrl "https://vigilant.internal.western-communication.com"
        :global vigilantToken "<PER-DEVICE-TOKEN>"
    }

# (b) Run it ONCE per boot. start-time=startup + interval=0s = one-shot at boot.
#     Do NOT give it a repeating interval (would churn the globals).
/system scheduler add name=vigilant-env-startup start-time=startup interval=0s \
    on-event="/system script run vigilant-env" \
    comment="Vigilant: re-declare globals on boot"

# (c) Run it now so the globals exist in the current session too.
/system script run vigilant-env

# (d) Confirm.
:put $vigilantUrl
:put [:typeof $vigilantToken]    ;# must NOT be 'nothing'
```

> The token is **per-device**, so this `vigilant-env` body is unique per router. The
> enrol/provisioning step generates it.

### 5.2 Install the daily self-update bootstrap

This is the body of `agent/bootstrap.rsc`. It only updates the collector script — it never
applies router config.

> **NEVER hand-edit the `vigilant-agent` script body on the router.** The agent is
> **centrally managed**: `vigilant-bootstrap` re-fetches it from `GET /agent/script` every
> 24h and **removes-then-recreates** the local `vigilant-agent` from the server's bytes
> (`bootstrap.rsc` lines 49–59; `handlers.js` `agentScript` serves
> `store.getCurrentAgentScript()` or the bundled `agent/vigilant-agent.rsc`). Any change you
> make to the local agent — including adding `check-certificate=no` to its fetch — is
> **silently overwritten on the next daily tick**, and ALL telemetry POSTs that depended on
> that edit then start failing (swallowed by the agent's `on-error` warning). The pilot
> "goes dark" a day later with no obvious cause. This is exactly why §2.2 makes the box
> validate the **public-root chain** (so the shipped agent's full-validation
> `mode=https` fetch works **unmodified**) instead of editing the agent. If a `/tool fetch`
> behaviour ever genuinely needs to change, change the **server-side** copy
> (`agent_scripts.rsc_text`, or the bundled `agent/vigilant-agent.rsc` that `agentScript`
> serves) and **bump `agent_version`** — never the router-local copy.

> **The bootstrap's OWN fetch must validate too.** `vigilant-bootstrap` is **not**
> self-updated (it is the thing that does the updating), so its fetch must work on its own.
> The shipped `bootstrap.rsc` drives `check-certificate=$cc` from a `vigilantTlsCheck`
> global that the bundled `vigilant-env` sets to `"no"` — i.e. it ships defaulting to
> **skip-validation**, which is the same insecure shortcut §2.2 rejects. For this onboarding
> set `vigilantTlsCheck "yes-without-crl"` (or remove the override and let it validate) so
> the bootstrap fetch chains to the public root exactly like the agent's, with the clock +
> trust store fixed per §2.2. Do not leave `vigilantTlsCheck "no"` in the `vigilant-env`
> body you persist in §5.1.

```routeros
# Grant fetch+sensitive (and the apply-path bits, harmless during the pilot) so the
# centrally-managed collector can fetch and self-update. For a strict telemetry-only pilot,
# read,write,test,sensitive,fetch is sufficient.
/system script add name=vigilant-bootstrap dont-require-permissions=no \
    policy=read,write,test,sensitive,fetch \
    source={ ...contents of agent/bootstrap.rsc script body... }

/system scheduler add name=vigilant-bootstrap interval=1d \
    on-event="/system script run vigilant-bootstrap" \
    comment="Vigilant: daily agent self-update"
```

### 5.3 Seed the collector now, then add its tick scheduler (fixes blocking-fact #3)

The bootstrap fetches the **current** agent from `GET /agent/script?serial=<serial>` (a
device route; auth = the per-device bearer), writes it to `vigilant-agent.rsc`, removes any
existing `vigilant-agent` script, and re-adds it from the fetched file. Run it once by hand
to bring the site up immediately instead of waiting for the daily tick.

```routeros
# (a) Seed the collector once now (fetches the current version by serial).
/system script run vigilant-bootstrap

# (b) Add the 10s tick scheduler — NEITHER file creates this; without it the collector
#     never runs. The "Vigilant" comment is REQUIRED so the §8 back-out can find it.
/system scheduler add name=vigilant-agent interval=10s \
    on-event="/system script run vigilant-agent" \
    comment="Vigilant: telemetry tick (10s)"
```

`interval=10s` matches `DEFAULT_POLL_S` (10s) in `config.js`.

After §5.1–5.3 you have **three** schedulers — `vigilant-env-startup` (boot),
`vigilant-bootstrap` (daily self-update), `vigilant-agent` (10s tick) — and the collector
body is centrally managed: you never hand-edit 250 routers again.

> **Known race (benign):** `vigilant-bootstrap` does `remove [find name="vigilant-agent"]`
> then re-adds the script. If the 10s tick fires in that ~2s window the run fails (script
> missing) — harmless once, the next tick recovers. The bootstrap removes only the
> **script**, never the **scheduler**, so the timer keeps pointing at the recreated script.
> **Caveat:** the bootstrap does **not** checksum the fetched agent body (its comment
> promises a server-side checksum review the script doesn't perform), so a corrupted/
> truncated fetched body would be installed and run every 10s — for now its integrity rests
> only on TLS + bearer (which is why §2.2's TLS decision matters).

### 5.4 Leave config-apply OFF (do NOT declare `vigilantApplyEnabled`)

The config-apply path in `vigilant-agent.rsc` no-ops unless the global
`vigilantApplyEnabled` is true; it **defaults to `false` when unset** (agent lines 305–306:
`:if ([:typeof $vigilantApplyEnabled] = "nothing") do={ :set vigilantApplyEnabled false }`).
**For the pilot, simply do not declare it.** Belt-and-braces, also **approve no jobs** in
the console, so `getPendingConfigJob` returns nothing and `job` is `null`.

```routeros
:put $vigilantApplyEnabled    ;# expect: error / empty -> treated as false
```

> **Reboot interaction (document, don't act on it during the pilot):** because
> `vigilantApplyEnabled` is a runtime global, a reboot wipes it back to unset → false. If
> apply is ever enabled estate-wide, a reboot turns it **off** until the startup scheduler
> re-asserts it — a safe-direction failure, but operationally surprising. If you enable
> apply (§9), the §5.1 `vigilant-env` script must also re-assert `:global
> vigilantApplyEnabled true`.

### 5.5 How to paste multi-line scripts safely

`source={ … }` blocks span many lines; line-ending/paste-buffering bugs are the #1 cause of
a half-pasted, broken script (an "adds fine" script with unbalanced/truncated source). Pick
the most robust method, and **always do it inside Safe Mode**:

- **Best — upload an `.rsc` and `/import`.** Drag the file into Winbox **Files**, or SFTP
  it (`scp agent/bootstrap.rsc leotemp@<router>:`), then:
  ```routeros
  /import file-name=bootstrap.rsc
  ```
  `/import` parses the whole file atomically and **stops on the first error**, so a
  malformed block fails loudly instead of leaving a partial script. This is also exactly the
  mechanism the agent's config-apply path relies on.
- **Winbox terminal — fresh "New Terminal" window**, paste the whole block in one go.
  Winbox handles bracketed multi-line `source={ }` paste better than a raw SSH line-buffer.
- **SSH (plink to `192.168.100.240`) — paste inside a single `source={ }` brace.** ROS
  treats everything between `{` and the matching `}` as one statement. Avoid pasting
  line-by-line; a dropped/merged line mid-script is hard to spot. If your terminal mangles
  CR/LF, prefer the `.rsc` + `/import` route.

Verify after pasting (still in Safe Mode):

```routeros
/system script print
/system scheduler print
:put $vigilantUrl ; :put [:typeof $vigilantToken]    ;# token type must NOT be 'nothing'
/log print where topics~"script"                     ;# check for fetch/apply errors
```

**Only press `Ctrl-X` to exit Safe Mode (commit) once** the scripts/schedulers print
correctly **and** the first telemetry POST has succeeded (device appears in `GET /fleet` —
§6). If anything looks wrong, let the Safe Mode session drop / `Ctrl-X`-revert and start
over from the pre-change state.

---

## 6. Verify it's reporting (admin)

Both verify routes are **admin** (bearer = `ENROLL_TOKEN`).

```bash
# Single device.
curl -sS https://vigilant.internal.western-communication.com/devices/<SERIAL> \
  -H "Authorization: Bearer $VIGILANT_ENROLL_TOKEN"

# Fleet overview.
curl -sS https://vigilant.internal.western-communication.com/fleet \
  -H "Authorization: Bearer $VIGILANT_ENROLL_TOKEN"
```

`GET /fleet` returns `{"devices":[...]}`. `GET /devices/:serial` returns the device detail
object, or `404 {"error":"not found"}` if the serial was never enrolled (or you typo'd it —
use the **exact** serial you enrolled).

### What "reporting" looks like

After the first accepted `POST /telemetry` the handler upserts `device_state` with
`status:'online'` and `last_seen_at` set to the sample time. A healthy first check-in shows:

- `status: "online"` (set on every accepted telemetry POST).
- `last_seen_at` fresh (within ~1 poll interval).
- **`rx_bps`/`tx_bps` on the WAN/active interfaces** — but note bps is a **delta between two
  samples** (`transform.deltaBps`), so the **first tick has no previous sample and rates are
  `null`**; they populate from the **second** tick onward. **Wait for at least the second
  tick** before judging throughput. If `rx_bps` is still null after several ticks, the
  device is sending but the agent's byte-counter reads need investigating — not "offline".
- For LTE/SIM sites: a non-null `lte` block (and `lte_signal` = rounded RSRP in
  `device_state`) once the agent's `lte/info` read succeeds; `lte` stays null on routers with
  no LTE interface.

### Serial cross-check (why a wrong serial silently stores nothing)

The ingest cross-checks `payload.serial == device.serial` (the serial bound to the token —
`handlers.js` step 4). A mismatch returns `409 {"error":"serial mismatch"}` and **nothing is
stored**. The agent reads its own serial automatically, so the usual cause is **enrolling
under the wrong serial**. Verify `GET /devices/<serial>` uses the exact serial from
`/system routerboard get serial-number`.

### Realtime tables Watchman subscribes to

Each accepted check-in upserts/appends these (Supabase Realtime) tables — Watchman's live
views should tick on every check-in:

- `device_state` — status/online, uptime, CPU/mem/temp, `lte_signal`, `last_seen_at` (per-device overview row).
- `interface_state` — per-port running/plugged/role + `rx_bps`/`tx_bps`.
- `lte_state` — parsed RSRP/RSRQ/SINR/RSSI/cell (only when a SIM is present).
- `neighbors`, and (slow tick only) `mac_hosts`.
- History tables appended every tick: `metrics_history`, `interface_history`, and `lte_history` (LTE sites).

If Watchman shows the device flip to **online** and the interface throughput graph starts
moving (from the 2nd tick), the site is enrolled and checking in.

### What the telemetry response controls

Every accepted `POST /telemetry` returns:

```json
{ "ok": true, "poll_interval_s": 10, "agent_version": 3, "job": null }
```

- **`poll_interval_s`** — `config.fastPollS` (3s) while the device's `poll_until` is in the
  future (to temporarily speed up a site you're watching), else `config.defaultPollS` (10s).
  **Known limitation:** the agent reads the response only for the config job/confirm and
  **never adjusts its scheduler interval**, so fast-poll has **no effect on the device**
  today. (Minor for a pilot.) The agent also never sends `payload.ts`, so the server
  computes bps over HTTP receive-time intervals (`handlers.js` falls back to `Date.now()`).
- **`agent_version`** — current server-side script version; the signal for a device on an
  older version to self-update via the daily bootstrap.
- **`job`** — `null` normally; when there is a **pending, approved** job for this device it's
  `{id, sha256, url: ".../config/<id>.rsc", confirm_window_s}`. The DRAFT config-apply path
  acts on this — but it is gated behind `vigilantApplyEnabled=false`, so for plain
  enrolment/check-in `job` does nothing until §9.
- **`confirm`** — present **only** when the server has affirmatively confirmed a just-applied
  job (`"confirm":"<jobid>"`); the only signal that cancels the agent's dead-man rollback.
  Absent during normal check-in.

---

## 7. Monitor the first 15 minutes (eyes-on for the first 5)

After committing the enrolment, **stay logged in** and watch:

### 7.1 The scheduled fetch isn't erroring

```routeros
/log print where message~"vigilant"
```

Expect telemetry succeeding **silently** (no warnings). The agent logs
`vigilant-agent: telemetry POST failed` on failure. **A persistent POST failure = TLS / DNS
/ token problem** (almost always the §2.2 TLS decision or a transcribed-wrong URL/token) —
back out and fix server-side; don't leave a scheduler hammering a broken endpoint.

> If telemetry `401`s even with a correct token, suspect the agent's header construction:
> the script folds Authorization and Content-Type into a single comma-joined
> `http-header-field` string
> (`"Authorization: Bearer " . $vigilantToken . ",Content-Type: application/json"`). The
> server's bearer regex is `/^Bearer\s+(.+)$/`, which would capture
> `<token>,Content-Type: application/json` as the token and miss the sha256 lookup → 401.
> If you hit this, split into two header fields (or rely on `/tool fetch`'s content-type for
> the POST) and verify the captured bearer server-side carries no trailing header text.

### 7.2 CPU contributed by the agent

The tick runs every ~10s; the slow path (MAC/ARP tables) runs every ~30 ticks (~5 min) and
is the heaviest. Watch CPU across at least one slow tick:

```routeros
/system resource print     ;# repeat; watch cpu-load
/tool profile duration=10  ;# attribute CPU to "script"/"scheduler" during a tick
```

A brief bump on the slow tick (busy LAN, large host table) is expected; **sustained** high
CPU is not — back out if the box is being starved.

### 7.3 WAN / PPP is unaffected (the production-impacting signal)

```routeros
/interface monitor-traffic pppoe-out1 once
/ppp active print count-only
/ip route print where dst-address="0.0.0.0/0" active=yes
```

Compare PPP session count and the default route against the pre-flight export. **Any** change
here coinciding with enrolment → **back out immediately** (§8).

### 7.4 Device appears in the fleet

`GET /fleet` / `GET /devices/<serial>` (§6) shows the serial checking in with fresh
telemetry — confirms the token + serial cross-check passed.

---

## 8. FULL rollback / back-out

This removes **every** artifact the enrolment + agent can create and returns the router to
its prior state. Run **in Safe Mode (`Ctrl-X`)**. Each step is idempotent.

```routeros
# ── Safe Mode first ── (press Ctrl-X in the terminal)

# 1) Schedulers — stop ALL Vigilant activity FIRST so nothing re-runs mid-teardown.
#    Remove by NAME and by COMMENT — the 10s agent tick is found by its "Vigilant" comment.
/system scheduler remove [find name="vigilant-rollback"]    ;# dead-man, only if a config apply was in flight
/system scheduler remove [find name="vigilant-bootstrap"]   ;# daily self-update
/system scheduler remove [find name="vigilant-env-startup"] ;# startup global loader
/system scheduler remove [find comment~"Vigilant"]          ;# catch the 10s agent-tick scheduler + any stragglers
/system scheduler print where on-event~"vigilant"           ;# verify the tick scheduler is gone

# 2) Scripts.
/system script remove [find name="vigilant-agent"]
/system script remove [find name="vigilant-bootstrap"]
/system script remove [find name="vigilant-env"]

# 3) Fetched / generated files.
/file remove [find name="vigilant-agent.rsc"]
/file remove [find where name~"vigilant-ca"]      ;# imported CA *file*, only if you pinned a private CA (§2.2)
/file remove [find where name~"vigilant-pre-"]    ;# pre-apply .rsc exports AND .backup files
/file remove [find where name~"vigilant-job-"]    ;# fetched config jobs (if any were pulled)

# 3b) Imported CA *certificate* — ONLY if you pinned a private CA per §2.2 (NOT the
#     default public-root path, which imports nothing). Removing the .pem FILE in step 3
#     does NOT remove the trusted CA entry from /certificate — leaving a third-party CA
#     trusted on a live production router. First identify it (the import-assigned name is
#     build-dependent, so match on the CN/issuer you saw at /certificate import time):
/certificate print
/certificate remove [find where name~"vigilant" or common-name~"vigilant"]
/certificate print                                ;# verify the entry is gone

# 4) Globals — clear the runtime/env globals the scripts set.
/system script environment remove [find name~"vigilant"]
```

The globals are `vigilantUrl`, `vigilantToken`, `vigilantTlsCheck`, `vigilantTick`,
`vigilantApplyEnabled`, `vigilantPendingJob`, and the function globals `vigilantClean` /
`vigilantJsonStr` / `vigilantJsonNum`.

> **`/system script environment remove` is non-fatal if it errors** (not present/identical on
> all ROS 7.x builds). Once the `vigilant-env` script + its startup scheduler are gone
> (steps 1–2), the globals are not re-set on next boot and clear on reboot — don't block the
> back-out on this step.

**Verify clean:**

```routeros
/system scheduler print where name~"vigilant"   ;# expect: no entries
/system script print where name~"vigilant"      ;# expect: no entries
/file print where name~"vigilant"               ;# expect: no entries
/certificate print                              ;# expect: no Vigilant CA left (only if you pinned one)
```

Then **`Ctrl-X`** to commit the back-out. If anything still looks wrong, restore the
pre-flight binary backup (router reboots into the exact prior state):

```routeros
/system backup load name=preflight-vigilant-20260624
```

> **Dead-man scheduler note:** `vigilant-rollback` exists **only** if a config apply was
> mid-flight (config path enabled — not the case during a telemetry-only pilot). It is
> cancelled **only** by an affirmative server `"confirm":"<jobid>"`. **Never hand-remove it
> to "tidy up"** after a config apply — that disarms the auto-revert and you lose
> self-recovery. If a half-applied bad change is in flight and you *want* the auto-revert,
> **don't** remove it; let it fire, then back out afterward.

---

## 9. LATER: enabling config-push (DEFERRED — do NOT do this during onboarding)

Onboarding enables telemetry only. Config-push writes to **live config** via `/import` and
the path is **DRAFT** (`vigilant-agent.rsc` header + lines 280–492 say *REVIEW-BEFORE-LIVE*).
Do **not** enable it as part of onboarding.

### The three independent gates already in the code (FYI)

With the master switch `true`, the agent still changes nothing unless: the server serves an
**approved** job for **this exact serial** (`getPendingConfigJob`), **and** the fetched bytes
match the server's `sha256` (and, where present, the `X-Vigilant-Sha256` header), **and** the
master switch `vigilantApplyEnabled` is true. The apply path pre-snapshots (`/export` +
`/system backup`), arms a **dead-man rollback scheduler** (`vigilant-rollback`, re-imports the
pre-change export after `confirm_window_s`, default 300s), then `/import`s — and the rollback
is cancelled **only** by the server's affirmative `"confirm":"<jobid>"`. Absence of errors is
**not** confirmation.

### The explicit operator gate — ALL must be true, signed off by Leo, flagged to Jake

1. Telemetry has run clean for **≥ 7 days** on the pilot site with **zero** `vigilant-agent`
   errors in `/log` and no WAN/PPP disruption attributable to the agent.
2. The config-apply block (`vigilant-agent.rsc` lines 280–492 — checksum gate, pre-snapshot,
   dead-man arm, server-confirmed cancel) has been **reviewed line-by-line**.
3. A config push has been rehearsed end-to-end on a **lab/throwaway** router, including a
   deliberately broken `.rsc` to prove the dead-man fires and self-recovers.
4. Verify `/file get [find name=…] sha256` actually returns a value on the **exact ROS
   build** — the script comments it may be absent on some builds; if so the integrity gate
   rests solely on the `X-Vigilant-Sha256` header, and the apply path also depends on the
   `header-fields` key existing in the `as-value` result, which is not guaranteed.
5. Out-of-band access to the pilot site is confirmed live.
6. `confirm_window_s` (default 300s) is understood: if the operator doesn't confirm health in
   Watchman within the window, the device **auto-rolls-back** — the intended safe default,
   not a failure.

Only then, on a **single non-critical** site, set `:global vigilantApplyEnabled true` — and
**persist it the same way `vigilant-env` persists the other globals** (add it to the §5.1
`vigilant-env` script), because a runtime-only `true` silently reverts to false on reboot and
will look like a server bug. Conversely, persisting `true` and forgetting it leaves the
live-config path armed after every self-update. Treat the master switch as a deliberate,
per-device, reviewed change, and **audit which devices have it `true` before any fleet-wide
change.** When you enable apply, the scheduler group may also need `reboot`/`policy` (§2.3),
but **only** if config jobs reboot the box or install users/scripts.
