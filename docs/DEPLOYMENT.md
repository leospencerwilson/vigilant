# Vigilant — deployment (IaaS, Coolify, Cloudflare Tunnel)

How to deploy Vigilant on the WCN Cloud IaaS: apply the schema, set env, stand the
ingest API up behind the Cloudflare Tunnel, run the worker, enrol a device, and
smoke-test with the simulator.

> The WCN MikroTik estate is **live production**. Nothing in this doc touches a router
> except `npm run enroll` (which only writes a DB row + prints a token) and the optional
> agent pilot, which is review-gated. See `ARCHITECTURE.md` §5 and `RUNBOOK-config-push.md`.

---

## 0. Topology recap

- Vigilant runs on the IaaS host `10.10.30.10` (Proxmox → Coolify VM), alongside the
  self-hosted Supabase stack and the WCN Cloud console.
- **Postgres is the existing self-hosted Supabase DB** — Vigilant uses its own `vigilant`
  schema in that database. We do **not** ship a Postgres container (see `docker-compose.yml`).
- Public reachability for device telemetry is via the **Cloudflare Tunnel** already running
  on the IaaS — `vigilant.western-communication.com` → `ingest:${PORT}`. No dst-NAT, no
  inbound firewall change on the WCN MikroTik (`server project/dc-deployment/02-public-exposure.md`).
- Only the **ingest** service is published through the tunnel. The **worker** is internal.

```
MikroTiks ──HTTPS POST /telemetry──▶ Cloudflare edge ──tunnel──▶ cloudflared (IaaS)
                                                                      │
                                                                      ▼
                                                             ingest container :PORT
                                                                      │  pg
                                                                      ▼
                                                   self-hosted Supabase Postgres (vigilant schema)
                                                                      ▲  pg
                                                              worker container (no inbound)
```

---

## 1. Environment

Copy `.env.example` to `.env` and fill it in. The same `.env` is loaded by **both**
services (`env_file: .env` in compose) and by the CLIs.

```bash
cp .env.example .env
```

Key variables (full list + defaults in `.env.example` / `src/shared/config.js`):

| Var | What | Notes |
|---|---|---|
| `VIGILANT_DB_URL` | Postgres connection string to the self-hosted Supabase DB | `postgresql://vigilant:<pw>@10.10.30.10:5432/postgres`. The `vigilant` schema is set via search_path in `db.js`. |
| `PORT` | Ingest HTTP listen port | Default `9100`. Cloudflare Tunnel targets this. |
| `ENROLL_TOKEN` | Admin bearer for `POST /enroll`, `GET /fleet`, `GET /devices/:serial` | Long random secret. **Never commit.** |
| `AGENT_SCRIPT_PATH` | Fallback agent script when `agent_scripts` table is empty | Default `./agent/vigilant-agent.rsc`. |
| `PUBLIC_BASE_URL` | Base URL used to build config-job `.rsc` fetch URLs | `https://vigilant.western-communication.com`. Must match the tunnel hostname. |
| `FAST_POLL_S` / `DEFAULT_POLL_S` | Poll cadence (drilldown vs normal) | `3` / `10`. |
| `STALE_AFTER_S` / `OFFLINE_AFTER_S` | Worker staleness thresholds | `45` / `120`. |
| `HISTORY_RAW_RETENTION_H` | Raw history kept before downsample/prune | `24`. |
| `NEIGHBOR_TTL_S` | Prune neighbours/mac_hosts not seen within this | `86400`. |
| `STORE_KIND` | `pg` (production) or `mem` (local/E2E) | Production = `pg`. |

> **Secrets discipline:** `VIGILANT_DB_URL` (contains the DB password) and `ENROLL_TOKEN`
> are secrets. In Coolify, set them as environment variables on the service, not in the
> repo. The app never logs them (see CONTRACT "Non-negotiables").

---

## 2. Apply the database schema

The migrate CLI runs `db/schema.sql` verbatim and idempotently against `VIGILANT_DB_URL`.
It is safe to re-run.

```bash
npm install
npm run migrate          # = node src/bin/migrate.js -> store.migrate()
```

This creates the `vigilant` schema, all tables, indexes, the `v_fleet` view, and adds the
live tables (`device_state`, `interface_state`, `lte_state`, `neighbors`, `config_jobs`,
`alerts`) to the `supabase_realtime` publication so Watchman / the console get pushes.

You can also apply it directly with psql if you prefer (same file):

```bash
psql "$VIGILANT_DB_URL" -f db/schema.sql
```

Verify:

```bash
psql "$VIGILANT_DB_URL" -c "SELECT count(*) FROM vigilant.devices;"
```

---

## 3. Deploy on Coolify (behind the Cloudflare Tunnel)

Vigilant ships a `docker-compose.yml` with two services off one image: `ingest` and
`worker`. Both load `.env`. Postgres is external (Supabase) — not in the compose.

1. **Create the resource in Coolify** as a *Docker Compose* application, pointed at this
   repo (or push the image to your registry and reference `vigilant:latest`). Coolify
   builds `Dockerfile` once and runs both services.
2. **Set environment variables** on the Coolify resource (section 1). At minimum:
   `VIGILANT_DB_URL`, `ENROLL_TOKEN`, `PUBLIC_BASE_URL`, `STORE_KIND=pg`.
3. **Network the ingest service to the tunnel.** The existing `cloudflared` on the IaaS
   already terminates `vigilant.western-communication.com`. Point that hostname's ingress
   rule at `http://ingest:${PORT}` (same Docker network). No host port is published and no
   change is made to the WCN MikroTik.
   - Cloudflared ingress example (on the IaaS, not in this repo):
     ```yaml
     ingress:
       - hostname: vigilant.western-communication.com
         service: http://ingest:9100
       - service: http_status:404
     ```
4. **Apply the schema** (section 2) — either run `npm run migrate` once from a Coolify
   "command"/exec, or via psql from the IaaS. Do this before first device traffic.
5. **Deploy.** Coolify starts both `ingest` and `worker`. The compose healthcheck hits
   `/healthz` on the ingest.

Confirm the ingest is up (from the IaaS / through the tunnel):

```bash
curl -s https://vigilant.western-communication.com/healthz      # -> ok
```

The worker has no inbound surface; confirm it from logs (it logs each `runOnce` pass).

---

## 4. Enrol a device

`npm run enroll` creates a `devices` row + a per-device bearer token (stored hashed in
`enrollment_tokens`) and prints the bootstrap globals to paste onto the router.

```bash
npm run enroll -- --serial HGT0A023T6C --site "Allied Huddersfield" \
                  --customer Allied --wan-type pppoe --tags allied,pharmacy
```

It prints something like:

```
device:  <uuid>  HGT0A023T6C
token:   <PER-DEVICE-ENROLMENT-TOKEN>     # shown ONCE — store it, it is not recoverable
bootstrap:
  :global vigilantUrl   "https://vigilant.western-communication.com"
  :global vigilantToken "<PER-DEVICE-ENROLMENT-TOKEN>"
```

On the router (reviewed, Safe Mode), set those two globals, then add the bootstrap
scheduler from `agent/bootstrap.rsc`. The bootstrap fetches the current agent script
daily; the agent pushes telemetry every `DEFAULT_POLL_S`. Pilot on **one** non-critical
router first — see `RUNBOOK-config-push.md`.

> `--wan-type` must be one of `pppoe | sim | dhcp | static | unknown` (schema CHECK).

---

## 5. Smoke-test with the simulator

The simulator POSTs a realistic telemetry payload (the same generator the e2e test uses)
to the live ingest, so you can prove the whole path — tunnel → ingest → Supabase →
Realtime — without touching a router. Use the token printed by `enroll`.

```bash
npm run simulate -- --url https://vigilant.western-communication.com \
                    --token "<PER-DEVICE-ENROLMENT-TOKEN>"
```

Send it twice (a couple of seconds apart): the first POST establishes interface byte
counters; the second produces non-zero `rx_bps`/`tx_bps` from the delta. Expected:

- HTTP `200` with `{"ok":true,"poll_interval_s":10,"agent_version":…}`.
- A row in `vigilant.device_state` (status flips to `online`), rows in `interface_state`,
  and `neighbors`. `mac_hosts` only when the payload includes them.
- Watchman / console subscribers see the Realtime push.

Quick DB check:

```bash
psql "$VIGILANT_DB_URL" -c \
  "SELECT serial,status,cpu_load,last_seen_at FROM vigilant.device_state s
     JOIN vigilant.devices d ON d.id=s.device_id;"
```

For a fully local dry-run (no Supabase, no tunnel) you can run the ingest with the
in-memory store and simulate against localhost:

```bash
STORE_KIND=mem PORT=9100 npm start &           # in-memory ingest
npm run simulate -- --url http://127.0.0.1:9100 --token <whatever>   # mem store accepts any enrolled token
```

---

## 6. The collector worker

The `worker` service runs `runOnce` on an interval (default 30s): mark devices
stale/offline by `last_seen_at`, evaluate alert rules, downsample + prune history, prune
stale neighbours / mac_hosts. It needs only `VIGILANT_DB_URL` and the threshold envs
(`STALE_AFTER_S`, `OFFLINE_AFTER_S`, `HISTORY_RAW_RETENTION_H`, `NEIGHBOR_TTL_S`).

Nightly read-only config snapshots are gated behind `ENABLE_NIGHTLY_SNAPSHOT` (default
`false` for v1) — leave off until the config-push pilot is signed off.

Run standalone (outside compose) with:

```bash
npm run start:worker      # = node src/worker/worker.js
```

---

## 7. Upgrades & rollback

- **App upgrade:** push a new image / redeploy in Coolify. Schema changes ship in
  `db/schema.sql` (idempotent) — run `npm run migrate` as part of the deploy.
- **Agent upgrade:** publish a new row in `agent_scripts` with `is_current=true` and bump
  the version; routers self-update within a day via `bootstrap.rsc`. No per-router edits.
- **Rollback:** redeploy the previous image tag in Coolify. The schema is additive and
  idempotent; no destructive migrations in v1.
