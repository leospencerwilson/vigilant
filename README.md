# Vigilant

Realtime MikroTik telemetry + safe config-push engine for the WCN estate.

Vigilant is the **backend/engine**: it ingests device telemetry, stores it in
self-hosted Supabase, and orchestrates review-gated config pushes. The existing
**Watchman** web UI and the WCN Cloud **console** are the *frontends* that consume it
(Supabase Realtime + a small action API). Runs on the WCN Cloud IaaS.

It replaces the current per-router scheduler that `POST`s a thin JSON blob every 6
minutes — with a fast (default 10s), rich, two-way channel: full system/health stats,
**per-port throughput** (computed server-side from byte-counter deltas), PPP/Wi-Fi/DHCP
state, alerts, and a Safe-Mode config-push path.

> ⚠️ The WCN MikroTik estate is **live production**. Everything in `agent/` is a DRAFT
> and must be reviewed before it touches a router. Config push is review-gated, applied
> under Safe Mode, with an automatic dead-man's-switch rollback. Never auto-apply.

## Why device-push (not central polling)

Some sites are on 4G/SIM (CGNAT) and others on dynamic-IP PPPoE — we cannot reliably
reach them inbound. So the router always initiates: it **pushes** telemetry out and
**pulls** its approved config jobs. See `docs/ARCHITECTURE.md` §2/§4.

## Layout

```
package.json             one manifest for the whole service (scripts: start, start:worker,
                         migrate, enroll, simulate, test); deps: pg, zod, dotenv
.env.example             every env var Vigilant reads — copy to .env
Dockerfile               container image; docker-compose.yml for ingest + worker
src/
  shared/                config, log, the Store interface + pg/mem backends, db pool,
                         telemetry zod schema/normalize, pure transforms, OUI lookup
  ingest/                createServer() HTTP API + per-route handlers (telemetry, agent
                         script, config pending/fetch/result, enroll, fleet, device detail)
  worker/                runWorker()/runOnce() — stale/offline marking, alert evaluation,
                         history downsample/prune, neighbor/mac-host TTL
  bin/                   migrate.js, enroll.js, simulate.js CLIs
test/                    node:test suite (transform, telemetry, oui, config, ingest e2e)
db/schema.sql            Supabase schema (own `vigilant` schema; Realtime-enabled);
                         migrate() applies it verbatim/idempotently
agent/bootstrap.rsc      DRAFT: daily self-update scheduler for the router
agent/vigilant-agent.rsc DRAFT: the collector + config-apply agent (device payload source of truth)
docs/                    contract, architecture, deployment, frontend integration, runbook
```

## Docs

- **[docs/CONTRACT.md](docs/CONTRACT.md)** — authoritative build contract: file layout,
  Store interface, routes, telemetry payload/response, env vars, test gate. Start here.
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — full design: collection model,
  schema, config push, security.
- **[docs/TELEMETRY-CATALOGUE.md](docs/TELEMETRY-CATALOGUE.md)** — what RouterOS 7 fields
  the agent collects and how they map to the payload.
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — deploy on the IaaS via Coolify behind the
  Cloudflare Tunnel: apply schema, set env, run ingest + worker.
- **[docs/FRONTEND-INTEGRATION.md](docs/FRONTEND-INTEGRATION.md)** — how Watchman and the
  WCN console consume Vigilant (Supabase Realtime + the small action API).
- **[docs/RUNBOOK-config-push.md](docs/RUNBOOK-config-push.md)** — review-gated config-push
  lifecycle: Safe Mode apply with dead-man rollback.

## Status

**Built (green).** The ingest API, worker, the three CLIs (`migrate`, `enroll`,
`simulate`), and the `node:test` suite are implemented per `docs/CONTRACT.md` and load
cleanly. `npm test` (`node --test`) passes with no external Postgres (tests run against the
in-memory store). The `agent/` `.rsc` files remain **DRAFTS** pending review.

**Not yet deployed.** Next step: apply `db/schema.sql` to the IaaS Supabase, stand the
ingest API up behind the Cloudflare Tunnel (see `docs/DEPLOYMENT.md`), and pilot the
rewritten agent on **one** non-critical router.

## Run it

Requires Node 20+. For a real run set `STORE_KIND=pg` and point `VIGILANT_DB_URL` at the
self-hosted Supabase Postgres; for a no-database smoke test set `STORE_KIND=mem`.

```sh
npm install                       # pg, zod, dotenv (no dev deps)

cp .env.example .env              # then edit: VIGILANT_DB_URL, ENROLL_TOKEN, PUBLIC_BASE_URL …

npm run migrate                   # apply db/schema.sql into the `vigilant` schema (pg store)

npm start                         # ingest HTTP API on $PORT (default 9100)
npm run start:worker              # alerts + history rollup loop (separate process)

# Enrol a device — prints the per-device bearer + RouterOS bootstrap snippet ONCE:
npm run enroll -- --serial HGT0A023T6C --site "Allied Huddersfield" \
  --customer Allied --wan-type pppoe --tags allied,pharmacy

# Drive synthetic telemetry at the ingest so you can watch data flow without a router:
npm run simulate -- --url http://localhost:9100 --token <bearer-from-enroll>

npm test                          # node --test — runs against the in-memory store
```

> The `--` after the npm script name forwards the flags to the underlying CLI.
> `enroll` and `simulate` accept `--flag value` or `--flag=value`. `simulate` also takes
> optional `--ticks N` (0 = forever), `--interval <ms>`, and `--serial <S>`.
