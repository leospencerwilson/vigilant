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
docs/ARCHITECTURE.md     full design — collection model, schema, config push, security
db/schema.sql            Supabase schema (own `vigilant` schema; Realtime-enabled)
agent/bootstrap.rsc      DRAFT: daily self-update scheduler for the router
agent/vigilant-agent.rsc DRAFT: the collector + config-apply agent
```

`ingest/` (telemetry API) and `worker/` (alerts + history rollup) get added when we build
them — see ARCHITECTURE §3 and the build order in §9.

## Status

Design + scaffold. Nothing deployed. Next step: apply `db/schema.sql` to the IaaS
Supabase, stand up the ingest API behind the Cloudflare Tunnel, and pilot the rewritten
agent on **one** non-critical router.
