# Watchman → Vigilant proxy (Vercel Function)

A same-origin proxy so the Watchman SPA can use Vigilant's admin API **without** ever
shipping the admin bearer to the browser. The browser calls `/api/vigilant/*` with the
logged-in user's Supabase access token; the function verifies it and forwards to Vigilant
with `ENROLL_TOKEN`.

```
browser ──(Supabase user JWT)──▶ /api/vigilant/fleet  (Vercel Function)
                                      │ verify JWT, swap for admin bearer
                                      ▼
                          VIGILANT_API_URL/fleet  (Authorization: Bearer ENROLL_TOKEN)
```

## Reachability

`VIGILANT_API_URL` must be reachable from Vercel's cloud (where the function runs).
`https://vigilant.internal.western-communication.com` **is** externally reachable — the
`internal` is just part of the subdomain name; the Cloudflare Tunnel publishes it publicly.
So set:

```
VIGILANT_API_URL=https://vigilant.internal.western-communication.com
```

**If that hostname is behind Cloudflare Access** (recommended for an admin API): issue a
**service token** for the proxy and set `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` —
the function sends them as `CF-Access-Client-*` headers so it passes Access while the API
stays closed to the open web. If the hostname is open (Tunnel public, no Access), leave
those unset; the bearer alone authenticates.

> Quick check that Vercel can reach it: `curl -s https://vigilant.internal.western-communication.com/healthz`
> should return `ok` from anywhere. If it only works on the VPN, it's Access-gated — use a
> service token (above).

## Files

```
api/vigilant/[...path].ts   the proxy (catch-all → /api/vigilant/*)
```

Copy `api/` into the Watchman repo root. Vite + Vercel serves `/api/*` as functions
automatically; no `vercel.json` change needed beyond the SPA rewrite you already have.

> If your existing `vercel.json` rewrites `/(.*)` → `/index.html`, make sure it does **not**
> swallow `/api/*`. Use a negative-lookahead source so API routes still hit the function:
> ```json
> { "rewrites": [{ "source": "/((?!api/).*)", "destination": "/index.html" }] }
> ```

## Environment variables (Vercel → Project → Settings → Environment Variables)

Server-side only — **do not** prefix with `VITE_` (that would ship them to the browser):

| Var | Value |
|---|---|
| `VIGILANT_API_URL` | `https://vigilant.internal.western-communication.com` (externally reachable Tunnel hostname) |
| `VIGILANT_ADMIN_TOKEN` | Vigilant's `ENROLL_TOKEN` |
| `SUPABASE_URL` | Your Supabase URL (used to verify the caller's JWT) |
| `SUPABASE_ANON_KEY` | Supabase anon key (apikey header for the verify call) |
| `CF_ACCESS_CLIENT_ID` | *(optional)* Cloudflare Access service-token id |
| `CF_ACCESS_CLIENT_SECRET` | *(optional)* Cloudflare Access service-token secret |

## Allowlist

The function only forwards these (method, path) pairs — everything else is `403`:

- `GET /fleet`
- `GET /devices/:serial`
- `GET /devices/:serial/history`
- `GET|POST /devices/:serial/config-jobs`
- `POST /config-jobs/:id/approve`
- `POST /config-jobs/:id/cancel`
- `GET|POST /devices/:serial/speedtests`
- `GET /oui/:mac`

`/enroll`, `/admin/migrate`, and all device routes are intentionally **not** proxied.

## Wiring the client

Point the typed client (from `WATCHMAN-API-AND-SCHEMA.md`) at the proxy, and pass the
user's Supabase access token as the bearer — the function swaps it for the admin token:

```ts
import { createClient } from "@supabase/supabase-js";
import { createVigilantApi } from "./vigilantApi";

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
);

// baseUrl is the same-origin proxy; the "token" is the USER's Supabase access token,
// not the admin token. Fetch it fresh per call so it isn't stale after a refresh.
async function vigilant() {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  return createVigilantApi("/api/vigilant", token);
}

// usage
const api = await vigilant();
const { devices } = await api.fleet();
const detail = await api.device("HGT0A023T6C");
```

> Token freshness: `supabase-js` refreshes the session in the background, so reading
> `getSession()` before each call (as above) keeps the access token current. If you'd rather
> build the client once, wrap the `token` as a getter and read it inside `call()`.

## Smoke test

```bash
# Should 401 without a valid user JWT:
curl -i https://<watchman>.vercel.app/api/vigilant/fleet

# Should 403 (blocked path) even with a valid JWT:
curl -i -H "Authorization: Bearer <user-jwt>" https://<watchman>.vercel.app/api/vigilant/enroll
```
