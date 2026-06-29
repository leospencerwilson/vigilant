// wc_field — Supabase Edge Function: vigilant-enroll
// Lives in the wc_field repo at: supabase/functions/vigilant-enroll/index.ts
//
// Browser (Vite SPA, behind the wc_field login) → THIS function → Vigilant admin API.
// The function holds Vigilant's ENROLL_TOKEN as a Supabase SECRET (never shipped to the
// browser), verifies the caller's Supabase session, then proxies the two calls the install
// wizard needs:
//     POST /functions/v1/vigilant-enroll?action=enroll   body: { serial, site_name?, customer?, wan_type?, tags? }
//     GET  /functions/v1/vigilant-enroll?action=verify&serial=HGT0A023T6C
//
// DEPLOY (must be --no-verify-jwt so the CORS preflight reaches us; we verify the JWT inside):
//     supabase functions deploy vigilant-enroll --no-verify-jwt
//     supabase secrets set VIGILANT_API_URL=https://vigilant.internal.western-communication.com
//     supabase secrets set VIGILANT_ENROLL_TOKEN=<ENROLL_TOKEN>
//     # optional, only if Vigilant's hostname is behind Cloudflare Access:
//     supabase secrets set CF_ACCESS_CLIENT_ID=... CF_ACCESS_CLIENT_SECRET=...
// (SUPABASE_URL and SUPABASE_ANON_KEY are injected automatically — used to verify the user.)

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// Tighten the origin to your deployed wc_field URL(s) in production instead of "*".
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
};
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json" } });

// Verify the wc_field user's Supabase session (the SPA sends their access token as the bearer).
async function verifyUser(authHeader: string | null): Promise<boolean> {
  const m = /^Bearer\s+(.+)$/i.exec(authHeader ?? "");
  if (!m) return false;
  const base = Deno.env.get("SUPABASE_URL");
  const anon = Deno.env.get("SUPABASE_ANON_KEY");
  if (!base || !anon) return false;
  try {
    const r = await fetch(`${base}/auth/v1/user`, { headers: { apikey: anon, Authorization: `Bearer ${m[1]}` } });
    return r.ok;
  } catch {
    return false;
  }
}

function vigilantHeaders(): HeadersInit {
  const h: Record<string, string> = {
    Authorization: `Bearer ${Deno.env.get("VIGILANT_ENROLL_TOKEN") ?? ""}`,
    "content-type": "application/json",
  };
  const id = Deno.env.get("CF_ACCESS_CLIENT_ID");
  const sec = Deno.env.get("CF_ACCESS_CLIENT_SECRET");
  if (id && sec) { h["CF-Access-Client-Id"] = id; h["CF-Access-Client-Secret"] = sec; }
  return h;
}

serve(async (req) => {
  // 1) CORS preflight — must return 200 (this is why we deploy with --no-verify-jwt).
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  // 2) AuthN — require a valid wc_field user session before touching the admin token.
  if (!(await verifyUser(req.headers.get("authorization")))) {
    return json(401, { ok: false, error: "unauthorized" });
  }

  const base = (Deno.env.get("VIGILANT_API_URL") ?? "").replace(/\/$/, "");
  const token = Deno.env.get("VIGILANT_ENROLL_TOKEN");
  if (!base || !token) return json(500, { ok: false, error: "function not configured" });

  const url = new URL(req.url);
  const action = url.searchParams.get("action");

  try {
    // 3a) Enrol — create the device + per-device token, return the install block.
    if (action === "enroll" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      if (!body || typeof body.serial !== "string" || !body.serial.trim()) {
        return json(400, { ok: false, error: "serial required" });
      }
      const r = await fetch(`${base}/enroll`, { method: "POST", headers: vigilantHeaders(), body: JSON.stringify(body) });
      const text = await r.text();
      return new Response(text, { status: r.status, headers: { ...CORS, "content-type": "application/json" } });
    }

    // 3b) Verify — poll the device until it reports online. 404 = not reporting yet.
    if (action === "verify" && req.method === "GET") {
      const serial = url.searchParams.get("serial");
      if (!serial) return json(400, { ok: false, error: "serial required" });
      const r = await fetch(`${base}/devices/${encodeURIComponent(serial)}`, { headers: vigilantHeaders() });
      const text = await r.text();
      return new Response(text, { status: r.status, headers: { ...CORS, "content-type": "application/json" } });
    }

    return json(404, { ok: false, error: "unknown action" });
  } catch (e) {
    // Most likely: VIGILANT_API_URL unreachable from Supabase's cloud (or Access-gated).
    return json(502, { ok: false, error: "vigilant unreachable", detail: String((e as Error)?.message ?? e) });
  }
});
