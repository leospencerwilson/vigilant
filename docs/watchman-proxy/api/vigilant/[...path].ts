// Vercel Serverless Function — Vigilant admin-API proxy for the Watchman SPA.
//
// Why this exists: Vigilant's admin endpoints are guarded by a single bearer
// (ENROLL_TOKEN). That token must NEVER ship in a Vite bundle. The browser instead calls
// this same-origin proxy with the logged-in user's Supabase access token; the proxy
// verifies that token, then forwards to Vigilant with the admin bearer (server-side only).
//
// Placement in the Watchman repo: copy this file to  api/vigilant/[...path].ts
// (Vercel maps it to  /api/vigilant/*  — the catch-all captures the Vigilant path.)
//
// Required Vercel env vars (Project → Settings → Environment Variables — NOT VITE_*):
//   VIGILANT_API_URL      https://vigilant.internal.western-communication.com  (the
//                         externally-reachable Cloudflare Tunnel hostname — the "internal"
//                         is just part of the name; it must resolve from Vercel. See README.)
//   VIGILANT_ADMIN_TOKEN  Vigilant's ENROLL_TOKEN (the admin bearer)
//   SUPABASE_URL          your Supabase URL (for verifying the caller's JWT)
//   SUPABASE_ANON_KEY     Supabase anon key (apikey header for the verify call)
// Optional, if your Vigilant tunnel sits behind Cloudflare Access service-token auth:
//   CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET

import type { VercelRequest, VercelResponse } from "@vercel/node";

// ── Endpoint allowlist ────────────────────────────────────────────────
// Only these (method, path) pairs may be proxied. Everything else → 403. This is what keeps
// the SPA from reaching /enroll, /admin/migrate, or the device routes through the proxy.
const SERIAL = "[^/]+";
const ID = "[^/]+";
const ALLOW: Array<{ method: string; re: RegExp }> = [
  { method: "GET",  re: new RegExp(`^/fleet$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/history$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/config-jobs$`) },
  { method: "POST", re: new RegExp(`^/devices/${SERIAL}/config-jobs$`) },
  { method: "POST", re: new RegExp(`^/config-jobs/${ID}/approve$`) },
  { method: "POST", re: new RegExp(`^/config-jobs/${ID}/cancel$`) },
  { method: "GET",  re: new RegExp(`^/devices/${SERIAL}/speedtests$`) },
  { method: "POST", re: new RegExp(`^/devices/${SERIAL}/speedtests$`) },
  { method: "GET",  re: new RegExp(`^/oui/${ID}$`) },
];

function isAllowed(method: string, path: string): boolean {
  return ALLOW.some((a) => a.method === method && a.re.test(path));
}

// Verify the caller's Supabase access token by asking Supabase who it belongs to.
// Returns the user id on success, or null. (No extra deps — just the auth REST endpoint.)
async function verifyUser(accessToken: string): Promise<string | null> {
  const base = process.env.SUPABASE_URL;
  const anon = process.env.SUPABASE_ANON_KEY;
  if (!base || !anon) return null;
  try {
    const r = await fetch(`${base}/auth/v1/user`, {
      headers: { apikey: anon, Authorization: `Bearer ${accessToken}` },
    });
    if (!r.ok) return null;
    const u = (await r.json()) as { id?: string };
    return u && u.id ? u.id : null;
  } catch {
    return null;
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const method = (req.method || "GET").toUpperCase();

  // 1. Rebuild the Vigilant path from the catch-all segments.
  const segs = req.query.path;
  const parts = Array.isArray(segs) ? segs : segs ? [segs] : [];
  const path = "/" + parts.map(encodeURIComponent).join("/");

  // 2. Allowlist check (method + path).
  if (!isAllowed(method, path)) {
    return res.status(403).json({ ok: false, error: "forbidden path" });
  }

  // 3. Authenticate the caller (the SPA sends the user's Supabase access token).
  const auth = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(Array.isArray(auth) ? auth[0] : auth);
  const userId = m ? await verifyUser(m[1].trim()) : null;
  if (!userId) return res.status(401).json({ ok: false, error: "unauthorized" });

  // 4. Forward to Vigilant with the admin bearer (preserve the query string).
  const targetBase = process.env.VIGILANT_API_URL;
  const adminToken = process.env.VIGILANT_ADMIN_TOKEN;
  if (!targetBase || !adminToken) {
    return res.status(500).json({ ok: false, error: "proxy not configured" });
  }
  const qs = req.url && req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
  const targetUrl = `${targetBase.replace(/\/$/, "")}${path}${qs}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${adminToken}`,
  };
  if (process.env.CF_ACCESS_CLIENT_ID && process.env.CF_ACCESS_CLIENT_SECRET) {
    headers["CF-Access-Client-Id"] = process.env.CF_ACCESS_CLIENT_ID;
    headers["CF-Access-Client-Secret"] = process.env.CF_ACCESS_CLIENT_SECRET;
  }
  let body: string | undefined;
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    // Vercel parses JSON bodies into req.body; re-serialise for the upstream call.
    body = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {});
    headers["Content-Type"] = "application/json";
  }

  try {
    const upstream = await fetch(targetUrl, { method, headers, body });
    const text = await upstream.text();
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    return res.send(text);
  } catch (e: any) {
    // Most likely cause: VIGILANT_API_URL is not reachable from Vercel (internal-only host).
    return res.status(502).json({
      ok: false,
      error: "upstream unreachable",
      detail: e?.message ?? String(e),
    });
  }
}
