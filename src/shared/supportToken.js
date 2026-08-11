'use strict';

// The capability a browser presents to the noVNC bridge on the WireGuard hub, so that opening a
// counter's screen is authorised by the operator's wc-field session and nothing else.
//
// WHY SIGNED AND NOT A LOOKUP TABLE. websockify ships a TokenFile plugin mapping a fixed string
// to a target; that is a permanent bearer, so anyone who ever saw a URL could open a pharmacy
// counter forever. Here the token IS the authorisation: minted only for an authenticated
// caller, valid seconds, naming one target.
//
// WHY VERIFICATION IS OFFLINE AT THE FAR END. Vigilant has no route to the hub (different
// network); the hub can only reach Vigilant outbound. So the bridge cannot be told about
// sessions and cannot call back to check one. A shared secret and a signature need neither.
//
// MIRRORS /etc/wcn/wcn_vnc_token.py ON THE HUB. If you change the payload shape, the TTL or the
// signing input here, change it there in the same breath or every session breaks.

const crypto = require('node:crypto');

// Long enough to load a page and open a socket; short enough that a token in a browser history,
// a proxy log or a screenshot is worthless by the time anyone reads it. The bridge enforces its
// own ceiling too, so this cannot be widened from here alone.
const TTL_S = 90;

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function mintSupportToken({ host, port = 5900 }) {
  const secret = process.env.SUPPORT_VNC_SECRET || '';
  // Read per call, not at module load: rotating the secret should not need a redeploy, and a
  // service that booted before the env was set must fail loudly rather than mint junk forever.
  if (!secret) throw new Error('SUPPORT_VNC_SECRET is not set — refusing to mint an unsigned support token');
  if (!host) throw new Error('mintSupportToken needs a host');
  const now = Date.now() / 1000;
  const body = Buffer.from(JSON.stringify({ h: String(host), p: Number(port), iat: now, exp: now + TTL_S }));
  const sig = crypto.createHmac('sha256', secret).update(body).digest();
  return {
    token: `${b64u(body)}.${b64u(sig)}`,
    expires_at: new Date((now + TTL_S) * 1000).toISOString(),
  };
}

module.exports = { mintSupportToken, TTL_S };
