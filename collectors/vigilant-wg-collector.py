#!/usr/bin/env python3
"""Push WireGuard peer state from the hub to Vigilant.

RUNS ON THE HUB (pmr-desktop-gateway). It is the only host that can see peer handshakes —
`wg show` reports what the hub itself has negotiated, and no other box has that view.

This is what makes `pi_tunnel_up` mean anything. A counter Pi also reports its OWN view of
the tunnel; when the two disagree, that disagreement is the diagnosis.
"""
import json, os, re, subprocess, sys, urllib.error, urllib.request

CONF = "/etc/vigilant/wg-collector.env"
UA = "vigilant-wg-collector/1"   # Cloudflare 403s Python's default signature (error 1010)


def load_conf():
    conf = {}
    try:
        with open(CONF) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    for k in ("VIGILANT_URL", "VIGILANT_ADMIN_TOKEN", "WG_IFACE"):
        if os.environ.get(k):
            conf[k] = os.environ[k]
    return conf


def peers(iface):
    """`wg show <if> dump`: first line is the interface, peer lines have 8 tab-separated
    fields — pubkey, psk, endpoint, allowed-ips, handshake(unix), rx, tx, keepalive."""
    try:
        out = subprocess.run(["wg", "show", iface, "dump"], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        print(f"collector: cannot read wg ({e})", file=sys.stderr)
        return None
    rows = []
    for line in out.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        hs = int(f[4]) if f[4].isdigit() else 0
        rows.append({
            "public_key": f[0],
            "endpoint": None if f[2] in ("(none)", "") else f[2],
            "allowed_ips": f[3] or None,
            # 0 means "never handshaked", which is not the same as "at the epoch".
            "latest_handshake": hs or None,
            "rx_bytes": int(f[5]) if f[5].isdigit() else 0,
            "tx_bytes": int(f[6]) if f[6].isdigit() else 0,
        })
    return rows


def main():
    conf = load_conf()
    missing = [k for k in ("VIGILANT_URL", "VIGILANT_ADMIN_TOKEN") if not conf.get(k)]
    if missing:
        print(f"collector: missing {', '.join(missing)} in {CONF}", file=sys.stderr)
        return 2
    rows = peers(conf.get("WG_IFACE") or "wg0")
    if rows is None:
        return 1
    req = urllib.request.Request(
        conf["VIGILANT_URL"].rstrip("/") + "/wg-peers/report",
        data=json.dumps({"peers": rows}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA,
                 "Authorization": f"Bearer {conf['VIGILANT_ADMIN_TOKEN']}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print(f"reported {len(rows)} peers -> {r.status} {r.read().decode()[:200]}", flush=True)
        return 0
    except urllib.error.HTTPError as e:
        print(f"collector: HTTP {e.code}" + (" (Cloudflare signature block?)" if e.code == 403 else ""), file=sys.stderr)
        return 1
    except Exception as e:
        print(f"collector: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
