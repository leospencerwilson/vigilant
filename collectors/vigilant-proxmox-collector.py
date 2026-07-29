#!/usr/bin/env python3
"""Push the Proxmox cluster's VM inventory to Vigilant.

RUNS ON A PROXMOX NODE. Vigilant sits on the DMZ VLAN and has no route to the Proxmox API
on the management VLAN, so this pushes rather than Vigilant pulling — which means no
DMZ-to-management firewall hole and no API token, because `pvesh` on a node is already
authenticated as root.

Any node works: pvesh reads /cluster/resources, so one node reports for the whole cluster.
Per-VM config is fetched for the VLAN tag, which is what maps a VM to a pharmacy
(tag = 100 + pharmacy index).

Stdlib only. Config in /etc/vigilant/proxmox-collector.env:
    VIGILANT_URL=https://vigilant.internal.western-communication.com
    VIGILANT_ADMIN_TOKEN=<the estate admin token>
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

CONF = "/etc/vigilant/proxmox-collector.env"
# Cloudflare fronts Vigilant and bans Python's default client signature with
# "error code: 1010" — every request 403s, including ones curl gets a 200 for.
UA = "vigilant-proxmox-collector/1"


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
    for k in ("VIGILANT_URL", "VIGILANT_ADMIN_TOKEN"):
        if os.environ.get(k):
            conf[k] = os.environ[k]
    return conf


def pvesh(path):
    try:
        out = subprocess.run(["pvesh", "get", path, "--output-format", "json"],
                             capture_output=True, text=True, timeout=25)
        return json.loads(out.stdout) if out.stdout.strip() else None
    except Exception:
        return None


def vlan_and_macs(node, vmid):
    """Pull the VLAN tag and MACs out of the VM's netN lines.

    A VM can be dual-homed (the PMR gateway carries the DMZ on net0 and the pharmacy VLAN on
    net1), so every tag is collected and the pharmacy-range one is preferred — tags 101+ are
    per-pharmacy, while 30 is the shared DMZ. Choosing the lowest or the first would map the
    gateway to the wrong place.
    """
    cfg = pvesh(f"/nodes/{node}/qemu/{vmid}/config")
    if not isinstance(cfg, dict):
        return None, []
    tags, macs = [], []
    for key, val in cfg.items():
        if not re.match(r"^net\d+$", key) or not isinstance(val, str):
            continue
        mac = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", val)
        if mac:
            macs.append(mac.group(1).upper())
        tag = re.search(r"\btag=(\d+)", val)
        if tag:
            tags.append(int(tag.group(1)))
    pharmacy_tags = [t for t in tags if t >= 101]
    return (pharmacy_tags[0] if pharmacy_tags else (tags[0] if tags else None)), macs


def collect():
    resources = pvesh("/cluster/resources?type=vm") or pvesh("/cluster/resources")
    if not isinstance(resources, list):
        print("collector: could not read /cluster/resources (is this a Proxmox node?)", file=sys.stderr)
        return None
    vms = []
    for r in resources:
        if r.get("type") != "qemu":
            continue
        vmid, node = r.get("vmid"), r.get("node")
        if vmid is None or not node:
            continue
        tag, macs = vlan_and_macs(node, vmid)
        vms.append({
            "vmid": vmid, "node": node, "name": r.get("name"), "status": r.get("status"),
            "vlan_tag": tag, "macs": macs, "cores": r.get("maxcpu"),
            "maxmem": r.get("maxmem"), "maxdisk": r.get("maxdisk"),
            "uptime_s": r.get("uptime"),
            # Templates are inventory noise and must never be matched to a live counter.
            "template": bool(r.get("template")),
        })
    return vms


def main():
    conf = load_conf()
    missing = [k for k in ("VIGILANT_URL", "VIGILANT_ADMIN_TOKEN") if not conf.get(k)]
    if missing:
        print(f"collector: missing {', '.join(missing)} in {CONF}", file=sys.stderr)
        return 2

    vms = collect()
    if vms is None:
        return 1

    body = json.dumps({"vms": vms}).encode()
    req = urllib.request.Request(
        conf["VIGILANT_URL"].rstrip("/") + "/proxmox/report",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA,
                 "Authorization": f"Bearer {conf['VIGILANT_ADMIN_TOKEN']}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = r.read().decode()[:400]
        print(f"reported {len(vms)} VMs -> {r.status} {resp}", flush=True)
        return 0
    except urllib.error.HTTPError as e:
        extra = " (Cloudflare may be blocking the client signature)" if e.code == 403 else ""
        print(f"collector: HTTP {e.code}{extra}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"collector: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
