#!/usr/bin/env python3
"""Vigilant agent for Raspberry Pi counter thin clients.

The existing Vigilant agent is RouterOS-only (a .rsc driven by /system scheduler), so a
Pi needs its own. The wire contract is unchanged: POST JSON to /telemetry with the
device's bearer token. From Vigilant's side a Pi is just a device of kind 'counter-pi',
so it inherits history, alerting and tags with no special casing.

STDLIB ONLY — no pip install on a kiosk device that has to cold-boot unattended.
Optional external tools are used if present and skipped if not:
    snmpget/snmpwalk (net-snmp)  printer page counts + toner
    lpstat (cups-client)         local queue depth / failed jobs
    wg (wireguard-tools)         this Pi's own view of the tunnel
    vcgencmd (raspi firmware)    undervoltage / thermal throttling

Two hard-won details:

  * `serial` MUST equal the serial the device was enrolled with. It is the token
    cross-check key: if it differs, the ingest returns 409 and the device silently stops
    being monitored while looking fine from the Pi's end. It comes from the env file
    written at install time, never guessed.

  * The default interval is 60s, NOT the 1s the RouterOS agent uses. That cadence is what
    saturated the ingest and filled the history tables; a counter Pi does not change state
    fast enough to justify it.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONF = "/etc/vigilant/agent.env"


# ── config ──────────────────────────────────────────────────────────────────
def load_conf():
    """Read KEY=value from the env file, then let real env vars win (handy for testing)."""
    conf = {}
    try:
        with open(CONF) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    for k in ("VIGILANT_URL", "VIGILANT_TOKEN", "VIGILANT_SERIAL",
              "VIGILANT_PRINTERS", "VIGILANT_PRINTER_EVERY", "VIGILANT_INTERVAL"):
        if os.environ.get(k):
            conf[k] = os.environ[k]
    return conf


def run(cmd, timeout=8):
    """Best-effort shell-out. Returns stdout or '' — a missing tool must never crash a tick."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def have(binary):
    return shutil.which(binary) is not None


# ── system metrics ──────────────────────────────────────────────────────────
def read_first(path, default=None):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except Exception:
        return default


def cpu_load_pct():
    """1-minute load as a percentage of total capacity, so it means the same thing as the
    routers' cpu_load and can share an alert rule."""
    try:
        load1 = float(open("/proc/loadavg").read().split()[0])
        return int(round(100.0 * load1 / max(1, os.cpu_count() or 1)))
    except Exception:
        return None


def meminfo():
    try:
        vals = {}
        for line in open("/proc/meminfo"):
            k, _, rest = line.partition(":")
            vals[k] = int(rest.split()[0]) * 1024  # kB -> bytes
        total = vals.get("MemTotal")
        # MemAvailable is the honest "what a new process could get" figure; MemFree alone
        # looks alarmingly low on Linux because of page cache.
        return total, vals.get("MemAvailable", vals.get("MemFree"))
    except Exception:
        return None, None


def cpu_temp_c():
    raw = read_first("/sys/class/thermal/thermal_zone0/temp")
    try:
        return round(int(raw) / 1000.0, 1)
    except Exception:
        return None


def pi_serial():
    """Hardware serial from /proc/cpuinfo — reported for reference only; it is NOT used as
    the Vigilant serial, which must match what enrolment recorded."""
    txt = read_first("/proc/cpuinfo", "") or ""
    m = re.search(r"^Serial\s*:\s*([0-9a-fA-F]+)", txt, re.M)
    return m.group(1) if m else None


def pi_model():
    return (read_first("/proc/device-tree/model", "") or "").replace("\x00", "").strip() or None


def throttled():
    """Undervoltage and thermal throttling are THE classic Pi field faults — a failing PSU
    or a hot cabinet shows up here long before the symptoms look like a Pi problem.
    Bit 0 = undervoltage now, 16 = undervoltage has occurred, 2/18 = throttled."""
    if not have("vcgencmd"):
        return None
    out = run(["vcgencmd", "get_throttled"]).strip()
    m = re.search(r"throttled=0x([0-9a-fA-F]+)", out)
    if not m:
        return None
    bits = int(m.group(1), 16)
    return {
        "raw": hex(bits),
        "undervoltage_now": bool(bits & 0x1),
        "throttled_now": bool(bits & 0x4),
        "undervoltage_since_boot": bool(bits & 0x10000),
        "throttled_since_boot": bool(bits & 0x40000),
    }


def disk_free_bytes(path="/"):
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except Exception:
        return None


def rootfs_readonly():
    """An SD card that has flipped read-only still boots and still shows a desktop, but the
    counter is quietly broken. Cheap to detect, easy to miss."""
    try:
        for line in open("/proc/mounts"):
            parts = line.split()
            if len(parts) > 3 and parts[1] == "/":
                return "ro" in parts[3].split(",")
    except Exception:
        pass
    return None


def uptime_s():
    try:
        return int(float(open("/proc/uptime").read().split()[0]))
    except Exception:
        return None


def ntp_synced():
    out = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip()
    if out in ("yes", "no"):
        return out == "yes"
    return None


def interfaces():
    """Cumulative counters from /proc/net/dev. Vigilant derives bps from deltas server-side,
    exactly as it does for routers — so we must NOT compute rates here."""
    out = []
    try:
        for line in open("/proc/net/dev").read().splitlines()[2:]:
            name, _, rest = line.partition(":")
            name = name.strip()
            if not name or name == "lo":
                continue
            f = rest.split()
            if len(f) < 16:
                continue
            oper = read_first(f"/sys/class/net/{name}/operstate", "unknown")
            out.append({
                "name": name,
                "type": "ether",
                "running": oper == "up",
                "plugged": oper == "up",
                "disabled": False,
                "rx_byte": int(f[0]), "rx_packet": int(f[1]), "rx_error": int(f[2]), "rx_drop": int(f[3]),
                "tx_byte": int(f[8]), "tx_packet": int(f[9]), "tx_error": int(f[10]), "tx_drop": int(f[11]),
                "mac": read_first(f"/sys/class/net/{name}/address"),
            })
    except Exception:
        pass
    return out


def default_route():
    out = run(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else None


def wg_state():
    """This Pi's own view of its tunnel. The hub's view is collected separately — when the
    two disagree, that difference is itself the diagnosis."""
    if not have("wg"):
        return None
    out = run(["wg", "show", "all", "dump"])
    peers = []
    for line in out.strip().splitlines():
        f = line.split("\t")
        # An interface line has 5 fields; a peer line has 9.
        if len(f) >= 9:
            hs = int(f[5]) if f[5].isdigit() else 0
            peers.append({
                "endpoint": f[3] if f[3] != "(none)" else None,
                "allowed_ips": f[4],
                "latest_handshake": hs or None,
                "handshake_age_s": int(time.time()) - hs if hs else None,
                "rx_bytes": int(f[6]) if f[6].isdigit() else None,
                "tx_bytes": int(f[7]) if f[7].isdigit() else None,
            })
    return peers or None


def rdp_session():
    """The whole point of the counter: is the kiosk RDP session actually up? A Pi that is
    online, warm and tunnelled but has no session is still a counter that cannot dispense."""
    for proc in ("xfreerdp3", "xfreerdp", "rdesktop"):
        if run(["pgrep", "-x", proc]).strip():
            return {"running": True, "client": proc}
    return {"running": False, "client": None}


# ── printers ────────────────────────────────────────────────────────────────
# Standard Printer MIB (RFC 3805) + Host Resources. Only what maps to something a human
# acts on: pages printed, how much toner is left, and why it has stopped.
OID = {
    "descr": "1.3.6.1.2.1.25.3.2.1.3.1",       # hrDeviceDescr
    "pages": "1.3.6.1.2.1.43.10.2.1.4.1.1",    # prtMarkerLifeCount
    "serial": "1.3.6.1.2.1.43.5.1.1.17.1",     # prtGeneralSerialNumber
    "alerts": "1.3.6.1.2.1.43.18.1.1.8",       # prtAlertDescription (walk)
    "supply_desc": "1.3.6.1.2.1.43.11.1.1.6",  # prtMarkerSuppliesDescription (walk)
    "supply_max": "1.3.6.1.2.1.43.11.1.1.8",   # prtMarkerSuppliesMaxCapacity (walk)
    "supply_level": "1.3.6.1.2.1.43.11.1.1.9",  # prtMarkerSuppliesLevel (walk)
}


def snmp_get(host, community, oid):
    if not have("snmpget"):
        return None
    out = run(["snmpget", "-v2c", "-c", community, "-Ovq", "-t", "2", "-r", "1", host, oid], timeout=6)
    out = out.strip().strip('"')
    return out or None


def snmp_walk(host, community, oid):
    if not have("snmpwalk"):
        return []
    out = run(["snmpwalk", "-v2c", "-c", community, "-Ovq", "-t", "2", "-r", "1", host, oid], timeout=8)
    return [l.strip().strip('"') for l in out.splitlines() if l.strip()]


def poll_printer(spec, community="public"):
    """spec is 'name@host' or just 'host'. Returns a printer dict, or None if unreachable —
    an unreachable printer is reported as such rather than dropped, so it can be alerted on."""
    name, _, host = spec.partition("@")
    if not host:
        host, name = name, name
    p = {"name": name, "address": host, "discovered_via": "snmp"}

    descr = snmp_get(host, community, OID["descr"])
    if descr is None:
        p["status"] = "unreachable"
        return p

    p["model"] = descr
    p["make"] = descr.split()[0] if descr else None
    p["serial"] = snmp_get(host, community, OID["serial"])
    pages = snmp_get(host, community, OID["pages"])
    if pages and pages.isdigit():
        p["page_count"] = int(pages)

    descs = snmp_walk(host, community, OID["supply_desc"])
    maxes = snmp_walk(host, community, OID["supply_max"])
    levels = snmp_walk(host, community, OID["supply_level"])
    supplies = []
    for i, d in enumerate(descs):
        mx = maxes[i] if i < len(maxes) else None
        lv = levels[i] if i < len(levels) else None
        entry = {"name": d, "type": "toner" if "toner" in d.lower() else ("drum" if "drum" in d.lower() else "supply")}
        try:
            mxi, lvi = int(mx), int(lv)
            entry["max_capacity"] = mxi
            entry["level"] = lvi
            # Negative levels are the MIB's "unknown"/"some remaining" sentinels, not a
            # quantity — reporting them as a percentage would invent data.
            if mxi > 0 and lvi >= 0:
                entry["pct"] = round(100.0 * lvi / mxi, 1)
        except (TypeError, ValueError):
            pass
        supplies.append(entry)
    p["supplies"] = supplies

    alerts = [a for a in snmp_walk(host, community, OID["alerts"]) if a]
    if alerts:
        p["state_reasons"] = "; ".join(alerts[:4])
    p["status"] = "stopped" if alerts else "idle"
    return p


def cups_queues():
    """Queue depth and failures — CUPS knows these and SNMP does not."""
    if not have("lpstat"):
        return {}
    per = {}
    for line in run(["lpstat", "-p"]).splitlines():
        m = re.match(r"printer (\S+) (is idle|now printing|disabled)", line)
        if m:
            per.setdefault(m.group(1), {})["status"] = (
                "printing" if "printing" in m.group(2) else "stopped" if "disabled" in m.group(2) else "idle")
    for line in run(["lpstat", "-o"]).splitlines():
        m = re.match(r"(\S+?)-\d+", line)
        if m:
            q = per.setdefault(m.group(1), {})
            q["queue_depth"] = q.get("queue_depth", 0) + 1
    return per


def collect_printers(conf):
    """VIGILANT_PRINTERS is a comma list of 'name@host' (or bare host). Empty = skip
    entirely: polling nothing is correct at a site with no printers configured yet."""
    specs = [s.strip() for s in (conf.get("VIGILANT_PRINTERS") or "").split(",") if s.strip()]
    if not specs:
        return []
    queues = cups_queues()
    out = []
    for spec in specs:
        p = poll_printer(spec)
        if not p:
            continue
        q = queues.get(p["name"]) or {}
        # CUPS wins on queue state; SNMP wins on hardware state.
        p["queue_depth"] = q.get("queue_depth", 0)
        if q.get("status") and p.get("status") == "idle":
            p["status"] = q["status"]
        out.append(p)
    return out


# ── payload + post ──────────────────────────────────────────────────────────
def build_payload(conf):
    total, avail = meminfo()
    return {
        # The token cross-check key — must match enrolment exactly.
        "serial": conf["VIGILANT_SERIAL"],
        "identity": socket.gethostname(),
        "ts": int(time.time() * 1000),
        "uptime": uptime_s(),
        "cpu_load": cpu_load_pct(),
        "total_memory": total,
        "free_memory": avail,
        "free_hdd": disk_free_bytes("/"),
        "cpu_temperature": cpu_temp_c(),
        "ntp_synced": ntp_synced(),
        "default_route": default_route(),
        "interfaces": interfaces(),
        # Pi/counter specifics. Not device_state columns, so they land in `raw` and are
        # still queryable and visible on the device page.
        "agent_kind": "counter-pi",
        "agent_version": 1,
        "os_version": (read_first("/etc/os-release", "") or "").split("PRETTY_NAME=")[-1].split("\n")[0].strip('"') or None,
        "hw_model": pi_model(),
        "hw_serial": pi_serial(),
        "throttling": throttled(),
        "rootfs_readonly": rootfs_readonly(),
        "rdp": rdp_session(),
        "wireguard": wg_state(),
    }


def post(url, token, path, body, timeout=15):
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()[:400]


def tick(conf, do_printers):
    url, token = conf["VIGILANT_URL"], conf["VIGILANT_TOKEN"]
    status, body = post(url, token, "/telemetry", build_payload(conf))
    print(f"telemetry {status} {body}", flush=True)

    if do_printers:
        printers = collect_printers(conf)
        if printers:
            s, b = post(url, token, "/printers/report", {"printers": printers})
            print(f"printers {s} ({len(printers)} polled) {b}", flush=True)


def explain_failure(e):
    """Turn an exception into the sentence someone debugging at 8am actually needs.

    409 gets called out by name because it is the platform's nastiest failure mode: the
    device keeps running, the network is fine, and it simply stops being monitored. That
    exact mismatch hid a dead pharmacy router for eleven days.
    """
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 409:
            return ("HTTP 409 — VIGILANT_SERIAL does not match the device this token belongs to. "
                    f"Fix VIGILANT_SERIAL in {CONF} to the serial shown on the Install Desktop page.")
        if e.code == 401:
            return f"HTTP 401 — VIGILANT_TOKEN rejected. Re-enrol the counter to issue a new token."
        return f"HTTP {e.code} — {e.reason}"
    if isinstance(e, urllib.error.URLError):
        return f"cannot reach VIGILANT_URL ({e.reason}) — check the tunnel and DNS"
    return f"{type(e).__name__}: {e}"


def tick_guarded(conf, do_printers):
    """One tick, never raising. Returns True on success."""
    try:
        tick(conf, do_printers)
        return True
    except Exception as e:  # noqa: BLE001 — an unattended kiosk must not die on one bad tick
        print(f"vigilant-pi-agent: {explain_failure(e)}", file=sys.stderr, flush=True)
        return False


def main():
    conf = load_conf()
    missing = [k for k in ("VIGILANT_URL", "VIGILANT_TOKEN", "VIGILANT_SERIAL") if not conf.get(k)]
    if missing:
        # Fail loudly: a silently misconfigured agent looks identical to a dead device.
        print(f"vigilant-pi-agent: missing {', '.join(missing)} in {CONF}", file=sys.stderr)
        return 2

    interval = int(conf.get("VIGILANT_INTERVAL") or 60)
    # Printers are polled far less often: toner does not move fast, and hammering the SNMP
    # agent on older printers can wedge them.
    printer_every = int(conf.get("VIGILANT_PRINTER_EVERY") or 15)

    # --once is what a human runs to check an install, so it must report the diagnosis and
    # a usable exit code rather than dumping a traceback.
    if "--once" in sys.argv:
        return 0 if tick_guarded(conf, do_printers=True) else 1

    n = 0
    while True:
        tick_guarded(conf, do_printers=(n % printer_every == 0))
        n += 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
