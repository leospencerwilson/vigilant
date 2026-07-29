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
    """Has the SD card flipped read-only? A worn card that ext4 has remounted `ro` still
    boots and still shows a desktop, while the counter is quietly broken.

    Two traps here, both hit in testing:

      * systemd's ProtectSystem=strict mounts / read-only INSIDE the unit's namespace, so
        this reported a fault on a perfectly healthy Pi. The unit therefore uses
        ProtectSystem=full, which still protects /usr and /boot but leaves / as it really
        is. If this ever starts firing everywhere, suspect the sandbox before the hardware.
      * /proc/mounts can carry more than one entry for /, the earlier one being a
        boot-time read-only mount. The LAST entry is the effective one.
    """
    effective = None
    try:
        for line in open("/proc/mounts"):
            parts = line.split()
            if len(parts) > 3 and parts[1] == "/":
                effective = "ro" in parts[3].split(",")
    except Exception:
        return None
    return effective


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


def primary_ip():
    """The Pi's real address on the site LAN — the one an engineer would actually connect
    to. Taken from the interface carrying the default route, so it follows the Pi between
    ethernet and wifi instead of being pinned to whichever came up first."""
    out = run(["ip", "-4", "route", "show", "default"])
    dev = re.search(r"\sdev\s+(\S+)", out)
    if not dev:
        return None
    addr = run(["ip", "-4", "-o", "addr", "show", "dev", dev.group(1)])
    m = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", addr)
    return m.group(1) if m else None


def loadavg():
    """All three windows. One number can't distinguish a passing spike from a Pi that has
    been struggling for a quarter of an hour."""
    try:
        a, b, c = open("/proc/loadavg").read().split()[:3]
        return {"1m": float(a), "5m": float(b), "15m": float(c)}
    except Exception:
        return None


def storage():
    """Total as well as free. 200 MB free means nothing without knowing whether the card is
    8 GB or 64 GB, and a filling SD card is the usual precursor to a kiosk failing oddly."""
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - (st.f_bfree * st.f_frsize)
        return {
            "total_bytes": total, "free_bytes": free,
            "used_pct": round(100.0 * used / total, 1) if total else None,
        }
    except Exception:
        return None


def swap():
    try:
        vals = {}
        for line in open("/proc/meminfo"):
            k, _, rest = line.partition(":")
            if k in ("SwapTotal", "SwapFree"):
                vals[k] = int(rest.split()[0]) * 1024
        if not vals.get("SwapTotal"):
            return None
        return {"total_bytes": vals["SwapTotal"], "free_bytes": vals.get("SwapFree")}
    except Exception:
        return None


def power():
    """Core voltage and ARM clock alongside the throttle flags. A sagging supply shows up
    here first; by the time undervoltage latches, the counter has probably already glitched."""
    if not have("vcgencmd"):
        return None
    out = {}
    v = re.search(r"volt=([0-9.]+)V", run(["vcgencmd", "measure_volts", "core"]))
    if v:
        out["core_volts"] = float(v.group(1))
    c = re.search(r"frequency\(\d+\)=(\d+)", run(["vcgencmd", "measure_clock", "arm"]))
    if c:
        out["arm_mhz"] = round(int(c.group(1)) / 1_000_000)
    return out or None


def failed_units():
    """Anything systemd has given up on. A kiosk can look alive while the thing that matters
    — the launcher, cups, the tunnel — sits in `failed` and nobody notices."""
    out = run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    names = [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("0 loaded")]
    return {"count": len(names), "units": names[:8]}


def display():
    """Is a screen actually connected? A counter Pi with a dead HDMI link is unusable, and
    nothing else we collect would reveal it."""
    try:
        connectors = []
        base = "/sys/class/drm"
        for entry in sorted(os.listdir(base)):
            status = read_first(f"{base}/{entry}/status")
            if status:
                connectors.append({"name": entry.replace("card0-", ""), "status": status})
        if not connectors:
            return None
        return {
            "connected": any(c["status"] == "connected" for c in connectors),
            "connectors": connectors[:6],
        }
    except Exception:
        return None


def wifi():
    """Signal strength when the Pi is on wifi. A counter that keeps dropping its RDP session
    is usually a weak-signal problem, and the number makes that arguable instead of guessed."""
    if not have("iw"):
        return None
    for dev in sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []:
        if not dev.startswith(("wlan", "wl")):
            continue
        link = run(["iw", "dev", dev, "link"])
        if "Not connected" in link:
            return {"device": dev, "connected": False}
        ssid = re.search(r"SSID:\s*(.+)", link)
        sig = re.search(r"signal:\s*(-?\d+)", link)
        rate = re.search(r"tx bitrate:\s*([0-9.]+)", link)
        return {
            "device": dev, "connected": True,
            "ssid": ssid.group(1).strip() if ssid else None,
            "signal_dbm": int(sig.group(1)) if sig else None,
            "tx_mbps": float(rate.group(1)) if rate else None,
        }
    return None


def storage_errors():
    """I/O errors in the kernel ring buffer. This is the LEADING indicator of SD wear — the
    card throws errors for a while before ext4 gives up and remounts read-only, so catching
    it here is the difference between a planned swap and a dead counter."""
    out = run(["dmesg", "--level=err,warn", "--notime"], timeout=6)
    if not out:
        return None
    hits = [l.strip() for l in out.splitlines()
            if re.search(r"mmcblk|I/O error|EXT4-fs error|remounting filesystem read-only", l, re.I)]
    return {"count": len(hits), "recent": hits[-3:]} if hits else {"count": 0, "recent": []}


def cups_jobs():
    """Completed and failed counts, so a printer that accepts jobs and silently bins them
    is visible. Queue depth alone looks healthy in exactly that case."""
    if not have("lpstat"):
        return None
    done = run(["lpstat", "-W", "completed", "-o"], timeout=8)
    return {
        "completed": len([l for l in done.splitlines() if l.strip()]),
        "queued": len([l for l in run(["lpstat", "-o"]).splitlines() if l.strip()]),
    }


def peripherals(rdp_argv=""):
    """What is actually plugged into this counter.

    Reported so the peripheral picture stops being a hand-maintained guess. Kept SEPARATE
    from the operator-set `peripherals` field on the counter: detection can only prove
    presence, never that a device WORKS end to end. NHS smartcard over the tunnel is the
    platform's open go/no-go, and "a reader is plugged in" is not the same as "it
    authenticates against Spine" — so both facts are carried, neither overwrites the other.
    """
    out = {}
    lsusb = run(["lsusb"]) if have("lsusb") else ""

    # Smartcard: readers advertise USB class CCID, and the common NHS-approved vendors are
    # recognisable by name when the class string is absent.
    reader = bool(re.search(r"CCID|smart\s*card|Gemalto|Identiv|SCM Micro|OMNIKEY|HID Global|ACS\b|Cherry", lsusb, re.I))
    out["smartcard_reader"] = "present" if reader else ("absent" if lsusb else "unknown")
    pcscd = run(["systemctl", "is-active", "pcscd"]).strip()
    out["smartcard_daemon"] = pcscd or "unknown"
    # Whether the kiosk is configured to pass it through at all.
    out["smartcard_redirected"] = "/smartcard" in rdp_argv

    # Printers: CUPS is the source of truth for what this Pi can print to.
    queues = cups_devices()
    out["printer_queues"] = len(queues)
    out["printer_names"] = sorted(queues.keys())[:6]
    out["printer_redirected"] = "/printer" in rdp_argv

    # Scanners: SANE if installed, otherwise fall back to the USB class.
    if have("scanimage"):
        sc = run(["scanimage", "-L"], timeout=10)
        out["scanner_detected"] = 0 if "No scanners" in sc else len(re.findall(r"^device", sc, re.M))
    else:
        out["scanner_detected"] = 1 if re.search(r"scanner", lsusb, re.I) else 0

    return out


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
    """The whole point of the counter: is the kiosk RDP session actually up, and pointed at
    the right server? A Pi that is online, warm and tunnelled but has no session is still a
    counter that cannot dispense — and one pointed at another pharmacy's PMR server is worse.

    We extract ONLY the /v: target. The FreeRDP command line also carries /u: and /p:, so
    the whole argv is deliberately never captured or sent — telemetry must not become a
    place credentials leak to.
    """
    for proc in ("xfreerdp3", "xfreerdp", "rdesktop"):
        pids = run(["pgrep", "-x", proc]).split()
        if not pids:
            continue
        target = None
        last_argv = ""
        for pid in pids:
            argv = (read_first(f"/proc/{pid}/cmdline", "") or "").replace("\x00", " ")
            last_argv = argv
            m = re.search(r"/v:(\S+)", argv) or re.search(r"\s(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\s", argv)
            if m:
                target = m.group(1)
                break
        # `flags` carries ONLY the redirection switches we care about, never the full argv
        # (which contains /u: and /p:).
        flags = " ".join(f for f in ("/smartcard", "/printer", "/drive", "/clipboard")
                         if f in last_argv)
        return {"running": True, "client": proc, "target": target, "redirect": flags or None}
    return {"running": False, "client": None, "target": None, "redirect": None}


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
    "supply_type": "1.3.6.1.2.1.43.11.1.1.5",   # prtMarkerSuppliesType (walk)
    # These two are the AUTHORITY on whether a printer is actually usable.
    "hr_status": "1.3.6.1.2.1.25.3.5.1.1.1",   # hrPrinterStatus
    "hr_errors": "1.3.6.1.2.1.25.3.5.1.2.1",   # hrPrinterDetectedErrorState (BITS)
}

# prtMarkerSuppliesType. Knowing toner from drum from waste box matters: a drum at 20% is a
# planned consumable order, a toner at 20% is a call today.
SUPPLY_TYPE = {
    1: "other", 2: "unknown", 3: "toner", 4: "waste_toner", 5: "ink", 6: "ink_cartridge",
    9: "drum", 10: "developer", 11: "fuser_oil", 12: "solid_wax", 13: "ribbon",
    15: "fuser", 16: "corona_wire", 18: "transfer_unit", 20: "waste_ink", 21: "cleaner",
}

# hrPrinterStatus enumeration.
HR_STATUS = {1: "unknown", 2: "unknown", 3: "idle", 4: "printing", 5: "idle"}

# hrPrinterDetectedErrorState is a BITS field: bit 0 is the MOST significant bit of the
# first octet. Order is fixed by the Host Resources MIB.
ERROR_BITS = [
    "lowPaper", "noPaper", "lowToner", "noToner", "doorOpen", "jammed", "offline",
    "serviceRequested", "inputTrayMissing", "outputTrayMissing", "markerSupplyMissing",
    "outputNearFull", "outputFull", "inputTrayEmpty", "overduePreventMaint",
]
# Conditions that actually stop printing, as opposed to ones worth mentioning. Getting this
# split wrong is how a monitoring tool teaches people to ignore it.
BLOCKING = {"noPaper", "noToner", "doorOpen", "jammed", "offline", "serviceRequested",
            "inputTrayMissing", "outputFull", "inputTrayEmpty"}

# Alert descriptions that are normal operating states, not faults. A printer asleep is a
# printer working correctly; treating "Sleep" as a fault marks most of an estate broken.
BENIGN_ALERTS = {"sleep", "ready", "power saver", "sleeping", "energy save", "idle", "online"}


def decode_error_bits(octet_string):
    """'00 ' / '0C 40' -> ['lowToner', …]. Absent or unparseable yields [] rather than a
    guess, because inventing a fault is worse than reporting none."""
    if not octet_string:
        return []
    hex_bytes = [b for b in octet_string.replace('"', "").split() if b]
    flags = []
    for byte_i, hb in enumerate(hex_bytes):
        try:
            val = int(hb, 16)
        except ValueError:
            continue
        for bit in range(8):
            if val & (0x80 >> bit):
                idx = byte_i * 8 + bit
                if idx < len(ERROR_BITS):
                    flags.append(ERROR_BITS[idx])
    return flags


def snmp_get(host, community, oid):
    if not have("snmpget"):
        return None
    out = run(["snmpget", "-v2c", "-c", community, "-Ovq", "-t", "2", "-r", "1", host, oid], timeout=6)
    out = out.strip().strip('"')
    return out or None


def snmp_walk(host, community, oid):
    """Walk an OID, PRESERVING POSITION.

    Blank entries must be kept: the supplies tables are parallel arrays joined by index, and
    a printer that returns an empty description for one cartridge (Brother does, for Black)
    would otherwise shift every later description onto the wrong level — labelling the drum's
    percentage as a toner's.
    """
    if not have("snmpwalk"):
        return []
    out = run(["snmpwalk", "-v2c", "-c", community, "-Ovq", "-t", "2", "-r", "1", host, oid], timeout=8)
    lines = out.splitlines()
    # Trim only the trailing blank line the command leaves behind, never interior ones.
    while lines and not lines[-1].strip():
        lines.pop()
    return [l.strip().strip('"') for l in lines]


def cups_devices():
    """Discover printers from CUPS rather than making someone list them.

    `lpstat -v` prints 'device for <queue>: <uri>', and the URI carries the address —
    ipp://192.168.88.221/ipp/print, socket://10.0.0.5:9100 and so on. The queue name is
    also what the operator sees in Watchman, so discovering here keeps the two in step.
    """
    found = {}
    for line in run(["lpstat", "-v"]).splitlines():
        m = re.match(r"device for (\S+?):\s*(\S+)", line.strip())
        if not m:
            continue
        queue, uri = m.group(1), m.group(2)
        host = re.match(r"^[a-z]+://([^/:@]+)", uri)
        if host:
            found[queue] = host.group(1)
    return found


def poll_printer(spec, community="public"):
    """spec is 'name@host' or just 'host'.

    An unreachable printer is REPORTED as unreachable rather than dropped, so it can be
    seen and alerted on. But "SNMP tooling isn't installed" is not the same as "the printer
    is down", and conflating them would put a false fault on every site without net-snmp.
    """
    name, _, host = spec.partition("@")
    if not host:
        host, name = name, name
    p = {"name": name, "address": host}

    if not have("snmpget"):
        # No SNMP available: whatever CUPS knows is all we can honestly claim.
        p["discovered_via"] = "cups"
        return p

    p["discovered_via"] = "snmp"
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

    # Parallel arrays joined by index: description, level, max capacity, type.
    descs = snmp_walk(host, community, OID["supply_desc"])
    levels = snmp_walk(host, community, OID["supply_level"])
    maxes = snmp_walk(host, community, OID["supply_max"])
    types = snmp_walk(host, community, OID["supply_type"])

    def num(seq, i):
        try:
            return int(seq[i])
        except (IndexError, TypeError, ValueError):
            return None

    supplies = []
    # Drive off the LEVEL table: it is the one the printer always populates fully, whereas a
    # description can be blank (Brother leaves Black's empty).
    for i in range(len(levels)):
        lvl, mx = num(levels, i), num(maxes, i)
        name = (descs[i] if i < len(descs) else "") or f"{SUPPLY_TYPE.get(num(types, i), 'supply')} {i + 1}"
        entry = {
            "name": name,
            "type": SUPPLY_TYPE.get(num(types, i), "supply"),
            "level": lvl,
            "max_capacity": mx,
        }
        # RFC 3805 sentinels are ANSWERS, not missing data, and each means something
        # different. Brother reports every toner as -3 with capacity -2: the printer is
        # telling us there is toner left but refusing to quantify it. Rendering that as
        # "unknown" reads as a broken sensor, so it gets its own state.
        if lvl == -3:
            entry["state"] = "some_remaining"
        elif lvl in (-1, -2) or lvl is None or mx is None or mx <= 0:
            entry["state"] = "unknown"
        elif lvl >= 0:
            entry["pct"] = round(100.0 * lvl / mx, 1)
            entry["state"] = "measured"
        supplies.append(entry)
    p["supplies"] = supplies

    # Status comes from hrPrinterStatus + hrPrinterDetectedErrorState, NOT from the alert
    # table. prtAlertDescription carries normal states like "Sleep" as entries, so treating
    # any alert as a fault reported a healthy sleeping printer as stopped — a false fault on
    # essentially every printer with power saving on.
    errors = decode_error_bits(snmp_get(host, community, OID["hr_errors"]))
    hr = snmp_get(host, community, OID["hr_status"])
    try:
        hr_status = HR_STATUS.get(int(hr), "unknown") if hr else None
    except ValueError:
        hr_status = None

    blocking = [e for e in errors if e in BLOCKING]
    if blocking:
        p["status"] = "stopped"
    elif hr_status:
        p["status"] = hr_status
    else:
        p["status"] = "idle"

    # Reasons are for a human reading the row: real error bits first, then any alert text
    # that isn't just a normal operating state.
    alerts = [a for a in snmp_walk(host, community, OID["alerts"])
              if a and a.strip().lower() not in BENIGN_ALERTS]
    reasons = errors + alerts
    if reasons:
        p["state_reasons"] = "; ".join(reasons[:4])
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
    """Which printers to poll.

    VIGILANT_PRINTERS ('name@host,…') is an explicit override for printers CUPS does not
    know about. Left empty — the normal case — we discover from CUPS, so a counter that
    already prints is monitored with no extra configuration and the queue names match what
    the operator sees. Nothing configured and nothing in CUPS means nothing to report,
    which is the right answer for a site with no printer yet.
    """
    specs = [s.strip() for s in (conf.get("VIGILANT_PRINTERS") or "").split(",") if s.strip()]
    if not specs:
        specs = [f"{q}@{h}" for q, h in cups_devices().items()]
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
    rdp = rdp_session()
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
        "primary_ip": primary_ip(),
        "wireguard": wg_state(),
        "rdp": rdp,
        # Detected, not asserted: proves presence, never that a peripheral works end to end.
        "peripherals": peripherals(rdp.get("redirect") or ""),
        # Counter-Pi specifics a router agent would have no reason to gather.
        "load": loadavg(),
        "storage": storage(),
        "swap": swap(),
        "power": power(),
        "failed_units": failed_units(),
        "display": display(),
        # NOT "wifi": that name is reserved by the contract for an array of WiFi
        # networks (SSID/channel). Sending an object under it fails schema validation
        # and the whole telemetry POST is rejected with a 400.
        "wifi_link": wifi(),
        "storage_errors": storage_errors(),
        "cups_jobs": cups_jobs(),
        "kernel": (run(["uname", "-r"]) or "").strip() or None,
    }


AGENT_UA = "vigilant-pi-agent/1"


def post(url, token, path, body, timeout=15):
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            # MUST be set. Vigilant is published through a Cloudflare tunnel, and
            # Cloudflare bans Python's default "Python-urllib/x.y" signature outright:
            # every request comes back 403 with "error code: 1010", including endpoints
            # that return 200 to curl. Nothing about the response mentions the User-Agent,
            # so this presents as an unexplained permissions failure.
            "User-Agent": AGENT_UA,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()[:400]


def tick(conf, do_printers):
    """One report. Returns the interval the SERVER asked for, if it gave one."""
    url, token = conf["VIGILANT_URL"], conf["VIGILANT_TOKEN"]
    status, body = post(url, token, "/telemetry", build_payload(conf))
    print(f"telemetry {status} {body}", flush=True)

    if do_printers:
        printers = collect_printers(conf)
        if printers:
            s, b = post(url, token, "/printers/report", {"printers": printers})
            print(f"printers {s} ({len(printers)} polled) {b}", flush=True)

    # The server dictates cadence via poll_interval_s, and we MUST honour it: staleness is
    # judged centrally (STALE_AFTER_S), so an agent reporting slower than the server expects
    # flaps between online and stale forever while being perfectly healthy. Letting the
    # server drive also means the interval can be retuned fleet-wide without touching a Pi.
    try:
        want = json.loads(body).get("poll_interval_s")
        # Floor at 10s so a server-side misconfiguration cannot turn the fleet into a
        # thundering herd, which is precisely how the router fleet saturated the ingest.
        if isinstance(want, (int, float)) and want >= 10:
            return int(want)
    except Exception:
        pass
    return None


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
        if e.code == 403:
            # Cloudflare sits in front of Vigilant and returns 1010 for a banned client
            # signature. It looks like an auth problem but the request never reached us.
            return ("HTTP 403 — blocked before reaching Vigilant (likely Cloudflare, "
                    "'error code: 1010' = banned client signature). Check the User-Agent.")
        return f"HTTP {e.code} — {e.reason}"
    if isinstance(e, urllib.error.URLError):
        return f"cannot reach VIGILANT_URL ({e.reason}) — check the tunnel and DNS"
    return f"{type(e).__name__}: {e}"


def tick_guarded(conf, do_printers):
    """One tick, never raising. Returns the server's requested interval, or False on error."""
    try:
        return tick(conf, do_printers) or True
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
        got = tick_guarded(conf, do_printers=(n % printer_every == 0))
        # `not isinstance(got, bool)` is essential: bool subclasses int, so a False return
        # from a failed tick would otherwise be accepted as an interval, giving sleep(0) and
        # a hot retry loop against the ingest.
        if isinstance(got, int) and not isinstance(got, bool) and got != interval:
            print(f"vigilant-pi-agent: interval {interval}s -> {got}s (server-directed)", flush=True)
            interval = got
        n += 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
