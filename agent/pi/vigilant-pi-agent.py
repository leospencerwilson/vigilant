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

import base64
import calendar
import glob
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CONF = "/etc/vigilant/agent.env"
# Runtime-writable copy of the config. The unit runs ProtectSystem=full, which mounts /etc
# READ-ONLY inside its namespace, so the agent cannot persist anything to CONF itself — the
# installer writes that as root at install time. Self-enrolment DOES have to persist (the
# per-device token it is issued), so it writes here instead; /var/lib is writable under
# ProtectSystem=full, which is why the boot target already lives there.
#
# Without this, a zero-touch Pi failed to save its token, the exception restarted the unit,
# and it re-enrolled roughly every 10 seconds — minting a fresh token each time and never
# sending one telemetry POST.
STATE_CONF = "/var/lib/wcn/agent.env"


# ── config ──────────────────────────────────────────────────────────────────
def load_conf():
    """Read KEY=value from the env file, then let real env vars win (handy for testing)."""
    conf = {}
    # CONF first, then STATE_CONF: a token persisted at runtime must override a stale one
    # baked into the image.
    for path in (CONF, STATE_CONF):
      try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip().strip('"').strip("'")
      except FileNotFoundError:
        pass
    for k in ("VIGILANT_URL", "VIGILANT_TOKEN", "VIGILANT_SERIAL",
              "VIGILANT_PRINTERS", "VIGILANT_PRINTER_EVERY", "VIGILANT_INTERVAL",
              "VIGILANT_DISCOVER_EVERY", "VIGILANT_BOOTSTRAP_TOKEN", "VIGILANT_AUTO_UPDATE",
              "VIGILANT_RELAY"):
        if os.environ.get(k):
            conf[k] = os.environ[k]
    return conf


# Keys persisted to the env file after self-enrol. The bootstrap token is kept so a device
# that loses its per-device token (re-image, wiped file) can register itself again.
_ENV_KEYS = ("VIGILANT_URL", "VIGILANT_TOKEN", "VIGILANT_SERIAL", "VIGILANT_BOOTSTRAP_TOKEN",
             "VIGILANT_PRINTERS", "VIGILANT_PRINTER_EVERY", "VIGILANT_INTERVAL",
             "VIGILANT_DISCOVER_EVERY", "VIGILANT_AUTO_UPDATE", "VIGILANT_RELAY")


def write_agent_env(conf):
    """Persist config to the env file, root-only (it holds a bearer token). Atomic replace so
    a crash mid-write can't leave a half-file that bricks the next boot."""
    os.makedirs(os.path.dirname(STATE_CONF), exist_ok=True)
    lines = [f"{k}={conf[k]}" for k in _ENV_KEYS if conf.get(k)]
    tmp = STATE_CONF + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_CONF)


def self_enrol(conf):
    """Zero-touch first boot: no per-device token yet, so register with the SHARED bootstrap
    token baked into the base image and persist the per-device token we are issued. The Pi's
    hardware serial is the identity — the same value used on every subsequent telemetry POST,
    so the token cross-check lines up. The device lands UNCLAIMED until an operator adopts it.
    """
    url = conf.get("VIGILANT_URL")
    bootstrap = conf.get("VIGILANT_BOOTSTRAP_TOKEN")
    serial = conf.get("VIGILANT_SERIAL") or pi_serial()
    if not (url and bootstrap and serial):
        return False
    body = {"serial": serial, "model": pi_model(), "identity": socket.gethostname()}
    try:
        status, resp = post(url, bootstrap, "/enrol/self", body, timeout=20)
    except Exception as e:
        print(f"vigilant-pi-agent: self-enrol failed: {explain_failure(e)}", file=sys.stderr, flush=True)
        return False
    try:
        data = json.loads(resp)
    except Exception:
        data = {}
    token = data.get("token")
    if status not in (200, 201) or not token:
        print(f"vigilant-pi-agent: self-enrol rejected ({status}) {resp[:160]}", file=sys.stderr, flush=True)
        return False
    conf["VIGILANT_TOKEN"] = token
    conf["VIGILANT_SERIAL"] = data.get("serial") or serial
    write_agent_env(conf)
    print(f"vigilant-pi-agent: self-enrolled as {conf['VIGILANT_SERIAL']} (unclaimed — adopt it in Watchman)", flush=True)
    return True


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
    — the launcher, cups, the tunnel — sits in `failed` and nobody notices.

    EXCEPT the support screen-sharing unit when no session is wanted. That unit is on-demand:
    it is started for a support session and stopped when the session ends, and x11vnc exits
    non-zero on SIGTERM, so systemd leaves it `failed` after every NORMAL use. Reporting that
    put a permanent "1 unit failed" on counters where nothing was wrong — which is exactly how
    a fault list stops being read.

    It is only suppressed when nothing is asking for a session. If Watchman HAS asked for one
    (support_vnc_min > 0) and the unit is failed, then it genuinely did not come up, and that is
    a real fault: an engineer is sitting waiting for a screen that will never arrive.
    """
    out = run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    names = [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("0 loaded")]
    if not RUNTIME.get("support_vnc_min"):
        names = [n for n in names if n.split(".")[0] != SUPPORT_VNC_UNIT]
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


# Vendors whose USB devices are smartcard readers. Needed because a reader that exposes NO
# CCID interface cannot be recognised by class, and name matching alone misses unbranded
# units. Deliberately narrow: Alcor Micro and friends also make SD-card readers, and calling
# one of those a smartcard reader is worse than not spotting it.
READER_VENDORS = {
    "076b": "HID Global / OMNIKEY",
    "04e6": "SCM Microsystems",
    "072f": "ACS",
    "08e6": "Gemalto",
    "0c4b": "Reiner SCT",
}
READER_NAME_RE = re.compile(r"smart\s*card|CCID|OMNIKEY|card\s*reader", re.I)


def _usb_dev_info(dev):
    """manufacturer/product/VID:PID for a USB device directory, as one display name."""
    parts = []
    for part in ("manufacturer", "product"):
        try:
            with open(os.path.join(dev, part)) as fh:
                parts.append(fh.read().strip())
        except Exception:
            parts.append("")
    vendor, product = parts[0], parts[1]
    vid = read_first(os.path.join(dev, "idVendor"), "") or ""
    pid = read_first(os.path.join(dev, "idProduct"), "") or ""
    # Vendors routinely repeat themselves in the product string ("Dell" + "Dell Smart
    # Card Reader Keyboard"), which reads as a typo in the UI.
    if product and vendor and product.lower().startswith(vendor.lower()):
        name = product
    else:
        name = " ".join(p for p in (vendor, product) if p)
    return {"name": name[:120] or None, "usb_id": f"{vid}:{pid}" if vid and pid else None}


def sysfs_card_reader():
    """Find USB smartcard readers by interface class rather than by product name.

    Returns (present, readers, undriven).
      present  — None when sysfs cannot be read at all, so the caller can fall back to lsusb
                 instead of reporting a confident "absent".
      readers  — interfaces with class 0x0b (Chip/SmartCard). These are the ones pcscd can
                 actually drive, through libccid.
      undriven — devices that ARE smartcard readers but expose no class-0b interface, so no
                 CCID driver will claim them and pcscd will never list them.

    That third list exists because of a fault that cost a day on the pilot. An OMNIKEY 5320
    (076b:5320) was plugged in and plainly visible in lsusb, but its ONLY interface is class
    ff (vendor-specific) rather than 0b, so libccid ignored it and pcsc_scan listed just the
    Dell keyboard's reader. On site that presents as "the reader is plugged in and does
    nothing" — indistinguishable from a dead reader or a broken RDP redirection, when it is
    in fact neither: the device needs HID's proprietary driver. Reporting it as
    present-but-undriven turns a day of guessing into a glance at telemetry.

    A combined device like the Dell SK-3205 exposes class 03 (HID) and 0b on separate
    interfaces, so the INTERFACE, not the device, is what has to be inspected. CCID readers
    usually have NO kernel driver bound, because pcscd drives them through libusb; absence of
    a driver is not a fault here.
    """
    try:
        ifaces = glob.glob("/sys/bus/usb/devices/*/bInterfaceClass")
    except Exception:
        return None, None, None
    if not ifaces:
        return None, None, None

    # Group interface classes by the DEVICE that owns them. A device qualifies as CCID on the
    # strength of any ONE of its interfaces, and must not then also be listed as undriven —
    # which is exactly what a naive per-interface scan does to the Dell keyboard.
    devs = {}
    for path in sorted(ifaces):
        try:
            with open(path) as fh:
                cls = fh.read().strip().lower()
        except Exception:
            continue
        # …:1.1 is an interface; its parent directory is the device holding the name files.
        dev = os.path.dirname(path).rsplit(":", 1)[0]
        devs.setdefault(dev, []).append((cls, os.path.basename(os.path.dirname(path))))

    readers, undriven = [], []
    for dev, entries in sorted(devs.items()):
        info = _usb_dev_info(dev)
        ccid = [iface for cls, iface in entries if cls == "0b"]
        if ccid:
            # ALL of them, not the first. The estate has both the Dell keyboard's built-in CCID
            # reader and standalone OMNIKEY units; NHS only supports specific HID Global models
            # by VID:PID (Omnikey 3121 = 076b:3031 / 076b:3021, 5321CR = 076b:5320). Reporting
            # one reader made it impossible to answer "is the supported reader actually plugged
            # into this thin client?" from telemetry, which cost a round of asking for lsusb.
            for iface in ccid:
                readers.append({"name": info["name"], "usb_id": info["usb_id"], "iface": iface})
            continue
        vid = (info["usb_id"] or ":").split(":")[0]
        if READER_NAME_RE.search(info["name"] or "") or vid in READER_VENDORS:
            undriven.append({
                "name": info["name"],
                "usb_id": info["usb_id"],
                "iface": entries[0][1] if entries else None,
                "usb_class": sorted({cls for cls, _ in entries}),
                "reason": "no CCID interface (class 0b) — needs a vendor driver; pcscd will not list it",
            })
    return (True if readers else False), readers, undriven


# ── USB printers, independently of CUPS ─────────────────────────────────────
# Every other printer check on this device starts from CUPS, so a printer with NO QUEUE is
# invisible to all of them. That is not hypothetical: a Zebra ZD421 sat plugged into a live
# counter and unusable from go-live, and nothing we reported could tell "this counter has no
# label printer" from "it has one and nobody ever made a queue for it". Walking sysfs answers
# the first half of that on its own, and cross-referencing CUPS answers the second.
#
# USB printer interfaces are bInterfaceClass 07. The protocol byte then says how the host may
# talk to it — reported because a unidirectional interface can never report "out of paper",
# which explains a printer that looks permanently healthy and is not.
PRINTER_IFACE_CLASS = "07"
PRINTER_IFACE_PROTOCOL = {
    "01": "unidirectional",
    "02": "bidirectional",
    "03": "ieee-1284.4",
}

# ⚠ manufacturer, product and serial are USB DESCRIPTOR strings. They are chosen by whoever
# built the device, not by us, and a hostile or simply faulty one can put ANYTHING in them —
# including a newline, which in a line-oriented report forges an extra record, or an escape
# sequence, which rewrites a support engineer's terminal. So every one of them is validated
# before it is reported: printable ASCII (0x20..0x7e — no newline, no tab, no control byte, no
# non-ASCII) and a hard 64-character cap. A field that fails is reported as null and the
# refusal is logged, rather than being sanitised into something that looks trustworthy.
# NOTHING here is ever passed to a shell; these values only ever become JSON.
USB_STR_MAX = 64
# The cap is written into the pattern rather than interpolated, so the pattern reads as what
# it is. Keep the two in step.
USB_STR_RE = re.compile(r"^[\x20-\x7e]{1,64}$")
# The kernel formats these itself as "%04x", so this can be exact rather than forgiving.
USB_ID_RE = re.compile(r"^[0-9a-f]{4}$")


def _usb_attr(dev, name):
    """Raw text of one sysfs attribute of a USB device. None when absent or empty.

    Read as BYTES and decoded with errors="replace" on purpose. A descriptor holding
    non-ASCII is a value that really is there and really is unreportable, and decoding it
    strictly would raise and make it indistinguishable from a missing file. The replacement
    character does not match USB_STR_RE, so such a device is refused-and-logged by the one
    place that does the logging instead of vanishing silently.

    The read is capped: a sysfs attribute is at most one page, and this is the one file in
    this function that a device has any influence over.
    """
    try:
        with open(os.path.join(dev, name), "rb") as fh:
            raw = fh.read(4096)
    except Exception:
        return None
    return raw.decode("ascii", "replace").strip() or None


def _usb_str(dev, name):
    """A descriptor string, or None if it is not safe to report. Logs every refusal.

    The refusal is logged with repr(), which escapes exactly the bytes that made the value
    unsafe — so a device that tries to forge a log line has its attempt printed as \\n rather
    than performed. Truncated to 80 characters for the same reason the value is refused.
    """
    value = _usb_attr(dev, name)
    if value is None:
        return None                     # genuinely absent; most devices carry no serial
    if USB_STR_RE.match(value):
        return value
    print(f"vigilant-pi-agent: refusing USB {name} of {os.path.basename(dev)}: {value[:80]!r} "
          f"(not printable ASCII within {USB_STR_MAX} chars)", flush=True)
    return None


def _usb_id(dev, name):
    """idVendor/idProduct as exactly four lowercase hex characters, or None."""
    value = (_usb_attr(dev, name) or "").lower()
    return value if USB_ID_RE.match(value) else None


def cups_scheduler_up():
    """True when cupsd answered, False when it is down, None when lpstat is not installed.

    Needed because "lpstat -v printed nothing" is AMBIGUOUS, and the two meanings pull in
    opposite directions: it is either a counter with no queues at all — the finding this whole
    section exists to report — or a counter whose cupsd is not running, where claiming every
    attached printer has no queue would raise a false alarm on every printer at the site at
    once. `lpstat -r` separates them, and it is only worth a shell-out in that ambiguous case.
    """
    if not have("lpstat"):
        return None
    out = run(["lpstat", "-r"], timeout=8)
    if not out.strip():
        return False
    return "not running" not in out.lower()


def _usb_uri_fields(uri):
    """(manufacturer, product, serial) from a CUPS usb:// device URI, or None if it is not one.

    All three come back percent-decoded and lower-cased, because CUPS writes
    "Zebra%20Technologies" where the sysfs descriptor says "Zebra Technologies".

    RESTRICTED TO usb:// ON PURPOSE. A counter's queue list also holds ipp:// client queues
    pointing at another counter's shared printer; those URIs describe a REMOTE device and must
    never be able to absorb a printer plugged into THIS Pi.
    """
    try:
        parts = urllib.parse.urlsplit(uri)
    except Exception:
        return None
    if parts.scheme.lower() != "usb":
        return None
    maker = urllib.parse.unquote(parts.netloc).strip().lower()
    product = urllib.parse.unquote(parts.path).strip("/").strip().lower()
    try:
        query = urllib.parse.parse_qs(parts.query)          # parse_qs percent-decodes for us
    except Exception:
        query = {}
    values = query.get("serial") or []
    serial = values[0].strip().lower() if values else ""
    return maker, product, serial


def _queue_for_usb_device(rec, uris):
    """Which CUPS queue, if any, belongs to this physical device.

    Returns (queue_name, matched_on). matched_on is None when nothing matched.

    A CUPS USB device URI is usb://<manufacturer>/<product>?serial=<serial>, percent-encoded,
    so the serial is the identifying field and is matched FIRST — it is the only one that
    separates two printers of the same model. Manufacturer+product is used ONLY when the
    device reports no usable serial at all, never as a second chance for a device whose serial
    simply is not in any queue: that case is the whole point of this check, and quietly
    matching it by model would turn the alarm off exactly when it should be sounding.

    EVERY COMPARISON IS EXACT, against a PARSED field — never a substring of the whole URI.
    Substring matching was verified against iPharm counter 1's real queues and matched serial
    "1" to Label-ZD420, serial "8" to a URI carrying port 631, and serial "ipp" to
    Pharmacy-Printer. Cheap and counterfeit USB hardware ships serials exactly like "0" and
    "1", so such a device was reported `queued` against a queue it has nothing to do with and
    dropped straight out of printers_unqueued — switching off the single alarm this whole
    function exists to raise.
    """
    parsed = []
    for queue, uri in uris:
        fields = _usb_uri_fields(uri)
        if fields is not None:
            parsed.append((queue, fields))

    serial = (rec.get("serial") or "").strip().lower()
    if serial:
        for queue, (_maker, _product, uri_serial) in parsed:
            if uri_serial and uri_serial == serial:
                return queue, "serial"
        return None, None
    maker = (rec.get("manufacturer") or "").strip().lower()
    product = (rec.get("product") or "").strip().lower()
    if maker and product:
        for queue, (uri_maker, uri_product, _serial) in parsed:
            if uri_maker == maker and uri_product == product:
                return queue, "name"
    return None, None


def sysfs_usb_printers():
    """USB printers attached to this Pi, whether or not CUPS has a queue for them.

    Returns (present, printers).
      present  — None when sysfs cannot be read at all, so the caller reports nothing rather
                 than a confident "no printers attached". False means sysfs was readable and
                 there is genuinely no class-07 device.
      printers — one record per device, capped, never None when present is not None.

    Built to the same rules as sysfs_card_reader(), for the same reason: this runs inside the
    telemetry path on a live pharmacy counter, so it returns a list in every case and raises
    in none. Grouped by DEVICE rather than by interface (a multifunction unit exposes printer
    and scanner interfaces separately and must be reported once), every read individually
    guarded so one unreadable node cannot abort the scan, and nothing executed — there is no
    subprocess call in this path.

    _usb_dev_info() is deliberately NOT reused: it collapses manufacturer and product into one
    display string, and it does no validation, both of which are wrong here.
    """
    try:
        ifaces = glob.glob("/sys/bus/usb/devices/*/bInterfaceClass")
    except Exception:
        return None, None
    if not ifaces:
        return None, None

    devs = {}
    for path in sorted(ifaces):
        try:
            with open(path) as fh:
                cls = fh.read().strip().lower()
        except Exception:
            continue
        if cls != PRINTER_IFACE_CLASS:
            continue
        # …:1.0 is an interface; its parent directory is the device holding the descriptor
        # strings. Same string surgery as sysfs_card_reader(): dirname, then split off the
        # LAST colon-suffix.
        iface_dir = os.path.dirname(path)
        dev = iface_dir.rsplit(":", 1)[0]
        devs.setdefault(dev, []).append(iface_dir)

    # The CUPS side is read ONCE, outside the loop — a per-device lpstat would be one shell-out
    # per printer on a 1 GB device every 30 seconds. The URIs are handed over RAW: decoding is
    # _usb_uri_fields()'s job, because it has to decode per FIELD. Flattening the URI to one
    # lower-cased string first is precisely what made the old substring match possible.
    try:
        uris = list(cups_queue_uris().items())
    except Exception:
        uris = None
    # An EMPTY queue list is not the same evidence as a populated one — see cups_scheduler_up().
    # Only a scheduler that is confirmed up turns "no queue matched" into a real finding.
    if uris is not None and not uris and not cups_scheduler_up():
        uris = None

    printers = []
    for dev, iface_dirs in sorted(devs.items()):
        rec = {
            # The Pi's own id for this device: its USB bus path, e.g. "1-1.3". This is what
            # names it in dmesg and in /sys, so it is the id an engineer can act on.
            "usb_path": os.path.basename(dev),
            "iface": os.path.basename(iface_dirs[0]),
            "vendor_id": _usb_id(dev, "idVendor"),
            "product_id": _usb_id(dev, "idProduct"),
            "manufacturer": _usb_str(dev, "manufacturer"),
            "product": _usb_str(dev, "product"),
            "serial": _usb_str(dev, "serial"),
        }
        # bInterfaceProtocol lives on the INTERFACE, not the device, so it is read relative to
        # the interface directory rather than to dev.
        proto = (_usb_attr(iface_dirs[0], "bInterfaceProtocol") or "").lower()
        rec["protocol"] = PRINTER_IFACE_PROTOCOL.get(proto, proto or None)

        if uris is None:
            # CUPS could not be read. "No queue" would be a lie in that state, and it is the
            # lie that raises a false alarm on a counter that is printing perfectly.
            rec["status"] = "unknown"
            rec["queue"] = None
        else:
            queue, how = _queue_for_usb_device(rec, uris)
            if queue:
                rec["status"] = "queued"
                rec["queue"] = queue
                rec["matched_on"] = how
            elif rec["serial"] or (rec["manufacturer"] and rec["product"]):
                # THE FINDING THIS FUNCTION EXISTS FOR: plugged in, powered, enumerated by the
                # kernel — and no CUPS queue points at it, so nothing on this counter can print
                # to it and no other check we have would ever say so.
                rec["status"] = "attached, no queue"
                rec["queue"] = None
            else:
                # Nothing usable to match on, so neither answer is honest.
                rec["status"] = "unknown"
                rec["queue"] = None
        printers.append(rec)
        # Bounded like every other list in this payload. A counter has two or three printers;
        # anything past eight is a fault or a hub full of something else.
        if len(printers) >= 8:
            break
    return (True if printers else False), printers


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

    # Smartcard reader: sysfs is authoritative — a USB interface with bInterfaceClass 0b is
    # a Chip/SmartCard interface by definition. Name-matching lsusb is kept only as a
    # fallback, because it both misses unbranded readers and false-positives on keyboards
    # that merely say "SmartCard" (the pilot's Dell SK-3205 is exactly that combined device).
    # Reading sysfs also needs no PC/SC client, so it works from this root systemd unit
    # without a polkit grant, which enumerating readers via pcscd would require.
    reader, reader_list, undriven = sysfs_card_reader()
    reader_name = (reader_list[0].get("name") if reader_list else None)
    if reader is None:
        matched = re.search(r"CCID|smart\s*card|Gemalto|Identiv|SCM Micro|OMNIKEY|HID Global|ACS\b|Cherry", lsusb, re.I)
        out["smartcard_reader"] = "present" if matched else ("absent" if lsusb else "unknown")
    else:
        out["smartcard_reader"] = "present" if reader else "absent"
    if reader_name:
        out["smartcard_reader_name"] = reader_name
    if reader_list:
        # The full set, with VID:PID, so a supported-model check needs no site visit.
        out["smartcard_readers"] = reader_list
        out["smartcard_reader_count"] = len(reader_list)
    if undriven:
        # Kept OUT of smartcard_readers and out of the count on purpose: those two answer "what
        # can this counter actually use", and an undriven reader cannot be used by anything.
        # Folding it in would make a thin client with one working reader and one useless one
        # look better equipped than one with a single working reader.
        out["smartcard_unsupported"] = undriven

    # pcscd is SOCKET-ACTIVATED: systemd holds /run/pcscd/pcscd.comm and only spawns the
    # daemon when a client connects, so `is-active: inactive` is the normal idle state and
    # alerting on it would fire every time nobody is using a card. What actually matters is
    # whether it can be started on demand, so the socket is reported as the healthy case and
    # a missing unit is distinguished from one that is installed but broken — `is-active`
    # alone answers "inactive" for a package that was never installed.
    if run(["systemctl", "show", "-p", "LoadState", "--value", "pcscd"]).strip() == "not-found":
        out["smartcard_daemon"] = "absent"
    elif run(["systemctl", "is-active", "pcscd"]).strip() == "active":
        out["smartcard_daemon"] = "active"
    elif run(["systemctl", "is-enabled", "pcscd.socket"]).strip() == "enabled":
        out["smartcard_daemon"] = "socket-ready"
    else:
        out["smartcard_daemon"] = "inactive"
    # Whether the kiosk is configured to pass it through at all.
    out["smartcard_redirected"] = "/smartcard" in rdp_argv

    # Printers: CUPS is the source of truth for what this Pi can print to.
    queues = cups_devices()
    out["printer_queues"] = len(queues)
    out["printer_names"] = sorted(queues.keys())[:6]
    # WHERE each queue points, so Watchman can draw the host dependency instead of saying
    # "not recorded" about a relationship that is plainly visible in lpstat. Same cap and the
    # same sort as printer_names, so the two lists line up and truncate together.
    roles = cups_queue_roles()
    out["printer_queue_roles"] = [
        {"queue": q, "kind": roles[q]["kind"], "host": roles[q]["host"]}
        for q in sorted(queues.keys())[:6] if q in roles
    ]
    out["printer_redirected"] = "/printer" in rdp_argv

    # …and CUPS is NOT the source of truth for what is plugged in, which is the gap this
    # closes. A device here with status "attached, no queue" is a printer nobody can print to
    # and that no other field on this device would ever mention.
    #
    # Nested inside `peripherals` rather than sent as a top-level payload key ON PURPOSE: this
    # object already lands in device_state.raw, so it needs no ingest change and cannot collide
    # with a contract name. A top-level key the ingest does not know fails schema validation
    # and takes the WHOLE telemetry POST down with it — see the wifi_link and relay_session
    # comments in build_payload — which on a counter means it stops being monitored entirely.
    attached, usb_printers = sysfs_usb_printers()
    if attached is not None:
        out["printers_attached"] = usb_printers
        out["printers_attached_count"] = len(usb_printers)
        orphans = [p["usb_path"] for p in usb_printers if p["status"] == "attached, no queue"]
        if orphans:
            out["printers_unqueued"] = orphans

    # Whether a printer table has been staged and is waiting to be promoted at this counter.
    out.update(printers_tab_state())

    # Scanners: SANE if installed, otherwise fall back to the USB class.
    if have("scanimage"):
        sc = run(["scanimage", "-L"], timeout=10)
        out["scanner_detected"] = 0 if "No scanners" in sc else len(re.findall(r"^device", sc, re.M))
    else:
        out["scanner_detected"] = 1 if re.search(r"scanner", lsusb, re.I) else 0

    return out


# ── the smartcard fix stack ─────────────────────────────────────────────────
# NHS smartcard login over RDP redirection needs FOUR faults fixed at once (2026-08-17).
# Two of them live on this Pi, and BOTH are invisible to every other check we have:
#
#   1. FreeRDP negotiates SCARD_PROTOCOL_RAW on a card that is T=1 only, pinning it in RAW
#      so every later connect dies with SCARD_E_PROTO_MISMATCH — the PIN never verifies.
#   2. FreeRDP re-copies the RDP server's dwCurrentState verbatim on every 100ms poll of
#      SCardGetStatusChange, INCLUDING SCARD_STATE_CHANGED. PC/SC requires that bit to be
#      cleared before re-arming, so pcsc-lite reports "changed" instantly, the wait never
#      blocks, and card INSERTIONS are never reported to Windows at all.
#
# Both are worked around by a forwarding libpcsclite.so.1 shim that FreeRDP loads instead of
# the system library. FreeRDP dlopen()s that soname BY NAME, so LD_PRELOAD cannot reach it —
# the only lever is LD_LIBRARY_PATH on the kiosk process, set by wcn-kiosk.
#
# WHY THIS IS MONITORED AT ALL: the shim is a file plus one exported environment variable.
# An apt upgrade that reinstalls libpcsclite, an edit to wcn-kiosk, a rebuilt image that
# skips the build step, or a rollback to stock FreeRDP each silently removes it — and the
# symptom is not an error anywhere. It is "the counter cannot log in", discovered by a
# pharmacist at 09:00. Nothing else in this agent would notice: pcscd still runs, the reader
# is still detected, the kiosk still connects. So the stack reports itself explicitly.
SHIM_LIB = "/usr/local/lib/wcn-pcsc/libpcsclite.so.1"
SHIM_DIR = "/usr/local/lib/wcn-pcsc"


def _kiosk_has_shim_env():
    """Whether the RUNNING kiosk process actually has the shim on its library path.

    Checked against /proc rather than by grepping wcn-kiosk, because the two can disagree in
    the way that matters: the launcher is a long-running bash loop that reads its own file
    lazily, so an edited script does NOT affect the live session until the kiosk restarts.
    A file that says the fix is present while the process running the pharmacy counter does
    not have it is exactly the state this check exists to catch.
    """
    for proc in ("xfreerdp3", "xfreerdp"):
        for pid in run(["pgrep", "-x", proc]).split():
            try:
                with open("/proc/%s/environ" % pid, "rb") as fh:
                    env = fh.read().decode("utf-8", "replace")
            except Exception:
                continue
            for kv in env.split("\0"):
                if kv.startswith("LD_LIBRARY_PATH="):
                    return SHIM_DIR in kv.split("=", 1)[1].split(":")
            return False          # process found, no LD_LIBRARY_PATH at all
    return None                    # no kiosk running: unknowable, not false


def smartcard_stack():
    """Is the smartcard fix stack intact on this Pi?

    Returns None on a device with no reader configured for redirection, so counters that
    were never meant to do smartcards do not report a permanent fault.

    `ok` is the single roll-up the alert rule reads. It is deliberately conservative: unknown
    counts as NOT ok for the file/env facts (a missing shim is a real outage) but the FreeRDP
    version is reported without gating `ok`, because a future release that fixes the upstream
    bug should not page anyone at 3am — the shim is harmless once redundant.
    """
    if not os.path.exists("/var/lib/wcn/kiosk.conf") and not os.path.exists(SHIM_LIB):
        return None

    out = {}

    # The shim itself. sha256 so a corrupted or half-written .so is distinguishable from a
    # correct one — "the file exists" is not the same as "the file is the fix".
    out["shim_present"] = os.path.exists(SHIM_LIB)
    if out["shim_present"]:
        try:
            import hashlib          # imported locally, as elsewhere in this file
            h = hashlib.sha256()
            with open(SHIM_LIB, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            out["shim_sha256"] = h.hexdigest()
            out["shim_bytes"] = os.path.getsize(SHIM_LIB)
        except Exception:
            out["shim_sha256"] = None

    # Wired into the LIVE session, not merely into the script (see _kiosk_has_shim_env).
    out["shim_active"] = _kiosk_has_shim_env()

    # FreeRDP version. Stock Debian 13 ships 3.15.0, which additionally suffers a
    # SCARD_E_CANCELLED storm; the fix stack was validated on 3.30.0 from trixie-backports.
    ver = run(["xfreerdp3", "--version"]) or run(["xfreerdp", "--version"])
    m = re.search(r"version\s+(\d+\.\d+\.\d+)", ver)
    out["freerdp_version"] = m.group(1) if m else None

    # The kiosk must be ASKING for redirection; without /smartcard the rest is moot.
    out["smartcard_flag"] = None
    try:
        with open("/var/lib/wcn/kiosk.conf") as fh:
            for line in fh:
                if line.startswith("RDP_SMARTCARD="):
                    out["smartcard_flag"] = line.strip().split("=", 1)[1] == "1"
    except Exception:
        pass

    # Roll-up. Only the two Pi-side fixes are judged here — the VM-side registry settings
    # (EnablePinPad, UseCardReaderPolling) are not visible from this device and are not
    # currently monitored anywhere. Recorded as a known gap rather than silently implied.
    out["ok"] = bool(out.get("shim_present")) and out.get("shim_active") is not False
    return out


# ── the on-console support menu (F4 "boot menu") ────────────────────────────
# What an engineer standing at a counter depends on, and what today has no remote visibility
# at all. Three separate failures, none of which anything else would notice:
#
#   * no secret provisioned  -> NOBODY can get into the support menu on that counter, ever.
#     Discovered only when someone is already on site and stuck.
#   * locked out             -> five wrong PINs locks it for 15 minutes, and the lock is on
#     DISK so a reboot does not clear it. Without this an engineer sits there re-entering a
#     PIN that cannot work yet, with no way to know why.
#   * boot wait misconfigured -> /etc/wcn/boot-wait is an unclamped integer. A stray value
#     held a counter on the splash for TEN MINUTES per boot on 2026-08-17 before anyone
#     noticed, because nothing reported it.
#
# The derived PIN IS reported, deliberately. It gates the on-console menu's device settings
# (static IP and similar), not access to data or the tunnel — an engineer standing at a counter
# needs it, and making them phone someone to get in is a worse outcome than it appearing in an
# authenticated operator UI. Estate owner's call, 2026-08-17.
#
# ⚠️ The SECRET is never reported, and must not be. The PIN is HMAC-SHA256(secret, board serial)
# truncated to six digits, so it is per-device: one PIN read aloud at a counter opens THAT
# counter and nothing else. Sending the secret would collapse that into an estate-wide key and
# make every future PIN forgeable, so only the derived value travels.
TOOLBOX_SECRET = "/etc/wcn/toolbox.secret"
TOOLBOX_LOCK = "/var/lib/wcn/toolbox.lock"
BOOT_WAIT_FILE = "/etc/wcn/boot-wait"


def toolbox():
    """Support-menu readiness. Never returns key material — see the block above."""
    out = {}

    # Provisioned at all? Size only, never contents: a zero-byte secret is a real and
    # otherwise-silent failure mode (the helper fails closed, so it looks like a wrong PIN).
    secret = None
    try:
        with open(TOOLBOX_SECRET, "rb") as fh:
            secret = fh.read().strip()
        out["secret_provisioned"] = bool(secret)
    except Exception:
        out["secret_provisioned"] = False

    # Derived exactly as the privileged helper does it, so the two can never disagree — a PIN
    # shown in the UI that the device rejects is worse than showing nothing. Any change to
    # wcn-toolbox-priv's derivation MUST be mirrored here.
    if secret:
        try:
            import hashlib
            import hmac as _hmac
            serial = ""
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("Serial"):
                        serial = line.split(":", 1)[1].strip()
                        break
            digest = _hmac.new(secret, serial.encode(), hashlib.sha256).digest()
            out["pin"] = "%06d" % (int.from_bytes(digest[:4], "big") % 1000000)
        except Exception:
            out["pin"] = None

    # Lockout state, from the same file the privileged helper writes.
    out["locked"] = False
    try:
        with open(TOOLBOX_LOCK) as fh:
            state = json.load(fh)
        until = int(state.get("until") or 0)
        remaining = until - int(time.time())
        out["failed_attempts"] = int(state.get("fails") or 0)
        if remaining > 0:
            out["locked"] = True
            out["locked_for_s"] = remaining
    except Exception:
        pass

    # The splash countdown. Reported so a misconfigured value is visible from the fleet view
    # rather than only to whoever is standing in front of the counter.
    try:
        with open(BOOT_WAIT_FILE) as fh:
            raw_wait = fh.read().strip()
        out["boot_wait_s"] = int(raw_wait) if raw_wait.isdigit() else None
    except Exception:
        out["boot_wait_s"] = None      # absent file = the toolbox default (5s)

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


# ── which VM this thin client boots into ────────────────────────────────────
# Watchman owns the choice; this file is the handoff to the kiosk launcher, which re-reads
# it on every reconnect. A file rather than an env var so the value is visible to anyone
# looking at the device, and so nothing needs restarting to read it.
#
# Under /var/lib rather than /etc for two reasons: it is server-managed state rather than
# hand-edited configuration (which is what /var/lib is FOR), and this unit runs with
# ProtectSystem=full, which mounts /etc read-only inside the service's namespace.
TARGET_FILE = "/var/lib/wcn/rdp-target"
USER_FILE = "/var/lib/wcn/rdp-user"   # per-counter RDP username; absent -> kiosk uses creds default
PASS_FILE = "/var/lib/wcn/rdp-pass"   # per-counter RDP password; 0600, value NEVER logged


def read_configured_user():
    try:
        with open(USER_FILE) as fh:
            return fh.read().strip() or None
    except Exception:
        return None


def read_configured_pass():
    try:
        with open(PASS_FILE) as fh:
            return fh.read().rstrip("\n") or None
    except Exception:
        return None


def read_configured_target():
    """The target this Pi is SET UP to use — reported separately from the one it is
    currently connected to, because those legitimately differ: on the Cloudflare fallback
    the live target is 127.0.0.1:33389, so comparing the connected address against the
    chosen VM would show a permanent false mismatch on any site whose WireGuard is down."""
    try:
        with open(TARGET_FILE) as fh:
            return fh.read().strip() or None
    except Exception:
        return None


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
        return {"running": True, "client": proc, "target": target, "redirect": flags or None,
                "configured_target": read_configured_target(), "configured_user": read_configured_user()}
    # Reported even when nothing is running: "configured for VM x but not connected" is a
    # more useful state than a row of nulls.
    return {"running": False, "client": None, "target": None, "redirect": None,
            "configured_target": read_configured_target(), "configured_user": read_configured_user()}


# ── editable per-thin-client settings ───────────────────────────────────────
# Watchman owns these values and the server sends the EFFECTIVE set (stored values merged
# over its own defaults) on every tick, for the same self-healing reason as the boot target.
# So this agent deliberately keeps no defaults it could drift from the UI with: the table
# below exists to RE-VALIDATE what arrives and to decide what to fall back to when a value
# is missing or malformed.
#
# Two destinations:
#   * session keys -> KIOSK_CONF, read by the kiosk launcher. Changing one only takes effect
#     when the session restarts, so the file is rewritten (and the kiosk restarted) ONLY when
#     the rendered content really changes.
#   * agent keys   -> this process's own polling loop, live, with no restart at all.
#
# Under /var/lib for the same two reasons as TARGET_FILE: it is server-managed state rather
# than hand-edited configuration, and this unit runs ProtectSystem=full, which mounts /etc
# read-only inside its namespace.
KIOSK_CONF = "/var/lib/wcn/kiosk.conf"

# key -> (kind, default, allowed).  kind "bool": allowed is None.
#                                  kind "int":  allowed is a frozenset of exact values,
#                                               or an inclusive (lo, hi) range.
#
# A CLOSED WHITELIST, and every entry is a boolean or a BOUNDED integer. That is the whole
# security model of this feature: these values originate in a browser, end up in a file a
# shell script parses, and some of them become xfreerdp argv. No free-text setting exists,
# so there is nothing here to quote, escape or inject with.
SESSION_SETTINGS = {
    "smartcard":        ("bool", True, None),
    "printer_redirect": ("bool", True, None),
    "clipboard":        ("bool", True, None),
    "bpp":              ("int", 16, frozenset((16, 24, 32))),
    # 0 means NEVER blank, which is what every counter does today.
    "blank_after_min":  ("int", 0, (0, 120)),
}
AGENT_SETTINGS = {
    # The 10s lower bound IS the existing thundering-herd floor, kept as a range check here:
    # a server-side mistake must not be able to make the fleet report faster than that.
    "report_interval_s": ("int", 30, (10, 900)),
    "printer_every":     ("int", 15, (0, 240)),    # 0 disables printer polling
    "discover_every":    ("int", 8, (0, 240)),     # 0 disables the LAN printer sweep
    # Screen thumbnail for the Watchman thin-client list. 0 DISABLES capture entirely, and that
    # switch matters more than a cadence normally would: a counter screen shows patient data, so
    # a site that has not agreed to it must be able to be certain no frame is ever taken.
    # 10 ticks at the default 30 s interval is every 5 minutes — enough for "what is on that
    # screen now", nowhere near enough to reconstruct someone's session.
    "screenshot_every":  ("int", 10, (0, 240)),
    # Whether this Pi will act as the reverse proxy for the site LAN at all (see the relay
    # section). Off means OFF and is enforced in three places, because "we turned that off"
    # has to be a statement a site can rely on: no session is opened, a live session is torn
    # down on the tick the setting arrives, and each worker re-checks before it fetches.
    # Enabled by default: the server side is already gated by auth, an inventory allowlist and
    # an audit row, and a feature that needs a per-device push before it works would be
    # discovered as "the relay is broken" during the incident someone needed it for.
    "relay_enabled":     ("bool", True, None),
    # Minutes to share this counter's LIVE screen for support. 0 = off, and off is the default:
    # a counter mirrors its screen only because an operator just asked it to.
    #
    # A DURATION, not a deadline — it keeps this table's bool/int-only invariant, and the Pi then
    # computes expiry from its OWN clock, so a device whose NTP has drifted cannot be handed a
    # timestamp already past (never opens) or hours ahead (never closes). Capped server-side at
    # 60; the range here is the second lock on the same door.
    "support_vnc_min":   ("int", 0, (0, 60)),
}

# The KEY= name each session setting takes in kiosk.conf. Held separately from the wire
# names so that neither side can be renamed by accident and silently change the other.
CONF_KEYS = {
    "smartcard": "RDP_SMARTCARD",
    "printer_redirect": "RDP_PRINTER",
    "clipboard": "RDP_CLIPBOARD",
    "bpp": "RDP_BPP",
    "blank_after_min": "BLANK_AFTER_MIN",
}
_CONF_TO_KEY = {v: k for k, v in CONF_KEYS.items()}

# The agent-side cadences actually in force. Module level because settings arrive in the
# middle of a tick and the loop in main() has to see the new value on its next pass without
# being restarted. Seeded from the env file in main(), so an older server that sends no
# settings leaves the pre-existing behaviour exactly as it was.
RUNTIME = {}


def validate_setting(spec, value):
    """One value against one spec. Returns the accepted value, or None to refuse it.

    Callers MUST test the result with `is None`: False is a legitimate accepted value.

    bool is a SUBCLASS of int in Python, so isinstance(True, int) is True. Without the two
    explicit bool checks below, `true` would sail through as bpp=1 and `1` would be accepted
    as a boolean — the same trap the interval guard in main() already has to work around.
    A value that disagrees with its declared type is REFUSED rather than coerced: the server
    validates types too, so a mismatch means one side has a bug that should be visible.
    """
    kind, _default, allowed = spec
    if kind == "bool":
        return value if isinstance(value, bool) else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if isinstance(allowed, frozenset):
        return value if value in allowed else None
    lo, hi = allowed
    return value if lo <= value <= hi else None


def validated_settings(raw, spec_table):
    """Every key of `raw` that spec_table allows, refusing the rest loudly. Keys that were
    not sent are left OUT rather than defaulted, so a caller can still tell "not sent" from
    "sent and refused"."""
    out = {}
    if not isinstance(raw, dict):
        return out
    # Iterated in spec order, not wire order, so the log reads the same way every time.
    for key, spec in spec_table.items():
        if key not in raw:
            continue
        clean = validate_setting(spec, raw[key])
        if clean is None:
            print(f"vigilant-pi-agent: refusing setting {key}={raw[key]!r} "
                  "(wrong type or out of range)", flush=True)
            continue
        out[key] = clean
    return out


def render_kiosk_conf(session):
    """The exact bytes kiosk.conf should hold for these session settings.

    Deterministic on purpose: fixed key order, no timestamp, no hostname. write_kiosk_conf
    decides whether to restart the kiosk by comparing this text with the file, so anything
    that varied per tick here would restart a live pharmacy counter every 30 seconds.
    """
    lines = ["# Managed by vigilant-pi-agent from Watchman — local edits are overwritten.",
             "# Booleans are 1/0 and integers are range-checked; the launcher checks again."]
    for key, (_kind, default, _allowed) in SESSION_SETTINGS.items():
        value = session.get(key, default)
        # int() covers both kinds: every allowed value is a bool or an int, and int(True) is 1.
        lines.append(f"{CONF_KEYS[key]}={int(value)}")
    return "\n".join(lines) + "\n"


def read_kiosk_text():
    try:
        with open(KIOSK_CONF) as fh:
            return fh.read()
    except Exception:
        return None


def session_in_force():
    """What the launcher will actually use on its next reconnect: kiosk.conf as it is on
    disk, with the same per-key fallback to the defaults that the launcher applies to a
    missing or malformed value. Reported so Watchman can show the operator the difference
    between what was asked for and what is really running."""
    eff = {k: default for k, (_kind, default, _allowed) in SESSION_SETTINGS.items()}
    for line in (read_kiosk_text() or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, raw = line.split("=", 1)
        key = _CONF_TO_KEY.get(name.strip())
        if key is None:
            continue                    # not one of ours; ignore rather than guess
        raw = raw.strip()
        if not re.fullmatch(r"\d{1,6}", raw):
            continue                    # malformed -> keep the default, as the launcher does
        kind = SESSION_SETTINGS[key][0]
        if kind == "bool":
            if raw in ("0", "1"):
                eff[key] = raw == "1"
            continue
        clean = validate_setting(SESSION_SETTINGS[key], int(raw))
        if clean is not None:
            eff[key] = clean
    return eff


def settings_in_force():
    """settings_applied for the telemetry payload: session keys read back off disk, agent
    keys from the live loop. Sent every tick so drift between requested and applied is
    visible in the UI instead of having to be guessed at from behaviour."""
    out = session_in_force()
    for key, (kind, default, _allowed) in AGENT_SETTINGS.items():
        value = RUNTIME.get(key)
        if kind == "bool":
            # Checked FIRST and separately: bool is a subclass of int, so the int branch below
            # would happily report a bool setting's default in place of its live value — and
            # for relay_enabled that means the UI claiming the relay is on at a site that
            # switched it off, which is exactly the lie this field exists to prevent.
            out[key] = value if isinstance(value, bool) else default
            continue
        # Reported AS IT IS, not re-clamped: a local env override outside the UI's range is
        # exactly the drift this field exists to surface. The bool exclusion is the
        # isinstance(True, int) trap again.
        out[key] = value if isinstance(value, int) and not isinstance(value, bool) else default
    return out


def write_kiosk_conf(session):
    """Render the session settings and write them ONLY if the content really differs.
    Returns True when the file changed and the kiosk therefore has to be restarted.

    The comparison is the crux: the server re-sends the effective settings on EVERY tick, so
    an unconditional rewrite-and-restart would drop the RDP session of a live pharmacy
    counter every 30 seconds forever. Byte comparison rather than a dict comparison, so a
    hand-edit or a truncated file is also repaired.
    """
    want = render_kiosk_conf(session)
    if read_kiosk_text() == want:
        return False
    try:
        os.makedirs(os.path.dirname(KIOSK_CONF), exist_ok=True)
        tmp = KIOSK_CONF + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(want)
        # 0644 because the launcher runs as the kiosk user and has to read it; atomic replace
        # so a crash mid-write cannot leave the launcher parsing half a file.
        os.chmod(tmp, 0o644)
        os.replace(tmp, KIOSK_CONF)
    except Exception as e:
        print(f"vigilant-pi-agent: cannot write {KIOSK_CONF}: {e}", flush=True)
        return False
    summary = " ".join(l for l in want.splitlines() if l and not l.startswith("#"))
    print(f"vigilant-pi-agent: session settings changed -> {KIOSK_CONF} [{summary}]", flush=True)
    return True


# ── the printer redirection table ───────────────────────────────────────────
# Which CUPS queues wcn-kiosk redirects into the RDP session, and under which WINDOWS DRIVER
# each one is presented. It replaces a hardcoded /printer: flag in the launcher, which is how
# the repo copy and the two live iPharm Pis silently diverged: one site's printer was compiled
# into a script and the next site's five were hand-edited on the device.
#
# TWO FILES, and the split is the whole point:
#
#   printers.tab       LIVE. wcn-kiosk reads ONLY this, and it re-reads on EVERY RECONNECT,
#                      not only at startup. A network blip is a reconnect. So writing this
#                      file IS the commit, and a half-finished change would be picked up
#                      mid-shift by a counter that happened to wobble.
#   printers.tab.next  PENDING. This agent writes ONLY this, and never the live file. A
#                      separate privileged verb promotes .next -> printers.tab and restarts
#                      the session as ONE deliberate action, at a moment somebody chose.
#
# NOTHING HERE RESTARTS ANYTHING — same rule as the branding block. Writing .next changes what
# the counter will do after the next promotion, never what it is doing now, so there is no
# reason for it to cost a live counter its session.
PRINTERS_TAB = "/var/lib/wcn/printers.tab"
PRINTERS_TAB_NEXT = PRINTERS_TAB + ".next"
PRINTERS_TAB_HEADER = "# Managed by vigilant-pi-agent from Watchman — local edits are overwritten."

# ── THE printers.tab CONTRACT — ONE format, THREE owners ────────────────────
# Owners, and what each is allowed to touch:
#   vigilant-pi-agent.py  (this file)  writes printers.tab.NEXT only, never the live file.
#   wcn-toolbox-priv      ('printing-promote')  validates .next, keeps .prev, swaps live,
#                                     restarts the session — as ONE action.
#   wcn-kiosk             reads printers.tab only, and turns it into xfreerdp argv.
#
# ALL THREE MUST ACCEPT AND REJECT EXACTLY THE SAME FILES. Every rule below is repeated
# verbatim in the other two files. Three owners each applying their own rules to one shared
# format is not a theoretical problem: it is the bug class that produced R1–R6, where a value
# was staged by one owner, promoted by a second and silently dropped by a third.
#
#   line            <queue_name>\t<windows_driver>\t<flags>   — exactly two TABs, LF only
#   blank / '#'     ignored
#   queue_name      ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$   i.e. 1..63 characters.
#                   It is the CUPS queue name AND the Windows printer name AND what ProScript
#                   stores in its report mapping — one string wearing three hats, which is why
#                   this is a tight allowlist and not a sanitiser.
#                   63 and not 64: wcn-toolbox-priv hands this same name to test-print and
#                   queue-clear, whose v_queue caps at 63. A 64-character name would promote
#                   and then be untestable — and because validation is all-or-nothing, ONE
#                   over-long name makes that site's WHOLE table permanently un-promotable.
#   windows_driver  printable ASCII 0x20..0x7e, 1..128 characters, NO COMMA.
#                   It cannot use the queue-name class: every real driver name has spaces
#                   ("ZDesigner ZD420-203dpi ZPL", "Brother HL-L5100DN series"). Bounded
#                   printable ASCII is safe for the reason v_ssid records — the value reaches
#                   its consumer as ONE element of an argv array, never as a shell word, and
#                   the TAB separator is what guarantees the split.
#                   THE COMMA is excluded at all three owners because comma is FreeRDP's OWN
#                   field separator inside /printer:<queue>,<driver>[,default]. Real driver
#                   names contain one ("Kyocera FS-1030D, KPDL"), so this needs no attacker,
#                   just an operator typing the true name. When only wcn-kiosk refused it, the
#                   table staged, validated, promoted and restarted the session — and the
#                   counter came back with that printer GONE while telemetry read converged.
#                   Refusing it HERE is what keeps the operator's mistake visible in Watchman.
#   flags           comma separated, a CLOSED SET, currently only `default`; empty is legal.
#                   At most ONE `default` in the whole table.
#   uniqueness      queue names unique across the table.
#   table size      at most PRINTERS_MAX queues. ONE number in all three: this agent refuses
#                   the push, the toolbox refuses the promotion, and wcn-kiosk counts anything
#                   past it as REJECTED rather than silently truncating the table.
#   file size       at most 64 KiB.
#   all or nothing  at both writing ends one bad line refuses the WHOLE table: which queue is
#                   `default` and which queues exist at all only mean anything relative to each
#                   other, so a partially applied table is internally consistent and wrong.
#
# THE ONE DELIBERATE ASYMMETRY, written down so nobody "fixes" it into a fourth disagreement:
# on a duplicate queue name, a second `default`, or more than PRINTERS_MAX queues, the two
# WRITING owners refuse the WHOLE table — so none of those can ever reach the live file through
# promotion. wcn-kiosk, which reads a file it did not write, resolves the same three per LINE
# (first queue wins, first `default` wins, the excess counted as rejected), because its
# non-negotiable job is that a counter never ends up with zero printers. Every PER-VALUE rule
# above is identical in all three; only these three whole-table conditions differ, and the
# kiosk's leniency is unreachable by anything that came through promotion.
TAB_QUEUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# 0x2c is the comma, and it is the one printable character carved out of the range — see the
# contract above. Excluding it from the pattern keeps ONE source of truth for the rule.
TAB_DRIVER_RE = re.compile(r"^[\x20-\x2b\x2d-\x7e]{1,128}$")
TAB_FLAGS = frozenset(("default",))
# Hard cap on redirected queues, shared with wcn-kiosk's PRINTERS_MAX and wcn-toolbox-priv's
# _printers_validate. A site has a handful; anything beyond this is a corrupt or runaway table,
# and every queue is an argv element and a printer installed inside the session.
PRINTERS_MAX = 32
# Same 64 KiB ceiling wcn-toolbox-priv and wcn-kiosk apply to the file itself.
PRINTERS_TAB_MAX_BYTES = 65536


def read_text_file(path):
    """A printers.tab-family file, or None. Bounded by the contract's 64 KiB ceiling.

    Read at every telemetry tick, so the bound is what keeps a corrupt or runaway file on a
    1 GB counter from being pulled into memory 120 times an hour. One byte over the ceiling is
    read too, so an oversized file is distinguishable from one that exactly fills it — and it
    then fails the same size rule wcn-toolbox-priv and wcn-kiosk apply.
    """
    try:
        with open(path) as fh:
            return fh.read(PRINTERS_TAB_MAX_BYTES + 1)
    except Exception:
        return None


def _tab_records(text):
    """The significant lines of a printers.tab body — comments and blanks dropped."""
    if text is None:
        return None
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def _tab_queue_names(text):
    """Queue names from a printers.tab body, in file order. None when the file is absent."""
    rows = _tab_records(text)
    if rows is None:
        return None
    return [r.split("\t", 1)[0] for r in rows][:16]


def _tab_flags(value, where):
    """Normalise one entry's flags to a sorted tuple, or None if any flag is not in the set.

    A list of strings is the wire shape; a comma-separated string is accepted because it is
    the shape the file itself uses and a server that echoes a line back should not be a fault.
    """
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        print(f"vigilant-pi-agent: printer table {where}: flags must be a list, "
              f"got {type(value).__name__}", flush=True)
        return None
    flags = set()
    for flag in value:
        if not isinstance(flag, str) or flag.strip() not in TAB_FLAGS:
            print(f"vigilant-pi-agent: printer table {where}: refusing flag {flag!r} "
                  f"(allowed: {', '.join(sorted(TAB_FLAGS))})", flush=True)
            return None
        flags.add(flag.strip())
    return tuple(sorted(flags))


def render_printers_tab(entries):
    """The exact bytes printers.tab.next should hold — or None if ANY entry is invalid.

    ALL OR NOTHING, deliberately. A printer table is a SET, not a bag of independent lines:
    which queue is `default` and which queues exist at all only mean anything relative to each
    other. Writing the good lines and dropping the bad one would hand a counter a table that
    is internally consistent and quietly WRONG — a label printer missing, or no default at
    all — and nothing downstream could tell that from an operator who meant it. Refusing the
    whole push leaves the previous .next exactly as it was and says which line was at fault.

    Deterministic, for the same reason render_kiosk_conf() is: the caller decides whether to
    write by comparing these bytes with the file, so no timestamp, no hostname, and the
    server's own ordering is preserved rather than re-sorted (the order sets the /printer:
    flag order the launcher emits).
    """
    # The cap is enforced HERE, at push time, so the operator is refused in Watchman with a
    # reason. wcn-kiosk caps at the same number, and before these three agreed it simply
    # stopped reading at 32 — a 40-queue table promoted cleanly, cost the counter its session,
    # and came back missing queues 33-40 and its default printer, logging a clean parse.
    if len(entries) > PRINTERS_MAX:
        print(f"vigilant-pi-agent: printer table has {len(entries)} queues, more than the "
              f"{PRINTERS_MAX} wcn-kiosk will redirect — refusing the whole table", flush=True)
        return None
    lines = [PRINTERS_TAB_HEADER]
    seen = set()
    defaults = []
    for i, entry in enumerate(entries):
        where = f"entry {i + 1}"
        if not isinstance(entry, dict):
            print(f"vigilant-pi-agent: printer table {where}: expected an object, "
                  f"got {type(entry).__name__} — refusing the whole table", flush=True)
            return None
        queue = entry.get("queue")
        driver = entry.get("driver")
        # repr() on every refusal: these strings came off the wire, and a value containing a
        # newline must be PRINTED as \n rather than allowed to forge a second log line.
        if not isinstance(queue, str) or not TAB_QUEUE_RE.match(queue):
            print(f"vigilant-pi-agent: printer table {where}: refusing queue name "
                  f"{queue!r} — refusing the whole table", flush=True)
            return None
        if not isinstance(driver, str) or not TAB_DRIVER_RE.match(driver):
            # The comma is named explicitly. It is the one refusal an operator hits by typing
            # the TRUE driver name off the Windows print server ("Kyocera FS-1030D, KPDL"), and
            # "not printable ASCII" would send them looking for the wrong thing entirely.
            if isinstance(driver, str) and "," in driver:
                why = ("it contains a COMMA, which is FreeRDP's own field separator inside "
                       "/printer: — rename the driver in Windows or omit the part after the "
                       "comma")
            else:
                why = "it must be printable ASCII, 1..128 characters"
            print(f"vigilant-pi-agent: printer table {where} ({queue}): refusing driver "
                  f"{str(driver)[:80]!r} — {why} — refusing the whole table", flush=True)
            return None
        if queue in seen:
            # Two lines for one queue would emit two /printer: flags naming the same Windows
            # printer, and which driver won would depend on FreeRDP's argv order.
            print(f"vigilant-pi-agent: printer table {where}: duplicate queue {queue!r} "
                  "— refusing the whole table", flush=True)
            return None
        flags = _tab_flags(entry.get("flags"), f"{where} ({queue})")
        if flags is None:
            print("vigilant-pi-agent: refusing the whole printer table", flush=True)
            return None
        if "default" in flags:
            defaults.append(queue)
        seen.add(queue)
        lines.append(f"{queue}\t{driver}\t{','.join(flags)}")
    if len(defaults) > 1:
        # "default" names the session's default printer. Two of them is not a preference the
        # file can express, and guessing which one the operator meant is worse than refusing.
        print(f"vigilant-pi-agent: printer table: {len(defaults)} queues marked default "
              f"({', '.join(defaults)}) — refusing the whole table", flush=True)
        return None
    return "\n".join(lines) + "\n"


def write_printers_tab_next(printers):
    """Render Watchman's queue list into printers.tab.NEXT. Returns True if the file changed.

    ⛔ This function must never write PRINTERS_TAB. The launcher re-reads the live file on
    every reconnect, so writing it here would apply a change at the next random network blip,
    to a counter mid-dispense, with nobody watching. Promotion is a separate privileged verb.
    """
    if printers is None:
        return False                    # the server has no opinion this tick
    if not isinstance(printers, list):
        print(f"vigilant-pi-agent: ignoring printer table of type "
              f"{type(printers).__name__}", flush=True)
        return False
    if not printers:
        # An empty table cannot MEAN "no printers here": the launcher's non-negotiable
        # fallback is that a file with no valid lines reverts to its hardcoded block, so an
        # empty file would silently restore some other site's printer. Leaving .next alone is
        # the only honest response to an empty push.
        print("vigilant-pi-agent: empty printer table in this push, "
              f"leaving {PRINTERS_TAB_NEXT} as it is", flush=True)
        return False

    want = render_printers_tab(printers)
    if want is None:
        return False                    # render_printers_tab has already said which line failed
    # Byte comparison before writing, exactly as write_kiosk_conf does: the server re-sends the
    # whole table every tick, and an unconditional rewrite would make print_tab_pending flap
    # and would rewrite a file the launcher may be reading.
    if read_text_file(PRINTERS_TAB_NEXT) == want:
        return False
    try:
        os.makedirs(os.path.dirname(PRINTERS_TAB_NEXT), exist_ok=True)
        tmp = PRINTERS_TAB_NEXT + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(want)
        # 0644 because the launcher runs as the kiosk user, and an atomic replace so neither
        # the launcher nor the promotion verb can ever see half a table.
        os.chmod(tmp, 0o644)
        os.replace(tmp, PRINTERS_TAB_NEXT)
    except Exception as e:
        print(f"vigilant-pi-agent: cannot write {PRINTERS_TAB_NEXT}: {e}", flush=True)
        return False
    queues = ", ".join(l.split("\t", 1)[0] for l in _tab_records(want) or [])
    print(f"vigilant-pi-agent: printer table staged -> {PRINTERS_TAB_NEXT} [{queues}] "
          "(pending promotion; nothing restarted)", flush=True)
    return True


def printers_tab_state():
    """What the counter is printing to now, and what it WILL print to once promoted.

    print_tab_pending is the operator-facing half: true means a table has been staged that the
    live file does not yet match, so Watchman can show "needs a session restart at this
    counter" rather than leaving somebody to wonder why a printer they added has not appeared.

    Compared on significant lines only, so rewording the managed-by header never reads as a
    pending change — the header is cosmetic and promoting for it would cost a session.
    """
    live = read_text_file(PRINTERS_TAB)
    pending = read_text_file(PRINTERS_TAB_NEXT)
    out = {
        "print_tab_live": _tab_queue_names(live),
        "print_tab_next": _tab_queue_names(pending),
        "print_tab_pending": False,
    }
    if pending is not None:
        out["print_tab_pending"] = (_tab_records(pending) or []) != (_tab_records(live) or [])
    return out


def apply_settings(settings):
    """Adopt the per-thin-client settings Watchman sent.

    Returns (kiosk_conf_changed, report_interval_s or None). The kiosk is NOT restarted here:
    the caller does that once, after the boot target has also been written, so a settings
    change and a target change arriving on the same tick interrupt the counter once and not
    twice.
    """
    if settings is None:
        return False, None              # not a counter-pi, or a server without this feature
    if not isinstance(settings, dict):
        print(f"vigilant-pi-agent: ignoring settings of type {type(settings).__name__}", flush=True)
        return False, None

    unknown = [k for k in settings if k not in SESSION_SETTINGS and k not in AGENT_SETTINGS]
    if unknown:
        # Closed whitelist: an unrecognised key is never written to disk and never applied.
        print(f"vigilant-pi-agent: ignoring unknown settings {', '.join(sorted(unknown))}", flush=True)

    session = validated_settings(settings, SESSION_SETTINGS)
    # The server contract is to send the whole effective set every tick, so a response with
    # not one usable session value is a broken server, not an instruction. Leaving the file
    # untouched in that case means a garbled push cannot silently revert an operator's
    # choices — and cannot cost a live counter a restart to do it. Where SOME keys are usable
    # the rest are filled from the defaults, which is exactly what the launcher would do with
    # them anyway, so the two sides cannot disagree about a missing key.
    changed = write_kiosk_conf(session) if session else False
    if not session:
        print("vigilant-pi-agent: no usable session settings in this push, "
              f"leaving {KIOSK_CONF} as it is", flush=True)

    agent = validated_settings(settings, AGENT_SETTINGS)
    for key, value in agent.items():
        if RUNTIME.get(key) != value:
            print(f"vigilant-pi-agent: {key} {RUNTIME.get(key)} -> {value} (from Watchman)", flush=True)
            RUNTIME[key] = value
    # `is False` because validated_settings omits keys that were not sent, and because a
    # missing key must not read as "disable". Torn down HERE rather than left for the workers
    # to notice: one of them can be parked in a 25 s long poll, and a site that has just
    # revoked relay access is entitled to have the channel shut on this tick, not the next.
    if agent.get("relay_enabled") is False:
        relay_close(reason="disabled from Watchman")
    # Torn down on THIS tick for the same reason as the relay: an operator who has just revoked
    # support access is entitled to have the screen stop being shared now, not in 30 seconds.
    # `== 0` and not `is False` — this one is an int, and a key that was NOT sent must not read
    # as "disable" and kill a session an earlier tick legitimately started.
    if agent.get("support_vnc_min") == 0:
        support_vnc_stop(reason="disabled from Watchman")
    return changed, agent.get("report_interval_s")


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


def cups_queue_uris():
    """queue -> its FULL DeviceURI: scheme, port and query string all intact.

    cups_devices() below reduces the same output to a bare host, which is everything the SNMP
    poller needs and lossy for everything else — usb://Zebra%20Technologies/ZTC%20ZD420…
    reduces to the vendor string, and the ?serial= that says WHICH Zebra is thrown away.
    Anything matching a physical device to a queue has to see the whole URI, so the parse is
    split in two here and cups_devices() keeps its exact previous behaviour on top.
    """
    if not have("lpstat"):
        return {}
    found = {}
    for line in run(["lpstat", "-v"]).splitlines():
        m = re.match(r"device for (\S+?):\s*(\S+)", line.strip())
        if m:
            found[m.group(1)] = m.group(2)
    return found


def cups_queue_roles():
    """queue -> {"kind", "host"} — WHERE a queue points, which is the fact that reveals sharing.

    ⭐ WHY THIS EXISTS. Watchman could not say which counter hosts a printer, because nothing
    told it. The payload carried a queue COUNT and up to six NAMES, and a name is identical
    whether the queue drives a printer plugged into this Pi or reaches one plugged into the
    counter next door. At iPharm two Zebras live on counter 1 and counter 2 reaches them over
    IPP — a real dependency, invisible to the platform, so the site read "shared to: not
    recorded" while the sharing was right there in lpstat.

    ⛔ THE RAW URI IS NOT REPORTED. It is built from IEEE-1284 strings the DEVICE supplies, and
    the whole platform treats those as untrusted. What is reported is a CLASSIFICATION —
    a closed set of kinds, plus a host only when that host validates as an address or a
    hostname. A device that lies about its make cannot put anything into this field.

      usb      the printer is plugged into THIS Pi. This counter is the host.
      remote   the queue is reached over the network at `host`.
      local    the queue points at this Pi itself. Not a dependency on anything.
      other    a scheme this does not classify, reported as itself rather than guessed at.

    ⚠️ `remote` DOES NOT MEAN "another counter". This device cannot tell a sibling Pi from the
    printer itself — ipp://192.168.55.17 is counter 1 and ipp://BRNB4220013EDFD.local is a
    Brother on the shop network, and both look identical from here. The PLATFORM decides, by
    matching `host` against the addresses of the site's own counters: a match is a sharing
    dependency worth drawing, anything else is a network printer that depends on nobody.
    Classifying that here would be guessing with the one piece of context this device lacks.
    """
    HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$")
    out = {}
    for queue, uri in cups_queue_uris().items():
        m = re.match(r"^([a-z0-9+.-]{1,16})://([^/:@?#]{0,255})", uri or "")
        if not m:
            out[queue] = {"kind": "other", "host": None}
            continue
        scheme, authority = m.group(1).lower(), m.group(2)
        if scheme == "usb":
            # The authority is the vendor string, never an address — do not report it as one.
            out[queue] = {"kind": "usb", "host": None}
            continue
        host = authority if HOST_RE.match(authority or "") else None
        if host and host in _own_addresses():
            # A counter does not depend on itself, whatever the scheme says.
            out[queue] = {"kind": "local", "host": None}
        elif host and scheme in ("ipp", "ipps", "socket", "http", "https", "lpd"):
            out[queue] = {"kind": "remote", "host": host}
        else:
            # An unclassified scheme still reports its host — pjltray:// at iPharm is a real
            # network printer reached through a custom backend, and hiding the host would lose
            # that. The kind says plainly that this was not classified.
            out[queue] = {"kind": "other", "host": host}
    return out


def _own_addresses():
    """This Pi's own IPv4 addresses plus localhost, so a self-referencing queue is not read as
    a dependency on another counter."""
    addrs = {"localhost", "127.0.0.1", "::1"}
    for line in run(["ip", "-4", "-o", "addr"]).splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            addrs.add(m.group(1))
    return addrs


def cups_devices():
    """Discover printers from CUPS rather than making someone list them.

    `lpstat -v` prints 'device for <queue>: <uri>', and the URI carries the address —
    ipp://192.168.88.221/ipp/print, socket://10.0.0.5:9100 and so on. The queue name is
    also what the operator sees in Watchman, so discovering here keeps the two in step.
    """
    found = {}
    for queue, uri in cups_queue_uris().items():
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


# ── printer discovery on the site LAN ───────────────────────────────────────
# Reading CUPS only ever finds printers someone already configured, which means a printer
# plugged in on site is invisible until a human notices and runs lpadmin. The Pi is the only
# Vigilant-managed thing ON that network, so it is the only thing that can find them.
#
# Probe ports, in the order they identify a printer:
#   9100  raw/JetDirect — near-universal on network printers
#   631   IPP           — modern printers and anything driverless
#   515   LPD           — older kit
PRINTER_PORTS = (9100, 631, 515)

# Hard ceiling on how much address space a sweep will touch. A /24 is 254 hosts, which is a
# couple of seconds; a /16 would be 65k and is certainly a misconfiguration rather than an
# intent, so it is refused instead of quietly hammering the site network for an hour.
MAX_SWEEP_HOSTS = 512


def sweep_targets():
    """Which addresses to probe: the Pi's own IPv4 subnets, excluding the tunnel.

    wg0 is skipped deliberately — it is a /32 point-to-point to the datacentre, so sweeping
    it would probe VM addresses over the WAN rather than the local network the printers are
    actually on.
    """
    targets, nets = [], []
    for line in run(["ip", "-4", "-o", "addr", "show"]).splitlines():
        f = line.split()
        if len(f) < 4:
            continue
        iface, cidr = f[1], f[3]
        if iface == "lo" or iface.startswith(("wg", "docker", "veth")):
            continue
        try:
            addr, _, bits = cidr.partition("/")
            bits = int(bits)
            octets = [int(o) for o in addr.split(".")]
        except Exception:
            continue
        if bits < 24 or bits > 30:
            # Anything wider than a /24 is refused (see MAX_SWEEP_HOSTS); anything narrower
            # than a /30 has no room for a printer.
            if bits < 24:
                print(f"vigilant-pi-agent: refusing to sweep {cidr} on {iface} — wider than /24", flush=True)
            continue
        size = 1 << (32 - bits)
        if size > MAX_SWEEP_HOSTS:
            continue
        base = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        network = base & ~(size - 1)
        self_ip = addr
        for i in range(1, size - 1):
            h = network + i
            ip = f"{(h >> 24) & 255}.{(h >> 16) & 255}.{(h >> 8) & 255}.{h & 255}"
            if ip != self_ip:
                targets.append(ip)
        nets.append(cidr)
    return targets, nets


def probe_host(ip, timeout=0.4):
    """Which printer ports answer on this address. Returns [] for anything that is not
    listening, which is the overwhelming majority of a subnet."""
    open_ports = []
    for port in PRINTER_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sk:
                sk.settimeout(timeout)
                if sk.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def discover_printers(known_addresses):
    """Sweep the site LAN and return records for printers nobody has configured.

    Threads are used rather than sequential probes because 254 hosts x 3 ports x 0.4s would
    take five minutes serially; capped so a Pi with one core does not spend the whole tick on
    it. Addresses already reported via CUPS are skipped, so a configured printer is never
    also reported as an unconfigured find.
    """
    targets, nets = sweep_targets()
    if not targets:
        return []
    from concurrent.futures import ThreadPoolExecutor

    hits = {}
    with ThreadPoolExecutor(max_workers=48) as pool:
        for ip, ports in zip(targets, pool.map(probe_host, targets)):
            if ports:
                hits[ip] = ports
    print(f"vigilant-pi-agent: swept {','.join(nets)} ({len(targets)} hosts), "
          f"{len(hits)} printer-like", flush=True)

    out = []
    for ip, ports in sorted(hits.items()):
        if ip in known_addresses:
            continue
        # SNMP turns "something is listening on 9100" into make, model, page count and toner.
        # Where it answers, that data is used and the record is indistinguishable from a
        # configured printer's; where it does not, the record is deliberately thin rather
        # than padded with guesses.
        p = poll_printer(f"{ip}@{ip}") or {}
        rec = {
            "name": p.get("descr") or p.get("model") or ip,
            "address": ip,
            # 'probe' is honest about the weakest case: a port answered and nothing more is
            # known. It is NOT called snmp/ipp unless that is actually what identified it.
            "discovered_via": "snmp" if p.get("page_count") is not None or p.get("descr")
                              else ("ipp" if 631 in ports else "probe"),
            "unconfigured": True,
            "open_ports": ports,
        }
        for k in ("make", "model", "serial", "status", "state_reasons", "page_count", "supplies"):
            if p.get(k) is not None:
                rec[k] = p[k]
        out.append(rec)
    return out


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

    # Discovery is SEPARATE from polling and much slower, so it runs on its own cadence
    # (VIGILANT_DISCOVER_EVERY printer passes, 0 to disable). Configured printers are polled
    # every pass regardless — a sweep failing must never stop known printers reporting.
    if conf.get("_discover"):
        try:
            out.extend(discover_printers({p.get("address") for p in out if p.get("address")}))
        except Exception as e:
            print(f"vigilant-pi-agent: printer discovery skipped: {type(e).__name__}: {e}", flush=True)
    return out


# ── log shipping ────────────────────────────────────────────────────────────
# Vigilant already stores per-device logs (device_logs, deduped on time+message, 100 per tick,
# pruned at 30 days) and shows them on the device page — the Pi just never sent any. Without
# this, diagnosing a kiosk problem needs someone physically at the counter, which is how a
# smartcard channel fault turned into an exchange of phone photos.
#
# Deliberately NARROW. A pharmacy counter must not hose arbitrary logs to a server:
#   * the kiosk log  — FreeRDP client output: channel errors, which transport it used, and
#     why a session dropped. This is the file that answers "did smartcard redirection work".
#   * the agent's and pcscd's own units — for faults in the monitoring path itself.
# Nothing else is read: no full journal, no application output, nothing that could carry
# patient data. FreeRDP masks the password in its own output, and the launcher never logs a
# credential, but REDACT is applied anyway because a log that leaks a secret to the server is
# far worse than a log that is slightly less readable.
KIOSK_LOG = "/var/log/wcn-kiosk.log"
LOG_UNITS = ("vigilant-agent", "pcscd")
REDACT = re.compile(r"(/p:|password=|passwd=|token=)\S+", re.I)

# Only lines worth a round trip. The kiosk log is chatty with keymap warnings on every
# connect; shipping those would push the interesting lines out of the 100-line budget.
LOG_KEEP = re.compile(
    r"smartcard|scard|rdpdr|channel|connecting via|ERROR|FATAL|Hangup|disconnect|"
    r"refus|denied|timeout|unable|failed",
    re.I,
)


# Control bytes that must never reach the server. Postgres rejects a NUL in `text` and a
# \u0000 escape in `jsonb`, so ONE such byte anywhere in the batch fails the whole telemetry
# write — not just the log insert — and the counter's last_seen_at stops advancing while the
# agent, the network and the ingest are all perfectly healthy.
#
# MEASURED 2026-08-19 on the pilot: 29,845 lines of /var/log/wcn-kiosk.log contain a NUL,
# because FreeRDP writes raw terminal control bytes there. Whether a given tick broke depended
# purely on where the tail window happened to land, which is what made this look intermittent
# and what sent three earlier diagnoses (payload size, log volume, a "poison line") the wrong
# way. The server strips these too; doing it here as well keeps a fleet of older servers safe
# and saves shipping bytes no reader would ever want to see.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _log_line(source, text):
    clean = _CTRL.sub("", REDACT.sub(r"\1<redacted>", text))
    return {"time": "", "topics": source, "message": clean[:400]}


# Keys of log lines already accepted by the server, so the same tail is not re-sent forever.
#
# NOTE ON HISTORY: this dedup was originally added because POSTs carrying `logs` hung >20s
# while the same POST without them answered in 0.2s, which was read as primary-key contention
# on (device_id, log_time, message). That diagnosis was WRONG. The hang was a NUL byte in a
# kiosk log line (see _CTRL above) failing the write, plus a missing `await` on the server that
# turned the resulting error into no-response-at-all. Both are fixed at the source.
#
# The dedup is kept on its own merits — re-sending an unchanged tail every tick is pure waste,
# and bounding the batch keeps one bad device from dominating the ingest — but it was never the
# cure, and anyone reading it as one will mis-diagnose the next stall.
#
# Bounded so a long-running agent cannot grow this without limit; the server still dedupes, so
# a line dropped here is only ever a duplicate we chose not to re-send.
_SENT_LOG_KEYS = set()
_SENT_LOG_CAP = 2000


def mark_logs_sent(logs):
    """Called only after the server has ACCEPTED the batch. On a failed POST nothing is marked,
    so the lines are retried on the next tick — the self-healing property is preserved."""
    for l in logs or []:
        _SENT_LOG_KEYS.add((str(l.get("time", "")), str(l.get("message", ""))))
    if len(_SENT_LOG_KEYS) > _SENT_LOG_CAP:
        # Cheap bound: drop the oldest half. Re-sending a few duplicates later is harmless
        # (the server dedupes); an unbounded set on a 1 GB device is not.
        for k in list(_SENT_LOG_KEYS)[: _SENT_LOG_CAP // 2]:
            _SENT_LOG_KEYS.discard(k)


def collect_logs(limit=25):
    """Recent interesting lines from the kiosk log and the two units we own.

    Only lines not already accepted by the server are returned, and the batch is bounded. Both
    matter: re-sending the same tail every tick is what stalled the ingest (see the comment on
    _SENT_LOG_KEYS), and an unbounded batch is what made the stall permanent rather than brief.
    """
    out = []
    try:
        with open(KIOSK_LOG, errors="replace") as fh:
            # Tail without reading a large file into memory: seek back a bounded window.
            try:
                fh.seek(0, os.SEEK_END)
                start = max(0, fh.tell() - 60000)
                fh.seek(start)
                # Only discard a partial line when we actually seeked INTO the file. Doing it
                # unconditionally silently ate the first line of any log smaller than the
                # window — which is every log on a freshly booted thin client.
                if start > 0:
                    fh.readline()
            except Exception:
                pass
            for line in fh.read().splitlines():
                line = line.strip()
                if line and LOG_KEEP.search(line):
                    out.append(_log_line("kiosk", line))
    except FileNotFoundError:
        pass
    except Exception as e:
        out.append(_log_line("agent", f"could not read {KIOSK_LOG}: {type(e).__name__}"))

    for unit in LOG_UNITS:
        txt = run(["journalctl", "-u", unit, "-n", "40", "--no-pager", "-o", "short-iso"], timeout=10)
        for line in txt.splitlines():
            line = line.strip()
            if line and LOG_KEEP.search(line):
                out.append(_log_line(unit, line))

    # Drop anything the server has already accepted. This is the fix for the stall described
    # on _SENT_LOG_KEYS: without it the same tail is re-sent every tick forever, and those
    # repeated rows are what the ingest contends on.
    fresh = [l for l in out
             if (str(l.get("time", "")), str(l.get("message", ""))) not in _SENT_LOG_KEYS]

    # Newest last, and well inside the server's 100-row cap. The bound is the second half of
    # the fix: a burst (a boot, a crash loop) must not produce a batch big enough to stall the
    # request that carries this device's liveness.
    return fresh[-limit:]


# ── agent self-update ───────────────────────────────────────────────────────
# The fleet is unreachable inbound by design, so without this every fix needs someone
# physically at a counter. Vigilant serves the current agent at /agent/pi-script,
# authenticated with the device's own token.
#
# OFF BY DEFAULT (VIGILANT_AUTO_UPDATE=1 to enable). A bad agent pushed to 500 clinical
# devices simultaneously is a far worse outcome than a slow rollout, so this is proven on one
# thin client first.
#
# Safety, in order — each of these guards a specific way this could brick a counter:
#   1. sha256 compared first; identical content is never rewritten (otherwise every tick
#      would reinstall and restart the agent).
#   2. the served body must match the sha256 the SERVER advertises — catches a truncated or
#      corrupted download before it is written anywhere.
#   3. it must PARSE as Python before being installed; a half-file would otherwise leave the
#      device with an agent that cannot start, and no way in to fix it.
#   4. the running version is kept as .prev.
#   5. a REVERT TIMER is armed BEFORE the restart. If the new agent never reports a
#      successful tick, systemd restores .prev on its own — the device recovers without a
#      site visit. That is the whole point: the failure mode of a remote update must not
#      require the access the update exists to avoid needing.
AGENT_PATH = "/usr/local/sbin/vigilant-pi-agent"
REVERT_UNIT = "vigilant-agent-revert"
REVERT_AFTER_S = 600

# Fastest cadence the agent will accept from the server. Matches config.fastPollS so the
# fast-poll window works; anything lower is refused as a misconfiguration.
MIN_POLL_S = 3


def _sha256_file(path):
    try:
        import hashlib
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        return None


def cancel_revert():
    """Called after a successful tick: the new agent works, so disarm the dead-man's switch."""
    if not os.path.exists("/run/vigilant-update-pending"):
        return
    run(["systemctl", "stop", REVERT_UNIT + ".timer"], timeout=15)
    try:
        os.unlink("/run/vigilant-update-pending")
    except Exception:
        pass
    print("vigilant-pi-agent: update confirmed working, revert disarmed", flush=True)


CMDLINE_TRIAL = "/var/lib/wcn/cmdline-trial"


def confirm_cmdline_trial():
    """Disarm a live quiet-boot cmdline.txt retrofit once it is proven good.

    A successful telemetry tick is proof this Pi booted the retrofitted cmdline.txt AND is back
    online, so the trial marker is deleted. That single unlink disarms the ENTIRE dead-man revert
    the privileged helper armed: wcn-cmdline-revert.service is ConditionPathExists on this file
    (so it is condition-skipped on every future boot once the marker is gone) and the deadman
    timer no-ops without it. A confirmed change just becomes permanent, nothing left to undo.

    The marker lives under /var/lib/wcn, which is writable to the agent; cmdline.txt itself and
    its backup are on /boot, which ProtectSystem=full keeps read-only here on purpose — restoring
    them is the boot-time unit's job (root, outside this namespace), never the agent's."""
    if not os.path.exists(CMDLINE_TRIAL):
        return
    try:
        os.unlink(CMDLINE_TRIAL)
        print("vigilant-pi-agent: quiet-boot cmdline change confirmed, revert disarmed", flush=True)
    except Exception:
        pass


TOOLBOX_PRIV = "/usr/local/sbin/wcn-toolbox-priv"


def sync_toolbox(conf):
    """Pull the on-console toolbox scripts on the SAME opt-in, slow cadence as the agent's own
    self-update, so wcn-toolbox / wcn-toolbox-priv track the agent live instead of only arriving
    with a reimage.

    The privileged helper does the actual fetch-validate-install: it runs OUTSIDE this unit's
    ProtectSystem namespace, so it can write /usr/local/bin (and, on older devices, /usr/local/sbin)
    that this agent process cannot. We just trigger it and surface its one-line result. Best-effort
    by design — any failure here is logged and never touches the telemetry tick. On a device whose
    installed helper predates this verb the call simply reports 'unknown verb' and is ignored; the
    first new helper has to arrive out-of-band (reimage / install-pi-agent.sh), after which every
    later toolbox change self-propagates through this path."""
    try:
        r = subprocess.run([TOOLBOX_PRIV, "toolbox-sync"],
                           capture_output=True, text=True, timeout=90)
        out = (r.stdout or r.stderr).strip()
        if out and "already current" not in out and "unknown verb" not in out:
            print("vigilant-pi-agent: " + out, flush=True)
    except Exception as e:
        print(f"vigilant-pi-agent: toolbox sync failed: {type(e).__name__}: {e}", flush=True)


def self_update(conf):
    import hashlib
    url, token = conf.get("VIGILANT_URL"), conf.get("VIGILANT_TOKEN")
    if not (url and token):
        return
    req = urllib.request.Request(
        url.rstrip("/") + "/agent/pi-script",
        headers={"Authorization": f"Bearer {token}", "User-Agent": AGENT_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            advertised = r.headers.get("x-vigilant-sha256")
    except Exception as e:
        print(f"vigilant-pi-agent: update check failed: {explain_failure(e)}", file=sys.stderr, flush=True)
        return

    got = hashlib.sha256(body).hexdigest()
    if advertised and advertised != got:
        print("vigilant-pi-agent: refusing update — sha256 does not match the server's", file=sys.stderr, flush=True)
        return
    if got == _sha256_file(AGENT_PATH):
        return                                  # already current; do not touch the device
    try:
        ast_mod = __import__("ast")
        ast_mod.parse(body.decode())
    except Exception as e:
        print(f"vigilant-pi-agent: refusing update — served agent does not parse ({type(e).__name__})",
              file=sys.stderr, flush=True)
        return

    try:
        tmp = AGENT_PATH + ".new"
        with open(tmp, "wb") as fh:
            fh.write(body)
        os.chmod(tmp, 0o755)
        shutil.copy2(AGENT_PATH, AGENT_PATH + ".prev")
        # Arm the revert BEFORE swapping, so a crash between here and the restart still recovers.
        open("/run/vigilant-update-pending", "w").write(got)
        run(["systemd-run", "--unit=" + REVERT_UNIT, f"--on-active={REVERT_AFTER_S}",
             "/bin/sh", "-c",
             f"cp {AGENT_PATH}.prev {AGENT_PATH} && rm -f /run/vigilant-update-pending && "
             f"systemctl restart vigilant-agent"], timeout=20)
        os.replace(tmp, AGENT_PATH)
        print(f"vigilant-pi-agent: updated to {got[:12]}…, restarting "
              f"(auto-revert in {REVERT_AFTER_S}s unless it reports)", flush=True)
        run(["systemctl", "restart", "vigilant-agent"], timeout=25)
    except Exception as e:
        print(f"vigilant-pi-agent: update install failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)


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
        # ⚠️ THE CAPABILITY FLOOR, AND THIS NUMBER IS THE SECOND HALF OF A FEATURE.
        # The server reads this back out of device_state.raw->>'agent_version' and refuses to
        # hand a counter job to anything below PMR_JOB_AGENT_VERSION (2), because handing a job
        # out IS the claim: an agent that cannot parse `pmr_job` does not ignore it, it
        # SWALLOWS it, and the job goes pending -> claimed -> expired with nothing having
        # happened and the pre-opening check emailing about a healthy counter.
        #
        # ⭐ AND IT IS NOT A CONSTANT, because "this build implements the branch" is not the
        # same claim as "this device can honour a job tonight". The branch is worth 2 only
        # while the ledger that makes execution once-only can actually be written, and an SD
        # card that has remounted read-only — the fault reported two lines below as
        # `rootfs_readonly` — takes that away from a device whose code is perfectly correct.
        # pmr_agent_version() re-proves it every tick BY WRITING THE LEDGER, and drops this
        # claim to 1 when it cannot: the job channel closes and nothing is swallowed, while
        # boot, settings and action (COUNTER_CHANNEL_AGENT_FLOOR, all floored at 1) carry on.
        # Raising this claim past what has just been proved would defeat the only protection
        # the floor provides.
        "agent_version": pmr_agent_version(conf),
        "os_version": (read_first("/etc/os-release", "") or "").split("PRETTY_NAME=")[-1].split("\n")[0].strip('"') or None,
        "hw_model": pi_model(),
        "hw_serial": pi_serial(),
        "throttling": throttled(),
        "rootfs_readonly": rootfs_readonly(),
        "primary_ip": primary_ip(),
        "wireguard": wg_state(),
        "rdp": rdp,
        # What the per-thin-client settings are ACTUALLY set to on this device, as opposed to
        # what Watchman asked for. Reported every tick so the UI can show drift — e.g. a
        # session option written to kiosk.conf but not yet picked up by a running session.
        "settings_applied": settings_in_force(),
        # Whether a reverse-proxy session is live, and to what. NOT called "relay": the wifi_link
        # comment above is the precedent — a name the ingest contract already means something
        # else by fails schema validation and takes the WHOLE telemetry POST down with it, so a
        # new field gets a name nothing can already have claimed.
        "relay_session": relay_status(),
        # Whether this counter is sharing its screen, and the per-session password Vigilant needs
        # to sign a viewer token. Reported only while genuinely live.
        "support_vnc": support_vnc_status(),
        # Detected, not asserted: proves presence, never that a peripheral works end to end.
        "peripherals": peripherals(rdp.get("redirect") or ""),
        # The smartcard FIX STACK, as opposed to `peripherals.smartcard_*` which reports what
        # is plugged in. Separate key because the two answer different questions and fail
        # independently: a counter can have a perfectly detected reader and still be unable to
        # log in because the libpcsclite shim went missing on an apt upgrade. See the block
        # above smartcard_stack() for why a silent regression here costs a pharmacy its morning.
        "smartcard_stack": smartcard_stack(),
        # On-console support menu: the per-device PIN an engineer needs at the counter, whether
        # the menu is locked out, and whether the splash countdown is sane. Carries the derived
        # PIN but never the estate secret it comes from.
        "toolbox": toolbox(),
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
        # Only on the slow pass; Vigilant dedupes, so nothing is lost by not sending every tick.
        "logs": collect_logs() if conf.get("_logs") else None,
        "kernel": (run(["uname", "-r"]) or "").strip() or None,
    }


AGENT_UA = "vigilant-pi-agent/1"


def post(url, token, path, body, timeout=15, limit=400):
    """Authenticated JSON POST. Returns (status, first `limit` chars of the reply).

    `limit` exists because most callers only log the reply, and an unbounded read of what
    turns out to be an HTML error page would flood the journal. A caller that PARSES the reply
    must raise it: the telemetry reply carries the settings, boot-target, action AND relay
    directives, and a reply clipped mid-JSON is not merely shortened — json.loads fails and
    EVERY directive in it is silently lost.
    """
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
        # Bounded READ, not just a bounded slice: a runaway reply is never pulled into memory
        # on a device with 1 GB of it. errors="replace" because a byte cap can land in the
        # middle of a multi-byte character.
        return r.status, r.read(limit).decode(errors="replace")


# ── screen thumbnail ────────────────────────────────────────────────────────
# WIDTH IS A PRIVACY CONTROL, not a bandwidth one. At 240px across a 1920px panel the text on a
# pharmacy record is not legible, while "logged out", "wrong server", "frozen session" and
# "black screen" all still read clearly at a glance. Raising it defeats the entire point, so it
# is a constant here rather than a pushed setting — the server can turn capture OFF
# (screenshot_every = 0) but cannot ask a counter for a sharper picture of a patient record.
SHOT_WIDTH = 240
SHOT_QUALITY = "6"      # ffmpeg -q:v (2 best .. 31 worst); 6 is ~8 KB at this width
SHOT_TIMEOUT = 25


def _kiosk_xauth():
    """The kiosk session's X authority file, or None.

    The agent runs as root while X belongs to the kiosk user, so it needs that user's cookie.

    /run/wcn-xauth is checked FIRST because the systemd unit is hardened with ProtectHome=yes,
    which replaces /home with an empty tmpfs inside the unit's namespace — the glob below then
    matches nothing no matter which user owns the session. The unit bind-mounts the cookie to
    that stable path (and bind-mounts /tmp/.X11-unix, which PrivateTmp=yes likewise hides).
    Without both of those, capture fails with no error anyone would connect to sandboxing.
    """
    for path in ["/run/wcn-xauth"] + sorted(glob.glob("/home/*/.Xauthority")):
        if os.access(path, os.R_OK):
            return path
    return None


def capture_screen():
    """One downscaled JPEG of the kiosk display as bytes, or None if it cannot be taken.

    ffmpeg does grab, scale and encode in a single pass to stdout, so no frame is ever written
    to the SD card — that matters for flash wear, and more because such a file would be a copy
    of patient-visible content sitting unencrypted on a device in a shop.

    Returns None on every failure path. A counter that cannot be photographed is not a fault
    worth reporting, let alone worth failing a telemetry tick over.
    """
    if not have("ffmpeg"):
        return None
    env = dict(os.environ)
    env["DISPLAY"] = env.get("DISPLAY") or ":0"
    xauth = _kiosk_xauth()
    if xauth:
        env["XAUTHORITY"] = xauth

    # x11grab needs an explicit size; probe it, because a wrong -video_size does not fail
    # cleanly, it silently captures a corner of the screen.
    geom = "1920x1080"
    if have("xdotool"):
        try:
            out = subprocess.run(["xdotool", "getdisplaygeometry"], capture_output=True,
                                 text=True, timeout=8, env=env).stdout.split()
            if len(out) == 2 and out[0].isdigit() and out[1].isdigit():
                geom = f"{int(out[0])}x{int(out[1])}"
        except Exception:
            pass
    try:
        proc = subprocess.run(
            ["ffmpeg", "-loglevel", "error", "-f", "x11grab", "-video_size", geom,
             "-i", env["DISPLAY"], "-frames:v", "1",
             # -2 keeps the height even, which mjpeg requires; scale=240:-1 can produce an odd
             # height and then ffmpeg fails with a height-not-divisible error.
             "-vf", f"scale={SHOT_WIDTH}:-2", "-q:v", SHOT_QUALITY,
             "-f", "mjpeg", "pipe:1"],
            capture_output=True, timeout=SHOT_TIMEOUT, env=env,
        )
    except Exception:
        return None
    img = proc.stdout or b""
    # Must actually be a JPEG: ffmpeg can exit 0 having written diagnostics, and the server
    # rejects non-JPEG anyway, so catch it here rather than spend an upload finding out.
    if len(img) < 128 or img[:3] != b"\xff\xd8\xff":
        return None
    return img


def send_screen(conf):
    """Capture and upload one thumbnail. Never raises."""
    img = capture_screen()
    if not img:
        return False
    try:
        status, _body = post(
            conf["VIGILANT_URL"], conf["VIGILANT_TOKEN"], "/screen",
            {
                "image_b64": base64.b64encode(img).decode("ascii"),
                "width": SHOT_WIDTH,
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            timeout=30,
        )
        return status == 200
    except Exception:
        # Deliberately silent: the screen is a convenience, and a failed upload must not add
        # noise to a log that is being read to diagnose real faults.
        return False


def apply_boot_target(boot):
    """Adopt the VM Watchman says this thin client should boot into.

    The value is validated to a bare IPv4:port before it is written, because the launcher
    interpolates it into BOTH /dev/tcp/<host>/<port> and xfreerdp's /v: argument. A target
    carrying shell metacharacters would otherwise be a command-injection route from the
    monitoring server into every counter in the estate, so this is a hard allowlist rather
    than an escape.

    Applying restarts the kiosk session, which reconnects in about 8 seconds. Switching
    which VM a counter uses is a deliberate act, so it is done immediately rather than
    deferred — but it IS a visible interruption to anyone mid-transaction.

    Returns True only if it restarted the kiosk, so a settings change written earlier in the
    same tick can be folded into this one restart instead of causing a second.
    """
    if not isinstance(boot, dict):
        return False
    target = boot.get("target")
    if not isinstance(target, str):
        return False
    target = target.strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", target):
        print(f"vigilant-pi-agent: refusing malformed boot target {target!r}", flush=True)
        return False

    changed = False
    if read_configured_target() != target:
        try:
            os.makedirs(os.path.dirname(TARGET_FILE), exist_ok=True)
            with open(TARGET_FILE, "w") as fh:
                fh.write(target + "\n")
            os.chmod(TARGET_FILE, 0o644)
            changed = True
            print(f"vigilant-pi-agent: boot target -> {target}", flush=True)
        except Exception as e:
            print(f"vigilant-pi-agent: cannot write {TARGET_FILE}: {e}", flush=True)
            return False

    user = boot.get("user")
    if isinstance(user, str) and user.strip():
        user = user.strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
            print(f"vigilant-pi-agent: refusing malformed rdp user {user!r}", flush=True)
        elif read_configured_user() != user:
            try:
                os.makedirs(os.path.dirname(USER_FILE), exist_ok=True)
                with open(USER_FILE, "w") as fh:
                    fh.write(user + "\n")
                os.chmod(USER_FILE, 0o644)
                changed = True
                print(f"vigilant-pi-agent: rdp user -> {user}", flush=True)
            except Exception as e:
                print(f"vigilant-pi-agent: cannot write {USER_FILE}: {e}", flush=True)

    passwd = boot.get("pass")
    if isinstance(passwd, str) and passwd != "":
        if read_configured_pass() != passwd:
            try:
                os.makedirs(os.path.dirname(PASS_FILE), exist_ok=True)
                fd = os.open(PASS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(passwd + "\n")
                changed = True
                print("vigilant-pi-agent: rdp password updated", flush=True)
            except Exception as e:
                print(f"vigilant-pi-agent: cannot write {PASS_FILE}: {e}", flush=True)

    if not changed:
        return False
    # ⛔ NOT `run()`. This return value becomes `restarted` in tick(), and `restarted` is what
    # pmr_settle() settles a deferred counter.session-restart against — so it must mean "a
    # session really went down", not "I wrote rdp-target". `run()` returns stdout and discards
    # the return code entirely, so a systemd refusal read as success and the server was told a
    # counter had been signed out when it had not.
    # restart_kiosk_session() exists for exactly this reason (read its docstring). The fix
    # originally landed only in the OTHER function that produces `restarted`; this is the
    # sibling it missed.
    # A refused restart is not lost work: wcn-kiosk re-reads the target file on every reconnect,
    # so the new target still takes effect at the next natural one — just not on this tick, and
    # we no longer claim otherwise.
    return restart_kiosk_session("boot target changed")


# ── fleet branding ──────────────────────────────────────────────────────────
# The parts of a thin client a person actually looks at: the boot splash, the console before
# login, and the kiosk's pre-connect screen. Watchman holds ONE set for the whole fleet, so
# there is nothing per-site to resolve on this side and no precedence rule to get wrong — the
# `sha` in the telemetry reply either matches what this device last applied or it does not.
#
# WHAT IS DELIBERATELY ABSENT: /boot/firmware/cmdline.txt (quiet, logo.nologo). It is the one
# file on a Pi with no remote recovery — a typo means the device does not boot, so no SSH, no
# agent, no tunnel, and somebody drives to a pharmacy with an SD card reader. Kernel verbosity
# is set ONCE at image bake time in build-image.sh. There is no live push for it, and there must
# never be one: nothing in this section may be extended to reach that file.
#
# The text bodies ride INLINE in the telemetry reply because they are a few hundred bytes each.
# The splash does NOT: device_state.raw is stored wholesale on every tick, so a PNG in there
# would be rewritten into the database ~2880 times a day per device. It is fetched separately,
# with this device's own token, and only when its sha differs from the file already on disk.
#
# NOTHING HERE RESTARTS ANYTHING. Branding is cosmetic, and wcn-kiosk re-reads its message file
# on each reconnect exactly as it re-reads rdp-target, so there is never a reason to drop a live
# pharmacy counter's RDP session for a change of wording.
#
# THE SANDBOX. This unit runs ProtectSystem=full, which mounts /etc AND /boot READ-ONLY inside
# its namespace — the same trap that made the enrolment token silently fail to persist to /etc
# (hence STATE_CONF) and that hid the X socket from screenshot capture. Writing branding
# therefore needs a SURGICAL grant, never a relaxed ProtectSystem. build-image.sh bakes it in;
# a device already in the field needs the same three lines as a drop-in:
#
#     systemctl edit vigilant-agent      # /etc/systemd/system/vigilant-agent.service.d/
#     [Service]
#     ReadWritePaths=-/etc/motd
#     ReadWritePaths=-/etc/issue
#     ReadWritePaths=-/usr/share/plymouth/themes/pix
#
# The "-" prefix is REQUIRED on all three: a non-optional path that does not exist FAILS the
# unit, and a failed unit is a dead monitoring agent restarting every 10s. Pi OS Lite may have
# no plymouth at all, so a missing splash theme must degrade to "no splash", never to "no agent".
BRANDING_STATE = "/var/lib/wcn/branding.json"
# Under /var/lib for the same two reasons as TARGET_FILE and KIOSK_CONF: it is server-managed
# state rather than hand-edited configuration, and /etc is read-only in this unit's namespace.
KIOSK_MESSAGE_PATH = "/var/lib/wcn/kiosk-message.txt"
MOTD_PATH = "/etc/motd"
ISSUE_PATH = "/etc/issue"
SPLASH_THEME_DIR = "/usr/share/plymouth/themes/pix"
SPLASH_PATH = SPLASH_THEME_DIR + "/splash.png"
# Kept beside the splash the FIRST time we overwrite it, so clearing the splash in Watchman can
# put the image's own back rather than leaving plymouth with nothing to draw.
SPLASH_BACKUP = SPLASH_PATH + ".wcn-orig"

# (wire key, file, atomic).
#
# THE `atomic` COLUMN IS FORCED BY THE SANDBOX, not a preference. The console grant is
# per-FILE — ReadWritePaths=-/etc/motd makes that one inode writable and leaves /etc itself
# read-only — so the usual write-temp-then-rename cannot be used for those two: creating
# /etc/motd.tmp needs write access to the DIRECTORY and fails with EROFS. They are truncated and
# rewritten in place, accepting that a crash mid-write leaves a short motd (cosmetic, and
# nothing boots from it). The kiosk message lives in a directory we really do own, so it gets the
# atomic path — the launcher may read it at any moment and must never see half a file.
#
# A corollary worth knowing: because the grant is a bind mount of an existing file, /etc/motd and
# /etc/issue must EXIST when the unit starts or there is no grant at all. build-image.sh creates
# them for that reason.
_BRANDING_FILES = (
    ("motd", MOTD_PATH, False),
    ("issue", ISSUE_PATH, False),
    ("kiosk_message", KIOSK_MESSAGE_PATH, True),
)

# 8 KB per item: generous for ASCII art, and small enough that three of them plus the settings,
# boot, action and relay directives all fit inside the bounded read tick() does of the telemetry
# reply. See post()'s docstring for why an over-long reply is not merely shortened — json.loads
# fails and EVERY directive in it is lost.
BRANDING_TEXT_MAX = 8192
# Mirrors the server's cap on the upload. Larger than any splash needs to be, and small enough
# that a Pi with 1 GB of RAM can hold one in memory while it is hashed.
SPLASH_MAX_BYTES = 2 * 1024 * 1024
SPLASH_FETCH_TIMEOUT_S = 30
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_SPLASH_SHA_RE = re.compile(r"[0-9a-f]{64}")

# C0 controls are stripped, except tab and newline. ESC (0x1b) is the one that matters: /etc/issue
# is rendered by getty BEFORE anyone has logged in, and a stray escape sequence there can leave a
# counter's console cleared, cursor-parked or colour-stuck with no session to fix it from. This
# feature is ASCII ART — it has no legitimate need to drive the terminal.
_BRANDING_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# (sha, path) pairs already reported. A failed write IS retried on every tick — deliberately,
# because the likeliest cause is the missing ReadWritePaths grant above and it then fixes itself
# the moment the unit is corrected — but it is logged ONCE per branding version rather than 2880
# times a day on every device in the fleet.
_BRANDING_LOGGED = set()


def _branding_text(key, value):
    """One pushed text body as the exact text to put on disk, or None if it was not sent.

    Callers MUST test the result with `is None`, the same trap validate_setting documents: "" is
    a legitimate value meaning the operator cleared the field, and that has to blank the file
    rather than leave last month's wording on the console.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        print(f"vigilant-pi-agent: refusing branding {key} of type {type(value).__name__}", flush=True)
        return None
    # A browser textarea submits CRLF. Normalised rather than left alone so the file compares
    # equal on the next tick instead of being rewritten forever, and because a bare CR on a
    # console overprints the line before it.
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = _BRANDING_CTRL_RE.sub("", text)
    if len(text) > BRANDING_TEXT_MAX:
        print(f"vigilant-pi-agent: truncating branding {key} at {BRANDING_TEXT_MAX} chars", flush=True)
        text = text[:BRANDING_TEXT_MAX]
    # Without this the last line of art runs straight into the login prompt.
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def _write_branding_file(path, data, atomic):
    """Write `data` (bytes) only if the file does not already hold exactly that. True if it wrote.

    Raises OSError, which the caller uses to decide whether to record the set as applied: an
    unwritable file has to be retried, never quietly recorded as done.

    THE COMPARISON IS THE POINT — this is an SD card. The server re-sends branding on every tick,
    so an unconditional rewrite would be three flash writes a minute, per device, forever, to put
    back bytes that were already there. Compared by content rather than by the recorded sha, so a
    hand-edit or a truncated file is repaired too once the set next changes.
    """
    try:
        with open(path, "rb") as fh:
            # +1 so a file that merely STARTS with `data` is still seen as different.
            if fh.read(len(data) + 1) == data:
                return False
    except OSError:
        pass                    # missing or unreadable: fall through and try to write it
    if atomic:
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        # 0644: the kiosk launcher runs as the kiosk user and has to read this, exactly as with
        # kiosk.conf and rdp-target.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    else:
        # Truncate in place — see _BRANDING_FILES: /etc is read-only in this unit's namespace, so
        # no sibling temp file can be created next to these. The mode is left as the image
        # shipped it.
        with open(path, "wb") as fh:
            fh.write(data)
    return True


def _read_branding_state():
    """What this device last applied. Missing or corrupt reads as "nothing yet", which is
    self-repairing: the worst case is one extra comparison pass and one set of writes."""
    try:
        with open(BRANDING_STATE) as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


def _write_branding_state(sha, splash_sha256):
    """Record what was applied. Atomic, and only ever reached when something really changed —
    a state file rewritten every tick would be exactly the flash wear this design avoids."""
    try:
        os.makedirs(os.path.dirname(BRANDING_STATE), exist_ok=True)
        tmp = BRANDING_STATE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"sha": sha, "splash_sha256": splash_sha256,
                       "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, fh)
        os.replace(tmp, BRANDING_STATE)
    except OSError as e:
        # Not fatal — the next tick simply redoes the comparisons — but worth a line, because the
        # retry is silent and free where this is neither.
        print(f"vigilant-pi-agent: cannot record branding state in {BRANDING_STATE}: {e}", flush=True)


def fetch_splash(conf, want_sha):
    """The fleet splash PNG as bytes, or None if it cannot be had or cannot be trusted.

    A GET with this device's OWN bearer token — the same one telemetry is reported with.
    AGENT_UA is mandatory here for the reason spelled out in post(): Cloudflare 403s urllib's
    default signature with "error code: 1010" and nothing in the reply mentions the User-Agent.
    """
    import hashlib
    url, token = conf.get("VIGILANT_URL"), conf.get("VIGILANT_TOKEN")
    if not (url and token):
        return None
    req = urllib.request.Request(
        url.rstrip("/") + "/branding/splash",
        headers={"Authorization": f"Bearer {token}", "User-Agent": AGENT_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=SPLASH_FETCH_TIMEOUT_S) as r:
            # Cap PLUS ONE: an oversized body is then DETECTED below rather than silently
            # truncated into a corrupt PNG that this device would happily install.
            body = r.read(SPLASH_MAX_BYTES + 1)
    except Exception as e:
        print(f"vigilant-pi-agent: splash fetch failed: {explain_failure(e)}", file=sys.stderr, flush=True)
        return None
    if len(body) > SPLASH_MAX_BYTES:
        print(f"vigilant-pi-agent: refusing splash — over {SPLASH_MAX_BYTES} bytes", flush=True)
        return None
    # MAGIC BYTES, not Content-Type: the header is whatever a proxy in the path felt like sending,
    # and an HTML error page served with a 200 is precisely what must not reach plymouth.
    if not body.startswith(PNG_MAGIC):
        print("vigilant-pi-agent: refusing splash — not a PNG", flush=True)
        return None
    if hashlib.sha256(body).hexdigest() != want_sha:
        # Telemetry advertised the sha, so a mismatch means these are not the bytes the set was
        # described by. Same check and same refusal as the agent self-update.
        print("vigilant-pi-agent: refusing splash — sha256 does not match the advertised one",
              flush=True)
        return None
    return body


def apply_splash(conf, want_sha):
    """Bring the boot splash into line with `want_sha` (None meaning "no WCN splash").

    Returns (sha256 now on disk or None, ok, wrote). `ok` is False only for a failure a retry
    could fix, which is what stops the set being recorded as applied.

    A MISSING PLYMOUTH IS NOT A FAILURE. Pi OS Lite may not have it installed at all, which is
    why the unit's grant is written ReadWritePaths=-/usr/share/plymouth/themes/pix with the
    optional "-" prefix. The degradation here is "no splash", never "no monitoring".

    No initramfs is regenerated and no plymouth command is run: the pix theme reads this file
    from the rootfs at boot, and a bad PNG simply shows nothing. Anything that rebuilds boot
    artefacts belongs at image bake time for the same reason cmdline.txt does — it is the class
    of mistake that ends in a device that will not boot.
    """
    if want_sha is not None and not _SPLASH_SHA_RE.fullmatch(want_sha):
        # Nothing to retry: the server sent something that is not a sha256, so there is no image
        # this device could go and get.
        print(f"vigilant-pi-agent: refusing malformed splash sha {want_sha!r}", flush=True)
        return _sha256_file(SPLASH_PATH), True, False
    if not os.path.isdir(SPLASH_THEME_DIR):
        print(f"vigilant-pi-agent: no plymouth theme at {SPLASH_THEME_DIR}, skipping splash",
              flush=True)
        return None, True, False
    have_sha = _sha256_file(SPLASH_PATH)
    if want_sha is None:
        # Cleared in Watchman. Restore the image's own splash if we still have it: deleting ours
        # outright would leave a device that used to have a splash booting to a black screen,
        # which reads to whoever is standing at it as a fault rather than as "branding removed".
        if not os.path.exists(SPLASH_BACKUP):
            return have_sha, True, False
        try:
            with open(SPLASH_BACKUP, "rb") as fh:
                orig = fh.read()
            restored = _write_branding_file(SPLASH_PATH, orig, atomic=True)
            if restored:
                print("vigilant-pi-agent: branding splash cleared, restored the image's own",
                      flush=True)
        except OSError as e:
            print(f"vigilant-pi-agent: cannot restore {SPLASH_PATH}: {e}", flush=True)
            return have_sha, False, False
        return _sha256_file(SPLASH_PATH), True, restored
    if have_sha == want_sha:
        return have_sha, True, False   # already correct: no fetch, no write, no flash wear
    img = fetch_splash(conf, want_sha)
    if img is None:
        return have_sha, False, False
    try:
        # Back up the original ONCE, before the first overwrite. Never refreshed afterwards, or
        # the second push would back up our own splash and the image's real one would be gone.
        if have_sha and not os.path.exists(SPLASH_BACKUP):
            shutil.copy2(SPLASH_PATH, SPLASH_BACKUP)
        _write_branding_file(SPLASH_PATH, img, atomic=True)
    except OSError as e:
        print(f"vigilant-pi-agent: cannot write {SPLASH_PATH}: {e}", flush=True)
        return have_sha, False, False
    print(f"vigilant-pi-agent: boot splash -> {want_sha[:12]}… ({len(img)} bytes)", flush=True)
    return want_sha, True, True


def apply_branding(conf, branding):
    """Adopt the fleet-wide branding Watchman sent. True if anything was written to disk.

    `sha` is an OPAQUE token to this agent: it identifies the whole set, and comparing it against
    the recorded one is what makes the overwhelmingly common case — nothing has changed — cost one
    small read and not a single write. The trade that buys is explicit: a local hand-edit to
    /etc/motd is not repaired until the set next changes. On an SD card that is the right way
    round; re-reading three files and re-hashing a 2 MB PNG every 30s on 354 devices to undo an
    edit only root could have made is not.
    """
    if branding is None:
        return False        # a server without this feature, or a device that is not a counter-pi
    if not isinstance(branding, dict):
        print(f"vigilant-pi-agent: ignoring branding of type {type(branding).__name__}", flush=True)
        return False
    sha = branding.get("sha")
    if not isinstance(sha, str) or not 1 <= len(sha) <= 128:
        print(f"vigilant-pi-agent: ignoring branding with unusable sha {sha!r}", flush=True)
        return False
    state = _read_branding_state()
    if state.get("sha") == sha:
        return False        # THE PATH TAKEN EVERY TICK: already applied, so touch nothing at all

    wrote, failed = [], []
    for key, path, atomic in _BRANDING_FILES:
        text = _branding_text(key, branding.get(key))
        if text is None:
            continue        # not sent — leave what is on disk rather than blanking it
        try:
            if _write_branding_file(path, text.encode(), atomic):
                wrote.append(path)
        except OSError as e:
            failed.append(path)
            if (sha, path) not in _BRANDING_LOGGED:
                _BRANDING_LOGGED.add((sha, path))
                print(f"vigilant-pi-agent: cannot write {path}: {e} — if that is a read-only "
                      f"filesystem the unit is missing 'ReadWritePaths=-{path}'", flush=True)

    # "" -> None: an empty string is how a cleared splash can arrive, and it must mean the same
    # thing as the key being null rather than being taken for a sha.
    splash_sha, splash_ok, splash_wrote = apply_splash(conf, branding.get("splash_sha256") or None)
    if splash_wrote:
        wrote.append(SPLASH_PATH)

    if failed or not splash_ok:
        # NOT recorded, so the next tick tries again. Recording a set that only half applied is
        # how the ProtectSystem trap stays invisible for a week: Watchman shows the branding as
        # delivered while the console still says Raspberry Pi OS. No state is written on this
        # path either, so a permanently failing write costs nothing but a log line per version.
        return bool(wrote)
    _write_branding_state(sha, splash_sha)
    print(f"vigilant-pi-agent: branding {sha[:12]}… applied "
          f"({', '.join(wrote) if wrote else 'no file needed changing'})", flush=True)
    return bool(wrote)


def clear_failed_units():
    """Clear systemd's failed state, and restart only what is MEANT to be running.

    THE UNIT NAMES COME FROM systemd ON THIS DEVICE, never from the server. That is the whole
    reason this is one named action rather than a "restart <unit>" the server parameterises:
    the server still sends a single word it cannot vary, so this cannot become a way to start
    an arbitrary unit on a pharmacy counter. Same rule as ACTIONS itself.

    RESET IS NOT RESTART, and the difference matters here. `wcn-support-vnc` is on-demand: it is
    started for a support session and stopped when it ends, and x11vnc exiting non-zero on
    SIGTERM leaves the unit sitting in `failed` afterwards. Restarting THAT would begin sharing a
    live counter's screen because someone clicked "fix" — the opposite of what was asked for. So
    every failed unit has its state cleared, and only units systemd says are `enabled` — the ones
    meant to run continuously — are actually restarted.
    """
    out = run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    names = [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("0 loaded")]
    if not names:
        print("vigilant-pi-agent: clear-failed: nothing is in a failed state", flush=True)
        return
    # A HARD AGGREGATE BUDGET. Every other service action is one `run(cmd, timeout=25)`, so 25s
    # was the ceiling on how long ANY action could occupy the agent. This one makes up to 16*3
    # subprocess calls, and run() swallows a timeout rather than raising, so without a budget a
    # Pi whose systemctl calls hang would sit here for minutes. That matters more than it looks:
    # this runs inside the single-threaded tick, and support_vnc_tick() — the ONLY thing that
    # ends a screen-sharing session whose time is up — does not run until the tick returns.
    # Blocking here would turn a support session's duration into a suggestion. Idempotent, so a
    # truncated pass simply finishes on the next click.
    deadline = time.monotonic() + 25
    cleared, restarted, skipped, ranout = [], [], [], False
    for unit in names[:16]:
        if time.monotonic() > deadline:
            ranout = True
            break
        # Re-validated even though systemd produced it: this is the side that turns a string into
        # argv, and a unit name is the one part of this that is not a literal in this file. The
        # leading character is constrained separately because systemd permits names beginning
        # with '-' (`-.mount`, `-.slice`), and `systemctl reset-failed -Hfoo.service` would have
        # the name eaten as the --host option. Belt and braces: '--' is passed as well.
        if not re.fullmatch(r"[A-Za-z0-9_@][A-Za-z0-9_.@-]*\.[a-z]+", unit or ""):
            print(f"vigilant-pi-agent: clear-failed: skipping odd unit name {unit!r}", flush=True)
            continue
        run(["systemctl", "reset-failed", "--", unit], timeout=10)
        cleared.append(unit)
        # `is-enabled` answers whether the unit FILE is installed, NOT whether it is a service
        # meant to stay running — every Type=oneshot unit with an [Install] section says
        # "enabled" too, and `systemctl restart` on an inactive oneshot RE-RUNS its ExecStart.
        # On a counter that could mean re-running a boot-time task mid-shift. Restart only a
        # long-running service: enabled AND not oneshot.
        enabled = run(["systemctl", "is-enabled", "--", unit], timeout=8).strip()
        utype = run(["systemctl", "show", "-p", "Type", "--value", "--", unit], timeout=8).strip()
        if enabled == "enabled" and utype != "oneshot":
            run(["systemctl", "restart", "--", unit], timeout=20)
            restarted.append(unit)
        else:
            skipped.append(unit)
    print("vigilant-pi-agent: clear-failed: cleared %s%s%s%s" % (
        ", ".join(cleared) or "nothing",
        ("; restarted " + ", ".join(restarted)) if restarted else "",
        ("; left stopped (on-demand or oneshot): " + ", ".join(skipped)) if skipped else "",
        "; ran out of time, run it again to finish" if ranout else "",
    ), flush=True)


# The service actions this device will carry out, and the command for each. The server
# sends only a NAME which is looked up here — it never sends a command line — so a
# compromised or mistaken server cannot turn this into arbitrary execution on a counter.
# An unrecognised name is logged and ignored.
ACTIONS = {
    "reboot": ["systemctl", "reboot"],
    # Cheaper than a reboot and fixes most "the screen is stuck" calls: drops the RDP
    # session and reconnects in about 8 seconds.
    "restart-kiosk": ["systemctl", "restart", "getty@tty1"],
    "restart-agent": ["systemctl", "restart", "vigilant-agent"],
    # A CALLABLE rather than an argv list: what this does depends on what systemd reports on
    # this device, which is exactly the point — the server never names the unit.
    "clear-failed": clear_failed_units,
}


def test_print(queue):
    """Print a page identifying this counter, so whoever is standing at the printer knows
    which thin client produced it — a blank test page proves the queue works but not which
    machine reached it.

    The queue name is re-validated HERE even though the server checks it: this is the side
    that turns it into argv, and a queue name is the one part of the action a caller could
    influence. subprocess takes a list, so there is no shell to inject into either.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", queue or ""):
        print(f"vigilant-pi-agent: refusing malformed print queue {queue!r}", flush=True)
        return
    body = (
        "Vigilant test print\n"
        "===================\n\n"
        f"host:   {socket.gethostname()}\n"
        f"queue:  {queue}\n"
        f"target: {read_configured_target() or 'not set'}\n"
        f"time:   {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n\n"
        "If you can read this, the queue and the printer are both working.\n"
    )
    try:
        p = subprocess.run(["lp", "-d", queue, "-t", "vigilant-test"],
                           input=body, capture_output=True, text=True, timeout=25)
        out = (p.stdout or p.stderr or "").strip()
        print(f"vigilant-pi-agent: test print -> {queue}: {out or 'submitted'}", flush=True)
    except Exception as e:
        print(f"vigilant-pi-agent: test print failed: {type(e).__name__}: {e}", flush=True)


def run_action(name):
    """Carry out a one-shot action the server handed us.

    The server has ALREADY cleared it before sending, so this runs at most once per
    request — deliberately, because a reboot directive that survived delivery would be
    collected again as the Pi came back up and the counter would reboot forever.
    """
    if not isinstance(name, str):
        return
    name = name.strip()
    # The only parameterised action: 'test-print:<cups queue>'. Split on the FIRST colon so a
    # queue name containing one is still passed through intact to be validated, rather than
    # being silently truncated into a different queue.
    if name.startswith("test-print:"):
        return test_print(name.split(":", 1)[1])
    cmd = ACTIONS.get(name)
    if not cmd:
        print(f"vigilant-pi-agent: ignoring unknown action {name!r}", flush=True)
        return
    # An entry is either a fixed command line or a function on this file. Both are literals
    # here; the server only ever chose which one by name.
    if callable(cmd):
        print(f"vigilant-pi-agent: service action '{name}'", flush=True)
        cmd()
        return
    print(f"vigilant-pi-agent: service action '{name}' -> {' '.join(cmd)}", flush=True)
    run(cmd, timeout=25)


# ── the PMR control plane on this device: JOBS ───────────────────────────────
# THE SAME RULE AS ACTIONS ABOVE, written out again rather than pointed at, because a reader
# who arrives at this table has to be able to check it here: the server sends only a NAME
# which is looked up in PMR_VERBS below — it never sends a command line, a path, a URL or a
# filename — so a compromised or mistaken server cannot turn this into arbitrary execution on
# a counter. A name that is not a key in that table is REFUSED and reported as refused. It is
# never guessed at, never prefix-matched, and never falls through to anything.
#
# Arguments are DATA. Every one is checked HERE, against the same closed bool/enum/range specs
# validate_setting() already uses, before it could become argv — exactly as test_print
# re-checks its queue name and relay_target re-checks its session target. "The server already
# validated it" is not a reason to skip that: it is precisely the assumption that would make a
# compromised server dangerous. None of today's three verbs takes an argument at all, so the
# check below is currently a refusal of everything — which is the correct shape for a table
# whose whole point is that it is closed.
#
# ── WHY A JOB IS NOT AN `action` ────────────────────────────────────────────
# An `action` is fire-and-forget: the server clears it as it hands it over, nobody
# acknowledges it, and nothing ever checks that it happened. A JOB has a ladder —
# pending, claimed, applied, CONFIRMED — and the top rung is the point of the whole thing: a
# job is done only when a reading taken afterwards shows the world really changed. This
# agent's part of that ladder is exactly two things, and neither of them is deciding a job
# worked:
#
#   * carry the verb out, ONCE, and
#   * say honestly what happened — applied, or failed and why.
#
# 'confirmed' is a word this device may never write, and there is no code path below that
# posts it: PMR_REPORTABLE is {applied, failed}, mirroring the server's own closed set. An
# executor can say it ran the thing; it can never say the thing is true.
#
# ── ⚠️ HANDING A JOB OUT IS THE CLAIM ───────────────────────────────────────
# There is no ack on the telemetry reply, so a job an agent cannot parse is not ignored — it
# is SWALLOWED: claimed, never run, never reported, expired at its deadline, and the
# pre-opening check then emails "this counter may not open" about a perfectly healthy one.
# That is why the server refuses to hand a counter job to an agent reporting agent_version
# below 2, and why bumping build_payload's "agent_version" to 2 is the LAST line of this
# feature rather than the first. The floor is only honest while the branch below actually
# works.
#
# ⭐ AND "ACTUALLY WORKS" IS A PROPERTY OF TONIGHT, NOT OF THE BUILD. The code being right is
# only half of it: this branch cannot honour anything without a writable ledger, and an SD
# card that has remounted read-only takes that away from a device whose code is perfect. So
# the claim is not a constant — pmr_agent_version() re-proves the ledger BY WRITING IT on
# every tick and claims 2 only when that write succeeded, dropping to 1 (boot, settings and
# action, none of which need a ledger) when it did not. Same idea, same shape and the same
# comments as job_branch_ready() in the Proxmox collector.
#
# ── ⚠️ ONE INTERRUPTION PER TICK ────────────────────────────────────────────
# Two of the three verbs cost a member of staff their session, and so do the boot target and
# the session settings. apply_boot_target already reasons about this for its own pair — "a
# settings change written earlier in the same tick can be folded into this one restart
# instead of causing a second" — and the job branch joins the SAME arrangement rather than
# opening a second one. Nothing below restarts anything on its own; the verbs that need the
# session dropped record that they need it and return "deferred", tick() performs the ONE
# restart, and pmr_settle() then turns "deferred" into applied or failed according to what
# actually happened. A counter with a boot-target change and a session-restart job on the
# same tick is interrupted once.
#
# ── ⚠️ IDEMPOTENCE, AND WHERE IT LIVES ──────────────────────────────────────
# A job whose result POST is lost is RE-OFFERED once its claim lapses (counter.session-restart
# is retry_ok with up to 3 attempts). Restarting the session a second time because an
# acknowledgement went missing is a second sign-out that changes nothing, so the outcome is
# written to a small on-disk LEDGER, keyed by the server's job id, BEFORE it is reported. A
# job id already in the ledger with a settled outcome is never carried out again — its
# recorded outcome is simply re-sent. The ledger is also what makes the result POST safe to
# retry at all: it is retried on every later tick until the server acknowledges it, and the
# retry re-sends a recorded fact rather than repeating an act.
#
# The one hole, named rather than papered over: if the ledger file itself is lost (a wiped
# /var/lib, a reimage), a re-offered session restart WOULD run a second time. That is the
# cheapest of the failure directions — one extra sign-out at 00:05 — and it cannot touch the
# other two verbs, because the server never re-offers a reboot or a promote (retry_ok false,
# max_attempts 1).
# ⚠️ THE TWO LEVELS THIS AGENT MAY CLAIM, and which one goes into the payload is decided
# every tick by pmr_agent_version() — never by this file being the build that implements the
# branch. 2 says "hand me counter jobs"; 1 says "boot, settings and action only", which is
# what an agent with an unwritable ledger honestly is. The floor is only a protection while
# the number is earned, so the number is worked out from a proof and not from a constant.
PMR_JOB_AGENT_VERSION = 2
PMR_BASE_AGENT_VERSION = 1
PMR_JOB_LEDGER = "/var/lib/wcn/pmr-jobs.json"
# Under /var/lib for the same two reasons as TARGET_FILE and BRANDING_STATE: it is
# server-related state rather than hand-edited configuration, and /etc is READ-ONLY inside
# this unit's ProtectSystem=full namespace.
PMR_LEDGER_MAX = 64          # bounded file on a device with an SD card
PMR_LEDGER_KEEP_S = 7 * 86400
# ⛔ ONE JOB PER TICK, BECAUSE THAT IS WHAT THIS CHANNEL SENDS. The counter channel's reply
# carries `pmr_job`, one object, from a claim (claimPmrJobForDevice) that is singular by
# construction. A ceiling of four was a bound on a shape that does not exist here, and on a
# device where a job costs a member of staff their session it is a bound worth having be the
# shape: see pmr_jobs_from_reply for why the `jobs` array is refused rather than accepted.
PMR_JOBS_PER_TICK = 1
PMR_RESULT_PATH = "/pmr/job-result"
PMR_LOG_MAX = 480
# The server's ids are UUIDs and it refuses anything else (isUuid in the store), so this side
# refuses anything else too — the id is the only field of a job that this agent puts back on
# the wire, and a bounded shape is what keeps it from carrying anything.
PMR_JOB_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# The closed set an EXECUTOR may report. Mirrors EXECUTOR_REPORTABLE_STATUSES on the server;
# the important word is the one that is NOT in it.
PMR_REPORTABLE = ("applied", "failed")
# HTTP codes that mean "stop trying": the server has an opinion and re-sending will not change
# it. 404 is the ordinary one — recordPmrJobResult only matches a job still in 'claimed', so a
# result the server already recorded comes back 404, and re-sending it forever would be noise.
PMR_TERMINAL_HTTP = frozenset((400, 404, 409, 410, 422, 501))


def _pmr_ledger_read():
    """What this device has already done about which job ids.

    A missing or corrupt file reads as EMPTY, and the consequence of that is stated in the
    block above rather than hidden here: the outcomes are lost and a re-offered session
    restart would run again. Entries whose id is not a well-formed job id are dropped on the
    way in, so nothing hand-edited into this file can reach the result POST."""
    try:
        with open(PMR_JOB_LEDGER) as fh:
            data = json.load(fh)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data
            if isinstance(e, dict) and isinstance(e.get("id"), str)
            and PMR_JOB_ID_RE.match(e["id"])]


def _pmr_ledger_write(entries):
    """Persist the ledger. Atomic, and FSYNCED — unlike the branding state file, this one is
    written immediately before `systemctl reboot`, so "it was in the page cache" is not good
    enough: the entry that survives the reboot is the only record that the reboot was ours."""
    try:
        os.makedirs(os.path.dirname(PMR_JOB_LEDGER), exist_ok=True)
        tmp = PMR_JOB_LEDGER + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(entries[-PMR_LEDGER_MAX:], fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, PMR_JOB_LEDGER)
        return True
    except OSError as e:
        # Loud, because the retry is silent and free where this is neither: without the ledger
        # a lost acknowledgement becomes a second sign-out.
        print(f"vigilant-pi-agent: cannot record pmr job state in {PMR_JOB_LEDGER}: {e}", flush=True)
        return False


def _pmr_ledger_get(entries, job_id):
    for e in entries:
        if e.get("id") == job_id:
            return e
    return None


def _pmr_ledger_put(entries, entry):
    for i, e in enumerate(entries):
        if e.get("id") == entry["id"]:
            entries[i] = entry
            return entries
    entries.append(entry)
    return entries


def _pmr_ledger_open():
    """Read the ledger AND PROVE IT CAN BE WRITTEN, BY WRITING IT. Returns the entries, or
    None if this device cannot record a job outcome right now.

    ⭐ THE PROOF IS THE WRITE, and it is taken again on every tick. A permission bit is not
    the fault this exists for: a counter Pi's SD card remounts read-only under I/O error —
    the very fault this agent reports elsewhere as `rootfs_readonly` — and after it, /var/lib
    is a directory that still looks fine and accepts nothing. The only thing that separates
    "we can start a job" from "we can finish one" is a completed fsynced replace, so that is
    what is done here.

    The cost is one small fsynced replace per tick, which is the price of the claim in the
    payload being earned rather than asserted."""
    entries = _pmr_ledger_read()
    if not _pmr_ledger_write(entries):
        return None
    return entries


def pmr_job_branch_ready(conf, entries):
    """Is this device genuinely able to take a counter job on this tick?

    All three, every tick — it can be spoken to and can answer (enrolled), the tool every verb
    in its own table ends in is here, and the ledger that makes execution once-only is open
    and WRITABLE. Only then is PMR_JOB_AGENT_VERSION claimed.

    Modelled on job_branch_ready() in the Proxmox collector, and for the same reason: handing
    a job out IS the claim, there is no ack on the telemetry reply, so a job an agent cannot
    honour is not ignored, it is SWALLOWED — claimed, never run, never reported, expired at
    its deadline, and the pre-opening check then emails about a healthy counter. Not being
    offered work is always better than being offered work that cannot be finished."""
    if not (conf.get("VIGILANT_URL") and conf.get("VIGILANT_TOKEN")):
        return False, "this device is not enrolled, so no job outcome could be reported"
    if not shutil.which("systemctl"):
        return False, ("`systemctl` is not on PATH, so no verb in this device's table can be "
                       "carried out")
    if entries is None:
        return False, (f"{PMR_JOB_LEDGER} cannot be written, so an outcome could not be "
                       "recorded and a re-offer could not be told apart from a first offer")
    return True, None


def pmr_agent_version(conf):
    """The version this payload may honestly claim, and the ledger proof that earns it.

    ⚠️ WHY THIS RETURNS 1 RATHER THAN OMITTING THE KEY, which is where it departs from the
    collector it copies. There, collector_version gates ONE channel, so omitting it is exactly
    right. Here the same integer gates FOUR: `pmr_job` is floored at PMR_JOB_AGENT_VERSION,
    but boot, settings and action are floored at 1 (COUNTER_CHANNEL_AGENT_FLOOR) and need no
    ledger, no once-only guarantee and no result POST — they are the capabilities this agent
    had before the job branch existed and it still has all three. Omitting the key yields null
    server-side, null meets no floor, and a counter with a read-only SD card would also stop
    being told which VM to boot into. So the rule is the collector's rule applied to a number
    that means more than one thing: claim the HIGHEST level actually proved, never a level
    that is merely hoped for. The job channel closes; the three that were never in doubt stay
    open.

    The proved ledger is handed on through conf, so that the tick that CLAIMS the capability
    and the tick that USES it are working from the same act. It is assigned on every path,
    including the failing ones, so a proof from an earlier tick can never be found here."""
    conf["_pmr_ledger"] = None
    entries = None
    if conf.get("VIGILANT_URL") and conf.get("VIGILANT_TOKEN") and shutil.which("systemctl"):
        entries = _pmr_ledger_open()
        conf["_pmr_ledger"] = entries
    ready, why_not = pmr_job_branch_ready(conf, entries)
    if ready:
        return PMR_JOB_AGENT_VERSION
    # Said out loud every tick it is true. "The nightly restart never lands on this counter"
    # is otherwise diagnosed as a broken queue on the server, when the answer is here.
    print(f"vigilant-pi-agent: NOT offering to take counter jobs this tick — {why_not}",
          flush=True)
    return PMR_BASE_AGENT_VERSION


def _pmr_rebooted_since(ts):
    """Can this device SEE that it restarted after `ts`? Uptime against wall time, which is
    the same test the server's own 'pi-uptime-reset' confirmation makes — a Pi that ignored a
    reboot is also online and also reporting, so "I am here" proves nothing.

    A counter Pi has no RTC, so a clock that went backwards over the reboot yields a negative
    age; that arm falls back to "the uptime is small enough that this is plainly a fresh
    boot" rather than concluding anything from a timestamp it cannot trust."""
    up = uptime_s()
    if not isinstance(up, (int, float)):
        return False
    age = time.time() - (ts or 0)
    if age < 0:
        return up < 900
    return up < age + 120


# ── the verb implementations ────────────────────────────────────────────────
# Each returns (status, log). 'deferred' is not a status the server has ever heard of and is
# never reported — it means "everything except the interruption is done; tick() owns that".

def _pmr_session_restart(job, plan):
    """counter.session-restart — drop the RDP session so the member of staff signs out and
    back in. The server's own note for this verb: "the Pi maps this name to its own local
    unit restart, exactly as ACTIONS maps restart-kiosk".

    IT DELIBERATELY RESTARTS NOTHING HERE. The restart is recorded as WANTED and performed
    once by tick(), so that a boot-target change or a session-settings change arriving on the
    same tick costs this counter one interruption rather than two or three."""
    plan["want_session_restart"] = True
    plan["deferred"].append(job["id"])
    return "deferred", "session restart folded into this tick's single kiosk restart"


def _pmr_reboot(job, plan):
    """counter.reboot — restart the thin client. Deferred for a second reason as well as the
    coalescing one: a reboot ends this process, so it must be the LAST thing that happens in a
    tick or it would swallow a queued service action and this tick's own job reports."""
    plan["want_reboot"] = job["id"]
    plan["deferred"].append(job["id"])
    return "deferred", "reboot deferred to the end of this tick"


def _pmr_printing_promote(job, plan):
    """counter.printing-promote — swap the staged printer table live and restart the session
    as ONE action.

    ⭐ IT SHELLS OUT TO THE VERB THE DEVICE ALREADY HAS. wcn-toolbox-priv implements
    `printing-promote`: it re-validates printers.tab.next against the §2 rules, keeps
    printers.tab.prev, swaps the live file atomically and kicks the session — with every
    failure path leaving the live set and the session alone. None of that is reimplemented
    here and none of it should be; this agent only chooses the NAME, and the argv below is a
    fixed literal pair with no value from the network anywhere in it. The three paths it
    touches are literals in that script, so the server chooses neither the bytes' destination
    nor the moment they are validated.

    The kick is INSIDE that verb, inseparable from the swap, which is why this one verb does
    interrupt the counter from here instead of deferring. It is still ONE interruption, and
    the flag below is how: plan["session_interrupted"] tells tick() the tick's single teardown
    has already been spent, so the restart it would otherwise issue a moment later is folded
    into this one instead of landing on a session that is already coming back up. A promote
    that reports "left alone" spent nothing and sets nothing."""
    if not os.path.exists(TOOLBOX_PRIV):
        return "failed", f"{TOOLBOX_PRIV} is not installed on this counter"
    try:
        r = subprocess.run([TOOLBOX_PRIV, "printing-promote"],
                           capture_output=True, text=True, timeout=120)
    except Exception as e:
        return "failed", f"printing-promote did not complete: {type(e).__name__}: {e}"
    out = " ".join(((r.stdout or "") + " " + (r.stderr or "")).split())
    if r.returncode != 0:
        # Its own refusals arrive here verbatim — "nothing to promote", "refusing to promote"
        # after the pre-flight validation, "the live set was not touched". Reported as the
        # failure they are, never smoothed into a success.
        return "failed", f"wcn-toolbox-priv printing-promote exited {r.returncode}: {out or 'no output'}"
    # "printers already current ... session left alone" is a success that cost nobody a
    # session, and the difference is worth carrying so the log does not claim an outage.
    if "left alone" not in out:
        plan["session_interrupted"] = True
    return "applied", out or "printers promoted"


# THE DEVICE'S OWN TABLE. Keys are the verb names the server may send; nothing outside this
# object can run. `args` is the closed per-verb argument spec in validate_setting's
# (kind, default, allowed) shape — empty on all three of today's verbs, which means every one
# of them refuses any argument at all.
#
# `acts_here` says whether the verb CHANGES THE DEVICE inside pmr_run_jobs' loop, as opposed
# to recording what it needs and leaving the doing to tick(). It is what decides whether the
# ledger has to be proved writable immediately before the call: a verb that only writes to the
# plan can be settled later, but a verb that tears a session down cannot be un-done if the
# record of it will not go to disk.
PMR_VERBS = {
    "counter.session-restart":  {"run": _pmr_session_restart,  "args": {}, "acts_here": False},
    "counter.reboot":           {"run": _pmr_reboot,           "args": {}, "acts_here": False},
    "counter.printing-promote": {"run": _pmr_printing_promote, "args": {}, "acts_here": True},
}


def pmr_new_plan():
    """What this tick's jobs need from tick(). Never a shared module-level object: a plan
    carries job ids, and one leaking into the next tick would settle a job twice."""
    return {"want_session_restart": False, "want_reboot": None,
            "session_interrupted": False, "deferred": [], "ran": 0}


def pmr_validate_args(spec, args):
    """The arguments of one job against one verb's closed spec. Returns None if they are
    acceptable, or the sentence explaining the refusal.

    Refuses rather than coerces, and refuses UNKNOWN keys rather than dropping them: an
    argument this build does not understand means the two sides disagree about what the verb
    does, and carrying it out on the half we recognise is how a partially-understood
    instruction becomes a wrong one. Fail closed, report the refusal, let a person look."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return "args must be a JSON object"
    allowed = ", ".join(sorted(spec)) or "no arguments"
    for key in sorted(args):
        if key not in spec:
            return f"unexpected argument {key!r} — this verb takes {allowed}"
        if validate_setting(spec[key], args[key]) is None:
            return f"argument {key!r} is the wrong type or out of range"
    for key in sorted(spec):
        if key not in args:
            return f"missing argument {key!r}"
    return None


def pmr_jobs_from_reply(parsed):
    """The control-plane jobs carried by a telemetry reply, as a bounded list of
    {id, verb, args}.

    ABSENT-NOT-NULL, the convention the rest of this reply already uses: the server omits the
    key on the ~2,879 ticks out of 2,880 that carry no job, so an absent key and an empty
    array both mean "nothing to do" and neither is an error.

    ⛔ ONE KEY, AND IT IS THE ONE THIS CHANNEL SENDS. `pmr_job` — a single object, from a
    claim that is singular server-side — is the whole of the counter channel's job shape. The
    `jobs` ARRAY belongs to the Proxmox node channel, on a reply to a POST this agent never
    makes, and it was accepted here only because "this side should not care which shape it is
    handed" sounded like tolerance. It is not tolerance on this device: every verb in
    PMR_VERBS costs a member of staff at a counter their session, so accepting the array
    widened what one reply can do to this pharmacy from ONE interruption to four, and bought
    no capability that anything on the wire actually uses. Narrowed deliberately — the reach
    of a channel should be what it sends, not what a parser could be made to swallow.

    A `jobs` key arriving here at all is therefore a disagreement about what this channel is,
    and it is said out loud rather than dropped in silence. If the counter channel is ever
    given the array form, widening it back is a deliberate edit that also owes this file a way
    to REPORT the jobs it will not run — the loud line below cannot do that, because a claimed
    job with no result is exactly what the whole ladder exists to prevent.

    NOTHING IS EXECUTED HERE and nothing is trusted. An entry with no usable id is dropped
    with a log line, because there is nothing to report a refusal AGAINST; an entry that has
    an id keeps it whatever else is wrong with it, so that the refusal can be reported."""
    out, seen = [], set()
    if not isinstance(parsed, dict):
        return out
    raw = []
    one = parsed.get("pmr_job")
    if one is not None:
        raw.append(one)
    if parsed.get("jobs") is not None:
        print("vigilant-pi-agent: refusing a 'jobs' key on the counter channel — this device "
              "takes one job per tick, on 'pmr_job'. Nothing from it has been run", flush=True)
    for item in raw:
        if len(out) >= PMR_JOBS_PER_TICK:
            print(f"vigilant-pi-agent: refusing more than {PMR_JOBS_PER_TICK} jobs on one "
                  "tick — the rest are left unclaimed", flush=True)
            break
        if not isinstance(item, dict):
            print(f"vigilant-pi-agent: ignoring malformed job entry ({type(item).__name__})", flush=True)
            continue
        jid = item.get("id")
        if not isinstance(jid, str) or not PMR_JOB_ID_RE.match(jid.strip()):
            print(f"vigilant-pi-agent: ignoring a job with no usable id ({jid!r}) — "
                  "there is nothing to report a refusal against", flush=True)
            continue
        jid = jid.strip()
        if jid in seen:
            # Handing a job out IS the claim, so it is handed out once; a repeat inside one
            # reply is a server-side mistake and running it twice is the expensive reading.
            print(f"vigilant-pi-agent: ignoring a repeat of job {jid} in the same reply", flush=True)
            continue
        verb = item.get("verb")
        out.append({
            "id": jid,
            # Kept as whatever arrived when it is not a string, so the refusal below names it.
            "verb": verb.strip() if isinstance(verb, str) else verb,
            "args": item.get("args"),
        })
        seen.add(jid)
    return out


def pmr_run_jobs(conf, parsed):
    """Carry out this tick's jobs — everything about them except the interruption — and
    return what tick() has to do next.

    Every outcome is written to the ledger BEFORE it is reported, which is the whole
    idempotence story: a job id already settled here is never carried out a second time, and
    a re-offer (which is what a lost acknowledgement produces) only re-sends what is recorded.
    A ledger entry still sitting at 'deferred' is the one exception: nothing was done for it
    yet, so it is re-attached to this tick's plan — safe precisely because the two deferring
    verbs perform no work of their own."""
    plan = pmr_new_plan()
    # The ledger build_payload proved writable a moment ago, on the tick that made the claim
    # this reply is answering. POPPED, never left behind: a ledger is per-tick state and one
    # leaking into the next tick would be a proof taken about a card that has since changed.
    entries = conf.pop("_pmr_ledger", None) if isinstance(conf, dict) else None
    jobs = pmr_jobs_from_reply(parsed)
    if not jobs:
        return plan
    if entries is None:
        # No proof came through — the payload was built elsewhere, or the branch was not
        # claimed at all. Take it now rather than assume it.
        entries = _pmr_ledger_open()
    if entries is None:
        # ⛔ THE LEDGER IS UNWRITABLE AND JOBS ARRIVED ANYWAY. The floor should have stopped
        # this: agent_version went out as 1 for exactly this reason. Reaching here means the
        # card went read-only between the payload and the reply, or a server ignored the
        # claim. NOTHING IS CARRIED OUT — without the ledger a re-offer cannot be told from a
        # first offer, and counter.session-restart is re-offered up to three times, which is
        # three sign-outs of a trading counter.
        #
        # And every job is still ANSWERED, straight from here, because a claimed job with no
        # result is the one outcome this control plane must never produce. The answer needs no
        # ledger: it reports that nothing was done, so re-sending it after a lost
        # acknowledgement repeats a fact and never an act.
        for job in jobs:
            log = (f"refused: {PMR_JOB_LEDGER} cannot be written on this counter, so this "
                   "job could not be recorded before it ran. NOTHING WAS DONE — check the "
                   "SD card, which has most likely remounted read-only.")
            print(f"vigilant-pi-agent: pmr job {job['id']} REFUSED, nothing run: {log}",
                  flush=True)
            code, detail = pmr_post_result(conf, job["id"], "failed", log)
            if not (code is not None and (200 <= code < 300 or code in PMR_TERMINAL_HTTP)):
                print(f"vigilant-pi-agent: pmr job {job['id']} refusal NOT acknowledged "
                      f"({code if code is not None else detail}) — it cannot be re-sent, "
                      "because the ledger it would be re-sent from is the thing that is "
                      "broken. The job will expire server-side, which is also honest: "
                      "nothing happened.", flush=True)
        return plan
    dirty = False
    # The reboot goes last: it ends this process, and a promote or a restart sharing the tick
    # with it must have been carried out and recorded first.
    jobs.sort(key=lambda j: 1 if j.get("verb") == "counter.reboot" else 0)
    for job in jobs:
        known = _pmr_ledger_get(entries, job["id"])
        if known and known.get("status") in PMR_REPORTABLE:
            print(f"vigilant-pi-agent: pmr job {job['id']} was already {known['status']} here "
                  "— NOT running it again, re-sending the recorded outcome", flush=True)
            # Being re-offered means the server never recorded it, so it is due again.
            known["reported"] = False
            dirty = True
            continue
        spec = PMR_VERBS.get(job["verb"]) if isinstance(job["verb"], str) else None
        if spec is None:
            status, log = "failed", (
                f"refused: unknown verb {job['verb']!r} — this device implements "
                + ", ".join(sorted(PMR_VERBS)))
        else:
            bad = pmr_validate_args(spec["args"], job["args"])
            if bad:
                status, log = "failed", "refused: " + bad
            elif spec.get("acts_here") and not _pmr_ledger_write(entries):
                # Cannot make the attempt durable, so do not make it. This verb tears the
                # session down inside the call, and the ledger was proved writable before the
                # payload went out — so a failure HERE means the card changed under us
                # mid-tick. Refused, not attempted, and reported as such.
                status, log = "failed", (
                    f"not attempted: {PMR_JOB_LEDGER} stopped being writable during this "
                    "tick, so this counter could not record the act before making it. "
                    "The live printer table and the session were left alone.")
            else:
                try:
                    status, log = spec["run"](job, plan)
                except Exception as e:
                    # An exception is a failure and is reported as one. It is never allowed to
                    # look like an applied job, and never allowed to end the tick.
                    status, log = "failed", f"{type(e).__name__}: {e}"
        entry = {"id": job["id"], "verb": job["verb"] if isinstance(job["verb"], str) else None,
                 "status": status, "log": (log or "")[:PMR_LOG_MAX],
                 "ts": int(time.time()), "reported": False}
        entries = _pmr_ledger_put(entries, entry)
        dirty = True
        plan["ran"] += 1
        print(f"vigilant-pi-agent: pmr job {entry['id']} {entry['verb']!r} -> "
              f"{status}: {entry['log']}", flush=True)
    if dirty:
        _pmr_ledger_write(entries)
    return plan


def pmr_post_result(conf, job_id, status, log):
    """POST /pmr/job-result — {job_id, status, result_log}. Returns (http status or None,
    detail). The server answers with awaiting_confirmation rather than "done", which is the
    point: this device has said what it did, and something else decides whether it worked."""
    url, token = conf.get("VIGILANT_URL"), conf.get("VIGILANT_TOKEN")
    if not (url and token):
        return None, "not enrolled"
    body = {"job_id": job_id, "status": status, "result_log": (log or "")[:PMR_LOG_MAX] or None}
    try:
        return post(url, token, PMR_RESULT_PATH, body, timeout=15)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read(200).decode(errors="replace")
        except Exception:
            detail = ""
        return e.code, detail
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def pmr_flush_results(conf, entries=None):
    """Re-send every recorded outcome the server has not acknowledged, oldest first.

    Called on EVERY tick, not only on ticks that carried a job: the result POST is the half of
    this exchange that can be lost, and a result sitting unsent is a job on its way to
    expiring. Retrying is safe because what is retried is a recorded fact and not an act."""
    if entries is None:
        entries = _pmr_ledger_read()
    dirty = False
    for e in entries:
        if e.get("reported") or e.get("status") not in PMR_REPORTABLE:
            continue        # 'deferred' has not happened yet; there is nothing to say about it
        status, log = e.get("status"), e.get("log") or ""
        if e.get("verify") == "uptime":
            # ⛔ THE ONE PLACE THIS DEVICE COULD HAVE LIED. The reboot outcome is written
            # before the command is issued, because the command ends this process — so before
            # it is ever SENT, the device checks it can actually see the reboot it is about to
            # claim. A `systemctl reboot` that returned 0 and did nothing is reported as the
            # failure it is, and the pre-opening check gets a person to the counter.
            if _pmr_rebooted_since(e.get("ts")):
                log = e["log"] = f"the thin client rebooted and is back with an uptime of {uptime_s()}s"
                e["verify"] = None
            else:
                status = e["status"] = "failed"
                log = e["log"] = "the reboot was issued but this device did not restart"
                e["verify"] = None
            dirty = True
        code, detail = pmr_post_result(conf, e["id"], status, log)
        if code is not None and (200 <= code < 300 or code in PMR_TERMINAL_HTTP):
            e["reported"] = True
            dirty = True
            print(f"vigilant-pi-agent: pmr job {e['id']} reported {status} (HTTP {code})", flush=True)
        else:
            print(f"vigilant-pi-agent: pmr job {e['id']} result NOT acknowledged "
                  f"({code if code is not None else detail}) — it will be re-sent next tick",
                  flush=True)
    # Prune by AGE alone, and only long after every verb's own ttl (the longest is a day).
    # By this point the server has either recorded the result or expired the job, so an entry
    # this old can prove nothing — including one still marked 'deferred' by a tick that died
    # between carrying a verb out and settling it, which is the only way one can be stranded.
    cutoff = time.time() - PMR_LEDGER_KEEP_S
    keep = [e for e in entries if (e.get("ts") or 0) >= cutoff]
    if dirty or len(keep) != len(entries):
        _pmr_ledger_write(keep)


def pmr_settle(conf, plan, restarted):
    """Turn this tick's deferred jobs into what actually happened, then report everything
    outstanding — and, last of all, reboot if a job asked for it.

    `restarted` is tick()'s answer to "was the counter's session interrupted on this tick",
    whether that came from the boot target, from the session settings or from a job. It is
    the ONE restart, and the deferred session restarts settle against it: applied if it
    happened, failed if it did not. Nothing here reports a restart this device did not see."""
    entries = _pmr_ledger_read()
    dirty = False
    for jid in plan.get("deferred") or []:
        e = _pmr_ledger_get(entries, jid)
        if not e or e.get("status") != "deferred" or jid == plan.get("want_reboot"):
            continue
        if restarted:
            e["status"], e["log"] = "applied", "the kiosk session was restarted"
        else:
            e["status"], e["log"] = "failed", "the kiosk session restart did not run"
        e["ts"], e["reported"] = int(time.time()), False
        dirty = True

    reboot_id = plan.get("want_reboot")
    if reboot_id:
        e = _pmr_ledger_get(entries, reboot_id)
        if e is not None and e.get("status") == "deferred":
            # WRITTEN AND FSYNCED FIRST, because `systemctl reboot` ends this process and an
            # outcome only in memory would be lost with it — leaving a job that was carried
            # out looking to the server exactly like one that was swallowed. The claim is not
            # SENT here: it is sent on the first tick after the device comes back, once
            # _pmr_rebooted_since() has proved there was a reboot to claim.
            e["status"], e["log"] = "applied", "reboot issued"
            e["ts"], e["reported"], e["verify"] = int(time.time()), False, "uptime"
            # ⛔ AND THE REBOOT IS GATED ON THAT WRITE HAVING WORKED. The paragraph above is
            # the whole reason this record exists; issuing the command anyway when the record
            # did not reach the disk produces exactly the outcome it was written to prevent —
            # a counter that went down, an on-disk ledger still reading 'deferred', and a job
            # the server cannot tell from one that was swallowed. counter.reboot is
            # max_attempts 1 and retry_ok false, so it is never re-offered and nobody would
            # ever learn what happened to it.
            #
            # WHICH WAY IT FAILS, STATED: it does not reboot. Refusing leaves a pharmacy
            # counter trading and produces an honest 'failed' that is posted on this very tick
            # (from memory — pmr_flush_results does not need the disk to send), which ends the
            # ladder and puts a person in front of it. The other direction takes the counter
            # down and tells nobody. That is the same choice as never passing --forceStop: the
            # failure direction is "the pharmacy keeps working and somebody is raised".
            if not _pmr_ledger_write(entries):
                e["status"], e["verify"] = "failed", None
                e["log"] = ("the reboot was NOT issued: this counter could not record it "
                            f"first ({PMR_JOB_LEDGER} is unwritable, most likely an SD card "
                            "that has remounted read-only). The device is still up and "
                            "still serving; a reboot it cannot record is a reboot it cannot "
                            "report.")
                print(f"vigilant-pi-agent: pmr job {reboot_id} counter.reboot NOT issued — "
                      f"{e['log']}", flush=True)
                dirty = True
            else:
                print(f"vigilant-pi-agent: pmr job {reboot_id} counter.reboot -> rebooting "
                      "now; the result is sent once this device is back", flush=True)
                try:
                    p = subprocess.run(["systemctl", "reboot"],
                                       capture_output=True, text=True, timeout=25)
                    rc, why = p.returncode, f"systemctl reboot exited {p.returncode}"
                except Exception as ex:
                    rc, why = 1, f"systemctl reboot did not complete: {type(ex).__name__}: {ex}"
                if rc == 0:
                    # Still here only because a reboot takes a few seconds to land. Nothing
                    # more is sent on this arm: the first tick after the device comes back
                    # reports it, and the uptime check there is what decides applied from
                    # failed.
                    return
                # It refused, so this device is not rebooting and must not say that it did.
                e["status"], e["log"], e["verify"] = "failed", why, None
                dirty = True

    if dirty:
        _pmr_ledger_write(entries)
    pmr_flush_results(conf, entries)


def restart_kiosk_session(reason):
    """The tick's ONE interruption of the counter. Returns whether it really happened, which
    is more than `run()` can say — a deferred job settles against this answer, and reporting
    a session restart that systemd refused would be exactly the "it exited 0, so it worked"
    claim the job ladder exists to make impossible."""
    print(f"vigilant-pi-agent: restarting kiosk ({reason})", flush=True)
    try:
        p = subprocess.run(["systemctl", "restart", "getty@tty1"],
                           capture_output=True, text=True, timeout=25)
    except Exception as e:
        print(f"vigilant-pi-agent: kiosk restart did not complete: {type(e).__name__}: {e}", flush=True)
        return False
    if p.returncode != 0:
        print(f"vigilant-pi-agent: kiosk restart exited {p.returncode}: "
              f"{(p.stderr or p.stdout or '').strip()[:200]}", flush=True)
        return False
    return True


# ── support screen sharing ───────────────────────────────────────────────────
# WHY x11vnc AND WHY DISPLAY :0. An engineer supporting a counter needs to see what the
# pharmacist sees, and the pharmacist needs to see that happening. Attaching to the LIVE display
# gives both for free: there is no second desktop, so the person at the counter watches the same
# pixels and can be shown things. A separate virtual display would have made support covert,
# which for a screen holding patient records is the wrong default.
#
# WHAT THIS IS NOT: reachable from the shop. x11vnc binds the WireGuard address ONLY, so the
# sole route in is the hub — the one thing that can already reach this Pi. -noipv6 is not
# optional: without it x11vnc ALSO binds [::] on every interface, and a Pi has link-local
# addresses on eth0 and wlan0, so the port would be live on the pharmacy LAN. There is no host
# firewall on these devices. The bind IS the control.
SUPPORT_VNC_PORT = 5900
SUPPORT_VNC_PASS = "/var/lib/wcn/vnc.pass"
# The unit resolves the X auth file and the wg address itself at start time — neither can be a
# literal here, and neither is visible from inside this process's namespace anyway.
SUPPORT_VNC_UNIT = "wcn-support-vnc"
# ON DISK, deliberately. This used to be a module-level dict, which desynchronised from
# reality every time the agent restarted while the unit kept running: Watchman would then report
# a password x11vnc had never loaded, and the operator got "password check failed". A file is
# also what lets an EXPIRED request stay expired across a restart instead of re-sharing a
# counter's screen every fifteen minutes for ever.
SUPPORT_VNC_STATE = "/var/lib/wcn/support-vnc.state"


def _support_state():
    """{password, until, minutes, expired}. Missing or unreadable reads as "no session", which
    is the safe direction: it can only ever cause a refusal, never an unintended share."""
    try:
        with open(SUPPORT_VNC_STATE) as fh:
            d = json.load(fh)
        return {"password": d.get("password"),
                "until": float(d.get("until") or 0),
                "minutes": int(d.get("minutes") or 0),
                "expired": bool(d.get("expired"))}
    except Exception:
        return {"password": None, "until": 0.0, "minutes": 0, "expired": False}


def _support_write(**kw):
    """Merge and persist. Written via a temp file and os.replace so a torn read can never look
    like a live session with half a password."""
    st = _support_state()
    st.update(kw)
    tmp = SUPPORT_VNC_STATE + ".new"
    with open(tmp, "w") as fh:
        json.dump(st, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SUPPORT_VNC_STATE)
    return st


def _support_forget():
    try:
        os.unlink(SUPPORT_VNC_STATE)
    except OSError:
        pass


def wg_local_ip():
    """This Pi's own address on wg0. Read from the interface, never derived: the estate does not
    follow the 10.255.<idx>.<n> convention the schema once assumed, and a derived address that
    no device answers on is a bug that hides until someone tries to connect."""
    out = run(["ip", "-4", "-o", "addr", "show", "wg0"])
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out or "")
    return m.group(1) if m else None


def _support_xauth():
    """The X authority file the RUNNING Xorg used. Read from /proc rather than assumed: on these
    images /run/wcn-xauth is written empty, and guessing ~/.Xauthority is how screen capture
    silently failed. No Xorg means nothing to share, which is not an error."""
    pids = run(["pgrep", "-x", "Xorg"]).split()
    if not pids:
        return None
    try:
        with open("/proc/%s/cmdline" % pids[0], "rb") as fh:
            argv = fh.read().split(b"\0")
    except OSError:
        return None
    for i, a in enumerate(argv):
        if a == b"-auth" and i + 1 < len(argv):
            return argv[i + 1].decode("utf-8", "replace") or None
    return None


def support_vnc_running():
    """Is OUR support unit active? Deliberately asks systemd about ONE named unit rather than
    looking for x11vnc processes: these Pis also run an unrelated x11vnc.service that shadows the
    display on localhost, and a name-based check made this feature kill it on every tick.

    THIS DISTINCTION IS LOAD-BEARING. These Pis already run an x11vnc.service that shadows the
    kiosk display on localhost, so a bare `pgrep x11vnc` is true when this feature owns nothing,
    and acting on that answer means killing another service's process every tick while systemd
    restarts it. We only ever manage the pid we started."""
    return run(["systemctl", "is-active", SUPPORT_VNC_UNIT]).strip() == "active"


def support_vnc_stop(reason="closed", expired=False):
    """Idempotent, and surgical: kills only the process this feature started. NEVER pkill by
    name — see support_vnc_running()."""
    was = support_vnc_running()
    if was:
        run(["systemctl", "stop", SUPPORT_VNC_UNIT])
    if expired:
        # Remember WHICH request we served. Watchman re-sends the whole effective settings set on
        # every tick, so without this the same `support_vnc_min` would start a new session the
        # moment the last one ended — for ever. Cleared properly when Watchman sends 0, which the
        # UI does when the operator closes the window.
        _support_write(password=None, until=0.0, expired=True)
    else:
        _support_forget()
    if was:
        print("vigilant-pi-agent: support screen sharing stopped (%s)" % reason, flush=True)


def _support_start(minutes, wg_ip):
    """Start x11vnc on the live display for `minutes`, bound to the tunnel address only.

    A FRESH PASSWORD EVERY SESSION, reported UPWARD in telemetry and never accepted downward:
    the settings table is a closed bool/int whitelist and pushing a secret through it would make
    it the first free-text value in a channel whose safety rests on there being none."""
    # NOTE: the X auth file is NOT resolved here. This process runs with PrivateTmp=yes, so
    # /tmp/serverauth.* is invisible to it; the unit does that resolution outside the namespace.
    # EIGHT characters. VNC auth derives its DES key from the first 8 bytes and discards the
    # rest, so a longer secret is not stronger — it is just a password whose tail is a lie.
    # urandom+base64 rather than the secrets module: both are already imported.
    password = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")[:8]
    try:
        rc = subprocess.call(["x11vnc", "-storepasswd", password, SUPPORT_VNC_PASS],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        print("vigilant-pi-agent: x11vnc is not installed", flush=True)
        return False
    if rc != 0:
        print("vigilant-pi-agent: could not store the support password", flush=True)
        return False
    try:
        os.chmod(SUPPORT_VNC_PASS, 0o640)
        shutil.chown(SUPPORT_VNC_PASS, group="westerncomms")
    except OSError:
        pass
    support_vnc_stop(reason="restarting")
    run(["systemctl", "start", SUPPORT_VNC_UNIT])
    # VERIFY, do not assume. An earlier version logged "started" from the fact that spawning
    # returned without raising, and reported success for two minutes while the server was in
    # fact dying instantly. If the unit is not active, say so.
    time.sleep(2)
    if not support_vnc_running():
        print("vigilant-pi-agent: support screen sharing FAILED to start "
              "(journalctl -u %s)" % SUPPORT_VNC_UNIT, flush=True)
        return False
    # Recorded only once the unit is CONFIRMED up, so a failed start never leaves a state file
    # claiming a live session with a password nothing is serving.
    _support_write(password=password, until=time.time() + minutes * 60,
                   minutes=minutes, expired=False)
    print("vigilant-pi-agent: support screen sharing started on %s:%d for %d min"
          % (wg_ip, SUPPORT_VNC_PORT, minutes), flush=True)
    return True


def support_vnc_tick():
    """Reconcile what is running with what Watchman asked for. Every tick.

    EXPIRY IS ENFORCED HERE, on this device, and that is the point: a support session ends
    because the Pi decided the time was up — not because a server remembered to say so, and not
    because someone closed a browser tab. Same reasoning as the relay's own local TTL."""
    want = RUNTIME.get("support_vnc_min") or 0
    st = _support_state()

    if want <= 0:
        # Only if WE have a session. Without this the branch fires on every tick of every Pi
        # that happens to run an unrelated x11vnc, which is how this feature started killing
        # x11vnc.service in a loop.
        if st["until"] or st["expired"] or support_vnc_running():
            support_vnc_stop(reason="turned off in Watchman")
        return

    # A CHANGED duration on a LIVE session: move the deadline and keep the password. Restarting
    # here is what broke "30 minutes" — it rotated the secret Watchman was already showing.
    if want != st["minutes"] and support_vnc_running() and not st["expired"]:
        _support_write(minutes=want, until=time.time() + want * 60)
        print("vigilant-pi-agent: support session duration now %d min "
              "(same password, not restarted)" % want, flush=True)
        return

    # Already served this exact request. Waiting for Watchman to send 0 or a different value is
    # what stops a counter re-sharing its screen every N minutes indefinitely.
    if st["expired"] and want == st["minutes"]:
        return

    if st["until"] and time.time() >= st["until"]:
        support_vnc_stop(reason="session expired", expired=True)
        return

    if not support_vnc_running():
        _support_start(want, wg_local_ip())


def support_vnc_status():
    """For telemetry. The password rides UP only while a session is genuinely live, so Vigilant
    can put it in the short-lived token it signs for the browser. It is a per-session secret for
    a port only the hub can reach, and it dies with the session."""
    st = _support_state()
    if not (support_vnc_running() and st["until"] > time.time()):
        return {"active": False}
    return {
        "active": True,
        "port": SUPPORT_VNC_PORT,
        "expires_in_s": int(st["until"] - time.time()),
        "password": st["password"],
    }

# ── relay: reverse HTTP proxy onto the site LAN ──────────────────────────────
# WHY IT IS SHAPED LIKE THIS. Nothing can dial IN to a Pi: the hub's forward chain is
# policy-drop apart from RDP to the VM range, and Vigilant has no route to the counter subnets
# at all. So an engineer who needs a printer's or a phone's web UI has to send someone to site,
# which is the cost this removes. The Pi is already the only Vigilant-managed thing on that LAN
# and it already dials out, so it dials out for this too.
#
# LONG POLL, not work carried on the telemetry tick: a browser that waited a poll cycle per
# image could never render a page. And plain HTTP request/response, because Vigilant is
# published through a Cloudflare tunnel — no raw TCP, no assumption that a WebSocket survives.
#
# This is a PROXY, not a tunnel, and these are the properties that keep that true:
#   * the target is fixed by the session directive. A browser request supplies a method, a path
#     and a body — never a host. relay_fetch builds every URL from the session's own ip/port.
#   * the Pi re-validates that target itself (relay_target), so a compromised or mistaken
#     server cannot point a counter at something the session did not name. Same reasoning as
#     ACTIONS: the server names a thing, this file decides what that is allowed to mean.
#   * one session per device, a hard local lifetime, bounded bodies, and three workers — never
#     an unbounded pool on a single-core device that also has a pharmacy counter to run.
#   * redirects are NOT followed and proxy_base is ignored, both of which would otherwise be
#     ways to move the Pi's requests (and its bearer token) somewhere else entirely.

# Ports a session may target. The only ones a printer or phone admin UI is on in this estate,
# and the narrowness IS the control: this exists to reach a web UI, not to reach whatever else
# happens to be listening on a pharmacy LAN.
RELAY_PORTS = frozenset((80, 443, 8080, 8443))

# Methods a browser may put through. No DELETE and no WebDAV verbs: the jobs this exists for
# are "read a status page" and "save a setting". Anything else is answered locally with a 405
# so the browser gets an immediate answer rather than waiting out the server's 504.
RELAY_METHODS = frozenset(("GET", "HEAD", "POST", "PUT"))

# A device admin page pulls a dozen-plus subresources (css, js, icons, status polls), and each one
# costs a full browser->Vigilant->Pi->device round trip. With three workers they queue four deep
# and the panel feels broken rather than slow. Eight is still bounded — the cap exists so a Pi
# cannot be turned into a load generator against a printer, not because eight sockets are dear —
# and a Pi 3 idles at 0.15 load, so the constraint is latency, not the CPU.
RELAY_WORKERS = 8
RELAY_POLL_TIMEOUT_S = 35       # the server holds /next for 25s — slack for the tunnel, then reconnect
RELAY_FETCH_TIMEOUT_S = 15      # a LAN device that has not answered in 15s is not about to
RELAY_REPLY_TIMEOUT_S = 30      # the reply POST carries the body, so it gets longer than a poll
RELAY_MAX_TTL_S = 600           # mirrors the server's 10-minute TTL; the Pi expires on its own too
RELAY_MAX_RESP_BYTES = 2_000_000   # a device admin page with images; base64 makes this ~2.7 MB on the wire
RELAY_MAX_REQ_BYTES = 1_000_000    # a firmware upload is not what this is for
RELAY_MAX_REQ_B64 = RELAY_MAX_REQ_BYTES * 4 // 3 + 64
RELAY_MAX_ERRORS = 8            # consecutive transport failures before a worker gives the session up
RELAY_ERROR_BACKOFF_S = 3

# The session id is interpolated into the URLs below, so it is held to a charset that cannot
# contain a path segment. Without this, a session_id of '../telemetry' would aim the Pi's own
# authenticated POSTs at another endpoint.
RELAY_SESSION_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
# A request target must be printable ASCII and nothing else: whitespace or a control character
# in the path is a request-splitting primitive, not a URL a browser produced.
RELAY_PATH_BAD_RE = re.compile(r"[^\x21-\x7e]")
RELAY_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
RELAY_HEADER_VALUE_BAD_RE = re.compile(r"[^\x20-\x7e\t]")

# Headers that must not cross the proxy in either direction. The first group is hop-by-hop
# (RFC 7230): they describe the connection they arrived on, not the message. content-length is
# dropped because the body is re-encoded and may be truncated at the cap, so a forwarded length
# would be a lie; host is dropped because it belongs to Vigilant's hostname, not the device's.
RELAY_DROP_HEADERS = frozenset((
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "transfer-encoding", "upgrade", "content-length", "host",
))
# Also dropped from the BROWSER's request:
#   accept-encoding — dropping it leaves http.client to send its own "identity", so the LAN
#                     side is never compressed: the size cap then counts real bytes, and a
#                     truncated page is partly renderable rather than a broken gzip stream.
#
# `cookie` is deliberately NOT dropped, and the original reason for dropping it turned out not to
# hold. It was dropped on the grounds that "those cookies are Vigilant's", but Vigilant's own API
# is bearer-only and sets no session cookie — so the only cookies that can arrive on
# /relay/<id>/p/* are ones a DEVICE set on that path. Dropping them meant a printer could serve
# its login form and issue a Set-Cookie, and then never see the cookie again: every subsequent
# request looked like a brand-new visitor, so no login could ever complete and the panel was
# unusable for anything behind auth. Authorization is likewise forwarded (Basic-auth devices),
# which is safe because the session id — not our field key — now authenticates that path.
RELAY_DROP_REQUEST = RELAY_DROP_HEADERS | {"accept-encoding"}
# And from the DEVICE's response: printer and phone UIs send X-Frame-Options: SAMEORIGIN, which
# makes the browser refuse to render them in Watchman's iframe.
RELAY_DROP_RESPONSE = RELAY_DROP_HEADERS | {"x-frame-options"}
RELAY_CSP_HEADERS = ("content-security-policy", "content-security-policy-report-only")

# The live session, or None. Module level for the same reason RUNTIME is: a directive arrives on
# the telemetry thread and the workers are elsewhere. The lock guards the swap, not the I/O.
RELAY = {"session": None}
_RELAY_LOCK = threading.Lock()
_RELAY_OPENER = None


def _relay_opener():
    """A urllib opener for the LAN side that does NOT follow redirects and does NOT verify TLS.

    Both are deliberate and neither is laziness:
      * Redirects: urllib follows them by default, which would let a device answer 302
        Location: http://anywhere/ and have the Pi fetch it — defeating the fixed target that
        makes this a proxy rather than a tunnel. Not following turns the 3xx into an HTTPError
        we forward to the browser instead, which is what a proxy should do anyway.
      * Certificates: every printer, phone and NAS on these LANs ships a self-signed cert with
        the wrong hostname on it, so verifying would mean the feature never working once. What
        verification would buy is already covered elsewhere — browser-to-Vigilant and
        Vigilant-to-Pi are both TLS — and the leg left unverified here is a cable inside a shop.
    """
    global _RELAY_OPENER
    if _RELAY_OPENER is None:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None     # unhandled -> urllib raises HTTPError, which we forward

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _RELAY_OPENER = urllib.request.build_opener(_NoRedirect,
                                                    urllib.request.HTTPSHandler(context=ctx))
    return _RELAY_OPENER


def _is_site_lan(ip):
    """RFC1918 only.

    NOT the primary control — the server has already checked the address against this site's
    inventory. This is the one that survives the server being wrong. Without it, "open a relay
    to 203.0.113.9:443" would turn 348 pharmacy Pis into an outbound HTTP proxy pool, which is
    a far more attractive thing to steal than a printer's status page. Every site LAN in the
    estate is RFC1918 behind its own router, so nothing legitimate is refused.
    """
    try:
        o = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    return o[0] == 192 and o[1] == 168


def relay_target(directive):
    """(ip, port) this session is allowed to reach, or None with the refusal logged.

    THE local enforcement point. Every URL a worker fetches is this ip and port plus a path, so
    a directive that does not name an in-range site address on an allowed port never becomes a
    session, and no later browser request can widen what a session may touch.
    """
    if not isinstance(directive, dict):
        return None
    raw_ip = directive.get("target_ip")
    ip = raw_ip.strip() if isinstance(raw_ip, str) else ""
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", ip)
    if not m or any(int(g) > 255 for g in m.groups()):
        print(f"vigilant-pi-agent: refusing relay target {raw_ip!r} — not an IPv4 address", flush=True)
        return None
    if not _is_site_lan(ip):
        print(f"vigilant-pi-agent: refusing relay target {ip} — not a site LAN (RFC1918) address", flush=True)
        return None
    port = directive.get("target_port")
    if isinstance(port, str) and port.strip().isdigit():
        port = int(port.strip())
    # isinstance(True, int) again: True must not be read as port 1.
    if isinstance(port, bool) or not isinstance(port, int) or port not in RELAY_PORTS:
        print(f"vigilant-pi-agent: refusing relay port {directive.get('target_port')!r} — "
              f"not one of {sorted(RELAY_PORTS)}", flush=True)
        return None
    return ip, port


def parse_iso8601(value):
    """Epoch seconds for an ISO-8601 UTC timestamp, or None.

    Fractional seconds and the trailing Z or offset are ignored on purpose: this only ever
    feeds a countdown that is clamped to RELAY_MAX_TTL_S, so second precision is ample, a
    non-UTC offset can cost at most an hour that the clamp absorbs, and nothing here depends on
    datetime.fromisoformat, whose handling of 'Z' varies with the Python on the image.
    """
    if not isinstance(value, str):
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", value.strip())
    if not m:
        return None
    try:
        return calendar.timegm(tuple(int(g) for g in m.groups()) + (0, 1, -1))
    except Exception:
        return None


def relay_ttl(directive):
    """How many seconds this session may live locally, clamped to RELAY_MAX_TTL_S.

    ttl_s is preferred over expires_at because a counter's clock is not trustworthy — the
    payload reports ntp_synced precisely because it is sometimes false — and an absolute
    timestamp measured against a skewed clock either expires the session on arrival or never.
    An expires_at is therefore only used as a RELATIVE remainder.
    """
    ttl = directive.get("ttl_s")
    if isinstance(ttl, str) and ttl.strip().isdigit():
        ttl = int(ttl.strip())
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        expires = parse_iso8601(directive.get("expires_at"))
        remaining = int(expires - time.time()) if expires else 0
        # A remainder of zero or less means the clock disagrees with the server, not that the
        # session is over: the server owns expiry and says so with a 410, which ends the
        # session within one poll. Falling back to the cap keeps a badly-timed Pi usable.
        ttl = remaining if remaining > 0 else RELAY_MAX_TTL_S
    return max(1, min(RELAY_MAX_TTL_S, ttl))


def relay_status():
    """The relay's state for telemetry: enough for an operator to answer "is someone inside
    this site's printer right now", and no more. The session id is truncated — the browser and
    the Pi both authenticate separately, so it is not a credential, but there is no reason for
    a full capability reference to sit in a log either."""
    with _RELAY_LOCK:
        sess = RELAY.get("session")
        enabled = bool(RUNTIME.get("relay_enabled"))
        if sess is None:
            return {"enabled": enabled, "active": False}
        return {
            "enabled": enabled,
            "active": True,
            "session": sess["id"][:8],
            "target": f"{sess['ip']}:{sess['port']}",
            "expires_in_s": max(0, int(sess["deadline"] - time.monotonic())),
            "served": sess["served"],
        }


def relay_close(sess=None, reason="closed"):
    """End the current session, or `sess` specifically. Idempotent and safe with none running:
    three workers plus apply_settings all race to call this and only the first announces it."""
    with _RELAY_LOCK:
        current = RELAY.get("session")
        target = sess if sess is not None else current
        if target is None:
            return
        if current is target:
            RELAY["session"] = None
        announce = not target["stop"].is_set()
        target["stop"].set()
        served, sid, where = target["served"], target["id"][:8], f"{target['ip']}:{target['port']}"
    if announce:
        print(f"vigilant-pi-agent: relay {sid}… -> {where} closed after {served} "
              f"request(s) ({reason})", flush=True)


def _relay_worker_done(sess):
    """Last worker out clears the session, so telemetry cannot report an active relay that has
    nobody left polling for it."""
    with _RELAY_LOCK:
        sess["alive"] -= 1
        if sess["alive"] <= 0 and RELAY.get("session") is sess:
            RELAY["session"] = None


def relay_headers(raw, drop):
    """Copy a header map, lower-cased, dropping `drop` and anything that could not have come
    out of a real HTTP message.

    The CR/LF check matters most: these values are handed to urllib as request headers, and one
    containing a newline is header injection. Names, values and count are all bounded so a
    single request cannot become a megabyte of headers either.
    """
    out = {}
    if not isinstance(raw, dict):
        return out
    for name, value in raw.items():
        if len(out) >= 32:
            break
        if not isinstance(name, str) or not RELAY_HEADER_NAME_RE.fullmatch(name):
            continue
        low = name.lower()
        if low in drop:
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or RELAY_HEADER_VALUE_BAD_RE.search(value):
            continue
        out[low] = value[:2048]
    return out


def strip_frame_ancestors(value):
    """A CSP with its frame-ancestors directive removed, '' if nothing is left.

    Only the framing control is taken out, not the whole header: a device that also sets
    script-src or object-src keeps that protection while it is rendered in Watchman's iframe.
    """
    kept = []
    for directive in value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        if directive.split()[0].lower() == "frame-ancestors":
            continue
        kept.append(directive)
    return "; ".join(kept)


def relay_response_headers(headers, truncated):
    """The device's response headers, cleaned for the browser.

    Duplicates collapse to the LAST value, which in practice only affects Set-Cookie; the
    device UIs here set a single session cookie, and inventing a comma-joined cookie header
    would break the login it is needed for.
    """
    out = {}
    for name, value in (headers.items() if headers else ()):
        low = name.lower()
        if low in RELAY_DROP_RESPONSE or not isinstance(value, str):
            continue
        if RELAY_HEADER_VALUE_BAD_RE.search(value):
            continue
        if low in RELAY_CSP_HEADERS:
            value = strip_frame_ancestors(value)
            if not value:
                continue
        out[low] = value[:4096]
    if truncated:
        # Say so, rather than let half a page look like a broken device.
        out["x-vigilant-truncated"] = "1"
    return out


def _relay_text(status, message):
    """A reply generated by the Pi itself rather than by the device. Always text/plain: it is
    read by a person wondering why the iframe is empty."""
    return status, {"content-type": "text/plain; charset=utf-8",
                    "cache-control": "no-store"}, message.encode()


def relay_fetch(sess, job):
    """Perform ONE browser request against this session's target. Returns (status, headers,
    body) and never raises.

    An unreachable device becomes a 502 the operator can read: dropping it silently just makes
    the browser wait out the server's 504 with nothing to show for it.
    """
    method = job.get("method")
    method = method.strip().upper() if isinstance(method, str) else "GET"
    if method not in RELAY_METHODS:
        return _relay_text(405, f"vigilant relay: {method} is not proxied")

    path = job.get("path") if isinstance(job.get("path"), str) else ""
    if not path.startswith("/") or len(path) > 2000 or RELAY_PATH_BAD_RE.search(path):
        return _relay_text(400, "vigilant relay: bad request path")

    body = None
    if method in ("POST", "PUT"):
        raw = job.get("body_b64")
        if isinstance(raw, str) and raw:
            if len(raw) > RELAY_MAX_REQ_B64:
                return _relay_text(413, "vigilant relay: request body too large")
            try:
                body = base64.b64decode(raw)
            except Exception:
                return _relay_text(400, "vigilant relay: request body is not base64")

    headers = relay_headers(job.get("headers"), RELAY_DROP_REQUEST)
    headers.setdefault("user-agent", AGENT_UA)
    # https on the TLS ports only. Nothing in this estate speaks TLS on 80, and guessing wrong
    # costs a 15-second timeout rather than failing cleanly.
    scheme = "https" if sess["port"] in (443, 8443) else "http"
    # ip is a validated dotted quad, port comes from RELAY_PORTS and path is printable ASCII
    # beginning with '/' — so this URL cannot address any host but the session's target.
    url = f"{scheme}://{sess['ip']}:{sess['port']}{path}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _relay_opener().open(req, timeout=RELAY_FETCH_TIMEOUT_S) as r:
            return _relay_read(r.status, r.headers, r)
    except urllib.error.HTTPError as e:
        # A 401, a 404 or a 302 from a printer is a RESPONSE, not a failure, and has to reach
        # the browser intact or its login flow and relative links stop working. (The 3xx lands
        # here because redirects are deliberately not followed — see _relay_opener.)
        return _relay_read(e.code, e.headers, e)
    except Exception as e:
        return _relay_text(502, f"vigilant relay: {sess['ip']}:{sess['port']} did not answer "
                                f"({type(e).__name__})")


def _relay_read(status, headers, stream):
    """Read a bounded body off the LAN response. One byte over the cap is enough to know it was
    truncated, and the cap is what stops a firmware image or an endless stream from being
    base64-expanded into the memory of a 1 GB device."""
    try:
        raw = stream.read(RELAY_MAX_RESP_BYTES + 1)
    except Exception as e:
        return _relay_text(502, f"vigilant relay: response failed mid-read ({type(e).__name__})")
    truncated = len(raw) > RELAY_MAX_RESP_BYTES
    return status, relay_response_headers(headers, truncated), raw[:RELAY_MAX_RESP_BYTES]


def _relay_next(url, token, sid):
    """Hold a GET open on /relay/:id/next until the server has a browser request for us.

    Returns (status, body). An HTTP status is RETURNED rather than raised because 204 and 410
    are both normal parts of this protocol — only the transport failing is exceptional.
    """
    req = urllib.request.Request(
        url.rstrip("/") + f"/relay/{sid}/next",
        headers={"Authorization": f"Bearer {token}", "User-Agent": AGENT_UA},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=RELAY_POLL_TIMEOUT_S) as r:
            return r.status, r.read(RELAY_MAX_REQ_B64 + 8192)
    except urllib.error.HTTPError as e:
        try:
            e.read()
        except Exception:
            pass
        return e.code, b""


def _relay_job(body):
    """The queued browser request out of a /next reply, or None if it is not one.

    request_id is validated here because it is the one field the reply MUST echo: without it the
    server cannot match our answer to the browser that is waiting, so there is nothing useful to
    be done with the rest of the job.
    """
    try:
        job = json.loads(body)
    except Exception:
        return None
    if not isinstance(job, dict):
        return None
    rid = job.get("request_id")
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        return None
    if isinstance(rid, str) and not 0 < len(rid) <= 128:
        return None
    return job


def _relay_worker(sess):
    """One of RELAY_WORKERS long-poll loops. Never raises: a relay that falls over must cost
    the counter nothing, and telemetry is on another thread entirely."""
    url, token = sess["url"], sess["token"]
    errors = 0
    try:
        while not sess["stop"].is_set():
            if time.monotonic() >= sess["deadline"]:
                relay_close(sess, "local TTL expired")
                return
            if not RUNTIME.get("relay_enabled"):
                relay_close(sess, "relay disabled")
                return

            job, why = None, None
            try:
                status, body = _relay_next(url, token, sess["id"])
            except Exception as e:
                status, body, why = None, b"", explain_failure(e)
            if why is None:
                if status == 410:
                    relay_close(sess, "server ended the session")
                    return
                if status in (401, 403, 404):
                    # None of these get better by retrying: the token was rejected, Cloudflare
                    # blocked the poll, or this session does not exist server-side.
                    relay_close(sess, f"server refused the poll (HTTP {status})")
                    return
                if status == 204 or (status == 200 and not body):
                    errors = 0
                    continue        # nothing queued — reconnect at once, that IS the design
                if status != 200:
                    why = f"HTTP {status} from the poll"
                else:
                    job = _relay_job(body)
                    if job is None:
                        why = "poll returned something that is not a job"
            if why is not None:
                # Anything unexpected is BACKED OFF, not retried flat out. Three workers
                # reconnecting in a tight loop against a server that has just started answering
                # 500 is how a small outage becomes a bigger one.
                errors += 1
                if errors >= RELAY_MAX_ERRORS:
                    relay_close(sess, f"{errors} consecutive poll failures ({why})")
                    return
                # Interruptible wait, so a close still takes effect immediately.
                sess["stop"].wait(RELAY_ERROR_BACKOFF_S)
                continue
            errors = 0
            request_id = job["request_id"]
            # Re-checked HERE, after the poll returned rather than only at the top of the loop:
            # a worker can sit in that call for 25 seconds, and a session revoked or expired
            # meanwhile must not get to make one last fetch onto the site LAN. Leaving the close
            # to whichever worker notices next keeps this path to a single decision.
            if (sess["stop"].is_set() or not RUNTIME.get("relay_enabled")
                    or time.monotonic() >= sess["deadline"]):
                return
            # Counted when the request is TAKEN, not when the reply lands: this number exists to
            # answer "is anyone actually inside this device right now", and a request whose reply
            # POST failed still happened on the site LAN. Counting it after the POST also lost
            # the last request of a session to the 410 that ended it.
            with _RELAY_LOCK:
                sess["served"] += 1
            status_out, headers_out, body_out = relay_fetch(sess, job)
            try:
                post(url, token, f"/relay/{sess['id']}/reply",
                     {"request_id": request_id, "status": status_out, "headers": headers_out,
                      "body_b64": base64.b64encode(body_out).decode("ascii")},
                     timeout=RELAY_REPLY_TIMEOUT_S)
            except Exception as e:
                # The browser will get the server's 504 for this one request. That is a bad
                # image, not a reason to tear down a session an engineer is working in.
                print(f"vigilant-pi-agent: relay reply failed: {explain_failure(e)}", flush=True)
    except Exception as e:  # noqa: BLE001 — see the docstring: a worker may not take the agent down
        print(f"vigilant-pi-agent: relay worker stopped: {type(e).__name__}: {e}", flush=True)
    finally:
        _relay_worker_done(sess)


def relay_open(conf, directive):
    """Start a relay session from an 'open-relay' directive. Refuses far more than it accepts."""
    if not RUNTIME.get("relay_enabled"):
        print("vigilant-pi-agent: ignoring relay directive — relay is disabled on this device",
              flush=True)
        return
    url, token = conf.get("VIGILANT_URL"), conf.get("VIGILANT_TOKEN")
    if not (url and token):
        return
    sid = directive.get("session_id")
    sid = sid.strip() if isinstance(sid, str) else ""
    if not RELAY_SESSION_RE.fullmatch(sid):
        print(f"vigilant-pi-agent: refusing malformed relay session id {directive.get('session_id')!r}",
              flush=True)
        return
    target = relay_target(directive)
    if target is None:
        return                      # relay_target has already said why
    ip, port = target

    with _RELAY_LOCK:
        current = RELAY.get("session")
    if current is not None:
        if current["id"] == sid and not current["stop"].is_set():
            return                  # already running — the server re-sends this every tick
        # One session per device, so a new one REPLACES the live one. The same rule the server
        # applies, applied here too so the two cannot disagree about which session is real.
        relay_close(current, "superseded by a new session")

    # proxy_base from the directive is deliberately IGNORED: every request below goes to
    # VIGILANT_URL. A server-supplied base would be a way to make a Pi POST its own bearer
    # token, and the contents of a site's LAN, to somewhere else.
    sess = {
        "id": sid, "ip": ip, "port": port, "url": url, "token": token,
        # monotonic, so an NTP step mid-session cannot extend or kill it.
        "deadline": time.monotonic() + relay_ttl(directive),
        "stop": threading.Event(), "served": 0, "alive": RELAY_WORKERS,
    }
    with _RELAY_LOCK:
        RELAY["session"] = sess
    for i in range(RELAY_WORKERS):
        # Daemon threads: a poll parked for 35 seconds must not hold up a restart, and there is
        # nothing here worth finishing at shutdown.
        threading.Thread(target=_relay_worker, args=(sess,), daemon=True,
                         name=f"relay-{i}").start()
    print(f"vigilant-pi-agent: relay {sid[:8]}… open -> {ip}:{port} for "
          f"{int(sess['deadline'] - time.monotonic())}s, {RELAY_WORKERS} workers", flush=True)


# Relay directives the device will act on, mirroring ACTIONS: the server names a thing and THIS
# file decides what that name is allowed to mean. An unrecognised name is logged and ignored.
RELAY_ACTIONS = ("open-relay", "close-relay")


def relay_directive(conf, directive):
    """Act on the relay part of a telemetry reply.

    Carried on the telemetry reply rather than by a poller of its own — a second poller would
    be a second thing to authenticate, a second thing to break and a second thing for
    Cloudflare to rate-limit.
    """
    if directive is None:
        # Absence is NOT a close. A reply that arrived truncated, or a server mid-deploy that
        # forgets the field for one tick, must not be able to drop a session an engineer is
        # working in; expiry is the server's 410 and the local TTL.
        return
    if not isinstance(directive, dict):
        print(f"vigilant-pi-agent: ignoring relay directive of type {type(directive).__name__}",
              flush=True)
        return
    action = directive.get("action")
    if not isinstance(action, str) or not action.strip():
        # A directive that carries a session and names no action can only mean open; anything
        # else has to say what it is.
        action = "open-relay" if directive.get("session_id") else ""
    action = action.strip()
    if action not in RELAY_ACTIONS:
        print(f"vigilant-pi-agent: ignoring unknown relay action {action!r}", flush=True)
        return
    if action == "close-relay":
        relay_close(reason="closed by Watchman")
        return
    relay_open(conf, directive)


def tick(conf, do_printers):
    """One report. Returns the interval the SERVER asked for, if it gave one."""
    url, token = conf["VIGILANT_URL"], conf["VIGILANT_TOKEN"]
    # limit raised well above post()'s default because this reply is PARSED, not just logged:
    # settings, boot target, action and relay session all ride in it, and at 400 bytes a reply
    # carrying a relay session would be clipped mid-JSON and every directive in it lost. The log
    # line stays short — a long body in the journal helps nobody.
    #
    # Raised again from 8000 when branding arrived: the reply now also carries three free-text
    # bodies (motd, issue, kiosk message), each of which the server caps at 8 KB, and the failure
    # mode is not "the motd is short" but "json.loads fails and the boot target, the settings, the
    # action and the relay session are ALL silently lost". 64 KB is a bounded read, so the memory
    # protection that limit= exists for still holds on a 1 GB device.
    payload = build_payload(conf)
    status, body = post(url, token, "/telemetry", payload, limit=64000)
    print(f"telemetry {status} {body[:400]}", flush=True)
    # Only once the server has ACCEPTED them: a failed POST marks nothing, so the lines are
    # retried on the next tick and the self-healing behaviour is unchanged.
    if status == 200 and payload.get("logs"):
        mark_logs_sent(payload["logs"])
    # A successful report is the ONLY evidence a just-installed agent actually works.
    if status == 200:
        cancel_revert()
        confirm_cmdline_trial()

    # Kept in its own guard: a malformed or unexpected boot directive must not stop the
    # interval negotiation below, or a bad push would also desynchronise the poll cadence.
    settings_interval = None
    try:
        parsed = json.loads(body)
        # ⚠️ THE ORDER OF THIS BLOCK IS A SAFETY PROPERTY, NOT A STYLE. Five of the directives
        # this reply can carry end in a pharmacy counter losing its session, and the counter
        # must be interrupted ONCE per tick however many of them arrive together. So every
        # directive that only WRITES runs first, the single interruption happens in the middle,
        # and the one directive that ends this process runs last of all:
        #
        #   1. settings, branding, printers.tab.next   write only, restart nothing
        #   2. the jobs                                everything about them but the restart
        #   3. the boot target                         writes, and restarts if it changed
        #   4. THE ONE RESTART                         if anything above still needs it
        #   5. the queued service action               at-most-once, so never skipped
        #   6. the relay                               a convenience
        #   7. settle + report the jobs, then reboot   ends the process, so it is last
        #
        # Settings first, because this only WRITES kiosk.conf; the restart it may need is
        # issued at step 4, after the boot target has been written, so that a settings change
        # and a target change landing on the same tick cost the counter one restart, not two.
        kiosk_changed, settings_interval = apply_settings(parsed.get("settings"))
        # Branding BEFORE the action and before any job, so a splash pushed and a reboot
        # requested on the same tick bring the new splash up on that very reboot. It restarts
        # nothing of its own: the kiosk re-reads its message file on the next reconnect, and
        # motd/issue/splash are read at login and at boot, so a wording change never costs a
        # counter its session.
        #
        # Its own guard, as with the relay: branding is cosmetic, and a bad push must not cost
        # this tick its printer report or its interval negotiation. It can also do a 2 MB HTTP GET
        # (only when the splash sha changed), which is one more reason not to let it throw here.
        try:
            apply_branding(conf, parsed.get("branding"))
        except Exception as e:
            print(f"vigilant-pi-agent: branding ignored ({type(e).__name__}: {e})", flush=True)
        # Grouped with branding because it shares branding's property: it restarts NOTHING. It
        # writes printers.tab.NEXT only, so the counter keeps printing exactly as it is until
        # somebody promotes the table deliberately. Its own guard for the same reason as the
        # others — a malformed printer push must not cost this tick its printer report or its
        # interval negotiation.
        #
        # ⭐ AND IT RUNS BEFORE THE JOBS, which is what makes a table staged on this very tick
        # the table a counter.printing-promote job on the same tick actually promotes. The
        # other order would promote the PREVIOUS set and leave the new one staged, having
        # spent the counter's session on it.
        try:
            write_printers_tab_next(parsed.get("printers"))
        except Exception as e:
            print(f"vigilant-pi-agent: printer table ignored ({type(e).__name__}: {e})", flush=True)
        # The control-plane jobs. Carried out here, but INTERRUPTING NOTHING here: a verb that
        # needs the session dropped records that in the plan and the single restart below
        # performs it. Its own guard, like branding and the relay — a malformed job must not
        # cost this tick its boot target, its queued action or its interval negotiation.
        plan = pmr_new_plan()
        try:
            plan = pmr_run_jobs(conf, parsed)
        except Exception as e:
            print(f"vigilant-pi-agent: pmr jobs ignored ({type(e).__name__}: {e})", flush=True)
        restarted = apply_boot_target(parsed.get("boot"))
        # ⭐ THE ONE INTERRUPTION MAY ALREADY HAVE HAPPENED, AND THIS IS WHERE THAT IS READ.
        # counter.printing-promote is the single verb that interrupts from inside the job
        # branch — the kick is inside wcn-toolbox-priv, inseparable from the swap — and it
        # records that as plan["session_interrupted"]. Folding it in here is what keeps the
        # rule at the top of this block true: a promote arriving with new session settings, or
        # with a session-restart job, costs this counter ONE teardown and not two. Without
        # this line the flag was written and never read, and the second teardown landed on a
        # session that was already coming back up.
        #
        # It sets `restarted` rather than merely suppressing the restart, because that is the
        # answer pmr_settle() settles deferred session-restart jobs against: the session DID
        # go down on this tick, so a job that asked for exactly that is applied, not failed.
        #
        # A boot-target change on the same tick is the one case that still costs two, and
        # deliberately: the promote's kick lands before the new target is written, so the
        # session it brings back is pointed at the old VM and genuinely needs the restart
        # apply_boot_target has already made above.
        if plan["session_interrupted"]:
            if not restarted:
                print("vigilant-pi-agent: the printing-promote job already dropped this "
                      "session — folding this tick's restart into it", flush=True)
            restarted = True
        if (kiosk_changed or plan["want_session_restart"]) and not restarted:
            why = "a session-restart job" if plan["want_session_restart"] else "new session settings"
            if kiosk_changed and plan["want_session_restart"]:
                why = "a session-restart job and new session settings, folded into one"
            restarted = restart_kiosk_session(why)
        # Deliberately after the boot target: if both arrive on the same tick, the device
        # should already be pointed at the right VM before it is restarted or rebooted.
        #
        # And deliberately BEFORE the job settle below: takeCounterAction() clears
        # pending_action as it hands it over, so this channel is at-most-once too, and a
        # reboot job that ran first would swallow a queued action outright.
        run_action(parsed.get("action"))
        # Its own guard, inside this one: the relay is a convenience, and a malformed session
        # must not cost the tick the interval negotiation below — nor the printer report.
        try:
            relay_directive(conf, parsed.get("relay"))
        except Exception as e:
            print(f"vigilant-pi-agent: relay directive ignored ({type(e).__name__}: {e})", flush=True)
        # LAST. It records what the restart above really did, re-sends every job result the
        # server has not acknowledged, and only then carries out a reboot job — which ends
        # this process, and so must not be able to skip anything above it.
        try:
            pmr_settle(conf, plan, restarted)
        except Exception as e:
            print(f"vigilant-pi-agent: pmr settle ignored ({type(e).__name__}: {e})", flush=True)
    except Exception as e:
        print(f"vigilant-pi-agent: directive ignored ({type(e).__name__})", flush=True)

    if do_printers:
        printers = collect_printers(conf)
        if printers:
            s, b = post(url, token, "/printers/report", {"printers": printers})
            print(f"printers {s} ({len(printers)} polled) {b}", flush=True)

    # A per-thin-client report_interval_s from Watchman is a deliberate choice for THIS
    # device, so it beats the fleet-wide poll_interval_s below. Already range-checked to
    # 10..900 by the time it gets here.
    if settings_interval:
        return settings_interval

    # The server dictates cadence via poll_interval_s, and we MUST honour it: staleness is
    # judged centrally (STALE_AFTER_S), so an agent reporting slower than the server expects
    # flaps between online and stale forever while being perfectly healthy. Letting the
    # server drive also means the interval can be retuned fleet-wide without touching a Pi.
    try:
        want = json.loads(body).get("poll_interval_s")
        # Floor exists so a server-side misconfiguration cannot turn the fleet into a
        # thundering herd — precisely how the router fleet saturated the ingest.
        #
        # It was 10, which silently broke the server's own fast-poll feature: config.fastPollS
        # is 3, so every fast-poll directive was discarded and `poll_until` did nothing at all.
        # 3 matches that constant, and the window is bounded server-side and opt-in per device,
        # so the herd protection that mattered is still there.
        if isinstance(want, (int, float)) and want >= MIN_POLL_S:
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
    # Zero-touch first boot: the base image ships VIGILANT_URL + a shared bootstrap token but
    # no per-device token, so register ourselves and persist the issued token before the
    # normal missing-key check. Once enrolled the file has VIGILANT_TOKEN and this is skipped.
    if not conf.get("VIGILANT_TOKEN") and conf.get("VIGILANT_BOOTSTRAP_TOKEN") and conf.get("VIGILANT_URL"):
        self_enrol(conf)
    missing = [k for k in ("VIGILANT_URL", "VIGILANT_TOKEN", "VIGILANT_SERIAL") if not conf.get(k)]
    if missing:
        # Fail loudly: a silently misconfigured agent looks identical to a dead device.
        print(f"vigilant-pi-agent: missing {', '.join(missing)} in {CONF}", file=sys.stderr)
        return 2

    interval = int(conf.get("VIGILANT_INTERVAL") or 60)
    # Printers are polled far less often: toner does not move fast, and hammering the SNMP
    # agent on older printers can wedge them.
    printer_every = int(conf.get("VIGILANT_PRINTER_EVERY") or 15)
    # A LAN sweep is far heavier than an SNMP poll, so it runs on its own multiple of the
    # printer pass — every 8th by default, roughly half-hourly at a 30s tick with printers
    # every 15. 0 disables it, for a site where sweeping is unwelcome.
    discover_every = int(conf.get("VIGILANT_DISCOVER_EVERY") or 8)

    # Seed the live cadences from the env file. The loop reads them back out of RUNTIME on
    # every pass, so settings pushed from Watchman take effect on the next tick with no
    # restart; until a server sends any, these env values stand and nothing has changed.
    RUNTIME.update({"report_interval_s": interval,
                    "printer_every": printer_every,
                    "discover_every": discover_every,
                    "screenshot_every": int(conf.get("VIGILANT_SCREENSHOT_EVERY") or 10),
                    # A site that will not have engineers reaching its LAN devices through the
                    # Pi can refuse it at install time with VIGILANT_RELAY=0, and Watchman can
                    # still turn it off live. Only an explicit off value disables it, so an
                    # unset or unparseable value leaves the shipped default in place rather
                    # than silently disabling a feature someone is relying on.
                    "relay_enabled": str(conf.get("VIGILANT_RELAY", "1")).strip().lower()
                    not in ("0", "false", "no", "off")})

    # --once is what a human runs to check an install, so it must report the diagnosis and
    # a usable exit code rather than dumping a traceback. Discovery is included: "did it find
    # the printer" is exactly what someone checks an install for.
    if "--once" in sys.argv:
        conf["_discover"] = discover_every > 0
        conf["_logs"] = True
        return 0 if tick_guarded(conf, do_printers=True) else 1

    n = 0
    printer_pass = 0
    while True:
        # Re-read per pass rather than per process: a cadence pushed from Watchman has to
        # apply live, which is the whole point of it being an agent setting and not a session
        # one. 0 DISABLES polling — and that test also guards the modulo, because a
        # ZeroDivisionError here is outside tick_guarded and would kill the agent outright.
        printer_every = RUNTIME["printer_every"]
        discover_every = RUNTIME["discover_every"]
        do_printers = printer_every > 0 and (n % printer_every == 0)
        if do_printers:
            conf["_discover"] = discover_every > 0 and (printer_pass % discover_every == 0)
            # Opt-in, and only on the slow pass: an update check every 30s is pointless load.
            if str(conf.get("VIGILANT_AUTO_UPDATE") or "").strip() in ("1", "true", "yes"):
                self_update(conf)
                sync_toolbox(conf)
        else:
            printer_pass += 1
        # Logs on EVERY tick. They used to be collected inside the printer branch above, which
        # silently tied them to VIGILANT_PRINTER_EVERY: at the shipped defaults (60 s interval,
        # every 15th tick) that is once every 15 minutes, and because each POST overwrites
        # device_state.raw wholesale, the UI showed `logs: null` on 14 ticks out of every 15 —
        # so clicking a thin client almost always showed nothing. The two have no reason to
        # share a cadence: this is a few KB of filtered text, whereas the printer pass hammers
        # SNMP on print servers old enough to wedge under it.
        conf["_logs"] = True
        got = tick_guarded(conf, do_printers=do_printers)
        # Screen thumbnail, AFTER the telemetry tick and on its own upload. Separate from the
        # payload on purpose: an image inside telemetry would be stored in device_state.raw,
        # which is written wholesale every tick. 0 disables it outright — the setting a site
        # that has not agreed to screen capture must be able to rely on.
        shot_every = RUNTIME.get("screenshot_every", 0)
        if shot_every > 0 and (n % shot_every == 0) and conf.get("VIGILANT_TOKEN"):
            send_screen(conf)
        # EVERY tick, not on a multiple: this both starts a session an operator has just asked
        # for and ENDS one whose time is up, and a counter that keeps sharing its screen for
        # several minutes after expiry because the reconcile runs every 10th tick would make the
        # duration a suggestion rather than a limit.
        support_vnc_tick()
        # `not isinstance(got, bool)` is essential: bool subclasses int, so a False return
        # from a failed tick would otherwise be accepted as an interval, giving sleep(0) and
        # a hot retry loop against the ingest.
        if isinstance(got, int) and not isinstance(got, bool) and got != interval:
            print(f"vigilant-pi-agent: interval {interval}s -> {got}s (server-directed)", flush=True)
            interval = got
            # Keep what we report as in force honest, including when the interval came from
            # the fleet-wide poll_interval_s rather than from this device's settings.
            RUNTIME["report_interval_s"] = interval
        n += 1
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
