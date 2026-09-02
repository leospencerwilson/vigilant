#!/usr/bin/env python3
"""Push the Proxmox cluster's VM inventory to Vigilant.

RUNS ON A PROXMOX NODE. Vigilant sits on the DMZ VLAN and has no route to the Proxmox API
on the management VLAN, so this pushes rather than Vigilant pulling — which means no
DMZ-to-management firewall hole and no API token, because `pvesh` on a node is already
authenticated as root.

Any node works: pvesh reads /cluster/resources, so one node reports for the whole cluster.
Per-VM config is fetched for the VLAN tag, which is what maps a VM to a pharmacy
(tag = 100 + pharmacy index).

Capacity (CPU/RAM averages from the node's RRD, real disk usage from the guest agent) is
sent alongside the inventory as its own `capacity` array. AGGREGATES ONLY — the raw RRD
series never leaves the node.

Each PMR Windows desktop's own printer list is sent the same way, as `printers`. It is read
from the guest, on THIS node's VMs only, and it is the only way that reading can exist: there
is no route from Vigilant to the Proxmox API, so there is no on-demand read to add.

The reply to that push is also how Vigilant hands this node WORK — a `jobs` array of
{id, verb, args}. The verb is a NAME looked up in this file's own JOB_VERBS table and is
never a command line; the arguments are re-validated here against bounds this file owns
before any of them becomes argv. See THE JOB CHANNEL below. Nothing listens: the channel is
the reply to an outbound POST, which is what keeps the no-inbound-hole property true.

Stdlib only. Config in /etc/vigilant/proxmox-collector.env:
    VIGILANT_URL=https://vigilant.internal.western-communication.com
    VIGILANT_ADMIN_TOKEN=<the estate admin token>
"""

import base64
import concurrent.futures
import errno
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CONF = "/etc/vigilant/proxmox-collector.env"
# Non-blocking flock. The pass has a deadline (below) but a node under load can still be slow,
# and the timer fires on a fixed interval — without this, an overrunning tick is simply doubled
# up and two collectors fight over pvedaemon on a node hosting live pharmacy desktops.
LOCK_PATH = "/run/vigilant-proxmox-collector.lock"
# Cloudflare fronts Vigilant and bans Python's default client signature with
# "error code: 1010" — every request 403s, including ones curl gets a 200 for.
UA = "vigilant-proxmox-collector/1"

# A guest that has not answered in five seconds is not about to. Bounded tightly because this
# runs on a node hosting live pharmacy desktops and the whole pass has to stay cheap.
PROBE_TIMEOUT_S = 5
# The RRD is a node-local file read, so it has no business inheriting pvesh's 25s default —
# that default is sized for a cluster round trip. Eight seconds is generous for a local read and
# is what stops an unreachable node costing 25s per call.
RRD_TIMEOUT_S = 8
# THREE, not six. pvedaemon runs 3 workers by default, so six of ours saturate it — which slows
# the Proxmox web UI and `qm` for an engineer working on a node that hosts live pharmacy
# desktops. The pool exists to stop a serial pass taking minutes, not to hammer the API.
WORKERS = 3
# Ship what completed rather than running forever. A pass that cannot finish inside this is
# already reporting stale numbers; a partial report with fresh readings for the VMs we did reach
# is strictly better than a tick that never posts. Must stay under the timer interval, and
# TimeoutStartSec in the unit file is set from it.
PASS_DEADLINE_S = 240

# (payload suffix, seconds of history to average over). ONE RRD call now backs all three.
#
# `month` is 1440 samples at 30 minutes = exactly 30 days, so the 1-day and 7-day windows are
# just timestamp slices of it. That leaves 48 samples behind the 1-day mean and 336 behind the
# 7-day one — ample for an average, and it removes two of the three pvesh spawns per VM (52 of
# 78 per tick across this estate). At the old 25s default an unreachable node's VM cost up to
# 100s of stall while holding a worker slot; now it is one call at RRD_TIMEOUT_S, and only if
# the node has not already been marked unreachable for this pass.
RRD_WINDOWS = (("1d", 86400), ("7d", 604800), ("30d", None))

# A whole node failing is a per-NODE fact, not a per-VM one, but it is discovered per VM. Without
# this, vanguard being down is re-learned once for every VM it hosts and each rediscovery costs a
# full timeout. First VM to hit it records it; every later VM on that node short-circuits.
_node_down = {}
_node_down_lock = threading.Lock()

# Transport-level failures only. "guest agent is not running" is a fact about ONE guest and must
# never take a whole node's other VMs down with it.
NODE_DOWN_HINTS = ("connection closed", "connection refused", "no route to host",
                   "network is unreachable", "host is down", "timeout after", "timed out")


def note_node_error(node, err):
    """Record a transport failure against `node`, first writer wins."""
    if not node or not err:
        return
    low = str(err).lower()
    if any(h in low for h in NODE_DOWN_HINTS):
        with _node_down_lock:
            _node_down.setdefault(node, str(err)[:200])


def node_is_down(node):
    with _node_down_lock:
        return _node_down.get(node)

# The guest agent reports every mount it can see, including attached ISOs (which always read
# 100% full) and Windows recovery partitions. Only a real data filesystem may become the site's
# disk reading, so this is an ALLOWLIST: anything unrecognised degrades to disk_source
# 'unknown' rather than being guessed at.
REAL_FS_TYPES = ("ntfs", "ext2", "ext3", "ext4", "xfs", "btrfs")


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


def pvesh(path, timeout=25, args=()):
    """Returns (data, error). NEVER a bare None.

    This used to return None for five different things — timeout, node down, malformed JSON,
    missing binary, and a legitimate empty answer — which was survivable while the only caller
    wanted a VLAN tag. It stops being survivable the moment we report on the guest agent: if
    "the agent is not running" and "we could not ask" arrive as the same value, Watchman states
    a fact about a live pharmacy VM that this collector never established. Every caller must be
    able to tell a real answer from a failure to get one.
    """
    try:
        out = subprocess.run(["pvesh", "get", path, *args, "--output-format", "json"],
                             capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None, "pvesh not found"
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout}s"
    except Exception as e:                                   # noqa: BLE001 - reported, not swallowed
        return None, f"{type(e).__name__}: {e}"
    if out.returncode != 0:
        err = (out.stderr or "").strip().splitlines()
        return None, (err[-1][:200] if err else f"exit {out.returncode}")
    body = (out.stdout or "").strip()
    if not body:
        return None, "empty response"
    try:
        return json.loads(body), None
    except ValueError:
        return None, "malformed json"


def parse_agent(val):
    """Proxmox stores `agent` as a PROPERTY STRING, not a boolean.

    Real values in this estate include `1`, `0`, `enabled=1,type=virtio` and
    `1,fstrim_cloned_disks=1`. A `cfg.get("agent") == 1` test reports every carefully-configured
    VM as having the agent disabled. Absent means the key was never set — reported as unknown,
    not as False, because those are different facts.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    for part in s.split(","):
        part = part.strip()
        if part.startswith("enabled="):
            return part.split("=", 1)[1].strip() == "1"
    head = s.split(",", 1)[0].strip()
    if head in ("0", "1"):
        return head == "1"
    return None


def vm_config(node, vmid):
    """Returns (vlan_tag, macs, agent_enabled, onboot, error) from ONE config read.

    A VM can be dual-homed (the PMR gateway carries the DMZ on net0 and the pharmacy VLAN on
    net1), so every tag is collected and the pharmacy-range one is preferred — tags 101+ are
    per-pharmacy, while 30 is the shared DMZ. Choosing the lowest or the first would map the
    gateway to the wrong place.
    """
    # `?current=1` asks for the RUNNING config rather than the pending one. Without it a
    # `qm set --agent enabled=1` that is waiting on a reboot reads as enabled while the agent
    # is still dead in the guest — manufacturing a "broken install" that is really an
    # unrestarted VM.
    # `--current 1` as a FLAG, not `?current=1` in the path: pvesh routes on the path alone and
    # answers a query string with "No 'get' handler defined", which fails the whole config read
    # — taking the VLAN tag with it.
    cfg, err = pvesh(f"/nodes/{node}/qemu/{vmid}/config", args=("--current", "1"))
    if not isinstance(cfg, dict):
        # Nothing is returned on failure, and collect() then OMITS these keys entirely rather
        # than sending blanks. Sending None here used to overwrite a VM's stored vlan_tag with
        # NULL on one transient node hiccup, which silently unlinked it from its pharmacy —
        # the reconciler joins on vlan_tag.
        return None, [], None, None, err or "unreadable config"
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
    vlan = pharmacy_tags[0] if pharmacy_tags else (tags[0] if tags else None)
    # Both come from the config call that was already being made, so they cost nothing extra.
    # `onboot` is here because it is the estate's own most urgent open item: it is 0 on every
    # Windows desktop, including the two iPharm trades on, so a node reboot leaves that
    # pharmacy with a gateway and no desktops. Nothing has ever surfaced it.
    return vlan, macs, parse_agent(cfg.get("agent")), bool(cfg.get("onboot")), None


def probe_agent(node, vmid):
    """Is the guest agent ACTUALLY running inside the guest? Returns a dict of what we learned.

    THIS IS THE ONLY CALL THAT ANSWERS THE REAL QUESTION. `agent enabled=1` in the config means
    Proxmox is configured to TALK to an agent; every Windows VM in this estate reads 1, because
    it is baked into every import path. Whether qemu-guest-agent is installed and bound inside
    Windows is a different fact, and only the guest can answer it.

    `get-osinfo` rather than `agent/ping`: it is read-only, safe against a desktop that is
    trading, GET-shaped so it fits pvesh's hardcoded `get` verb, and a success answers both
    questions at once while also returning the Windows build — which the estate records nowhere.

    `agent_ok` is TRUE/FALSE only when we genuinely established it, and None otherwise. A VM
    that is powered off has no agent to answer, and reporting that as False would put a fault on
    every legitimately stopped VM.
    """
    out = {"agent_ok": None, "guest_os": None, "guest_ips": [], "agent_error": None}
    info, err = pvesh(f"/nodes/{node}/qemu/{vmid}/agent/get-osinfo", timeout=PROBE_TIMEOUT_S)
    if isinstance(info, dict):
        res = info.get("result") if isinstance(info.get("result"), dict) else info
        out["agent_ok"] = True
        name = res.get("pretty-name") or res.get("name")
        ver = res.get("version") or res.get("kernel-version")
        out["guest_os"] = " ".join(x for x in (name, ver) if x)[:120] or None
    else:
        low = (err or "").lower()
        # Proxmox says this in as many words when the agent is configured but nothing answers.
        # Anything else — node down, timeout, permissions — is NOT evidence about the guest.
        if "not running" in low or "guest agent" in low:
            out["agent_ok"] = False
        out["agent_error"] = (err or "no answer")[:200]
        return out

    # The address Windows ACTUALLY holds. Everything else in the platform derives a VM's address
    # arithmetically and then compares one derivation against another, so the two agree by
    # construction — which is how VM 305's NIC being on the wrong address blocked a live counter
    # while every screen stayed green. This is the only reading that reflects what Windows did.
    ifaces, ierr = pvesh(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
                         timeout=PROBE_TIMEOUT_S)
    rows = None
    if isinstance(ifaces, dict):
        rows = ifaces.get("result") if isinstance(ifaces.get("result"), list) else None
    elif isinstance(ifaces, list):
        rows = ifaces
    if rows is None:
        out["agent_error"] = (ierr or "no interfaces")[:200]
        return out
    ips = []
    for nic in rows:
        if not isinstance(nic, dict):
            continue
        if str(nic.get("name", "")).lower().startswith("lo"):
            continue
        for a in nic.get("ip-addresses") or []:
            if not isinstance(a, dict) or a.get("ip-address-type") != "ipv4":
                continue
            ip = a.get("ip-address")
            # APIPA means DHCP never answered — worth reporting, not worth treating as an
            # address, so it is kept and the UI decides.
            if ip and ip != "127.0.0.1":
                ips.append(ip)
    out["guest_ips"] = sorted(set(ips))[:8]
    return out


def rrd_mean(samples, key):
    """Mean of `key` across RRD rows, IGNORING rows where it is absent or null.

    RRD pads the head of a series with nulls — a VM created four days ago still returns 1440
    rows for the month timeframe, and ~1250 of them are null. A naive sum()/len() divides a
    real total by a padded count and under-reports the average by whatever fraction of the
    window the VM did not exist for. Returns None when NOTHING in the series was a reading,
    which is a different fact from an average of zero and is carried through as such.
    """
    vals = []
    for row in samples:
        if not isinstance(row, dict):
            continue
        v = row.get(key)
        # bool is a subclass of int in Python and must not be averaged as 0/1.
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        vals.append(v)
    if not vals:
        return None
    return sum(vals) / len(vals)


def vm_rrd(node, vmid):
    """CPU/RAM averages from the node's own RRD. Returns (dict, error).

    NODE-LOCAL — this never touches the guest, so it works on a stopped VM and does not need
    the agent. RRD_TIMEOUT_S, not PROBE_TIMEOUT_S and not pvesh's 25s default: five seconds is
    calibrated for a guest round-trip and twenty-five for a cluster one, while this is a local
    file read that either answers immediately or is not going to.

    ONE CALL, SLICED THREE WAYS. This used to make three — day, week and month — which on an
    unreachable node was three full timeouts per VM while holding a worker slot. `month` is 1440
    samples at 30 minutes, i.e. exactly 30 days, so the shorter windows are timestamp slices of
    the same series: 48 samples behind the 1-day mean, 336 behind the 7-day one.

    `--timeframe` goes in `args` as a FLAG. pvesh routes on the path alone and answers a query
    string with "No 'get' handler defined" (the same trap documented in vm_config).
    """
    data, err = pvesh(f"/nodes/{node}/qemu/{vmid}/rrddata", timeout=RRD_TIMEOUT_S,
                      args=("--timeframe", "month"))
    if not isinstance(data, list):
        # RETURNED, not discarded. A permanently broken RRD path used to be invisible: the guest
        # agent kept answering, so a row was still written every tick and the UI aged its
        # timestamp forward over CPU/RAM numbers that had been frozen for weeks.
        return {}, err or "no rrd data"

    now = time.time()

    def within(span):
        if span is None:
            return data
        cut = now - span
        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            t = row.get("time")
            # bool is a subclass of int and is not a timestamp.
            if isinstance(t, bool) or not isinstance(t, (int, float)) or t < cut:
                continue
            out.append(row)
        return out

    out = {}
    for suffix, span in RRD_WINDOWS:
        window = within(span)
        # `cpu` is a FRACTION 0..1 in RRD; the whole platform reports percent.
        cpu = rrd_mean(window, "cpu")
        mem = rrd_mean(window, "mem")
        out[f"cpu_pct_{suffix}"] = None if cpu is None else round(cpu * 100, 2)
        out[f"mem_bytes_{suffix}"] = None if mem is None else int(round(mem))
        if suffix == "1d":
            # Memory PRESSURE, not usage: Windows will happily sit at 95% of a comfortable
            # allocation, so "how often did something stall waiting for memory" is the reading
            # that distinguishes a full VM from a starved one.
            pressure = rrd_mean(window, "pressurememorysome")
            out["mem_pressure_1d"] = None if pressure is None else round(pressure, 3)

    # A call that SUCCEEDS but yields nothing readable is a third outcome, distinct from both a
    # failed call and a good one. It happens on a VM younger than its RRD file, or if Proxmox
    # renames a series. Without this the row ships with every reading None and no error, so
    # sampled_at correctly freezes and the UI has nothing to say about why — the same silent
    # staleness the error channel was added to prevent.
    if all(v is None for v in out.values()):
        return {}, "rrd returned no readings (%d rows)" % len(data)
    return out, None


def vm_disk(node, vmid):
    """Real in-guest disk usage from the agent. Returns (dict, error) — never a zero.

    THE ONLY SOURCE OF TRUTH FOR DISK. RRD's `disk` is always 0 for a qemu VM because Proxmox
    cannot see inside the guest filesystem, and `maxdisk` is only the nominal virtual disk size
    (238GiB for VM 305, which is really 88% full). Reporting either as a disk reading would put
    a false all-clear on a live dispensing server.

    On any failure the numbers are ABSENT, not zero — the caller marks the row 'unknown'.
    """
    fs, err = pvesh(f"/nodes/{node}/qemu/{vmid}/agent/get-fsinfo", timeout=PROBE_TIMEOUT_S)
    # Same unwrap as network-get-interfaces: the answer is {"result": [...]} or a bare list.
    entries = None
    if isinstance(fs, dict):
        entries = fs.get("result") if isinstance(fs.get("result"), list) else None
    elif isinstance(fs, list):
        entries = fs
    if entries is None:
        return None, (err or "no filesystem info")[:200]

    best = None
    for f in entries:
        if not isinstance(f, dict):
            continue
        ftype = str(f.get("type") or "").strip().lower()
        mount = str(f.get("mountpoint") or "").strip()
        # CDFS is an attached ISO and always reads 100% full — it is the single most likely
        # thing to be mistaken for a full disk on a Windows VM.
        if not mount or ftype in ("cdfs", "iso9660", "udf"):
            continue
        if not any(ftype.startswith(t) for t in REAL_FS_TYPES):
            continue
        used, total = f.get("used-bytes"), f.get("total-bytes")
        if not isinstance(used, (int, float)) or not isinstance(total, (int, float)):
            continue
        if isinstance(used, bool) or isinstance(total, bool) or total <= 0:
            continue
        # LARGEST filesystem wins: a Windows VM also exposes a ~500MB recovery partition, and
        # "first" or "smallest" would report that as the site's disk.
        if best is None or total > best["disk_total_bytes"]:
            best = {"disk_mount": mount[:120],
                    "disk_used_bytes": int(used), "disk_total_bytes": int(total)}
    if best is None:
        return None, "no real filesystem reported"
    return best, None


# ── WHAT WINDOWS ITSELF LISTS ────────────────────────────────────────────────
# The printers modal draws a confirmation per printer — green when the queue is in the
# desktop's Windows printer list, amber when it is redirected but not there yet, red when it
# should be and is not. That join needs ONE reading nothing in the estate produced: the list
# Windows holds inside the RDP session.
#
# ⛔ AND IT CAN ONLY BE PRODUCED HERE. Vigilant sits on the DMZ VLAN with no route to the
# Proxmox API, no inbound hole and no API token — a deliberate property of this platform, not
# a gap to route around. So there is no on-demand read: this pass takes the reading and pushes
# it with everything else, and the UI ages it on screen. Nothing below opens a socket or
# shortens the timer.
#
# ⭐ MEASURED ON VMs 305 AND 306 (2026-08-26). `qm guest exec` + Get-Printer DOES return
# redirected queues, despite the documented session-0 scoping caveat:
#     Pharmacy-ETP (redirected 2) / Label-ZD420 (redirected 2) / Label-GK420d (redirected 2)
#     Pharmacy-Printer (redirected 2) / Microsoft Print to PDF
# Label-ZD421 is in both kiosk scripts and in NEITHER list, because the session has not
# restarted since it was added. That is the amber state, live, and it is the case this feed
# exists to render.
#
# The " (redirected 2)" suffix is RDP's own decoration and is NOT stripped here — the guest's
# string is reported exactly as the guest gave it. The read path is the single documented place
# that derives the matchable name from it, so the decoration is handled once, visibly.
PRINTER_LIST_CAP = 64
PRINTER_NAME_MAX = 120
# What the GUEST gets. Same reasoning as PROBE_TIMEOUT_S and only a little longer: Get-Printer
# on a loaded Windows desktop is slower than get-osinfo, and this runs on a node hosting live
# pharmacy desktops. Only VMs whose agent ALREADY answered this pass reach it, so a VM with no
# agent costs nothing at all.
PRINTER_EXEC_TIMEOUT_S = 8
# A printer name is a string from inside a Windows box: untrusted, and bound before it is
# reported. C0/C1 controls out, length bounded, list capped.
PRINTER_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# ⛔ THE MARKER IS WHAT MAKES "WINDOWS HAS NO PRINTERS" PROVABLE. A session with no printers and
# a call whose output we never captured both arrive as an empty stdout, and they are completely
# different facts — one is a real fault worth showing, the other is "nobody looked", which must
# never render as a finding. So the script states its own count first, and an answer without
# that line is reported as an ERROR with no list, never as an empty list.
_PRINTER_PS = (
    # ⛔ THE PROGRESS STREAM IS WHY THIS READ RETURNED NOTHING FOR THREE VMs. PowerShell writes a
    # CLIXML <Obj S="progress"> blob to STDERR on a first-use module load, `qm guest exec` carries
    # it back inside err-data, and that blob ALONE is about 1KB — which run_local's output bound
    # then truncated, so the JSON answer was cut mid-string and every VM reported a parse error
    # while Get-Printer had actually succeeded. Silencing it is the fix; the wider bound below is
    # the belt to its braces.
    "$ProgressPreference = 'SilentlyContinue'; "
    "$ErrorActionPreference = 'Stop'; "
    "$p = @(Get-Printer | ForEach-Object { $_.Name }); "
    "Write-Output ('VIGILANT-PRINTERS ' + $p.Count); "
    "$p | ForEach-Object { Write-Output $_ }"
)
# -EncodedCommand takes UTF-16LE base64, which is also what keeps quoting out of the argv.
_PRINTER_ENC = base64.b64encode(_PRINTER_PS.encode("utf-16-le")).decode("ascii")
_PRINTER_MARKER_RE = re.compile(r"^VIGILANT-PRINTERS (\d+)$")


def clean_printer_name(raw):
    """One name, bounded. None for anything that is not a usable string."""
    if not isinstance(raw, str):
        return None
    name = PRINTER_CTRL_RE.sub("", raw).strip()
    return name[:PRINTER_NAME_MAX] if name else None


def wants_printer_list(vlan_tag, guest_os):
    """Is this a PMR Windows desktop worth asking? Cheap gate, no calls.

    Tags 101+ are the per-pharmacy VLANs (tag = 100 + pharmacy index), so a VM outside that
    range is not a pharmacy desktop. The OS check keeps `powershell.exe` off the Linux PMR
    gateway, which shares the pharmacy VLAN. An UNKNOWN OS is still asked: get-osinfo not
    naming the guest is not evidence that it is not Windows.
    """
    if vlan_tag is None or vlan_tag < 101:
        return False
    os_name = (guest_os or "").lower()
    return not os_name or "windows" in os_name


def vm_printers(node, vmid, local_node):
    """(names, error). NEVER ([], "..."), and never [] for a call that did not happen.

    ⛔ ABSENT IS NOT EMPTY. `(None, None)` means "not asked" and produces NO row at all, so the
    stored reading — and its age — are left exactly as they were. `([], None)` is a REAL answer:
    the guest was read and Windows lists nothing, which is a fault worth seeing. An empty list
    standing in for either of the other two is the failure this whole feed exists to clear.

    ⛔ LOCAL VMs ONLY, and a VM on another node reports NOTHING rather than an error. `qm` acts
    on this node; the inventory above is cluster-wide because pvesh is, but this is not. Three
    nodes push here under the same estate token, so a "not on this node" error row from node B
    would clobber node A's real reading for the same vmid every 15 minutes. Silence is the only
    correct answer to a question this node was not asked. The collector is installed per node —
    the job branch already requires that — so each desktop is read by the node that hosts it.

    run_local() and vm_is_local() are defined further down with the job channel and are reused
    deliberately: argv as a LIST (no shell to inject into) and the cluster filesystem's own
    answer to "is this VM here", which needs no pvesh and survives the rest of the cluster
    being unreachable.

    ⭐ AND IT COSTS PVEDAEMON NOTHING. `qm` is a local CLI talking to this VM's own qmp socket,
    not an API round trip, so unlike the pvesh probes above it does not draw on pvedaemon's
    three workers — which is the pool an engineer running `qm` or the Proxmox web UI on a node
    hosting live pharmacy desktops is competing for. That is the reason this could be added
    without shortening the timer or widening the pool, and both must stay as they are.
    """
    if not local_node or node != local_node or not vm_is_local(local_node, int(vmid)):
        return None, None
    argv = ["qm", "guest", "exec", str(int(vmid)),
            "--timeout", str(PRINTER_EXEC_TIMEOUT_S),
            "--", "powershell.exe", "-NoProfile", "-NonInteractive",
            "-EncodedCommand", _PRINTER_ENC]
    # A little longer than the guest's own timeout so `qm` gets to report the guest timing out
    # rather than being killed mid-sentence and looking like a broken node.
    # Enough for the JSON envelope plus PRINTER_LIST_CAP names, not enough to be a memory
    # question. The list itself is capped after parsing, so this bounds only the read.
    rc, out = run_local(argv, PRINTER_EXEC_TIMEOUT_S + 5, limit=16000)
    body = (out or "").strip()
    if rc == 127:
        return None, body[:200] or "qm not found on this node"
    try:
        answer = json.loads(body)
    except ValueError:
        # rc is included because `qm guest exec` says "QEMU guest agent is not running" on
        # stderr and exits non-zero, and that sentence is the whole diagnosis.
        return None, ("qm guest exec exited %s: %s" % (rc, body[:150])).strip()
    if not isinstance(answer, dict):
        return None, "unexpected answer from qm guest exec"
    if not answer.get("exited"):
        return None, "the guest did not finish within %ds" % PRINTER_EXEC_TIMEOUT_S
    code = answer.get("exitcode")
    if code not in (0, None):
        err = str(answer.get("err-data") or "").strip()
        return None, ("Get-Printer exited %s: %s" % (code, err))[:200].strip()
    data = answer.get("out-data")
    if not isinstance(data, str):
        return None, "the guest returned no output to read"
    lines = data.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    marker = _PRINTER_MARKER_RE.match(lines[0].strip() if lines else "")
    if not marker:
        # See the marker note above: without it an empty stdout is unattributable, and the
        # honest answer to an unattributable reading is "we do not know".
        return None, "the guest's answer did not carry this collector's marker"
    declared = int(marker.group(1))
    names = []
    for raw in lines[1:]:
        name = clean_printer_name(raw)
        if name is None:
            continue
        names.append(name)
        if len(names) >= PRINTER_LIST_CAP:
            break
    if declared > len(names):
        # Reported ALONGSIDE the names, not instead of them: a capped or partly-unreadable list
        # is still evidence for the printers that ARE in it, and a name's ABSENCE from a capped
        # list is not evidence at all. Said out loud so the modal is not the thing that has to
        # infer it.
        return names, "the guest listed %d printers and %d were readable" % (declared, len(names))
    return names, None


# ── NODE HEADROOM ────────────────────────────────────────────────────────────
# "Can this NODE host another pharmacy?" — a different question from the per-VM capacity
# above, which asks whether one pharmacy's server is running out of room. Nothing in the
# estate reported this, so Watchman could not refuse a site build and name the resource that
# was short.
#
# MEASURED 2026-08-25: wcn-zfs had 143 GB free and one site costs about 197 GB, with 67 GB of
# 188 GB RAM free. The arithmetic that turns those into a yes or no lives on the server, in
# src/shared/nodeCapacity.js; this only reports what it read.
#
# ⛔ A FIGURE THIS PASS COULD NOT READ IS SENT AS null, NEVER AS 0. The ingest stores null and
# the judgement answers "unknown", which is neither a refusal nor an approval. A 0 would read
# as "completely full", which is a much louder claim than the one we are entitled to make.
#
# Only storages that can actually hold a VM disk are reported: a site is placed on ONE pool
# and cannot be placed on a backup or ISO store, so including those would offer headroom that
# is not available for the thing being judged.
def _num(v):
    """A number, or None. Never a 0 standing in for a value we did not read."""
    if v is None:
        return None
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if n != n or n in (float("inf"), float("-inf")) or n < 0:
        return None
    return int(n)


def collect_nodes():
    """[{node, storage_name, mem_*, storage_*, cpu_cores, read_error}] — one row per pool."""
    nodes, err = pvesh("/nodes")
    if not isinstance(nodes, list):
        print(f"collector: could not read /nodes ({err}) — no node headroom this pass",
              file=sys.stderr)
        return []

    out = []
    for n in nodes:
        name = n.get("node")
        if not name:
            continue
        # A node that has already failed a transport call this pass is skipped rather than
        # retried per storage — the same rule the VM loop applies, and for the same reason: one
        # unreachable node must not spend the pass deadline for every other node.
        down = node_is_down(name)
        if down or n.get("status") != "online":
            out.append({
                "node": name, "storage_name": "-",
                "mem_total_bytes": None, "mem_free_bytes": None,
                "storage_total_bytes": None, "storage_free_bytes": None,
                "cpu_cores": None,
                "read_error": (down or f"node status {n.get('status')!r}")[:200],
            })
            continue

        # Proxmox's own arithmetic, not ours: `maxmem` is the node's memory and `mem` is what
        # it reports as in use, which is exactly the pair its own summary screen subtracts.
        # Either one missing makes the answer unknown rather than a half-computed number.
        mem_total = _num(n.get("maxmem"))
        mem_used = _num(n.get("mem"))
        mem_free = None if mem_total is None or mem_used is None else max(0, mem_total - mem_used)
        cores = _num(n.get("maxcpu"))

        stores, serr = pvesh(f"/nodes/{name}/storage")
        if serr:
            note_node_error(name, serr)
        if not isinstance(stores, list):
            out.append({
                "node": name, "storage_name": "-",
                "mem_total_bytes": mem_total, "mem_free_bytes": mem_free,
                "storage_total_bytes": None, "storage_free_bytes": None,
                "cpu_cores": cores,
                "read_error": str(serr or "no storage list")[:200],
            })
            continue

        any_pool = False
        for st in stores:
            pool = st.get("storage")
            if not pool:
                continue
            # A site's disks are images. A backup or template store has headroom that cannot
            # be used for the thing being judged, so reporting it would be misleading.
            content = str(st.get("content") or "")
            if "images" not in content and "rootdir" not in content:
                continue
            if not st.get("active") or not st.get("enabled", 1):
                continue
            any_pool = True
            out.append({
                "node": name,
                "storage_name": pool,
                "mem_total_bytes": mem_total,
                "mem_free_bytes": mem_free,
                "storage_total_bytes": _num(st.get("total")),
                # `avail` is what a new disk could claim. NOT total minus used, which differs
                # on ZFS and would be us inventing a figure Proxmox did not state.
                "storage_free_bytes": _num(st.get("avail")),
                "cpu_cores": cores,
                "read_error": None,
            })
        if not any_pool:
            out.append({
                "node": name, "storage_name": "-",
                "mem_total_bytes": mem_total, "mem_free_bytes": mem_free,
                "storage_total_bytes": None, "storage_free_bytes": None,
                "cpu_cores": cores,
                "read_error": "no active image storage on this node",
            })
    return out


# ── VM Windows health: ProScript, its SQL, and the VM-side smartcard service ──
#
# ⛔ NAMES DISCOVERED, NOT GUESSED (2026-08-28, on VM 305). The dispensing gate is the
# `ProScriptConnect Server Service` plus the SQL instance it needs (`MSSQL$<instance>`), and the
# VM-side smartcard is `SCardSvr`. Guessing a service name would report a running pharmacy as
# down, so these are read from the live estate and matched by the stable service name (SQL by the
# `MSSQL$` prefix because the instance suffix varies per site). READ-ONLY: Get-Service only.
_HEALTH_PS = (
    "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='SilentlyContinue'; "
    "$ps = (Get-Service -Name 'ProScriptConnect Server Service').Status; "
    "$sql = (Get-Service | Where-Object { $_.Name -like 'MSSQL$*' } | Select-Object -First 1).Status; "
    "$sc = (Get-Service -Name 'SCardSvr').Status; "
    "Write-Output ('VIGILANT-HEALTH proscript=' + $ps + ' sql=' + $sql + ' scardsvr=' + $sc)"
)
_HEALTH_ENC = base64.b64encode(_HEALTH_PS.encode("utf-16-le")).decode("ascii")
_HEALTH_RE = re.compile(r"VIGILANT-HEALTH proscript=(\S*) sql=(\S*) scardsvr=(\S*)")


def _svc_state(v):
    """A Windows service status string -> our tri-state. Empty/absent -> 'unknown', never a
    confident 'stopped', because a service that is not installed and one we could not read are
    different facts."""
    t = (v or "").strip().lower()
    if t in ("running",):
        return "running"
    if t in ("stopped", "startpending", "stoppending", "paused"):
        return "stopped"
    return "unknown"


def vm_windows_health(node, vmid, local_node):
    """(dict, error). Only for a LOCAL, agent-answering Windows VM — same gate as vm_printers.

    Returns proscript / sql / scardsvr tri-states. `None` dict means not asked (another node,
    no agent); the columns then stay as they were rather than degrading to a confident value.
    """
    if not local_node or node != local_node or not vm_is_local(local_node, int(vmid)):
        return None, None
    argv = ["qm", "guest", "exec", str(int(vmid)),
            "--timeout", str(PRINTER_EXEC_TIMEOUT_S),
            "--", "powershell.exe", "-NoProfile", "-NonInteractive",
            "-EncodedCommand", _HEALTH_ENC]
    rc, out = run_local(argv, PRINTER_EXEC_TIMEOUT_S + 5, limit=16000)
    body = (out or "").strip()
    try:
        answer = json.loads(body)
    except ValueError:
        return None, ("qm guest exec exited %s: %s" % (rc, body[:150])).strip()
    if not isinstance(answer, dict) or not answer.get("exited"):
        return None, "the guest did not finish"
    data = answer.get("out-data")
    if not isinstance(data, str):
        return None, "the guest returned no output"
    m = _HEALTH_RE.search(data)
    if not m:
        return None, "the guest's answer did not carry the health marker"
    return {"proscript": _svc_state(m.group(1)), "sql": _svc_state(m.group(2)),
            "scardsvr": _svc_state(m.group(3))}, None


def vm_last_backup(node, vmid):
    """(epoch_seconds_or_None, error). The end time of this VM's most recent SUCCESSFUL vzdump,
    from the node's task history. None with no error means no successful backup is on record —
    which, with the estate's NFS backup stores offline, is the true and important answer."""
    tasks, err = pvesh("/nodes/%s/tasks" % node, timeout=20,
                       args=("--typefilter", "vzdump", "--limit", "500"))
    if err:
        return None, err
    if not isinstance(tasks, list):
        return None, "unexpected task list"
    best = None
    want = str(int(vmid))
    for t in tasks:
        if t.get("status") != "OK":
            continue
        # vzdump task id looks like 'UPID:node:...:vzdump:' with the vmid in the 'id' field.
        if str(t.get("id") or "") != want:
            continue
        end = t.get("endtime")
        if isinstance(end, (int, float)) and (best is None or end > best):
            best = int(end)
    return best, None


def collect(probe=True, local_node=None):
    """`local_node` is this node's own validated name, or None.

    Passed in rather than looked up here so main() establishes the node's identity ONCE, and
    so a caller that has no identity (a test, or a box whose cluster filesystem cannot name it)
    simply reads no printer lists rather than guessing at which VMs are local.
    """
    resources, err = pvesh("/cluster/resources?type=vm")
    if not isinstance(resources, list):
        resources, err = pvesh("/cluster/resources")
    if not isinstance(resources, list):
        print(f"collector: could not read /cluster/resources ({err}) — is this a Proxmox node?",
              file=sys.stderr)
        return None

    rows = []
    for r in resources:
        if r.get("type") != "qemu":
            continue
        vmid, node = r.get("vmid"), r.get("node")
        if vmid is None or not node:
            continue
        rows.append(r)

    deadline = time.time() + PASS_DEADLINE_S

    def one(r):
        vmid, node = r.get("vmid"), r.get("node")
        # Templates are inventory noise, never match a live counter, and can never run an agent
        # — so they are skipped BEFORE the per-VM calls rather than filtered after paying for
        # them. At 348 sites that is the difference between a cheap pass and a slow one.
        template = bool(r.get("template"))
        status = r.get("status")
        running = status == "running"
        v = {
            "vmid": vmid, "node": node, "name": r.get("name"), "status": status,
            "cores": r.get("maxcpu"), "maxmem": r.get("maxmem"), "maxdisk": r.get("maxdisk"),
            "uptime_s": r.get("uptime"), "template": template,
        }
        if template:
            return v

        # /cluster/resources still lists the VMs of a member that is down — vanguard answers
        # every pvesh with "Connection closed by 192.168.50.51" — so without this gate each of
        # its VMs pays a fresh set of timeouts to rediscover the same fact. The inventory row
        # still goes, with the reason attached; only the readings are skipped.
        down = node_is_down(node)
        if down:
            v["node_error"] = down
            return v

        # Ship what completed. Past the deadline the remaining VMs report inventory only, which
        # is what /cluster/resources already gave us for free, so the pass still POSTs.
        if time.time() > deadline:
            v["node_error"] = "pass deadline reached"
            return v

        vlan, macs, agent_enabled, onboot, cfg_err = vm_config(node, vmid)
        note_node_error(node, cfg_err)
        # Re-checked, because THIS call may be the one that discovered the node is down. Without
        # the re-check the discovering VM still goes on to pay for an RRD read and a guest probe
        # against a node we now know is unreachable — three timeouts instead of one.
        down = node_is_down(node)
        if down:
            v["node_error"] = down
            return v
        if cfg_err:
            # KEYS OMITTED, not blanked. The write path COALESCEs, so a transient failure leaves
            # the last good values in place instead of unlinking the VM from its pharmacy.
            v["config_error"] = cfg_err
        else:
            v.update({"vlan_tag": vlan, "macs": macs,
                      "agent_enabled": agent_enabled, "onboot": onboot})

        # CPU/RAM averages. Node-local, so it is NOT gated on `running` — a VM that was
        # stopped an hour ago still has 30 days of history worth reporting. It IS below the
        # template early-return: templates never run, so their RRD is flat zero.
        #
        # It IS gated on the status being one we recognise. `running` and `stopped` are the two
        # states with an RRD behind them; anything else (`unknown` for a VM on a member that has
        # just dropped, or a migration in flight) has no series to average and only costs a
        # timeout to find that out.
        rrd, rrd_err = {}, None
        if status in ("running", "stopped"):
            rrd, rrd_err = vm_rrd(node, vmid)
            note_node_error(node, rrd_err)
        else:
            rrd_err = f"no rrd for status {status!r}"

        # Only a RUNNING, non-template VM can answer. Asking a stopped one would return an
        # error we would then have to be careful not to read as "the agent is missing".
        # NOT fed to note_node_error, deliberately: a probe timeout is a fact about ONE guest —
        # a Windows box under load answers slowly — and must never condemn the node its 25 other
        # VMs live on. Only the node-local control-plane calls (config, rrd) do that.
        disk = None
        if probe and running:
            v.update(probe_agent(node, vmid))
            v["agent_checked_at"] = int(time.time())
            # Gated on the probe having SUCCEEDED, not merely on the VM running. VMs 302/303/304
            # have no agent installed at all, and without this gate each one burns a full
            # PROBE_TIMEOUT_S inside a three-worker pool every single tick.
            if v.get("agent_ok") is True:
                disk, _disk_err = vm_disk(node, vmid)

        # ── the desktop's own Windows printer list ──────────────────────────
        # Gated on the SAME agent_ok the disk read is gated on, plus a cheap pharmacy/Windows
        # test that costs no calls, plus locality — so a VM with no agent, a Linux gateway, a
        # non-pharmacy VM and another node's VM all cost nothing. The deadline is re-checked
        # because this is the last per-VM call of the pass and it is the one worth dropping:
        # a stale printer list still renders, correctly aged, while a pass that never POSTs
        # loses the inventory too.
        if (probe and running and v.get("agent_ok") is True
                and wants_printer_list(v.get("vlan_tag"), v.get("guest_os"))
                and time.time() <= deadline):
            names, printers_err = vm_printers(node, vmid, local_node)
            if names is not None or printers_err:
                v["printers"] = {
                    "vmid": vmid, "node": node, "name": r.get("name"),
                    # The names EXACTLY as the guest gave them, RDP's suffix included.
                    "printers": names,
                    # WHEN IT WAS READ, not when the server receives it — the pass is pushed at
                    # the end and the UI ages this on screen, so a receive time would under-
                    # state the age of every reading by however long the rest of the pass took.
                    # Only set when there IS a list: an error carries no reading to date.
                    "read_at": int(time.time()) if names is not None else None,
                    "source": "guest-agent" if names is not None else None,
                    "error": printers_err,
                }

        # Report a capacity row only if we ESTABLISHED something. A pass that read neither the
        # RRD nor the guest sends no row at all, so the write path leaves the last good reading
        # — and its timestamp — untouched, rather than stamping "now" onto nothing.
        vm_health = None
        if (probe and running and v.get("agent_ok") is True
                and wants_printer_list(v.get("vlan_tag"), v.get("guest_os"))
                and time.time() <= deadline):
            vm_health, _health_err = vm_windows_health(node, vmid, local_node)
            if vm_health is None and _health_err:
                vm_health = {"error": _health_err}
        backup_at = None
        backup_err = None
        if wants_printer_list(v.get("vlan_tag"), v.get("guest_os")):
            backup_at, backup_err = vm_last_backup(node, vmid)
        if (any(x is not None for x in rrd.values()) or disk is not None
                or vm_health is not None or backup_at is not None):
            cap = {"vmid": vmid, "node": node, "name": r.get("name"),
                   "cores": r.get("maxcpu"), "mem_max_bytes": r.get("maxmem"),
                   # SENT, not swallowed. The write path only advances sampled_at on a row that
                   # carried an RRD reading, and this is what says why it did not — otherwise a
                   # VM whose RRD is broken but whose agent still answers reports a disk-only
                   # row forever with no indication the CPU/RAM figures beside it are frozen.
                   "rrd_error": rrd_err}
            cap.update(rrd)
            if disk is not None:
                cap.update(disk)
                cap["disk_source"] = "agent"
            else:
                # NEVER 0. The columns stay empty and the source says why they are empty.
                cap.update({"disk_mount": None, "disk_used_bytes": None,
                            "disk_total_bytes": None, "disk_source": "unknown"})
            # Split out of `v` by main() into the payload's own `capacity` array.
            if vm_health is not None:
                cap["proscript"] = vm_health.get("proscript")
                cap["vm_sql"] = vm_health.get("sql")
                cap["vm_scardsvr"] = vm_health.get("scardsvr")
                cap["health_error"] = vm_health.get("error")
            if backup_at is not None:
                cap["last_backup_at"] = backup_at
            cap["backup_error"] = backup_err
            v["capacity"] = cap
        return v

    # Threaded because the probe is a per-VM round trip and this runs on a node that also hosts
    # pharmacy desktops — a serial pass over 26 VMs with two agent calls each is minutes of
    # wall-clock. Small pool: the point is to not spend the whole tick here, not to hammer the
    # API.
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(one, rows))


# ── THE JOB CHANNEL ──────────────────────────────────────────────────────────
# Vigilant hands this node work on the REPLY to the report it already pushes. That is the
# only channel there is, and it is the channel deliberately: Vigilant sits on the DMZ VLAN
# with no route to the Proxmox API, there is no inbound hole, no listener and no API token,
# and every line below has to be readable as keeping it that way. Nothing here opens a
# socket, and nothing here can be reached from outside this node.
#
# ── THE LAW THIS CODE LIVES UNDER ────────────────────────────────────────────
# The same sentence that sits above ACTIONS in the Pi agent, and it has to be true here too:
#
#   "The server sends only a NAME which is looked up here — it never sends a command line —
#    so a compromised or mistaken server cannot turn this into arbitrary execution."
#
# So: JOB_VERBS below is THIS NODE'S table. The server's `verb` is a lookup key into it and
# is never anything else. An unrecognised name is refused and REPORTED, never guessed at.
# Arguments arrive as data and are re-validated here — against bounds this file owns, not
# against the server's word that it already checked — before any of them becomes argv. No
# free-text string from the server reaches a command line: the only values that survive
# validation are integers, and the only strings in an argv are literals written above.
#
# ⚠️ RE-VALIDATION IS NOT DUPLICATION. src/shared/pmrVerbs.js checks the same bounds server
# side. That check protects against an operator mistake; this one protects against the
# server, which is the assumption that makes a compromised server survivable. "The server
# already checked" is exactly the reasoning that must not appear here.

# ⛔ THE VERSION THIS COLLECTOR CLAIMS, and it is a claim about a capability.
# The server's floor is pmrVerbs.PMR_JOB_COLLECTOR_VERSION (2). Handing a job out IS the
# claim — there is no ack — so a collector that reports 2 and then cannot act SWALLOWS the
# job: claimed, never run, never reported, expired at its deadline. Two of the four verbs on
# this path take a live pharmacy desktop down, so a swallowed job reads as a shutdown that
# happened when it did not.
#
# Therefore this number is NOT sent unconditionally. job_branch_ready() below proves, on
# every pass, that the three things this branch cannot work without are actually present —
# this node knows its own name, `qm` exists, and the journal that makes execution
# once-only is readable and writable. If any of them is missing the key is OMITTED, the
# server reads version 0, offers nothing, and says so in `jobs_skipped`. Not being offered
# work is always better than being offered work we cannot honestly finish.
COLLECTOR_VERSION = 2

# The write-ahead record of every job this node has been handed. It is what makes execution
# ONCE-ONLY across process restarts, and it is where a result waits between the pass that
# produced it and the push that reports it.
#
# ⚠️ THIS FILE IS THE ONLY THING STANDING BETWEEN A LOST ACKNOWLEDGEMENT AND A SECOND
# SHUTDOWN. The server also refuses to re-offer a power verb (max_attempts 1, retry_ok
# false), but that is the server's guarantee; this is ours, and the whole point of the design
# is that neither side relies on the other being right.
JOURNAL_PATH = "/var/lib/vigilant/proxmox-jobs.json"
# Long enough to outlive the longest ttl_s in the verb table (vm.set-onboot, 86400s) many
# times over, so a job cannot expire server-side, be re-created, and find its tombstone gone.
JOURNAL_TTL_S = 7 * 86400
JOURNAL_MAX_ENTRIES = 500
# What the server hands out per reply (store.claimPmrJobsForNode caps at 4). Applied again
# here because a bound the other side promises is not a bound.
MAX_JOBS_PER_PASS = 4
# The ingest slices job_results at 50.
MAX_RESULTS_PER_PUSH = 50

# ⛔ HOW LONG THE GUEST GETS, and it is Proxmox's own timer, not ours. `qm shutdown --timeout`
# makes the node abandon the attempt if the guest has not gone by then.
#
# ⚠️ AND `--forceStop` IS NEVER PASSED, on this verb or any other. With it, a Windows desktop
# that is mid-transaction is pulled out at the wall. Without it, a guest that will not stop
# leaves the job FAILING — which raises a person — and leaves the pharmacy trading. That is
# the direction to fail in, and it is not a tuning decision.
GUEST_STOP_TIMEOUT_S = 45

# The whole pass, measured from the moment main() starts: collection, the POST, and the job
# work after it. TimeoutStartSec in the unit file is 420s and systemd KILLS the process at
# that point, so this leaves 40s of margin. A job is only STARTED if its own timeout fits
# inside what is left, so the phase cannot overrun this — and a job that does not fit is
# reported FAILED rather than silently skipped, because a claimed job with no result is the
# one outcome this control plane must never produce.
HARD_PASS_BUDGET_S = 380

# A pmr_jobs.id is a uuid server-side (store.pg.js isUuid). Bounded here because it is echoed
# back in job_results and used as a filename-free dictionary key — never as a path, never as
# argv — and because junk in this field means a malformed reply, which is worth refusing
# loudly rather than carrying around.
JOB_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# A Proxmox node name. Used to build a path under /etc/pve, so it is checked before it is,
# and it is only ever OUR OWN name that gets this far — a name from the server is compared
# against this one and then discarded.
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# The final assertion before exec: every token of an argv must look like this. Nothing that
# passed the argument validators can fail it — that is the point. It is here so that adding a
# verb whose builder interpolates a server string breaks immediately and visibly.
ARGV_TOKEN_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _short(v, limit=120):
    """A server-supplied value, made safe to put in a log line and a result_log.

    repr() so a control character cannot rearrange a log line, and BOUNDED because
    result_log is stored and displayed — a refusal is not a place for the server to write an
    essay into the estate's database.
    """
    r = repr(v)
    return r if len(r) <= limit else r[:limit] + "...(truncated)"


# ── argument validators — the closed patterns arguments are checked against ───
# Each returns (value, error). A value only exists if it passed.
#
# ⛔ NO COERCION FROM TEXT. "305" is refused rather than read as 305, for the same reason the
# server refuses a collector_version that arrives as a string: a value arriving in the wrong
# type is a bug in whatever produced it, and quietly fixing it up hides exactly the class of
# mistake this validation exists to catch. bool is refused explicitly because it is a
# subclass of int in Python and True would otherwise pass as 1.
def arg_vmid(v):
    """A bounded integer. It becomes an argument to `qm` on a node hosting live desktops."""
    if isinstance(v, bool) or not isinstance(v, int):
        return None, "must be an integer, got %s" % type(v).__name__
    # The same 100..999999 range as ARG_SPECS.vmid in src/shared/pmrVerbs.js, restated here
    # rather than imported, because this side must hold even if that side is wrong.
    if not 100 <= v <= 999999:
        return None, "%d is outside 100..999999" % v
    return v, None


def arg_onboot(v):
    """1 or 0 — the vocabulary the Proxmox config key uses and the collector reads back."""
    if isinstance(v, bool) or not isinstance(v, int) or v not in (0, 1):
        return None, "must be the integer 0 or 1"
    return v, None


# ── THIS NODE'S VERB TABLE ───────────────────────────────────────────────────
# A verb is a KEY here. The server names one; this table decides what that name means on
# this machine. Every argv builder below receives ONLY values that came out of the
# validators above, so every element it produces is either a literal written on this line or
# str() of a bounded integer.
def _argv_set_onboot(a):
    return ["qm", "set", str(a["vmid"]), "--onboot", str(a["onboot"])]


def _argv_start(a):
    return ["qm", "start", str(a["vmid"])]


def _argv_shutdown(a):
    # --timeout, and deliberately NO --forceStop. See GUEST_STOP_TIMEOUT_S.
    return ["qm", "shutdown", str(a["vmid"]), "--timeout", str(GUEST_STOP_TIMEOUT_S)]


def _argv_reboot(a):
    return ["qm", "reboot", str(a["vmid"]), "--timeout", str(GUEST_STOP_TIMEOUT_S)]


JOB_VERBS = {
    # The converging verb: a configuration property, reversible, interrupts nothing. onboot
    # is 0 on every Windows desktop in this estate, so a node reboot leaves a pharmacy with
    # a gateway and no desktops — this is the verb that fixes that.
    "vm.set-onboot": {
        "args": {"vmid": arg_vmid, "onboot": arg_onboot},
        "argv": _argv_set_onboot,
        "disruptive": False,
        # A config write on /etc/pve. Fast, or something is wrong with the cluster fs.
        "timeout_s": 30,
    },
    # Starting a stopped VM interrupts nothing — there is no session to lose.
    "vm.start": {
        "args": {"vmid": arg_vmid},
        "argv": _argv_start,
        "disruptive": False,
        # `qm start` returns once qemu is up, not once Windows is. 90s is generous for a
        # busy node and still bounded.
        "timeout_s": 90,
    },
    # ⚠️ DISRUPTIVE. This ends someone's Windows session at a pharmacy counter.
    "vm.shutdown": {
        "args": {"vmid": arg_vmid},
        "argv": _argv_shutdown,
        "disruptive": True,
        # The guest's own timer plus slack for the node to give up on it.
        "timeout_s": GUEST_STOP_TIMEOUT_S + 20,
    },
    # ⚠️ DISRUPTIVE, for the same reason.
    "vm.reboot": {
        "args": {"vmid": arg_vmid},
        "argv": _argv_reboot,
        "disruptive": True,
        "timeout_s": GUEST_STOP_TIMEOUT_S + 20,
    },
}


# ── WHO THIS NODE IS, established locally ────────────────────────────────────
def local_node_name():
    """This node's Proxmox name, or None if it cannot be established.

    ⛔ READ FROM THE NODE, NEVER TAKEN FROM THE SERVER. /etc/pve/local is a symlink to
    /etc/pve/nodes/<name> maintained by pmxcfs, so it is Proxmox's own answer to "who am I"
    and it cannot be influenced from the DMZ.

    None is a real answer and it disables the whole job branch. A collector that cannot name
    itself cannot tell its own jobs from another node's, and the correct thing to do with a
    job you cannot prove is yours is to not be offered it.
    """
    name = ""
    try:
        name = os.path.basename(os.readlink("/etc/pve/local").rstrip("/"))
    except OSError:
        # The hostname is what Proxmox derives the node name from, so it is a reasonable
        # fallback — but ONLY if the cluster filesystem agrees that a node by that name
        # exists here. A bare hostname on a box that is not a Proxmox node is not an identity.
        name = socket.gethostname().split(".")[0].strip()
    if not name or not NODE_NAME_RE.match(name):
        return None
    if not os.path.isdir(os.path.join("/etc/pve/nodes", name)):
        return None
    return name


def vm_is_local(node, vmid):
    """Is this VM ACTUALLY on this node? The cluster filesystem's own answer.

    /etc/pve/nodes/<node>/qemu-server/<vmid>.conf existing IS what "the VM is on that node"
    means in Proxmox — the inventory this collector reports is derived from the same place.
    A local file read: no pvesh, no timeout, and it works while the rest of the cluster is
    unreachable.

    `node` is this node's own validated name and `vmid` is a bounded integer, so nothing that
    came off the wire as a string is in this path.
    """
    return os.path.isfile("/etc/pve/nodes/%s/qemu-server/%d.conf" % (node, vmid))


# ── THE JOURNAL ──────────────────────────────────────────────────────────────
def _journal_read():
    """Returns (entries, error). entries is a dict keyed by job id; None means UNAVAILABLE.

    ⛔ A CORRUPT OR UNREADABLE JOURNAL IS 'UNAVAILABLE', NEVER 'EMPTY'. An empty journal says
    "nothing has ever run here", which is the one sentence that could turn a lost
    acknowledgement into a second shutdown. It is also not overwritten — the file is left
    exactly as found for whoever comes to look, and the job branch simply stays off until
    they have.
    """
    try:
        with open(JOURNAL_PATH) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}, None                       # never used: a genuinely fresh node
    except (OSError, ValueError) as e:
        return None, "%s: %s" % (type(e).__name__, e)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        return None, "journal is not in the expected shape"
    entries = {}
    for jid, entry in data["jobs"].items():
        if isinstance(jid, str) and isinstance(entry, dict):
            entries[jid] = entry
    return entries, None


def journal_write(entries):
    """Atomic replace, fsynced. Returns True only if the new content is really on disk.

    Called at every point the record must survive a kill — in particular BEFORE a disruptive
    command runs. A False here is what stops that command running at all.
    """
    try:
        os.makedirs(os.path.dirname(JOURNAL_PATH), exist_ok=True)
        tmp = JOURNAL_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"jobs": entries}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, JOURNAL_PATH)
        return True
    except OSError as e:
        print(f"collector: cannot write {JOURNAL_PATH} ({e})", file=sys.stderr)
        return False


def journal_open(now=None):
    """Load the journal, settle anything a previous pass left in flight, prove writability.

    Returns the entries dict, or None if the journal is unusable — which turns the job
    branch off for this pass.

    ⛔ SETTLING IS THE HALF OF REQUIREMENT 5 THAT IS EASY TO MISS. A pass killed between
    starting `qm shutdown` and recording its outcome leaves an entry in state 'running'. That
    job may never be re-offered (max_attempts 1), so nobody would ever hear about it. It is
    closed here as FAILED, saying plainly that it was interrupted and NOT retried — the
    result is honest, the ladder ends, and the pre-opening check gets a person in front of it.
    """
    now = int(now if now is not None else time.time())
    entries, err = _journal_read()
    if entries is None:
        print(f"collector: job journal unusable ({err}) — taking NO jobs this pass; "
              f"the file is left untouched for inspection", file=sys.stderr)
        return None
    for jid, e in entries.items():
        if e.get("state") == "running":
            e["state"] = "done"
            e["status"] = "failed"
            e["finished_at"] = now
            e["log"] = ("the collector was interrupted while this job was in flight. It was "
                        "NOT retried, and whether the command took effect is unknown — check "
                        "the VM before assuming either way.")
            print(f"collector: job {jid} was interrupted by a previous pass — reporting it "
                  f"failed, not retrying it", file=sys.stderr)
    entries = journal_prune(entries, now)
    # Write once now, unconditionally. It proves the directory is writable BEFORE
    # collector_version 2 is claimed, which is the difference between "we can finish a job"
    # and "we can start one".
    if not journal_write(entries):
        return None
    return entries


def journal_prune(entries, now):
    """Drop tombstones that have outlived their usefulness. Reported results only."""
    out = {}
    for jid, e in entries.items():
        rep = e.get("reported_at")
        if isinstance(rep, int) and now - rep > JOURNAL_TTL_S:
            continue
        out[jid] = e
    if len(out) <= JOURNAL_MAX_ENTRIES:
        return out
    # Oldest REPORTED entries go first: an unreported result is still owed to the server and
    # a tombstone still protects a job from a second attempt, so the ones that have done both
    # jobs are the only ones safe to lose. Keyed by the DICTIONARY KEY rather than by the
    # entry's own 'id' field — the key is the job id this file is indexed by, and an entry
    # whose body disagrees with its key must still be removable.
    reported = sorted((jid for jid, e in out.items() if isinstance(e.get("reported_at"), int)),
                      key=lambda jid: out[jid].get("reported_at") or 0)
    for jid in reported[:len(out) - JOURNAL_MAX_ENTRIES]:
        out.pop(jid, None)
    return out


def pending_results(entries):
    """The results owed to the server, oldest first.

    Reported on the NEXT push rather than in a POST of their own: this collector makes one
    outbound request per pass by design, the unit file says so, and adding a second would be
    a second thing to reason about on the only channel that exists. The cost is that a result
    is up to one timer interval old when it lands, which every confirm_deadline_s on this
    path (2400s) is sized for.
    """
    owed = [e for e in entries.values()
            if e.get("state") == "done" and e.get("reported_at") is None
            and e.get("status") in ("applied", "failed") and isinstance(e.get("id"), str)]
    owed.sort(key=lambda e: e.get("finished_at") or 0)
    return [{"job_id": e["id"], "status": e["status"], "result_log": (e.get("log") or "")[:2000]}
            for e in owed[:MAX_RESULTS_PER_PUSH]]


def mark_reported(entries, results, now=None):
    """A 200 means the body was processed, so these are delivered.

    Not re-sent afterwards. recordPmrJobResult only closes a job still in 'claimed', so a
    result the server declined (an expired job, say) would be declined identically forever —
    re-sending it would be a loop that changes nothing. The entry STAYS as a tombstone, which
    is the part that matters: it is what stops the job running twice.
    """
    now = int(now if now is not None else time.time())
    for r in results:
        e = entries.get(r["job_id"])
        if e is not None:
            e["reported_at"] = now


# ── PLANNING A JOB — every refusal this side can make ────────────────────────
def plan_job(job, node, is_local=None):
    """Turn one server job into either an argv to run or a refusal to report.

    Returns (plan, unusable). Exactly one is set:
      plan     {"job_id", "verb", "argv", ...}          — validated, safe to run
      plan     {"job_id", "verb", "refused": "why"}     — reported FAILED with the reason
      unusable "why"                                     — no id to report against; logged only

    ⛔ REFUSED IS REPORTED, NOT DROPPED. A job that vanishes silently is 'claimed' forever
    and reads as work in flight; a job that fails with a reason ends the ladder and raises a
    person. Those are very different things to be looking at when a pharmacy is opening.
    """
    is_local = is_local or vm_is_local
    if not isinstance(job, dict):
        return None, "job entry is not an object"
    jid = job.get("id")
    if not isinstance(jid, str) or not JOB_ID_RE.match(jid):
        return None, "job has no usable id (%s)" % _short(jid)

    verb = job.get("verb")
    spec = JOB_VERBS.get(verb) if isinstance(verb, str) else None
    if spec is None:
        # ⛔ NEVER GUESSED AT. Not a prefix match, not a fallback, not "it looks like a
        # start". A name this table does not hold means the two sides disagree about what
        # this node can do, and the only safe response is to say so.
        return {"job_id": jid, "verb": _short(verb), "refused":
                "unknown verb %s — this node implements only: %s"
                % (_short(verb), ", ".join(sorted(JOB_VERBS)))}, None

    args = job.get("args")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return {"job_id": jid, "verb": verb,
                "refused": "args is not an object (%s)" % type(args).__name__}, None

    # ── REFUSING A FOREIGN NODE ───────────────────────────────────────────────
    # ⛔ REFUSED, NEVER FORWARDED. Forwarding would mean this node acting on another node's
    # VMs on the server's say-so, which is the whole shape of thing this design exists to
    # not have. There is no code path here that can reach another node, and there must not
    # be one: `qm` is local by construction.
    #
    # The server already scopes its claim to the credential's node. This check exists
    # because that is the server's guarantee, not ours.
    for where in ("job", "args"):
        claimed = job.get("node") if where == "job" else args.get("node")
        if claimed is None:
            continue
        if not isinstance(claimed, str) or claimed.strip() != node:
            return {"job_id": jid, "verb": verb, "refused":
                    "%s names node %s, but this is node %r — refused, not forwarded"
                    % (where, _short(claimed), node)}, None

    # A closed set: an argument this verb does not take means the sides disagree about the
    # verb, and running the part we recognise while ignoring the rest would be guessing.
    extra = sorted(set(args) - set(spec["args"]) - {"node"})
    if extra:
        return {"job_id": jid, "verb": verb, "refused":
                "unexpected argument(s) for %s: %s"
                % (verb, _short(", ".join(extra)))}, None

    clean = {}
    for name, check in spec["args"].items():
        if name not in args:
            return {"job_id": jid, "verb": verb,
                    "refused": "missing argument %r for %s" % (name, verb)}, None
        val, err = check(args[name])
        if err:
            return {"job_id": jid, "verb": verb,
                    "refused": "argument %r %s" % (name, err)}, None
        clean[name] = val

    # ── AND THE VM ITSELF MUST BE OURS ────────────────────────────────────────
    # The node-name check above only fires if the server volunteered a name, and today it
    # does not — jobs arrive as {id, verb, args}. THIS is the check that actually catches a
    # job for another node's VM: a vmid with no config file under our own name is not ours,
    # whatever the reply said.
    if not is_local(node, clean["vmid"]):
        return {"job_id": jid, "verb": verb, "refused":
                "VM %d is not on node %r (no /etc/pve/nodes/%s/qemu-server/%d.conf) — "
                "refused, not forwarded" % (clean["vmid"], node, node, clean["vmid"])}, None

    argv = spec["argv"](clean)
    # The last gate before exec. Nothing that reached here can fail it — which is exactly
    # why it is worth having: a future verb whose builder lets a server string through
    # breaks here, loudly, instead of quietly becoming an argument.
    for tok in argv:
        if not isinstance(tok, str) or not ARGV_TOKEN_RE.match(tok):
            return {"job_id": jid, "verb": verb,
                    "refused": "refusing malformed argv token %s for %s"
                                % (_short(tok), verb)}, None

    return {"job_id": jid, "verb": verb, "argv": argv, "vmid": clean["vmid"],
            "disruptive": spec["disruptive"], "timeout_s": spec["timeout_s"]}, None


def run_local(argv, timeout_s, limit=1000):
    """Run one already-validated argv. Returns (rc, output).

    A list, so there is no shell to inject into even if everything above were wrong.

    `limit` bounds the captured output. 1000 suits a job's log line; a caller that has to PARSE
    what it gets back must pass enough to hold a whole answer, because a truncated JSON document
    fails as a parse error that reads exactly like the command having failed.
    """
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s)
    except FileNotFoundError:
        return 127, "qm not found on this node"
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ds" % timeout_s
    except Exception as e:                                   # noqa: BLE001 - reported, not swallowed
        return 1, "%s: %s" % (type(e).__name__, e)
    return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()[:limit]


# ── RUNNING THE BATCH ────────────────────────────────────────────────────────
def run_job_batch(jobs, node, entries, deadline, run=None, is_local=None, commit=None,
                  now=None):
    """Execute the jobs from a report reply. Returns a list of log lines.

    SERIAL, not threaded. WORKERS=3 is for read-only probes; these change the state of a
    machine, and two of them power a pharmacy desktop down. A pool here would let a start
    and a shutdown of the same VM interleave, and would put three `qm` invocations on top of
    pvedaemon's three workers on a node hosting live desktops.
    """
    run = run or run_local
    is_local = is_local or vm_is_local
    commit = commit if commit is not None else (lambda: journal_write(entries))
    clock = now or time.time
    out = []

    if jobs is None:
        return out                                   # the ordinary idle reply: no key at all
    if not isinstance(jobs, list):
        out.append("reply's 'jobs' is not an array (%s) — ignored" % type(jobs).__name__)
        return out
    if len(jobs) > MAX_JOBS_PER_PASS:
        out.append("reply offered %d jobs, more than the %d this pass will take — the rest "
                   "stay pending and come back next tick"
                   % (len(jobs), MAX_JOBS_PER_PASS))

    seen = set()
    for job in jobs[:MAX_JOBS_PER_PASS]:
        plan, unusable = plan_job(job, node, is_local=is_local)
        if plan is None:
            # Nothing to report against — there is no id to attach a result to. Loud on
            # stderr is all that is available, and it is a malformed server, not a job.
            out.append("refused a job with no usable id: %s" % unusable)
            continue
        jid = plan["job_id"]

        # ⛔ ONCE-ONLY, AND THIS IS WHERE IT IS ENFORCED. Any prior record at all — applied,
        # failed, refused, interrupted — means this node has already been handed this job.
        # A lost acknowledgement puts the server in exactly this position: it re-offers a
        # job we already ran. It does not run again. The outcome we recorded the first time
        # is reported instead (pending_results picks it up if it is still owed).
        if jid in seen:
            out.append("job %s offered twice in one reply — attempted once" % jid)
            continue
        seen.add(jid)
        prior = entries.get(jid)
        if prior is not None:
            # A record with no reportable outcome can only come from a journal that was
            # damaged in shape rather than in syntax. Closed as failed rather than left
            # silent: the job has been attempted here, so it must not run, and the server is
            # still owed an answer.
            if prior.get("status") not in ("applied", "failed"):
                prior["state"] = "done"
                prior["status"] = "failed"
                prior["finished_at"] = int(clock())
                prior["log"] = ("a previous attempt at this job is recorded on this node with "
                                "no outcome. It has NOT been run again; check the VM before "
                                "assuming either way.")
                prior["reported_at"] = None
                commit()
            elif prior.get("reported_at") is not None:
                # Already told the server once and it asked again: re-owe the answer rather
                # than leave the re-offer unanswered.
                prior["reported_at"] = None
                commit()
            out.append("job %s was already attempted here (%s) — NOT run again"
                       % (jid, prior.get("status") or prior.get("state")))
            continue

        entry = {"id": jid, "verb": plan.get("verb"), "vmid": plan.get("vmid"),
                 "state": "done", "status": None, "log": None,
                 "started_at": int(clock()), "finished_at": int(clock()),
                 "reported_at": None}

        if "refused" in plan:
            entry["status"] = "failed"
            entry["log"] = plan["refused"][:2000]
            entries[jid] = entry
            commit()
            out.append("job %s REFUSED: %s" % (jid, plan["refused"]))
            continue

        # ── the pass budget ───────────────────────────────────────────────────
        # Only start what can finish inside the budget, so the phase cannot overrun
        # HARD_PASS_BUDGET_S and the flock/TimeoutStartSec pair keeps holding. A job that
        # does not fit is FAILED with the reason, not skipped: skipping leaves it claimed
        # and silent, which is the outcome this whole ladder exists to prevent.
        if clock() + plan["timeout_s"] > deadline:
            entry["status"] = "failed"
            entry["log"] = ("not attempted: the pass ran out of its time budget before this "
                            "job could be started. Nothing was run and the VM was not "
                            "touched.")
            entries[jid] = entry
            commit()
            out.append("job %s not attempted (pass budget)" % jid)
            continue

        # ── WRITE-AHEAD, and this is the line that makes a second shutdown impossible ──
        # The record that this job was STARTED goes to disk, fsynced, BEFORE the command
        # runs. If the process dies at any point after this — killed by TimeoutStartSec, the
        # node rebooting, anything — the next pass finds state 'running' and settles it as
        # failed rather than starting it again.
        entry["state"] = "running"
        entries[jid] = entry
        if not commit():
            # Cannot make the attempt durable, so do not make it. Without the record, a kill
            # mid-command would leave nothing to stop a second one.
            del entries[jid]
            out.append("job %s NOT run: the journal could not be written, so a second "
                       "attempt could not be ruled out" % jid)
            continue

        rc, output = run(plan["argv"], plan["timeout_s"])
        entry["finished_at"] = int(clock())
        entry["state"] = "done"
        shown = " ".join(plan["argv"])
        if rc == 0:
            entry["status"] = "applied"
            entry["log"] = ("%s -> exit 0. %s" % (shown, output or "(no output)"))[:2000]
        else:
            entry["status"] = "failed"
            # ⚠️ 'failed' HERE MEANS 'NOT PROVEN', WHICH IS THE HONEST WORD. A `qm shutdown`
            # that hit its timeout may still be in progress inside the guest. Saying
            # 'applied' because we asked would be the "it exited 0, so it worked" mistake
            # one level up; saying 'failed' ends the ladder and puts a person in front of it.
            entry["log"] = ("%s -> exit %d. %s%s" % (
                shown, rc, output or "(no output)",
                "  NOTE: the command did not complete here; whether the guest acted on it "
                "is unknown from this side." if rc == 124 else ""))[:2000]
        commit()
        # ⚠️ 'applied' IS NOT 'IT WORKED'. It says this node ran the thing. Whether the world
        # changed is decided by Vigilant, from a reading taken separately.
        out.append("job %s %s: %s" % (jid, entry["status"], shown))
    return out


def job_branch_ready(node, entries):
    """Is this collector genuinely able to take a job on this pass?

    All three, every pass — the node knows its own name, `qm` is here, and the journal that
    makes execution once-only is open. Only then is COLLECTOR_VERSION claimed. Anything less
    and the key is omitted, the server reads 0, and it hands out nothing.
    """
    if not node:
        return False, "this node cannot establish its own Proxmox name from /etc/pve/local"
    if entries is None:
        return False, "the job journal is unusable, so once-only execution is not guaranteed"
    if not shutil.which("qm"):
        return False, "`qm` is not on PATH, so no verb in the table can be carried out"
    return True, None


def acquire_lock():
    """Non-blocking flock. Returns the held file object, or None if another pass owns it.

    The fd is deliberately never closed — it is released when the process exits, which is the
    only correct moment. Kept in a local of main() for the lifetime of the pass so it cannot be garbage
    collected mid-pass and silently drop the lock.
    """
    try:
        fh = open(LOCK_PATH, "a+")
    except OSError as e:
        # /run not writable (a non-root test run) is not a reason to refuse to collect.
        print(f"collector: cannot open {LOCK_PATH} ({e}) — continuing unlocked", file=sys.stderr)
        return False
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        if e.errno in (errno.EACCES, errno.EAGAIN):
            fh.close()
            return None
        raise
    return fh


def main():
    # THE WHOLE PASS, from here: collection, the push, and any job work that arrives on the
    # reply. TimeoutStartSec is 420s and systemd kills the process there, so HARD_PASS_BUDGET_S
    # leaves margin and the job phase refuses to start anything that would not finish inside it.
    # The collection phase keeps its own PASS_DEADLINE_S — that one bounds the part of the pass
    # that talks to other nodes, this one bounds the pass.
    pass_deadline = time.time() + HARD_PASS_BUDGET_S

    # EXIT 0, not an error: an overrunning tick being skipped is the designed behaviour, and a
    # failure exit would light up the timer's unit as failed every time it worked correctly.
    lock = acquire_lock()
    if lock is None:
        print("collector: a previous pass is still running — skipping this tick", flush=True)
        return 0

    conf = load_conf()
    missing = [k for k in ("VIGILANT_URL", "VIGILANT_ADMIN_TOKEN") if not conf.get(k)]
    if missing:
        print(f"collector: missing {', '.join(missing)} in {CONF}", file=sys.stderr)
        return 2

    # ── the job branch is decided BEFORE the push, because the push is where it is claimed ──
    # collector_version is an offer to take work, and the offer is answered on the same reply.
    # So everything that offer depends on has to be true now, not hoped for later: this node's
    # own name, and a journal that can record an attempt before it is made.
    node = local_node_name()
    journal = journal_open()
    can_take_jobs, why_not = job_branch_ready(node, journal)
    if not can_take_jobs:
        # Said out loud every pass. "Onboot never converges" is otherwise diagnosed as a broken
        # queue on the server, when the answer is here.
        print(f"collector: NOT offering to take jobs this pass — {why_not}", file=sys.stderr)

    vms = collect(local_node=node)
    if vms is None:
        return 1

    # Lifted out of each VM into its own top-level array, which is the shape the ingest
    # validates. AGGREGATES ONLY — the raw RRD series is 26 VMs x 1440 samples x 3 timeframes
    # and the ingest's readBody() concatenates the whole body into a string with no size cap.
    capacity = []
    for v in vms:
        cap = v.pop("capacity", None)
        if cap:
            capacity.append(cap)

    # Lifted out the same way, and for the same reason, as `capacity`: its own top-level array
    # is the shape the ingest validates. A VM this pass did not read reports NO ROW here — the
    # array is short, never padded with empties, because an empty list is a claim about Windows
    # and this pass is not entitled to make it on a desktop it never asked.
    printers = []
    for v in vms:
        pr = v.pop("printers", None)
        if pr:
            printers.append(pr)

    # Node headroom: one row per (node, pool). Collected AFTER the VM pass so a node already
    # known unreachable is reported as unreadable rather than retried.
    nodes = collect_nodes()

    payload = {"vms": vms, "capacity": capacity, "printers": printers, "nodes": nodes}

    # ── NAMING OURSELVES, and it is a SAFETY CHECK rather than a courtesy ─────────────
    # The ingest compares this against the node its per-node token belongs to and REFUSES the
    # push if they differ. That refusal is the cleanest possible outcome for the worst
    # misconfiguration on this path — a token issued for node A ending up on node B — because
    # the alternative is this collector being handed node A's jobs while running on node B.
    # It costs nothing when it is right and it is loud when it is wrong, and the inventory
    # write happens before that check server-side, so the estate's VM view is never the price.
    if node:
        payload["node"] = node

    # RESULTS OWED FROM EARLIER PASSES, reported on the push this collector already makes.
    results = pending_results(journal) if journal is not None else []
    if results:
        payload["job_results"] = results

    if can_take_jobs:
        payload["collector_version"] = COLLECTOR_VERSION

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        conf["VIGILANT_URL"].rstrip("/") + "/proxmox/report",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA,
                 "Authorization": f"Bearer {conf['VIGILANT_ADMIN_TOKEN']}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            # The WHOLE reply, not the first 400 bytes: the jobs ride on it. Bounded, because
            # a body of unknown size from the network is not read into memory unbounded — 256K
            # is far beyond the four jobs the ingest will ever put here.
            raw = r.read(262144).decode("utf-8", "replace")
            http_status = r.status
    except urllib.error.HTTPError as e:
        extra = " (Cloudflare may be blocking the client signature)" if e.code == 403 else ""
        # The BODY as well as the code. A 400 on this route is most likely the node-name
        # mismatch above, and that message names both sides of it — which is the difference
        # between a five-minute fix and a mystery.
        try:
            detail = e.read(2048).decode("utf-8", "replace").strip()[:300]
        except Exception:                                # noqa: BLE001 - diagnostics only
            detail = ""
        print(f"collector: HTTP {e.code}{extra} {detail}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"collector: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    # Unreachable nodes are named in the log line: a pass that quietly reports fewer
    # capacity rows looks exactly like a pass where nothing changed.
    skipped = ", ".join(sorted(_node_down)) or "none"
    print(f"reported {len(vms)} VMs, {len(capacity)} capacity rows, "
          f"{len(printers)} printer readings, {len(nodes)} node headroom rows "
          f"(nodes skipped: {skipped}) -> {http_status} {raw[:400]}", flush=True)

    reply = None
    try:
        reply = json.loads(raw)
    except ValueError:
        pass
    if not isinstance(reply, dict):
        # A 200 whose body is not an object means the inventory landed but nothing on the job
        # channel can be trusted. Report it and take no work — a malformed reply is exactly
        # the reply not to start guessing at.
        print("collector: reply was not a JSON object — no jobs taken from it",
              file=sys.stderr)
        reply = {}

    # The results in this push were delivered with it. Marked BEFORE any job runs, so a
    # crash in the job phase cannot cost a result its acknowledgement and re-send it.
    if results and journal is not None:
        mark_reported(journal, results)
        journal_write(journal)

    # Why the server says this node is getting no work. Surfaced verbatim rather than
    # summarised: it distinguishes "you have no per-node token" from "your version is below
    # the floor", and those have completely different fixes.
    if isinstance(reply.get("jobs_skipped"), str):
        print(f"collector: server says: {reply['jobs_skipped']}", flush=True)

    if can_take_jobs:
        for line in run_job_batch(reply.get("jobs"), node, journal, pass_deadline):
            print(f"collector: {line}", flush=True)
    elif reply.get("jobs"):
        # Should be unreachable — the version was not claimed, so nothing should have been
        # offered. Said very loudly if it happens anyway, because handing a job out IS the
        # claim and these ones have just been swallowed.
        print(f"collector: ⚠️ the server offered {len(reply['jobs'])} job(s) to a collector "
              f"that did not claim it could take any ({why_not}). They have been CLAIMED "
              f"server-side and NOT run — they will expire and must be re-created.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
