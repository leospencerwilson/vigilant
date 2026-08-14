#!/usr/bin/env bash
# Bake the WCN thin-client SD image from a stock Raspberry Pi OS Lite (64-bit) image.
#
# Run this ONCE on a Linux box to produce wcn-thin-client.img.xz, then host that artifact
# (it's multi-GB) and point VITE_THIN_CLIENT_IMAGE_URL at it. Every Pi uses the one image;
# it self-enrols on first boot with the SHARED bootstrap token baked in here, so there is no
# per-device step. See the Install Thin Client page for the operator side.
#
# This customises the image by loop-mounting its rootfs and copying files in — no emulation,
# no chroot needed for what we do (drop files + enable a unit + write env). First boot does
# the rest (the agent self-enrols; the kiosk starts).
#
# Requires: root, xz, and a stock image. NOT run in CI here — it touches loop devices.
set -euo pipefail

# ── inputs ───────────────────────────────────────────────────────────────────
BASE_IMG="${1:-}"
VIGILANT_URL="${2:-}"
BOOTSTRAP_TOKEN="${3:-}"
if [ -z "$BASE_IMG" ] || [ -z "$VIGILANT_URL" ] || [ -z "$BOOTSTRAP_TOKEN" ]; then
  echo "usage: build-image.sh RASPIOS_LITE.img VIGILANT_URL BOOTSTRAP_TOKEN [authorized_keys]" >&2
  echo "  BOOTSTRAP_TOKEN is the SELF_ENROL_TOKEN from Vigilant's .env" >&2
  exit 2
fi
# Optional 4th argument: an authorized_keys file baked into the image. Supplied rather than
# hardcoded so nobody has to edit this script to add an engineer, and so a key is never
# committed to the repo.
#
# WHY THIS MATTERS: the first fleet Pi shipped with exactly ONE engineer's key and no inbound
# route, which meant every fix needed that person or someone physically on site. At 500
# devices that is unsupportable. Put every on-call engineer's key in here.
AUTH_KEYS="${4:-}"
OUT="wcn-thin-client.img"
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v xz >/dev/null || { echo "xz not installed"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (loop mounts)"; exit 1; }

# ── work on a copy ───────────────────────────────────────────────────────────
cp --reflink=auto "$BASE_IMG" "$OUT"

# Map partitions; rootfs is the 2nd partition on a stock RPi OS image.
LOOP="$(losetup --show -fP "$OUT")"
trap 'umount "$MNT/boot/firmware" 2>/dev/null || true; umount "$MNT" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true' EXIT
MNT="$(mktemp -d)"
mount "${LOOP}p2" "$MNT"
mount "${LOOP}p1" "$MNT/boot/firmware" 2>/dev/null || mount "${LOOP}p1" "$MNT/boot" || true

# ── drop in the agent + kiosk ────────────────────────────────────────────────
install -D -m 0755 "$HERE/vigilant-pi-agent.py" "$MNT/usr/local/sbin/vigilant-pi-agent"
install -D -m 0755 "$HERE/../pi/wcn-kiosk"        "$MNT/usr/local/bin/wcn-kiosk"

# ── bootstrap config: URL + shared token, NO per-device token yet ────────────
# The agent finds no VIGILANT_TOKEN on first boot, so it self-enrols with the bootstrap
# token and rewrites this file with the per-device token it is issued.
install -d -m 0755 "$MNT/etc/vigilant"
cat > "$MNT/etc/vigilant/agent.env" <<EOF
VIGILANT_URL=$VIGILANT_URL
VIGILANT_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
VIGILANT_AUTO_UPDATE=1
EOF
chmod 0600 "$MNT/etc/vigilant/agent.env"

# ── support access: engineers' keys ─────────────────────────────────────────
if [ -n "$AUTH_KEYS" ] && [ -r "$AUTH_KEYS" ]; then
  install -d -m 0700 -o 1000 -g 1000 "$MNT/home/westerncomms/.ssh"
  install -m 0600 -o 1000 -g 1000 "$AUTH_KEYS" "$MNT/home/westerncomms/.ssh/authorized_keys"
  echo "  baked $(grep -c '^ssh-' "$AUTH_KEYS" 2>/dev/null || echo '?') support key(s)"
else
  echo "  WARNING: no authorized_keys supplied — this image will be reachable by nobody." >&2
  echo "           Pass one as the 4th argument, or you will need physical access to fix it." >&2
fi

# ── WireGuard: let the hub reach the thin client ─────────────────────────────
# AllowedIPs is WireGuard's routing table, so a Pi with only 10.1.0.0/24 can RECEIVE from the
# hub but has no route to reply — SSH from the hub looks filtered and remote support is
# impossible. Including the hub subnet is what makes a thin client supportable without a site
# visit. Applied as an idempotent first-boot fixup because wg0.conf is site-specific (keys,
# endpoint, address) and is not created here.
install -D -m 0755 /dev/stdin "$MNT/usr/local/sbin/wcn-wg-allow-hub" <<'FIX'
#!/bin/sh
# Add the support subnets to AllowedIPs if a site config exists and lacks them. Safe to re-run.
#
# BOTH are required, for different reasons, and getting only the first is the trap:
#   10.255.0.0/24  the tunnel itself, so the Pi can address other tunnel endpoints.
#   10.10.30.0/24  the MANAGEMENT LAN behind the hub. An inbound SSH from the bastion
#                  arrives with source 10.10.30.10, so with no route back the Pi accepts
#                  the SYN and cannot answer it. MEASURED on the pilot Pi: with only
#                  10.255.0.0/24 present the tunnel handshakes and telemetry flows, yet
#                  port 22 is unreachable from the bastion. Silent, and looks like a
#                  firewall drop rather than a missing route.
CONF=/etc/wireguard/wg0.conf
[ -r "$CONF" ] || exit 0
changed=0
for net in 10.255.0.0/24 10.10.30.0/24; do
  # Literal match: the dots must not act as wildcards, or 10.10.30.0/24 would be
  # considered already present by an unrelated 10.10.300/24-shaped string.
  grep -qF "$net" "$CONF" && continue
  [ "$changed" = 0 ] && cp "$CONF" "$CONF.bak-allowhub"
  # Only the FIRST AllowedIPs line: a multi-peer config must not have every peer widened.
  sed -i "0,/^AllowedIPs/s#^\(AllowedIPs *= *.*\)\$#\1, $net#" "$CONF"
  changed=1
done
[ "$changed" = 1 ] && systemctl restart wg-quick@wg0
exit 0
FIX
cat > "$MNT/etc/systemd/system/wcn-wg-allow-hub.service" <<'EOF'
[Unit]
Description=Ensure WireGuard AllowedIPs includes the support hub subnet
After=network-online.target
ConditionPathExists=/etc/wireguard/wg0.conf

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wcn-wg-allow-hub
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/wcn-wg-allow-hub.service \
   "$MNT/etc/systemd/system/multi-user.target.wants/wcn-wg-allow-hub.service"

# ── branding targets must EXIST in the image ─────────────────────────────────
# The unit below grants write access to /etc/motd and /etc/issue with ReadWritePaths, and systemd
# implements that as a BIND MOUNT of the named file. A path that does not exist at unit start
# therefore gets no grant at all — and because the entries are (correctly) optional, that failure
# is silent: the agent would keep running and every branding write would come back EROFS. Stock
# Raspberry Pi OS ships both files, but a stripped base image is exactly the sort of thing that
# would cost a day here, so create them if they are missing rather than assume.
[ -e "$MNT/etc/motd" ]  || : > "$MNT/etc/motd"
[ -e "$MNT/etc/issue" ] || : > "$MNT/etc/issue"
chmod 0644 "$MNT/etc/motd" "$MNT/etc/issue"

# ── systemd unit for the agent ───────────────────────────────────────────────
cat > "$MNT/etc/systemd/system/vigilant-agent.service" <<'EOF'
[Unit]
Description=Vigilant agent (counter Pi)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/sbin/vigilant-pi-agent
Restart=always
RestartSec=10
# full (not strict): strict remounts / read-only inside the unit namespace, which made the
# agent's own SD-wear check misreport a healthy Pi as faulty.
ProtectSystem=full
# The screen thumbnail is an X11 grab, so it needs the display socket and the session cookie.
# Granted explicitly, so that hardening this unit later (PrivateTmp / ProtectHome both hide
# exactly these) cannot silently break capture with no error that names sandboxing.
#
# The "-" prefix is REQUIRED, not tidiness: the kiosk creates both paths when it starts X, so
# on a cold boot the agent can reach this point before they exist. A non-optional bind would
# fail the unit and leave it restarting every 10s until someone logged in — turning a missing
# screenshot into a dead monitoring agent, which is far worse than no screenshot.
BindReadOnlyPaths=-/tmp/.X11-unix
BindReadOnlyPaths=-/home/westerncomms/.Xauthority:/run/wcn-xauth
# Fleet branding: the agent writes the WCN console text and the boot splash when Watchman pushes
# a new set. ProtectSystem=full mounts /etc AND /boot read-only inside this namespace, so these
# three paths are granted SURGICALLY — do NOT relax ProtectSystem to get them, and do NOT add
# /boot or /boot/firmware. cmdline.txt (quiet, logo.nologo) is set once at bake time on purpose:
# it is the one file with no remote recovery, and a typo in it means a Pi that does not boot, so
# no SSH, no agent and a drive to a pharmacy with an SD card reader.
#
# The "-" prefix is REQUIRED on every line, not tidiness: a non-optional ReadWritePaths entry
# whose path does not exist FAILS THE UNIT, and a failed unit is a dead monitoring agent
# restarting every 10s. Pi OS Lite may have no plymouth installed at all, so that theme directory
# legitimately does not exist on some devices. A missing splash theme must degrade to "no splash",
# never to "no agent".
#
# The first two are per-FILE grants: the inode becomes writable, /etc itself stays read-only. The
# agent therefore rewrites those two in place instead of renaming a temp file over them, and the
# files must exist in the image (created above) for the bind to happen at all.
ReadWritePaths=-/etc/motd
ReadWritePaths=-/etc/issue
ReadWritePaths=-/usr/share/plymouth/themes/pix
# The agent replaces its OWN binary when Watchman ships a new one (VIGILANT_AUTO_UPDATE=1
# above), and that binary lives under /usr - which ProtectSystem=full mounts read-only
# inside this namespace. Without this grant EVERY self-update fails with EROFS, silently,
# while the agent otherwise looks perfectly healthy. Measured on a fresh install 2026-08-14.
ReadWritePaths=-/usr/local/sbin

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/vigilant-agent.service \
   "$MNT/etc/systemd/system/multi-user.target.wants/vigilant-agent.service"

# NOTE: the kiosk (xinit/getty autologin -> wcn-kiosk), FreeRDP, pcscd, CUPS and the
# WireGuard interface are the remaining image content. They are site-independent EXCEPT the
# WireGuard key: a Pi generates its own key on first boot and reports its public key in
# telemetry, so the hub side is provisioned at adoption. Wire that into first-boot here.

sync
umount "$MNT/boot/firmware" 2>/dev/null || umount "$MNT/boot" 2>/dev/null || true
umount "$MNT"
losetup -d "$LOOP"
trap - EXIT
rmdir "$MNT"

# ── compress for distribution ────────────────────────────────────────────────
xz -T0 -9 -f "$OUT"
echo "built ${OUT}.xz — host it and set VITE_THIN_CLIENT_IMAGE_URL to its download URL"
