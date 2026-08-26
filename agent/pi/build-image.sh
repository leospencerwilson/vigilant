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
  echo "usage: build-image.sh RASPIOS_LITE.img VIGILANT_URL BOOTSTRAP_TOKEN [authorized_keys] [toolbox_secret_file]" >&2
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
# Optional 5th argument: a file containing the ESTATE toolbox secret, baked in like the
# bootstrap token above. Supplied rather than hardcoded for the same reason as the keys — it
# must never be committed.
#
# It is deliberately estate-wide, NOT per-device, and that is safe because the PIN a person
# types is HMAC-SHA256(this secret, that board's serial) truncated to six digits: every Pi
# built from one image still has a DIFFERENT PIN, so a number read aloud at a counter opens
# that counter and nothing else. Baking a per-device secret is impossible here anyway — one
# image serves the whole fleet, which is the entire point of self-enrolment.
TOOLBOX_SECRET_FILE="${5:-}"
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

# ── the on-console support toolbox ("BIOS" for a thin client) ────────────────
# Without this a rebuilt counter comes up with NO support menu, and the failure is invisible
# until someone is standing at a dark counter during an outage — which is the exact scenario
# the toolbox exists for. It was hand-installed on the pilot; that is why it is here now.
#
# The two halves have deliberately different modes, and this is the security model:
#   wcn-toolbox      0755  runs UNPRIVILEGED as westerncomms on tty1, can act only by naming
#                          a verb in the helper below. It must never be root: tty1 autologins
#                          westerncomms and the chain is getty -> .bash_profile -> startx ->
#                          wcn-kiosk, so an escape from a menu there is a root shell at a
#                          pharmacy counter, one `cat` from the RDP creds and the wg key.
#   wcn-toolbox-priv 0700  root-only. Holds every privileged verb, reads the PIN secret, and
#                          never prints it.
install -D -m 0755 "$HERE/wcn-toolbox"      "$MNT/usr/local/bin/wcn-toolbox"
install -D -m 0700 "$HERE/wcn-toolbox-priv" "$MNT/usr/local/sbin/wcn-toolbox-priv"

# Console splash. Optional by design — the toolbox tests [ -r "$LOGO" ] and simply omits it,
# so a missing file costs branding, never a boot.
if [ -r "$HERE/wcn-logo.ansi" ]; then
  install -D -m 0644 "$HERE/wcn-logo.ansi" "$MNT/usr/local/share/wcn/logo.ansi"
fi

install -d -m 0755 "$MNT/etc/wcn"

# The F4 window before the desktop starts. FOUR seconds, matching the pilot.
#
# ⚠️ The toolbox reads this as an unclamped integer and a bad value is not rejected: a stray
# 600 held a counter on the splash for TEN MINUTES on every boot (2026-08-17) and nothing
# reported it. Keep it small, and note the agent now reports it so the fleet view catches a
# repeat.
echo 4 > "$MNT/etc/wcn/boot-wait"
chmod 0644 "$MNT/etc/wcn/boot-wait"

if [ -n "$TOOLBOX_SECRET_FILE" ] && [ -r "$TOOLBOX_SECRET_FILE" ]; then
  install -m 0600 -o root -g root "$TOOLBOX_SECRET_FILE" "$MNT/etc/wcn/toolbox.secret"
  echo "  baked the toolbox PIN secret"
else
  # Fail LOUD but do not abort: an image without it still boots and still runs the kiosk, and
  # a pharmacy counter that works is worth more than one that refuses to build. But every
  # PIN-gated action is unreachable, so this must not pass unnoticed.
  echo "  WARNING: no toolbox secret supplied — the support menu will refuse every PIN action" >&2
  echo "           on every Pi from this image. Pass the secret file as the 5th argument." >&2
fi

# Boot into the toolbox, which shows the F4 window and then starts the desktop itself.
#
# `exec` (not a child) is REQUIRED, not stylistic: as a child of the interactive login shell
# the whiptail menu is not in the terminal's foreground process group, takes a SIGTTOU and
# freezes to a black screen. Owning the tty1 session is what keeps the menu in the foreground.
# The bare `startx` after it is a hard fail-open — reached only if the toolbox binary is
# missing or unrunnable, so a broken toolbox can never cost a pharmacy its counter.
install -d -m 0755 -o 1000 -g 1000 "$MNT/home/westerncomms"
cat > "$MNT/home/westerncomms/.bash_profile" <<'PROFILE'
# Physical console only; SSH logins (any other tty) are unaffected.
if [ "$(tty)" = "/dev/tty1" ] && [ -z "${DISPLAY:-}" ]; then
    exec /usr/local/bin/wcn-toolbox --boot
    exec startx
fi
PROFILE
chmod 0644 "$MNT/home/westerncomms/.bash_profile"
chown 1000:1000 "$MNT/home/westerncomms/.bash_profile"

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

# ── quiet boot (bake-time ONLY) ──────────────────────────────────────────────
# The counter should come up like a commercial thin client — a black screen then the WCN splash
# and progress bar the toolbox draws — not a wall of kernel and systemd text. That verbosity is
# controlled by cmdline.txt, which is THE ONE FILE ON THE PI WITH NO REMOTE RECOVERY: a typo
# means a device that will not boot, so no SSH, no agent, no tunnel, and a drive to a pharmacy
# with an SD reader. So it is set here at bake time and NEVER pushed live (a live retrofit, if it
# is ever done, has to carry its own write-validate-reboot-with-dead-man-revert — see the agent).
#
# We MODIFY the existing line in place, we never rewrite it: root=, rootfstype= and the partition
# UUID the firmware hands the kernel are preserved byte-for-byte, and we only append the tokens
# the line does not already carry. cmdline.txt must also stay a SINGLE line — a stray newline is
# itself a non-boot — so it is read with the newline stripped and written back as one line.
CMDLINE=""
for c in "$MNT/boot/firmware/cmdline.txt" "$MNT/boot/cmdline.txt"; do
  [ -f "$c" ] && { CMDLINE="$c"; break; }
done
if [ -n "$CMDLINE" ]; then
  line="$(tr -d '\n' < "$CMDLINE")"
  # Add the tokens the line does not already carry:
  #   quiet loglevel=3            hush the kernel printk stream
  #   logo.nologo                 drop the framebuffer raspberries
  #   vt.global_cursor_default=0  no blinking cursor left on the console
  #   consoleblank=0              never blank the counter's screen on a timer
  #   systemd.show_status=false   hide the [ OK ] unit ladder
  #   plymouth.enable=0           no Plymouth at all. On a Pi 3B the GPU is not up for ~12s, so
  #                               Plymouth only ever showed a text-dot fallback or, with splash off,
  #                               dumped the boot log. The WCN brand is carried by wcn-boot-logo and
  #                               the toolbox instead. Proven on the pilot 2026-08-19.
  for tok in quiet loglevel=3 logo.nologo vt.global_cursor_default=0 consoleblank=0 systemd.show_status=false plymouth.enable=0; do
    case " $line " in *" $tok "*) ;; *) line="$line $tok" ;; esac
  done
  # REMOVE two tokens the stock image ships that fight a clean boot: console=tty1 dumps the kernel
  # log onto the screen (serial console is kept), and splash asks the now-disabled Plymouth to draw.
  # root=, its PARTUUID and rootfstype are never touched — only these two named tokens are dropped.
  line=" $line "; line="${line// console=tty1 / }"; line="${line// splash / }"
  line="$(printf '%s' "$line" | sed 's/^ *//; s/  */ /g; s/ *$//')"
  printf '%s\n' "$line" > "$CMDLINE"
  echo "cmdline.txt: quiet tokens + plymouth.enable=0 ensured; console=tty1 + splash removed (root=/PARTUUID untouched)"
else
  echo "WARNING: no cmdline.txt found in image — boot verbosity left as-is" >&2
fi

# Firmware rainbow splash off, so power-on is black, not a colour square.
CONFIGTXT=""
for c in "$MNT/boot/firmware/config.txt" "$MNT/boot/config.txt"; do
  [ -f "$c" ] && { CONFIGTXT="$c"; break; }
done
if [ -n "$CONFIGTXT" ] && ! grep -qE '^disable_splash=1' "$CONFIGTXT"; then
  printf 'disable_splash=1\n' >> "$CONFIGTXT"
  echo "config.txt: disable_splash=1"
fi

# The last visible noise is agetty on tty1: without this it clears the (now quiet) console and
# prints a login banner before autologin, undoing the hush a fraction before the toolbox paints.
# --noclear leaves the screen alone, --noissue drops the banner (/etc/issue is blanked above too),
# and the autologin user is westerncomms, whose .bash_profile execs the toolbox. The empty first
# ExecStart= is REQUIRED: it clears the base unit's ExecStart so this fully-specified one wins,
# regardless of what the stock image shipped.
install -d "$MNT/etc/systemd/system/getty@tty1.service.d"
cat > "$MNT/etc/systemd/system/getty@tty1.service.d/autologin.conf" <<'GETTY'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin westerncomms --noclear --noissue %I $TERM
GETTY

# ── first-boot provisioning: MUST be non-interactive or a headless Pi HANGS ───
# Stock Raspberry Pi OS first boot is interactive, and that is fatal for a counter Pi with no
# keyboard. TWO stock units block it, and MEASURED on the first real boot of this image
# (2026-08-19) they cost a black screen, no DHCP lease, and no self-enrolment:
#   systemd-firstboot.service  ConditionFirstBoot=yes, ordered Before=sysinit.target, runs
#                              `systemd-firstboot --prompt-locale --prompt-keymap
#                              --prompt-timezone --prompt-root-password` with StandardInput=tty.
#                              It waits for console input BEFORE networking starts, so a headless
#                              Pi never reaches multi-user.target — NetworkManager and the agent
#                              never run. This is THE hang.
#   userconfig.service         the Raspberry Pi user-creation wizard, also StandardInput=tty.
# And the stock image ships uid 1000 as `pi` (nologin) with NO `westerncomms`, so even past the
# hang the autologin above would fail on a user that does not exist.

# 1. The primary user must EXIST. Rename the stock pi (uid/gid 1000) to westerncomms with a real
#    login shell, across every account db, its group memberships (sudo/video/render/gpio/…) and
#    the NOPASSWD sudoers drop-in — so the autologin, kiosk, SSH keys and toolbox sudo all land
#    on a user that is actually there.
sed -i 's#^pi:x:1000:1000:\([^:]*\):/home/pi:[^:]*#westerncomms:x:1000:1000:\1:/home/westerncomms:/bin/bash#' "$MNT/etc/passwd"
sed -i 's#^pi:#westerncomms:#' "$MNT/etc/shadow"
sed -i 's#\bpi\b#westerncomms#g' "$MNT/etc/group" "$MNT/etc/gshadow" 2>/dev/null || true
sed -i 's#^pi:#westerncomms:#' "$MNT/etc/subuid" "$MNT/etc/subgid" 2>/dev/null || true
for f in "$MNT"/etc/sudoers.d/*; do [ -f "$f" ] && sed -i 's#\bpi\b#westerncomms#g' "$f"; done
# Carry any stock skeleton from /home/pi into the home the earlier steps populated, then drop it.
if [ -d "$MNT/home/pi" ]; then cp -an "$MNT/home/pi/." "$MNT/home/westerncomms/" 2>/dev/null || true; rm -rf "$MNT/home/pi"; fi
chown -R 1000:1000 "$MNT/home/westerncomms"
echo "  renamed stock pi -> westerncomms (uid 1000)"

# 1b. The toolbox's unprivileged TUI reaches its root helper via `sudo -n /usr/local/sbin/wcn-toolbox-priv`
#     (fixed argv, non-interactive). NEITHER this image nor install-pi-agent.sh ever created the
#     sudoers rule that makes that work, and trixie ships no pi-NOPASSWD file to inherit — so without
#     this EVERY PIN-gated / network / printer / remote-support action silently fails. Grant NOPASSWD
#     to that ONE binary only (the documented security model); sudo requires the file be 0440.
install -d -m 0755 "$MNT/etc/sudoers.d"
printf '%s\n' 'westerncomms ALL=(root) NOPASSWD: /usr/local/sbin/wcn-toolbox-priv' > "$MNT/etc/sudoers.d/010-wcn-toolbox"
chmod 0440 "$MNT/etc/sudoers.d/010-wcn-toolbox"
echo "  installed toolbox sudoers rule (NOPASSWD wcn-toolbox-priv)"

# 2. Neutralise the interactive first-boot units. Mask both (symlink to /dev/null). machine-id is
#    still (re)generated non-interactively by systemd early in boot, so masking firstboot loses
#    only the console questions — which we answer in step 3.
ln -sf /dev/null "$MNT/etc/systemd/system/systemd-firstboot.service"
ln -sf /dev/null "$MNT/etc/systemd/system/userconfig.service"
rm -f "$MNT/etc/systemd/system/multi-user.target.wants/userconfig.service"
echo "  masked systemd-firstboot + userconfig (the headless hang)"

# 3. Preseed the answers firstboot would have prompted for, so the system has sane UK defaults.
echo 'LANG=en_GB.UTF-8' > "$MNT/etc/locale.conf"
echo 'KEYMAP=gb'        > "$MNT/etc/vconsole.conf"
echo 'Europe/London'    > "$MNT/etc/timezone"
ln -sf /usr/share/zoneinfo/Europe/London "$MNT/etc/localtime"

# 4. Enable SSH. The baked engineer keys are useless unless sshd runs, and stock RPi OS ships it
#    disabled. The boot-partition sentinel is the canonical trigger; also wire the unit directly
#    so it does not hinge on the sshswitch generator.
touch "$MNT/boot/firmware/ssh" 2>/dev/null || touch "$MNT/boot/ssh" 2>/dev/null || true
[ -e "$MNT/lib/systemd/system/ssh.service" ] && \
  ln -sf /lib/systemd/system/ssh.service "$MNT/etc/systemd/system/multi-user.target.wants/ssh.service"
echo "  enabled SSH (boot sentinel + unit)"

# ── clean, fast, branded boot (bake-time) ────────────────────────────────────
# Turns the stock verbose boot into: black -> WCN mark on the console -> the toolbox loader -> the
# VM, and cuts ~8s of pointless boot wait. Every line here was proven on the pilot Pi 3B 2026-08-19.

# 1. Silence systemd's [ OK ] unit ladder at the source. The cmdline systemd.show_status=false is
#    not honoured on its own once Plymouth is not covering the console; ShowStatus=no is.
if [ -f "$MNT/etc/systemd/system.conf" ]; then
  if grep -qE '^#?ShowStatus=' "$MNT/etc/systemd/system.conf"; then
    sed -i 's/^#\?ShowStatus=.*/ShowStatus=no/' "$MNT/etc/systemd/system.conf"
  else
    printf 'ShowStatus=no\n' >> "$MNT/etc/systemd/system.conf"
  fi
fi

# 2. Cut the two big boot-time waits. NetworkManager-wait-online blocks boot ~6s for no kiosk
#    benefit (the agent handles connectivity); cloud-init sits in the critical chain ~10s and is
#    first-boot provisioning this image does not use (NetworkManager owns the network, the agent
#    self-enrols). Both are reversible on a device if ever needed.
ln -sf /dev/null "$MNT/etc/systemd/system/NetworkManager-wait-online.service"
touch "$MNT/etc/cloud/cloud-init.disabled" 2>/dev/null || true

# 3. No login banner between the boot logo and the toolbox: keep motd empty and hush login for
#    westerncomms (getty already runs --noissue above).
: > "$MNT/etc/motd"
touch "$MNT/home/westerncomms/.hushlogin"
chown 1000:1000 "$MNT/home/westerncomms/.hushlogin"

# 4. The early console brand: wcn-boot-logo paints the WCN mark to tty1 the moment there is a
#    framebuffer, filling the black until the toolbox takes over with the SAME mark. Ordered early
#    (sysinit) so it is not the ~15s-late thing multi-user ordering would make it.
install -D -m 0755 "$HERE/wcn-boot-logo"         "$MNT/usr/local/bin/wcn-boot-logo"
install -D -m 0644 "$HERE/wcn-boot-logo.service" "$MNT/etc/systemd/system/wcn-boot-logo.service"
install -d "$MNT/etc/systemd/system/sysinit.target.wants"
ln -sf /etc/systemd/system/wcn-boot-logo.service \
   "$MNT/etc/systemd/system/sysinit.target.wants/wcn-boot-logo.service"

# 5. The composed splash (black + centred mark) the X kiosk paints on its root while the VM
#    connects — the same image at both stages. Optional: wcn-kiosk falls back to a black root.
[ -r "$HERE/wcn-splash.png" ] && \
  install -D -m 0644 "$HERE/wcn-splash.png" "$MNT/usr/local/share/wcn/splash.png"

# The support banner the X kiosk launches: an always-on-top strip showing a message support pushes
# from wc-field (the agent writes it to /var/lib/wcn/kiosk-message.txt). Needs python3-tk, present
# in the base image.
install -D -m 0755 "$HERE/wcn-banner" "$MNT/usr/local/bin/wcn-banner"

# 6. feh paints that splash on the X root. The image is customised WITHOUT a chroot, so feh cannot
#    be apt-installed here; a one-shot first-boot unit installs it once (online by then) and stands
#    down. A missing feh is not an error — wcn-kiosk degrades to a solid black root.
install -D -m 0755 /dev/stdin "$MNT/usr/local/sbin/wcn-firstboot" <<'FB'
#!/bin/sh
# First-boot package top-ups that cannot be baked without a chroot (no emulation here). Installs:
#   feh              paints the splash on the X root (missing -> black root, not fatal)
#   wireguard-tools  `wg`, REQUIRED to bring up the tunnel when the counter is adopted
#   snmp             `snmpget`, printer telemetry collector
#   cups-client      `lpstat`, print-queue collector
# Idempotent; stands down ONLY once the essentials are present, so a first boot with no network
# simply retries on the next boot rather than shipping a half-provisioned counter.
apt-get update -qq || true
apt-get install -y -q feh wireguard-tools snmp cups-client || true
if command -v feh >/dev/null 2>&1 && command -v wg >/dev/null 2>&1; then
    systemctl disable wcn-firstboot.service 2>/dev/null || true
fi
FB
cat > "$MNT/etc/systemd/system/wcn-firstboot.service" <<'UNIT'
[Unit]
Description=WCN first-boot package top-ups
After=NetworkManager.service
# No ConditionPathExists gate: the script self-disables once feh AND wg are present, and must be
# free to re-run across boots until then (a first boot with no network installs nothing).

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wcn-firstboot
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/wcn-firstboot.service \
   "$MNT/etc/systemd/system/multi-user.target.wants/wcn-firstboot.service"

sync
umount "$MNT/boot/firmware" 2>/dev/null || umount "$MNT/boot" 2>/dev/null || true
umount "$MNT"
losetup -d "$LOOP"
trap - EXIT
rmdir "$MNT"

# ── compress for distribution ────────────────────────────────────────────────
xz -T0 -9 -f "$OUT"
echo "built ${OUT}.xz — host it and set VITE_THIN_CLIENT_IMAGE_URL to its download URL"
