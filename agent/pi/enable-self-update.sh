#!/usr/bin/env bash
# Make an ALREADY-DEPLOYED counter Pi self-update, and keep it self-updating.
#
# New Pis built from build-image.sh already have all of this baked in. This script is only for
# devices imaged BEFORE 2026-08-14, whose agent unit lacks the writable-path grants and whose
# agent.env has no VIGILANT_AUTO_UPDATE line. On those, self-update fails SILENTLY: the agent
# keeps running and reporting, so nothing looks wrong, but /usr is read-only inside its
# ProtectSystem=full namespace and every update dies with EROFS. Same failure hides branding.
#
# Run it on the device (or push it over SSH). Idempotent — safe to re-run, safe to run on a
# device that is already correct.
#
#   sudo ./enable-self-update.sh
#
# What it does, and why each piece is load-bearing:
#   1. A drop-in granting the four paths the agent must rewrite — its own binary and the three
#      branding targets — WITHOUT relaxing ProtectSystem. The "-" prefix keeps a missing path
#      (e.g. no plymouth theme) non-fatal, so the grant can never itself dead a device.
#   2. VIGILANT_AUTO_UPDATE=1 in the env, so the agent actually checks.
#   3. enable + start, so it is running to check at all.
# The binary that self-update installs never touches the unit or the env, so both survive every
# future update; only a re-image replaces them (with the baked-in equivalents).
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

UNIT=vigilant-agent
ENV=/etc/vigilant/agent.env
DROPIN_DIR=/etc/systemd/system/${UNIT}.service.d
DROPIN=$DROPIN_DIR/10-selfupdate.conf

[ -f "$ENV" ] || { echo "no $ENV — is the agent installed?" >&2; exit 1; }

install -d -m0755 "$DROPIN_DIR"
cat > "$DROPIN" <<'EOF'
[Service]
# Grant exactly the paths the agent rewrites, without relaxing ProtectSystem=full. These four
# match the paths build-image.sh bakes into a fresh image. The "-" prefix makes a missing path
# non-fatal. Accumulates with any ReadWritePaths already in the unit (e.g. /run).
ReadWritePaths=-/usr/local/sbin
ReadWritePaths=-/etc/motd
ReadWritePaths=-/etc/issue
ReadWritePaths=-/usr/share/plymouth/themes/pix
EOF
echo "wrote $DROPIN"

if grep -q '^VIGILANT_AUTO_UPDATE=' "$ENV"; then
    # Force it on even if a previous value was 0/blank.
    sed -i 's/^VIGILANT_AUTO_UPDATE=.*/VIGILANT_AUTO_UPDATE=1/' "$ENV"
else
    printf 'VIGILANT_AUTO_UPDATE=1\n' >> "$ENV"
fi
echo "set VIGILANT_AUTO_UPDATE=1 in $ENV"

systemctl daemon-reload
systemctl enable --now "$UNIT"

echo
echo "done. ReadWritePaths now: $(systemctl show "$UNIT" -p ReadWritePaths --value)"
echo "the agent will pull the server's current version on its next tick (auto-reverts if the"
echo "new build does not check in within 10 minutes)."
