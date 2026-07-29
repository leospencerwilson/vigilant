#!/usr/bin/env bash
# Install the Vigilant agent on a counter Pi.
#
#   sudo ./install-pi-agent.sh \
#        --url https://vigilant.internal.western-communication.com \
#        --token <bearer from Install Desktop> \
#        --serial PI-RX54554-2 \
#        [--printers "brother-counter@192.168.1.50,label@192.168.1.51"]
#
# The SERIAL is not optional and not guessable: Vigilant cross-checks it against the
# device the token belongs to and returns 409 on a mismatch, which presents as "the Pi
# went dark" rather than as a configuration error. Take it from the Install Desktop page.
set -euo pipefail

URL=""; TOKEN=""; SERIAL=""; PRINTERS=""; INTERVAL="60"
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    # Preferred over --token: an argument is visible in `ps` to every local user for as
    # long as the install runs, and this is a bearer token that can post as the device.
    --token-file) TOKEN="$(cat "$2")"; shift 2;;
    --serial) SERIAL="$2"; shift 2;;
    --printers) PRINTERS="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

for v in URL TOKEN SERIAL; do
  if [ -z "${!v}" ]; then echo "--${v,,} is required" >&2; exit 2; fi
done
if [ "$(id -u)" != "0" ]; then echo "run with sudo" >&2; exit 2; fi

echo "→ optional collectors"
# Deliberately not fatal: the agent degrades to system metrics only, which is still
# useful, and a kiosk at a pharmacy is a bad place to block on a package install.
MISSING=""
for pkg in snmp cups-client wireguard-tools; do
  case "$pkg" in
    snmp) command -v snmpget >/dev/null || MISSING="$MISSING snmp";;
    cups-client) command -v lpstat >/dev/null || MISSING="$MISSING cups-client";;
    wireguard-tools) command -v wg >/dev/null || MISSING="$MISSING wireguard-tools";;
  esac
done
if [ -n "$MISSING" ]; then
  echo "   installing:$MISSING"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING || \
    echo "   ⚠ install failed — agent will run without those collectors"
else
  echo "   all present"
fi

echo "→ agent"
install -m 0755 -o root -g root vigilant-pi-agent.py /usr/local/sbin/vigilant-pi-agent

echo "→ config"
install -d -m 0750 /etc/vigilant
# 0600 root-only: this file holds a bearer token that can post as this device.
umask 077
cat > /etc/vigilant/agent.env <<EOF
# Vigilant agent — written by install-pi-agent.sh
# SERIAL must match the enrolled device or the ingest returns 409.
VIGILANT_URL=$URL
VIGILANT_TOKEN=$TOKEN
VIGILANT_SERIAL=$SERIAL
VIGILANT_INTERVAL=$INTERVAL
# Comma-separated 'name@host' printers to poll by SNMP. Name should match the CUPS queue
# so reports merge with the queue stats and with anything set by hand in Watchman.
VIGILANT_PRINTERS=$PRINTERS
# Poll printers every Nth tick (toner moves slowly; hammering old SNMP agents wedges them).
VIGILANT_PRINTER_EVERY=15
EOF
chmod 0600 /etc/vigilant/agent.env

echo "→ service"
cat > /etc/systemd/system/vigilant-agent.service <<'EOF'
[Unit]
Description=Vigilant agent (counter Pi)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/vigilant/agent.env
ExecStart=/usr/local/sbin/vigilant-pi-agent
# The agent loops internally, so a clean exit is abnormal — always come back. A kiosk is
# unattended by definition; it must recover from a transient failure without a human.
Restart=always
RestartSec=15
# It only reads /proc, /sys and runs read-only queries.
NoNewPrivileges=true
# `full`, NOT `strict`: strict mounts / read-only inside the unit's namespace, which made
# the agent's own "has the SD card flipped read-only?" check fire on every healthy Pi.
# full still protects /usr and /boot while leaving / reported as it really is.
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vigilant-agent.service

echo
echo "✓ installed. First report:"
sleep 3
systemctl --no-pager -l status vigilant-agent.service | tail -n 12 || true
echo
echo "Follow with:  journalctl -u vigilant-agent -f"
echo "A 409 means VIGILANT_SERIAL does not match the enrolled device."
