#!/usr/bin/env bash
# PMR desktop gateway agent — runs on VM 300 (pmr-desktop-gateway).
#
# Pulls every pharmacy's dnsmasq drop-in from Vigilant (GET /gateway/dnsmasq), writes the ones
# that changed into /etc/dnsmasq.d, removes drop-ins for sites that no longer exist, and reloads
# dnsmasq ONLY when something changed AND `dnsmasq --test` passes. If the test fails, the previous
# files are restored and dnsmasq is left untouched — a bad render can never take DNS/DHCP down.
#
# Idempotent and safe to run on a timer. Source of truth is the Site Configurator; this file is
# never hand-edited. Config comes from /etc/pmr-gateway-agent.env:
#   VIGILANT_URL=https://vigilant.western-communication.com
#   GATEWAY_PULL_TOKEN=<scoped token>            # GATEWAY_PULL_TOKEN in Vigilant's env
#   DNSMASQ_DIR=/etc/dnsmasq.d                   # optional, this is the default
#   RELOAD_CMD="systemctl reload dnsmasq"        # optional; falls back to restart if reload unsupported
set -euo pipefail
shopt -s nullglob   # an unmatched *.conf glob expands to nothing, not the literal pattern

ENV_FILE="${PMR_GATEWAY_ENV:-/etc/pmr-gateway-agent.env}"
# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

: "${VIGILANT_URL:?VIGILANT_URL not set}"
: "${GATEWAY_PULL_TOKEN:?GATEWAY_PULL_TOKEN not set}"
DNSMASQ_DIR="${DNSMASQ_DIR:-/etc/dnsmasq.d}"
RELOAD_CMD="${RELOAD_CMD:-systemctl reload dnsmasq}"
PREFIX="pmr-"   # only files we own carry this prefix; nothing else in the dir is touched

log() { echo "pmr-gateway-agent: $*"; }
need() { command -v "$1" >/dev/null 2>&1 || { log "missing dependency: $1"; exit 2; }; }
need curl; need jq; need dnsmasq

stage="$(mktemp -d)"; backup="$(mktemp -d)"
trap 'rm -rf "$stage" "$backup"' EXIT

manifest="$(curl -fsS -H "Authorization: Bearer ${GATEWAY_PULL_TOKEN}" "${VIGILANT_URL%/}/gateway/dnsmasq")" \
  || { log "pull failed"; exit 1; }
if [ "$(jq -r '.ok' <<<"$manifest")" != "true" ]; then
  log "server error: $(jq -rc '.error // .' <<<"$manifest")"; exit 1
fi

# Surface any site the server could not render — visible, never silent.
while IFS= read -r line; do [ -n "$line" ] && log "$line"; done < <(jq -r '.skipped[]? | "skipped \(.code): \(.reason)"' <<<"$manifest")

# Write each drop-in into the staging dir. Read from a process substitution (not a pipe) so a
# bad filename aborts the whole run instead of a subshell that the parent ignores.
while IFS= read -r row; do
  fn="$(base64 --decode <<<"$row" | jq -r '.filename')"
  case "$fn" in
    "${PREFIX}"*.conf) : ;;
    *) log "refusing suspicious filename from server: $fn"; exit 3 ;;
  esac
  base64 --decode <<<"$row" | jq -r '.config' > "${stage}/${fn}"
done < <(jq -r '.files[] | @base64' <<<"$manifest")

# Anything to do? Compare the staged set against the live owned files, both ways.
changed=0
for src in "${stage}/${PREFIX}"*.conf; do
  dst="${DNSMASQ_DIR}/$(basename "$src")"
  { [ ! -f "$dst" ] || ! cmp -s "$src" "$dst"; } && changed=1
done
for dst in "${DNSMASQ_DIR}/${PREFIX}"*.conf; do
  [ -f "${stage}/$(basename "$dst")" ] || changed=1
done
if [ "$changed" -eq 0 ]; then log "no change"; exit 0; fi

# Back up the live owned files, then swap in the staged set.
for dst in "${DNSMASQ_DIR}/${PREFIX}"*.conf; do cp -a "$dst" "${backup}/"; done
apply() { # $1 = source dir to copy owned files from (empty = just clear ours)
  for dst in "${DNSMASQ_DIR}/${PREFIX}"*.conf; do rm -f "$dst"; done
  [ -n "${1:-}" ] && for src in "$1/${PREFIX}"*.conf; do cp -a "$src" "${DNSMASQ_DIR}/"; done
  return 0
}

apply "$stage"
if dnsmasq --test 2>/dev/null; then
  if $RELOAD_CMD 2>/dev/null || systemctl restart dnsmasq; then
    log "applied $(ls "${DNSMASQ_DIR}/${PREFIX}"*.conf 2>/dev/null | wc -l | tr -d ' ') drop-in(s), reloaded dnsmasq"
    exit 0
  fi
  log "reload failed — restoring previous config"
fi
# dnsmasq --test failed (or reload failed): roll back and leave dnsmasq as it was.
apply "$backup"
dnsmasq --test >/dev/null 2>&1 || log "WARNING: restored config also fails dnsmasq --test — investigate"
log "rejected new config (dnsmasq --test failed); previous config restored"
exit 1
