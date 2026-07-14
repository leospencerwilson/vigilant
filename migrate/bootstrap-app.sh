#!/usr/bin/env bash
# Vigilant migration — deploy the app (ingest + worker) against the local Postgres (task #5).
# Run ON the VM, AFTER bootstrap-db.sh. Idempotent.
#
#   bash ~/vigilant/migrate/bootstrap-app.sh
#
# Reads the PG password from ~/vigilant-pg.pw. Prompts for the two app tokens + CORS origin
# (paste works over AnyDesk/SSH now). Writes .env + a compose override that joins the app to
# the vigilant-net network (so it can reach the vigilant-pg container by name), then starts it.
set -euo pipefail

REPO="$HOME/vigilant"
PWFILE="$HOME/vigilant-pg.pw"
[ -f "$PWFILE" ] || { echo "Missing $PWFILE — run bootstrap-db.sh first."; exit 1; }
PGPW="$(cat "$PWFILE")"

echo "== Vigilant app deploy =="

read -rp "Master ENROLL_TOKEN (ven_...): " ENROLL_TOKEN
read -rp "Field key = wc-field's VITE_VIGILANT_FIELD_KEY (vfk_...): " FIELD_ENROLL_TOKEN
read -rp "CORS origin (wc-field URL, or * ) [*]: " CORS; CORS="${CORS:-*}"

# --- .env ---
cat > "$REPO/.env" <<ENV
STORE_KIND=pg
VIGILANT_DB_URL=postgresql://postgres:${PGPW}@vigilant-pg:5432/postgres
VIGILANT_DB_SSL=false
PORT=3000
PUBLIC_BASE_URL=https://vigilant.internal.western-communication.com
ENROLL_TOKEN=${ENROLL_TOKEN}
FIELD_ENROLL_TOKEN=${FIELD_ENROLL_TOKEN}
CORS_ALLOW_ORIGINS=${CORS}
DEFAULT_POLL_S=10
FAST_POLL_S=3
STALE_AFTER_S=45
OFFLINE_AFTER_S=120
NEIGHBOR_TTL_S=86400
HISTORY_RAW_RETENTION_H=24
ENABLE_NIGHTLY_SNAPSHOT=false
AGENT_SCRIPT_PATH=./agent/vigilant-agent.rsc
ENV
chmod 600 "$REPO/.env"
echo "Wrote $REPO/.env"

# --- compose override: put ingest+worker on vigilant-net, publish ingest locally for testing ---
cat > "$REPO/docker-compose.override.yml" <<'OVR'
services:
  ingest:
    networks: [default, vigilant-net]
    ports:
      - "127.0.0.1:3000:3000"
  worker:
    networks: [default, vigilant-net]
networks:
  vigilant-net:
    external: true
OVR
echo "Wrote $REPO/docker-compose.override.yml"

# --- build + start ---
cd "$REPO"
docker compose up -d --build

echo ""
echo "Waiting for ingest to answer..."
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:3000/healthz >/dev/null 2>&1 && break; sleep 2
done

echo ""
echo "== health =="
curl -s http://127.0.0.1:3000/healthz; echo
echo "== fleet (via field key) — should list your devices =="
curl -s -H "Authorization: Bearer ${FIELD_ENROLL_TOKEN}" http://127.0.0.1:3000/fleet \
  | head -c 400; echo
echo ""
echo "== containers =="
docker compose ps
