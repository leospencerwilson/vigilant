#!/usr/bin/env bash
# Vigilant migration — Postgres + schema + data load (tasks #3 + #4).
# Runs ON the new VM. Pulls data from the WCN API (first-party). Idempotent.
#
#   bash bootstrap-db.sh
#
# Prompts once for the WCN API token (validated + retried, so a corrupted paste
# can't silently break it). Postgres password is auto-generated and saved to
# ~/vigilant-pg.pw.
set -euo pipefail

BASE="https://console.western-communication.com/api/customers/internal"
REPO="https://github.com/leospencerwilson/vigilant"
PWFILE="$HOME/vigilant-pg.pw"

echo "== Vigilant DB bootstrap =="

# --- Postgres password (generate once, reuse on re-run) ---
if [ -f "$PWFILE" ]; then
  PGPW="$(cat "$PWFILE")"
  echo "Reusing existing PG password from $PWFILE"
else
  PGPW="$(openssl rand -hex 16)"
  echo "$PGPW" > "$PWFILE"; chmod 600 "$PWFILE"
  echo "Generated PG password -> $PWFILE"
fi

# --- WCN API token: prompt + validate, so a mangled paste is caught ---
TOKEN=""
while true; do
  read -rp "Paste WCN API token (wcn_...): " TOKEN
  TOKEN="$(echo -n "$TOKEN" | tr -d '[:space:]')"
  code="$(curl -s -o /dev/null -w '%{http_code}' -m 20 -H "Authorization: Bearer $TOKEN" "$BASE/apps" || echo 000)"
  [ "$code" = "200" ] && { echo "Token OK."; break; }
  echo "  -> rejected (HTTP $code). Paste may be corrupted — try again."
done

# --- docker network / volume / postgres ---
docker network create vigilant-net 2>/dev/null || true
docker volume create vigilant_pgdata 2>/dev/null || true
docker rm -f vigilant-pg 2>/dev/null || true
docker run -d --name vigilant-pg --restart=unless-stopped --network vigilant-net \
  -e POSTGRES_PASSWORD="$PGPW" -v vigilant_pgdata:/var/lib/postgresql/data postgres:16 >/dev/null
echo "Postgres container up. Waiting for readiness..."
for i in $(seq 1 30); do
  docker exec vigilant-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 2
done

# --- schema ---
[ -d "$HOME/vigilant" ] || git clone --depth 1 "$REPO" "$HOME/vigilant"
docker cp "$HOME/vigilant/db/schema.sql" vigilant-pg:/schema.sql
echo "Applying schema (Supabase-only bits will NOTICE-and-skip; that's expected)..."
docker exec -e PGPASSWORD="$PGPW" vigilant-pg psql -q -U postgres -d postgres -f /schema.sql

# --- export data from the WCN API (skip the two huge history tables) ---
DATA=/tmp/vdata; mkdir -p "$DATA"
TABLES="devices enrollment_tokens alert_rules alerts agent_scripts config_jobs config_snapshots audit_log device_state interface_state lte_state lte_history neighbors mac_hosts wifi_networks wireless_clients speedtest_jobs device_logs"
echo "Exporting tables from API..."
for t in $TABLES; do
  curl -s -m 180 -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"sql\":\"select coalesce(jsonb_agg(x),'[]'::jsonb) as data from vigilant.$t x\"}" \
    "$BASE/db/query" > "$DATA/$t.json"
  printf "  %-20s %s bytes\n" "$t" "$(wc -c < "$DATA/$t.json" | tr -d ' ')"
done

# --- loader (embedded) ---
LOADDIR=/tmp/vigload; mkdir -p "$LOADDIR"
cat > "$LOADDIR/load.js" <<'LOADER'
const fs=require("fs"),path=require("path");const {Client}=require("pg");
const DATA=process.env.DATA_DIR||"/data";const URL=process.env.VIGILANT_DB_URL;
const ORDER=["devices","alert_rules","agent_scripts","audit_log","enrollment_tokens","device_state","interface_state","lte_state","lte_history","neighbors","mac_hosts","wifi_networks","wireless_clients","config_jobs","config_snapshots","speedtest_jobs","device_logs","alerts"];
const SEQ={alert_rules:"id",alerts:"id",audit_log:"id",config_snapshots:"id"};
function rows(t){const f=path.join(DATA,t+".json");if(!fs.existsSync(f))return null;const p=JSON.parse(fs.readFileSync(f,"utf8"));const r=Array.isArray(p)?p:(p&&p.rows&&p.rows[0]&&p.rows[0].data)||p.data||[];return Array.isArray(r)?r:[];}
(async()=>{const c=new Client({connectionString:URL});await c.connect();try{await c.query("SET search_path=vigilant,public");await c.query("BEGIN");
await c.query("TRUNCATE vigilant.devices,vigilant.alert_rules,vigilant.agent_scripts,vigilant.audit_log RESTART IDENTITY CASCADE");
for(const t of ORDER){const rs=rows(t);if(rs===null){console.log("skip  "+t);continue;}if(!rs.length){console.log("empty "+t);continue;}
const res=await c.query("INSERT INTO vigilant."+t+" SELECT * FROM jsonb_populate_recordset(NULL::vigilant."+t+", $1::jsonb)",[JSON.stringify(rs)]);console.log("load  "+t+"  "+res.rowCount);}
for(const [t,col] of Object.entries(SEQ)){await c.query("SELECT setval(pg_get_serial_sequence('vigilant."+t+"','"+col+"'),COALESCE((SELECT MAX("+col+") FROM vigilant."+t+"),1),(SELECT COUNT(*) FROM vigilant."+t+")>0)");}
await c.query("COMMIT");console.log("\nDone. Committed.");}catch(e){await c.query("ROLLBACK").catch(()=>{});console.error("FAILED, rolled back:",e.message);process.exit(1);}finally{await c.end();}})();
LOADER

echo "Loading data..."
docker run --rm --network vigilant-net -v "$DATA":/data -v "$LOADDIR":/app -w /app \
  -e VIGILANT_DB_URL="postgresql://postgres:$PGPW@vigilant-pg:5432/postgres" -e DATA_DIR=/data \
  node:20 bash -lc "npm i pg --silent >/dev/null 2>&1 && node load.js"

echo ""
echo "== DONE. Verify: =="
docker exec -e PGPASSWORD="$PGPW" vigilant-pg psql -U postgres -d postgres -c \
  "select 'devices' t, count(*) from vigilant.devices union all select 'enrollment_tokens', count(*) from vigilant.enrollment_tokens union all select 'interface_state', count(*) from vigilant.interface_state order by 1;"
