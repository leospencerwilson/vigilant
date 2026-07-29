#!/bin/bash
# Sample the live Vigilant write rate over N seconds. Used to compare the
# per-row vs batched write path. Rates are per second.
N=${1:-30}
Q="select xact_commit||' '||tup_inserted||' '||tup_updated from pg_stat_database where datname = current_database();"

read -r C1 I1 U1 <<<"$(docker exec vigilant-pg psql -U postgres -d postgres -At -c "$Q")"
L1=$(cut -d' ' -f1 /proc/loadavg)
sleep "$N"
read -r C2 I2 U2 <<<"$(docker exec vigilant-pg psql -U postgres -d postgres -At -c "$Q")"
L2=$(cut -d' ' -f1 /proc/loadavg)

awk -v c1="$C1" -v c2="$C2" -v i1="$I1" -v i2="$I2" -v u1="$U1" -v u2="$U2" -v n="$N" \
  'BEGIN{ printf "commits/s = %8.0f\ninserts/s = %8.0f\nupdates/s = %8.0f\n", (c2-c1)/n, (i2-i1)/n, (u2-u1)/n }'
echo "load      = $L1 -> $L2"
docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' | grep vigilant
