#!/usr/bin/env bash
# run_recon_3x.sh — stability check for W1: call HexStrike's nmap N times against
# the target and record each run's outcome. This is the ancestor of HexStrikeAdapter
# and the seed of the W5 consistency experiment.
#
#   bash run_recon_3x.sh            # 3 runs (default)
#   RUNS=5 bash run_recon_3x.sh     # 5 runs
#
# Records:  runs/stability/recon_stability.jsonl  (one line per run)
#           + a human summary to stdout
set -uo pipefail

DOCKER="${DOCKER:-sudo docker}"
HEX_URL="${HEX_URL:-http://127.0.0.1:8888}"
TARGET_NAME="${TARGET_NAME:-juiceshop}"
SCAN_TYPE="${SCAN_TYPE:--sV}"       # -sV = TCP connect, no root needed
PORTS="${PORTS:-3000}"
RUNS="${RUNS:-3}"

OUT_DIR="${OUT_DIR:-runs/stability}"
OUT="$OUT_DIR/recon_stability.jsonl"
mkdir -p "$OUT_DIR"
: > "$OUT"   # truncate: this is a fresh stability session

# resolve target container IP (host reaches labnet by IP)
IP=$($DOCKER inspect "$TARGET_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
if [ -z "$IP" ]; then
  echo "!! could not resolve IP for container '$TARGET_NAME' — is it running? (bash sandbox_up.sh)"
  exit 1
fi
echo "target $TARGET_NAME = $IP:$PORTS   |   $RUNS runs   |   scan $SCAN_TYPE"
echo "----------------------------------------------------------------"

ok=0
for i in $(seq 1 "$RUNS"); do
  # NOTE: HexStrike's nmap handler IGNORES a "use_cache":false body param (it reads
  # the field but never passes it down), so it silently replays cached results.
  # The only thing that actually forces a real re-scan is clearing the cache first.
  curl -s -m 10 -X POST "$HEX_URL/api/cache/clear" -o /dev/null
  body="{\"target\":\"$IP\",\"scan_type\":\"$SCAN_TYPE\",\"ports\":\"$PORTS\",\"use_recovery\":false}"
  start=$(date +%s.%N)
  # -m 120: hard client-side timeout so a hung run is recorded as a failure, not a freeze
  resp=$(curl -s -m 120 -w '\n%{http_code}' -X POST "$HEX_URL/api/tools/nmap" \
           -H "Content-Type: application/json" -d "$body")
  end=$(date +%s.%N)

  http_code=$(printf '%s' "$resp" | tail -n1)
  json=$(printf '%s' "$resp" | sed '$d')
  elapsed=$(awk "BEGIN{printf \"%.2f\", $end-$start}")

  # pull return_code and host-up signal out of the JSON (grep, no jq dependency)
  rc=$(printf '%s' "$json" | grep -o '"return_code":[0-9-]*' | head -1 | grep -o '[0-9-]*$')
  rc="${rc:-null}"
  host_up=$(printf '%s' "$json" | grep -c "Host is up")

  if [ "$http_code" = "200" ] && [ "$rc" = "0" ] && [ "$host_up" -ge 1 ]; then
    verdict="ok"; ok=$((ok+1))
  else
    verdict="fail"
  fi

  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "{\"run\":$i,\"ts\":\"$ts\",\"http_code\":\"$http_code\",\"return_code\":$rc,\"host_up\":$host_up,\"elapsed_s\":$elapsed,\"verdict\":\"$verdict\"}" >> "$OUT"
  printf "run %d/%d  ->  %-4s  http=%s  rc=%s  host_up=%s  %ss\n" "$i" "$RUNS" "$verdict" "$http_code" "$rc" "$host_up" "$elapsed"
done

echo "----------------------------------------------------------------"
echo "stable: $ok/$RUNS runs ok    |    log -> $OUT"
if [ "$ok" -eq "$RUNS" ]; then
  echo "W1 stability criterion MET (all $RUNS runs succeeded)."
else
  echo "W1 stability criterion NOT met — inspect the failed run(s) in $OUT."
fi
