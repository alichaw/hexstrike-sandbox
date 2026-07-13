#!/usr/bin/env bash
# verify_isolation.sh — prove sandbox isolation with reproducible evidence.
# Writes a timestamped proof to  isolation-proof/gate-a.txt
#
# Gate A passes IFF all three hold:
#   A0  network Internal=true
#   A1  egress to the internet is BLOCKED
#   A2  the target IS reachable inside the sandbox   (the reverse control:
#       proves the sandbox is isolated, not simply broken)
#
#   bash verify_isolation.sh
set -uo pipefail

DOCKER="${DOCKER:-sudo docker}"
NET="${NET:-labnet}"
TARGET_NAME="${TARGET_NAME:-juiceshop}"
TARGET_IMAGE="${TARGET_IMAGE:-bkimminich/juice-shop}"
TARGET_PORT="${TARGET_PORT:-3000}"
NODE="${NODE:-/nodejs/bin/node}"
EXT_HOST="${EXT_HOST:-1.1.1.1}"     # raw IP on purpose: tests pure egress, bypasses DNS
EXT_PORT="${EXT_PORT:-443}"

OUT_DIR="${OUT_DIR:-isolation-proof}"
OUT="$OUT_DIR/gate-a.txt"
mkdir -p "$OUT_DIR"

# TCP connect test from a throwaway container on $NET.
# args: host port label_ok label_bad  (always exits 0, prints one label)
conn_test() {
  $DOCKER run --rm --network "$NET" --entrypoint "$NODE" "$TARGET_IMAGE" -e \
    'const s=require("net").connect('"$2"',"'"$1"'");s.setTimeout(5000);s.on("connect",()=>{console.log("'"$3"'");process.exit()});s.on("timeout",()=>{console.log("'"$4"'");process.exit()});s.on("error",()=>{console.log("'"$4"'");process.exit()})'
}

{
  echo "# Isolation proof — network '$NET'"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# host: $(hostname)"
  echo
  echo "## A0  network is internal (expect Internal=true)"
  $DOCKER network inspect "$NET" --format 'Internal={{.Internal}}  Subnet={{range .IPAM.Config}}{{.Subnet}}{{end}}'
  echo
  echo "## A1  egress to $EXT_HOST:$EXT_PORT  (expect BLOCKED)"
  conn_test "$EXT_HOST" "$EXT_PORT" "EGRESS: REACHED (BAD)" "EGRESS: BLOCKED (GOOD)"
  echo
  echo "## A2  reach target $TARGET_NAME:$TARGET_PORT  (expect REACHED)"
  conn_test "$TARGET_NAME" "$TARGET_PORT" "TARGET: REACHED (GOOD)" "TARGET: UNREACHABLE (BAD)"
} | tee "$OUT"

echo
echo "evidence written -> $OUT"
