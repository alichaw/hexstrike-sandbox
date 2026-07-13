#!/usr/bin/env bash
# sandbox_up.sh — bring the isolated lab sandbox up from a cold boot.
# Idempotent: safe to run after every reboot. Ensures the no-egress network
# exists and is internal, then (re)starts the target on it and waits for it.
#
#   bash sandbox_up.sh
#
# Override any of these:  NET, SUBNET, TARGET_NAME, TARGET_IMAGE, TARGET_PORT, DOCKER
set -uo pipefail

DOCKER="${DOCKER:-sudo docker}"
NET="${NET:-labnet}"
SUBNET="${SUBNET:-172.18.0.0/16}"
TARGET_NAME="${TARGET_NAME:-juiceshop}"
TARGET_IMAGE="${TARGET_IMAGE:-bkimminich/juice-shop}"
TARGET_PORT="${TARGET_PORT:-3000}"
NODE="${NODE:-/nodejs/bin/node}"

echo "== 1. ensure network '$NET' exists and is internal =="
if $DOCKER network inspect "$NET" >/dev/null 2>&1; then
  internal=$($DOCKER network inspect "$NET" --format '{{.Internal}}')
  if [ "$internal" != "true" ]; then
    echo "!! '$NET' exists but Internal=$internal (NOT isolated). Refusing to continue."
    echo "   Fix:  $DOCKER network rm $NET   then re-run this script."
    exit 1
  fi
  echo "   ok: '$NET' exists, Internal=true"
else
  echo "   creating internal network '$NET' ($SUBNET)"
  $DOCKER network create --internal --subnet "$SUBNET" "$NET" >/dev/null
fi

echo "== 2. (re)start target '$TARGET_NAME' on '$NET' =="
$DOCKER rm -f "$TARGET_NAME" >/dev/null 2>&1 || true
$DOCKER run -d --name "$TARGET_NAME" --network "$NET" "$TARGET_IMAGE" >/dev/null
echo "   started; waiting for it to accept connections..."

echo "== 3. wait for $TARGET_NAME:$TARGET_PORT (from inside the sandbox) =="
probe() {
  $DOCKER run --rm --network "$NET" --entrypoint "$NODE" "$TARGET_IMAGE" -e \
    'const s=require("net").connect('"$TARGET_PORT"',"'"$TARGET_NAME"'");s.setTimeout(3000);s.on("connect",()=>{console.log("UP");process.exit(0)});s.on("timeout",()=>process.exit(1));s.on("error",()=>process.exit(1))' 2>/dev/null
}
for i in $(seq 1 30); do
  if [ "$(probe)" = "UP" ]; then
    echo "   ok: target reachable after $i tr$([ "$i" = 1 ] && echo y || echo ies)"
    $DOCKER ps --filter "name=$TARGET_NAME" --format '   {{.Names}}  {{.Status}}'
    echo "sandbox is up."
    exit 0
  fi
  sleep 2
done
echo "!! target did not become reachable within ~60s"
echo "   check logs:  $DOCKER logs $TARGET_NAME"
exit 1
