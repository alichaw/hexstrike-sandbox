#!/usr/bin/env bash
# bootstrap_all.sh — one command to rebuild the whole isolated lab after a reboot.
#
# Runs the five W1 pieces in order, verifies each, and finally proves isolation is
# actually in effect (target reachable, external blocked). Stops at the first
# failure so you never end up in a half-up "looks fine but isn't" state.
#
#   cd ~/hexstrike-ai/sandbox
#   sudo bash bootstrap_all.sh
#
# Notes:
# - Run with sudo (needs docker + iptables + su to the hexstrike user).
# - The HexStrike server is started in the BACKGROUND (logs to server.out).
# - Re-runnable: every step is idempotent.
set -uo pipefail

# ---- config (override via env if your paths differ) ----
SANDBOX_DIR="${SANDBOX_DIR:-$(eval echo ~${SUDO_USER:-$USER})/hexstrike-ai/sandbox}"
PROJECT_DIR="${PROJECT_DIR:-/home/kali/hexstrike-ai}"
VENV="${VENV:-$PROJECT_DIR/hexstrike-env}"
HEX_USER="${HEX_USER:-hexstrike}"
HEX_URL="${HEX_URL:-http://127.0.0.1:8888}"
TARGET_NAME="${TARGET_NAME:-juiceshop}"
SERVER_LOG="${SERVER_LOG:-$PROJECT_DIR/server.out}"

# sudo aware: these scripts already call `sudo docker`; when we're root that's a no-op
step() { echo; echo "==================== $* ===================="; }
die()  { echo; echo "!! FAILED: $*"; echo "   (fix this before continuing — sandbox is NOT fully up)"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo:  sudo bash bootstrap_all.sh"
cd "$SANDBOX_DIR" 2>/dev/null || die "sandbox dir not found: $SANDBOX_DIR"

# ---- 1. network + target ----
step "1/7  sandbox up (labnet + $TARGET_NAME)"
bash sandbox_up.sh || die "sandbox_up.sh"

# ---- 2. isolation proof (Gate A) ----
step "2/7  verify isolation (Gate A)"
bash verify_isolation.sh || die "verify_isolation.sh"
grep -q "EGRESS: BLOCKED" isolation-proof/gate-a.txt || die "egress not blocked — isolation broken"

# ---- 3. grant restricted user access ----
step "3/7  grant hexstrike user access (ACL)"
bash grant_hexstrike_access.sh || die "grant_hexstrike_access.sh"
sudo -u "$HEX_USER" test -r "$PROJECT_DIR/hexstrike_server.py" || die "hexstrike cannot read server.py"

# ---- 4. firewall (uid egress control) ----
step "4/7  apply constrained traceroute endpoint"
python3 "$SANDBOX_DIR/patches/apply_traceroute_endpoint.py" \
  "$PROJECT_DIR/hexstrike_server.py" || die "traceroute endpoint patch"

step "5/7  apply egress firewall (uid $HEX_USER)"
bash firewall_up.sh || die "firewall_up.sh"

# ---- 5. start HexStrike server as the restricted user (background) ----
step "6/7  start HexStrike server as '$HEX_USER'"
# kill any server already listening on 8888 (from a previous run)
pkill -f "hexstrike_server.py" 2>/dev/null && sleep 2 || true
# HOME=/tmp so libs that write ~/.cache don't crash (hexstrike has no home dir)
sudo -u "$HEX_USER" env HOME=/tmp bash -c \
  "cd '$PROJECT_DIR' && source '$VENV/bin/activate' && nohup python3 hexstrike_server.py > '$SERVER_LOG' 2>&1 &"

echo "   waiting for server to answer on $HEX_URL/health ..."
up=0
for i in $(seq 1 30); do
  if curl -s -m 2 "$HEX_URL/health" | grep -q '"status":"healthy"'; then
    up=1; echo "   server healthy after ${i}s"; break
  fi
  sleep 1
done
[ "$up" = 1 ] || die "server did not become healthy — check $SERVER_LOG"

# Endpoint smoke test: localhost avoids contacting any external target.
trace_body=$(mktemp)
trace_http=$(curl -s -o "$trace_body" -w "%{http_code}" -X POST \
  "$HEX_URL/api/tools/traceroute" -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","max_hops":2,"timeout":1,"queries":1}')
[ "$trace_http" = "200" ] || die "traceroute endpoint returned HTTP $trace_http"
grep -q '"return_code":0' "$trace_body" || die "traceroute endpoint smoke test failed"
rm -f "$trace_body"
echo "   traceroute endpoint: healthy"

# confirm it's really running as the restricted user
whoami_srv=$(ps -o user= -C python3 | tr -d ' ' | head -1)
echo "   server process user: $whoami_srv (expected: $HEX_USER)"

# ---- 6. prove isolation is in effect on the server itself ----
step "7/7  prove isolation on the live server"
IP=$(docker inspect "$TARGET_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
[ -n "$IP" ] || die "cannot resolve target IP"

nmap_port() { # target -> prints port state (open/filtered/closed) via HexStrike
  curl -s -X POST "$HEX_URL/api/cache/clear" -o /dev/null
  curl -s -X POST "$HEX_URL/api/tools/nmap" -H "Content-Type: application/json" \
    -d "{\"target\":\"$1\",\"scan_type\":\"-sV\",\"ports\":\"$2\",\"use_recovery\":false}" \
    | grep -oE 'open|filtered|closed' | head -1
}

tgt_state=$(nmap_port "$IP" 3000)
ext_state=$(nmap_port "1.1.1.1" 80)
echo "   target $IP:3000  -> ${tgt_state:-none}   (expect: open)"
echo "   external 1.1.1.1:80 -> ${ext_state:-none}   (expect: filtered)"

echo
if [ "$tgt_state" = "open" ] && [ "$ext_state" = "filtered" ]; then
  echo "########################################################"
  echo "#  SANDBOX FULLY UP — isolation verified.              #"
  echo "#  target reachable (open), external blocked (filtered)#"
  echo "########################################################"
  echo "server log: $SERVER_LOG    drops: sudo dmesg | grep HEXSTRIKE-DROP"
else
  die "isolation check inconclusive (target=$tgt_state external=$ext_state) — inspect before trusting the sandbox"
fi
