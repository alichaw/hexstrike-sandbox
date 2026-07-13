#!/usr/bin/env bash
# grant_hexstrike_access.sh — give the restricted `hexstrike` user JUST enough
# access to run the HexStrike server from kali's home, using ACLs (no chown, no
# moving the project, kali's daily use untouched).
#
#   sudo bash grant_hexstrike_access.sh            # apply
#   sudo bash grant_hexstrike_access.sh --revoke   # remove all granted ACLs
#   sudo bash grant_hexstrike_access.sh --verify   # show effective ACLs
set -uo pipefail

HEX_USER="${HEX_USER:-hexstrike}"
KALI_HOME="${KALI_HOME:-/home/kali}"
PROJECT="${PROJECT:-$KALI_HOME/hexstrike-ai}"
LOG_FILE="${LOG_FILE:-$PROJECT/hexstrike.log}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
id "$HEX_USER" >/dev/null 2>&1 || { echo "!! user '$HEX_USER' missing: sudo useradd -r -s /usr/sbin/nologin $HEX_USER"; exit 1; }

apply() {
  # 1. traverse-only into kali's home (x, NOT read) — lets hexstrike pass THROUGH
  #    /home/kali to reach the project, without reading kali's other files.
  setfacl -m "u:$HEX_USER:x" "$KALI_HOME"

  # 2. recursive read + directory-enter on the whole project (rX = read files,
  #    enter dirs). This covers the code AND the venv's site-packages.
  setfacl -R -m "u:$HEX_USER:rX" "$PROJECT"
  # default ACL so files created later inherit the read grant
  setfacl -R -d -m "u:$HEX_USER:rX" "$PROJECT"

  # 3. write access ONLY where the server actually writes: the log file, and the
  #    project dir itself (so it can create runs/cache files). Minimal surface.
  [ -f "$LOG_FILE" ] && setfacl -m "u:$HEX_USER:rw" "$LOG_FILE"
  setfacl -m "u:$HEX_USER:rwx" "$PROJECT"

  echo "granted: '$HEX_USER' can traverse $KALI_HOME, read $PROJECT (+venv), write log & project dir"
  echo "run --verify to inspect, then test:  sudo -u $HEX_USER test -r $PROJECT/hexstrike_server.py && echo READABLE"
}

revoke() {
  setfacl -x "u:$HEX_USER" "$KALI_HOME" 2>/dev/null || true
  setfacl -R -x "u:$HEX_USER" "$PROJECT" 2>/dev/null || true
  setfacl -R -d -x "u:$HEX_USER" "$PROJECT" 2>/dev/null || true
  echo "revoked: all '$HEX_USER' ACLs removed from $KALI_HOME and $PROJECT"
}

verify() {
  echo "== $KALI_HOME =="; getfacl -p "$KALI_HOME" 2>/dev/null | grep -E "hexstrike|^# file"
  echo "== $PROJECT =="; getfacl -p "$PROJECT" 2>/dev/null | grep -E "hexstrike|^# file"
  echo "== can hexstrike read the server? =="
  sudo -u "$HEX_USER" test -r "$PROJECT/hexstrike_server.py" && echo "READABLE ✅" || echo "NOT readable ❌"
}

case "${1:-apply}" in
  --revoke|revoke) revoke ;;
  --verify|verify) verify ;;
  *)               apply ;;
esac
