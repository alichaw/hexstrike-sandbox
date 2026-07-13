#!/usr/bin/env bash
# firewall_up.sh — constrain the attack agent's egress by UID.
#
# Everything run as user `hexstrike` (the HexStrike server + the nmap/etc. it
# spawns) may ONLY reach the lab network (labnet). Any other destination is
# LOGGED then DROPPED. Your own user (kali) and Claude Desktop are untouched.
#
# Idempotent: safe to re-run. WSL clears iptables on restart, so re-run after boot.
#   sudo bash firewall_up.sh          # apply
#   sudo bash firewall_up.sh --down   # remove (rollback)
#   sudo bash firewall_up.sh --status # show current rules + drop log tail
set -uo pipefail

HEX_USER="${HEX_USER:-hexstrike}"
LAB_SUBNET="${LAB_SUBNET:-172.18.0.0/16}"
CHAIN="HEXSTRIKE_EGRESS"
LOG_PREFIX="HEXSTRIKE-DROP "

need_root() { [ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }; }

uid_of() { id -u "$HEX_USER" 2>/dev/null; }

down() {
  # unhook from OUTPUT, then flush+delete our chain. Ignore errors if absent.
  while iptables -C OUTPUT -m owner --uid-owner "$(uid_of)" -j "$CHAIN" 2>/dev/null; do
    iptables -D OUTPUT -m owner --uid-owner "$(uid_of)" -j "$CHAIN"
  done
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "removed: egress restriction for user '$HEX_USER'"
}

status() {
  echo "== OUTPUT hook =="
  iptables -S OUTPUT | grep -i "$CHAIN" || echo "(no hook — firewall is DOWN)"
  echo "== $CHAIN rules =="
  iptables -S "$CHAIN" 2>/dev/null || echo "(chain absent)"
  echo "== recent blocked egress attempts (dmesg) =="
  dmesg 2>/dev/null | grep "$LOG_PREFIX" | tail -10 || echo "(none logged yet)"
}

up() {
  local uid; uid=$(uid_of)
  [ -n "$uid" ] || { echo "!! user '$HEX_USER' does not exist. Create it first:"; \
                     echo "   sudo useradd -r -s /usr/sbin/nologin $HEX_USER"; exit 1; }

  # rebuild cleanly so re-running never stacks duplicate rules
  down >/dev/null 2>&1 || true
  iptables -N "$CHAIN"

  # 1. allow loopback (local IPC, 127.0.0.1:8888, etc.)
  iptables -A "$CHAIN" -o lo -j ACCEPT
  # 2. allow the lab network only (the target lives here)
  iptables -A "$CHAIN" -d "$LAB_SUBNET" -j ACCEPT
  # 3. everything else: log (rate-limited) then drop
  iptables -A "$CHAIN" -m limit --limit 10/min -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
  iptables -A "$CHAIN" -j DROP

  # hook: only traffic owned by uid(hexstrike) enters our chain
  iptables -A OUTPUT -m owner --uid-owner "$uid" -j "$CHAIN"

  echo "applied: user '$HEX_USER' (uid $uid) may reach $LAB_SUBNET + loopback only; else LOG+DROP"
}

need_root
case "${1:-up}" in
  --down|down)     down ;;
  --status|status) status ;;
  *)               up ;;
esac
