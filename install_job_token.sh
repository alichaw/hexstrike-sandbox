#!/usr/bin/env bash
# Install the Harness job-create capability for the restricted HexStrike service.
set -euo pipefail

SOURCE_FILE="${1:-$HOME/agent-eval-harness/.secrets/job-create.token}"
DEST_FILE="${JOB_CREATE_TOKEN_FILE:-/etc/hexstrike/job-create.token}"
HEX_GROUP="${HEX_GROUP:-hexstrike}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
[ -s "$SOURCE_FILE" ] || { echo "token source missing or empty: $SOURCE_FILE" >&2; exit 1; }
install -d -o root -g "$HEX_GROUP" -m 0750 "$(dirname "$DEST_FILE")"
install -o root -g "$HEX_GROUP" -m 0640 "$SOURCE_FILE" "$DEST_FILE"
echo "installed job-create token at $DEST_FILE (value not displayed)"
