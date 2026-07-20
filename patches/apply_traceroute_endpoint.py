#!/usr/bin/env python3
"""Idempotently add a constrained traceroute endpoint to HexStrike."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROUTE_MARKER = '@app.route("/api/tools/traceroute", methods=["POST"])'
INSERT_BEFORE = '@app.route("/api/tools/httpx", methods=["POST"])'

ENDPOINT = r'''
@app.route("/api/tools/traceroute", methods=["POST"])
def traceroute_tool():
    """Run a bounded, IPv4-only traceroute without accepting raw flags."""
    import ipaddress
    import shlex

    try:
        params = request.get_json(silent=True) or {}
        if not isinstance(params, dict):
            return jsonify({"error": "JSON object required"}), 400

        allowed_keys = {"target", "max_hops", "timeout", "queries"}
        unknown_keys = sorted(set(params) - allowed_keys)
        if unknown_keys:
            return jsonify({"error": f"Unsupported parameters: {', '.join(unknown_keys)}"}), 400

        target = str(params.get("target", "")).strip()
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            return jsonify({"error": "Target must be a valid IPv4 address"}), 400
        if address.version != 4:
            return jsonify({"error": "Only IPv4 targets are supported"}), 400

        def bounded_int(name, default, minimum, maximum):
            try:
                value = int(params.get(name, default))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return value

        try:
            max_hops = bounded_int("max_hops", 8, 1, 30)
            timeout = bounded_int("timeout", 2, 1, 10)
            queries = bounded_int("queries", 1, 1, 3)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        command = (
            f"traceroute -n -m {max_hops} -w {timeout} -q {queries} "
            f"{shlex.quote(str(address))}"
        )
        logger.info(f"Starting constrained traceroute to {address}")
        result = execute_command(command)
        logger.info(f"Traceroute completed for {address}")
        return jsonify(result)
    except Exception as exc:
        logger.error(f"Error in traceroute endpoint: {exc}")
        return jsonify({"error": f"Server error: {exc}"}), 500

'''

def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} /path/to/hexstrike_server.py", file=sys.stderr)
        return 2

    server_path = Path(sys.argv[1])
    text = server_path.read_text(encoding="utf-8")

    if ROUTE_MARKER in text:
        print("traceroute endpoint already present")
        return 0
    if INSERT_BEFORE not in text:
        print(f"insertion marker not found in {server_path}", file=sys.stderr)
        return 1

    backup_path = server_path.with_suffix(server_path.suffix + ".pre-traceroute")
    if not backup_path.exists():
        shutil.copy2(server_path, backup_path)

    updated = text.replace(INSERT_BEFORE, ENDPOINT + INSERT_BEFORE, 1)
    server_path.write_text(updated, encoding="utf-8")
    print(f"added constrained traceroute endpoint to {server_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
