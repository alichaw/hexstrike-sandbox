#!/usr/bin/env python3
"""Idempotently add a target-scoped, cancellable nmap job API."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROUTE_MARKER = '@app.route("/api/jobs/nmap", methods=["POST"])'
INSERT_BEFORE = '@app.route("/api/tools/httpx", methods=["POST"])'

ENDPOINT = r'''
# Cancellable jobs are restricted by a root-owned /32 target matrix.
import ipaddress as _hex_ipaddress
import json as _hex_json
import os as _hex_os
import re as _hex_re
import secrets as _hex_secrets
import signal as _hex_signal
import stat as _hex_stat
import subprocess as _hex_subprocess
import threading as _hex_threading
import time as _hex_time
from pathlib import Path as _HexPath

_HEX_JOB_TARGETS = _HexPath("/etc/hexstrike/job-targets.json")
_hex_jobs = {}
_hex_jobs_lock = _hex_threading.Lock()


def _hex_target_allowed(target):
    try:
        info = _HEX_JOB_TARGETS.stat()
        if info.st_uid != 0 or _hex_stat.S_IMODE(info.st_mode) != 0o640:
            return False, "target matrix must be root-owned mode 0640"
        document = _hex_json.loads(_HEX_JOB_TARGETS.read_text(encoding="utf-8"))
        entries = document.get("allowed_targets", [])
        networks = [_hex_ipaddress.ip_network(item, strict=True) for item in entries]
        if not networks or any(network.prefixlen != 32 for network in networks):
            return False, "target matrix accepts IPv4 /32 entries only"
        address = _hex_ipaddress.ip_address(target)
        if address.version != 4:
            return False, "IPv4 target required"
        return any(address in network for network in networks), "target not allowed"
    except (OSError, TypeError, ValueError, _hex_json.JSONDecodeError):
        return False, "invalid or unreadable target matrix"


def _hex_job_view(job):
    view = {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job.get("finished_at"),
    }
    if job["status"] in {"succeeded", "failed", "cancelled"}:
        view["result"] = job.get("result", {})
    return view


def _hex_authorized_job(job_id):
    job = _hex_jobs.get(job_id)
    supplied = request.headers.get("X-Job-Token", "")
    if job is None or not supplied or not _hex_secrets.compare_digest(supplied, job["token"]):
        return None
    return job


def _hex_wait_job(job):
    stdout, stderr = job["process"].communicate()
    rc = job["process"].returncode
    with _hex_jobs_lock:
        cancelled = job.get("cancel_requested", False)
        job["status"] = "cancelled" if cancelled else ("succeeded" if rc == 0 else "failed")
        job["finished_at"] = _hex_time.time()
        job["result"] = {
            "success": rc == 0 and not cancelled,
            "return_code": rc,
            "stdout": stdout[-200000:],
            "stderr": stderr[-50000:],
            "timed_out": False,
            "cancelled": cancelled,
        }


@app.route("/api/jobs/nmap", methods=["POST"])
def create_nmap_job():
    """Start one allowlisted nmap process without shell interpretation."""
    params = request.get_json(silent=True) or {}
    if not isinstance(params, dict):
        return jsonify({"error": "JSON object required"}), 400
    allowed = {"target", "scan_type", "ports", "use_recovery"}
    unknown = sorted(set(params) - allowed)
    if unknown:
        return jsonify({"error": f"Unsupported parameters: {', '.join(unknown)}"}), 400

    target = str(params.get("target", "")).strip()
    target_allowed, target_error = _hex_target_allowed(target)
    if not target_allowed:
        return jsonify({"error": target_error}), 403

    scan_type = str(params.get("scan_type", "-sV")).strip()
    scan_args = {
        "-sn": ["-sn"],
        "-Pn": ["-Pn"],
        "-sV": ["-sV"],
        "-Pn -sV": ["-Pn", "-sV"],
    }.get(scan_type)
    if scan_args is None:
        return jsonify({"error": "Unsupported scan_type"}), 400

    ports = str(params.get("ports", "")).strip()
    if ports and (not _hex_re.fullmatch(r"[0-9,-]{1,200}", ports) or scan_type == "-sn"):
        return jsonify({"error": "Invalid ports"}), 400

    command = ["nmap", *scan_args]
    if ports:
        command.extend(["-p", ports])
    command.append(target)

    job_id = _hex_secrets.token_urlsafe(24)
    token = _hex_secrets.token_urlsafe(32)
    process = _hex_subprocess.Popen(
        command,
        stdout=_hex_subprocess.PIPE,
        stderr=_hex_subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    job = {
        "job_id": job_id,
        "token": token,
        "status": "running",
        "created_at": _hex_time.time(),
        "process": process,
        "cancel_requested": False,
    }
    with _hex_jobs_lock:
        _hex_jobs[job_id] = job
    _hex_threading.Thread(target=_hex_wait_job, args=(job,), daemon=True).start()
    return jsonify({"job_id": job_id, "job_token": token, "status": "running"}), 202


@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_hex_job(job_id):
    with _hex_jobs_lock:
        job = _hex_authorized_job(job_id)
        if job is None:
            return jsonify({"error": "job not found"}), 404
        return jsonify(_hex_job_view(job))


@app.route("/api/jobs/<job_id>", methods=["DELETE"])
def cancel_hex_job(job_id):
    with _hex_jobs_lock:
        job = _hex_authorized_job(job_id)
        if job is None:
            return jsonify({"error": "job not found"}), 404
        if job["status"] != "running":
            return jsonify(_hex_job_view(job))
        job["cancel_requested"] = True
        process = job["process"]

    if process.poll() is None:
        try:
            _hex_os.killpg(process.pid, _hex_signal.SIGTERM)
            process.wait(timeout=2)
        except ProcessLookupError:
            pass
        except _hex_subprocess.TimeoutExpired:
            _hex_os.killpg(process.pid, _hex_signal.SIGKILL)
    return jsonify({"job_id": job_id, "status": "cancelling"}), 202

'''


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} /path/to/hexstrike_server.py", file=sys.stderr)
        return 2
    server_path = Path(sys.argv[1])
    text = server_path.read_text(encoding="utf-8")
    if ROUTE_MARKER in text:
        print("cancellable job API already present")
        return 0
    if INSERT_BEFORE not in text:
        print(f"insertion marker not found in {server_path}", file=sys.stderr)
        return 1
    backup = server_path.with_suffix(server_path.suffix + ".pre-cancellable-jobs")
    if not backup.exists():
        shutil.copy2(server_path, backup)
    server_path.write_text(text.replace(INSERT_BEFORE, ENDPOINT + INSERT_BEFORE, 1), encoding="utf-8")
    print(f"added target-scoped cancellable nmap API to {server_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
