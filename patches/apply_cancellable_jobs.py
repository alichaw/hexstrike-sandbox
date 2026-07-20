#!/usr/bin/env python3
"""Idempotently add target-scoped, cancellable tool job APIs."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

PATCH_MARKER = "# Cancellable jobs v10"
BLOCK_STARTS = (
    "# Cancellable jobs v9",
    "# Cancellable jobs v8",
    "# Cancellable jobs v7",
    "# Cancellable jobs v6",
    "# Cancellable jobs v5",
    "# Cancellable jobs v4",
    "# Cancellable jobs v3",
    "# Cancellable jobs v2",
    "# Cancellable jobs are restricted by a root-owned /32 target matrix.",
)
INSERT_BEFORE = '@app.route("/api/tools/httpx", methods=["POST"])'

ENDPOINT = r'''
# Cancellable jobs v10
# Jobs are restricted by a root-owned IPv4 /32 target matrix.
import hashlib as _hex_hashlib
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
from urllib.parse import urlsplit as _hex_urlsplit

_HEX_JOB_TARGETS = _HexPath("/etc/hexstrike/job-targets.json")
_HEX_NUCLEI_TEMPLATES = _HexPath("/var/lib/hexstrike/.local/nuclei-templates")
_HEX_NUCLEI_BASELINE_WEB_V1 = (
    "http/technologies/tech-detect.yaml",
    "http/misconfiguration/http-missing-security-headers.yaml",
)
_hex_jobs = {}
_hex_jobs_lock = _hex_threading.Lock()


def _hex_job_config():
    info = _HEX_JOB_TARGETS.stat()
    if info.st_uid != 0 or _hex_stat.S_IMODE(info.st_mode) != 0o640:
        raise ValueError("target matrix must be root-owned mode 0640")
    document = _hex_json.loads(_HEX_JOB_TARGETS.read_text(encoding="utf-8"))
    expected = str(document.get("create_token_sha256", ""))
    if not _hex_re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid create token hash")
    return document


def _hex_create_authorized():
    try:
        expected = _hex_job_config()["create_token_sha256"]
    except (OSError, TypeError, ValueError, _hex_json.JSONDecodeError):
        return False
    supplied = request.headers.get("X-Job-Create-Token", "")
    actual = _hex_hashlib.sha256(supplied.encode()).hexdigest()
    return bool(supplied) and _hex_secrets.compare_digest(actual, expected)


def _hex_target_allowed(target):
    try:
        document = _hex_job_config()
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


def _hex_tool_allowed(tool):
    try:
        allowed_tools = _hex_job_config().get("allowed_tools", [])
        return tool in allowed_tools
    except (OSError, TypeError, ValueError, _hex_json.JSONDecodeError):
        return False


def _hex_validate_url(value):
    try:
        parsed = _hex_urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None, "invalid target URL"
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None, "target URL must not contain path, query, or fragment"
        address = _hex_ipaddress.ip_address(parsed.hostname or "")
        if address.version != 4 or not (1 <= (parsed.port or 80) <= 65535):
            return None, "invalid IPv4 URL"
        allowed, error = _hex_target_allowed(str(address))
        return (value, "") if allowed else (None, error)
    except ValueError:
        return None, "invalid target URL"


def _hex_start_job(command):
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
    if not _hex_create_authorized():
        return jsonify({"error": "job creation unauthorized"}), 401
    if not _hex_tool_allowed("nmap"):
        return jsonify({"error": "tool not enabled"}), 403

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

    return _hex_start_job(command)


@app.route("/api/jobs/httpx", methods=["POST"])
def create_httpx_job():
    """Start one bounded HTTP metadata probe without shell interpretation."""
    if not _hex_create_authorized():
        return jsonify({"error": "job creation unauthorized"}), 401
    if not _hex_tool_allowed("httpx"):
        return jsonify({"error": "tool not enabled"}), 403

    params = request.get_json(silent=True) or {}
    allowed = {
        "target", "probe", "tech_detect", "status_code", "content_length",
        "title", "web_server", "threads",
    }
    if not isinstance(params, dict):
        return jsonify({"error": "JSON object required"}), 400
    unknown = sorted(set(params) - allowed)
    if unknown:
        return jsonify({"error": f"Unsupported parameters: {', '.join(unknown)}"}), 400

    target, error = _hex_validate_url(str(params.get("target", "")).strip())
    if target is None:
        return jsonify({"error": error}), 403

    try:
        threads = int(params.get("threads", 10))
    except (TypeError, ValueError):
        return jsonify({"error": "threads must be an integer"}), 400
    if not 1 <= threads <= 10:
        return jsonify({"error": "threads must be between 1 and 10"}), 400

    command = ["httpx", "-u", target, "-t", str(threads)]
    flags = {
        "probe": "-probe",
        "tech_detect": "-tech-detect",
        "status_code": "-sc",
        "content_length": "-cl",
        "title": "-title",
        "web_server": "-server",
    }
    for name, flag in flags.items():
        value = params.get(name, name == "probe")
        if not isinstance(value, bool):
            return jsonify({"error": f"{name} must be boolean"}), 400
        if value:
            command.append(flag)
    return _hex_start_job(command)


@app.route("/api/jobs/gobuster", methods=["POST"])
def create_gobuster_job():
    """Start a low-rate directory enumeration with fixed-safe arguments."""
    if not _hex_create_authorized():
        return jsonify({"error": "job creation unauthorized"}), 401
    if not _hex_tool_allowed("gobuster"):
        return jsonify({"error": "tool not enabled"}), 403

    params = request.get_json(silent=True) or {}
    allowed = {"url", "mode", "wordlist", "exclude_length"}
    if not isinstance(params, dict):
        return jsonify({"error": "JSON object required"}), 400
    unknown = sorted(set(params) - allowed)
    if unknown:
        return jsonify({"error": f"Unsupported parameters: {', '.join(unknown)}"}), 400

    target, error = _hex_validate_url(str(params.get("url", "")).strip())
    if target is None:
        return jsonify({"error": error}), 403
    if params.get("mode", "dir") != "dir":
        return jsonify({"error": "Only dir mode is supported"}), 400

    wordlist = str(params.get("wordlist", ""))
    if wordlist != "/usr/share/wordlists/dirb/common.txt":
        return jsonify({"error": "Unsupported wordlist"}), 400

    exclude_length = params.get("exclude_length")
    if exclude_length is not None:
        try:
            exclude_length = int(exclude_length)
        except (TypeError, ValueError):
            return jsonify({"error": "exclude_length must be an integer"}), 400
        if not 1 <= exclude_length <= 10000000:
            return jsonify({"error": "exclude_length out of range"}), 400

    command = [
        "gobuster", "dir", "-u", target, "-w", wordlist,
        "-t", "5", "--delay", "100ms", "--no-error",
    ]
    if exclude_length is not None:
        command.extend(["--exclude-length", str(exclude_length)])
    return _hex_start_job(command)


@app.route("/api/jobs/nuclei", methods=["POST"])
def create_nuclei_job():
    """Start one approval-gated, bounded vulnerability scan."""
    if not _hex_create_authorized():
        return jsonify({"error": "job creation unauthorized"}), 401
    if not _hex_tool_allowed("nuclei"):
        return jsonify({"error": "tool not enabled"}), 403

    params = request.get_json(silent=True) or {}
    allowed = {"target", "template_set", "rate_limit", "concurrency", "timeout"}
    if not isinstance(params, dict):
        return jsonify({"error": "JSON object required"}), 400
    unknown = sorted(set(params) - allowed)
    if unknown:
        return jsonify({"error": f"Unsupported parameters: {', '.join(unknown)}"}), 400

    target, error = _hex_validate_url(str(params.get("target", "")).strip())
    if target is None:
        return jsonify({"error": error}), 403

    template_set = str(params.get("template_set", "baseline-web-v1")).strip()
    if template_set != "baseline-web-v1":
        return jsonify({"error": "Unsupported template set"}), 400

    template_paths = []
    template_root = _HEX_NUCLEI_TEMPLATES.resolve()
    for relative in _HEX_NUCLEI_BASELINE_WEB_V1:
        candidate = (template_root / relative).resolve()
        try:
            candidate.relative_to(template_root)
        except ValueError:
            return jsonify({"error": "invalid managed template path"}), 500
        try:
            info = candidate.stat()
        except OSError:
            return jsonify({"error": "managed template missing"}), 500
        if info.st_uid != 0 or _hex_stat.S_IMODE(info.st_mode) != 0o640:
            return jsonify({"error": "managed template permissions invalid"}), 500
        template_paths.append(str(candidate))

    try:
        rate_limit = int(params.get("rate_limit", 5))
        concurrency = int(params.get("concurrency", 1))
        timeout = int(params.get("timeout", 5))
    except (TypeError, ValueError):
        return jsonify({"error": "numeric limits must be integers"}), 400
    if not 1 <= rate_limit <= 5 or concurrency != 1 or not 1 <= timeout <= 5:
        return jsonify({"error": "scan limits exceed the bounded profile"}), 400

    command = ["nuclei", "-u", target]
    for template_path in template_paths:
        command.extend(["-templates", template_path])
    command.extend([
        "-type", "http",
        "-disable-unsigned-templates",
        "-disable-update-check",
        "-rate-limit", str(rate_limit),
        "-concurrency", str(concurrency),
        "-bulk-size", "1",
        "-timeout", str(timeout),
        "-retries", "0",
        "-max-host-error", "3",
        "-no-interactsh",
        "-silent",
    ])
    return _hex_start_job(command)


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
    if PATCH_MARKER in text:
        print("cancellable job API v5 already present")
        return 0
    if INSERT_BEFORE not in text:
        print(f"insertion marker not found in {server_path}", file=sys.stderr)
        return 1
    backup = server_path.with_suffix(server_path.suffix + ".pre-cancellable-jobs")
    if not backup.exists():
        shutil.copy2(server_path, backup)
    block_start = next((item for item in BLOCK_STARTS if item in text), None)
    if block_start is not None:
        start = text.index(block_start)
        end = text.index(INSERT_BEFORE, start)
        updated = text[:start] + ENDPOINT + text[end:]
        action = "upgraded"
    else:
        updated = text.replace(INSERT_BEFORE, ENDPOINT + INSERT_BEFORE, 1)
        action = "added"
    server_path.write_text(updated, encoding="utf-8")
    print(f"{action} authenticated cancellable tool API in {server_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
