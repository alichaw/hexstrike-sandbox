import py_compile
import subprocess
import sys
from pathlib import Path


def test_patcher_adds_authenticated_nmap_and_httpx_jobs(tmp_path: Path):
    server = tmp_path / "hexstrike_server.py"
    server.write_text(
        'from flask import Flask, request, jsonify\napp = Flask(__name__)\n'
        '@app.route("/api/tools/httpx", methods=["POST"])\n'
        'def httpx():\n    return jsonify({})\n',
        encoding="utf-8",
    )
    patcher = Path(__file__).parents[1] / "patches" / "apply_cancellable_jobs.py"
    subprocess.run([sys.executable, str(patcher), str(server)], check=True)
    first = server.read_text(encoding="utf-8")
    assert "HEXSTRIKE_CANCELLABLE_JOBS_V2" in first
    assert '@app.route("/api/jobs/nmap"' in first
    assert '@app.route("/api/jobs/httpx"' in first
    assert "X-Job-Create-Token" in first
    assert "compare_digest(supplied, expected)" in first
    assert "network.prefixlen != 32" in first
    assert "family=_hex_socket.AF_INET" in first
    assert "target must resolve to exactly one IPv4 address" in first
    assert '"threads must be an integer from 1 to 20"' in first
    py_compile.compile(str(server), doraise=True)

    subprocess.run([sys.executable, str(patcher), str(server)], check=True)
    assert server.read_text(encoding="utf-8") == first
