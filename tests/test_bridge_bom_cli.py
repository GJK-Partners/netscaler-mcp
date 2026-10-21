"""Both Python bridges, as real processes, fed exactly what Windows
PowerShell 5.1 sends on a UTF-8 console: the JSON request with a UTF-8
byte-order mark in front and a CRLF behind it. Measured on a code page
65001 host; on a code page 850 host the same script sends no mark."""

from __future__ import annotations

import json
import subprocess
import sys

BOM = b"\xef\xbb\xbf"


def _bridge(module: str, request: dict) -> subprocess.CompletedProcess:
    payload = BOM + json.dumps(request).encode("ascii") + b"\r\n"
    return subprocess.run(
        [sys.executable, "-m", module],
        input=payload,
        capture_output=True,
        timeout=30,
    )


def test_the_measure_bridge_reads_a_marked_request_as_the_same_request():
    proc = _bridge("nsmcp.upgrade_measure", {"actie": "vorm", "verzoeken": []})
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert json.loads(proc.stdout.decode("utf-8"))["poort"] == []


def test_the_gate_bridge_never_blames_the_mark_for_an_unreadable_request():
    """A request that is refused for its content still exits 2, but the
    reason is its content - never json failing at character 0 on the mark."""
    proc = _bridge("nsmcp.upgrade_gate", {"fase": "R9"})
    stderr = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode == 2
    assert "Expecting value" not in stderr
    assert "Traceback" not in stderr
