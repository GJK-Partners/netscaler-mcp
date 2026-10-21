"""`start_detached()` against the REAL Windows PowerShell, not a Python stand-in.

Measured on the lab (8-9-2026): started with DETACHED_PROCESS, powershell.exe
5.1 exits 0 at once without running anything and without a byte of output -
so the real .ps1 runner never wrote `fase_gestart`. The NEP-runner of the
other tests is a Python script and never showed it. This test starts the real
interpreter through the product's own launcher and demands the output in the
log: the one proof that the runner can start at all on Windows.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from nsmcp import handelen
from nsmcp.handelen import (
    RUNNER_HOST_GEBONDEN,
    RUNNER_LOSGEKOPPELD,
    RUNNER_NIET_BEOORDEELD,
    start_detached,
)
from nsmcp.powershell import powershell_path

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell only")


def test_the_real_powershell_runs_and_logs_when_started_detached(tmp_path: Path):
    log = tmp_path / "runner.log"
    start_detached(
        [
            str(powershell_path()),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Write-Host 'gestart'; Write-Output 'klaar'; exit 7",
        ],
        log_path=log,
    )
    deadline = time.monotonic() + 30
    text = ""
    while time.monotonic() < deadline:
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        if "klaar" in text:
            break
        time.sleep(0.5)
    assert "gestart" in text and "klaar" in text, (
        "de losgekoppelde powershell.exe schreef niets naar zijn log: " + repr(text)
    )


# ---------------------------------------------------------------------------
# Integration on the release (14-9-2026). MEASURED on the workstation: every
# product server the desktop client starts sits inside a Windows Job Object.
# The runner therefore asks to break away first and REPORTS what it measured
# - one of three fixed sentences - instead of refusing the host or assuming.
# ---------------------------------------------------------------------------


def test_the_start_reports_the_measured_runner_lifetime(tmp_path: Path):
    label = start_detached(
        [str(powershell_path()), "-NoProfile", "-NonInteractive", "-Command", "exit 0"],
        log_path=tmp_path / "runner.log",
    )
    assert label in {RUNNER_LOSGEKOPPELD, RUNNER_HOST_GEBONDEN, RUNNER_NIET_BEOORDEELD}


class _Popen:
    """Records the creation flags of every attempt; refuses breakaway when told to."""

    def __init__(self, refuse_breakaway: bool):
        self.refuse_breakaway, self.flags, self.pid = refuse_breakaway, [], 4242

    def __call__(self, arguments, **kwargs):
        flags = kwargs.get("creationflags", 0)
        self.flags.append(flags)
        if self.refuse_breakaway and flags & handelen._CREATE_BREAKAWAY_FROM_JOB:
            raise OSError(None, "Access is denied", None, handelen._ERROR_ACCESS_DENIED)
        return self


def _breakaway(flags: int) -> bool:
    return bool(flags & handelen._CREATE_BREAKAWAY_FROM_JOB)


def test_inside_a_job_breakaway_is_asked_first_and_a_refusal_falls_back(tmp_path, monkeypatch):
    popen = _Popen(refuse_breakaway=True)
    monkeypatch.setattr(handelen.subprocess, "Popen", popen)
    monkeypatch.setattr(handelen, "_process_in_job", lambda pid=None: True)
    assert start_detached(["x"], log_path=tmp_path / "r.log") == RUNNER_HOST_GEBONDEN
    assert [_breakaway(f) for f in popen.flags] == [True, False]
    assert all(f & subprocess.CREATE_NO_WINDOW and f & subprocess.CREATE_NEW_PROCESS_GROUP for f in popen.flags)


def test_inside_a_job_a_granted_breakaway_is_reported_as_losgekoppeld(tmp_path, monkeypatch):
    popen = _Popen(refuse_breakaway=False)
    monkeypatch.setattr(handelen.subprocess, "Popen", popen)
    answers = iter([True, False])  # the host: inside a job; the child: outside
    monkeypatch.setattr(handelen, "_process_in_job", lambda pid=None: next(answers))
    assert start_detached(["x"], log_path=tmp_path / "r.log") == RUNNER_LOSGEKOPPELD
    assert [_breakaway(f) for f in popen.flags] == [True]


def test_outside_a_job_no_breakaway_is_requested(tmp_path, monkeypatch):
    popen = _Popen(refuse_breakaway=True)
    monkeypatch.setattr(handelen.subprocess, "Popen", popen)
    monkeypatch.setattr(handelen, "_process_in_job", lambda pid=None: False)
    assert start_detached(["x"], log_path=tmp_path / "r.log") == RUNNER_LOSGEKOPPELD
    assert [_breakaway(f) for f in popen.flags] == [False]


def test_an_unanswered_measurement_is_reported_as_not_assessed(tmp_path, monkeypatch):
    popen = _Popen(refuse_breakaway=False)
    monkeypatch.setattr(handelen.subprocess, "Popen", popen)
    monkeypatch.setattr(handelen, "_process_in_job", lambda pid=None: None)
    assert start_detached(["x"], log_path=tmp_path / "r.log") == RUNNER_NIET_BEOORDEELD


def test_a_start_failure_that_is_not_a_breakaway_refusal_is_an_action_error(tmp_path, monkeypatch):
    def broken(arguments, **kwargs):
        raise OSError(2, "not found")

    monkeypatch.setattr(handelen.subprocess, "Popen", broken)
    monkeypatch.setattr(handelen, "_process_in_job", lambda pid=None: True)
    with pytest.raises(handelen.ActionError):
        start_detached(["x"], log_path=tmp_path / "r.log")
