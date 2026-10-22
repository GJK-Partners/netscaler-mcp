"""1.0.3 P-2: no Python child process imports code from its working directory.

MEASURED before (1.0.2): the PowerShell bridge `_GjkAanroepPython` in
`Invoke-GjkUpgradeFase.ps1` and `Invoke-GjkConfigOpslaan.ps1` started
`& $GatePython -m $Module`. `-m` puts the WORKING DIRECTORY first on the
module path, and the server's children inherited the server's own working
directory. A planted `nsmcp` package there (a supplier-writable directory
the server happened to start in) replaced `nsmcp.upgrade_measure` - the
module that forms the gate decisions - although every PowerShell pin
matched.

Two halves, both tested here:
- every Python child (the bridge in both scripts, a `.py` runner, a `.py`
  presenter) starts in isolated mode (`-I`: no working directory, no
  script directory, no PYTHON* variables on the module path);
- every child the product starts gets an explicit, fixed working directory
  (`child_working_directory()`), never the inherited one.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from nsmcp import code_channel, handelen, powershell
from nsmcp.powershell import child_working_directory

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
BRIDGE_SCRIPTS = ("Invoke-GjkUpgradeFase.ps1", "Invoke-GjkConfigOpslaan.ps1")


def _bridge(script: str) -> str:
    text = (SCRIPTS / script).read_text(encoding="ascii")
    match = re.search(r"(?ms)^function _GjkAanroepPython \{.*?^\}", text)
    assert match, f"{script}: _GjkAanroepPython niet gevonden"
    return match.group()


def _plant(directory: Path, markers: Path) -> tuple[Path, Path]:
    """A marker-only shadow `nsmcp` package: importing it writes a marker,
    running its upgrade_measure writes a second one and answers like a
    passing gate would."""
    package = directory / "nsmcp"
    package.mkdir(parents=True)
    init_marker = markers / "package-imported.txt"
    run_marker = markers / "bridge-executed.txt"
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(init_marker)!r}).write_text('marker', encoding='ascii')\n",
        encoding="ascii",
    )
    (package / "upgrade_measure.py").write_text(
        f"from pathlib import Path\nPath({str(run_marker)!r}).write_text('marker', encoding='ascii')\n"
        "print('{\"poort\": []}')\n",
        encoding="ascii",
    )
    return init_marker, run_marker


@pytest.mark.skipif(sys.platform != "win32", reason="the bridge is Windows PowerShell")
@pytest.mark.parametrize("script", BRIDGE_SCRIPTS)
def test_the_exact_bridge_does_not_import_a_planted_package_from_its_working_directory(tmp_path, script):
    """The probe of the review, as a test: the EXACT bridge function out of
    the shipped script, started from a supplier directory that carries a
    shadow `nsmcp`. The genuine module must answer (it refuses the empty
    request with exit 2); the planted code may not run."""
    exe = powershell.powershell_path()
    if not exe.is_file():
        pytest.skip("Windows PowerShell niet aanwezig")
    supplier = tmp_path / "aanlevermap"
    markers = tmp_path / "markers"
    markers.mkdir()
    init_marker, run_marker = _plant(supplier, markers)
    python = sys.executable.replace("'", "''")
    harness = tmp_path / "bridge.ps1"
    harness.write_text(
        # 'Continue', not the scripts' own 'Stop': the genuine module refuses
        # the empty request on stderr, and under 'Stop' Windows PowerShell
        # 5.1 turns that redirected stderr line into a terminating error
        # before the exit code can be read. The bridge function itself is
        # the exact shipped text.
        "$ErrorActionPreference = 'Continue'\n"
        f"$GatePython = '{python}'\n"
        f"{_bridge(script)}\n"
        "$r = _GjkAanroepPython -Module 'nsmcp.upgrade_measure' -JsonIn '{}'\n"
        "Write-Host ('BRIDGE_EXIT=' + $r.ExitCode)\n",
        encoding="ascii",
    )
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    run = subprocess.run(
        [str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        cwd=supplier,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert not init_marker.exists(), f"{script}: het geplante pakket is geimporteerd\n{run.stdout}{run.stderr}"
    assert not run_marker.exists(), f"{script}: de geplante code is uitgevoerd\n{run.stdout}{run.stderr}"
    # The genuine installed module answered: it refuses an empty request.
    assert "BRIDGE_EXIT=2" in run.stdout, run.stdout + run.stderr


def test_every_python_call_in_the_scripts_is_isolated():
    """A source guard over every script, not only the two known bridges: a
    later `& $GatePython -m ...` without `-I` fails here."""
    calls = []
    for path in sorted(SCRIPTS.glob("*.ps1")):
        for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
            if re.search(r"&\s*\$GatePython\b", line):
                calls.append((path.name, number, line))
    assert {name for name, _, _ in calls} >= set(BRIDGE_SCRIPTS), calls
    bare = [(name, number) for name, number, line in calls if not re.search(r"&\s*\$GatePython\s+-I\s", line)]
    assert bare == [], bare


def test_the_child_working_directory_is_fixed_and_absolute():
    cwd = child_working_directory()
    assert cwd.is_absolute() and cwd.is_dir()
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        assert cwd == Path(root) / "System32"
    # Not the directory the test (and so a server) happens to run in.
    assert cwd != Path.cwd()


def test_the_child_working_directory_refuses_a_relative_system_root(monkeypatch):
    if sys.platform != "win32":
        pytest.skip("the system root is a Windows notion")
    monkeypatch.setenv("SystemRoot", "relatief")
    with pytest.raises(powershell.PowerShellMissing):
        child_working_directory()


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        raise OSError("spion: niet gestart")


def test_start_powershell_sets_the_fixed_working_directory(monkeypatch, tmp_path):
    spy = _Spy()
    monkeypatch.setattr(powershell.subprocess, "Popen", spy)
    exe = tmp_path / "powershell.exe"
    exe.write_text("", encoding="ascii")
    monkeypatch.setattr(powershell, "powershell_path", lambda: exe)
    with pytest.raises(OSError):
        powershell.start_powershell(["-NoProfile"])
    assert spy.calls and spy.calls[0][1].get("cwd") == child_working_directory()


def test_a_python_runner_starts_isolated(tmp_path):
    runner = tmp_path / "runner.py"
    runner.write_text("print('x')\n", encoding="ascii")
    argv = handelen.upgrade_command(runner, ["-Fase", "R0"])
    assert argv[1] == "-I" and argv[2] == str(runner), argv


def test_the_upgrade_preview_and_the_detached_run_set_the_fixed_working_directory(monkeypatch, tmp_path):
    spy = _Spy()
    monkeypatch.setattr(handelen.subprocess, "Popen", spy)
    with pytest.raises(handelen.ActionError):
        handelen._default_upgrade_process_runner(["x"], 5)
    with pytest.raises(handelen.ActionError):
        handelen.start_detached(["x"], log_path=tmp_path / "log.txt")
    assert len(spy.calls) >= 2
    assert all(kwargs.get("cwd") == child_working_directory() for _, kwargs in spy.calls), spy.calls


def test_a_python_presenter_starts_isolated_in_the_fixed_working_directory(tmp_path):
    """A REAL presenter process reports how it was started: its working
    directory and whether isolated mode is on. It delivers nothing, so the
    channel fails closed - what matters is what the child saw."""
    seen = tmp_path / "gezien.json"
    presenter = tmp_path / "presenter.py"
    presenter.write_text(
        "import json, os, sys, pathlib\n"
        f"pathlib.Path({str(seen)!r}).write_text(json.dumps("
        "{'cwd': os.getcwd(), 'isolated': sys.flags.isolated}), encoding='utf-8')\n"
        "print('{}')\n",
        encoding="ascii",
    )
    channel = code_channel.SsoCodeChannel(presenter, "https://voorbeeld.invalid/goedkeuring", 5)
    with pytest.raises(code_channel.CodeChannelError):
        channel("certificaat_vervangen", "[TARGET] doos", {"dienst": "x"}, "AB2345", "voorstel", "A", "lab")
    observed = json.loads(seen.read_text(encoding="utf-8"))
    assert observed["isolated"] == 1, observed
    assert Path(observed["cwd"]) == child_working_directory(), observed


def _unusable_working_directory(monkeypatch, tmp_path) -> Path:
    """`%SystemRoot%` on an existing directory WITHOUT a System32 below it,
    while PowerShell itself is found (its path is pinned to a real file)."""
    if sys.platform != "win32":
        pytest.skip("the system root is a Windows notion")
    root = tmp_path / "GEHEIM-WERKMAP-ROOT"
    root.mkdir()
    monkeypatch.setenv("SystemRoot", str(root))
    exe = tmp_path / "powershell.exe"
    exe.write_text("", encoding="ascii")
    monkeypatch.setattr(powershell, "powershell_path", lambda: exe)
    return root


def test_r3_5_an_unusable_working_directory_is_named_as_such_in_a_scan(monkeypatch, tmp_path):
    """R3-5: MEASURED before, a scan said "Windows PowerShell niet gevonden"
    when the fixed working directory was the reason. The reason is now the
    working directory, without a local path."""
    from nsmcp import collect

    _unusable_working_directory(monkeypatch, tmp_path)
    spy = _Spy()
    monkeypatch.setattr(powershell.subprocess, "Popen", spy)
    with pytest.raises(collect.CollectNotStarted) as caught:
        collect._run_powershell(["-NoProfile"], 5)
    text = str(caught.value)
    assert "werkmap" in text, text
    assert "niet gevonden" not in text, text
    assert "GEHEIM-WERKMAP-ROOT" not in text and str(tmp_path) not in text, text
    assert spy.calls == [], "no process may start"


def test_r3_5_the_other_starters_name_the_working_directory_without_a_path(monkeypatch, tmp_path):
    _unusable_working_directory(monkeypatch, tmp_path)
    spy = _Spy()
    monkeypatch.setattr(handelen.subprocess, "Popen", spy)
    monkeypatch.setattr(code_channel.subprocess, "Popen", spy)
    messages = []
    for call in (
        lambda: handelen._default_upgrade_process_runner(["x"], 5),
        lambda: handelen.start_detached(["x"], log_path=tmp_path / "log.txt"),
    ):
        with pytest.raises(handelen.ActionError) as caught:
            call()
        messages.append(str(caught.value))
    presenter = tmp_path / "presenter.py"
    presenter.write_text("print('{}')\n", encoding="ascii")
    channel = code_channel.SsoCodeChannel(presenter, "https://voorbeeld.invalid/goedkeuring", 5)
    with pytest.raises(code_channel.CodeChannelError) as caught:
        channel("certificaat_vervangen", "[TARGET] doos", {"dienst": "x"}, "AB2345", "voorstel", "A", "lab")
    messages.append(str(caught.value))
    for text in messages:
        assert "werkmap" in text, text
        assert "GEHEIM-WERKMAP-ROOT" not in text and str(tmp_path) not in text, text
    assert spy.calls == [], "no process may start"
