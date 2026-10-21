"""The small read script of the pre-flight (`scripts/Invoke-GjkLiveMeting.ps1`),
driven with the NEP-transport the runner tests use.

Only where `powershell.exe` exists, like `tests/test_runner_script.py`. What is
tested here is the SCRIPT: that it measures through the runner's own transport
function, that it refuses a forbidden box before any transport is loaded, that
a failed session or a failed `df` never prints a number, and that what it does
print is exactly the one line the server reads
(`nsmcp.preflight.free_space_from_script`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nsmcp.preflight import free_space_from_script

pytestmark = pytest.mark.skipif(
    shutil.which("powershell.exe") is None, reason="het leesscript vraagt Windows PowerShell 5.1"
)

REPO = Path(__file__).parent.parent
SCRIPT = REPO / "scripts" / "Invoke-GjkLiveMeting.ps1"
TRANSPORT_NEP = Path(__file__).parent / "fixtures" / "runner" / "GjkUpgrade-NepTransport.ps1"
GOEDE_VINGERAFDRUK = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
NEP_WACHTWOORD = "TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a"


def _run(
    tmp_path: Path,
    *,
    adres: str = "127.0.0.1",
    doel: str = "lab-02-test",
    vingerafdruk: str = GOEDE_VINGERAFDRUK,
    extra_args: list[str] | None = None,
    responses: str | None = None,
    transport: Path | None = TRANSPORT_NEP,
    meting: str = "vrije-ruimte",
) -> tuple[subprocess.CompletedProcess, Path]:
    markers = tmp_path / "markers"
    argumenten = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT),
        "-Meting",
        meting,
        "-Doel",
        doel,
        "-Adres",
        adres,
        "-Gebruiker",
        "gjktestgebruiker",
        "-CredentialTarget",
        "GJK/Test/leesscript",
        "-HostsleutelVingerafdruk",
        vingerafdruk,
    ]
    if transport is not None:
        argumenten += ["-Transport", str(transport)]
    argumenten += extra_args or []
    env = dict(os.environ)
    env["GJK_TEST_MARKERDIR"] = str(markers)
    if responses is not None:
        pad = tmp_path / "responses.json"
        pad.write_text(responses, encoding="utf-8")
        env["GJK_TEST_RESPONSES"] = str(pad)
    proc = subprocess.run(argumenten, capture_output=True, text=True, timeout=60, cwd=str(REPO), env=env)
    return proc, markers


def _commands(markers: Path) -> list[str]:
    pad = markers / "commands.txt"
    return pad.read_text(encoding="ascii").splitlines() if pad.exists() else []


def test_the_script_is_ascii_and_parses_on_windows_powershell_5_1():
    SCRIPT.read_text(encoding="ascii")
    uit = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$fout = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', "
            "[ref]$null, [ref]$fout); if ($fout.Count -gt 0) { $fout | ForEach-Object { Write-Output $_.ToString() } }"
            " else { 'ok' }",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "ok" in uit.stdout, uit.stdout + uit.stderr


def test_the_free_space_is_measured_through_the_transport_and_read_by_the_server(tmp_path):
    proc, markers = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[VRIJ_MB] 8789" in proc.stdout.splitlines()
    assert free_space_from_script(proc.returncode, proc.stdout) == (8789, "")
    assert _commands(markers) == ["shell df -k /var"]
    assert (markers / "ssh-sessie-geopend.txt").exists()
    assert (markers / "ssh-sessie-gesloten.txt").exists()
    assert "[EINDSTATUS]" in proc.stdout
    assert NEP_WACHTWOORD not in proc.stdout + proc.stderr


def test_a_differing_host_key_prints_no_number_and_sends_no_command(tmp_path):
    proc, markers = _run(tmp_path, vingerafdruk="11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[VRIJ_MB]" not in proc.stdout
    assert "[FOUT] kon geen SSH-sessie openen: hostsleutel wijkt af" in proc.stdout
    assert _commands(markers) == []
    waarde, reden = free_space_from_script(proc.returncode, proc.stdout)
    assert waarde is None and "hostsleutel wijkt af" in reden


@pytest.mark.parametrize(
    "stdout,exitcode",
    [
        ("Filesystem 1K-blocks Used Avail Use% Mounted on\n/dev/x 10000000 100000 9000000 2% /var", 1),
        ("Filesystem 1K-blocks Used Avail Use% Mounted on\n/dev/x 10000000 100000 veel 2% /var", 0),
    ],
)
def test_a_failed_or_unreadable_df_prints_no_number(tmp_path, stdout, exitcode):
    import json

    proc, _markers = _run(tmp_path, responses=json.dumps([{"match": "df -k", "stdout": stdout, "exitcode": exitcode}]))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[VRIJ_MB]" not in proc.stdout
    assert "[FOUT]" in proc.stdout
    assert free_space_from_script(proc.returncode, proc.stdout)[0] is None


@pytest.mark.parametrize(
    "adres,doel,verboden",
    [
        ("203.0.113.9", "lab-02-test", "203.0.113.9"),
        ("127.0.0.1", "lab-02-test", "198.51.100.7,127.0.0.1"),
        ("127.0.0.1", "lab-01", None),
        ("127.0.0.1", "lab-01.intern.example", None),
    ],
)
def test_a_forbidden_box_is_refused_before_any_transport_call(tmp_path, adres, doel, verboden):
    extra = ["-VerbodenAdressen", verboden] if verboden else []
    proc, markers = _run(tmp_path, adres=adres, doel=doel, extra_args=extra)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[VRIJ_MB]" not in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_a_non_ascii_argument_is_refused_before_any_transport_call(tmp_path):
    proc, markers = _run(tmp_path, doel="lab-" + chr(0xE9))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_a_stray_positional_argument_is_refused_not_bound_silently(tmp_path):
    proc, markers = _run(tmp_path, extra_args=["-VerbodenAdressen", "198.51.100.7", "127.0.0.1"])
    assert proc.returncode != 0
    assert "[VRIJ_MB]" not in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_the_script_measures_only_and_knows_one_measurement(tmp_path):
    proc, markers = _run(tmp_path, meting="iets-anders")
    assert proc.returncode != 0
    assert not markers.exists() or not any(markers.iterdir())
    tekst = SCRIPT.read_text(encoding="ascii")
    assert "Get-GjkVrijeRuimteVar -Sessie $sessie" in tekst
    for schrijvend in ("save ns config", "Copy-GjkFile", "installns", "reboot", "mkdir"):
        assert schrijvend not in tekst
