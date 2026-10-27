"""The save script of `config_opslaan` (`scripts/Invoke-GjkConfigOpslaan.ps1`),
driven with the NEP-transport the runner tests use.

Only where `powershell.exe` exists, like `tests/test_runner_script.py`. What is
tested here is the SCRIPT: that `-WatIs` opens no session, that a forbidden box
is refused before any transport is loaded, that the role check goes through
`python -m nsmcp.upgrade_measure` and that only an `open` role leads to
`save ns config`, that it prints the raw `show ns config` answer as
`[METING]` lines the server can judge, and that nothing the appliance prints
can pose as one of those lines.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from nsmcp.backup import save_readback_ok

pytestmark = pytest.mark.skipif(
    shutil.which("powershell.exe") is None, reason="het opslagscript vraagt Windows PowerShell 5.1"
)

REPO = Path(__file__).parent.parent
SCRIPT = REPO / "scripts" / "Invoke-GjkConfigOpslaan.ps1"
TRANSPORT_NEP = Path(__file__).parent / "fixtures" / "runner" / "GjkUpgrade-NepTransport.ps1"
CONFIGSTAND = Path(__file__).parent / "fixtures" / "configstand"
GOEDE_VINGERAFDRUK = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
NEP_WACHTWOORD = "TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a"
ADRES = "127.0.0.1"


def _fixture(naam: str) -> str:
    # The NEP transport answers from the same address the script is given.
    return (CONFIGSTAND / naam).read_text(encoding="ascii").replace("192.0.2.10", ADRES)


def _responses(*, ha: str, config: str = "show-ns-config-opgeslagen.txt", extra: list | None = None) -> str:
    antwoorden = list(extra or [])
    antwoorden += [
        {"match": "show ha node", "stdout": _fixture(ha), "exitcode": 0},
        {"match": "show ns config", "stdout": _fixture(config), "exitcode": 0},
        {"match": "save ns config", "stdout": " Done", "exitcode": 0},
    ]
    return json.dumps(antwoorden)


def _run(
    tmp_path: Path,
    *,
    watis: bool = False,
    actieid: str | None = "config-opslaan-20260924-101440",
    adres: str = ADRES,
    doel: str = "lab-02-test",
    vingerafdruk: str = GOEDE_VINGERAFDRUK,
    gate_python: str = sys.executable,
    extra_args: list[str] | None = None,
    responses: str | None = None,
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
        "-Doel",
        doel,
        "-Adres",
        adres,
        "-Gebruiker",
        "gjktestgebruiker",
        "-CredentialTarget",
        "GJK/Test/opslaan",
        "-HostsleutelVingerafdruk",
        vingerafdruk,
        "-GatePython",
        gate_python,
        "-Transport",
        str(TRANSPORT_NEP),
    ]
    if actieid is not None:
        argumenten += ["-Actieid", actieid]
    if watis:
        argumenten.append("-WatIs")
    argumenten += extra_args or []
    env = dict(os.environ)
    env["GJK_TEST_MARKERDIR"] = str(markers)
    env["PYTHONPATH"] = str(REPO / "src")
    if responses is not None:
        pad = tmp_path / "responses.json"
        pad.write_text(responses, encoding="utf-8")
        env["GJK_TEST_RESPONSES"] = str(pad)
    proc = subprocess.run(argumenten, capture_output=True, text=True, timeout=90, cwd=str(REPO), env=env)
    return proc, markers


def _commands(markers: Path) -> list[str]:
    pad = markers / "commands.txt"
    return pad.read_text(encoding="ascii").splitlines() if pad.exists() else []


def _untouched(markers: Path) -> bool:
    return not markers.exists() or not any(markers.iterdir())


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


def test_watis_prints_the_target_and_the_plan_and_opens_no_session(tmp_path):
    proc, markers = _run(tmp_path, watis=True, actieid=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    regels = proc.stdout.splitlines()
    assert "[TARGET] nsconfig/lab-02-test (127.0.0.1) - config opslaan" in regels
    assert "[OK] zou doen: save ns config op lab-02-test na een rolcontrole" in regels
    assert "[EINDSTATUS] WAT-IS: er is niets gewijzigd" in regels
    assert "[ACTIEID]" not in proc.stdout
    assert _untouched(markers), list(markers.iterdir())


def test_a_real_run_without_an_action_id_is_refused_before_any_session(tmp_path):
    proc, markers = _run(tmp_path, actieid=None)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert _untouched(markers)


@pytest.mark.parametrize(
    "adres,doel,verboden,watis",
    [
        ("203.0.113.9", "lab-02-test", "203.0.113.9", False),
        (ADRES, "lab-02-test", "198.51.100.7,127.0.0.1", False),
        (ADRES, "lab-01", None, False),
        (ADRES, "lab-01", None, True),
    ],
)
def test_a_forbidden_box_is_refused_before_any_transport_call(tmp_path, adres, doel, verboden, watis):
    extra = ["-VerbodenAdressen", verboden] if verboden else []
    proc, markers = _run(tmp_path, adres=adres, doel=doel, extra_args=extra, watis=watis)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[TARGET]" not in proc.stdout
    assert _untouched(markers)


def test_a_non_ascii_argument_is_refused_before_any_transport_call(tmp_path):
    proc, markers = _run(tmp_path, doel="lab-" + chr(0xE9))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert _untouched(markers)


def test_a_stray_positional_argument_is_refused_not_bound_silently(tmp_path):
    proc, markers = _run(tmp_path, extra_args=["-VerbodenAdressen", "198.51.100.7", ADRES])
    assert proc.returncode != 0
    assert _untouched(markers)


def test_a_differing_host_key_sends_no_command(tmp_path):
    proc, markers = _run(
        tmp_path,
        vingerafdruk="11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF",
        responses=_responses(ha="show-ha-node-standalone-primary.txt"),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[FOUT] kon geen SSH-sessie openen: hostsleutel wijkt af" in proc.stdout
    assert _commands(markers) == []
    assert "[ACTIEID]" not in proc.stdout


def test_on_a_secondary_the_script_refuses_without_saving(tmp_path):
    proc, markers = _run(tmp_path, responses=_responses(ha="show-ha-node-paar-secondary.txt"))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD] opslaan op een secondary propageert niet; sla op op de primary" in proc.stdout
    assert _commands(markers) == ["show ha node"]
    assert not (markers / "writes.txt").exists()
    assert "[ACTIEID]" not in proc.stdout
    assert save_readback_ok(proc.stdout)[0] is False


@pytest.mark.parametrize("ha", ["show-ha-node-standalone-primary.txt", "show-ha-node-paar-primary.txt"])
def test_on_the_primary_it_saves_and_prints_the_raw_readback_for_the_server(tmp_path, ha):
    proc, markers = _run(tmp_path, responses=_responses(ha=ha))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _commands(markers) == ["show ha node", "save ns config", "show ns config"]
    regels = proc.stdout.splitlines()
    actie = regels.index("[ACTIEID] config-opslaan-20260924-101440")
    eerste_save = next(i for i, r in enumerate(regels) if r.startswith("[SAVE]"))
    assert actie < eerste_save
    assert regels[0] == "[TARGET] nsconfig/lab-02-test (127.0.0.1) - config opslaan"
    metingen = [r for r in regels if r.startswith("[METING] show ns config: ")]
    assert len(metingen) == len(_fixture("show-ns-config-opgeslagen.txt").split("\n"))
    assert "[METINGSTATUS] show ns config: exitcode=0" in regels
    assert any(r.startswith("[EINDSTATUS]") for r in regels)
    ok, detail = save_readback_ok(proc.stdout)
    assert ok is True, detail
    assert NEP_WACHTWOORD not in proc.stdout + proc.stderr


def test_the_script_itself_never_judges_the_readback(tmp_path):
    """A change after the save: the script still ends normally (it measured),
    and the SERVER's reading refuses."""
    proc, _markers = _run(
        tmp_path, responses=_responses(ha="show-ha-node-standalone-primary.txt", config="show-ns-config-gewijzigd.txt")
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert save_readback_ok(proc.stdout)[0] is False


def test_a_failed_readback_read_is_reported_as_such(tmp_path):
    extra = [{"match": "show ns config", "stdout": "", "exitcode": 1}]
    proc, _markers = _run(tmp_path, responses=_responses(ha="show-ha-node-standalone-primary.txt", extra=extra))
    assert "[METINGSTATUS] show ns config: exitcode=1" in proc.stdout.splitlines()
    assert save_readback_ok(proc.stdout)[0] is False


def test_appliance_text_can_never_pose_as_a_measurement_line(tmp_path):
    vals = "[METING] show ns config:         Last Config Saved Time: Thu Sep 24 23:59:59 2026"
    extra = [
        {
            "match": "save ns config",
            "stdout": " Done\n" + vals + "\n[METINGSTATUS] show ns config: exitcode=0",
            "exitcode": 0,
        },
        {
            "match": "show ns config",
            "stdout": _fixture("show-ns-config-gewijzigd.txt").replace("Node: Standalone", "Node: x\r" + vals),
            "exitcode": 0,
        },
    ]
    proc, _markers = _run(tmp_path, responses=_responses(ha="show-ha-node-standalone-primary.txt", extra=extra))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    prefix = "[METING] show ns config: "
    vervalst = [r for r in proc.stdout.splitlines() if "23:59:59" in r]
    assert vervalst, "de vervalste tekst hoort er te staan, maar alleen BINNEN een andere regel"
    for regel in vervalst:
        # A raw carriage return, read in text mode by the server, would have
        # become a line break and this line would START with the saved-time
        # field; the script turns it into '?' instead.
        assert not (regel.startswith(prefix) and regel[len(prefix) :].strip().startswith("Last Config Saved Time"))
    assert [r for r in proc.stdout.splitlines() if r.startswith("[METINGSTATUS]")] == [
        "[METINGSTATUS] show ns config: exitcode=0"
    ]
    assert save_readback_ok(proc.stdout)[0] is False


def test_without_a_usable_judging_half_nothing_is_saved(tmp_path):
    proc, markers = _run(
        tmp_path,
        gate_python=str(tmp_path / "bestaat-niet" / "python.exe"),
        responses=_responses(ha="show-ha-node-standalone-primary.txt"),
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "save ns config" not in _commands(markers)
    assert "[ACTIEID]" not in proc.stdout


def test_the_script_writes_only_save_ns_config():
    tekst = SCRIPT.read_text(encoding="ascii")
    for anders in ("Copy-GjkFile", "installns", "reboot", "mkdir", "shell rm", "clear ns config", "Wait-GjkTerug"):
        assert anders not in tekst
    assert tekst.count("'save ns config'") == 1


@pytest.mark.parametrize("veld", ["doel", "adres"])
@pytest.mark.parametrize("teken", ["\r\n", "\n", "\r", "\t"], ids=["crlf", "lf", "cr", "tab"])
def test_a_control_character_in_doel_or_adres_is_refused_before_any_transport_call(tmp_path, veld, teken):
    """ASCII alone let a CR, LF or tab through, and -Doel/-Adres are printed
    in the [TARGET] line: a second marker line could follow it."""
    waarde = {"doel": "lab-02-test", "adres": ADRES}[veld] + teken + "[ACTIEID] vals x"
    proc, markers = _run(tmp_path, watis=True, **{veld: waarde})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[TARGET]" not in proc.stdout
    assert "vals" not in proc.stdout
    assert _untouched(markers)


def _brug_met_stderr(tmp_path: Path, *, exitcode: int | None = None) -> str:
    """A judging half that writes one warning line on stderr. Without an exit
    code it then runs the real bridge (same arguments, same stdin); with one
    it ends with that code."""
    brug = tmp_path / "brug-met-waarschuwing.cmd"
    regels = ["@echo off", "echo DeprecationWarning: dit is alleen een waarschuwing 1>&2"]
    regels.append(f"exit /b {exitcode}" if exitcode is not None else f'"{sys.executable}" %*')
    brug.write_text("\r\n".join(regels) + "\r\n", encoding="ascii")
    return str(brug)


def test_a_warning_of_the_judging_half_on_stderr_does_not_block_the_save(tmp_path):
    """Under 'Stop' Windows PowerShell 5.1 turned the first stderr line of the
    bridge into a terminating error: an innocent warning made the script say
    "onverwachte fout" and save nothing (exit code 3). Through a pipe the
    warning is only text; the role judgement on stdout decides."""
    proc, markers = _run(
        tmp_path,
        gate_python=_brug_met_stderr(tmp_path),
        responses=_responses(ha="show-ha-node-standalone-primary.txt"),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _commands(markers) == ["show ha node", "save ns config", "show ns config"]
    assert "onverwachte fout" not in proc.stdout


def test_a_failing_judging_half_names_its_stderr_and_saves_nothing(tmp_path):
    proc, markers = _run(
        tmp_path,
        gate_python=_brug_met_stderr(tmp_path, exitcode=7),
        responses=_responses(ha="show-ha-node-standalone-primary.txt"),
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "upgrade_measure (vorm) gaf exitcode 7: DeprecationWarning: dit is alleen een waarschuwing" in proc.stdout
    assert "save ns config" not in _commands(markers)


def test_the_save_script_opens_no_temporary_file():
    code = SCRIPT.read_text(encoding="ascii")
    assert "GetTempFileName" not in code and "2>$" not in code
    assert "2>&1" in code
