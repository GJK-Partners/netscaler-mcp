"""Pre-write evidence must never overwrite a later measurement."""

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from upgrade_gate_harness import pre_gate_context

from nsmcp.upgrade import Gate, append_line, evaluate_phase, ledger_line, stand_answer


@pytest.mark.parametrize("outcome", ["dicht", "niet beoordeeld"])
def test_later_negative_reading_survives_an_open_pre_gate(outcome):
    context = pre_gate_context("R4")
    context["gates"] = (Gate("hostsleutel gepind", "voorwaarde", outcome, "after reboot read", "after reboot failure"),)
    verdict = evaluate_phase("R4", {"actieid_uit_script": "a-1"}, context)
    gates = {gate.name: gate for gate in verdict.gates}
    assert gates["hostsleutel gepind"].outcome == outcome
    assert gates["hostsleutel gepind"].evidence == "after reboot read"
    assert gates["voorpoort: hostsleutel gepind"].outcome == "open"
    assert verdict.outcome == "poort dicht"
    row = ledger_line(
        verdict,
        run="r1",
        doel="lab-02",
        actieid="a-1",
        bevestiger="test",
        started=context["gestart"],
        ended=context["gestart"],
        event="poort_dicht",
    )
    answer = stand_answer([row], datetime.now(UTC), 24).to_text()
    assert "voorpoort: hostsleutel gepind: open" in answer
    assert "after reboot read" in answer


def test_open_closing_read_cannot_cancel_a_closed_pre_gate():
    context = pre_gate_context("R4")
    pre = context["lines"][-1]
    host = next(g for g in pre["poort"] if g["naam"] == "hostsleutel gepind")
    host.update(uitkomst="dicht", bewijs="before reboot read", reden="pre-write refusal")
    pre["uitkomst"] = "dicht"
    context["gates"] = (Gate("hostsleutel gepind", "voorwaarde", "open", "later read"),)
    verdict = evaluate_phase("R4", {"actieid_uit_script": "a-1"}, context)
    gates = {gate.name: gate for gate in verdict.gates}
    assert verdict.outcome == "poort dicht"
    assert gates["hostsleutel gepind"].evidence == "later read"
    assert gates["voorpoort: hostsleutel gepind"].outcome == "dicht"
    assert gates["voorpoort van deze poging"].outcome == "dicht"


def _run_fake_phase(tmp_path, phase, *, post_reboot_failure=False):
    if shutil.which("powershell.exe") is None:
        pytest.skip("Windows PowerShell 5.1 ontbreekt")
    repo = Path(__file__).resolve().parents[1]
    fake = repo / "tests/fixtures/runner/GjkUpgrade-NepTransport.ps1"
    transport = tmp_path / "transport.ps1"
    source = f". '{fake}'\n"
    if post_reboot_failure:
        source += """
function Wait-GjkTerug {
    [pscustomobject]@{
        ok=$false; reden='hostsleutel wijkt af: synthetic post-reboot failure'
        poort22Terug=(Get-Date); authTerug=$null; versie=''
    }
}
"""
    transport.write_text(source, encoding="utf-8")
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    bundle = firmware / "build-14.1-72.57_nc_64.tgz"
    bundle.write_bytes(b"nep-bundel-inhoud")
    bundle.with_suffix(".tgz.sha256").write_text(
        hashlib.sha256(bundle.read_bytes()).hexdigest(),
        encoding="ascii",
    )
    ledger = tmp_path / "ledger.jsonl"
    previous = "R" + str(int(phase[1:]) - 1)
    append_line(
        ledger,
        {
            "run": "r1",
            "doel": "lab-02-test",
            "fase": previous,
            "gebeurtenis": "voormeting_vast" if previous == "R0" else "fase_geslaagd",
            "uitkomst": "geslaagd",
        },
    )
    markers = tmp_path / "markers"
    import os

    env = dict(os.environ, GJK_TEST_MARKERDIR=str(markers))
    proc = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repo / "scripts/Invoke-GjkUpgradeFase.ps1"),
            "-Doel",
            "lab-02-test",
            "-Adres",
            "127.0.0.1",
            "-Fase",
            phase,
            "-Run",
            "r1",
            "-Gebruiker",
            "synthetic",
            "-CredentialTarget",
            "GJK/Test/upgrade-review",
            "-HostsleutelVingerafdruk",
            "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            "-Doelbuild",
            "14.1-72.57",
            "-Firmwaremap",
            str(firmware),
            "-Ledger",
            str(ledger),
            "-GatePython",
            sys.executable,
            "-Actieid",
            "a-1",
            "-Bevestiger",
            "synthetic",
            "-Transport",
            str(transport),
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    return proc, rows, markers


def test_r4_runner_preserves_post_reboot_hostkey_failure_and_pre_evidence(tmp_path):
    proc, rows, _ = _run_fake_phase(tmp_path, "R4", post_reboot_failure=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    pre = next(r for r in rows if r.get("gebeurtenis") == "voorpoort")
    assert next(g for g in pre["poort"] if g["naam"] == "hostsleutel gepind")["uitkomst"] == "open"
    closing = rows[-1]
    gates = {g["naam"]: g for g in closing["poort"]}
    assert gates["hostsleutel gepind"]["uitkomst"] == "dicht"
    assert "synthetic post-reboot failure" in gates["hostsleutel gepind"]["bewijs"]
    assert gates["voorpoort: hostsleutel gepind"]["uitkomst"] == "open"
    assert closing["uitkomst"] == "poort dicht"


def test_precheck_absence_probe_excludes_existing_symlink_entry(tmp_path):
    proc, _, markers = _run_fake_phase(tmp_path, "R2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    commands = (markers / "commands.txt").read_text(encoding="ascii").splitlines()
    read = next(c for c in commands if c.startswith("shell cat /var/tmp/"))
    path = read.split()[-1]
    probe = next(c for c in commands if "test ! -e " in c)
    assert f"test ! -e {path} && test ! -L {path} && echo AFWEZIG" in probe
    assert commands.index(probe) < commands.index(read)


def test_r1_missing_drift_acceptance_stops_before_mkdir_or_upload(tmp_path):
    proc, rows, markers = _run_fake_phase(tmp_path, "R1")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not (markers / "writes.txt").exists()
    pre = next(r for r in rows if r.get("gebeurtenis") == "voorpoort")
    gate = next(g for g in pre["poort"] if g["naam"] == "drift afwezig of bewust geaccepteerd")
    assert gate["uitkomst"] == "dicht"
