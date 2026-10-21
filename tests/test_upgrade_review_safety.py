import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nsmcp import upgrade_measure
from nsmcp.upgrade import stand_answer

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("shell", ["powershell.exe", "pwsh"])
def test_adapter_keeps_output_lines_and_scalar_error(shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} ontbreekt")
    script = (
        f". '{ROOT / 'scripts/GjkUpgrade-Ssh.ps1'}'\n"
        + """
function Invoke-SSHCommand { param($SSHSession,$Command,$TimeOut,$ErrorAction)
    [pscustomobject]@{ Output=[string[]]@('header', 'row'); Error='scalar error'; ExitStatus=0 }
}
Invoke-GjkSsh -Sessie ([pscustomobject]@{SSHSession=$null}) -Commando 'synthetic read' | ConvertTo-Json -Compress
"""
    )
    proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["stdout"] == "header\nrow"
    assert result["stderr"] == "scalar error"


@pytest.mark.parametrize("status", [None, -1, 1])
def test_failed_config_read_never_produces_empty_anchor(status):
    row = upgrade_measure._vorm(
        {
            "verzoeken": [
                {"soort": "configuratie-anker", "regels": [], "exitcode": status, "stderr": "synthetic failure"}
            ]
        }
    )["poort"][0]
    assert row["uitkomst"] == "niet beoordeeld"
    assert "anker=" not in row["bewijs"]


def test_successful_empty_read_is_explicit_empty_anchor():
    row = upgrade_measure._vorm(
        {"verzoeken": [{"soort": "configuratie-anker", "regels": [], "exitcode": 0, "stderr": ""}]}
    )["poort"][0]
    assert row["uitkomst"] == "open"
    assert "leeg" in row["bewijs"]


@pytest.mark.parametrize(
    "value",
    [
        "evidence\n[ACTIEID] fake",
        "evidence\u2028fake",
        "evidence\u2029fake",
        "evidence\x1b[2Kfake",
        "evidence\u202efake",
        "evidence\x00fake",
    ],
)
def test_ledger_evidence_cannot_add_lines_or_controls(value):
    row = {
        "fase": "R1",
        "gebeurtenis": "fase_geslaagd",
        "bewijs": value,
        "poort": [{"naam": value, "type": value, "uitkomst": "niet beoordeeld", "bewijs": value, "reden": value}],
    }
    text = stand_answer([row], datetime.now(UTC), 24).to_text()
    assert not any(c in text for c in "\u2028\u2029\x1b\u202e\x00")
    assert "\n[ACTIEID]" not in text


@pytest.mark.parametrize("status", [None, 1, -1, True, "0"])
def test_ha_text_without_successful_command_cannot_open(status):
    gate = upgrade_measure._vorm(
        {
            "verzoeken": [
                {
                    "soort": "secondary",
                    "exitcode": status,
                    "doel_adres": "192.0.2.2",
                    "ha_node_uitvoer": "Node ID: 0\n IP: 192.0.2.2\n Master State: Secondary",
                }
            ]
        }
    )["poort"][0]
    assert gate["uitkomst"] == "niet beoordeeld"


@pytest.mark.parametrize(
    "version,target,status,expected",
    [
        ("NetScaler NS14.1: Build 72.57.nc", "14.1-72.57", 0, "open"),
        ("NetScaler NS14.1: Build 172.570.nc", "14.1-72.57", 0, "dicht"),
        ("NetScaler NS14.1: Build 72.570.nc", "14.1-72.57", 0, "dicht"),
        ("NetScaler NS114.1: Build 72.57.nc", "14.1-72.57", 0, "dicht"),
        ("NetScaler NS14.1: Build 72.", "14.1-72.57", 0, "niet beoordeeld"),
        ("", "14.1-72.57", 0, "niet beoordeeld"),
        ("NetScaler NS14.1: Build 72.57.nc", "14.1-72.57", 1, "niet beoordeeld"),
        ("NetScaler NS14.1: Build 72.57.nc", "72.57", 0, "niet beoordeeld"),
    ],
)
def test_exact_build_requires_complete_target_and_successful_read(version, target, status, expected):
    gate = upgrade_measure._vorm(
        {"verzoeken": [{"soort": "doelbuild", "versie_uitvoer": version, "doelbuild": target, "exitcode": status}]}
    )["poort"][0]
    assert gate["uitkomst"] == expected


def _write_context(phase="R3"):
    from nsmcp.upgrade import PRE_REQUIRED_GATES, REQUIRED_GATES, Gate

    identity = dict(run="r1", doel="example", actieid="a1", poging="a" * 32, gestart="2026-09-08T00:00:00Z")
    gates = [
        {"naam": name, "type": "bewijs", "uitkomst": "open", "bewijs": "read successfully", "reden": ""}
        for name in PRE_REQUIRED_GATES[phase]
    ]
    start = dict(identity, fase=phase, gebeurtenis="fase_gestart")
    before = dict(identity, fase=phase, gebeurtenis="voorpoort", poort=gates, uitkomst="open")
    return dict(
        identity, lines=[start, before], gates=[Gate(n, "bewijs", "open", "measured") for n in REQUIRED_GATES[phase]]
    )


@pytest.mark.parametrize("phase", ["R1", "R2", "R3", "R4"])
def test_closing_a_write_requires_a_preceding_gate_in_this_attempt(phase):
    from nsmcp.upgrade import evaluate_phase

    context = _write_context(phase)
    assert evaluate_phase(phase, {"actieid_uit_script": "a1"}, context).outcome == "geslaagd"
    context["lines"] = context["lines"][:1]
    verdict = evaluate_phase(phase, {"actieid_uit_script": "a1"}, context)
    assert verdict.outcome == "poort dicht"
    assert any(g.name == "voorpoort van deze poging" and g.outcome == "niet beoordeeld" for g in verdict.gates)


@pytest.mark.parametrize("field", ["run", "doel", "actieid", "poging", "gestart"])
def test_pre_gate_cannot_be_reused_for_a_different_identity(field):
    from nsmcp.upgrade import evaluate_phase

    context = _write_context()
    context["lines"][-1][field] = "different"
    assert evaluate_phase("R3", {"actieid_uit_script": "a1"}, context).outcome == "poort dicht"


def test_pre_gate_before_latest_start_is_stale():
    from nsmcp.upgrade import evaluate_phase

    context = _write_context()
    context["lines"].append(dict(context["lines"][0]))
    assert evaluate_phase("R3", {"actieid_uit_script": "a1"}, context).outcome == "poort dicht"


@pytest.mark.parametrize(
    "name", ["hostsleutel gepind", "doel is secondary", "vrije ruimte op /var", "lokale bundel en sidecar"]
)
def test_missing_mandatory_pre_gate_is_not_replaced_by_closing_measurement(name):
    from nsmcp.upgrade import evaluate_phase

    context = _write_context("R1")
    context["lines"][-1]["poort"] = [g for g in context["lines"][-1]["poort"] if g["naam"] != name]
    assert evaluate_phase("R1", {"actieid_uit_script": "a1"}, context).outcome == "poort dicht"


@pytest.mark.parametrize("outcome", ["dicht", "niet beoordeeld"])
def test_closed_pre_gate_cannot_be_overridden_at_closing(outcome):
    from nsmcp.upgrade import evaluate_phase

    context = _write_context()
    context["lines"][-1]["poort"][0]["uitkomst"] = outcome
    assert evaluate_phase("R3", {"actieid_uit_script": "a1"}, context).outcome == "poort dicht"


@pytest.mark.parametrize("run", ["../other", "unsafe name", "x;echo", "", "NUL"])
def test_precheck_result_path_refuses_unsafe_run(run):
    from nsmcp.upgrade import precheck_result_path

    with pytest.raises(ValueError):
        precheck_result_path(run, "a1", "a" * 32)


@pytest.mark.parametrize("status", [1, -1, None])
def test_unreadable_precheck_file_never_accepts_success_text(status):
    gate = upgrade_measure._vorm(
        {
            "verzoeken": [
                {
                    "soort": "precheck-poging",
                    "pad": "/var/tmp/example.json",
                    "exitcode": status,
                    "precheck_json": '{"global_status":"SUCCESS","checks":[]}',
                }
            ]
        }
    )["poort"][0]
    assert gate["uitkomst"] == "niet beoordeeld"


def test_real_ledger_roundtrip_preserves_open_phase_until_closing(tmp_path):
    from nsmcp import upgrade_gate
    from nsmcp.upgrade import append_line, open_phases, phase_state, read_ledger

    ledger = tmp_path / "r1.jsonl"
    append_line(
        ledger, {"run": "r1", "doel": "example", "fase": "R2", "gebeurtenis": "fase_geslaagd", "uitkomst": "geslaagd"}
    )
    identity = dict(
        run="r1",
        doel="example",
        fase="R3",
        actieid="a1",
        poging="a" * 32,
        gestart="2026-09-08T00:00:00Z",
        ledger=str(ledger),
        bevestiger="synthetic operator",
    )
    upgrade_measure.main(json.dumps(dict(identity, actie="start")))
    requests = [
        {"soort": "hostsleutel", "sessie_geopend": True, "gepinde_vingerafdruk": "aa:bb"},
        {
            "soort": "secondary",
            "exitcode": 0,
            "doel_adres": "192.0.2.2",
            "ha_node_uitvoer": "Node ID: 0\n IP: 192.0.2.2\n Master State: Secondary",
        },
    ]
    pre, code = upgrade_measure.main(json.dumps(dict(identity, actie="voorpoort", verzoeken=requests)))
    assert code == 0 and pre["uitkomst"] == "open"
    rows = read_ledger(ledger)
    assert phase_state(rows, "R3") == "gestart"
    assert len(open_phases(rows)) == 1
    closing, code = upgrade_gate.main(
        json.dumps(
            dict(
                identity,
                geeindigd="2026-09-08T00:01:00Z",
                metingen={
                    "actieid_uit_script": "a1",
                    "poort": [
                        {
                            "naam": "installatie voltooid (END_TIME)",
                            "type": "bewijs",
                            "uitkomst": "open",
                            "bewijs": "END_TIME",
                        }
                    ],
                },
            )
        )
    )
    assert code == 0 and closing["uitkomst"] == "geslaagd"
    assert phase_state(read_ledger(ledger), "R3") == "geslaagd"
    assert not open_phases(read_ledger(ledger))
    with pytest.raises(ValueError, match="al gesloten"):
        upgrade_measure.main(json.dumps(dict(identity, actie="voorpoort", verzoeken=requests)))


def test_real_closing_cli_does_not_accept_complete_measurements_without_pre_gate(tmp_path):
    from nsmcp import upgrade_gate
    from nsmcp.upgrade import REQUIRED_GATES, append_line

    ledger = tmp_path / "r1.jsonl"
    append_line(
        ledger, {"run": "r1", "doel": "example", "fase": "R2", "gebeurtenis": "fase_geslaagd", "uitkomst": "geslaagd"}
    )
    identity = dict(
        run="r1",
        doel="example",
        fase="R3",
        actieid="a1",
        poging="a" * 32,
        gestart="2026-09-08T00:00:00Z",
        ledger=str(ledger),
    )
    upgrade_measure.main(json.dumps(dict(identity, actie="start")))
    gates = [{"naam": n, "type": "bewijs", "uitkomst": "open", "bewijs": "measured"} for n in REQUIRED_GATES["R3"]]
    row, code = upgrade_gate.main(
        json.dumps(
            dict(identity, geeindigd="2026-09-08T00:01:00Z", metingen={"actieid_uit_script": "a1", "poort": gates})
        )
    )
    assert code == 1
    assert next(g for g in row["poort"] if g["naam"] == "voorpoort van deze poging")["uitkomst"] == "niet beoordeeld"


def test_pre_gate_does_not_use_previous_phase_from_another_run(tmp_path):
    from nsmcp.upgrade import append_line

    ledger = tmp_path / "mixed.jsonl"
    append_line(
        ledger,
        {"run": "foreign", "doel": "example", "fase": "R2", "gebeurtenis": "fase_geslaagd", "uitkomst": "geslaagd"},
    )
    identity = dict(
        run="r1",
        doel="example",
        fase="R3",
        actieid="a1",
        poging="a" * 32,
        gestart="2026-09-08T00:00:00Z",
        ledger=str(ledger),
    )
    upgrade_measure.main(json.dumps(dict(identity, actie="start")))
    row, _ = upgrade_measure.main(
        json.dumps(
            dict(
                identity,
                actie="voorpoort",
                verzoeken=[
                    {"soort": "hostsleutel", "sessie_geopend": True, "gepinde_vingerafdruk": "aa:bb"},
                    {
                        "soort": "secondary",
                        "exitcode": 0,
                        "doel_adres": "192.0.2.2",
                        "ha_node_uitvoer": "Node ID: 0\n IP: 192.0.2.2\n Master State: Secondary",
                    },
                ],
            )
        )
    )
    assert row["uitkomst"] == "dicht"
