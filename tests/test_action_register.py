"""The action register: the WRITER side of the contract R0 reads.

Until 8-9-2026 the register had readers (`backup_register_gate`,
`rollback_point_evidence`, the runner's `-Actieregister`) and no writer at
all, so R0 could never close `geslaagd` on a real appliance. These tests pin
the writer in `mcp_server._act()` and the round trip to the readers: a
confirmed `onderhoud_backup_maken` writes exactly one row, that row opens
R0's gate and names the backup for the rollback point, a proposal writes
nothing, a failed read-back is recorded as `mislukt`, and a register that
cannot be written warns in the answer instead of staying silent.

The write script is a stand-in (the same `-BackupNaam` echo the backup
tests in tests/test_handelen_zonder_code.py use): no PowerShell, no
appliance, per the lab rule.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp.code_channel import WINDOW_LABEL
from nsmcp.handelen import Allowlist, MaintenanceConfig
from nsmcp.mcp_server import build_server, forget_identities
from nsmcp.upgrade import (
    REGISTER_OBJECT_FIELD,
    REGISTER_OUTCOMES,
    backup_register_gate,
    read_ledger,
    register_line,
    rollback_point_evidence,
)

TARGET = "lab"


class _CodeSpy:
    label = WINDOW_LABEL

    def __init__(self) -> None:
        self.codes: list[str] = []

    def __call__(self, tool, target, arguments, code, proposal_text, marker, section) -> None:
        self.codes.append(code)


def _backup_runner(found: bool = True):
    def run(arguments, timeout_s):
        naam = arguments[arguments.index("-BackupNaam") + 1]
        if "-WatIs" in arguments:
            return (
                0,
                (
                    f"[OK] zou doen: backup maken met naam {naam}\n[TARGET] doel\n"
                    "[EINDSTATUS] WAT-IS: er is niets gewijzigd\n"
                ),
                "",
            )
        if found:
            text = (
                "[ACTIEID] id-1\n[TARGET] doel\n"
                f"[OK] teruggelezen op de collectie config/systembackup: {naam}.tgz, 41 MB, "
                "2026-09-06T14:03:12Z, level full\n"
                "[EINDSTATUS] backup gemaakt en teruggelezen\n"
            )
        else:
            text = "[ACTIEID] id-1\n[TARGET] doel\n[EINDSTATUS] backup gemaakt, teruglezing ontbreekt\n"
        return 0, text, ""

    return run


def _server(tmp_path: Path, *, register: Path | None, found: bool = True):
    forget_identities()
    export = tmp_path / "export"
    (export / "objects").mkdir(parents=True)
    (export / "bindings").mkdir()
    (export / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-01T10:00:00.0000000Z",
                "resources": {},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    kennis = tmp_path / "kennis.json"
    kennis.write_text('{"versie":"x","datum":"2026-09-01"}', encoding="utf-8")
    doelen = tmp_path / "doelen.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": TARGET,
                        "adres": "10.0.0.10",
                        "credentialTarget": "GJK/Test/register/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# stand-in", encoding="utf-8")
    runner = tmp_path / "runner.ps1"
    runner.write_text("# ongebruikt", encoding="utf-8")
    (tmp_path / "ledger").mkdir()
    (tmp_path / "firmware").mkdir()
    onderhoud = MaintenanceConfig(
        runner=runner,
        ledgermap=tmp_path / "ledger",
        firmwaremap=tmp_path / "firmware",
        soak_uren=24,
        ssh_gebruiker="nsroot",
        actieregister=register,
    )
    spy = _CodeSpy()
    server = build_server(
        export,
        kennis,
        targets_path=doelen,
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=_backup_runner(found),
        code_presenter=spy,
        allowlist=Allowlist(per_target={TARGET: {"onderhoud_backup_maken": True}}),
        onderhoud=onderhoud,
    )
    server.code_spy = spy
    return server


def _call(server, name, args):
    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="test", version="1.0")
        ) as client:
            return await client.call_tool(name, args)

    return asyncio.run(go())


def _text(result) -> str:
    return " ".join(b.text for b in result.content if hasattr(b, "text"))


def _rows(register: Path) -> list[dict]:
    skipped: list = []
    rows = list(read_ledger(register, skipped=skipped))
    assert skipped == [], skipped
    return rows


@pytest.mark.parametrize("script_failed", [False, True])
def test_register_failure_stays_visible_when_the_action_also_failed(
    tmp_path,
    monkeypatch,
    script_failed,
):
    original_runner = _backup_runner

    def factory(found=True):
        runner = original_runner(found=False)

        def run(arguments, timeout_s):
            if script_failed and "-WatIs" not in arguments:
                return 1, "[EINDSTATUS] handeling geweigerd\n", ""
            return runner(arguments, timeout_s)

        return run

    monkeypatch.setitem(globals(), "_backup_runner", factory)
    register = tmp_path / "register-directory"
    register.mkdir()
    server = _server(tmp_path, register=register)
    assert not _call(server, "onderhoud_backup_maken", {}).isError
    result = _call(
        server,
        "onderhoud_backup_maken",
        {
            "bevestiging": server.code_spy.codes[-1],
        },
    )
    assert result.isError
    text = _text(result)
    assert "actieregister" in text
    assert "duurzame registratie NIET vastgesteld" in text
    assert "controleer het actieregister" in text
    assert "Onverwachte fout" not in text


def test_register_line_carries_the_fields_the_readers_expect():
    now = datetime(2026, 9, 8, 18, 30, 5, 123456, tzinfo=UTC)
    row = register_line(
        tool="onderhoud_backup_maken",
        doel="lab",
        actieid="id-1",
        uitkomst="geslaagd",
        bevestiger="labproef",
        objectnaam="gjk_preupgrade_lab_20260908_183005",
        now=now,
    )
    assert row == {
        "tijd": "2026-09-08T18:30:05Z",
        "tool": "onderhoud_backup_maken",
        "doel": "lab",
        "actieid": "id-1",
        "uitkomst": "geslaagd",
        "bevestiger": "labproef",
        REGISTER_OBJECT_FIELD: "gjk_preupgrade_lab_20260908_183005",
    }
    assert REGISTER_OUTCOMES == ("geslaagd", "mislukt")
    zonder = register_line(
        tool="dienst_lid_uitschakelen",
        doel="lab",
        actieid=None,
        uitkomst="mislukt",
        bevestiger=None,
        objectnaam=None,
        now=now,
    )
    assert REGISTER_OBJECT_FIELD not in zonder
    assert zonder["actieid"] is None and zonder["bevestiger"] is None
    with pytest.raises(ValueError):
        register_line(tool="x", doel="lab", actieid=None, uitkomst="gestart", bevestiger=None, objectnaam=None)


def test_a_confirmed_backup_writes_one_row_that_opens_r0_and_names_the_rollback_point(tmp_path):
    register = tmp_path / "register" / "acties.jsonl"
    server = _server(tmp_path, register=register)

    voorstel = _call(server, "onderhoud_backup_maken", {})
    assert voorstel.isError is False, _text(voorstel)
    assert not register.exists(), "een voorstel schrijft niets in het actieregister"

    done = _call(server, "onderhoud_backup_maken", {"bevestiging": server.code_spy.codes[-1]})
    assert done.isError is False, _text(done)
    assert "UITGEVOERD (onderhoud_backup_maken)" in _text(done)
    assert "actieregister" not in _text(done), "een geslaagde registerregel is stil"

    rows = _rows(register)
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "onderhoud_backup_maken"
    assert row["doel"] == TARGET
    assert row["uitkomst"] == "geslaagd"
    assert row["actieid"] == "id-1"
    assert row[REGISTER_OBJECT_FIELD].startswith("gjk_preupgrade_lab_")
    assert row["tijd"].endswith("Z")

    # The round trip: what the writer wrote is what R0's readers need.
    gate = backup_register_gate(rows, TARGET)
    assert gate.outcome == "open", gate
    assert "actieid=id-1" in gate.evidence
    bewijs = rollback_point_evidence(rows, None, "snapshot-1", TARGET)
    assert row[REGISTER_OBJECT_FIELD] in bewijs
    assert "snapshotverwijzing snapshot-1" in bewijs
    # A different target never inherits this backup.
    assert backup_register_gate(rows, "ander-doel").outcome == "dicht"


def test_a_failed_readback_is_recorded_as_mislukt_and_r0_stays_closed(tmp_path):
    register = tmp_path / "acties.jsonl"
    server = _server(tmp_path, register=register, found=False)
    voorstel = _call(server, "onderhoud_backup_maken", {})
    assert voorstel.isError is False, _text(voorstel)

    done = _call(server, "onderhoud_backup_maken", {"bevestiging": server.code_spy.codes[-1]})
    assert done.isError is True
    assert "handeling MISLUKT" in _text(done)

    rows = _rows(register)
    assert len(rows) == 1 and rows[0]["uitkomst"] == "mislukt"
    assert rows[0][REGISTER_OBJECT_FIELD].startswith("gjk_preupgrade_lab_")
    assert backup_register_gate(rows, TARGET).outcome == "dicht"


def test_without_a_configured_register_nothing_is_written(tmp_path):
    server = _server(tmp_path, register=None)
    _voorstel = _call(server, "onderhoud_backup_maken", {})
    done = _call(server, "onderhoud_backup_maken", {"bevestiging": server.code_spy.codes[-1]})
    assert done.isError is False, _text(done)
    assert "actieregister" not in _text(done)
    assert [p for p in tmp_path.rglob("*.jsonl")] == []


def test_an_unwritable_register_warns_in_the_answer_but_the_action_still_counts(tmp_path):
    register = tmp_path / "register-als-map"
    register.mkdir()  # a directory where the file should be: every append fails
    server = _server(tmp_path, register=register)
    _voorstel = _call(server, "onderhoud_backup_maken", {})
    done = _call(server, "onderhoud_backup_maken", {"bevestiging": server.code_spy.codes[-1]})
    assert done.isError is False, _text(done)
    tekst = _text(done)
    assert "UITGEVOERD (onderhoud_backup_maken)" in tekst
    assert "actieregister: duurzame registratie NIET vastgesteld" in tekst
    assert "controleer het actieregister voor vervolgacties" in tekst
