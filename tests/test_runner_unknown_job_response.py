"""Unknown Windows job binding must preserve the started phase acknowledgement."""

from upgrade_fase_harness import _call, _propose, _server, _text

from nsmcp import mcp_server
from nsmcp.handelen import RUNNER_NIET_BEOORDEELD
from nsmcp.upgrade import read_ledger


def test_unknown_job_measurement_keeps_phase_started_response(tmp_path, monkeypatch):
    server = _server(tmp_path)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    launch = mcp_server.start_detached

    def unknown_job(*args, **kwargs):
        launch(*args, **kwargs)
        return RUNNER_NIET_BEOORDEELD

    monkeypatch.setattr(mcp_server, "start_detached", unknown_job)
    result = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    rows = [row for path in (tmp_path / "ledger").glob("*.jsonl") for row in read_ledger(path)]
    assert any(row["gebeurtenis"] == "fase_gestart" for row in rows)
    assert not result.isError, _text(result)
    assert "FASE GESTART" in _text(result)
    assert "niet beoordeeld" in _text(result)
    assert "Windows gaf geen uitsluitsel" in _text(result)
