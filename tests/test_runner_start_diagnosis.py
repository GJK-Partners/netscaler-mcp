"""1.1 E.3: an honest diagnosis when a child process does not start.

MEASURED before (1.0.3), two places:

1. `handelen.start_detached` wrapped an unusable fixed working directory
   (`ChildWorkingDirectoryUnusable`), a log file that did not open and a
   failed `Popen` all three as a plain `ActionError` with `str(exc)` in it,
   and `mcp_server` answered every one of them with "het proces of zijn
   logbestand kon niet worden geopend" - wrong for the working directory.
2. `handelen.upgrade_command` calls `check_script_pins`; its
   `ScriptPinMismatch` is a subclass of `PowerShellMissing`, and
   `mcp_server` then said "Windows PowerShell niet gevonden" - wrong too.

Now `start_detached` raises one of three typed subclasses of `ActionError`
(`RunnerWorkdirUnusable`, `RunnerLogUnopenable`, `RunnerProcessNotStarted`),
each with a fixed kind and the CLASS of the underlying error for the action
log, and ONLY on a path where it is proven that no child process exists.
Once `Popen` returned a child, any later failure is "a child may exist": not
one of the three, the target stays held. `mcp_server` maps on TYPE to five
fixed sentences; an unknown `ActionError` gets the general sentence without
its text and does NOT release the target (fail-closed). The save route
(`perform_save`) and the live measurement (`_free_var_mb_over_ssh`) get the
same typed mapping. An answer never carries an exception text or a path.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import mcp.types as types
import pytest
from conftest import _export_dir, _knowledge_file, maintenance_config
from mcp.shared.memory import create_connected_server_and_client_session
from test_product_surface import _BackupCodeSpy
from test_upgrade_start_window import (
    ONBESLIST,
    RUN,
    WAIT_S,
    _confirm_r1,
    _held_runner,
    _propose_r1,
    _window_server,
)
from upgrade_fase_harness import TARGET_NAME, _call, _text

from nsmcp import handelen, mcp_server
from nsmcp.handelen import (
    ActionError,
    Allowlist,
    PowerShellNotFound,
    ProcessNotStarted,
    RunnerLogUnopenable,
    RunnerProcessNotStarted,
    RunnerWorkdirUnusable,
    ScriptPinRefused,
)
from nsmcp.powershell import ChildWorkingDirectoryUnusable, PowerShellMissing, ScriptPinMismatch

SENTINEL = "SENTINEL-E3-9f1c"
SENTINEL_PATH = "C:\\" + SENTINEL + "\\geheim\\runner.log"

WERKMAP = "de vaste werkmap voor kindprocessen is niet bruikbaar"
LOGBESTAND = "het logbestand naast het ledger kon niet worden geopend"
PROCES = "het proces kon niet worden gestart"
SCRIPTPIN = "een script van de faserunner wijkt af van zijn pin"
POWERSHELL = "Windows PowerShell niet gevonden"
ONBESLISTE_START = (
    "De start van de handeling is onbeslist: of de faserunner gestart is, is niet vast te stellen. "
    "Het doel blijft bezet tot de regel fase_gestart in het ledger staat of de tijdslimiet van de fase "
    "verstreken is. De bevestigingscode is verbruikt."
)


@pytest.fixture
def short_wait(monkeypatch):
    monkeypatch.setattr(mcp_server, "START_WAIT_S", WAIT_S)


def _action_rows(err: str) -> list[dict]:
    prefix = mcp_server.ACTION_LOG_PREFIX
    return [json.loads(line[len(prefix) :].strip()) for line in err.splitlines() if line.startswith(prefix)]


def _assert_free(server) -> None:
    """The target is free: another writing tool on it is not refused as an
    undecided start."""
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert not r.isError, _text(r)
    assert "onbeslist" not in _text(r), _text(r)


def _assert_held(server) -> None:
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r.isError, _text(r)
    assert ONBESLIST in _text(r), _text(r)


def _assert_no_leak(text: str, tmp_path: Path) -> None:
    assert SENTINEL not in text, text
    assert str(tmp_path) not in text, text
    assert "runner.log" not in text and ".jsonl" not in text, text


def _only_during_the_detached_start(monkeypatch) -> list[bool]:
    """A flag that is True only while `mcp_server` runs `start_detached` -
    so a fault injected into `handelen` hits the confirmed start and not the
    `-WatIs` preview that runs before it (the preview uses the same
    working directory and the same `Popen`)."""
    during: list[bool] = [False]
    real = mcp_server.start_detached

    def wrapped(*args, **kwargs):
        during[0] = True
        try:
            return real(*args, **kwargs)
        finally:
            during[0] = False

    monkeypatch.setattr(mcp_server, "start_detached", wrapped)
    return during


# ---------------------------------------------------------------------------
# The product sentences
# ---------------------------------------------------------------------------


def test_the_runner_start_sentences_are_pinned_byte_for_byte():
    assert mcp_server.RUNNER_NIET_GESTART_WERKMAP == WERKMAP
    assert mcp_server.RUNNER_NIET_GESTART_LOGBESTAND == LOGBESTAND
    assert mcp_server.RUNNER_NIET_GESTART_PROCES == PROCES
    assert mcp_server.RUNNER_NIET_GESTART_SCRIPTPIN == SCRIPTPIN
    assert mcp_server.RUNNER_NIET_GESTART_POWERSHELL == POWERSHELL
    assert mcp_server.RUNNER_START_ONBESLIST_TEXT == ONBESLISTE_START
    assert not hasattr(mcp_server, "RUNNER_NIET_GESTART_ALGEMEEN")
    assert mcp_server.RUNNER_NIET_GESTART_REDEN == "de faserunner kon niet gestart worden ({soort})"
    assert mcp_server.SCRIPT_NIET_GESTART_REDEN == "het script van deze handeling kon niet gestart worden ({soort})"
    assert mcp_server.SCRIPT_NIET_GESTART_VOORSTEL_TEXT == (
        "Het voorstel kon niet worden opgesteld: {reden}. Er is geen bevestigingscode uitgegeven en er is "
        "niets gewijzigd."
    )
    assert mcp_server.SCRIPT_NIET_GESTART_EVIDENCE == "het starten van het script van deze handeling"


@pytest.mark.parametrize(
    "exc,sentence",
    [
        (ScriptPinMismatch("x"), SCRIPTPIN),
        (ChildWorkingDirectoryUnusable("x"), WERKMAP),
        (PowerShellMissing("x"), POWERSHELL),
        (RunnerWorkdirUnusable(ChildWorkingDirectoryUnusable), WERKMAP),
        (RunnerLogUnopenable(PermissionError), LOGBESTAND),
        (RunnerProcessNotStarted(FileNotFoundError), PROCES),
        (ScriptPinRefused(ScriptPinMismatch), SCRIPTPIN),
        (PowerShellNotFound(PowerShellMissing), POWERSHELL),
        (ActionError(SENTINEL), None),
        (RuntimeError(SENTINEL), None),
    ],
)
def test_the_mapping_is_on_type_and_never_on_text(exc, sentence):
    assert mcp_server._not_started_sentence(exc) == sentence


# ---------------------------------------------------------------------------
# handelen: the typed errors and where they may come from
# ---------------------------------------------------------------------------


def test_a_typed_start_failure_carries_its_kind_and_the_class_of_its_cause_only():
    for cls, kind in (
        (RunnerWorkdirUnusable, "werkmap"),
        (RunnerLogUnopenable, "logbestand"),
        (RunnerProcessNotStarted, "proces"),
        (ScriptPinRefused, "scriptpin"),
        (PowerShellNotFound, "powershell"),
    ):
        error = cls(RuntimeError(SENTINEL + " " + SENTINEL_PATH))
        assert isinstance(error, ActionError) and isinstance(error, ProcessNotStarted)
        assert error.soort == kind
        assert error.oorzaak == "RuntimeError"
        assert str(error) == kind
        assert SENTINEL not in repr(error.args)
        assert cls(PermissionError).oorzaak == "PermissionError"


class _Child:
    pid = 4242


def test_start_detached_names_an_unusable_working_directory_and_starts_nothing(monkeypatch, tmp_path):
    started = []

    def unusable():
        raise ChildWorkingDirectoryUnusable(SENTINEL)

    monkeypatch.setattr(handelen, "child_working_directory", unusable)
    monkeypatch.setattr(handelen.subprocess, "Popen", lambda *a, **k: started.append(a) or _Child())
    with pytest.raises(RunnerWorkdirUnusable) as caught:
        handelen.start_detached(["x"], log_path=tmp_path / "r.log")
    assert caught.value.oorzaak == "ChildWorkingDirectoryUnusable"
    assert SENTINEL not in str(caught.value)
    assert started == []


def test_start_detached_names_a_log_file_that_does_not_open_and_starts_nothing(monkeypatch, tmp_path):
    started = []
    monkeypatch.setattr(handelen.subprocess, "Popen", lambda *a, **k: started.append(a) or _Child())
    log_path = tmp_path / "is-een-map.log"
    log_path.mkdir()
    with pytest.raises(RunnerLogUnopenable) as caught:
        handelen.start_detached(["x"], log_path=log_path)
    assert caught.value.oorzaak in {"PermissionError", "IsADirectoryError"}, caught.value.oorzaak
    assert str(tmp_path) not in str(caught.value)
    assert started == []


def test_start_detached_names_a_popen_that_failed_on_every_attempt(monkeypatch, tmp_path):
    def broken(*_args, **_kwargs):
        raise FileNotFoundError(2, SENTINEL, SENTINEL_PATH)

    monkeypatch.setattr(handelen.subprocess, "Popen", broken)
    with pytest.raises(RunnerProcessNotStarted) as caught:
        handelen.start_detached(["x"], log_path=tmp_path / "r.log")
    assert caught.value.oorzaak == "FileNotFoundError"
    assert SENTINEL not in str(caught.value)


def test_a_failure_after_popen_is_never_a_not_started_error(monkeypatch, tmp_path):
    """Once `Popen` returned a child, a later failure says nothing about
    whether that child runs: it is not one of the typed errors and not an
    `ActionError` at all."""
    if handelen.sys.platform != "win32":
        pytest.skip("the Job Object measurement is a Windows notion")
    monkeypatch.setattr(handelen.subprocess, "Popen", lambda *a, **k: _Child())
    real = handelen._process_in_job

    def measurement_fails(pid=None):
        if pid is None:
            return real()
        raise OSError(5, SENTINEL)

    monkeypatch.setattr(handelen, "_process_in_job", measurement_fails)
    with pytest.raises(BaseException) as caught:
        handelen.start_detached(["x"], log_path=tmp_path / "r.log")
    assert not isinstance(caught.value, ActionError), type(caught.value)


@pytest.mark.parametrize(
    "raised,typed,cause",
    [
        (ChildWorkingDirectoryUnusable(SENTINEL), RunnerWorkdirUnusable, "ChildWorkingDirectoryUnusable"),
        (ScriptPinMismatch(SENTINEL), ScriptPinRefused, "ScriptPinMismatch"),
        (PowerShellMissing(SENTINEL_PATH), PowerShellNotFound, "PowerShellMissing"),
        (FileNotFoundError(2, SENTINEL, SENTINEL_PATH), RunnerProcessNotStarted, "FileNotFoundError"),
    ],
)
def test_the_typed_script_runner_names_why_nothing_started(monkeypatch, raised, typed, cause):
    def start(_arguments):
        raise raised

    monkeypatch.setattr(handelen, "start_powershell", start)
    with pytest.raises(typed) as caught:
        handelen.typed_runner(["-File", "x.ps1"], 5)
    assert type(caught.value) is typed
    assert caught.value.oorzaak == cause
    assert SENTINEL not in str(caught.value)


def test_perform_save_and_the_live_measurement_use_the_typed_runner():
    import inspect

    assert "typed_runner" in inspect.getsource(handelen.perform_save)
    assert "typed_runner" in inspect.getsource(mcp_server.build_server)


# ---------------------------------------------------------------------------
# The phase runner, end to end
# ---------------------------------------------------------------------------


def test_unusable_workdir_is_named_as_such(tmp_path, short_wait, monkeypatch, capsys):
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    during = _only_during_the_detached_start(monkeypatch)
    real = handelen.child_working_directory

    def unusable():
        if during[0]:
            raise ChildWorkingDirectoryUnusable(SENTINEL + " " + SENTINEL_PATH)
        return real()

    monkeypatch.setattr(handelen, "child_working_directory", unusable)
    capsys.readouterr()
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    assert WERKMAP in text, text
    assert "logbestand" not in text, text
    assert "PowerShell" not in text, text
    _assert_no_leak(text, tmp_path)
    rows = _action_rows(capsys.readouterr().err)
    assert rows[-1]["uitkomst"] == "mislukt" and rows[-1]["oorzaak"] == "ChildWorkingDirectoryUnusable", rows[-1]
    _assert_free(server)


def test_a_log_file_that_does_not_open_is_named_without_a_path(tmp_path, short_wait, monkeypatch):
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    during = _only_during_the_detached_start(monkeypatch)

    def no_log(path, *args, **kwargs):
        if during[0]:
            raise PermissionError(13, SENTINEL, str(path))
        return open(path, *args, **kwargs)

    monkeypatch.setattr(handelen, "open", no_log, raising=False)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    assert LOGBESTAND in text, text
    assert "werkmap" not in text and "PowerShell" not in text, text
    _assert_no_leak(text, tmp_path)
    _assert_free(server)


def test_script_pin_mismatch_is_not_reported_as_missing_powershell(tmp_path, short_wait, monkeypatch):
    """The pin check of the REAL start (the one in `upgrade_command` that
    `mcp_server` calls after the code is redeemed) fails; the preview before
    it passed."""
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    during: list[bool] = [False]
    real_command = mcp_server.upgrade_command

    def command(*args, **kwargs):
        during[0] = True
        try:
            return real_command(*args, **kwargs)
        finally:
            during[0] = False

    def pins(_script):
        if during[0]:
            raise ScriptPinMismatch(SENTINEL + " " + SENTINEL_PATH)

    monkeypatch.setattr(mcp_server, "upgrade_command", command)
    monkeypatch.setattr(handelen, "check_script_pins", pins)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    assert SCRIPTPIN in text, text
    assert "PowerShell niet gevonden" not in text, text
    _assert_no_leak(text, tmp_path)
    _assert_free(server)


# ---------------------------------------------------------------------------
# The -WatIs preview of the faserunner: the same typed mapping
#
# MEASURED before: the preview runs first, on the proposal AND on the
# confirmed call, with the same pin check. A changed or unpinned script fell
# there already, as a bare `ActionError` - the answer said "(ActionError)" and
# the SCRIPTPIN sentence the manual promises never came.
# ---------------------------------------------------------------------------

_TYPED_CLASS_NAMES = (
    "ActionError",
    "ScriptPinRefused",
    "PowerShellNotFound",
    "RunnerWorkdirUnusable",
    "RunnerProcessNotStarted",
    "ScriptPinMismatch",
    "PowerShellMissing",
    "ChildWorkingDirectoryUnusable",
    "FileNotFoundError",
)

_PREVIEW_FAULTS = [
    ("scriptpin", SCRIPTPIN, ScriptPinRefused, "ScriptPinMismatch"),
    ("powershell", POWERSHELL, PowerShellNotFound, "PowerShellMissing"),
    ("werkmap", WERKMAP, RunnerWorkdirUnusable, "ChildWorkingDirectoryUnusable"),
    ("proces", PROCES, RunnerProcessNotStarted, "FileNotFoundError"),
]


def _fail_the_preview_start(monkeypatch, where: str) -> None:
    """A start failure of the `-WatIs` preview, injected where it really
    arises: the pin check and the interpreter dispatch of `upgrade_command`,
    the working directory and `Popen` of the preview's own process runner.
    Every one carries the sentinel and a path in its text."""
    if where == "scriptpin":

        def pins(_script):
            raise ScriptPinMismatch(SENTINEL + " " + SENTINEL_PATH)

        monkeypatch.setattr(handelen, "check_script_pins", pins)
    elif where == "powershell":

        def command(*_args, **_kwargs):
            raise PowerShellMissing("Windows PowerShell niet gevonden op " + SENTINEL_PATH)

        monkeypatch.setattr(handelen, "upgrade_command", command)
    elif where == "werkmap":

        def unusable():
            raise ChildWorkingDirectoryUnusable(SENTINEL + " " + SENTINEL_PATH)

        monkeypatch.setattr(handelen, "child_working_directory", unusable)
    else:

        def popen(*_args, **_kwargs):
            raise FileNotFoundError(2, SENTINEL, SENTINEL_PATH)

        monkeypatch.setattr(handelen.subprocess, "Popen", popen)


def _assert_no_class_name(text: str) -> None:
    for name in _TYPED_CLASS_NAMES:
        assert name not in text, text


@pytest.mark.parametrize("where,sentence,typed,cause", _PREVIEW_FAULTS)
def test_the_preview_start_raises_a_typed_error_without_text(tmp_path, monkeypatch, where, sentence, typed, cause):
    runner = tmp_path / "runner.py"
    runner.write_text("", encoding="ascii")
    monkeypatch.setattr(handelen, "check_script_pins", lambda _script: None)
    _fail_the_preview_start(monkeypatch, where)
    with pytest.raises(typed) as caught:
        handelen.run_upgrade_preview(["-WatIs"], runner=runner)
    assert type(caught.value) is typed
    assert caught.value.oorzaak == cause
    assert SENTINEL not in str(caught.value)
    assert mcp_server._not_started_sentence(caught.value) == sentence


@pytest.mark.parametrize("where,sentence,typed,cause", _PREVIEW_FAULTS)
def test_a_preview_that_cannot_start_on_the_proposal_names_why(tmp_path, monkeypatch, where, sentence, typed, cause):
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    _fail_the_preview_start(monkeypatch, where)
    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
    text = _text(r)
    assert r.isError, text
    assert f"voorstel kon niet worden opgesteld: {sentence}" in text, text
    _assert_no_class_name(text)
    _assert_no_leak(text, tmp_path)


@pytest.mark.parametrize("where,sentence,typed,cause", _PREVIEW_FAULTS)
def test_a_preview_that_cannot_start_on_the_confirmed_call_names_why(
    tmp_path, short_wait, monkeypatch, where, sentence, typed, cause
):
    """The pin changes (or PowerShell goes) between the proposal and the
    confirmed call: the preview of the confirmed call says why, the code is
    not redeemed and the target is free."""
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    _fail_the_preview_start(monkeypatch, where)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    assert f"de controle vooraf mislukte ({sentence})" in text, text
    assert "De bevestigingscode is niet ingewisseld" in text, text
    _assert_no_class_name(text)
    _assert_no_leak(text, tmp_path)
    _assert_free(server)


def test_a_popen_that_fails_names_the_process(tmp_path, short_wait, monkeypatch):
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    during = _only_during_the_detached_start(monkeypatch)
    real_popen = handelen.subprocess.Popen

    def popen(*args, **kwargs):
        if during[0]:
            raise FileNotFoundError(2, SENTINEL, SENTINEL_PATH)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(handelen.subprocess, "Popen", popen)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    assert f"de faserunner kon niet gestart worden ({PROCES})" in text, text
    _assert_no_leak(text, tmp_path)
    _assert_free(server)


def test_failure_after_popen_keeps_the_target_reserved(tmp_path, short_wait, monkeypatch):
    """`Popen` really started the (held) runner; the Job Object measurement
    of the child then fails. A child exists: the target stays held, and the
    answer does not say the runner did not start."""
    if handelen.sys.platform != "win32":
        pytest.skip("the Job Object measurement is a Windows notion")
    runner = _held_runner(tmp_path, hold_s=1.5)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)
    real = handelen._process_in_job

    def measurement_fails(pid=None):
        if pid is None:
            return real()
        raise OSError(5, SENTINEL)

    monkeypatch.setattr(handelen, "_process_in_job", measurement_fails)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    for sentence in (WERKMAP, LOGBESTAND, PROCES, SCRIPTPIN):
        assert sentence not in text, text
    assert "De handeling is niet gestart" not in text, text
    _assert_no_leak(text, tmp_path)
    _assert_held(server)
    time.sleep(2.0)


def test_an_unknown_action_error_says_the_start_is_undecided_and_keeps_the_target_held(
    tmp_path, short_wait, monkeypatch
):
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code = _propose_r1(server)

    def unknown(*_args, **_kwargs):
        raise ActionError(SENTINEL + " " + SENTINEL_PATH)

    monkeypatch.setattr(mcp_server, "start_detached", unknown)
    r = _confirm_r1(server, code)
    text = _text(r)
    assert r.isError, text
    # Whether a child exists is not established: the answer says so, never
    # "niet gestart", and the finding is not marked as established.
    assert ONBESLISTE_START in text, text
    assert "De handeling is niet gestart" not in text, text
    assert "kon niet gestart worden" not in text, text
    assert f"{ONBESLISTE_START} [vastgesteld]" not in text, text
    assert "[niet vastgesteld]" in text, text
    _assert_no_class_name(text)
    _assert_no_leak(text, tmp_path)
    _assert_held(server)


# ---------------------------------------------------------------------------
# config_opslaan (perform_save)
# ---------------------------------------------------------------------------


def _save_server(tmp_path: Path, *, fail_preview, fail_real):
    """`config_opslaan` against an injected save-script runner that can fail
    to start on the preview, on the real run, or neither."""
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# niet gebruikt door config_opslaan", encoding="utf-8")
    (tmp_path / "Invoke-GjkConfigOpslaan.ps1").write_text("# stand-in", encoding="ascii")
    doelen = tmp_path / "doelen-opslaan.json"
    doelen.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "192.0.2.10",
                        "credentialTarget": "GJK/Test/lab",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    calls = {"preview": 0}

    def run(arguments, timeout_s):
        if "-WatIs" in arguments:
            calls["preview"] += 1
            if fail_preview is not None and calls["preview"] >= fail_preview[0]:
                raise fail_preview[1]
            return (
                0,
                "[TARGET] nsconfig/lab (192.0.2.10) - config opslaan\n[OK] zou doen: save ns config\n"
                "[EINDSTATUS] WAT-IS: er is niets gewijzigd\n",
                "",
            )
        raise fail_real

    presenter = _BackupCodeSpy()
    server = mcp_server.build_server(
        _export_dir(tmp_path),
        _knowledge_file(tmp_path),
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=run,
        code_presenter=presenter,
        onderhoud=maintenance_config(tmp_path),
        allowlist=Allowlist(per_target={"lab": {"config_opslaan": True}}),
        targets_path=doelen,
    )
    server.code_spy = presenter
    return server


def _save_call(server, args):
    import asyncio

    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-desktop", version="1.0")
        ) as client:
            return await client.call_tool("config_opslaan", args)

    return asyncio.run(go())


def test_a_save_script_that_cannot_start_on_the_proposal_names_why(tmp_path):
    server = _save_server(
        tmp_path, fail_preview=(1, RunnerWorkdirUnusable(ChildWorkingDirectoryUnusable)), fail_real=None
    )
    r = _save_call(server, {})
    text = _text(r)
    assert r.isError, text
    assert (
        "Het voorstel kon niet worden opgesteld: het script van deze handeling kon niet gestart worden "
        f"({WERKMAP}). Er is geen bevestigingscode uitgegeven en er is niets gewijzigd."
    ) in text, text
    assert "controle van deze aanroep tegen de configuratie" not in text, text


def test_a_save_script_that_cannot_start_after_the_redeem_says_nothing_started(tmp_path, capsys):
    server = _save_server(tmp_path, fail_preview=None, fail_real=ScriptPinRefused(ScriptPinMismatch))
    assert not _save_call(server, {}).isError
    capsys.readouterr()
    r = _save_call(server, {"bevestiging": server.code_spy.codes[-1]})
    text = _text(r)
    assert r.isError, text
    assert (
        "De handeling is niet gestart: het script van deze handeling kon niet gestart worden "
        f"({SCRIPTPIN}). De bevestigingscode is verbruikt."
    ) in text, text
    assert "uitkomst is NIET vastgesteld" not in text, text
    rows = _action_rows(capsys.readouterr().err)
    assert rows[-1]["uitkomst"] == "mislukt" and rows[-1]["oorzaak"] == "ScriptPinMismatch", rows[-1]


def test_a_save_preview_that_cannot_start_on_the_execution_call_names_why(tmp_path):
    server = _save_server(tmp_path, fail_preview=(2, PowerShellNotFound(PowerShellMissing)), fail_real=None)
    assert not _save_call(server, {}).isError
    r = _save_call(server, {"bevestiging": server.code_spy.codes[-1]})
    text = _text(r)
    assert r.isError, text
    assert f"de controle vooraf mislukte ({POWERSHELL})" in text, text
    assert "PowerShellNotFound" not in text, text


def test_an_unknown_error_after_the_redeem_of_a_save_keeps_its_honest_unknown_outcome(tmp_path):
    server = _save_server(tmp_path, fail_preview=None, fail_real=ActionError(SENTINEL))
    assert not _save_call(server, {}).isError
    r = _save_call(server, {"bevestiging": server.code_spy.codes[-1]})
    text = _text(r)
    assert r.isError, text
    assert "uitkomst is NIET vastgesteld" in text, text
    assert SENTINEL not in text, text
