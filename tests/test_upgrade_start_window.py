"""The start window of a confirmed phase.

`onderhoud_upgrade_fase` starts its runner detached and waits at most
`START_WAIT_S` for the runner's own `fase_gestart` row. A runner that is only
SLOW (it writes that row after the wait) used to leave the target open: the
answer said "telt niet als gestart ... kan nog steeds draaien", the ledger
carried no open phase, and a new proposal plus confirmation for the same
phase and run launched a SECOND runner against the same appliance - and read
the first runner's row as its own start. Measured offline with a slow
NEP-runner: two `fase_gestart` rows R1 with different action ids.

These tests pin the two halves of the fix:

- the server keeps an undecided start in its own register, per target, and
  every writing tool on that target - proposal and confirmed call alike -
  refuses until the runner's row lands (then the ordinary open-phase gate
  takes over) or the phase's own time limit passes (then the refusal lifts,
  audibly);
- `python -m nsmcp.upgrade_measure` action `start`, the one writer of
  `fase_gestart`, refuses on a target that already carries an open phase
  within its limit (tests/test_upgrade_measure.py).

The wait and the limit are shortened with monkeypatch, so each test takes
seconds; the NEP-runner here writes its row only when the test releases it
(a `.vrij` file next to the run's ledger file), so no test depends on how
fast a process happens to start. Every runner a test starts has finished
before that test returns.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import mcp.types as types
import pytest
from conftest import provenance_dir_for
from mcp.shared.memory import create_connected_server_and_client_session
from upgrade_fase_harness import (
    _NEP_RUNNER_TEMPLATE,
    DOELBUILD,
    SECOND_TARGET_NAME,
    TARGET_NAME,
    IdentifyingCodeSpy,
    _anchor_target,
    _call,
    _export,
    _firmwaremap,
    _knowledge,
    _r0_gesloten,
    _text,
)

from nsmcp import mcp_server, upgrade
from nsmcp.handelen import Allowlist, MaintenanceConfig, RunnerProcessNotStarted
from nsmcp.upgrade import append_line, read_ledger

# 1.1 B.3 point 3: every test of this module runs under the runtime seam
# check (`open_audit` in tests/conftest.py): a product open by path
# outside `nsmcp.localpath` fails it.
pytestmark = pytest.mark.usefixtures("open_audit")

RUN = "run-venster"
WAIT_S = 1
# The longest a released runner may take to write its row, and the longest a
# runner waits for its release before it gives up without writing anything.
LAND_WITHIN_S = 15.0
RUNNER_HOLD_S = 12.0

_HOLD_MARKER = "    if True:\n        bevestiger"


def _held_runner(tmp_path: Path, *, hold_s: float = RUNNER_HOLD_S) -> Path:
    """The harness NEP-runner, but it writes `fase_gestart` only once the
    test creates `<ledger>.vrij`; without that file it gives up after
    `hold_s` and exits without writing a row."""
    body = _NEP_RUNNER_TEMPLATE.format(write_gestart=True, sleep_after_start_s=0.0, write_actieid=True)
    assert _HOLD_MARKER in body
    body = body.replace("import json\n", "import json\nimport os\n", 1)
    hold = (
        '    vrij = ledger + ".vrij"\n'
        f"    einde = time.monotonic() + {hold_s!r}\n"
        "    while not os.path.exists(vrij):\n"
        "        if time.monotonic() >= einde:\n"
        "            return 0\n"
        "        time.sleep(0.05)\n"
    )
    body = body.replace(_HOLD_MARKER, hold + _HOLD_MARKER, 1)
    pad = tmp_path / "vastgehouden_runner.py"
    pad.write_text(body, encoding="utf-8")
    return pad


HOSTKEY = "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f"
# Two more configured names that the ledger's open-phase gate counts as
# `TARGET_NAME` (`upgrade_gate._normalised_target()`): an FQDN form and a
# capitalised form. Each carries an address of its own: the start refuses a
# targets file in which two targets share an address (tests/test_start.py),
# so this is how such names can still sit side by side in a configuration
# the server starts - and the register must hold them together all the same,
# because the gate it stands in for does.
FQDN_ALIAS = TARGET_NAME + ".lab"
CASE_ALIAS = TARGET_NAME.upper()


def _window_server(tmp_path: Path, runner: Path, *, aliases: tuple[str, ...] = ()):
    """One server, two targets. `TARGET_NAME` may run the phase tool AND
    `onderhoud_backup_maken`; `SECOND_TARGET_NAME` only the backup. Every
    name in `aliases` is one more configured name the open-phase gate
    counts as `TARGET_NAME`, with an address of its own (10.0.0.20 and up),
    allowed both tools. The backup's write script is an injected stand-in
    that records every REAL (non -WatIs) run in `server.write_runs`, so
    nothing but the phase runner is a real process."""
    export_dir = _export(tmp_path)
    _anchor_target(export_dir, TARGET_NAME)
    knowledge_path = _knowledge(tmp_path)
    doelen = {
        "doelen": [
            {
                "naam": TARGET_NAME,
                "adres": "10.0.0.2",
                "credentialTarget": "GJK/Test/netscaler-02/nitro-write",
                "certificaat": "keten",
                "ssh_hostsleutel_vingerafdruk": HOSTKEY,
            },
            {
                "naam": SECOND_TARGET_NAME,
                "adres": "10.0.0.3",
                "credentialTarget": "GJK/Test/netscaler-03/nitro-write",
                "certificaat": "keten",
            },
            *(
                {
                    "naam": alias,
                    "adres": f"10.0.0.{20 + index}",
                    "credentialTarget": "GJK/Test/netscaler-02/nitro-write",
                    "certificaat": "keten",
                    "ssh_hostsleutel_vingerafdruk": HOSTKEY,
                }
                for index, alias in enumerate(aliases)
            ),
        ]
    }
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps(doelen), encoding="utf-8")
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# ongebruikt: action_run vervangt dit", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    for row in _r0_gesloten(RUN, doelbuild=DOELBUILD):
        append_line(ledgermap / f"{RUN}.jsonl", row)
    onderhoud = MaintenanceConfig(
        runner=runner,
        ledgermap=ledgermap,
        firmwaremap=_firmwaremap(tmp_path),
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    allowlist = Allowlist(
        per_target={
            TARGET_NAME: {"onderhoud_upgrade_fase": True, "onderhoud_backup_maken": True},
            SECOND_TARGET_NAME: {"onderhoud_backup_maken": True},
            **{alias: {"onderhoud_upgrade_fase": True, "onderhoud_backup_maken": True} for alias in aliases},
        }
    )
    write_runs: list[list[str]] = []

    def spy_write_script(arguments, timeout_s):
        if "-WatIs" in arguments:
            return 0, "[OK] zou doen: een backup maken\n[TARGET] doel\n[EINDSTATUS] WAT-IS: er is niets gewijzigd\n", ""
        write_runs.append(list(arguments))
        return 0, "[ACTIEID] id-1\n[TARGET] doel\n[EINDSTATUS] actie uitgevoerd en teruggelezen\n", ""

    presenter = IdentifyingCodeSpy()
    server = mcp_server.build_server(
        export_dir,
        knowledge_path,
        targets_path=targets_path,
        action_script=schrijf,
        fixture_dir=tmp_path,
        action_run=spy_write_script,
        code_presenter=presenter,
        allowlist=allowlist,
        onderhoud=onderhoud,
        provenance_dir=provenance_dir_for(export_dir),
    )
    server.code_spy = presenter
    server.ledgermap = ledgermap
    server.write_runs = write_runs
    return server


def _ledger_file(server) -> Path:
    return server.ledgermap / f"{RUN}.jsonl"


def _started_rows_r1(server) -> list[dict]:
    return [
        r
        for r in read_ledger(_ledger_file(server))
        if r.get("gebeurtenis") == "fase_gestart" and r.get("fase") == "R1" and r.get("run") == RUN
    ]


def _release_and_wait_for_the_row(server, *, expected: int = 1) -> None:
    """Let the held runner write its row, and wait until it is there."""
    Path(str(_ledger_file(server)) + ".vrij").write_text("", encoding="utf-8")
    einde = time.monotonic() + LAND_WITHIN_S
    while len(_started_rows_r1(server)) < expected:
        assert time.monotonic() < einde, "de vastgehouden runner schreef zijn regel niet"
        time.sleep(0.05)


def _wait_for_runner_exit(seconds: float) -> None:
    """A held runner that is never released exits by itself after its hold;
    wait that long so no process outlives the test."""
    time.sleep(seconds)


def _propose_r1(server) -> str:
    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
    assert not r.isError, _text(r)
    return server.code_spy.codes[-1]


def _confirm_r1(server, code: str):
    return _call(
        server,
        "onderhoud_upgrade_fase",
        {"fase": "R1", "run": RUN, "doel": TARGET_NAME, "bevestiging": code},
    )


ONBESLIST = "op dit doel is de start van fase R1 (run run-venster) nog onbeslist"


@pytest.fixture
def short_wait(monkeypatch):
    monkeypatch.setattr(mcp_server, "START_WAIT_S", WAIT_S)


def test_a_slow_runner_leaves_the_target_blocked_for_every_writing_call(tmp_path, short_wait):
    """Tests 1-4 of the window in one sequence, on one server: the timeout
    says the target stays blocked; a new proposal, a confirmation with a
    code issued before the first start, and another writing tool on the same
    target are all refused with the undecided-start reason; the same tool
    on another target is not touched; once the row lands the ordinary
    open-phase refusal takes over; and exactly ONE runner wrote a start."""
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    code2 = _propose_r1(server)

    r1 = _confirm_r1(server, code1)
    text1 = _text(r1)
    assert r1.isError, text1
    assert f"de fase heeft binnen {WAIT_S} seconden geen regel fase_gestart in het ledger geschreven" in text1
    assert "losgekoppeld gestart en kan nog steeds draaien" in text1
    assert (
        "Het doel blijft geblokkeerd voor elke schrijvende tool, ook voor een nieuw voorstel, tot die "
        "regel verschijnt of de tijdslimiet van fase R1 (3600 s) verstrijkt, om " in text1
    )

    # 2. A fresh proposal for the same phase and run: refused, no code issued.
    codes_before = len(server.code_spy.codes)
    r2 = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
    assert r2.isError, _text(r2)
    assert ONBESLIST in _text(r2)
    assert len(server.code_spy.codes) == codes_before, "een voorstel in het venster gaf toch een code uit"

    # ... and the confirmation with a code issued BEFORE the first start.
    r3 = _confirm_r1(server, code2)
    assert r3.isError, _text(r3)
    assert ONBESLIST in _text(r3)

    # 3. Another writing tool on the same target: refused, proposal included.
    r4 = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r4.isError, _text(r4)
    assert ONBESLIST in _text(r4)
    # ... and on ANOTHER target: not touched.
    r5 = _call(server, "onderhoud_backup_maken", {"doel": SECOND_TARGET_NAME})
    assert not r5.isError, _text(r5)
    assert "onbeslist" not in _text(r5)

    # 4. The row lands: the ordinary open-phase gate takes over.
    _release_and_wait_for_the_row(server)
    code3 = _propose_r1(server)
    r6 = _confirm_r1(server, code3)
    assert r6.isError, _text(r6)
    assert "er staat nog een fase open op dit doel" in _text(r6)
    assert "onbeslist" not in _text(r6)
    r7 = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r7.isError, _text(r7)
    assert "er staat nog een fase open op dit doel" in _text(r7)

    rows = _started_rows_r1(server)
    assert len(rows) == 1, [r.get("actieid") for r in rows]


def test_the_undecided_start_lifts_audibly_at_the_phase_limit_and_a_start_is_allowed_again(
    tmp_path, short_wait, monkeypatch
):
    """5. The runner never writes its row (it gives up before its release):
    once the time limit of the phase has passed, the refusal lifts - and
    says so in the answer that is let through - and a new start of the same
    phase and run goes ahead."""
    monkeypatch.setitem(upgrade.PHASE_LIMITS_S, "R1", 4)
    runner = _held_runner(tmp_path, hold_s=2.0)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    r1 = _confirm_r1(server, code1)
    assert r1.isError
    assert "tijdslimiet van fase R1 (4 s)" in _text(r1)

    r2 = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
    assert r2.isError and ONBESLIST in _text(r2)

    # Ask again until the limit has passed: refused with the same reason
    # until then, let through - with the lift in its own answer - after.
    einde = time.monotonic() + 15.0
    while True:
        r3 = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
        if not r3.isError:
            break
        assert ONBESLIST in _text(r3), _text(r3)
        assert time.monotonic() < einde, "de blokkade verviel niet na de tijdslimiet"
        time.sleep(0.25)
    text3 = _text(r3)
    assert "- onbesliste start: de start van fase R1 (run run-venster) bleef onbeslist tot de tijdslimiet" in text3
    assert "het doel is weer vrij" in text3
    # The first runner gave up after its 2 s hold, well before the 4 s limit.
    assert _started_rows_r1(server) == []

    # The new start: this runner may write at once, and the wait is the
    # product's own again (it returns the moment the row is there).
    monkeypatch.setattr(mcp_server, "START_WAIT_S", 20)
    Path(str(_ledger_file(server)) + ".vrij").write_text("", encoding="utf-8")
    code2 = server.code_spy.codes[-1]
    r4 = _confirm_r1(server, code2)
    assert not r4.isError, _text(r4)
    assert "FASE GESTART" in _text(r4)
    assert len(_started_rows_r1(server)) == 1


def test_the_stand_shows_an_undecided_start(tmp_path, short_wait):
    """6. `onderhoud_upgrade_stand` names the undecided start as its own
    finding, with when the runner started and until when the target stays
    blocked."""
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    assert _confirm_r1(server, code1).isError

    r = _call(server, "onderhoud_upgrade_stand", {"doel": TARGET_NAME})
    text = _text(r)
    assert not r.isError, text
    regel = next((line for line in text.splitlines() if line.startswith("- onbesliste start: ")), "")
    assert regel.startswith(
        "- onbesliste start: de start van fase R1 (run run-venster) is onbeslist: de faserunner is "
        "losgekoppeld gestart en heeft binnen 1 s geen regel fase_gestart geschreven"
    ), text
    assert regel.endswith("[vastgesteld]"), regel
    assert re.search(
        r"bewijs: faserunner gestart om \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ, geen regel fase_gestart binnen 1 s, "
        r"deadline \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
        text,
    ), text

    _release_and_wait_for_the_row(server)
    after = _text(_call(server, "onderhoud_upgrade_stand", {"doel": TARGET_NAME}))
    assert "- onbesliste start: " not in after


def test_another_configured_name_for_the_same_box_is_held_in_the_window_too(tmp_path, short_wait):
    """The register holds the target NAME in the spelling the ledger's
    open-phase gate compares on (`upgrade_gate._normalised_target()`:
    capitalisation and the domain part of an FQDN do not make another
    target), not one exact spelling - and the configuration accepts two such
    names side by side. A name with another first label is another target
    to both; that two names never mean one address is the start's own check
    (tests/test_start.py). Measured before the register used the same
    rule: inside the window a backup on `<doel>.lab` was proposed AND really
    run, while the ledger gate refused that very alias once the row had
    landed. Now, on either alias: the other writing tool's proposal and its
    confirmed call, and the phase tool itself (the same run, and a new R0),
    are refused with the undecided-start reason; the stand on the alias
    names the undecided start; once the row lands the ordinary open-phase
    gate refuses the alias, as before."""
    aliases = (FQDN_ALIAS, CASE_ALIAS)
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner, aliases=aliases)
    # A code per alias for the confirmed call in the window, issued before
    # the start.
    backup_codes = {}
    for alias in aliases:
        r = _call(server, "onderhoud_backup_maken", {"doel": alias})
        assert not r.isError, _text(r)
        backup_codes[alias] = server.code_spy.codes[-1]
    code1 = _propose_r1(server)
    assert _confirm_r1(server, code1).isError

    for alias in aliases:
        codes_before = len(server.code_spy.codes)
        voorstel = _call(server, "onderhoud_backup_maken", {"doel": alias})
        assert voorstel.isError, (alias, _text(voorstel))
        assert ONBESLIST in _text(voorstel), (alias, _text(voorstel))
        bevestigd = _call(server, "onderhoud_backup_maken", {"doel": alias, "bevestiging": backup_codes[alias]})
        assert bevestigd.isError, (alias, _text(bevestigd))
        assert ONBESLIST in _text(bevestigd), (alias, _text(bevestigd))
        zelfde_run = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": alias})
        assert zelfde_run.isError, (alias, _text(zelfde_run))
        assert ONBESLIST in _text(zelfde_run), (alias, _text(zelfde_run))
        nieuwe_run = _call(
            server, "onderhoud_upgrade_fase", {"fase": "R0", "doel": alias, "snapshotverwijzing": "checkpoint-1"}
        )
        assert nieuwe_run.isError, (alias, _text(nieuwe_run))
        assert "nog onbeslist" in _text(nieuwe_run), (alias, _text(nieuwe_run))
        assert len(server.code_spy.codes) == codes_before, "een voorstel op een alias in het venster gaf een code uit"
        stand = _call(server, "onderhoud_upgrade_stand", {"doel": alias})
        assert not stand.isError, _text(stand)
        assert "- onbesliste start: de start van fase R1 (run run-venster) is onbeslist" in _text(stand), (
            alias,
            _text(stand),
        )
    assert server.write_runs == [], "een schrijfactie op een alias liep in het venster toch"

    _release_and_wait_for_the_row(server)
    for alias in aliases:
        na = _call(server, "onderhoud_backup_maken", {"doel": alias})
        assert na.isError, (alias, _text(na))
        assert "er staat nog een fase open op dit doel" in _text(na), (alias, _text(na))
        assert "onbeslist" not in _text(na)
    assert len(_started_rows_r1(server)) == 1
    assert server.write_runs == []


def test_another_configured_name_for_the_same_box_is_free_again_once_the_limit_has_passed(
    tmp_path, short_wait, monkeypatch
):
    """The alias is held until the phase's time limit, then let through -
    with the lift in its own answer, as for the configured name itself."""
    monkeypatch.setitem(upgrade.PHASE_LIMITS_S, "R1", 4)
    runner = _held_runner(tmp_path, hold_s=2.0)
    server = _window_server(tmp_path, runner, aliases=(FQDN_ALIAS,))
    code1 = _propose_r1(server)
    assert _confirm_r1(server, code1).isError

    geweigerd = 0
    einde = time.monotonic() + 15.0
    while True:
        r = _call(server, "onderhoud_backup_maken", {"doel": FQDN_ALIAS})
        if not r.isError:
            break
        assert ONBESLIST in _text(r), _text(r)
        geweigerd += 1
        assert time.monotonic() < einde, "de blokkade op de alias verviel niet na de tijdslimiet"
        time.sleep(0.25)
    assert geweigerd > 0, "de alias werd in het venster niet vastgehouden"
    text = _text(r)
    assert "- onbesliste start: de start van fase R1 (run run-venster) bleef onbeslist tot de tijdslimiet" in text
    assert "het doel is weer vrij" in text
    assert _started_rows_r1(server) == []


def test_a_wait_that_breaks_off_still_leaves_the_target_blocked(tmp_path, short_wait, monkeypatch):
    """Not only the timeout: when the wait for the row itself fails (here:
    the ledger file cannot be read while waiting), the runner was still
    launched, so the target is held the same way - never left open because
    the wait raised."""
    runner = _held_runner(tmp_path, hold_s=1.0)
    server = _window_server(tmp_path, runner)

    def broken_wait(*_args, **_kwargs):
        raise PermissionError("gesimuleerd: het ledgerbestand is niet leesbaar")

    code1 = _propose_r1(server)
    monkeypatch.setattr(mcp_server, "wait_for_start", broken_wait)
    r1 = _confirm_r1(server, code1)
    assert r1.isError
    r2 = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r2.isError, _text(r2)
    assert (
        "op dit doel is de start van fase R1 (run run-venster) nog onbeslist: de faserunner is "
        "losgekoppeld gestart en het wachten op zijn regel fase_gestart brak af" in _text(r2)
    )
    _wait_for_runner_exit(1.5)


BROKE_OFF = (
    "op dit doel is de start van fase R1 (run run-venster) nog onbeslist: de faserunner is "
    "losgekoppeld gestart en het wachten op zijn regel fase_gestart brak af"
)


def _cancel(client, request_id: int):
    """`notifications/cancelled` for `request_id` - what a client sends on a
    timeout or when the operator presses stop."""
    return client.send_notification(
        types.ClientNotification(
            types.CancelledNotification(
                method="notifications/cancelled",
                params=types.CancelledNotificationParams(requestId=request_id, reason="de operator brak af"),
            )
        )
    )


def test_a_call_cancelled_while_the_runner_is_being_launched_leaves_the_target_blocked(
    tmp_path, short_wait, monkeypatch
):
    """The client cancels the confirmed call while `start_detached()` is
    still busy in its worker thread. The waiting coroutine unwinds, but the
    thread finishes the launch: a runner exists and may write its row any
    moment. The register must already hold the target then - it used to be
    filled only once the launch had RETURNED, so a call cancelled during the
    launch left nothing behind and every writing tool on the target was let
    through while the ledger was still empty."""
    runner = _held_runner(tmp_path, hold_s=1.0)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)

    real_start = mcp_server.start_detached
    in_launch = threading.Event()
    go_on = threading.Event()
    launched: list[str] = []

    def slow_launch(argv, *, log_path):
        in_launch.set()
        assert go_on.wait(10.0), "de test gaf de start niet vrij"
        host = real_start(argv, log_path=log_path)
        launched.append(host)
        return host

    monkeypatch.setattr(mcp_server, "start_detached", slow_launch)

    async def go():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-desktop", version="1.0")
        ) as client:
            request_id = client._request_id
            taak = asyncio.create_task(
                client.call_tool(
                    "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME, "bevestiging": code1}
                )
            )
            einde = time.monotonic() + 10.0
            while not in_launch.is_set():
                assert time.monotonic() < einde, "de start werd nooit aangeroepen"
                await asyncio.sleep(0.02)
            await _cancel(client, request_id)
            try:
                await taak
            except Exception:  # noqa: BLE001 - McpError: Request cancelled
                pass
            go_on.set()

    # `asyncio.run()` returns only after the worker thread has finished the
    # launch (it shuts the default executor down).
    asyncio.run(go())
    assert len(launched) == 1, "de faserunner werd niet gestart"

    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r.isError, _text(r)
    assert BROKE_OFF in _text(r), _text(r)
    assert server.write_runs == []
    _wait_for_runner_exit(1.5)


def _carries(exc: BaseException, kind: type[BaseException]) -> bool:
    """Whether `exc` is `kind`, or an exception group that holds one."""
    if isinstance(exc, kind):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_carries(inner, kind) for inner in exc.exceptions)
    return False


def test_an_interrupt_right_after_the_launch_leaves_the_target_blocked(tmp_path, short_wait, monkeypatch):
    """The same, the blunt way: the launch really happens and the thread
    that ran it raises an interrupt on its way back. Whatever breaks off
    after the start was requested, the target stays held."""
    runner = _held_runner(tmp_path, hold_s=1.0)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    real_start = mcp_server.start_detached
    launched: list[str] = []

    def launch_then_interrupt(argv, *, log_path):
        launched.append(real_start(argv, log_path=log_path))
        raise KeyboardInterrupt

    monkeypatch.setattr(mcp_server, "start_detached", launch_then_interrupt)
    with pytest.raises(BaseException) as onderbroken:
        _confirm_r1(server, code1)
    assert _carries(onderbroken.value, KeyboardInterrupt), repr(onderbroken.value)
    assert len(launched) == 1

    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r.isError, _text(r)
    assert BROKE_OFF in _text(r), _text(r)
    assert server.write_runs == []
    _wait_for_runner_exit(1.5)


# While the confirmed call still waits for the runner's row - the normal
# case, for up to `START_WAIT_S` - the target is held already (from the
# request on). That state has a sentence of its own; "brak af" is for a wait
# that was cancelled or raised.
WAITING = (
    "op dit doel is de start van fase R1 (run run-venster) nog onbeslist: de faserunner is "
    "losgekoppeld gestart en de server wacht nog op zijn regel fase_gestart (tot "
)
_MOMENT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"


def _session(server):
    return create_connected_server_and_client_session(
        server, client_info=types.Implementation(name="claude-desktop", version="1.0")
    )


async def _until_set(event: threading.Event, what: str) -> None:
    einde = time.monotonic() + 10.0
    while not event.is_set():
        assert time.monotonic() < einde, what
        await asyncio.sleep(0.02)


def _moment_after(prefix: str, text: str) -> datetime:
    m = re.search(re.escape(prefix) + f"({_MOMENT})", text)
    assert m, text
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def test_a_start_still_waiting_for_its_row_is_named_as_waiting_not_as_broken_off(tmp_path, monkeypatch):
    """Measured with two client sessions on one server: while a confirmed
    phase call still waited for its row, another caller on the target was
    refused - rightly - with "het wachten op zijn regel fase_gestart brak af",
    and `onderhoud_upgrade_stand` reported the same [vastgesteld]; seconds
    later the same phase call answered FASE GESTART. The wait had not broken
    off, it was still running. Now both read that the server still waits
    for the row, and until when; the phase call ends with FASE GESTART once
    the row lands, and nothing but that runner wrote."""
    wait_s = 15
    monkeypatch.setattr(mcp_server, "START_WAIT_S", wait_s)
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    real_wait = mcp_server.wait_for_start
    waiting = threading.Event()

    def observed_wait(*args, **kwargs):
        waiting.set()
        return real_wait(*args, **kwargs)

    monkeypatch.setattr(mcp_server, "wait_for_start", observed_wait)

    async def go():
        async with _session(server) as a, _session(server) as b:
            fase = asyncio.create_task(
                a.call_tool(
                    "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME, "bevestiging": code1}
                )
            )
            await _until_set(waiting, "de server begon niet te wachten op de regel")
            wait_started = datetime.now(UTC)
            backup = await b.call_tool("onderhoud_backup_maken", {"doel": TARGET_NAME})
            stand = await b.call_tool("onderhoud_upgrade_stand", {"doel": TARGET_NAME})
            Path(str(_ledger_file(server)) + ".vrij").write_text("", encoding="utf-8")
            return wait_started, backup, stand, await fase

    wait_started, backup, stand, fase = asyncio.run(go())

    tekst = _text(backup)
    assert backup.isError, tekst
    assert WAITING in tekst, tekst
    assert "brak af" not in tekst, tekst
    tot = _moment_after(WAITING, tekst)
    assert timedelta(seconds=wait_s - 3) <= tot - wait_started <= timedelta(seconds=wait_s + 1), (tot, wait_started)

    stand_tekst = _text(stand)
    assert not stand.isError, stand_tekst
    regel = next((line for line in stand_tekst.splitlines() if line.startswith("- onbesliste start: ")), "")
    assert regel.startswith(
        "- onbesliste start: de start van fase R1 (run run-venster) is onbeslist: de faserunner is "
        "losgekoppeld gestart en de server wacht nog op zijn regel fase_gestart (tot "
    ), stand_tekst
    assert regel.endswith("[vastgesteld]"), regel
    assert re.search(
        rf"bewijs: faserunner gestart om {_MOMENT}, het wachten op de regel fase_gestart loopt tot {_MOMENT}, "
        rf"deadline {_MOMENT}",
        stand_tekst,
    ), stand_tekst
    assert "brak af" not in stand_tekst, stand_tekst

    assert not fase.isError, _text(fase)
    assert "FASE GESTART" in _text(fase)
    assert len(_started_rows_r1(server)) == 1
    assert server.write_runs == []


def test_a_wait_cancelled_while_it_runs_turns_from_waiting_into_broken_off(tmp_path, monkeypatch):
    """The two states on one start, told apart: while the wait runs,
    another caller reads that the server still waits for the row; once the
    client cancels the phase call during that wait, the same caller - and
    the stand - read that the wait broke off. The runner was launched and
    may still write its row, so the target stays held either way. (The wait
    here is held by the test instead of polling the ledger, so the window
    does not depend on how fast this machine answers.)"""
    runner = _held_runner(tmp_path, hold_s=2.0)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    waiting = threading.Event()
    release = threading.Event()

    def held_wait(*_args, **_kwargs):
        waiting.set()
        assert release.wait(20.0), "de test gaf het wachten niet vrij"

    monkeypatch.setattr(mcp_server, "wait_for_start", held_wait)

    async def go():
        async with _session(server) as a, _session(server) as b:
            request_id = a._request_id
            fase = asyncio.create_task(
                a.call_tool(
                    "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME, "bevestiging": code1}
                )
            )
            try:
                await _until_set(waiting, "de server begon niet te wachten op de regel")
                tijdens = await b.call_tool("onderhoud_backup_maken", {"doel": TARGET_NAME})
                await _cancel(a, request_id)
                try:
                    await fase
                except Exception:  # noqa: BLE001 - McpError: Request cancelled
                    pass
                # The refusal turns into "brak af" once the cancelled call
                # has unwound; every answer until then is a refusal too.
                einde = time.monotonic() + 10.0
                while True:
                    na = await b.call_tool("onderhoud_backup_maken", {"doel": TARGET_NAME})
                    assert na.isError, _text(na)
                    if BROKE_OFF in _text(na):
                        break
                    assert WAITING in _text(na), _text(na)
                    assert time.monotonic() < einde, "het wachten werd na de annulering niet als afgebroken gemeld"
                    await asyncio.sleep(0.05)
                stand = await b.call_tool("onderhoud_upgrade_stand", {"doel": TARGET_NAME})
            finally:
                release.set()
            return tijdens, na, stand

    tijdens, na, stand = asyncio.run(go())

    assert tijdens.isError, _text(tijdens)
    assert WAITING in _text(tijdens), _text(tijdens)
    assert "brak af" not in _text(tijdens)
    assert "wacht nog" not in _text(na), _text(na)
    stand_tekst = _text(stand)
    assert (
        "- onbesliste start: de start van fase R1 (run run-venster) is onbeslist: de faserunner is "
        "losgekoppeld gestart en het wachten op zijn regel fase_gestart brak af" in stand_tekst
    ), stand_tekst
    assert "wacht nog" not in stand_tekst, stand_tekst
    assert server.write_runs == []
    _wait_for_runner_exit(2.0)


def test_a_start_that_launched_nothing_does_not_hold_the_target(tmp_path, short_wait, monkeypatch):
    """The other side of holding the target from the moment the start is
    requested: when `start_detached()` reports that no child exists (one of
    its three typed errors, since 1.1 - an unknown `ActionError` no longer
    counts as that proof), nothing was launched and nothing may write, so the hold
    is taken back - the answer says the phase did not start, and the next
    writing call on the target is not refused as undecided."""
    runner = _held_runner(tmp_path)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)

    def launches_nothing(*_args, **_kwargs):
        raise RunnerProcessNotStarted(OSError)

    monkeypatch.setattr(mcp_server, "start_detached", launches_nothing)
    r1 = _confirm_r1(server, code1)
    assert r1.isError, _text(r1)
    assert "de faserunner kon niet gestart worden" in _text(r1)
    r2 = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert not r2.isError, _text(r2)
    assert "onbeslist" not in _text(r2)


def test_a_start_that_launched_nothing_keeps_an_earlier_lapsed_hold_audible(tmp_path, short_wait, monkeypatch):
    """Taking the hold back restores what the register held BEFORE the
    request: a hold that already lapsed at its limit stays named in the
    answers that go through, until a start that really launched replaces
    it - a failed launch is not such a start."""
    monkeypatch.setitem(upgrade.PHASE_LIMITS_S, "R1", 4)
    runner = _held_runner(tmp_path, hold_s=2.0)
    server = _window_server(tmp_path, runner)
    code1 = _propose_r1(server)
    assert _confirm_r1(server, code1).isError

    einde = time.monotonic() + 15.0
    while True:
        voorstel = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": RUN, "doel": TARGET_NAME})
        if not voorstel.isError:
            break
        assert time.monotonic() < einde, "de blokkade verviel niet na de tijdslimiet"
        time.sleep(0.25)
    vervallen = "bleef onbeslist tot de tijdslimiet"
    assert vervallen in _text(voorstel)
    code2 = server.code_spy.codes[-1]

    def launches_nothing(*_args, **_kwargs):
        raise RunnerProcessNotStarted(OSError)

    monkeypatch.setattr(mcp_server, "start_detached", launches_nothing)
    r2 = _confirm_r1(server, code2)
    assert r2.isError and "de faserunner kon niet gestart worden" in _text(r2), _text(r2)
    r3 = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert not r3.isError, _text(r3)
    assert vervallen in _text(r3), _text(r3)
    assert "nog onbeslist" not in _text(r3)


def test_the_register_deadline_is_the_phase_limit_and_never_zero_for_r0_or_r6():
    """The deadline is the launch moment plus the phase's own time limit;
    R0 and R6, which carry no limit of their own, get the same derived
    ceiling `open_phases()` uses - never 0 (no block at all) and never
    unbounded."""
    moment = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
    fallback = upgrade.NO_CEILING_FALLBACK_S
    for fase, verwacht in (("R1", 3600), ("R2", 900), ("R5", 300), ("R0", fallback), ("R6", fallback)):
        start = upgrade.UndecidedStart(
            target=TARGET_NAME,
            run=RUN,
            phase=fase,
            launched=moment,
            ledger_path=Path("niet-aanwezig.jsonl"),
            already_started=0,
            wait_s=20,
            broke_off=False,
        )
        assert start.limit_s == verwacht > 0
        assert start.deadline == moment + timedelta(seconds=verwacht)
