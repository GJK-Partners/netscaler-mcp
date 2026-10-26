"""`onderhoud_upgrade_fase` - the configuration, the start and the
weigeringen.

The NEP-runner, the code channel stand-ins and the server/call helpers all
live in `tests/upgrade_fase_harness.py`, so `tests/test_product_surface.py`
can pin this tool's answer without importing another TEST module for it.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from upgrade_fase_harness import (
    DOELBUILD,
    HOSTKEY,
    SECOND_TARGET_NAME,
    TARGET_NAME,
    BareBevestigerAttributeSpy,
    CodeSpy,
    _anchor_target,
    _argv_rows,
    _call,
    _export,
    _firmwaremap,
    _knowledge,
    _nep_runner,
    _propose,
    _r0_gesloten,
    _regel,
    _server,
    _targets_file,
    _text,
    _two_target_write_server,
    _with_floor,
)

from nsmcp import mcp_server
from nsmcp.handelen import (
    ActionError,
    MaintenanceConfig,
    Refusal,
    build_upgrade_arguments,
    validate_phase_arguments,
)
from nsmcp.target import CertAgreement, Target
from nsmcp.upgrade import NO_CEILING_FALLBACK_S, START_WAIT_S, append_line, read_ledger

# ---------------------------------------------------------------------------
# fixtures the tests below take by name (pytest resolves them)
# ---------------------------------------------------------------------------


@pytest.fixture
def server_zonder_sso(tmp_path):
    return _server(tmp_path, code_presenter=CodeSpy())


@pytest.fixture
def config_zonder_vingerafdruk(tmp_path):
    """A full CONFIG FILE (start.py's own input), not a built server: the
    hostkey check is a STARTUP error, not a tool-call refusal."""
    export_dir = _export(tmp_path)
    knowledge_path = _knowledge(tmp_path)
    targets_path = _targets_file(tmp_path, hostkey=None)
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# x", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    firmwaremap = _firmwaremap(tmp_path)
    runner = _nep_runner(tmp_path)
    verzamelscript = tmp_path / "verzamel.ps1"
    verzamelscript.write_text("# ongebruikt in deze test", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export_dir),
        "kennispad": str(knowledge_path),
        "doelen": str(targets_path),
        "verzamelscript": str(verzamelscript),
        "handelen": {
            "schrijfscript": str(schrijf),
            "fixturemap": str(tmp_path),
            "codekanaal": {"soort": "venster"},
            "toegestaan": {TARGET_NAME: {"onderhoud_upgrade_fase": True}},
        },
        "onderhoud": {
            "runner": str(runner),
            "ledgermap": str(ledgermap),
            "firmwaremap": str(firmwaremap),
            "soak_uren": 24,
            "ssh_gebruiker": "nsroot",
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


@pytest.fixture
def nep_runner(tmp_path):
    return _nep_runner(tmp_path)


@pytest.fixture
def ledgermap(tmp_path):
    m = tmp_path / "ledger"
    m.mkdir()
    return m


@pytest.fixture
def traag_runner(tmp_path):
    """Never writes `fase_gestart`."""
    return _nep_runner(tmp_path, "traag.py", write_gestart=False)


def _open_r0_ledger(tmp_path, *, age_s: int):
    """A ledger directory holding ONE foreign run with an open R0 on this
    target - a `fase_gestart` row with no closing row, `age_s` seconds old.

    Both the `tijd` field (which `open_phases()` reads) and `gestart` carry
    that moment, so the age is the row's own and not the wall clock at
    fixture time."""
    m = tmp_path / "ledger"
    m.mkdir(exist_ok=True)
    moment = datetime.now(UTC) - timedelta(seconds=age_s)
    stamp = moment.isoformat().replace("+00:00", "Z")
    row = _regel(run="andere-run", fase="R0", gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stamp)
    row["tijd"] = stamp
    append_line(m / "andere-run.jsonl", row)
    return m


@pytest.fixture
def ledger_lopend(tmp_path):
    """A run with a LIVE open R0 on this target: a `fase_gestart` row
    written a second ago, well inside the ceiling `open_phases()` measures
    it against. A phase that is genuinely running on this appliance right
    now - so a second run is refused (weigering 2), and
    R0 does NOT adopt it."""
    return _open_r0_ledger(tmp_path, age_s=1)


@pytest.fixture
def ledger_stale_r0(tmp_path):
    """The same shape, but PAST its ceiling: an open R0 older than
    `NO_CEILING_FALLBACK_S` (R0 carries no ceiling of its own) with no
    closing row. That phase counts as `mislukt` with reason `tijdslimiet`,
    not as open - and it is the only open R0 that R0 adopts, so a stale run
    can be re-closed instead of locking the target forever."""
    from nsmcp.upgrade import NO_CEILING_FALLBACK_S

    return _open_r0_ledger(tmp_path, age_s=NO_CEILING_FALLBACK_S + 120)


@pytest.fixture
def ledger_with_open_r1(tmp_path):
    """A FOREIGN run that is open on a phase this caller is not asking for:
    R0 closed, R1 started and never closed. A new run's R0 on the same
    target is refused by the open-run check - weigering 2."""
    m = tmp_path / "ledger"
    m.mkdir()
    now = datetime.now(UTC)
    append_line(
        m / "andere-run.jsonl",
        _regel(
            run="andere-run",
            fase="R0",
            gebeurtenis="voormeting_vast",
            uitkomst="geslaagd",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    append_line(
        m / "andere-run.jsonl",
        _regel(
            run="andere-run",
            fase="R1",
            gebeurtenis="fase_gestart",
            uitkomst="gestart",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    return m


@pytest.fixture
def ledger_soak_open(tmp_path):
    """A CLOSED previous run whose R6 opened the soak window recently -
    still binding, including on R0 of a NEXT run on the same target."""
    m = tmp_path / "ledger"
    m.mkdir()
    now = datetime.now(UTC)
    append_line(
        m / "vorige-run.jsonl",
        _regel(
            run="vorige-run",
            fase="R6",
            gebeurtenis="soak_open",
            uitkomst="geslaagd",
            gestart=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        ),
    )
    return m


@pytest.fixture
def ledger_zonder_r0(tmp_path):
    """An empty ledger directory: R1 on a run whose own file carries no
    closed R0 at all - `order_gate` refuses (`phase_state([], "R0")` is
    `niet beoordeeld`, never `geslaagd`)."""
    m = tmp_path / "ledger"
    m.mkdir()
    return m


@pytest.fixture
def ledger_r1_gesloten(tmp_path):
    """Run-a's own file with R0 `geslaagd` and
    R1 already closed `poort dicht` - the exact shape a re-run of R1 on
    this SAME run must now be refused for, before the runner ever
    launches."""
    m = tmp_path / "ledger"
    m.mkdir()
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    append_line(
        m / "run-a.jsonl",
        _regel(
            run="run-a",
            fase="R0",
            gebeurtenis="voormeting_vast",
            uitkomst="geslaagd",
            gestart=now,
        ),
    )
    append_line(
        m / "run-a.jsonl",
        _regel(
            run="run-a",
            fase="R1",
            gebeurtenis="poort_dicht",
            uitkomst="poort dicht",
            gestart=now,
        ),
    )
    return m


@pytest.fixture
def ledger_r1_gesloten_plus_nieuwe_run(tmp_path, ledger_r1_gesloten):
    """The same target, PLUS a brand-new run (`run-c`) whose own R0 already
    closed `geslaagd` - the legitimate escape H1's fix sentence names: "wie
    deze fase opnieuw wil proberen, start een nieuwe run"."""
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for regel in _r0_gesloten("run-c", gestart=now):
        append_line(ledger_r1_gesloten / "run-c.jsonl", regel)
    return ledger_r1_gesloten


# ---------------------------------------------------------------------------
# the tests
# ---------------------------------------------------------------------------


def test_the_runner_refuses_a_channel_that_cannot_identify_the_confirmer(server_zonder_sso, tmp_path):
    """MUTATIEPROEF 8. Haal de bevestiger-controle weg en deze test valt om."""
    code, _ = _propose(server_zonder_sso, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server_zonder_sso,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "de faserunner weigert te starten op een kanaal dat de bevestiger niet kan identificeren" in _text(r)


def test_the_runner_refuses_a_channel_with_only_a_bare_bevestiger_attribute(tmp_path):
    """A channel with a bare `.bevestiger` attribute
    and no `bevestiger_for` must be refused exactly like `server_zonder_sso`
    above (no identifying capability at all) - not silently accepted
    through the attribute. Before the fix this passed the gate."""
    server = _server(tmp_path, code_presenter=BareBevestigerAttributeSpy())
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "de faserunner weigert te starten op een kanaal dat de bevestiger niet kan identificeren" in _text(r)


def test_the_runner_refuses_an_unknown_host_key(config_zonder_vingerafdruk, capsys):
    """MUTATIEPROEF 9, productkant: een doel dat de fase mag uitvoeren maar
    geen gepinde hostsleutel draagt, is een STARTfout."""
    from nsmcp.start import run as start_run

    code = start_run([str(config_zonder_vingerafdruk)])
    assert code == 1
    fout = capsys.readouterr().err
    assert f"doel {TARGET_NAME} mag onderhoud_upgrade_fase uitvoeren" in fout
    assert "ssh_hostsleutel_vingerafdruk" in fout
    assert "de runner pint de hostsleutel en accepteert er nooit een" in fout


@pytest.fixture
def config_met_onveilige_doelnaam(tmp_path):
    """A target name is any non-empty string - `_target_for()`
    (mcp_server.py) only checks MEMBERSHIP in the configured names, never
    their own grammar. `run_id(doelnaam, ...)` (upgrade.py) then builds
    `<tijdstempel>Z-<doelnaam>` as R0's OWN run name, and a doelnaam
    carrying a character `is_safe_run_name()`'s path-segment grammar
    rejects makes THAT check fail on every R0 call - a misleading refusal
    about "de run-naam voor deze fase" over a `run` the operator never
    supplied. This target carries a valid hostkey (the OTHER start-time
    check, tested above, must not be what fires here).

    Merge note (semantic conflict between two branches): a name
    with a SPACE used to sit here and exercised this same gate - but
    mergefix's `_allowlist()` now runs FIRST and refuses
    a space itself (it is outside `[A-Za-z0-9._-]`), so this test would
    see mergefix's sentence instead of this gate's own. A trailing dot is
    the one shape `_allowlist()`'s character grammar still lets through
    (only bare "." and ".." are reserved there) while `run_id()`
    (`<tijdstempel>Z-<doelnaam>`) puts `doelnaam` at the END of the
    wrapped value, so `is_safe_run_name()`'s "does not end with '.'" rule
    still catches it - see
    `test_a_target_name_rejected_by_both_gates_shows_mergefixs_message`
    below for the order this depends on, and the module docstring / this
    fixture's neighbour test for why a bare reserved Windows device name
    (CON, NUL, ...) does NOT work here: `is_safe_run_name()`'s device-name
    check looks at the value BEFORE ITS FIRST DOT, and the timestamp
    prefix `run_id()` always prepends has no dot in it - so that branch
    never fires on a run_id()-wrapped doelnaam, only on a raw `run` value
    (the operator-supplied R1..R6 argument, or one adopted from a ledger
    row) that never went through `run_id()` at all."""
    onveilige_naam = "lab02."
    export_dir = _export(tmp_path)
    knowledge_path = _knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": onveilige_naam,
                        "adres": "10.0.0.2",
                        "credentialTarget": "GJK/Test/lab02/nitro-write",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": HOSTKEY,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# x", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    firmwaremap = _firmwaremap(tmp_path)
    runner = _nep_runner(tmp_path)
    verzamelscript = tmp_path / "verzamel.ps1"
    verzamelscript.write_text("# ongebruikt in deze test", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export_dir),
        "kennispad": str(knowledge_path),
        "doelen": str(targets_path),
        "verzamelscript": str(verzamelscript),
        "handelen": {
            "schrijfscript": str(schrijf),
            "fixturemap": str(tmp_path),
            "codekanaal": {"soort": "venster"},
            "toegestaan": {onveilige_naam: {"onderhoud_upgrade_fase": True}},
        },
        "onderhoud": {
            "runner": str(runner),
            "ledgermap": str(ledgermap),
            "firmwaremap": str(firmwaremap),
            "soak_uren": 24,
            "ssh_gebruiker": "nsroot",
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path, onveilige_naam


def test_the_server_refuses_to_start_on_a_target_name_run_id_cannot_use(
    config_met_onveilige_doelnaam,
    capsys,
):
    """Caught at configuration-read time, next to
    `_require_upgrade_hostkeys` - never at the first R0 call, where the
    same defect used to surface as "de run-naam voor deze fase is geen
    veilig pad-segment", a sentence about a `run` the operator never gave.

    Byte-exact against `_require_safe_upgrade_target_names()`'s own
    `ConfigError` text (also pinned, standalone, in
    `test_product_surface.py::test_the_backup_target_name_refusal_texts_are_frozen`)
    - not a substring, so this test cannot pass on mergefix's DIFFERENT
    refusal sentence for a doelnaam that happens to contain some other
    disallowed character."""
    from nsmcp.start import run as start_run

    path, onveilige_naam = config_met_onveilige_doelnaam
    code = start_run([str(path)])
    assert code == 1
    fout = capsys.readouterr().err
    assert fout == (
        f"Fout: doel {onveilige_naam} mag onderhoud_upgrade_fase uitvoeren maar de doelnaam "
        "is geen veilig pad-segment; onderhoud_upgrade_fase vormt uit deze doelnaam de eerste "
        "run-naam (alleen letters, cijfers, punt, liggend streepje en koppelteken)\n"
    )


def test_a_target_name_rejected_by_both_gates_shows_mergefixs_message(tmp_path, capsys):
    """Pins the ORDER the two independently-added gates now run in, so the
    next merge does not rediscover the shadowing above by surprise:
    `start._allowlist()` (mergefix's character grammar) reads
    `handelen.toegestaan` and runs BEFORE
    `start._require_safe_upgrade_target_names()` (a later fix) gets a
    look at the same doelnaam - see `start.build_server_from_config()`.
    A doelnaam BOTH gates would refuse (a space is outside `_allowlist()`'s
    `[A-Za-z0-9._-]` charset AND outside `is_safe_run_name()`'s path-segment
    grammar) therefore always surfaces mergefix's sentence, never the other
    gate's - proven here by asserting mergefix's own text is present and
    the other gate's
    "veilig pad-segment" clause is NOT."""
    onveilige_naam = "lab 02"
    export_dir = _export(tmp_path)
    knowledge_path = _knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": onveilige_naam,
                        "adres": "10.0.0.2",
                        "credentialTarget": "GJK/Test/lab-02/nitro-write",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": HOSTKEY,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# x", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    firmwaremap = _firmwaremap(tmp_path)
    runner = _nep_runner(tmp_path)
    verzamelscript = tmp_path / "verzamel.ps1"
    verzamelscript.write_text("# ongebruikt in deze test", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export_dir),
        "kennispad": str(knowledge_path),
        "doelen": str(targets_path),
        "verzamelscript": str(verzamelscript),
        "handelen": {
            "schrijfscript": str(schrijf),
            "fixturemap": str(tmp_path),
            "codekanaal": {"soort": "venster"},
            "toegestaan": {onveilige_naam: {"onderhoud_upgrade_fase": True}},
        },
        "onderhoud": {
            "runner": str(runner),
            "ledgermap": str(ledgermap),
            "firmwaremap": str(firmwaremap),
            "soak_uren": 24,
            "ssh_gebruiker": "nsroot",
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")

    from nsmcp.start import run as start_run

    code = start_run([str(path)])
    assert code == 1
    fout = capsys.readouterr().err
    assert "voldoet niet aan de eisen" in fout
    assert "veilig pad-segment" not in fout


def _config_met_doel_adres(tmp_path, *, adres: str = "10.0.0.2", hostkey: str = HOSTKEY):
    """A full CONFIG FILE (`start.py`'s
    own input) whose single target carries `adres`/`hostkey` as given - a
    VALID other field throughout, so only the ONE start-time check under
    test fires."""
    export_dir = _export(tmp_path)
    knowledge_path = _knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": TARGET_NAME,
                        "adres": adres,
                        "credentialTarget": "GJK/Test/netscaler-02/nitro-write",
                        "certificaat": "keten",
                        "ssh_hostsleutel_vingerafdruk": hostkey,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    schrijf = tmp_path / "schrijf.ps1"
    schrijf.write_text("# x", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    firmwaremap = _firmwaremap(tmp_path)
    runner = _nep_runner(tmp_path)
    verzamelscript = tmp_path / "verzamel.ps1"
    verzamelscript.write_text("# ongebruikt in deze test", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export_dir),
        "kennispad": str(knowledge_path),
        "doelen": str(targets_path),
        "verzamelscript": str(verzamelscript),
        "handelen": {
            "schrijfscript": str(schrijf),
            "fixturemap": str(tmp_path),
            "codekanaal": {"soort": "venster"},
            "toegestaan": {TARGET_NAME: {"onderhoud_upgrade_fase": True}},
        },
        "onderhoud": {
            "runner": str(runner),
            "ledgermap": str(ledgermap),
            "firmwaremap": str(firmwaremap),
            "soak_uren": 24,
            "ssh_gebruiker": "nsroot",
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_the_server_refuses_to_start_when_an_upgrade_target_has_a_hostname_address(
    tmp_path,
    capsys,
):
    """H2. `secondary_gate` compares Node ID 0's own `IP:` field against
    `-Adres` as a literal string, on purpose (no name lookup in the judging
    half) - so a target configured with a HOSTNAME can never match, and
    `doel is secondary` reads `niet beoordeeld` on every R1 and R5 forever.
    Caught at configuration-read time now, next to the hostkey and
    run-name-grammar checks, rather than as an undiagnosable `niet
    beoordeeld` the operator only discovers mid-upgrade."""
    from nsmcp.start import run as start_run

    path = _config_met_doel_adres(tmp_path, adres="ns01.uwdomein.local")
    code = start_run([str(path)])
    assert code == 1
    fout = capsys.readouterr().err
    assert f"doel {TARGET_NAME} mag onderhoud_upgrade_fase uitvoeren" in fout
    assert "ns01.uwdomein.local" in fout
    assert "geen letterlijk IPv4-adres" in fout


def test_the_legitimate_literal_ip_target_still_starts_fine(tmp_path):
    """H2's legitimate path: a target that DOES carry the NSIP as a literal
    IPv4 `adres` - exactly what the fix requires - builds without error and
    registers `onderhoud_upgrade_fase`. A gate that only refuses is how H2
    got here; this is the other half.

    `build_server_from_config()` directly, never `start.run()`: the latter
    calls the real, blocking stdio server on a valid config (`start.py`'s
    own `run()` docstring) - exactly what would hang this test."""
    import nsmcp.start as start

    path = _config_met_doel_adres(tmp_path, adres="10.0.0.2")
    server = start.build_server_from_config(path)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "onderhoud_upgrade_fase" in names


def test_the_server_refuses_to_start_when_an_upgrade_targets_hostkey_is_not_hex(
    tmp_path,
    capsys,
):
    """`target._normalize_fingerprint`
    strips `:`/`-` and uppercases but never validates hex.
    `ssh-keygen -l`'s own DEFAULT output shape - `SHA256:abcXYZ/+q` -
    normalizes to `SHA256ABCXYZ/+Q`, which is not valid hex.
    `_posh_ssh_wire_fingerprint()` would raise a bare `ValueError` on that
    the first time a phase call built its arguments, masked into the
    generic "Onverwachte fout" text. Caught at configuration-read time
    instead, with a message naming the expected form."""
    from nsmcp.start import run as start_run

    path = _config_met_doel_adres(tmp_path, hostkey="SHA256:abcXYZ/+q")
    code = start_run([str(path)])
    assert code == 1
    fout = capsys.readouterr().err
    assert f"doel {TARGET_NAME} mag onderhoud_upgrade_fase uitvoeren" in fout
    assert "geen geldige hex-vingerafdruk" in fout
    assert "SHA256:<base64>" in fout


def test_the_legitimate_hex_hostkey_target_still_starts_fine(tmp_path):
    """Minor's legitimate path: a target whose pinned hostkey IS valid hex
    (the `ssh-keygen -l -E md5` shape, colon-separated) builds without
    error and registers `onderhoud_upgrade_fase` - the same target every
    other test in this file already relies on, made explicit here."""
    import nsmcp.start as start

    path = _config_met_doel_adres(tmp_path, hostkey=HOSTKEY)
    server = start.build_server_from_config(path)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "onderhoud_upgrade_fase" in names


def test_a_phase_starts_and_the_call_returns_before_the_phase_ends(tmp_path, nep_runner, ledgermap):
    """Het gereedschap keert terug zodra de regel fase_gestart er staat, niet
    als de fase klaar is. Gemeten reden: R1 duurt 460 s en de tijdslimiet van
    een schrijftool is 300 s.

    Timing-sensitive assertion: the sleep and the
    threshold used to be the SAME 1.5 s - zero margin on a slow machine.
    The sleep is now 5 s and the threshold 3 s: `wait_for_start()` polls
    every 0.2 s, so a correct implementation returns in well under a
    second, and 3 s still leaves 2 full seconds of margin below the
    artificial delay - a slow CI runner cannot flip this test green for
    the wrong reason (it caught up with the sleep) or red for the right
    behaviour (it was merely slow to detect the ledger line)."""
    trage_runner = _nep_runner(tmp_path, "traag_maar_start.py", sleep_after_start_s=5.0)
    server = _server(tmp_path, runner=trage_runner, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    started_at = time.monotonic()
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    duration = time.monotonic() - started_at

    assert not r.isError, _text(r)
    assert "FASE GESTART" in _text(r)
    assert duration < 3.0, f"de aanroep wachtte {duration:.1f}s - dat is op de fase zelf, niet op fase_gestart"

    (ledger_file,) = list(ledgermap.glob("*.jsonl"))
    rows = read_ledger(ledger_file)
    assert any(r["gebeurtenis"] == "fase_gestart" and r["fase"] == "R0" for r in rows)


def test_a_phase_that_never_writes_fase_gestart_is_a_failure_after_twenty_seconds(
    tmp_path,
    traag_runner,
    ledgermap,
    monkeypatch,
):
    assert START_WAIT_S == 20

    # The 20 s deadline itself is upgrade.wait_for_start's own, already
    # measured in tests/test_upgrade.py - this test proves mcp_server.py
    # reports the right FAILURE when that deadline passes, without
    # actually waiting 20 real seconds in this suite.
    monkeypatch.setattr(mcp_server, "wait_for_start", lambda *a, **k: None)
    server = _server(tmp_path, runner=traag_runner, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    text = _text(r)
    assert (
        f"de fase heeft binnen {START_WAIT_S} seconden geen regel fase_gestart in het ledger "
        "geschreven; de fase telt niet als gestart" in text
    )
    # The detached child is not stopped when the wait expires, and cannot be -
    # the message must say so, not just that the ledger stayed silent.
    assert "losgekoppeld gestart en kan nog steeds draaien" in text
    assert "dit product kan dat proces niet stoppen" in text


def test_a_second_run_on_the_same_target_is_refused_while_one_is_open(
    tmp_path,
    ledger_lopend,
):
    """Weigering 2, on the phase that carries the whole
    single-writer guarantee: a LIVE open R0 on this target - started a
    second ago, nowhere near its ceiling - refuses a second run.

    An earlier version retargeted this test onto an open
    R1 (`ledger_with_open_r1` below) because bounded-by-nothing R0 adoption
    made the R0 case pass. The R0 case is the one the guarantee is about,
    so it is back here, and the R1 case kept its own test."""
    server = _server(tmp_path, ledgermap=ledger_lopend)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "er staat nog een fase open op dit doel; vraag de stand op met onderhoud_upgrade_stand" in _text(r)


def test_a_live_open_r0_is_not_adopted_and_no_second_runner_starts(tmp_path, ledger_lopend):
    """The same refusal, proven by what did NOT happen on the appliance.

    RED before the fix: `open_phases()` was
    called with no clock, so every open phase came back `expired=False` and
    R0 adopted ANY open R0 on the target - including one that started a
    second ago. `run_name` then EQUALLED the adopted run, so the open-phase
    refusal below it (`open_phase.run != run_name`) never fired,
    `order_gate("R0", ...)` is `open` unconditionally, and `start_detached`
    launched a SECOND runner against the same appliance and the same ledger
    file. This test reads that ledger file: a second `fase_gestart` row for
    the still-open R0 IS the second writer."""
    ledger_file = ledger_lopend / "andere-run.jsonl"
    before = len(read_ledger(ledger_file))
    server = _server(tmp_path, ledgermap=ledger_lopend)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError, _text(r)
    assert "er staat nog een fase open op dit doel" in _text(r)
    assert len(read_ledger(ledger_file)) == before, (
        "een tweede faserunner heeft in het ledger van de openstaande run geschreven"
    )


def test_a_second_run_is_refused_while_a_foreign_r1_is_open(tmp_path, ledger_with_open_r1):
    """The same refusal one phase further on: the foreign run closed its R0
    and is now inside R1. Nothing about R0's adoption rule may open this
    door either."""
    server = _server(tmp_path, ledgermap=ledger_with_open_r1)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "er staat nog een fase open op dit doel; vraag de stand op met onderhoud_upgrade_stand" in _text(r)


def test_a_live_open_r1_of_the_callers_own_run_is_not_re_entered_and_no_second_runner_starts(
    tmp_path,
):
    """The R1 twin of test_a_live_open_r0_is_not_adopted_and_no_second_runner_starts:
    an earlier fix closed this hole for R0
    ("alleen een VERLOPEN open fase" is adopted), but left R1..R6 open -
    `blocking_phase(..., except_run=run_name)` skipped EVERY non-expired
    open phase of the run being called, including the caller's OWN live
    one. So `fase=R1 run=A` while A's R1 was 60 seconds into a
    460-second upload could start a SECOND runner against the same
    appliance and the same ledger file, simply by being invoked again
    with the SAME run name. This reads the ledger file: a second
    `fase_gestart` row for the still-open R1 IS the second writer."""
    run = "mijn-eigen-lopende-run"
    m = tmp_path / "ledger"
    m.mkdir()
    now = datetime.now(UTC)
    append_line(
        m / f"{run}.jsonl",
        _regel(
            run=run,
            fase="R0",
            gebeurtenis="voormeting_vast",
            uitkomst="geslaagd",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    append_line(
        m / f"{run}.jsonl",
        _regel(
            run=run,
            fase="R1",
            gebeurtenis="fase_gestart",
            uitkomst="gestart",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    ledger_file = m / f"{run}.jsonl"
    before = len(read_ledger(ledger_file))

    server = _server(tmp_path, ledgermap=m)
    code, _ = _propose(server, fase="R1", run=run)

    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": run, "bevestiging": code})
    assert r.isError, _text(r)
    assert "er staat nog een fase open op dit doel; vraag de stand op met onderhoud_upgrade_stand" in _text(r)
    assert len(read_ledger(ledger_file)) == before, (
        "een tweede faserunner heeft in het ledger van de eigen, nog lopende run geschreven"
    )


def test_a_genuine_refusal_on_the_execution_leg_is_not_masked_by_an_unknown_key(tmp_path):
    """Dezelfde bevinding als in test_mcp_server.py,
    maar op de UITVOERINGSpoot van onderhoud_upgrade_fase - waar de code al
    is ingewisseld (confirmations.redeem) vlak voordat een echte weigering
    (hier: weigering 2, een al open fase op dit doel) optreedt. Een
    onbekende sleutel in dezelfde aanroep mag die echte weigering niet
    vervangen door de onbekend-argument-hint: de beheerder zou anders de
    naam "herstellen" terwijl de code al verbrand is en de werkelijke reden
    nooit getoond werd."""
    run = "mijn-eigen-lopende-run-i1"
    m = tmp_path / "ledger"
    m.mkdir()
    now = datetime.now(UTC)
    append_line(
        m / f"{run}.jsonl",
        _regel(
            run=run,
            fase="R0",
            gebeurtenis="voormeting_vast",
            uitkomst="geslaagd",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    append_line(
        m / f"{run}.jsonl",
        _regel(
            run=run,
            fase="R1",
            gebeurtenis="fase_gestart",
            uitkomst="gestart",
            gestart=now.isoformat().replace("+00:00", "Z"),
        ),
    )
    server = _server(tmp_path, ledgermap=m)
    code, _ = _propose(server, fase="R1", run=run)

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": run,
            "bevestiging": code,
            "onbekende_sleutel": "x",
        },
    )
    assert r.isError, _text(r)
    assert "er staat nog een fase open op dit doel; vraag de stand op met onderhoud_upgrade_stand" in _text(r)
    assert "onbekend argument" not in _text(r)


def test_d1_a_geweigerd_marker_line_is_fully_masked_not_just_known_values(tmp_path):
    """Gemeten (17-9-2026): de GEWEIGERD-tak koos
    de rauwe markerregel VOOR `_from_script()` ooit draaide -
    `_marker(stdout, "[GEWEIGERD]") or _from_script(...)` kort sluit op de
    marker zodra die bestaat, dus bekende adres- en credential-waarden in
    die regel liepen ongemaskeerd door, terwijl dezelfde tekst ZONDER
    marker via `_from_script()` wel gemaskeerd zou zijn. De regel gaat nu
    eerst door `_from_script()`."""
    server = _server(tmp_path)
    address = "10.0.0.2"  # het adres dat _targets_file() voor dit doel configureert
    credential = "GJK/Test/netscaler-02/nitro-write"  # idem, credentialTarget
    with patch.object(
        mcp_server,
        "run_upgrade_preview",
        return_value=(1, f"[GEWEIGERD] failed {address} {credential}\n", ""),
    ):
        r = _call(server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1"})
    assert r.isError, _text(r)
    tekst = _text(r)
    assert address not in tekst, tekst
    assert credential not in tekst, tekst
    assert "<adres>" in tekst, tekst
    assert "<credential-target>" in tekst, tekst


def _action_log_lines(captured: str) -> list:
    from nsmcp.mcp_server import ACTION_LOG_PREFIX

    rows = []
    for line in captured.splitlines():
        if line.startswith(ACTION_LOG_PREFIX):
            rows.append(json.loads(line[len(ACTION_LOG_PREFIX) :].strip()))
    return rows


def test_the_soak_window_refuses_every_phase_on_the_same_target(tmp_path, ledgermap):
    """De UITVOERINGSpoort (A1: "dubbel is hier goed, de uitvoering is de
    waarheid") blijft ook nu het VOORSTEL zijn eigen soakpoort heeft
    (zie hieronder): het venster kan opengaan NADAT een geldige code al is
    uitgegeven - een ander runs R6 sluit in de tussentijd de soak - en dat
    moet de uitvoering nog steeds weigeren. Propose dus terwijl er nog geen
    open venster is, open het venster daarna, en bevestig pas dan."""
    server = _server(tmp_path, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    now = datetime.now(UTC)
    append_line(
        ledgermap / "vorige-run.jsonl",
        _regel(
            run="vorige-run",
            fase="R6",
            gebeurtenis="soak_open",
            uitkomst="geslaagd",
            gestart=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        ),
    )

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "het soakvenster loopt nog tot" in _text(r)


def test_the_voorstel_step_also_refuses_during_the_soak_window(tmp_path, ledger_soak_open, capsys):
    """A1: het VOORSTEL toetste het soakvenster tot nu toe niet - alleen de
    UITVOERING deed dat, dus een voorstel binnen het venster gaf gewoon een
    code uit die de beheerder nooit geldig kon inwisselen (die code
    verbrandde stil bij de latere weigering). Fix: dezelfde soakpoort, met
    dezelfde weigeringszin, al bij het voorstel - voor er een code wordt
    uitgegeven en voor er een actielogregel "voorstel" ontstaat."""
    server = _server(tmp_path, ledgermap=ledger_soak_open)

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )

    assert r.isError, _text(r)
    assert "het soakvenster loopt nog tot" in _text(r)
    assert server.code_spy.codes == [], "het voorstel mag binnen het soakvenster geen code uitgeven"
    uitkomsten = [row["uitkomst"] for row in _action_log_lines(capsys.readouterr().err)]
    assert "voorstel" not in uitkomsten


def test_the_confirmation_code_is_bound_to_the_target_label_including_the_phase(tmp_path):
    """Een code voor R1 dekt geen R3 af."""
    server = _server(tmp_path)
    code_r1, _ = _propose(server, fase="R1", run="een-vorige-run")
    code_r3, _ = _propose(server, fase="R3", run="een-vorige-run")
    assert code_r1 != code_r3

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R3",
            "run": "een-vorige-run",
            "bevestiging": code_r1,
        },
    )
    assert r.isError
    assert "hoort bij een andere handeling of een ander doel" in _text(r)


def test_the_confirmation_code_is_bound_to_the_target_label_including_the_build(tmp_path, ledgermap):
    """Een code voor build 72.57 dekt geen 66.59 - het
    voorheen ongeteste stuk van de docstring hierboven, nu zijn eigen test.
    Het [TARGET]-etiket waaraan de code gebonden is draagt de doelbuild
    (de nep-runner drukt hem af), en die verandert als de firmwaremap
    tussen voorstel en bevestiging verandert - precies zo'n verandering
    hoort een code niet te dekken."""
    firmwaremap = tmp_path / "firmware"
    firmwaremap.mkdir()
    bundle_72 = firmwaremap / f"build-{DOELBUILD}_nc_64.tgz"
    bundle_72.write_bytes(b"72.57")
    server = _server(tmp_path, firmwaremap=firmwaremap, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    # De firmwaremap draagt nu build 66.59 in plaats van 72.57.
    bundle_72.unlink()
    (firmwaremap / "build-14.1-66.59_nc_64.tgz").write_bytes(b"66.59")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "hoort bij een andere handeling of een ander doel" in _text(r)


def test_the_cleanup_argument_is_part_of_the_confirmed_label(tmp_path):
    """oude_buildbomen_opruimen staat in het [TARGET]-etiket; een mens bevestigt
    de opruiming zelf."""
    server = _server(tmp_path)
    code_zonder, _ = _propose(server, fase="R1", run="een-vorige-run")
    code_met, _ = _propose(server, fase="R1", run="een-vorige-run", oude_buildbomen_opruimen=True)
    assert code_zonder != code_met

    labels = [c["target"] for c in server.code_spy.calls]
    assert labels[0] != labels[1]
    assert "oude buildbomen opruimen" not in labels[0]
    assert "oude buildbomen opruimen" in labels[1]

    # De code zonder opruiming dekt de aanroep MET opruiming niet af.
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "een-vorige-run",
            "oude_buildbomen_opruimen": True,
            "bevestiging": code_zonder,
        },
    )
    assert r.isError
    assert "hoort bij een andere handeling of een ander doel" in _text(r)


def test_the_runner_never_removes_a_build_tree_without_the_confirmed_argument(tmp_path, nep_runner, ledgermap):
    server = _server(tmp_path, runner=nep_runner, ledgermap=ledgermap)
    for run_name in ("run-a", "run-b"):
        for regel in _r0_gesloten(run_name, gestart="2026-09-06T08:00:00Z", geeindigd="2026-09-06T08:05:00Z"):
            append_line(ledgermap / f"{run_name}.jsonl", regel)

    code_zonder, _ = _propose(server, fase="R1", run="run-a")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "run-a",
            "bevestiging": code_zonder,
        },
    )
    assert not r.isError, _text(r)
    # Close out run-a's R1 by hand so the target-wide open-run check does
    # not refuse run-b next - this test is about the cleanup ARGUMENT, the
    # open-run refusal has its own dedicated test above.
    append_line(
        ledgermap / "run-a.jsonl",
        _regel(run="run-a", fase="R1", gebeurtenis="fase_geslaagd", uitkomst="geslaagd"),
    )

    code_met, _ = _propose(server, fase="R1", run="run-b", oude_buildbomen_opruimen=True)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "run-b",
            "oude_buildbomen_opruimen": True,
            "bevestiging": code_met,
        },
    )
    assert not r.isError, _text(r)

    argv_files = sorted(ledgermap.glob("*.argv.json"))
    all_argv = [json.loads(row) for path in argv_files for row in path.read_text(encoding="utf-8").splitlines()]
    zonder_run = [a for a in all_argv if "run-a" in a and "-Actieid" in a]
    met_run = [a for a in all_argv if "run-b" in a and "-Actieid" in a]
    assert zonder_run and all("-OudeBuildbomenOpruimen" not in a for a in zonder_run)
    assert met_run and all("-OudeBuildbomenOpruimen" in a for a in met_run)


def test_a_phase_without_a_rollback_point_is_refused(tmp_path, ledger_zonder_r0):
    """R1 zonder een gesloten R0."""
    server = _server(tmp_path, ledgermap=ledger_zonder_r0)
    code, _ = _propose(server, fase="R1", run="run-zonder-r0")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "run-zonder-r0",
            "bevestiging": code,
        },
    )
    assert r.isError
    assert "fase R0 is niet gesloten; deze fase kan niet starten" in _text(r)


def test_a_closed_phase_is_refused_before_the_runner_launches_not_after(
    tmp_path,
    ledger_r1_gesloten,
    nep_runner,
):
    """R1 already closed `poort dicht` in
    run-a's own file. A retry of R1 on the SAME run must be refused HERE -
    before the faserunner is ever launched a second time - not only inside
    `upgrade_gate.main()`'s `ClosedPhaseError`, which fires AFTER the
    appliance work already ran and appends no closing row.

    Proven by absence, not just by the refusal text: `onderhoud_upgrade_fase`
    re-validates with its own `-WatIs` preflight on EVERY confirmed call
    (unconditionally, before any weigering) - so a second `-WatIs` argv
    entry is expected either way and proves nothing about H1. What must
    stay absent is a REAL launch: no argv entry without `-WatIs` (that is
    `build_upgrade_arguments(preview=False, ...)`, reached only after every
    weigering passes), no `.log` file for this run (written only by
    `start_detached()`), and no new ledger row - if the fix regressed to
    only refusing inside the subprocess, all three would appear."""
    server = _server(tmp_path, ledgermap=ledger_r1_gesloten, runner=nep_runner)
    code, _ = _propose(server, fase="R1", run="run-a")

    (ledger_bestand,) = ledger_r1_gesloten.glob("*.jsonl")
    regels_voor = ledger_bestand.read_text(encoding="utf-8")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "run-a",
            "bevestiging": code,
        },
    )

    assert r.isError
    assert (
        "de fase wordt niet opnieuw gestart: deze fase staat al gesloten in het ledger van "
        "deze run; wie deze fase opnieuw wil proberen, start een nieuwe run"
    ) in _text(r)
    assert ledger_bestand.read_text(encoding="utf-8") == regels_voor
    assert not list(ledger_r1_gesloten.glob("*.log"))
    for argv_pad in ledger_r1_gesloten.glob("*.argv.json"):
        for regel in argv_pad.read_text(encoding="utf-8").splitlines():
            assert "-WatIs" in json.loads(regel)


def test_a_closed_phase_can_still_be_retried_as_a_new_run(
    tmp_path,
    ledger_r1_gesloten_plus_nieuwe_run,
    nep_runner,
    monkeypatch,
):
    """H1's legitimate path: "wie deze fase opnieuw wil proberen, start een
    nieuwe run" is not just a sentence - a genuinely NEW run (run-c, its own
    R0 already closed `geslaagd`) still starts R1 normally, even though an
    EARLIER run (run-a) on the very same target already closed R1 `poort
    dicht`. A gate that only refuses is how H1 got here; this is the other
    half.

    `sys.executable` is monkeypatched to `sys._base_executable` (the real
    interpreter behind a venv's `Scripts\\python.exe` launcher stub, on
    every CPython >= 3.11 that has one) purely as a LOCAL environment
    workaround, not a product change: on this machine's venv, launching the
    launcher STUB itself with `DETACHED_PROCESS` (`start_detached()`,
    `handelen.py`) hangs indefinitely at the OS level with near-zero CPU -
    reproduced with a two-line synthetic script that has nothing to do with
    this codebase, and identically on SEVEN already-passing, wholly
    unmodified tests in this same file (`test_a_phase_starts_and_the_call_
    returns_before_the_phase_ends` among them) run against unmodified
    `1ad0c00`. Launching the BASE interpreter directly does not hang. Where
    `sys._base_executable` is absent (not a venv, or an older CPython), this
    falls back to `sys.executable` unchanged - a no-op there."""
    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledger_r1_gesloten_plus_nieuwe_run, runner=nep_runner)
    code, _ = _propose(server, fase="R1", run="run-c")

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R1",
            "run": "run-c",
            "bevestiging": code,
        },
    )

    assert not r.isError, _text(r)
    assert "FASE GESTART" in _text(r)
    regels = read_ledger(next(ledger_r1_gesloten_plus_nieuwe_run.glob("run-c.jsonl")))
    assert any(regel.get("fase") == "R1" and regel.get("gebeurtenis") == "fase_gestart" for regel in regels)


GEHEIM = "GEHEIM-niet-echt-CorrectHorseBatteryStaple-9f3a"


def test_the_runner_never_writes_a_secret_anywhere(tmp_path, nep_runner, ledgermap, capsys, monkeypatch):
    """Niet in een argument, niet in het ledger, niet op stdout, niet in de
    actielogboekregel. Alleen de targetnaam.

    The old `"wachtwoord" not in text.lower()` line
    could never fail - nothing anywhere in this test ever wrote that word,
    so it measured nothing (an earlier skeleton line `assert GEHEIM
    not in text` was never carried over). `GEHEIM` here is a synthetic
    secret placed in THIS TEST PROCESS's environment - exactly the shape of
    a real leak (a stray credential left in a shell's environment, or a
    future debug/verbose mode that dumps `os.environ` into a log line) -
    and the subprocess this code starts INHERITS that environment by
    default (`start_detached`/`run_upgrade_preview` pass no `env=`
    override, so nothing strips it). Nothing in this whole call path reads
    `os.environ` for a secret today, so this assertion is real: it fails
    the moment something starts echoing the environment anywhere in this
    pipeline - proven below by temporarily making the nep-runner do exactly
    that (RED evidence in the fix report), then reverting."""
    monkeypatch.setenv("GJK_ZOU_NOOIT_GELEKT_MOGEN_WORDEN", GEHEIM)
    server = _server(tmp_path, runner=nep_runner, ledgermap=ledgermap)
    code, voorstel_tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)

    (ledger_file,) = list(ledgermap.glob("*.jsonl"))
    for row in read_ledger(ledger_file):
        text = json.dumps(row)
        assert "wachtwoord" not in text.lower()
        assert code not in text
        assert GEHEIM not in text

    assert code not in _text(r)
    assert GEHEIM not in _text(r)
    assert code not in voorstel_tekst
    assert GEHEIM not in voorstel_tekst
    for argv_pad in ledgermap.glob("*.argv.json"):
        inhoud = argv_pad.read_text(encoding="utf-8")
        assert code not in inhoud
        assert GEHEIM not in inhoud
    for log_pad in ledgermap.glob("*.log"):
        inhoud = log_pad.read_text(encoding="utf-8", errors="replace")
        assert code not in inhoud
        assert GEHEIM not in inhoud


def test_the_phase_argument_only_accepts_r0_to_r6():
    for slecht in ("R7", "R-1", "", "0", "R99"):
        with pytest.raises(Refusal) as fout:
            validate_phase_arguments({"fase": slecht, "run": "x"})
        assert fout.value.code == "onbekend-argument"
    # r0 (lowercase) IS accepted - it is normalized before the check.
    schoon = validate_phase_arguments({"fase": "r0", "snapshotverwijzing": "chk"})
    assert schoon["fase"] == "R0"


def test_a_phase_specific_argument_on_the_wrong_phase_is_refused():
    """snapshotverwijzing alleen bij R0, drift_geaccepteerd en
    oude_buildbomen_opruimen alleen bij R1."""
    with pytest.raises(Refusal) as fout:
        validate_phase_arguments({"fase": "R2", "snapshotverwijzing": "chk-1", "run": "x"})
    assert fout.value.code == "onbekend-argument"

    with pytest.raises(Refusal):
        validate_phase_arguments(
            {
                "fase": "R0",
                "snapshotverwijzing": "chk-1",
                "drift_geaccepteerd": "True",
            }
        )

    with pytest.raises(Refusal):
        validate_phase_arguments(
            {
                "fase": "R2",
                "run": "x",
                "oude_buildbomen_opruimen": "True",
            }
        )

    # At the RIGHT phase, both are accepted.
    schoon = validate_phase_arguments(
        {
            "fase": "R1",
            "run": "x",
            "drift_geaccepteerd": "True",
            "oude_buildbomen_opruimen": "True",
        }
    )
    assert schoon["drift_geaccepteerd"] is True
    assert schoon["oude_buildbomen_opruimen"] is True


# ---------------------------------------------------------------------------
# `run` becomes a filesystem path stem
# (`onderhoud.ledgermap / f"{run}.jsonl"`) and was never validated as one -
# a path separator, '..', a drive letter, a UNC prefix, an ADS marker, a
# reserved Windows device name, a trailing dot/space or a control character
# could all escape `onderhoud.ledgermap`. This closes it.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "malicious",
    [
        "..",
        "../evil",
        "..\\evil",
        "sub/../../evil",
        "a/b",
        "a\\b",
        "/etc/passwd",
        "C:\\Windows\\System32\\evil",
        "\\\\server\\share\\evil",
        "CON",
        "run.",
    ],
)
def test_an_unsafe_operator_supplied_run_is_refused_on_form(malicious):
    """RED case 1/2/3 (task): a path separator, '..', an absolute/UNC path -
    `validate_phase_arguments()` is the SAME seam every other phase
    argument is checked on (fase, snapshotverwijzing), so this raises
    BEFORE `_upgrade_work()` ever reads a target, a ledger row or builds a
    path - the earliest possible refusal in the whole call."""
    with pytest.raises(Refusal) as exc:
        validate_phase_arguments({"fase": "R1", "run": malicious})
    assert exc.value.code == "run-naamgrammatica"


def test_a_safe_operator_supplied_run_still_passes():
    """Regression guard: the new check must not refuse the ordinary shapes
    R1..R6 already exercise elsewhere in this file (`run-a`, `een-vorige-run`,
    a real `run_id()` value)."""
    for safe_value in ("run-a", "een-vorige-run", "20260906T120000Z-lab-02"):
        clean = validate_phase_arguments({"fase": "R1", "run": safe_value})
        assert clean["run"] == safe_value


def _malicious_stale_r0_ledger(tmp_path: Path, *, malicious_run: str) -> Path:
    """A stale (past-ceiling) R0 `fase_gestart` row whose OWN `run` field
    tries to escape `ledgermap` - a value from a file this product does not
    control, never typed by an operator. The row is past
    `NO_CEILING_FALLBACK_S`, the same shape `ledger_stale_r0` above uses, so
    R0 attempts to ADOPT it rather than refuse it as still open."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir(exist_ok=True)
    moment = datetime.now(UTC) - timedelta(seconds=NO_CEILING_FALLBACK_S + 120)
    stamp = moment.isoformat().replace("+00:00", "Z")
    row = _regel(run=malicious_run, fase="R0", gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stamp)
    row["tijd"] = stamp
    # The LEDGER FILE itself keeps a safe, product-chosen name - the attack
    # lives entirely inside the row's `run` FIELD, the one `open_phases()`
    # reads and R0's adoption logic hands straight to `run_name`.
    append_line(ledgermap / "adopted-run-source.jsonl", row)
    return ledgermap


@pytest.mark.parametrize(
    "malicious_run",
    [
        "..\\..\\evil",
        "../../evil",
        "..\\outside-ledgermap",
        "../outside-ledgermap",
    ],
)
def test_an_adopted_run_that_tries_to_escape_ledgermap_is_refused(tmp_path, malicious_run):
    """RED case 4 (task): an ADOPTED run name read back out of a ledger
    row - not typed by the operator at all, and therefore never checked by
    `validate_phase_arguments()` - is the more interesting attack path.
    Refused before the faserunner preview is ever invoked and before
    anything is written: the ledger directory holds, after the call,
    EXACTLY the one file this fixture wrote itself and nothing else -
    no `.argv.json`, no `.log`, and nothing outside `ledgermap` either."""
    ledgermap = _malicious_stale_r0_ledger(tmp_path, malicious_run=malicious_run)
    before = sorted(p.name for p in ledgermap.iterdir())
    outside_ledgermap = tmp_path / "evil.jsonl"

    server = _server(tmp_path, ledgermap=ledgermap)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )

    assert r.isError, _text(r)
    after = sorted(p.name for p in ledgermap.iterdir())
    assert after == before, after
    assert not outside_ledgermap.exists()


# ---------------------------------------------------------------------------
# The honest ActionError from
# handelen._firmware_target_build() must reach the operator instead of
# _guarded_async's generic "Onverwachte fout" masking.
# ---------------------------------------------------------------------------


def _empty_firmwaremap(tmp_path: Path) -> Path:
    m = tmp_path / "firmware-leeg"
    m.mkdir()
    return m


def _double_firmwaremap(tmp_path: Path) -> Path:
    m = tmp_path / "firmware-dubbel"
    m.mkdir()
    (m / f"build-{DOELBUILD}_nc_64.tgz").write_bytes(b"een")
    (m / "build-14.1-66.59_nc_64.tgz").write_bytes(b"twee")
    return m


def _mismatched_firmwaremap(tmp_path: Path) -> Path:
    m = tmp_path / "firmware-mismatch"
    m.mkdir()
    (m / "NSVPX-Firmware-14.1-72.57.tgz").write_bytes(b"niet-de-verwachte-vorm")
    return m


@pytest.mark.parametrize(
    "maker,expected",
    [
        (_empty_firmwaremap, "draagt geen firmwarebundel van de vorm"),
        (_double_firmwaremap, "draagt meer dan een firmwarebundel"),
        (_mismatched_firmwaremap, "draagt geen firmwarebundel van de vorm"),
    ],
    ids=["leeg", "dubbel", "verkeerde-naam"],
)
def test_an_honest_firmware_error_reaches_the_operator_instead_of_the_generic_message(
    tmp_path,
    maker,
    expected,
):
    """`_firmware_target_build()`'s honest
    sentence ("onderhoud.firmwaremap draagt ...") used to be raised OUTSIDE
    every local `try` in `mcp_server._upgrade_work()`, so it ran on into
    `_guarded_async`'s bare `except Exception -> mask_error()` and came out
    as the generic "Onverwachte fout" text - an empty, doubly-filled or
    non-matching firmware directory is the most likely misconfiguration in
    this whole chapter, and it was undiagnosable."""
    firmwaremap = maker(tmp_path)
    server = _server(tmp_path, firmwaremap=firmwaremap)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )
    assert r.isError
    text = _text(r)
    assert "Onverwachte fout" not in text
    assert "onderhoud.firmwaremap" in text
    assert expected in text


# ---------------------------------------------------------------------------
# `-Actieregister` is wired through when
# `onderhoud.actieregister` is configured, and omitted when it is not.
# ---------------------------------------------------------------------------


def _argv_seen(ledgermap: Path) -> list[list[str]]:
    argv_files = sorted(ledgermap.glob("*.argv.json"))
    return [json.loads(row) for path in argv_files for row in path.read_text(encoding="utf-8").splitlines()]


def test_actieregister_is_passed_to_the_runner_when_configured(tmp_path, nep_runner, ledgermap):
    actieregister = tmp_path / "actieregister.jsonl"
    server = _server(
        tmp_path,
        runner=nep_runner,
        ledgermap=ledgermap,
        actieregister=actieregister,
    )
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)

    all_argv = _argv_seen(ledgermap)
    confirmed = [a for a in all_argv if "-Actieid" in a]
    assert confirmed
    for argv in confirmed:
        assert "-Actieregister" in argv
        assert argv[argv.index("-Actieregister") + 1] == str(actieregister)


def test_actieregister_is_omitted_when_not_configured(tmp_path, nep_runner, ledgermap):
    server = _server(tmp_path, runner=nep_runner, ledgermap=ledgermap)
    assert server.onderhoud.actieregister is None
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)

    all_argv = _argv_seen(ledgermap)
    confirmed = [a for a in all_argv if "-Actieid" in a]
    assert confirmed
    for argv in confirmed:
        assert "-Actieregister" not in argv


def test_an_honest_firmware_error_reaches_the_operator_on_a_confirmed_call_too(tmp_path, monkeypatch):
    """The SECOND call site (mcp_server.py, `real_args = build_upgrade_arguments(...)`
    right after redeem) gets the same honest sentence - and, unlike the
    proposal-time failure, says the code was CONSUMED. `_upgrade_work()`
    re-runs the PREVIEW even on a confirmed call, so a firmware directory
    that is ALREADY broken before the call fails at the FIRST (preview)
    call site instead (proven above) - to reach the second, THIS test
    makes `build_upgrade_arguments()` fail only on its SECOND invocation
    within one confirmed request (the preview re-run succeeds, so the flow
    reaches redeem; only the real-args build then fails), simulating the
    firmware directory changing in the narrow window between the two.
    "De bevestigingscode is verbruikt" is what distinguishes this call
    site's own framing from the proposal-time one ("niet ingewisseld")."""
    server = _server(tmp_path)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    origineel = mcp_server.build_upgrade_arguments
    attempts = {"n": 0}

    def failing_on_the_second_attempt(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 2:
            raise ActionError("onderhoud.firmwaremap draagt meer dan een firmwarebundel (gesimuleerd voor deze test)")
        return origineel(*args, **kwargs)

    monkeypatch.setattr(mcp_server, "build_upgrade_arguments", failing_on_the_second_attempt)

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError
    text = _text(r)
    assert "Onverwachte fout" not in text
    assert "draagt meer dan een firmwarebundel (gesimuleerd voor deze test)" in text
    assert "De bevestigingscode is verbruikt" in text


# ---------------------------------------------------------------------------
# EVERY write tool on a target refuses while a
# phase is open on that target - not only onderhoud_upgrade_fase on itself.
# ---------------------------------------------------------------------------


def test_a_second_write_tool_is_refused_while_a_phase_is_open_on_the_same_target(tmp_path):
    """The single-writer gate is released while the phase is
    still running (the detached runner uploads for ~460s afterwards) - so
    EVERY write tool must refuse on a target with an open phase, reusing
    the same open-run check and pinned sentence onderhoud_upgrade_fase
    already runs on itself."""
    server = _two_target_write_server(tmp_path, open_target=TARGET_NAME)
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r.isError
    assert "er staat nog een fase open op dit doel; vraag de stand op met onderhoud_upgrade_stand" in _text(r)


def test_a_preview_without_an_actieid_is_refused_before_a_code_is_ever_issued(tmp_path):
    """`scripts/README.md`'s own contract: "Elke
    aanroep (ook -WatIs) drukt af: [TARGET] ... [ACTIEID] ..." - EVERY call,
    including a preview, is contractually required to print BOTH labels.
    A preview that gives a target but no actie-id used to go undetected
    here: a CONFIRMED call would then build `-Actieid`-less real arguments
    and only find out 20 seconds later, via the generic 'geen regel
    fase_gestart' message, that the real runner refused it. Checking
    `actie_id_voorstel` fails closed immediately with the honest detail -
    and, since this is the FIRST (unconfirmed) call, before any
    confirmation code is even issued."""
    runner_without_actieid = _nep_runner(tmp_path, "zonder_actieid.py", write_actieid=False)
    server = _server(tmp_path, runner=runner_without_actieid)

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )
    assert r.isError
    text = _text(r)
    assert "voorstel kon niet worden opgesteld" in text
    assert not server.code_spy.calls, "er is een code uitgegeven zonder geldig actie-id"


_ACTIEID_ON_FIRST_CALL_ONLY_RUNNER = '''\
"""A NEP-runner that honours [ACTIEID] on its FIRST call (the proposal) but
drops it on every later call - simulating a runner that stops honouring its
own documented contract (scripts/README.md: "Elke aanroep (ook -WatIs)
drukt af: [TARGET] ... [ACTIEID] ...") mid-flow, so the SECOND (confirmed)
call's own re-run of the preview is the one that is missing it."""
import sys
from pathlib import Path

argv = sys.argv[1:]
teller_pad = Path(__file__).with_suffix(".teller")
teller = int(teller_pad.read_text()) if teller_pad.exists() else 0
teller_pad.write_text(str(teller + 1))

doel = argv[argv.index("-Doel") + 1] if "-Doel" in argv else ""
adres = argv[argv.index("-Adres") + 1] if "-Adres" in argv else ""
fase = argv[argv.index("-Fase") + 1] if "-Fase" in argv else ""
doelbuild = argv[argv.index("-Doelbuild") + 1] if "-Doelbuild" in argv else ""
print(f"[TARGET] {doel} ({adres}) - fase {fase} naar build {doelbuild}")
if teller == 0:
    print("[ACTIEID] upgrade-eerste-aanroep")
sys.exit(0)
'''


def test_a_confirmed_call_without_an_actieid_in_the_preview_is_refused_immediately(
    tmp_path,
    ledgermap,
):
    """Same check, on the CONFIRMED path specifically: a runner that still
    honours [ACTIEID] on the PROPOSAL (so a valid code IS issued) but drops
    it on the confirmed call's own re-run of the preview - proving the
    fix reaches BOTH branches, not only the propose-time one covered
    above, and that the confirmed path fails FAST instead of waiting the
    full START_WAIT_S for a ledger line that will never appear."""
    runner = tmp_path / "actieid_alleen_eerste_keer.py"
    runner.write_text(_ACTIEID_ON_FIRST_CALL_ONLY_RUNNER, encoding="utf-8")
    server = _server(tmp_path, runner=runner, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    started_at = time.monotonic()
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    duration = time.monotonic() - started_at

    assert r.isError
    assert duration < 5, f"de weigering wachtte {duration:.1f}s - hoort meteen te komen, niet na START_WAIT_S"
    text = _text(r)
    assert "geen regel fase_gestart" not in text
    assert "de controle vooraf mislukte" in text


def test_a_second_write_tool_is_allowed_on_a_different_target(tmp_path):
    """The counter-probe: the SAME server, a target with NO open phase, is
    not caught by the new gate - it must not become a blanket refusal."""
    server = _two_target_write_server(tmp_path, open_target=TARGET_NAME)
    r = _call(server, "onderhoud_backup_maken", {"doel": SECOND_TARGET_NAME})
    assert not r.isError, _text(r)
    assert "VOORSTEL" in _text(r)


# ---------------------------------------------------------------------------
# The cross-tool refusal must have an EXIT.
#
# The gate added earlier had no age bound and no
# `!= run_name` exemption, and `open_run` has no time bound either: any
# target row with `fase_gestart` and no closing row refused EVERY other
# write tool forever. That state is reachable along a documented path -
# `scripts/README.md`'s exit code 3 ("de runner kon zijn werk niet eens
# proberen te voltooien ... er komt geen sluitregel in het ledger") happens
# AFTER `fase_gestart` is written, as does a killed detached runner, which
# this product admits it cannot stop.
# ---------------------------------------------------------------------------


def _seconds_ago(seconds: int) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=seconds)


def test_a_phase_still_within_its_ceiling_keeps_every_other_write_tool_out(tmp_path):
    """The half of the gate that must NOT change: an R1 that started one
    minute ago is genuinely still running (its ceiling is 3600 s), so the
    refusal stands - the single-writer window the detached start opens is
    real."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R1",
        open_started=_seconds_ago(60),
    )
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert r.isError
    assert "er staat nog een fase open op dit doel" in _text(r)


def test_a_phase_past_its_ceiling_no_longer_locks_the_other_write_tools(tmp_path):
    """The EXIT. An R1 whose `fase_gestart` is older than PHASE_LIMITS_S['R1']
    (3600 s) with no closing row is not `open` any more - it is `mislukt`
    with reason `tijdslimiet`, the word `upgrade.py` already writes for
    exactly this - so the refusal lifts by itself."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R1",
        open_started=_seconds_ago(3600 + 120),
    )
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert not r.isError, _text(r)
    assert "VOORSTEL" in _text(r)


def test_the_lifted_refusal_says_why_it_lifted(tmp_path):
    """... and it does not lift SILENTLY: the answer names the phase, its
    ceiling and the fact that no closing row was ever written, so the
    operator learns WHY the refusal is gone instead of finding it missing."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R1",
        open_started=_seconds_ago(3600 + 120),
    )
    text = _text(_call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME}))
    assert "tijdslimiet" in text
    assert "R1" in text
    assert "3600" in text
    assert "sluitregel" in text


def test_a_phase_with_no_ceiling_of_its_own_still_lets_the_refusal_lift(tmp_path):
    """R0 and R6 carry NO duration gate (`PHASE_LIMITS_S` is 0 for both), so
    a ceiling read straight from that table would lock the target forever on
    exactly the phase the report calls out. The widest ceiling this product
    knows stands in for it."""
    from nsmcp.upgrade import NO_CEILING_FALLBACK_S

    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R0",
        open_started=_seconds_ago(NO_CEILING_FALLBACK_S + 120),
    )
    r = _call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME})
    assert not r.isError, _text(r)


def test_a_stale_r0_can_close_itself_by_adopting_its_own_open_run(tmp_path, ledger_stale_r0):
    """A stale R0 used to be the one state NOTHING could clear: R1-R6 can
    name the open run and retry, but R0 minted a FRESH run id every time, so
    it could never re-close what it opened. R0 now adopts the open run on
    this target - and ONLY when that run's R0 is past
    its ceiling. A live one keeps refusing (see
    `test_a_live_open_r0_is_not_adopted_and_no_second_runner_starts`)."""
    server = _server(tmp_path, ledgermap=ledger_stale_r0)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)
    assert "FASE GESTART" in _text(r)
    assert "- run: andere-run" in _text(r), _text(r)


def test_the_refusal_names_onderhoud_upgrade_stand_without_the_stale_caveat(tmp_path):
    """`onderhoud_upgrade_stand` is now registered - `_stand_hint()`
    (mcp_server.py) asks the server itself whether that tool is really on
    it, so the caveat this refusal used to carry ("dat gereedschap is op
    deze server nog niet aangemeld") is gone now that it truly is: the
    refusal just points at the tool that can actually answer."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R1",
        open_started=_seconds_ago(60),
    )
    text = _text(_call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME}))
    assert "vraag de stand op met onderhoud_upgrade_stand" in text
    assert "niet aangemeld" not in text
    assert "onderhoud.ledgermap" not in text


def test_the_allowlist_refusal_comes_before_the_open_phase_refusal(tmp_path):
    """The cross-tool gate used to run BEFORE
    `validate()`, so a caller whose allowlist forbids the tool on that
    target learned that a phase was open there - a fact about the target's
    maintenance state, handed to someone who may not touch it at all."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R1",
        open_started=_seconds_ago(60),
        allow_on_open_target=False,
    )
    text = _text(_call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME}))
    assert "er staat nog een fase open op dit doel" not in text
    assert "geweigerd:" in text
    assert "onderhoud_backup_maken" in text


# ---------------------------------------------------------------------------
# An unreadable ledger must REFUSE, not wave through
# ---------------------------------------------------------------------------


def test_the_cross_tool_gate_refuses_when_the_ledger_directory_cannot_be_read(
    tmp_path,
    monkeypatch,
):
    """`_rows_for_target` returns an empty tuple when the ledger directory
    cannot be listed, and an empty tuple reads as "no phase open" - the
    single-writer window reopens silently. A safety gate that cannot read
    its evidence refuses."""
    import pathlib

    server = _two_target_write_server(tmp_path, open_target=TARGET_NAME)
    real_glob = pathlib.Path.glob

    def unreadable(self, pattern, *a, **kw):
        if self.name == "ledger":
            raise PermissionError(13, "toegang geweigerd")
        return real_glob(self, pattern, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "glob", unreadable)
    r = _call(server, "onderhoud_backup_maken", {"doel": SECOND_TARGET_NAME})
    assert r.isError, _text(r)
    assert "ledger" in _text(r).lower()


def test_an_unreadable_run_file_also_refuses_the_cross_tool_gate(tmp_path, monkeypatch):
    """Same rule one level down: a run FILE that exists but cannot be read
    could be the one carrying the open phase."""
    import pathlib

    server = _two_target_write_server(tmp_path, open_target=TARGET_NAME)
    # 1.1 B: a ledger file is read with one `localpath.read_local` walk.
    from nsmcp import localpath

    real_read_local = localpath.read_local

    def unreadable(path, *a, **kw):
        if pathlib.Path(path).suffix == ".jsonl":
            raise PermissionError(13, "toegang geweigerd")
        return real_read_local(path, *a, **kw)

    monkeypatch.setattr(localpath, "read_local", unreadable)
    r = _call(server, "onderhoud_backup_maken", {"doel": SECOND_TARGET_NAME})
    assert r.isError, _text(r)


# ---------------------------------------------------------------------------
# The PHASE path reads the ledger strictly too, the refusal is
# bounded, and a lift that is followed by a refusal is not silent
# ---------------------------------------------------------------------------


def test_the_phase_path_refuses_when_the_ledger_directory_cannot_be_read(
    tmp_path,
    monkeypatch,
):
    """The carve-out repaired. This read used to stay tolerant by pointing at
    the per-LINE tolerance `read_ledger()` provides; a directory that cannot
    be LISTED is a different fact. Zero rows passed BOTH weigering 2 (open
    phase) and weigering 3 (soak) silently - on the one tool that starts
    appliance work."""
    import pathlib

    server = _server(tmp_path)
    real_glob = pathlib.Path.glob

    def unreadable(self, pattern, *a, **kw):
        if self.name == "ledger":
            raise PermissionError(13, "toegang geweigerd")
        return real_glob(self, pattern, *a, **kw)

    monkeypatch.setattr(pathlib.Path, "glob", unreadable)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )
    assert r.isError, _text(r)
    text = _text(r)
    assert "ledgermap kon niet gelezen worden" in text
    assert "deze fase wordt daarom niet gestart" in text


def test_an_unreadable_run_file_also_refuses_the_phase_path(tmp_path, monkeypatch):
    """Same rule one level down: a run FILE that exists but cannot be read
    could be the one carrying the open phase."""
    import pathlib

    server = _server(tmp_path)
    append_line(
        server.onderhoud.ledgermap / "andere-run.jsonl",
        _regel(run="andere-run", fase="R0", gebeurtenis="voormeting_vast", uitkomst="geslaagd"),
    )
    # 1.1 B: a ledger file is read with one `localpath.read_local` walk.
    from nsmcp import localpath

    real_read_local = localpath.read_local

    def unreadable(path, *a, **kw):
        if pathlib.Path(path).suffix == ".jsonl":
            raise PermissionError(13, "toegang geweigerd")
        return real_read_local(path, *a, **kw)

    monkeypatch.setattr(localpath, "read_local", unreadable)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )
    assert r.isError, _text(r)
    assert "regelbestand in de ledgermap kon niet gelezen worden" in _text(r)


def test_a_malformed_line_still_does_not_brick_the_phase_path(tmp_path):
    """The tolerance that STAYS on this path too: one unparseable LINE is
    not an unreadable ledger, and this is the tool that runs the upgrade."""
    server = _server(tmp_path)
    with (server.onderhoud.ledgermap / "rommel.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("dit is geen json\n")
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert not r.isError, _text(r)
    assert "FASE GESTART" in _text(r)


def test_an_adopted_run_does_not_mask_a_foreign_live_phase(tmp_path):
    """`blocking_phase()` returned "the first non-expired open phase" and the
    caller compared THAT one against its own run name - so a foreign run's
    LIVE phase further down the same target's rows was never inspected once
    a phase of the adopted run came back first. The exemption belongs inside
    the search (`except_run`), not after it."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()

    def _row(*, run, fase, age_s):
        moment = datetime.now(UTC) - timedelta(seconds=age_s)
        stamp = moment.isoformat().replace("+00:00", "Z")
        row = _regel(run=run, fase=fase, gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stamp)
        row["tijd"] = stamp
        return row

    # The run R0 would adopt: its R0 is past the ceiling. Its R1 is NOT -
    # and used to be the one phase the refusal looked at.
    append_line(ledgermap / "andere-run.jsonl", _row(run="andere-run", fase="R0", age_s=7200))
    append_line(ledgermap / "andere-run.jsonl", _row(run="andere-run", fase="R1", age_s=120))
    # A DIFFERENT run, genuinely inside a phase on the same appliance.
    append_line(ledgermap / "derde-run.jsonl", _row(run="derde-run", fase="R2", age_s=60))

    server = _server(tmp_path, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError, _text(r)
    assert "er staat nog een fase open op dit doel" in _text(r)


def test_the_open_phase_refusal_bounds_the_phase_name_it_read_from_the_ledger(tmp_path):
    """`OpenPhase.phase` is `row["fase"]` off an UNTRUSTED ledger row and is
    echoed straight into an operator-facing refusal. Hardening says such a
    string is never echoed raw."""
    server = _two_target_write_server(
        tmp_path,
        open_target=TARGET_NAME,
        open_phase="R" + "9" * 5000,
        open_started=_seconds_ago(60),
    )
    text = _text(_call(server, "onderhoud_backup_maken", {"doel": TARGET_NAME}))
    assert "er staat nog een fase open op dit doel" in text
    assert "...(afgekapt)" in text
    assert "9" * 400 not in text


def test_a_lift_followed_by_a_refusal_is_not_silent(tmp_path):
    """SECURITY.md: "de weigering verdwijnt niet stilzwijgend". The lift
    notice only ever travelled with a RENDERED answer, so a call that lifted
    a stale refusal and then hit the soak gate discarded it - the operator
    saw the soak refusal and never learned that a phase on this target had
    been declared `mislukt` with reason `tijdslimiet`.

    Design row A1 now refuses a VOORSTEL inside the soak window too, so
    the code here is minted FIRST, on an empty ledger, and both the stale
    phase and the soak window only appear afterwards - between the
    proposal and its confirmation - which is exactly the race the
    EXECUTION-time gate still exists to catch."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    server = _server(tmp_path, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")

    now = datetime.now(UTC)
    stale = (now - timedelta(seconds=7200)).isoformat().replace("+00:00", "Z")
    stale_row = _regel(run="andere-run", fase="R1", gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stale)
    stale_row["tijd"] = stale
    append_line(ledgermap / "andere-run.jsonl", stale_row)
    append_line(
        ledgermap / "vorige-run.jsonl",
        _regel(
            run="vorige-run",
            fase="R6",
            gebeurtenis="soak_open",
            uitkomst="geslaagd",
            gestart=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        ),
    )

    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError, _text(r)
    text = _text(r)
    assert "het soakvenster loopt nog tot" in text
    assert "tijdslimiet" in text
    assert "R1" in text


def test_the_voorstel_refusal_also_carries_a_lift_notice(tmp_path):
    """De VOORSTEL-weigering op het soakvenster
    droeg geen lift-melding - staat er naast het soakvenster ook een
    verlopen fase, dan hoorde de beheerder dat pas na het venster, terwijl
    de lift een PURE LEZING is (`expired_phases`) en niets verloren gaat
    door hem mee te geven, zoals de uitvoeringspoort dat al deed."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    now = datetime.now(UTC)
    stale = (now - timedelta(seconds=7200)).isoformat().replace("+00:00", "Z")
    stale_row = _regel(run="andere-run", fase="R1", gebeurtenis="fase_gestart", uitkomst="gestart", gestart=stale)
    stale_row["tijd"] = stale
    append_line(ledgermap / "andere-run.jsonl", stale_row)
    append_line(
        ledgermap / "vorige-run.jsonl",
        _regel(
            run="vorige-run",
            fase="R6",
            gebeurtenis="soak_open",
            uitkomst="geslaagd",
            gestart=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        ),
    )

    server = _server(tmp_path, ledgermap=ledgermap)
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
        },
    )
    assert r.isError, _text(r)
    text = _text(r)
    assert "het soakvenster loopt nog tot" in text
    assert "tijdslimiet" in text
    assert "R1" in text


def test_a_malformed_line_still_does_not_brick_a_running_upgrade(tmp_path):
    """The tolerance that STAYS (`read_ledger`'s per-line skipping): a single
    unparseable LINE is not an unreadable ledger."""
    server = _two_target_write_server(tmp_path, open_target=TARGET_NAME)
    with (server.ledgermap / "rommel.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("dit is geen json\n")
    r = _call(server, "onderhoud_backup_maken", {"doel": SECOND_TARGET_NAME})
    assert not r.isError, _text(r)


def test_a_retried_phase_does_not_read_the_previous_attempt_as_its_own_start(
    tmp_path,
    ledger_stale_r0,
):
    """The retry path the report calls the escape (`R1-R6` naming the same
    run, and now R0 adopting its own) walks straight into `wait_for_start`:
    the STALE `fase_gestart` row of the previous attempt matches run/phase
    exactly, so the tool would report FASE GESTART on a runner that never
    wrote a line. Only a row that was not there before this start counts."""
    runner = _nep_runner(tmp_path, write_gestart=False)
    server = _server(tmp_path, ledgermap=ledger_stale_r0, runner=runner)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {
            "fase": "R0",
            "snapshotverwijzing": "checkpoint-1",
            "bevestiging": code,
        },
    )
    assert r.isError, _text(r)
    assert "geen regel fase_gestart" in _text(r)


def test_the_hostsleutel_argument_reaches_powershell_in_posh_sshs_own_wire_form(tmp_path):
    """target.py's storage form is padded hex
    with no separators (`_normalize_fingerprint`: strip ':'/'-', uppercase).
    Posh-SSH 3.2.7's own comparison (`NewSessionBase.cs:312-325`) formats the
    OFFERED key as lowercase, colon-separated, per-byte '{0:x}' - UNPADDED -
    and compares with a plain '=='. A stored fingerprint therefore never
    matches the offered key unless `build_upgrade_arguments()` converts it to
    that exact wire form before it reaches `-HostsleutelVingerafdruk`.

    This fingerprint's first byte (0x05) is BELOW 0x10 - precisely the case
    a padded implementation gets wrong: '05' where Posh-SSH's own format
    would print a single digit '5'."""
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
        ssh_hostsleutel_vingerafdruk="05:64:7f:4b:f8:69:78:c8:a4:89:86:a2:cf:38:de:4b",
    )
    # The storage/comparison form target.py keeps: padded, uppercase, no separators.
    assert target.ssh_hostsleutel_vingerafdruk == "05647F4BF86978C8A48986A2CF38DE4B"

    firmwaremap = _firmwaremap(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    args = build_upgrade_arguments(
        {"fase": "R1", "snapshotverwijzing": None, "drift_geaccepteerd": False, "oude_buildbomen_opruimen": False},
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
    )
    idx = args.index("-HostsleutelVingerafdruk")
    assert args[idx + 1] == "5:64:7f:4b:f8:69:78:c8:a4:89:86:a2:cf:38:de:4b"


def test_a_hostsleutel_without_a_short_byte_is_still_lowercase_and_unpadded(tmp_path):
    """The non-degenerate case: every byte here is already >= 0x10, so a
    padded-vs-unpadded bug would NOT show up - only case matters. Posh-SSH's
    own format is lowercase; target.py's storage form is uppercase."""
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
        ssh_hostsleutel_vingerafdruk=HOSTKEY,
    )
    firmwaremap = _firmwaremap(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    args = build_upgrade_arguments(
        {"fase": "R1", "snapshotverwijzing": None, "drift_geaccepteerd": False, "oude_buildbomen_opruimen": False},
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
    )
    idx = args.index("-HostsleutelVingerafdruk")
    assert args[idx + 1] == HOSTKEY.lower()


def test_an_unpinned_target_still_passes_an_empty_hostsleutel_argument(tmp_path):
    """No regression on the existing "no pin at all" path: `Target` allows
    `ssh_hostsleutel_vingerafdruk=None`, and the wire conversion must not
    turn that into a crash or into a literal 'None'."""
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
    )
    firmwaremap = _firmwaremap(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    args = build_upgrade_arguments(
        {"fase": "R1", "snapshotverwijzing": None, "drift_geaccepteerd": False, "oude_buildbomen_opruimen": False},
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
    )
    idx = args.index("-HostsleutelVingerafdruk")
    assert args[idx + 1] == ""


def test_forbidden_addresses_reach_the_runner_as_verboden_adressen(tmp_path):
    """handelen.verboden_adressen (via start.py) komt hier aan als
    `forbidden_addresses` en moet als `-VerbodenAdressen <adres>,<adres>`
    op de argumentlijst staan - EEN komma-argument, want `powershell.exe
    -File` bindt van twee losse waarden alleen de eerste aan een
    [string[]]-parameter. De enige plek waar het echte adres van een
    voorgoed read-only doos nog terechtkomt, nooit als letterlijke waarde in
    code."""
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
    )
    firmwaremap = _firmwaremap(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    args = build_upgrade_arguments(
        {"fase": "R1", "snapshotverwijzing": None, "drift_geaccepteerd": False, "oude_buildbomen_opruimen": False},
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
        forbidden_addresses=("203.0.113.42", "lab-99"),
    )
    idx = args.index("-VerbodenAdressen")
    assert args[idx + 1] == "203.0.113.42,lab-99"
    assert "lab-99" not in args[idx + 2 :]


def test_no_forbidden_addresses_means_no_flag_at_all(tmp_path):
    """Standaard leeg (start.py's default zonder handelen.verboden_adressen):
    -VerbodenAdressen komt dan helemaal niet op de argumentlijst - dezelfde
    vorm als -ExportRoot en -Actieregister hierboven al hebben."""
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
    )
    firmwaremap = _firmwaremap(tmp_path)
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=firmwaremap,
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    args = build_upgrade_arguments(
        {"fase": "R1", "snapshotverwijzing": None, "drift_geaccepteerd": False, "oude_buildbomen_opruimen": False},
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
    )
    assert "-VerbodenAdressen" not in args


def test_the_r1_proposal_names_the_export_drift_and_the_three_ways_its_drift_gate_opens(tmp_path):
    """R1 measures the configuration state itself now (`show ns config`,
    `drift_live_gate`). The proposal says so BEFORE the window, with the
    export's drift counts, so the operator can save first with config_opslaan
    or accept the drift on purpose instead of meeting a closed gate."""
    server = _server(tmp_path, code_presenter=CodeSpy())
    _code, tekst = _propose(server, fase="R1", run="run-1")
    assert (
        "- driftpoort: R1 meet de stand zelf met show ns config en opent de driftpoort op een van drie "
        "manieren: aantoonbaar niets gewijzigd sinds de laatste opslag, eerst opgeslagen met config_opslaan "
        "op de primary of het standalone-doel, of bewust geaccepteerd met drift_geaccepteerd=true [vastgesteld]"
    ) in tekst, tekst
    assert "- drift: volgens de export" in tekst


def test_no_other_phase_proposal_carries_the_drift_choice(tmp_path):
    server = _server(tmp_path, code_presenter=CodeSpy())
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    assert "driftpoort" not in tekst


# ---------------------------------------------------------------------------
# R0: de doelbuild tegenover de vloer. De server berekent de vloer uit de
# export en het kennispakket en geeft hem de runner mee; de acceptatie
# (doelbuild_geaccepteerd) hoort alleen bij R0.
# ---------------------------------------------------------------------------


def test_doelbuild_geaccepteerd_belongs_to_r0_only():
    for fase in ("R1", "R2", "R3", "R4", "R5", "R6"):
        with pytest.raises(Refusal) as fout:
            validate_phase_arguments({"fase": fase, "run": "x", "doelbuild_geaccepteerd": "True"})
        assert fout.value.code == "onbekend-argument"
    schoon = validate_phase_arguments({"fase": "R0", "snapshotverwijzing": "chk", "doelbuild_geaccepteerd": "True"})
    assert schoon["doelbuild_geaccepteerd"] is True
    zonder = validate_phase_arguments({"fase": "R0", "snapshotverwijzing": "chk"})
    assert zonder["doelbuild_geaccepteerd"] is False


def _r0_clean(**extra) -> dict:
    clean = validate_phase_arguments({"fase": "R0", "snapshotverwijzing": "chk"})
    clean.update(extra)
    return clean


def _floor_args(tmp_path, clean, **floor) -> list[str]:
    target = Target(
        name="netscaler-02",
        address="10.0.0.2",
        credential_target="GJK/Test/netscaler-02/nitro-write",
        agreement=CertAgreement.CHAIN,
    )
    onderhoud = MaintenanceConfig(
        runner=tmp_path / "runner.ps1",
        ledgermap=tmp_path / "ledger",
        firmwaremap=_firmwaremap(tmp_path),
        soak_uren=24,
        ssh_gebruiker="nsroot",
    )
    return build_upgrade_arguments(
        clean,
        target=target,
        onderhoud=onderhoud,
        run_name="run-1",
        actie_id="",
        bevestiger=None,
        preview=True,
        **floor,
    )


def test_r0_hands_the_runner_the_floor_its_bulletin_and_the_acceptance(tmp_path):
    args = _floor_args(
        tmp_path, _r0_clean(doelbuild_geaccepteerd=True), floor_build="14.1-73.32", floor_bulletin="CTX696939"
    )
    assert args[args.index("-Vloerbuild") + 1] == "14.1-73.32"
    assert args[args.index("-VloerBulletin") + 1] == "CTX696939"
    assert "-DoelbuildGeaccepteerd" in args
    zonder = _floor_args(tmp_path, _r0_clean(), floor_build="14.1-73.32", floor_bulletin="CTX696939")
    assert "-DoelbuildGeaccepteerd" not in zonder


def test_r0_hands_the_runner_the_package_its_floor_came_from(tmp_path):
    args = _floor_args(
        tmp_path,
        _r0_clean(),
        floor_build="14.1-73.32",
        floor_bulletin="CTX696939",
        floor_package="2026.09",
        floor_package_date="2026-09-06",
    )
    assert args[args.index("-VloerPakket") + 1] == "2026.09"
    assert args[args.index("-VloerPakketDatum") + 1] == "2026-09-06"


@pytest.mark.parametrize(
    "pakket,datum",
    [("VOORBEELD - geen echte basis", "2026-09-06"), ("2026.09", "geen datum"), ("2026.09\n- vals", "2026-09-06")],
)
def test_a_package_label_without_the_runner_form_never_travels_but_the_floor_does(tmp_path, pakket, datum):
    args = _floor_args(
        tmp_path,
        _r0_clean(),
        floor_build="14.1-73.32",
        floor_bulletin="CTX696939",
        floor_package=pakket,
        floor_package_date=datum,
    )
    assert "-VloerPakket" not in args and "-VloerPakketDatum" not in args
    assert args[args.index("-Vloerbuild") + 1] == "14.1-73.32"


def test_without_a_floor_no_package_travels(tmp_path):
    args = _floor_args(tmp_path, _r0_clean(), floor_package="2026.09", floor_package_date="2026-09-06")
    assert "-VloerPakket" not in args and "-VloerPakketDatum" not in args


def test_no_other_phase_carries_the_package_arguments(tmp_path):
    clean = validate_phase_arguments({"fase": "R1", "run": "run-1"})
    args = _floor_args(
        tmp_path,
        clean,
        floor_build="14.1-73.32",
        floor_bulletin="CTX696939",
        floor_package="2026.09",
        floor_package_date="2026-09-06",
    )
    assert "-VloerPakket" not in args and "-VloerPakketDatum" not in args


def test_no_floor_means_no_floor_arguments(tmp_path):
    args = _floor_args(tmp_path, _r0_clean())
    assert "-Vloerbuild" not in args and "-VloerBulletin" not in args


def test_without_any_floor_the_acceptance_still_reaches_the_runner(tmp_path):
    """No floor known at all: R0's floor gate opens on the acceptance as a
    human decision, so the acceptance has to travel."""
    args = _floor_args(tmp_path, _r0_clean(doelbuild_geaccepteerd=True))
    assert "-Vloerbuild" not in args
    assert "-DoelbuildGeaccepteerd" in args


@pytest.mark.parametrize("vloer", ["13.1-FIPS-37.272", "14.1-FIPS-73.32"])
def test_an_acceptance_never_travels_past_a_known_floor_the_runner_cannot_see(tmp_path, vloer):
    """A floor the knowledge package DOES know but that has no runner form (a
    FIPS train) is not "no floor known": the runner would read its absence as
    exactly that and open on the acceptance, while the plan says R0 closes
    there. The acceptance stays behind, so R0 closes."""
    args = _floor_args(tmp_path, _r0_clean(doelbuild_geaccepteerd=True), floor_build=vloer, floor_bulletin="CTX696939")
    assert "-Vloerbuild" not in args
    assert "-DoelbuildGeaccepteerd" not in args


@pytest.mark.parametrize(
    "vloer,bulletin",
    [("14.1-FIPS-73.32", "CTX696939"), ("14.1-\u0667\u0663.32", "CTX696939"), ("73.32", "CTX696939")],
)
def test_a_floor_of_another_shape_never_reaches_the_runner(tmp_path, vloer, bulletin):
    args = _floor_args(tmp_path, _r0_clean(), floor_build=vloer, floor_bulletin=bulletin)
    assert "-Vloerbuild" not in args
    assert vloer not in args


def test_an_unprintable_bulletin_label_is_left_out_but_the_floor_still_travels(tmp_path):
    args = _floor_args(tmp_path, _r0_clean(), floor_build="14.1-73.32", floor_bulletin="(bulletin-id niet leesbaar)")
    assert args[args.index("-Vloerbuild") + 1] == "14.1-73.32"
    assert "-VloerBulletin" not in args


def test_no_other_phase_carries_the_floor_arguments(tmp_path):
    clean = validate_phase_arguments({"fase": "R1", "run": "run-1"})
    args = _floor_args(
        tmp_path, clean, floor_build="14.1-73.32", floor_bulletin="CTX696939", current_build="14.1-66.59"
    )
    assert "-Vloerbuild" not in args and "-VloerBulletin" not in args and "-DoelbuildGeaccepteerd" not in args
    assert "-Huidigebuild" not in args


def test_r0_hands_the_runner_the_current_build(tmp_path):
    args = _floor_args(tmp_path, _r0_clean(), current_build="14.1-66.59")
    assert args[args.index("-Huidigebuild") + 1] == "14.1-66.59"
    assert "-Huidigebuild" not in _floor_args(tmp_path, _r0_clean())


def test_without_a_current_build_the_acceptance_still_reaches_the_runner(tmp_path):
    """No current build known: R0's floor gate opens on the acceptance as a
    human decision, with that gap in its evidence."""
    args = _floor_args(tmp_path, _r0_clean(doelbuild_geaccepteerd=True))
    assert "-Huidigebuild" not in args
    assert "-DoelbuildGeaccepteerd" in args


@pytest.mark.parametrize("huidig", ["1\u0664.1-66.59", "66.59", "14.1-66.59; reboot", "13.1-FIPS-37.272"])
def test_a_current_build_without_the_runner_form_never_travels_and_neither_does_the_acceptance(tmp_path, huidig):
    """A current build the export DOES carry but that has no runner form is
    not "no current build known": the runner would read its absence as
    exactly that and open on the acceptance. The acceptance stays behind, so
    R0 closes."""
    args = _floor_args(tmp_path, _r0_clean(doelbuild_geaccepteerd=True), current_build=huidig)
    assert "-Huidigebuild" not in args
    assert huidig not in args
    assert "-DoelbuildGeaccepteerd" not in args


def test_the_server_derives_the_floor_for_r0_from_the_export_and_the_knowledge_package(tmp_path):
    server = _server(tmp_path, floor={})
    _propose(server, fase="R0", snapshotverwijzing="checkpoint-1", doelbuild_geaccepteerd=True)
    voorvertoning = _argv_rows(server.onderhoud.ledgermap)[-1]
    assert voorvertoning[voorvertoning.index("-Vloerbuild") + 1] == "14.1-73.32"
    assert voorvertoning[voorvertoning.index("-VloerBulletin") + 1] == "CTX696939"
    assert voorvertoning[voorvertoning.index("-Huidigebuild") + 1] == "14.1-72.57"
    assert "-DoelbuildGeaccepteerd" in voorvertoning


def test_the_proposal_and_the_execution_hand_the_runner_the_pinned_package_of_the_floor(
    tmp_path, ledgermap, monkeypatch
):
    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledgermap, floor={})
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    )
    assert not r.isError, _text(r)
    rijen = _argv_rows(ledgermap)
    voorvertoning = [argv for argv in rijen if "-WatIs" in argv][-1]
    echt = [argv for argv in rijen if "-WatIs" not in argv][-1]
    for argv in (voorvertoning, echt):
        assert argv[argv.index("-VloerPakket") + 1] == "2026.09"
        assert argv[argv.index("-VloerPakketDatum") + 1] == "2026-09-06"


def test_the_execution_hands_the_runner_the_current_build_read_afresh(tmp_path, ledgermap, monkeypatch):
    """The real launch reads the export again, like the floor: never a
    current build carried over from the proposal."""
    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledgermap, floor={})
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    _with_floor(tmp_path, version="NetScaler NS14.1: Build 66.59.nc")
    r = _call(
        server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    )
    assert not r.isError, _text(r)
    echt = [argv for argv in _argv_rows(ledgermap) if "-WatIs" not in argv][-1]
    assert echt[echt.index("-Huidigebuild") + 1] == "14.1-66.59"


@pytest.mark.parametrize(
    "fase,extra",
    [("R0", {"snapshotverwijzing": "checkpoint-1"}), ("R1", {"run": "run-1"})],
)
@pytest.mark.parametrize("export_target", [SECOND_TARGET_NAME, None], ids=["ander-doel", "geen-doel"])
def test_a_phase_on_an_export_of_another_or_no_target_is_refused_before_the_preview(
    tmp_path, fase, extra, export_target
):
    """The current build and the floor come from the ONE export of this
    server. An export of another target would hand R0 that appliance's
    build - a 14.1 build there opens the floor gate for a target that may
    still run 13.1 - and every proposal would show it as this target's
    build. An export that records no target cannot prove it is this one.
    Refused before the preview, with the reason: no runner starts, no code
    exists."""
    from nsmcp.disclosure import Disclosure

    # The bundle at the floor: on the other target's 14.1 build the floor
    # gate would open.
    firmwaremap = _firmwaremap(tmp_path, doelbuild="14.1-73.32")
    server = _server(tmp_path, code_presenter=CodeSpy(), export_target=export_target, firmwaremap=firmwaremap, floor={})
    r = _call(server, "onderhoud_upgrade_fase", {"fase": fase, **extra})
    gestart = _argv_rows(server.onderhoud.ledgermap)
    assert not gestart, f"de faserunner is gestart: {gestart}"
    assert not server.code_spy.codes, "er is een code aangemaakt"
    assert r.isError, _text(r)
    reden = (
        mcp_server.ander_doel_text(SECOND_TARGET_NAME, Disclosure.FULL)
        if export_target
        else mcp_server.EXPORT_DOEL_ONBEKEND_TEXT
    )
    assert reden in _text(r)


def test_an_export_of_another_target_before_the_redeem_says_the_code_stays_valid(tmp_path, ledgermap, monkeypatch):
    """The execution reads the export before it redeems the code too. Refused
    there, the code is untouched - and the answer says so, so the operator
    refreshes and confirms with the same code instead of asking for a new
    proposal. Proven: once the export describes this target again, the same
    code starts the phase."""
    from nsmcp.disclosure import Disclosure

    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledgermap, floor={})
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    _anchor_target(tmp_path / "export", SECOND_TARGET_NAME)
    argumenten = {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    r = _call(server, "onderhoud_upgrade_fase", argumenten)
    assert r.isError, _text(r)
    assert not [argv for argv in _argv_rows(ledgermap) if "-WatIs" not in argv], "de faserunner is echt gestart"
    assert "De bevestigingscode is niet ingewisseld en blijft geldig" in _text(r), _text(r)
    reden = mcp_server.ander_doel_text(SECOND_TARGET_NAME, Disclosure.FULL)
    assert mcp_server.EXPORTDOEL_VOOR_INWISSELEN_TEXT.format(reden=reden) in _text(r)

    _anchor_target(tmp_path / "export", TARGET_NAME)
    opnieuw = _call(server, "onderhoud_upgrade_fase", argumenten)
    assert not opnieuw.isError, _text(opnieuw)
    assert [argv for argv in _argv_rows(ledgermap) if "-WatIs" not in argv], "de faserunner is niet gestart"


def test_an_export_of_another_target_after_the_redeem_starts_nothing_and_says_the_code_is_spent(
    tmp_path, ledgermap, monkeypatch
):
    """The export is read again after the code is redeemed. A scan of
    another target that lands between the preview and that read must not
    reach the runner either - and the code is spent by then, so the answer
    says so instead of the generic error."""
    from nsmcp.disclosure import Disclosure

    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledgermap, floor={})
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    echte_voorvertoning = mcp_server.run_upgrade_preview

    def voorvertoning_waarna_een_ander_doel_gescand_wordt(args, **kwargs):
        uitkomst = echte_voorvertoning(args, **kwargs)
        _anchor_target(tmp_path / "export", SECOND_TARGET_NAME)
        return uitkomst

    monkeypatch.setattr(mcp_server, "run_upgrade_preview", voorvertoning_waarna_een_ander_doel_gescand_wordt)
    argumenten = {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    r = _call(server, "onderhoud_upgrade_fase", argumenten)
    assert not [argv for argv in _argv_rows(ledgermap) if "-WatIs" not in argv], "de faserunner is echt gestart"
    assert r.isError, _text(r)
    reden = mcp_server.ander_doel_text(SECOND_TARGET_NAME, Disclosure.FULL)
    assert mcp_server.EXPORTDOEL_NA_INWISSELEN_TEXT.format(reden=reden) in _text(r)

    # Spent indeed: with the export of this target back, the same code is
    # refused by the confirmation store, and still nothing starts.
    monkeypatch.setattr(mcp_server, "run_upgrade_preview", echte_voorvertoning)
    _anchor_target(tmp_path / "export", TARGET_NAME)
    opnieuw = _call(server, "onderhoud_upgrade_fase", argumenten)
    assert opnieuw.isError, _text(opnieuw)
    assert "bevestigingscode onbekend of al gebruikt" in _text(opnieuw)
    assert not [argv for argv in _argv_rows(ledgermap) if "-WatIs" not in argv], "de faserunner is echt gestart"


_VOORSTEL_VLOERREGELS = (
    "- huidige build: 14.1-72.57 [vastgesteld]\n"
    "    bewijs: config/nsversion: NS14.1: Build 72.57\n"
    "- doelbuild: 14.1-72.57 [vastgesteld]\n"
    "    bewijs: de enige bundel in onderhoud.firmwaremap (build-14.1-72.57_nc_64.tgz, 0 MB)\n"
    "- vloer: 14.1-73.32; doelbuild ONDER de vloer; blijven open: CTX696604 (fix 72.61), CTX696939 "
    "(fix 73.32); R0 sluit tenzij doelbuild_geaccepteerd=true [vastgesteld]\n"
    "    bewijs: kennispakket '2026.09' van 2026-09-06, bulletin CTX696939\n"
)


@pytest.mark.parametrize(
    "fase,extra",
    [("R0", {"snapshotverwijzing": "checkpoint-1"}), ("R1", {"run": "run-1"}), ("R5", {"run": "run-1"})],
)
def test_every_phase_proposal_ends_with_the_target_build_and_the_floor(tmp_path, fase, extra):
    """Three lines of the product's own - the current build, the target
    build, and the floor with R0's verdict - AFTER every fixed line of the
    proposal (and after R1's drift lines), so no pinned prefix moves."""
    server = _server(tmp_path, code_presenter=CodeSpy(), floor={})
    _code, tekst = _propose(server, fase=fase, **extra)
    assert _VOORSTEL_VLOERREGELS in tekst, tekst
    vloerregels = tekst.index(_VOORSTEL_VLOERREGELS)
    assert tekst.index("- bevestigingscode: ") < vloerregels
    if fase == "R1":
        assert tekst.index("- driftpoort: ") < vloerregels
    regels = [r for r in tekst[vloerregels + len(_VOORSTEL_VLOERREGELS) :].splitlines() if r.startswith("- ")]
    assert not regels, f"na de vloerregels staat nog een bevinding: {regels}"


def test_a_proposal_without_a_floor_says_so_and_what_r0_then_does(tmp_path):
    server = _server(tmp_path, code_presenter=CodeSpy())
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    assert "- huidige build: niet vastgesteld [niet vastgesteld]" in tekst
    assert "- doelbuild: 14.1-72.57 [vastgesteld]" in tekst
    assert "- vloer: niet vastgesteld [niet vastgesteld]" in tekst
    assert "zonder vloer sluit R0 de vloerpoort tenzij doelbuild_geaccepteerd=true" in tekst


def test_a_proposal_without_a_floor_for_a_bundle_in_another_release_line_says_r0_closes_even_when_accepted(tmp_path):
    """The appliance runs 13.1 and the package knows no 13.1 floor; the
    bundle is 14.1. Without the current build this proposal used to say "R0
    sluit tenzij doelbuild_geaccepteerd=true" - and R0 then opened."""
    server = _server(tmp_path, code_presenter=CodeSpy(), floor={"version": "NetScaler NS13.1: Build 60.1.nc"})
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    assert "- huidige build: 13.1-60.1 [vastgesteld]" in tekst
    assert "- vloer: niet vastgesteld [niet vastgesteld]" in tekst
    assert "doelbuild andere releaselijn dan de huidige build; R0 sluit, ook met doelbuild_geaccepteerd=true" in tekst
    assert "tenzij doelbuild_geaccepteerd=true" not in tekst


def test_an_r0_proposal_that_carries_the_acceptance_says_r0_opens_as_a_human(tmp_path):
    """doelbuild_geaccepteerd=true is IN this call and travels to the runner:
    the floor line must not still say "R0 sluit tenzij
    doelbuild_geaccepteerd=true" - it says what R0 will do with it."""
    server = _server(tmp_path, code_presenter=CodeSpy(), floor={})
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1", doelbuild_geaccepteerd=True)
    assert (
        "- vloer: 14.1-73.32; doelbuild ONDER de vloer; blijven open: CTX696604 (fix 72.61), CTX696939 "
        "(fix 73.32); R0 opent de vloerpoort als mens: doelbuild_geaccepteerd=true is in deze aanroep "
        "meegegeven [vastgesteld]\n"
    ) in tekst, tekst
    assert "tenzij doelbuild_geaccepteerd=true" not in tekst


def test_an_r0_proposal_without_a_floor_that_carries_the_acceptance_says_r0_opens_as_a_human(tmp_path):
    server = _server(tmp_path, code_presenter=CodeSpy())
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1", doelbuild_geaccepteerd=True)
    assert (
        "zonder vloer opent R0 de vloerpoort als mens: doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
    ) in tekst, tekst
    assert "tenzij doelbuild_geaccepteerd=true" not in tekst


def test_an_acceptance_that_cannot_reach_the_runner_is_refused_before_a_code_exists(tmp_path, monkeypatch):
    """A floor the knowledge package knows but without the runner's form (a
    FIPS train): the acceptance never reaches the runner, so R0 closes with
    or without it. The call is refused up front with that reason, instead of
    a code for an R0 that then closes on a reason pointing back at the
    acceptance."""
    from nsmcp.update_advice import Floor

    fips = Floor("14.1-FIPS-73.32", "CTX696939", "kennispakket '2026.09' van 2026-09-06, bulletin CTX696939")
    monkeypatch.setattr(mcp_server, "export_floor", lambda export, knowledge: fips)
    server = _server(tmp_path, code_presenter=CodeSpy(), floor={})
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "doelbuild_geaccepteerd": True},
    )
    assert r.isError
    assert mcp_server.DOELBUILD_ACCEPTATIE_REIST_NIET_TEXT in _text(r)
    assert not server.code_spy.codes
    assert not _argv_rows(server.onderhoud.ledgermap), "de faserunner is gestart"
    # Without the acceptance the proposal stands, and says R0 closes there.
    _code, tekst = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    assert "R0 sluit de vloerpoort, ook met doelbuild_geaccepteerd=true" in tekst


@pytest.mark.parametrize(
    "namen,zin",
    [
        ((), "de ingestelde firmwaremap bevat geen bundel"),
        (
            ("build-14.1-72.57_nc_64.tgz", "build-14.1-73.32_nc_64.tgz"),
            "de ingestelde firmwaremap bevat meer dan een bundel",
        ),
    ],
    ids=["nul", "twee"],
)
@pytest.mark.parametrize("openheid", ["volledig", "beperkt"])
def test_a_failed_proposal_names_the_local_firmware_directory_only_at_volledig(tmp_path, namen, zin, openheid):
    """The writing tools exist at 'volledig' and 'beperkt'. The reason a
    proposal cannot be drawn up with zero or two bundles names the local
    firmware directory (or its bundle names) only at 'volledig'; below that
    it says what the configured directory holds."""
    from nsmcp.disclosure import Disclosure

    firmwaremap = tmp_path / "firmware-lokaal"
    firmwaremap.mkdir()
    for naam in namen:
        (firmwaremap / naam).write_bytes(b"x")
    server = _server(tmp_path, firmwaremap=firmwaremap, code_presenter=CodeSpy(), disclosure=Disclosure(openheid))
    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1"})
    tekst = _text(r)
    assert r.isError
    assert "voorstel kon niet worden opgesteld" in tekst
    if openheid == "volledig":
        assert zin not in tekst
        for gezien in namen or ("firmware-lokaal",):
            assert gezien in tekst
    else:
        assert zin in tekst
        for verborgen in ("firmware-lokaal", *namen):
            assert verborgen not in tekst


# ---------------------------------------------------------------------------
# De runbinding: de doelbuild wordt per fase opnieuw uit de map gelezen. Wisselt
# de bundel na R0, dan zou R3 iets anders installeren dan R0 beoordeelde - dus
# R1..R6 weigeren een bundel die afwijkt van die van R0 in dezelfde run.
# ---------------------------------------------------------------------------

_AFWIJKEND = "de doelbuild van deze run (R0) wijkt af van de bundel in onderhoud.firmwaremap; start een nieuwe run"
_ONLEESBAAR = "de doelbuild van deze run (R0) staat niet leesbaar in het ledger; start een nieuwe run"


def _wissel_bundel(firmwaremap: Path, naar: str = "14.1-73.32") -> None:
    for pad in firmwaremap.iterdir():
        pad.unlink()
    (firmwaremap / f"build-{naar}_nc_64.tgz").write_bytes(b"andere-bundel")


def test_a_bundle_swapped_after_r0_is_refused_at_the_next_proposal_before_any_code(tmp_path, ledgermap):
    server = _server(tmp_path, ledgermap=ledgermap)
    for regel in _r0_gesloten("run-1"):
        append_line(ledgermap / "run-1.jsonl", regel)
    _wissel_bundel(server.onderhoud.firmwaremap)
    codes_voor = list(server.code_spy.codes)

    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": "run-1"})
    assert r.isError, _text(r)
    assert _AFWIJKEND in _text(r)
    assert "14.1-72.57" not in _text(r)
    assert server.code_spy.codes == codes_voor


def test_a_run_whose_r0_target_build_is_unreadable_is_refused_before_the_runner_starts(tmp_path, ledgermap):
    """A start row without the field (written before the binding existed)
    gives no binding to check: the proposal leaves that to the execution,
    and the execution refuses - no real launch, no new ledger row."""
    server = _server(tmp_path, ledgermap=ledgermap)
    for regel in _r0_gesloten("run-1", doelbuild=None):
        append_line(ledgermap / "run-1.jsonl", regel)
    code, _ = _propose(server, fase="R1", run="run-1")
    regels_voor = (ledgermap / "run-1.jsonl").read_text(encoding="utf-8")

    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": "run-1", "bevestiging": code})
    assert r.isError, _text(r)
    assert _ONLEESBAAR in _text(r), _text(r)
    assert (ledgermap / "run-1.jsonl").read_text(encoding="utf-8") == regels_voor
    assert all("-WatIs" in argv for argv in _argv_rows(ledgermap))


def test_the_same_bundle_as_r0_still_starts_the_next_phase(tmp_path, ledgermap, monkeypatch):
    monkeypatch.setattr(sys, "executable", getattr(sys, "_base_executable", sys.executable))
    server = _server(tmp_path, ledgermap=ledgermap)
    for regel in _r0_gesloten("run-1"):
        append_line(ledgermap / "run-1.jsonl", regel)
    code, _ = _propose(server, fase="R1", run="run-1")
    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R1", "run": "run-1", "bevestiging": code})
    assert not r.isError, _text(r)
    assert "FASE GESTART" in _text(r)


def test_a_code_without_the_floor_acceptance_does_not_cover_a_call_with_it(tmp_path, ledgermap):
    """doelbuild_geaccepteerd belongs to the confirmed call: a code the
    operator confirmed WITHOUT it does not start an R0 that accepts a
    target build below the floor."""
    server = _server(tmp_path, ledgermap=ledgermap)
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server,
        "onderhoud_upgrade_fase",
        {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "doelbuild_geaccepteerd": True, "bevestiging": code},
    )
    assert r.isError, _text(r)
    assert "hoort bij een andere handeling of een ander doel" in _text(r)
    assert all("-WatIs" in argv for argv in _argv_rows(ledgermap))


def test_without_a_readable_build_the_server_passes_no_floor(tmp_path):
    server = _server(tmp_path)
    _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    voorvertoning = _argv_rows(server.onderhoud.ledgermap)[-1]
    assert "-Vloerbuild" not in voorvertoning
    assert "-Huidigebuild" not in voorvertoning


# ---------------------------------------------------------------------------
# A runner that cannot be started after the code was redeemed: the answer
# says so - nothing started, the code is spent, and why - instead of the
# generic "unexpected error" text that says none of the three.
# ---------------------------------------------------------------------------

_LOKAAL_PAD = r"C:\niet-in-een-antwoord\runner.ps1"


def _start_failure(server, ledgermap, *, zin="De handeling is niet gestart"):
    code, _ = _propose(server, fase="R0", snapshotverwijzing="checkpoint-1")
    r = _call(
        server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    )
    tekst = _text(r)
    assert r.isError, tekst
    assert "Onverwachte fout" not in tekst
    assert zin in tekst, tekst
    assert "De bevestigingscode is verbruikt" in tekst, tekst
    # Fragments without a backslash: `_LOKAAL_PAD` is a raw string, so both
    # sit intact whether the message carries it through `!r` (escaped
    # backslashes) or literally (real backslashes) - either way the leak
    # assertion below can actually fail on a regression.
    assert "niet-in-een-antwoord" not in tekst
    assert "runner.ps1" not in tekst
    assert not any(
        regel.get("gebeurtenis") == "fase_gestart" for pad in ledgermap.glob("*.jsonl") for regel in read_ledger(pad)
    )
    nog_eens = _call(
        server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1", "bevestiging": code}
    )
    assert nog_eens.isError
    assert "De handeling is niet gestart" not in _text(nog_eens)
    return tekst


def test_a_detached_start_that_fails_after_the_redeem_says_the_start_is_undecided_and_the_code_is_spent(
    tmp_path, ledgermap, monkeypatch
):
    """An `ActionError` of no known type: whether a child exists is not
    established (1.1), so the answer never says the runner did not start."""
    server = _server(tmp_path, ledgermap=ledgermap)

    def weigert(*_args, **_kwargs):
        raise ActionError(
            f"kon de faserunner niet losgekoppeld starten: [WinError 5] Toegang geweigerd: {_LOKAAL_PAD!r}"
        )

    monkeypatch.setattr(mcp_server, "start_detached", weigert)
    tekst = _start_failure(server, ledgermap, zin="De start van de handeling is onbeslist")
    assert "De handeling is niet gestart" not in tekst
    assert "ActionError" not in tekst


def test_a_missing_powershell_after_the_redeem_says_nothing_started_and_the_code_is_spent(
    tmp_path, ledgermap, monkeypatch
):
    from nsmcp.powershell import PowerShellMissing

    server = _server(tmp_path, ledgermap=ledgermap)

    def ontbreekt(*_args, **_kwargs):
        raise PowerShellMissing(f"Windows PowerShell niet gevonden op {_LOKAAL_PAD}; er wordt geen proces gestart")

    monkeypatch.setattr(mcp_server, "upgrade_command", ontbreekt)
    tekst = _start_failure(server, ledgermap)
    assert "Windows PowerShell niet gevonden" in tekst
