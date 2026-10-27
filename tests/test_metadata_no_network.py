"""1.1 B, herstelronde 1 (I-1 of the red review of part 2): metadata questions
and listings never contact the network.

Measured in the review: an `exists()`, `is_dir()`, `glob()`, `iterdir()`,
`resolve()` or `mkdir(parents=True)` by NAME on a path whose ancestor is a
symbolic link to `\\\\192.0.2.x\\x` took 21 s and ended in ERROR_BAD_NETPATH -
the redirector really contacted the host, from reading tools. Every such
place now asks the `localpath` walk (`exists_local`, `list_local`,
`mkdir_local`), which reads a link's target text and refuses a network target
at the spelling step before anything of it is opened.

The proof per repaired place: an ancestor is a directory symlink to the
documentation address `\\\\192.0.2.10\\x` (never routed), the call ends in the
place's own fail-closed route, the seam shows no open naming the share, and
the call takes less than 100 ms (a network contact takes about 21 s). Needs
the right to create a symbolic link (Developer Mode or the privilege); without
it every case is skipped with the reason."""

from __future__ import annotations

import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nsmcp import localpath

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="de wandeling over NtCreateFile bestaat alleen op Windows"),
    pytest.mark.usefixtures("open_audit"),
]

SHARE = "\\\\192.0.2.10\\x"
# A host of its own per test: after one real contact the redirector caches a
# host as unreachable and a later call by name would come back fast (measured
# in mutation 87), so the 100 ms bound only proves something with a fresh host.
_HOSTS = iter(range(20, 250))


def _fresh_share() -> str:
    return "\\\\192.0.2." + str(next(_HOSTS)) + "\\x"


LIMIT_S = 0.1


@pytest.fixture
def share_link(tmp_path, monkeypatch):
    """`tmp_path/share` -> the share, and a recording seam."""
    link = tmp_path / "share"
    try:
        os.symlink(_fresh_share(), link, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")
    native = localpath._Native(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    return link, native


def _no_contact(native, call):
    started = time.perf_counter()
    try:
        outcome = ("returned", call())
    except Exception as exc:  # the place's own route: asserted by the caller
        outcome = ("raised", exc)
    elapsed = time.perf_counter() - started
    for record in native.opens:
        assert "192.0.2." not in record["name"] and "mup" not in record["name"].lower(), record
    assert elapsed < LIMIT_S, f"{elapsed:.3f} s: zo lang duurt een netwerkcontact"
    return outcome


def test_the_ledger_map_listing(share_link):
    from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target

    link, native = share_link
    kind, value = _no_contact(native, lambda: _rows_for_target(link / "ledger" / "_.jsonl", "lab", strict=True))
    assert kind == "raised" and isinstance(value, LedgerUnreadable)
    assert localpath.REASONS["netwerkpad"] in str(value)
    assert _no_contact(native, lambda: _rows_for_target(link / "ledger" / "_.jsonl", "lab")) == ("returned", ())


def test_the_firmware_map_listing(share_link):
    from nsmcp.handelen import FirmwareBundleError, firmware_target_build

    link, native = share_link
    kind, value = _no_contact(native, lambda: firmware_target_build(link / "firmware"))
    assert kind == "raised" and isinstance(value, FirmwareBundleError)
    assert value.zonder_pad == "onderhoud.firmwaremap is geweigerd: " + localpath.REASONS["netwerkpad"]


def test_the_kept_exports_and_a_taken_name(share_link):
    from nsmcp import retention

    link, native = share_link
    assert _no_contact(native, lambda: retention.kept_exports(link / "export")) == ("returned", ())
    assert _no_contact(native, lambda: retention._name_taken(link / "export.bewaard-x")) == ("returned", True)


def test_the_plain_path_gate_of_a_comparison(share_link):
    from nsmcp.export import plain_path

    link, native = share_link
    assert _no_contact(native, lambda: plain_path(link / "export.bewaard-x", directory=True)) == ("returned", False)


def test_the_object_file_count_of_the_coverage(share_link):
    from nsmcp.coverage import _object_file_present
    from nsmcp.export import Export

    link, native = share_link
    export = Export(directory=link / "export")
    assert _no_contact(native, lambda: _object_file_present(export, "sslcertkey")) == ("returned", False)


def test_the_export_of_the_runner_measurement(share_link):
    from nsmcp.upgrade_measure import _load_export_or_none

    link, native = share_link
    assert _no_contact(native, lambda: _load_export_or_none(str(link / "export"))) == ("returned", None)


def test_the_directory_of_the_pseudonym_table_and_its_lock(share_link):
    from nsmcp import disclosure

    link, native = share_link
    table = link / "beheer" / "tabel.json"
    kind, value = _no_contact(native, lambda: disclosure._ProcessLock(table).__enter__())
    assert kind == "raised" and isinstance(value, disclosure.PseudonymTablePathRefused)
    kind, value = _no_contact(native, lambda: disclosure._atomic_write(table, {}))
    assert kind == "raised" and isinstance(value, disclosure.PseudonymTablePathRefused)


def test_the_provenance_map_and_the_export_identity(share_link):
    from nsmcp.export import export_identity, record_provenance

    link, native = share_link
    kind, value = _no_contact(
        native, lambda: record_provenance(link / "herkomst", "lab", "0" * 64, link / "export", datetime.now(UTC))
    )
    assert kind == "raised" and isinstance(value, localpath.PathRefused) and value.soort == "netwerkpad"
    kind, value = _no_contact(native, lambda: export_identity(link / "export"))
    assert kind == "returned" and value == os.path.normcase(str((link / "export").absolute()))


def test_the_map_of_the_action_register(share_link, tmp_path):
    import dataclasses

    from conftest import maintenance_config

    from nsmcp.mcp_server import _write_action_register

    link, native = share_link
    onderhoud = dataclasses.replace(maintenance_config(tmp_path), actieregister=link / "register" / "acties.jsonl")
    kind, value = _no_contact(
        native,
        lambda: _write_action_register(
            onderhoud,
            tool="onderhoud_backup_maken",
            doel="lab",
            actieid="a-1",
            uitkomst="geslaagd",
            bevestiger="u-1",
            objectnaam="b-1",
        ),
    )
    assert kind == "returned" and value is not None
    assert value.outcome == "duurzame registratie NIET vastgesteld (" + localpath.REASONS["netwerkpad"] + ")"


def test_the_knowledge_refresh_names_and_its_log(share_link):
    from nsmcp.knowledge_refresh import _sibling_path, _write_log_line

    link, native = share_link
    kind, value = _no_contact(native, lambda: _sibling_path(link / "kennis.json", "afgekeurd", datetime.now(UTC)))
    assert kind == "raised" and isinstance(value, localpath.PathRefused)
    kind, value = _no_contact(native, lambda: _write_log_line(link / "_beheer", "AFGEKEURD", link / "k.json", "r"))
    assert (kind, value) == ("returned", False)


def test_the_places_beside_the_export_of_a_scan(share_link):
    from nsmcp import collect

    link, native = share_link
    export_dir = link / "export"
    assert _no_contact(native, lambda: collect._recover_interrupted_swap(export_dir)) == ("returned", False)
    kind, value = _no_contact(native, lambda: collect._clean_stale_work_dirs(export_dir))
    assert kind == "raised" and isinstance(value, collect.CollectError)
    assert _no_contact(native, lambda: localpath.exists_local_or_none(link / "verzamel.ps1")) == ("returned", None)


def test_the_script_directory_of_the_pin_and_the_powershell_checks(share_link):
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, check_script_pins, set_script_policy

    link, native = share_link
    set_script_policy(ScriptPolicy(pins={"runner.ps1": "0" * 64}))
    try:
        kind, value = _no_contact(native, lambda: check_script_pins(link / "runner.ps1"))
    finally:
        set_script_policy(ScriptPolicy())
    assert kind == "raised" and isinstance(value, ScriptPinMismatch)
    assert _no_contact(native, lambda: localpath.is_local_file(link / "powershell.exe")) == ("returned", False)
    assert _no_contact(native, lambda: localpath.is_local_dir(link / "System32")) == ("returned", False)


def test_the_start_check_of_a_file(share_link):
    from nsmcp.start import ConfigError, _require_file

    link, native = share_link
    kind, value = _no_contact(native, lambda: _require_file(link / "nsmcp.json", "configuratiebestand"))
    assert kind == "raised" and isinstance(value, ConfigError) and "niet gevonden" in str(value)


def test_the_ledger_path_of_a_run_is_text_only(share_link):
    from nsmcp.upgrade import ledger_path_for

    link, native = share_link
    kind, value = _no_contact(native, lambda: ledger_path_for(link / "ledger", "run-1"))
    assert kind == "returned" and value == Path(str(link / "ledger" / "run-1.jsonl"))
    assert native.opens == [], "een tekstbewerking opent niets"
    with pytest.raises(ValueError):
        ledger_path_for(link / "ledger", "..")


# ---------------------------------------------------------------------------
# Herstelronde 2 (H1-M-1): the scan route - free space, a new work map, the
# removal of a tree and of the scan lock - without network contact.
# ---------------------------------------------------------------------------


def test_the_free_space_of_the_map_around_the_export(share_link):
    from nsmcp import retention

    link, native = share_link
    assert _no_contact(native, lambda: retention.free_mb(link / "export")) == ("returned", None)


def test_a_new_work_map_beside_the_export(share_link):
    link, native = share_link
    kind, value = _no_contact(native, lambda: localpath.mkdtemp_local(link, "export.nieuw-", root=None))
    assert kind == "raised" and isinstance(value, localpath.PathRefused) and value.soort == "netwerkpad"


def test_removing_a_tree_and_the_scan_lock(share_link):
    from nsmcp import collect, retention

    link, native = share_link
    kind, value = _no_contact(native, lambda: retention._remove_tree(link / "export.vorig"))
    assert kind == "raised" and isinstance(value, localpath.PathRefused)
    assert _no_contact(native, lambda: collect._release_lock(link / "export.lock")) == ("returned", None)
    assert _no_contact(native, lambda: collect._remove_beside(link / "export.mislukt", link / "export")) == (
        "returned",
        None,
    )
