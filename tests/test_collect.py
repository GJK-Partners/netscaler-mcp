import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.collect import CollectError, build_arguments, collect, read_single_resource
from nsmcp.export import load_export
from nsmcp.target import CertAgreement, Target


@pytest.fixture
def script(tmp_path):
    """An EXISTING but empty script file.

    Deliberately not the real NSHC script: collect() checks fail-closed
    that the file exists, and the `run` stub takes over execution. If the
    real path stood here, these tests would fail on every machine without
    an NSHC checkout - and a bare clone of this repo must be able to run.
    """
    p = tmp_path / "collector.ps1"
    p.write_text("# leeg; draai() neemt het over in de test", encoding="utf-8")
    return p


def chain_target() -> Target:
    return Target(
        name="lab",
        address="10.0.0.10",
        credential_target="gjk/netscaler/lab/readonly",
        agreement=CertAgreement.CHAIN,
    )


def pin_target() -> Target:
    return Target(
        name="lab",
        address="10.0.0.10",
        credential_target="gjk/netscaler/lab/readonly",
        agreement=CertAgreement.FINGERPRINT,
        fingerprint="aa:bb:cc",
    )


def write_valid_export(dir_: Path) -> None:
    (dir_ / "objects").mkdir(parents=True, exist_ok=True)
    (dir_ / "bindings").mkdir(parents=True, exist_ok=True)
    (dir_ / "export-manifest.json").write_text(
        json.dumps(
            {
                "collectedAtUtc": "2026-08-20T12:00:00.0000000Z",
                "resources": {"sslcertkey": {"status": "OK"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )


def test_arguments_always_carry_skiptransport_and_the_target_name(script):
    args = build_arguments(chain_target(), Path("C:/uit"), script)
    assert "-SkipTransport" in args
    assert "-CredentialTarget" in args
    assert "gjk/netscaler/lab/readonly" in args
    assert "10.0.0.10" in args


def test_arguments_never_contain_the_escape_hatch(script):
    """The hard rule from the design: no interactive escape hatch, and none
    is coming. This test is the lock on that door."""
    for target in (chain_target(), pin_target()):
        args = build_arguments(target, Path("C:/uit"), script)
        assert not any("AcceptSelfSigned" in a for a in args)


def test_fingerprint_target_passes_the_pin(script):
    args = build_arguments(pin_target(), Path("C:/uit"), script)
    i = args.index("-ExpectedCertThumbprint")
    assert args[i + 1] == "AABBCC"


def test_chain_target_passes_no_pin(script):
    args = build_arguments(chain_target(), Path("C:/uit"), script)
    assert "-ExpectedCertThumbprint" not in args


def test_successful_scan_swaps_the_export(tmp_path, script):
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "oud.txt").write_text("vorige ronde", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    result = collect(chain_target(), export_dir, script, run=run_stub)
    assert result == export_dir
    assert (export_dir / "export-manifest.json").exists()
    assert not (export_dir / "oud.txt").exists()


@pytest.mark.parametrize("use_gate", [False, True])
def test_collect_forwards_retention_and_keeps_previous_scan(tmp_path, script, use_gate):
    from nsmcp.collect import SwapGate, _recover_interrupted_swap
    from nsmcp.retention import Retention, newest_kept

    export_dir = tmp_path / "export"
    write_valid_export(export_dir)
    manifest = export_dir / "export-manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["manifestVersion"] = "1.1"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    (export_dir / "old.txt").write_text("prior", encoding="utf-8")

    def runner(arguments, timeout_s):
        write_valid_export(Path(arguments[arguments.index("-OutDir") + 1]))
        return 0, ""

    result = collect(
        chain_target(),
        export_dir,
        script,
        run=runner,
        retention=Retention(enabled=True),
        stop=SwapGate() if use_gate else None,
    )
    assert result == export_dir
    assert not (export_dir / "old.txt").exists()
    assert (newest_kept(export_dir) / "old.txt").is_file()
    assert not (tmp_path / "export.vorig").exists()
    assert _recover_interrupted_swap(export_dir) is False


def test_post_swap_keep_error_never_reports_scan_failure_or_removes_current(tmp_path, monkeypatch, caplog):
    import importlib

    module = importlib.import_module("nsmcp.collect")
    from nsmcp.retention import Retention

    current = tmp_path / "export"
    work = tmp_path / "export.nieuw-test"
    write_valid_export(current)
    write_valid_export(work)
    (work / "new.txt").write_text("new", encoding="utf-8")

    def broken_keep(*args):
        raise OSError("PRIVATE_VALUE")

    monkeypatch.setattr(module, "keep", broken_keep)
    module._swap(work, current, Retention(enabled=True))
    assert (current / "new.txt").is_file()
    assert not (tmp_path / "export.vorig").exists()
    assert "PRIVATE_VALUE" not in caplog.text
    assert "bewaren" in caplog.text


def test_failed_swap_with_retention_still_recovers_previous(tmp_path, monkeypatch):
    from nsmcp.collect import _recover_interrupted_swap, _swap
    from nsmcp.retention import Retention, kept_exports

    current = tmp_path / "export"
    work = tmp_path / "export.nieuw-test"
    write_valid_export(current)
    write_valid_export(work)
    (current / "old.txt").write_text("prior", encoding="utf-8")
    original = Path.rename

    def fail(self, target):
        if self == work:
            raise PermissionError("PRIVATE_VALUE")
        return original(self, target)

    monkeypatch.setattr(Path, "rename", fail)
    with pytest.raises(CollectError, match="omwisselen"):
        _swap(work, current, Retention(enabled=True))
    assert kept_exports(current) == ()
    assert _recover_interrupted_swap(current) is True
    assert (current / "old.txt").is_file()


@pytest.mark.parametrize("use_gate", [False, True])
def test_collect_prunes_per_target_after_success_and_logs_safely(
    tmp_path, script, monkeypatch, caplog, capsys, use_gate
):
    from dataclasses import replace

    from nsmcp import retention
    from nsmcp.collect import SwapGate

    current = tmp_path / "export"
    counter = 0

    def runner(arguments, timeout_s):
        nonlocal counter
        counter += 1
        directory = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(directory)
        manifest = directory / "export-manifest.json"
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        raw.update(manifestVersion="1.1", collectedAtUtc=f"2026-09-{counter:02d}T08:00:00Z")
        manifest.write_text(json.dumps(raw), encoding="utf-8")
        return 0, ""

    monkeypatch.setattr(retention, "free_mb", lambda _: 5000)
    for name in ("lab-a", "lab-b", "lab-a", "lab-b", "lab-a"):
        collect(
            replace(chain_target(), name=name),
            current,
            script,
            run=runner,
            retention=retention.Retention(enabled=True, count=1),
            stop=SwapGate() if use_gate else None,
        )
    kept = retention.kept_exports(current)
    assert len(kept) == 2
    assert {retention.target_identity(p) for p in kept} == {"lab-a", "lab-b"}
    records = [r for r in caplog.records if r.message.startswith("bewaarbeleid:")]
    assert [r.message for r in records] == [
        "bewaarbeleid: bewaarde export 20260901T080000Z verwijderd",
        "bewaarbeleid: bewaarde export 20260902T080000Z verwijderd",
    ]
    assert all(r.levelname == "WARNING" for r in records)
    assert capsys.readouterr().out == ""


def test_swap_retention_logs_visible_on_default_stderr_in_fresh_process(tmp_path):
    import sys

    command = """
import json
from pathlib import Path
from nsmcp.collect import _swap
from nsmcp.retention import Retention
import nsmcp.retention as retention
root = Path(__import__('sys').argv[1])
retention.free_mb = lambda _: 5000
for day in (1, 2, 3):
    work = root / 'work'
    work.mkdir()
    (work / 'export-manifest.json').write_text(json.dumps({
        'manifestVersion': '1.1', 'resources': {}, 'files': {},
        'collectedAtUtc': f'2026-09-{day:02d}T08:00:00Z'
    }), encoding='utf-8')
    _swap(work, root / 'export', Retention(enabled=True, count=1))
"""
    result = subprocess.run([sys.executable, "-c", command, str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr.count("bewaarbeleid: bewaarde export 20260901T080000Z verwijderd") == 1


@pytest.mark.parametrize("failure", ["prune", "logging", "keep_and_logging"])
def test_post_swap_cleanup_or_logging_error_cannot_claim_rollback(tmp_path, monkeypatch, capsys, failure):
    import importlib
    import logging

    module = importlib.import_module("nsmcp.collect")
    from nsmcp.retention import Retention

    current = tmp_path / "export"
    work = tmp_path / "work"
    write_valid_export(current)
    write_valid_export(work)
    (work / "new.txt").write_text("new", encoding="utf-8")

    def broken(*args, **kwargs):
        raise OSError("PRIVATE_TARGET\nPRIVATE_PATH")

    if failure == "prune":
        monkeypatch.setattr(module, "prune", broken)
    else:
        monkeypatch.setattr(logging.Logger, "warning", broken)
        monkeypatch.setattr(module, "prune", lambda *a: ("bewaarbeleid: bewaarde export 20260901T080000Z verwijderd",))
        if failure == "keep_and_logging":
            monkeypatch.setattr(module, "keep", broken)
    module._swap(work, current, Retention(enabled=True))
    assert (current / "new.txt").is_file()
    captured = capsys.readouterr()
    assert captured.out == "" and "PRIVATE_" not in captured.err
    if failure != "prune":
        assert "bewaarbeleid:" in captured.err


def test_nonzero_exit_code_leaves_the_previous_export_untouched(tmp_path, script):
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")
    original = (export_dir / "export-manifest.json").read_text(encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 1, "kon niet inloggen"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    # Not "1" (which also happens to match a year or a path): the
    # literal phrase reporting the exit code.
    assert "exitcode 1" in str(err.value)
    assert (export_dir / "export-manifest.json").read_text(encoding="utf-8") == original


def test_scan_without_manifest_does_not_pass_as_an_empty_export(tmp_path, script):
    """Exit code 0 but no manifest: that is not 'nothing found', that is a
    failed scan. Without this gate the next question would answer 'zero
    certificates' and look green."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "manifest" in str(err.value).lower()


def test_manifest_without_timestamp_is_refused(tmp_path, script):
    """Without collectedAtUtc no answer can report its data age - then the
    scan is not usable."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(json.dumps({"resources": {}}), encoding="utf-8")
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "tijdstempel" in str(err.value).lower()


def test_an_interrupted_swap_is_recovered(tmp_path, script):
    """If the process dies between the two renames, the current export sits
    as .vorig and there is no export. The next call puts it back - so the
    server never answers on nothing because of last time's crash. The
    follow-up scan deliberately fails here: that way the recovered CONTENT
    (not just "a directory named export") is the only thing that can stay
    standing, and the test is not fooled by the normal swap that a
    successful follow-up scan would use to clean up .vorig anyway."""
    export_dir = tmp_path / "export"
    previous = tmp_path / "export.vorig"
    write_valid_export(previous)
    (previous / "kenmerk.txt").write_text("de herstelde export", encoding="utf-8")
    assert not export_dir.exists()

    def run_stub(arguments, timeout_s):
        return 1, "de vervolgscan mislukt bewust"

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub)

    assert export_dir.exists()
    assert (export_dir / "kenmerk.txt").read_text(encoding="utf-8") == "de herstelde export"
    assert not previous.exists()


def test_recovery_does_not_overwrite_an_existing_export(tmp_path, script):
    """Negative check: if a current export DOES stand next to an old .vorig,
    the recovery must not roll it back."""
    export_dir = tmp_path / "export"
    write_valid_export(export_dir)
    (export_dir / "kenmerk.txt").write_text("de geldende", encoding="utf-8")
    previous = tmp_path / "export.vorig"
    write_valid_export(previous)
    (previous / "kenmerk.txt").write_text("de oude", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        return 1, "mislukt"

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub)
    assert (export_dir / "kenmerk.txt").read_text(encoding="utf-8") == "de geldende"


def test_missing_collect_script_is_an_error_before_anything_runs(tmp_path):
    with pytest.raises(CollectError) as err:
        collect(chain_target(), tmp_path / "export", tmp_path / "bestaat-niet.ps1")
    assert "verzamelscript" in str(err.value).lower()


def test_the_credential_target_does_not_leak_in_the_error_message(tmp_path, script):
    """Error texts end up in logs. The target name is not a secret, but it
    does not belong unasked in every error line either."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return 1, "iets ging mis met gjk/netscaler/lab/readonly"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "gjk/netscaler/lab/readonly" not in str(err.value)


# --- Extra tests (self-review against the three failure patterns) ---
#
# The next three tests cover a form of failure pattern 1 ("str(x) is a
# conversion, not a type gate") the given tests above do not touch: those
# only test a MISSING key. JSON null (the key is there, the value is not)
# is a different case - str(None) becomes the text "None", which is
# non-empty, so an emptiness check without an isinstance gate lets it
# through.


def test_manifest_with_null_timestamp_is_refused(tmp_path, script):
    """collectedAtUtc: null must be refused just like a missing field -
    str(None).strip() is the text 'None' and is non-empty."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": None,
                    "resources": {"sslcertkey": {"status": "OK"}},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "tijdstempel" in str(err.value).lower()


def test_manifest_with_non_dict_resources_is_refused(tmp_path, script):
    """resources as a list is non-empty and would bypass a bare
    'not resources' check, without being a usable resource shape."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "2026-08-20T12:00:00.0000000Z",
                    "resources": ["niet", "een", "dict"],
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "resources" in str(err.value).lower()


def test_manifest_that_is_not_an_object_is_refused(tmp_path, script):
    """Valid JSON that is not an object (here: a list) must not crash on
    .get() - it must come out fail-closed as a CollectError, like every
    other broken manifest shape."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        return 0, ""

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub)


# --- The subprocess boundary -----------------------------------------------


def test_os_error_during_swap_becomes_a_collect_error(tmp_path, script, monkeypatch):
    """If the swap itself fails (for example a still-open file handle on
    Windows), that must not be a bare OSError breaking the CollectError
    contract. And the previous export must stay recoverable: if the export
    directory is gone but .vorig remains, the next call puts it back."""
    export_dir = tmp_path / "export"
    write_valid_export(export_dir)
    (export_dir / "kenmerk.txt").write_text("de geldende", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    original_rename = Path.rename

    def broken_rename(self, target):
        # The last step of the swap (work dir -> export dir) fails; the
        # earlier step (export dir -> .vorig) must simply proceed.
        if Path(target) == export_dir:
            raise PermissionError(5, "toegang geweigerd")
        return original_rename(self, target)

    monkeypatch.setattr(Path, "rename", broken_rename)

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub)

    previous = tmp_path / "export.vorig"
    assert previous.exists()
    assert (previous / "kenmerk.txt").read_text(encoding="utf-8") == "de geldende"


def test_manifest_where_everything_is_error_is_refused(tmp_path, script):
    """Every resource has status Error: nothing was read. That must not pass
    as a scan result - otherwise a broken scan swaps out a good export for
    nothing."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "2026-08-20T12:00:00.0000000Z",
                    "resources": {
                        "sslcertkey": {"status": "Error"},
                        "lbvserver": {"status": "Error"},
                    },
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "bruikbare" in str(err.value).lower()


def test_manifest_with_one_usable_and_one_failed_resource_is_accepted(tmp_path, script):
    """A partial scan where part could be read is an honest result - the
    read path itself turns the failed half into a read gap. It must not be
    rejected as 'nothing read'."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "objects").mkdir(parents=True, exist_ok=True)
        (out / "bindings").mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "2026-08-20T12:00:00.0000000Z",
                    "resources": {
                        "sslcertkey": {"status": "OK"},
                        "lbvserver": {"status": "Error"},
                    },
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    result = collect(chain_target(), export_dir, script, run=run_stub)
    assert result == export_dir


def test_credential_target_scrub_works_regardless_of_case(tmp_path, script):
    """The scrub must also hit a different spelling of the target name, not
    only exactly the casing the target's credential_target happens to
    have."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return 1, "iets ging mis met GJK/NetScaler/Lab/ReadOnly"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "gjk/netscaler/lab/readonly" not in str(err.value).lower()


def test_error_message_contains_the_informative_line_from_a_realistic_stack_trace(tmp_path, script):
    """A real PowerShell error is longer than the two-line piece of stack
    trace this test once had: the informative line does not sit right
    before the closing lines but a long way before them (the callstack,
    the "At <path>:line" context, CategoryInfo/FullyQualifiedErrorId and
    usually PSComputerName too push it further forward). The window must
    be wide enough to still cover such a realistic case, and at the same
    time stay clearly bounded - not the whole text."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    head_lines = [
        "Start-Transcript ge\u00efnitialiseerd",
        "Verbinden met 10.0.0.10",
    ]
    tail_lines = [
        "AUTH MISLUKT: ongeldige credential target",
        'Exception calling "Invoke-RestMethod" with "3" argument(s): "De externe server '
        'heeft een fout geretourneerd: (401) Unauthorized."',
        "At C:\\nshc\\collector.ps1:142 char:9",
        "+         Invoke-RestMethod @splat",
        "+         ~~~~~~~~~~~~~~~~~~~~~~~~",
        "    + CategoryInfo          : NotSpecified: (:) [Invoke-RestMethod], WebException",
        "    + FullyQualifiedErrorId : System.Net.WebException,Microsoft.PowerShell.Commands.InvokeRestMethodCommand",
        "    + PSComputerName        : 10.0.0.10",
        "   op Invoke-NshcCollect, regel 42",
        "   op <ScriptBlock>, regel 1",
    ]
    assert len(tail_lines) == 10
    stderr = "\n".join(head_lines + tail_lines) + "\n"

    def run_stub(arguments, timeout_s):
        return 1, stderr

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    text = str(err.value)
    assert "AUTH MISLUKT: ongeldige credential target" in text
    # Begrensd, niet onbeperkt: de allereerste head_lines vallen wel buiten het venster.
    assert "Start-Transcript ge\u00efnitialiseerd" not in text
    assert "Verbinden met 10.0.0.10" not in text


def test_failed_validation_preserves_the_work_dir_for_investigation(tmp_path, script):
    """A scan with exit code 0 that does not pass validation must not throw
    away its traces: the error message literally says this is a failed
    scan, so the evidence must remain for investigation."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "bewijsbestand.txt").write_text("sporen van de mislukte scan", encoding="utf-8")
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    failed_dir = tmp_path / "export.mislukt"
    assert failed_dir.exists()
    assert (failed_dir / "bewijsbestand.txt").read_text(encoding="utf-8") == "sporen van de mislukte scan"
    # The directory NAME, never the absolute
    # path - the full path carries this machine's directory layout and
    # (via mcp_server.py's status_ververs, which never renders through the
    # disclosure seam) would reach the answer text unmasked.
    assert failed_dir.name in str(err.value)
    assert str(failed_dir) not in str(err.value)


def test_failed_export_slot_does_not_grow_on_repeated_failures(tmp_path, script):
    """Two failures in a row must not pile up a second directory; the slot
    is fixed and the newest replaces the previous one."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    attempts = {"n": 0}

    def run_stub(arguments, timeout_s):
        attempts["n"] += 1
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "poging.txt").write_text(str(attempts["n"]), encoding="utf-8")
        return 0, ""

    for _ in range(2):
        with pytest.raises(CollectError):
            collect(chain_target(), export_dir, script, run=run_stub)

    failed_dir = tmp_path / "export.mislukt"
    children = list(tmp_path.glob("export.mislukt*"))
    assert children == [failed_dir]
    assert (failed_dir / "poging.txt").read_text(encoding="utf-8") == "2"


# --- Setup and locking -----------------------------------------------------


def test_export_on_a_not_yet_existing_parent_directory_succeeds(tmp_path, script):
    """On a fresh installation the parent directory of the export directory
    does not exist yet. `tempfile.mkdtemp(dir=...)` expects that directory
    to already exist and otherwise throws a bare OSError (WinError 3) -
    exactly the contract breach this design rules out ("never silent,
    never as an empty export" also holds for the very first scan ever).
    The parent directory must therefore be created first, within the same
    error handling as the rest of the setup."""
    export_dir = tmp_path / "nog-niet-bestaande-map" / "export"
    assert not export_dir.parent.exists()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    result = collect(chain_target(), export_dir, script, run=run_stub)
    assert result == export_dir
    assert (export_dir / "export-manifest.json").exists()


def test_concurrent_scan_during_active_scan_is_refused_by_the_lock(tmp_path, script):
    """Two scans at once on the same target is undesirable (a scan takes
    minutes and loads the appliance) and the design already rejects it
    ("never over the current export"). Instead of trying to make two scans
    both safe (that previously repaired only the work-dir name, not .vorig
    - see this function's history), the lock refuses a second scan while
    the first is still running. This launches scan B in the middle of scan
    A, while A's lock still stands - the sharpest case, and the case the
    old (replaced) version of this test could not see because B still got
    its own work dir back then."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    def run_a(arguments, timeout_s):
        with pytest.raises(CollectError, match="er loopt al een scan"):
            collect(chain_target(), export_dir, script, run=lambda *a, **k: (0, ""))
        out_a = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out_a)
        return 0, ""

    result = collect(chain_target(), export_dir, script, run=run_a)
    assert result == export_dir

    # Afterwards the lock is free again: a next scan does not have to wait.
    def run_c(arguments, timeout_s):
        out_c = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out_c)
        return 0, ""

    assert collect(chain_target(), export_dir, script, run=run_c) == export_dir


def test_a_stale_lock_is_refused_not_taken_over(tmp_path, script):
    """The stale-lock takeover has been removed (two races turned out to
    live in this one place - see the removal section further down this
    file): if the lock exists, refuse, period. No age check, no takeover.
    This plants a lock well older than the given time limit - under the
    old takeover machinery it would have been taken over - and the run
    stub must therefore never run: if it does, that proves the takeover
    still lives."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")
    lock_file = tmp_path / "export.lock"
    lock_file.write_text("99999", encoding="utf-8")
    stale_time = time.time() - 20  # ruim ouder dan de tijdslimiet van 10s hieronder
    os.utime(lock_file, (stale_time, stale_time))

    def run_must_not_run(arguments, timeout_s):
        raise AssertionError("bij een bestaand slot mag er geen scan starten, hoe oud ook")

    with pytest.raises(CollectError, match="er loopt al een scan"):
        collect(chain_target(), export_dir, script, run=run_must_not_run, timeout_s=10)

    # No takeover: the lock still stands exactly as it stood, and the
    # export is unchanged.
    assert lock_file.exists()
    assert lock_file.read_text(encoding="utf-8") == "99999"
    assert (export_dir / "export-manifest.json").read_text(encoding="utf-8") == '{"resources":{}}'


def test_refusal_message_names_lock_path_pid_and_operator_advice(tmp_path, script):
    """The message must really help a person who hits a stuck lock, now that
    the takeover is gone and this thus becomes a manual step: the pid
    inside it (read back, not just written), and the simple statement
    that the file may go when no scan is running any more.

    The BARE NAME of the lock file, never the full
    absolute path - a `CollectError` message reaches `status_ververs`'s
    answer without ever passing through the disclosure seam (see
    mcp_server.py), so a local filesystem path here would leak at every
    disclosure level. This test used to assert the opposite (the full
    path IS in the text) - that was the defect, not a premise to keep."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    lock_file = tmp_path / "export.lock"
    lock_file.write_text("424242", encoding="utf-8")

    def run_must_not_run(arguments, timeout_s):
        raise AssertionError("bij een bestaand slot mag er geen scan starten")

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_must_not_run)

    text = str(err.value)
    assert str(lock_file) not in text
    assert lock_file.name in text
    assert "424242" in text
    assert "geen scan" in text.lower()


def test_failed_lock_write_leaves_no_lock_file_behind(tmp_path, script, monkeypatch):
    """If writing the pid into the brand-new lock file fails (the file then
    already exists thanks to O_CREAT|O_EXCL, but the content does not), it
    must not remain. The staleness detection used to resolve such a
    half-created lock at the next scan; now that it is gone (see above),
    an empty lock-file corpse would refuse every later scan forever if
    this were not cleaned up explicitly."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def broken_fdopen(fd, *a, **k):
        os.close(fd)
        raise OSError(28, "geen ruimte meer op het apparaat")

    monkeypatch.setattr(os, "fdopen", broken_fdopen)

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=lambda *a, **k: (0, ""))

    assert not (tmp_path / "export.lock").exists()


def test_no_staleness_or_takeover_machinery_present_any_more():
    """Documenting gate: greps the module itself for the removed stale-lock
    takeover, so a future 'convenient' reintroduction fails here
    immediately instead of only at the next race."""
    source = Path(__file__).resolve().parent.parent / "src" / "nsmcp" / "collect.py"
    text = source.read_text(encoding="utf-8")
    assert "import time" not in text
    assert "st_mtime" not in text
    assert "leeftijd_s" not in text


# --- Recovery of an interrupted swap must run BEFORE the lock: if the ---
# process dies between the two renames of _swap, .lock also remains (the
# finally releasing it never ran) - and _acquire_lock would then refuse
# every next call before recovery ever got a chance. Permanently, until a
# person removes the lock file by hand.


def test_recovery_runs_even_when_the_lock_of_that_same_crash_still_stands(tmp_path, script):
    """Reproduces the crash the docstring of `_recover_interrupted_swap`
    literally talks about: the process dies EXACTLY between the two
    renames. Then both `export.vorig` (the old, valid export) and
    `export.lock` (of that same dead scan - the finally releasing the lock
    never ran) remain.

    Important: this calls `collect()` (the real caller), not
    `_recover_interrupted_swap()` directly - a test on that pure function
    in isolation could not pin the bug, because the bug sits in the ORDER
    in which `collect()` calls it relative to the lock, not in the
    function itself.

    The scan itself may remain refused (the crash's lock is still there,
    and stale-lock takeover is deliberately not brought back) - but the
    DATA must already be back before a person ever intervenes, not only
    after a next successful scan."""
    export_dir = tmp_path / "export"
    previous = tmp_path / "export.vorig"
    write_valid_export(previous)
    (previous / "kenmerk.txt").write_text("de export van voor de crash", encoding="utf-8")
    lock_file = tmp_path / "export.lock"
    lock_file.write_text("13579", encoding="utf-8")
    assert not export_dir.exists()

    def run_must_not_run(arguments, timeout_s):
        raise AssertionError("het slot van de crash staat er nog; er mag geen scan starten")

    with pytest.raises(CollectError, match="er loopt al een scan") as err:
        collect(chain_target(), export_dir, script, run=run_must_not_run)

    # The core of the repair: despite the (justified) refusal the export
    # is back - not only at a next, successful scan.
    assert export_dir.exists(), "het herstel had voor het slot moeten lopen"
    assert (export_dir / "kenmerk.txt").read_text(encoding="utf-8") == "de export van voor de crash"
    assert not previous.exists()

    # The refusal must say what is going on: this lock is probably the
    # corpse of the crash just recovered, not a genuine running scan.
    text = str(err.value)
    assert "hersteld" in text.lower() or "onderbroken" in text.lower()


def test_os_error_during_swap_recovery_becomes_a_collect_error(tmp_path, script, monkeypatch):
    """The rename inside `_recover_interrupted_swap` (.vorig -> export dir)
    sat outside `collect`'s try/except OSError - the same contract breach
    as with the swap itself, now on the recovery step instead of the swap
    step.

    The run stub below deliberately returns exit code 1 ("irrelevant - het
    herstel faalt al voor de scan begint"). Without `match=` on
    `pytest.raises` this test cannot distinguish between the intended
    route (the recovery step itself fails) and that exit-code-1 route:
    surgically remove the `raise CollectError(...)` in the except branch
    of `_recover_interrupted_swap` and recovery falls silently through to
    `return True`, the scan still runs through the stub, and that returns
    the same `CollectError` class (now for exit code 1) - a bare
    `pytest.raises(CollectError)` then stays green while the recovery
    route itself is no longer tested. `match=` pins the text to the
    recovery route, so that mutation does make this test fail."""
    export_dir = tmp_path / "export"
    previous = tmp_path / "export.vorig"
    write_valid_export(previous)
    assert not export_dir.exists()

    original_rename = Path.rename

    def broken_rename(self, target):
        if self == previous:
            raise PermissionError(5, "toegang geweigerd")
        return original_rename(self, target)

    monkeypatch.setattr(Path, "rename", broken_rename)

    def run_stub(arguments, timeout_s):
        return 1, "irrelevant - het herstel faalt al voor de scan begint"

    with pytest.raises(CollectError, match="herstellen"):
        collect(chain_target(), export_dir, script, run=run_stub)


def test_recovery_race_where_another_caller_already_won_gives_no_error(tmp_path, script, monkeypatch):
    """The hardening branch in `_recover_interrupted_swap`: if the own
    rename (.vorig -> export dir) fails with an OSError but the export dir
    THEN exists after all, another racing caller has meanwhile put it back
    itself - there is nothing left to recover. That must simply yield
    False (`collect()` continues with a normal scan), not a CollectError
    about a recovery that is in fact long done. Without this branch the
    SECOND caller would wrongly report its own failed rename as a real
    recovery error, while the export is actually already fine."""
    export_dir = tmp_path / "export"
    previous = tmp_path / "export.vorig"
    write_valid_export(previous)
    assert not export_dir.exists()

    original_rename = Path.rename

    def other_caller_wins_the_race(self, target):
        if self == previous and Path(target) == export_dir:
            # Simulates a racing second caller completing the rename just
            # before us: the export dir already exists when WE try.
            write_valid_export(export_dir)
            raise FileExistsError(183, "een andere aanroeper won de race")
        return original_rename(self, target)

    monkeypatch.setattr(Path, "rename", other_caller_wins_the_race)

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    result = collect(chain_target(), export_dir, script, run=run_stub)

    assert result == export_dir, (
        "de race werd herkend als 'al hersteld door een ander', dus de gewone "
        "scan mocht gewoon doorgaan in plaats van te falen op een herstelfout"
    )


def test_a_leftover_work_dir_of_an_aborted_scan_is_cleaned_up(tmp_path, script):
    """If a process is killed between mkdtemp and the finally,
    <export>.nieuw-XXXXXXXX remains; nothing ever cleaned that up. At the
    start of the next scan - while the own lock already stands, so nobody
    else can still be using such a directory - that junk is cleaned up."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")
    leftover = tmp_path / "export.nieuw-oudepoging"
    leftover.mkdir()
    (leftover / "rommel.txt").write_text("van een afgebroken scan", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)
    assert not leftover.exists()


# --- Stale-lock takeover removed (instead of repaired) ---
#
# Two races both turned out to come from the same mechanism: the
# stale-lock takeover in _acquire_lock. The decision is to remove that
# mechanism instead of repairing it a third time - see the tests above
# (`test_a_stale_lock_is_refused_not_taken_over`,
# `test_refusal_message_names_lock_path_pid_and_operator_advice`,
# `test_failed_lock_write_leaves_no_lock_file_behind`,
# `test_no_staleness_or_takeover_machinery_present_any_more`), which
# replace the old takeover test.


def test_cleanup_of_old_work_dirs_uses_no_glob_matching(tmp_path, script):
    """An export directory name with a glob metacharacter (here:
    `export[1]`, valid in a Windows directory name) must not let the
    cleanup wander to a different export. `Path.glob` interprets `[1]` as
    a character class: the own `export[1].nieuw-eigen` then does NOT match
    (there is no literal `[` in the class), but `export1.nieuw-actief` -
    the work dir of an entirely different, active export, protected by a
    different lock - does."""
    export_dir = tmp_path / "export[1]"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    own_junk = tmp_path / "export[1].nieuw-eigen"
    own_junk.mkdir()
    (own_junk / "rommel.txt").write_text("van een afgebroken scan op dit doel", encoding="utf-8")

    other_active_work_dir = tmp_path / "export1.nieuw-actief"
    other_active_work_dir.mkdir()
    (other_active_work_dir / "in-gebruik.txt").write_text("een andere export, een ander slot", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)

    assert not own_junk.exists()
    assert other_active_work_dir.exists()
    assert (other_active_work_dir / "in-gebruik.txt").exists()


def test_cleanup_skips_a_file_with_a_matching_name(tmp_path, script):
    """A file (not a directory) that happens to match the `.nieuw-` pattern
    must be skipped with an explicit `is_dir()` check. That used to happen
    silently through `shutil.rmtree(..., ignore_errors=True)`, which never
    did anything on a file anyway; now it is deliberate code, not
    coincidence."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    same_named_file = tmp_path / "export.nieuw-log.txt"
    same_named_file.write_text("geen map, mag niet crashen of verdwijnen", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)
    assert same_named_file.exists()


def test_work_dir_prefix_is_pinned_to_what_the_cleanup_looks_for(tmp_path, script):
    """Nothing else tests the name of the work dir `collect` itself creates.
    If the mkdtemp prefix changes, the cleanup test for leftover work dirs
    (`test_a_leftover_work_dir_of_an_aborted_scan_is_cleaned_up`) stays
    green while the cleanup finds nothing in practice any more - the two
    are not pinned to each other. This test captures the real work dir
    name (through the `run` callback, which receives `-OutDir`) and checks
    that it carries the prefix `_clean_stale_work_dirs` looks for."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    work_dir_name: dict[str, str] = {}

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        work_dir_name["naam"] = out.name
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)
    assert work_dir_name["naam"].startswith(f"{export_dir.name}.nieuw-")


def test_cleanup_does_not_touch_a_work_dir_of_another_export_in_the_same_parent(tmp_path, script):
    """The assertion that was lost when an earlier test was replaced: a work
    dir belonging to a DIFFERENT target - its own lock, its own export
    name - must not be touched by this target's cleanup, even though it
    sits in the same parent directory. Separate from the glob
    metacharacter test above: here it is purely about two ordinary,
    different export names side by side."""
    export_dir = tmp_path / "export-a"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    other_export_work_dir = tmp_path / "export-b.nieuw-nogbezig"
    other_export_work_dir.mkdir()
    (other_export_work_dir / "in-gebruik.txt").write_text("hoort bij export-b", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)
    assert other_export_work_dir.exists()
    assert (other_export_work_dir / "in-gebruik.txt").exists()


# --- A stop signal must terminate the real child process, not merely ------
# let the Python call return.


def test_stop_signal_terminates_a_real_child_process_and_collect_does_not_swap(tmp_path, script):
    """Proven with a REAL PowerShell child process (no run stub):
    `collect(..., stop=...)` must, as soon as `stop` is set while the
    collector script is still running, really make that child process stop
    (not merely let the Python call return) AND leave the previous,
    current export untouched.

    The script writes its own PID as soon as it starts (proof that it
    really runs, no shot in the dark) and then sleeps 30 seconds - well
    longer than this test may take if the stop signal really works. After
    `stop.set()`, `tasklist` verifies that the PID really no longer exists
    - not merely that `collect()` returned."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    pid_file = tmp_path / "kind.pid"
    long_script = tmp_path / "lang.ps1"
    long_script.write_text(
        f"$PID | Out-File -FilePath '{pid_file}' -Encoding ascii\nStart-Sleep -Seconds 30\n",
        encoding="utf-8",
    )

    stop = threading.Event()
    outcome: dict = {}

    def run_the_scan():
        try:
            collect(chain_target(), export_dir, long_script, timeout_s=60, stop=stop)
        except CollectError as err:
            outcome["fout"] = err
        except BaseException as exc:  # pragma: no cover - moet nooit gebeuren
            outcome["onverwacht"] = exc

    thread = threading.Thread(target=run_the_scan)
    thread.start()

    # Waited on the CONTENT, not on the file. PowerShell creates the file the
    # moment it opens it and writes the pid a beat later, so waiting on
    # existence alone read an empty string and this test fell over on
    # `int('')` - a race in the test, not in the product (keuring
    # 9c1feca..4b442a7, P3). The bound and everything asserted below are
    # unchanged.
    deadline = time.time() + 15
    geschreven = ""
    while time.time() < deadline:
        try:
            geschreven = pid_file.read_text(encoding="utf-8").strip()
        except OSError:
            # The file exists but the child still holds it - keep waiting.
            geschreven = ""
        if geschreven.isdigit():
            break
        time.sleep(0.05)
    assert geschreven.isdigit(), (
        f"het kindproces heeft nooit zijn eigen pid weggeschreven (bestaat={pid_file.exists()}, inhoud={geschreven!r})"
    )
    child_pid = int(geschreven)

    stop.set()
    thread.join(timeout=20)
    assert not thread.is_alive(), "collect() keerde niet terug nadat het stopsignaal gezet werd"

    # The child process really terminated - not merely our call returning.
    tasklist = subprocess.run(["tasklist", "/FI", f"PID eq {child_pid}"], capture_output=True, text=True, check=False)
    assert str(child_pid) not in tasklist.stdout, (
        f"het kindproces (pid {child_pid}) draait na het stopsignaal nog steeds:\n{tasklist.stdout}"
    )

    assert "fout" in outcome, f"collect() gaf geen CollectError: {outcome}"
    assert "onverwacht" not in outcome, outcome.get("onverwacht")
    assert (export_dir / "export-manifest.json").read_text(encoding="utf-8") == '{"resources":{}}', (
        "de omwisseling gebeurde toch, ondanks het stopsignaal"
    )


# ---------------------------------------------------------------------------
# All three KNOWN values of the target must be masked in a failed-scan
# report. The address and (under a fingerprint agreement) the fingerprint
# sit on the command line (build_arguments) just as much as the credential
# target, and thus just as much within reach of a collector error - a DNS
# error names the address literally, a pin mismatch the expected
# fingerprint.
# ---------------------------------------------------------------------------


def test_address_and_fingerprint_are_masked_like_the_credential_target(tmp_path, script):
    """All three are known values of the target (see build_arguments): the
    masking must hit all three, not only the credential target name."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return (
            1,
            "kon geen verbinding maken met 10.0.0.10: verwachte vingerafdruk AABBCC "
            "kwam niet overeen met de credential gjk/netscaler/lab/readonly",
        )

    with pytest.raises(CollectError) as err:
        collect(pin_target(), export_dir, script, run=run_stub)
    text = str(err.value)
    assert "10.0.0.10" not in text
    assert "AABBCC" not in text
    assert "gjk/netscaler/lab/readonly" not in text


# ---------------------------------------------------------------------------
# An export must know WHICH target produced it. collect() records that in
# the work dir, before the swap (so it lands atomically); load_export()
# reads it back.
# ---------------------------------------------------------------------------


def test_successful_scan_records_the_target_just_before_the_swap(tmp_path, script):
    """After a successful scan the export itself must be able to say which
    target produced it."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)

    export = load_export(export_dir)
    assert export.target_name == "lab"


def test_the_gate_carries_the_manifest_hash_of_the_export_it_swapped_in(tmp_path, script):
    """The caller records THIS hash as collected - the one written beside
    the target in the work map - never a second reading of the export map
    after the swap. An aborted swap carries none."""
    import hashlib

    from nsmcp.collect import SwapGate

    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        write_valid_export(Path(arguments[arguments.index("-OutDir") + 1]))
        return 0, ""

    gate = SwapGate()
    collect(chain_target(), export_dir, script, run=run_stub, stop=gate)
    written = (export_dir / "scan-doel.txt").read_text(encoding="utf-8").splitlines()[1]
    manifest = hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()
    assert gate.manifest_hash == written == manifest

    aborted = SwapGate()
    aborted.request_cancellation()
    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub, stop=aborted)
    assert aborted.manifest_hash is None


def test_a_supplied_export_without_scan_file_has_no_target_name(tmp_path):
    """Negative check: an export not scanned by this server (no scan-target
    file) must never GUESS the target - that must honestly stay
    'niet vastgelegd' (None)."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    write_valid_export(export_dir)

    export = load_export(export_dir)
    assert export.target_name is None


# ---------------------------------------------------------------------------
# The swap gate must check READABILITY of collectedAtUtc, not only
# PRESENCE. A manifest with "collectedAtUtc": "gisteren" used to pass the
# gate and get swapped in, after which the answer itself reported
# "tijdstempel onleesbaar" - the gate promises in its own error message
# that it covers this ("zonder collectedAtUtc kan geen antwoord zijn
# gegevensleeftijd melden"), so it must really be able to PARSE it.
# ---------------------------------------------------------------------------


def test_manifest_with_unreadable_timestamp_is_refused_by_the_swap_gate(tmp_path, script):
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "gisteren",
                    "resources": {"sslcertkey": {"status": "OK"}},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    assert "onleesbaar" in str(err.value).lower()


# ---------------------------------------------------------------------------
# The commit gate. A cancellation landing AFTER _verify() but BEFORE the
# swap used to let the swap proceed - the only stop check sat BEFORE
# _verify(), not after it. This test hooks _verify() itself (the seam) to
# set `stop` at exactly that late moment. See the regression coverage for
# the literal RED/GREEN pytest output of the original repair.
# ---------------------------------------------------------------------------


def test_stop_after_verify_but_before_the_swap_does_not_swap(tmp_path, script, monkeypatch):
    """A cancellation landing after _verify() has already validated but
    BEFORE the swap itself happens must always be treated by collect() as
    an aborted scan - never as a successful swap. The previous, current
    export must remain untouched and collect() must raise a
    CollectError."""
    import nsmcp.collect as collect_module
    from nsmcp.collect import SwapGate

    export_dir = tmp_path / "export"
    write_valid_export(export_dir)
    (export_dir / "kenmerk.txt").write_text("de vorige, geldende export", encoding="utf-8")

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    stop = SwapGate()
    original_verify = collect_module._verify

    def verify_and_cancel(work_dir):
        # The REAL check runs first, as always.
        original_verify(work_dir)
        # The cancellation lands HERE: after a successful check, before
        # the swap. This is exactly the window.
        stop.cancel()

    monkeypatch.setattr(collect_module, "_verify", verify_and_cancel)

    with pytest.raises(CollectError):
        collect(chain_target(), export_dir, script, run=run_stub, stop=stop)

    assert (export_dir / "kenmerk.txt").read_text(encoding="utf-8") == "de vorige, geldende export", (
        "de omwisseling gebeurde toch, ondanks dat de annulering na _verify() maar voor de "
        "omwisseling landde - de gemeten kapotte middenweg"
    )
    assert stop.outcome == "aborted"


def test_stop_that_loses_the_lock_race_reports_committed_not_aborted(tmp_path, script):
    """The flip side of the same gate: if the WORKER wins the race for the
    lock (it commits while the cancellation is still waiting on the lock),
    `cancel()` must return that honestly - "committed", not "aborted" or
    None. This is the guarantee mcp_server.py leans on to never report
    "aborted" about a swap that has already irreversibly happened."""
    from nsmcp.collect import SwapGate

    gate = SwapGate()
    order: list[str] = []

    def swap():
        order.append("omgewisseld")

    outcome = gate.decide(swap)
    assert outcome == "committed"
    assert order == ["omgewisseld"]
    # `stop_set_at_commit_boundary` is the explicit bookkeeping that lets
    # mcp_server.py report the causal order ("cancellation AFTER the commit
    # boundary") without deriving it. No stop request at the check: False.
    assert gate.stop_set_at_commit_boundary is False

    # The cancellation now comes TOO LATE: the swap has already happened.
    # It must know that, not assume it won.
    late_cancellation = gate.cancel()
    assert late_cancellation == "committed"


def test_stop_that_wins_the_lock_race_prevents_the_swap(tmp_path, script):
    """And the first half of that same guarantee: if the cancellation wins
    the race (it sets stop BEFORE the worker decides), `swap` must never
    be called."""
    from nsmcp.collect import SwapGate

    gate = SwapGate()
    order: list[str] = []

    cancelled = gate.cancel()
    assert cancelled is None  # de worker had nog geen beslissing genomen

    def swap():
        order.append("omgewisseld")  # mag NOOIT gebeuren

    outcome = gate.decide(swap)
    assert outcome == "aborted"
    assert order == [], "swap werd aangeroepen ondanks dat stop al gezet was"
    # The stop request was already there at the check - True, the flip
    # side of the assert in the previous test.
    assert gate.stop_set_at_commit_boundary is True


# ---------------------------------------------------------------------------
# Overlapping known values must be masked completely. A fixed replacement
# order (credential target first, then address, then fingerprint) replaced
# the SHORTER name first when it happened to be a substring of a LONGER
# known value - the remainder of that longer value then stayed visible in
# the error message.
# ---------------------------------------------------------------------------


def test_credential_target_inside_the_address_is_still_fully_masked(tmp_path, script):
    """target-inside-address: the credential target name ('ns01') is a
    substring of the address ('ns01.example') here. The fixed order
    replaced 'ns01' first, after which '.example' - a piece of the known
    address value - simply remained."""
    target = Target(
        name="lab",
        address="ns01.example",
        credential_target="ns01",
        agreement=CertAgreement.CHAIN,
    )
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return 1, "verbinding met ns01.example via ns01 mislukt"

    with pytest.raises(CollectError) as err:
        collect(target, export_dir, script, run=run_stub)

    text = str(err.value)
    assert "example" not in text.lower(), text
    assert "ns01" not in text.lower(), text


def test_address_inside_the_credential_target_is_still_fully_masked(tmp_path, script):
    """address-inside-target: now the ADDRESS ('ns01') is the shorter value
    and sits as a substring inside the credential target name
    ('gjk/netscaler/ns01/readonly'). The same sort-by-length must cover
    this too, regardless of which FIELD happens to carry the longer
    value."""
    target = Target(
        name="lab",
        address="ns01",
        credential_target="gjk/netscaler/ns01/readonly",
        agreement=CertAgreement.CHAIN,
    )
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return 1, "verbinding met ns01 via gjk/netscaler/ns01/readonly mislukt"

    with pytest.raises(CollectError) as err:
        collect(target, export_dir, script, run=run_stub)

    text = str(err.value)
    assert "gjk/netscaler/ns01/readonly" not in text
    assert "ns01" not in text.lower(), text


def test_masking_works_regardless_of_case_with_overlapping_values(tmp_path, script):
    """The same overlap as above, now with DIFFERENT casing in the error
    message - the sort by length must not break the existing
    case-insensitive replacement."""
    target = Target(
        name="lab",
        address="NS01.EXAMPLE",
        credential_target="ns01",
        agreement=CertAgreement.CHAIN,
    )
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        return 1, "verbinding met NS01.example via NS01 mislukt"

    with pytest.raises(CollectError) as err:
        collect(target, export_dir, script, run=run_stub)

    text = str(err.value)
    assert "example" not in text.lower(), text
    assert "ns01" not in text.lower(), text


# ---------------------------------------------------------------------------
# The CollectError contract also covers filesystem operations. An OSError
# while reading the manifest or while enumerating old work dirs used to
# leak out raw - the generic, masked "onverwachte fout" whose details are
# explicitly NOT preserved (see mcp_server.py::mask_error), so the
# operator lost the usable cause.
# ---------------------------------------------------------------------------


def test_manifest_permissionerror_on_read_becomes_a_contextual_collect_error(tmp_path, script, monkeypatch):
    """manifest.read_text() raising a PermissionError (for example an ACL
    conflict) must become a contextual CollectError, with the OSError
    preserved as cause - not a raw PermissionError.

    The SURFACE TEXT no longer echoes the raw
    PermissionError message (`OSError.__str__()` can carry a full absolute
    path on Windows) - it names the KIND only (`_os_error_kind`). The
    original exception is not lost, though: it is still the real
    PermissionError, still reachable via `__cause__`, just no longer
    stringified into the message an operator (and the model) reads."""
    export_dir = tmp_path / "export"

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")
        return 0, ""

    original_read_text = Path.read_text

    def broken_read_text(self, *a, **k):
        if self.name == "export-manifest.json":
            raise PermissionError(13, "toegang geweigerd")
        return original_read_text(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", broken_read_text)

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    # A failed _verify() is preserved-as-failed by collect() and wrapped
    # again (see _preserve_as_failed/collect()), so the original
    # PermissionError can sit one CollectError step further down the
    # __cause__ chain instead of directly on it - walk the chain instead
    # of checking just one step.
    cause = err.value.__cause__
    while cause is not None and not isinstance(cause, PermissionError):
        cause = cause.__cause__
    assert isinstance(cause, PermissionError), (
        f"de oorspronkelijke PermissionError ging verloren uit de __cause__-keten van {err.value!r}"
    )
    assert "toegang geweigerd" not in str(err.value)  # C2: never the raw OS message
    assert "geen toegang" in str(err.value)


def test_cleanup_permissionerror_on_iterdir_becomes_a_contextual_collect_error(tmp_path, script, monkeypatch):
    """The parent directory's iterdir() raising a PermissionError (for
    example an ACL on the parent directory) during cleanup of old work
    dirs must become a contextual CollectError, not a raw
    PermissionError.

    Same repair as the manifest-read test above -
    the KIND survives in the text, the raw OS message (and any path in
    it) does not; the real exception still survives as `__cause__`."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (export_dir / "export-manifest.json").write_text('{"resources":{}}', encoding="utf-8")

    original_iterdir = Path.iterdir

    def broken_iterdir(self, *a, **k):
        if self == export_dir.parent:
            raise PermissionError(13, "toegang geweigerd tot de ouder-map")
        return original_iterdir(self, *a, **k)

    monkeypatch.setattr(Path, "iterdir", broken_iterdir)

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=lambda *a, **k: (0, ""))

    assert isinstance(err.value.__cause__, PermissionError), (
        f"de oorspronkelijke PermissionError ging verloren; __cause__ is {err.value.__cause__!r}"
    )
    assert "toegang geweigerd tot de ouder-map" not in str(err.value)  # C2: never the raw OS message
    assert "geen toegang" in str(err.value)


# ---------------------------------------------------------------------------
# The REAL NSHC 1.0 collector logs through `Write-Host` - so stdout, not
# stderr (see NshcCollector-PlakEditie.ps1 line 68). On a non-zero exit
# code, only capturing stderr throws the informative stdout half away.
# Every test above injects a run stub (a fake runner with signature
# (arguments, timeout_s) -> (exitcode, stderr)) and therefore never
# touches the REAL `_run_powershell` - this is the FIRST test that starts
# a real PowerShell child process and lets its stdout-only FAIL line try
# to reach the short report. No param() block needed: PowerShell binds
# unknown named arguments (-NetScaler, -OutDir, ...) only to explicitly
# declared parameters - without a param() block they land unused in
# $args, exactly as the existing
# `test_stop_signal_terminates_a_real_child_process...` above already
# shows with a param()-less script.
# ---------------------------------------------------------------------------


def test_failed_scan_shows_the_write_host_line_not_just_no_error_line(tmp_path):
    """A real PowerShell script that logs its failure reason through
    Write-Host (stdout) and then does `exit 1` must really get that
    failure reason back in the CollectError - not the contentless
    'geen foutregel' that arises when only stderr is captured."""
    export_dir = tmp_path / "export"
    ps1 = tmp_path / "faalscript.ps1"
    ps1.write_text(
        "Write-Host 'FAIL: het zelfondertekende certificaat is niet vertrouwd; "
        "GESTOPT VOORDAT om inloggegevens is gevraagd'\n"
        "exit 1\n",
        encoding="utf-8",
    )

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, ps1, timeout_s=60)

    text = str(err.value)
    assert "geen foutregel" not in text, f"de write-host-regel had het kort verslag moeten halen: {text}"
    assert "het zelfondertekende certificaat is niet vertrouwd" in text
    assert "GESTOPT VOORDAT om inloggegevens is gevraagd" in text


# ---------------------------------------------------------------------------
# `read_single_resource` - ONE resource, live, for the pre-flight (B3, check 8).
#
# This function is the live half of `status_update_preflight`, the
# SECOND documented exception to "a reading tool never opens a socket" (design
# 2.10 row 13, 3.1). The product process still opens no socket; the collector
# script does, in the same separate process a scan uses, with the same
# `doelen` credential. Everything below therefore drives it through the `run`
# stub - no test in this repository ever contacts an appliance.
# ---------------------------------------------------------------------------


def _live_manifest(out: Path, resource: str, payload: dict) -> None:
    """What a collector run for ONE resource leaves behind."""
    (out / "objects").mkdir(parents=True, exist_ok=True)
    property_name = resource.split("/")[-1].split("?", 1)[0]
    (out / "objects" / f"{property_name}.json").write_text(json.dumps({property_name: payload}), encoding="utf-8")
    (out / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-05T10:00:00.0000000Z",
                "resources": {resource: {"status": "OK", "propertyName": property_name}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(out)


def test_a_single_resource_read_asks_the_script_for_exactly_that_resource(tmp_path, script):
    seen = {}

    def run(arguments, timeout_s):
        seen["arguments"] = list(arguments)
        out = Path(arguments[arguments.index("-OutDir") + 1])
        _live_manifest(out, "stat/system", {"disk1avail": "9000"})
        return 0, ""

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert gap is None
    assert row == {"disk1avail": "9000"}
    assert seen["arguments"][-2:] == ["-OnlyResources", "stat/system"]
    # The same argument list a scan builds, plus that one pair - not a second
    # route and not a second credential.
    assert "-SkipTransport" in seen["arguments"]
    assert "gjk/netscaler/lab/readonly" in seen["arguments"]
    assert "-AcceptSelfSignedCert" not in seen["arguments"]


def test_a_single_resource_read_leaves_no_directory_behind(tmp_path, script):
    captured = {}

    def run(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        captured["out"] = out
        _live_manifest(out, "stat/system", {"disk1avail": "9000"})
        return 0, ""

    read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert not captured["out"].exists(), "de tijdelijke uitvoermap moet opgeruimd zijn"


def test_a_single_resource_read_never_touches_the_export_directory(tmp_path, script):
    """Not a second scan route: nothing is swapped into the export directory."""
    export_dir = tmp_path / "export"
    write_valid_export(export_dir)
    before = (export_dir / "export-manifest.json").read_bytes()

    def run(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        assert out != export_dir
        _live_manifest(out, "stat/system", {"disk1avail": "9000"})
        return 0, ""

    read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert (export_dir / "export-manifest.json").read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["collector.ps1", "export"]


def test_a_script_that_does_not_know_the_argument_is_a_read_gap_never_a_value(tmp_path, script):
    """The collector script sits OUTSIDE this product (it is configured), so
    the product cannot force `-OnlyResources` support. What it can do is never
    turn a script that lacks it into a silent green."""

    def run(arguments, timeout_s):
        return 1, "A parameter cannot be found that matches parameter name 'OnlyResources'."

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert row is None
    assert gap is not None
    assert "OnlyResources" in gap.reason


def test_a_run_without_an_object_file_is_a_read_gap(tmp_path, script):
    def run(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "2026-09-05T10:00:00.0000000Z",
                    "resources": {"stat/system": {"status": "OK", "propertyName": "system"}},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert row is None and gap is not None


def test_a_run_without_a_manifest_is_a_read_gap(tmp_path, script):
    def run(arguments, timeout_s):
        return 0, ""

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert row is None and gap is not None
    assert "manifest" in gap.reason


def test_a_missing_script_is_a_read_gap_before_anything_runs(tmp_path):
    row, gap = read_single_resource(chain_target(), "stat/system", tmp_path / "bestaat-niet.ps1", timeout_s=60)

    assert row is None and gap is not None
    assert "verzamelscript" in gap.reason


def test_the_credential_target_never_leaks_into_the_read_gap(tmp_path, script):
    """The same scrub as a failed scan: address, credential-target name and
    fingerprint are masked in whatever the script printed.

    The three values are read off the TARGET rather than written out, so this
    test cannot drift away from the normalization `Target` applies (a
    fingerprint loses its separators and goes uppercase) - and it measures
    exactly what `_scrub_error_text` promises: the values this product KNOWS
    are of this target, which are also the values that stand on the command
    line."""
    target = pin_target()

    def run(arguments, timeout_s):
        return 1, (f"Kan niet inloggen op {target.address} met {target.credential_target} ({target.fingerprint})")

    row, gap = read_single_resource(target, "stat/system", script, timeout_s=60, run=run)

    assert row is None and gap is not None
    for known in (target.address, target.credential_target, target.fingerprint):
        assert known not in gap.reason


def test_a_timeout_is_a_read_gap_and_not_an_exception(tmp_path, script):
    """Fail closed in EVERY direction: a CollectError out of the runner
    becomes a read gap here, never an exception the pre-flight has to catch
    (it would then lose the other eight checks over it)."""

    def run(arguments, timeout_s):
        raise CollectError("de scan is na 60 seconden afgebroken; de vorige gegevens blijven gelden")

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert row is None and gap is not None
    assert "afgebroken" in gap.reason


def test_a_resource_the_manifest_calls_unusable_is_a_read_gap(tmp_path, script):
    def run(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        (out / "objects").mkdir(parents=True, exist_ok=True)
        (out / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": "2026-09-05T10:00:00.0000000Z",
                    "resources": {"stat/system": {"status": "RBAC_DENIED", "propertyName": "system"}},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        return 0, ""

    row, gap = read_single_resource(chain_target(), "stat/system", script, timeout_s=60, run=run)

    assert row is None and gap is not None
    assert "RBAC_DENIED" in gap.reason


def test_failed_lock_write_and_failed_cleanup_do_not_lose_the_original_error(tmp_path, script, monkeypatch):
    """If writing the pid INTO the brand-new lock file fails, AND the
    cleanup attempt of that (empty) lock file fails as well, that SECOND
    OSError must not overwrite the first, informative CollectError with a
    bare OSError - the same discipline _release_lock already knows for the
    release, now also here on the cleanup unlink.

    "Informative" no longer means the raw OS message
    text (see the two tests above) - it means the WRITE failure's own
    __cause__ survives, not the cleanup failure's. `errno=28` (ENOSPC)
    classifies as `_os_error_kind`'s generic branch, distinct from the
    cleanup's `errno=13` (EACCES) only in `__cause__.errno`, so that is
    what this test now pins."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def broken_fdopen(fd, *a, **k):
        os.close(fd)
        raise OSError(28, "geen ruimte meer op het apparaat")

    monkeypatch.setattr(os, "fdopen", broken_fdopen)

    original_unlink = Path.unlink

    def broken_unlink(self, *a, **k):
        if self.name == "export.lock":
            raise OSError(13, "toegang geweigerd bij opruimen")
        return original_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", broken_unlink)

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=lambda *a, **k: (0, ""))

    assert isinstance(err.value.__cause__, OSError), (
        f"de originele schrijffout ging verloren; __cause__ is {err.value.__cause__!r}"
    )
    assert err.value.__cause__.errno == 28, (
        "de opruimfout (errno 13) heeft de schrijffout (errno 28) overschreven "
        f"achter de mislukte opruiming: {err.value.__cause__!r}"
    )
    assert "geen ruimte meer op het apparaat" not in str(err.value)  # C2: never the raw OS message


def test_the_phase_report_reads_the_typed_phase_file(tmp_path):
    """A16: the classification comes from a TYPE, not from an error text."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "DNS", "ok": True},
                    {"name": "TCP_443", "ok": True},
                    {"name": "TLS", "ok": True},
                    {"name": "NITRO_LOGIN", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    words = {r.phase: r.word for r in report}
    assert words["DNS"] == "bereikt"
    assert words["TLS"] == "bereikt"
    assert words["NITRO-login"] == "mislukt"
    # A-6: NOT "niet bereikt (eerdere fase faalde)" - that phrase is in
    # neither design 2.1.1 nor A16's own row in 2.2. A phase never
    # attempted because an earlier one failed genuinely was not
    # established, so it carries the SAME word as every other "we do not
    # know" case in this product (Certainty.NOT_ESTABLISHED).
    assert words["identiteit"] == "niet vastgesteld"


def test_a_changed_error_message_never_changes_a_phase(tmp_path):
    """The counter-probe on the rule: two runs with a completely different
    error text and the same phase file give the SAME phases."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    payload = json.dumps(
        {
            "schemaVersion": "1.0",
            "phases": [
                {"name": "DNS", "ok": True},
                {"name": "TCP_443", "ok": False},
            ],
        }
    )
    (work / PHASE_FILE).write_text(payload, encoding="utf-8")
    first = [(r.phase, r.word) for r in phase_report(work, tmp_path / "export")]
    (work / "stderr.txt").write_text("een totaal andere foutzin", encoding="utf-8")
    second = [(r.phase, r.word) for r in phase_report(work, tmp_path / "export")]
    assert first == second


def test_without_a_phase_file_the_phases_come_from_artefacts(tmp_path):
    """No contract, no guessing: what the product can establish itself it
    establishes; the rest is honestly 'niet vastgesteld'."""
    from nsmcp.collect import phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-09-06T10:00:00.0000000Z",'
        '"resources":{"config/nsversion":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    words = {r.phase: r.word for r in phase_report(work, tmp_path / "export")}
    assert words["DNS"] == "niet vastgesteld"
    assert words["NITRO-login"] == "bereikt"
    assert words["identiteit"] == "bereikt"


def test_an_unknown_phase_name_is_reported_not_dropped(tmp_path):
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [{"name": "QUANTUM", "ok": False}]}),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    assert any("onbekende fase" in r.detail for r in report)


def test_a_malformed_ok_is_reported_as_malformed_not_as_unmentioned(tmp_path):
    """D-3: `"ok": "true"` (a JSON string, not a boolean) must not silently
    drop the phase, and the report must not claim the file 'does not
    report' a phase it plainly mentions - only malformed."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [{"name": "DNS", "ok": "true"}]}),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    dns = next(r for r in report if r.phase == "DNS")
    assert dns.word == "niet vastgesteld"
    assert "meldt deze fase niet" not in dns.detail, "dat is de ONTKRACHTE, onware bewering (D-3)"
    assert "true" not in dns.detail, "D-3: de aangeleverde waarde mag nooit geechood worden"


def test_a_malformed_ok_string_gets_an_accurate_shape_not_a_false_blank_claim(tmp_path):
    """C4, MEASURED: `export.shape_of` calls ANY string "een lege of
    alleen-witruimte tekstwaarde" - false for `{"ok": "true"}`, a non-blank
    string. The detail must say the value lacks the SHAPE of a boolean,
    never the untrue claim that it is blank (the same defect the
    not-echoed check above cannot see: a false-but-different sentence would
    still pass it)."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [{"name": "DNS", "ok": "true"}]}),
        encoding="utf-8",
    )
    dns = next(r for r in phase_report(work, tmp_path / "export") if r.phase == "DNS")
    assert "lege" not in dns.detail and "witruimte" not in dns.detail, (
        "'true' is een niet-lege string - deze bewering is onwaar voor deze waarde (C4)"
    )
    assert "boolean" in dns.detail


def test_a_malformed_non_dict_entry_string_gets_an_accurate_shape_not_a_false_blank_claim(tmp_path):
    """Same C4 defect, for the list-entry case: the string "kapot" is not
    an object, but it is also not blank."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": ["kapot"]}),
        encoding="utf-8",
    )
    loose = next(r for r in phase_report(work, tmp_path / "export") if r.phase == "(fase-invoer)")
    assert "lege" not in loose.detail and "witruimte" not in loose.detail, (
        "'kapot' is een niet-lege string - deze bewering is onwaar voor deze waarde (C4)"
    )
    assert "object" in loose.detail


def test_malformed_entries_of_every_shape_are_reported_not_dropped(tmp_path):
    """Three more malformed shapes in one file - a numeric `ok`, an entry
    that is not even an object, and an entry without a `name` at all - none
    of them may vanish (D-3). The nameless entry's `ok: true` is a genuine,
    readable fact this file explicitly reports -
    it is reported as "bereikt" by position, never dropped as "niet
    vastgesteld" the way it silently was before `ok` was ever read."""
    from nsmcp.collect import PHASE_FILE, PHASE_ORDER, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "TCP_443", "ok": 1},
                    "kapot",
                    {"ok": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    tcp = next(r for r in report if r.phase == "TCP")
    assert tcp.word == "niet vastgesteld"
    assert "type int" in tcp.detail, "de VORM (shape_of), nooit de waarde zelf"
    extra = [r for r in report if r.phase not in PHASE_ORDER]
    assert len(extra) == 2, "de kapotte invoer en de naamloze invoer moeten allebei zichtbaar blijven"
    non_dict_entry = next(r for r in extra if "misvormd" in r.detail)
    nameless_entry = next(r for r in extra if "mist een bruikbare naam" in r.detail)
    assert non_dict_entry.word == "niet vastgesteld", "de kapotte invoer heeft geen ok om te lezen"
    assert nameless_entry.word == "bereikt", (
        "ok: true is een echt gemeld feit, niet vastgesteld zou het laten verdwijnen"
    )


def test_a_hostile_unknown_phase_name_is_never_echoed_verbatim(tmp_path):
    """`status_ververs` answers OUTSIDE the disclosure seam (no render()
    pass, see mcp_server.py), so a supplied phase name that fails the same
    positive shape gate the rest of this product applies to a supplied
    value reaching unmasked text (`answer.repeatable_token`) must never
    reach the summary text verbatim - the shape gate is the only
    protection there is here."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    hostile = "line one\nDOEL: geheim.example.local\nrm -rf /"
    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [{"name": hostile, "ok": False}]}),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    text = phase_summary(report)
    assert hostile not in text
    assert "geheim.example.local" not in text
    assert "(onbekende fase)" in text


def test_an_unreadable_phase_file_reports_every_phase_honestly_not_via_artefacts(tmp_path):
    """MEASURED: a truncated `scan-fasen.json`
    (exactly what a killed or timed-out collect script can leave) used to
    fall through to `_phases_from_artefacts`, whose detail line claims "dit
    fasebestand ontbreekt" - untrue, the file is right there - and, worse,
    can land on a BETTER outcome than an honest read ever would: a usable
    manifest sitting next to it made NITRO-login/identiteit read "bereikt"
    from the artefacts, purely because the real phase file could not be
    read. This premise is the manifest: it alone (without the broken phase
    file) WOULD make NITRO-login/identiteit read "bereikt" via
    `_phases_from_artefacts` - proving the fallback is the more favourable
    outcome this fix must refuse to land on."""
    from nsmcp.collect import PHASE_FILE, _phases_from_artefacts, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-09-06T10:00:00.0000000Z",'
        '"resources":{"config/nsversion":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    # Premise: the manifest ALONE really does yield the more favourable
    # "bereikt" via the artefact fallback - so falling through to it here
    # would be landing on the better outcome, not a neutral one.
    artefact_words = {r.phase: r.word for r in _phases_from_artefacts(work)}
    assert artefact_words["NITRO-login"] == "bereikt"
    assert artefact_words["identiteit"] == "bereikt"

    (work / PHASE_FILE).write_text("{not json", encoding="utf-8")

    report = phase_report(work, tmp_path / "export")
    words = {r.phase: r.word for r in report}
    assert all(word == "niet vastgesteld" for word in words.values())
    dns = next(r for r in report if r.phase == "DNS")
    assert "ontbreekt" not in dns.detail, "het bestand bestaat echt - dit mag niet beweren van niet"
    assert "onleesbaar" in dns.detail or "geldige JSON" in dns.detail


@pytest.mark.parametrize(
    "payload",
    [
        '{"schemaVersion": "1.0", "phases": "kapot"}',
        '{"schemaVersion": "1.0"}',
        "[1, 2, 3]",
    ],
)
def test_every_unreadable_phase_file_shape_reports_honestly_not_via_artefacts(tmp_path, payload):
    """C2: not just bad JSON - a `phases` that is not a list, a `phases` key
    missing entirely, and a root that is not an object at all must all take
    the SAME "unreadable" path, never the artefact fallback."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(payload, encoding="utf-8")
    report = phase_report(work, tmp_path / "export")
    assert all(r.word == "niet vastgesteld" for r in report)
    # "de sleutel ontbreekt" (a KEY inside the file is missing) is true and
    # allowed; "dit fasebestand ontbreekt" (the FILE itself, per the
    # artefact fallback) would be false here and must never appear.
    assert all("fasebestand ontbreekt" not in r.detail for r in report)


@pytest.mark.parametrize(
    "raised, expected_kind",
    [
        (lambda p: PermissionError(13, "Permission denied", str(p)), "geen toegang"),
        (lambda p: IsADirectoryError(21, "Is a directory", str(p)), "geen bestand"),
        (lambda p: NotADirectoryError(20, "Not a directory", str(p)), "geen bestand"),
        (lambda p: OSError(5, "Input/output error", str(p)), "onbekende leesfout"),
    ],
)
def test_an_unreadable_phase_file_never_leaks_the_absolute_path_or_the_os_message(
    tmp_path, monkeypatch, raised, expected_kind
):
    """MEASURED (new in `a3fcdf2`): a directory
    standing in for `scan-fasen.json` raises exactly the `PermissionError`
    Windows raises for that, and `f"...: {exc}"` put the full absolute
    local temp-directory path into the answer at every disclosure level -
    the same leak class C5's second half exists to prevent, reinstated one
    branch over. Premise asserted first: the exception really does carry
    the full path in its own text. The fix must classify BY TYPE only -
    permission / not a file / anything else - and never echo the OS
    message or the path, for every OSError subtype this branch can see."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    phase_path = work / PHASE_FILE
    phase_path.write_text("{}", encoding="utf-8")  # must exist to reach read_text()

    exc = raised(phase_path)
    # Premise, asserted first: the exception really does carry the full
    # path (`OSError.__str__` reprs the filename, escaping backslashes -
    # `work.name`, a plain directory name with none of those, survives
    # that untouched and proves the path is really embedded).
    assert work.name in str(exc), "premisse: deze OS-foutmelding bevat echt het volledige pad"

    original_read_text = Path.read_text

    def broken_read_text(self, *a, **k):
        if self.name == PHASE_FILE:
            raise exc
        return original_read_text(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", broken_read_text)

    report = phase_report(work, tmp_path / "export")
    text = phase_summary(report)
    assert work.name not in text, "geen deel van het absolute pad in het antwoord"
    assert str(phase_path) not in text and str(tmp_path) not in text, "geen absoluut pad"
    assert "Permission denied" not in text and "Input/output error" not in text, "nooit de kale OS-foutmelding"
    assert expected_kind in text


def test_a_non_dict_root_gets_an_accurate_shape_not_a_false_blank_claim(tmp_path):
    """MEASURED (new in `a3fcdf2`): a bare
    `shape_of(raw)` call on a NON-BLANK string root (`"kapot"`) names it
    "een lege of alleen-witruimte tekstwaarde" - false, verbatim the C4
    defect this same round already fixed for the sibling `phases`-key
    site one line below. `_phase_shape` is the one already-proved helper
    for this, not a second bare `shape_of` call."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text('"kapot"', encoding="utf-8")

    report = phase_report(work, tmp_path / "export")
    dns = next(r for r in report if r.phase == "DNS")
    assert "lege" not in dns.detail and "witruimte" not in dns.detail, (
        "'kapot' is een niet-lege string - deze bewering is onwaar voor deze waarde (N2/C4)"
    )
    assert "object" in dns.detail


def test_a_bom_prefixed_phase_file_is_read_not_treated_as_a_read_gap(tmp_path):
    """Folded in deliberately: Windows
    PowerShell 5.1 writes a UTF-8 BOM by default, so a real collect
    script's `scan-fasen.json` would carry one. Plain `utf-8` turns the
    BOM into the first character of the JSON text, so even a perfectly
    well-formed file fails to parse and degrades to five "niet
    vastgesteld" read gaps on every real scan - `export.py:1083` already
    uses `utf-8-sig` for exactly this reason."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    payload = json.dumps({"schemaVersion": "1.0", "phases": [{"name": "DNS", "ok": True}]})
    (work / PHASE_FILE).write_bytes(b"\xef\xbb\xbf" + payload.encode("utf-8"))

    report = phase_report(work, tmp_path / "export")
    dns = next(r for r in report if r.phase == "DNS")
    assert dns.word == "bereikt", "een BOM-voorvoegsel mag het bestand niet tot een leesgat maken"


def test_the_cascade_uses_canonical_order_not_array_order(tmp_path):
    """MEASURED: `[{"IDENTITY", ok:true}, {"DNS", ok:false}]` (IDENTITY
    listed FIRST in the array, even though DNS comes first in the real scan
    sequence) used to yield the self-contradictory "identiteit: bereikt"
    behind a "De scan strandde in fase DNS" heading. The cascade must run in
    PHASE_ORDER, never array order."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "IDENTITY", "ok": True},
                    {"name": "DNS", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    words = {r.phase: r.word for r in report}
    assert words["DNS"] == "mislukt"
    assert words["identiteit"] == "niet vastgesteld", (
        "DNS komt canoniek VOOR identiteit; een mislukte DNS-fase mag een latere fase "
        "nooit als bereikt laten gelden, ongeacht de volgorde in de array"
    )
    text = phase_summary(report)
    assert "strandde in fase DNS" in text
    assert "identiteit: bereikt" not in text


def test_a_duplicate_phase_name_is_reported_as_malformed(tmp_path):
    """Two contradicting entries for the SAME phase cannot both be
    trusted - reported as malformed, not as "last value wins" (which used
    to print both "DNS: bereikt" and "DNS: mislukt" in one answer)."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "DNS", "ok": True},
                    {"name": "DNS", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    dns_reports = [r for r in report if r.phase == "DNS"]
    assert len(dns_reports) == 1, "geen dubbele DNS-regel - een tegenstrijdige invoer is EEN malformed melding"
    assert dns_reports[0].word == "niet vastgesteld"
    assert "meer dan eens" in dns_reports[0].detail
    # A phase this product cannot classify taints what follows it too:
    words = {r.phase: r.word for r in report}
    assert words["TCP"] == "niet vastgesteld"
    assert "eerdere fase faalde" in next(r for r in report if r.phase == "TCP").detail


def test_a_malformed_ok_taints_every_later_phase_in_canonical_order(tmp_path):
    """MEASURED: `[DNS ok, TCP malformed, TLS ok, NITRO_LOGIN ok,
    IDENTITY ok]` used to give TCP "niet vastgesteld" while TLS/NITRO-login/
    identiteit all still read "bereikt" - under the heading "Geen fase
    meldde een mislukking." A later phase cannot honestly be "bereikt"
    while its prerequisite is not established."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "DNS", "ok": True},
                    {"name": "TCP_443", "ok": "kapot"},
                    {"name": "TLS", "ok": True},
                    {"name": "NITRO_LOGIN", "ok": True},
                    {"name": "IDENTITY", "ok": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    words = {r.phase: r.word for r in phase_report(work, tmp_path / "export")}
    assert words["DNS"] == "bereikt", "DNS zelf is en blijft direct vastgesteld"
    assert words["TCP"] == "niet vastgesteld"
    assert words["TLS"] == "niet vastgesteld"
    assert words["NITRO-login"] == "niet vastgesteld"
    assert words["identiteit"] == "niet vastgesteld"


def test_an_unattributed_failure_is_not_silently_swallowed_by_the_headline(tmp_path):
    """C3, MEASURED: `{"name": "PROD_NS01_GEHEIM", "ok": false}` - a failure
    the file explicitly reports, just under a NAME (recognised-shape but
    unknown) this product does not recognise - used to vanish into "niet
    vastgesteld", leaving "Geen fase meldde een mislukking" standing as an
    untrue heading. The failure must surface (by position, never by the
    name itself - C5), and an independently, directly established EARLIER
    fact (DNS: bereikt) must stand regardless. This is ONE of four
    unattributable shapes - see the three
    sibling tests directly below for the other three: a missing name, a
    blank name, and a bare non-dict entry."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    {"name": "DNS", "ok": True},
                    {"name": "PROD_NS01_GEHEIM", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    text = phase_summary(report)
    assert "PROD_NS01_GEHEIM" not in text, "C5: nooit de aangeleverde naam zelf"
    assert text.splitlines()[0] != "Geen fase meldde een mislukking.", (
        "het bestand meldde wel degelijk een mislukking - deze kop mag dat niet ontkennen"
    )
    words = {r.phase: r.word for r in report}
    assert words["DNS"] == "bereikt"


@pytest.mark.parametrize(
    "entry_one, description",
    [
        ({"ok": False}, "ontbrekende naam"),
        ({"name": "   ", "ok": False}, "lege naam"),
    ],
)
def test_an_unattributable_entry_with_a_clean_reported_failure_surfaces_without_tainting_established_facts(
    tmp_path, entry_one, description
):
    """MEASURED for both rows: `entry_one` reports
    a genuine, readable `ok: false` this product cannot attribute to any
    phase at all (no name, or a blank one). `ok` used to be discarded by a
    `continue` BEFORE it was ever read, so this vanished and left "Geen
    fase meldde een mislukking" standing as an outright false claim -
    "the file reported a failure and the product says none did" - while
    five well-formed phases elsewhere in the SAME file all read "bereikt".
    The failure must surface (by position, never any supplied text - C5).
    The five independently, directly established facts stand regardless:
    a genuinely reported "bereikt" is not retroactively cast into doubt by
    an unrelated entry this product cannot even place - the same
    "established facts stand" rule the sibling test above already proves
    for the named-but-unrecognised case."""
    from nsmcp.collect import PHASE_FILE, PHASE_ORDER, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    entry_one,
                    {"name": "DNS", "ok": True},
                    {"name": "TCP_443", "ok": True},
                    {"name": "TLS", "ok": True},
                    {"name": "NITRO_LOGIN", "ok": True},
                    {"name": "IDENTITY", "ok": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    text = phase_summary(report)
    assert text.splitlines()[0] != "Geen fase meldde een mislukking.", (
        f"{description}: het bestand meldde wel degelijk een mislukking"
    )
    words = {r.phase: r.word for r in report}
    for dutch in PHASE_ORDER:
        assert words[dutch] == "bereikt", f"{description}: {dutch} was direct en onafhankelijk vastgesteld"


@pytest.mark.parametrize(
    "entry_one, description",
    [
        ({"name": "PROD_NS01_GEHEIM", "ok": "kapot"}, "onbekende naam met onbruikbare ok"),
        ("kapot", "geen object"),
    ],
)
def test_an_unattributable_read_gap_taints_the_five_named_phases_instead_of_the_better_outcome(
    tmp_path, entry_one, description
):
    """MEASURED for both rows: `entry_one` is a
    genuine read gap this product cannot attribute to a phase AND cannot
    classify true or false either - unlike row 1/2, there is no readable
    fact to surface here at all. Landing on "Geen fase meldde een
    mislukking" with all five OTHER, well-formed phases reading "bereikt"
    is landing on the more favourable outcome exactly where this product
    could not verify anything - "the workstream's recurring class". The
    read gap must taint every canonical phase exactly as an unclassifiable
    NAMED entry already does (the same mechanism, extended - not a second
    one), and the headline must not claim an all-clear it never
    established. Premise asserted first: without `entry_one`, these same
    five entries really do read fully "bereikt" - the more favourable
    outcome this fix must refuse to land on.

    A later fix: this test used to pin only
    `word != "bereikt"`, which a false DETAIL could still pass - exactly
    how the previous version of this fix shipped with every one of these five phases
    printing "niet getest: een eerdere fase faalde" (untrue: none of
    DNS/TCP/TLS/NITRO-login/identiteit ever failed here - every single one
    of their own `ok` values is `True`, MEASURED). Strengthened to assert
    the detail text: it must never blame a phantom earlier phase, and for
    DNS specifically - the FIRST canonical phase, for which no earlier
    phase can even exist - "niet getest" is doubly false since DNS's own
    `ok: true` genuinely was read."""
    from nsmcp.collect import PHASE_FILE, PHASE_ORDER, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    five_clean = [
        {"name": "DNS", "ok": True},
        {"name": "TCP_443", "ok": True},
        {"name": "TLS", "ok": True},
        {"name": "NITRO_LOGIN", "ok": True},
        {"name": "IDENTITY", "ok": True},
    ]
    (work / PHASE_FILE).write_text(json.dumps({"schemaVersion": "1.0", "phases": five_clean}), encoding="utf-8")
    baseline = {r.phase: r.word for r in phase_report(work, tmp_path / "export")}
    assert all(baseline[dutch] == "bereikt" for dutch in PHASE_ORDER), (
        "premisse: zonder de niet-toe-te-wijzen invoer zijn deze vijf fases echt bereikt"
    )

    (work / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [entry_one, *five_clean]}), encoding="utf-8"
    )
    report = phase_report(work, tmp_path / "export")
    text = phase_summary(report)
    assert text.splitlines()[0] != "Geen fase meldde een mislukking.", (
        f"{description}: een leesgat mag niet onder een geruststellende kop verdwijnen"
    )
    words = {r.phase: r.word for r in report}
    details = {r.phase: r.detail for r in report if r.phase in PHASE_ORDER}
    for dutch in PHASE_ORDER:
        assert words[dutch] != "bereikt", (
            f"{description}: {dutch} mag niet op de gunstigere uitkomst landen naast een leesgat"
        )
        # None of these five phases' own `ok` is ever
        # False here, so "een eerdere fase faalde" would be an outright
        # false claim about every single one of them - a phantom earlier
        # failure that never happened.
        assert "eerdere fase faalde" not in details[dutch], (
            f"{description}: {dutch}: geen van de vijf canonieke fasen is echt mislukt hier"
        )
        assert details[dutch] == (
            "het fasebestand meldt deze fase, maar bevat ook een fase-invoer "
            "die niet aan een fase kon worden toegewezen"
        ), f"{description}: {dutch}: de reden moet de niet-toewijsbare invoer noemen, niet fantoomfalen"
    assert "PROD_NS01_GEHEIM" not in text, "C5: nooit de aangeleverde naam zelf"


def test_an_unattributed_gap_never_blames_a_phantom_earlier_phase(tmp_path):
    """The exact
    reproduction: `["kapot", {"name": "DNS", "ok": true}]`. An earlier
    fix seeded the cascade's `failed` accumulator straight from
    `unattributed_gap` BEFORE the canonical walk, so DNS - the FIRST phase
    in `PHASE_ORDER`, for which an earlier phase cannot exist - printed
    "niet vastgesteld (niet getest: een eerdere fase faalde)" even though
    its own `ok: true` genuinely WAS read (MEASURED). Both halves of that
    sentence were false: DNS was tested, and no earlier phase failed
    because none can. TCP/TLS/NITRO-login/identiteit (absent from this
    tiny file entirely) are the exact same sibling defect one level over -
    none of them has any earlier canonical phase that actually failed
    either, so they must not blame one.

    The WORD stays "niet vastgesteld" for all five - unchanged from round
    2's own, separately-reviewed choice never to land an unattributable
    read gap on the more favourable outcome. Only the DETAIL must become
    true."""
    from nsmcp.collect import PHASE_FILE, phase_report

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    "kapot",
                    {"name": "DNS", "ok": True},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    by_phase = {r.phase: r for r in report}

    dns = by_phase["DNS"]
    assert dns.word == "niet vastgesteld"
    assert "eerdere fase faalde" not in dns.detail, "DNS is de EERSTE canonieke fase - er kan geen eerdere fase bestaan"
    assert "niet getest" not in dns.detail, (
        "DNS's eigen ok (true) is wel degelijk gelezen - 'niet getest' is hier onwaar"
    )
    assert dns.detail == (
        "het fasebestand meldt deze fase, maar bevat ook een fase-invoer die niet aan een fase kon worden toegewezen"
    ), "de reden moet de niet-toewijsbare invoer noemen, niet een fantoomfase"

    for dutch in ("TCP", "TLS", "NITRO-login", "identiteit"):
        detail = by_phase[dutch].detail
        assert by_phase[dutch].word == "niet vastgesteld"
        assert "eerdere fase faalde" not in detail, (
            f"{dutch}: geen enkele canonieke fase is hier echt mislukt - er is geen eerdere fase die faalde"
        )
        assert detail == "het fasebestand meldt deze fase niet", (
            f"{dutch}: het fasebestand noemt deze fase inderdaad niet - dat blijft de ware, onveranderde reden"
        )


def test_an_established_failure_before_any_other_real_failure_is_never_masked_by_a_gap(tmp_path):
    """The exact reproduction:
    `["kapot", DNS ok:true, TCP ok:true, TLS ok:true, NITRO_LOGIN ok:true,
    IDENTITY ok:false]`. IDENTITY is a NAMED canonical phase whose own `ok`
    was genuinely read as `False` - a real, established failure, and the
    FIRST real `PHASE_ORDER` failure in this file (every phase before it
    is genuinely `True`). An earlier fix (the `elif unattributed_gap`
    branch) still let the unrelated "kapot" gap outrank that established
    failure, printing "niet vastgesteld" instead of "mislukt" and
    suppressing the "De scan strandde" headline for a real, measured
    problem - the defect had moved from the DETAIL string (that earlier
    fix) to the WORD. `_PHASE_PRECEDENCE` puts
    `own_ok_false` above `unattributed_gap` precisely so this cannot
    recur."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    "kapot",
                    {"name": "DNS", "ok": True},
                    {"name": "TCP_443", "ok": True},
                    {"name": "TLS", "ok": True},
                    {"name": "NITRO_LOGIN", "ok": True},
                    {"name": "IDENTITY", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    identiteit = next(r for r in report if r.phase == "identiteit")
    assert identiteit.word == "mislukt", (
        "IDENTITY's eigen ok: false is echt gelezen - een niet-gerelateerd leesgat "
        "elders mag dat nooit naar 'niet vastgesteld' verlagen"
    )
    text = phase_summary(report)
    assert text.splitlines()[0] == "De scan strandde in fase identiteit.", (
        "een echt gemeten mislukking mag nooit onder een andere kop verdwijnen"
    )


def test_an_isolated_established_failure_alongside_a_gap_is_never_masked(tmp_path):
    """The isolated reproduction: `["kapot", {"name": "TLS",
    "ok": false}]`. TLS's own `ok: false` was genuinely read; the
    unattributable "kapot" entry elsewhere must not downgrade it."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "phases": [
                    "kapot",
                    {"name": "TLS", "ok": False},
                ],
            }
        ),
        encoding="utf-8",
    )
    report = phase_report(work, tmp_path / "export")
    tls = next(r for r in report if r.phase == "TLS")
    assert tls.word == "mislukt"
    text = phase_summary(report)
    assert text.splitlines()[0] == "De scan strandde in fase TLS."


_EXPECTED_RUNG_ORDER = (
    "malformed",
    "earlier_real_failure",
    "own_ok_false",
    "unattributed_gap",
    "own_ok_true",
    "absent",
)


_OWN_STATUSES = (True, False, "malformed", "absent")


_POSITION_TO_PHASE = {
    "first": ("DNS", "DNS"),
    "middle": ("TLS", "TLS"),
    "last": ("identiteit", "IDENTITY"),
}


def _matrix_cells():
    """Every (position, own_status, earlier_real_failure, unattributed_gap)
    combination that can actually be constructed. `earlier_real_failure`
    is excluded for `position == "first"`: DNS is the first canonical
    phase, so no earlier `PHASE_ORDER` phase can exist for it to be
    tainted by - the fact itself is not constructible, not merely untested.
    """
    cells = []
    for position in ("first", "middle", "last"):
        earlier_options = (False,) if position == "first" else (False, True)
        for own_status in _OWN_STATUSES:
            for earlier_real_failure in earlier_options:
                for unattributed_gap in (False, True):
                    cells.append((position, own_status, earlier_real_failure, unattributed_gap))
    return cells


def _build_phase_file_entries(position, own_status, earlier_real_failure, unattributed_gap):
    """The `"phases"` list for one matrix cell, plus the Dutch name of the
    phase under test. `earlier_real_failure` is manufactured by giving DNS
    a genuine `ok: false` (DNS is always canonically before TLS/identiteit,
    the only two non-"first" positions this matrix uses) - it cascades
    forward through every phase after it exactly like any other real
    `PHASE_ORDER` failure, whether or not those phases have entries of
    their own."""
    dutch, source_name = _POSITION_TO_PHASE[position]
    entries = []
    if earlier_real_failure:
        entries.append({"name": "DNS", "ok": False})
    if unattributed_gap:
        entries.append("kapot")
    if own_status is True:
        entries.append({"name": source_name, "ok": True})
    elif own_status is False:
        entries.append({"name": source_name, "ok": False})
    elif own_status == "malformed":
        entries.append({"name": source_name, "ok": "kapot"})
    elif own_status == "absent":
        pass
    else:
        raise AssertionError(f"onbekende own_status {own_status!r}")
    return dutch, entries


def _expected_rung(own_status, earlier_real_failure, unattributed_gap):
    """The winning rung for one cell, per `_EXPECTED_RUNG_ORDER` - written
    independently of `_PHASE_PRECEDENCE`'s own predicates."""
    if own_status == "malformed":
        return "malformed"
    if earlier_real_failure:
        return "earlier_real_failure"
    if own_status is False:
        return "own_ok_false"
    if unattributed_gap and own_status != "absent":
        return "unattributed_gap"
    if own_status is True:
        return "own_ok_true"
    return "absent"


def _expected_word_and_detail(rung, dutch):
    """What this product must TRUTHFULLY say once `rung` has won, for the
    phase named `dutch`. Every string here is the literal text
    `src/nsmcp/collect.py` prints for that rung - not a paraphrase."""
    if rung == "malformed":
        return "niet vastgesteld", (
            f"fase {dutch}: het fasebestand meldt deze fase, maar de uitkomst is onbruikbaar "
            "(zonder de vorm van een boolean)"
        )
    if rung == "earlier_real_failure":
        return "niet vastgesteld", "niet getest: een eerdere fase faalde"
    if rung == "own_ok_false":
        return "mislukt", ""
    if rung == "unattributed_gap":
        return "niet vastgesteld", (
            "het fasebestand meldt deze fase, maar bevat ook een fase-invoer "
            "die niet aan een fase kon worden toegewezen"
        )
    if rung == "own_ok_true":
        return "bereikt", ""
    if rung == "absent":
        return "niet vastgesteld", "het fasebestand meldt deze fase niet"
    raise AssertionError(f"onbekende rung {rung!r}")


def _expected_headline(dutch, own_status, earlier_real_failure):
    """Which headline `phase_summary` must print for one cell. Only the
    facts that can put a "mislukt" phase on the board matter here: DNS
    (the manufactured earlier failure) always outranks the phase under
    test's own state once it is real; otherwise the phase under test
    itself is the only candidate. `unattributed_gap` alone (no "mislukt"
    anywhere) is handled by the caller, which already knows whether a
    loose gap entry is present."""
    if earlier_real_failure:
        return "De scan strandde in fase DNS."
    if own_status is False:
        return f"De scan strandde in fase {dutch}."
    return None


def test_the_precedence_table_matches_this_declared_order():
    """Pins `_PHASE_PRECEDENCE`'s rung NAMES and their order directly -
    independent of the exhaustive matrix below, so a reordering regression
    fails immediately and legibly, by name, without needing a single cell
    to be worked out by hand."""
    from nsmcp.collect import _PHASE_PRECEDENCE

    assert tuple(name for name, _matches, _build in _PHASE_PRECEDENCE) == _EXPECTED_RUNG_ORDER


@pytest.mark.parametrize(
    "position, own_status, earlier_real_failure, unattributed_gap",
    _matrix_cells(),
    ids=[
        f"{position}-own={own_status}-earlier={earlier_real_failure}-gap={unattributed_gap}"
        for position, own_status, earlier_real_failure, unattributed_gap in _matrix_cells()
    ],
)
def test_phase_precedence_exhaustive_matrix(tmp_path, position, own_status, earlier_real_failure, unattributed_gap):
    """Every reachable (position x own_status x earlier_real_failure x
    unattributed_gap) cell - 40 in total - built from a real phase file
    and read through the real `phase_report`/`phase_summary`, checked
    against the independent oracle above. Asserts the WORD, the DETAIL,
    and the HEADLINE for every cell, so a future change that reorders a
    rung, misclassifies a fact, or leaves a false sentence standing at any
    reachable input is caught at collection-generated scale, not by hand."""
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    dutch, entries = _build_phase_file_entries(position, own_status, earlier_real_failure, unattributed_gap)
    work = tmp_path / "werk"
    work.mkdir()
    (work / PHASE_FILE).write_text(json.dumps({"schemaVersion": "1.0", "phases": entries}), encoding="utf-8")

    report = phase_report(work, tmp_path / "export")
    actual = next(r for r in report if r.phase == dutch)

    rung = _expected_rung(own_status, earlier_real_failure, unattributed_gap)
    expected_word, expected_detail = _expected_word_and_detail(rung, dutch)
    assert actual.word == expected_word, f"{dutch} ({rung}): verwacht woord {expected_word!r}, kreeg {actual.word!r}"
    assert actual.detail == expected_detail, (
        f"{dutch} ({rung}): verwachte detail {expected_detail!r}, kreeg {actual.detail!r}"
    )

    text = phase_summary(report)
    expected_stranded_headline = _expected_headline(dutch, own_status, earlier_real_failure)
    if expected_stranded_headline is not None:
        assert text.splitlines()[0] == expected_stranded_headline, (
            f"{dutch} ({rung}): een echt gemeten mislukking moet de 'strandde'-kop krijgen"
        )
    elif unattributed_gap:
        assert text.splitlines()[0] == ("Niet elke fase-invoer in het fasebestand kon vastgesteld worden.")
    else:
        assert text.splitlines()[0] == "Geen fase meldde een mislukking."


def test_phase_report_without_evidence_reports_every_phase_honestly(tmp_path):
    """`work_dir=None`: this attempt produced no directory of its own
    (refused before one existed). Reporting a STALE directory from an
    unrelated, earlier attempt would assert more than this attempt
    established - so every phase is honestly 'niet vastgesteld' instead."""
    from nsmcp.collect import PHASE_ORDER, phase_report

    report = phase_report(None, tmp_path / "export")
    assert {r.phase for r in report} == set(PHASE_ORDER)
    assert all(r.word == "niet vastgesteld" for r in report)


def test_nonzero_exit_code_also_preserves_the_work_dir_for_phase_diagnosis(tmp_path, script):
    """MEASURED: before this fix, a non-zero exit
    code deleted the work directory unconditionally - `_preserve_as_failed`
    was never called on this branch - so the phase report could never read a phase file
    for the single most common real failure shape (the script itself
    detects and reports a failed phase, then exits non-zero). This is the
    counterpart, for the exit-code-nonzero branch, of
    `test_failed_validation_preserves_the_work_dir_for_investigation`
    (which already covered the exit-code-0-but-invalid-manifest branch)."""
    from nsmcp.collect import PHASE_FILE

    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / PHASE_FILE).write_text('{"schemaVersion":"1.0","phases":[]}', encoding="utf-8")
        return 1, "kon niet verbinden"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    failed_dir = tmp_path / "export.mislukt"
    assert failed_dir.exists()
    assert (failed_dir / PHASE_FILE).exists()
    assert err.value.evidence_dir == failed_dir
    assert failed_dir.name in str(err.value)
    assert str(failed_dir) not in str(err.value)


def test_the_production_path_reads_phases_from_where_the_evidence_actually_lands(tmp_path, script):
    """`phase_report(export_dir.parent,
    export_dir)` - the original production call - can never see
    this attempt's evidence. The work directory is a TEMPORARY sibling of
    `export_dir` (collect.py's own `tempfile.mkdtemp(dir=export_dir.parent)`
    at the mkdtemp call in `collect()`), renamed on failure to
    `<export_dir>.mislukt`, never to `export_dir.parent` itself.

    This drives the REAL `collect()` (not a hand-rolled work directory)
    with a run stub that writes the typed phase file and THEN exits
    non-zero - the most common real failure shape - and proves both
    halves: the ORIGINAL call finds nothing (all five phases fall back to
    'niet vastgesteld'), the CORRECTED one (`CollectError.evidence_dir`)
    finds the real phases."""
    from nsmcp.collect import PHASE_FILE, phase_report

    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / PHASE_FILE).write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "phases": [
                        {"name": "DNS", "ok": True},
                        {"name": "TCP_443", "ok": False},
                    ],
                }
            ),
            encoding="utf-8",
        )
        return 1, "TCP-connect mislukt"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    # The original production call, proven broken:
    broken = phase_report(export_dir.parent, export_dir)
    assert {r.word for r in broken} == {"niet vastgesteld"}, (
        "export_dir.parent must never be able to see this attempt's evidence - "
        "if this assertion starts failing, the on-disk layout changed and "
        "C-1's premise needs re-measuring, not deleting"
    )

    # The corrected call, using where collect() says the evidence actually is:
    assert err.value.evidence_dir == tmp_path / "export.mislukt"
    fixed = phase_report(err.value.evidence_dir, export_dir)
    words = {r.phase: r.word for r in fixed}
    assert words["DNS"] == "bereikt"
    assert words["TCP"] == "mislukt"


def test_a_refused_lock_carries_no_evidence_dir(tmp_path, script):
    """A scan refused before a work directory ever existed (a concurrent
    scan already holds the lock) must not point a phase diagnosis at a
    STALE directory from an unrelated, earlier attempt."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    (tmp_path / "export.lock").write_text("999999", encoding="utf-8")

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=lambda a, t: (0, ""))

    assert err.value.evidence_dir is None


def test_missing_script_carries_no_evidence_dir(tmp_path):
    """Refused before anything about THIS attempt exists on disk at all."""
    with pytest.raises(CollectError) as err:
        collect(chain_target(), tmp_path / "export", tmp_path / "bestaat-niet.ps1")
    assert err.value.evidence_dir is None


def test_a_successful_scan_still_carries_no_evidence_dir(tmp_path, script):
    """Not an error path, so nothing to preserve or point at - the default
    stays None on the (never-raised) happy path too; this only documents
    that CollectError's default is never accidentally something else."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        write_valid_export(out)
        return 0, ""

    collect(chain_target(), export_dir, script, run=run_stub)
    # No CollectError is raised on success, so there is nothing to assert
    # about evidence_dir here beyond "collect() returned normally" - this
    # test exists to make the happy path explicit in this section rather
    # than leaving it implicit.
    assert (export_dir / "export-manifest.json").exists()


def _stale_mislukt_with_real_evidence(export_dir: Path) -> Path:
    """A genuine `.mislukt` from an EARLIER, unrelated failed attempt,
    holding real phase evidence - the thing C1 measured being destroyed."""
    from nsmcp.collect import PHASE_FILE

    stale = export_dir.parent / f"{export_dir.name}.mislukt"
    stale.mkdir(parents=True)
    (stale / PHASE_FILE).write_text(
        json.dumps({"schemaVersion": "1.0", "phases": [{"name": "DNS", "ok": False}]}),
        encoding="utf-8",
    )
    return stale


def test_a_cancelled_scan_does_not_destroy_the_previous_failures_evidence(tmp_path, script):
    """MEASURED: before this fix, `_run_powershell`'s
    own CollectError for a caller cancellation (collect.py:158) reached the
    SAME `except CollectError: _preserve_as_failed(...)` as a produced,
    non-zero exit - which first `rmtree`s any EXISTING `.mislukt` and then
    renames this attempt's still-EMPTY work directory into that slot. A
    genuine previous failure's evidence was destroyed and replaced with
    nothing, and the answer then claimed it was "bewaard voor onderzoek"."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    stale = _stale_mislukt_with_real_evidence(export_dir)
    original = (stale / "scan-fasen.json").read_text(encoding="utf-8")

    def run_stub(arguments, timeout_s):
        raise CollectError("de scan is afgebroken door de aanroeper; de vorige gegevens blijven gelden")

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    assert "afgebroken door de aanroeper" in str(err.value)
    assert err.value.evidence_dir is None
    assert stale.exists(), "de bestaande .mislukt van een EERDERE mislukking mag niet verdwijnen"
    assert (stale / "scan-fasen.json").read_text(encoding="utf-8") == original
    # No empty work directory leaked behind either (leaked, not preserved,
    # not destructively swapped in):
    assert list(export_dir.parent.glob(f"{export_dir.name}.nieuw-*")) == []


def test_a_timed_out_scan_does_not_destroy_the_previous_failures_evidence(tmp_path, script):
    """Same measurement as the cancellation test above, for the timeout
    branch of `_run_powershell` (collect.py:163)."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    stale = _stale_mislukt_with_real_evidence(export_dir)
    original = (stale / "scan-fasen.json").read_text(encoding="utf-8")

    def run_stub(arguments, timeout_s):
        raise CollectError(f"de scan is na {timeout_s} seconden afgebroken; de vorige gegevens blijven gelden")

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub, timeout_s=5)

    assert "seconden afgebroken" in str(err.value)
    assert err.value.evidence_dir is None
    assert stale.exists(), "de bestaande .mislukt van een EERDERE mislukking mag niet verdwijnen"
    assert (stale / "scan-fasen.json").read_text(encoding="utf-8") == original
    assert list(export_dir.parent.glob(f"{export_dir.name}.nieuw-*")) == []


def test_a_powershell_start_failure_does_not_destroy_the_previous_failures_evidence(tmp_path, script):
    """Same measurement, for `_run_powershell`'s own start failure
    (collect.py:147, "kon PowerShell niet starten") - this attempt never
    even got a child process running, let alone a scan to preserve."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()
    stale = _stale_mislukt_with_real_evidence(export_dir)
    original = (stale / "scan-fasen.json").read_text(encoding="utf-8")

    def run_stub(arguments, timeout_s):
        raise CollectError(
            "kon PowerShell niet starten: [WinError 2] Het systeem kan het opgegeven bestand niet vinden"
        )

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)

    assert "kon PowerShell niet starten" in str(err.value)
    assert err.value.evidence_dir is None
    assert stale.exists(), "de bestaande .mislukt van een EERDERE mislukking mag niet verdwijnen"
    assert (stale / "scan-fasen.json").read_text(encoding="utf-8") == original
    assert list(export_dir.parent.glob(f"{export_dir.name}.nieuw-*")) == []


# ---------------------------------------------------------------------------
# The failed-script tail travels as
# `CollectError.script_output`, and `without_script_output()` is the one way
# to obtain the same error without it. The end-to-end proof (all three
# disclosure levels through status_ververs) lives in test_mcp_server.py; the
# two contracts below are the ones that test cannot see.
# ---------------------------------------------------------------------------


def test_the_failed_script_tail_is_typed_and_withheld_around_the_evidence_wrapper(tmp_path, script):
    """The tail sits INSIDE the message that `collect()` wraps with
    `(bewaard voor onderzoek in <naam>)`: withholding must replace the
    tail only, and keep the exit code, the wrapper and `evidence_dir`."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    def run_stub(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        return 1, "CERTIFICAAT WIJKT AF. aangetroffen 9F3A0C77 (subject CN=ns-vip-intern.klant.local)"

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=run_stub)
    error = err.value
    assert error.script_output and "9F3A0C77" in error.script_output
    assert error.script_output in str(error)  # premise: the tail really is in the message

    withheld = error.without_script_output()
    text = str(withheld)
    assert "9F3A0C77" not in text and "ns-vip-intern.klant.local" not in text
    assert "exitcode 1" in text
    assert "bewaard voor onderzoek in export.mislukt" in text
    assert "scriptuitvoer niet getoond op deze stand" in text
    assert withheld.evidence_dir == error.evidence_dir == tmp_path / "export.mislukt"
    assert withheld.script_output is None


def test_an_empty_script_tail_is_this_products_own_text_and_is_not_withheld(tmp_path, script):
    """`geen foutregel` is written by this product, not by the script: an
    error without any script output must come back unchanged from
    `without_script_output()`, never claiming something was withheld."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=lambda *a, **k: (1, "   \n\n"))
    error = err.value
    assert "geen foutregel" in str(error)
    assert error.script_output is None
    assert error.without_script_output() is error
    assert "niet getoond op deze stand" not in str(error.without_script_output())


def test_withholding_replaces_the_tail_where_it_stands_not_the_products_own_prefix(tmp_path, script):
    """Review finding on the first version of `without_script_output()`: a
    plain `str.replace(tail, ...)` hit the product's OWN prefix when the
    script happened to print a word that prefix contains (`exitcode`) -
    leak-safe, but the message came out garbled and the exit code was
    gone. The tail sits at ONE known place: right after the prefix."""
    export_dir = tmp_path / "export"
    export_dir.mkdir()

    with pytest.raises(CollectError) as err:
        collect(chain_target(), export_dir, script, run=lambda *a, **k: (1, "exitcode"))
    error = err.value
    assert error.script_output == "exitcode"

    text = str(error.without_script_output())
    assert text.startswith("het verzamelscript stopte met exitcode 1: scriptuitvoer niet getoond op deze stand"), text
    assert text.count("exitcode") == 1, text


def test_withholding_fails_closed_when_the_tail_is_not_where_the_message_puts_it(tmp_path):
    """The structurally impossible case, pinned so the branch cannot rot:
    a CollectError whose recorded tail does not sit right after the
    product's prefix. Never guess which part of the message was safe -
    the WHOLE message becomes the fixed phrase; `evidence_dir` survives."""
    from nsmcp.collect import SCRIPT_OUTPUT_NOT_SHOWN

    slot = tmp_path / "export.mislukt"
    odd = CollectError("de vorm klopt niet: iets anders staat hier", evidence_dir=slot, script_output="9F3A0C77")
    withheld = odd.without_script_output()
    assert str(withheld) == SCRIPT_OUTPUT_NOT_SHOWN
    assert withheld.evidence_dir == slot
    assert withheld.script_output is None
