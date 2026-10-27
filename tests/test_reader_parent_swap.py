"""1.1 B.5: per reader family of B.3 a negative parent-swap proof on Windows.

Every family reads its files through `nsmcp.localpath`. Each proof here puts a
REAL junction (`_winapi.CreateJunction`, no administrator right needed) in the
place of a directory on the way to a file the family reads, to a directory
outside the approved place that holds a file of the same name with a needle in
it - and, where the family reads from a root, swaps that directory mid-walk
through the seam (`localpath._native.between`), the way
tests/test_localpath_windows.py proves the module itself. Each proof checks:

- the family's OWN failure route (a read gap, a typed error, "no record"),
  with the fixed sentence of the kind where the family names it;
- the seam: no open of the file outside the approved tree was ever attempted
  (an open of the junction itself is the refusal, not a breach);
- the needle test: neither the outside path nor the outside content reaches
  an answer at openness `beperkt` or `minimaal`.

A refusal that only comes after an open of the place outside the root would
not count as a passing proof; that is why the proofs read the seam.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from datetime import date
from pathlib import Path

import mcp.types as types
import pytest
from conftest import _knowledge_file, seal_manifest, write_signed_table
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import localpath
from nsmcp.disclosure import Disclosure
from nsmcp.export import load_export
from nsmcp.localpath import REASONS

pytestmark = [
    pytest.mark.skipif(
        sys.platform != "win32", reason="een junction en de NtCreateFile-wandeling bestaan alleen op Windows"
    ),
    pytest.mark.usefixtures("open_audit"),
]

# The needle: the name of the directory outside the approved place AND a value
# in the file there. Neither may ever reach an answer below `volledig`.
NAALD = "NAALDBUITEN7Q3"


@pytest.fixture
def seam(monkeypatch):
    native = localpath._Native(record=True)
    monkeypatch.setattr(localpath, "_native", native)
    return native


def _junction(link: Path, target: Path) -> None:
    import _winapi

    _winapi.CreateJunction(str(target), str(link))


def _replace_by_junction(directory: Path, outside: Path) -> None:
    """`directory` moved aside and a junction to `outside` in its place."""
    directory.rename(directory.with_name(directory.name + "-weg"))
    _junction(directory, outside)


def _swap_before(native, component: str, swap) -> None:
    """Runs `swap` once, right before the walk opens `component` (its parent held)."""
    done: list[int] = []

    def between(index, name):
        if name == component and not done:
            done.append(index)
            swap()

    native.between = between


def _opened_names(native) -> list[str]:
    return [record["name"] for record in native.opens]


def _outside_dir(tmp_path: Path) -> Path:
    outside = tmp_path / NAALD
    outside.mkdir()
    return outside


def _answers(server, calls) -> dict[str, str]:
    async def scenario():
        out = {}
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            for name, args in calls:
                result = await client.call_tool(name, args)
                out[name] = " ".join(block.text for block in result.content if hasattr(block, "text"))
        return out

    return asyncio.run(scenario())


def _assert_no_needle(text: str, tmp_path: Path, *needles: str) -> None:
    for needle in (NAALD, str(tmp_path), tmp_path.name, *needles):
        assert needle not in text, f"{needle!r} lekt in het antwoord"


# ---------------------------------------------------------------------------
# Family: export (manifest, object, binding and text files, target file, scan log)
# ---------------------------------------------------------------------------


def _cert_object(name: str) -> dict:
    return {"sslcertkey": [{"certkey": name, "daystoexpiration": 9, "status": "Valid"}]}


def _export(tmp_path: Path) -> Path:
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "sslcertkey.json").write_text(json.dumps(_cert_object("CERT-BINNEN")), encoding="utf-8")
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-19T10:00:00.0000000Z",
        "resources": {"config/sslcertkey": {"status": "OK"}},
        "files": {},
    }
    (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export_dir)
    return export_dir


def _outside_objects_the_manifest_accepts(tmp_path: Path, export_dir: Path) -> Path:
    """An outside `objects` directory whose `sslcertkey.json` carries the
    needle AND whose hash the manifest carries: were the link followed, the
    outside file would pass every check and reach the answer."""
    outside = _outside_dir(tmp_path)
    (outside / "sslcertkey.json").write_text(json.dumps(_cert_object(NAALD)), encoding="utf-8")
    shutil.copy(export_dir / "objects" / "sslcertkey.json", tmp_path / "binnen-kopie.json")
    (export_dir / "objects" / "sslcertkey.json").write_bytes((outside / "sslcertkey.json").read_bytes())
    seal_manifest(export_dir)
    return outside


def test_export_a_junction_inside_the_export_is_a_read_gap_of_its_kind(tmp_path, seam):
    export_dir = _export(tmp_path)
    outside = _outside_objects_the_manifest_accepts(tmp_path, export_dir)
    _replace_by_junction(export_dir / "objects", outside)

    objects, gap = load_export(export_dir).objects("config/sslcertkey")

    assert objects == []
    assert gap is not None and gap.reason == "objectbestand kon niet gelezen worden: " + REASONS["koppeling"]
    assert _opened_names(seam).count("sslcertkey.json") == 0, "het bestand buiten de export had geen open-poging"


def test_export_an_ancestor_swapped_mid_walk_never_opens_outside_the_export(tmp_path, seam):
    export_dir = _export(tmp_path)
    outside = _outside_objects_the_manifest_accepts(tmp_path, export_dir)
    export = load_export(export_dir)
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, "objects", lambda: _replace_by_junction(export_dir / "objects", outside))

    objects, gap = export.objects("config/sslcertkey")

    assert objects == [] and gap is not None
    assert REASONS["koppeling"] in gap.reason
    names = _opened_names(seam)
    assert "objects" in names and "sslcertkey.json" not in names, names


def test_export_the_export_map_itself_a_junction_refuses_the_manifest_with_its_kind(tmp_path, seam):
    real = _export(tmp_path)
    link = tmp_path / "export-link"
    _junction(link, real)

    export = load_export(link)

    assert export.manifest_missing and export.manifest_refused == "koppeling"
    _, gap = export.objects("config/sslcertkey")
    assert gap is not None and REASONS["koppeling"] in gap.reason
    assert _opened_names(seam).count("export-manifest.json") == 0


def test_export_a_stream_name_is_refused_before_any_open(tmp_path, seam):
    export_dir = _export(tmp_path)
    export = load_export(export_dir)
    before = seam.calls["NtCreateFile"]
    raw, gap = export._read_verified_bytes("objects/sslcertkey.json:zijstroom")
    assert raw is None and gap is not None and REASONS["stroom"] in gap.reason
    assert seam.calls["NtCreateFile"] == before


def test_export_a_junction_target_file_and_scan_log_are_not_recorded(tmp_path, seam):
    from nsmcp import coverage
    from nsmcp.export import TARGET_FILE

    export_dir = _export(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / "doel").mkdir()
    (outside / "doel" / "x").write_text(NAALD, encoding="utf-8")
    _junction(export_dir / TARGET_FILE, outside / "doel")
    _junction(export_dir / coverage.LOG_FILE, outside / "doel")

    export = load_export(export_dir)

    assert export.target_name is None
    assert coverage._log_lines(export) is None


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_export_the_needle_never_reaches_an_answer(tmp_path, level):
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    export_dir = _export(tmp_path)
    outside = _outside_objects_the_manifest_accepts(tmp_path, export_dir)
    _replace_by_junction(export_dir / "objects", outside)
    server = build_server(export_dir, _knowledge_file(tmp_path), disclosure=level)

    answers = _answers(server, [("certificaat_wat_verloopt_er", {}), ("rapport_dekking", {})])

    for text in answers.values():
        _assert_no_needle(text, tmp_path)
    if level is Disclosure.LIMITED:
        assert REASONS["koppeling"] in answers["certificaat_wat_verloopt_er"]
    else:  # minimaal counts the read gaps and names none
        assert "1 leesgat(en)" in answers["certificaat_wat_verloopt_er"]


# ---------------------------------------------------------------------------
# Family: provenance (read and append), root = the provenance map
# ---------------------------------------------------------------------------


def _provenance(tmp_path: Path, export_dir: Path) -> Path:
    from conftest import record_collected

    provenance = tmp_path / "config" / "herkomst"
    record_collected(export_dir, "lab", provenance)
    return provenance


def _manifest_hash(export_dir: Path) -> str:
    import hashlib

    return hashlib.sha256((export_dir / "export-manifest.json").read_bytes()).hexdigest()


def test_provenance_a_swapped_provenance_map_is_no_record_and_its_file_is_never_opened(tmp_path, seam):
    from nsmcp.export import PROVENANCE_FILE, collected_for

    export_dir = _export(tmp_path)
    provenance = _provenance(tmp_path, export_dir)
    assert collected_for(provenance, "lab", _manifest_hash(export_dir), export_dir) is not None, "premisse"
    outside = _outside_dir(tmp_path)
    shutil.copy(provenance / PROVENANCE_FILE, outside / PROVENANCE_FILE)
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, "herkomst", lambda: _replace_by_junction(provenance, outside))

    assert collected_for(provenance, "lab", _manifest_hash(export_dir), export_dir) is None
    names = _opened_names(seam)
    assert names[-1] == "herkomst" and PROVENANCE_FILE not in names, names


def test_provenance_an_append_on_a_link_writes_nothing_and_logs_the_kind(tmp_path, seam, capsys):
    from datetime import UTC, datetime

    from nsmcp.export import PROVENANCE_FILE, record_provenance

    export_dir = _export(tmp_path)
    provenance = tmp_path / "config" / "herkomst"
    provenance.mkdir(parents=True)
    outside = _outside_dir(tmp_path)
    _junction(provenance / PROVENANCE_FILE, outside)

    with pytest.raises(OSError) as refused:
        record_provenance(provenance, "lab", _manifest_hash(export_dir), export_dir, datetime.now(UTC))

    assert isinstance(refused.value, localpath.PathRefused) and refused.value.soort == "koppeling"
    assert list(outside.iterdir()) == [] and seam.calls["WriteFile"] == 0
    err = capsys.readouterr().err
    assert "herkomst niet vastgelegd: geweigerd (soort=koppeling)" in err
    assert NAALD not in err and str(tmp_path) not in err


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_provenance_the_needle_never_reaches_an_answer(tmp_path, level):
    from nsmcp.export import PROVENANCE_FILE
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    export_dir = _export(tmp_path)
    provenance = _provenance(tmp_path, export_dir)
    outside = _outside_dir(tmp_path)
    shutil.copy(provenance / PROVENANCE_FILE, outside / PROVENANCE_FILE)
    _replace_by_junction(provenance, outside)
    server = build_server(export_dir, _knowledge_file(tmp_path), disclosure=level, provenance_dir=provenance)

    text = _answers(server, [("certificaat_wat_verloopt_er", {})])["certificaat_wat_verloopt_er"]

    _assert_no_needle(text, tmp_path)
    assert "herkomst: niet vastgesteld" in text


# ---------------------------------------------------------------------------
# Family: kept exports (retention, compare), root = the volume root of the text
# ---------------------------------------------------------------------------


def _kept(tmp_path: Path) -> tuple[Path, Path]:
    base = tmp_path / "exports"
    base.mkdir()
    current = _export(base)
    kept = base / "export.bewaard-20260801T080000Z"
    shutil.copytree(current, kept)
    manifest = json.loads((kept / "export-manifest.json").read_text(encoding="utf-8"))
    manifest["collectedAtUtc"] = "2026-08-01T08:00:00.0000000Z"
    (kept / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return current, kept


def test_kept_a_kept_export_swapped_for_a_link_mid_walk_is_not_kept_and_never_read(tmp_path, seam):
    from nsmcp.retention import kept_exports

    current, kept = _kept(tmp_path)
    assert kept_exports(current) == (kept,), "premisse"
    outside = _outside_dir(tmp_path)
    shutil.copytree(kept, outside / "kopie")
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, kept.name, lambda: _replace_by_junction(kept, outside / "kopie"))

    assert kept_exports(current) == ()
    names = _opened_names(seam)
    assert kept.name in names and "export-manifest.json" not in names[names.index(kept.name) :], names


def test_kept_an_ancestor_of_the_exports_that_is_a_link_refuses_every_kept_export(tmp_path, seam):
    from nsmcp.retention import kept_exports

    real = tmp_path / "echt"
    real.mkdir()
    current, kept = _kept(real)
    _junction(tmp_path / "via", real)

    assert kept_exports(tmp_path / "via" / "exports" / "export") == ()


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_kept_the_needle_never_reaches_a_comparison_answer(tmp_path, level):
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    current, kept = _kept(tmp_path)
    outside = _outside_dir(tmp_path)
    shutil.copytree(kept, outside / "kopie")
    _replace_by_junction(kept, outside / "kopie")
    server = build_server(current, _knowledge_file(tmp_path), disclosure=level)

    answers = _answers(
        server,
        [("rapport_vergelijk", {"mapA": kept.name, "mapB": "export"}), ("rapport_wat_is_er_veranderd", {})],
    )

    for text in answers.values():
        _assert_no_needle(text, tmp_path, "kopie")
    assert "staat niet naast de huidige export" in answers["rapport_vergelijk"]


# ---------------------------------------------------------------------------
# Family: collector (work manifests, phase file, scan lock, the swap)
# ---------------------------------------------------------------------------


def _work_export(base: Path, name: str = "werk") -> Path:
    work = base / name
    (work / "objects").mkdir(parents=True)
    (work / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "EMPTY"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    return work


def test_collector_a_work_map_swapped_mid_walk_fails_the_scan_and_is_never_read(tmp_path, seam):
    from nsmcp.collect import CollectError, _verify

    work = _work_export(tmp_path)
    outside = _work_export(tmp_path, NAALD)
    _swap_before(seam, "werk", lambda: _replace_by_junction(work, outside))

    with pytest.raises(CollectError) as refused:
        _verify(work)

    assert str(refused.value) == "het export-manifest kon niet gelezen worden: " + REASONS["koppeling"]
    names = _opened_names(seam)
    assert names[-1] == "werk" and "export-manifest.json" not in names, names


def test_collector_a_phase_file_that_is_a_link_is_unreadable_with_its_kind(tmp_path, seam):
    from nsmcp.collect import PHASE_FILE, phase_report, phase_summary

    work = _work_export(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / "x").mkdir()
    _junction(work / PHASE_FILE, outside / "x")

    text = phase_summary(phase_report(work, tmp_path / "export"))

    assert REASONS["koppeling"] in text
    _assert_no_needle(text, tmp_path)


def test_collector_a_lock_in_the_place_of_a_link_refuses_the_scan_and_writes_nothing(tmp_path, seam):
    from nsmcp.collect import CollectError, _acquire_lock, _read_lock_pid

    export_dir = tmp_path / "export"
    export_dir.mkdir()
    outside = _outside_dir(tmp_path)
    (outside / "1234").write_text(NAALD, encoding="utf-8")
    _junction(tmp_path / "export.lock", outside)

    with pytest.raises(CollectError) as refused:
        _acquire_lock(export_dir)

    assert str(refused.value) == "kon geen slot aanmaken voor de scan: " + REASONS["koppeling"]
    assert seam.calls["WriteFile"] == 0 and sorted(p.name for p in outside.iterdir()) == ["1234"]
    assert _read_lock_pid(tmp_path / "export.lock") == "onbekend"


def test_collector_a_work_map_swapped_for_a_link_before_the_swap_is_never_moved_in(tmp_path, seam):
    from nsmcp.collect import CollectError, _swap

    export_dir = _work_export(tmp_path, "export")
    work = _work_export(tmp_path, "export.nieuw-test")
    outside = _work_export(tmp_path, NAALD)
    _replace_by_junction(work, outside)

    with pytest.raises(CollectError, match="omwisselen"):
        _swap(work, export_dir)

    assert (outside / "export-manifest.json").is_file(), "het doel van de koppeling is niet verplaatst"
    assert seam.calls["NtSetInformationFile"] >= 1


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_collector_the_needle_never_reaches_the_scan_answer(tmp_path, level):
    from nsmcp.collect import PHASE_FILE
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    export_dir = _export(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / PHASE_FILE).mkdir()

    def scan_with_a_linked_manifest(arguments, timeout_s):
        out = Path(arguments[arguments.index("-OutDir") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (outside / "export-manifest.json").write_text(json.dumps({"collectedAtUtc": NAALD}), encoding="utf-8")
        _junction(out / "export-manifest.json", outside)
        _junction(out / PHASE_FILE, outside / PHASE_FILE)
        return 0, ""

    script = tmp_path / "collector.ps1"
    script.write_text("# leeg; de test neemt de aanroep over", encoding="utf-8")
    targets = tmp_path / "doelen.json"
    targets.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": "lab",
                        "adres": "10.0.0.10",
                        "credentialTarget": "gjk/netscaler/lab/readonly",
                        "certificaat": "keten",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    server = build_server(
        export_dir,
        _knowledge_file(tmp_path),
        targets_path=targets,
        collect_script=script,
        run=scan_with_a_linked_manifest,
        disclosure=level,
    )

    text = _answers(server, [("status_ververs", {"doelnaam": "lab"})])["status_ververs"]

    _assert_no_needle(text, tmp_path)
    assert "het export-manifest kon niet gelezen worden: " + REASONS["koppeling"] in text
    assert "het fasebestand is onleesbaar: " + REASONS["koppeling"] in text


# ---------------------------------------------------------------------------
# Families without a root (the path is configured or given on the command
# line): knowledge package (server, CLI, regression matrix, refresh log),
# configuration and targets. A link above such a path is FOLLOWED by design
# (B.2 step 5), so the negative proof is the parent swapped for what may
# never be followed: a link to a share (a documentation address, never
# routed) and, through the seam, a cloud placeholder. The refresh log has a
# root (the beheer map) and gets the junction proof of the rooted families.
# ---------------------------------------------------------------------------

_SHARE = "\\\\192.0.2.10\\x"


def _swap_for_share_link(directory: Path) -> None:
    import os

    directory.rename(directory.with_name(directory.name + "-weg"))
    try:
        os.symlink(_SHARE, directory, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")


def _knowledge_package(tmp_path: Path) -> Path:
    directory = tmp_path / NAALD / "kennis"
    directory.mkdir(parents=True)
    path = directory / "kennis.json"
    path.write_text(json.dumps({"versie": "2026.08", "datum": "2026-08-16", "cve": []}), encoding="utf-8")
    return path


def _assert_no_share_open(native) -> None:
    for record in native.opens:
        name = record["name"].lower()
        assert "192.0.2.10" not in name and "mup" not in name, record


def test_knowledge_a_parent_swapped_for_a_share_link_is_absent_and_the_share_never_opened(tmp_path, seam):
    from nsmcp.knowledge import load_knowledge

    path = _knowledge_package(tmp_path)
    assert not load_knowledge(path, date(2026, 8, 20)).missing, "premisse"
    seam.opens.clear()
    seam.events.clear()
    drive_checks = seam.calls["GetDriveTypeW"]
    _swap_before(seam, "kennis", lambda: _swap_for_share_link(path.parent))

    knowledge = load_knowledge(path, date(2026, 8, 20))

    assert knowledge.missing and knowledge.reason == "kennispakket geweigerd: " + REASONS["netwerkpad"]
    _assert_no_share_open(seam)
    assert seam.calls["GetDriveTypeW"] - drive_checks == 1, "het doel van de koppeling kwam niet voorbij de spelling"


def test_knowledge_a_cloud_placeholder_on_the_way_is_absent_with_its_kind(tmp_path, seam, monkeypatch):
    from conftest import reparse_at

    from nsmcp.knowledge import load_knowledge

    path = _knowledge_package(tmp_path)
    reparse_at(monkeypatch, path.parent, tag=0x9000601A)

    knowledge = load_knowledge(path, date(2026, 8, 20))

    assert knowledge.missing and knowledge.reason == "kennispakket geweigerd: " + REASONS["herparseerpunt"]
    assert seam.calls["DeviceIoControl"] == 0 and seam.calls["ReadFile"] == 0


def test_knowledge_the_cli_refuses_with_its_kind_and_never_names_the_path(tmp_path, seam, monkeypatch, capsys):
    from conftest import reparse_at

    from nsmcp import knowledge, knowledge_regression

    path = _knowledge_package(tmp_path)
    matrix = path.parent / "matrix.json"
    matrix.write_text("{}", encoding="utf-8")
    reparse_at(monkeypatch, path.parent, tag=0x9000601A)

    assert knowledge.main(["--digest", str(path)]) == 1
    assert knowledge.main(["--controleer", str(path)]) == 1
    err = capsys.readouterr().err
    assert "Fout: kennispakket geweigerd: " + REASONS["herparseerpunt"] + "; geen kennispin berekend" in err
    assert NAALD not in err
    raw, problem = knowledge_regression._read_matrix(matrix)
    assert raw is None and problem == "regressiematrix geweigerd: " + REASONS["herparseerpunt"]


def test_knowledge_the_refresh_log_in_the_place_of_a_link_is_not_written(tmp_path, seam, capsys):
    from nsmcp.knowledge_refresh import LOG_FILE_NAME, _write_log_line

    beheer = tmp_path / "_beheer"
    beheer.mkdir()
    outside = _outside_dir(tmp_path)
    _junction(beheer / LOG_FILE_NAME, outside)

    assert _write_log_line(beheer, "AFGEKEURD", tmp_path / "kennis.json", "reden") is False

    assert list(outside.iterdir()) == [] and seam.calls["WriteFile"] == 0
    assert "kennisverversing: geen logregel: geweigerd (soort=koppeling)" in capsys.readouterr().err


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_knowledge_the_needle_never_reaches_an_answer(tmp_path, monkeypatch, level):
    from conftest import reparse_at

    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    path = _knowledge_package(tmp_path)
    reparse_at(monkeypatch, path.parent, tag=0x9000601A)
    server = build_server(_export(tmp_path), path, disclosure=level)

    answers = _answers(server, [("status_cve_controle", {}), ("kennis_uitleg", {"onderwerp": "ns.conf"})])

    for text in answers.values():
        _assert_no_needle(text, tmp_path)


# ---------------------------------------------------------------------------
# Family: configuration and targets (no root)
# ---------------------------------------------------------------------------


def test_config_a_parent_swapped_for_a_share_link_is_a_config_error_of_its_kind(tmp_path, seam):
    from nsmcp.start import ConfigError, load_config

    directory = tmp_path / NAALD / "config"
    directory.mkdir(parents=True)
    path = directory / "nsmcp.json"
    path.write_text("{}", encoding="utf-8")
    # The start check walks the path first (and would refuse the swap
    # itself), then `_require_file` walks it (herstelronde 1: no stat by
    # name any more); the swap lands right before the READ walk opens `config`.
    encounters = []

    def between(index, name):
        if name == "config":
            encounters.append(index)
            if len(encounters) == 3:
                _swap_for_share_link(directory)

    seam.between = between

    with pytest.raises(ConfigError) as refused:
        load_config(path)

    assert str(refused.value) == "configuratiebestand onleesbaar: " + REASONS["netwerkpad"]
    assert NAALD not in str(refused.value)
    _assert_no_share_open(seam)


def test_targets_a_cloud_placeholder_on_the_way_is_a_target_error_of_its_kind(tmp_path, seam, monkeypatch):
    from conftest import reparse_at

    from nsmcp.target import TargetError, load_targets

    directory = tmp_path / NAALD
    directory.mkdir()
    path = directory / "doelen.json"
    path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    assert load_targets(path) == {}, "premisse"
    reparse_at(monkeypatch, directory, tag=0x9000601A)
    reads = seam.calls["ReadFile"]

    with pytest.raises(TargetError) as refused:
        load_targets(path)

    assert str(refused.value) == "doelenbestand onleesbaar: " + REASONS["herparseerpunt"]
    assert seam.calls["ReadFile"] == reads


def test_targets_a_parent_swapped_for_a_share_link_mid_walk_is_refused(tmp_path, seam):
    from nsmcp.target import TargetError, load_targets

    directory = tmp_path / NAALD
    directory.mkdir()
    path = directory / "doelen.json"
    path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    _swap_before(seam, NAALD, lambda: _swap_for_share_link(directory))

    with pytest.raises(TargetError) as refused:
        load_targets(path)

    assert str(refused.value) == "doelenbestand onleesbaar: " + REASONS["netwerkpad"]
    _assert_no_share_open(seam)


# ---------------------------------------------------------------------------
# Family: pseudonym table with its lock, root = the table's directory
# ---------------------------------------------------------------------------


def _table(tmp_path: Path) -> Path:
    table = tmp_path / "beheer" / "tabel.json"
    table.parent.mkdir(parents=True)
    write_signed_table(table, {"object-01": "CERT-BINNEN"})
    return table


def _limited_render(table: Path):
    from nsmcp.answer import Answer, Certainty, Finding
    from nsmcp.disclosure import render

    answer = Answer(
        question="q",
        findings=[Finding(subject="CERT-BINNEN", outcome="o", certainty=Certainty.ESTABLISHED, evidence="e")],
    )
    return render(answer, Disclosure.LIMITED, tool="x", extra_names=("CERT-BINNEN",), pseudonym_table_path=table)


def test_table_a_table_directory_swapped_mid_walk_is_refused_and_never_read(tmp_path, seam):
    from nsmcp.disclosure import PseudonymTablePathRefused

    table = _table(tmp_path)
    assert "object-01" in _limited_render(table), "premisse"
    outside = _outside_dir(tmp_path)
    write_signed_table((outside / "tabel.json"), {"object-01": NAALD})
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, "beheer", lambda: _replace_by_junction(table.parent, outside))

    with pytest.raises(PseudonymTablePathRefused) as refused:
        _limited_render(table)

    assert REASONS["koppeling"] in str(refused.value)
    assert NAALD not in str(refused.value) and str(tmp_path) not in str(refused.value)
    assert "tabel.json" not in _opened_names(seam) and "tabel.json.lock" not in _opened_names(seam)


def test_table_a_link_in_the_place_of_the_table_is_refused_and_never_overwritten(tmp_path, seam):
    from nsmcp.disclosure import PseudonymTablePathRefused

    table = _table(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / "x").write_text(NAALD, encoding="utf-8")
    table.unlink()
    _junction(table, outside)

    with pytest.raises(PseudonymTablePathRefused) as refused:
        _limited_render(table)

    assert str(refused.value).startswith("de vertaaltabel is geweigerd: " + REASONS["koppeling"])
    assert [p.name for p in outside.iterdir()] == ["x"] and seam.calls["WriteFile"] == 0


def test_table_a_link_in_the_place_of_the_lock_is_refused_before_the_table_is_read(tmp_path, seam):
    from nsmcp.disclosure import PseudonymTablePathRefused

    table = _table(tmp_path)
    outside = _outside_dir(tmp_path)
    _junction(table.with_name("tabel.json.lock"), outside)
    seam.opens.clear()  # the signed test table was written through the seam during the setup

    with pytest.raises(PseudonymTablePathRefused) as refused:
        _limited_render(table)

    assert str(refused.value).startswith("het slot naast de vertaaltabel is geweigerd: " + REASONS["koppeling"])
    assert "tabel.json" not in _opened_names(seam), "de tabel zelf is niet geopend"
    assert list(outside.iterdir()) == []


_PROBE = (
    "import os, sys\n"
    "lock, spare = sys.argv[1], sys.argv[2]\n"
    "try:\n"
    "    with open(lock, 'ab') as stream:\n"
    "        stream.write(b'x')\n"
    "    print('SCHRIJFT')\n"
    "except OSError:\n"
    "    print('GEWEIGERD')\n"
    "try:\n"
    "    open(spare, 'wb').close()\n"
    "    os.replace(spare, lock)\n"
    "    print('VERVANGT')\n"
    "except OSError:\n"
    "    print('NIETVERVANGEN')\n"
)

_HOLDER = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from nsmcp import disclosure\n"
    "lock = disclosure._ProcessLock(Path(sys.argv[1]))\n"
    "lock.__enter__()\n"
    "print('HOUDT', flush=True)\n"
    "time.sleep(30)\n"
)


def _probe(lock: Path, spare: Path) -> list[str]:
    import subprocess

    run = subprocess.run(
        [sys.executable, "-c", _PROBE, str(lock), str(spare)], capture_output=True, text=True, check=True, timeout=60
    )
    return run.stdout.split()


def test_table_the_lock_keeps_another_process_out_and_lets_it_in_once_free(tmp_path):
    """M-1 of the red review: two-sided, with the PRODUCT holding the lock.
    While `_ProcessLock` holds the lock file, a second process can neither
    write it nor replace it; once it is free, the same process can do both.
    A product lock that shared writing (or deletion) lets the second process
    in while it is held, and this test falls."""
    from nsmcp import disclosure

    table = _table(tmp_path)
    lock = table.with_name("tabel.json.lock")
    with disclosure._ProcessLock(table):
        held = _probe(lock, tmp_path / "reserve-1")
    free = _probe(lock, tmp_path / "reserve-2")
    assert held == ["GEWEIGERD", "NIETVERVANGEN"], held
    assert free == ["SCHRIJFT", "VERVANGT"], free


def test_table_a_second_process_holding_the_lock_is_a_lock_refusal(tmp_path, monkeypatch):
    """The other side: a second PROCESS takes the product's own lock and
    holds it; this process waits and is refused with the time-bounded
    `PseudonymTableLocked`, and reads the table once the holder is gone."""
    import subprocess

    from nsmcp import disclosure
    from nsmcp.disclosure import PseudonymTableLocked

    table = _table(tmp_path)
    monkeypatch.setattr(disclosure, "_PROCESS_LOCK_TIMEOUT_S", 0.3)
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(table)], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "HOUDT"
        with pytest.raises(PseudonymTableLocked, match="niet verkrijgen"):
            _limited_render(table)
    finally:
        holder.kill()
        holder.wait(timeout=30)
        holder.stdout.close()
    assert "object-01" in _limited_render(table), "na het loslaten werkt het slot weer"


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_table_the_needle_never_reaches_an_answer(tmp_path, level):
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    export_dir = _export(tmp_path)
    table = _table(tmp_path)
    outside = _outside_dir(tmp_path)
    write_signed_table((outside / "tabel.json"), {"object-01": NAALD})
    _replace_by_junction(table.parent, outside)
    server = build_server(export_dir, _knowledge_file(tmp_path), disclosure=level, pseudonym_table_path=table)

    text = _answers(server, [("certificaat_wat_verloopt_er", {})])["certificaat_wat_verloopt_er"]

    _assert_no_needle(text, tmp_path)
    if level is Disclosure.LIMITED:
        assert REASONS["koppeling"] in text


# ---------------------------------------------------------------------------
# Family: ledger (read and append) and action register, root = the file's map
# ---------------------------------------------------------------------------


def _ledger_row(run: str, doel: str = "lab") -> dict:
    return {
        "tijd": "2026-10-26T08:00:00Z",
        "run": run,
        "doel": doel,
        "fase": "R0",
        "gebeurtenis": "fase_gestart",
        "poort": [],
        "uitkomst": "",
        "bewijs": "",
        "actieid": "a-1",
        "bevestiger": "u-1",
        "gestart": "2026-10-26T08:00:00Z",
        "geeindigd": None,
    }


def test_ledger_a_ledger_map_swapped_mid_walk_is_unreadable_and_never_read(tmp_path, seam):
    from nsmcp.upgrade import append_line, read_ledger
    from nsmcp.upgrade_gate import LedgerUnreadable, _rows_from_file

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    run_file = ledgermap / "run-1.jsonl"
    append_line(run_file, _ledger_row("run-1"))
    assert len(read_ledger(run_file)) == 1, "premisse"
    outside = _outside_dir(tmp_path)
    (outside / "run-1.jsonl").write_text(json.dumps(_ledger_row(NAALD)) + "\n", encoding="utf-8")
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, "ledger", lambda: _replace_by_junction(ledgermap, outside))

    with pytest.raises(LedgerUnreadable) as refused:
        _rows_from_file(run_file, strict=True)

    assert str(refused.value) == (
        "een regelbestand in de ledgermap kon niet gelezen worden (" + REASONS["koppeling"] + ")"
    )
    names = _opened_names(seam)
    assert names[-1] == "ledger" and "run-1.jsonl" not in names, names


def test_ledger_an_append_on_a_link_writes_no_line(tmp_path, seam):
    from nsmcp.upgrade import append_line

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside = _outside_dir(tmp_path)
    _junction(ledgermap / "run-1.jsonl", outside)

    with pytest.raises(OSError) as refused:
        append_line(ledgermap / "run-1.jsonl", _ledger_row("run-1"))

    assert isinstance(refused.value, localpath.PathRefused) and refused.value.soort == "koppeling"
    assert list(outside.iterdir()) == [] and seam.calls["WriteFile"] == 0


def test_ledger_the_gate_cli_writes_no_line_on_a_refused_ledger_and_fails(tmp_path, seam):
    from nsmcp import upgrade_gate

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside = _outside_dir(tmp_path)
    _junction(ledgermap / "run-1.jsonl", outside)

    with pytest.raises(OSError):
        upgrade_gate.append_line(ledgermap / "run-1.jsonl", _ledger_row("run-1"))
    assert list(outside.iterdir()) == []


def test_register_a_link_in_the_place_of_the_register_is_not_assessed(tmp_path, seam):
    from nsmcp.upgrade import backup_register_gate
    from nsmcp.upgrade_measure import _read_register_or_none

    register_map = tmp_path / "register"
    register_map.mkdir()
    outside = _outside_dir(tmp_path)
    (outside / "x").mkdir()
    _junction(register_map / "acties.jsonl", outside / "x")

    lines = _read_register_or_none(str(register_map / "acties.jsonl"))

    assert lines is None
    assert backup_register_gate(lines, "lab").outcome == "niet beoordeeld"
    assert "acties.jsonl" in _opened_names(seam)


def test_register_the_writer_on_a_link_reports_it_and_writes_nothing(tmp_path, seam):
    import dataclasses

    from conftest import maintenance_config

    from nsmcp.mcp_server import _write_action_register

    config = maintenance_config(tmp_path)
    register = tmp_path / "register" / "acties.jsonl"
    register.parent.mkdir()
    outside = _outside_dir(tmp_path)
    _junction(register, outside)
    onderhoud = dataclasses.replace(config, actieregister=register)

    finding = _write_action_register(
        onderhoud,
        tool="onderhoud_backup_maken",
        doel="lab",
        actieid="a-1",
        uitkomst="geslaagd",
        bevestiger="u-1",
        objectnaam="b-1",
    )

    assert finding is not None and finding.outcome == (
        "duurzame registratie NIET vastgesteld (" + REASONS["koppeling"] + ")"
    )
    assert list(outside.iterdir()) == [] and seam.calls["WriteFile"] == 0


# ---------------------------------------------------------------------------
# Family: runner log (append), root = the ledger map
# ---------------------------------------------------------------------------


def test_runner_log_a_link_in_the_place_of_the_log_starts_nothing(tmp_path, seam, monkeypatch):
    from nsmcp import handelen
    from nsmcp.handelen import RunnerLogUnopenable

    started = []
    monkeypatch.setattr(handelen.subprocess, "Popen", lambda *a, **k: started.append(a))
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside = _outside_dir(tmp_path)
    _junction(ledgermap / "run-1.log", outside)

    with pytest.raises(RunnerLogUnopenable) as refused:
        handelen.start_detached(["x"], log_path=ledgermap / "run-1.log")

    assert refused.value.oorzaak == "PathRefused" and started == []
    assert list(outside.iterdir()) == [] and seam.calls["WriteFile"] == 0
    _assert_no_needle(str(refused.value), tmp_path)


def test_runner_log_a_ledger_map_swapped_mid_walk_starts_nothing(tmp_path, seam, monkeypatch):
    from nsmcp import handelen
    from nsmcp.handelen import RunnerLogUnopenable

    started = []
    monkeypatch.setattr(handelen.subprocess, "Popen", lambda *a, **k: started.append(a))
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside = _outside_dir(tmp_path)
    _swap_before(seam, "ledger", lambda: _replace_by_junction(ledgermap, outside))

    with pytest.raises(RunnerLogUnopenable):
        handelen.start_detached(["x"], log_path=ledgermap / "run-1.log")

    assert started == [] and list(outside.iterdir()) == []
    assert _opened_names(seam)[-1] == "ledger"


def test_runner_log_a_plain_log_takes_the_child_output(tmp_path):
    from nsmcp import handelen

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    handelen.start_detached([sys.executable, "-c", "print('kind')"], log_path=ledgermap / "run-1.log")
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and b"kind" not in (ledgermap / "run-1.log").read_bytes():
        time.sleep(0.1)
    assert b"kind" in (ledgermap / "run-1.log").read_bytes()


# ---------------------------------------------------------------------------
# Family: firmware bundle (Python side), root = onderhoud.firmwaremap
# ---------------------------------------------------------------------------

_BUNDLE = "build-14.1-72.57_nc_64.tgz"


def _firmwaremap(tmp_path: Path) -> Path:
    firmwaremap = tmp_path / "firmware"
    firmwaremap.mkdir()
    (firmwaremap / _BUNDLE).write_bytes(b"\0" * 2048)
    return firmwaremap


def test_firmware_a_bundle_that_is_a_link_is_no_target_build(tmp_path, seam):
    from nsmcp.handelen import FirmwareBundleError, firmware_target_build

    firmwaremap = _firmwaremap(tmp_path)
    assert firmware_target_build(firmwaremap).build == "14.1-72.57", "premisse"
    outside = _outside_dir(tmp_path)
    (firmwaremap / _BUNDLE).unlink()
    _junction(firmwaremap / _BUNDLE, outside)

    with pytest.raises(FirmwareBundleError) as refused:
        firmware_target_build(firmwaremap)

    assert (
        refused.value.zonder_pad == "de firmwarebundel in onderhoud.firmwaremap is geweigerd: " + REASONS["koppeling"]
    )
    assert str(firmwaremap) in str(refused.value), "bij volledig mag het pad erbij"
    _assert_no_needle(refused.value.zonder_pad, tmp_path)


def test_firmware_a_firmware_map_swapped_mid_walk_never_opens_the_bundle_outside(tmp_path, seam):
    from nsmcp.handelen import FirmwareBundleError, firmware_target_build

    firmwaremap = _firmwaremap(tmp_path)
    firmware_target_build(firmwaremap)
    outside = _outside_dir(tmp_path)
    (outside / _BUNDLE).write_bytes(b"\0" * 4096)
    seam.opens.clear()
    seam.events.clear()
    _swap_before(seam, "firmware", lambda: _replace_by_junction(firmwaremap, outside))

    with pytest.raises(FirmwareBundleError):
        firmware_target_build(firmwaremap)

    names = _opened_names(seam)
    assert names[-1] == "firmware" and _BUNDLE not in names, names


@pytest.mark.parametrize("level", [Disclosure.FULL, Disclosure.LIMITED, Disclosure.MINIMAL])
def test_firmware_the_path_reaches_an_answer_only_at_volledig(tmp_path, level):
    import dataclasses

    from conftest import maintenance_config

    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    firmwaremap = _firmwaremap(tmp_path)
    outside = _outside_dir(tmp_path)
    (firmwaremap / _BUNDLE).unlink()
    _junction(firmwaremap / _BUNDLE, outside)
    onderhoud = dataclasses.replace(maintenance_config(tmp_path), firmwaremap=firmwaremap)
    server = build_server(_export(tmp_path), _knowledge_file(tmp_path), disclosure=level, onderhoud=onderhoud)

    text = _answers(server, [("onderhoud_upgrade_plan", {})])["onderhoud_upgrade_plan"]

    if level is not Disclosure.MINIMAL:  # minimaal counts the gaps and names none
        assert "de firmwarebundel in onderhoud.firmwaremap is geweigerd: " + REASONS["koppeling"] in text
    if level is Disclosure.FULL:
        assert str(firmwaremap) in text
    else:
        _assert_no_needle(text, tmp_path)


# ---------------------------------------------------------------------------
# Family: script pin, root = the script's directory
# ---------------------------------------------------------------------------


def test_scriptpin_a_script_directory_swapped_mid_walk_starts_no_process(tmp_path, seam):
    import hashlib

    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, check_script_pins, set_script_policy

    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "runner.ps1").write_text("# echt", encoding="ascii")
    outside = _outside_dir(tmp_path)
    (outside / "runner.ps1").write_text("# echt", encoding="ascii")
    pin = hashlib.sha256(b"# echt").hexdigest()
    set_script_policy(ScriptPolicy(pins={"runner.ps1": pin}))
    try:
        check_script_pins(scripts / "runner.ps1")
        seam.opens.clear()
        seam.events.clear()
        _swap_before(seam, "scripts", lambda: _replace_by_junction(scripts, outside))
        with pytest.raises(ScriptPinMismatch) as refused:
            check_script_pins(scripts / "runner.ps1")
    finally:
        set_script_policy(ScriptPolicy())

    assert REASONS["koppeling"] in str(refused.value)
    names = _opened_names(seam)
    assert "runner.ps1" not in names, names
    _assert_no_needle(str(refused.value), tmp_path)


def test_scriptpin_a_script_that_is_a_link_is_refused_even_with_matching_bytes(tmp_path, seam):
    import hashlib
    import os

    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, check_script_pins, set_script_policy

    scripts = tmp_path / "scripts"
    scripts.mkdir()
    outside = _outside_dir(tmp_path)
    (outside / "runner.ps1").write_text("# buiten", encoding="ascii")
    try:
        os.symlink(outside / "runner.ps1", scripts / "runner.ps1")
    except OSError as exc:  # pragma: no cover - depends on the symlink right of the account
        pytest.skip(f"symbolische link niet toegestaan op deze machine: {exc.__class__.__name__}")
    set_script_policy(ScriptPolicy(pins={"runner.ps1": hashlib.sha256(b"# buiten").hexdigest()}))
    try:
        with pytest.raises(ScriptPinMismatch) as refused:
            check_script_pins(scripts / "runner.ps1")
    finally:
        set_script_policy(ScriptPolicy())
    assert REASONS["koppeling"] in str(refused.value)
    assert seam.calls["ReadFile"] == 0


# ---------------------------------------------------------------------------
# The ledger needle: the run state at beperkt and minimaal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_ledger_the_needle_never_reaches_the_run_state(tmp_path, level):
    from conftest import maintenance_config

    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    onderhoud = maintenance_config(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / f"{NAALD}.jsonl").write_text(json.dumps(_ledger_row(NAALD)) + "\n", encoding="utf-8")
    shutil.rmtree(onderhoud.ledgermap)
    _junction(onderhoud.ledgermap, outside)
    server = build_server(_export(tmp_path), _knowledge_file(tmp_path), disclosure=level, onderhoud=onderhoud)

    text = _answers(server, [("onderhoud_upgrade_stand", {"run": NAALD})])["onderhoud_upgrade_stand"]

    _assert_no_needle(text, tmp_path)


def test_knowledge_a_junction_in_the_place_of_the_package_is_absent_and_nothing_is_read(tmp_path, seam):
    from nsmcp.knowledge import load_knowledge

    path = _knowledge_package(tmp_path)
    outside = tmp_path / "buiten-map"
    outside.mkdir()
    path.unlink()
    _junction(path, outside)
    reads = seam.calls["ReadFile"]

    knowledge = load_knowledge(path, date(2026, 8, 20))

    assert knowledge.missing and knowledge.reason.startswith("kennispad wijst naar een map, geen bestand")
    assert seam.calls["ReadFile"] == reads


def test_export_on_a_network_drive_is_a_read_gap_of_its_kind_without_any_open(tmp_path, seam, monkeypatch):
    export_dir = _export(tmp_path)
    monkeypatch.setattr(seam, "GetDriveTypeW", lambda root: localpath.DRIVE_REMOTE)
    opens = seam.calls["NtCreateFile"]

    export = load_export(export_dir)

    assert export.manifest_missing and export.manifest_refused == "netwerkstation"
    _, gap = export.objects("config/sslcertkey")
    assert gap is not None and REASONS["netwerkstation"] in gap.reason
    assert seam.calls["NtCreateFile"] == opens, "niets geopend op het netwerkstation"


def test_config_a_cloud_placeholder_after_the_start_check_is_a_config_error_of_its_kind(tmp_path, seam, monkeypatch):
    """The read walk of the configuration file itself, without any network
    in play: the start check walks the path first (and passes), then the
    configuration's directory reports a cloud placeholder (seam) right
    before the read walk opens it."""
    from nsmcp.start import ConfigError, load_config

    directory = tmp_path / NAALD / "config"
    directory.mkdir(parents=True)
    path = directory / "nsmcp.json"
    path.write_text("{}", encoding="utf-8")
    names: dict[int, str] = {}
    encounters: list[int] = []
    real_open = seam.NtCreateFile
    real_tag = seam.query_attribute_tag

    def tracked_open(parent, name, *args, **kwargs):
        status, handle = real_open(parent, name, *args, **kwargs)
        if handle is not None:
            names[handle] = name
        return status, handle

    def tag_after_the_check(handle):
        status, attributes, tag = real_tag(handle)
        if names.get(handle) == "config" and len(encounters) >= 3:
            return status, attributes | localpath.FILE_ATTRIBUTE_REPARSE_POINT, 0x9000601A
        return status, attributes, tag

    def between(index, name):
        if name == "config":
            encounters.append(index)

    monkeypatch.setattr(seam, "NtCreateFile", tracked_open)
    monkeypatch.setattr(seam, "query_attribute_tag", tag_after_the_check)
    seam.between = between
    reads = seam.calls["ReadFile"]

    with pytest.raises(ConfigError) as refused:
        load_config(path)

    assert len(encounters) == 3, "premisse: de startcontrole, _require_file en de lezing liepen elk een keer"
    assert str(refused.value) == "configuratiebestand onleesbaar: " + REASONS["herparseerpunt"]
    assert seam.calls["ReadFile"] == reads and NAALD not in str(refused.value)


# ---------------------------------------------------------------------------
# Hardlink (B.2 step 6, revision 3): a file outside the export with a second
# name inside it is a read gap of its own kind, nothing of it read.
# ---------------------------------------------------------------------------


def _hardlinked_object(tmp_path: Path) -> Path:
    import os

    export_dir = _export(tmp_path)
    outside = _outside_dir(tmp_path)
    (outside / "sslcertkey.json").write_text(json.dumps(_cert_object(NAALD)), encoding="utf-8")
    (export_dir / "objects" / "sslcertkey.json").unlink()
    os.link(outside / "sslcertkey.json", export_dir / "objects" / "sslcertkey.json")
    seal_manifest(export_dir)  # the manifest even carries the hash of the outside bytes
    return export_dir


def test_export_a_hardlink_inside_the_export_is_a_read_gap_and_nothing_is_read(tmp_path, seam):
    export_dir = _hardlinked_object(tmp_path)
    export = load_export(export_dir)
    reads = seam.calls["ReadFile"]

    objects, gap = export.objects("config/sslcertkey")

    assert objects == []
    assert gap is not None and gap.reason == "objectbestand kon niet gelezen worden: " + REASONS["hardlink"]
    assert seam.calls["ReadFile"] == reads, "niets van het bestand met twee namen gelezen"


@pytest.mark.parametrize("level", [Disclosure.LIMITED, Disclosure.MINIMAL])
def test_export_the_needle_of_a_hardlink_never_reaches_an_answer(tmp_path, level):
    from nsmcp.mcp_server import build_server, forget_identities

    forget_identities()
    export_dir = _hardlinked_object(tmp_path)
    server = build_server(export_dir, _knowledge_file(tmp_path), disclosure=level)

    text = _answers(server, [("certificaat_wat_verloopt_er", {})])["certificaat_wat_verloopt_er"]

    _assert_no_needle(text, tmp_path)
    if level is Disclosure.LIMITED:
        assert REASONS["hardlink"] in text
    else:
        assert "1 leesgat(en)" in text


def test_ledger_an_append_on_a_hardlink_writes_no_line(tmp_path, seam):
    import os

    from nsmcp.upgrade import append_line

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside = _outside_dir(tmp_path)
    (outside / "elders.jsonl").write_text("", encoding="utf-8")
    os.link(outside / "elders.jsonl", ledgermap / "run-1.jsonl")

    with pytest.raises(OSError) as refused:
        append_line(ledgermap / "run-1.jsonl", _ledger_row("run-1"))

    assert isinstance(refused.value, localpath.PathRefused) and refused.value.soort == "hardlink"
    assert (outside / "elders.jsonl").read_bytes() == b"" and seam.calls["WriteFile"] == 0
