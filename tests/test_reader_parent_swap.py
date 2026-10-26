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
from pathlib import Path

import mcp.types as types
import pytest
from conftest import _knowledge_file, seal_manifest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import localpath
from nsmcp.disclosure import Disclosure
from nsmcp.export import load_export
from nsmcp.localpath import REASONS

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="een junction en de NtCreateFile-wandeling bestaan alleen op Windows"
)

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
