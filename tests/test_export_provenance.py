"""A target-bound answer needs THIS server's own record that it collected the
export for that target.

`scan-doel.txt` carries the target name and the sha256 of the manifest it
belongs to. That proves the two belong together - not where they came from:
whoever supplies an export writes both. Measured: an export of target B,
relabelled as target A with the hash recomputed, answered
`status_overzicht(doel="target-a")` with build 14.1-66.59 `[vastgesteld]`
and `doel: target-a`. `status_ververs` - and only it - now appends a record
per scan outside the export map, and a target-bound answer (and every
writing tool that relies on the export) needs the newest record for that
target to carry this manifest's hash.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import itertools
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import mcp.types as types
import pytest
from conftest import PATH_SPELLINGS, directory_link, provenance_dir_for, seal_manifest, spelled
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp.mcp_server import build_server

FIXTURES = Path(__file__).parent / "fixtures"
PREFLIGHT_EXPORT = FIXTURES / "preflight-export"
REFUSED = "doel niet vastgesteld: de export is niet door deze server voor dit doel verzameld"
SUPPLIED = "herkomst: niet vastgesteld (aangeleverde export)"


def _ask(server, tool: str, arguments: dict | None = None) -> tuple[bool, str]:
    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool(tool, arguments or {})

    result = asyncio.run(scenario())
    return result.isError, "\n".join(block.text for block in result.content if hasattr(block, "text"))


def _targets(tmp_path: Path) -> Path:
    path = tmp_path / "doelen.json"
    path.write_text(
        json.dumps(
            {
                "doelen": [
                    {
                        "naam": naam,
                        "adres": adres,
                        "credentialTarget": f"offline/{naam}/readonly",
                        "certificaat": "keten",
                    }
                    for naam, adres in (("target-a", "192.0.2.10"), ("target-b", "192.0.2.11"))
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _knowledge(tmp_path: Path) -> Path:
    path = tmp_path / "kennis.json"
    path.write_text(json.dumps({"versie": "offline", "datum": "2026-09-28", "cve": []}), encoding="utf-8")
    return path


def _manifest_hash(export: Path) -> str:
    return hashlib.sha256((export / "export-manifest.json").read_bytes()).hexdigest()


def _label(export: Path, doel: str, digest: str | None = None) -> None:
    (export / "scan-doel.txt").write_text(f"{doel}\n{digest or _manifest_hash(export)}\n", encoding="utf-8")


def _export_of_b(tmp_path: Path) -> Path:
    """The fixture as an export this server collected for target-b."""
    export = tmp_path / "export"
    shutil.copytree(PREFLIGHT_EXPORT, export)
    _label(export, "target-b")
    return export


def _record(export: Path, doel: str, digest: str | None = None, *, identity: Path | None = None, when=None):
    from nsmcp.export import record_provenance

    record_provenance(
        provenance_dir_for(export),
        doel,
        digest or _manifest_hash(export),
        identity or export,
        when or datetime.now(UTC),
    )


def _server(tmp_path: Path, export: Path, **kwargs):
    return build_server(export, _knowledge(tmp_path), targets_path=_targets(tmp_path), **kwargs)


# --- the measured attack ------------------------------------------------------


def test_an_export_of_another_target_relabelled_with_a_recomputed_hash_is_refused(tmp_path):
    export = _export_of_b(tmp_path)
    _label(export, "target-a")  # the forgery: name changed, hash recomputed
    error, text = _ask(_server(tmp_path, export), "status_overzicht", {"doel": "target-a"})
    # Measured before: no error, "- build: 14.1-66.59 [vastgesteld]", "doel: target-a".
    assert error is True, text
    assert REFUSED in text
    assert "[vastgesteld]" not in text


def test_the_relabelled_export_is_refused_even_where_this_server_did_collect_it_for_the_other_target(tmp_path):
    export = _export_of_b(tmp_path)
    _record(export, "target-b")
    _label(export, "target-a")
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


def test_a_marker_with_a_stale_hash_is_still_refused(tmp_path):
    export = _export_of_b(tmp_path)
    _record(export, "target-a")
    _label(export, "target-a", "0" * 64)
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert "zegt niet welk doel hij beschrijft" in text


# --- what a record does and does not prove ------------------------------------


def test_an_export_this_server_collected_for_the_target_is_answered(tmp_path):
    export = _export_of_b(tmp_path)
    _label(export, "target-a")
    _record(export, "target-a", when=datetime(2026, 9, 29, 8, 15, tzinfo=UTC))
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is False, text
    assert "- build: 14.1-66.59 [vastgesteld]" in text
    assert "doel: target-a, herkomst: verzameld door deze server op 2026-09-29 08:15 UTC." in text


def test_an_older_scan_put_back_is_refused(tmp_path):
    export = _export_of_b(tmp_path)
    _label(export, "target-a")
    _record(export, "target-a", when=datetime.now(UTC) - timedelta(days=2))
    _record(export, "target-a", "f" * 64)  # a newer scan of target-a left another manifest
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


def test_a_record_for_another_export_map_does_not_count(tmp_path):
    export = _export_of_b(tmp_path)
    _label(export, "target-a")
    _record(export, "target-a", identity=tmp_path / "andere-exportmap")
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


def test_a_record_inside_the_export_map_does_not_count(tmp_path):
    # Whoever supplies the export can write inside it; the server reads its
    # records only from its own provenance map.
    from nsmcp.export import record_provenance

    export = _export_of_b(tmp_path)
    _label(export, "target-a")
    record_provenance(export, "target-a", _manifest_hash(export), export, datetime.now(UTC))
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


# --- without a target: the answer stands, and says where the export came from --


def test_without_a_target_the_data_age_line_says_the_export_was_supplied(tmp_path):
    export = _export_of_b(tmp_path)
    _label(export, "target-a")
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_overzicht")
    assert error is False, text
    assert text.splitlines()[-1].endswith(f"doel: target-a, {SUPPLIED}.")


def test_without_a_target_the_data_age_line_names_this_servers_scan(tmp_path):
    export = _export_of_b(tmp_path)
    _record(export, "target-b", when=datetime(2026, 9, 28, 23, 5, tzinfo=UTC))
    server = _server(tmp_path, export, provenance_dir=provenance_dir_for(export))
    error, text = _ask(server, "status_cve_controle")
    assert error is False, text
    assert text.splitlines()[-1].endswith(
        "doel: target-b, herkomst: verzameld door deze server op 2026-09-28 23:05 UTC."
    )


def test_reading_tools_write_no_provenance(tmp_path):
    export = _export_of_b(tmp_path)
    provenance = provenance_dir_for(export)
    server = _server(tmp_path, export, provenance_dir=provenance)
    for tool, arguments in (("status_overzicht", {}), ("status_overzicht", {"doel": "target-b"})):
        _ask(server, tool, arguments)
    assert not provenance.exists()


# --- status_ververs writes the record, and only it ----------------------------


def _scan(arguments, timeout_s):
    uit = Path(arguments[arguments.index("-OutDir") + 1])
    (uit / "objects").mkdir(parents=True, exist_ok=True)
    (uit / "bindings").mkdir(parents=True, exist_ok=True)
    (uit / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-29T07:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "EMPTY"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(uit)
    return 0, ""


def _scanning_server(tmp_path: Path, **kwargs):
    export = tmp_path / "export"
    shutil.copytree(PREFLIGHT_EXPORT, export)
    script = tmp_path / "collector.ps1"
    script.write_text("# leeg; de test neemt de scan over", encoding="utf-8")
    server = build_server(
        export,
        _knowledge(tmp_path),
        targets_path=_targets(tmp_path),
        collect_script=script,
        run=_scan,
        **kwargs,
    )
    return server, export


def test_status_ververs_records_the_export_it_collected(tmp_path):
    server, export = _scanning_server(tmp_path, provenance_dir=provenance_dir_for(tmp_path / "export"))
    error, text = _ask(server, "status_ververs", {"doelnaam": "target-a"})
    assert error is False, text
    assert "is gelukt" in text
    assert "herkomst: verzameld door deze server op" in text
    records = [
        json.loads(line)
        for line in (provenance_dir_for(export) / "herkomst.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1
    assert records[0]["doel"] == "target-a"
    assert records[0]["manifestSha256"] == _manifest_hash(export)
    assert set(records[0]) == {"tijd", "doel", "manifestSha256", "exportmap"}

    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is False, text

    # An export supplied after the scan, relabelled with a recomputed hash.
    manifest = json.loads((export / "export-manifest.json").read_text(encoding="utf-8"))
    manifest["collectedAtUtc"] = "2026-09-29T09:00:00.0000000Z"
    (export / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    _label(export, "target-a")
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


def test_an_export_replaced_right_after_the_swap_is_not_recorded_as_collected(tmp_path, monkeypatch):
    # The record used to come from a second reading of the export map AFTER
    # the swap. An export put in its place in that window - relabelled for
    # the target, hash recomputed - was recorded as collected by this server.
    import nsmcp.mcp_server as server_module

    real_collect = server_module.collect

    def collect_then_replace(target, export_dir, *args, **kwargs):
        result = real_collect(target, export_dir, *args, **kwargs)
        manifest = json.loads((export_dir / "export-manifest.json").read_text(encoding="utf-8"))
        manifest["collectedAtUtc"] = "2026-09-29T09:00:00.0000000Z"
        (export_dir / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        seal_manifest(export_dir)
        _label(export_dir, target.name)
        return result

    monkeypatch.setattr(server_module, "collect", collect_then_replace)
    server, export = _scanning_server(tmp_path, provenance_dir=provenance_dir_for(tmp_path / "export"))
    error, text = _ask(server, "status_ververs", {"doelnaam": "target-a"})
    assert error is False, text
    assert "De herkomst is niet vastgelegd: de export in de exportmap is niet de export die deze scan verzamelde" in (
        text
    )
    records = provenance_dir_for(export) / "herkomst.jsonl"
    assert not records.exists() or _manifest_hash(export) not in records.read_text(encoding="utf-8")

    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


def test_status_ververs_without_a_provenance_map_says_the_provenance_was_not_recorded(tmp_path):
    server, _export = _scanning_server(tmp_path)
    error, text = _ask(server, "status_ververs", {"doelnaam": "target-a"})
    assert error is False, text
    assert "De herkomst is niet vastgelegd: deze server heeft geen herkomstmap" in text
    error, text = _ask(server, "status_overzicht", {"doel": "target-a"})
    assert error is True, text
    assert REFUSED in text


# --- the configuration chooses a map outside the export -----------------------


def _spy(monkeypatch) -> dict:
    import nsmcp.mcp_server as real

    seen: dict = {}

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real.build_server(*args, **kwargs)

    monkeypatch.setattr("nsmcp.start.build_server", spy)
    return seen


def test_without_onderhoud_the_provenance_map_lies_under_the_configuration_directory(tmp_path, monkeypatch):
    from nsmcp.start import build_server_from_config

    export = _export_of_b(tmp_path)
    config_dir = tmp_path / "beheer"
    config_dir.mkdir()
    config = config_dir / "config.json"
    config.write_text(
        json.dumps({"profiel": "dienst", "exportmap": str(export), "kennispad": str(_knowledge(tmp_path))}),
        encoding="utf-8",
    )
    seen = _spy(monkeypatch)
    build_server_from_config(config)
    assert seen["provenance_dir"] == config_dir.resolve() / "herkomst"


def _config_with_onderhoud(tmp_path: Path, export: Path, ledgermap: Path | None = None):
    """A configuration with `handelen` and `onderhoud`; `ledgermap` replaces
    the maintenance configuration's own ledger map."""
    from conftest import maintenance_config

    onderhoud = maintenance_config(tmp_path / "onderhoud")
    if ledgermap is not None:
        ledgermap.mkdir(parents=True, exist_ok=True)
        onderhoud = dataclasses.replace(onderhoud, ledgermap=ledgermap)
    onderhoud.runner.write_text("# ongebruikt", encoding="utf-8")
    onderhoud.firmwaremap.mkdir()
    (tmp_path / "scripts").mkdir()
    schrijf = tmp_path / "scripts" / "schrijf.ps1"
    schrijf.write_text("# ongebruikt", encoding="utf-8")
    (tmp_path / "kennis").mkdir()
    (tmp_path / "fixtures").mkdir()
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "profiel": "afgeschermd",
                "exportmap": str(export),
                "kennispad": str(_knowledge(tmp_path / "kennis")),
                "handelen": {
                    "schrijfscript": str(schrijf),
                    "fixturemap": str(tmp_path / "fixtures"),
                    "codekanaal": {"soort": "bestand", "pad": str(tmp_path / "codes" / "code.txt")},
                    "toegestaan": {},
                },
                "onderhoud": {
                    "runner": str(onderhoud.runner),
                    "ledgermap": str(onderhoud.ledgermap),
                    "firmwaremap": str(onderhoud.firmwaremap),
                    "soak_uren": 24,
                    "ssh_gebruiker": "nsroot",
                },
            }
        ),
        encoding="utf-8",
    )
    return config, onderhoud


def test_with_onderhoud_the_provenance_map_lies_in_the_ledger_map(tmp_path, monkeypatch):
    from nsmcp.start import build_server_from_config

    config, onderhoud = _config_with_onderhoud(tmp_path, _export_of_b(tmp_path))
    seen = _spy(monkeypatch)
    build_server_from_config(config)
    assert seen["provenance_dir"] == onderhoud.ledgermap / "herkomst"


# Measured: with the configuration file or the ledger map inside the export
# map, the provenance map lay inside it too, and a record supplied with the
# export answered a target-bound question as "verzameld door deze server".


def _refused_at_startup(config: Path) -> str:
    from nsmcp.start import ConfigError, build_server_from_config

    with pytest.raises(ConfigError) as refused:
        build_server_from_config(config)
    return str(refused.value)


def _service_config(config_dir: Path, export: Path, knowledge: Path) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    config = config_dir / "config.json"
    config.write_text(
        json.dumps({"profiel": "dienst", "exportmap": str(export), "kennispad": str(knowledge)}), encoding="utf-8"
    )
    return config


def test_a_configuration_file_inside_the_export_map_is_refused_at_startup(tmp_path):
    export = _export_of_b(tmp_path)
    message = _refused_at_startup(_service_config(export, export, _knowledge(tmp_path)))
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message
    assert repr(export / "herkomst") in message


def test_a_ledger_map_inside_the_export_map_is_refused_at_startup(tmp_path):
    export = _export_of_b(tmp_path)
    config, _onderhoud = _config_with_onderhoud(tmp_path, export, ledgermap=export / "ledger")
    message = _refused_at_startup(config)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


def test_an_export_map_inside_the_provenance_map_is_refused_at_startup(tmp_path):
    # Beside the export map lie the scan's work map, the previous export and
    # the lock; whoever replaces the export writes there too.
    export = tmp_path / "beheer" / "herkomst" / "export"
    shutil.copytree(PREFLIGHT_EXPORT, export)
    message = _refused_at_startup(_service_config(tmp_path / "beheer", export, _knowledge(tmp_path)))
    assert message.startswith("de exportmap mag niet in de herkomstmap staan"), message


def test_a_provenance_map_beside_the_export_map_is_accepted(tmp_path):
    from nsmcp.start import build_server_from_config

    export = tmp_path / "beheer" / "export"
    shutil.copytree(PREFLIGHT_EXPORT, export)
    assert build_server_from_config(_service_config(tmp_path / "beheer", export, _knowledge(tmp_path)))


# Measured: the same map inside the export map, written with the Windows
# extended prefix, was accepted as lying beside it - `Path.resolve()` keeps
# that spelling, so a comparison on resolved text alone saw two different
# drives. Every spelling of one location must get the same answer: a map
# inside the export map refused, a map beside it accepted.


def _provenance_refusal(provenance: Path, export: Path) -> str:
    from nsmcp.start import ConfigError, _check_provenance_dir

    with pytest.raises(ConfigError) as refused:
        _check_provenance_dir(provenance, export)
    return str(refused.value)


@pytest.mark.parametrize("exists", [False, True], ids=["nog-niet-aangemaakt", "bestaat"])
@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_a_provenance_map_inside_the_export_map_is_refused_in_every_spelling(tmp_path, monkeypatch, spelling, exists):
    export = tmp_path / "export"
    export.mkdir()
    (tmp_path / "elders").mkdir()
    provenance = export / "herkomst"
    if exists:
        provenance.mkdir()
    monkeypatch.chdir(tmp_path)
    message = _provenance_refusal(spelled(provenance, spelling), export)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_an_export_map_in_another_spelling_still_holds_the_provenance_map(tmp_path, monkeypatch, spelling):
    export = tmp_path / "export"
    export.mkdir()
    (tmp_path / "elders").mkdir()
    monkeypatch.chdir(tmp_path)
    message = _provenance_refusal(export / "herkomst", spelled(export, spelling))
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_an_export_map_inside_the_provenance_map_is_refused_in_every_spelling(tmp_path, monkeypatch, spelling):
    provenance = tmp_path / "herkomst"
    export = provenance / "export"
    export.mkdir(parents=True)
    (provenance / "elders").mkdir()
    monkeypatch.chdir(tmp_path)
    message = _provenance_refusal(provenance, spelled(export, spelling))
    assert message.startswith("de exportmap mag niet in de herkomstmap staan"), message


@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_a_provenance_map_beside_the_export_map_is_accepted_in_every_spelling(tmp_path, monkeypatch, spelling):
    from nsmcp.start import _check_provenance_dir

    export = tmp_path / "beheer" / "export"
    export.mkdir(parents=True)
    (tmp_path / "beheer" / "elders").mkdir()
    provenance = tmp_path / "beheer" / "herkomst"
    monkeypatch.chdir(tmp_path)
    _check_provenance_dir(spelled(provenance, spelling), export)
    _check_provenance_dir(provenance, spelled(export, spelling))


@pytest.mark.parametrize(
    ("given", "peeled"),
    [
        ("\\\\?\\C:\\export\\herkomst", "C:\\export\\herkomst"),
        ("\\\\.\\C:\\export\\herkomst", "C:\\export\\herkomst"),
        ("\\\\?\\UNC\\localhost\\C$\\export", "\\\\localhost\\C$\\export"),
        ("\\\\?\\unc\\localhost\\C$\\export", "\\\\localhost\\C$\\export"),
        # A bare drive after the prefix names the volume, not "the current
        # directory on that drive" a bare `C:` would read as.
        ("\\\\?\\C:", "C:\\"),
        # No drive or share to peel down to: left for the identity check.
        ("\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\export", None),
        ("C:\\export", None),
    ],
)
def test_the_extended_prefix_is_peeled_down_to_the_drive_or_share_it_names(given, peeled):
    from nsmcp.start import _without_extended_prefix

    assert _without_extended_prefix(given) == (given if peeled is None else peeled)


def test_a_provenance_map_reached_through_a_link_into_the_export_map_is_refused(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    link = tmp_path / "elders"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(export), str(link))
    else:
        link.symlink_to(export, target_is_directory=True)
    message = _provenance_refusal(link / "herkomst", export)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


# Measured: a map written through a link that lies IN the export map and
# points out of it was accepted - its resolved place lies outside - while the
# server uses the path as written. Whoever writes the export map can replace
# that link by a real directory after the start, and the provenance record
# then lies in the export map after all. The path as written counts too.


@pytest.mark.parametrize("below", ["uit", "uit/herkomst"])
@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_a_provenance_map_through_a_link_inside_the_export_map_is_refused(tmp_path, monkeypatch, spelling, below):
    export = tmp_path / "export"
    export.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    directory_link(export / "uit", outside)
    monkeypatch.chdir(tmp_path)
    provenance = export.joinpath(*below.split("/"))
    message = _provenance_refusal(spelled(provenance, spelling), export)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


@pytest.mark.parametrize("spelling", PATH_SPELLINGS)
def test_an_export_map_through_a_link_inside_the_provenance_map_is_refused(tmp_path, monkeypatch, spelling):
    provenance = tmp_path / "beheer" / "herkomst"
    provenance.mkdir(parents=True)
    outside = tmp_path / "buiten"
    (outside / "export").mkdir(parents=True)
    directory_link(provenance / "uit", outside)
    monkeypatch.chdir(tmp_path)
    message = _provenance_refusal(provenance, spelled(provenance / "uit" / "export", spelling))
    assert message.startswith("de exportmap mag niet in de herkomstmap staan"), message


def test_a_map_reached_through_a_link_that_lies_outside_both_maps_is_accepted(tmp_path):
    from nsmcp.start import _check_provenance_dir

    export = tmp_path / "export"
    export.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    directory_link(tmp_path / "naast", outside)
    _check_provenance_dir(tmp_path / "naast" / "herkomst", export)
    directory_link(tmp_path / "export-koppeling", export)
    _check_provenance_dir(tmp_path / "beheer" / "herkomst", tmp_path / "export-koppeling")


# A path the check cannot compare is no path shown to lie outside: the start
# stops, instead of the refusal moving to the first write.


def test_a_provenance_map_that_cannot_be_compared_is_refused(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    provenance = tmp_path / "her\x00komst"
    message = _provenance_refusal(provenance, export)
    assert message == f"kan niet vaststellen dat de herkomstmap buiten de exportmap ligt ({export!r}): {provenance!r}"
    assert "\x00" not in message


def test_an_export_map_that_cannot_be_compared_is_refused(tmp_path):
    export = tmp_path / "ex\x00port"
    message = _provenance_refusal(tmp_path / "herkomst", export)
    assert message.startswith("kan niet vaststellen dat de herkomstmap buiten de exportmap ligt"), message
    assert "\x00" not in message


def test_the_identity_check_alone_refuses_a_map_inside_and_accepts_one_beside(tmp_path, monkeypatch):
    # As for a spelling no text rule maps back, such as the administrative
    # share, which a machine without that share cannot write: the text
    # comparison is taken away and the identity of the directory decides.
    from nsmcp import start

    export = tmp_path / "beheer" / "export"
    export.mkdir(parents=True)
    beside = tmp_path / "beheer" / "herkomst"
    beside.mkdir()
    keys = itertools.count()
    monkeypatch.setattr(start, "_text_keys", lambda path: (f"<{next(keys)}>",))
    assert start._lies_within(export, export) is True
    assert start._lies_within(export / "herkomst", export) is True
    assert start._lies_within(beside, export) is False
    assert start._lies_within(export, beside) is False


def _without_file_numbers(real_stat):
    """`os.stat` as on a file system that reports no file number (0)."""

    def stat(path, *args, **kwargs):
        fields = list(real_stat(path, *args, **kwargs))
        fields[1] = 0
        return os.stat_result(fields)

    return stat


def test_without_file_numbers_a_map_beside_the_export_map_is_not_taken_for_one_inside(tmp_path, monkeypatch):
    # Some network file systems report no file number. Every directory on the
    # volume would then share one identity; the check keeps to the text
    # comparison instead of refusing every map.
    from nsmcp.start import _check_provenance_dir, _lies_within

    export = tmp_path / "beheer" / "export"
    export.mkdir(parents=True)
    beside = tmp_path / "beheer" / "herkomst"
    beside.mkdir()
    monkeypatch.setattr(os, "stat", _without_file_numbers(os.stat))
    assert os.stat(export).st_ino == 0
    _check_provenance_dir(beside, export)
    assert _lies_within(beside, export) is False
    assert _lies_within(export / "herkomst", export) is True


def test_without_file_numbers_a_map_through_a_link_inside_the_export_map_is_still_refused(tmp_path, monkeypatch):
    # With no identity to compare, the text of the path as written is what
    # still sees the link in the export map.
    export = tmp_path / "export"
    export.mkdir()
    outside = tmp_path / "buiten"
    outside.mkdir()
    directory_link(export / "uit", outside)
    monkeypatch.setattr(os, "stat", _without_file_numbers(os.stat))
    message = _provenance_refusal(export / "uit" / "herkomst", export)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


@pytest.mark.parametrize("spelling", ["uitgebreid", "unc-uitgebreid", "beheershare"])
def test_a_configuration_file_inside_the_export_map_is_refused_at_startup_in_another_spelling(tmp_path, spelling):
    # The configuration path is the command-line argument: without
    # `onderhoud` the provenance map lies beside it, in the spelling given.
    export = _export_of_b(tmp_path)
    config = _service_config(export, export, _knowledge(tmp_path))
    message = _refused_at_startup(spelled(config, spelling))
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


# --- the writing tools --------------------------------------------------------


def test_an_upgrade_phase_on_an_export_this_server_did_not_collect_is_refused(tmp_path):
    from upgrade_fase_harness import TARGET_NAME, _anchor_target, _argv_rows, _call, _server, _text

    server = _server(tmp_path, floor={})
    export = tmp_path / "export"
    manifest = json.loads((export / "export-manifest.json").read_text(encoding="utf-8"))
    manifest["collectedAtUtc"] = "2026-09-07T10:00:00.0000000Z"
    (export / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(export)
    _anchor_target(export, TARGET_NAME, record=False)
    r = _call(server, "onderhoud_upgrade_fase", {"fase": "R0", "snapshotverwijzing": "checkpoint-1"})
    assert r.isError, _text(r)
    assert REFUSED in _text(r)
    assert not server.code_spy.codes, "er is een code aangemaakt"
    assert not _argv_rows(server.onderhoud.ledgermap), "de faserunner is gestart"


def test_the_save_proposal_counts_no_drift_from_an_export_this_server_did_not_collect(tmp_path):
    # The shipped lab export names `lab` with a matching hash - and this
    # server holds no record of collecting it.
    from test_handelen_zonder_code import SaveScript, _save_server
    from upgrade_fase_harness import _call, _text

    from nsmcp.mcp_server import VERVANGEN_DOEL_EVIDENCE, forget_identities

    forget_identities()
    export = tmp_path / "export-kopie"
    shutil.copytree(FIXTURES / "lab-export-vpx-20260826", export)
    tekst = _text(_call(_save_server(tmp_path, SaveScript(), export_dir=export), "config_opslaan", {}))
    assert "alleen in running" not in tekst, tekst
    assert (
        "- drift: niet vastgesteld [niet vastgesteld]\n"
        f"    bewijs: {VERVANGEN_DOEL_EVIDENCE}\n"
        f"    reden: {REFUSED}; ververs eerst met status_ververs\n"
    ) in tekst, tekst


def test_the_replacement_proposal_names_no_use_from_an_export_this_server_did_not_collect(tmp_path):
    from test_cert_usage import _bind_target, _copy, _propose, _write_server

    export = _copy(tmp_path)
    _bind_target(export, "lab")  # the name and the hash, without this server's record
    server, _spy, _presenter = _write_server(tmp_path, export, target=None)
    text = _propose(server)
    assert "ook elders in gebruik" not in text, text
    assert "gebruik buiten de binding niet vastgesteld [niet vastgesteld]" in text
    assert f"reden: {REFUSED}" in text
