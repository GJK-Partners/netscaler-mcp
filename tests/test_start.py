"""The production entrance: ONE configuration file, loaded fail-closed,
profile enforcement, and the thin CLI layer around it.

The same disciplines as target.py: str(x) is a conversion, not a type gate;
every rejection gets its own, recognizable Dutch message; the forbidden-keys
sweep from target.py is reused (not rebuilt) over the WHOLE configuration
document, not only over a targets list.

The REAL stdio server is NEVER started here: it blocks and would hang a
test run. Almost every test below ends in an error path (exit code 1 or 2)
and therefore never reaches `server.run()` anyway. The valid path is the
exception (mutant-proven, see the docstring of `run()` in start.py): there
`monkeypatch` replaces `FastMCP.run` with a spy - still no real blocking
server, but measurably proving that `run()` is actually called.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
from pathlib import Path

import mcp.types as types
import pytest
from conftest import PATH_SPELLINGS, directory_link, expiry_text_today, seal_manifest, spelled
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp import backup, start
from nsmcp.disclosure import Disclosure
from nsmcp.mcp_server import build_server, forget_identities
from nsmcp.start import ConfigError, build_server_from_config, load_config, run


def _run_counter(monkeypatch):
    """Replaces FastMCP.run with a spy that RECORDS the transport argument.

    The older spy swallowed *a, **kw and proved only THAT run() was called -
    an edit to run("streamable-http") kept the suite green while the product
    would have opened a socket. Patches the CLASS, not an instance: the
    FastMCP object is only built during the test."""
    calls = []
    monkeypatch.setattr(FastMCP, "run", lambda self, *a, **kw: calls.append((self, a, kw)))
    return calls


CERT = "wildcard_gjk"
VSERVER = "LB_VS_PORTAAL"


def write(tmp_path: Path, content) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def base_config(tmp_path: Path, **overrides) -> dict:
    """A minimal valid service-profile document; overrides add/replace."""
    doc = {
        "profiel": "dienst",
        "exportmap": str(tmp_path / "export"),
        "kennispad": str(tmp_path / "kennis.json"),
    }
    doc.update(overrides)
    return doc


@pytest.mark.parametrize(
    "section,expected",
    [
        ({}, (True, 5, 2048)),
        ({"exports_per_doel": 3, "vrije_ruimte_vloer_mb": 500}, (True, 3, 500)),
        ({"exports_per_doel": 0}, (False, 0, 2048)),
    ],
)
def test_bewaren_policy_is_validated_and_forwarded(tmp_path, monkeypatch, section, expected):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)  # the release checks both paths before build_server()
    captured = {}
    monkeypatch.setattr(start, "build_server", lambda *a, **kw: captured.update(kw))
    build_server_from_config(write(tmp_path, base_config(tmp_path, bewaren=section)))
    policy = captured["retention"]
    assert (policy.enabled, policy.count, policy.floor_mb) == expected


@pytest.mark.parametrize(
    "section",
    [
        None,
        [],
        True,
        "yes",
        {"exports_per_doel": True},
        {"exports_per_doel": -1},
        {"exports_per_doel": "3"},
        {"vrije_ruimte_vloer_mb": False},
        {"vrije_ruimte_vloer_mb": -1},
        {"PRIVATE_FIELD": 1},
    ],
)
def test_bewaren_refuses_wrong_shapes_without_echoing_values(tmp_path, section):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)  # the release checks both paths before build_server()
    with pytest.raises(ConfigError, match="bewaren") as exc:
        build_server_from_config(write(tmp_path, base_config(tmp_path, bewaren=section)))
    assert "PRIVATE_FIELD" not in str(exc.value)


def test_bewaren_reaches_collect_through_status_refresh(tmp_path, monkeypatch):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)  # the release checks both paths before build_server()
    from nsmcp import mcp_server
    from nsmcp.retention import Retention
    from nsmcp.target import CertAgreement, Target

    captured = {}
    monkeypatch.setattr(
        mcp_server,
        "load_targets",
        lambda path: {
            "lab": Target(
                name="lab", address="192.0.2.1", credential_target="GJK/Test/retention", agreement=CertAgreement.CHAIN
            ),
        },
    )
    monkeypatch.setattr(mcp_server, "collect", lambda *a, **kw: captured.update(kw))
    policy = Retention(enabled=True, count=3, floor_mb=500)
    server = mcp_server.build_server(
        tmp_path / "export",
        tmp_path / "knowledge.json",
        targets_path=tmp_path / "targets.json",
        collect_script=tmp_path / "collector.ps1",
        retention=policy,
    )

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_ververs", {"doelnaam": "lab"})

    result = asyncio.run(scenario())
    assert result.isError is False
    assert captured["retention"] is policy


def _real_export(tmp_path: Path) -> Path:
    """An export with a REAL certificate and a REAL binding - see
    tests/test_no_network.py for the same construction and the reason for it
    (an empty directory proves nothing: all three tools fall back early
    there)."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir(parents=True)
    # FILE NAME/SHAPE: the REAL NSHC 1.0 collector writes
    # `objects/sslcertkey.json` (no "config_" prefix) and
    # `bindings/sslvserver_sslcertkey_binding.by-parent.json` in the
    # by-parent shape - see `tests/fixtures/lab-export-vpx-20260826/`.
    (export_dir / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": CERT, "daystoexpiration": 9, "status": "Valid"}]}),
        encoding="utf-8",
    )
    # De OBJECTBRON van de parents. De echte collector schrijft die altijd
    # (`config/sslvserver` in het manifest, `objects/sslvserver.json` op
    # schijf); zonder die bron is de parentlijst van het bindingsbestand niet
    # te kruiscontroleren en meldt de motor daar terecht een leesgat over.
    (export_dir / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": VSERVER}]}), encoding="utf-8"
    )
    raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [
                {
                    "parentName": VSERVER,
                    "outcome": "OK",
                    "data": {
                        "sslvserver_sslcertkey_binding": [
                            {"certkeyname": CERT, "vservername": VSERVER, "snicert": False, "ca": False}
                        ]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {
                    "config/sslcertkey": {"status": "OK"},
                    "config/sslvserver": {"status": "OK"},
                },
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        raw.encode("utf-8")
                    ).hexdigest()
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)
    return export_dir


def _real_knowledge(tmp_path: Path) -> Path:
    path = tmp_path / "kennis.json"
    path.write_text(json.dumps({"versie": "2026.08", "datum": "2026-08-16", "cve": []}), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Loading the configuration file - fail-closed, every rejection recognizable
# --------------------------------------------------------------------------


def test_missing_config_file_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="configuratiebestand niet gevonden"):
        load_config(tmp_path / "bestaat-niet.json")


def test_path_to_a_directory_gives_config_error_not_a_raw_traceback(tmp_path):
    """is_file() instead of exists() (exists() is also true for a
    directory) now catches a directory EARLY and explicitly, with its own
    message - instead of blowing up on IsADirectoryError only once
    read_text() starts on it."""
    with pytest.raises(ConfigError, match="configuratiebestand is een map"):
        load_config(tmp_path)


def test_broken_json_gives_a_clear_error(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ dit is geen json", encoding="utf-8")
    with pytest.raises(ConfigError, match="geen geldige JSON"):
        load_config(path)


def test_top_level_list_gives_config_error_not_a_raw_traceback(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(["profiel", "dienst"]), encoding="utf-8")
    with pytest.raises(ConfigError, match="moet een object zijn"):
        load_config(path)


def test_config_file_as_number_gives_config_error(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("5", encoding="utf-8")
    with pytest.raises(ConfigError, match="moet een object zijn"):
        load_config(path)


@pytest.mark.parametrize("field", ["profiel", "exportmap", "kennispad"])
def test_missing_required_field_is_refused(tmp_path, field):
    doc = base_config(tmp_path)
    del doc[field]
    path = write(tmp_path, doc)
    with pytest.raises(ConfigError, match=f"mist verplicht veld.*{field}"):
        load_config(path)


def test_unknown_field_is_refused(tmp_path):
    path = write(tmp_path, base_config(tmp_path, onzin="iets"))
    with pytest.raises(ConfigError, match="onbekend veld.*onzin"):
        load_config(path)


def test_a_password_in_the_configuration_is_refused(tmp_path):
    """Reuses target.py's _forbidden_keys sweep - only the Credential
    Manager target name belongs in configuration."""
    path = write(tmp_path, base_config(tmp_path, wachtwoord="hunter2"))
    with pytest.raises(ConfigError, match="geheim"):
        load_config(path)


def test_secret_one_level_deeper_is_also_detected(tmp_path):
    path = write(tmp_path, base_config(tmp_path, extra={"apiKey": "hunter2"}))
    with pytest.raises(ConfigError, match="geheim"):
        load_config(path)


def test_secret_is_named_by_key_but_the_value_is_never_echoed(tmp_path):
    """The error message may name the KEY (so the operator knows what to
    remove) but never the VALUE - that would leak the secret straight into
    a log or terminal."""
    path = write(tmp_path, base_config(tmp_path, apiKey="hunter2-geheime-waarde"))
    with pytest.raises(ConfigError, match="geheim") as info:
        load_config(path)
    assert "apiKey" in str(info.value)
    assert "hunter2-geheime-waarde" not in str(info.value)


def test_clientsecret_is_recognized_as_a_forbidden_key(tmp_path):
    path = write(tmp_path, base_config(tmp_path, clientSecret="x"))
    with pytest.raises(ConfigError, match="geheim"):
        load_config(path)


def test_a_valid_document_loads_without_error(tmp_path):
    path = write(tmp_path, base_config(tmp_path))
    raw = load_config(path)
    assert raw["profiel"] == "dienst"


def test_optional_fields_may_be_absent(tmp_path):
    path = write(tmp_path, base_config(tmp_path))
    raw = load_config(path)
    assert "doelen" not in raw
    assert "verzamelscript" not in raw


def test_typo_in_required_field_names_both_the_missing_and_the_unknown_field(tmp_path):
    """An operator who types 'profiel' as 'profil' used to see only
    'mist verplicht veld: profiel' - the typo itself ('profil') was named
    nowhere, so the operator had to guess what was wrong. Both fields in
    ONE message makes the typo immediately visible."""
    doc = base_config(tmp_path)
    doc["profil"] = doc.pop("profiel")
    path = write(tmp_path, doc)
    with pytest.raises(ConfigError) as info:
        load_config(path)
    message = str(info.value)
    assert "profiel" in message
    assert "profil" in message


def test_duplicate_key_at_the_top_level_is_refused(tmp_path):
    """json.loads() by default lets the LAST one win for a key occurring
    twice at the same level. A configuration with 'profiel' twice (first
    afgeschermd, then online) thereby silently loads as 'online' - the
    fail-closed structure check above never sees anything was wrong,
    because after json.loads() it only gets the winning document. Literal
    JSON text, because a Python dict cannot carry a duplicate key
    (json.dumps() cannot build this)."""
    path = tmp_path / "config.json"
    path.write_text(
        '{"profiel": "afgeschermd", "exportmap": "x", "kennispad": "y", "profiel": "online"}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="profiel.*dubbel"):
        load_config(path)


def test_duplicate_key_at_a_nested_level_is_also_refused(tmp_path):
    """json.loads() calls object_pairs_hook for EVERY object it
    encounters, regardless of nesting depth - this proves the hook also
    sees a duplicate BELOW the top level, not only on it. 'nest' is not an
    existing configuration field: if the hook missed nested duplicates,
    json.loads() would simply succeed and load_config() would instead
    report 'onbekend veld: nest' - a different signal, which this test
    thus sharply distinguishes from a correct fix."""
    path = tmp_path / "config.json"
    path.write_text(
        '{"profiel": "dienst", "exportmap": "x", "kennispad": "y", "nest": {"a": 1, "a": 2}}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="a.*dubbel"):
        load_config(path)


def test_optional_fields_may_be_present(tmp_path):
    path = write(
        tmp_path,
        base_config(
            tmp_path,
            profiel="afgeschermd",
            doelen=str(tmp_path / "doelen.json"),
            verzamelscript=str(tmp_path / "verzamel.ps1"),
        ),
    )
    raw = load_config(path)
    assert raw["doelen"] == str(tmp_path / "doelen.json")


def test_openheid_field_is_known_and_optional(tmp_path):
    """load_config() must not refuse 'openheid' as an unknown field -
    otherwise the config field is unusable before it ever reaches
    build_server_from_config()."""
    path = write(tmp_path, base_config(tmp_path, openheid="beperkt"))
    raw = load_config(path)
    assert raw["openheid"] == "beperkt"


# --------------------------------------------------------------------------
# Field validation - str(x) is a conversion, not a type gate (see target.py)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("value", [123, True, None, ["online"], {"x": 1}])
def test_profiel_field_with_wrong_type_is_refused(tmp_path, value):
    path = write(tmp_path, base_config(tmp_path, profiel=value))
    with pytest.raises(ConfigError, match="profiel moet tekst zijn"):
        build_server_from_config(path)


def test_empty_profiel_field_is_refused(tmp_path):
    path = write(tmp_path, base_config(tmp_path, profiel="   "))
    with pytest.raises(ConfigError, match="profiel mag niet leeg zijn"):
        build_server_from_config(path)


def test_unknown_profile_is_refused_and_does_not_fall_back(tmp_path):
    """load_profile (profile.py, UNCHANGED) is the source of truth - a
    typo in the profile field must never silently become a default profile.
    load_profile() itself throws a ValueError (its own, correct contract);
    build_server_from_config() converts it at the seam into ConfigError
    (message unchanged) so this function throws ONE error class for every
    rejection, not two - and run()'s except tuple no longer has to catch a
    bare ValueError that would otherwise also hide a real programming
    error."""
    path = write(tmp_path, base_config(tmp_path, profiel="productie"))
    with pytest.raises(ConfigError, match="onbekend profiel"):
        build_server_from_config(path)


@pytest.mark.parametrize("value", [123, True, None, ["x"]])
def test_exportmap_field_with_wrong_type_is_refused(tmp_path, value):
    path = write(tmp_path, base_config(tmp_path, exportmap=value))
    with pytest.raises(ConfigError, match="exportmap moet tekst zijn"):
        build_server_from_config(path)


@pytest.mark.parametrize("value", [123, True, None, ["x"]])
def test_kennispad_field_with_wrong_type_is_refused(tmp_path, value):
    path = write(tmp_path, base_config(tmp_path, kennispad=value))
    with pytest.raises(ConfigError, match="kennispad moet tekst zijn"):
        build_server_from_config(path)


@pytest.mark.parametrize("value", [123, True, None, ["x"]])
def test_doelen_field_with_wrong_type_is_refused(tmp_path, value):
    """None deliberately included: a present key with JSON null is
    different from an absent key (see target.py's
    test_credential_target_null_is_refused for the same discipline) and
    must be refused here too, not silently read as 'no targets'."""
    path = write(tmp_path, base_config(tmp_path, profiel="afgeschermd", doelen=value))
    with pytest.raises(ConfigError, match="doelen moet tekst zijn"):
        build_server_from_config(path)


@pytest.mark.parametrize("value", [123, True, None, ["x"]])
def test_verzamelscript_field_with_wrong_type_is_refused(tmp_path, value):
    path = write(tmp_path, base_config(tmp_path, profiel="afgeschermd", verzamelscript=value))
    with pytest.raises(ConfigError, match="verzamelscript moet tekst zijn"):
        build_server_from_config(path)


# --------------------------------------------------------------------------
# Profile enforcement (minimal, YAGNI)
# --------------------------------------------------------------------------


def test_service_profile_with_doelen_is_refused(tmp_path):
    """The service profile answers only on a supplied export - scanning is
    explicitly out of scope for this profile. Configuring `doelen` anyway is
    not a no-op, it is an operator who meant something this profile cannot
    deliver."""
    path = write(
        tmp_path,
        base_config(tmp_path, doelen=str(tmp_path / "doelen.json")),
    )
    with pytest.raises(ConfigError, match="alleen op een aangeleverde export"):
        build_server_from_config(path)


def test_service_profile_with_verzamelscript_is_refused(tmp_path):
    path = write(
        tmp_path,
        base_config(tmp_path, verzamelscript=str(tmp_path / "verzamel.ps1")),
    )
    with pytest.raises(ConfigError, match="alleen op een aangeleverde export"):
        build_server_from_config(path)


def test_service_profile_without_doelen_or_verzamelscript_builds_normally(tmp_path):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    path = write(tmp_path, base_config(tmp_path))
    server = build_server_from_config(path)
    assert {t.name for t in server._tool_manager.list_tools()} == {
        "certificaat_wat_verloopt_er",
        "certificaat_wat_breekt_er",
        "certificaat_wat_moet_ik_doen",
        "status_cve_controle",
        "dienst_status",
        "dienst_keten",
        "status_overzicht",
        "status_namen",
        "status_doelen",
        "status_gezondheid",
        "status_update_advies",
        "status_update_preflight",
        "kennis_uitleg",
        "rapport_dekking",
        "rapport_vergelijk",
        "rapport_wat_is_er_veranderd",
        "ha_stand",
        "config_drift",
        "beveiliging_verstopte_regels",
        "beveiliging_tls_baseline",
        "beveiliging_beheervlak",
        "beveiliging_headers",
        "beveiliging_scorekaart",
    }


@pytest.mark.parametrize("profile_name", ["afgeschermd", "online"])
def test_shielded_and_online_pass_doelen_and_verzamelscript_through(tmp_path, monkeypatch, profile_name):
    """SHIELDED and ONLINE differ today in nothing but what the
    configuration MAY contain (see the design, section "Drie profielen") -
    both simply pass doelen/verzamelscript through to build_server(). A spy
    on build_server proves that without having to run a real scan."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")

    seen = {}

    def spy(
        export_dir,
        knowledge_path,
        *,
        targets_path=None,
        collect_script=None,
        run=None,
        decide=None,
        disclosure=None,
        pseudonym_table_path=None,
        chapters=None,
        action_script=None,
        fixture_dir=None,
        code_presenter=None,
        allowlist=None,
        onderhoud=None,
        forbidden_addresses=(),
        knowledge_pin=None,
        provenance_dir=None,
    ):
        seen["targets_path"] = targets_path
        seen["collect_script"] = collect_script
        import nsmcp.mcp_server as real_module

        return real_module.build_server(
            export_dir,
            knowledge_path,
            targets_path=targets_path,
            collect_script=collect_script,
            run=run,
            decide=decide,
            disclosure=disclosure,
            pseudonym_table_path=pseudonym_table_path,
            chapters=chapters,
            action_script=action_script,
            fixture_dir=fixture_dir,
            code_presenter=code_presenter,
            allowlist=allowlist,
            onderhoud=onderhoud,
            forbidden_addresses=forbidden_addresses,
            knowledge_pin=knowledge_pin,
            provenance_dir=provenance_dir,
        )

    monkeypatch.setattr("nsmcp.start.build_server", spy)

    path = write(
        tmp_path,
        base_config(
            tmp_path,
            profiel=profile_name,
            doelen=str(targets_path),
            verzamelscript=str(script),
        ),
    )
    build_server_from_config(path)

    assert seen["targets_path"] == targets_path
    assert seen["collect_script"] == script


# --------------------------------------------------------------------------
# The openheid field: optional, defaults to volledig, refuses an unknown
# value fail-closed just like profiel - no silent fallback.
# --------------------------------------------------------------------------


def _spy_on_build_server(monkeypatch):
    """Replaces nsmcp.start.build_server with a spy that itself calls the
    REAL build_server (not a mock simulating something) - the same
    construction as the spy above, now also with
    disclosure/pseudonym_table_path so these tests prove what
    build_server_from_config() actually passes through."""
    seen: dict = {}

    def spy(
        export_dir,
        knowledge_path,
        *,
        targets_path=None,
        collect_script=None,
        run=None,
        decide=None,
        disclosure=None,
        pseudonym_table_path=None,
        chapters=None,
        action_script=None,
        fixture_dir=None,
        code_presenter=None,
        allowlist=None,
        onderhoud=None,
        forbidden_addresses=(),
        knowledge_pin=None,
        provenance_dir=None,
    ):
        seen["disclosure"] = disclosure
        seen["knowledge_pin"] = knowledge_pin
        seen["pseudonym_table_path"] = pseudonym_table_path
        seen["allowlist"] = allowlist
        seen["onderhoud"] = onderhoud
        seen["forbidden_addresses"] = forbidden_addresses
        import nsmcp.mcp_server as real_module

        return real_module.build_server(
            export_dir,
            knowledge_path,
            targets_path=targets_path,
            collect_script=collect_script,
            run=run,
            decide=decide,
            disclosure=disclosure,
            pseudonym_table_path=pseudonym_table_path,
            chapters=chapters,
            action_script=action_script,
            fixture_dir=fixture_dir,
            code_presenter=code_presenter,
            allowlist=allowlist,
            onderhoud=onderhoud,
            forbidden_addresses=forbidden_addresses,
            knowledge_pin=knowledge_pin,
            provenance_dir=provenance_dir,
        )

    monkeypatch.setattr("nsmcp.start.build_server", spy)
    return seen


def test_no_openheid_field_builds_with_default_volledig(tmp_path, monkeypatch):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    seen = _spy_on_build_server(monkeypatch)

    path = write(tmp_path, base_config(tmp_path))
    build_server_from_config(path)

    assert seen["disclosure"] is Disclosure.FULL


def test_openheid_beperkt_is_passed_to_build_server(tmp_path, monkeypatch):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    seen = _spy_on_build_server(monkeypatch)

    path = write(tmp_path, base_config(tmp_path, openheid="beperkt"))
    build_server_from_config(path)

    assert seen["disclosure"] is Disclosure.LIMITED


def test_the_kennispin_reaches_build_server_and_its_absence_is_none(tmp_path, monkeypatch):
    from nsmcp.knowledge import KnowledgePin

    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    seen = _spy_on_build_server(monkeypatch)

    build_server_from_config(write(tmp_path, base_config(tmp_path)))
    assert seen["knowledge_pin"] is None

    pin = {"versie": "2026.08", "digest": "AB" * 32}
    build_server_from_config(write(tmp_path, base_config(tmp_path, kennispin=pin)))
    assert seen["knowledge_pin"] == KnowledgePin(version="2026.08", digest="ab" * 32)


def test_unknown_openheid_is_refused_and_does_not_fall_back(tmp_path):
    """The same discipline as the unknown profile: a typo in the openheid
    field must never silently become a different setting."""
    path = write(tmp_path, base_config(tmp_path, openheid="open"))
    with pytest.raises(ConfigError, match="volledig"):
        build_server_from_config(path)


def test_main_with_unknown_openheid_prints_error_and_returns_exit_code_1(tmp_path, monkeypatch, capsys):
    path = write(tmp_path, base_config(tmp_path, openheid="open"))
    calls = _run_counter(monkeypatch)

    code = run([str(path)])

    assert code == 1
    assert calls == []
    out = capsys.readouterr()
    assert "volledig" in out.err


def test_shielded_with_only_doelen_is_refused_and_starts_nothing(tmp_path, monkeypatch, capsys):
    """With only 'doelen' present (and existing) the server used to build
    right through - four tools registered, run() reached run() and returned
    exit code 0, while scanning without a collect script is impossible.
    `doelen`/`verzamelscript` must be a pair for afgeschermd/online: both
    present, or both absent - never half. Also proves that run() is called
    ZERO times on this path."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path)),
    )
    calls = _run_counter(monkeypatch)

    code = run([str(path)])

    assert code == 1
    assert calls == []
    out = capsys.readouterr()
    assert "verzamelscript ontbreekt" in out.err


def test_shielded_with_only_verzamelscript_is_refused_and_starts_nothing(tmp_path, monkeypatch, capsys):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", verzamelscript=str(script)),
    )
    calls = _run_counter(monkeypatch)

    code = run([str(path)])

    assert code == 1
    assert calls == []
    out = capsys.readouterr()
    assert "doelen ontbreekt" in out.err


# --------------------------------------------------------------------------
# hoofdstukken/handelen: which chapters register their tools, and the
# writing tools' two prerequisite files (schrijfscript, fixturemap) - both
# fail-closed, just like every other configuration field above.
# --------------------------------------------------------------------------


def _config(tmp_path, **extra):
    # exist_ok=True: some tests (e.g. the handelen-validation scenarios)
    # call this helper more than once against the SAME tmp_path.
    export = tmp_path / "export"
    (export / "objects").mkdir(parents=True, exist_ok=True)
    (export / "bindings").mkdir(exist_ok=True)
    (export / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-09-01T10:00:00.0000000Z","resources":{},"files":{}}',
        encoding="utf-8",
    )
    kennis = tmp_path / "kennis.json"
    kennis.write_text('{"versie":"x","datum":"2026-09-01"}', encoding="utf-8")
    body = {"profiel": "dienst", "exportmap": str(export), "kennispad": str(kennis)}
    body.update(extra)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_hoofdstukken_limits_the_registered_tools(tmp_path):
    server = start.build_server_from_config(_config(tmp_path, hoofdstukken=["certificaat"]))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"certificaat_wat_verloopt_er", "certificaat_wat_breekt_er", "certificaat_wat_moet_ik_doen"}


def test_start_chapters_matches_the_build_server_chapters_default():
    """`start.CHAPTERS` is `mcp_server.DEFAULT_CHAPTERS`, imported rather
    than copied (see `start.py`'s own comment on `CHAPTERS`), so the two
    cannot drift apart today - but a future change that stops importing it
    and hand-maintains a separate list instead would reopen exactly that
    drift. Pinned here as a regression guard against that.

    MUTATIEPROEF: add a chapter to only one of the two and this test falls
    over with a set-equality diff naming the drifted chapter."""
    default_chapters = inspect.signature(build_server).parameters["chapters"].default
    assert start.CHAPTERS == default_chapters


def test_onderhoud_is_a_recognized_hoofdstuk(tmp_path):
    """`onderhoud` joins `start.CHAPTERS`. MUTATIEPROEF: drop it
    from that set and this test falls over with `ConfigError: onbekend
    hoofdstuk: onderhoud`.

    A later change updated the expectation: `onderhoud_upgrade_plan` is a
    READING tool and registers with the chapter alone, unlike
    `onderhoud_backup_maken` which additionally needs a `handelen` section
    (a later gate). No `handelen` section here, so exactly the one reading
    tool shows up - this still proves only that "onderhoud" itself is
    accepted as a chapter name, not rejected as unknown."""
    server = start.build_server_from_config(_config(tmp_path, hoofdstukken=["onderhoud"]))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == set(), "zonder onderhoud-config blijft het hoofdstuk ongepubliceerd"


# --------------------------------------------------------------------------
# The seven pinned onderhoud start errors
# plus the eighth, newly-pinned one (unknown field).
# Error 6 (the per-target hostkey check) already has its own dedicated test
# - tests/test_upgrade_fase.py::test_the_runner_refuses_an_unknown_host_key
# (MUTATIEPROEF 9) - so it is not repeated here.
# --------------------------------------------------------------------------


def _onderhoud(tmp_path, **overrides):
    runner = tmp_path / "runner.ps1"
    runner.write_text("# x", encoding="utf-8")
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir(exist_ok=True)
    firmwaremap = tmp_path / "firmware"
    firmwaremap.mkdir(exist_ok=True)
    body = {
        "runner": str(runner),
        "ledgermap": str(ledgermap),
        "firmwaremap": str(firmwaremap),
        "soak_uren": 24,
        "ssh_gebruiker": "nsroot",
    }
    body.update(overrides)
    return body


def test_onderhoud_missing_field_is_a_startup_error(tmp_path, capsys):
    """Startfout 1 (tabelrij 1)."""
    onderhoud = _onderhoud(tmp_path)
    del onderhoud["ssh_gebruiker"]
    del onderhoud["soak_uren"]
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onderhoud mist veld: soak_uren, ssh_gebruiker" in fout


def test_onderhoud_soak_uren_below_24_is_a_startup_error(tmp_path, capsys):
    """Startfout 2 (tabelrij 2)."""
    onderhoud = _onderhoud(tmp_path, soak_uren=23)
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onderhoud.soak_uren moet minimaal 24 zijn" in fout
    assert "juist de nacht is het venster" in fout


def test_onderhoud_runner_that_is_not_a_file_is_a_startup_error(tmp_path, capsys):
    """Startfout 3 (tabelrij 3)."""
    onderhoud = _onderhoud(tmp_path, runner=str(tmp_path / "bestaat-niet.ps1"))
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onderhoud.runner is geen bestand" in fout


def test_onderhoud_ledgermap_that_is_not_a_directory_is_a_startup_error(tmp_path, capsys):
    """Startfout 4 (tabelrij 4)."""
    onderhoud = _onderhoud(tmp_path, ledgermap=str(tmp_path / "bestaat-niet"))
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onderhoud.ledgermap is geen map" in fout


def test_onderhoud_without_handelen_is_a_startup_error(tmp_path, capsys):
    """Startfout 5 (tabelrij 5)."""
    onderhoud = _onderhoud(tmp_path)
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onderhoud vereist de sectie handelen" in fout
    assert "een fase is een schrijvende handeling" in fout


def test_onderhoud_without_any_target_allowed_builds_with_no_error_and_no_tool(tmp_path):
    """Startfout-tabelrij 7: geen doel dat onderhoud_upgrade_fase mag -> geen
    fout, de tool meldt zich alleen niet aan (profielregel, ontwerp 3.1)."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {}
    onderhoud = _onderhoud(tmp_path)
    server = start.build_server_from_config(_config(tmp_path, handelen=handelen, onderhoud=onderhoud))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "onderhoud_upgrade_fase" not in names


def test_onderhoud_unknown_field_is_a_startup_error(tmp_path, capsys):
    """Een achtste startfout, niet eerder gepind maar wel
    productoppervlak sinds het bestaat (`start.py:283`), en dus alsnog gepind."""
    onderhoud = _onderhoud(tmp_path, gateway="10.0.0.1")
    code = run([str(_config(tmp_path, onderhoud=onderhoud))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "onbekend veld in onderhoud: gateway" in fout


def test_onderhoud_actieregister_is_optional_and_reaches_maintenance_config(tmp_path, monkeypatch):
    """Het pad bereikt `MaintenanceConfig`
    ongewijzigd zodra het geconfigureerd is."""
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    pad = tmp_path / "actieregister.jsonl"
    onderhoud = _onderhoud(tmp_path, actieregister=str(pad))
    start.build_server_from_config(_config(tmp_path, handelen=handelen, onderhoud=onderhoud))
    assert seen["onderhoud"].actieregister == pad


def test_onderhoud_without_actieregister_defaults_to_none(tmp_path, monkeypatch):
    """De keerzijde: afwezig is geen startfout en degradeert eerlijk naar
    `None`, niet naar een verzonnen pad."""
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    onderhoud = _onderhoud(tmp_path)
    start.build_server_from_config(_config(tmp_path, handelen=handelen, onderhoud=onderhoud))
    assert seen["onderhoud"].actieregister is None


def test_handelen_verboden_adressen_is_optional_and_defaults_to_empty(tmp_path, monkeypatch):
    """Afwezig is geen startfout en degradeert eerlijk naar een lege tuple -
    de guard van de faserunner weigert dan alleen op naam
    (scripts/Invoke-GjkUpgradeFase.ps1)."""
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    assert seen["forbidden_addresses"] == ()


def test_handelen_verboden_adressen_reaches_build_server(tmp_path, monkeypatch):
    """De lijst bereikt build_server() ongewijzigd zodra ze geconfigureerd
    is - dezelfde discipline als onderhoud.actieregister hierboven."""
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    handelen["verboden_adressen"] = ["203.0.113.42", "lab-99"]
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    assert seen["forbidden_addresses"] == ("203.0.113.42", "lab-99")


def test_handelen_verboden_adressen_must_be_a_list(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["verboden_adressen"] = "203.0.113.42"
    code = run([str(_config(tmp_path, handelen=handelen))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "handelen.verboden_adressen moet een lijst teksten zijn" in fout


@pytest.mark.parametrize("element", ["", "   ", "adres met spatie", " lab-99", "lab-99 "])
def test_handelen_verboden_adressen_rejects_empty_or_whitespace_elements(tmp_path, capsys, element):
    handelen = _handelen(tmp_path)
    handelen["verboden_adressen"] = [element]
    code = run([str(_config(tmp_path, handelen=handelen))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "handelen.verboden_adressen" in fout
    assert "niet-lege tekst" in fout
    assert "witruimte" in fout


def test_handelen_verboden_adressen_rejects_non_string_elements(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["verboden_adressen"] = [123]
    code = run([str(_config(tmp_path, handelen=handelen))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "handelen.verboden_adressen" in fout


def test_unknown_hoofdstuk_is_refused(tmp_path):
    with pytest.raises(start.ConfigError, match="onbekend hoofdstuk"):
        start.build_server_from_config(_config(tmp_path, hoofdstukken=["certificaat", "gateway"]))


def test_hoofdstukken_must_be_a_list_of_text(tmp_path):
    with pytest.raises(start.ConfigError, match="hoofdstukken"):
        start.build_server_from_config(_config(tmp_path, hoofdstukken="certificaat"))


def test_handelen_requires_both_fields_as_existing_files_and_dir(tmp_path):
    with pytest.raises(start.ConfigError, match="schrijfscript"):
        start.build_server_from_config(
            _config(
                tmp_path, handelen={"fixturemap": str(tmp_path), "codekanaal": {"soort": "venster"}, "toegestaan": {}}
            )
        )
    script = tmp_path / "schrijf.ps1"
    script.write_text("# x", encoding="utf-8")
    with pytest.raises(start.ConfigError, match="fixturemap"):
        start.build_server_from_config(
            _config(
                tmp_path,
                handelen={
                    "schrijfscript": str(script),
                    "fixturemap": str(tmp_path / "bestaat-niet"),
                    "codekanaal": {"soort": "venster"},
                    "toegestaan": {},
                },
            )
        )
    with pytest.raises(start.ConfigError, match="onbekend veld in handelen"):
        start.build_server_from_config(
            _config(
                tmp_path,
                handelen={
                    "schrijfscript": str(script),
                    "fixturemap": str(tmp_path),
                    "codekanaal": {"soort": "venster"},
                    "toegestaan": {},
                    "poort": 1,
                },
            )
        )


def test_without_handelen_the_writing_tools_do_not_exist(tmp_path):
    server = start.build_server_from_config(_config(tmp_path))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert not any(
        n in names
        for n in (
            "certificaat_klaarzetten",
            "certificaat_vervangen",
            "dienst_lid_uitschakelen",
            "dienst_lid_inschakelen",
        )
    )


def test_with_handelen_the_writing_tools_exist(tmp_path):
    script = tmp_path / "schrijf.ps1"
    script.write_text("# x", encoding="utf-8")
    server = start.build_server_from_config(
        _config(
            tmp_path,
            handelen={
                "schrijfscript": str(script),
                "fixturemap": str(tmp_path),
                "codekanaal": {"soort": "venster"},
                "toegestaan": {},
            },
        )
    )
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {
        "certificaat_klaarzetten",
        "certificaat_vervangen",
        "dienst_lid_uitschakelen",
        "dienst_lid_inschakelen",
    } <= names


# --------------------------------------------------------------------------
# Existence of doelen/verzamelscript - a configured path that does not exist
# is not "no targets" (that is load_targets()'s contract for the
# UNconfigured case), it is an operator who meant something that is not
# there.
# --------------------------------------------------------------------------


def test_shielded_with_nonexistent_targets_file_is_refused(tmp_path):
    """Profile afgeschermd, doelen points to a path
    that does not exist. load_targets() returns {} for a missing file -
    correct when nobody configured targets, wrong when the operator
    explicitly put a path here. Without this check the server builds right
    through: four tools registered, status_ververs offered, while
    scanning is impossible. verzamelscript is REALLY present (existing) so
    this specifically hits the existence check of targets_path, not the
    pair check above."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen-bestaat-niet.json"
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )
    with pytest.raises(ConfigError, match="doelenbestand niet gevonden"):
        build_server_from_config(path)


def test_shielded_with_nonexistent_collect_script_is_refused(tmp_path):
    """verzamelscript points to a path that does not exist; doelen is
    REALLY present (existing) so this specifically hits the existence check
    of verzamelscript, not the pair check above."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    script = tmp_path / "verzamel-bestaat-niet.ps1"
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )
    with pytest.raises(ConfigError, match="verzamelscript niet gevonden"):
        build_server_from_config(path)


def test_shielded_with_targets_file_as_directory_is_refused(tmp_path):
    """exists() is also true for a directory. Without is_file() this spot
    simply accepted a directory as 'doelen' (it does exist, after all) -
    the error only came one step later, at load_targets() inside
    build_server(), as a less clear raw OSError."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen-map"
    targets_path.mkdir()
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )
    with pytest.raises(ConfigError, match="doelenbestand is een map"):
        build_server_from_config(path)


def test_shielded_with_collect_script_as_directory_is_refused(tmp_path):
    """A directory as collect
    script used to simply build four tools - scanning would only fail AT
    scan TIME (subprocess.Popen on a directory), far from where the
    operator can see the mistake."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    script = tmp_path / "verzamel-map"
    script.mkdir()
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )
    with pytest.raises(ConfigError, match="verzamelscript is een map"):
        build_server_from_config(path)


def test_main_with_nonexistent_targets_file_prints_error_and_returns_exit_code_1(tmp_path, capsys):
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen-bestaat-niet.json"
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )
    code = run([str(path)])
    assert code == 1
    out = capsys.readouterr()
    assert "doelenbestand niet gevonden" in out.err


# --------------------------------------------------------------------------
# run() - the thin CLI layer. Every test below ends in an error path (exit
# code 1 or 2) - the REAL, blocking stdio server (server.run()) is touched
# in NONE of these tests. The valid path (run() actually reached, through a
# spy replacing the real blocking call) stands apart, at the end of this
# block - see the docstring there.
# --------------------------------------------------------------------------


def test_main_without_arguments_prints_usage_and_returns_exit_code_2(capsys):
    code = run([])
    assert code == 2
    out = capsys.readouterr()
    assert "Gebruik" in out.err
    assert out.out == ""


def test_main_with_two_arguments_prints_usage_and_returns_exit_code_2(capsys):
    code = run(["a.json", "b.json"])
    assert code == 2
    out = capsys.readouterr()
    assert "Gebruik" in out.err


def test_main_with_help_flag_prints_usage_and_returns_exit_code_2(capsys):
    """--help must not be treated as a configuration path - otherwise
    load_config() reports 'configuratiebestand niet gevonden: --help',
    which only confuses the operator."""
    code = run(["--help"])
    assert code == 2
    out = capsys.readouterr()
    assert "Gebruik" in out.err
    assert out.out == ""


def test_main_with_short_help_flag_prints_usage_and_returns_exit_code_2(capsys):
    code = run(["-h"])
    assert code == 2
    out = capsys.readouterr()
    assert "Gebruik" in out.err


def test_main_with_missing_config_file_prints_error_and_returns_exit_code_1(tmp_path, capsys):
    code = run([str(tmp_path / "bestaat-niet.json")])
    assert code == 1
    out = capsys.readouterr()
    assert "niet gevonden" in out.err


def test_main_with_unknown_profile_prints_error_and_returns_exit_code_1(tmp_path, capsys):
    path = write(tmp_path, base_config(tmp_path, profiel="productie"))
    code = run([str(path)])
    assert code == 1
    out = capsys.readouterr()
    assert "onbekend profiel" in out.err


def test_main_with_service_plus_doelen_prints_error_and_returns_exit_code_1(tmp_path, capsys):
    path = write(tmp_path, base_config(tmp_path, doelen=str(tmp_path / "doelen.json")))
    code = run([str(path)])
    assert code == 1
    out = capsys.readouterr()
    assert "aangeleverde export" in out.err


def test_main_with_broken_targets_file_prints_error_and_returns_exit_code_1_no_traceback(tmp_path, capsys):
    """build_server() loads the targets file IMMEDIATELY when building the
    server (load_targets() in mcp_server.py), not only at the first tool
    call - so a broken targets file already fails here, with a TargetError
    (target.py) instead of a ConfigError or ValueError. Without TargetError
    in run()'s except tuple it escapes as a raw traceback on stderr instead
    of the tidy 'Fout: ...' line every other rejection gets here - exactly
    the "fix that leaves the same kind of gap one step further" this
    assignment warns about. verzamelscript is REALLY present (existing) so
    this specifically hits the targets-file parse error, not the pair
    check."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text("{ kapotte json", encoding="utf-8")
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    path = write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )

    code = run([str(path)])

    assert code == 1
    out = capsys.readouterr()
    assert out.err.startswith("Fout:")
    assert "Traceback" not in out.err
    assert "doelenbestand" in out.err


def test_main_with_valid_config_calls_run_exactly_once_and_returns_exit_code_0(tmp_path, monkeypatch):
    """Mutant-proven: a mutant replacing server.run() everywhere with None
    left all (then 57) start tests green - not a single test checked that
    run() actually makes the server run on a VALID configuration. Every
    test in this file until this one ended in an error path (exit code 1
    or 2).

    FastMCP.run is replaced here by a spy: no real blocking stdio server
    (that would hang the test run), but measurable WHETHER and how often
    run() was called. See the regression coverage for the RED proof with the
    re-inserted mutant against exactly this test."""
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    path = write(tmp_path, base_config(tmp_path))
    calls = _run_counter(monkeypatch)

    code = run([str(path)])

    assert code == 0
    assert len(calls) == 1


# --------------------------------------------------------------------------
# Integration: a real service configuration answers a real question through
# the existing in-memory session machinery (same pattern as
# tests/test_mcp_server.py and tests/test_no_network.py).
# --------------------------------------------------------------------------


def test_service_config_answers_certificaat_wat_verloopt_er_through_a_real_session(tmp_path):
    forget_identities()
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    path = write(tmp_path, base_config(tmp_path))
    server = build_server_from_config(path)

    import asyncio

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("certificaat_wat_verloopt_er", {"horizon_dagen": 90})

    result = asyncio.run(scenario())

    assert result.isError is False
    text = " ".join(b.text for b in result.content if hasattr(b, "text"))
    assert expiry_text_today(9, "2026-08-20") in text


def test_handelen_with_openheid_beperkt_starts_and_registers_the_writing_tools(tmp_path, monkeypatch):
    """C2 replaces the startup refusal this test used to pin.

    `handelen` combined with an openheid below 'volledig' used to be a
    ConfigError: the writing tools built their own text, never travelled
    through the disclosure seam, and their refusals named the whole
    allowlist. All three are repaired, so the combination now STARTS - and
    this measures what the operator configured actually arriving: the
    allowlist reaches build_server(), and the four writing tools are
    registered."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab": {"certificaat_klaarzetten": {"certnaam": ["cert-2027"]}}}
    seen = _spy_on_build_server(monkeypatch)
    server = start.build_server_from_config(_config(tmp_path, openheid="beperkt", handelen=handelen))
    assert seen["disclosure"] is Disclosure.LIMITED
    assert seen["allowlist"].targets() == ("lab",)
    assert seen["allowlist"].entry("lab", "certificaat_klaarzetten") == {"certnaam": ("cert-2027",)}
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


def test_handelen_with_openheid_minimaal_is_refused_at_startup(tmp_path):
    """The second level below 'volledig' is NOT like the first.

    'minimaal' renders an answer as counts, so a write proposal loses its
    VOORSTEL line, its arguments and the instruction line about the
    confirmation code - while a code is issued and shown to the
    administrator all the same. That is a two-step flow with an unreachable
    second step, so the combination is refused at startup instead of served
    broken. Measured on the REASON, not just on the type: an operator has to
    learn which level to pick instead."""
    handelen = _handelen(tmp_path)
    with pytest.raises(start.ConfigError) as info:
        start.build_server_from_config(_config(tmp_path, openheid="minimaal", handelen=handelen))
    melding = str(info.value)
    assert "minimaal" in melding
    assert "voorstel" in melding
    assert "beperkt" in melding and "volledig" in melding


def test_handelen_with_openheid_volledig_still_builds(tmp_path):
    """Counter-probe for the two above: the explicit 'volledig' setting keeps
    doing what it always did."""
    script = tmp_path / "schrijf.ps1"
    script.write_text("# x", encoding="utf-8")
    server = start.build_server_from_config(
        _config(
            tmp_path,
            openheid="volledig",
            handelen={
                "schrijfscript": str(script),
                "fixturemap": str(tmp_path),
                "codekanaal": {"soort": "venster"},
                "toegestaan": {},
            },
        )
    )
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


# --------------------------------------------------------------------------
# handelen.codekanaal: WHERE the confirmation code goes. Mandatory, because
# the code no longer travels in the tool result - a configuration that does
# not say where it goes is a configuration whose writing tools cannot work.
# --------------------------------------------------------------------------


_STANDAARD_KANAAL = object()


def _handelen(tmp_path, kanaal=_STANDAARD_KANAAL):
    # A sentinel, not None: JSON null IS a value a configuration can carry here
    # and these tests must be able to hand it over.
    script = tmp_path / "schrijf.ps1"
    script.write_text("# x", encoding="utf-8")
    return {
        "schrijfscript": str(script),
        "fixturemap": str(tmp_path),
        "codekanaal": {"soort": "venster"} if kanaal is _STANDAARD_KANAAL else kanaal,
        # Mandatory since 1.0. An empty object is the honest default here:
        # these tests are about the CHANNEL, not about what is allowed.
        "toegestaan": {},
    }


def _code_file(tmp_path):
    # NOT under tmp_path: that is the fixturemap in _config() above, and a
    # code file inside a directory the product itself reads is refused.
    return tmp_path.parent / "bevestigingscode.txt"


def _bestand(tmp_path, pad=None):
    return {"soort": "bestand", "pad": str(_code_file(tmp_path) if pad is None else pad)}


def test_handelen_without_codekanaal_is_refused_with_a_reason(tmp_path):
    section = _handelen(tmp_path)
    section.pop("codekanaal")
    with pytest.raises(start.ConfigError) as info:
        start.build_server_from_config(_config(tmp_path, handelen=section))
    melding = str(info.value)
    assert "codekanaal" in melding
    assert "venster" in melding and "bestand" in melding


def test_handelen_with_the_window_channel_builds_the_writing_tools(tmp_path):
    server = start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path)))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


def test_handelen_with_the_file_channel_builds_the_writing_tools(tmp_path):
    server = start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path))))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


def test_a_codekanaal_that_is_not_an_object_with_a_soort_is_refused(tmp_path):
    """The shape is deliberately ALWAYS an object with a soort - never a bare
    string - so a later kind (an approval through SSO/Entra, a push) fits next
    to today's two without a second configuration shape."""
    for kanaal in ("venster", "bestand", 3, [], None):
        with pytest.raises(start.ConfigError, match="codekanaal"):
            start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, kanaal)))
    with pytest.raises(start.ConfigError, match="soort"):
        start.build_server_from_config(
            _config(tmp_path, handelen=_handelen(tmp_path, {"pad": str(_code_file(tmp_path))}))
        )


def test_an_unknown_soort_names_the_kinds_this_version_has(tmp_path):
    with pytest.raises(start.ConfigError) as info:
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, {"soort": "push"})))
    # !r-quoted: `kind` is not yet checked for control
    # characters at this point (see the fix in _code_channel()), so an unknown
    # kind reads quoted. Separately, `sso` is now a real kind: the
    # unknown-kind example stays "push", and the allowed list gained sso.
    assert str(info.value) == "onbekende soort codekanaal: 'push'; toegestaan: venster, bestand, sso"


def test_the_file_kind_without_a_pad_is_refused(tmp_path):
    with pytest.raises(start.ConfigError, match="pad"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, {"soort": "bestand"})))


def test_an_unknown_field_inside_a_codekanaal_is_refused(tmp_path):
    for kanaal in (
        {"soort": "venster", "pad": str(_code_file(tmp_path))},
        {"soort": "bestand", "pad": str(_code_file(tmp_path)), "extra": 1},
    ):
        with pytest.raises(start.ConfigError, match="onbekend veld in handelen.codekanaal"):
            start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, kanaal)))


def test_a_pad_that_is_not_text_is_refused(tmp_path):
    with pytest.raises(start.ConfigError, match="codekanaal.pad"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, {"soort": "bestand", "pad": 3})))


def test_a_relative_code_file_path_is_refused(tmp_path):
    with pytest.raises(start.ConfigError, match="absoluut"):
        start.build_server_from_config(
            _config(tmp_path, handelen=_handelen(tmp_path, {"soort": "bestand", "pad": "bevestigingscode.txt"}))
        )


def test_a_code_file_inside_a_directory_the_product_reads_is_refused(tmp_path):
    """Exportmap, fixturemap and the directories of the knowledge/targets/
    collect files: the product reads those itself, and everything in them
    can end up in an answer. A confirmation code has no business there."""
    export = tmp_path / "export"
    for verboden in (export / "code.txt", tmp_path / "code.txt", tmp_path / "diep" / "code.txt"):
        with pytest.raises(start.ConfigError, match="die het product zelf"):
            start.build_server_from_config(
                _config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, verboden)))
            )


@pytest.mark.parametrize("spelling", [spelling for spelling in PATH_SPELLINGS if spelling != "relatief"])
def test_a_code_file_inside_a_directory_the_product_reads_is_refused_in_every_spelling(tmp_path, spelling):
    """Measured on the provenance map's check, which has the same form: the
    Windows extended spelling of a path inside the export map was taken for
    a path outside it, because `Path.resolve()` keeps that spelling. A
    relative path never reaches this check - it is refused as not absolute."""
    verboden = spelled(tmp_path / "export" / "code.txt", spelling)
    with pytest.raises(start.ConfigError, match="die het product zelf"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, verboden))))


@pytest.mark.parametrize("spelling", [spelling for spelling in PATH_SPELLINGS if spelling != "relatief"])
def test_a_code_file_through_a_link_inside_a_directory_the_product_reads_is_refused(tmp_path, spelling):
    """A link in the export map that points out of it: the resolved place
    of the code file lies outside, but the channel writes the path as
    configured, and whoever writes the export map can replace the link by a
    real directory after the start."""
    outside = tmp_path.parent / f"{tmp_path.name}-buiten"
    outside.mkdir()
    export = tmp_path / "export"
    export.mkdir()
    directory_link(export / "uit", outside)
    verboden = spelled(export / "uit" / "code.txt", spelling)
    with pytest.raises(start.ConfigError, match="die het product zelf") as refused:
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, verboden))))
    assert repr(export) in str(refused.value)


def test_a_code_file_path_that_cannot_be_compared_is_refused(tmp_path):
    """A path the check cannot compare - here one with a NUL character,
    which `Path.resolve()` refuses - is no path shown to lie outside: the
    start stops, instead of the refusal moving to the first write. Quoted
    like the other messages (operator text)."""
    code_file = tmp_path.parent / f"{tmp_path.name}-code\x00\nFout: niets aan de hand.txt"
    with pytest.raises(start.ConfigError) as refused:
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, code_file))))
    message = str(refused.value)
    assert message.startswith(
        "kan niet vaststellen dat handelen.codekanaal.pad buiten een map ligt die het product zelf leest of schrijft"
    ), message
    assert message.endswith(f": {code_file!r}"), message
    assert "\x00" not in message and "\n" not in message


@pytest.mark.parametrize("spelling", [spelling for spelling in PATH_SPELLINGS if spelling != "relatief"])
def test_a_code_file_beside_the_directories_the_product_reads_is_accepted_in_every_spelling(tmp_path, spelling):
    code_file = spelled(_code_file(tmp_path), spelling)
    assert start.build_server_from_config(
        _config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, code_file)))
    )


# The Windows spellings of an absolute path, and what the start check has to
# make of each. The last two look absolute to `os.path.isabs()` on Python
# 3.11 and 3.12 (a root without a drive, and a drive without a root), but
# both are resolved against the working directory or the current drive:
# the check refuses them, as it always has.
_PREFIXED_SPELLINGS = (
    r"\\?\C:\codes\code.txt",
    r"\\?\UNC\server\share\codes\code.txt",
    r"\\?\Volume{00000000-0000-0000-0000-000000000000}\codes\code.txt",
    r"\\.\C:\codes\code.txt",
)


@pytest.mark.skipif(os.name != "nt", reason="deze spellingen bestaan alleen op Windows")
@pytest.mark.parametrize(
    ("text", "absolute"),
    [
        (r"C:\codes\code.txt", True),
        (r"\\server\share\codes\code.txt", True),
        *((text, True) for text in _PREFIXED_SPELLINGS),
        ("code.txt", False),
        (r"codes\code.txt", False),
        (r"\codes\code.txt", False),
        ("C:code.txt", False),
    ],
)
def test_the_absolute_check_reads_every_windows_spelling(text, absolute):
    assert start._is_absolute_path(Path(text)) is absolute


@pytest.mark.skipif(os.name != "nt", reason="deze spellingen bestaan alleen op Windows")
def test_a_prefixed_path_is_absolute_whatever_pathlib_says(monkeypatch):
    """Measured on the CI runner with Python 3.11: pathlib there reads
    `\\\\?\\Volume{...}\\...` as not absolute, where 3.12 reads it as
    absolute. An extended or device prefix is never resolved against the
    working directory, so the prefix alone makes the path absolute - also
    when `Path.is_absolute()` answers False, as it does on 3.11."""
    monkeypatch.setattr(Path, "is_absolute", lambda self: False)
    for text in _PREFIXED_SPELLINGS:
        assert start._is_absolute_path(Path(text)) is True, text
    for text in ("code.txt", r"codes\code.txt", r"\codes\code.txt"):
        assert start._is_absolute_path(Path(text)) is False, text


def test_a_volume_guid_code_path_reaches_the_containment_check_whatever_pathlib_says(tmp_path, monkeypatch):
    """The CI runner with Python 3.11 refused the volume-GUID spelling of a
    code file as "moet een absoluut pad zijn", before the check whether it
    lies inside a directory the product reads: pathlib on 3.11 reads that
    spelling as not absolute. With `Path.is_absolute()` answering False, as
    there, a file inside the export map is still refused as lying inside it,
    and a file in a directory beside it is still accepted."""
    export = tmp_path / "export"
    export.mkdir()
    beside = tmp_path / "naast-de-export"
    beside.mkdir()
    inside = spelled(export / "code.txt", "volume-guid")
    outside = spelled(beside / "code.txt", "volume-guid")
    monkeypatch.setattr(Path, "is_absolute", lambda self: False)
    with pytest.raises(start.ConfigError, match="die het product zelf") as refused:
        start._check_code_path(inside, [export])
    assert repr(export) in str(refused.value)
    assert start._check_code_path(outside, [export]) == outside


def test_a_code_file_that_is_a_directory_is_refused(tmp_path):
    map_ = tmp_path.parent / "codemap"
    map_.mkdir(exist_ok=True)
    with pytest.raises(start.ConfigError, match="geen bestand"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _bestand(tmp_path, map_))))


def test_a_code_file_inside_the_write_scripts_own_directory_is_refused(tmp_path):
    """A later fix: `_check_code_path`'s docstring promises 'outside
    every directory the product itself reads or writes', but the write
    script's OWN directory was missing from `gelezen_mappen` - the product
    both reads that script (`_require_file` above) and writes into its
    directory (the fixtures the script itself produces there). `_handelen()`
    above nests the script INSIDE the fixturemap, so it never exercises this
    gap; a real deployment's configuration does not: `schrijfscript` lives
    under one `...\\film\\` directory and `fixturemap` under a wholly
    different tree (`a different fixture directory`). Measured before the fix:
    `pad` set to the write script itself built without error - so the first
    proposal would have overwritten the script.

    `script_dir` is deliberately OUTSIDE `tmp_path`: `_config()` puts
    `kennis.json` directly in `tmp_path`, which already makes `tmp_path`
    itself a forbidden directory - nesting the script under `tmp_path` would
    make this test pass for the wrong reason (via `kennispad`'s directory,
    not via the write script's). A sibling directory keeps the two apart,
    the way the real `film` and `routes` trees are apart."""
    script_dir = tmp_path.parent / f"{tmp_path.name}-film"
    script_dir.mkdir(exist_ok=True)
    script = script_dir / "Invoke-GjkLabWrite.ps1"
    script.write_text("# x", encoding="utf-8")
    fixture_dir = tmp_path / "gjk-demo-certs"
    fixture_dir.mkdir()
    handelen = {
        "schrijfscript": str(script),
        "fixturemap": str(fixture_dir),
        "codekanaal": {"soort": "bestand", "pad": str(script)},
        "toegestaan": {},
    }
    with pytest.raises(start.ConfigError, match="die het product zelf"):
        start.build_server_from_config(_config(tmp_path, handelen=handelen))

    # Not just that one filename - the whole directory is off limits, so a
    # different file next to the script is refused too.
    handelen["codekanaal"] = {"soort": "bestand", "pad": str(script_dir / "code.txt")}
    with pytest.raises(start.ConfigError, match="die het product zelf"):
        start.build_server_from_config(_config(tmp_path, handelen=handelen))


def test_the_real_demo_layout_is_still_accepted(tmp_path):
    """Counter-probe for the fix above: production nests `schrijfscript`
    under a `film` directory that sits NEXT TO (not inside) `fixturemap`,
    and puts the code file in a third, unrelated directory
    (a separate operator directory outside both). The fix must
    not reject that layout - only the script's own directory (and the other
    already-forbidden directories) are off limits for the code file."""
    script_dir = tmp_path.parent / f"{tmp_path.name}-film"
    script_dir.mkdir(exist_ok=True)
    script = script_dir / "Invoke-GjkLabWrite.ps1"
    script.write_text("# x", encoding="utf-8")
    fixture_dir = tmp_path / "gjk-demo-certs"
    fixture_dir.mkdir()
    code_file = tmp_path.parent / f"{tmp_path.name}-bevestigingscode.txt"
    handelen = {
        "schrijfscript": str(script),
        "fixturemap": str(fixture_dir),
        "codekanaal": {"soort": "bestand", "pad": str(code_file)},
        "toegestaan": {},
    }
    server = start.build_server_from_config(_config(tmp_path, handelen=handelen))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


# --------------------------------------------------------------------------
# handelen.codekanaal, soort sso: a separate presenter
# process that can also say WHO delivered the code. Three fields, none of
# them optional - pad (the presenter), autoriteit (the https approval
# authority) and wachttijd_s (how long the product waits on delivery).
# --------------------------------------------------------------------------


def _sso(tmp_path, pad=None, autoriteit="https://voorbeeld.invalid/goedkeuren", wachttijd_s=30):
    # NOT under tmp_path, for the same reason _code_file() isn't: a presenter
    # script inside a directory the product itself reads is refused. Named
    # with tmp_path.name, not the bare tmp_path.parent a prior version used:
    # tmp_path.parent alone is the
    # shared pytest run directory, not scoped to this test, and every test
    # using the default pad would otherwise write the SAME file. A real
    # file: the presenter path is now checked for existence - a
    # caller that passes its own `pad` is deliberately testing a path that
    # must be refused before existence is ever checked (wrong directory,
    # relative), so it is left exactly as given, not created here.
    if pad is None:
        presenter = tmp_path.parent / f"{tmp_path.name}-sso-presenter.py"
        presenter.write_text("import sys\nsys.stdin.readline()\nprint('{}')\n", encoding="utf-8")
    else:
        presenter = pad
    return {
        "soort": "sso",
        "pad": str(presenter),
        "autoriteit": autoriteit,
        "wachttijd_s": wachttijd_s,
    }


def test_handelen_with_the_sso_channel_builds_the_writing_tools(tmp_path):
    server = start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path))))
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert "certificaat_klaarzetten" in names


def test_the_sso_kind_missing_any_field_is_refused(tmp_path):
    for veld in ("pad", "autoriteit", "wachttijd_s"):
        kanaal = _sso(tmp_path)
        del kanaal[veld]
        with pytest.raises(
            start.ConfigError,
            match="codekanaal van soort sso mist het veld",
        ) as info:
            start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, kanaal)))
        assert veld in str(info.value)


def test_sso_autoriteit_must_be_an_https_url(tmp_path):
    with pytest.raises(start.ConfigError, match="https-url"):
        start.build_server_from_config(
            _config(
                tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path, autoriteit="http://voorbeeld.invalid/goedkeuren"))
            )
        )


def test_sso_wachttijd_s_must_be_a_positive_int(tmp_path):
    # True: bool is an int subclass in
    # Python, so a bare isinstance(x, int) check lets it through -
    # "wachttijd_s": true would silently become a one-second wait instead of
    # this configuration error.
    for slecht in (0, -1, "30", 30.0, True):
        with pytest.raises(start.ConfigError, match="positief geheel getal"):
            start.build_server_from_config(
                _config(tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path, wachttijd_s=slecht)))
            )


def test_an_unknown_field_inside_an_sso_codekanaal_is_refused(tmp_path):
    kanaal = _sso(tmp_path)
    kanaal["extra"] = 1
    with pytest.raises(start.ConfigError, match="onbekend veld in handelen.codekanaal"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, kanaal)))


def test_an_sso_presenter_path_inside_a_directory_the_product_reads_is_refused(tmp_path):
    """The same discipline as the file channel's own code path (`_check_code_
    path`, reused here, not rebuilt): the presenter script has no business
    inside a directory this product itself reads or writes."""
    export = tmp_path / "export"
    with pytest.raises(start.ConfigError, match="die het product zelf"):
        start.build_server_from_config(
            _config(tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path, pad=export / "presenter.py")))
        )


def test_an_sso_relative_presenter_path_is_refused(tmp_path):
    with pytest.raises(start.ConfigError, match="absoluut"):
        start.build_server_from_config(
            _config(tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path, pad="presenter.py")))
        )


def test_an_sso_presenter_path_that_does_not_exist_is_refused(tmp_path):
    """`_check_code_path` alone (built for
    the `bestand` kind's code FILE, which does not need to exist yet) let a
    typo in `pad` start the server happily - every write in that session
    then died at the channel, after the code was already issued and burnt.
    The presenter is an executable dependency like `schrijfscript` and
    `fixturemap`, both of which already refuse to start on a missing path."""
    missing = tmp_path.parent / f"{tmp_path.name}-does-not-exist.py"
    with pytest.raises(start.ConfigError, match="niet gevonden"):
        start.build_server_from_config(_config(tmp_path, handelen=_handelen(tmp_path, _sso(tmp_path, pad=missing))))


# --------------------------------------------------------------------------
# handelen.toegestaan: WHAT is allowed, per target per action. Mandatory
# since 1.0 - the allowlist used to be a module constant in handelen.py, and
# a list the caller can edit by editing the code is not a list. A missing
# key is a startup error and not a silent "nothing allowed": that would be a
# third, invisible state next to on and off.
# --------------------------------------------------------------------------


_DEMO_TOEGESTAAN = {
    "lab": {
        "certificaat_klaarzetten": {"certnaam": ["gjk-zaakportaal-2027"]},
        "onderhoud_backup_maken": True,
    }
}


def test_a_handelen_section_without_toegestaan_is_a_startup_error(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    del handelen["toegestaan"]
    code = run([str(_config(tmp_path, handelen=handelen))])
    assert code == 1
    fout = capsys.readouterr().err
    assert "handelen mist veld: toegestaan" in fout
    assert "de allowlist komt sinds 1.0 uit de configuratie" in fout


def test_an_empty_toegestaan_is_valid_and_means_nothing_is_allowed(tmp_path, monkeypatch):
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {}
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    assert seen["allowlist"].targets() == ()


def test_the_configured_allowlist_reaches_build_server(tmp_path, monkeypatch):
    """The counter-probe to the empty one above: without this a loader that
    always handed over an EMPTY allowlist would pass every test here."""
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = _DEMO_TOEGESTAAN
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    lijst = seen["allowlist"]
    assert lijst.targets() == ("lab",)
    assert lijst.entry("lab", "certificaat_klaarzetten") == {"certnaam": ("gjk-zaakportaal-2027",)}
    assert lijst.entry("lab", "onderhoud_backup_maken") is True


def test_a_denylisted_name_in_the_allowlist_is_refused_at_startup(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {
        "lab": {
            "certificaat_vervangen": {
                "dienst": ["lb_vs_demo"],
                "nieuwcert": ["ns-server-certificate"],
            }
        }
    }
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert "ns-server-certificate" in capsys.readouterr().err


def test_a_denylisted_value_with_an_embedded_newline_stays_one_line(tmp_path, capsys):
    """Hardening: `candidate` here is an allowlist
    VALUE straight from the operator's own configuration, echoed with plain
    quotes instead of `!r` before this fix. A value carrying a real newline
    (reachable through this DENIED_PREFIXES branch) then split the single
    `Fout: ...` line `run()` prints into two - and the second line could
    read as its own, forged `Fout:` line in the product's own output.
    `!r`-quoting escapes the newline instead of emitting it, so the output
    the operator sees stays on one line."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {
        "lab": {
            "certificaat_vervangen": {
                "dienst": ["lb_vs_demo"],
                "nieuwcert": ["nshttps-\nFout: niets aan de hand"],
            }
        }
    }
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    regels = fout.splitlines()
    assert len(regels) == 1, f"verwacht een enkele regel, kreeg: {regels!r}"
    assert regels[0].startswith("Fout:")
    assert "\\n" in regels[0]


# --------------------------------------------------------------------------
# The SAME class of bug as the denylist test right above,
# but at five more places in this file - an untrusted value (a JSON key or
# a configuration string) echoed unquoted inside an f-string that
# `run()` prints as a single 'Fout: ...' line. A value carrying a real
# newline then split that one line into two, and the second line reads as
# its own, forged 'Fout:' line (or worse, a forged reassurance) in the
# product's own output. Table-driven so all five (plus what the same sweep
# found alongside them - see the docstring below) share one assertion
# instead of five near-identical test bodies.
# --------------------------------------------------------------------------


def _config_with_unknown_toegestaan_argument(tmp_path):
    """`unknown_args` is `entry.keys()` - the argument NAMES an
    operator wrote under `handelen.toegestaan.<naam>.<tool>` - never checked
    for control characters before this point."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {
        "lab": {
            "certificaat_vervangen": {
                "dienst": ["lb_vs_demo"],
                "nieuwcert": ["ns-eigen-cert"],
                "extra\nFout: niets aan de hand": ["x"],
            }
        }
    }
    return _config(tmp_path, handelen=handelen)


def _config_with_unknown_hoofdstuk(tmp_path):
    """`unknown_chapters` comes from the operator's `hoofdstukken`
    list, stripped and lowered but NOT newline-checked - strip() only
    removes leading/trailing whitespace."""
    return _config(tmp_path, hoofdstukken=["gateway\nFout: niets aan de hand"])


def _config_with_unknown_top_level_field(tmp_path):
    """The standalone message: `unknown` is `raw.keys() - _ALLOWED_FIELDS`
    - a top-level JSON key the operator typed. All three required fields
    stay present, so this hits the standalone branch, not the combined one."""
    doc = base_config(tmp_path)
    doc["onzin\nFout: niets aan de hand"] = "x"
    return write(tmp_path, doc)


def _config_missing_and_unknown_top_level_field(tmp_path):
    """The COMBINED message ('mist verplicht veld ... en bevat
    onbekend veld ...') renders the SAME `unknown` set as the standalone
    message above, in
    its own f-string - a second rendering site for one variable, exactly
    like the codekanaal-soort case below. A missing required field plus an unknown one
    with an embedded newline reaches this branch instead of the standalone
    one."""
    doc = base_config(tmp_path)
    del doc["kennispad"]
    doc["onzin\nFout: niets aan de hand"] = "x"
    return write(tmp_path, doc)


def _config_with_unknown_handelen_field(tmp_path):
    """`unknown_action_fields` is `section.keys()` under `handelen` -
    again operator-typed JSON keys, not filtered for control characters."""
    handelen = _handelen(tmp_path)
    handelen["extra\nFout: niets aan de hand"] = 1
    return _config(tmp_path, handelen=handelen)


def _config_with_unknown_codekanaal_soort(tmp_path):
    """`kind` is `handelen.codekanaal.soort`, read by `_require_text`
    (strips only leading/trailing whitespace) and echoed before it is known
    to be one of `KINDS` - the exact point an arbitrary operator string is
    still in play."""
    handelen = _handelen(tmp_path, kanaal={"soort": "venster\nFout: niets aan de hand"})
    return _config(tmp_path, handelen=handelen)


def _config_with_unknown_codekanaal_field(tmp_path):
    """The same 'vorm' to look for - `unknown` here is `set(fields) - _CHANNEL_FIELDS[...]`, the
    field names under `handelen.codekanaal` next to `soort`."""
    handelen = _handelen(tmp_path, kanaal={"soort": "venster", "extra\nFout: niets aan de hand": "x"})
    return _config(tmp_path, handelen=handelen)


def _config_with_secret_key_carrying_a_newline(tmp_path):
    """Found by the same sweep, same 'vorm' as the four `unknown`
    sites above (a `', '.join(sorted(...))` over untrusted JSON keys) -
    `secrets` is `_forbidden_keys(raw)`, which keeps the ORIGINAL key text
    (`found.add(str(key))` in target.py), not a normalized/safe form."""
    doc = base_config(tmp_path)
    doc["wachtwoord\nFout: niets aan de hand"] = "hunter2"
    return write(tmp_path, doc)


# --------------------------------------------------------------------------
# `_require_file()`
# still interpolates `path` RAW in both its messages - reachable
# through THREE configuration fields (handelen.schrijfscript, doelen,
# verzamelscript) plus the CLI configuration path itself, all four
# funnelling through this ONE shared helper. The same sweep also re-walked
# every `ConfigError` site in the module and found two more of the
# identical shape: `_check_code_path()` (THREE messages, one function)
# and a `handelen.fixturemap` check that sits right next to the
# schrijfscript fix but never went through `_require_file()` at all.
# Every row below carries a real embedded newline in the field the comment
# names; every row must still print EXACTLY one 'Fout:' line.
# --------------------------------------------------------------------------


def _config_with_schrijfscript_that_does_not_exist(tmp_path):
    """`handelen.schrijfscript` goes through
    `_require_file()`, reachable end-to-end - a schrijfscript value that
    does not exist, carrying an embedded
    newline, hits the 'niet gevonden' branch."""
    handelen = _handelen(tmp_path)
    handelen["schrijfscript"] = str(tmp_path / "geen-schrijfscript.ps1") + "\nFout: niets aan de hand"
    return _config(tmp_path, handelen=handelen)


def _config_with_fixturemap_that_is_not_a_directory(tmp_path):
    """One more `_require_file()`-shaped site - `handelen.fixturemap` is checked directly against
    `is_dir()`, right next to the schrijfscript check above, with the
    identical unguarded `{fixture_dir}` interpolation. A nonexistent
    fixturemap carrying an embedded newline hits 'handelen.fixturemap is
    geen map: ...' the same way."""
    handelen = _handelen(tmp_path)
    handelen["fixturemap"] = str(tmp_path / "geen-map") + "\nFout: niets aan de hand"
    return _config(tmp_path, handelen=handelen)


def _config_with_targets_path_that_does_not_exist(tmp_path):
    """`doelen` reaches `_require_file()` as
    'doelenbestand', but only once its pairing with `verzamelscript` is
    satisfied - so verzamelscript here is a REAL, existing script, and only
    `doelen` carries the embedded newline."""
    script = tmp_path / "verzamel.ps1"
    script.write_text("# x", encoding="utf-8")
    doc = base_config(
        tmp_path,
        profiel="afgeschermd",
        doelen=str(tmp_path / "doelen-bestaat-niet.json") + "\nFout: niets aan de hand",
        verzamelscript=str(script),
    )
    return write(tmp_path, doc)


def _config_with_collect_script_that_does_not_exist(tmp_path):
    """Symmetric to the case above - `doelen` here is
    REAL and existing, so the pairing check passes and only `verzamelscript`
    carries the embedded newline, reaching its own `_require_file()` call."""
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": []}), encoding="utf-8")
    doc = base_config(
        tmp_path,
        profiel="afgeschermd",
        doelen=str(targets_path),
        verzamelscript=str(tmp_path / "verzamel-bestaat-niet.ps1") + "\nFout: niets aan de hand",
    )
    return write(tmp_path, doc)


def _cli_configpad_that_does_not_exist(tmp_path):
    """The FOURTH call site - `configuratiebestand`
    itself, checked before the JSON is even read. No config file is written
    here on purpose: the CLI argument IS the untrusted value, and it never
    needs to exist on disk to reach the 'niet gevonden' branch."""
    return tmp_path / "config-bestaat-niet.json\nFout: niets aan de hand"


def _config_with_relative_codekanaal_pad(tmp_path):
    """`_check_code_path()`'s reproduction -
    `handelen.codekanaal.pad` is not absolute, and the embedded newline
    survives into the 'moet een absoluut pad zijn' message before the path
    is normalized or checked any further."""
    handelen = _handelen(tmp_path, kanaal={"soort": "bestand", "pad": "relatief\nFout: niets aan de hand"})
    return _config(tmp_path, handelen=handelen)


def _config_with_codekanaal_pad_inside_a_forbidden_directory(tmp_path):
    """`_check_code_path()`: the third message in the same function,
    reached once `pad` IS absolute and not a directory but resolves inside
    one of the directories the product itself reads or writes - here the
    fixturemap, which `_handelen()` sets to `tmp_path` itself. Proves the
    fix on this branch too, not only the 'niet absoluut' branch above."""
    handelen = _handelen(
        tmp_path,
        kanaal={
            "soort": "bestand",
            "pad": str(tmp_path / "onder-fixturemap") + "\nFout: niets aan de hand",
        },
    )
    return _config(tmp_path, handelen=handelen)


@pytest.mark.parametrize(
    "row_id, build_config",
    [
        ("r307-onbekend-argument-in-toegestaan", _config_with_unknown_toegestaan_argument),
        ("r419-onbekend-hoofdstuk", _config_with_unknown_hoofdstuk),
        ("r138-onbekend-veld-configuratie-los", _config_with_unknown_top_level_field),
        ("r133-onbekend-veld-configuratie-gecombineerd", _config_missing_and_unknown_top_level_field),
        ("r475-onbekend-veld-in-handelen", _config_with_unknown_handelen_field),
        ("r180-onbekende-soort-codekanaal", _config_with_unknown_codekanaal_soort),
        ("r196-onbekend-veld-in-codekanaal", _config_with_unknown_codekanaal_field),
        ("r120-geheim-sleutel-met-regeleinde", _config_with_secret_key_carrying_a_newline),
        ("r91-schrijfscript-niet-gevonden", _config_with_schrijfscript_that_does_not_exist),
        ("r554-fixturemap-geen-map", _config_with_fixturemap_that_is_not_a_directory),
        ("r602-doelenbestand-niet-gevonden", _config_with_targets_path_that_does_not_exist),
        ("r604-verzamelscript-niet-gevonden", _config_with_collect_script_that_does_not_exist),
        ("r102-cli-configpad-niet-gevonden", _cli_configpad_that_does_not_exist),
        ("r399-codekanaal-pad-niet-absoluut", _config_with_relative_codekanaal_pad),
        ("r408-codekanaal-pad-buiten-toegestane-map", _config_with_codekanaal_pad_inside_a_forbidden_directory),
    ],
)
def test_all_reachable_line_forgeries_stay_one_line(tmp_path, capsys, row_id, build_config):
    """The reachable places `start.py`
    echoed an untrusted value unquoted, PLUS three more the same sweep found
    sharing the identical form (a `', '.join(sorted(...))` - or, for the
    codekanaal-soort case, a bare interpolation - over JSON keys or a
    configuration string never checked for control characters), PLUS the
    SEVEN more a follow-up sweep found: `_require_file()` (four call sites:
    handelen.schrijfscript/doelen/verzamelscript plus the CLI configuration
    path itself), `_check_code_path()` (three messages in one
    function), and `handelen.fixturemap`'s own unguarded check,
    which shares `_require_file()`'s exact shape but never called it. Every
    row's value carries a real embedded newline; every row must still print
    EXACTLY one 'Fout:' line - not two, and not a second line that could
    pass as its own message.

    Two places are not rows here on
    purpose: the `UnknownKind` backstop in `_code_channel()` and
    its `MissingField` neighbour render the SAME `kind`
    variable as the codekanaal-soort case above - but by the time either is reached, `kind` has
    already passed `if kind not in KINDS`, so it can only hold one of the
    fixed, safe strings in `KINDS` itself, exactly like `naam` further down
    this file once `valid_target_name()` has passed it. Both are left BARE
    in the fix, deliberately, matching that same codebase convention (quote
    only what is still untrusted AT THAT POINT) - neither is independently
    reachable with an attacker-chosen newline, so inventing a config that
    reaches them with unsafe text would not be honest and no row claims to
    RED-prove them.
    """
    path = build_config(tmp_path)
    exit_code = run([str(path)])
    assert exit_code == 1, f"{row_id}: verwachtte exitcode 1"
    fout = capsys.readouterr().err
    regels = fout.splitlines()
    assert len(regels) == 1, f"{row_id}: verwacht een enkele regel, kreeg: {regels!r}"
    assert regels[0].startswith("Fout:"), f"{row_id}: {regels[0]!r}"
    # Escaped, not emitted: the embedded newline must survive as the two
    # characters backslash-n inside the one line, exactly like
    # test_a_denylisted_value_with_an_embedded_newline_stays_one_line above -
    # NOT as a real line break (which len(regels) == 1 already rules out).
    assert "\\n" in regels[0], f"{row_id}: {regels[0]!r}"


def test_the_objectless_form_is_refused_for_a_tool_that_names_its_object(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab": {"certificaat_klaarzetten": True}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert "vormt zijn object niet zelf" in capsys.readouterr().err


def test_an_unknown_tool_name_in_the_allowlist_is_refused_at_startup(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab": {"status_overzicht": True}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert "status_overzicht" in capsys.readouterr().err


def test_an_object_entry_that_misses_an_argument_is_refused_at_startup(tmp_path, capsys):
    """An entry that names `dienst` but not `nieuwcert` starts cleanly and
    then refuses EVERY call at proposal time, with an allowed-values list
    that is empty - exactly the mid-proposal debugging this function exists
    to prevent. So it is a startup error: an object-form entry carries the
    whole argument set of its tool, or it carries nothing anyone can use.
    """
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab": {"certificaat_vervangen": {"dienst": ["lb_vs_demo"]}}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert "nieuwcert" in fout
    assert "certificaat_vervangen" in fout


def test_an_empty_list_per_argument_is_still_accepted_at_startup(tmp_path, monkeypatch):
    """The counter-probe to the test above, and a design decision, not an
    oversight: absent, false and an EMPTY LIST all mean "not allowed"
    (`Allowlist` docstring). An operator who removes the last value must not
    be forced to remove the key as well - that is how a wildcard gets
    written by accident. Present-but-empty stays valid.
    """
    seen = _spy_on_build_server(monkeypatch)
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab": {"certificaat_vervangen": {"dienst": [], "nieuwcert": []}}}
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    assert seen["allowlist"].entry("lab", "certificaat_vervangen") == {
        "dienst": (),
        "nieuwcert": (),
    }


def test_two_target_names_that_normalize_to_one_are_refused_at_startup(tmp_path, capsys):
    """Target names go through `_require_text`, which strips. So "lab" and
    " lab" in one `toegestaan` object become the same key and the second
    section silently overwrites the first - a whole allowlist section gone
    without a word. JSON itself only refuses LITERALLY duplicate keys.
    """
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {
        "lab": {"onderhoud_backup_maken": True},
        " lab": {"certificaat_klaarzetten": {"certnaam": ["gjk-zaakportaal-2027"]}},
    }
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert "lab" in fout
    assert "twee keer" in fout


# --------------------------------------------------------------------------
# handelen.toegestaan doelnamen: the SAME grammar backup_name() uses.
# Before this fix, _allowlist() accepted any
# non-empty stripped string as a target name - "lab noord" and "../x" both
# passed - and backup_name() then refused exactly those with a ValueError
# that _act() does not catch, so the server STARTED fine and every backup
# proposal on that target ended in the masked "Onverwachte fout ...". The
# grammar is therefore imported here from nsmcp.backup (the single source of
# truth), so the two checks can never drift apart again.
# --------------------------------------------------------------------------


def test_a_target_name_with_a_space_is_refused_at_startup(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab noord": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert fout.startswith("Fout:")
    assert "lab noord" in fout
    assert "[A-Za-z0-9._-]" in fout


def test_a_target_name_that_looks_like_a_path_escape_is_refused_at_startup(tmp_path, capsys):
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"../x": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert capsys.readouterr().err.startswith("Fout:")


def test_a_bare_double_dot_target_name_is_refused_at_startup(tmp_path, capsys):
    """ ".." alone passes the character-class regex (both characters are
    dots) - the shared predicate (`nsmcp.backup.valid_target_name`)
    additionally excludes this one reserved value, so both call sites
    refuse it identically."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"..": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert capsys.readouterr().err.startswith("Fout:")


def test_a_bare_single_dot_target_name_is_refused_at_startup(tmp_path, capsys):
    """ "." is equally "a path instruction" as ".." -
    the rationale the shared predicate already uses to refuse ".." - so it
    is refused the same way, at the same seam."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {".": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert capsys.readouterr().err.startswith("Fout:")


def test_an_empty_target_name_is_refused_by_require_text(tmp_path, capsys):
    """Caught by `_require_text` (non-empty check), not by the new grammar
    check below it - pinned here so a future change cannot silently move
    this refusal to the wrong check without a test noticing."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert fout.startswith("Fout:")
    assert "mag niet leeg zijn" in fout


def test_a_whitespace_only_target_name_is_refused_by_require_text(tmp_path, capsys):
    """Same check as the empty-name case above: `_require_text` strips
    before checking, so a whitespace-only name is caught there too, not by
    the new grammar check."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"   ": {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert fout.startswith("Fout:")
    assert "mag niet leeg zijn" in fout


def test_a_non_ascii_target_name_is_refused_at_startup(tmp_path, capsys):
    # \u00e9 escapes (not typed literally): keeps this SOURCE FILE
    # pure ASCII while the constructed target name still carries real
    # non-ASCII characters ("lab-een" with two accented e's) at runtime.
    naam = "lab-\u00e9\u00e9n"
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {naam: {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    assert capsys.readouterr().err.startswith("Fout:")


def test_an_80_character_target_name_of_only_allowed_characters_is_refused_at_startup(
    tmp_path,
    capsys,
):
    """REVERSED: the ORIGINAL version of this
    test decided, deliberately, to accept an 80-character target because it
    read `handelen._NAME`'s 63-character cap as "a DIFFERENT grammar" - not
    a precedent for doelnaam - while, two lines above that same decision,
    citing THAT exact grammar as the model for the CHARACTER CLASS. It
    cannot be the precedent for one and not the other: an 80-character
    doelnaam forms a 111-character appliance object name
    (`gjk_preupgrade_<80 chars>_<15-char stamp>`), which `handelen._NAME`
    itself would refuse if it ever had to validate that name - so the risk
    the original decision accepted was a write that either the write
    script or the appliance truncates or rejects, discovered only at
    `readback_ok()`, AFTER the backup was actually written. Refused here,
    at startup, instead."""
    naam = "a" * 80
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {naam: {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert fout.startswith("Fout:")
    assert "32" in fout


def test_a_target_name_at_exactly_the_length_budget_is_accepted_at_startup(tmp_path, monkeypatch):
    """The budget itself (`backup.MAX_TARGET_LENGTH`, 32 today, derived from
    `handelen._NAME`'s 63-character ceiling) - not retyped as a literal
    here, so a future change to the fixed prefix or stamp width moves this
    test's expectation with it."""
    naam = "a" * backup.MAX_TARGET_LENGTH
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {naam: {}}
    seen = _spy_on_build_server(monkeypatch)
    start.build_server_from_config(_config(tmp_path, handelen=handelen))
    assert seen["allowlist"].targets() == (naam,)


def test_a_target_name_one_character_over_the_length_budget_is_refused_at_startup(
    tmp_path,
    capsys,
):
    naam = "a" * (backup.MAX_TARGET_LENGTH + 1)
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {naam: {}}
    assert run([str(_config(tmp_path, handelen=handelen))]) == 1
    fout = capsys.readouterr().err
    assert fout.startswith("Fout:")
    assert repr(naam) in fout


def test_a_target_name_with_a_space_no_longer_starts_a_server_that_masks_the_backup_call(tmp_path):
    """The OLD behaviour: this exact configuration
    used to build and start a server without complaint, and only the FIRST
    backup proposal on "lab noord" then failed, uncaught, as the generic
    "Onverwachte fout ... De details zijn niet bewaard" - an opaque failure
    at call time with no way for the operator to see why, and
    `_allowlist()`'s own docstring already promised the opposite ("Strict
    at STARTUP on purpose"). Pinning that the configuration itself is now
    refused AT STARTUP is the proof that scenario can no longer happen: a
    server that never starts can never mask a backup call."""
    handelen = _handelen(tmp_path)
    handelen["toegestaan"] = {"lab noord": {"onderhoud_backup_maken": True}}
    with pytest.raises(start.ConfigError):
        start.build_server_from_config(_config(tmp_path, handelen=handelen))


def test_an_empty_chapter_list_is_a_startup_error(tmp_path):
    """SECURITY 20. `hoofdstukken: []` built a server with zero tools,
    silently, exit code 0. An operator who writes that meant something by it;
    a server that answers nothing is not that."""
    with pytest.raises(start.ConfigError, match="hoofdstukken mag niet leeg zijn"):
        start.build_server_from_config(_config(tmp_path, hoofdstukken=[]))


def test_a_nonexistent_export_directory_is_a_start_error(tmp_path):
    """The README promises a Dutch `Fout: ...` line and exit code 1 for a bad
    configuration; measured, a configuration with a nonexistent exportmap and
    kennispad simply started. Fail-closed is this product's core claim, so the
    promise is kept rather than the sentence weakened."""
    kennis = tmp_path / "kennis.json"
    kennis.write_text(json.dumps({"versie": "x", "datum": "2026-09-01", "cve": []}), encoding="utf-8")
    path = write(tmp_path, base_config(tmp_path, kennispad=str(kennis)))
    with pytest.raises(ConfigError, match="exportmap niet gevonden"):
        build_server_from_config(path)


def test_a_nonexistent_knowledge_path_is_a_start_error(tmp_path):
    (tmp_path / "export").mkdir()
    path = write(tmp_path, base_config(tmp_path))
    with pytest.raises(ConfigError, match="kennispad niet gevonden"):
        build_server_from_config(path)


def test_an_export_path_that_is_a_file_reports_the_right_reason(tmp_path):
    """A path that EXISTS but is a FILE (an operator pointing at
    export-manifest.json or at a zip) fell into the "niet gevonden" branch
    below and was told a wrong reason - the path is right there, just the
    wrong kind. Same discipline as handelen.fixturemap's "is geen map" and
    _require_file's "is een map, geen bestand" (see their docstrings): say
    what the path actually is, not that it is missing."""
    kennis = tmp_path / "kennis.json"
    kennis.write_text(json.dumps({"versie": "x", "datum": "2026-09-01", "cve": []}), encoding="utf-8")
    export_file = tmp_path / "export"
    export_file.write_text("{}", encoding="utf-8")
    path = write(tmp_path, base_config(tmp_path, kennispad=str(kennis)))
    with pytest.raises(ConfigError, match="exportmap is geen map"):
        build_server_from_config(path)


def test_a_knowledge_path_that_is_a_directory_is_a_start_error(tmp_path):
    """Coverage for the other type confusion introduced by this check:
    _require_file()'s existing is_dir() branch already answers this
    correctly (start.py) - no product change, just pinning it."""
    (tmp_path / "export").mkdir()
    (tmp_path / "kennis.json").mkdir()
    path = write(tmp_path, base_config(tmp_path))
    with pytest.raises(ConfigError, match="kennispad is een map, geen bestand"):
        build_server_from_config(path)


def test_a_bad_configuration_really_prints_fout_and_exits_with_one(tmp_path, capsys, monkeypatch):
    """The bare `Fout: ` prefix pinned nothing about WHICH check fired: with
    only the knowledge-path check surviving a regression, this test would
    still pass by tripping over kennispad instead of exportmap - and its
    failure mode reaches server.run(), which raises here (captured stdin is
    not readable) but would HANG under an open stdin (see the module
    docstring and the run() section comment below: the real, blocking
    server must never be reached). The run-spy proves that directly instead
    of relying on a startswith() on the wrong end of the string."""
    calls = _run_counter(monkeypatch)
    path = write(tmp_path, base_config(tmp_path))

    code = run([str(path)])

    assert code == 1
    assert calls == []
    assert capsys.readouterr().err.startswith("Fout: exportmap niet gevonden")


def test_the_server_runs_on_stdio_and_the_spy_records_the_argument(tmp_path, monkeypatch):
    """SECURITY 14. The FastMCP default IS stdio today, but a default is not a
    guarantee: a library caller can do .run("sse") on the same object, and no
    test noticed the difference."""
    calls = _run_counter(monkeypatch)
    path = _config(tmp_path)
    assert run([str(path)]) == 0
    assert len(calls) == 1
    _, args, kwargs = calls[0]
    assert kwargs.get("transport") == "stdio" or args[:1] == ("stdio",)


def test_running_the_module_directly_exits_with_the_run_code(tmp_path):
    """SECURITY 23. `python -m nsmcp.start <config>` used to do nothing and
    return exit code 0 - a silent no-op that cost a whole invalid measurement
    in the security spike."""
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "nsmcp.start"],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "Gebruik: netscaler-mcp" in completed.stderr


def test_the_three_new_chapters_are_accepted(tmp_path):
    """A1: een configuratie die beveiliging, rapport en ha noemt laadt."""
    server = start.build_server_from_config(_config(tmp_path, hoofdstukken=["beveiliging", "rapport", "ha"]))
    assert server is not None


def test_the_chapter_set_is_the_one_the_server_uses():
    """Een tweede lijst met hoofdstukken is een tweede waarheid. Er is er een."""
    from nsmcp.mcp_server import DEFAULT_CHAPTERS, build_server

    assert start.CHAPTERS is DEFAULT_CHAPTERS
    assert start.CHAPTERS == frozenset(
        {"status", "certificaat", "dienst", "kennis", "beveiliging", "rapport", "ha", "onderhoud", "config"}
    )
    # Pin build_server's OWN default parameter too: without this, someone could
    # re-inline a literal chapter set into `chapters:` in build_server and every
    # assertion above would still pass (start.CHAPTERS is still DEFAULT_CHAPTERS
    # by identity) - this is the exact second truth this task exists to prevent.
    build_server_default = inspect.signature(build_server).parameters["chapters"].default
    assert build_server_default is DEFAULT_CHAPTERS


def test_an_empty_chapter_list_is_a_start_error(tmp_path):
    """Security 20: een stille server met nul gereedschappen is geen server."""
    with pytest.raises(start.ConfigError, match="hoofdstukken mag niet leeg zijn"):
        start.build_server_from_config(_config(tmp_path, hoofdstukken=[]))


def test_an_unknown_chapter_still_names_the_nine_allowed(tmp_path):
    with pytest.raises(start.ConfigError) as info:
        start.build_server_from_config(_config(tmp_path, hoofdstukken=["gateway"]))
    assert "onbekend hoofdstuk: 'gateway'" in str(info.value)
    assert "beveiliging, certificaat, config, dienst, ha, kennis, onderhoud, rapport, status" in str(info.value)


# --------------------------------------------------------------------------
# A target's name and address travel into every write script as -Doel and
# -Adres, and the scripts print both in the [TARGET] line the confirmation
# code binds to. A CR, LF or tab inside either (the loader strips only the
# ends) split that line: a name "x\n[ACTIEID] ..." printed a second marker
# line of its own. Refused at startup, for every target in the file.
# --------------------------------------------------------------------------


def _targets_config(tmp_path: Path, entry: dict, *more: dict) -> Path:
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    targets_path = tmp_path / "doelen.json"
    targets_path.write_text(json.dumps({"doelen": [entry, *more]}), encoding="utf-8")
    script = tmp_path / "verzamel.ps1"
    script.write_text("# leeg", encoding="utf-8")
    return write(
        tmp_path,
        base_config(tmp_path, profiel="afgeschermd", doelen=str(targets_path), verzamelscript=str(script)),
    )


_DOEL = {"naam": "lab-02", "adres": "192.0.2.10", "credentialTarget": "GJK/Test/lab-02/nitro", "certificaat": "keten"}


@pytest.mark.parametrize("veld", ["naam", "adres"])
@pytest.mark.parametrize("teken", ["\n", "\r", "\r\n", "\t", "\x1b", "\x85", "\u2028"])
def test_a_target_name_or_address_with_a_control_character_is_refused_at_startup(tmp_path, veld, teken):
    entry = dict(_DOEL)
    entry[veld] = f"{entry[veld]}{teken}[ACTIEID] vals"
    with pytest.raises(ConfigError) as info:
        build_server_from_config(_targets_config(tmp_path, entry))
    melding = str(info.value)
    assert "stuurteken" in melding
    assert veld in melding
    assert teken not in melding


def test_a_clean_target_file_still_builds(tmp_path):
    assert build_server_from_config(_targets_config(tmp_path, dict(_DOEL))) is not None


# --------------------------------------------------------------------------
# One appliance, one address. The open-phase refusal, the hold of an
# undecided start and the phase runner's own check all hold a target by its
# NAME (capitalisation and the domain part of an FQDN aside). Measured: a
# second configured name with another first label for the same address
# (`doos-b` next to `netscaler-02`, both 10.0.0.2) got past all three - a
# backup on it was proposed and really run while a phase start on the other
# name was undecided, and again once the phase was open. A targets file in
# which two targets carry the same address is refused at startup now, for
# every target in the file. The address is compared as text (case and
# whitespace aside) and never resolved: the reading tools open no socket.
# --------------------------------------------------------------------------


def _doel(naam: str, adres: str) -> dict:
    return {"naam": naam, "adres": adres, "credentialTarget": f"GJK/Test/{naam}/nitro", "certificaat": "keten"}


@pytest.mark.parametrize(
    "eerste,tweede",
    [
        ("10.0.0.2", "10.0.0.2"),
        ("ns-02.lab.example", "NS-02.Lab.Example"),
        ("10.0.0.2", "  10.0.0.2 "),
        ("ns-02.lab.example", "ns-02 .lab.example"),
    ],
)
def test_two_targets_with_the_same_address_are_refused_at_startup(tmp_path, eerste, tweede):
    config = _targets_config(
        tmp_path,
        _doel("netscaler-02", eerste),
        _doel("lab-03", "10.0.0.3"),
        _doel("doos-b", tweede),
    )
    with pytest.raises(ConfigError) as info:
        build_server_from_config(config)
    melding = str(info.value)
    assert melding.startswith("doelenbestand: "), melding
    assert "'netscaler-02'" in melding and "'doos-b'" in melding, melding
    assert "hetzelfde adres" in melding, melding
    assert "lab-03" not in melding, melding


def test_targets_with_different_addresses_start(tmp_path):
    """The whole text is compared: an address that only begins like another
    is another address. And nothing is resolved - a host name next to an
    IP address is two addresses, whatever the name resolves to."""
    config = _targets_config(
        tmp_path,
        _doel("netscaler-02", "10.0.0.2"),
        _doel("netscaler-20", "10.0.0.20"),
        _doel("doos-b", "ns-02.lab.example"),
    )
    assert build_server_from_config(config) is not None


# --------------------------------------------------------------------------
# The export map is the one map a supplying party may write. Measured: only
# the provenance map and the code file were held against it - an action
# register, firmware map, collect script, knowledge file, target file,
# runner, write script or fixture map INSIDE the export map started without
# a word, and a runner or write script there is code run by whoever
# supplies the export. Every path the server reads, runs or writes is held
# against it now, and the maps the product itself writes or picks a bundle
# from may not hold the export map either. Each refusal names its field.
#
# The code file (and the sso presenter) may not sit in a map the product
# itself reads or writes: measured, `pad` = `<ledgermap>\herkomst\
# herkomst.jsonl` or the action register itself started, and every proposal
# then overwrote the provenance record or the register.
# --------------------------------------------------------------------------

_HOSTKEY = "10:21:32:43:54:65:76:87:98:a9:ba:cb:dc:ed:fe:1f"
_MANIFEST = {"manifestVersion": "1.1", "collectedAtUtc": "2026-09-06T10:00:00.0000000Z", "resources": {}, "files": {}}


def _side_by_side(tmp_path: Path) -> tuple[Path, dict]:
    """Every map and file of a full configuration in a place of its own, next
    to each other: the layout the documentation recommends. Returns the
    root and the configuration body (absolute paths)."""
    root = tmp_path / "opstelling"
    export = root / "export"
    (export / "objects").mkdir(parents=True)
    (export / "export-manifest.json").write_text(json.dumps(_MANIFEST), encoding="utf-8")
    for sub in ("beheer", "kennis", "doelen", "scripts", "faserunner", "fixtures", "ledger", "firmware", "codes"):
        (root / sub).mkdir()
    (root / "kennis" / "kennis.json").write_text(
        json.dumps({"versie": "2026.09", "datum": "2026-09-06", "cve": []}), encoding="utf-8"
    )
    doel = {
        "naam": "doos-a",
        "adres": "10.0.0.2",
        "credentialTarget": "GJK/Test/doos-a/x",
        "certificaat": "keten",
        "ssh_hostsleutel_vingerafdruk": _HOSTKEY,
    }
    (root / "doelen" / "doelen.json").write_text(json.dumps({"doelen": [doel]}), encoding="utf-8")
    for script in ("verzamel.ps1", "schrijf.ps1"):
        (root / "scripts" / script).write_text("# x", encoding="utf-8")
    (root / "faserunner" / "runner.ps1").write_text("# x", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export),
        "kennispad": str(root / "kennis" / "kennis.json"),
        "doelen": str(root / "doelen" / "doelen.json"),
        "verzamelscript": str(root / "scripts" / "verzamel.ps1"),
        "handelen": {
            "schrijfscript": str(root / "scripts" / "schrijf.ps1"),
            "fixturemap": str(root / "fixtures"),
            "codekanaal": {"soort": "bestand", "pad": str(root / "codes" / "code.txt")},
            "toegestaan": {},
        },
        "onderhoud": {
            "runner": str(root / "faserunner" / "runner.ps1"),
            "ledgermap": str(root / "ledger"),
            "firmwaremap": str(root / "firmware"),
            "soak_uren": 24,
            "ssh_gebruiker": "nsroot",
            "actieregister": str(root / "ledger" / "register.jsonl"),
        },
    }
    return root, body


def _start_with(root: Path, body: dict, *, config: Path | None = None):
    config = config or root / "beheer" / "config.json"
    config.write_text(json.dumps(body), encoding="utf-8")
    return build_server_from_config(config)


def _start_refusal(root: Path, body: dict, *, config: Path | None = None) -> str:
    with pytest.raises(ConfigError) as refused:
        _start_with(root, body, config=config)
    return str(refused.value)


def test_a_configuration_with_every_map_side_by_side_starts(tmp_path):
    root, body = _side_by_side(tmp_path)
    assert _start_with(root, body) is not None


def _copy_into_export(root: Path, source: str) -> str:
    target = root / "export" / Path(source).name
    target.write_bytes(Path(source).read_bytes())
    return str(target)


def _dir_in_export(root: Path, name: str) -> str:
    target = root / "export" / name
    target.mkdir()
    return str(target)


def _put_kennispad(root, body):
    body["kennispad"] = _copy_into_export(root, body["kennispad"])


def _put_doelen(root, body):
    body["doelen"] = _copy_into_export(root, body["doelen"])


def _put_verzamelscript(root, body):
    body["verzamelscript"] = _copy_into_export(root, body["verzamelscript"])


def _put_schrijfscript(root, body):
    body["handelen"]["schrijfscript"] = _copy_into_export(root, body["handelen"]["schrijfscript"])


def _put_fixturemap_below(root, body):
    body["handelen"]["fixturemap"] = _dir_in_export(root, "fixtures")


def _put_fixturemap_same(root, body):
    body["handelen"]["fixturemap"] = str(root / "export")


def _put_runner(root, body):
    body["onderhoud"]["runner"] = _copy_into_export(root, body["onderhoud"]["runner"])


def _put_firmwaremap_below(root, body):
    body["onderhoud"]["firmwaremap"] = _dir_in_export(root, "firmware")


def _put_firmwaremap_same(root, body):
    body["onderhoud"]["firmwaremap"] = str(root / "export")


def _put_actieregister(root, body):
    body["onderhoud"]["actieregister"] = str(root / "export" / "register.jsonl")


@pytest.mark.parametrize(
    ("veld", "plaats"),
    [
        ("kennispad", _put_kennispad),
        ("doelen", _put_doelen),
        ("verzamelscript", _put_verzamelscript),
        ("handelen.schrijfscript", _put_schrijfscript),
        ("handelen.fixturemap", _put_fixturemap_below),
        ("handelen.fixturemap", _put_fixturemap_same),
        ("onderhoud.runner", _put_runner),
        ("onderhoud.firmwaremap", _put_firmwaremap_below),
        ("onderhoud.firmwaremap", _put_firmwaremap_same),
        ("onderhoud.actieregister", _put_actieregister),
    ],
)
def test_a_path_the_server_reads_runs_or_writes_inside_the_export_map_is_refused(tmp_path, veld, plaats):
    root, body = _side_by_side(tmp_path)
    plaats(root, body)
    message = _start_refusal(root, body)
    assert message.startswith(f"{veld} ligt in de exportmap ({root / 'export'!r}): "), message


def test_the_configuration_file_inside_the_export_map_is_refused_with_onderhoud_too(tmp_path):
    """Without `onderhoud` the provenance map next to the configuration
    already refused this (tests/test_export_provenance.py); with it, the
    provenance map lies in the ledger map and nothing held the file itself."""
    root, body = _side_by_side(tmp_path)
    message = _start_refusal(root, body, config=root / "export" / "config.json")
    assert message.startswith(f"het configuratiebestand ligt in de exportmap ({root / 'export'!r}): "), message


def test_a_ledger_map_inside_the_export_map_is_still_refused(tmp_path):
    """Its provenance map lies in it too; that refusal (pinned in
    tests/test_export_provenance.py) comes first and stays the reason."""
    root, body = _side_by_side(tmp_path)
    body["onderhoud"]["ledgermap"] = _dir_in_export(root, "ledger")
    body["onderhoud"]["actieregister"] = str(root / "export" / "ledger" / "register.jsonl")
    message = _start_refusal(root, body)
    assert message.startswith("de herkomstmap mag niet in de exportmap staan"), message


@pytest.mark.parametrize(
    ("veld", "sleutel"), [("onderhoud.ledgermap", "ledgermap"), ("onderhoud.firmwaremap", "firmwaremap")]
)
def test_an_export_map_inside_a_map_the_product_writes_or_picks_a_bundle_from_is_refused(tmp_path, veld, sleutel):
    """The other way round: whoever replaces the export map writes the map
    that holds it (the scan's work map, the previous export and the lock
    lie beside it), so the export map may not lie in the ledger map or the
    firmware map."""
    root, body = _side_by_side(tmp_path)
    holder = Path(body["onderhoud"][sleutel])
    export = holder / "export"
    (export / "objects").mkdir(parents=True)
    (export / "export-manifest.json").write_text(json.dumps(_MANIFEST), encoding="utf-8")
    body["exportmap"] = str(export)
    message = _start_refusal(root, body)
    assert message.startswith(f"de exportmap ligt in {veld} ({holder!r}): {export!r}"), message


def test_the_documented_layout_with_the_export_beside_the_scripts_under_the_configuration_starts(tmp_path):
    """The layout of the configuration example in the manual: configuration,
    knowledge, collect script and export together under one administrative
    map. The export map lies in the map of the configuration file and of
    the collect script - allowed; the manual says when that is safe."""
    beheer = tmp_path / "netscaler-mcp"
    export = beheer / "export"
    (export / "objects").mkdir(parents=True)
    (export / "export-manifest.json").write_text(json.dumps(_MANIFEST), encoding="utf-8")
    (beheer / "kennis.json").write_text(
        json.dumps({"versie": "2026.09", "datum": "2026-09-06", "cve": []}), encoding="utf-8"
    )
    doel = {"naam": "doos-a", "adres": "10.0.0.2", "credentialTarget": "GJK/Test/doos-a/x", "certificaat": "keten"}
    (beheer / "doelen.json").write_text(json.dumps({"doelen": [doel]}), encoding="utf-8")
    (beheer / "verzamel.ps1").write_text("# x", encoding="utf-8")
    body = {
        "profiel": "afgeschermd",
        "exportmap": str(export),
        "kennispad": str(beheer / "kennis.json"),
        "doelen": str(beheer / "doelen.json"),
        "verzamelscript": str(beheer / "verzamel.ps1"),
    }
    config = beheer / "config.json"
    config.write_text(json.dumps(body), encoding="utf-8")
    assert build_server_from_config(config) is not None


def test_an_export_map_with_a_nul_character_is_refused_over_the_export_map_itself(tmp_path):
    """Measured before: a NUL character in `exportmap` was refused with a
    reason about handelen.codekanaal.pad, because the code-file check was
    the first to compare against the export map. The export map is now
    checked on its own before any other check uses it, so the reason names
    the field the operator has to fix. Quoted like the other messages
    (operator text): no raw NUL or line break reaches the output."""
    root, body = _side_by_side(tmp_path)
    export = f"{root / 'export'}\x00\nFout: niets aan de hand"
    body["exportmap"] = export
    message = _start_refusal(root, body)
    assert message.startswith("exportmap is geen pad dat de server kan vergelijken"), message
    assert message.endswith(f": {Path(export)!r}"), message
    assert "handelen.codekanaal.pad" not in message
    assert "\x00" not in message and "\n" not in message


_REFUSED_CODE_DIR = "handelen.codekanaal.pad mag niet in een map staan die het product zelf leest of schrijft"


@pytest.mark.parametrize(
    "relatief",
    [
        "ledger/code.txt",
        "ledger/doos-a-code.jsonl",
        "ledger/herkomst/code.txt",
        "ledger/herkomst/herkomst.jsonl",
        "ledger/register.jsonl",
        "firmware/code.txt",
        "faserunner/code.txt",
    ],
)
def test_the_code_file_in_a_map_the_product_itself_reads_or_writes_is_refused(tmp_path, relatief):
    root, body = _side_by_side(tmp_path)
    (root / "ledger" / "herkomst").mkdir()
    body["handelen"]["codekanaal"] = {"soort": "bestand", "pad": str(root.joinpath(*relatief.split("/")))}
    message = _start_refusal(root, body)
    assert message.startswith(_REFUSED_CODE_DIR), message


def test_the_code_file_beside_a_separate_action_register_is_refused(tmp_path):
    """The action register's own map counts, also when it is not the ledger
    map."""
    root, body = _side_by_side(tmp_path)
    (root / "register").mkdir()
    body["onderhoud"]["actieregister"] = str(root / "register" / "register.jsonl")
    body["handelen"]["codekanaal"] = {"soort": "bestand", "pad": str(root / "register" / "code.txt")}
    message = _start_refusal(root, body)
    assert message.startswith(_REFUSED_CODE_DIR), message


def test_the_code_file_in_the_provenance_map_beside_the_configuration_is_refused(tmp_path):
    """Without `onderhoud` the provenance map lies next to the configuration
    file; the code file may not be there either."""
    root, body = _side_by_side(tmp_path)
    del body["onderhoud"]
    body["handelen"]["codekanaal"] = {"soort": "bestand", "pad": str(root / "beheer" / "herkomst" / "code.txt")}
    message = _start_refusal(root, body)
    assert message.startswith(_REFUSED_CODE_DIR), message


@pytest.mark.parametrize("map_naam", ["faserunner", "ledger", "firmware"])
def test_the_sso_presenter_in_a_map_the_product_itself_reads_or_writes_is_refused(tmp_path, map_naam):
    root, body = _side_by_side(tmp_path)
    presenter = root / map_naam / "presenter.py"
    presenter.write_text("# x", encoding="utf-8")
    body["handelen"]["codekanaal"] = {
        "soort": "sso",
        "pad": str(presenter),
        "autoriteit": "https://voorbeeld.invalid",
        "wachttijd_s": 5,
    }
    message = _start_refusal(root, body)
    assert message.startswith(_REFUSED_CODE_DIR), message


def test_b3_preflight_without_a_target_claims_no_live_read_through_a_real_session(tmp_path):
    """B3 (1.0.2), measured in the public test: no target, no collect script,
    and the evidence of check 8 still said "live gelezen"."""
    forget_identities()
    _real_export(tmp_path)
    _real_knowledge(tmp_path)
    server = build_server_from_config(write(tmp_path, base_config(tmp_path)))

    import asyncio

    async def scenario():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="claude-code", version="1.0")
        ) as client:
            return await client.call_tool("status_update_preflight", {})

    result = asyncio.run(scenario())

    assert result.isError is False
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    regel8 = text[text.index("- 8. ") :].split("\n- ", 1)[0]
    assert "niet gelezen: er is geen doel ingesteld" in regel8
    assert "live gelezen" not in regel8
    assert "live lezing" not in regel8
    assert "verzamelscript, live" not in text
