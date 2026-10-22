"""1.0.3 R3-1 / R3-4: a refused or half-read by-parent binding file never puts
a value it carries - a parent name, an object name, a resource name - into a
read-gap reason, in either binding shape and through every reader.

MEASURED before (review of 1.0.3): the LIST reader already named an unusable
parent by its position, but the AGGREGATE reader still put the raw parentName
into five reasons (single-row shape, more than one document, data not an
object, duplicate parent, EMPTY with data). `rapport_dekking` cross-checks
EVERY binding file in the manifest, and a file outside the tolerant name
harvest (`disclosure.AGGREGATE_BINDING_FILES`), such as `vpnvserver_binding`
or `lbmonitor_binding`, is never harvested: at `beperkt` the real name came
out 16 times out of 16, and a name of 300 characters came out uncut.

The rule is structural and lives in one place (`export._parent_at`): a reason
says WHERE in the file and HOW MANY, never the value. The tests drive the
reviewer's probe through the real MCP server at all three openness levels,
for a file outside and a file inside the harvest, in both shapes, with a
short name, a name of 300 characters and one with control characters.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp.disclosure import AGGREGATE_BINDING_FILES, Disclosure
from nsmcp.export import _binding_rows, _checked_aggregate_documents, _flatten_by_parent, load_export
from nsmcp.mcp_server import build_server, forget_identities

_NAMES = {
    "kort": "GEHEIMEGATEWAY01",
    "lang": "GEHEIM_" + "Y" * 300,
    "stuurteken": "GEHEIM\u202eGATE\x1bWAY-02",
}
# The printable fragment that may never come back (see test_binding_parent_position).
_FRAGMENTS = {"kort": "GEHEIMEGATEWAY01", "lang": "Y" * 129, "stuurteken": "GATE"}

# (binding resource, parent resource, parent key, shape). Two aggregate files
# OUTSIDE the tolerant harvest (the reviewer's two), one aggregate file INSIDE
# it, and one list file outside it.
_FILES = {
    "vpnvserver_binding": ("vpnvserver", "name", "aggregate"),
    "lbmonitor_binding": ("lbmonitor", "monitorname", "aggregate"),
    "servicegroup_binding": ("servicegroup", "servicegroupname", "aggregate"),
    "sslvserver_ecccurve_binding": ("sslvserver", "vservername", "list"),
}


def _aggregate_cases(name: str, resource: str) -> dict[str, list]:
    """The reviewer's four aggregate forms, plus the outcome forms."""
    return {
        "dubbele-parent": [
            {"parentName": name, "outcome": "OK", "data": {resource: {"name": name}}},
            {"parentName": name, "outcome": "OK", "data": {resource: {"name": name}}},
        ],
        "leeg-met-data": [{"parentName": name, "outcome": "EMPTY", "data": {resource: {"name": "x"}}}],
        "data-geen-object": [{"parentName": name, "outcome": "OK", "data": "tekst"}],
        "meer-documenten": [{"parentName": name, "outcome": "OK", "data": {resource: [{"a": 1}, {"b": 2}]}}],
        "mislukt": [{"parentName": name, "outcome": "FAILED", "data": None}],
        "vrije-outcome": [{"parentName": name, "outcome": name, "data": None}],
    }


def _list_cases(name: str, resource: str) -> dict[str, list]:
    return {
        "leeg-met-data": [{"parentName": name, "outcome": "EMPTY", "data": {resource: [{"vservername": name}]}}],
        "mislukt": [{"parentName": name, "outcome": "FAILED", "data": None}],
        "vrije-outcome": [{"parentName": name, "outcome": name, "data": None}],
        "element-geen-object": [{"parentName": name, "outcome": "OK", "data": {resource: [name]}}],
    }


def _cases(binding: str, name: str) -> dict[str, list]:
    shape = _FILES[binding][2]
    return _aggregate_cases(name, binding) if shape == "aggregate" else _list_cases(name, binding)


def _document(binding: str, parents: list, **overrides) -> dict:
    parent_resource, parent_key, shape = _FILES[binding]
    doc = {
        "bindingResource": binding,
        "parentResource": parent_resource,
        "parentKey": parent_key,
        "shape": shape,
        "parents": parents,
    }
    doc.update(overrides)
    return doc


def _export(root: Path, binding: str, document: dict) -> Path:
    case = root / "export"
    (case / "objects").mkdir(parents=True)
    (case / "bindings").mkdir()
    raw = json.dumps({"sslcertkey": [{"certkey": "cert_fixture", "daystoexpiration": 10}]}).encode()
    (case / "objects" / "sslcertkey.json").write_bytes(raw)
    content = json.dumps(document).encode()
    file_name = f"{binding}.by-parent.json"
    (case / "bindings" / file_name).write_bytes(content)
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-10-22T00:00:00Z",
        "resources": {"config/sslcertkey": {"status": "OK", "payloadSha256": hashlib.sha256(raw).hexdigest()}},
        "files": {f"bindings/{file_name}": hashlib.sha256(content).hexdigest()},
    }
    (case / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return case


def _knowledge(root: Path) -> Path:
    path = root / "kennis.json"
    path.write_text(json.dumps({"versie": "fixture", "datum": "2026-10-21", "cve": []}), encoding="utf-8")
    return path


def _ask(root: Path, export_dir: Path, level: Disclosure) -> tuple[bool, str]:
    forget_identities()
    server = build_server(
        export_dir, _knowledge(root), disclosure=level, pseudonym_table_path=root / f"tabel-{level.value}.json"
    )

    async def run():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="test-client", version="1")
        ) as client:
            result = await client.call_tool("rapport_dekking", {})
            text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
            return result.isError, text + "\n" + json.dumps(result.structuredContent or {})

    return asyncio.run(run())


def test_the_files_cover_both_sides_of_the_tolerant_harvest():
    """Guard on the parametrisation itself: the leak sat in the files the
    harvest does NOT cover, and the rule must hold for the ones it does."""
    assert "vpnvserver_binding.by-parent.json" not in AGGREGATE_BINDING_FILES
    assert "lbmonitor_binding.by-parent.json" not in AGGREGATE_BINDING_FILES
    assert "servicegroup_binding.by-parent.json" in AGGREGATE_BINDING_FILES
    assert "sslvserver_ecccurve_binding.by-parent.json" not in AGGREGATE_BINDING_FILES


_MCP_CASES = [
    (binding, label, case)
    for binding in _FILES
    for label in _NAMES
    for case in (_aggregate_cases if _FILES[binding][2] == "aggregate" else _list_cases)("x", binding)
]


@pytest.mark.parametrize(("binding", "label", "case"), _MCP_CASES)
def test_no_source_value_reaches_the_coverage_report(tmp_path, binding, label, case):
    name = _NAMES[label]
    export_dir = _export(tmp_path, binding, _document(binding, _cases(binding, name)[case]))
    file_name = f"{binding}.by-parent.json"
    # beperkt first: under a mutation the first failure is then the leak the
    # finding is about.
    for level in (Disclosure.LIMITED, Disclosure.MINIMAL, Disclosure.FULL):
        is_error, text = _ask(tmp_path, export_dir, level)
        assert is_error is False, (level, text)
        assert _FRAGMENTS[label] not in text, f"{level.value}: {text}"
        if level is not Disclosure.MINIMAL:
            # The reason stays visible and says WHERE in the file.
            assert file_name in text and "parent op positie" in text, f"{level.value}: {text}"


@pytest.mark.parametrize("label", list(_NAMES))
def test_a_duplicate_parent_names_both_positions(label):
    binding = "vpnvserver_binding"
    raw = _document(binding, _aggregate_cases(_NAMES[label], binding)["dubbele-parent"])
    gap = _checked_aggregate_documents(f"{binding}.by-parent.json", raw)[1]
    assert gap is not None and _FRAGMENTS[label] not in gap.reason, gap.reason
    assert "dubbele parent op positie 2" in gap.reason and "positie 1" in gap.reason, gap.reason


@pytest.mark.parametrize("label", list(_NAMES))
def test_a_nested_list_of_the_wrong_shape_names_the_parent_by_position(label):
    """The nested read of `binding_rows` (the chain and certificate tools)
    refuses the whole file on one bad nested list: same rule."""
    binding = "lbvserver_binding"
    name = _NAMES[label]
    raw = {
        "bindingResource": binding,
        "shape": "aggregate",
        "parents": [
            {"parentName": "GOED-01", "outcome": "OK", "data": {binding: {"name": "GOED-01"}}},
            {"parentName": name, "outcome": "OK", "data": {binding: {"name": name, "lbvserver_service_binding": name}}},
        ],
    }
    grouped, gap = _binding_rows(f"{binding}.by-parent.json", raw, ("lbvserver_service_binding",))
    assert grouped == {} and gap is not None
    assert _FRAGMENTS[label] not in gap.reason, gap.reason
    assert "parent op positie 2" in gap.reason and "lbvserver_service_binding" in gap.reason, gap.reason


@pytest.mark.parametrize("label", list(_NAMES))
@pytest.mark.parametrize("shape", ["list", "aggregate"])
def test_a_mismatching_binding_resource_is_never_repeated(label, shape):
    """R3-4: the bindingResource of a refused file is supplied text, also when
    it has the form of a binding identity. Only the identity the requested
    file name implies is named."""
    binding = "sslvserver_ecccurve_binding" if shape == "list" else "vpnvserver_binding"
    file_name = f"{binding}.by-parent.json"
    for value in (_NAMES[label], "geheimegateway01_binding", "lbvserver_appfwpolicy_binding"):
        raw = _document(binding, [], bindingResource=value)
        gap = (
            (_flatten_by_parent(file_name, raw)[1])
            if shape == "list"
            else _checked_aggregate_documents(file_name, raw)[1]
        )
        assert gap is not None, value
        fragment = _FRAGMENTS[label] if value == _NAMES[label] else value
        assert fragment not in gap.reason, gap.reason
        assert repr(binding) in gap.reason and "komt niet overeen" in gap.reason, gap.reason


def test_a_parent_resource_of_another_identity_is_not_repeated(tmp_path):
    """The cross-check opens `config/<parentResource>`; when that source is not
    usable, the reason named it - a value from the file. Named only when it is
    the parent resource the file's own identity implies."""
    binding = "vpnvserver_binding"
    parents = [{"parentName": "GW-01", "outcome": "OK", "data": {binding: {"name": "GW-01"}}}]
    for value, named in (("GEHEIMEBRON01", False), ("vpnvserver", True)):
        export_dir = _export(tmp_path / value, binding, _document(binding, parents, parentResource=value))
        coverage = load_export(export_dir).binding_parents(f"{binding}.by-parent.json")
        text = " ".join(f"{gap.source} {gap.reason}" for gap in coverage.gaps)
        assert coverage.gaps, value
        assert (value in text) is named, text
        assert "niet te kruiscontroleren" in text, text


@pytest.mark.parametrize("label", list(_NAMES))
def test_an_unknown_shape_is_not_repeated_by_the_child_key_reader(label):
    """The child-key read of `binding_rows` echoed any shape of object-name
    form; a shape is supplied text like every other field."""
    raw = {"bindingResource": "lbvserver_binding", "shape": _NAMES[label], "parents": []}
    grouped, gap = _binding_rows("lbvserver_binding.by-parent.json", raw, ("lbvserver_service_binding",))
    assert grouped == {} and gap is not None
    assert _FRAGMENTS[label] not in gap.reason and "onbekende bindingsvorm" in gap.reason, gap.reason
