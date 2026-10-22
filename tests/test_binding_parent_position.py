"""1.0.3 P-1: an unusable parent in a LIST-shape by-parent file is named by
its position in the file, never by its raw parentName or a free outcome value.

MEASURED before (1.0.2): a hash-valid `sslvserver_sslcertkey_binding
.by-parent.json` with one parent of outcome FAILED put the raw parentName in
the read-gap reason. The reader then refuses the whole file, so the
structural name harvest (`names_from_export`) never collects that name, and
neither the masking at `beperkt` nor the 128-character cut could see it: the
name came out whole through `certificaat_wat_breekt_er` at `beperkt`, also a
name of 5007 characters.

The test drives every list-shape error branch that used to echo the name,
with a short name, a name over 128 characters and a name carrying control
characters, through the real MCP server at all three openness levels. The
read gap and its reason must stay visible; the raw name may not come back.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp.disclosure import Disclosure
from nsmcp.export import _flatten_by_parent
from nsmcp.mcp_server import build_server, forget_identities

BINDING = "sslvserver_sslcertkey_binding"
FILE = f"{BINDING}.by-parent.json"

_NAMES = {
    "kort": "PARENT-GEHEIM-01",
    "lang": "PARENT_" + "X" * 300,
    "stuurteken": "PARENT\u202eGEHEIM\x1b-02",
}
# The printable fragment of each name that may never come back. For the name
# with control characters the filter would already replace the controls, so
# the fragment around them is what proves the name itself did not leak.
_FRAGMENTS = {"kort": "PARENT-GEHEIM-01", "lang": "X" * 129, "stuurteken": "GEHEIM"}


def _parents(name: str) -> dict[str, list]:
    """One list per error branch that carried the parent name before."""
    return {
        "leeg-met-data": [{"parentName": name, "outcome": "EMPTY", "data": {BINDING: [{"vservername": name}]}}],
        "mislukt": [{"parentName": name, "outcome": "FAILED", "data": None}],
        "vrije-outcome": [{"parentName": name, "outcome": name, "data": None}],
        "ok-zonder-data": [{"parentName": name, "outcome": "OK", "data": None}],
        "ok-zonder-lijst": [{"parentName": name, "outcome": "OK", "data": {BINDING: name}}],
        "element-geen-object": [{"parentName": name, "outcome": "OK", "data": {BINDING: [name]}}],
    }


def _export(root: Path, parents: list) -> Path:
    case = root / "export"
    (case / "objects").mkdir(parents=True)
    (case / "bindings").mkdir()
    raw = json.dumps({"sslcertkey": [{"certkey": "cert_fixture", "daystoexpiration": 10}]}).encode()
    (case / "objects" / "sslcertkey.json").write_bytes(raw)
    binding = json.dumps(
        {
            "bindingResource": BINDING,
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": parents,
        }
    ).encode()
    (case / "bindings" / FILE).write_bytes(binding)
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-10-22T00:00:00Z",
        "resources": {"config/sslcertkey": {"status": "OK", "payloadSha256": hashlib.sha256(raw).hexdigest()}},
        "files": {f"bindings/{FILE}": hashlib.sha256(binding).hexdigest()},
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
        export_dir,
        _knowledge(root),
        disclosure=level,
        pseudonym_table_path=root / f"tabel-{level.value}.json",
    )

    async def run():
        async with create_connected_server_and_client_session(
            server, client_info=types.Implementation(name="test-client", version="1")
        ) as client:
            result = await client.call_tool("certificaat_wat_breekt_er", {"certnaam": "cert_fixture"})
            text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
            return result.isError, text + "\n" + json.dumps(result.structuredContent or {})

    return asyncio.run(run())


_CASES = [(label, branch) for label in _NAMES for branch in _parents("x")]


@pytest.mark.parametrize(("label", "branch"), _CASES)
def test_the_reader_names_an_unusable_parent_by_position_only(label, branch):
    name = _NAMES[label]
    parents = [{"parentName": "GOED-01", "outcome": "EMPTY", "data": None}, *_parents(name)[branch]]
    raw = {"bindingResource": BINDING, "shape": "list", "parents": parents}
    flat, gap, grouped = _flatten_by_parent(FILE, raw)
    assert gap is not None and flat == [] and grouped == {}
    assert _FRAGMENTS[label] not in gap.reason, gap.reason
    assert "op positie 2" in gap.reason, gap.reason


@pytest.mark.parametrize(("label", "branch"), _CASES)
def test_no_raw_parent_name_reaches_a_certificate_answer(tmp_path, label, branch):
    name = _NAMES[label]
    export_dir = _export(tmp_path, _parents(name)[branch])
    # beperkt first: under a mutation the first failure is then the leak the
    # finding is about, not the (by-design) name at volledig.
    for level in (Disclosure.LIMITED, Disclosure.MINIMAL, Disclosure.FULL):
        is_error, text = _ask(tmp_path, export_dir, level)
        assert is_error is False, (level, text)
        assert _FRAGMENTS[label] not in text, f"{level.value}: {text}"
        if level is Disclosure.MINIMAL:
            assert "1 leesgat(en)" in text, text
        else:
            # The reason stays visible and says WHERE the unusable parent sits.
            assert f"{FILE}: parent op positie 1" in text, text


@pytest.mark.parametrize("label", list(_NAMES))
@pytest.mark.parametrize("field", ["shape", "bindingResource"])
def test_a_free_file_level_value_is_not_echoed(label, field):
    """The two file-level values the list reader used to echo verbatim: a
    shape it does not support and a bindingResource that does not match the
    file name. Both are supplied text and can carry a name as well."""
    name = _NAMES[label]
    raw = {"bindingResource": BINDING, "shape": "list", "parents": []}
    raw[field] = name
    gap = _flatten_by_parent(FILE, raw)[1]
    assert gap is not None and _FRAGMENTS[label] not in gap.reason, gap.reason
    assert ("niet ondersteund" if field == "shape" else "komt niet overeen") in gap.reason


def test_a_known_collector_outcome_stays_named():
    """The closed collector vocabulary is not a free value: it stays in the
    reason, so the operator still learns WHY the parent was unusable."""
    raw = {
        "bindingResource": BINDING,
        "shape": "list",
        "parents": [{"parentName": "P", "outcome": "RBAC_DENIED", "data": None}],
    }
    gap = _flatten_by_parent(FILE, raw)[1]
    assert gap is not None and "RBAC_DENIED" in gap.reason, gap.reason
