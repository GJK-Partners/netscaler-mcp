"""1.0.3 R3H-1 / R3H-2: the parent-list cross-check of a by-parent binding file
that IS accepted never puts `parentResource` or `parentKey` - two values the
file carries - into a read-gap reason.

MEASURED before (re-review of 1.0.3): `binding_parents` already described a
`parentResource` that is not the one the file identity implies ("waarde niet
herhaald"), but then embedded the nested reason of `objects()`, which named
the expected key - that same value - straight after it: 3 of 5 variants
leaked at `beperkt`. And `parentKey` came out unmasked and uncut ("<value> is
niet bruikbaar", a line of 480 characters for a value of 300) whenever an
object in the parent source lacked that field.

Driven through the real MCP server at all three openness levels, with the
reviewer's variants. Synthetic export, no appliance.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import mcp.types as types
import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from nsmcp.disclosure import Disclosure, names_from_export
from nsmcp.export import load_export
from nsmcp.mcp_server import build_server, forget_identities

_BINDING = "vpnvserver_binding"
_FILE = f"{_BINDING}.by-parent.json"
_LEVELS = (Disclosure.LIMITED, Disclosure.MINIMAL, Disclosure.FULL)

# parentResource must pass the object-name gate to reach the cross-check at all.
# The long one stays under the Windows path limit: it becomes a file name.
_RESOURCES = {"kort": "geheimegateway01", "lang": "geheim_" + "y" * 100}
# parentKey is never used as a path; any text reaches the reason.
_KEYS = {"kort": "GEHEIMEGATEWAY01", "lang": "GEHEIM_" + "Y" * 300, "stuurteken": "GEHEIM\u202eGW\x07X01"}
_FRAGMENTS = {
    "geheimegateway01": "geheimegateway01",
    "geheim_" + "y" * 100: "y" * 40,
    "GEHEIMEGATEWAY01": "GEHEIMEGATEWAY01",
    "GEHEIM_" + "Y" * 300: "Y" * 40,
    # After the character filter the control characters become "?"; the
    # printable remainder may not come back either.
    "GEHEIM\u202eGW\x07X01": "X01",
}


def _ok_parent(name: str = "p1") -> dict:
    return {"parentName": name, "outcome": "OK", "data": {_BINDING: {"name": name}}}


def _document(parent_resource: str, parent_key: str) -> dict:
    return {
        "bindingResource": _BINDING,
        "parentResource": parent_resource,
        "parentKey": parent_key,
        "shape": "aggregate",
        "parents": [_ok_parent()],
    }


def _export(root: Path, document: dict, objects: dict[str, object]) -> Path:
    case = root / "export"
    (case / "objects").mkdir(parents=True)
    (case / "bindings").mkdir()
    resources = {}
    for resource, payload in objects.items():
        raw = json.dumps(payload).encode()
        (case / "objects" / f"{resource.split('/')[-1]}.json").write_bytes(raw)
        resources[resource] = {"status": "OK", "payloadSha256": hashlib.sha256(raw).hexdigest()}
    content = json.dumps(document).encode()
    (case / "bindings" / _FILE).write_bytes(content)
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-10-22T00:00:00Z",
        "resources": resources,
        "files": {f"bindings/{_FILE}": hashlib.sha256(content).hexdigest()},
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


def _resource_variants(value: str) -> dict[str, dict[str, object]]:
    """The reviewer's five variants of an accepted file whose parentResource
    is NOT the one the file identity implies."""
    return {
        "geen-lijst": {f"config/{value}": {value: "geen lijst"}},
        "element-geen-object": {f"config/{value}": {value: ["x"]}},
        "sleutel-ontbreekt": {f"config/{value}": {"x": []}},
        "bruikbaar": {f"config/{value}": {value: [{"name": "p1"}, {"name": "p2"}]}},
        "niet-in-manifest": {"config/vpnvserver": {"vpnvserver": [{"name": "p1"}]}},
    }


_RESOURCE_CASES = [(label, variant) for label in _RESOURCES for variant in _resource_variants("x")]


@pytest.mark.parametrize(("label", "variant"), _RESOURCE_CASES)
def test_a_parent_resource_of_another_identity_never_reaches_a_reason(tmp_path, label, variant):
    value = _RESOURCES[label]
    export_dir = _export(tmp_path, _document(value, "name"), _resource_variants(value)[variant])
    # Not harvested: nothing would mask it afterwards.
    assert value not in names_from_export(load_export(export_dir))
    for level in _LEVELS:
        is_error, text = _ask(tmp_path, export_dir, level)
        assert is_error is False, (level, text)
        assert _FRAGMENTS[value] not in text, f"{level.value}: {text}"
        if level is not Disclosure.MINIMAL and variant != "bruikbaar":
            # The gap stays visible and says what is wrong, and the claim
            # "(waarde niet herhaald)" is literally true.
            assert "niet te kruiscontroleren" in text and "waarde niet herhaald" in text, f"{level.value}: {text}"


@pytest.mark.parametrize("variant", ["geen-lijst", "element-geen-object", "sleutel-ontbreekt"])
def test_the_nested_reason_keeps_its_diagnosis_without_the_key(tmp_path, variant):
    """Unit level: the object source is still diagnosed (no list, element not
    an object), only the key it was looked under is described."""
    value = _RESOURCES["kort"]
    export_dir = _export(tmp_path, _document(value, "name"), _resource_variants(value)[variant])
    coverage = load_export(export_dir).binding_parents(_FILE)
    text = " ".join(f"{gap.source} {gap.reason}" for gap in coverage.gaps)
    assert coverage.gaps and value not in text, text
    expected = "geen object" if variant == "element-geen-object" else "geen lijst"
    assert expected in text and "de sleutel die parentResource noemt" in text, text


def test_the_parent_resource_of_the_own_identity_is_still_named(tmp_path):
    """The reason keeps naming the source and its key when that is the
    product's own expectation (`vpnvserver` for `vpnvserver_binding`)."""
    export_dir = _export(tmp_path, _document("vpnvserver", "name"), {"config/vpnvserver": {"vpnvserver": "geen lijst"}})
    coverage = load_export(export_dir).binding_parents(_FILE)
    text = " ".join(f"{gap.source} {gap.reason}" for gap in coverage.gaps)
    assert "config/vpnvserver:" in text and "'vpnvserver'" in text, text


@pytest.mark.parametrize("label", list(_KEYS))
def test_a_parent_key_never_reaches_a_reason(tmp_path, label):
    value = _KEYS[label]
    objects = {"config/vpnvserver": {"vpnvserver": [{"name": "p1"}, {"other": 1}]}}
    export_dir = _export(tmp_path, _document("vpnvserver", value), objects)
    for level in _LEVELS:
        is_error, text = _ask(tmp_path, export_dir, level)
        assert is_error is False, (level, text)
        assert _FRAGMENTS[value] not in text, f"{level.value}: {text}"
        # Uncut was the second half of the finding (a line of 480); the
        # structured copy at the end is one JSON line and is left out.
        lines = [line for line in text.splitlines() if not line.startswith("{")]
        assert max(map(len, lines)) < 300, f"{level.value}: {text}"
        if level is not Disclosure.MINIMAL:
            # Still visible, by position: both objects lack the field.
            assert "(object 1)" in text and "(object 2)" in text, f"{level.value}: {text}"
            assert "het veld dat parentKey noemt" in text, f"{level.value}: {text}"
