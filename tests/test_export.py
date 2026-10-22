import ast
import dataclasses
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from config_export_harness import (
    COLLECTOR_MARKER,
    COLLECTOR_MARKER_LINES,
    DOH,
    LAB,
    NEW_SECRET,
    OLD_SECRET,
    WITHHELD_ONLY_PAIRS,
    config_pair,
)
from conftest import seal_manifest

from nsmcp import export as export_module
from nsmcp.export import TARGET_FILE, load_export

CERTS = {"sslcertkey": [{"certkey": "cert_a", "daystoexpiration": 12, "status": "Valid"}]}

# FILE NAME/SHAPE: the REAL NSHC 1.0 collector writes
# `objects/sslcertkey.json` (without a "config_" prefix) and
# `bindings/sslvserver_sslcertkey_binding.by-parent.json` in the by-parent
# shape - see `tests/fixtures/lab-export-vpx-20260826/` for the real proof.
# Every fixture in this file used to build the same (by now outdated)
# flat/"config_" assumption as the production code - and therefore could
# NEVER catch the two live findings. These helpers now build the REAL
# shape.
BINDING_FILE = "sslvserver_sslcertkey_binding.by-parent.json"


def _by_parent(parents: dict[str, list[dict]]) -> dict:
    """Builds the by-parent shape the real collector writes: one parent
    per key in `parents`, each with outcome OK and its bindings under
    "sslvserver_sslcertkey_binding" in "data" (see
    bindings/sslvserver_sslcertkey_binding.by-parent.json in the live
    fixture)."""
    return {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {
                "parentName": name,
                "outcome": "OK",
                "data": {"sslvserver_sslcertkey_binding": bindings},
            }
            for name, bindings in parents.items()
        ],
    }


def _build(tmp_path: Path, resources=None, with_binding_file=True, hash_matches=True) -> Path:
    (tmp_path / "objects").mkdir()
    (tmp_path / "bindings").mkdir()
    obj = tmp_path / "objects" / "sslcertkey.json"
    obj.write_text(json.dumps(CERTS), encoding="utf-8")
    files = {}
    if with_binding_file:
        b = tmp_path / "bindings" / BINDING_FILE
        content = json.dumps(_by_parent({"LB_VS_A": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]}))
        b.write_text(content, encoding="utf-8")
        real_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        files[f"bindings/{BINDING_FILE}"] = real_hash if hash_matches else "0" * 64
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-08-19T10:00:00.0000000Z",
        "resources": resources if resources is not None else {"config/sslcertkey": {"status": "OK"}},
        "files": files,
    }
    (tmp_path / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(tmp_path)
    return tmp_path


def test_successful_read_yields_objects(tmp_path):
    e = load_export(_build(tmp_path))
    objs, gap = e.objects("config/sslcertkey")
    assert gap is None
    assert objs[0]["certkey"] == "cert_a"


def test_empty_is_different_from_not_read(tmp_path):
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": {"status": "EMPTY"}}))
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is None, "EMPTY is een gelezen leegte en dus geen leesgat"


def test_failed_read_yields_a_read_gap_not_an_empty_list(tmp_path):
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": {"status": "RBAC_DENIED"}}))
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None
    assert "RBAC_DENIED" in gap.reason


def test_resource_absent_from_the_manifest_is_a_read_gap(tmp_path):
    e = load_export(_build(tmp_path, resources={}))
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niet in het manifest" in gap.reason


def test_manipulated_binding_file_is_not_trusted(tmp_path):
    e = load_export(_build(tmp_path, hash_matches=False))
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "hash" in gap.reason.lower()


def test_missing_manifest_makes_everything_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "export-manifest.json").unlink()
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_broken_manifest_json_makes_everything_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "export-manifest.json").write_text("{niet geldige json", encoding="utf-8")
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_non_utf8_manifest_makes_everything_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "export-manifest.json").write_bytes(b"\xff\xfe\x00\x01")
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_object_file_missing_while_manifest_says_ok(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "objects" / "sslcertkey.json").unlink()
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "bestand ontbreekt" in gap.reason.lower()


def test_unreadable_object_file_is_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "objects" / "sslcertkey.json").write_text("{niet geldige json", encoding="utf-8")
    seal_manifest(dir_)
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "onleesbaar" in gap.reason.lower()


def test_non_utf8_object_file_is_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "objects" / "sslcertkey.json").write_bytes(b"\xff\xfe\x00\x01")
    seal_manifest(dir_)
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "onleesbaar" in gap.reason.lower()


# ---------------------------------------------------------------------------
# Silent emptiness on a deviating key.
#
# objects() used to do `rauw.get(sleutel, [])`. An object file the manifest
# calls OK and that parses fine, but that carries its list under a
# DIFFERENT key, thereby yielded zero objects without a read gap. "We
# looked in the wrong place" silently became "there was nothing" - exactly
# the distinction the module docstring of export.py calls the core of this
# product.
# ---------------------------------------------------------------------------


def _rewrite_object_file(dir_: Path, content) -> None:
    (dir_ / "objects" / "sslcertkey.json").write_text(json.dumps(content), encoding="utf-8")
    seal_manifest(dir_)


def test_object_file_with_a_different_key_is_a_read_gap(tmp_path):
    """The core case: valid JSON, manifest says OK, but the list sits
    under "sslcertkeys" instead of "sslcertkey". Before the repair this
    yielded zero objects and no read gap - a certificate overview that
    looked empty and trustworthy while nothing had been read.
    """
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, {"sslcertkeys": [{"certkey": "cert_a"}]})
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None, "op de verkeerde plek kijken is geen lege lijst"
    assert "sslcertkey" in gap.reason


def test_object_file_without_any_key_is_a_read_gap(tmp_path):
    """A separate branch from the test above: an empty JSON object has no
    keys at all. `rauw.get(sleutel, [])` returned an empty list here just
    as silently.
    """
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, {})
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None


def test_object_file_with_null_under_the_expected_key_is_a_read_gap(tmp_path):
    """Same failure class, third shape: the key exists but carries JSON
    null (as a collector may write for a field it did not fetch).
    `list(None)` gave a bare TypeError here that the front door masked as
    "onverwachte fout" - a generic error message instead of the read gap
    it really is.
    """
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, {"sslcertkey": None})
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None


def test_object_file_with_a_list_at_top_level_is_a_read_gap(tmp_path):
    """Fourth shape: the file is valid JSON but not an object at all, so
    no expected key can be found in it. `rauw.get(...)` gave a bare
    AttributeError here that surfaced as "onverwachte fout". This too is
    "we looked in the wrong place".
    """
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, [{"certkey": "cert_a"}])
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None


def test_object_file_with_a_string_element_is_a_read_gap_not_a_crash(tmp_path):
    """`objects()` used to validate only the CONTAINER (is it a list
    under the right key?), not the ELEMENTS inside it. A correctly hashed,
    syntactically valid object file with a list element that is a bare
    STRING (instead of an object) passed that check effortlessly and came
    out unhindered as `list(content)` - after which the REAL
    `what_expires()` crashes as soon as it tries `.get("certkey")` on the
    element (see test_expiry.py for that variant through the real caller).
    The same kind of gap as the one in `_flatten_by_parent`, one function
    further along: every list element must POSITIVELY be an object,
    otherwise a read gap naming the shape, never a silent pass-through."""
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, {"sslcertkey": [{"certkey": "cert_a"}, "niet-een-object"]})
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == [], "een niet-object element mag nooit stilzwijgend meetellen, ook niet naast geldige objecten"
    assert gap is not None, (
        "een niet-object element in de lijst moet een leesgat opleveren, geen crash bij de aanroeper"
    )
    assert "sslcertkey" in gap.reason


def test_empty_list_under_the_right_key_remains_a_read_emptiness(tmp_path):
    """Counter-probe: a genuinely empty list under the RIGHT key is a
    read emptiness and thus no read gap. Without this test, a mutation
    declaring every empty outcome a read gap would also turn all tests
    above green - and then the product would lie the other way: raising
    alarm where nothing is.
    """
    dir_ = _build(tmp_path)
    _rewrite_object_file(dir_, {"sslcertkey": []})
    e = load_export(dir_)
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is None


def test_bindings_without_manifest_is_also_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "export-manifest.json").unlink()
    e = load_export(dir_)
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_no_hash_in_manifest_is_a_read_gap(tmp_path):
    e = load_export(_build(tmp_path, with_binding_file=False))
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "geen hash" in gap.reason.lower()


def test_binding_file_missing_while_manifest_has_a_hash(tmp_path):
    dir_ = _build(tmp_path)
    (dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").unlink()
    e = load_export(dir_)
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "bindingsbestand ontbreekt" in gap.reason.lower()


def test_unreadable_binding_file_is_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    path = dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json"
    content = b"{niet geldige json"
    path.write_bytes(content)
    correct_hash = hashlib.sha256(content).hexdigest()
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = correct_hash
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "onleesbaar" in gap.reason.lower()


def test_non_utf8_binding_file_is_a_read_gap(tmp_path):
    dir_ = _build(tmp_path)
    path = dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json"
    content = b"\xff\xfe\x00\x01"
    path.write_bytes(content)
    correct_hash = hashlib.sha256(content).hexdigest()
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = correct_hash
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None
    assert "onleesbaar" in gap.reason.lower()


def test_successful_bindings_read_yields_all_bindings_flat(tmp_path):
    dir_ = _build(tmp_path)
    path = dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json"
    content = json.dumps(
        _by_parent(
            {
                "LB_VS_A": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}],
                "LB_VS_B": [
                    {"certkeyname": "cert_b", "vservername": "LB_VS_B"},
                    {"certkeyname": "cert_c", "vservername": "LB_VS_B"},
                ],
            }
        )
    )
    path.write_text(content, encoding="utf-8")
    correct_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = correct_hash
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is None
    assert len(bindings) == 3
    assert {b["certkeyname"] for b in bindings} == {"cert_a", "cert_b", "cert_c"}
    assert {b["vservername"] for b in bindings} == {"LB_VS_A", "LB_VS_B"}


# ---------------------------------------------------------------------------
# Negative regressions on `_flatten_by_parent` and its neighbours: shapes
# the real collector does not write, but which this file cannot rule out
# because the manifest only guards the HASH of the whole, not the shape of
# the content inside it.
# ---------------------------------------------------------------------------


def _rewrite_binding_file(dir_: Path, content) -> None:
    """Rewrites the binding file with NEW content and updates the hash in
    the manifest, so the hash check passes and the test really reaches
    `_flatten_by_parent` - otherwise every test here already strands on
    "hash wijkt af van het manifest", before the shape of the content is
    ever looked at."""
    path = dir_ / "bindings" / BINDING_FILE
    text = json.dumps(content)
    path.write_text(text, encoding="utf-8")
    correct_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = correct_hash
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_binding_element_that_is_not_an_object_is_a_read_gap_not_a_crash(tmp_path):
    """A list element that is not an object (here a bare string) passes
    the hash check just fine - that check only covers the bytes of the
    WHOLE file, not the shape of each element inside - and used to come
    out unhindered. `what_breaks()` then crashes on it with a bare
    AttributeError as soon as the element tries `.get("certkeyname")`: a
    string has no `.get`. A crash is never an acceptable outcome - every
    binding item here must positively be an object (dict), otherwise a
    read gap naming the shape."""
    dir_ = _build(tmp_path)
    content = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {
                "parentName": "LB_VS_A",
                "outcome": "OK",
                "data": {"sslvserver_sslcertkey_binding": ["niet-een-object"]},
            }
        ],
    }
    _rewrite_binding_file(dir_, content)
    e = load_export(dir_)
    bindings, gap = e.bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None, "een niet-object element in de lijst mag nooit stilzwijgend doorstromen naar what_breaks()"
    # 1.0.3 (P-1): the parent is named by its position, never by its name.
    assert "parent op positie 1" in gap.reason and "LB_VS_A" not in gap.reason


def test_bindingresource_for_a_different_object_is_a_read_gap(tmp_path):
    """The binding file carried a bindingResource for a DIFFERENT object
    ('lbvserver_appfwpolicy_binding') than what the file name itself
    implies ('sslvserver_sslcertkey_binding.by-parent.json' expects
    'sslvserver_sslcertkey_binding'). Before the fix, whatever
    bindingResource the file happened to carry was trusted, without
    checking it against the requested identity - evidence for another
    object could thus pass as evidence for THIS file."""
    dir_ = _build(tmp_path)
    content = {
        "bindingResource": "lbvserver_appfwpolicy_binding",
        "parentResource": "lbvserver",
        "parentKey": "name",
        "shape": "list",
        "parents": [
            {
                "parentName": "LB_VS_A",
                "outcome": "OK",
                "data": {"lbvserver_appfwpolicy_binding": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]},
            }
        ],
    }
    _rewrite_binding_file(dir_, content)
    e = load_export(dir_)
    bindings, gap = e.bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None, "bewijs voor een ander object mag nooit meetellen als bewijs voor dit bestand"
    assert "sslvserver_sslcertkey_binding" in gap.reason, "de reden moet de VERWACHTE identiteit benoemen"
    # 1.0.3 (R3-4): the value the refused file carries is never repeated,
    # also when it has the form of a binding identity.
    assert "lbvserver_appfwpolicy_binding" not in gap.reason, "de AANWEZIGE waarde uit het bestand wordt niet herhaald"


def test_outcome_empty_with_data_is_a_read_gap_not_a_silent_emptiness(tmp_path):
    """A parent with outcome EMPTY that STILL carries data (here a real
    binding under the bindingResource key) is a contradictory reading -
    the file claims 'nothing read' and 'here is content' at the same time.
    Before the fix EMPTY was trusted outright (`continue`) and the data
    vanished silently: what_breaks() then saw zero bindings while there
    really was a bound vserver."""
    dir_ = _build(tmp_path)
    content = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {
                "parentName": "LB_VS_A",
                "outcome": "EMPTY",
                "data": {"sslvserver_sslcertkey_binding": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]},
            }
        ],
    }
    _rewrite_binding_file(dir_, content)
    e = load_export(dir_)
    bindings, gap = e.bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None, "EMPTY met data is een tegenstrijdige lezing, geen betrouwbare leegte"
    # 1.0.3 (P-1): the parent is named by its position, never by its name.
    assert "parent op positie 1" in gap.reason and "LB_VS_A" not in gap.reason


def test_outcome_empty_without_data_remains_a_read_emptiness(tmp_path):
    """Counter-probe to the previous test (the same discipline as
    `test_empty_list_under_the_right_key_remains_a_read_emptiness`
    above): a parent that carries outcome EMPTY and REALLY has no data
    (the key is absent entirely) rightly yields zero bindings for that
    parent - no read gap. Without this test, a mutation declaring EVERY
    EMPTY parent a read gap would also pass here, and then the product
    lies the other way: alarm where nothing is."""
    dir_ = _build(tmp_path)
    content = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {"parentName": "LB_VS_LEEG", "outcome": "EMPTY"},
            {
                "parentName": "LB_VS_A",
                "outcome": "OK",
                "data": {"sslvserver_sslcertkey_binding": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]},
            },
        ],
    }
    _rewrite_binding_file(dir_, content)
    e = load_export(dir_)
    bindings, gap = e.bindings(BINDING_FILE)
    assert gap is None, f"onverwacht leesgat bij een echt lege parent: {gap}"
    assert len(bindings) == 1
    assert bindings[0]["vservername"] == "LB_VS_A"


def test_bulk_bindings_resource_with_query_reads_the_data_under_the_right_key(tmp_path):
    """A valid bulk bindings resource (with a query string in the
    resource name, as the REAL collector uses for bulk bindings - see
    `config/lbvserver_rewritepolicy_binding?bulkbindings=yes` in the live
    fixture) used to read as a read gap. The file name was rightly built
    WITHOUT the query string, but the JSON key used to look up the payload
    kept the query string - and that key never exists in the file, so a
    valid file read as 'no list under the expected key'. Fix: use the same
    query-free name for BOTH."""
    (tmp_path / "objects").mkdir()
    (tmp_path / "bindings").mkdir()
    resource = "config/lbvserver_rewritepolicy_binding?bulkbindings=yes"
    obj = tmp_path / "objects" / "lbvserver_rewritepolicy_binding.json"
    obj.write_text(
        json.dumps({"lbvserver_rewritepolicy_binding": [{"policyname": "pol_a", "priority": "100"}]}),
        encoding="utf-8",
    )
    manifest = {
        "collectedAtUtc": "2026-08-19T10:00:00.0000000Z",
        "resources": {resource: {"status": "OK"}},
        "files": {},
    }
    (tmp_path / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(tmp_path)
    e = load_export(tmp_path)
    objs, gap = e.objects(resource)
    assert gap is None, f"onverwacht leesgat bij een geldige bulk-bindingsresource: {gap}"
    assert objs == [{"policyname": "pol_a", "priority": "100"}]


# ---------------------------------------------------------------------------
# A question during `status_ververs` can combine an OLD manifest with NEW
# object files.
#
# `load_export` reads the manifest ONCE; `Export.objects()`/`bindings()`
# open the corresponding files later, lazily. `status_ververs`
# deliberately runs the scan off-loop (a test elsewhere measures that
# responsiveness) - so a reader can fall between the manifest moment and
# the file moment, exactly when `_swap` (collect.py) swaps the export
# directory: current -> .vorig, new -> current. Whoever reads then gets
# the NEW file under the OLD manifest: new certificates under old
# statuses, stamped with the old collectedAtUtc. That is the falsely green
# outcome this product must rule out - a read gap belongs here, not mixed
# data.
# ---------------------------------------------------------------------------


def _write_export_version(dir_: Path, *, collected_at: str, cert_name: str) -> None:
    """Builds a complete, standalone export version - separate from
    `_build()` (which uses the same fixed collectedAtUtc for all tests
    above, and thus cannot produce two DISTINGUISHABLE manifest
    versions)."""
    (dir_ / "objects").mkdir(parents=True, exist_ok=True)
    (dir_ / "bindings").mkdir(parents=True, exist_ok=True)
    (dir_ / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": cert_name}]}), encoding="utf-8"
    )
    (dir_ / "export-manifest.json").write_text(
        json.dumps(
            {
                "collectedAtUtc": collected_at,
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(dir_)


def test_swap_during_the_read_of_an_object_file_yields_a_read_gap_not_mixed_data(
    tmp_path,
):
    """The core test: load the manifest of the OLD export, then swap the
    directory (the same two renames as `_swap`), and only then read the
    object file. The read must be a read gap - never the new data under
    the old manifest."""
    export_dir = tmp_path / "export"
    _write_export_version(export_dir, collected_at="2026-08-19T10:00:00.0000000Z", cert_name="cert_oud")
    e = load_export(export_dir)  # the OLD manifest is now pinned inside `e`

    previous = tmp_path / "export.vorig"
    export_dir.rename(previous)
    new_dir = tmp_path / "export.nieuw"
    _write_export_version(new_dir, collected_at="2026-08-20T09:00:00.0000000Z", cert_name="cert_nieuw_na_omwisseling")
    new_dir.rename(export_dir)

    objs, gap = e.objects("config/sslcertkey")
    assert objs == [], "de nieuwe data mag nooit onder het oude manifest naar buiten komen"
    assert gap is not None, "een omwisseling tijdens het lezen is een leesgat, geen stille read"


def test_swap_during_the_read_of_a_binding_file_yields_a_read_gap_even_when_the_hash_happens_to_match(
    tmp_path,
):
    """Sharper variant for `bindings()`: the hash verification against
    manifest.files already protects against a MODIFIED binding file, but
    not against this swap when the bindings happen to be UNCHANGED (same
    bytes, so same hash) while the rest of the export - and thus
    collectedAtUtc - has been replaced. Without a separate manifest
    identity check that slips silently through the hash check."""
    content = json.dumps(_by_parent({"LB_VS_A": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]}))
    hash_ = hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _write(dir_: Path, collected_at: str) -> None:
        (dir_ / "bindings").mkdir(parents=True, exist_ok=True)
        (dir_ / "objects").mkdir(parents=True, exist_ok=True)
        (dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(content, encoding="utf-8")
        (dir_ / "export-manifest.json").write_text(
            json.dumps(
                {
                    "collectedAtUtc": collected_at,
                    "resources": {"config/sslcertkey": {"status": "OK"}},
                    "files": {f"bindings/{BINDING_FILE}": hash_},
                }
            ),
            encoding="utf-8",
        )

    export_dir = tmp_path / "export"
    _write(export_dir, "2026-08-19T10:00:00.0000000Z")
    e = load_export(export_dir)

    previous = tmp_path / "export.vorig"
    export_dir.rename(previous)
    new_dir = tmp_path / "export.nieuw"
    _write(new_dir, "2026-08-20T09:00:00.0000000Z")  # same bindings, different manifest
    new_dir.rename(export_dir)

    bindings, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert bindings == []
    assert gap is not None, "hash-gelijkheid alleen is niet genoeg als de rest van de export is omgewisseld"


def test_manifest_vanishing_just_before_the_read_is_a_read_gap_not_a_crash(tmp_path, monkeypatch):
    """Second symptom of the same finding: if the read falls in the
    middle of `_swap`'s window in which `export/` briefly does not exist
    at all, `load_export` must not crash on a bare FileNotFoundError.
    Simulates the race by making `Path.exists()` LIE (yes, while the file
    is not there) - so the test is not coupled to whether the
    implementation uses `read_text` or `read_bytes`, only to the
    observable behavior."""
    dir_ = tmp_path / "export"
    dir_.mkdir()  # deliberately NO export-manifest.json: that IS the race

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "export-manifest.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None


def test_object_file_vanishing_just_before_the_read_is_a_read_gap_not_a_crash(tmp_path, monkeypatch):
    """The same TOCTOU class, now on the object file itself."""
    dir_ = _build(tmp_path)
    (dir_ / "objects" / "sslcertkey.json").unlink()

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "sslcertkey.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None


def test_binding_file_vanishing_just_before_the_read_is_a_read_gap_not_a_crash(tmp_path, monkeypatch):
    """The same TOCTOU class, now on the binding file: `bindings()` used
    to have NO try/except at all around `bestand.read_bytes()`."""
    dir_ = _build(tmp_path)
    (dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").unlink()

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "sslvserver_sslcertkey_binding.by-parent.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    e = load_export(dir_)
    _, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is not None


# ---------------------------------------------------------------------------
# `OSError.__str__()` carries the full absolute local
# path on Windows - an ACL-locked object/binding file, or the TOCTOU window
# above, put that path straight into `ReadGap.reason` at EVERY disclosure
# level (no name family collects a filesystem path). The two TOCTOU tests
# above already force the same OSError family through `read_bytes()`; these
# reuse that exact mechanism and add the premise+outcome check the class
# needs.
#
# NOTE on the premise check: `OSError.__str__()` embeds the filename via
# `repr()`, so on Windows every backslash is DOUBLED in the printed text -
# `str(tmp_path) in gap.reason` would therefore be False even on the LEAKING
# code, and prove nothing. `tmp_path.name` (one path SEGMENT, no separator)
# survives that escaping unchanged, so it is what these tests probe for -
# confirmed directly against a raw OSError first, so the premise does not
# depend on assuming that escaping quirk.
# ---------------------------------------------------------------------------


def test_object_file_read_error_names_no_local_path(tmp_path, monkeypatch):
    dir_ = _build(tmp_path)
    target = dir_ / "objects" / "sslcertkey.json"
    target.unlink()

    # Premise: a raw OSError from exactly this failure really does carry
    # the tmp_path directory name.
    try:
        target.read_bytes()
    except OSError as exc:
        assert tmp_path.name in str(exc)
    else:
        pytest.fail("premisse faalt: het bestand is nog leesbaar")

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "sslcertkey.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None  # premise: this really is a read gap
    assert tmp_path.name not in gap.reason, f"lokaal pad lekt in het leesgat: {gap.reason}"


def test_binding_file_read_error_names_no_local_path(tmp_path, monkeypatch):
    dir_ = _build(tmp_path)
    target = dir_ / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json"
    target.unlink()

    try:
        target.read_bytes()
    except OSError as exc:
        assert tmp_path.name in str(exc)  # premise
    else:
        pytest.fail("premisse faalt: het bestand is nog leesbaar")

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "sslvserver_sslcertkey_binding.by-parent.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    e = load_export(dir_)
    _, gap = e.bindings("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is not None  # premise
    assert tmp_path.name not in gap.reason, f"lokaal pad lekt in het leesgat: {gap.reason}"


# ---------------------------------------------------------------------------
# `_read_target_name` used to be the ONLY read of the export directory
# without a manifest identity check - the three reads above (manifest,
# object file, binding file) all verify that they still belong to the same
# manifest `load_export` was loaded with; the target-name read did not, and
# could thus attribute a target name to an export it never belonged to. The
# fix: scan-doel.txt carries the manifest hash next to the target name, and
# `_read_target_name` only returns a name when that hash matches the LOADED
# manifest.
# ---------------------------------------------------------------------------


def test_supplied_export_with_stale_scan_file_has_no_target_name(tmp_path):
    """Route a: there is only ONE export directory per server (see
    collect.py), so a SUPPLIED export can land in the same directory where
    an earlier scan left its scan-doel.txt. That old file belongs to a
    DIFFERENT manifest than the one just supplied - the recorded hash must
    no longer match, and the target name must honestly stay
    'niet vastgelegd' (None), never adopt the old target."""
    dir_ = _build(tmp_path)
    # An old scan-doel.txt from a previous scan ("lab"), with a hash
    # belonging to a manifest that no longer sits here - exactly what
    # remains when a supplied export is copied over it without cleaning up
    # this file.
    (dir_ / TARGET_FILE).write_text("lab\n" + "0" * 64 + "\n", encoding="utf-8")

    e = load_export(dir_)

    assert e.target_name is None, (
        "een doelnaam mag nooit gegokt worden vanuit een scan-doel.txt dat bij "
        "een ander manifest hoort dan het geladen manifest"
    )


def test_swap_between_manifest_read_and_target_name_read_yields_no_target_name(tmp_path, monkeypatch):
    """Route b: `load_export` reads the manifest bytes first and only
    then scan-doel.txt. If a swap lands exactly in between, a naive read
    would combine the NEW scan-doel.txt (new target name, new hash) with
    the OLD, already loaded manifest (old collectedAtUtc). The identity
    check must stop that: the target name only counts when the recorded
    hash belongs to the manifest THIS object actually loaded."""
    dir_ = _build(tmp_path, resources={"config/sslcertkey": {"status": "OK"}})
    old_manifest_bytes = (dir_ / "export-manifest.json").read_bytes()
    old_hash = hashlib.sha256(old_manifest_bytes).hexdigest()
    (dir_ / TARGET_FILE).write_text(f"lab\n{old_hash}\n", encoding="utf-8")

    original_read_bytes = Path.read_bytes

    def swap_after_manifest_read(self, *a, **k):
        content = original_read_bytes(self, *a, **k)
        if self.name == "export-manifest.json":
            # The swap lands here: AFTER the manifest has been read, but
            # BEFORE scan-doel.txt is read (that happens later in
            # load_export). Both the manifest and scan-doel.txt change -
            # just like with a real _swap.
            new_manifest = {
                "collectedAtUtc": "2026-08-20T09:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}},
                "files": {},
            }
            new_bytes = json.dumps(new_manifest).encode("utf-8")
            (dir_ / "export-manifest.json").write_bytes(new_bytes)
            new_hash = hashlib.sha256(new_bytes).hexdigest()
            (dir_ / TARGET_FILE).write_text(f"prod\n{new_hash}\n", encoding="utf-8")
        return content

    monkeypatch.setattr(Path, "read_bytes", swap_after_manifest_read)

    e = load_export(dir_)

    assert e.collected_at == "2026-08-19T10:00:00.0000000Z", "het OUDE, geladen manifest moet gelden"
    assert e.target_name is None, (
        "de nieuwe doelnaam ('prod') hoort bij het NIEUWE manifest, niet bij het "
        "oude manifest dat hier daadwerkelijk geladen is - hij mag dus nooit "
        "worden toegeschreven aan deze Export"
    )


def _build_empty_resource(dir_: Path, *, collected_at: str) -> Path:
    """Standalone export version with an EMPTY-status resource, for the
    identity-check test on the EMPTY branch of objects() below."""
    (dir_ / "objects").mkdir(parents=True, exist_ok=True)
    (dir_ / "bindings").mkdir(parents=True, exist_ok=True)
    (dir_ / "export-manifest.json").write_text(
        json.dumps(
            {
                "collectedAtUtc": collected_at,
                "resources": {"config/sslcertkey": {"status": "EMPTY"}},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(dir_)
    return dir_


def test_swap_during_the_read_of_an_empty_resource_yields_a_read_gap(tmp_path):
    """Second half of the fix: the EMPTY branch of objects() did - unlike
    the OK branch (see the swap tests above) - NO identity check. A swap
    between `load_export()` and the question for an EMPTY resource must
    therefore also yield a read gap here, not silently 'nothing found'
    under a manifest that has meanwhile been replaced."""
    export_dir = tmp_path / "export"
    _build_empty_resource(export_dir, collected_at="2026-08-19T10:00:00.0000000Z")
    e = load_export(export_dir)

    previous = tmp_path / "export.vorig"
    export_dir.rename(previous)
    new_dir = tmp_path / "export.nieuw"
    _build_empty_resource(new_dir, collected_at="2026-08-20T09:00:00.0000000Z")
    new_dir.rename(export_dir)

    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None, "EMPTY zonder identiteitscontrole verstopt een omwisseling"


# ---------------------------------------------------------------------------
# The manifest itself must be positively checked for SHAPE: valid JSON is
# not a manifest with a valid shape. A top-level LIST, a `resources` that
# is itself a list, a STRING entry for a resource, or a non-empty `files`
# LIST all used to give a bare AttributeError far from the read. Every test
# below goes through the PUBLIC call (`load_export` +
# `.objects()`/`.bindings()`), not through direct field manipulation on
# Export, and proves: no crash, an honest read gap.
# ---------------------------------------------------------------------------


def test_manifest_with_a_list_at_top_level_is_a_read_gap_not_a_crash(tmp_path):
    """Shape 1: the manifest file is valid JSON, but at top level a LIST
    instead of an object - `rauw.get("resources", {})` in `load_export`
    used to crash bare on an AttributeError here, BEFORE any Export object
    even existed."""
    dir_ = _build(tmp_path)
    (dir_ / "export-manifest.json").write_text(
        json.dumps([{"resources": {"config/sslcertkey": {"status": "OK"}}, "files": {}}]),
        encoding="utf-8",
    )
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_resources_as_list_in_the_manifest_is_a_read_gap_not_a_crash(tmp_path):
    """Shape 2: the manifest is an object, but `resources` itself is a
    (non-empty) LIST instead of an object. `load_export` used to build an
    Export from this without checking, with `resources` as a list; the
    crash only landed at the next `.get()` in `Export.status()`."""
    dir_ = _build(tmp_path)
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"] = ["config/sslcertkey"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_resource_entry_as_string_is_a_read_gap_not_a_crash(tmp_path):
    """Shape 3: `resources` is itself a valid object, but the entry FOR
    THIS ONE resource is a bare STRING ("OK") instead of
    `{"status": "OK"}`. The entry used to be truthy enough to pass the
    `if not vermelding` guard, after which `vermelding.get("status", ...)`
    crashed - a string has no `.get`."""
    dir_ = _build(tmp_path, resources={"config/sslcertkey": "OK"})
    e = load_export(dir_)
    _, gap = e.objects("config/sslcertkey")
    assert gap is not None
    assert "niet bruikbaar" in gap.reason.lower()


def test_files_as_list_in_the_manifest_is_a_read_gap_not_a_crash(tmp_path):
    """Shape 4: `files` is a (non-empty) LIST instead of an object.
    `bindings()` used to crash on `self.file_hashes.get(...)` as soon as a
    hash was asked for - a list has no `.get`."""
    dir_ = _build(tmp_path)
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = ["0" * 64]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    bindings, gap = e.bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None
    assert "niets is te vertrouwen" in gap.reason.lower()


def test_falsy_non_dict_entry_is_reported_as_invalid_not_as_missing(tmp_path):
    """A resource whose manifest entry is present but falsy and not a dict
    (here: an empty string) IS in the manifest - the read gap must say the
    entry is unusable, not claim the resource is absent."""
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": ""}))
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None
    assert "niet bruikbaar" in gap.reason.lower()
    assert "niet in het manifest" not in gap.reason


def test_null_entry_is_reported_as_invalid_not_as_missing(tmp_path):
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": None}))
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None
    assert "niet bruikbaar" in gap.reason.lower()
    assert "niet in het manifest" not in gap.reason


def test_empty_dict_entry_is_present_but_carries_no_status(tmp_path):
    """An empty object entry is IN the manifest; without a status the read
    is unusable (ONBEKEND) - it is not 'absent from the manifest'."""
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": {}}))
    objs, gap = e.objects("config/sslcertkey")
    assert objs == []
    assert gap is not None
    assert "niet bruikbaar" in gap.reason.lower()
    assert "ONBEKEND" in gap.reason


# ---------------------------------------------------------------------------
# Kruiscontrole van de parentlijst tegen de objectbron.
#
# Gemeten op de echte labexport (2026-08-27): `objects/sslvserver.json`
# draagt DRIE virtuele servers, `bindings/sslvserver_sslcertkey_binding
# .by-parent.json` draagt TWEE parents. Een parent die AANWEZIG is met een
# onbruikbare outcome faalt netjes closed (`_flatten_by_parent`); een parent
# die HELEMAAL ONTBREEKT was onzichtbaar - de vlakke lijst kwam compleet
# ogend naar boven, zonder leesgat. Dat is een eigen faalklasse en die
# hoort hier gemeten te worden.
# ---------------------------------------------------------------------------


def _with_parent_objects(dir_: Path, names: list[str], status: str = "OK", key: str = "vservername") -> Path:
    """Zet de OBJECTBRON van de parents (`objects/sslvserver.json` plus de
    manifestvermelding `config/sslvserver`) naast het bindingsbestand - net
    zoals de echte collector dat doet."""
    (dir_ / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{key: n} for n in names]}), encoding="utf-8"
    )
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"]["config/sslvserver"] = {"status": status}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(dir_)
    return dir_


def test_a_fully_covered_parent_list_yields_no_read_gap(tmp_path):
    """Tegenproef eerst: staat elke virtuele server uit de objectbron ook
    als parent in het bindingsbestand, dan is de lijst aantoonbaar compleet
    en hoort er GEEN leesgat te komen. Zonder deze test zou een uitbreiding
    die altijd een leesgat meldt hier groen blijven."""
    dir_ = _with_parent_objects(_build(tmp_path), ["LB_VS_A"])
    e = load_export(dir_)
    dekking = e.binding_parents(BINDING_FILE)
    assert dekking.gaps == ()
    assert dekking.names == ("LB_VS_A",)


def test_a_parent_object_without_a_binding_entry_is_a_read_gap(tmp_path):
    """De gemeten faalklasse: LB_VS_B staat in de objectbron maar draagt
    geen parent-vermelding in het bindingsbestand. Zijn bindingen zijn dus
    nooit gelezen - en dan is 'dit zijn alle geraakte diensten' niet vast
    te stellen."""
    dir_ = _with_parent_objects(_build(tmp_path), ["LB_VS_A", "LB_VS_B"])
    e = load_export(dir_)
    dekking = e.binding_parents(BINDING_FILE)
    assert len(dekking.gaps) == 1, f"onverwachte leesgaten: {dekking.gaps}"
    gat = dekking.gaps[0]
    assert "LB_VS_B" in gat.reason
    assert "LB_VS_A" not in gat.reason, "de gedekte parent hoort niet in het leesgat"
    assert "config/sslvserver" in gat.reason, "de reden moet de objectbron benoemen"


def test_a_binding_parent_the_object_source_does_not_know_is_a_read_gap(tmp_path):
    """Het spiegelbeeld: het bindingsbestand draagt een parent die de
    objectbron niet kent. Ook dat is tegenspraak tussen twee bronnen uit
    hetzelfde manifest, en dus niet vast te stellen welke van de twee
    klopt."""
    dir_ = _with_parent_objects(_build(tmp_path), [])
    e = load_export(dir_)
    dekking = e.binding_parents(BINDING_FILE)
    assert len(dekking.gaps) == 1, f"onverwachte leesgaten: {dekking.gaps}"
    assert "LB_VS_A" in dekking.gaps[0].reason


def test_the_parent_list_without_an_object_source_cannot_be_cross_checked(tmp_path):
    """Zonder objectbron is de parentlijst niet te kruiscontroleren. Dat is
    een ANDERE reden dan een ontbrekende parent en moet dat ook zeggen -
    fail-closed op wat je niet kunt meten, zonder te doen alsof je een
    verschil gemeten hebt."""
    e = load_export(_build(tmp_path))  # geen config/sslvserver in het manifest
    dekking = e.binding_parents(BINDING_FILE)
    assert len(dekking.gaps) == 1
    reden = dekking.gaps[0].reason
    assert "kruiscontroleren" in reden
    assert "config/sslvserver" in reden
    # Uit een bron die niet gelezen is komt geen enkele naam; wat overblijft
    # zijn de parentnamen die het bindingsbestand ZELF draagt.
    assert dekking.names == ("LB_VS_A",)


def test_an_unusable_parent_name_in_the_object_source_is_a_read_gap(tmp_path):
    """Fail-closed geldt ook voor het IDENTITEITSVELD waarop vergeleken
    wordt: een object waarvan de naam geen bruikbare tekst is, kan niet
    tegen de parentlijst gelegd worden."""
    dir_ = _build(tmp_path)
    (dir_ / "objects" / "sslvserver.json").write_text(
        json.dumps({"sslvserver": [{"vservername": "LB_VS_A"}, {"vservername": None}]}),
        encoding="utf-8",
    )
    manifest_path = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"]["config/sslvserver"] = {"status": "OK"}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(dir_)
    e = load_export(dir_)
    dekking = e.binding_parents(BINDING_FILE)
    assert len(dekking.gaps) == 1
    # R3H-2: parentKey is a value from the binding file and is described,
    # never repeated; the object stays findable by its position.
    assert "het veld dat parentKey noemt" in dekking.gaps[0].reason
    assert "vservername" not in dekking.gaps[0].reason
    assert "(object 2)" in dekking.gaps[0].source
    assert "None" not in dekking.gaps[0].reason, "de ruwe waarde hoort niet gereproduceerd te worden"


def test_binding_parents_carries_the_parent_names_for_the_name_collection(tmp_path):
    """De parentnamen zijn echte objectnamen van deze appliance en moeten
    dus ook de naamverzameling van de openheidslaag bereiken - anders lekt
    een naam die alleen in een leesgat staat in de stand 'beperkt'."""
    dir_ = _with_parent_objects(_build(tmp_path), ["LB_VS_A", "LB_VS_B"])
    e = load_export(dir_)
    assert set(e.binding_parents(BINDING_FILE).names) == {"LB_VS_A", "LB_VS_B"}


# ---------------------------------------------------------------------------
# De INHOUD van een bindingsbestand mag geen pad worden.
#
# `binding_parents()` bouwt `config/<parentResource>` uit een veld dat in het
# bindingsbestand STAAT, en `objects()` saneerde dat met
# `resource.split("/")[-1]`. Die sanering splitst niet op de backslash, en op
# Windows is dat wel degelijk een padscheider. Gemeten op 2026-08-27:
# parentResource = "..\\..\\geheim" opende, decodeerde en ontleedde
# `<tmp>\geheim.json` - BUITEN de exportmap. De inhoud lekte niet, maar het
# verschil tussen "ontbreekt", "kon niet gelezen worden" en "geen lijst onder
# de sleutel" verraadt bestaan en leesbaarheid van een willekeurig pad, en die
# tekst reist het antwoord in. `export.py` beschrijft een export expliciet als
# iets dat AANGELEVERD kan zijn, dus dit is een reeel scenario.
#
# De reparatie is POSITIEF valideren (alleen letters, cijfers en liggende
# streepjes) in plaats van saneren, op twee plekken: bij de bron
# (`binding_parents`) en in `objects()` zelf - dat is waar de sanering faalde,
# en een aanroeper die morgen dezelfde fout maakt hoort daar geen nieuw gat te
# openen.
# ---------------------------------------------------------------------------


def _spy_on_reads(monkeypatch) -> list[Path]:
    """Legt elk bestand vast dat via `Path.read_bytes` echt GEOPEND wordt.

    Een leesgat met de juiste tekst bewijst nog niet dat er niets geopend is;
    dit doet dat wel. Dit is precies de handeling die gemeten werd: het
    bestand werd geopend, gedecodeerd en ontleed."""
    gelezen: list[Path] = []
    echt = Path.read_bytes

    def spion(self, *args, **kwargs):
        gelezen.append(Path(self))
        return echt(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", spion)
    return gelezen


def _assert_nothing_outside_was_opened(gelezen: list[Path], export_dir: Path) -> None:
    binnen = export_dir.resolve()
    for pad in gelezen:
        opgelost = Path(pad).resolve()
        assert opgelost == binnen or binnen in opgelost.parents, f"buiten de exportmap geopend: {opgelost}"


def _with_parent_resource(dir_: Path, parent_resource: str) -> Path:
    """Zet `parentResource` in het bindingsbestand op een AANGELEVERDE waarde,
    herstelt de hash in het manifest en zet de bijbehorende resource op OK -
    een aangeleverde export draagt immers een manifest dat bij zijn eigen
    bestanden past. Zonder die twee stappen strandt de aanval al eerder en
    meet de test niets."""
    pad = dir_ / "bindings" / BINDING_FILE
    doc = json.loads(pad.read_text(encoding="utf-8"))
    doc["parentResource"] = parent_resource
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest["resources"][f"config/{parent_resource}"] = {"status": "OK"}
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    return dir_


def _plant_target_outside(tmp_path: Path) -> Path:
    """Legt het doelwit van de gemeten ontsnapping klaar: `<tmp>\\geheim.json`,
    een map HOGER dan de exportmap, met herkenbare inhoud."""
    buiten = tmp_path.parent / "geheim.json"
    buiten.write_text(json.dumps({"geheim": [{"veld": "GEHEIME_INHOUD"}]}), encoding="utf-8")
    return buiten


def _traversal_vormen(tmp_path: Path) -> dict[str, str]:
    """De vier vormen die minstens gedekt moeten zijn. `absoluut` is bewust in
    Windows-vorm (backslashes), want een absoluut pad MET schuine strepen wordt
    door `split("/")[-1]` toevallig al onschadelijk gemaakt - en een toevallige
    dekking is geen dekking."""
    return {
        "backslash": "..\\..\\geheim",
        "schuine-streep": "../../geheim",
        "absoluut": str(tmp_path.parent / "geheim"),
        "punt": "sslcertkey.json",
    }


@pytest.mark.parametrize("vorm", ["backslash", "schuine-streep", "absoluut", "punt"])
def test_a_parent_resource_that_is_no_object_name_opens_nothing(tmp_path, monkeypatch, vorm):
    """De gemeten faalklasse. Geen van deze vier vormen is een objectnaam, dus
    geen van de vier mag een bestand openen - ook niet een dat toevallig binnen
    de exportmap valt."""
    parent_resource = _traversal_vormen(tmp_path)[vorm]
    _plant_target_outside(tmp_path)
    dir_ = _with_parent_resource(_build(tmp_path), parent_resource)
    e = load_export(dir_)
    gelezen = _spy_on_reads(monkeypatch)
    dekking = e.binding_parents(BINDING_FILE)

    _assert_nothing_outside_was_opened(gelezen, dir_)
    assert len(dekking.gaps) == 1, f"onverwachte leesgaten: {dekking.gaps}"
    reden = dekking.gaps[0].reason
    assert "vorm van een objectnaam" in reden, f"onverwachte reden: {reden}"
    tekst = f"{dekking.gaps[0].source} {reden}"
    assert "GEHEIM" not in tekst
    assert parent_resource not in tekst, "de waarde hoort niet gereproduceerd te worden"
    # De parentlijst zelf is wel gewoon gelezen; alleen de kruiscontrole valt
    # weg. Fail-closed mag het antwoord niet leegtrekken.
    assert dekking.names == ("LB_VS_A",)


def test_the_refusal_reads_the_same_for_an_existing_and_a_non_existing_target(tmp_path, monkeypatch):
    """De kern van het lek was niet de INHOUD maar het ONDERSCHEID: "ontbreekt"
    versus "kon niet gelezen worden" versus "geen lijst onder de sleutel"
    verraadt bestaan en leesbaarheid van een willekeurig pad. Twee weigeringen
    - een met en een zonder bestand op het doelpad - moeten daarom letterlijk
    dezelfde tekst geven."""
    # Twee GESCHEIDEN bomen, want `..\..\geheim.json` vanuit `<basis>/export/
    # objects/` wijst naar `<basis>/geheim.json`. Delen ze een basis, dan wijzen
    # beide naar hetzelfde bestand en meet de test niets.
    bestaat = tmp_path / "met-doelwit" / "export"
    ontbreekt = tmp_path / "zonder-doelwit" / "export"
    for basis in (bestaat, ontbreekt):
        basis.mkdir(parents=True)
    (bestaat.parent / "geheim.json").write_text(json.dumps({"geheim": []}), encoding="utf-8")
    assert not (ontbreekt.parent / "geheim.json").exists()

    redenen = []
    for basis in (bestaat, ontbreekt):
        dir_ = _with_parent_resource(_build(basis), "..\\..\\geheim")
        dekking = load_export(dir_).binding_parents(BINDING_FILE)
        assert len(dekking.gaps) == 1
        redenen.append(dekking.gaps[0].reason)
    assert redenen[0] == redenen[1], (
        "de weigering mag geen bestaan of leesbaarheid verraden;"
        f" met doelwit: {redenen[0]!r}, zonder doelwit: {redenen[1]!r}"
    )


def test_objects_itself_refuses_a_resource_that_is_no_object_name(tmp_path, monkeypatch):
    """De sanering faalde in `objects()`; daar hoort de reparatie dus ook te
    staan. Een aanroeper die morgen opnieuw een resourcenaam uit bestandsinhoud
    samenstelt, mag daarmee geen nieuw gat openen."""
    _plant_target_outside(tmp_path)
    dir_ = _build(tmp_path)
    manifest_pad = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["resources"]["config/..\\..\\geheim"] = {"status": "OK"}
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    e = load_export(dir_)
    # De EXPORTGRENS (load_export) weigert deze sleutel sinds taak 3b al bij
    # het laden, dus hij staat niet meer in `resources`. Deze test meet de
    # TWEEDE laag: dat `objects()` zelf weigert, ook wanneer de sleutel langs
    # de grens heen in de vermeldingen terechtkomt (een aanroeper die zelf een
    # `Export` bouwt, of die morgen weer een resourcenaam uit bestandsinhoud
    # samenstelt). Zonder deze regel zou de test de grens meten in plaats van
    # de laag waar hij over gaat.
    e.resources["config/..\\..\\geheim"] = {"status": "OK"}
    gelezen = _spy_on_reads(monkeypatch)

    objs, gap = e.objects("config/..\\..\\geheim")

    _assert_nothing_outside_was_opened(gelezen, dir_)
    assert objs == []
    assert gap is not None
    assert "vorm van een objectnaam" in gap.reason, f"onverwachte reden: {gap.reason}"
    # Ook de BRON van een leesgat reist het antwoord in; daar hoort de
    # geweigerde waarde dus evenmin in te staan.
    tekst = f"{gap.source} {gap.reason}"
    assert "GEHEIM" not in tekst
    assert "geheim" not in tekst, "de waarde hoort niet gereproduceerd te worden"


# ---------------------------------------------------------------------------
# De DERDE gedocumenteerde uitkomst van `binding_parents`, op zijn REDEN.
#
# Overlevende mutatie (2026-08-27): `if parent_resource is None or
# parent_key is None:` -> `if False:` hield de hele suite groen. De
# gedegradeerde versie geeft nog wel een leesgat, maar met de VERKEERDE reden -
# via `objects("config/None")` komt er "resource staat niet in het manifest"
# uit, wat een uitspraak is over het manifest terwijl het probleem in het
# BINDINGSBESTAND zit. Van de drie uitkomsten die deze functie documenteert was
# "de vergelijking kan niet gemaakt worden omdat het bestand geen bron
# declareert" nergens op zijn reden getoetst. Het bestaan van een leesgat
# vastpinnen is niet genoeg; de reden is hier het product.
# ---------------------------------------------------------------------------


def _drop_binding_field(dir_: Path, veld: str) -> Path:
    """Haalt een veld uit het bindingsbestand en herstelt de hash in het
    manifest - anders strandt de lezing al op de hashcontrole en meet de test
    iets anders dan bedoeld."""
    pad = dir_ / "bindings" / BINDING_FILE
    doc = json.loads(pad.read_text(encoding="utf-8"))
    del doc[veld]
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    return dir_


@pytest.mark.parametrize("veld", ["parentResource", "parentKey"])
def test_a_binding_file_without_a_declared_parent_source_says_exactly_that(tmp_path, veld):
    """De objectbron staat er hier WEL (config/sslvserver, gedekt), dus alles
    wat misgaat komt uit het bindingsbestand zelf. De reden moet dat ook
    zeggen: welk veld ontbreekt, en niet iets over het manifest."""
    dir_ = _drop_binding_field(_with_parent_objects(_build(tmp_path), ["LB_VS_A"]), veld)
    dekking = load_export(dir_).binding_parents(BINDING_FILE)

    assert len(dekking.gaps) == 1, f"onverwachte leesgaten: {dekking.gaps}"
    reden = dekking.gaps[0].reason
    assert f"geen bruikbare {veld}" in reden, f"onverwachte reden: {reden}"
    # De degradatie die 551 tests overleefde, geeft juist deze twee: een
    # verwijzing naar het manifest en een verzonnen resourcenaam
    # ("config/None"). Beide horen hier niet te staan.
    assert "manifest" not in reden, "dit is geen uitspraak over het manifest"
    assert "config/" not in reden, "er is geen objectbron om naar te verwijzen"
    # Wat WEL gelezen is blijft staan: fail-closed op de kruiscontrole mag de
    # parentlijst zelf niet weggooien.
    assert dekking.names == ("LB_VS_A",)


def test_a_legitimate_parent_resource_still_cross_checks(tmp_path):
    """Tegenproef: de positieve toets mag de gewone weg niet dichtzetten.
    Zonder deze test zou een versie die ALLES weigert hierboven groen
    blijven."""
    dir_ = _with_parent_objects(_build(tmp_path), ["LB_VS_A", "LB_VS_B"])
    dekking = load_export(dir_).binding_parents(BINDING_FILE)
    assert len(dekking.gaps) == 1
    assert "LB_VS_B" in dekking.gaps[0].reason
    assert "vorm van een objectnaam" not in dekking.gaps[0].reason


# ---------------------------------------------------------------------------
# Een ONTBREKENDE sleutel is geen JSON-null.
#
# `shape_of` noemt beide "een lege waarde (JSON null)" - een uitspraak over de
# INHOUD, die bij een ontbrekende sleutel helemaal niet gedaan kan worden.
# impact.py onderscheidt die twee al met een _MISSING-schildwacht ("de sleutel
# ontbreekt"); binding_parents deed dat niet, en dat is precies het soort
# gelijkschakeling waar dit product op afgerekend hoort te worden.
# ---------------------------------------------------------------------------


def _binding_with_first_parent(dir_: Path, parent: dict) -> Path:
    """Vervangt de eerste parent-vermelding in het bindingsbestand en herstelt
    de hash in het manifest."""
    pad = dir_ / "bindings" / BINDING_FILE
    doc = json.loads(pad.read_text(encoding="utf-8"))
    doc["parents"][0] = parent
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = dir_ / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    return dir_


def _basis(tmp_path: Path, naam: str) -> Path:
    """Een eigen, bestaande basismap per variant - `_build` maakt zelf geen
    tussenliggende mappen aan."""
    pad = tmp_path / naam
    pad.mkdir()
    return pad


def _first_gap_reason(dir_: Path) -> str:
    dekking = load_export(dir_).binding_parents(BINDING_FILE)
    assert dekking.gaps, "zonder leesgat meet deze test niets"
    return dekking.gaps[0].reason


def test_a_parent_entry_distinguishes_a_missing_name_from_a_json_null(tmp_path):
    lege_data = {"data": {"sslvserver_sslcertkey_binding": []}, "outcome": "OK"}
    ontbreekt = _binding_with_first_parent(_build(_basis(tmp_path, "ontbreekt")), dict(lege_data))
    null = _binding_with_first_parent(_build(_basis(tmp_path, "null")), {"parentName": None, **lege_data})

    reden_ontbreekt = _first_gap_reason(ontbreekt)
    reden_null = _first_gap_reason(null)

    assert "de sleutel ontbreekt" in reden_ontbreekt, f"onverwachte reden: {reden_ontbreekt}"
    assert "JSON null" not in reden_ontbreekt, "over een sleutel die er niet is valt niets te zeggen"
    assert "JSON null" in reden_null, f"onverwachte reden: {reden_null}"
    assert "parentName" in reden_ontbreekt and "parentName" in reden_null


def test_an_object_in_the_source_distinguishes_a_missing_key_from_a_json_null(tmp_path):
    def _bron(basis: Path, object_: dict) -> Path:
        dir_ = _build(basis)
        (dir_ / "objects" / "sslvserver.json").write_text(json.dumps({"sslvserver": [object_]}), encoding="utf-8")
        manifest_pad = dir_ / "export-manifest.json"
        manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
        manifest["resources"]["config/sslvserver"] = {"status": "OK"}
        manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
        seal_manifest(dir_)
        return dir_

    reden_ontbreekt = _first_gap_reason(_bron(_basis(tmp_path, "ontbreekt"), {"iets_anders": "x"}))
    reden_null = _first_gap_reason(_bron(_basis(tmp_path, "null"), {"vservername": None}))

    assert "de sleutel ontbreekt" in reden_ontbreekt, f"onverwachte reden: {reden_ontbreekt}"
    assert "JSON null" not in reden_ontbreekt
    assert "JSON null" in reden_null, f"onverwachte reden: {reden_null}"
    # R3H-2: the field is described, its name (parentKey, a value from the
    # binding file) is not repeated - the distinction above stays.
    assert "het veld dat parentKey noemt" in reden_ontbreekt and "het veld dat parentKey noemt" in reden_null
    assert "vservername" not in reden_ontbreekt and "vservername" not in reden_null


# ---------------------------------------------------------------------------
# The read-gap idiom above ("de sleutel ontbreekt" if raw is
# MISSING else shape_of(raw)) used to be a byte-identical one-liner copied
# into five modules (export.py, ha.py, hidden_rules.py, impact.py, names.py)
# - six call sites in total, since impact.py had it twice. The module that
# once forgot to copy it reproduced the defect the two tests above exist to
# catch. This is the ONE consolidated helper every one of those six sites
# now goes through: a primitive on a raw value already fetched
# (`shape_or_missing`) plus a thin container wrapper
# (`shape_or_missing_at`) that calls it - not two independent
# implementations - and the ONE pinned sentence (`KEY_MISSING_TEXT`) both
# use, so it can no longer drift half-updated across five files.
# ---------------------------------------------------------------------------


def test_key_missing_text_is_pinned():
    """The exact sentence, pinned once, in the one place it is now defined.
    Every one of the six former copies used this literal string - a change
    here is therefore a deliberate product-surface change, never an
    accident five files over."""
    assert export_module.KEY_MISSING_TEXT == "de sleutel ontbreekt"


def test_missing_is_a_single_shared_sentinel_object():
    """Eight modules used to each define their OWN `_MISSING = object()`.
    Two different sentinel objects for the same meaning is the same defect
    one layer down - so this must be ONE object, and every
    consumer's own name for it must be THIS object, not a fresh one with the
    same meaning.

    The previous version of this test
    (`assert export_module.MISSING is export_module.MISSING`) tested
    Python's own identity operator on a single name - it could not fail no
    matter what any consumer module did, so it proved nothing about the
    invariant its name and docstring claimed. This version imports every
    consumer and checks ITS sentinel against `export.MISSING` by identity -
    the exact probe that caught three
    modules (`collect.py`, `dienst.py`, `overzicht.py`) silently keeping
    their own fresh `object()` after an earlier fix claimed they shared
    one. `ha.py`, `hidden_rules.py` and `impact.py` keep a local `_MISSING`
    alias because they use it more broadly than the read-gap idiom;
    `names.py` imports the public `MISSING` name directly instead."""
    from nsmcp import collect, dienst, ha, hidden_rules, impact, names, overzicht

    aliased = (collect, dienst, ha, hidden_rules, impact, overzicht)
    mismatched = [m.__name__ for m in aliased if m._MISSING is not export_module.MISSING]
    assert mismatched == [], f"these modules hold a DIFFERENT object than export.MISSING: {mismatched}"
    assert names.MISSING is export_module.MISSING


def test_shape_or_missing_names_the_absent_key_with_the_pinned_sentence():
    """The primitive, on the MISSING sentinel itself: the pinned sentence,
    never shape_of's wording for a value that was never there."""
    assert export_module.shape_or_missing(export_module.MISSING) == "de sleutel ontbreekt"


def test_shape_or_missing_names_the_shape_of_a_present_value():
    """The primitive, on anything else: shape_of's verdict, byte for byte -
    delegation, not a second implementation of the shape rules."""
    for value in (42, None, True, [], {}, "geheime waarde", "   "):
        assert export_module.shape_or_missing(value) == export_module.shape_of(value)


def test_shape_or_missing_at_is_the_container_form_of_the_same_primitive():
    """The thin container wrapper: container.get(key, MISSING) fed straight
    into shape_or_missing - the two call SHAPES family A used (container +
    key, and a raw value already fetched) share one decision."""
    assert export_module.shape_or_missing_at({}, "ontbrekend") == "de sleutel ontbreekt"
    assert export_module.shape_or_missing_at({"veld": [1, 2, 3]}, "veld") == export_module.shape_of([1, 2, 3])
    assert export_module.shape_or_missing_at({"veld": None}, "veld") == export_module.shape_of(None)


def test_key_missing_text_appears_nowhere_else_in_src_as_a_stray_copy():
    """The pinned sentence lives in exactly THREE files under `src/nsmcp/`:
    its ONE definition (`export.py`'s `KEY_MISSING_TEXT`), and the two
    FAMILY B readers that legitimately hard-code the same wording for their
    own, measured correction of `shape_of` (`dienst._shape`,
    `collect._phase_shape` - see their docstrings; the design's Global
    Constraints forbid folding FAMILY B into FAMILY A).

    A SEVENTH silent copy of the FAMILY A
    one-liner (`overzicht.py:193`) survived an earlier pass because nothing
    forbade a stray copy of the literal from reappearing outside the
    consolidated helper. This is that guard - an eighth consumer that writes
    the phrase out by hand instead of calling `shape_or_missing` /
    `shape_or_missing_at` now fails here first, before it ever reaches
    production."""
    root = Path(__file__).resolve().parent.parent / "src" / "nsmcp"
    allowed = {"export.py", "dienst.py", "collect.py"}
    offenders = [
        path.name
        for path in sorted(root.glob("*.py"))
        if path.name not in allowed and export_module.KEY_MISSING_TEXT in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"stray copy of the pinned sentence in: {offenders}"


# ---------------------------------------------------------------------------
# `single()` and `running_config_lines()` - both measured against the REAL
# collector export in `tests/fixtures/lab-export-vpx-20260826/`, because both
# exist precisely because the synthetic fixtures above did not match it: the
# real `config/nsversion` carries an OBJECT (not a list), and the three
# SAML/LSN conditions are not collected as objects at all - they sit in the
# running config the export already carries.
# ---------------------------------------------------------------------------

LIVE_EXPORT = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


def _live_copy(tmp_path: Path) -> Path:
    """A writable copy of the live export, so a test may manipulate it."""
    target = tmp_path / "export"
    shutil.copytree(LIVE_EXPORT, target)
    return target


def _rewrite_manifest(directory: Path, change) -> None:
    path = directory / "export-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    change(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def test_single_reads_the_object_shape_of_the_live_nsversion(tmp_path):
    e = load_export(LIVE_EXPORT)
    obj, gap = e.single("config/nsversion")
    assert gap is None, f"onverwacht leesgat: {gap}"
    assert obj is not None
    assert obj["version"].startswith("NetScaler NS14.1: Build 72.57.nc")


def test_single_also_accepts_a_list_with_exactly_one_object(tmp_path):
    e = load_export(_build(tmp_path))
    obj, gap = e.single("config/sslcertkey")
    assert gap is None
    assert obj["certkey"] == "cert_a"


def test_single_refuses_a_key_that_carries_more_than_one_object(tmp_path):
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "a"}, {"certkey": "b"}]}), encoding="utf-8"
    )
    seal_manifest(directory)
    obj, gap = load_export(directory).single("config/sslcertkey")
    assert obj is None
    assert gap is not None
    assert "draagt geen enkel object onder de verwachte sleutel 'sslcertkey'" in gap.reason


def test_single_refuses_a_key_that_carries_no_object_at_all(tmp_path):
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(json.dumps({"sslcertkey": "geen object"}), encoding="utf-8")
    seal_manifest(directory)
    obj, gap = load_export(directory).single("config/sslcertkey")
    assert obj is None
    assert gap is not None
    assert "draagt geen enkel object onder de verwachte sleutel 'sslcertkey'" in gap.reason


def test_single_inherits_the_status_check_of_objects(tmp_path):
    e = load_export(_build(tmp_path, resources={"config/sslcertkey": {"status": "RBAC_DENIED"}}))
    obj, gap = e.single("config/sslcertkey")
    assert obj is None
    assert gap is not None and "RBAC_DENIED" in gap.reason


def test_running_config_of_the_live_export_is_read_and_verified(tmp_path):
    lines, gap = load_export(LIVE_EXPORT).running_config_lines()
    assert gap is None, f"onverwacht leesgat: {gap}"
    assert len(lines) == 333
    assert lines[0].startswith("#NS14.1 Build 72.57")
    assert not lines[0].endswith("\n")


def test_a_manipulated_running_config_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    path = directory / "parsed" / "runningconfig.txt"
    path.write_bytes(path.read_bytes() + b"add authentication samlAction SNEAKY\r\n")
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None
    assert "komt niet overeen met het manifest" in gap.reason


def test_running_config_without_a_hash_in_the_manifest_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(directory, lambda m: m["files"].pop("parsed/runningconfig.txt"))
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None
    assert "manifest draagt geen hash voor parsed/runningconfig.txt" in gap.reason


def test_running_config_not_usably_in_the_manifest_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(
        directory,
        lambda m: m["resources"].__setitem__("config/nsrunningconfig", {"status": "RBAC_DENIED"}),
    )
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None and "RBAC_DENIED" in gap.reason


def test_running_config_absent_from_the_manifest_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(directory, lambda m: m["resources"].pop("config/nsrunningconfig"))
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None and "niet in het manifest" in gap.reason


def test_running_config_file_missing_while_the_manifest_promises_it(tmp_path):
    directory = _live_copy(tmp_path)
    (directory / "parsed" / "runningconfig.txt").unlink()
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None and "ontbreekt" in gap.reason


# A config text is split on LF alone, a CRLF read as one LF. `str.splitlines()`
# also breaks a line on a lone carriage return, a vertical tab, a form feed,
# a file, group or record separator, NEL and the Unicode line and paragraph
# separators, and every reader then got the rest of that line as a line of
# its own - the credential filter of this read included. Such a character is
# part of the line it stands in.
LINE_BREAKS_OTHER_THAN_LF = (0x0D, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029)


@pytest.mark.parametrize("ending", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("code_point", LINE_BREAKS_OTHER_THAN_LF, ids=lambda code: f"U+{code:04X}")
def test_a_line_break_other_than_lf_stays_inside_its_config_line(tmp_path, code_point, ending):
    line = f"add server SRV-002 192.0.2.11 -comment voor{chr(code_point)}na"
    running = ["# kop", "add server SRV-001 192.0.2.10", line, " Done"]
    saved = ["# kop", "add server SRV-001 192.0.2.10", line]
    directory = config_pair(tmp_path, running, saved)
    for file_name in ("runningconfig.txt", "savedconfig.txt"):
        path = directory / "parsed" / file_name
        path.write_bytes(path.read_bytes().replace(b"\n", ending.encode("ascii")))
    export = load_export(directory)
    assert export.running_config_lines() == (running, None)
    assert export.saved_config_lines() == (saved, None)


# ---------------------------------------------------------------------------
# The lines that differ between running and saved ONLY in the part the
# credential filter cuts away. Every reader gets the cut lines, so no reader
# can see such a difference; the export counts it - a number, never a line,
# never the value - and keeps nothing of the files it read for that count.
# ---------------------------------------------------------------------------


def _nothing_counted():
    return export_module.WithheldCounts(differing=0, not_comparable=0)


@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_a_difference_only_in_the_withheld_part_is_counted_and_nothing_else(tmp_path, name):
    from nsmcp.config_drift import comparable_lines

    running_line, saved_line = WITHHELD_ONLY_PAIRS[name]
    base = ["# kop", "add server SRV-001 192.0.2.10"]
    export = load_export(config_pair(tmp_path, [*base, running_line, " Done"], [*base, saved_line]))
    counts, gap = export.withheld_only_difference(comparable_lines)
    assert (counts, gap) == (export_module.WithheldCounts(differing=1, not_comparable=0), None)
    assert [type(value) for value in dataclasses.astuple(counts)] == [int, int]
    # Nothing of the two files stays on the export after the count.
    state = repr(vars(export))
    for value in (OLD_SECRET, NEW_SECRET):
        assert value not in state


@pytest.mark.parametrize("name", sorted(WITHHELD_ONLY_PAIRS))
def test_an_equal_withheld_part_counts_nothing(tmp_path, name):
    from nsmcp.config_drift import comparable_lines

    line, _ = WITHHELD_ONLY_PAIRS[name]
    base = ["# kop", "add server SRV-001 192.0.2.10"]
    export = load_export(config_pair(tmp_path, [*base, line, " Done"], [*base, line]))
    assert export.withheld_only_difference(comparable_lines) == (_nothing_counted(), None)


def test_the_digest_key_is_drawn_fresh_for_every_call_and_shared_by_its_two_sides(tmp_path, monkeypatch):
    """The documents promise a key that exists for one call only. Pinned
    here: the running and the saved side of one call share a key (or no
    line could compare), two calls never do, the key is 32 bytes, and the
    digest of the same line differs from one call to the next - so no
    digest from one call is a value a later reader could test a guess
    against. Nor is it a plain or an unkeyed hash of the line."""
    import hmac

    from nsmcp.config_drift import comparable_lines

    running_line, saved_line = WITHHELD_ONLY_PAIRS["system-user"]
    running = ["# kop", "add server SRV-001 192.0.2.10", running_line, " Done"]
    export = load_export(config_pair(tmp_path, running, ["# kop", "add server SRV-001 192.0.2.10", saved_line]))
    echt = export_module._cut_and_digest
    gezien: list[tuple[bytes, list]] = []

    def spion(lines, comparable, key):
        triples = echt(lines, comparable, key)
        gezien.append((key, triples))
        return triples

    monkeypatch.setattr(export_module, "_cut_and_digest", spion)
    eerste = export.withheld_only_difference(comparable_lines)
    tweede = export.withheld_only_difference(comparable_lines)
    assert eerste == tweede == (export_module.WithheldCounts(differing=1, not_comparable=0), None)
    assert len(gezien) == 4  # PREMISE: two sides per call, two calls
    (sleutel_1, running_1), (sleutel_1b, _), (sleutel_2, running_2), (sleutel_2b, _) = gezien
    assert sleutel_1 == sleutel_1b and sleutel_2 == sleutel_2b
    assert sleutel_1 != sleutel_2
    assert len(sleutel_1) == len(sleutel_2) == 32
    assert [cut for cut, _, _ in running_1] == [cut for cut, _, _ in running_2]
    for (_, digest_1, _), (_, digest_2, _) in zip(running_1, running_2, strict=True):
        assert digest_1 != digest_2
    onbesleuteld = {
        variant
        for line in running
        for variant in (
            hashlib.sha256(line.strip().encode("utf-8")).digest(),
            hmac.new(b"", line.strip().encode("utf-8"), hashlib.sha256).digest(),
        )
    }
    assert not onbesleuteld & {digest for _, digest, _ in running_1}


def test_a_visible_difference_is_not_counted_as_a_withheld_one(tmp_path):
    from nsmcp.config_drift import comparable_lines

    base = ["# kop", "add server SRV-001 192.0.2.10"]
    export = load_export(
        config_pair(
            tmp_path,
            [*base, "set lb vserver LBV-001 -comment een", " Done"],
            [*base, "set lb vserver LBV-001 -comment twee"],
        )
    )
    assert export.withheld_only_difference(comparable_lines) == (_nothing_counted(), None)


def test_the_withheld_count_reads_through_the_same_hash_check(tmp_path):
    """A saved config that no longer matches its manifest hash is a read gap
    for the count too - never a count of zero."""
    from nsmcp.config_drift import comparable_lines

    running_line, saved_line = WITHHELD_ONLY_PAIRS["system-user"]
    directory = config_pair(tmp_path, ["# kop", running_line, " Done"], ["# kop", saved_line])
    (directory / "parsed" / "savedconfig.txt").write_text("gewijzigd\n", encoding="utf-8")
    counts, gap = load_export(directory).withheld_only_difference(comparable_lines)
    assert counts is None
    assert gap is not None and "komt niet overeen met het manifest" in gap.reason


# ---------------------------------------------------------------------------
# The lines whose value the collector itself already withheld. It writes a
# fixed marker in place of a credential value on the jumphost, in the running
# and the saved config alike: two such lines are equal in the files whether
# or not the value on the appliance changed, so no count can compare them.
# The export counts them in the same read, as a number, and nothing else.
# ---------------------------------------------------------------------------


def test_the_collector_marker_is_the_literal_both_lab_exports_carry():
    assert export_module.COLLECTOR_REDACTION_MARKER == COLLECTOR_MARKER == "<REDACTED>"
    assert f"`{COLLECTOR_MARKER}`" in (LAB / "README.md").read_text(encoding="utf-8")
    for fixture in (LAB, DOH):
        for name in ("runningconfig.txt", "savedconfig.txt"):
            assert COLLECTOR_MARKER in (fixture / "parsed" / name).read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("name", sorted(COLLECTOR_MARKER_LINES))
def test_a_value_the_collector_withheld_is_counted_as_not_comparable(tmp_path, name):
    from nsmcp.config_drift import comparable_lines

    line = COLLECTOR_MARKER_LINES[name]
    base = ["# kop", "add server SRV-001 192.0.2.10"]
    export = load_export(config_pair(tmp_path, [*base, line, " Done"], [*base, line]))
    assert export.withheld_only_difference(comparable_lines) == (
        export_module.WithheldCounts(differing=0, not_comparable=1),
        None,
    )


def test_a_value_the_collector_withheld_on_one_side_only_is_not_counted(tmp_path):
    """Such a line differs in what every reader sees: a visible difference,
    counted by the comparison itself, not a line that could not be compared."""
    from nsmcp.config_drift import comparable_lines

    base = ["# kop", "add server SRV-001 192.0.2.10"]
    line = COLLECTOR_MARKER_LINES["rpcnode-password"]
    export = load_export(config_pair(tmp_path, [*base, line, " Done"], base))
    assert export.withheld_only_difference(comparable_lines) == (_nothing_counted(), None)


@pytest.mark.parametrize(("fixture", "per_side"), [(LAB, 10), (DOH, 8)], ids=["lab-20260826", "lab-doh-synthetic"])
def test_every_line_the_collector_withheld_on_a_lab_export_is_counted(fixture, per_side):
    """Measured on the files themselves: every line with the marker, and
    nothing else, on the lab export and on the synthetic DoH export."""
    from nsmcp.config_drift import comparable_lines

    for name in ("runningconfig.txt", "savedconfig.txt"):
        text = (fixture / "parsed" / name).read_text(encoding="utf-8-sig")
        assert sum(COLLECTOR_MARKER in line for line in text.splitlines()) == per_side
    assert load_export(fixture).withheld_only_difference(comparable_lines) == (
        export_module.WithheldCounts(differing=0, not_comparable=per_side),
        None,
    )


@pytest.mark.parametrize("value", [-1, 1.0, True, "1", None])
def test_the_withheld_counts_are_whole_numbers_and_nothing_else(value):
    with pytest.raises(ValueError):
        export_module.WithheldCounts(differing=value, not_comparable=0)
    with pytest.raises(ValueError):
        export_module.WithheldCounts(differing=0, not_comparable=value)


# ---------------------------------------------------------------------------
# The two doors to the lines BEFORE the credential filter. Only
# `_config_text_lines()` (which cuts every line before any caller sees it)
# and `withheld_only_difference()` (which hands out two counts) may read
# them. A third caller would put the raw lines where the filter never ran,
# and the docstring alone would not stop it - so the source is read here.
# ---------------------------------------------------------------------------

_RAW_LINE_DOORS = {
    "_verified_config_text_lines": {"_config_text_lines", "withheld_only_difference"},
    "_cut_and_digest": {"withheld_only_difference"},
}


def _references(tree, names):
    """(name, innermost enclosing function) for every reference to one of
    `names`: as an attribute, as a bare name, or as a whole string (a
    `getattr` by name). A definition itself is not a reference."""
    found = set()

    def visit(node, function):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else function
            if isinstance(child, ast.Attribute) and child.attr in names:
                found.add((child.attr, function))
            elif isinstance(child, ast.Name) and child.id in names:
                found.add((child.id, function))
            elif isinstance(child, ast.Constant) and isinstance(child.value, str) and child.value in names:
                found.add((child.value, function))
            visit(child, inner)

    visit(tree, None)
    return found


def test_only_the_two_named_methods_read_the_lines_before_the_credential_filter():
    source = Path(export_module.__file__)
    found = _references(ast.parse(source.read_text(encoding="utf-8")), set(_RAW_LINE_DOORS))
    expected = {(name, function) for name, functions in _RAW_LINE_DOORS.items() for function in functions}
    assert found == expected
    # No other module of the package names either door at all.
    for path in sorted(source.parent.glob("*.py")):
        if path != source:
            assert not _references(ast.parse(path.read_text(encoding="utf-8")), set(_RAW_LINE_DOORS)), path.name


def test_the_door_guard_sees_a_third_caller():
    """The guard above must be able to fail: a third method, a bare call and
    a `getattr` by name are each seen, with the function they stand in."""
    snippet = (
        "class Export:\n"
        "    def third(self):\n"
        "        return self._verified_config_text_lines('a', 'b')\n"
        "def helper(lines):\n"
        "    return _cut_and_digest(lines, None, b'')\n"
        "def sneaky(export):\n"
        "    return getattr(export, '_verified_config_text_lines')\n"
    )
    assert _references(ast.parse(snippet), set(_RAW_LINE_DOORS)) == {
        ("_verified_config_text_lines", "third"),
        ("_cut_and_digest", "helper"),
        ("_verified_config_text_lines", "sneaky"),
    }


def test_the_second_door_returns_two_counts_or_a_read_gap_and_nothing_else():
    tree = ast.parse(Path(export_module.__file__).read_text(encoding="utf-8"))
    method = next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "withheld_only_difference"
    )
    returned = [node.value for node in ast.walk(method) if isinstance(node, ast.Return)]
    assert len(returned) == 2  # PREMISE: the read gap and the counts
    shapes = set()
    for value in returned:
        assert isinstance(value, ast.Tuple) and len(value.elts) == 2
        first, second = value.elts
        if isinstance(first, ast.Constant):
            assert first.value is None and isinstance(second, ast.Name)
            shapes.add("gap")
        else:
            assert isinstance(first, ast.Call) and isinstance(first.func, ast.Name)
            assert first.func.id == "WithheldCounts"
            assert isinstance(second, ast.Constant) and second.value is None
            shapes.add("counts")
    assert shapes == {"gap", "counts"}
    assert [field.name for field in dataclasses.fields(export_module.WithheldCounts)] == [
        "differing",
        "not_comparable",
    ]


# ---------------------------------------------------------------------------
# SECURITY 3. The manifest carries a payloadSha256 per resource and nothing
# used it. Measured: objects/nsversion.json forged to build "NS99.9", manifest
# untouched, and `single("config/nsversion")` returned the forged build as
# [vastgesteld]. The customer documentation promises a hash per file; from
# here that promise is true for object files as well.
# ---------------------------------------------------------------------------


def test_a_forged_object_file_is_refused_against_the_manifest_hash(tmp_path):
    directory = _build(tmp_path)
    forged = directory / "objects" / "sslcertkey.json"
    forged.write_text(
        json.dumps({"sslcertkey": [{"certkey": "vervalst", "daystoexpiration": 1}]}),
        encoding="utf-8",
    )
    export = load_export(directory)
    objects, gap = export.objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "komt niet overeen met het manifest" in gap.reason
    assert "niet vertrouwd" in gap.reason


def test_a_source_without_a_payload_hash_is_a_read_gap(tmp_path):
    directory = _build(tmp_path)
    manifest_path = directory / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"]["config/sslcertkey"].pop("payloadSha256", None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    export = load_export(directory)
    objects, gap = export.objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "geen hash in het manifest" in gap.reason


def test_the_hash_comparison_ignores_the_case_the_collector_happens_to_write(tmp_path):
    """The real NSHC collector writes the hash in UPPER case; hashlib produces
    lower case. A case-sensitive comparison would turn every real export into
    one long read gap."""
    directory = _build(tmp_path)
    manifest_path = directory / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["resources"]["config/sslcertkey"]["payloadSha256"] = manifest["resources"]["config/sslcertkey"][
        "payloadSha256"
    ].upper()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    export = load_export(directory)
    _, gap = export.objects("config/sslcertkey")
    assert gap is None


def test_the_real_lab_export_still_reads_every_object_source_it_used_to(tmp_path):
    """The counter-proof for the whole change: on the REAL fixture the new
    check may not produce a single new read gap for a source the product
    actually reads.

    `config/nsversion` goes through `single()` and not through `objects()`:
    the real collector writes a singleton resource as an OBJECT under the key,
    so `objects()` was already a read gap there long before this check existed
    (see the docstring of `Export.single`). Reading it with the wrong accessor
    would prove nothing about the manifest hash.
    """
    export = load_export(LIVE_EXPORT)
    for resource in ("config/sslcertkey", "config/vpnvserver", "config/nshttpprofile", "config/hanode"):
        _, gap = export.objects(resource)
        assert gap is None, f"{resource} became a read gap: {gap}"
    _, gap = export.single("config/nsversion")
    assert gap is None, f"config/nsversion became a read gap: {gap}"


# ---------------------------------------------------------------------------
# SECURITY 8 AND 9. Measured: an object file with 60.000 nested arrays raised
# a RecursionError past `except (JSONDecodeError, UnicodeDecodeError)` and
# became the generic masked error; 100.000 objects loaded in 0,06 s without a
# ceiling. Every one of these is now a read gap with a reason a human can act
# on.
# ---------------------------------------------------------------------------


def _reseal(directory):
    from conftest import seal_manifest

    seal_manifest(directory)


def test_an_object_file_above_the_byte_cap_becomes_a_read_gap(tmp_path, monkeypatch):
    from nsmcp import limits

    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "x" * 500}]}), encoding="utf-8"
    )
    _reseal(directory)
    # Derived from the manifest's
    # own measured size, not a hardcoded 400 - the manifest (load_export,
    # _manifest_unchanged) now carries the same ceiling, and must fit
    # under it so this test still exercises the OBJECT ceiling it names,
    # not an incidental "geen manifest" read gap from the manifest
    # ceiling instead. A fixed number silently starts testing the WRONG
    # ceiling the moment a future fixture-builder change grows the
    # manifest past it; deriving from the real size cannot go stale.
    ceiling = (directory / "export-manifest.json").stat().st_size + 50
    monkeypatch.setattr(limits, "MAX_FILE_BYTES", ceiling)
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", ceiling)
    objects, gap = load_export(directory).objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "groter dan het plafond" in gap.reason


def test_an_object_file_with_too_many_objects_becomes_a_read_gap_with_the_count(tmp_path, monkeypatch):
    monkeypatch.setattr(export_module, "MAX_OBJECTS_PER_FILE", 3)
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": f"c{i}"} for i in range(9)]}),
        encoding="utf-8",
    )
    _reseal(directory)
    objects, gap = load_export(directory).objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "9" in gap.reason and "3" in gap.reason


def test_a_deeply_nested_object_file_becomes_a_read_gap_with_a_named_reason(tmp_path):
    """Depth only needs to clear the product's own ceiling (MAX_JSON_DEPTH), not
    stress the JSON parser. This used to build 2000 levels on the premise that
    json.dumps/json.loads handle that "without trouble" on every supported
    Python - measured true on CPython 3.12.10, but false on CPython 3.11 (also
    in the CI matrix): there, json.dumps() on the fixture itself raises
    RecursionError before exceeds_depth ever runs, so the test failed for the
    wrong reason. 3x the real ceiling clears it with a wide margin and stays
    far under any observed parser failure point - CPython 3.11 already fails
    at 2000, and this repo's 3.12.10 venv only starts failing past 2997.
    """
    directory = _build(tmp_path)
    depth = export_module.MAX_JSON_DEPTH * 3
    payload = "x"
    for _ in range(depth):
        payload = [payload]
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": payload}]}), encoding="utf-8"
    )
    _reseal(directory)
    objects, gap = load_export(directory).objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "diep genest" in gap.reason


def test_an_object_file_that_blows_the_parser_is_a_read_gap_and_not_a_masked_error(
    tmp_path,
):
    """The 60.000-level probe of the security spike: json.loads itself raises
    RecursionError before any depth check can look at the result.

    The exact threshold is version- and build-dependent, so this test does not
    lean on a specific number - it goes far past any of them instead. Measured
    in this venv (CPython 3.12.10): a bare nested-list document starts raising
    RecursionError from json.loads around 3000 levels - not "about 5000" as this
    docstring previously said; that number was never actually re-measured. On
    CPython 3.11 (also in the CI matrix) the threshold is lower still - task
    28/29's CI runs show the equivalent 2000-level fixture failing there, which
    is why the DEPTH-check test above no longer uses 2000. 60.000 clears every
    observed threshold on both versions with a wide margin, so the reason
    asserted here reliably names the parse failure, not the depth: a depth
    check alone would leave this hole open behind a green suite.
    """
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_bytes(b'{"sslcertkey": ' + b"[" * 60000 + b"]" * 60000 + b"}")
    _reseal(directory)
    objects, gap = load_export(directory).objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "onleesbaar" in gap.reason or "diep genest" in gap.reason or "kon niet verwerkt worden" in gap.reason, (
        gap.reason
    )
    assert "RecursionError" in gap.reason, gap.reason


def test_a_text_projection_above_the_line_cap_becomes_a_read_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(export_module, "MAX_TEXT_LINES", 5)
    directory = _live_copy(tmp_path)
    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None
    assert "regels" in gap.reason
    assert gap.source == "parsed/runningconfig.txt", gap.source


def test_a_capped_saved_config_names_the_saved_file_not_the_running_one(tmp_path, monkeypatch):
    """Both ceilings of the SHARED reader.

    `_config_text_lines` serves running AND saved config. Its
    two ceiling branches labelled their read gap `parsed/runningconfig.txt`
    unconditionally, so an operator hitting the ceiling on the SAVED config
    was pointed at a file that was read perfectly well. Every other branch
    in that function already names the file it was handed; these two now
    do too.

    Both ceilings are measured, not one: they are two separate literals
    and fixing only the one a test happened to reach is how the other
    survives a green suite.
    """
    monkeypatch.setattr(export_module, "MAX_TEXT_LINES", 5)
    directory = _live_copy(tmp_path)
    lines, gap = load_export(directory).saved_config_lines()
    assert lines == []
    assert gap is not None
    assert "regels" in gap.reason
    assert gap.source == "parsed/savedconfig.txt", gap.source

    # ...and the byte ceiling, the other of the two branches. The ceiling
    # has to sit ABOVE the manifest (which every read re-reads through the
    # same ceiling) and BELOW this file, so the file grows rather than the
    # ceiling shrinking. The bytes are never trusted anyway: this branch
    # comes before the hash comparison, on purpose.
    saved = directory / "parsed" / "savedconfig.txt"
    manifest_bytes = (directory / "export-manifest.json").stat().st_size
    ceiling = manifest_bytes + 1000
    saved.write_text("regel\n" * ceiling, encoding="utf-8", newline="\n")
    assert saved.stat().st_size > ceiling, "premisse: het bestand moet echt boven het plafond uitkomen"
    monkeypatch.setattr(export_module, "MAX_TEXT_LINES", 10_000_000)
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", ceiling)
    lines, gap = load_export(directory).saved_config_lines()
    assert lines == []
    assert gap is not None
    assert "plafond" in gap.reason, gap.reason
    assert gap.source == "parsed/savedconfig.txt", gap.source


def test_a_capped_read_never_produces_a_verdict(tmp_path, monkeypatch):
    """The whole point: a ceiling is fail-closed. A truncated read may never
    become a shorter answer that looks complete."""
    monkeypatch.setattr(export_module, "MAX_OBJECTS_PER_FILE", 1)
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "a"}, {"certkey": "b"}]}),
        encoding="utf-8",
    )
    _reseal(directory)
    objects, gap = load_export(directory).objects("config/sslcertkey")
    assert objects == []
    assert gap is not None


# ---------------------------------------------------------------------------
# THE SAME PARSE-TIME HOLE IN THE OTHER TWO READERS. `_object_payload` is not
# the only place this module hands untrusted bytes to `json.loads`: the
# by-parent binding files and the manifest itself do the same. A RecursionError
# raised INSIDE the parser escapes `except (JSONDecodeError, UnicodeDecodeError)`
# there just as well, so each of those parses needs its own proof - not the
# assumption that one fixed catch covers three call sites.
# ---------------------------------------------------------------------------


def _deep_bytes(levels: int = 60000) -> bytes:
    """A syntactically valid JSON document that only the parser can refuse."""
    return b"[" * levels + b"]" * levels


def test_a_binding_file_that_blows_the_parser_is_a_read_gap(tmp_path):
    directory = _build(tmp_path)
    payload = _deep_bytes()
    (directory / "bindings" / BINDING_FILE).write_bytes(payload)
    _rewrite_manifest(
        directory,
        lambda m: m["files"].__setitem__(f"bindings/{BINDING_FILE}", hashlib.sha256(payload).hexdigest()),
    )
    bindings, gap = load_export(directory).bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None
    assert "kon niet verwerkt worden" in gap.reason, gap.reason
    assert "RecursionError" in gap.reason, gap.reason


def test_a_deeply_nested_binding_file_is_a_read_gap_with_a_named_reason(tmp_path):
    """Same depth choice and reasoning as the object-file depth test above:
    3x MAX_JSON_DEPTH clears the product's ceiling with margin and stays far
    under CPython's json RecursionError zone on every supported version - see
    that test's docstring for the measurements.
    """
    directory = _build(tmp_path)
    document = _by_parent({"LB_VS_A": [{"certkeyname": "cert_a", "vservername": "LB_VS_A"}]})
    depth = export_module.MAX_JSON_DEPTH * 3
    nested = "x"
    for _ in range(depth):
        nested = [nested]
    document["parents"][0]["data"]["sslvserver_sslcertkey_binding"][0]["diep"] = nested
    payload = json.dumps(document).encode("utf-8")
    (directory / "bindings" / BINDING_FILE).write_bytes(payload)
    _rewrite_manifest(
        directory,
        lambda m: m["files"].__setitem__(f"bindings/{BINDING_FILE}", hashlib.sha256(payload).hexdigest()),
    )
    bindings, gap = load_export(directory).bindings(BINDING_FILE)
    assert bindings == []
    assert gap is not None
    assert "diep genest" in gap.reason, gap.reason


def test_a_manifest_that_blows_the_parser_is_a_missing_manifest_not_an_exception(
    tmp_path,
):
    """`load_export` is the very first read of every answer. A RecursionError
    escaping HERE masks the whole session, not one source."""
    directory = _build(tmp_path)
    (directory / "export-manifest.json").write_bytes(_deep_bytes())
    export = load_export(directory)
    assert export.manifest_missing is True
    objects, gap = export.objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "geen manifest" in gap.reason, gap.reason


# ---------------------------------------------------------------------------
# The manifest is the TRUST ANCHOR
# every other read in this file checks against, and `load_export` reads it
# FIRST on every answer - yet, unlike every other reader here
# (_object_payload, _binding_document, running_config_lines,
# _read_target_name, load_knowledge), it carried no byte ceiling before the
# decode/parse, and `_manifest_unchanged` re-reads and hashes it on EVERY
# source read with no ceiling either. limits.py's own docstring claims
# every reader gets a ceiling before the work that scales with its size;
# these two calls did not.
# ---------------------------------------------------------------------------


def test_an_oversized_manifest_is_a_missing_manifest_not_an_unbounded_read(tmp_path, monkeypatch):
    """Same shape as `_read_target_name`: the byte cap applies BEFORE the
    manifest is decoded or parsed, even when the content would otherwise be
    a perfectly valid manifest. An oversized manifest is refused the same
    honest way a missing one already is."""
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", 500)
    directory = _build(tmp_path)
    _rewrite_manifest(directory, lambda m: m.__setitem__("padding", "x" * 1000))

    export = load_export(directory)

    assert export.manifest_missing is True
    objects, gap = export.objects("config/sslcertkey")
    assert objects == []
    assert gap is not None
    assert "geen manifest" in gap.reason, gap.reason


def test_manifest_unchanged_re_read_is_bounded_before_the_hash(tmp_path, monkeypatch):
    """`_manifest_unchanged()` re-reads and hashes the manifest on every
    source read. Proven by making hashlib.sha256 raise if it is ever handed
    more than the ceiling's worth of bytes: with the fix, the size check
    refuses the re-read before the hash ever runs; without it, the
    unbounded hash runs regardless of size and this raises instead of
    returning an honest read gap."""
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", 500)
    directory = _build(tmp_path)
    export = load_export(directory)
    assert export.manifest_missing is False

    _rewrite_manifest(directory, lambda m: m.__setitem__("padding", "x" * 1000))

    real_sha256 = hashlib.sha256

    def _guarded_sha256(data=b""):
        if len(data) > 500:
            raise AssertionError("sha256 kreeg manifestbytes boven het plafond")
        return real_sha256(data)

    monkeypatch.setattr(export_module.hashlib, "sha256", _guarded_sha256)

    objects, gap = export.objects("config/sslcertkey")

    assert objects == []
    assert gap is not None


# ---------------------------------------------------------------------------
# `_read_target_name` reads scan-doel.txt with
# `read_text(encoding="utf-8")` guarded only by `except OSError`.
# `UnicodeDecodeError` is a `ValueError`, not an `OSError`, so a scan-doel.txt
# with invalid UTF-8 bytes used to escape straight out of `load_export` - the
# first read of every answer - as the generic masked "Onverwachte fout ...
# geen logboek", exactly the same failure shape as a missing file. The same read
# also carried no byte ceiling, unlike every other untrusted read in this
# file. Both are now handled the same way the existing `except OSError`
# branch already handles a missing file: `target_name` stays None, and
# `load_export` never raises.
# ---------------------------------------------------------------------------


def test_a_target_file_with_invalid_utf8_yields_no_target_name_not_an_exception(tmp_path):
    """Before the fix this call raised `UnicodeDecodeError` out of
    `load_export` itself - there is no try/except around this call on
    purpose, so an escaping exception fails the test exactly like it would
    have failed a real answer."""
    directory = _build(tmp_path)
    invalid_utf8 = bytes([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x81])
    (directory / TARGET_FILE).write_bytes(invalid_utf8)

    export = load_export(directory)

    assert export.target_name is None, (
        "een scan-doel.txt dat niet als UTF-8 leesbaar is, mag nooit een gok "
        "worden - hetzelfde eerlijke 'niet vastgelegd' als een ontbrekend bestand"
    )


def test_a_target_file_above_the_byte_cap_yields_no_target_name(tmp_path, monkeypatch):
    """Same ceiling, same place as every other reader in this file: the byte
    cap applies BEFORE the content is trusted for anything - decoding,
    splitting into lines, or comparing the recorded hash - even when the
    content would otherwise be a perfectly valid, matching target name.
    Without the cap this content parses cleanly and yields 'lab'; the
    assertion below is therefore red before the fix and green after.

    The manifest itself now carries
    the SAME ceiling (load_export, _manifest_unchanged), so a 32-byte
    ceiling can no longer share `_build`'s 351-byte manifest without the
    manifest read being refused first - which would prove nothing about
    THIS reader's own cap. A minimal `{}` manifest (2 bytes) keeps this
    test about the target file's cap, not the manifest's."""
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", 32)
    directory = tmp_path
    manifest_bytes = b"{}"
    (directory / "export-manifest.json").write_bytes(manifest_bytes)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    scan_doel_content = "lab" + chr(10) + manifest_hash + chr(10)
    (directory / TARGET_FILE).write_text(scan_doel_content, encoding="utf-8")

    export = load_export(directory)

    assert export.manifest_missing is False  # premise: the tiny manifest itself cleared the ceiling
    assert export.target_name is None, (
        "een scan-doel.txt groter dan het plafond mag niet gelezen worden, ook "
        "niet als de inhoud verder geldig en kloppend is"
    )


# ---------------------------------------------------------------------------
# THE ORDERING IS NOT PINNED BY ANY TEST YET.
# `test_an_object_file_above_the_byte_cap_becomes_a_read_gap` reseals the
# object file, so its manifest hash always matches - that test passes
# identically whether the byte cap in `_object_payload` runs before or after
# the manifest-hash comparison. This test leaves the hash deliberately WRONG
# and asserts the BYTE reason still wins: if the two checks were ever
# swapped, the hash-mismatch reason ("komt niet overeen met het manifest")
# would win instead, because the wrong hash would be seen first and the
# byte-cap check would never run on a document that already returned. That
# is exactly what would make this assertion fail under a swap.
# ---------------------------------------------------------------------------


def test_the_byte_cap_wins_over_a_wrong_manifest_hash_pinning_the_order(tmp_path, monkeypatch):
    directory = _build(tmp_path)
    (directory / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "x" * 500}]}), encoding="utf-8"
    )
    # Deliberately WRONG hash - not resealed, on purpose: this is the fixture
    # that proves the order, not one that should ever be repaired. The
    # substituted hash is the same 64-hex-char length as a real one, so
    # this does not change the manifest's byte size.
    _rewrite_manifest(
        directory,
        lambda m: m["resources"]["config/sslcertkey"].__setitem__("payloadSha256", "0" * 64),
    )
    # Derived from the manifest's
    # own measured size - see the same note on
    # test_an_object_file_above_the_byte_cap_becomes_a_read_gap above; the
    # manifest must fit under the ceiling for this test to still be about
    # the OBJECT byte cap and the hash-order it pins, and a hardcoded
    # number cannot silently go stale against a growing fixture.
    ceiling = (directory / "export-manifest.json").stat().st_size + 50
    monkeypatch.setattr(export_module, "MAX_FILE_BYTES", ceiling)

    objects, gap = load_export(directory).objects("config/sslcertkey")

    assert objects == []
    assert gap is not None
    assert "groter dan het plafond" in gap.reason, gap.reason
    assert "komt niet overeen met het manifest" not in gap.reason, gap.reason


def test_running_config_read_error_names_no_local_path(tmp_path, monkeypatch):
    """The same TOCTOU-forced OSError as the two
    tests above, now on `_config_text_lines()` - the site that used to
    interpolate `{exc}` directly (export.py, the running/saved-config
    reader both share this method).

    See the NOTE above `test_object_file_read_error_names_no_local_path`
    for why the premise/assertion probe `tmp_path.name`, not `str(tmp_path)`."""
    directory = _live_copy(tmp_path)
    target = directory / "parsed" / "runningconfig.txt"
    target.unlink()

    try:
        target.read_bytes()
    except OSError as exc:
        assert tmp_path.name in str(exc)  # premise
    else:
        pytest.fail("premisse faalt: het bestand is nog leesbaar")

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "runningconfig.txt":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    lines, gap = load_export(directory).running_config_lines()
    assert lines == []
    assert gap is not None  # premise
    assert tmp_path.name not in gap.reason, f"lokaal pad lekt in het leesgat: {gap.reason}"


# ---------------------------------------------------------------------------
# `systemuser_rows()`. Same discipline, its own method - see
# the comment at SYSTEMUSER_RESOURCE/SYSTEMUSER_FILE in export.py for why it
# is neither a third `_config_text_lines` caller nor a second `_object_payload`
# path: the hash lives on the resource's OWN manifest entry, not under
# `files`, and the content is a JSON list, not text lines.
# ---------------------------------------------------------------------------


def _rewrite_systemuser_file(directory: Path, content: dict) -> None:
    """Rewrites `parsed/systemuser.json` AND its hash on the resource's own
    manifest entry together, so a test can probe what happens AFTER the hash
    check (the shape gate) instead of only ever hitting the hash mismatch."""
    raw = json.dumps(content).encode("utf-8")
    (directory / "parsed" / "systemuser.json").write_bytes(raw)
    _rewrite_manifest(
        directory,
        lambda m: m["resources"]["config/systemuser"].__setitem__(
            "payloadSha256", hashlib.sha256(raw).hexdigest().upper()
        ),
    )


def test_systemuser_of_the_live_export_is_read_and_verified(tmp_path):
    rows, gap = load_export(LIVE_EXPORT).systemuser_rows()
    assert gap is None, f"onverwacht leesgat: {gap}"
    assert rows == [
        {
            "username": "nsroot",
            "externalauth": "DISABLED",
            "logging": "ENABLED",
            "timeout": 900,
            "allowedmanagementinterface": ["CLI", "API"],
        }
    ]


def test_a_manipulated_systemuser_file_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    path = directory / "parsed" / "systemuser.json"
    path.write_bytes(path.read_bytes().replace(b"nsroot", b"toor"))
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None
    assert "komt niet overeen met het manifest" in gap.reason


def test_systemuser_without_a_hash_on_its_own_resource_entry_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(
        directory,
        lambda m: m["resources"]["config/systemuser"].pop("payloadSha256"),
    )
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None
    assert "manifest draagt geen hash voor config/systemuser" in gap.reason


def test_systemuser_not_usably_in_the_manifest_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(directory, lambda m: m["resources"].__setitem__("config/systemuser", {"status": "RBAC_DENIED"}))
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None and "RBAC_DENIED" in gap.reason


def test_systemuser_absent_from_the_manifest_is_a_read_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(directory, lambda m: m["resources"].pop("config/systemuser"))
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None and "niet in het manifest" in gap.reason


def test_systemuser_file_missing_while_the_manifest_promises_it(tmp_path):
    directory = _live_copy(tmp_path)
    (directory / "parsed" / "systemuser.json").unlink()
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None and "ontbreekt" in gap.reason


def test_systemuser_empty_status_is_a_read_emptiness_not_a_gap(tmp_path):
    directory = _live_copy(tmp_path)
    _rewrite_manifest(directory, lambda m: m["resources"].__setitem__("config/systemuser", {"status": "EMPTY"}))
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is None, f"onverwacht leesgat: {gap}"


def test_systemuser_with_a_dict_instead_of_a_list_under_the_key_is_a_read_gap(tmp_path):
    """The shape gate sits AFTER the hash check (`_rewrite_systemuser_file`
    keeps them in sync), never before it - a caller must not be able to skip
    trust verification by supplying a shape the gate would refuse anyway."""
    directory = _live_copy(tmp_path)
    _rewrite_systemuser_file(directory, {"systemuser": {"username": "nsroot"}})
    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None
    assert "geen lijst onder de verwachte sleutel 'systemuser'" in gap.reason


def test_systemuser_read_error_names_no_local_path(tmp_path, monkeypatch):
    """Same TOCTOU-forced OSError class as
    test_running_config_read_error_names_no_local_path above, now on
    `systemuser_rows()`."""
    directory = _live_copy(tmp_path)
    target = directory / "parsed" / "systemuser.json"
    target.unlink()

    try:
        target.read_bytes()
    except OSError as exc:
        assert tmp_path.name in str(exc)  # premise
    else:
        pytest.fail("premisse faalt: het bestand is nog leesbaar")

    original_exists = Path.exists

    def lies_about_existence(self, *a, **k):
        if self.name == "systemuser.json":
            return True
        return original_exists(self, *a, **k)

    monkeypatch.setattr(Path, "exists", lies_about_existence)

    rows, gap = load_export(directory).systemuser_rows()
    assert rows == []
    assert gap is not None  # premise
    assert tmp_path.name not in gap.reason, f"lokaal pad lekt in het leesgat: {gap.reason}"


# ---------------------------------------------------------------------------
# The two digests the manifest carries, as ONE pair of functions the readers
# and the fixture generator (scripts/make_doh_fixture.py) share.
# ---------------------------------------------------------------------------


def test_the_payload_digest_is_the_upper_case_sha256_of_the_raw_bytes():
    raw = b'{\r\n  "a": 1\r\n}\r\n'
    assert export_module.payload_digest(raw) == hashlib.sha256(raw).hexdigest().upper()


def test_the_config_text_digest_is_taken_over_the_lf_normalized_text():
    crlf = b"#NS14.1 Build 72.57\r\nadd server SRV-1 192.0.2.1\r\n"
    lf = b"#NS14.1 Build 72.57\nadd server SRV-1 192.0.2.1\n"
    assert export_module.config_text_digest(crlf) == export_module.config_text_digest(lf)
    assert export_module.config_text_digest(lf) == hashlib.sha256(lf).hexdigest().upper()
    # A byte order mark is not content either: the reader decodes utf-8-sig.
    assert export_module.config_text_digest(b"\xef\xbb\xbf" + lf) == export_module.config_text_digest(lf)


def test_every_reader_compares_against_the_shared_digests(tmp_path):
    """The readers hash through the same two functions the fixture generator
    writes the manifest with: a manifest written with them reads without a
    single read gap."""
    root = tmp_path / "export"
    (root / "objects").mkdir(parents=True)
    (root / "parsed").mkdir()
    (root / "bindings").mkdir()
    obj = b'{\r\n  "nsversion": {\r\n    "version": "NetScaler NS14.1: Build 72.57.nc"\r\n  }\r\n}\r\n'
    (root / "objects" / "nsversion.json").write_bytes(obj)
    running = b"#NS14.1 Build 72.57\r\nadd server SRV-1 192.0.2.1\r\n"
    (root / "parsed" / "runningconfig.txt").write_bytes(running)
    users = b'{\r\n  "systemuser": [\r\n    {\r\n      "username": "nsroot"\r\n    }\r\n  ]\r\n}\r\n'
    (root / "parsed" / "systemuser.json").write_bytes(users)
    binding = json.dumps(
        {
            "bindingResource": "lbvserver_binding",
            "parentResource": "lbvserver",
            "parentKey": "name",
            "shape": "list",
            "parents": [{"parentName": "LBV-A", "outcome": "EMPTY", "data": None}],
        }
    ).encode("ascii")
    (root / "bindings" / "lbvserver_binding.by-parent.json").write_bytes(binding)
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-06T10:00:00.0000000Z",
        "resources": {
            "config/nsversion": {"status": "OK", "payloadSha256": export_module.payload_digest(obj)},
            "config/nsrunningconfig": {"status": "OK"},
            "config/systemuser": {"status": "OK", "payloadSha256": export_module.payload_digest(users)},
        },
        "files": {
            "parsed/runningconfig.txt": export_module.config_text_digest(running),
            "bindings/lbvserver_binding.by-parent.json": export_module.payload_digest(binding),
        },
    }
    (root / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    export = load_export(root)
    assert export.single("config/nsversion")[1] is None
    assert export.running_config_lines()[1] is None
    assert export.systemuser_rows()[1] is None
    assert export.bindings("lbvserver_binding.by-parent.json")[1] is None
