"""The shared by-parent binding reader: `Export.binding_rows()`.

Two shapes come out of the real collector. `shape: "list"` writes a bare list
of rows per parent; `shape: "aggregate"` writes ONE document per parent with a
nested `<parent>_<child>_binding` list per bound child type. The list form
must read exactly as `grouped_bindings()` always did; the aggregate form must
be asked for BY CHILD KEY, because a blind union of every nested list turns a
servicegroup into a service (the rows of `lbvserver_servicegroup_binding`
carry `servicename == servicegroupname`, measured on the synthetic DoH fixture,
which carries that shape as the collector writes it).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.export import load_export

FIXTURES = Path(__file__).parent / "fixtures"
LAB = FIXTURES / "lab-export-vpx-20260826"
DOH = FIXTURES / "lab-export-vpx-doh-synthetic"

LB_FILE = "lbvserver_binding.by-parent.json"
GROUP = "lbvserver_servicegroup_binding"
SERVICE = "lbvserver_service_binding"


def _list_files(root: Path) -> list[str]:
    names = []
    for path in sorted((root / "bindings").glob("*.by-parent.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("shape") == "list":
            names.append(path.name)
    return names


def _write(tmp_path: Path, file_name: str, document: dict) -> Path:
    root = tmp_path / "export"
    (root / "objects").mkdir(parents=True)
    (root / "bindings").mkdir()
    raw = json.dumps(document)
    (root / "bindings" / file_name).write_text(raw, encoding="utf-8")
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-24T06:00:00.0000000Z",
        "resources": {},
        "files": {f"bindings/{file_name}": hashlib.sha256(raw.encode("utf-8")).hexdigest()},
    }
    (root / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(root)
    return root


def _aggregate(parents: list[dict], resource: str = "lbvserver_binding") -> dict:
    return {
        "bindingResource": resource,
        "parentResource": "lbvserver",
        "parentKey": "name",
        "shape": "aggregate",
        "parents": parents,
    }


def _lb_parent(name: str, **children) -> dict:
    document = {"name": name}
    document.update(children)
    return {"parentName": name, "outcome": "OK", "data": {"lbvserver_binding": document}}


# ---------------------------------------------------------------------------
# The list form: byte-equal to grouped_bindings().
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root", [LAB, DOH], ids=["lab", "doh"])
def test_the_list_form_reads_exactly_like_grouped_bindings_on_the_real_exports(root):
    export = load_export(root)
    files = _list_files(root)
    assert files, "premise: the real export carries list-shaped binding files"
    for file_name in files:
        assert export.binding_rows(file_name) == export.grouped_bindings(file_name), file_name


def test_the_list_form_keeps_an_empty_parent_apart_from_an_absent_one(tmp_path):
    document = {
        "bindingResource": "sslvserver_sslcertkey_binding",
        "parentResource": "sslvserver",
        "parentKey": "vservername",
        "shape": "list",
        "parents": [
            {"parentName": "VS-A", "outcome": "OK", "data": {"sslvserver_sslcertkey_binding": [{"certkeyname": "C"}]}},
            {"parentName": "VS-B", "outcome": "EMPTY", "data": None},
        ],
    }
    export = load_export(_write(tmp_path, "sslvserver_sslcertkey_binding.by-parent.json", document))
    grouped, gap = export.binding_rows("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is None
    assert grouped == {"VS-A": [{"certkeyname": "C"}], "VS-B": None}
    assert (grouped, gap) == export.grouped_bindings("sslvserver_sslcertkey_binding.by-parent.json")


def test_the_list_form_with_child_keys_returns_the_rows_under_the_binding_resource(tmp_path):
    """A consumer that reads both shapes asks with child keys and gets pairs
    back on both: under the list form every row is one of the file's own
    binding resource."""
    document = {
        "bindingResource": "lbvserver_binding",
        "parentResource": "lbvserver",
        "parentKey": "name",
        "shape": "list",
        "parents": [
            {"parentName": "LBV-A", "outcome": "OK", "data": {"lbvserver_binding": [{"servicegroupname": "SG-A"}]}}
        ],
    }
    export = load_export(_write(tmp_path, LB_FILE, document))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP, SERVICE))
    assert gap is None
    assert grouped == {"LBV-A": [("lbvserver_binding", {"servicegroupname": "SG-A"})]}


# ---------------------------------------------------------------------------
# The aggregate form.
# ---------------------------------------------------------------------------


def test_the_aggregate_form_without_child_keys_is_refused_never_a_silent_union():
    export = load_export(DOH)
    grouped, gap = export.binding_rows(LB_FILE)
    assert grouped == {}
    assert gap is not None and gap.source == LB_FILE
    assert "aggregate" in gap.reason and "kindsleutel" in gap.reason


def test_the_aggregate_form_returns_each_requested_child_under_its_own_key():
    export = load_export(DOH)
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP, SERVICE))
    assert gap is None
    assert len(grouped) == 12
    pairs = grouped["LBV-APP-001"]
    assert [key for key, _row in pairs] == [GROUP]
    assert pairs[0][1]["servicegroupname"] == "SG-APP-001"


def test_the_union_trap_a_servicegroup_row_never_reads_as_a_service():
    """MEASURED on the synthetic DoH fixture: every row of
    lbvserver_servicegroup_binding carries servicename == servicegroupname
    (7 of 7). Asked per child key, exactly TWO rows in the whole file are a
    real service binding."""
    export = load_export(DOH)
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP, SERVICE))
    assert gap is None
    group_rows = [row for pairs in grouped.values() if pairs for key, row in pairs if key == GROUP]
    service_rows = [row for pairs in grouped.values() if pairs for key, row in pairs if key == SERVICE]
    assert len(group_rows) == 7
    assert all(row["servicename"] == row["servicegroupname"] for row in group_rows), "premise of the trap"
    assert len(service_rows) == 2


def test_an_absent_child_key_is_no_binding_of_that_kind(tmp_path):
    export = load_export(_write(tmp_path, LB_FILE, _aggregate([_lb_parent("LBV-A")])))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert gap is None
    assert grouped == {"LBV-A": []}


def test_a_parent_read_as_empty_is_none_not_an_empty_list(tmp_path):
    parents = [{"parentName": "LBV-A", "outcome": "EMPTY", "data": None}]
    export = load_export(_write(tmp_path, LB_FILE, _aggregate(parents)))
    assert export.binding_rows(LB_FILE, children=(GROUP,)) == ({"LBV-A": None}, None)


@pytest.mark.parametrize(
    "bad", [5, "SG-A", {"servicegroupname": "SG-A"}, ["tekst"]], ids=["getal", "tekst", "object", "lijst-met-tekst"]
)
def test_a_child_list_of_the_wrong_shape_is_a_read_gap_for_the_file(tmp_path, bad):
    parents = [_lb_parent("LBV-A", **{GROUP: bad}), _lb_parent("LBV-B", **{GROUP: [{"servicegroupname": "SG-B"}]})]
    export = load_export(_write(tmp_path, LB_FILE, _aggregate(parents)))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert grouped == {}
    assert gap is not None and GROUP in gap.reason


def test_a_child_key_that_was_not_asked_for_is_not_read(tmp_path):
    """A wrong shape under a key nobody asked for costs nothing: that list
    is not read, so it cannot be misread either."""
    parents = [_lb_parent("LBV-A", **{GROUP: [{"servicegroupname": "SG-A"}], "lbvserver_rewritepolicy_binding": 5})]
    export = load_export(_write(tmp_path, LB_FILE, _aggregate(parents)))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert gap is None
    assert grouped == {"LBV-A": [(GROUP, {"servicegroupname": "SG-A"})]}


@pytest.mark.parametrize(
    ("parents", "fragment"),
    [
        ([_lb_parent("LBV-A"), _lb_parent("LBV-A")], "dubbele parent"),
        (
            [{"parentName": "LBV-A", "outcome": "EMPTY", "data": {"lbvserver_binding": {"name": "LBV-A"}}}],
            "tegenstrijdige lezing",
        ),
        ([{"parentName": "LBV-A", "outcome": "RBAC_DENIED", "data": None}], "niet bruikbaar gelezen"),
        (
            [{"parentName": "LBV-A", "outcome": "OK", "data": {"lbvserver_binding": [{"name": "a"}, {"name": "b"}]}}],
            "meer dan een document",
        ),
        ([{"parentName": None, "outcome": "OK", "data": {"lbvserver_binding": {"name": "a"}}}], "parentName"),
    ],
    ids=["dubbel", "empty-met-data", "outcome", "twee-documenten", "parentnaam"],
)
def test_the_file_level_refusals_of_the_aggregate_form(tmp_path, parents, fragment):
    export = load_export(_write(tmp_path, LB_FILE, _aggregate(parents)))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert grouped == {}
    assert gap is not None and fragment in gap.reason


def test_an_aggregate_file_that_claims_another_binding_resource_is_a_read_gap(tmp_path):
    export = load_export(_write(tmp_path, LB_FILE, _aggregate([_lb_parent("LBV-A")], resource="servicegroup_binding")))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert grouped == {}
    assert gap is not None and "identiteit" in gap.reason


def test_an_unknown_shape_is_a_read_gap(tmp_path):
    document = dict(_aggregate([_lb_parent("LBV-A")]), shape="boom")
    export = load_export(_write(tmp_path, LB_FILE, document))
    grouped, gap = export.binding_rows(LB_FILE, children=(GROUP,))
    assert grouped == {}
    assert gap is not None and "niet ondersteund" in gap.reason


# ---------------------------------------------------------------------------
# Which nested kinds each parent carries.
# ---------------------------------------------------------------------------


def test_the_child_keys_of_each_parent_are_named():
    export = load_export(DOH)
    keys, gap = export.binding_child_keys("sslcertkey_binding.by-parent.json")
    assert gap is None
    assert keys["ns-server-certificate"] == ("sslcertkey_service_binding",)
    assert keys["CERT-SPARE-001"] == ()
    assert keys["CERT-WEB-001"] == ("sslcertkey_sslvserver_binding",)


def test_the_list_form_carries_no_nested_kinds():
    export = load_export(LAB)
    keys, gap = export.binding_child_keys("sslvserver_sslcertkey_binding.by-parent.json")
    assert gap is None
    assert set(keys.values()) == {()}


# ---------------------------------------------------------------------------
# binding_parents() validates both shapes.
# ---------------------------------------------------------------------------


def test_binding_parents_cross_checks_an_aggregate_file():
    export = load_export(DOH)
    coverage = export.binding_parents(LB_FILE)
    assert coverage.gaps == ()
    assert "LBV-APP-001" in coverage.names


def test_binding_parents_refuses_what_the_aggregate_reader_refuses(tmp_path):
    export = load_export(_write(tmp_path, LB_FILE, _aggregate([_lb_parent("LBV-A"), _lb_parent("LBV-A")])))
    coverage = export.binding_parents(LB_FILE)
    assert len(coverage.gaps) == 1
    assert "dubbele parent" in coverage.gaps[0].reason
