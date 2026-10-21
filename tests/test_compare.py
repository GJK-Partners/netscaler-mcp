"""One engine, four uses. Three kinds of difference, strictly separated -
and a fourth kind of ignorance (a field that was READ but is not usable
text or a plain number) that must never collapse into either "equal" or
"different". A block's own summary line may never claim more certainty
than the block holds: a resource excluded entirely (a real read gap or an
unreliable identity) or a NOT_ESTABLISHED entry inside a block both
downgrade that block's own "N [vastgesteld]"/"geen [vastgesteld]" line to
"niet vastgesteld" - "geen" is reserved for a block this answer actually
finished reading, on both sides, for every compared resource.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from conftest import _knowledge_file, seal_manifest
from upgrade_fase_harness import _call, _text

from nsmcp import compare as compare_module, disclosure as disclosure_module
from nsmcp.answer import Certainty
from nsmcp.compare import MODES, DifferenceKind, compare_answer, compare_exports
from nsmcp.disclosure import Disclosure, names_from_export, render
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.mcp_server import build_server, forget_identities
from nsmcp.retention import KEPT_SUFFIX

_KNOWLEDGE = Knowledge(version="vergelijktest", date="2026-09-06", age_days=0, missing=False)
_FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"

# A REAL NSHC export attempts every resource it supports, whether or not the
# appliance actually uses it (MEASURED on `_FIXTURE`: all seven of
# `compare.COMPARED`'s resources are present). A synthetic export that
# mentions only `config/lbvserver` would make the other six read as
# ONTBREEKT (not in the manifest at all) on BOTH sides - itself an equal
# failure the coverage-block fix (C1) now reports - which is realistic for
# a genuinely broken collector but not for the vast majority of tests in
# this file that are not exercising that. This default therefore matches
# what a real export looks like: every COMPARED resource present, EMPTY
# unless a test writes real rows for it. `_export()` MERGES a caller's own
# `resources` into this - never replaces it - so a test that overrides
# `config/lbvserver`'s status still gets the other six at their normal
# default instead of inventing six more asymmetries by accident.
_DEFAULT_RESOURCES = {
    "config/lbvserver": {"status": "OK"},
    "config/csvserver": {"status": "EMPTY"},
    "config/vpnvserver": {"status": "EMPTY"},
    "config/servicegroup": {"status": "EMPTY"},
    "config/service": {"status": "EMPTY"},
    "config/sslcertkey": {"status": "EMPTY"},
    "config/nsversion": {"status": "EMPTY"},
}


def _export(tmp_path, name, lbvservers, resources=None, extra_files=None):
    directory = tmp_path / name
    (directory / "objects").mkdir(parents=True, exist_ok=True)
    (directory / "objects" / "lbvserver.json").write_text(json.dumps({"lbvserver": lbvservers}), encoding="utf-8")
    for rel_path, payload in (extra_files or {}).items():
        path = directory / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    (directory / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-06T08:00:00.0000000Z",
                "resources": {**_DEFAULT_RESOURCES, **(resources or {})},
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    # An object file without its hash in the manifest is a read gap.
    seal_manifest(directory)
    return load_export(directory)


# --- A compared field that NAMES another appliance object. The comparison
# writes its two values as "A=<naam>, B=<naam>" - also when the object it
# names is absent from the export (a dangling reference), and then no other
# name family knows that name: it reached the answer verbatim at 'beperkt'.
# Per reference field: (resource, object file, identity field, identity,
# name on side A, name on side B). Synthetic names only. ---
DANGLING_REFERENCES = {
    "targetlbvserver": ("config/csvserver", "csvserver", "name", "CS-001", "PRIVATE-LB-A", "PRIVATE-LB-B"),
    "linkcertkeyname": ("config/sslcertkey", "sslcertkey", "certkey", "CERT-001", "PRIVATE-CERT-A", "PRIVATE-CERT-B"),
}

# Every compared configuration field that is NOT a reference, with what it
# carries instead. A field added to `compare.COMPARED` must land in the
# references above or in this table (a state field: the one below) - see
# test_every_compared_field_is_a_reference_or_a_value.
COMPARED_VALUE_FIELDS = {
    "servicetype": "een protocolwaarde van de appliance",
    "lbmethod": "een methodewaarde van de appliance",
    "persistencetype": "een persistentiewaarde van de appliance",
    "port": "een poortnummer",
    "ipv46": "een adres, geen objectnaam",
    "publickeysize": "een sleutellengte",
    "signaturealg": "een algoritmewaarde van de appliance",
    "version": "de build zelf",
}

# The same for every compared STATE field: a state word of the appliance,
# never an object name.
COMPARED_STATE_VALUE_FIELDS = {
    "curstate": "een standwaarde van de appliance (UP, DOWN, ...)",
    "state": "een standwaarde van de appliance (ENABLED, DISABLED)",
    "svrstate": "een standwaarde van de appliance (UP, DOWN, OUT OF SERVICE, ...)",
}


def _dangling_rows(field: str, side: str) -> tuple[str, dict]:
    resource, collection, key, identity, left_name, right_name = DANGLING_REFERENCES[field]
    row = {key: identity, field: left_name if side == "A" else right_name}
    if collection == "csvserver":
        row.update({"curstate": "UP", "servicetype": "HTTP"})
    return resource, {f"objects/{collection}.json": {collection: [row]}}


def _dangling_export(tmp_path, name, fields, side):
    resources, files = {}, {}
    for field in fields:
        resource, extra = _dangling_rows(field, side)
        resources[resource] = {"status": "OK"}
        files.update(extra)
    return _export(tmp_path, name, [], resources=resources, extra_files=files)


@pytest.mark.parametrize("field", sorted(DANGLING_REFERENCES))
def test_a_dangling_reference_is_a_name_the_export_knows(tmp_path, field):
    resource, _collection, key, identity, left_name, right_name = DANGLING_REFERENCES[field]
    left = _dangling_export(tmp_path, "links", [field], "A")
    right = _dangling_export(tmp_path, "rechts", [field], "B")
    # Premise: the named object is absent - no lbvserver at all, and the one
    # certificate is the one that carries the reference.
    assert left.objects("config/lbvserver")[0] == []
    assert [row[key] for row in left.objects(resource)[0]] == [identity]
    assert left_name in names_from_export(left)
    assert right_name in names_from_export(right)


@pytest.mark.parametrize("field", sorted(DANGLING_REFERENCES))
def test_beperkt_masks_a_dangling_reference_in_the_comparison(tmp_path, field):
    """The route of `rapport_vergelijk`: `compare_answer`, then `render` with
    the names of both exports. At 'volledig' the two names are the
    difference (the premise); at 'beperkt' each is a pseudonym; at
    'minimaal' the line is gone."""
    _resource, _collection, _key, _identity, left_name, right_name = DANGLING_REFERENCES[field]
    left = _dangling_export(tmp_path, "links", [field], "A")
    right = _dangling_export(tmp_path, "rechts", [field], "B")
    answer = compare_answer(left, right, _KNOWLEDGE, "run-diff")
    names = names_from_export(left) + names_from_export(right)

    def shown(level):
        return render(
            answer, level, tool="rapport_vergelijk", extra_names=names, pseudonym_table_path=tmp_path / "tabel.json"
        )

    assert f"{field}: A={left_name}, B={right_name} [vastgesteld]" in shown(Disclosure.FULL)
    limited = shown(Disclosure.LIMITED)
    assert left_name not in limited and right_name not in limited
    assert re.search(rf"- object-\d+: {field}: A=object-\d+, B=object-\d+ \[vastgesteld\]", limited), limited
    minimal = shown(Disclosure.MINIMAL)
    assert left_name not in minimal and right_name not in minimal


def test_without_the_reference_family_the_names_leak_at_beperkt(tmp_path, monkeypatch):
    """Mutation: switch the reference family off. The check above must then
    see both names at 'beperkt' - otherwise it could not have failed."""
    monkeypatch.setattr(disclosure_module, "names_in_compare_sources", lambda export: ())
    left = _dangling_export(tmp_path, "links", sorted(DANGLING_REFERENCES), "A")
    right = _dangling_export(tmp_path, "rechts", sorted(DANGLING_REFERENCES), "B")
    text = render(
        compare_answer(left, right, _KNOWLEDGE, "run-diff"),
        Disclosure.LIMITED,
        tool="rapport_vergelijk",
        extra_names=names_from_export(left) + names_from_export(right),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    for field, (*_, left_name, right_name) in DANGLING_REFERENCES.items():
        assert left_name in text and right_name in text, field


def _unclassified_compared_fields(compared):
    """Every (resource, field) in `compared` that is not exactly one of the
    two: a reference, harvested as a name, or a value named with what it
    carries - a configuration field in `COMPARED_VALUE_FIELDS`, a state
    field in `COMPARED_STATE_VALUE_FIELDS`."""
    references = {(resource, field) for resource, fields in compare_module.REFERENCE_FIELDS.items() for field in fields}
    unclassified = []
    for resource, _key, config_fields, state_fields, _single in compared:
        for fields, values in ((config_fields, COMPARED_VALUE_FIELDS), (state_fields, COMPARED_STATE_VALUE_FIELDS)):
            for field in fields:
                if ((resource, field) in references) == (field in values):
                    unclassified.append((resource, field))
    return unclassified


def test_every_compared_field_is_a_reference_or_a_value():
    """Every configuration and state field `compare.COMPARED` writes into a
    difference line is either a reference - harvested as a name - or a value
    named in `COMPARED_VALUE_FIELDS` or `COMPARED_STATE_VALUE_FIELDS` with
    what it carries instead. A new field that is in neither fails here,
    before it can print an object name nothing masks."""
    references = {(resource, field) for resource, fields in compare_module.REFERENCE_FIELDS.items() for field in fields}
    assert _unclassified_compared_fields(compare_module.COMPARED) == []
    compared = {
        (resource, field)
        for resource, _key, config_fields, state_fields, _single in compare_module.COMPARED
        for field in (*config_fields, *state_fields)
    }
    assert references <= compared, "een verwijzingsveld dat niet vergeleken wordt"
    assert {field: resource for resource, field in references} == {
        field: case[0] for field, case in DANGLING_REFERENCES.items()
    }


@pytest.mark.parametrize("kind", ["configuratieveld", "standveld"])
def test_an_unclassified_compared_field_fails_the_classification(kind):
    """Mutation: a field that names an object (`backupvserver`) added to the
    compared fields of `config/lbvserver`, once as a configuration field and
    once as a state field. The classification above must see it either way,
    or it could not have failed on the day such a field is added."""
    mutated = []
    for resource, key, config_fields, state_fields, single in compare_module.COMPARED:
        if resource == "config/lbvserver" and kind == "configuratieveld":
            config_fields = (*config_fields, "backupvserver")
        elif resource == "config/lbvserver":
            state_fields = (*state_fields, "backupvserver")
        mutated.append((resource, key, config_fields, state_fields, single))
    assert _unclassified_compared_fields(tuple(mutated)) == [("config/lbvserver", "backupvserver")]


@pytest.mark.parametrize("tool", ["rapport_vergelijk", "rapport_wat_is_er_veranderd"])
def test_both_compare_tools_mask_a_dangling_reference_at_beperkt(tmp_path, tool):
    """Through the real MCP server at openheid 'beperkt': the kept previous
    export (side A) and the current one (side B), both reference fields
    dangling and different on the two sides."""
    forget_identities()
    fields = sorted(DANGLING_REFERENCES)
    current = _dangling_export(tmp_path, "export", fields, "B")
    kept = _dangling_export(tmp_path, f"export{KEPT_SUFFIX}20260819T090000Z", fields, "A")
    manifest_path = kept.directory / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collectedAtUtc"] = "2026-08-19T09:00:00.0000000Z"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    server = build_server(
        current.directory,
        _knowledge_file(tmp_path),
        disclosure=Disclosure.LIMITED,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    args = {"mapA": kept.directory.name, "mapB": current.directory.name} if tool == "rapport_vergelijk" else {}
    result = _call(server, tool, args)
    text = _text(result)
    assert not result.isError, text
    for field, (*_, left_name, right_name) in DANGLING_REFERENCES.items():
        assert left_name not in text and right_name not in text, field
        assert re.search(rf"- object-\d+: {field}: A=object-\d+, B=object-\d+ \[vastgesteld\]", text), (field, text)


def test_a_state_difference_is_never_a_configuration_difference(tmp_path):
    left = _export(tmp_path, "a", [{"name": "LB_A", "curstate": "UP", "lbmethod": "LEASTCONNECTION"}])
    right = _export(tmp_path, "b", [{"name": "LB_A", "curstate": "DOWN", "lbmethod": "LEASTCONNECTION"}])
    result = compare_exports(left, right, "HA-parity")
    assert [d.subject for d in result.configuration] == []
    assert [d.subject for d in result.state] == ["LB_A"]


def test_ha_parity_reports_no_finding_on_a_state_difference_alone(tmp_path):
    left = _export(tmp_path, "c", [{"name": "LB_A", "curstate": "UP"}])
    right = _export(tmp_path, "d", [{"name": "LB_A", "curstate": "DOWN"}])
    text = compare_answer(left, right, _KNOWLEDGE, "HA-parity").to_text()
    assert "- configuratieverschillen: geen [vastgesteld]" in text
    assert "standverschillen zijn bij HA-pariteit normaal" in text


def test_a_missing_object_is_a_configuration_difference(tmp_path):
    left = _export(tmp_path, "e", [{"name": "LB_A", "curstate": "UP"}, {"name": "LB_B", "curstate": "UP"}])
    right = _export(tmp_path, "f", [{"name": "LB_A", "curstate": "UP"}])
    result = compare_exports(left, right, "drift")
    assert [(d.subject, d.detail) for d in result.configuration] == [("LB_B", "aanwezig in A, niet in B")]


def test_a_different_coverage_is_a_coverage_difference_and_never_drift(tmp_path):
    left = _export(tmp_path, "g", [{"name": "LB_A", "curstate": "UP"}])
    right = _export(tmp_path, "h", [], resources={"config/lbvserver": {"status": "RBAC_DENIED"}})
    result = compare_exports(left, right, "drift")
    assert [d.subject for d in result.coverage] == ["config/lbvserver"]
    assert result.coverage[0].certainty is Certainty.ESTABLISHED
    assert result.configuration == (), "een bron die in B niet gelezen is levert geen verdwenen object op"
    text = compare_answer(left, right, _KNOWLEDGE, "drift").to_text()
    assert "- dekkingsverschillen: 1 [vastgesteld]" in text


def test_the_four_modes_are_the_pinned_ones():
    """Dispatch ruling (binding over the preflight's Dutch sample): the API
    modes are the NSHC healthcheck's own labels, literally - parity with the
    tool this module mirrors. Dutch prose explaining them lives only in the
    tool description and the handleiding, never in `MODES` itself."""
    assert MODES == ("HA-parity", "drift", "run-diff", "pre/post")


def test_an_unknown_mode_is_refused(tmp_path):
    left = _export(tmp_path, "i", [])
    right = _export(tmp_path, "j", [])
    try:
        compare_exports(left, right, "zomaar")
    except ValueError as exc:
        assert "zomaar" in str(exc)
    else:
        raise AssertionError("een onbekende modus hoort geweigerd te worden")


def test_a_field_present_but_unreadable_is_not_established_and_never_echoes_the_raw_value(tmp_path):
    """`lbmethod` is a JSON bool on the left, real text on the right -
    neither absent nor equal, so this must become NOT VASTGESTELD named by
    its shape, never by `True` or `LEASTCONNECTION` - and the block's own
    summary line must say so too: a block holding a
    NOT_ESTABLISHED entry may not claim "geen [vastgesteld]"."""
    left = _export(tmp_path, "k", [{"name": "LB_A", "curstate": "UP", "lbmethod": True}])
    right = _export(tmp_path, "l", [{"name": "LB_A", "curstate": "UP", "lbmethod": "LEASTCONNECTION"}])
    result = compare_exports(left, right, "drift")
    assert len(result.configuration) == 1
    diff = result.configuration[0]
    assert diff.subject == "LB_A"
    assert diff.certainty is Certainty.NOT_ESTABLISHED
    assert "lbmethod" in diff.detail
    assert "waarde van het type bool" in diff.reason
    text = compare_answer(left, right, _KNOWLEDGE, "drift").to_text()
    assert "True" not in text
    assert "LEASTCONNECTION" not in text
    assert "lbmethod" in text and "niet vastgesteld" in text
    # The summary line itself must not claim "geen [vastgesteld]" next
    # to an unestablished field - it must say NIET VASTGESTELD too.
    assert "- configuratieverschillen: geen [vastgesteld]" not in text
    assert "- configuratieverschillen: niet vastgesteld [niet vastgesteld]" in text
    assert "1 veld/object(en) niet vastgesteld" in text


def test_a_missing_state_field_is_not_established_not_silently_equal(tmp_path):
    """State fields are required (health.py's own `_classify_state`
    precedent) - a genuinely ABSENT curstate is not the same honest silence
    an absent config field is."""
    left = _export(tmp_path, "m", [{"name": "LB_A"}])
    right = _export(tmp_path, "n", [{"name": "LB_A", "curstate": "UP"}])
    result = compare_exports(left, right, "drift")
    assert result.configuration == ()
    assert len(result.state) == 1
    diff = result.state[0]
    assert diff.subject == "LB_A"
    assert diff.certainty is Certainty.NOT_ESTABLISHED
    assert "curstate" in diff.detail
    assert "de sleutel ontbreekt" in diff.reason


def test_nsversion_is_compared_through_the_singleton_reader(tmp_path):
    """`config/nsversion` is a bare object in a real export, not a list of
    one - `_index()` must read it through `export.single()`, never treat
    the natural `objects()` shape-gap on it as a genuine read failure."""
    resources = {"config/lbvserver": {"status": "OK"}, "config/nsversion": {"status": "OK"}}
    left = _export(
        tmp_path,
        "o",
        [],
        resources=resources,
        extra_files={"objects/nsversion.json": {"nsversion": {"version": "13.1-49.13"}}},
    )
    right = _export(
        tmp_path,
        "p",
        [],
        resources=resources,
        extra_files={"objects/nsversion.json": {"nsversion": {"version": "14.1-21.57"}}},
    )
    result = compare_exports(left, right, "run-diff")
    assert sorted(d.subject for d in result.configuration) == ["13.1-49.13", "14.1-21.57"]
    assert all(d.certainty is Certainty.ESTABLISHED for d in result.configuration)
    assert all(d.subject_is_name is False for d in result.configuration), (
        "a version string is not an appliance object name"
    )
    assert result.state == ()


def test_difference_kind_names_exactly_the_three_blocks():
    assert {member.value for member in DifferenceKind} == {"configuratie", "stand", "dekking"}


def test_the_real_export_compared_with_itself_has_no_not_established_fields():
    """A plain (non-bool) int is a READABLE value, not an unclear shape -
    `port`/`publickeysize` are JSON ints on the real export, so comparing
    it with itself must establish equality everywhere, never report those
    fields as niet vastgesteld."""
    export = load_export(_FIXTURE)
    result = compare_exports(export, export, "run-diff")
    assert result.configuration == ()
    assert result.state == ()


def test_equal_integer_fields_are_an_established_equality(tmp_path):
    left = _export(tmp_path, "q", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    right = _export(tmp_path, "r", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    assert compare_exports(left, right, "drift").configuration == ()


def test_different_integer_fields_are_an_established_configuration_difference(tmp_path):
    left = _export(tmp_path, "s", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    right = _export(tmp_path, "t", [{"name": "LB_A", "curstate": "UP", "port": 8443}])
    result = compare_exports(left, right, "drift")
    assert len(result.configuration) == 1
    diff = result.configuration[0]
    assert diff.certainty is Certainty.ESTABLISHED
    assert diff.detail == "port: A=443, B=8443"


def test_a_bool_next_to_a_matching_int_is_still_not_established(tmp_path):
    """`bool` subclasses `int` in Python - this pins that a bool never
    slips through the int-is-readable branch."""
    left = _export(tmp_path, "u", [{"name": "LB_A", "curstate": "UP", "port": True}])
    right = _export(tmp_path, "v", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    result = compare_exports(left, right, "drift")
    assert len(result.configuration) == 1
    diff = result.configuration[0]
    assert diff.certainty is Certainty.NOT_ESTABLISHED
    assert "type bool" in diff.reason


def test_text_and_integer_with_the_same_digits_compare_as_equal(tmp_path):
    left = _export(tmp_path, "w", [{"name": "LB_A", "curstate": "UP", "port": "443"}])
    right = _export(tmp_path, "x", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    assert compare_exports(left, right, "drift").configuration == ()


# --- The motor must stay fail-closed on a
# gap shared by both sides, a form gap behind an OK manifest, an unreliable
# identity, and must name its own reading scope. ---


def test_equal_read_failure_on_both_sides_is_never_geen_vastgesteld(tmp_path):
    """C1: RBAC_DENIED on `config/lbvserver` on BOTH sides must not read as
    'geen [vastgesteld]' anywhere - equal missing coverage is not a
    successful comparison. The coverage block reports it too, as
    NOT_ESTABLISHED (we know only that NEITHER side proves anything here,
    not that they agree on nothing changing)."""
    left = _export(tmp_path, "c1a", [], resources={"config/lbvserver": {"status": "RBAC_DENIED"}})
    right = _export(tmp_path, "c1b", [], resources={"config/lbvserver": {"status": "RBAC_DENIED"}})
    result = compare_exports(left, right, "drift")
    assert [d.subject for d in result.coverage] == ["config/lbvserver"]
    assert result.coverage[0].certainty is Certainty.NOT_ESTABLISHED
    assert result.coverage[0].reason
    text = compare_answer(left, right, _KNOWLEDGE, "drift").to_text()
    assert "- dekkingsverschillen: geen [vastgesteld]" not in text
    assert "- dekkingsverschillen: niet vastgesteld [niet vastgesteld]" in text
    # the same resource also excludes the configuration block from an
    # honest "geen" - it has config fields and was never actually compared.
    assert "- configuratieverschillen: geen [vastgesteld]" not in text
    assert "- configuratieverschillen: niet vastgesteld [niet vastgesteld]" in text
    assert "niet in de vergelijking meegenomen" in text


def test_a_form_gap_behind_an_ok_manifest_is_a_real_readgap(tmp_path):
    """C2: `coverage_of()` only verifies the manifest hash, never the
    SHAPE of the content - an object instead of a list behind a
    status:OK manifest entry is a genuine read failure this module must
    catch itself, and surface as a real `ReadGap` (never a silent
    'geen [vastgesteld]')."""
    left = _export(tmp_path, "c2a", [{"name": "LB_A", "curstate": "UP"}])
    right_dir = tmp_path / "c2b"
    (right_dir / "objects").mkdir(parents=True)
    # An OBJECT, not a list - a malformed lbvserver.json a real manifest
    # hash can still match byte-for-byte.
    (right_dir / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": {"name": "LB_A", "curstate": "UP"}}), encoding="utf-8"
    )
    (right_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-06T08:00:00.0000000Z",
                "resources": _DEFAULT_RESOURCES,
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(right_dir)
    right = load_export(right_dir)

    result = compare_exports(left, right, "drift")
    assert result.configuration == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].source == "config/lbvserver (B)"
    assert result.gaps[0].reason

    text = compare_answer(left, right, _KNOWLEDGE, "drift").to_text()
    assert "- configuratieverschillen: geen [vastgesteld]" not in text
    assert "NIET VASTGESTELD (geen stille aanname):" in text
    assert "config/lbvserver (B)" in text


def test_duplicate_identity_is_reported_never_silently_overwritten(tmp_path):
    """Two rows sharing one name used to let a plain dict comprehension
    keep only the LAST one, silently - a real difference could hide behind
    the row that lost. Now it is its own NOT_ESTABLISHED finding."""
    left = _export(
        tmp_path,
        "i2a",
        [
            {"name": "LB_A", "curstate": "UP", "port": 80},
            {"name": "LB_A", "curstate": "UP", "port": 443},
        ],
    )
    right = _export(tmp_path, "i2b", [{"name": "LB_A", "curstate": "UP", "port": 443}])
    result = compare_exports(left, right, "drift")
    assert len(result.configuration) == 1
    diff = result.configuration[0]
    assert diff.subject == "config/lbvserver"
    assert diff.certainty is Certainty.NOT_ESTABLISHED
    assert "dubbel" in diff.reason
    assert "LB_A" in diff.reason


def test_a_row_without_a_readable_identity_is_reported_never_silently_dropped(tmp_path):
    """A row whose identity field is not usable text used to simply
    never enter the index - invisible on both sides of the diff. Now it is
    its own NOT_ESTABLISHED finding, named by count, never by guessing a
    name for it."""
    left = _export(tmp_path, "i2c", [{"name": True, "curstate": "UP"}])
    right = _export(tmp_path, "i2d", [])
    result = compare_exports(left, right, "drift")
    assert len(result.configuration) == 1
    diff = result.configuration[0]
    assert diff.subject == "config/lbvserver"
    assert diff.certainty is Certainty.NOT_ESTABLISHED
    assert "zonder leesbare naam" in diff.reason


def test_coverage_difference_carries_the_underlying_gap_reason(tmp_path):
    """`SourceState.reason` (coverage.py) must travel with a coverage
    Difference - the word alone ("GEWEIGERD") does not say WHY."""
    left = _export(tmp_path, "i4a", [{"name": "LB_A", "curstate": "UP"}])
    right = _export(tmp_path, "i4b", [], resources={"config/lbvserver": {"status": "RBAC_DENIED"}})
    result = compare_exports(left, right, "drift")
    assert len(result.coverage) == 1
    assert "RBAC_DENIED" in result.coverage[0].reason


def test_the_answer_names_its_own_scope(tmp_path):
    """An empty block is a statement about the SEVEN compared
    resources and their own field set, never about the appliance's whole
    configuration - bindings, monitors, SSL profiles, policies and the
    running config are out of scope, and the answer says so."""
    left = _export(tmp_path, "i7a", [])
    right = _export(tmp_path, "i7b", [])
    answer = compare_answer(left, right, _KNOWLEDGE, "drift")
    subjects = [n.subject for n in answer.not_assessed]
    assert any("buiten deze vergelijking" in s for s in subjects)
    reasons = " ".join(n.reason for n in answer.not_assessed)
    assert "bindingen" in reasons and "running config" in reasons


def test_minimal_disclosure_does_not_double_count_the_block_summaries(tmp_path):
    """M3: the three block-header findings summarize the findings that
    follow them - `disclosure._minimal()`'s "N vastgestelde bevinding(en)"
    must count the real differences once, not the summary lines too."""
    left = _export(tmp_path, "m3a", [{"name": "LB_A", "curstate": "UP"}, {"name": "LB_B", "curstate": "UP"}])
    right = _export(tmp_path, "m3b", [{"name": "LB_A", "curstate": "UP"}])
    answer = compare_answer(left, right, _KNOWLEDGE, "drift")
    text = render(answer, Disclosure.MINIMAL, tool="rapport_vergelijk")
    # exactly one real difference (LB_B present only in A); the three block
    # headers must not inflate that to four.
    assert "- 1 bevinding(en)" in text


# --- rapport_wat_is_er_veranderd (automation 2): a thin shell on the same
# engine, tested here alongside it so the two can never drift apart. ---


def test_both_tools_land_on_the_same_engine(monkeypatch, tmp_path):
    """A thin shell. If it ever grows its own comparison, this test is
    where that shows - not in a customer report that says two things."""
    import nsmcp.compare as module

    calls = []
    original = module.compare_exports

    def spy(left, right, mode):
        calls.append(mode)
        return original(left, right, mode)

    monkeypatch.setattr(module, "compare_exports", spy)
    left = _export(tmp_path, "k", [{"name": "LB_A", "curstate": "UP"}])
    right = _export(tmp_path, "l", [{"name": "LB_A", "curstate": "UP"}])
    module.compare_answer(left, right, _KNOWLEDGE, "run-diff")
    module.compare_answer(left, right, _KNOWLEDGE, "drift")
    assert calls == ["run-diff", "drift"]


def test_two_newest_picks_the_current_export_and_the_newest_kept_one(tmp_path):
    """`two_newest()` ranks through `retention.newest_kept()` - which sorts
    by each candidate's OWN manifest `collectedAtUtc`, never by its name
    suffix. The two kept siblings below therefore carry DISTINCT, correctly
    ordered timestamps: giving them the SAME timestamp ties the sort and
    makes the pick depend on filesystem iteration order instead of on a
    real "which one is newer" fact, so that is not reproduced here."""
    from nsmcp.compare import two_newest
    from nsmcp.retention import KEPT_SUFFIX

    current = tmp_path / "export"
    (current / "objects").mkdir(parents=True)
    (current / "export-manifest.json").write_text(
        json.dumps(
            {"manifestVersion": "1.1", "collectedAtUtc": "2026-09-06T08:00:00.0000000Z", "resources": {}, "files": {}}
        ),
        encoding="utf-8",
    )
    seal_manifest(current)
    for stamp, moment in (
        ("20260901T080000Z", "2026-09-01T08:00:00.0000000Z"),
        ("20260903T080000Z", "2026-09-03T08:00:00.0000000Z"),
    ):
        kept = tmp_path / f"export{KEPT_SUFFIX}{stamp}"
        (kept / "objects").mkdir(parents=True)
        (kept / "export-manifest.json").write_text(
            json.dumps({"manifestVersion": "1.1", "collectedAtUtc": moment, "resources": {}, "files": {}}),
            encoding="utf-8",
        )
        seal_manifest(kept)
    older, newer = two_newest(current)
    assert newer == current
    assert older.name == f"export{KEPT_SUFFIX}20260903T080000Z"


def test_without_a_kept_export_it_says_there_is_nothing_to_compare(tmp_path):
    """Issue #28: no kept export means 'nothing to compare with', never
    'geen verschillen'. Those two read the same to a hurried human and mean
    the opposite."""
    from nsmcp.compare import two_newest

    current = tmp_path / "export"
    (current / "objects").mkdir(parents=True)
    (current / "export-manifest.json").write_text(
        json.dumps(
            {"manifestVersion": "1.1", "collectedAtUtc": "2026-09-06T08:00:00.0000000Z", "resources": {}, "files": {}}
        ),
        encoding="utf-8",
    )
    seal_manifest(current)
    assert two_newest(current) == (None, current)
