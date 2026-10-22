from __future__ import annotations

import hashlib
import json
from pathlib import Path

from conftest import seal_manifest

from nsmcp.dienst import names_in_service_sources, service_status
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge

K = Knowledge(version="x", date="2026-09-02", age_days=0, missing=False)

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


def _export(tmp_path: Path, lbvservers, lb_parents, sg_parents, lb_status="OK") -> Path:
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    manifest = {
        "manifestVersion": "1.1",
        "collectedAtUtc": "2026-09-02T06:00:00.0000000Z",
        "resources": {"config/lbvserver": {"status": lb_status}},
        "files": {},
    }
    (m / "objects" / "lbvserver.json").write_text(
        json.dumps({"errorcode": 0, "message": "Done", "lbvserver": lbvservers}), encoding="utf-8"
    )
    # Deviation from the original fixture text (adapted minimally):
    # `_binding_document()` (export.py) refuses
    # ANY by-parent binding file whose "bindings/<name>" key is absent from
    # manifest.files ("geen hash in het manifest; geen hash is geen
    # vertrouwen") - the same hash-or-nothing discipline every other fixture
    # in this suite (test_no_network.py, test_disclosure.py) already
    # follows. The original `manifest["files"] = {}` left both binding files
    # unhashed, so every case - including the success case - read back as a
    # read gap instead of the intended content. Hashes are added here, verbatim
    # otherwise.
    for fname, resource, parent_resource, parent_key, parents in (
        ("lbvserver_binding.by-parent.json", "lbvserver_binding", "lbvserver", "name", lb_parents),
        ("servicegroup_binding.by-parent.json", "servicegroup_binding", "servicegroup", "servicegroupname", sg_parents),
    ):
        body = {
            "bindingResource": resource,
            "parentResource": parent_resource,
            "parentKey": parent_key,
            "shape": "aggregate",
            "parents": parents,
        }
        raw = json.dumps(body)
        (m / "bindings" / fname).write_text(raw, encoding="utf-8")
        manifest["files"][f"bindings/{fname}"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    (m / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(m)
    return m


# MEASURED SHAPE, and the reason these two helpers look the way they do.
# On the real collector output in `tests/fixtures/lab-export-vpx-20260826/`
# every file with `shape == "aggregate"` writes `data.<bindingResource>` as an
# OBJECT (the parent key field plus one nested "<parent>_<child>_binding" LIST
# per bound child type), never as a bare list - proven by
# `test_real_aggregate_files_write_data_resource_as_an_object` below, which
# reads all three real aggregate files. The synthetic parents here mirror
# `bindings/vpnvserver_binding.by-parent.json` (parentKey "name", data object
# with "name" + nested binding lists) with lbvserver/servicegroup content.
def _lb_parent(name, sg):
    return {
        "parentName": name,
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": name, "lbvserver_servicegroup_binding": [{"servicegroupname": sg}]}},
    }


def _sg_parent(sg, members):
    return {
        "parentName": sg,
        "outcome": "OK",
        "data": {"servicegroup_binding": {"servicegroupname": sg, "servicegroup_servicegroupmember_binding": members}},
    }


def _one_member(tmp_path, member, service="d", group="sg"):
    """One vserver, one bound servicegroup, one member - the shortest road to
    a single member line."""
    root = _export(
        tmp_path,
        [{"name": service, "effectivestate": "UP", "health": "100"}],
        [_lb_parent(service, group)],
        [_sg_parent(group, [member])],
    )
    return service_status(load_export(root), K, service)


# ---------------------------------------------------------------------------
# The real shape, measured - the premise under every synthetic fixture above.
# ---------------------------------------------------------------------------


def test_real_aggregate_files_write_data_resource_as_an_object():
    """MEASURED on the real collector output. The three files this export
    carries with `shape == "aggregate"` - vpnvserver_binding,
    sslcertkey_binding, lbmonitor_binding - all write
    `parents[].data.<bindingResource>` as an OBJECT, while every
    `shape == "list"` file writes a LIST there. This is the ONLY real
    aggregate-shape evidence the repo has, and it is what `_aggregate_rows`
    must accept: an earlier version demanded a list on the aggregate files
    too, so every real aggregate file read as "niet de verwachte vorm".
    """
    aggregate, listed = [], []
    for path in sorted((FIXTURE / "bindings").glob("*.by-parent.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        resource = raw["bindingResource"]
        for parent in raw["parents"]:
            data = parent.get("data")
            if not isinstance(data, dict) or resource not in data:
                continue
            (aggregate if raw["shape"] == "aggregate" else listed).append(type(data[resource]).__name__)
    assert aggregate and set(aggregate) == {"dict"}, aggregate
    assert listed and set(listed) == {"list"}, listed


# ---------------------------------------------------------------------------
# The original four tests (bodies/assertions unchanged).
# ---------------------------------------------------------------------------


def test_status_lists_the_vserver_and_its_members(tmp_path):
    export = load_export(
        _export(
            tmp_path,
            [{"name": "gjkdemo_lb_vs_proefdienst_443", "effectivestate": "UP", "health": "100"}],
            [_lb_parent("gjkdemo_lb_vs_proefdienst_443", "gjkdemo_sg_proefdienst")],
            [
                _sg_parent(
                    "gjkdemo_sg_proefdienst",
                    [
                        {"servername": "gjkdemo_web01", "port": 3389, "svrstate": "UP"},
                        {"servername": "gjkdemo_web02", "port": 3389, "svrstate": "OUT OF SERVICE"},
                    ],
                )
            ],
        )
    )
    text = service_status(export, K, "gjkdemo_lb_vs_proefdienst_443").to_text()
    assert "gjkdemo_lb_vs_proefdienst_443: effectivestate=UP, health=100 [vastgesteld]" in text
    assert "gjkdemo_web01: UP (poort 3389) [vastgesteld]" in text
    assert "gjkdemo_web02: OUT OF SERVICE (poort 3389) [vastgesteld]" in text


def test_unknown_vserver_is_a_finding_not_an_error(tmp_path):
    export = load_export(_export(tmp_path, [], [], []))
    text = service_status(export, K, "bestaat_niet").to_text()
    assert "bestaat_niet: niet gevonden in config/lbvserver" in text


def test_missing_member_file_is_a_read_gap(tmp_path):
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [])
    (root / "bindings" / "servicegroup_binding.by-parent.json").unlink()
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text and "servicegroup_binding.by-parent.json" in text


def test_wrong_shape_is_a_read_gap_not_a_guess(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [{"parentName": "sg", "outcome": "OK", "data": {"servicegroup_binding": "geen lijst"}}],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text and "vorm" in text


# ---------------------------------------------------------------------------
# The aggregate shape itself.
# ---------------------------------------------------------------------------


def test_a_list_with_exactly_one_object_is_read_like_the_object(tmp_path):
    """NITRO answers the same singleton in both shapes depending on the
    resource, and `Export.single()` already accepts both for object files.
    The same both-shapes rule here, so an export that happens to wrap the
    aggregate row in a list of one still reads."""
    lb = {
        "parentName": "d",
        "outcome": "OK",
        "data": {"lbvserver_binding": [{"name": "d", "lbvserver_servicegroup_binding": [{"servicegroupname": "sg"}]}]},
    }
    sg = {
        "parentName": "sg",
        "outcome": "OK",
        "data": {
            "servicegroup_binding": [
                {
                    "servicegroupname": "sg",
                    "servicegroup_servicegroupmember_binding": [
                        {"servername": "web01", "port": 3389, "svrstate": "UP"}
                    ],
                }
            ]
        },
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [lb], [sg])
    text = service_status(load_export(root), K, "d").to_text()
    assert "web01: UP (poort 3389) [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


def test_an_empty_data_list_is_a_read_gap_naming_the_shape(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [{"parentName": "sg", "outcome": "OK", "data": {"servicegroup_binding": []}}],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text
    assert "lijst met 0 element" in text


def test_a_non_object_element_in_the_data_list_is_a_read_gap(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [{"parentName": "sg", "outcome": "OK", "data": {"servicegroup_binding": ["tekst"]}}],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text and "vorm" in text
    assert "lid/leden" not in text


def test_data_itself_not_an_object_is_a_read_gap(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [{"parentName": "sg", "outcome": "OK", "data": ["geen object"]}],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text and "vorm" in text


# ---------------------------------------------------------------------------
# More than one row, and a duplicate parent.
# ---------------------------------------------------------------------------


def test_more_than_one_document_for_a_parent_is_a_read_gap_not_the_first_row(tmp_path):
    """`data[resource][0]` silently threw away every further row. Two rows
    for one parent means it cannot be established which of them carries the
    bindings of this object - so it is a read gap, not row one."""
    sg = {
        "parentName": "sg",
        "outcome": "OK",
        "data": {
            "servicegroup_binding": [
                {
                    "servicegroupname": "sg",
                    "servicegroup_servicegroupmember_binding": [
                        {"servername": "web01", "port": 3389, "svrstate": "UP"}
                    ],
                },
                {
                    "servicegroupname": "sg",
                    "servicegroup_servicegroupmember_binding": [
                        {"servername": "web02", "port": 3389, "svrstate": "UP"}
                    ],
                },
            ]
        },
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [sg])
    text = service_status(load_export(root), K, "d").to_text()
    assert "meer dan een document" in text
    assert "web01" not in text and "web02" not in text


def test_a_duplicate_parent_is_a_read_gap_not_a_silent_overwrite(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [
            _sg_parent("sg", [{"servername": "web01", "port": 3389, "svrstate": "UP"}]),
            _sg_parent("sg", [{"servername": "web02", "port": 3389, "svrstate": "UP"}]),
        ],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "dubbele parent" in text
    assert "web01" not in text and "web02" not in text


# ---------------------------------------------------------------------------
# An absent or unreadable parent is never "0 lid/leden".
# ---------------------------------------------------------------------------


def test_a_bound_servicegroup_absent_from_the_file_is_not_established(tmp_path):
    """The third state of export.py's module docstring: the servicegroup IS
    bound (read from the lbvserver file), but the servicegroup file carries
    no parent entry for it at all. Its members were never read, so "0
    lid/leden [vastgesteld]" would be an unread source posing as an
    established emptiness."""
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [_sg_parent("een_andere_groep", [])],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "0 lid/leden" not in text
    assert "NIET VASTGESTELD" in text
    assert "sg ontbreekt in het bindingsbestand" in text


def test_a_servicegroup_read_gap_yields_no_member_count_at_all(tmp_path):
    """With the servicegroup file unreadable the old code still
    rendered "servicegroup met 0 lid/leden [vastgesteld]" right next to the
    gap - a count next to the statement that nothing was counted."""
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [])
    (root / "bindings" / "servicegroup_binding.by-parent.json").unlink()
    answer = service_status(load_export(root), K, "d")
    text = answer.to_text()
    assert "lid/leden" not in text
    assert all(f.certainty.value == "niet vastgesteld" for f in answer.findings if f.subject == "sg")


def test_a_parent_with_outcome_empty_that_carries_data_is_a_read_gap(tmp_path):
    """Mirrors the EMPTY branch of `export._flatten_by_parent`: EMPTY plus
    data is a contradictory reading, never a silent emptiness."""
    sg = {
        "parentName": "sg",
        "outcome": "EMPTY",
        "data": {
            "servicegroup_binding": {
                "servicegroupname": "sg",
                "servicegroup_servicegroupmember_binding": [{"servername": "web01", "port": 3389, "svrstate": "UP"}],
            }
        },
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [sg])
    text = service_status(load_export(root), K, "d").to_text()
    assert "tegenstrijdige lezing" in text
    assert "web01" not in text


def test_a_parent_read_as_genuinely_empty_is_zero_members_established(tmp_path):
    """The other side of the same coin: EMPTY without data IS an established
    emptiness (the collector read it and there was nothing), so it must NOT
    become a read gap."""
    sg = {"parentName": "sg", "outcome": "EMPTY", "data": None}
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [sg])
    text = service_status(load_export(root), K, "d").to_text()
    assert "sg: servicegroup met 0 lid/leden [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


def test_the_vserver_absent_from_its_own_binding_file_is_not_established(tmp_path):
    """Same third state one level up: the lbvserver exists in
    config/lbvserver but has no parent entry in the lbvserver binding file,
    so which servicegroup it hangs on was never read - never "geen
    servicegroup gebonden [vastgesteld]"."""
    root = _export(
        tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("een_andere_dienst", "sg")], []
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "geen servicegroup gebonden" not in text
    assert "NIET VASTGESTELD" in text and "d ontbreekt in het bindingsbestand" in text


# ---------------------------------------------------------------------------
# config/lbvserver unreadable is not "niet gevonden".
# ---------------------------------------------------------------------------


def test_unreadable_lbvserver_source_is_not_a_not_found_claim(tmp_path):
    """ "Niet gevonden" is a statement about a source that WAS read. With
    config/lbvserver denied, whether this dienst exists is simply
    unknown."""
    root = _export(tmp_path, [], [], [], lb_status="RBAC_DENIED")
    text = service_status(load_export(root), K, "d").to_text()
    assert "niet gevonden in config/lbvserver" not in text
    assert "NIET VASTGESTELD" in text and "RBAC_DENIED" in text
    assert "[vastgesteld]" not in text


# ---------------------------------------------------------------------------
# Member fields.
# ---------------------------------------------------------------------------


def test_a_member_without_a_readable_svrstate_is_not_established(tmp_path):
    answer = _one_member(tmp_path, {"servername": "web02", "port": 3389, "svrstate": None})
    text = answer.to_text()
    assert "web02: toestand niet leesbaar (poort 3389) [niet vastgesteld]" in text
    assert "None" not in text


def test_a_member_without_an_svrstate_key_is_not_established(tmp_path):
    text = _one_member(tmp_path, {"servername": "web02", "port": 3389}).to_text()
    assert "web02: toestand niet leesbaar (poort 3389) [niet vastgesteld]" in text


def test_an_unknown_svrstate_value_is_not_established_and_names_the_value(tmp_path):
    text = _one_member(tmp_path, {"servername": "web02", "port": 3389, "svrstate": "TROUBLESHOOTING"}).to_text()
    assert "TROUBLESHOOTING" in text
    assert "[vastgesteld]" not in text.split("web02:")[1].split("\n")[0]


def test_the_known_nitro_states_are_mapped_explicitly(tmp_path):
    for state in ("UP", "DOWN", "OUT OF SERVICE", "GOING OUT OF SERVICE"):
        text = _one_member(
            tmp_path / state.replace(" ", "_"), {"servername": "web01", "port": 3389, "svrstate": state}
        ).to_text()
        assert f"web01: {state} (poort 3389) [vastgesteld]" in text


def test_a_member_without_a_servername_is_identified_by_its_ip(tmp_path):
    """An IP-bound member carries no servername. "None: ? (poort 3389)" both
    claimed an established state and put the literal string "None" into the
    text (and thus into the disclosure pseudonym table)."""
    for field in ("ip", "ipaddress"):
        text = _one_member(tmp_path / field, {field: "10.20.30.40", "port": 3389, "svrstate": "UP"}).to_text()
        assert "10.20.30.40: UP (poort 3389), lid op IP [vastgesteld]" in text
        assert "None" not in text


def test_a_member_with_neither_a_name_nor_an_ip_is_a_read_gap(tmp_path):
    answer = _one_member(tmp_path, {"port": 3389, "svrstate": "UP"})
    text = answer.to_text()
    assert "None" not in text
    assert "NIET VASTGESTELD" in text
    assert all(f.subject != "None" for f in answer.findings)


def test_a_member_without_a_readable_port_is_not_established(tmp_path):
    text = _one_member(tmp_path, {"servername": "web01", "svrstate": "UP"}).to_text()
    assert "web01" in text and "poort niet leesbaar" in text
    assert "web01: UP (poort 3389) [vastgesteld]" not in text


# ---------------------------------------------------------------------------
# Nested binding values are positively type-checked.
# ---------------------------------------------------------------------------


def test_a_numeric_nested_servicegroup_binding_is_a_read_gap_not_a_crash(tmp_path):
    """`lbvserver_servicegroup_binding: 5` used to raise TypeError, which the
    server layer masked as "onverwachte fout"."""
    lb = {
        "parentName": "d",
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": "d", "lbvserver_servicegroup_binding": 5}},
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [lb], [])
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text and "lbvserver_servicegroup_binding" in text


def test_a_textual_nested_servicegroup_binding_is_a_read_gap_not_none_bound(tmp_path):
    """A string used to iterate per character and yield "geen servicegroup
    gebonden [vastgesteld]" - a false green."""
    lb = {
        "parentName": "d",
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": "d", "lbvserver_servicegroup_binding": "sg"}},
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [lb], [])
    text = service_status(load_export(root), K, "d").to_text()
    assert "geen servicegroup gebonden" not in text
    assert "NIET VASTGESTELD" in text


def test_a_non_object_entry_in_the_member_list_is_a_read_gap(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "d", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("d", "sg")],
        [_sg_parent("sg", [{"servername": "web01", "port": 3389, "svrstate": "UP"}, "tekst"])],
    )
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text
    assert "lid/leden" not in text


def test_a_non_list_member_binding_is_a_read_gap(tmp_path):
    sg = {
        "parentName": "sg",
        "outcome": "OK",
        "data": {
            "servicegroup_binding": {
                "servicegroupname": "sg",
                "servicegroup_servicegroupmember_binding": {"servername": "web01"},
            }
        },
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [sg])
    text = service_status(load_export(root), K, "d").to_text()
    assert "NIET VASTGESTELD" in text
    assert "lid/leden" not in text


def test_an_unreadable_servicegroupname_is_a_read_gap(tmp_path):
    lb = {
        "parentName": "d",
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": "d", "lbvserver_servicegroup_binding": [{"servicegroupname": None}]}},
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [lb], [])
    text = service_status(load_export(root), K, "d").to_text()
    assert "geen servicegroup gebonden" not in text
    assert "NIET VASTGESTELD" in text
    assert "None" not in text


# ---------------------------------------------------------------------------
# Branches kept from the previous round.
# ---------------------------------------------------------------------------


def test_vserver_without_a_bound_servicegroup_is_a_finding_not_a_guess(tmp_path):
    """The vserver is found and its parent entry IS present, but names no
    servicegroup at all - a normal configuration state (not a read problem),
    so it stays an ESTABLISHED finding."""
    lb = {
        "parentName": "d",
        "outcome": "OK",
        "data": {"lbvserver_binding": {"name": "d", "lbvserver_servicegroup_binding": []}},
    }
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [lb], [])
    text = service_status(load_export(root), K, "d").to_text()
    assert "d: geen servicegroup gebonden [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


def test_unreadable_lbvserver_binding_file_is_a_read_gap_and_stops_there(tmp_path):
    root = _export(tmp_path, [{"name": "d", "effectivestate": "UP", "health": "100"}], [_lb_parent("d", "sg")], [])
    (root / "bindings" / "lbvserver_binding.by-parent.json").unlink()
    answer = service_status(load_export(root), K, "d")
    text = answer.to_text()
    assert "NIET VASTGESTELD" in text and "lbvserver_binding.by-parent.json" in text
    assert all(f.subject != "sg" for f in answer.findings)


def test_real_fixture_has_no_lbvserver_so_any_service_is_not_found():
    """MEASURED (2026-09-02) on `tests/fixtures/lab-export-vpx-20260826/`
    (the real collector output): `config/lbvserver` and `config/servicegroup`
    both read as manifest status EMPTY with objectCount 0, and the manifest
    carries NO hash for `bindings/lbvserver_binding.by-parent.json` or
    `bindings/servicegroup_binding.by-parent.json` - neither file was ever
    written by the collector for this lab appliance. So the one honest
    real-fixture assertion this export supports is the real, hash-verified
    read of `config/lbvserver` coming back genuinely empty (gap=None, not a
    read gap) - proven by reaching the same 'niet gevonden' finding as the
    synthetic case, but through the real collector's own bytes.
    """
    export = load_export(FIXTURE)
    text = service_status(export, K, "welke_naam_dan_ook").to_text()
    assert "welke_naam_dan_ook: niet gevonden in config/lbvserver" in text
    assert "bewijs: config/lbvserver: 0 virtuele servers" in text


# ---------------------------------------------------------------------------
# The name family covers every name this tool prints or accepts.
# ---------------------------------------------------------------------------


def test_the_name_family_covers_vserver_group_member_and_ip(tmp_path):
    root = _export(
        tmp_path,
        [{"name": "de_dienst", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("de_dienst", "de_groep")],
        [
            _sg_parent(
                "de_groep",
                [
                    {"servername": "de_webserver", "port": 3389, "svrstate": "UP"},
                    {"ip": "10.20.30.40", "port": 3389, "svrstate": "UP"},
                ],
            )
        ],
    )
    names = names_in_service_sources(load_export(root))
    assert set(names) == {"de_dienst", "de_groep", "de_webserver", "10.20.30.40"}


def test_the_name_family_still_harvests_names_from_an_unusable_file(tmp_path):
    """The family exists to make names MASKABLE, not to establish facts: the
    harvest stays tolerant where the analysis is strict. Since 1.0.3 (R3-1)
    the gap that reports a duplicate parent names it by its POSITION, never
    by its name, so the name no longer depends on this harvest to stay out
    of the answer at 'beperkt'; the harvest is the second safety net."""
    root = _export(
        tmp_path,
        [{"name": "de_dienst", "effectivestate": "UP", "health": "100"}],
        [_lb_parent("de_dienst", "de_groep")],
        [_sg_parent("de_groep", []), _sg_parent("de_groep", [])],
    )
    export = load_export(root)
    reasons = " ".join(g.reason for g in service_status(export, K, "de_dienst").read_gaps)
    assert "dubbele parent op positie 2" in reasons and "de_groep" not in reasons, reasons
    assert "de_groep" in names_in_service_sources(export)


def test_an_unknown_svrstate_longer_than_a_token_is_not_echoed(tmp_path):
    """MEASURED before this repair: `_STATE_TOKEN` in dienst.py had no length
    bound, so a single 232-character uppercase "state" matched the token shape
    and was repeated verbatim in the answer - straight into the model's
    context, past the disclosure seam (which does not know this value as a
    name and therefore cannot mask it)."""
    smuggled = "A" * 232
    text = _one_member(tmp_path, {"servername": "web02", "port": 3389, "svrstate": smuggled}).to_text()
    assert smuggled not in text
    assert "zonder de vorm van een toestand" in text


def test_a_short_unknown_svrstate_is_still_named(tmp_path):
    """Counter-probe: the length bound must not silence a real, short NITRO
    state this version happens not to know."""
    text = _one_member(tmp_path, {"servername": "web02", "port": 3389, "svrstate": "TROUBLESHOOTING"}).to_text()
    assert "TROUBLESHOOTING" in text


# ---------------------------------------------------------------------------
# The LIVE MEASURED shape. Until this measurement the two files this
# module reads were the only ones it had never actually seen: the fixture
# export `lab-export-vpx-20260826` carries neither of them (that lab had no
# lbvserver and no servicegroup), so their shape was INFERRED from the three
# other aggregate files. The records below are verbatim from a live collector
# run on 2026-09-02 (lab appliance, film service built by
# `scenario/Add-GjkDemoFilmDienst.ps1` in the demo repo) - field for field,
# values included, keeping only the parents that carry the point. They pin
# four things that were assumptions until they were measured:
#   1. `data.<bindingResource>` is an OBJECT here too, like the other
#      aggregate files, with one `parents[]` entry per parent.
#   2. The member fields really are `servername`, `port`, `svrstate` - and the
#      address field is `ip`, NOT `ipaddress` (MEMBER_IP_FIELDS accepted both
#      because no real member binding existed to settle it).
#   3. `svrstate` speaks the vocabulary MEMBER_STATES already knew: "UP" and,
#      with a member disabled on the appliance, "OUT OF SERVICE". No unknown
#      token appeared.
#   4. A vserver WITHOUT servicegroup bindings gets a parent entry all the
#      same, outcome OK, with the nested binding key simply ABSENT - so it
#      lands on the ESTABLISHED "geen servicegroup gebonden" branch and not on
#      the read gap for an absent parent. That distinction decides whether
#      every unbound service would read as a read gap; it is now measured.
# ---------------------------------------------------------------------------

# Verbatim from bindings/servicegroup_binding.by-parent.json, live 2026-09-02
# - except the member address below: the measured value was a real
# lab-range address, replaced by hand with a TEST-NET-3 value (RFC 5737);
# every other field stayed exactly as measured.
LIVE_SG_PARENT = {
    "parentName": "gjkdemo_sg_proefdienst",
    "outcome": "OK",
    "data": {
        "servicegroup_binding": {
            "servicegroupname": "gjkdemo_sg_proefdienst",
            "servicegroup_servicegroupmember_binding": [
                {
                    "servicegroupname": "gjkdemo_sg_proefdienst",
                    "ip": "203.0.113.22",
                    "port": 3389,
                    "svrstate": "UP",
                    "statechangetimesec": "Wed Sep  2 14:22:40 2026",
                    "tickssincelaststatechange": "4850",
                    "weight": "1",
                    "servername": "gjkdemo_web02",
                    "customserverid": "None",
                    "serverid": "0",
                    "state": "ENABLED",
                    "hashid": "0",
                    "graceful": "NO",
                    "delay": 0,
                    "delay1": 0,
                    "nameserver": "0.0.0.0",
                    "dbsttl": 0,
                    "orderstr": "Default",
                    "trofsdelay": "0",
                },
                {
                    "servicegroupname": "gjkdemo_sg_proefdienst",
                    "ip": "192.0.2.1",
                    "port": 3389,
                    "svrstate": "UP",
                    "statechangetimesec": "Wed Sep  2 14:22:40 2026",
                    "tickssincelaststatechange": "4855",
                    "weight": "1",
                    "servername": "gjkdemo_web01",
                    "customserverid": "None",
                    "serverid": "0",
                    "state": "ENABLED",
                    "hashid": "0",
                    "graceful": "NO",
                    "delay": 0,
                    "delay1": 0,
                    "nameserver": "0.0.0.0",
                    "dbsttl": 0,
                    "orderstr": "Default",
                    "trofsdelay": "0",
                },
            ],
            "servicegroup_servicegroupentitymonbindings_binding": [
                {
                    "servicegroupname": "gjkdemo_sg_proefdienst",
                    "servicegroupentname2": "gjkdemo_sg_proefdienst?gjkdemo_web02?3389",
                    "monitor_name": "tcp-default",
                    "monitor_state": "UP",
                    "passive": False,
                    "monitortotalprobes": "10",
                    "monitortotalfailedprobes": "0",
                    "monitorcurrentfailedprobes": "0",
                    "lastresponse": "Success - TCP syn+ack received.",
                    "responsetime": "0",
                },
            ],
        }
    },
}

# Verbatim from bindings/lbvserver_binding.by-parent.json, live 2026-09-02:
# the bound demo service, plus one of the three vservers that carry no
# servicegroup binding at all.
LIVE_LB_PARENT_BOUND = {
    "parentName": "gjkdemo_lb_vs_proefdienst_443",
    "outcome": "OK",
    "data": {
        "lbvserver_binding": {
            "name": "gjkdemo_lb_vs_proefdienst_443",
            "lbvserver_servicegroup_binding": [
                {
                    "name": "gjkdemo_lb_vs_proefdienst_443",
                    "servicegroupname": "gjkdemo_sg_proefdienst",
                    "stateflag": "536936464",
                    "servicename": "gjkdemo_sg_proefdienst",
                }
            ],
            "lbvserver_servicegroupmember_binding": [
                {
                    "name": "gjkdemo_lb_vs_proefdienst_443",
                    "servicegroupname": "gjkdemo_sg_proefdienst",
                    "ipv46": "203.0.113.22",
                    "port": 3389,
                    "servicetype": "TCP",
                    "curstate": "UP",
                    "weight": "1",
                    "dynamicweight": "0",
                    "vserverid": "hklefnp_mc_wt_qspfgejfotu_443",
                    "orderstr": "None",
                }
            ],
        }
    },
}
LIVE_LB_PARENT_UNBOUND = {
    "parentName": "lb_vs_gjk_zaakportaal_443",
    "outcome": "OK",
    "data": {"lbvserver_binding": {"name": "lb_vs_gjk_zaakportaal_443"}},
}

# Verbatim from objects/lbvserver.json, live 2026-09-02: `health` is a STRING
# and both `curstate` and `effectivestate` are present with the same value.
LIVE_LBVSERVERS = [
    {"name": "lb_vs_gjk_zaakportaal_443", "curstate": "DOWN", "effectivestate": "DOWN", "health": "0"},
    {"name": "gjkdemo_lb_vs_proefdienst_443", "curstate": "UP", "effectivestate": "UP", "health": "100"},
]


def _live_export(tmp_path: Path):
    return load_export(
        _export(
            tmp_path,
            LIVE_LBVSERVERS,
            [LIVE_LB_PARENT_UNBOUND, LIVE_LB_PARENT_BOUND],
            [LIVE_SG_PARENT],
        )
    )


def test_live_measured_binding_shape_yields_the_demo_answer(tmp_path):
    """The live product answer of 2026-09-02, reproduced line for line from
    the measured records. This is demo scene 2: the service, its group, and
    both members with their state and port."""
    text = service_status(_live_export(tmp_path), K, "gjkdemo_lb_vs_proefdienst_443").to_text()
    assert "gjkdemo_lb_vs_proefdienst_443: effectivestate=UP, health=100 [vastgesteld]" in text
    assert "gjkdemo_sg_proefdienst: servicegroup met 2 lid/leden [vastgesteld]" in text
    assert "gjkdemo_web02: UP (poort 3389) [vastgesteld]" in text
    assert "gjkdemo_web01: UP (poort 3389) [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


def test_live_measured_member_address_field_is_ip(tmp_path):
    """MEASURED: the member carries `ip`, never `ipaddress`. Both stay
    accepted (MEMBER_IP_FIELDS), but the fallback is no longer the
    load-bearing one: strip the servername from the measured record and the
    member is still identified, by the field the appliance really writes."""
    members = LIVE_SG_PARENT["data"]["servicegroup_binding"]["servicegroup_servicegroupmember_binding"]
    member = dict(members[1])
    assert "ip" in member and "ipaddress" not in member
    member.pop("servername")
    text = _one_member(tmp_path, member).to_text()
    assert "192.0.2.1: UP (poort 3389), lid op IP [vastgesteld]" in text


def test_live_measured_disabled_member_reads_as_out_of_service(tmp_path):
    """Verbatim from the same file after
    `Invoke-GjkLabWrite.ps1 -Actie disable-member` on the lab: `svrstate`
    becomes "OUT OF SERVICE" (the admin field `state` becomes "DISABLED",
    which this module deliberately does not read). "OUT OF SERVICE" was
    already in MEMBER_STATES; this pins that the appliance writes those very
    words."""
    disabled = {
        "servicegroupname": "gjkdemo_sg_proefdienst",
        "ip": "192.0.2.1",
        "port": 3389,
        "svrstate": "OUT OF SERVICE",
        "statechangetimesec": "Wed Sep  2 14:24:40 2026",
        "tickssincelaststatechange": "1518",
        "weight": "1",
        "servername": "gjkdemo_web01",
        "customserverid": "None",
        "serverid": "0",
        "state": "DISABLED",
        "hashid": "0",
        "graceful": "NO",
        "delay": 0,
        "delay1": 0,
        "nameserver": "0.0.0.0",
        "dbsttl": 0,
        "orderstr": "Default",
        "trofsdelay": "0",
    }
    text = _one_member(tmp_path, disabled).to_text()
    assert "gjkdemo_web01: OUT OF SERVICE (poort 3389) [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


def test_live_measured_vserver_without_bindings_is_present_with_the_key_absent(tmp_path):
    """MEASURED and load-bearing: the collector DOES write a parent entry for
    a vserver that has no servicegroup bound - outcome OK, `data` carrying
    only the name, the nested `lbvserver_servicegroup_binding` key absent.
    Absent-key is the "no bindings of this kind" branch of
    `_nested_bindings`, so such a service answers with the ESTABLISHED "geen
    servicegroup gebonden". Had the collector omitted the parent instead,
    every unbound service would have answered with a read gap.
    """
    assert "lbvserver_servicegroup_binding" not in LIVE_LB_PARENT_UNBOUND["data"]["lbvserver_binding"]
    text = service_status(_live_export(tmp_path), K, "lb_vs_gjk_zaakportaal_443").to_text()
    assert "lb_vs_gjk_zaakportaal_443: geen servicegroup gebonden [vastgesteld]" in text
    assert "NIET VASTGESTELD" not in text


# ---------------------------------------------------------------------------
# A half name gets CANDIDATES, never a choice.
#
# Measured in the practice runs: asked about "de proefdienst", the model
# passed that Dutch word through and
# got back a bare "niet gevonden in config/lbvserver" - no way forward, and
# the whole scene cascaded from there. The four writing tools' allowlist
# refusals DO name valid names, and there the model corrected itself. So this
# reading tool names them too: it lists what it read, and chooses nothing.
# ---------------------------------------------------------------------------


def _vserver(name):
    return {"name": name, "effectivestate": "UP", "health": "100"}


def test_an_unknown_name_names_the_candidates_that_contain_it(tmp_path):
    export = load_export(
        _export(
            tmp_path,
            [
                _vserver("gjkdemo_lb_vs_proefdienst_443"),
                _vserver("lb_vs_proefdienst_api_443"),
                _vserver("lb_vs_gjk_zaakportaal_443"),
            ],
            [],
            [],
        )
    )
    text = service_status(export, K, "proefdienst").to_text()
    assert "proefdienst: niet gevonden in config/lbvserver" in text
    assert (
        "kandidaten (naam bevat 'proefdienst', hoofdletterongevoelig): "
        "gjkdemo_lb_vs_proefdienst_443, lb_vs_proefdienst_api_443 [vastgesteld]"
    ) in text
    assert "lb_vs_gjk_zaakportaal_443" not in text


def test_the_candidate_search_is_case_insensitive(tmp_path):
    export = load_export(_export(tmp_path, [_vserver("GJKDEMO_LB_VS_Proefdienst_443")], [], []))
    text = service_status(export, K, "PROEFdienst").to_text()
    assert ("kandidaten (naam bevat 'PROEFdienst', hoofdletterongevoelig): GJKDEMO_LB_VS_Proefdienst_443") in text


def test_at_most_five_candidates_are_named_and_they_are_sorted(tmp_path):
    export = load_export(_export(tmp_path, [_vserver(f"lb_vs_web{n}_443") for n in range(9, 0, -1)], [], []))
    text = service_status(export, K, "web").to_text()
    regel = [line for line in text.splitlines() if line.startswith("- kandidaten")][0]
    assert regel == (
        "- kandidaten (naam bevat 'web', hoofdletterongevoelig): lb_vs_web1_443, "
        "lb_vs_web2_443, lb_vs_web3_443, lb_vs_web4_443, lb_vs_web5_443 [vastgesteld]"
    )


def test_without_a_single_candidate_the_answer_says_so(tmp_path):
    export = load_export(_export(tmp_path, [_vserver("lb_vs_gjk_zaakportaal_443")], [], []))
    text = service_status(export, K, "proefdienst").to_text()
    assert "kandidaten (naam bevat 'proefdienst', hoofdletterongevoelig): geen kandidaten" in text


def test_the_real_fixture_with_zero_vservers_reports_no_candidates():
    """The real collector export of the lab reads config/lbvserver back
    genuinely empty. Nothing to suggest, and the answer says that instead of
    staying silent about it."""
    text = service_status(load_export(FIXTURE), K, "welke_naam_dan_ook").to_text()
    assert "welke_naam_dan_ook: niet gevonden in config/lbvserver" in text
    assert ("kandidaten (naam bevat 'welke_naam_dan_ook', hoofdletterongevoelig): geen kandidaten") in text


def test_a_found_dienst_gets_no_candidate_line(tmp_path):
    """Counter-probe: candidates belong to a name that was NOT found. A
    resolved question must not be padded with near-misses."""
    export = load_export(_export(tmp_path, [_vserver("de_dienst")], [], []))
    text = service_status(export, K, "de_dienst").to_text()
    assert "kandidaten" not in text
