"""The chain from VIP to backend, measured on the real export."""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.answer import stamp_data
from nsmcp.chain import CHAIN_WORDS, LINK_LABELS, chains_of, names_in_chain_sources, service_chain
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 8, 26)
_KNOWLEDGE = Knowledge(version="ketentest", date="2026-08-26", age_days=0, missing=False)


def test_the_real_export_has_two_gateway_entrypoints_and_no_readable_chain():
    export = load_export(FIXTURE)
    text = stamp_data(service_chain(export, _KNOWLEDGE, ""), export.collected_at, TODAY, export.target_name).to_text()

    assert "Vraag: waar hangt deze dienst aan, van VIP tot backend" in text
    assert "- VSRV-003: niet vastgesteld [niet vastgesteld]" in text
    assert "- VSRV-002: niet vastgesteld [niet vastgesteld]" in text
    assert "- losse objecten: geen [vastgesteld]" in text


def test_an_unreadable_binding_never_reads_as_no_backends(tmp_path):
    """Issue #8: a missing servicegroup_binding gives a read gap, never
    'geen backends'. That is the single most dangerous false statement this
    tool could make."""
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": [{"name": "LB_VS_A", "curstate": "UP"}]}), encoding="utf-8"
    )
    (export_dir / "export-manifest.json").write_text(
        '{"manifestVersion":"1.1","collectedAtUtc":"2026-08-26T10:00:00.0000000Z",'
        '"resources":{"config/lbvserver":{"status":"OK"}},"files":{}}',
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chains = chains_of(load_export(export_dir))
    assert chains[0].verdict == "niet vastgesteld"
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = service_chain(load_export(export_dir), _KNOWLEDGE, "LB_VS_A").to_text()
    assert "geen backends" not in text


def test_a_complete_chain_says_so(tmp_path):
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": [{"name": "LB_VS_A", "curstate": "UP", "ipv46": "10.0.0.1", "port": 443}]}),
        encoding="utf-8",
    )
    (export_dir / "objects" / "servicegroup.json").write_text(
        json.dumps({"servicegroup": [{"servicegroupname": "SG_A", "state": "ENABLED"}]}), encoding="utf-8"
    )
    raw = json.dumps(
        {
            "bindingResource": "lbvserver_binding",
            "parentResource": "lbvserver",
            "parentKey": "name",
            "shape": "list",
            "parents": [
                {
                    "parentName": "LB_VS_A",
                    "outcome": "OK",
                    "data": {"lbvserver_binding": [{"name": "LB_VS_A", "servicegroupname": "SG_A"}]},
                }
            ],
        }
    )
    (export_dir / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
    raw2 = json.dumps(
        {
            "bindingResource": "servicegroup_binding",
            "parentResource": "servicegroup",
            "parentKey": "servicegroupname",
            "shape": "list",
            "parents": [
                {
                    "parentName": "SG_A",
                    "outcome": "OK",
                    "data": {
                        "servicegroup_binding": [{"servicegroupname": "SG_A", "servername": "web01", "port": 443}]
                    },
                }
            ],
        }
    )
    (export_dir / "bindings" / "servicegroup_binding.by-parent.json").write_text(raw2, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/lbvserver": {"status": "OK"}, "config/servicegroup": {"status": "OK"}},
                "files": {
                    "bindings/lbvserver_binding.by-parent.json": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    "bindings/servicegroup_binding.by-parent.json": hashlib.sha256(raw2.encode("utf-8")).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "keten compleet"
    assert [link.label for link in chain.links] == ["ingang", "backendgroep", "lid"]


def test_a_gap_names_where_it_sits(tmp_path):
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True)
    (export_dir / "bindings").mkdir()
    (export_dir / "objects" / "lbvserver.json").write_text(
        json.dumps({"lbvserver": [{"name": "LB_VS_B", "curstate": "UP"}]}), encoding="utf-8"
    )
    raw = json.dumps(
        {
            "bindingResource": "lbvserver_binding",
            "parentResource": "lbvserver",
            "parentKey": "name",
            "shape": "list",
            "parents": [{"parentName": "LB_VS_B", "outcome": "OK", "data": {"lbvserver_binding": []}}],
        }
    )
    (export_dir / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/lbvserver": {"status": "OK"}},
                "files": {"bindings/lbvserver_binding.by-parent.json": hashlib.sha256(raw.encode("utf-8")).hexdigest()},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "backendgroep"


def test_the_three_chain_words_are_pinned():
    assert CHAIN_WORDS == ("keten compleet", "gat in de keten", "niet vastgesteld")


def test_the_link_labels_are_pinned():
    """Moved pin: `lb-doel` (a contentswitching-vserver's hop to a
    loadbalancing-vserver, whether resolved via its default-LB binding or
    via a policy) and `beleid` (a policy NAME, shown only when cspolicy/
    csaction cannot resolve it to a target) - the content-switching route
    this module now follows (see the module docstring's "WHAT IS
    FOLLOWED")."""
    assert LINK_LABELS == ("ingang", "backendgroep", "lid", "lb-doel", "beleid")


def test_every_link_label_chains_of_produces_is_a_pinned_label():
    """LINK_LABELS is not merely descriptive: every Link this module builds,
    on the real export, uses one of exactly these three labels."""
    export = load_export(FIXTURE)
    for chain in chains_of(export):
        for link in chain.links:
            assert link.label in LINK_LABELS


def test_every_produced_verdict_is_a_pinned_chain_word_and_all_three_occur(tmp_path):
    """CHAIN_WORDS had a label counterpart
    (`test_every_link_label_chains_of_produces_is_a_pinned_label` above) but
    no verdict counterpart - and the real fixture alone only ever exercises
    one of the three words. Across a representative set of synthetic
    exports (one per verdict), every produced verdict is in CHAIN_WORDS, and
    all three actually occur - not merely individually type-safe."""
    seen: set[str] = set()

    complete = _write_export(
        tmp_path / "compleet",
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=_sg_binding({"servername": "web01", "port": 80}),
    )
    seal_manifest(complete)  # an object file without its hash is a read gap
    seen.add(chains_of(load_export(complete))[0].verdict)

    sg_doc_empty = {
        "bindingResource": "servicegroup_binding",
        "parentResource": "servicegroup",
        "parentKey": "servicegroupname",
        "shape": "list",
        "parents": [{"parentName": "SG_A", "outcome": "EMPTY", "data": None}],
    }
    gap = _write_export(
        tmp_path / "gat",
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=sg_doc_empty,
    )
    seal_manifest(gap)  # an object file without its hash is a read gap
    seen.add(chains_of(load_export(gap))[0].verdict)

    for chain in chains_of(load_export(FIXTURE)):
        seen.add(chain.verdict)

    for verdict in seen:
        assert verdict in CHAIN_WORDS
    assert seen == set(CHAIN_WORDS)


def test_the_entry_names_are_masked_at_beperkt(tmp_path):
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export = load_export(FIXTURE)
    answer = service_chain(export, _KNOWLEDGE, "")
    full = render(
        answer,
        Disclosure.FULL,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "VSRV-003" in full, "zonder de echte naam bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "VSRV-003" not in limited
    assert "niet vastgesteld" in limited


def test_a_member_name_is_masked_at_beperkt(tmp_path):
    """The leak test above stops at the entry name and
    (separately) the entry address; nothing pinned that a MEMBER name
    (servername/ip inside a servicegroup binding) is masked too."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=_sg_binding({"servername": "web01", "port": 80}),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    answer = service_chain(export, _KNOWLEDGE, "")
    full = render(
        answer,
        Disclosure.FULL,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "web01" in full, "zonder de echte naam bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "web01" not in limited


# ---------------------------------------------------------------------------
# FIELD x CASE MATRIX
#
# Every field this module reads out of the export, pinned across its three
# cases (key absent / key present-but-unreadable / key present-and-readable).
# The full table has one row per cell below.
# Each helper below builds the SMALLEST export that isolates one field; the
# manifest is hand-built (not the real collector's shape) exactly like the
# tmp_path tests above.
# ---------------------------------------------------------------------------


def _write_export(
    tmp_path: Path,
    *,
    lbvserver_rows=None,
    servicegroup_rows=None,
    service_rows=None,
    lb_binding: dict | None = None,
    sg_binding: dict | None = None,
    lbvserver_status: str = "OK",
    servicegroup_status: str = "OK",
    service_status: str = "EMPTY",
) -> Path:
    """A minimal, self-contained export directory for one field-case cell.

    `lbvserver_rows=None` means the resource is absent from the manifest
    entirely (NIET_IN_MANIFEST, a read gap) - the "key absent" case one
    layer up, for tests that need a whole SOURCE absent rather than one
    field inside it. Passing `[]` with `lbvserver_status="EMPTY"` gives the
    honest, read, zero-entries case instead.
    """
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True, exist_ok=True)
    (export_dir / "bindings").mkdir(parents=True, exist_ok=True)
    resources: dict = {}
    files: dict = {}

    if lbvserver_rows is not None:
        resources["config/lbvserver"] = {"status": lbvserver_status}
        (export_dir / "objects" / "lbvserver.json").write_text(
            json.dumps({"lbvserver": lbvserver_rows}), encoding="utf-8"
        )
    if servicegroup_rows is not None:
        resources["config/servicegroup"] = {"status": servicegroup_status}
        (export_dir / "objects" / "servicegroup.json").write_text(
            json.dumps({"servicegroup": servicegroup_rows}), encoding="utf-8"
        )
    else:
        resources["config/servicegroup"] = {"status": "EMPTY"}
    if service_rows is not None:
        resources["config/service"] = {"status": service_status}
        (export_dir / "objects" / "service.json").write_text(json.dumps({"service": service_rows}), encoding="utf-8")
    else:
        resources["config/service"] = {"status": "EMPTY"}

    if lb_binding is not None:
        raw = json.dumps(lb_binding)
        (export_dir / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
        files["bindings/lbvserver_binding.by-parent.json"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if sg_binding is not None:
        raw2 = json.dumps(sg_binding)
        (export_dir / "bindings" / "servicegroup_binding.by-parent.json").write_text(raw2, encoding="utf-8")
        files["bindings/servicegroup_binding.by-parent.json"] = hashlib.sha256(raw2.encode("utf-8")).hexdigest()

    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": resources,
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    return export_dir


def _lb_binding(entry_row: dict) -> dict:
    """One lbvserver_binding.by-parent.json parent, OK, one row."""
    return {
        "bindingResource": "lbvserver_binding",
        "parentResource": "lbvserver",
        "parentKey": "name",
        "shape": "list",
        "parents": [{"parentName": "LB_VS_A", "outcome": "OK", "data": {"lbvserver_binding": [entry_row]}}],
    }


def _sg_binding(member_row: dict, parent_name: str = "SG_A") -> dict:
    return {
        "bindingResource": "servicegroup_binding",
        "parentResource": "servicegroup",
        "parentKey": "servicegroupname",
        "shape": "list",
        "parents": [{"parentName": parent_name, "outcome": "OK", "data": {"servicegroup_binding": [member_row]}}],
    }


# --- field 1: lbvserver row's own "name" (entry identity) ------------------


@pytest.mark.parametrize(
    "raw_name,expected_entry",
    [
        (None, "(naamloos)"),  # absent
        (True, "(naamloos)"),  # present, unreadable (bool)
        (["x"], "(naamloos)"),  # present, unreadable (list)
        ("   ", "(naamloos)"),  # present, whitespace-only
        ("LB_VS_A", "LB_VS_A"),  # present, readable
    ],
)
def test_entry_name_field(tmp_path, raw_name, expected_entry):
    row = {"curstate": "UP"}
    if raw_name is not None:
        row["name"] = raw_name
    export_dir = _write_export(tmp_path, lbvserver_rows=[row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chains = chains_of(load_export(export_dir))
    # An unnamed entry is still HONESTLY present (naamloos), never dropped -
    # dropping it would be the silently favourable branch (one fewer
    # unaccountable vserver in the answer).
    assert len(chains) == 1
    assert chains[0].entry == expected_entry
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = service_chain(load_export(export_dir), _KNOWLEDGE, "").to_text()
    if isinstance(raw_name, (bool, list)):
        assert str(raw_name) not in text


# --- fields 2/3: lbvserver row's "ipv46"/"port" (decorative only) ----------


@pytest.mark.parametrize(
    "row_extra,expect_in_detail",
    [
        ({}, None),  # both absent: no detail at all
        ({"ipv46": True, "port": ["x"]}, None),  # both unreadable: no detail, no raw value
        ({"ipv46": "10.0.0.9", "port": 443}, "10.0.0.9:443"),  # both readable (real fixture shape: int port)
        ({"ipv46": "10.0.0.9", "port": "443"}, "10.0.0.9:443"),  # port as numeric text
    ],
)
def test_entry_endpoint_fields(tmp_path, row_extra, expect_in_detail):
    row = {"name": "LB_VS_A", **row_extra}
    export_dir = _write_export(tmp_path, lbvserver_rows=[row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chains = chains_of(load_export(export_dir))
    assert chains[0].links[0].label == "ingang"
    detail = chains[0].links[0].detail
    if expect_in_detail is None:
        assert detail == ""
        # Never the raw unreadable value, whatever it was.
        for value in row_extra.values():
            if not isinstance(value, str):
                assert str(value) not in detail
    else:
        assert detail == expect_in_detail


# --- fields 4/5: entry binding row's "servicegroupname"/"servicename" ------


def test_entry_binding_row_target_fields_absent_is_honest_zero(tmp_path):
    """Neither field present on the (only) binding row: an honest, empty
    attachment - 'gat in de keten', not a read gap. NITRO binding files can
    carry rows this module has no use for; absence alone proves nothing."""
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A"}),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "backendgroep"


@pytest.mark.parametrize("bad_value", [True, 7, ["SG_A"], {"x": 1}, None])
def test_entry_binding_row_target_field_present_but_unreadable(tmp_path, bad_value):
    """servicegroupname present but the wrong shape PROVES an attachment
    exists - niet vastgesteld, never the favourable 'gat in de keten' (which
    would claim a known absence of backends)."""
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": bad_value}),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "niet vastgesteld"
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = service_chain(load_export(export_dir), _KNOWLEDGE, "").to_text()
    assert "gat in de keten" not in text
    assert str(bad_value) not in text


def test_entry_binding_row_one_field_readable_the_other_unreadable_is_still_surfaced(tmp_path):
    """The shape probe used to run only inside
    `if not group_name and not service_name`, so a row with ONE readable
    target field and ONE unreadable one skipped the probe entirely and
    silently dropped the unreadable attachment - the chain could still
    reach 'keten compleet'. Each field is now probed on its own absence."""
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A", "servicename": True}),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "niet vastgesteld"
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    text = service_chain(load_export(export_dir), _KNOWLEDGE, "").to_text()
    assert "gat in de keten" not in text
    assert "keten compleet" not in text
    assert "True" not in text


def test_entry_binding_row_target_field_readable(tmp_path):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        # No servicegroup_binding file at all -> the group itself becomes a
        # "not read" gap (field 4/5 already proved readable at this point).
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert [link.name for link in chain.links if link.label == "backendgroep"] == ["SG_A"]
    # The group WAS identified; its members were not read - niet vastgesteld
    # bij lid, not a favourable "keten compleet".
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lid"


# --- whole-resource gap for an entry point (RBAC_DENIED etc.) --------------


def test_entry_resource_wholly_unreadable_is_surfaced_not_silently_dropped(tmp_path):
    export_dir = _write_export(tmp_path, lbvserver_rows=None)
    # No config/lbvserver key in resources at all -> NIET_IN_MANIFEST.
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    chains = chains_of(export)
    assert chains == ()
    answer = service_chain(export, _KNOWLEDGE, "")
    reasons = [g.reason for g in answer.read_gaps]
    assert any("lbvserver" in r or "manifest" in r for r in reasons)
    assert not answer.is_complete()


# --- fields 6/7: servicegroup member row's "servername"/"ip" ---------------


@pytest.mark.parametrize(
    "member_row,expect_gap",
    [
        ({"port": 80}, True),  # both absent
        ({"servername": True, "port": 80}, True),  # servername unreadable, ip absent
        ({"servername": "web01", "port": 80}, False),  # servername readable
        ({"ip": "10.0.0.5", "port": 80}, False),  # ip readable, no servername
    ],
)
def test_member_identity_fields(tmp_path, member_row, expect_gap):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=_sg_binding(member_row),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    if expect_gap:
        assert chain.verdict == "niet vastgesteld"
        assert chain.gap_at == "lid"
        seal_manifest(export_dir)  # an object file without its hash is a read gap
        text = service_chain(load_export(export_dir), _KNOWLEDGE, "").to_text()
        assert "True" not in text
    else:
        assert chain.verdict == "keten compleet"
        assert any(link.label == "lid" for link in chain.links)


# --- field 8: servicegroup member row's "port" (decorative only) -----------


@pytest.mark.parametrize(
    "port_value,expected_detail",
    [
        (None, ""),
        (True, ""),
        ("veel-te-lang-en-geen-getal", ""),
        (8443, "8443"),
        ("8443", "8443"),
    ],
)
def test_member_port_field(tmp_path, port_value, expected_detail):
    member_row = {"servername": "web01"}
    if port_value is not None:
        member_row["port"] = port_value
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=_sg_binding(member_row),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    lid = [link for link in chain.links if link.label == "lid"][0]
    assert lid.detail == expected_detail


# --- servicegroup member grouping: parent absent vs. genuinely empty -------


def test_group_absent_from_binding_file_is_a_gap_not_zero_members(tmp_path):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=_sg_binding({"servername": "web01"}, parent_name="SG_OTHER"),
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lid"


def test_group_read_as_empty_is_a_confirmed_gap_not_a_read_gap(tmp_path):
    """An established (read, EMPTY-outcome) zero
    members is a CONFIRMED absence - 'gat in de keten' at 'lid' - never the
    favourable 'keten compleet' this used to render, and never 'niet
    vastgesteld' either (that word is reserved for a binding that could not
    be read at all)."""
    sg_doc = {
        "bindingResource": "servicegroup_binding",
        "parentResource": "servicegroup",
        "parentKey": "servicegroupname",
        "shape": "list",
        "parents": [{"parentName": "SG_A", "outcome": "EMPTY", "data": None}],
    }
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_A"}),
        sg_binding=sg_doc,
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lid"
    assert not any(link.label == "lid" for link in chain.links)


# --- fields 9/10: loose-object identity (servicegroup/service) -------------


@pytest.mark.parametrize(
    "raw_name,expected",
    [
        (None, "(naamloos)"),
        (False, "(naamloos)"),
        ([], "(naamloos)"),
        ("SG_LOS", "SG_LOS"),
    ],
)
def test_loose_servicegroup_identity_field(tmp_path, raw_name, expected):
    row = {"state": "ENABLED"}
    if raw_name is not None:
        row["servicegroupname"] = raw_name
    export_dir = _write_export(tmp_path, lbvserver_rows=[], servicegroup_rows=[row])
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    loose_answer = service_chain(load_export(export_dir), _KNOWLEDGE, "")
    outcome = [f.outcome for f in loose_answer.findings if f.subject == "losse objecten"][0]
    assert expected in outcome


def test_loose_objects_source_unreadable_is_never_geen(tmp_path):
    """config/servicegroup fails to read entirely -> 'niet vast te stellen',
    never the favourable 'geen [vastgesteld]' - the exact defect class this
    whole module exists to close, one block past the chain itself."""
    export_dir = _write_export(tmp_path, lbvserver_rows=[], servicegroup_rows=None)
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    export = load_export(export_dir)
    # Force config/servicegroup into the manifest with an unusable status,
    # rather than absent (which is a different, already-covered case).
    import dataclasses

    export = dataclasses.replace(
        export,
        resources={
            **export.resources,
            "config/servicegroup": {"status": "RBAC_DENIED"},
        },
    )
    answer = service_chain(export, _KNOWLEDGE, "")
    found = [f for f in answer.findings if f.subject == "losse objecten"][0]
    assert found.outcome == "niet vast te stellen"
    assert found.certainty.value == "niet vastgesteld"
    assert not answer.is_complete()


# --- names_in_chain_sources: harvests names that only surface via a gap ----


def test_names_in_chain_sources_covers_a_group_named_only_in_a_gap_reason(tmp_path):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_lb_binding({"name": "LB_VS_A", "servicegroupname": "SG_GHOST"}),
        # No servicegroup_binding file at all: SG_GHOST's members are never read.
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    names = names_in_chain_sources(load_export(export_dir))
    assert "SG_GHOST" in names
    assert "LB_VS_A" in names


@pytest.mark.parametrize("ipv46_key", ["ipv46", "IPv46"])
def test_names_in_chain_sources_covers_the_entry_address_independently(tmp_path, ipv46_key):
    """The real fixture's Gateway-vserver addresses happen to be masked by
    an UNRELATED family (mgmt_plane.py); this proves chain.py does not
    depend on that coincidence for an address no other family reads.

    The `IPv46` case: `chains_of()` PRINTS this field
    case-insensitively (`field_text`); this used to HARVEST it with an
    exact-case `row.get("ipv46")`, so a differently-cased key rendered the
    address into the answer text while this function never saw it, leaving
    it unmasked at 'beperkt'. Printed-and-harvested must stay in step."""
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A", ipv46_key: "203.0.113.9", "port": 443}],
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    names = names_in_chain_sources(load_export(export_dir))
    assert "203.0.113.9" in names

    seal_manifest(export_dir)  # an object file without its hash is a read gap
    answer = service_chain(load_export(export_dir), _KNOWLEDGE, "")
    from nsmcp.disclosure import Disclosure, render

    full = render(
        answer,
        Disclosure.FULL,
        tool="dienst_keten",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "203.0.113.9" in full, "zonder het echte adres bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_keten",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "203.0.113.9" not in limited


# ---------------------------------------------------------------------------
# The aggregate shape, measured on the synthetic DoH fixture: 12
# loadbalancing- and 5 contentswitching-vservers, every binding file of these
# entries written as 'aggregate'.
# ---------------------------------------------------------------------------

DOH = Path(__file__).parent / "fixtures" / "lab-export-vpx-doh-synthetic"


def _doh_chain(name: str):
    return [c for c in chains_of(load_export(DOH)) if c.entry == name][0]


def test_an_aggregate_lb_chain_is_read_to_its_members():
    chain = _doh_chain("LBV-APP-001")
    assert chain.verdict == "keten compleet"
    assert [(link.label, link.name) for link in chain.links] == [
        ("ingang", "LBV-APP-001"),
        ("backendgroep", "SG-APP-001"),
        ("lid", "SRV-APP-001"),
        ("lid", "SRV-APP-002"),
        ("lid", "SRV-APP-003"),
        ("lid", "SRV-APP-004"),
    ]


def test_an_aggregate_lb_chain_through_a_service_binding_is_complete():
    chain = _doh_chain("LBV-WEB-001")
    assert chain.verdict == "keten compleet"
    assert [(link.label, link.name) for link in chain.links] == [
        ("ingang", "LBV-WEB-001"),
        ("backendgroep", "SVC-WEB-001"),
    ]


def test_a_servicegroup_binding_row_never_doubles_as_a_service():
    """The union trap one level up: every lbvserver_servicegroup_binding row
    carries servicename == servicegroupname. Read per child key, the group
    appears once, as a group."""
    chain = _doh_chain("LBV-APP-001")
    assert [link.name for link in chain.links if link.label == "backendgroep"] == ["SG-APP-001"]


def test_the_doh_export_counts_11_complete_and_6_gap():
    """Following the contentswitching step adds no `niet vastgesteld`
    verdict on this export (cspolicy/csaction are both fully present and
    readable here). MEASURED on the synthetic fixture: of the 5
    contentswitching entries, 2 (CSV-WEB-001/002) resolve to a fully
    readable downstream chain (`keten compleet`); the other 3 (CSV-DOH-001,
    CSV-DOH-002, CSV-EMPTY-001) carry neither a default-LB binding nor a
    policy binding at all (`gat in de keten`). Of the 12 loadbalancing
    entries, 9 are complete and 3 (LBV-DOH-002, LBV-NODOH-001, LBV-DNS-002)
    carry no servicegroup and no service. 9+2=11, 3+3=6."""
    verdicts = [c.verdict for c in chains_of(load_export(DOH))]
    assert len(verdicts) == 17
    assert verdicts.count("keten compleet") == 11
    assert verdicts.count("gat in de keten") == 6
    assert verdicts.count("niet vastgesteld") == 0


def test_without_an_argument_a_summary_line_opens_the_answer():
    text = service_chain(load_export(DOH), _KNOWLEDGE, "").to_text()
    lines = text.splitlines()
    assert lines[2] == ("- samenvatting: 17 ketens: 11 keten compleet, 6 gat in de keten [vastgesteld]")
    assert lines[3] == "    bewijs: ingangen: 5 Contentswitching-vserver, 12 Loadbalancing-vserver, 0 Gateway-vserver"


def test_a_named_chain_gets_no_summary_line():
    text = service_chain(load_export(DOH), _KNOWLEDGE, "LBV-APP-001").to_text()
    assert "samenvatting" not in text
    assert "- LBV-APP-001: keten compleet [vastgesteld]" in text


def test_the_summary_line_is_not_established_when_an_entry_source_is_unread(tmp_path):
    export_dir = _write_export(tmp_path, lbvserver_rows=[{"name": "LB_VS_A"}], lbvserver_status="RBAC_DENIED")
    text = service_chain(load_export(export_dir), _KNOWLEDGE, "").to_text()
    assert "- samenvatting: 0 ketens [niet vastgesteld]" in text
    # This synthetic export carries no csvserver or vpnvserver entry at all;
    # absent from the manifest is unread too.
    assert "reden: niet elke ingangsbron is gelezen: config/csvserver, config/lbvserver, config/vpnvserver" in text


def test_a_contentswitching_entry_without_any_binding_is_a_gap():
    """Moved pin: CSV-EMPTY-001 carries no `csvserver_lbvserver_binding` and no
    `csvserver_cspolicy_binding` row at all in `csvserver_binding.by-parent.
    json` (MEASURED) - a contentswitching-vserver with no route at all,
    the same `gat in de keten` an loadbalancing-vserver gets for `geen
    servicegroup en geen service`."""
    chain = _doh_chain("CSV-EMPTY-001")
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "csvserver_binding.by-parent.json draagt voor CSV-EMPTY-001 geen standaard load balancer en geen csbeleid"
    )


def test_a_gateway_entry_is_not_established_with_its_own_reason():
    text = service_chain(load_export(FIXTURE), _KNOWLEDGE, "").to_text()
    assert "- samenvatting: 2 ketens: 2 niet vastgesteld [vastgesteld]" in text
    assert (
        "- VSRV-003: niet vastgesteld [niet vastgesteld]\n"
        "    bewijs: Gateway-vserver: VSRV-003 (192.0.2.4:443)\n"
        "    reden: een Gateway-vserver hangt niet aan een servicegroup; die keten volgt deze versie niet"
    ) in text
    assert "wordt niet ondersteund" not in text


def _aggregate_lb(document: dict) -> dict:
    return {
        "bindingResource": "lbvserver_binding",
        "parentResource": "lbvserver",
        "parentKey": "name",
        "shape": "aggregate",
        "parents": [{"parentName": "LB_VS_A", "outcome": "OK", "data": {"lbvserver_binding": document}}],
    }


def _aggregate_sg(members: list) -> dict:
    return {
        "bindingResource": "servicegroup_binding",
        "parentResource": "servicegroup",
        "parentKey": "servicegroupname",
        "shape": "aggregate",
        "parents": [
            {
                "parentName": "SG_A",
                "outcome": "OK",
                "data": {
                    "servicegroup_binding": {
                        "servicegroupname": "SG_A",
                        "servicegroup_servicegroupmember_binding": members,
                    }
                },
            }
        ],
    }


def test_an_aggregate_group_row_without_a_group_name_is_not_an_honest_zero(tmp_path):
    """Under the aggregate shape a row in lbvserver_servicegroup_binding IS a
    servicegroup attachment; without a readable servicegroupname it attaches
    to something unnamed - never 'geen servicegroup en geen service'."""
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"name": "LB_VS_A"}]}),
        sg_binding=_aggregate_sg([]),
    )
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "niet vastgesteld"
    assert "servicegroupname" in chain.reason


def test_an_aggregate_group_with_zero_members_is_a_gap_at_lid(tmp_path):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb(
            {"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A", "servicename": "SG_A"}]}
        ),
        sg_binding=_aggregate_sg([]),
    )
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lid"
    assert [link.name for link in chain.links] == ["LB_VS_A", "SG_A"]


def test_an_aggregate_member_list_of_the_wrong_shape_is_not_established(tmp_path):
    export_dir = _write_export(
        tmp_path,
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg("geen lijst"),
    )
    chain = chains_of(load_export(export_dir))[0]
    assert chain.verdict == "niet vastgesteld"
    assert "servicegroup_servicegroupmember_binding" in chain.reason


# --- content switching -> load balancing ------------------------------------
#
# A contentswitching-vserver's own route: its default load balancer
# (`csvserver_lbvserver_binding`) and its policies (`csvserver_cspolicy_
# binding`, resolved through `cspolicy.action` -> `csaction.targetlbvserver`
# when the binding row carries no `targetlbvserver` of its own), each
# continued into the SAME Loadbalancing-vserver chain the tests above already
# exercise - never a second walk of servicegroup/member data.

KETEN_CS = Path(__file__).parent / "fixtures" / "keten-cs"


def _cs_binding(parent_name: str, document: dict) -> dict:
    """One `csvserver_binding.by-parent.json` parent, aggregate shape, OK -
    the real collector's own shape for this file (measured on the DoH
    fixture: `csvserver_binding.by-parent.json` carries `csvserver_
    cspolicy_binding` and `csvserver_lbvserver_binding` nested per parent,
    exactly like `lbvserver_binding.by-parent.json` carries its own two
    child lists)."""
    return {
        "bindingResource": "csvserver_binding",
        "parentResource": "csvserver",
        "parentKey": "name",
        "shape": "aggregate",
        "parents": [{"parentName": parent_name, "outcome": "OK", "data": {"csvserver_binding": document}}],
    }


def _write_cs_export(
    tmp_path: Path,
    *,
    csvserver_rows: list,
    cs_binding: dict | None = None,
    lbvserver_rows=None,
    lb_binding: dict | None = None,
    sg_binding: dict | None = None,
    cspolicy_rows=None,
    csaction_rows=None,
) -> Path:
    """A minimal export carrying one or more contentswitching-vservers plus
    whatever loadbalancing/cspolicy/csaction data a case needs.

    `cspolicy_rows=None` (the default) and `csaction_rows=None` mean those
    two resources are absent from the manifest entirely: a test that needs
    cspolicy/csaction ACTUALLY read passes rows explicitly. Same `rows=None`
    idiom as `_write_export` above for `lbvserver_rows`.
    """
    export_dir = tmp_path / "export"
    (export_dir / "objects").mkdir(parents=True, exist_ok=True)
    (export_dir / "bindings").mkdir(parents=True, exist_ok=True)
    resources: dict = {"config/csvserver": {"status": "OK"}}
    files: dict = {}
    (export_dir / "objects" / "csvserver.json").write_text(json.dumps({"csvserver": csvserver_rows}), encoding="utf-8")
    if lbvserver_rows is not None:
        resources["config/lbvserver"] = {"status": "OK"}
        (export_dir / "objects" / "lbvserver.json").write_text(
            json.dumps({"lbvserver": lbvserver_rows}), encoding="utf-8"
        )
    resources["config/servicegroup"] = {"status": "EMPTY"}
    resources["config/service"] = {"status": "EMPTY"}
    if cspolicy_rows is not None:
        resources["config/cspolicy"] = {"status": "OK"}
        (export_dir / "objects" / "cspolicy.json").write_text(json.dumps({"cspolicy": cspolicy_rows}), encoding="utf-8")
    if csaction_rows is not None:
        resources["config/csaction"] = {"status": "OK"}
        (export_dir / "objects" / "csaction.json").write_text(json.dumps({"csaction": csaction_rows}), encoding="utf-8")
    if cs_binding is not None:
        raw = json.dumps(cs_binding)
        (export_dir / "bindings" / "csvserver_binding.by-parent.json").write_text(raw, encoding="utf-8")
        files["bindings/csvserver_binding.by-parent.json"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if lb_binding is not None:
        raw2 = json.dumps(lb_binding)
        (export_dir / "bindings" / "lbvserver_binding.by-parent.json").write_text(raw2, encoding="utf-8")
        files["bindings/lbvserver_binding.by-parent.json"] = hashlib.sha256(raw2.encode("utf-8")).hexdigest()
    if sg_binding is not None:
        raw3 = json.dumps(sg_binding)
        (export_dir / "bindings" / "servicegroup_binding.by-parent.json").write_text(raw3, encoding="utf-8")
        files["bindings/servicegroup_binding.by-parent.json"] = hashlib.sha256(raw3.encode("utf-8")).hexdigest()

    (export_dir / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-09-25T10:00:00.0000000Z",
                "resources": resources,
                "files": files,
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(export_dir)  # an object file without its hash is a read gap
    return export_dir


def _cs_chain(export_dir: Path, entry: str):
    return [c for c in chains_of(load_export(export_dir)) if c.entry == entry][0]


def test_a_cs_route_follows_its_default_lb_to_a_complete_chain(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-A"}],
        cs_binding=_cs_binding("CSV-A", {"name": "CSV-A", "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}]}),
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([{"servername": "web01", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-A")
    assert chain.verdict == "keten compleet"
    assert [(link.label, link.name) for link in chain.links] == [
        ("ingang", "CSV-A"),
        ("lb-doel", "LB_VS_A"),
        ("backendgroep", "SG_A"),
        ("lid", "web01"),
    ]


def test_a_cs_route_resolves_a_policy_through_cspolicy_and_csaction(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-B"}],
        cs_binding=_cs_binding("CSV-B", {"name": "CSV-B", "csvserver_cspolicy_binding": [{"policyname": "CSPOL-B"}]}),
        cspolicy_rows=[{"policyname": "CSPOL-B", "action": "CSACT-B"}],
        csaction_rows=[{"name": "CSACT-B", "targetlbvserver": "LB_VS_A"}],
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([{"servername": "web01", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-B")
    assert chain.verdict == "keten compleet"
    assert [(link.label, link.name) for link in chain.links] == [
        ("ingang", "CSV-B"),
        ("lb-doel", "LB_VS_A"),
        ("backendgroep", "SG_A"),
        ("lid", "web01"),
    ]


def test_a_cs_policy_binding_with_its_own_targetlbvserver_needs_no_cspolicy(tmp_path):
    """A `csvserver_cspolicy_binding` row that already carries its own
    `targetlbvserver` skips the cspolicy/csaction indirection entirely, so
    neither source needs to be in the export."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-C"}],
        cs_binding=_cs_binding(
            "CSV-C",
            {"name": "CSV-C", "csvserver_cspolicy_binding": [{"policyname": "CSPOL-C", "targetlbvserver": "LB_VS_A"}]},
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([{"servername": "web01", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-C")
    assert chain.verdict == "keten compleet"


def test_a_cs_route_without_cspolicy_or_csaction_in_the_export_is_not_established(tmp_path):
    """cspolicy/csaction absent from the manifest makes the WHOLE route
    `niet vastgesteld`; the answer then shows only the standard load
    balancer and the policy names themselves - never a guessed target."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-D"}],
        cs_binding=_cs_binding(
            "CSV-D",
            {
                "name": "CSV-D",
                "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-D"}],
            },
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
    )
    chain = _cs_chain(export_dir, "CSV-D")
    assert chain.verdict == "niet vastgesteld"
    assert [(link.label, link.name) for link in chain.links] == [
        ("ingang", "CSV-D"),
        ("lb-doel", "LB_VS_A"),
        ("beleid", "CSPOL-D"),
    ]
    assert "cspolicy" in chain.reason


def test_a_cs_route_to_an_unknown_lb_name_is_a_gap(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-E"}],
        cs_binding=_cs_binding(
            "CSV-E", {"name": "CSV-E", "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_GEEN"}]}
        ),
        lbvserver_rows=[{"name": "LB_VS_OTHER"}],
    )
    chain = _cs_chain(export_dir, "CSV-E")
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lb-doel"
    assert [(link.label, link.name) for link in chain.links] == [("ingang", "CSV-E"), ("lb-doel", "LB_VS_GEEN")]
    assert "LB_VS_GEEN" in chain.reason


def test_a_cs_route_when_lbvserver_itself_is_unread_is_not_established(tmp_path):
    """The same distinction as everywhere else in this module: a target name
    absent from a SOURCE THAT WAS READ is an established gap; a target name
    that cannot be checked because `config/lbvserver` itself is not in the
    export is unknown, never a gap."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-F"}],
        cs_binding=_cs_binding("CSV-F", {"name": "CSV-F", "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}]}),
    )
    chain = _cs_chain(export_dir, "CSV-F")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert "config/lbvserver" in chain.reason


def test_a_cs_entry_without_any_route_is_a_gap(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-G"}],
        cs_binding=_cs_binding("CSV-G", {"name": "CSV-G"}),
    )
    chain = _cs_chain(export_dir, "CSV-G")
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lb-doel"
    assert "geen standaard load balancer en geen csbeleid" in chain.reason


def _cs_list_binding(*parents: dict) -> dict:
    """`csvserver_binding.by-parent.json` in the LIST shape: the shared
    reader reads it (`Export.binding_rows` yields its rows under the file's
    own binding resource), but its rows are not grouped as a standard load
    balancer or a policy binding."""
    return {
        "bindingResource": "csvserver_binding",
        "parentResource": "csvserver",
        "parentKey": "name",
        "shape": "list",
        "parents": list(parents),
    }


def test_a_cs_route_in_the_list_shape_is_not_established_never_a_gap(tmp_path):
    """Rows the reader DID read, in a shape this version does not follow for
    a contentswitching route: "geen standaard load balancer en geen
    csbeleid" would claim a known absence of a route while a route may sit
    right there."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-LIJST"}],
        cs_binding=_cs_list_binding(
            {
                "parentName": "CSV-LIJST",
                "outcome": "OK",
                "data": {"csvserver_binding": [{"name": "CSV-LIJST", "lbvserver": "LBV-01"}]},
            }
        ),
        lbvserver_rows=[{"name": "LBV-01"}],
    )
    chain = _cs_chain(export_dir, "CSV-LIJST")
    assert chain.verdict == "niet vastgesteld", chain.reason
    assert chain.gap_at == "lb-doel"
    from nsmcp.chain import CS_UNGROUPED_TEXT

    assert chain.reason == CS_UNGROUPED_TEXT.format(bestand="csvserver_binding.by-parent.json", naam="CSV-LIJST")
    assert [link.name for link in chain.links] == ["CSV-LIJST"]


def test_an_empty_cs_parent_in_the_list_shape_is_still_a_gap(tmp_path):
    """No row at all: nothing in a shape this version does not follow, so the
    known absence of a route stands."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-LEEG"}],
        cs_binding=_cs_list_binding({"parentName": "CSV-LEEG", "outcome": "EMPTY", "data": None}),
    )
    chain = _cs_chain(export_dir, "CSV-LEEG")
    assert chain.verdict == "gat in de keten"
    assert (
        chain.reason
        == "csvserver_binding.by-parent.json draagt voor CSV-LEEG geen standaard load balancer en geen csbeleid"
    )


def _cs_entry_with_only(tmp_path: Path, kind: str):
    """A contentswitching-vserver whose own binding document carries no
    standard load balancer and no policy, only one nested kind this version
    does not read. The shared reader DOES see that kind
    (`Export.binding_child_keys`), so the route is unknown, not absent."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-ANDERS"}],
        cs_binding=_cs_binding("CSV-ANDERS", {"name": "CSV-ANDERS", kind: [{"name": "CSV-ANDERS", "vserver": "VS-1"}]}),
    )
    return _cs_chain(export_dir, "CSV-ANDERS")


@pytest.mark.parametrize(
    "kind",
    [
        "csvserver_gslbvserver_binding",
        "csvserver_vpnvserver_binding",
        "csvserver_onbekendesoort_binding",
    ],
)
def test_a_cs_entry_routing_only_through_an_unread_kind_is_not_a_gap(tmp_path, kind):
    """A GSLB-type or Unified-Gateway contentswitching-vserver routes through
    a nested kind outside `CS_CHILDREN`. "gat in de keten" would claim a
    KNOWN absence of a route; the honest answer is that this version does
    not follow that kind, with the kind named in the reason."""
    chain = _cs_entry_with_only(tmp_path, kind)
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "csvserver_binding.by-parent.json draagt voor CSV-ANDERS geen standaard load balancer en geen"
        f" csbeleid, wel een bindingssoort die deze versie niet leest ({kind}); niet vast te stellen"
        " waarnaar deze vserver routeert"
    )
    assert [link.name for link in chain.links] == ["CSV-ANDERS"]


def _cs_route_with_default_lb_and(tmp_path: Path, kind: str):
    """A contentswitching-vserver whose standard load balancer leads to a
    complete chain on its own, and whose document ALSO carries `kind`."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-NAAST"}],
        cs_binding=_cs_binding(
            "CSV-NAAST",
            {
                "name": "CSV-NAAST",
                "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}],
                kind: [{"name": "CSV-NAAST", "policyname": "POL-1", "vserver": "VS-1"}],
            },
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([{"servername": "web01", "port": 80}]),
    )
    return _cs_chain(export_dir, "CSV-NAAST")


@pytest.mark.parametrize(
    "kind",
    [
        "csvserver_vpnvserver_binding",
        "csvserver_gslbvserver_binding",
        "csvserver_onbekendesoort_binding",
    ],
)
def test_a_followed_cs_route_next_to_an_unread_routing_kind_is_not_established(tmp_path, kind):
    """The standard load balancer is complete on its own, but the document
    also carries a kind that can route elsewhere (a VPN or GSLB vserver, or
    a kind this version has no rule for). "keten compleet" would answer for
    only part of the route; the same fact reached through csaction (an
    action whose target is not a loadbalancing-vserver) is already "niet
    vastgesteld" - one fact, one answer."""
    chain = _cs_route_with_default_lb_and(tmp_path, kind)
    assert chain.verdict == "niet vastgesteld"
    assert chain.reason == (
        f"csvserver_binding.by-parent.json draagt voor CSV-NAAST ook een bindingssoort die deze versie niet"
        f" leest ({kind}); die route volgt deze versie niet; alleen de standaard load balancer en de"
        " beleidsnamen zijn hier vastgesteld"
    )
    assert [(link.label, link.name) for link in chain.links] == [("ingang", "CSV-NAAST"), ("lb-doel", "LB_VS_A")]


@pytest.mark.parametrize("kind", ["csvserver_responderpolicy_binding", "csvserver_rewritepolicy_binding"])
def test_a_followed_cs_route_next_to_a_policy_binding_keeps_its_verdict(tmp_path, kind):
    """A responder, rewrite or similar policy binding does not route to
    another vserver: the followed route keeps its own verdict (measured on
    the DoH fixture: a contentswitching-vserver with cspolicy, responder-
    and rewritepolicy bindings)."""
    chain = _cs_route_with_default_lb_and(tmp_path, kind)
    assert chain.verdict == "keten compleet"
    assert [link.name for link in chain.links] == ["CSV-NAAST", "LB_VS_A", "SG_A", "web01"]


def test_a_cs_route_bubbles_a_gap_from_its_target_lb(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-H"}],
        cs_binding=_cs_binding("CSV-H", {"name": "CSV-H", "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}]}),
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([]),
    )
    chain = _cs_chain(export_dir, "CSV-H")
    assert chain.verdict == "gat in de keten"
    assert chain.gap_at == "lid"


def test_a_cs_route_bubbles_a_read_gap_from_its_target_lb(tmp_path):
    """Different from `..._when_lbvserver_itself_is_unread...` above: here
    `config/lbvserver` IS read and DOES carry `LB_VS_A` - only that entry's
    OWN binding file is unreadable, so its OWN chain is `niet vastgesteld`
    (not absent from `lb_by_name`), and the CS route must bubble THAT
    chain's own `gap_at`/`reason`, not invent a new one."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-I"}],
        cs_binding=_cs_binding("CSV-I", {"name": "CSV-I", "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}]}),
        lbvserver_rows=[{"name": "LB_VS_A"}],
    )
    chain = _cs_chain(export_dir, "CSV-I")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "backendgroep"
    assert [link.name for link in chain.links] == ["CSV-I", "LB_VS_A"]
    assert chain.reason == "geen hash in het manifest; geen hash is geen vertrouwen"


def test_two_policies_resolving_to_the_same_lb_are_not_walked_twice(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-J"}],
        cs_binding=_cs_binding(
            "CSV-J",
            {
                "name": "CSV-J",
                "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}],
                "csvserver_cspolicy_binding": [
                    {"policyname": "CSPOL-J1", "targetlbvserver": "LB_VS_A"},
                    {"policyname": "CSPOL-J2", "targetlbvserver": "LB_VS_A"},
                ],
            },
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
        lb_binding=_aggregate_lb({"name": "LB_VS_A", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG_A"}]}),
        sg_binding=_aggregate_sg([{"servername": "web01", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-J")
    assert chain.verdict == "keten compleet"
    assert [link.name for link in chain.links if link.label == "lb-doel"] == ["LB_VS_A"]


def test_the_keten_cs_fixture_covers_all_three_chain_words():
    export = load_export(KETEN_CS)
    chains = {c.entry: c for c in chains_of(export) if c.kind == "Contentswitching-vserver"}
    assert chains["CSV-KETEN-DEFLB"].verdict == "keten compleet"
    assert chains["CSV-KETEN-GAT"].verdict == "gat in de keten"
    assert chains["CSV-KETEN-BELEID"].verdict == "niet vastgesteld"
    assert [link.name for link in chains["CSV-KETEN-BELEID"].links] == ["CSV-KETEN-BELEID", "CSPOL-KETEN-01"]
    assert chains["CSV-KETEN-LEEG"].verdict == "gat in de keten"


def test_every_link_label_the_doh_export_produces_is_a_pinned_label():
    """`test_every_link_label_chains_of_produces_is_a_pinned_label` above
    measures this on the Gateway-only real export (FIXTURE); the DoH export
    is the one fixture with real contentswitching data, so this is where
    `lb-doel` actually has to show up."""
    export = load_export(DOH)
    labels = {link.label for chain in chains_of(export) for link in chain.links}
    assert labels <= set(LINK_LABELS)
    assert "lb-doel" in labels


def test_names_in_chain_sources_covers_a_cs_route_and_its_policy_names(tmp_path):
    """A CS entry name, a resolved LB target and a policy name each reach
    `names_in_chain_sources()` - the entry/target through the generic link
    walk (every `chain.links` name), the policy name the same way when it
    reaches a `Link` (see the masking test below for when it does NOT reach
    one, and still must not leak)."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-D"}],
        cs_binding=_cs_binding(
            "CSV-D",
            {
                "name": "CSV-D",
                "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-D"}],
            },
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
    )
    names = names_in_chain_sources(load_export(export_dir))
    assert {"CSV-D", "LB_VS_A", "CSPOL-D"} <= set(names)


def test_a_cs_policy_name_and_its_lb_target_are_masked_at_beperkt(tmp_path):
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-D"}],
        cs_binding=_cs_binding(
            "CSV-D",
            {
                "name": "CSV-D",
                "csvserver_lbvserver_binding": [{"lbvserver": "LB_VS_A"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-D"}],
            },
        ),
        lbvserver_rows=[{"name": "LB_VS_A"}],
    )
    export = load_export(export_dir)
    answer = service_chain(export, _KNOWLEDGE, "")
    full = render(
        answer,
        Disclosure.FULL,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-vol.json",
    )
    assert "CSPOL-D" in full and "LB_VS_A" in full, "zonder de echte namen bewijst deze test niets"

    limited = render(
        answer,
        Disclosure.LIMITED,
        tool="dienst_keten",
        extra_names=names_from_export(export),
        pseudonym_table_path=tmp_path / "tabel-beperkt.json",
    )
    assert "CSPOL-D" not in limited
    assert "LB_VS_A" not in limited
    assert "niet vastgesteld" in limited


_NAME_KEYS = ("name", "lbvserver", "policyname", "servicegroupname", "servicename", "servername", "ip", "ipv46")


def _fixture_names(root: Path) -> set[str]:
    """Every value the fixture itself carries under a name-shaped key - the
    independent measurement an openness proof needs: not a list this module
    ALREADY reads, but a walk of the raw files, so a name this code forgets
    to harvest still shows up as a leak instead of silently passing."""
    found: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _NAME_KEYS and isinstance(value, str) and value.strip():
                    found.add(value.strip())
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for sub in ("objects", "bindings"):
        for path in (root / sub).glob("*.json"):
            walk(json.loads(path.read_text(encoding="utf-8")))
    return found


def _render_keten(export, answer, level, path):
    from nsmcp.disclosure import names_from_export, render

    return render(answer, level, tool="dienst_keten", extra_names=names_from_export(export), pseudonym_table_path=path)


def test_no_real_fixture_name_reaches_a_limited_keten_answer(tmp_path):
    """Independent openness proof on `keten-cs`, over EVERY name-shaped
    value the fixture's raw files carry (not just the ones this module
    happens to walk): none of them, standing on its own, in the answer at
    `beperkt` - proven against `volledig`, where they DO appear, so a
    weakened premise cannot pass this test by accident."""
    from nsmcp.disclosure import Disclosure

    export = load_export(KETEN_CS)
    answer = service_chain(export, _KNOWLEDGE, "")
    names = _fixture_names(KETEN_CS)
    full = _render_keten(export, answer, Disclosure.FULL, tmp_path / "vol.json")
    shown = {n for n in names if n in full}
    assert {"CSV-KETEN-DEFLB", "LBV-KETEN-OK", "LBV-KETEN-ONBEKEND", "CSPOL-KETEN-01", "SG-KETEN-OK"} <= shown
    limited = _render_keten(export, answer, Disclosure.LIMITED, tmp_path / "beperkt.json")
    assert [n for n in sorted(names) if n in limited] == []


def test_an_action_name_in_an_unresolved_policy_reason_is_masked_at_beperkt(tmp_path):
    """A csaction with `targetvserver` instead of `targetlbvserver` (CS to
    CS, or a Unified Gateway action - real NetScaler usage) leaves its own
    NAME only in the unresolved-policy reason text, never in a `Link` - so
    only the direct cspolicy/csaction harvest in `names_in_chain_sources()`
    (not the generic link walk) can mask it."""
    from nsmcp.disclosure import Disclosure

    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-X"}],
        cs_binding=_cs_binding("CSV-X", {"name": "CSV-X", "csvserver_cspolicy_binding": [{"policyname": "CSPOL-X"}]}),
        cspolicy_rows=[{"policyname": "CSPOL-X", "action": "CSACT-EIGEN-X"}],
        csaction_rows=[{"name": "CSACT-EIGEN-X", "targetvserver": "CSV-Y"}],
        lbvserver_rows=[{"name": "LBV-X"}],
    )
    export = load_export(export_dir)
    answer = service_chain(export, _KNOWLEDGE, "")
    full = _render_keten(export, answer, Disclosure.FULL, tmp_path / "vol.json")
    assert "CSACT-EIGEN-X" in full, "premisse: de actienaam staat in het volledige antwoord"
    limited = _render_keten(export, answer, Disclosure.LIMITED, tmp_path / "beperkt.json")
    assert "CSPOL-X" not in limited
    assert "CSACT-EIGEN-X" not in limited


# --- the fail-closed branches, each with its own pinned reason --------------
#
# Every branch below combines an unresolvable policy with a default load
# balancer that WOULD, on its own, resolve to "keten compleet" - so a mutant
# that silently drops the unresolvable policy (turning the three
# `policy_unresolved.add(...)` calls into a no-op) produces a false "keten
# compleet" here instead of the correct "niet vastgesteld", and these tests
# catch it.


def test_a_policy_without_a_readable_action_in_cspolicy_is_not_established(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-1"}],
        cs_binding=_cs_binding(
            "CSV-1",
            {
                "name": "CSV-1",
                "csvserver_lbvserver_binding": [{"lbvserver": "LBV-1"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-1"}],
            },
        ),
        cspolicy_rows=[{"policyname": "CSPOL-1"}],  # no "action" field
        lbvserver_rows=[{"name": "LBV-1"}],
        lb_binding=_aggregate_lb({"name": "LBV-1", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG-1"}]}),
        sg_binding=_aggregate_sg([{"servername": "srv1", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-1")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "beleid"
    assert chain.reason == (
        "beleid CSPOL-1 van CSV-1 heeft geen leesbare actie in cspolicy; alleen de standaard load"
        " balancer en de beleidsnamen zijn hier vastgesteld"
    )


def test_an_action_without_a_readable_target_in_csaction_is_not_established(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-2"}],
        cs_binding=_cs_binding(
            "CSV-2",
            {
                "name": "CSV-2",
                "csvserver_lbvserver_binding": [{"lbvserver": "LBV-1"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-2"}],
            },
        ),
        cspolicy_rows=[{"policyname": "CSPOL-2", "action": "CSACT-2"}],
        csaction_rows=[{"name": "CSACT-2"}],  # no target field at all
        lbvserver_rows=[{"name": "LBV-1"}],
        lb_binding=_aggregate_lb({"name": "LBV-1", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG-1"}]}),
        sg_binding=_aggregate_sg([{"servername": "srv1", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-2")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "beleid"
    assert chain.reason == (
        "actie CSACT-2 van beleid CSPOL-2 heeft geen leesbaar doel in csaction; alleen de standaard load"
        " balancer en de beleidsnamen zijn hier vastgesteld"
    )


def test_cspolicy_read_but_csaction_missing_from_the_export_is_not_established(tmp_path):
    """Different from `..._without_cspolicy_or_csaction_in_the_export...`
    above: THERE neither source is in the export; HERE cspolicy resolves
    the action fine and only csaction is missing."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-3"}],
        cs_binding=_cs_binding(
            "CSV-3",
            {
                "name": "CSV-3",
                "csvserver_lbvserver_binding": [{"lbvserver": "LBV-1"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-3"}],
            },
        ),
        cspolicy_rows=[{"policyname": "CSPOL-3", "action": "CSACT-3"}],
        lbvserver_rows=[{"name": "LBV-1"}],
        lb_binding=_aggregate_lb({"name": "LBV-1", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG-1"}]}),
        sg_binding=_aggregate_sg([{"servername": "srv1", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-3")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "beleid"
    assert chain.reason == (
        "csaction is niet vast te stellen: resource staat niet in het manifest van deze export; alleen de"
        " standaard load balancer en de beleidsnamen zijn hier vastgesteld"
    )


def test_a_csaction_target_that_is_not_a_loadbalancing_vserver_says_so(tmp_path):
    """`targetvserver` (CS to CS, or a Unified Gateway action) is a
    DIFFERENT, known fact from `targetlbvserver` being unreadable or
    absent - the reason must say so, never the generic 'geen leesbaar
    doel'."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-9"}],
        cs_binding=_cs_binding(
            "CSV-9",
            {
                "name": "CSV-9",
                "csvserver_lbvserver_binding": [{"lbvserver": "LBV-1"}],
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-9"}],
            },
        ),
        cspolicy_rows=[{"policyname": "CSPOL-9", "action": "CSACT-9"}],
        csaction_rows=[{"name": "CSACT-9", "targetvserver": "CSV-OTHER"}],
        lbvserver_rows=[{"name": "LBV-1"}],
        lb_binding=_aggregate_lb({"name": "LBV-1", "lbvserver_servicegroup_binding": [{"servicegroupname": "SG-1"}]}),
        sg_binding=_aggregate_sg([{"servername": "srv1", "port": 80}]),
    )
    chain = _cs_chain(export_dir, "CSV-9")
    assert chain.verdict == "niet vastgesteld"
    assert chain.reason == (
        "actie CSACT-9 van beleid CSPOL-9 verwijst naar een vserver die geen loadbalancing-vserver is;"
        " die stap volgt deze versie niet; alleen de standaard load balancer en de beleidsnamen zijn hier"
        " vastgesteld"
    )


def test_an_unreadable_lbvserver_field_is_not_a_silent_gap(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-4"}],
        cs_binding=_cs_binding(
            "CSV-4", {"name": "CSV-4", "csvserver_lbvserver_binding": [{"lbvserver": ["LBV-1", "LBV-2"]}]}
        ),
    )
    chain = _cs_chain(export_dir, "CSV-4")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "een standaard-LB-binding van CSV-4 draagt lbvserver als een waarde van het type list in plaats"
        " van tekst; niet vast te stellen waarnaar deze vserver routeert"
    )
    assert [link.name for link in chain.links] == ["CSV-4"]


def test_a_policy_row_without_a_readable_policyname_is_not_a_silent_gap(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-5"}],
        cs_binding=_cs_binding("CSV-5", {"name": "CSV-5", "csvserver_cspolicy_binding": [{"priority": "100"}]}),
    )
    chain = _cs_chain(export_dir, "CSV-5")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "een beleidsbinding van CSV-5 draagt policyname niet als tekst (de sleutel ontbreekt); niet vast"
        " te stellen waarnaar deze vserver routeert"
    )


def test_an_unreadable_targetlbvserver_on_a_policy_row_is_not_a_silent_fallthrough(tmp_path):
    """`targetlbvserver` PRESENT but unreadable (a list, here) must not
    fall through silently to the cspolicy route - that route was never
    even asked for in this export, and the row DOES attach to something,
    with only its name unreadable."""
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-8"}],
        cs_binding=_cs_binding(
            "CSV-8",
            {
                "name": "CSV-8",
                "csvserver_cspolicy_binding": [{"policyname": "CSPOL-8", "targetlbvserver": ["LBV-1"]}],
            },
        ),
    )
    chain = _cs_chain(export_dir, "CSV-8")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "een beleidsbinding van CSV-8 draagt targetlbvserver als een waarde van het type list in plaats"
        " van tekst; niet vast te stellen waarnaar deze vserver routeert"
    )


def test_an_unreadable_csvserver_binding_file_is_not_established(tmp_path):
    export_dir = _write_cs_export(tmp_path, csvserver_rows=[{"name": "CSV-6"}], cs_binding=None)
    chain = _cs_chain(export_dir, "CSV-6")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == "geen hash in het manifest; geen hash is geen vertrouwen"


def test_a_cs_parent_absent_from_the_binding_file_is_not_established(tmp_path):
    export_dir = _write_cs_export(
        tmp_path,
        csvserver_rows=[{"name": "CSV-7A"}, {"name": "CSV-7B"}],
        cs_binding=_cs_binding("CSV-7A", {"name": "CSV-7A"}),
    )
    chain = _cs_chain(export_dir, "CSV-7B")
    assert chain.verdict == "niet vastgesteld"
    assert chain.gap_at == "lb-doel"
    assert chain.reason == (
        "csvserver_binding.by-parent.json draagt geen parent-vermelding voor CSV-7B; de bindingen van"
        " deze vserver zijn niet gelezen"
    )
