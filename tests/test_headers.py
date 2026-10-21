"""Security-header coverage follows the response-side configuration evidence."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.answer import Certainty, stamp_data
from nsmcp.disclosure import names_from_export
from nsmcp.export import load_export
from nsmcp.headers import HEADER_WORDS, HEADERS, header_coverage, headers_answer
from nsmcp.knowledge import Knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 8, 26)
KNOWLEDGE = Knowledge(version="headertest", date="2026-08-26", age_days=0, missing=False)
KNOWN_NON_HEADER_ACTION_TYPES = (
    "noop",
    "delete",
    "delete_http_header",
    "corrupt_http_header",
    "insert_before",
    "insert_after",
    "replace",
    "replace_http_res",
    "delete_all",
    "replace_all",
    "insert_before_all",
    "insert_after_all",
    "clientless_vpn_encode",
    "clientless_vpn_encode_all",
    "clientless_vpn_decode",
    "clientless_vpn_decode_all",
    "insert_sip_header",
    "delete_sip_header",
    "corrupt_sip_header",
    "replace_sip_res",
    "replace_diameter_header_field",
    "replace_dns_header_field",
    "replace_dns_answer_section",
    "replace_mqtt",
    "delete_mqtt",
    "insert_mqtt",
    "insert_before_mqtt",
    "insert_after_mqtt",
)
GLOBAL_PROTOCOL_PREFIXES = ("", "OTHERTCP_", "SIPUDP_", "SIPTCP_", "DIAMETER_", "RADIUS_", "DNS_", "HTTPQUIC_", "MQTT_")
KNOWN_GLOBAL_TYPES = tuple(
    f"{prefix}{direction}_{priority}"
    for prefix in GLOBAL_PROTOCOL_PREFIXES
    for direction in ("REQ", "RES")
    for priority in ("OVERRIDE", "DEFAULT")
)
GLOBAL_HTTP_RESPONSES = ("RES_DEFAULT", "RES_OVERRIDE", "HTTPQUIC_RES_DEFAULT", "HTTPQUIC_RES_OVERRIDE")


def test_the_real_export_has_no_bound_hsts_and_no_rewrite_headers():
    # Before 1.0.2 this pinned "aanwezig en gebonden [vastgesteld]" - the
    # false green fixed in 1.0.2. See the HSTS tests at the end of this file.
    export = load_export(FIXTURE)
    text = stamp_data(headers_answer(export, KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()

    assert "Vraag: staan de security-headers er echt op" in text
    assert "- Strict-Transport-Security: niet beoordeeld [niet vastgesteld]" in text
    for header in HEADERS[1:]:
        assert f"- {header}: afwezig [vastgesteld]" in text


def test_hsts_frontend_profile_without_a_vserver_binding_is_only_defined(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"name": "FE_HSTS", "sslprofiletype": "FrontEnd", "hsts": "ENABLED"}],
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "wel gedefinieerd, niet gebonden"
    assert result.vservers == ()
    assert "geen vserver bindt" in result.reason


def test_feature_policy_action_is_the_permissions_policy_alias(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "ACT_FP", "type": "insert_http_header", "target": "Feature-Policy"}],
        policies=[{"name": "POL_FP", "action": "ACT_FP"}],
        bindings=[{"name": "LB_A", "policyname": "POL_FP", "bindpoint": "RESPONSE"}],
    )

    result = _by_header(export)["Permissions-Policy"]

    assert result.word == "aanwezig en gebonden"
    assert result.vservers == ("LB_A",)


def test_response_binding_name_enters_the_disclosure_name_shield(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "ACT_XFO", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "POL_XFO", "action": "ACT_XFO"}],
        bindings=[{"name": "HEADER_VSERVER_SECRET", "policyname": "POL_XFO", "bindpoint": "RESPONSE"}],
    )

    assert "HEADER_VSERVER_SECRET" in names_from_export(export)


def test_an_action_without_an_effective_response_binding_is_only_defined(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "ACT_XFO", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "POL_XFO", "action": "ACT_XFO"}],
        bindings=[{"name": "LB_A", "policyname": "POL_XFO", "bindpoint": "REQUEST"}],
    )

    assert _by_header(export)["X-Frame-Options"].word == "wel gedefinieerd, niet gebonden"


def test_hsts_rewrite_does_not_replace_frontend_profile_evidence(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "ACT_HSTS", "type": "insert_http_header", "target": "Strict-Transport-Security"}],
        policies=[{"name": "POL_HSTS", "action": "ACT_HSTS"}],
        bindings=[{"name": "LB_A", "policyname": "POL_HSTS", "bindpoint": "RESPONSE"}],
    )

    assert _by_header(export)["Strict-Transport-Security"].word == "afwezig"


def test_source_read_gap_is_propagated_once_and_never_becomes_absence(tmp_path):
    export = _export(tmp_path, resource_status={"config/rewritepolicy": "RBAC_DENIED"})

    answer = headers_answer(export, KNOWLEDGE)

    assert all(f.certainty is Certainty.NOT_ESTABLISHED for f in answer.findings[1:])
    assert all(f.outcome == "niet beoordeeld" for f in answer.findings[1:])
    assert [(g.source, g.reason) for g in answer.read_gaps] == [
        ("config/rewritepolicy", "read niet bruikbaar: RBAC_DENIED"),
    ]


def test_undecodable_verdict_field_reports_shape_without_echoing_value(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "ACT_XFO", "type": ["insert_http_header"], "target": "X-Frame-Options"}],
    )

    answer = headers_answer(export, KNOWLEDGE)
    result = _by_header(export)["X-Frame-Options"]

    assert result.word == "niet beoordeeld"
    assert "een waarde van het type list" in result.reason
    assert "insert_http_header" not in result.reason
    assert any(g.source == "config/rewriteaction.type" for g in answer.read_gaps)


def test_hsts_profile_requires_a_readable_name(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"sslprofiletype": "FrontEnd", "hsts": "ENABLED"}],
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "niet beoordeeld"
    assert any(g.source == "config/sslprofile.name" for g in result.read_gaps)


def test_unknown_hsts_profile_vocabulary_is_a_shape_gap_without_value_echo(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"name": "FE_HSTS", "sslprofiletype": "FrontEnd", "hsts": "MAYBE"}],
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "niet beoordeeld"
    assert "tekst buiten het verwachte vocabulaire" in result.reason
    assert "MAYBE" not in result.reason


def test_unknown_profile_type_is_a_shape_gap_without_value_echo(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"name": "FE_HSTS", "sslprofiletype": "Sideways", "hsts": "ENABLED"}],
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "niet beoordeeld"
    assert "tekst buiten het verwachte vocabulaire" in result.reason
    assert "Sideways" not in result.reason


@pytest.mark.parametrize(
    ("actions", "policies", "source"),
    [
        ([{"name": "A", "target": "X-Frame-Options"}], [], "config/rewriteaction.type"),
        ([{"name": "A", "type": "insert_http_header"}], [], "config/rewriteaction.target"),
        ([{"type": "noop"}], [], "config/rewriteaction.name"),
        ([], [{"name": "P"}], "config/rewritepolicy.action"),
        ([], [{"action": "A"}], "config/rewritepolicy.name"),
    ],
)
def test_missing_relevant_action_and_policy_fields_are_gaps(tmp_path, actions, policies, source):
    result = _by_header(_export(tmp_path, actions=actions, policies=policies))["X-Frame-Options"]

    assert result.word == "niet beoordeeld"
    assert any(g.source == source and "sleutel ontbreekt" in g.reason for g in result.read_gaps)


def test_unknown_action_type_is_a_gap_without_value_echo(tmp_path):
    unknown = _by_header(_export(tmp_path, actions=[{"name": "A", "type": "UNKNOWN"}]))["X-Frame-Options"]

    assert unknown.word == "niet beoordeeld"
    assert "UNKNOWN" not in unknown.reason


@pytest.mark.parametrize("action_type", KNOWN_NON_HEADER_ACTION_TYPES)
def test_every_known_non_header_action_type_is_valid_absence(tmp_path, action_type):
    known = _by_header(_export(tmp_path, actions=[{"name": "A", "type": action_type}]))["X-Frame-Options"]

    assert known.word == "afwezig"


@pytest.mark.parametrize(
    "resource",
    [
        "config/lbvserver_rewritepolicy_binding?bulkbindings=yes",
        "config/csvserver_rewritepolicy_binding?bulkbindings=yes",
        "config/vpnvserver_rewritepolicy_binding?bulkbindings=yes",
    ],
)
def test_local_response_binding_requires_an_identity(tmp_path, resource):
    export = _export(
        tmp_path,
        actions=[{"name": "A", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "P", "action": "A"}],
        bindings_by_resource={resource: [{"policyname": "P", "bindpoint": "RESPONSE"}]},
    )

    result = _by_header(export)["X-Frame-Options"]

    assert result.word == "niet beoordeeld"
    assert any(g.source.endswith(".name/vservername") for g in result.read_gaps)


def test_unknown_local_bindpoint_is_a_gap_without_value_echo(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "A", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "P", "action": "A"}],
        bindings=[{"name": "LB", "policyname": "P", "bindpoint": "SIDEWAYS"}],
    )

    result = _by_header(export)["X-Frame-Options"]

    assert result.word == "niet beoordeeld"
    assert "SIDEWAYS" not in result.reason


@pytest.mark.parametrize("direction", GLOBAL_HTTP_RESPONSES)
def test_global_response_binding_counts_via_its_type_field(tmp_path, direction):
    export = _export(
        tmp_path,
        actions=[{"name": "A", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "P", "action": "A"}],
        bindings_by_resource={"config/rewriteglobal_rewritepolicy_binding": [{"policyname": "P", "type": direction}]},
    )

    result = _by_header(export)["X-Frame-Options"]

    assert result.word == "aanwezig en gebonden"
    assert result.vservers == ("globaal",)


@pytest.mark.parametrize("direction", sorted(set(KNOWN_GLOBAL_TYPES) - set(GLOBAL_HTTP_RESPONSES)))
def test_known_non_http_response_global_type_is_valid_negative_coverage(tmp_path, direction):
    export = _export(
        tmp_path,
        actions=[{"name": "A", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "P", "action": "A"}],
        bindings_by_resource={"config/rewriteglobal_rewritepolicy_binding": [{"policyname": "P", "type": direction}]},
    )

    assert _by_header(export)["X-Frame-Options"].word == "wel gedefinieerd, niet gebonden"


def test_unknown_global_type_is_a_gap_without_value_echo(tmp_path):
    export = _export(
        tmp_path,
        actions=[{"name": "A", "type": "insert_http_header", "target": "X-Frame-Options"}],
        policies=[{"name": "P", "action": "A"}],
        bindings_by_resource={
            "config/rewriteglobal_rewritepolicy_binding": [{"policyname": "P", "type": "UNKNOWN_GLOBAL"}]
        },
    )

    result = _by_header(export)["X-Frame-Options"]

    assert result.word == "niet beoordeeld"
    assert "UNKNOWN_GLOBAL" not in result.reason


def test_missing_vserver_binding_fields_make_hsts_not_assessed(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"name": "FE_HSTS", "sslprofiletype": "FrontEnd", "hsts": "ENABLED"}],
        vservers=[{"vservername": "LB_A"}],
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "niet beoordeeld"
    assert "niet gelezen" in result.reason
    assert any(g.source == "config/sslvserver.sslprofile" for g in result.read_gaps)


def test_unreadable_vserver_source_makes_hsts_not_assessed(tmp_path):
    export = _export(
        tmp_path,
        profiles=[{"name": "FE_HSTS", "sslprofiletype": "FrontEnd", "hsts": "ENABLED"}],
        resource_status={"config/sslvserver": "RBAC_DENIED"},
    )

    result = _by_header(export)["Strict-Transport-Security"]

    assert result.word == "niet beoordeeld"
    assert "niet gelezen" in result.reason
    assert any(g.source == "config/sslvserver" for g in result.read_gaps)


def test_header_vocabulary_is_closed():
    assert HEADERS == (
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    )
    assert HEADER_WORDS == (
        "aanwezig en gebonden",
        "wel gedefinieerd, niet gebonden",
        "afwezig",
        "niet beoordeeld",
    )


def _by_header(export):
    return {result.header: result for result in header_coverage(export)}


def _export(
    tmp_path: Path,
    *,
    actions=(),
    policies=(),
    bindings=(),
    bindings_by_resource=None,
    profiles=(),
    vservers=(),
    resource_status=None,
):
    root = tmp_path / "export"
    objects = root / "objects"
    objects.mkdir(parents=True)
    local_bindings = {
        "config/lbvserver_rewritepolicy_binding?bulkbindings=yes": list(bindings),
        "config/csvserver_rewritepolicy_binding?bulkbindings=yes": [],
        "config/vpnvserver_rewritepolicy_binding?bulkbindings=yes": [],
        "config/rewriteglobal_rewritepolicy_binding": [],
    }
    local_bindings.update(bindings_by_resource or {})
    rows_by_resource = {
        "config/rewriteaction": list(actions),
        "config/rewritepolicy": list(policies),
        "config/sslprofile": list(profiles),
        "config/sslvserver": list(vservers),
        **local_bindings,
    }
    resources = {}
    overridden = resource_status or {}
    for resource, rows in rows_by_resource.items():
        property_name = resource.rsplit("/", 1)[-1].split("?", 1)[0]
        status = overridden.get(resource, "OK")
        resources[resource] = {"status": status, "propertyName": property_name}
        if status == "OK":
            (objects / f"{property_name}.json").write_text(json.dumps({property_name: rows}), encoding="utf-8")
    (root / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": resources,
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(root)
    return load_export(root)


# --- 1.0.2: HSTS is only "aanwezig en gebonden" when a vserver binds it --
#
# Measured in the public test of 1.0.0: on the shipped lab export every
# sslvserver carries hsts DISABLED and no sslprofile; the only profiles with
# hsts ENABLED are the built-in `ns_default_ssl_profile_secure_frontend(_cloud)`.
# The answer still said "aanwezig en gebonden [vastgesteld]" with the evidence
# "binding onbekend door een leesgat".

_HSTS = "Strict-Transport-Security"
_FE_HSTS = {"name": "FE_HSTS", "sslprofiletype": "FrontEnd", "hsts": "ENABLED"}
_FE_PLAIN = {"name": "FE_PLAIN", "sslprofiletype": "FrontEnd", "hsts": "DISABLED"}
_BUILTIN_SECURE = {"name": "ns_default_ssl_profile_secure_frontend", "sslprofiletype": "FrontEnd", "hsts": "ENABLED"}


def test_b2_the_lab_export_never_says_hsts_is_present_and_bound():
    export = load_export(FIXTURE)
    result = _by_header(export)[_HSTS]
    assert result.word != "aanwezig en gebonden"
    assert result.word == "niet beoordeeld"
    assert result.vservers == ()
    assert any(g.source == "config/sslvserver.sslprofile" for g in result.read_gaps)
    text = stamp_data(headers_answer(export, KNOWLEDGE), export.collected_at, TODAY, export.target_name).to_text()
    assert f"- {_HSTS}: niet beoordeeld [niet vastgesteld]" in text
    assert "NIET VASTGESTELD" in text
    assert "config/sslvserver.sslprofile" in text.split("NIET VASTGESTELD", 1)[1]


def test_b2_a_bound_hsts_profile_is_present_and_bound_with_the_vserver_names(tmp_path):
    export = _export(
        tmp_path,
        profiles=[_FE_HSTS, _FE_PLAIN],
        vservers=[
            {"vservername": "LB_B", "sslprofile": "FE_HSTS"},
            {"vservername": "LB_A", "sslprofile": "fe_hsts"},
            {"vservername": "LB_C", "sslprofile": "FE_PLAIN"},
        ],
    )
    result = _by_header(export)[_HSTS]
    assert result.word == "aanwezig en gebonden"
    assert result.vservers == ("LB_A", "LB_B")
    assert "LB_A, LB_B" in result.evidence
    assert result.read_gaps == ()


def test_b2_a_defined_hsts_profile_that_no_vserver_binds_is_only_defined(tmp_path):
    export = _export(
        tmp_path,
        profiles=[_FE_HSTS, _FE_PLAIN],
        vservers=[{"vservername": "LB_A", "sslprofile": "FE_PLAIN"}],
    )
    result = _by_header(export)[_HSTS]
    assert result.word == "wel gedefinieerd, niet gebonden"
    assert result.vservers == ()


def test_b2_an_unbound_builtin_profile_does_not_count(tmp_path):
    export = _export(
        tmp_path,
        profiles=[_BUILTIN_SECURE, _FE_PLAIN],
        vservers=[{"vservername": "LB_A", "sslprofile": "FE_PLAIN"}],
    )
    result = _by_header(export)[_HSTS]
    assert result.word == "afwezig"


def test_b2_a_builtin_profile_counts_once_a_vserver_binds_it(tmp_path):
    export = _export(
        tmp_path,
        profiles=[_BUILTIN_SECURE],
        vservers=[{"vservername": "LB_A", "sslprofile": "ns_default_ssl_profile_secure_frontend"}],
    )
    result = _by_header(export)[_HSTS]
    assert result.word == "aanwezig en gebonden"
    assert result.vservers == ("LB_A",)


@pytest.mark.parametrize(
    "vservers, resource_status, gap_source",
    [
        ([{"vservername": "LB_A"}], None, "config/sslvserver.sslprofile"),
        ((), {"config/sslvserver": "RBAC_DENIED"}, "config/sslvserver"),
    ],
    ids=["field-missing", "source-unread"],
)
def test_b2_a_binding_read_gap_is_not_assessed_never_present(tmp_path, vservers, resource_status, gap_source):
    export = _export(tmp_path, profiles=[_FE_HSTS], vservers=vservers, resource_status=resource_status)
    result = _by_header(export)[_HSTS]
    assert result.word == "niet beoordeeld"
    assert any(g.source == gap_source for g in result.read_gaps)
    finding = next(f for f in headers_answer(export, KNOWLEDGE).findings if f.subject == _HSTS)
    assert finding.certainty is Certainty.NOT_ESTABLISHED


def test_b2_a_bound_profile_next_to_a_binding_gap_stays_bound_and_names_the_gap(tmp_path):
    export = _export(
        tmp_path,
        profiles=[_FE_HSTS],
        vservers=[{"vservername": "LB_A", "sslprofile": "FE_HSTS"}, {"vservername": "LB_B"}],
    )
    result = _by_header(export)[_HSTS]
    assert result.word == "aanwezig en gebonden"
    assert result.vservers == ("LB_A",)
    assert any(g.source == "config/sslvserver.sslprofile" for g in result.read_gaps)


def test_b2_headers_and_tls_baseline_do_not_contradict_on_the_lab_export():
    """Cross-check on one export: a vserver the header answer calls bound to
    HSTS must not be flagged "hsts uit" by the TLS baseline, and a header
    answer of "aanwezig en gebonden" needs at least one such vserver."""
    from nsmcp.tls_baseline import grade_per_vserver

    export = load_export(FIXTURE)
    result = _by_header(export)[_HSTS]
    hsts_off = {g.vserver for g in grade_per_vserver(export) if "hsts uit" in g.kenmerken}
    assert hsts_off, "de labexport hoort vservers met 'hsts uit' te dragen"
    assert not set(result.vservers) & hsts_off
    if result.word == "aanwezig en gebonden":
        assert set(result.vservers) - hsts_off
    assert result.word != "aanwezig en gebonden"
