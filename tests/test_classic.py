"""1.1 A.5.1: the classic classification, `src/nsmcp/classic.py`.

Two halves, two rules:

- `classify_markers` is the 1.0.3 marker table, moved. Within 14.1 its
  outcome is byte for byte what 1.0.3 produced (spec section 2, rule 5); the
  test below keeps a frozen copy of the 1.0.3 functions and compares them on
  every running and saved config line of every fixture plus a synthetic
  corpus.
- `classify` is the classification for the transition 13.1 -> 14.1: feature
  first, expression form second, `ns_true`/`ns_false` prove only the form,
  no catch-all, a truly unknown form stays undecided (set 4).

The fragments in tests/fixtures/classic/ are synthetic (see its README).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from conftest import seal_manifest
from read_tools_harness import FIXED_DAY, KNOWLEDGE, export_fixtures

from nsmcp import classic
from nsmcp.classic import (
    ADVANCED_PREFIXES,
    CLASSIC_PREFIXES,
    SET_BLOCKING,
    SET_DEPRECATED,
    SET_UNBOUND,
    SET_UNDECIDED,
    classify,
    classify_markers,
    markers_bound,
)
from nsmcp.export import load_export
from nsmcp.knowledge import load_knowledge
from nsmcp.preflight import ATTENTION, BLOCKER, NO_BLOCKER, NOT_ASSESSED, _check_2_classic_transition

FIXTURES = Path(__file__).parent / "fixtures"
CLASSIC = FIXTURES / "classic"
_KNOWLEDGE = load_knowledge(KNOWLEDGE, today=FIXED_DAY)


def _lines(name: str) -> list[str]:
    return (CLASSIC / name).read_text(encoding="utf-8").splitlines()


def _sets(lines: list[str]) -> dict[int, int]:
    """line number -> set, for every finding."""
    return {f.line: f.verzameling for f in classify(lines).findings}


# ---------------------------------------------------------------------------
# The frozen 1.0.3 functions (preflight._markers / preflight._is_bound at
# d04eff8), copied as they were. Never edited: they are the reference.
# ---------------------------------------------------------------------------

_REMOVED_PREFIXES_1_0_3 = ("add filter action", "add filter policy", "add cr policy")
_CLASSIC_EXPRESSIONS_1_0_3 = ("ns_true", "ns_false")
_DEPRECATED_PREFIXES_1_0_3 = ("add authentication", "add vpn", "bind authentication", "bind vpn")


def _markers_1_0_3(lines):
    removed, deprecated, bound = [], [], []
    for number, raw in enumerate(lines, start=1):
        lowered = raw.strip().lower()
        hit = any(lowered.startswith(prefix) for prefix in _REMOVED_PREFIXES_1_0_3) or any(
            expression in lowered for expression in _CLASSIC_EXPRESSIONS_1_0_3
        )
        if not hit:
            continue
        if any(lowered.startswith(prefix) for prefix in _DEPRECATED_PREFIXES_1_0_3):
            deprecated.append(number)
            continue
        removed.append(number)
        if lowered.startswith("bind "):
            bound.append(number)
    return removed, deprecated, bound


def _is_bound_1_0_3(lines, marker_lines):
    names = set()
    for number in marker_lines:
        parts = lines[number - 1].strip().split()
        if len(parts) >= 4 and parts[0].lower() == "add":
            names.add(parts[3].strip('"').lower())
    if not names:
        return False
    for raw in lines:
        lowered = raw.strip().lower()
        if not lowered.startswith("bind "):
            continue
        tokens = {token.strip('"') for token in lowered.split()}
        if names & tokens:
            return True
    return False


def _corpus() -> list[list[str]]:
    corpora: list[list[str]] = []
    for export_dir in export_fixtures():
        for name in ("runningconfig.txt", "savedconfig.txt"):
            path = export_dir / "parsed" / name
            if path.is_file():
                corpora.append(path.read_text(encoding="utf-8").splitlines())
    for path in sorted(CLASSIC.glob("*.conf")):
        corpora.append(path.read_text(encoding="utf-8").splitlines())
    corpora.append(
        [
            "ADD CR POLICY X -rule ns_true",
            '  add filter policy "met spatie" -rule ns_false',
            'bind lb vserver V -policyName "met spatie"',
            "bind cs vserver V -policyName P -gotoPriorityExpression ns_true",
            "add vpn sessionPolicy S ns_true A",
            "add rewrite policy R ns_true A",
            "add cr policy",
            "",
        ]
    )
    return corpora


def test_classic_in_line_markers_are_byte_identical_to_1_0_3():
    corpora = _corpus()
    assert len(corpora) > 10
    for lines in corpora:
        removed, deprecated, bound = classify_markers(lines)
        assert (removed, deprecated, bound) == _markers_1_0_3(lines)
        assert markers_bound(lines, removed) == _is_bound_1_0_3(lines, removed)
        assert markers_bound(lines, deprecated) == _is_bound_1_0_3(lines, deprecated)


def test_the_in_line_tables_moved_unchanged():
    assert classic._REMOVED_PREFIXES == _REMOVED_PREFIXES_1_0_3
    assert classic._CLASSIC_EXPRESSIONS == _CLASSIC_EXPRESSIONS_1_0_3
    assert classic._DEPRECATED_PREFIXES == _DEPRECATED_PREFIXES_1_0_3
    assert classic.MARKERS_SEARCHED == "'add filter', 'add cr policy', ns_true, ns_false"


def test_preflight_no_longer_owns_the_classic_tables():
    """Spec section 2, rule 2: one owner per rule. `preflight` calls the
    module, it does not keep a second copy of the tables."""
    from nsmcp import preflight

    for name in ("_REMOVED_PREFIXES", "_CLASSIC_EXPRESSIONS", "_DEPRECATED_PREFIXES", "_SEARCHED"):
        assert not hasattr(preflight, name), name


# ---------------------------------------------------------------------------
# Set 1 and 2: features from which classic is removed.
# ---------------------------------------------------------------------------


def test_classic_classification_filter_policy_bound_blocks():
    sets = _sets(_lines("verzameling-1-filter-gebonden.conf"))
    assert sets[2] == SET_BLOCKING
    # The action is named by the policy, but no bind line names it.
    assert sets[1] == SET_UNBOUND
    assert 3 not in sets


def test_classic_classification_filter_policy_unbound_is_set_2():
    lines = _lines("verzameling-1-filter-gebonden.conf")[:2]
    assert _sets(lines) == {1: SET_UNBOUND, 2: SET_UNBOUND}


def test_classic_ns_true_in_bound_cs_policy_blocks():
    assert _sets(_lines("verzameling-1-cs-ns-true-gebonden.conf")) == {2: SET_BLOCKING}


def test_classic_ns_true_in_bound_cmp_policy_blocks():
    """CTX296948 table 2 row 4 names the classic compression policy, so the
    family has its vendor row: set 1, not 4."""
    assert _sets(_lines("verzameling-1-cmp-ns-true-gebonden.conf")) == {2: SET_BLOCKING}


def test_classic_classification_cs_url_unbound_is_set_2():
    assert _sets(_lines("verzameling-2-cs-url-ongebonden.conf")) == {1: SET_UNBOUND}


def test_classic_classification_cs_domain_bound_blocks_whatever_the_rule():
    lines = [
        'add cs policy CSP_DOM -domain "oud.voorbeeld.test"',
        "bind cs vserver CS_VS -policyName CSP_DOM -targetLBVserver LB_VS",
    ]
    assert _sets(lines) == {1: SET_BLOCKING}


def test_classic_classification_sc_policy_bound_blocks():
    lines = ["add sc policy SC_OUD -rule TRUE -action ACS", "bind lb vserver LB_VS -policyName SC_OUD"]
    assert _sets(lines) == {1: SET_BLOCKING}


@pytest.mark.parametrize(
    "line",
    [
        "add cr policy P_OUD -rule REQ.HTTP.URL==/oud",
        "add appfw policy P_OUD ns_true APPFW_PROF",
        "add ssl policy P_OUD -rule ns_true -reqAction CLIENTAUTH",
        'add cmp policy P_OUD -rule "REQ.HTTP.URL CONTAINS /oud" -resAction COMPRESS',
        "add cs policy P_OUD -rule METHOD==GET",
        'add cs policy P_OUD -rule "URL == /oud/*"',
        'add cs policy P_OUD -rule "HEADER Host EXISTS"',
        'add cs policy P_OUD -rule "RES.HTTP.HEADER Server EXISTS"',
    ],
)
def test_classic_classification_a_classic_expression_in_a_removed_family_blocks_when_bound(line):
    lines = [line, "bind lb vserver LB_VS -policyName P_OUD"]
    assert _sets(lines) == {1: SET_BLOCKING}
    assert _sets(lines[:1]) == {1: SET_UNBOUND}


def test_classic_classification_lb_vserver_rule_is_classic_and_bound_by_its_own_bind():
    lines = [
        "add lb vserver LB_OUD HTTP 192.0.2.40 80 -persistenceType RULE -rule ns_true",
        "bind lb vserver LB_OUD SVC_1",
    ]
    assert _sets(lines) == {1: SET_BLOCKING}


def test_classic_lb_vserver_without_a_rule_is_no_policy_line():
    assert _sets(["add lb vserver LB_NIEUW HTTP 192.0.2.41 80 -persistenceType SOURCEIP"]) == {}


def test_classic_lb_vserver_with_rule_persistence_but_no_readable_rule_is_undecided():
    assert _sets(["add lb vserver LB_X HTTP 192.0.2.42 80 -persistenceType RULE"]) == {1: SET_UNDECIDED}


def test_classic_advanced_http_req_is_not_classic():
    """Advanced expressions in families that also had a classic form, an
    `ns_` inside a string literal, a leading negation, `true` in lower case,
    the advanced authentication policy and an advanced named expression:
    none of them is a finding."""
    assert _sets(_lines("advanced-geen-classic.conf")) == {}


def test_classic_an_expression_in_a_removed_family_that_is_neither_is_undecided():
    lines = ['add cs policy CSP_Q -rule "Q.URL.CONTAINS(\\"x\\")"', "bind cs vserver CS_VS -policyName CSP_Q"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_mixed_advanced_and_classic_markers_are_undecided():
    """An advanced prefix with a classic token outside a string literal is
    not a form this module can name; the strictest reading is undecided."""
    lines = ['add cs policy CSP_MIX -rule "HTTP.REQ.IS_VALID && ns_true"', "bind cs vserver CS_VS -policyName CSP_MIX"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_an_advanced_builtin_name_is_not_proof_of_classic():
    """`ns_adv_*` are the built-in ADVANCED compression policies; an `ns_`
    token start alone would call them classic. Undecided, never blocking."""
    lines = ["add cs policy CSP_ADV -rule ns_adv_iets", "bind cs vserver CS_VS -policyName CSP_ADV"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_lowercase_advanced_prefix_is_not_advanced():
    """The advanced prefix list is pinned as the appliance writes it; a form
    outside it is undecided, not quietly advanced."""
    lines = ['add cs policy CSP_LC -rule "http.req.url.contains(\\"x\\")"', "bind cs vserver CS_VS -policyName CSP_LC"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_unreadable_quoting_is_undecided():
    lines = ['add cs policy CSP_OPEN -rule "ns_true', "bind cs vserver CS_VS -policyName CSP_OPEN"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_a_bind_line_with_ns_true_proves_nothing_by_itself():
    """`ns_true` as goto expression on a bind line is no removed feature."""
    assert _sets(["bind cs vserver CS_VS -policyName CSP_X -gotoPriorityExpression ns_true"]) == {}


# ---------------------------------------------------------------------------
# Set 3: deprecated, never blocking.
# ---------------------------------------------------------------------------


def test_classic_ns_true_in_audit_is_deprecated_not_blocking():
    classification = classify(_lines("verzameling-3-audit-ns-true-gebonden.conf"))
    assert {f.line: f.verzameling for f in classification.findings} == {2: SET_DEPRECATED}
    assert classification.blocking == ()


def test_classic_gateway_authentication_is_never_blocking():
    classification = classify(_lines("verzameling-3-gateway-gebonden.conf"))
    assert {f.line: f.verzameling for f in classification.findings} == {2: SET_DEPRECATED, 4: SET_DEPRECATED}
    assert classification.blocking == () and classification.unbound == ()


@pytest.mark.parametrize(
    "line",
    [
        "add tm sessionPolicy TM_OUD ns_true TM_ACT",
        "add authorization policy AZ_OUD ns_true ALLOW",
        'add authorization policy AZ_OUD "REQ.HTTP.URL CONTAINS /x" DENY',
        "add vpn sessionPolicy VS_OUD ns_true VS_ACT",
        "add vpn trafficPolicy VT_OUD ns_true VT_ACT",
        "add audit nslogPolicy NL_OUD ns_false NL_ACT",
        "add authentication radiusPolicy R_OUD ns_true R_ACT",
        "add authentication localPolicy L_OUD ns_true",
    ],
)
def test_classic_classification_deprecated_families_are_set_3_bound_or_not(line):
    assert _sets([line]) == {1: SET_DEPRECATED}
    assert _sets([line, "bind vpn global -policyName X_OUD", "bind system global VS_OUD"]) == {1: SET_DEPRECATED}


def test_classic_an_advanced_session_policy_is_not_deprecated():
    assert _sets(["add vpn sessionPolicy VS_NIEUW true VS_ACT"]) == {}


def test_classic_an_authentication_policy_type_without_a_vendor_row_is_undecided():
    """CTX296948 table 3 names local, RADIUS, LDAP, negotiate, SAML, DFA and
    web authentication; a classic `certPolicy` has no row there."""
    assert _sets(["add authentication certPolicy C_OUD ns_true C_ACT"]) == {1: SET_UNDECIDED}


# ---------------------------------------------------------------------------
# Named expressions follow the feature that uses them.
# ---------------------------------------------------------------------------


def test_classic_named_expression_inherits_the_using_feature():
    sets = _sets(_lines("named-expressions.conf"))
    # NE_AUDIT (2) used by the audit policy (3): deprecated, like its user.
    assert sets[2] == SET_DEPRECATED and sets[3] == SET_DEPRECATED
    # NE_LOS (5): classic content, no user anywhere: undecided.
    assert sets[5] == SET_UNDECIDED
    # NE_CS (6) used by the bound CS policy (7): both blocking.
    assert sets[6] == SET_BLOCKING and sets[7] == SET_BLOCKING
    assert set(sets) == {2, 3, 5, 6, 7}


def test_classic_named_expression_used_by_sets_1_and_3_is_undecided_itself():
    lines = [
        "add policy expression NE_BEIDE ns_true",
        "add cs policy CSP_B -rule NE_BEIDE",
        "bind cs vserver CS_VS -policyName CSP_B",
        "add audit syslogPolicy SYS_B NE_BEIDE SYS_ACT",
    ]
    assert _sets(lines) == {1: SET_UNDECIDED, 2: SET_BLOCKING, 4: SET_DEPRECATED}


def test_classic_named_expression_used_by_an_unbound_removed_family_is_set_2():
    lines = ["add policy expression NE_LOS2 ns_true", "add cs policy CSP_L -rule NE_LOS2"]
    assert _sets(lines) == {1: SET_UNBOUND, 2: SET_UNBOUND}


def test_classic_an_advanced_named_expression_makes_its_user_advanced():
    lines = [
        'add policy expression NE_ADV "HTTP.REQ.URL.EQ(\\"/\\")"',
        "add cs policy CSP_A -rule NE_ADV",
        "bind cs vserver CS_VS -policyName CSP_A",
    ]
    assert _sets(lines) == {}


# ---------------------------------------------------------------------------
# Set 4: what is truly unknown stays undecided.
# ---------------------------------------------------------------------------


def test_classic_unknown_family_is_undecided():
    assert _sets(_lines("verzameling-4-onbekende-familie.conf")) == {1: SET_UNDECIDED}


def test_classic_a_family_the_spec_names_no_class_for_stays_undecided():
    """Priority queuing is in CTX296948 table 1, but A.5.1 names no class for
    it: adding a blocking class is a spec change with review, so it stays
    undecided here (never blocking, never open)."""
    lines = ["add pq policy PQ_OUD -rule ns_true -priority 1", "bind lb vserver LB_VS -policyName PQ_OUD"]
    assert _sets(lines) == {1: SET_UNDECIDED}


# ---------------------------------------------------------------------------
# The shape of the output: line numbers, own words, a source per class.
# ---------------------------------------------------------------------------


def test_classic_expression_prefix_lists_are_pinned():
    assert ADVANCED_PREFIXES == (
        "HTTP.",
        "CLIENT.",
        "SERVER.",
        "SYS.",
        "TARGET.",
        "AAA.",
        "DNS.",
        "TCP.",
        "SSL.",
        "TEXT.",
    )
    assert CLASSIC_PREFIXES == ("REQ.", "RES.")


def test_classic_every_class_in_sets_1_and_3_names_a_source():
    seen = set()
    for path in sorted(CLASSIC.glob("*.conf")):
        for finding in classify(path.read_text(encoding="utf-8").splitlines()).findings:
            if finding.verzameling in (SET_BLOCKING, SET_UNBOUND, SET_DEPRECATED):
                assert finding.bron.startswith("CTX296948 tabel "), finding
                seen.add(finding.verzameling)
    assert seen == {SET_BLOCKING, SET_UNBOUND, SET_DEPRECATED}
    for family in classic._FAMILIES.values():
        assert family.bron.startswith("CTX296948 tabel "), family


def test_classic_findings_never_carry_text_from_the_line():
    secret = "GEHEIMNAAM7"
    lines = [
        f"add cs policy CSP_{secret} -rule ns_true",
        f"bind cs vserver VS_{secret} -policyName CSP_{secret}",
        f"add {secret.lower()} policy X_{secret} ns_true",
        f"add policy expression NE_{secret} ns_true",
    ]
    findings = classify(lines).findings
    assert len(findings) == 3
    for finding in findings:
        for value in (finding.kind, finding.klasse, finding.bron):
            assert secret.lower() not in value.lower(), finding


def test_classic_set_accessors_list_line_numbers_only():
    classification = classify(_lines("named-expressions.conf"))
    assert classification.blocking == (6, 7)
    assert classification.unbound == ()
    assert classification.deprecated == (2, 3)
    assert classification.undecided == (5,)


# ---------------------------------------------------------------------------
# Pre-flight check 2 in transition mode (wired behind the configuration key
# by the next step; here the check itself).
# ---------------------------------------------------------------------------


def _export_with_running(tmp_path: Path, extra: list[str], *, drop_running: bool = False):
    """The pre-flight base export with lines appended to its running config,
    re-sealed the way `tests/test_preflight.py::_variant` does it."""
    target = tmp_path / "export"
    shutil.copytree(FIXTURES / "preflight-export", target)
    running = target / "parsed" / "runningconfig.txt"
    text = running.read_text(encoding="utf-8")
    if not text.endswith("\n"):
        text += "\n"
    text += "".join(line + "\n" for line in extra)
    running.write_text(text, encoding="utf-8")
    manifest_path = target / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
        text.replace("\r\n", "\n").encode("utf-8")
    ).hexdigest()
    if drop_running:
        del manifest["resources"]["config/nsrunningconfig"]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    seal_manifest(target)
    (target / "scan-doel.txt").write_text(
        "preflight-lab\n" + hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n", encoding="utf-8"
    )
    return load_export(target)


def test_classic_transition_check_on_a_clean_config_is_no_blocker(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, []))
    assert check.word == NO_BLOCKER
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence


def test_classic_transition_check_blocks_on_set_1(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines("verzameling-1-filter-gebonden.conf")))
    assert check.word == BLOCKER
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence


def test_classic_undecided_is_not_assessed_in_transition_mode(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines("verzameling-4-onbekende-familie.conf")))
    assert check.word == NOT_ASSESSED
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence


def test_classic_transition_check_set_1_outweighs_undecided(tmp_path):
    extra = _lines("verzameling-4-onbekende-familie.conf") + _lines("verzameling-1-cs-ns-true-gebonden.conf")
    assert _check_2_classic_transition(_export_with_running(tmp_path, extra)).word == BLOCKER


@pytest.mark.parametrize(
    "fragment",
    [
        "verzameling-3-audit-ns-true-gebonden.conf",
        "verzameling-3-gateway-gebonden.conf",
        "verzameling-2-cs-url-ongebonden.conf",
    ],
)
def test_classic_transition_check_only_sets_2_and_3_is_an_attention_point(tmp_path, fragment):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines(fragment)))
    assert check.word == ATTENTION


def test_classic_transition_evidence_names_counts_and_line_numbers_never_text(tmp_path):
    secret = "GEHEIMNAAM8"
    extra = [f"add cs policy CSP_{secret} -rule ns_true", f"bind cs vserver VS_{secret} -policyName CSP_{secret}"]
    export = _export_with_running(tmp_path, extra)
    lines, gap = export.running_config_lines()
    assert gap is None
    first = len(lines) - 1
    check = _check_2_classic_transition(export)
    assert check.word == BLOCKER
    assert secret not in check.evidence and secret not in check.reason
    assert f"verzameling 1 (verwijderd en gebonden): 1 op regel {first}" in check.evidence


def test_classic_transition_check_without_running_config_is_not_assessed(tmp_path):
    export = _export_with_running(tmp_path, [], drop_running=True)
    assert _check_2_classic_transition(export).word == NOT_ASSESSED


def test_the_in_line_pre_flight_still_uses_the_1_0_3_check(tmp_path):
    """Spec section 2, rule 5: the transition check is not wired into the
    nine checks; the in-line check 2 still says what 1.0.3 said (an `ns_true`
    on an unbound line of any family: `aandachtspunt`), where the transition
    check says `niet beoordeeld`."""
    from nsmcp.preflight import _check_2_classic_markers, preflight_checks

    export = _export_with_running(tmp_path, _lines("verzameling-4-onbekende-familie.conf"))
    assert _check_2_classic_markers(export).word == ATTENTION
    assert _check_2_classic_transition(export).word == NOT_ASSESSED
    in_line = next(c for c in preflight_checks(export, _KNOWLEDGE, 9000, 1081) if c.number == 2)
    assert in_line == _check_2_classic_markers(export)
