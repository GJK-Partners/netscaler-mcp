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
    lines = ['add cs policy CSP_C -rule "CONNECTION.SRCIP.EQ(192.0.2.1)"', "bind cs vserver CS_VS -policyName CSP_C"]
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
    """A family without a vendor row (an ICA access policy is in none of the
    three tables of CTX296948) stays undecided with a classic expression,
    bound or not: never blocking, never open (ruling R3b: set 4 is only for
    forms without a vendor row)."""
    lines = ["add ica accessPolicy IA_OUD ns_true IA_PROF", "bind vpn vserver V -policy IA_OUD"]
    assert _sets(lines) == {1: SET_UNDECIDED}


@pytest.mark.parametrize(
    ("line", "row"),
    [
        ("add pq policy PQ_OUD -rule ns_true -priority 1", 2),
        ("add dos policy DOS_OUD -qDepth 100", 3),
        ("add appqoe policy AQ_OUD -rule ns_true -action AQ_ACT", 4),
    ],
)
def test_classic_table_1_families_block_with_their_row(line, row):
    """Ruling R3b: every form with its own row in CTX296948 table 1 or 2
    blocks the transition (set 1 bound, set 2 unbound - both block)."""
    name = line.split()[3]
    bound = classify([line, f"bind lb vserver LB_VS -policyName {name}"]).findings
    assert [(f.verzameling, f.bron.startswith(f"CTX296948 tabel 1 rij {row} ")) for f in bound] == [
        (SET_BLOCKING, True)
    ]
    assert _sets([line]) == {1: SET_UNBOUND}


def test_classic_an_advanced_appqoe_policy_is_no_finding():
    assert _sets(['add appqoe policy AQ_NIEUW -rule "HTTP.REQ.URL.CONTAINS(\\"x\\")" -action AQ_ACT']) == {}


@pytest.mark.parametrize(
    ("line", "row"),
    [
        ("add tunnel trafficPolicy TT_OUD ns_true TT_ACT", 14),
        ("add aaa preauthenticationpolicy PA_OUD ns_true PA_ACT", 4),
    ],
)
def test_classic_table_3_families_without_a_spec_class_are_deprecated_with_their_row(line, row):
    """Ruling R3b: set 4 is only for forms without a vendor row, so the table 3
    rows A.5.1 did not list are set 3 (never blocking) with their row."""
    findings = classify([line]).findings
    assert [f.verzameling for f in findings] == [SET_DEPRECATED]
    assert findings[0].bron.startswith(f"CTX296948 tabel 3 rij {row} ")


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


def _export_with_configs(
    tmp_path: Path,
    running_extra: list[str],
    saved_extra: list[str] | None = None,
    *,
    drop_running: bool = False,
    with_saved: bool = True,
    saved_hash_wrong: bool = False,
):
    """The pre-flight base export with lines appended to its running config
    and, next to it, a saved config (the base running config plus
    `saved_extra`, by default the same lines as the running config), re-sealed
    the way `tests/test_preflight.py::_variant` does it."""
    target = tmp_path / "export"
    shutil.copytree(FIXTURES / "preflight-export", target)
    running = target / "parsed" / "runningconfig.txt"
    base = running.read_text(encoding="utf-8")
    if not base.endswith("\n"):
        base += "\n"
    text = base + "".join(line + "\n" for line in running_extra)
    running.write_text(text, encoding="utf-8")
    manifest_path = target / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["parsed/runningconfig.txt"] = hashlib.sha256(
        text.replace("\r\n", "\n").encode("utf-8")
    ).hexdigest()
    if with_saved:
        saved_text = base + "".join(line + "\n" for line in (running_extra if saved_extra is None else saved_extra))
        (target / "parsed" / "savedconfig.txt").write_text(saved_text, encoding="utf-8")
        manifest["resources"]["config/nssavedconfig"] = {
            "status": "OK",
            "propertyName": "nssavedconfig",
            "objectCount": 1,
        }
        digest = hashlib.sha256(saved_text.replace("\r\n", "\n").encode("utf-8")).hexdigest()
        manifest["files"]["parsed/savedconfig.txt"] = ("0" * 64) if saved_hash_wrong else digest
    if drop_running:
        del manifest["resources"]["config/nsrunningconfig"]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    seal_manifest(target)
    (target / "scan-doel.txt").write_text(
        "preflight-lab\n" + hashlib.sha256(manifest_path.read_bytes()).hexdigest() + "\n", encoding="utf-8"
    )
    return load_export(target)


def _export_with_running(tmp_path: Path, extra: list[str], *, drop_running: bool = False):
    return _export_with_configs(tmp_path, extra, drop_running=drop_running)


def test_classic_transition_check_on_a_clean_config_is_no_blocker(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, []))
    assert check.word == NO_BLOCKER
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence


def test_classic_transition_check_blocks_on_set_1(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines("verzameling-1-filter-gebonden.conf")))
    assert check.word == BLOCKER
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence
    assert "vanaf 13.1 verwijderd" in check.reason and "in 14.1" not in check.reason


def test_classic_undecided_is_not_assessed_in_transition_mode(tmp_path):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines("verzameling-4-onbekende-familie.conf")))
    assert check.word == NOT_ASSESSED
    assert "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config" in check.evidence


def test_classic_transition_check_set_1_outweighs_undecided(tmp_path):
    extra = _lines("verzameling-4-onbekende-familie.conf") + _lines("verzameling-1-cs-ns-true-gebonden.conf")
    assert _check_2_classic_transition(_export_with_running(tmp_path, extra)).word == BLOCKER


def test_classic_transition_blocks_on_an_unbound_removed_feature(tmp_path):
    """Ruling R2 (review I-2): the vendor check refuses every command of a
    removed feature, bound or not. Set 2 blocks the transition like set 1,
    and the sentence never says it does not hold the transition back."""
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines("verzameling-2-cs-url-ongebonden.conf")))
    assert check.word == BLOCKER
    assert "houdt de overstap niet tegen" not in check.reason
    assert "gebonden of niet" in check.reason


@pytest.mark.parametrize(
    "fragment", ["verzameling-3-audit-ns-true-gebonden.conf", "verzameling-3-gateway-gebonden.conf"]
)
def test_classic_transition_check_only_set_3_is_an_attention_point(tmp_path, fragment):
    check = _check_2_classic_transition(_export_with_running(tmp_path, _lines(fragment)))
    assert check.word == ATTENTION
    assert "deprecated" in check.reason


def test_classic_transition_reads_the_saved_config_too(tmp_path):
    """Ruling R1 (review I-1): classic of tables 1 and 2 no longer loads from
    13.1 on, so on a running 13.1 it can only survive in the saved
    configuration - which is what the vendor check reads."""
    export = _export_with_configs(tmp_path, [], _lines("verzameling-1-filter-gebonden.conf"))
    check = _check_2_classic_transition(export)
    assert check.word == BLOCKER
    assert check.name == "classic-configuratie in de draaiende en de opgeslagen configuratie"
    assert "(0 in de draaiende configuratie en 2 in de opgeslagen configuratie)" in check.reason
    saved, gap = export.saved_config_lines()
    assert gap is None
    policy_line = len(saved) - 1
    assert "parsed/runningconfig.txt (draaiend)" in check.evidence
    assert (
        f"parsed/savedconfig.txt (opgeslagen), {len(saved)} regels: verzameling 1 (verwijderd en gebonden): 1 op"
        f" regel {policy_line}" in check.evidence
    )


def test_classic_transition_blocks_on_a_rest_form_in_the_saved_config(tmp_path):
    export = _export_with_configs(tmp_path, [], ["set cmp parameter -policyType CLASSIC"])
    assert _check_2_classic_transition(export).word == BLOCKER


def test_classic_transition_without_saved_config_is_not_assessed_with_the_fixed_reason(tmp_path):
    check = _check_2_classic_transition(_export_with_configs(tmp_path, [], with_saved=False))
    assert check.word == NOT_ASSESSED
    assert check.reason == "opgeslagen configuratie niet in de export"


def test_classic_transition_unreadable_saved_config_is_not_assessed(tmp_path):
    check = _check_2_classic_transition(_export_with_configs(tmp_path, [], saved_hash_wrong=True))
    assert check.word == NOT_ASSESSED
    assert check.reason != "opgeslagen configuratie niet in de export"


def test_classic_transition_a_removed_feature_in_the_readable_source_outweighs_a_read_gap(tmp_path):
    """A.5.1 R0 order: `dicht` on set 1 in either source comes before `niet
    beoordeeld` on an unreadable one."""
    export = _export_with_configs(tmp_path, _lines("verzameling-1-filter-gebonden.conf"), with_saved=False)
    assert _check_2_classic_transition(export).word == BLOCKER


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


def test_the_bounded_line_list_never_cuts_a_number():
    from nsmcp.preflight import _bounded_numbers

    numbers = tuple(range(1000, 1200))
    text = _bounded_numbers(numbers)
    assert text.endswith(", ...(afgekapt)")
    listed = text[: -len(", ...(afgekapt)")].split(", ")
    assert all(item.isdigit() and int(item) in numbers for item in listed)
    assert len(text) <= 200 + len(", ...(afgekapt)")
    assert _bounded_numbers((3, 7)) == "3, 7"
    assert _bounded_numbers(()) == "-"


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


# ---------------------------------------------------------------------------
# Herstelronde 1: forms of CTX296948 table 2 outside the class list (ruling
# R3), and the review's minor findings.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lines", "line", "row"),
    [
        (
            [
                'add cs policy CE -rule "SYS.EVAL_CLASSIC_EXPR(\\"REQ.HTTP.URL CONTAINS /x\\")"',
                "bind cs vserver V -policyName CE",
            ],
            1,
            9,
        ),
        (['add responder policy RE "SYS.EVAL_CLASSIC_EXPR(\\"ns_true\\")" NOOP'], 1, 9),
        (['add rewrite action RA replace HTTP.REQ.URL "SYS.EVAL_CLASSIC_EXPR(\\"ns_true\\")"'], 1, 9),
        (["add policy patclass PC"], 1, 10),
        (['add rewrite action RA replace_all HTTP.REQ.URL "\\"x\\"" -pattern abc'], 1, 8),
        (['add rewrite action RB replace HTTP.REQ.URL "\\"x\\"" -bypassSafetyCheck YES'], 1, 11),
        (['add cache policy CB -rule "HTTP.REQ.BODY.CONTAINS(\\"x\\")" -action NOCACHE'], 1, 12),
        (["set cmp parameter -policyType CLASSIC"], 1, 13),
        (['add cs policy CQ -rule "Q.URL.CONTAINS(\\"x\\")"', "bind cs vserver V -policyName CQ"], 1, 2),
        (['add rewrite policy RS "S.STATUS.EQ(200)" NOOP'], 1, 2),
        (['add policy expression NE_Q "Q.HEADER(\\"Host\\").EXISTS"'], 1, 2),
    ],
)
def test_classic_table_2_rest_forms_block_with_their_row(lines, line, row):
    """Ruling R3b: a form with its own row in CTX296948 table 2 blocks the
    transition (set 1), with the row as its source."""
    findings = {f.line: f for f in classify(lines).findings}
    assert findings[line].verzameling == SET_BLOCKING
    assert findings[line].bron.startswith(f"CTX296948 tabel 2 rij {row} ")


def test_classic_http_req_body_with_argument_and_advanced_cmp_parameter_are_no_finding():
    lines = [
        'add cache policy CB -rule "HTTP.REQ.BODY(1000).CONTAINS(\\"x\\")" -action NOCACHE',
        "set cmp parameter -policyType ADVANCED",
    ]
    assert _sets(lines) == {}


@pytest.mark.parametrize(
    "bind",
    [
        "bind cmp global ns_cmp_content_type -priority 10000 -gotoPriorityExpression END -type RES_DEFAULT",
        "bind cmp global ns_nocmp_xml_ie -priority 8700",
        "bind cmp global ns_cmp_msapp -priority 9000",
        "bind lb vserver LB_VS -policyName ns_cmp_mscss -priority 100",
        "bind cmp policylabel CMP_LABEL ns_nocmp_mozilla_47 100",
    ],
)
def test_classic_builtin_classic_policy_only_on_a_bind_line_blocks(bind):
    """Ruling R3b with review H-1/H-7: the vendor's built-in CLASSIC
    compression policies (`ns_cmp_*`, `ns_nocmp_*`) on a policy position of a
    bind line block, with table 2 row 4 as the source."""
    finding = classify([bind]).findings
    assert [f.verzameling for f in finding] == [SET_BLOCKING]
    assert finding[0].bron.startswith("CTX296948 tabel 2 rij 4 ")


@pytest.mark.parametrize(
    "bind",
    [
        "bind ssl profile ns_default_ssl_profile_frontend -eccCurveName P_256",
        "bind ssl profile ns_default_ssl_profile_backend -cipherName DEFAULT_BACKEND -cipherPriority 1",
        "bind ssl vserver SSL_VS -certkeyName ns-server-certificate",
        "bind cs vserver CS_VS -policyName ns_eigen_naam -priority 100",
        "bind cmp global ns_adv_nocmp_xml_ie -priority 8700 -gotoPriorityExpression END -type RES_DEFAULT",
        "bind lb vserver LB_VS ns_cmp_dienst",
    ],
)
def test_classic_vendor_objects_with_an_ns_name_that_are_no_classic_policy_are_no_finding(bind):
    """Review H-1: the default SSL profiles, the default certificate, a
    policy name outside the allowlist, an advanced built-in and a service
    (no policy position) are no classic policy."""
    assert classify([bind]).findings == ()


def test_classic_the_transition_never_blocks_an_existing_export_fixture():
    """Review H-1: the export fixtures are 14.1 configurations without
    classic; the transition check must not say `blokkade` on any of them,
    and neither configuration holds a removed feature."""
    for export_dir in export_fixtures():
        export = load_export(export_dir)
        check = _check_2_classic_transition(export)
        assert check.word != BLOCKER, (export_dir.name, check.reason)
        for reader in (export.running_config_lines, export.saved_config_lines):
            lines, gap = reader()
            if gap is None:
                assert classify(lines).removed == (), export_dir.name


def test_classic_advanced_builtins_goto_expressions_and_declared_names_on_a_bind_line_are_no_finding():
    lines = [
        "bind cmp global ns_adv_cmp_content_type -priority 100 -gotoPriorityExpression END -type RES_DEFAULT",
        "bind cs vserver CS_VS -policyName P -priority 100 -gotoPriorityExpression ns_true",
        'add cmp policy ns_eigen -rule "HTTP.RES.HEADER(\\"Content-Type\\").CONTAINS(\\"text\\")" -resAction COMPRESS',
        "bind cmp global ns_eigen -priority 200",
    ]
    assert _sets(lines) == {}


def test_classic_an_unreadable_bind_line_keeps_a_removed_feature_removed():
    """Ruling R3c (review H-2): an unreadable bind line leaves the binding
    open, but a readable command of a removed feature is refused by the
    vendor bound or not: set 2 (blocking the transition), the uncertainty in
    the class."""
    lines = [
        'add filter policy "F P" -rule ns_true -reqAction FA',
        'bind lb vserver L -policyName "F P -priority 1',
    ]
    findings = classify(lines).findings
    assert [(f.line, f.verzameling) for f in findings] == [(1, SET_UNBOUND)]
    assert "binding niet vast te stellen" in findings[0].klasse
    assert classify(lines).removed == (1,)


def test_classic_a_classic_lb_rule_without_a_bind_line_is_removed():
    """Ruling R3c (review H-2): `-rule` is a parameter of the vserver, not a
    bound policy; the vendor refuses the classic rule either way."""
    findings = classify(
        ['add lb vserver LBV HTTP 192.0.2.43 80 -persistenceType RULE -rule "REQ.HTTP.HEADER Host == x"']
    ).findings
    assert [(f.line, f.verzameling) for f in findings] == [(1, SET_UNBOUND)]


def test_classic_an_unreadable_policy_line_itself_stays_undecided():
    assert _sets(['add filter policy "F P -rule ns_true']) == {1: SET_UNDECIDED}


@pytest.mark.parametrize(
    "prefix", ["CLIENT.OS(win10) EXISTS", "CLIENT.APPLICATION.PROCESS(x) EXISTS", "CLIENT.SYSTEM.DOMAIN EQ x"]
)
def test_classic_client_security_expression_is_classic(prefix):
    """Review M-3 and ruling R3b: classic client-security (EPA) expressions
    begin with `CLIENT.` too; CTX296948 table 3 row 18 says they keep working.
    In a Gateway session policy that is set 3, never advanced, never blocking."""
    findings = classify([f'add vpn sessionPolicy VE "{prefix}" VA']).findings
    assert [f.verzameling for f in findings] == [SET_DEPRECATED]


def test_classic_client_security_head_in_a_removed_family_is_undecided():
    """Review H-6: whether an advanced form with this head exists is not
    established; in a removed family the strictest reading is undecided -
    never blocking, never open."""
    lines = ['add cs policy CSE -rule "CLIENT.APPLICATION.PROCESS(x) EXISTS"', "bind cs vserver V -policyName CSE"]
    assert _sets(lines) == {1: SET_UNDECIDED}


def test_classic_client_ip_is_still_advanced():
    assert _sets(['add vpn sessionPolicy VN "CLIENT.IP.SRC.IN_SUBNET(192.0.2.0/24)" VA']) == {}


def test_classic_named_expression_in_set_1_cites_the_users_row():
    """Review M-4: table 3 row 1 says classic named expressions keep working;
    a blocking verdict on one rests on the row of the feature that uses it."""
    findings = {f.line: f for f in classify(_lines("named-expressions.conf")).findings}
    assert findings[6].verzameling == SET_BLOCKING
    assert findings[6].bron == findings[7].bron == "CTX296948 tabel 2 rij 6 (Content Switching Classic policy)"
    assert findings[2].bron.startswith("CTX296948 tabel 3 rij 1 ")


def test_classic_the_gateway_bind_source_names_the_authorization_row():
    lines = ["add authorization policy AZ ns_true ALLOW", "bind vpn vserver V -policy AZ -priority 1"]
    findings = {f.line: f for f in classify(lines).findings}
    assert findings[2].verzameling == SET_DEPRECATED
    assert "5-12" in findings[2].bron


def test_classic_removed_accessor_is_sets_1_and_2():
    classification = classify(
        _lines("verzameling-1-filter-gebonden.conf") + _lines("verzameling-2-cs-url-ongebonden.conf")
    )
    assert classification.removed == (1, 2, 4)


# ---------------------------------------------------------------------------
# Herkeuring 1: HTMLInjection, the rows without a known form, literals.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "bron"),
    [
        ("add filter htmlinjectionvariable HV1 -value x", "CTX296948 tabel 1 rij 7 "),
        ("set filter htmlinjectionparameter -rate 1", "CTX296948 tabel 1 rij 7 "),
        ("set filter prebodyInjection pre.html", "CTX296948 tabel 1 rij 7 "),
        ("set filter postbodyInjection post.html", "CTX296948 tabel 1 rij 7 "),
        ("bind filter global FP_OUD", "CTX296948 tabel 2 rij 1 "),
    ],
)
def test_classic_filter_and_html_injection_commands_block(line, bron):
    """Review H-3: HTMLInjection (table 1 row 7) and every other command of
    the classic Filter feature (table 2 row 1) block the transition."""
    findings = classify([line]).findings
    assert [f.verzameling for f in findings] == [SET_BLOCKING]
    assert findings[0].bron.startswith(bron)


@pytest.mark.parametrize(
    ("line", "row"),
    [
        ("add ns httpProfile HP_SPDY -spdy ENABLED", 5),
        ("set ns httpProfile nshttp_default_profile -http2 ENABLED", 6),
        ("add appflow action AF_ACT -collectors COL -clientSideMeasurements ENABLED", 8),
    ],
)
def test_classic_candidate_parameters_of_rows_without_a_known_form_are_undecided(line, row):
    """Review H-3/H-5: SPDY, HTTP/2 and AppFlow client-side measurements have a
    row but no known classic command form; their probable parameters are
    undecided with the row, never blocking, never green."""
    findings = classify([line]).findings
    assert [f.verzameling for f in findings] == [SET_UNDECIDED]
    assert findings[0].bron.startswith(f"CTX296948 tabel 1 rij {row} ")


def test_classic_candidate_parameters_switched_off_are_no_finding():
    lines = [
        "add ns httpProfile HP_UIT -spdy DISABLED -http2 DISABLED",
        "add appflow action AF_UIT -collectors COL -clientSideMeasurements DISABLED",
    ]
    assert _sets(lines) == {}


def test_classic_transition_names_the_rows_it_does_not_examine(tmp_path):
    """Review H-3/H-5: the evidence always says which rows lie outside the
    search, also next to `geen blokkade`."""
    from nsmcp.classic import NOT_EXAMINED_ROWS

    assert NOT_EXAMINED_ROWS == (
        "niet onderzocht: SPDY, HTTP/2-classic, AppFlow client-side measurements (tabel 1 rij 5, 6, 8)"
    )
    check = _check_2_classic_transition(_export_with_running(tmp_path, []))
    assert check.word == NO_BLOCKER
    assert NOT_EXAMINED_ROWS in check.evidence


@pytest.mark.parametrize(
    "lines",
    [
        ['add cs policy CSR -rule "HTTP.REQ.URL.REGEX_MATCH(re/^S.Admin/)"', "bind cs vserver V -policyName CSR"],
        ['add cs policy CSR -rule "HTTP.REQ.URL.REGEX_MATCH(re#ns_true#)"', "bind cs vserver V -policyName CSR"],
        ['add responder action RA respondwith "\\"use SYS.EVAL_CLASSIC_EXPR no more\\""'],
        ['add responder action RB respondwith "\\"see HTTP.REQ.BODY.x\\""'],
        ['add rewrite action RC replace HTTP.REQ.URL "\\"/\\"" -comment "SYS.EVAL_CLASSIC_EXPR and Q.URL"'],
        ['add responder policy RP "HTTP.REQ.URL.CONTAINS(q/S.Admin/)" NOOP'],
    ],
)
def test_classic_literals_and_comments_are_no_form(lines):
    """Review H-4: inside a string, regex or q literal and in a comment the
    text is data, never a form."""
    assert _sets(lines) == {}


def test_classic_an_unreadable_line_with_a_rest_form_stays_undecided():
    """Ruling R3c: a line that is itself not readable stays undecided, also
    when its raw text carries a form with a vendor row."""
    assert _sets(['add rewrite action RA replace HTTP.REQ.URL "SYS.EVAL_CLASSIC_EXPR(']) == {1: SET_UNDECIDED}
