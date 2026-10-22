"""Level-1 scorecard: honest denominator and dynamic outcome severity."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp import scorecard
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.scorecard import CONTROLS, OUT_OF_SCOPE, scorecard_results

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
KNOWLEDGE = Knowledge(version="test", date="2026-08-26", age_days=0, missing=False)


def test_catalog_has_twenty_three_fixed_and_one_conditional_control():
    ids = [control.id for control in CONTROLS]
    assert len(ids) == len(set(ids)) == 24
    assert sum(control.conditional for control in CONTROLS) == 1


def test_measured_license_and_feature_axes_remain_separate():
    results = {r.control.id: r for r in scorecard_results(load_export(FIXTURE), KNOWLEDGE)}
    for control_id in (
        "ANNA-SEC-APPFW-VPN-001",
        "ANNA-SEC-IPREP-001",
        "ANNA-SEC-BOTMGMT-001",
    ):
        assert results[control_id].applicability == "van toepassing"
    license_result = results["ANNA-LIC-001"]
    assert license_result.status == "NIET BEOORDEELD"
    assert license_result.severity == "Hoog"
    assert "daystoexpiration ontbreekt" in license_result.reason


def test_ha004_uses_the_drift_state_of_the_current_ha_engine():
    """On the first lab export config-drift is `onbevestigd`: its headers say
    the configuration changed after the last save, and ten lines per side
    carry a value the collector withheld, so that change cannot be compared.
    HA-004 is then NIET BEOORDEELD with that reason, and the source that
    falls short is the pair of config texts - never `config/hanode`, which
    has nothing to do with it. The second lab export was saved at its last
    change: PASS."""
    results = {r.control.id: r for r in scorecard_results(load_export(FIXTURE), KNOWLEDGE)}
    drift = results["GJK-L1-HA-004"]
    assert (drift.status, drift.severity) == ("NIET BEOORDEELD", "Midden")
    assert drift.reason.startswith("10 regels per kant dragen een waarde die de verzamelaar al achterhield")
    assert [(gap.source, gap.reason) for gap in drift.read_gaps] == [
        ("parsed/runningconfig.txt en parsed/savedconfig.txt", drift.reason)
    ]
    second = {
        r.control.id: r
        for r in scorecard_results(load_export(FIXTURE.parent / "lab-export-vpx-doh-synthetic"), KNOWLEDGE)
    }
    assert (second["GJK-L1-HA-004"].status, second["GJK-L1-HA-004"].severity) == ("PASS", "Midden")


def test_denominator_is_eighteen_without_confirmed_scan_context():
    results = scorecard_results(load_export(FIXTURE), KNOWLEDGE)
    assert len([result for result in results if result.in_denominator]) == 18
    assert len(OUT_OF_SCOPE) == 7
    assert "ANNA-SEC-IPREP-SCAN-001" not in {result.control.id for result in results}


def make_export(tmp_path, rows, *, statuses=None):
    root = tmp_path / "export"
    (root / "objects").mkdir(parents=True, exist_ok=True)
    resources = {}
    for resource, values in rows.items():
        key = resource.rsplit("/", 1)[-1].split("?", 1)[0]
        resources[resource] = {"status": (statuses or {}).get(resource, "OK"), "propertyName": key}
        (root / "objects" / f"{key}.json").write_text(json.dumps({key: values}), encoding="utf-8")
    (root / "export-manifest.json").write_text(
        json.dumps(
            {"manifestVersion": "1.1", "collectedAtUtc": "2026-08-26T10:00:00Z", "resources": resources, "files": {}}
        ),
        encoding="utf-8",
    )
    seal_manifest(root)
    return load_export(root)


def baseline_rows():
    return {
        "config/sslvserver": [{"vservername": "synthetic", "sslprofile": "safe", "ssl2": "DISABLED"}],
        "config/sslprofile": [{"name": "safe", "ssl2": "DISABLED", "ssl3": "DISABLED", "tls1": "DISABLED"}],
        "config/sslcertkey": [
            {
                "certkey": "synthetic",
                "daystoexpiration": 365,
                "publickeysize": 2048,
                "signaturealg": "sha256WithRSAEncryption",
            }
        ],
    }


@pytest.mark.parametrize(
    "resource,field",
    [
        ("config/sslprofile", "ssl2"),
        ("config/sslprofile", "ssl3"),
        ("config/sslprofile", "tls1"),
        ("config/sslcertkey", "daystoexpiration"),
        ("config/sslcertkey", "publickeysize"),
        ("config/sslcertkey", "signaturealg"),
    ],
)
def test_baseline_each_criterion_missing_is_a_real_gap(tmp_path, resource, field):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    del rows[resource][0][field]
    result = baseline_result(make_export(tmp_path, rows))
    assert result.status == "NIET BEOORDEELD"
    assert any(g.source == resource and field in g.reason and "sleutel ontbreekt" in g.reason for g in result.read_gaps)


@pytest.mark.parametrize(
    "resource,field,value",
    [
        ("config/sslprofile", "ssl2", "ENABLED"),
        ("config/sslprofile", "ssl3", "ENABLED"),
        ("config/sslprofile", "tls1", "ENABLED"),
        ("config/sslcertkey", "daystoexpiration", -1),
        ("config/sslcertkey", "daystoexpiration", 30),
        ("config/sslcertkey", "publickeysize", 1024),
        ("config/sslcertkey", "signaturealg", "sha1WithRSAEncryption"),
    ],
)
def test_baseline_each_conclusive_failure(tmp_path, resource, field, value):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    rows[resource][0][field] = value
    assert baseline_result(make_export(tmp_path, rows)).status == "FAIL"


def feature_rows(feature, enabled=False, licensed=True):
    rows = {"config/nslicense": {feature: licensed}, "config/nsfeature": {feature: enabled}}
    if feature == "appfw":
        rows.update(
            {
                "config/vpnvserver": [{"name": "synthetic"}],
                "config/authenticationvserver": [],
                "config/aaaparameter": {"wafprotection": ["DISABLED"]},
                "config/vpnvserver_appfwpolicy_binding?bulkbindings=yes": [],
                "config/authenticationvserver_appfwpolicy_binding?bulkbindings=yes": [],
            }
        )
    elif feature == "rep":
        rows.update({f"config/{s}policy": [] for s in ("responder", "rewrite", "appfw", "cs")})
    else:
        rows.update(
            {
                "config/botprofile": [],
                "config/botpolicy": [],
                "config/botsettings": {},
                "config/lbvserver_botpolicy_binding?bulkbindings=yes": [],
                "config/csvserver_botpolicy_binding?bulkbindings=yes": [],
                "config/botglobal_botpolicy_binding": [],
            }
        )
    return rows


def feature_result(export, feature):
    cid = {"appfw": "ANNA-SEC-APPFW-VPN-001", "bot": "ANNA-SEC-BOTMGMT-001", "rep": "ANNA-SEC-IPREP-001"}[feature]
    control = next(c for c in CONTROLS if c.id == cid)
    return scorecard._feature_control(control, export, feature)


@pytest.mark.parametrize("feature", ["appfw", "bot", "rep"])
@pytest.mark.parametrize(
    "enabled,configured,status,severity",
    [
        (False, False, "FAIL", "Laag"),
        (True, False, "FAIL", "Midden"),
        (False, True, "FAIL", "Hoog"),
        (True, True, "PASS", "Info"),
    ],
)
def test_feature_branches_independent_of_implementation_table(tmp_path, feature, enabled, configured, status, severity):
    rows = feature_rows(feature, enabled)
    if configured:
        if feature == "appfw":
            rows["config/aaaparameter"] = {"wafprotection": ["DEFAULT"]}
        elif feature == "rep":
            rows["config/responderpolicy"] = [{"rule": "CLIENT.IP.SRC.IPREP_IS_MALICIOUS"}]
        else:
            rows["config/botpolicy"] = [{"name": "synthetic"}]
            rows["config/botglobal_botpolicy_binding"] = [{"policyname": "synthetic"}]
    if feature == "appfw" and not configured:
        severity = "Midden"
    result = feature_result(make_export(tmp_path, rows), feature)
    assert (result.status, result.severity, result.applicability) == (status, severity, "van toepassing")


@pytest.mark.parametrize("feature", ["appfw", "bot", "rep"])
@pytest.mark.parametrize("source", ["config/nslicense", "config/nsfeature"])
@pytest.mark.parametrize("value", [None, "", "UNKNOWN", [], {}, [True], 2])
def test_unknown_switch_shape_never_becomes_false_or_na(tmp_path, feature, source, value):
    rows = feature_rows(feature)
    rows[source][feature] = value
    result = feature_result(make_export(tmp_path, rows), feature)
    assert (result.status, result.severity, result.applicability) == ("NIET BEOORDEELD", "Midden", "onbekend")
    assert result.read_gaps and result.read_gaps[0].source == source
    assert "UNKNOWN" not in result.reason


@pytest.mark.parametrize("feature", ["appfw", "bot", "rep"])
def test_explicit_false_license_is_the_only_unlicensed_branch(tmp_path, feature):
    rows = feature_rows(feature, licensed=False)
    result = feature_result(make_export(tmp_path, rows), feature)
    assert (result.status, result.severity, result.applicability) == ("NIET BEOORDEELD", "Info", "niet van toepassing")
    del rows["config/nslicense"][feature]
    result = feature_result(make_export(tmp_path, rows), feature)
    assert result.applicability == "onbekend"
    assert "sleutel ontbreekt" in result.read_gaps[0].reason


@pytest.mark.parametrize(
    "tokens,expected",
    [
        (["DEFAULT"], "PASS"),
        (["AUTH"], "PASS"),
        (["VPN"], "PASS"),
        (["AUTH", "VPN"], "PASS"),
        (["PORTAL"], "FAIL"),
        (["DISABLED"], "FAIL"),
        ([], "NIET BEOORDEELD"),
        (["AUTH", "DISABLED"], "NIET BEOORDEELD"),
        (["UNKNOWN"], "NIET BEOORDEELD"),
        ([["AUTH"]], "NIET BEOORDEELD"),
        ([1], "NIET BEOORDEELD"),
        (None, "NIET BEOORDEELD"),
    ],
)
def test_waf_documented_string_array_tokens(tmp_path, tokens, expected):
    rows = feature_rows("appfw", True)
    rows["config/aaaparameter"] = {"wafprotection": tokens}
    result = feature_result(make_export(tmp_path, rows), "appfw")
    assert result.status == expected
    if expected == "NIET BEOORDEELD":
        assert result.read_gaps and "wafprotection" in result.read_gaps[0].reason


def test_appfw_scope_and_direct_binding_branches(tmp_path):
    rows = feature_rows("appfw", True)
    rows["config/vpnvserver"] = []
    result = feature_result(make_export(tmp_path, rows), "appfw")
    assert (result.status, result.severity, result.applicability) == ("NIET BEOORDEELD", "Info", "niet van toepassing")
    export = make_export(tmp_path, rows, statuses={"config/authenticationvserver": "RBAC_DENIED"})
    assert feature_result(export, "appfw").severity == "Midden"
    rows["config/vpnvserver"] = [{"name": "synthetic"}]
    rows["config/vpnvserver_appfwpolicy_binding?bulkbindings=yes"] = [{"policyname": "synthetic"}]
    rows["config/aaaparameter"] = {}
    assert feature_result(make_export(tmp_path, rows), "appfw").status == "PASS"


@pytest.mark.parametrize(
    "days,status,severity",
    [
        (-1, "FAIL", "Hoog"),
        (0, "FAIL", "Hoog"),
        (1, "FAIL", "Midden"),
        (30, "FAIL", "Midden"),
        (31, "PASS", "Info"),
        (None, "NIET BEOORDEELD", "Hoog"),
        ([], "NIET BEOORDEELD", "Hoog"),
        (True, "NIET BEOORDEELD", "Hoog"),
    ],
)
def test_license_expiry_branch_severities(tmp_path, days, status, severity):
    control = next(c for c in CONTROLS if c.id == "ANNA-LIC-001")
    # On the export's own day (age 0): the ladder itself. The age correction
    # since 1.0.3 is pinned in test_expiry_age_consumers.py.
    result = scorecard._license(
        control, make_export(tmp_path, {"config/nslicense": {"daystoexpiration": days}}), date(2026, 8, 26)
    )
    assert (result.status, result.severity) == (status, severity)


NOW = datetime(2026, 8, 26, 10, tzinfo=UTC)
SCAN_RESOURCE = "config/systemfile?args=filename:iprep.log,filelocation:%2Fvar%2Flog"


def scan_export(tmp_path, projection, *, status="OK", stamp="2026-08-26T10:00:00Z", hash_ok=True):
    export = make_export(tmp_path, {"config/nsfeature": {"rep": True}})
    root = export.directory
    (root / "parsed").mkdir(exist_ok=True)
    content = json.dumps(projection).encode()
    (root / "parsed" / "iprep-scan.json").write_bytes(content)
    path = root / "export-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["collectedAtUtc"] = stamp
    manifest["resources"][SCAN_RESOURCE] = {
        "status": status,
        "payloadSha256": hashlib.sha256(content).hexdigest() if hash_ok else "0" * 64,
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return load_export(root)


def scan_result(export, now=NOW):
    return scorecard._scan(CONTROLS[-1], export, now=now)


@pytest.mark.parametrize(
    "status,age,errors,expected,severity",
    [
        ("OK", 1, 0, "PASS", "Info"),
        ("OK", 1440, 0, "PASS", "Info"),
        ("OK", 1441, 0, "FAIL", "Midden"),
        ("OK", 1, 1, "FAIL", "Hoog"),
        ("NOT_SUPPORTED", 1, 0, "NIET BEOORDEELD", "Info"),
        ("RBAC_DENIED", 1, 0, "NIET BEOORDEELD", "Midden"),
        ("EMPTY", 1, 0, "NIET BEOORDEELD", "Midden"),
    ],
)
def test_scan_source_and_verdict_branches(tmp_path, status, age, errors, expected, severity):
    export = scan_export(
        tmp_path, {"lastUpdateAgeMinutes": age, "errorLineCount": errors, "errorCategories": []}, status=status
    )
    result = scan_result(export)
    assert (result.status, result.severity) == (expected, severity)


@pytest.mark.parametrize("field", ["lastUpdateAgeMinutes", "errorLineCount", "errorCategories"])
@pytest.mark.parametrize("value", [None, "", {}, [None], True, "INJECT_SECRET"])
def test_scan_malformed_decisive_fields_are_canonical_gaps(tmp_path, field, value):
    projection = {"lastUpdateAgeMinutes": 1, "errorLineCount": 0, "errorCategories": []}
    projection[field] = value
    result = scan_result(scan_export(tmp_path, projection))
    assert result.status == "NIET BEOORDEELD"
    assert any(g.source == "parsed/iprep-scan.json" and field in g.reason for g in result.read_gaps)
    assert "INJECT_SECRET" not in str(result)


def test_scan_age_includes_elapsed_export_time_and_needs_stamp_and_hash(tmp_path):
    projection = {"lastUpdateAgeMinutes": 1, "errorLineCount": 0, "errorCategories": []}
    export = scan_export(tmp_path, projection)
    assert scan_result(export, datetime(2026, 8, 28, 10, tzinfo=UTC)).status == "FAIL"
    assert scan_result(scan_export(tmp_path, projection, stamp=None)).status == "NIET BEOORDEELD"
    assert scan_result(scan_export(tmp_path, projection, hash_ok=False)).status == "NIET BEOORDEELD"


def test_disabled_or_unknown_rep_never_opens_projection(tmp_path, monkeypatch):
    from nsmcp.export import Export

    def forbidden(self):
        pytest.fail("scan read without confirmed feature")

    monkeypatch.setattr(Export, "iprep_scan_projection", forbidden)
    for value in (False, None, [], "UNKNOWN"):
        export = make_export(tmp_path, {"config/nsfeature": {"rep": value}})
        assert len(scorecard_results(export, KNOWLEDGE)) == 23


@pytest.mark.parametrize(
    "letter,gap,status,severity",
    [
        ("B", False, "PASS", "Info"),
        ("A", False, "PASS", "Info"),
        ("C", False, "FAIL", "Midden"),
        ("F", False, "FAIL", "Hoog"),
        ("T", False, "FAIL", "Hoog"),
        ("C", True, "NIET BEOORDEELD", "Midden"),
    ],
)
def test_grade_projection_uses_establishment_and_source_baseline(tmp_path, monkeypatch, letter, gap, status, severity):
    from nsmcp.answer import ReadGap
    from nsmcp.tls_baseline import Grade

    g = Grade(
        "synthetic",
        letter,
        70,
        "config/sslvserver",
        read_gap=ReadGap(source="config/sslcertkey", reason="test bron-gat") if gap else None,
    )
    monkeypatch.setattr(scorecard, "grade_per_vserver", lambda e, **_: (g,))
    export = make_export(tmp_path, {"config/sslvserver": []})
    r = next(r for r in scorecard_results(export, KNOWLEDGE) if r.control.id == "GJK-L1-013")
    assert (r.status, r.severity) == (status, severity)


def test_mixed_safe_and_unknown_grades_never_aggregate_to_pass(tmp_path, monkeypatch):
    from nsmcp.answer import ReadGap
    from nsmcp.tls_baseline import Grade

    safe = Grade("synthetic", "A", 90, "config/sslvserver")
    unknown = replace(
        safe, letter="NIET BEOORDEELD", score=None, read_gap=ReadGap(source="config/sslcertkey", reason="test bron-gat")
    )
    monkeypatch.setattr(scorecard, "grade_per_vserver", lambda e, **_: (safe, unknown))
    r = next(
        r
        for r in scorecard_results(make_export(tmp_path, {"config/sslvserver": []}), KNOWLEDGE)
        if r.control.id == "GJK-L1-013"
    )
    assert (r.status, r.severity) == ("NIET BEOORDEELD", "Midden")


@pytest.mark.parametrize(
    "count,status,severity",
    [(0, "FAIL", "Hoog"), (1, "FAIL", "Midden"), (3, "FAIL", "Midden"), (4, "PASS", "Laag"), (6, "PASS", "Laag")],
)
def test_header_projection_source_threshold(tmp_path, monkeypatch, count, status, severity):
    from nsmcp.headers import HEADERS, HeaderResult

    headers = tuple(
        HeaderResult(name, "aanwezig en gebonden" if i < count else "afwezig", evidence="test")
        for i, name in enumerate(HEADERS)
    )
    monkeypatch.setattr(scorecard, "header_coverage", lambda e: headers)
    result = next(
        r
        for r in scorecard_results(make_export(tmp_path, {}), KNOWLEDGE)
        if r.control.id == "ANNA-SEC-HTTP-HEADERS-001"
    )
    assert (result.status, result.severity) == (status, severity)


@pytest.mark.parametrize(
    "verdicts,expected,severity",
    [
        ((("GERAAKT", 9.8),), "FAIL", "Hoog"),
        ((("GERAAKT", 6.5),), "FAIL", "Midden"),
        ((("NIET GERAAKT", 9.8),), "PASS", "Info"),
        ((("NIET VASTGESTELD", 9.8),), "NIET BEOORDEELD", "Midden"),
        ((("NIET GERAAKT", 9.8), ("NIET VASTGESTELD", 9.8)), "NIET BEOORDEELD", "Midden"),
    ],
)
def test_cve_uses_structured_verdict_and_hit_severity(tmp_path, monkeypatch, verdicts, expected, severity):
    from nsmcp.cve import CveVerdict

    monkeypatch.setattr(scorecard, "cve_verdicts", lambda e, k: (tuple(CveVerdict(v, n) for v, n in verdicts), ()))
    result = next(r for r in scorecard_results(make_export(tmp_path, {}), KNOWLEDGE) if r.control.id == "GJK-L1-014")
    assert (result.status, result.severity) == (expected, severity)


@pytest.mark.parametrize("dimension_index,severity", [(0, "Hoog"), (1, "Midden"), (2, "Hoog"), (3, "Midden")])
@pytest.mark.parametrize(
    "state,status",
    [("safe", "PASS"), ("unsafe", "FAIL"), ("onbevestigd", "NIET BEOORDEELD"), ("safe_with_gap", "NIET BEOORDEELD")],
)
def test_ha_every_dimension_status_polarity_and_severity(
    tmp_path, monkeypatch, dimension_index, severity, state, status
):
    from nsmcp.answer import ReadGap
    from nsmcp.ha import ha_result

    export = load_export(FIXTURE)
    base, _ = ha_result(export)
    d = base.dimensions[dimension_index]
    word = (
        d.safe_state
        if state in ("safe", "safe_with_gap")
        else ("uit" if d.safe_state == "aan" else "aan")
        if state == "unsafe"
        else "onbevestigd"
    )
    gap = ReadGap(source="config/hanode", reason="veld ontbreekt") if state == "safe_with_gap" else None
    new = replace(d, state=word, reason="veld ontbreekt" if state == "onbevestigd" else "", read_gap=gap)
    ha = replace(base, **{("roles", "sync", "forced", "drift")[dimension_index]: new})
    monkeypatch.setattr(scorecard, "ha_result", lambda e: (ha, ()))
    result = next(
        r for r in scorecard_results(export, KNOWLEDGE) if r.control.id == f"GJK-L1-HA-{dimension_index + 1:03}"
    )
    assert (result.status, result.severity) == (status, severity)
    if status == "NIET BEOORDEELD":
        assert result.read_gaps


@pytest.mark.parametrize(
    "cid,resources,severity",
    [
        (
            "GJK-L1-005",
            ("config/ntpserver", "config/dnsnameserver", "config/snmpcommunity", "config/snmpmanager"),
            "Midden",
        ),
        ("GJK-L1-006", ("config/auditsyslogpolicy", "config/auditsyslogaction"), "Hoog"),
    ],
)
@pytest.mark.parametrize("scenario,status", [("present", "PASS"), ("absent", "FAIL"), ("unread", "NIET BEOORDEELD")])
def test_basic_control_branches(tmp_path, cid, resources, severity, scenario, status):
    rows = {r: [] for r in resources}
    if scenario != "absent":
        rows[resources[0]] = [{"name": "synthetic"}]
        rows[resources[1]] = [{"name": "synthetic"}]
    export = make_export(tmp_path, rows, statuses={resources[0]: "RBAC_DENIED"} if scenario == "unread" else None)
    result = scorecard._basic(next(c for c in CONTROLS if c.id == cid), export)
    assert (result.status, result.severity) == (status, severity)


def test_all_vocabulary_denominator_and_fixed_section_are_exact():
    assert scorecard.STATUS_WORDS == ("PASS", "FAIL", "NIET BEOORDEELD")
    assert scorecard.SEVERITY_WORDS == ("Kritiek", "Hoog", "Midden", "Laag", "Info")
    assert scorecard.CONFIDENCE_WORDS == ("hoog", "gemiddeld", "laag", "niet vastgesteld")
    assert scorecard.APPLICABILITY_WORDS == ("van toepassing", "niet van toepassing", "invoer nodig", "onbekend")
    export = load_export(FIXTURE)
    results = scorecard_results(export, KNOWLEDGE)
    expected = sum(r.in_denominator and r.status in ("PASS", "FAIL") for r in results)
    answer = scorecard.scorecard_answer(export, KNOWLEDGE)
    assert answer.findings[0].outcome == f"{expected} van 18 beoordeeld, 5 controls buiten het bereik van deze meting"
    assert len(answer.not_assessed) == 7
    assert {r.control.id for r in results if not r.in_denominator} == {
        "GJK-L1-004",
        "GJK-L1-007",
        "GJK-L1-009",
        "GJK-L1-011",
        "GJK-L1-012",
    }
    from nsmcp.advice import ADVICE_CAN

    assert ADVICE_CAN not in answer.to_text()
    assert "nshc-iprep-baseline" in answer.to_text() and "2026.07.1" in answer.to_text()


def test_confirmed_scan_context_is_nineteen(tmp_path):
    export = scan_export(tmp_path, {"lastUpdateAgeMinutes": 1, "errorLineCount": 0, "errorCategories": []})
    results = scorecard_results(export, KNOWLEDGE, now=NOW)
    assert len(results) == 24 and sum(r.in_denominator for r in results) == 19


@pytest.mark.parametrize("cid", ["GJK-L1-002", "GJK-L1-003"])
@pytest.mark.parametrize("verdict", ["PASS", "FAIL", "NIET BEOORDEELD"])
def test_management_projection_each_branch_is_high(tmp_path, cid, verdict):
    from nsmcp.mgmt_plane import DimensionResult

    dimensions = {
        name: DimensionResult(
            name, verdict, "config/nsip", unread=("config/nsip",) if verdict == "NIET BEOORDEELD" else ()
        )
        for name in ("transport", "certificaat", "RBAC")
    }
    result = scorecard._management(next(c for c in CONTROLS if c.id == cid), make_export(tmp_path, {}), dimensions)
    assert (result.status, result.severity) == (verdict, "Hoog")
    if verdict == "NIET BEOORDEELD":
        assert result.read_gaps[0].source == "config/nsip"


@pytest.mark.parametrize("resource", ["config/sslvserver", "config/sslprofile", "config/sslcertkey"])
def test_baseline_resource_failures_are_original_gaps(tmp_path, resource):
    from nsmcp.tls_baseline import baseline_result

    result = baseline_result(make_export(tmp_path, baseline_rows(), statuses={resource: "RBAC_DENIED"}))
    assert result.status == "NIET BEOORDEELD"
    assert any(g.source == resource and "RBAC_DENIED" in g.reason for g in result.read_gaps)


@pytest.mark.parametrize(
    "resource,key",
    [
        ("config/sslprofile", "ssl2"),
        ("config/sslprofile", "ssl3"),
        ("config/sslprofile", "tls1"),
        ("config/sslcertkey", "daystoexpiration"),
        ("config/sslcertkey", "publickeysize"),
        ("config/sslcertkey", "signaturealg"),
    ],
)
@pytest.mark.parametrize("value", [None, "", [], {}, True, "UNKNOWN_PRIVATE"])
def test_baseline_malformed_fields_never_pass_or_echo(tmp_path, resource, key, value):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    rows[resource][0][key] = value
    result = baseline_result(make_export(tmp_path, rows))
    assert result.status == "NIET BEOORDEELD"
    assert result.read_gaps and "UNKNOWN_PRIVATE" not in str(result)


def test_baseline_safe_empty_profiles_unbound_vserver_and_all_certificates(tmp_path):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    assert baseline_result(make_export(tmp_path, rows)).status == "PASS"
    rows["config/sslvserver"] = [
        {"vservername": "synthetic", "sslprofile": "", "ssl2": "DISABLED", "ssl3": "DISABLED", "tls1": "DISABLED"}
    ]
    rows["config/sslprofile"] = []
    assert baseline_result(make_export(tmp_path, rows)).status == "PASS"
    rows["config/sslcertkey"].append(
        {"certkey": "unbound", "daystoexpiration": 2, "publickeysize": 2048, "signaturealg": "sha256WithRSAEncryption"}
    )
    assert baseline_result(make_export(tmp_path, rows)).status == "FAIL"


def test_scan_rule_confidence_and_feature_recheck_prevent_reads(tmp_path, monkeypatch):
    from nsmcp.export import Export

    export = make_export(tmp_path, {"config/nsfeature": {"rep": None}})
    monkeypatch.setattr(Export, "iprep_scan_projection", lambda self: pytest.fail("unconfirmed read"))
    result = scan_result(export)
    assert (result.status, result.severity) == ("NIET BEOORDEELD", "Midden")
    assert result.read_gaps[0].source == "config/nsfeature"
    export = make_export(tmp_path, {"config/nsfeature": {"rep": True}})
    monkeypatch.setitem(scorecard.IPREP_BASELINE.rules, "patternsConfirmed", False)
    assert scan_result(export).read_gaps[0].source == "nshc-iprep-baseline"


def test_cve_helper_returns_evaluator_verdicts_not_rendered_text(monkeypatch):
    from test_cve import ECHTE_BULLETINS

    from nsmcp.answer import Answer
    from nsmcp.cve import cve_verdicts

    monkeypatch.setattr(Answer, "to_text", lambda self: pytest.fail("rendered text was parsed"))
    records, _ = cve_verdicts(load_export(FIXTURE), replace(KNOWLEDGE, cve=tuple(ECHTE_BULLETINS)))
    assert len(records) == sum(len(b["cves"]) for b in ECHTE_BULLETINS)
    assert all(r.verdict in ("GERAAKT", "NIET GERAAKT", "NIET VASTGESTELD") for r in records)


@pytest.mark.parametrize(
    "feature,source", [("rep", "config/responderpolicy"), ("bot", "config/botpolicy"), ("appfw", "config/aaaparameter")]
)
def test_feature_missing_config_evidence_is_medium_unknown(tmp_path, feature, source):
    result = feature_result(
        make_export(tmp_path, feature_rows(feature, True), statuses={source: "RBAC_DENIED"}), feature
    )
    assert (result.status, result.severity) == ("NIET BEOORDEELD", "Midden")
    assert any(g.source == source and "RBAC_DENIED" in g.reason for g in result.read_gaps)


@pytest.mark.parametrize(
    "algorithm",
    [
        "UNKNOWN_PRIVATE_ecdsa",
        "UNKNOWN_PRIVATE_sha256WithRSAEncryption",
        "UNKNOWN_PRIVATE_sha1",
        "unknown-ecdsa",
        "unknown-sha1",
    ],
)
def test_review_signature_substrings_are_never_algorithm_evidence(tmp_path, algorithm):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    rows["config/sslcertkey"][0]["signaturealg"] = algorithm
    result = baseline_result(make_export(tmp_path, rows))
    assert result.status == "NIET BEOORDEELD"
    assert any(g.source == "config/sslcertkey" and "signaturealg" in g.reason for g in result.read_gaps)
    assert algorithm not in str(result)


@pytest.mark.parametrize(
    "errors,status,severity",
    [(1, "FAIL", "Hoog"), (0, "NIET BEOORDEELD", "Midden"), (None, "NIET BEOORDEELD", "Midden")],
)
def test_review_database_errors_precede_unknown_freshness(tmp_path, errors, status, severity):
    result = scan_result(
        scan_export(tmp_path, {"errorLineCount": errors, "errorCategories": ["dns"], "lastUpdateAgeMinutes": None})
    )
    assert (result.status, result.severity) == (status, severity)
    assert any(g.source == "parsed/iprep-scan.json" and "lastUpdateAgeMinutes" in g.reason for g in result.read_gaps)


@pytest.mark.parametrize(
    "transport,certificate,status",
    [
        ("FAIL", "NIET BEOORDEELD", "FAIL"),
        ("NIET BEOORDEELD", "FAIL", "FAIL"),
        ("PASS", "NIET BEOORDEELD", "NIET BEOORDEELD"),
        ("NIET BEOORDEELD", "PASS", "NIET BEOORDEELD"),
    ],
)
def test_review_management_independent_fail_wins_over_other_gap(tmp_path, transport, certificate, status):
    from nsmcp.mgmt_plane import DimensionResult

    dimensions = {
        name: DimensionResult(
            name, verdict, "config/nsip", unread=("config/nsip",) if verdict == "NIET BEOORDEELD" else ()
        )
        for name, verdict in (("transport", transport), ("certificaat", certificate))
    }
    export = make_export(tmp_path, {"config/nsip": []}, statuses={"config/nsip": "RBAC_DENIED"})
    result = scorecard._management(next(c for c in CONTROLS if c.id == "GJK-L1-002"), export, dimensions)
    assert (result.status, result.severity) == (status, "Hoog")
    assert any(g.source == "config/nsip" and g.reason == "read niet bruikbaar: RBAC_DENIED" for g in result.read_gaps)


@pytest.mark.parametrize(
    "algorithm,size,status",
    [
        ("sha256WithRSAEncryption", 2048, "PASS"),
        ("ecdsa-with-SHA256", 256, "PASS"),
        ("sha1WithRSAEncryption", 2048, "FAIL"),
        ("md5WithRSAEncryption", 2048, "FAIL"),
    ],
)
def test_review_understood_algorithm_names_keep_semantics(tmp_path, algorithm, size, status):
    from nsmcp.tls_baseline import baseline_result

    rows = baseline_rows()
    rows["config/sslcertkey"][0].update(signaturealg=algorithm, publickeysize=size)
    result = baseline_result(make_export(tmp_path, rows))
    assert result.status == status
    assert not result.read_gaps
