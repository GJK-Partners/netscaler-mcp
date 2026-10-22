"""1.0.3 P-3: every consumer of `daystoexpiration` counts from TODAY.

`daystoexpiration` is the appliance's count AT THE SCAN. Since 1.0.2 the
certificate list and the preflight take the age of the export off
(`expiry.age_of` / `remaining_days` / `bucket_from_today`); the TLS grade,
the TLS baseline criterion and the licence line of the scorecard still read
the raw field.

MEASURED before (1.0.2), the negative invariant of the review: a hash-valid
copy of the lab export (collected 26-8), judged on 22-10, all four
certificates at 45 days at the scan. The certificate list said four expired
certificates; the TLS criterion said `PASS` with zero deviations, and two
grades stayed C without the expired-certificate mark. A false green.

The same certificates are run here through the list, the TLS grade, the
TLS criterion and the scorecard, fresh and old, on the boundary, negative,
and with an unreadable and a future export date (no positive expiry verdict
then).
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.expiry import what_expires
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.scorecard import scorecard_results
from nsmcp.tls_baseline import KENMERKEN, NOT_ASSESSED_WORD, baseline_result, grade_per_vserver, tls_baseline

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
K = Knowledge(version="2026.10", date="2026-10-21", age_days=1, missing=False)
TODAY = date(2026, 10, 22)  # 57 days after the export of 2026-08-26
EXPIRED_MARK = KENMERKEN["expired-cert"]


def _export(tmp_path: Path, days, *, collected_at: str | None = "keep"):
    copied = tmp_path / "export"
    shutil.copytree(FIXTURE, copied)
    certfile = copied / "objects" / "sslcertkey.json"
    document = json.loads(certfile.read_text(encoding="utf-8"))
    for row in document["sslcertkey"]:
        row["daystoexpiration"] = days
    certfile.write_text(json.dumps(document), encoding="utf-8")
    if collected_at != "keep":
        manifest_path = copied / "export-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if collected_at is None:
            manifest.pop("collectedAtUtc", None)
        else:
            manifest["collectedAtUtc"] = collected_at
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    seal_manifest(copied)
    return load_export(copied)


def _criterion(export, today):
    return next(c for c in baseline_result(export, today=today).criteria if c.criterion == "daystoexpiration")


def _scorecard(export, today):
    now = datetime(today.year, today.month, today.day, 12, 0, tzinfo=UTC)
    return {r.control.id: r for r in scorecard_results(export, K, now=now)}


def _graded(export, today):
    return [g for g in grade_per_vserver(export, today=today) if g.letter != NOT_ASSESSED_WORD]


def test_the_negative_invariant_old_export_all_three_say_expired(tmp_path):
    export = _export(tmp_path, 45)
    expired = [f for f in what_expires(export, K, 90, today=TODAY).findings if f.expired]
    assert len(expired) == 4, "premisse: de lijst noemt vier verlopen certificaten"

    criterion = _criterion(export, TODAY)
    assert criterion.status == "FAIL", criterion

    graded = _graded(export, TODAY)
    assert graded, "premisse: er zijn beoordeelde TLS-vservers"
    for grade in graded:
        assert EXPIRED_MARK in grade.kenmerken, grade

    text = tls_baseline(export, K, today=TODAY).to_text()
    assert EXPIRED_MARK in text

    card = _scorecard(export, TODAY)
    assert card["GJK-L1-010"].status == "FAIL", card["GJK-L1-010"]
    # The grading control stays NIET BEOORDEELD on this export: its grades
    # carry the unexpanded-cipher-group read gap, which the control does not
    # count as an established letter. It may never read PASS.
    assert card["GJK-L1-013"].status != "PASS", card["GJK-L1-013"]


def test_a_fresh_export_with_the_same_count_is_not_expired(tmp_path):
    """Control: the SAME 45 days on an export of today are not expired - the
    test above fails on the age, not on the count."""
    export = _export(tmp_path, 45, collected_at="2026-10-22T08:00:00Z")
    assert not [f for f in what_expires(export, K, 90, today=TODAY).findings if f.expired]
    for grade in _graded(export, TODAY):
        assert EXPIRED_MARK not in grade.kenmerken, grade
    # 45 days is a "notice", not a deviation of the criterion.
    assert _criterion(export, TODAY).status == "PASS"


@pytest.mark.parametrize(
    ("raw", "expired_grade", "criterion_status"),
    [
        (56, True, "FAIL"),  # -1 day today: expired
        (57, False, "FAIL"),  # 0 days left today: expires today, not yet expired (R3-3)
        (58, False, "FAIL"),  # 1 day left: critical, still a deviation
        (200, False, "PASS"),  # 143 days left
        (-3, True, "FAIL"),  # already negative at the scan
    ],
)
def test_boundary_and_negative_counts_are_corrected_for_age(tmp_path, raw, expired_grade, criterion_status):
    export = _export(tmp_path, raw)
    graded = _graded(export, TODAY)
    assert graded
    for grade in graded:
        assert (EXPIRED_MARK in grade.kenmerken) is expired_grade, (raw, grade)
    assert _criterion(export, TODAY).status == criterion_status


@pytest.mark.parametrize("stamp", [None, "", "onleesbaar", "2099-01-01T00:00:00Z"])
def test_an_unreadable_or_future_date_gives_no_positive_expiry_verdict(tmp_path, stamp):
    export = _export(tmp_path, 400, collected_at=stamp)
    criterion = _criterion(export, TODAY)
    assert criterion.status != "PASS", criterion
    assert any("leeftijd" in gap.reason for gap in criterion.read_gaps), criterion
    # No grade may stand as assessed on an expiry it could not count.
    for grade in grade_per_vserver(export, today=TODAY):
        if grade.letter != NOT_ASSESSED_WORD:
            pytest.fail(f"grade zonder leesbare exportdatum: {grade}")
    card = _scorecard(export, TODAY)
    assert card["GJK-L1-010"].status != "PASS"
    assert card["GJK-L1-013"].status != "PASS"


def test_the_licence_line_counts_from_today(tmp_path):
    """The licence carries a `daystoexpiration` from the scan too."""

    def licence(days, stamp="keep"):
        export = _export(tmp_path / f"{days}-{bool(stamp)}", 400, collected_at=stamp)
        root = tmp_path / f"{days}-{bool(stamp)}" / "export"
        path = root / "objects" / "nslicense.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["nslicense"]["daystoexpiration"] = days
        path.write_text(json.dumps(document), encoding="utf-8")
        seal_manifest(root)
        del export
        card = _scorecard(load_export(root), TODAY)
        return next(r for r in card.values() if "config/nslicense" in r.evidence or "nslicense" in r.reason)

    # 40 at the scan, 57 days ago: expired today.
    old = licence(40)
    assert old.status == "FAIL" and old.severity == "Hoog", old
    assert "-17 dagen" in old.evidence, old
    # 200 at the scan: 143 days left today, no finding.
    assert licence(200).status == "PASS"
    # No readable export date: no positive licence verdict.
    unknown = licence(200, None)
    assert unknown.status != "PASS", unknown


@pytest.mark.parametrize(("raw", "expired"), [(56, True), (57, False), (58, False)])
def test_on_the_boundary_day_list_grade_and_licence_agree(tmp_path, raw, expired):
    """R3-3: ONE definition for every consumer (`expiry.is_expired`): 0 days
    left today is "verloopt vandaag", not yet expired; a negative count is
    expired. MEASURED before: on scan value 57 the list said "verloopt over 0
    dagen" (not expired) while both grades carried "verlopen certificaat" and
    the licence line said "verlopen (0 dagen)"."""
    export = _export(tmp_path / "certs", raw)
    findings = what_expires(export, K, 90, today=TODAY).findings
    dated = [f for f in findings if f.days_left is not None]
    assert len(dated) == 4, findings
    for finding in dated:
        assert finding.expired is expired, finding
        if raw == 57:
            assert finding.outcome.startswith("verloopt vandaag"), finding
            assert "over 0 dagen" not in finding.outcome, finding
    graded = _graded(export, TODAY)
    assert graded
    for grade in graded:
        assert (EXPIRED_MARK in grade.kenmerken) is expired, (raw, grade)

    root = tmp_path / "licence" / "export"
    _export(tmp_path / "licence", 400)
    path = root / "objects" / "nslicense.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["nslicense"]["daystoexpiration"] = raw
    path.write_text(json.dumps(document), encoding="utf-8")
    seal_manifest(root)
    card = _scorecard(load_export(root), TODAY)
    line = next(r for r in card.values() if "config/nslicense" in r.evidence)
    assert line.status == "FAIL", line
    assert ("verlopen" in line.evidence) is expired, line
    if raw == 57:
        assert "verloopt vandaag" in line.evidence, line


def test_the_tls_module_names_its_boundary_day_deviation_from_nshc():
    """R3H-3: since R3-3 the grade no longer caps to `T` on 0 days left, where
    NSHC does. CHANGELOG and HANDLEIDING say so; the module that claims to
    mirror NSHC must say so too, so a later parity measurement does not read
    it as an unexplained difference."""
    import nsmcp.tls_baseline as module

    doc = " ".join((module.__doc__ or "").split())
    assert "except on the boundary day" in doc, doc[:600]
    assert "verloopt vandaag" in doc and "expiry.is_expired" in doc, doc[:600]
