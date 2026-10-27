"""B7 - `onderhoud_upgrade_plan`: the seven phases, read-only.

The fixtures `lab_export` / `knowledge` do not live in `tests/conftest.py` on
this branch (that file only fixes pytest's temporary base directory), so they
are defined here - on the same REAL collector export the rest of the suite
uses: `tests/fixtures/lab-export-vpx-20260826/` (NS14.1, build 72.57).

`nsmcp.ha.ha_result` is available on this branch; the guarded-import
route around it (a defensive fallback, not a real gap today) is exercised
by deliberately faking its absence - measured, not assumed
(`test_the_ha_gap_is_named_and_not_silently_green` below).
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from conftest import table_rows

import nsmcp.upgrade_plan as upgrade_plan_module
from nsmcp.answer import Certainty, ReadGap
from nsmcp.export import load_export
from nsmcp.knowledge import Knowledge
from nsmcp.preflight import CERT_MARGIN_DAYS, NO_BLOCKER, Check
from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS, PHASE_NAMES, PHASE_TITLES, upgrade_plan

FIXTURES = Path(__file__).parent / "fixtures"
LIVE_EXPORT = FIXTURES / "lab-export-vpx-20260826"


@pytest.fixture
def lab_export():
    """The REAL collector export. Its build is 14.1-72.57."""
    return load_export(LIVE_EXPORT)


@pytest.fixture
def knowledge() -> Knowledge:
    """A package that offers 14.1-72.61 and names a floor of the same build -
    close enough above the fixture's 72.57 that check 6 has something real to
    weigh, without this file needing to know every number `preflight.py`
    computes from it."""
    return Knowledge(
        version="test-2026.09",
        date="2026-09-01",
        age_days=4,
        missing=False,
        cve=(
            {
                "bulletin": "CTX696604",
                "datum": "2026-06-30",
                "getroffen": {"14.1": "< 72.61"},
                "fix": {"14.1": "72.61"},
                "cves": [],
                "advies": "upgrade",
                "extraStapNaUpgrade": "",
            },
        ),
        offered_builds={"14.1": "72.61"},
        offered_date="2026-09-01",
        offered_source="release notes",
    )


def test_there_are_seven_phases_named_r0_to_r6():
    assert PHASE_NAMES == ("R0", "R1", "R2", "R3", "R4", "R5", "R6")
    assert set(PHASE_TITLES) == set(PHASE_NAMES)


def test_the_plan_names_the_secondary_first_sequence(lab_export, knowledge):
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "secondary eerst" in tekst
    assert "de tweede node is een menselijke handeling" in tekst


def test_the_plan_names_config_opslaan_as_the_step_after_the_final_validation(lab_export, knowledge):
    """Saving on the primary after the final validation now has a tool of its
    own; the failover, the second node and restoring haStatus stay human."""
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "config_opslaan op de primary na de eindvalidatie" in tekst
    assert "save ns config na de eindvalidatie" not in tekst


def test_the_plan_names_the_soak_window_in_hours(lab_export, knowledge):
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=36).to_text()
    assert "36 uur" in tekst


def test_a_soak_below_the_minimum_is_named_as_such(lab_export, knowledge):
    assert MINIMUM_SOAK_HOURS == 24
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=8).to_text()
    assert "minimaal 24 uur" in tekst


def test_the_plan_never_offers_the_old_build_as_a_recovery_path(lab_export, knowledge):
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text().lower()
    assert "een terugrol van de firmware herstelt de build, niet de configuratie" in tekst
    assert "terug naar de oude build" not in tekst


def test_the_plan_names_the_vendor_downgrade_prerequisite_script(lab_export, knowledge):
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "NetScaler Firmware Downgrade Pre-requisite Script" in tekst


# A LITERAL pin, independent of `PHASE_GATES` itself (the
# original version of this test derived its expectation FROM that same
# dict, so gutting `PHASE_GATES` to empty tuples could never be caught by
# it - the rendered text and the test's own expectation would shrink
# together). Copied once from the design; a real change
# to a phase's gates must update this table too, on purpose.
# Bijgewerkt tegen wat
# scripts/Invoke-GjkUpgradeFase.ps1 ECHT produceert - zie het bijbehorende
# commentaar bij PHASE_GATES zelf (upgrade_plan.py) voor de volledige
# toelichting per verschil.
_EXPECTED_PHASE_GATES = {
    "R0": "backupobject aanwezig (bewijs); vorige buildboom aanwezig (bewijs); "
    "leeftijd van de export (bewijs); familietellingen (bewijs); "
    "configuratie-anker (bewijs); hypervisor-snapshotverwijzing ingevoerd (mens); "
    "doelbuild op of boven de vloer, of bewust geaccepteerd (bewijs of mens)",
    "R1": "R0 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); doel is secondary "
    "(bewijs); vrije ruimte op /var (bewijs); firmware-hash (bewijs); buildboom "
    "staat er nog (bewijs); drift afwezig of bewust geaccepteerd (bewijs of mens)",
    "R2": "R1 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); "
    "pre-check-ondersteuning aanwezig (bewijs); vendor-precheck (bewijs)",
    "R3": "R2 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); installatie voltooid (END_TIME) (bewijs)",
    "R4": "R3 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); SSH-auth terug na reboot (bewijs)",
    "R5": "R4 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); doel is secondary "
    "(bewijs); configuratie-anker (bewijs); doelbuild bereikt (bewijs)",
    "R6": "R5 gesloten (voorwaarde); hostsleutel gepind (voorwaarde); het soakvenster loopt (tijd)",
}


def test_every_phase_names_the_gate_that_must_open(lab_export, knowledge):
    """The previous version of this test was near-vacuous -
    "bewijs" matches the render's own evidence label, "mens" matches
    "menselijke", "tijd" matches "wandkloktijd", and "R0".."R6" match the
    phase TITLES, so gutting `PHASE_GATES` to empty tuples broke only the
    "voorwaarde" assertion. This version checks the literal rendered
    "poorten: ..." line per phase against a table copied independently from
    the design, so a gutted `PHASE_GATES` has nothing left to match against."""
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert set(_EXPECTED_PHASE_GATES) == set(PHASE_NAMES)
    for fase, verwachte_poorten in _EXPECTED_PHASE_GATES.items():
        assert f"poorten: {verwachte_poorten}" in tekst, f"{fase}: poorten niet gevonden"


def test_the_upgrade_plan_makes_no_write_call(monkeypatch, lab_export, knowledge):
    """B7 is read-only, en dat is een test en geen belofte."""
    import nsmcp.handelen as handelen

    def ontploft(*a, **k):
        raise AssertionError("onderhoud_upgrade_plan mag niets schrijven")

    monkeypatch.setattr(handelen, "perform", ontploft)
    monkeypatch.setattr(handelen, "default_runner", ontploft)
    upgrade_plan(lab_export, knowledge, soak_hours=24)


# ---------------------------------------------------------------------------
# The HA guarded import - measured, not assumed (`nsmcp.ha` is present on
# this branch; the tests below fake its absence/shape to reach specific
# branches deterministically).
# ---------------------------------------------------------------------------


def test_the_ha_gap_is_named_and_not_silently_green(lab_export, knowledge, monkeypatch):
    """Without `nsmcp.ha.ha_result` the volgorde-finding must fail closed: a
    named reason, never a silent `[vastgesteld]` on a source nobody read."""
    monkeypatch.setattr(upgrade_plan_module, "_ha_result", None)
    antwoord = upgrade_plan(lab_export, knowledge, soak_hours=24)
    volgorde = next(f for f in antwoord.findings if f.subject == "volgorde")
    assert volgorde.certainty is Certainty.NOT_ESTABLISHED
    assert "nsmcp.ha.ha_result" in volgorde.reason
    assert "secondary eerst" in volgorde.outcome


# ---------------------------------------------------------------------------
# A later fix: the previous
# code bound `result, gaps = _ha_result(export)` and then NEVER READ
# `result` again - any gapless read, including a standalone appliance with
# no HA pair (`node_count` 0 or 1), printed `[vastgesteld] secondary eerst
# ... daarna pas de andere node`: a claim about a second node that was never
# established to exist. These three tests drive the MODULE-PRESENT path
# from the TEST side by injecting a fake into the guarded-import symbol
# (`upgrade_plan_module._ha_result`) - a deterministic fake instead of a
# real export, so each `node_count` case is exercised precisely.
# ---------------------------------------------------------------------------


class _FakeHaResult:
    """The one field `_volgorde_finding` may use to decide applicability:
    `node_count`. Deliberately not the full `HaResult` shape from the real
    design - the point of this test is that B7 does not need more than this
    to fail closed correctly."""

    def __init__(self, node_count: int) -> None:
        self.node_count = node_count


def test_the_ha_ordering_fails_closed_on_a_module_present_read_gap(lab_export, knowledge, monkeypatch):
    """`nsmcp.ha` present, but `ha_result` itself reports a read gap (RBAC,
    missing resource, ...): still NOT_ESTABLISHED, with THAT gap's own
    reason - never established just because the module import succeeded."""
    gap = ReadGap(source="config/hanode", reason="RBAC_DENIED op config/hanode")
    monkeypatch.setattr(upgrade_plan_module, "_ha_result", lambda export: (_FakeHaResult(0), (gap,)))
    antwoord = upgrade_plan(lab_export, knowledge, soak_hours=24)
    volgorde = next(f for f in antwoord.findings if f.subject == "volgorde")
    assert volgorde.certainty is Certainty.NOT_ESTABLISHED
    assert volgorde.reason == gap.reason
    assert gap in antwoord.read_gaps


def test_the_ha_ordering_is_not_established_without_an_actual_pair(lab_export, knowledge, monkeypatch):
    """`nsmcp.ha` present, no gaps, but `node_count` is 1 (a standalone
    appliance - no HA pair was ever read): the ordering claim ("secondary
    eerst ... daarna pas de andere node") presupposes a second node, so this
    must stay NOT_ESTABLISHED with a NAMED reason, not silently green just
    because the read itself succeeded."""
    monkeypatch.setattr(upgrade_plan_module, "_ha_result", lambda export: (_FakeHaResult(1), ()))
    antwoord = upgrade_plan(lab_export, knowledge, soak_hours=24)
    volgorde = next(f for f in antwoord.findings if f.subject == "volgorde")
    assert volgorde.certainty is Certainty.NOT_ESTABLISHED
    assert "geen HA-paar gelezen" in volgorde.reason
    assert "secondary eerst" in volgorde.outcome


def test_the_ha_ordering_is_established_when_a_pair_is_actually_read(lab_export, knowledge, monkeypatch):
    """`nsmcp.ha` present, no gaps, `node_count` is 2 (or more): an actual
    HA pair was read, so the ordering claim may be ESTABLISHED."""
    monkeypatch.setattr(upgrade_plan_module, "_ha_result", lambda export: (_FakeHaResult(2), ()))
    antwoord = upgrade_plan(lab_export, knowledge, soak_hours=24)
    volgorde = next(f for f in antwoord.findings if f.subject == "volgorde")
    assert volgorde.certainty is Certainty.ESTABLISHED
    assert volgorde.reason == ""
    assert "2 node" in volgorde.evidence


# ---------------------------------------------------------------------------
# The pre-flight summary: every check that is NOT "geen blokkade" gets a
# finding, in B3's own words - never a second vocabulary for the same nine
# checks (ONE RULE, ONE OWNER).
# ---------------------------------------------------------------------------


def test_the_plan_names_every_preflight_check_that_is_not_geen_blokkade(lab_export, knowledge, monkeypatch):
    import nsmcp.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "_ha_result", None)
    monkeypatch.setattr(preflight_module, "_usage_per_certificate", None)
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "3. HA-stand en sync" in tekst
    assert "5. certificaathorizon over het venster heen" in tekst


def test_check_eight_names_that_b3_measures_it_live(lab_export, knowledge):
    """B7 never measures live (design: read-only). Check 8's own reason from
    `preflight.py` talks about a live read that "yielded nothing usable" -
    which would be misleading here, since B7 never attempts one. B7 replaces
    that reason with its own, naming `status_update_preflight`.

    The OLD version of this test only checked the REASON line
    for the old phrase, but `lines[acht:acht + 3]` also includes the BEWIJS
    line - and that line, unfixed, unconditionally read
    "stat/system, live gelezen; ..." regardless of the reason above it: a
    claim that a live read happened, one line above the sentence saying it
    never does. The gate below now checks the WHOLE 3-line block (subject +
    bewijs + reden) for that false claim, not just the reason."""
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "8. vrije ruimte op /var" in tekst
    assert "status_update_preflight" in tekst
    lines = tekst.splitlines()
    acht = next(i for i, line in enumerate(lines) if line.startswith("- 8. vrije ruimte op /var"))
    block = "\n".join(lines[acht : acht + 3])
    assert "leverde geen bruikbare waarde" not in block
    assert "live gelezen" not in block, "check 8's block claims a live read happened - B7 never measures live"


def test_check_8_assumed_floor_is_bound_to_preflights_own_formula():
    """MEASURED: `_CHECK_8_ASSUMED_FLOOR_MB`
    re-derived B3's `eigen_vloer` FORMULA a second time
    (`VENDOR_FLOOR_MB + 2 * ASSUMED_BUNDLE_MB`) - the NUMBERS were imported
    from `preflight.py`, the ARITHMETIC was not, so the two modules could
    state different `/var` floors the moment a real bundle size ever made
    them disagree. Proven by RELOADING `upgrade_plan` after monkeypatching
    `preflight.own_floor_mb`: a coincidentally-equal second copy would not
    move when the shared formula does; a real import-and-call does."""
    import importlib

    from nsmcp import preflight

    original = preflight.own_floor_mb
    try:
        preflight.own_floor_mb = lambda bundle_mb: 999999
        reloaded = importlib.reload(upgrade_plan_module)
        assert reloaded._CHECK_8_ASSUMED_FLOOR_MB == 999999
    finally:
        preflight.own_floor_mb = original
        importlib.reload(upgrade_plan_module)


def test_check_8_assumed_floor_matches_the_real_value_today():
    from nsmcp import preflight

    assert upgrade_plan_module._CHECK_8_ASSUMED_FLOOR_MB == preflight.own_floor_mb(preflight.ASSUMED_BUNDLE_MB) == 6204


def test_a_geen_blokkade_check_gets_no_finding(lab_export, knowledge):
    """Check 1 (licence) is `geen blokkade` on the real lab export - measured,
    not assumed (there is no "1. ..." line in the manual render this task's
    report quotes). Only checks that are NOT `geen blokkade` may add a
    finding; a check that passes silently stays silent, exactly like B3."""
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "1. licentiemodus en licentieserver" not in tekst


def test_the_certificate_horizon_widens_with_the_soak_window(lab_export, knowledge, monkeypatch):
    """The BINDING INTERFACE DECISION: check 5 of `preflight_checks` computes
    a horizon of `CERT_MARGIN_DAYS` (30) from now by default because it
    carries no window. B7 knows the planned window (the soak, in whole days,
    rounded up) and passes it in - `preflight.py` owns the addition, B7 only
    supplies the window (one rule, one owner)."""
    # Since the usage reader is on the release, check 5 passes on the lab
    # export (every certificate is far from expiry) and a passing check is
    # not listed in the plan. The HANDOFF under test is the horizon sentence,
    # so the ladder is pinned to `warning` here (its own mapping is proven
    # in tests/test_preflight.py) to make the check show its evidence.
    import nsmcp.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "bucket_from_today", lambda days, age: "warning")
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=36).to_text()
    verwacht_venster_dagen = math.ceil(36 / 24)
    verwachte_horizon = CERT_MARGIN_DAYS + verwacht_venster_dagen
    assert f"horizon {verwachte_horizon} dagen vanaf nu" in tekst
    assert "nu wel bekend" in tekst
    assert "leestool niet bekend" not in tekst


def test_a_soak_below_the_minimum_still_uses_the_clamped_window_for_the_horizon(lab_export, knowledge, monkeypatch):
    """soak_hours=0 is clamped to MINIMUM_SOAK_HOURS (24) for the plan text;
    the certificate horizon must use that SAME clamped window, not the raw
    argument - a second, uncoordinated horizon here would be exactly the
    contradiction ONE RULE, ONE OWNER exists to prevent. 0 is deliberately
    chosen over 8 (a simpler example): `math.ceil(0 / 24)` is 0 whole
    days but `math.ceil(8 / 24)` is already 1, same as the clamped 24 - a
    mutation that used the raw argument here would still pass at soak_hours=8
    by coincidence, which is exactly the gap this test closes."""
    # Since the usage reader is on the release, check 5 passes on the lab
    # export (every certificate is far from expiry) and a passing check is
    # not listed in the plan. The HANDOFF under test is the horizon sentence,
    # so the ladder is pinned to `warning` here (its own mapping is proven
    # in tests/test_preflight.py) to make the check show its evidence.
    import nsmcp.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "bucket_from_today", lambda days, age: "warning")
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=0).to_text()
    verwachte_horizon = CERT_MARGIN_DAYS + math.ceil(MINIMUM_SOAK_HOURS / 24)
    assert f"horizon {verwachte_horizon} dagen vanaf nu" in tekst


# ---------------------------------------------------------------------------
# The widened evidence NAMED a horizon (e.g. 31 dagen) that
# the classification behind it (`_certificate_word`, `bucket()`'s fixed
# 14/30/60/90 ladder) does not yet apply - that ladder still hardcodes
# `CERT_MARGIN_DAYS` (30) in its own reason. A certificate expiring on day
# 31 would get `geen blokkade` under evidence claiming a 31-day horizon was
# weighed. The sentence itself must say which horizon the judgement ACTUALLY
# uses today - not the ladder (a separate module's), only the sentence.
# ---------------------------------------------------------------------------


def test_the_certificate_horizon_sentence_names_which_margin_the_judgement_uses(lab_export, knowledge, monkeypatch):
    # Since the usage reader is on the release, check 5 passes on the lab
    # export (every certificate is far from expiry) and a passing check is
    # not listed in the plan. The HANDOFF under test is the horizon sentence,
    # so the ladder is pinned to `warning` here (its own mapping is proven
    # in tests/test_preflight.py) to make the check show its evidence.
    import nsmcp.preflight as preflight_module

    monkeypatch.setattr(preflight_module, "bucket_from_today", lambda days, age: "warning")
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=36).to_text()
    assert f"vaste marge van {CERT_MARGIN_DAYS} dagen" in tekst, (
        "de bewijsregel noemt het bredere venster, maar zegt niet dat de toets eronder nog"
        " tegen de vaste marge aanloopt"
    )


# ---------------------------------------------------------------------------
# `mcp_server._soak_hours()` is the caller that reads
# `onderhoud.soak_uren` when configured, never this module directly -
# `upgrade_plan()` itself only ever receives `soak_hours` as a plain
# argument. The old evidence ("onderhoud.soak_uren") named a source this
# module never actually reads, the same defect class as above. The
# soakvenster finding stays ESTABLISHED (the plan text is a
# deterministic function of its argument, not an appliance fact), but the
# evidence must say so honestly: an argument, not a config read.
# ---------------------------------------------------------------------------


def test_the_soak_finding_does_not_claim_a_config_read_that_does_not_exist(lab_export, knowledge):
    antwoord = upgrade_plan(lab_export, knowledge, soak_hours=24)
    soakvenster = next(f for f in antwoord.findings if f.subject == "soakvenster")
    # Naming the path is fine and honest (it says the section does not exist
    # yet); claiming it AS THE SOURCE, bare and unqualified, is not - that
    # was the old, defective evidence in full.
    assert soakvenster.evidence != "onderhoud.soak_uren"
    assert "argument soak_hours" in soakvenster.evidence
    assert "geen configuratielezing" in soakvenster.evidence


# ---------------------------------------------------------------------------
# `_preflight_findings` skips every NO_BLOCKER check and B7
# emits no heading of its own, so a plan on an export where all nine checks
# pass prints ZERO pre-flight lines - indistinguishable from a plan where the
# pre-flight never ran. `preflight._heading_finding` already owns the
# all-clear sentence for B3; this test drives that path by monkeypatching
# `preflight_checks` (the real fixture cannot reach it: not all nine
# checks read NO_BLOCKER on it at once).
# ---------------------------------------------------------------------------


def _vloerkennis(fixes=(("CTX696604", "72.61"), ("CTX696939", "73.32")), tak: str = "14.1") -> Knowledge:
    return Knowledge(
        version="test-2026.09",
        date="2026-09-01",
        age_days=4,
        missing=False,
        cve=tuple(
            {
                "bulletin": naam,
                "datum": "2026-06-30",
                "getroffen": {tak: f"< {fix}"},
                "fix": {tak: fix},
                "cves": [],
                "advies": "upgrade",
                "extraStapNaUpgrade": "",
            }
            for naam, fix in fixes
        ),
    )


def _bundel(build: str = "14.1-72.57", mb: int = 1123):
    from nsmcp.handelen import FirmwareBundle

    return FirmwareBundle(build=build, naam=f"build-{build}_nc_64.tgz", mb=mb)


def _bevinding(antwoord, subject: str):
    (gevonden,) = [f for f in antwoord.findings if f.subject == subject]
    return gevonden


def test_the_plan_names_the_target_build_the_floor_and_the_verdict_below_the_floor(lab_export):
    tekst = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel()).to_text()
    assert (
        "- huidige build: 14.1-72.57 [vastgesteld]\n"
        "    bewijs: config/nsversion: NS14.1: Build 72.57\n"
        "- doelbuild: 14.1-72.57 [vastgesteld]\n"
        "    bewijs: de enige bundel in onderhoud.firmwaremap (build-14.1-72.57_nc_64.tgz, 1123 MB)\n"
        "- vloer: 14.1-73.32 [vastgesteld]\n"
        "    bewijs: kennispakket 'test-2026.09' van 2026-09-01, bulletin CTX696939\n"
        "- doelbuild tegenover vloer: ONDER de vloer; blijven open: CTX696604 (fix 72.61), "
        "CTX696939 (fix 73.32); R0 sluit tenzij doelbuild_geaccepteerd=true [vastgesteld]\n"
        "    bewijs: doelbuild 14.1-72.57 onder vloer 14.1-73.32 (CTX696939); huidige build 14.1-72.57\n"
    ) in tekst


def test_the_current_build_and_the_three_floor_lines_follow_the_soak_line(lab_export):
    antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel())
    onderwerpen = [f.subject for f in antwoord.findings]
    soak = onderwerpen.index("soakvenster")
    assert onderwerpen[soak + 1 : soak + 5] == ["huidige build", "doelbuild", "vloer", "doelbuild tegenover vloer"]


def test_the_current_build_comes_from_the_same_version_read_as_the_overview(lab_export, knowledge):
    """`config/nsversion`, parsed the way `status_overzicht` shows it: the
    plan and the overview cannot name two different current builds."""
    from nsmcp.overzicht import overview
    from nsmcp.update_advice import export_current_build

    huidig = export_current_build(lab_export)
    assert (huidig.build, huidig.evidence, huidig.reason) == ("14.1-72.57", "config/nsversion: NS14.1: Build 72.57", "")
    (build,) = [f for f in overview(lab_export, knowledge).findings if f.subject == "build"]
    assert build.outcome == huidig.build


def test_a_target_build_at_or_above_the_floor_opens_r0_on_evidence(lab_export):
    for build in ("14.1-73.32", "14.1-74.1"):
        antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel(build))
        oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
        assert oordeel.certainty is Certainty.ESTABLISHED
        assert oordeel.outcome == "op of boven de vloer; R0 opent de vloerpoort op bewijs"


@pytest.mark.parametrize("build", ["14.1-72.57", "14.1-72.50"], ids=["herinstallatie", "downgrade"])
def test_a_target_build_not_higher_than_the_current_build_is_named_as_a_human_decision(lab_export, build):
    """The appliance runs 14.1-72.57; a bundle of that build or lower, at or
    above the floor, no longer reads as "opens on evidence"."""
    from nsmcp.upgrade_plan import (
        FLOOR_VERDICT_NOT_HIGHER,
        FLOOR_VERDICT_NOT_HIGHER_ACCEPTED,
        floor_verdict_finding,
    )

    kennis = _vloerkennis(fixes=(("CTX696604", "72.50"),))
    oordeel = _bevinding(
        upgrade_plan(lab_export, kennis, soak_hours=24, doelbuild=_bundel(build)), "doelbuild tegenover vloer"
    )
    assert oordeel.certainty is Certainty.ESTABLISHED
    assert oordeel.outcome == FLOOR_VERDICT_NOT_HIGHER
    assert FLOOR_VERDICT_NOT_HIGHER == (
        "niet hoger dan de huidige build (herinstallatie of downgrade binnen de releaselijn); "
        "R0 sluit tenzij doelbuild_geaccepteerd=true"
    )
    assert oordeel.evidence.endswith("; doelbuild niet hoger dan de huidige build")
    from nsmcp.update_advice import export_current_build, export_floor

    geaccepteerd = floor_verdict_finding(
        _bundel(build),
        export_floor(lab_export, kennis),
        kennis,
        huidig=export_current_build(lab_export),
        geaccepteerd=True,
    )
    assert geaccepteerd.outcome == FLOOR_VERDICT_NOT_HIGHER_ACCEPTED


def test_a_target_build_on_another_branch_closes_r0_even_when_accepted(lab_export):
    """The appliance runs 14.1; a 13.1 bundle is another release line than
    the current build, which the plan names before the floor."""
    antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel("13.1-63.18"))
    oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
    assert oordeel.certainty is Certainty.ESTABLISHED
    assert oordeel.outcome == "andere releaselijn dan de huidige build; R0 sluit, ook met doelbuild_geaccepteerd=true"
    assert oordeel.evidence == "doelbuild 13.1-63.18 (releaselijn 13.1), huidige build 14.1-72.57 (releaselijn 14.1)"


def test_without_a_floor_a_target_build_in_another_release_line_still_closes_r0_even_when_accepted(lab_export):
    """No floor for the appliance's own line used to leave the plan at "R0
    sluit tenzij doelbuild_geaccepteerd=true" for ANY target build - also
    one in another release line. The current build closes that."""
    antwoord = upgrade_plan(lab_export, _vloerkennis(tak="13.1"), soak_hours=24, doelbuild=_bundel("13.1-63.18"))
    assert _bevinding(antwoord, "vloer").outcome == "niet vastgesteld"
    oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
    assert oordeel.certainty is Certainty.ESTABLISHED
    assert oordeel.outcome == "andere releaselijn dan de huidige build; R0 sluit, ook met doelbuild_geaccepteerd=true"


def test_a_current_build_without_the_runner_form_is_a_form_verdict_not_an_open_door(lab_export, monkeypatch):
    """A current build that does not travel to the runner must not read as
    "unknown" there - the acceptance then stays behind (handelen), so the
    plan says R0 closes, also with the acceptance."""
    from nsmcp.update_advice import CurrentBuild
    from nsmcp.upgrade_plan import FLOOR_VERDICT_FORM

    monkeypatch.setattr(
        upgrade_plan_module,
        "export_current_build",
        lambda export: CurrentBuild("1\u0664.1-72.57", "config/nsversion: NS1\u0664.1: Build 72.57"),
    )
    antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel())
    oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
    assert (oordeel.certainty, oordeel.reason) == (Certainty.NOT_ESTABLISHED, FLOOR_VERDICT_FORM)


@pytest.mark.parametrize(
    "reden",
    [
        "onderhoud.firmwaremap draagt geen firmwarebundel van de vorm build-<tak>-<build>_nc_64.tgz: C:\\x",
        "onderhoud.firmwaremap draagt meer dan een firmwarebundel; er is dan geen eenduidige doelbuild: a, b",
    ],
)
def test_zero_or_two_bundles_leave_the_target_build_not_established_with_the_reason(lab_export, reden):
    from nsmcp.upgrade_plan import FLOOR_VERDICT_NO_TARGET

    antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=reden)
    doel = _bevinding(antwoord, "doelbuild")
    assert (doel.outcome, doel.certainty, doel.reason) == ("niet vastgesteld", Certainty.NOT_ESTABLISHED, reden)
    oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
    assert oordeel.certainty is Certainty.NOT_ESTABLISHED
    assert oordeel.reason == FLOOR_VERDICT_NO_TARGET
    assert _bevinding(antwoord, "vloer").outcome == "14.1-73.32"


def test_no_floor_is_named_not_established_with_its_reason(lab_export):
    antwoord = upgrade_plan(lab_export, _vloerkennis(tak="13.1"), soak_hours=24, doelbuild=_bundel())
    vloer = _bevinding(antwoord, "vloer")
    assert (vloer.outcome, vloer.certainty) == ("niet vastgesteld", Certainty.NOT_ESTABLISHED)
    assert vloer.reason == "tak 14.1 komt in geen enkel bulletin met een leesbare fix-build voor"
    oordeel = _bevinding(antwoord, "doelbuild tegenover vloer")
    assert oordeel.certainty is Certainty.NOT_ESTABLISHED
    assert oordeel.reason.startswith("de vloer is niet vastgesteld")
    assert oordeel.reason.endswith("R0 de vloerpoort tenzij doelbuild_geaccepteerd=true")


def test_without_a_firmware_directory_the_target_build_is_named_not_read(lab_export, knowledge):
    doel = _bevinding(upgrade_plan(lab_export, knowledge, soak_hours=24), "doelbuild")
    assert doel.certainty is Certainty.NOT_ESTABLISHED
    assert "onderhoud.firmwaremap" in doel.reason


def test_the_floor_lines_survive_every_disclosure_level_that_shows_findings(lab_export, tmp_path):
    """A build number is not an object name: the seam may not mask it, and
    it may not land in the pseudonym table either."""

    from nsmcp.answer import Answer
    from nsmcp.disclosure import Disclosure, names_from_export, render
    from nsmcp.update_advice import export_current_build, export_floor
    from nsmcp.upgrade_plan import proposal_floor_findings

    antwoord = upgrade_plan(lab_export, _vloerkennis(), soak_hours=24, doelbuild=_bundel())
    vloer = export_floor(lab_export, _vloerkennis())
    voorstel = Answer(
        question="voorstel",
        findings=proposal_floor_findings(_bundel(), vloer, _vloerkennis(), huidig=export_current_build(lab_export)),
    )
    tabel = tmp_path / "openheid-vertaaltabel.json"
    namen = names_from_export(lab_export)
    for tekst in (
        render(antwoord, Disclosure.FULL, tool="onderhoud_upgrade_plan"),
        render(
            antwoord, Disclosure.LIMITED, tool="onderhoud_upgrade_plan", extra_names=namen, pseudonym_table_path=tabel
        ),
        render(
            voorstel, Disclosure.LIMITED, tool="onderhoud_upgrade_fase", extra_names=namen, pseudonym_table_path=tabel
        ),
    ):
        assert "- huidige build: 14.1-72.57 [vastgesteld]" in tekst
        assert "- doelbuild: 14.1-72.57 [vastgesteld]" in tekst
        assert "14.1-73.32" in tekst
        assert "CTX696939" in tekst
    tabelinhoud = table_rows(tabel) if tabel.exists() else {}
    assert not {n for n in tabelinhoud.values() if n not in set(namen)}


def test_the_plan_tool_reads_the_one_bundle_in_the_firmware_directory(tmp_path):
    from upgrade_fase_harness import _call, _server, _text

    server = _server(tmp_path, floor={})
    tekst = _text(_call(server, "onderhoud_upgrade_plan", {}))
    assert "- huidige build: 14.1-72.57 [vastgesteld]" in tekst
    assert "- doelbuild: 14.1-72.57 [vastgesteld]" in tekst
    assert "bewijs: de enige bundel in onderhoud.firmwaremap (build-14.1-72.57_nc_64.tgz, 0 MB)" in tekst
    assert "- vloer: 14.1-73.32 [vastgesteld]" in tekst
    assert "- doelbuild tegenover vloer: ONDER de vloer; blijven open: CTX696604 (fix 72.61)" in tekst


def test_the_plan_tool_names_an_unknown_current_build_and_what_r0_then_does(tmp_path):
    """The harness export carries no config/nsversion: no current build, and
    so no floor either. The plan names the missing current build first."""
    from upgrade_fase_harness import _call, _server, _text

    tekst = _text(_call(_server(tmp_path), "onderhoud_upgrade_plan", {}))
    assert "- huidige build: niet vastgesteld [niet vastgesteld]" in tekst
    assert "- doelbuild tegenover vloer: niet vastgesteld [niet vastgesteld]" in tekst
    assert (
        "reden: de huidige build is niet vastgesteld; zonder huidige build sluit R0 de vloerpoort "
        "tenzij doelbuild_geaccepteerd=true"
    ) in tekst


@pytest.mark.parametrize("namen", [(), ("build-14.1-72.57_nc_64.tgz", "build-14.1-73.32_nc_64.tgz")])
def test_the_plan_tool_names_zero_or_two_bundles_honestly(tmp_path, namen):
    from upgrade_fase_harness import _call, _server, _text

    firmwaremap = tmp_path / "leeg-of-dubbel"
    firmwaremap.mkdir()
    for naam in namen:
        (firmwaremap / naam).write_bytes(b"x")
    tekst = _text(_call(_server(tmp_path, firmwaremap=firmwaremap), "onderhoud_upgrade_plan", {}))
    assert "- doelbuild: niet vastgesteld [niet vastgesteld]" in tekst
    assert "reden: onderhoud.firmwaremap draagt " in tekst


_ZERO_OR_TWO = pytest.mark.parametrize(
    "namen,zin",
    [
        ((), "de ingestelde firmwaremap bevat geen bundel"),
        (
            ("build-14.1-72.57_nc_64.tgz", "build-14.1-73.32_nc_64.tgz"),
            "de ingestelde firmwaremap bevat meer dan een bundel",
        ),
    ],
    ids=["nul", "twee"],
)


def _plan_at(tmp_path, namen, openheid) -> tuple[str, Path]:
    from upgrade_fase_harness import _call, _server, _text

    from nsmcp.disclosure import Disclosure

    firmwaremap = tmp_path / "firmware-lokaal"
    firmwaremap.mkdir()
    for naam in namen:
        (firmwaremap / naam).write_bytes(b"x")
    server = _server(tmp_path, firmwaremap=firmwaremap, disclosure=Disclosure(openheid))
    return _text(_call(server, "onderhoud_upgrade_plan", {})), firmwaremap


@_ZERO_OR_TWO
def test_at_volledig_the_plan_names_the_local_firmware_directory(tmp_path, namen, zin):
    tekst, firmwaremap = _plan_at(tmp_path, namen, "volledig")
    assert "reden: onderhoud.firmwaremap draagt " in tekst
    assert zin not in tekst
    for gezien in namen or (str(firmwaremap),):
        assert gezien in tekst


@_ZERO_OR_TWO
def test_at_beperkt_the_plan_says_what_the_firmware_directory_holds_without_its_path(tmp_path, namen, zin):
    tekst, firmwaremap = _plan_at(tmp_path, namen, "beperkt")
    assert "- doelbuild: niet vastgesteld [niet vastgesteld]" in tekst
    assert f"reden: {zin}" in tekst
    for verborgen in ("firmware-lokaal", *namen):
        assert verborgen not in tekst


@_ZERO_OR_TWO
def test_at_minimaal_the_plan_names_neither_the_path_nor_the_bundles(tmp_path, namen, zin):
    tekst, _firmwaremap = _plan_at(tmp_path, namen, "minimaal")
    for verborgen in ("firmware-lokaal", *namen):
        assert verborgen not in tekst


def test_an_all_clear_preflight_prints_the_b3_heading(lab_export, knowledge, monkeypatch):
    alle_negen = tuple(Check(n, f"toets {n}", NO_BLOCKER, f"bewijs {n}") for n in range(1, 10))
    monkeypatch.setattr(upgrade_plan_module, "preflight_checks", lambda *a, **k: alle_negen)
    tekst = upgrade_plan(lab_export, knowledge, soak_hours=24).to_text()
    assert "negen toetsen, geen blokkade" in tekst
    assert "- kop:" in tekst
