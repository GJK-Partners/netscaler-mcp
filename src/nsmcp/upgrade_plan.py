"""The plan for an upgrade within 14.1 - read, never write.

Seven phases, the HA order, the soak window, the rollback path per phase, and
per phase the gate that has to open. This module computes that picture out of
the export, the knowledge package and the pre-flight; it starts nothing and
it changes nothing. The test `test_the_upgrade_plan_makes_no_write_call`
proves that instead of promising it.

The hard rule of design 2.3 stands above every rollback line here: a firmware
rollback restores the BUILD, not the CONFIGURATION. Within 14.1 the vendor
rollback is supported - `installns` runs its own
`NetScaler Firmware Downgrade Pre-requisite Script` for it, which reported
`Done with warnings (code=17)` on the lab - but the inverse of an upgrade
remains the backup or the hypervisor snapshot.

THE PRE-FLIGHT IS CALLED, NEVER COPIED. Every check that can stop the window
(licence, classic markers, HA, drift, the certificate horizon, build/branch,
form factor, free space, the rollback path) already lives in
`preflight.preflight_checks` - the same nine checks
`status_update_preflight` runs. This module calls that function and folds
every check that is NOT `geen blokkade` into a finding, in `preflight.py`'s
own words. Two exceptions, both named where they happen:

- Check 8 (free space) is always `niet beoordeeld` here, because this
  module never measures live (design: read-only) - `_check_8_free_space`'s
  own reason AND evidence both talk about a live read ("stat/system, live
  gelezen; ..."), which would be misleading in a tool that never attempts
  one. This module replaces BOTH with its own, naming `status_update_preflight`
  as the tool that does measure it (a later fix: the evidence used to be
  carried through unchanged, one line above a reason saying the opposite).
- Check 5 (the certificate horizon) gets the PLANNED window from this module
  - the BINDING INTERFACE DECISION between the two modules: `preflight_checks` carries no
  window of its own and defaults to a horizon of `CERT_MARGIN_DAYS` (30) from
  now. This module knows the window (the soak, rounded up to whole days) and
  passes `CERT_MARGIN_DAYS + venster_dagen` in as `cert_horizon_days` - the
  ADDITION itself stays owned by `preflight.py`, never a second, uncoordinated
  horizon built here. One rule, one owner.

`nsmcp.ha.ha_result` is available on this branch, and the "volgorde"
finding (secondary first) takes the exact same route `preflight._check_3_ha`
already does: a guarded import (kept as a defensive fallback), `niet
vastgesteld` with the name of what is missing if it is ever absent -
never a stub, never a silent green on a source nobody read.
A successful read is STILL not enough by itself: the ordering claim is
about a SECOND node, so it is only
ESTABLISHED once `ha_result`'s own `node_count` shows an actual pair (>= 2)
was read - a standalone appliance, or any other gapless read with fewer
than two nodes, stays `niet vastgesteld` with a named reason.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.preflight import (
    ASSUMED_BUNDLE_MB,
    CERT_MARGIN_DAYS,
    FREE_SPACE_RESOURCE,
    NO_BLOCKER,
    NOT_ASSESSED as PREFLIGHT_NOT_ASSESSED,
    VENDOR_FLOOR_MB,
    _heading_finding,
    own_floor_mb,
    preflight_checks,
)
from nsmcp.update_advice import CurrentBuild, Floor, as_pair, export_current_build, export_floor, open_bulletins

if TYPE_CHECKING:
    from nsmcp.handelen import FirmwareBundle

# GUARDED IMPORT, kept as a defensive fallback - `nsmcp.ha` is always
# present on this branch; see `preflight._check_3_ha`, the same route.
try:
    from nsmcp.ha import ha_result as _ha_result
except ImportError:
    _ha_result = None

_HA_ABSENT = (
    "de HA-bron (nsmcp.ha.ha_result) bestaat niet in deze bouw; de rolverdeling is daarmee"
    " niet gelezen, en of secondary eerst van toepassing is, staat dan niet vast"
)
# `ha_result` can succeed (no read gap) on an export that
# still carries no actual HA PAIR - a standalone appliance, or any read
# where `node_count` is not at least 2. The ordering claim ("secondary
# eerst ... daarna pas de andere node") presupposes a second node exists;
# without one it is not simply unproven, it is a claim about a node the
# read never established. Named here, once - the same discipline as
# `_HA_ABSENT` above for the guarded-import-missing case.
_HA_NO_PAIR = "geen HA-paar gelezen; de volgorde is dan niet van toepassing"

PHASE_NAMES: tuple[str, ...] = ("R0", "R1", "R2", "R3", "R4", "R5", "R6")
PHASE_TITLES: dict[str, str] = {
    "R0": "terugrolpunt en voormeting",
    "R1": "overzetten",
    "R2": "vendor-precheck",
    "R3": "installeren",
    "R4": "herstarten en terugkomen",
    "R5": "na-meting van de node",
    "R6": "soak",
}
# Deze tabel liep achter op
# wat scripts/Invoke-GjkUpgradeFase.ps1 ECHT produceert. Bijgewerkt tegen die
# script - elke poortnaam hieronder is letterlijk overgenomen uit de
# Gate(...)-aanroep die hem vormt (secondary_gate -> "doel is secondary",
# hash_gate -> "firmware-hash", niet de eerder verzonnen namen "doel
# aantoonbaar secondary"/ontbrekende hashregel). R0 draagt GEEN
# "hostsleutel gepind" (R0 opent geen sessie, raakt de appliance
# niet aan) en drie nieuwe bewijspoorten uit zijn eigen bronnen (het
# actieregister en de export): "leeftijd van de export" en
# "familietellingen" bestonden voor deze ronde niet. Elke andere fase draagt
# nu wel "hostsleutel gepind (voorwaarde)" - de eerlijke sessiepoort
# (hostkey_session_gate), niet de oude zelfvergelijking. "vendor-precheck"
# (R2) en "SSH-auth terug na reboot" (R4) zijn VOORWAARDELIJK (alleen als de
# buildboom .pre-check-supported draagt, resp. alleen als de herverbinding
# na de reboot mislukt) en staan er toch in: een poort die soms niet
# gevormd wordt is nog steeds een poort dit script kan produceren.
PHASE_GATES: dict[str, tuple[str, ...]] = {
    "R0": (
        "backupobject aanwezig (bewijs)",
        "vorige buildboom aanwezig (bewijs)",
        "leeftijd van de export (bewijs)",
        "familietellingen (bewijs)",
        "configuratie-anker (bewijs)",
        "hypervisor-snapshotverwijzing ingevoerd (mens)",
        "doelbuild op of boven de vloer, of bewust geaccepteerd (bewijs of mens)",
    ),
    "R1": (
        "R0 gesloten (voorwaarde)",
        "hostsleutel gepind (voorwaarde)",
        "doel is secondary (bewijs)",
        "vrije ruimte op /var (bewijs)",
        "firmware-hash (bewijs)",
        "buildboom staat er nog (bewijs)",
        "drift afwezig of bewust geaccepteerd (bewijs of mens)",
    ),
    "R2": (
        "R1 gesloten (voorwaarde)",
        "hostsleutel gepind (voorwaarde)",
        "pre-check-ondersteuning aanwezig (bewijs)",
        "vendor-precheck (bewijs)",
    ),
    "R3": ("R2 gesloten (voorwaarde)", "hostsleutel gepind (voorwaarde)", "installatie voltooid (END_TIME) (bewijs)"),
    "R4": ("R3 gesloten (voorwaarde)", "hostsleutel gepind (voorwaarde)", "SSH-auth terug na reboot (bewijs)"),
    "R5": (
        "R4 gesloten (voorwaarde)",
        "hostsleutel gepind (voorwaarde)",
        "doel is secondary (bewijs)",
        "configuratie-anker (bewijs)",
        "doelbuild bereikt (bewijs)",
    ),
    "R6": ("R5 gesloten (voorwaarde)", "hostsleutel gepind (voorwaarde)", "het soakvenster loopt (tijd)"),
}
PHASE_ROLLBACK: dict[str, str] = {
    "R0": "niets geschreven; het terugrolpunt zelf is de backup en de hypervisor-snapshot",
    "R1": "verwijder de overgezette bundel; dat kost alleen schijfruimte",
    "R2": "geen; de precheck leest alleen",
    "R3": "alleen de vorige buildboom, en dan uitsluitend de BUILD - de configuratie komt terug uit de backup of de snapshot. installns draait bij een downgrade zelf het NetScaler Firmware Downgrade Pre-requisite Script",
    "R4": "geen; wachten, of de hypervisor-snapshot",
    "R5": "geen; de na-meting leest alleen",
    "R6": "geen; het soakvenster is tijd, geen handeling",
}

MINIMUM_SOAK_HOURS = 24
_HOURS_PER_DAY = 24

ROLLBACK_RULE = (
    "Een terugrol van de firmware herstelt de build, niet de configuratie. De upgrade wijzigt de "
    "configuratie en slaat die op; de inverse van een upgrade is de backup of de "
    "hypervisor-snapshot."
)
# Saving on the primary after the final validation has a tool now
# (`config_opslaan`); the failover, the second node and restoring haStatus
# stay human steps.
HUMAN_STEPS = (
    "Na het soakvenster: de failover, de tweede node en het terugzetten van haStatus zijn menselijke "
    "handelingen; daar is geen gereedschap voor, de tweede node is een menselijke handeling. Daarna "
    "volgt config_opslaan op de primary na de eindvalidatie."
)

# What B7 says instead of check 8's own reason ("de live lezing ... leverde
# geen bruikbare waarde"), which would claim an attempt that never happened:
# B7 is read-only by design (module docstring) and never measures live at
# all. Named here, once, rather than inline where it is used.
_CHECK_8_REASON = (
    "onderhoud_upgrade_plan leest niet live; status_update_preflight meet de vrije ruimte op"
    " /var wel, vlak voor het venster"
)
# Check 8's own EVIDENCE (`preflight._check_8_free_space`) names the route
# that ran ("live gelezen via <route>") or, when none ran, "niet gelezen:
# <reden>" - written for `status_update_preflight`, which really does attempt
# a live read. B7 never attempts one at all, so it states its own evidence:
# the reason above already says so, and the evidence must say the SAME
# thing, not something else, one line above it. This names the same vendorvloer/bundel/uitpakkosten numbers
# `_check_8_free_space` computes - through `preflight.own_floor_mb()`, not a
# second copy of the formula (the numbers were
# imported, the arithmetic was retyped, and the two could disagree the
# moment a real bundle size landed).
_CHECK_8_ASSUMED_FLOOR_MB = own_floor_mb(ASSUMED_BUNDLE_MB)
_CHECK_8_EVIDENCE = (
    f"{FREE_SPACE_RESOURCE} is hier niet gelezen (onderhoud_upgrade_plan is read-only en meet"
    f" niet live); status_update_preflight toetst dat straks tegen vendorvloer"
    f" {VENDOR_FLOOR_MB} MB + bundel {ASSUMED_BUNDLE_MB} MB + uitpakkosten {ASSUMED_BUNDLE_MB}"
    f" MB = {_CHECK_8_ASSUMED_FLOOR_MB} MB (aangenomen bundelgrootte {ASSUMED_BUNDLE_MB} MB)"
)
_PREFLIGHT_CHECK_8_NUMBER = 8


def _volgorde_finding(export) -> tuple[Finding, list[ReadGap]]:
    """The HA-ordering finding ("secondary eerst"), and the read gaps it
    surfaced, if any. See the module docstring for the guarded-import route.

    A successful read (no gaps) is not by itself enough for
    ESTABLISHED - `result` used to be bound and never read again, so ANY
    gapless read, including a standalone appliance with no HA pair at all,
    printed ESTABLISHED. The ordering claim is about a SECOND node; it may
    only be ESTABLISHED once an actual pair (`node_count >= 2`) was read.
    """
    outcome = "secondary eerst; deze node wordt gefaseerd bijgewerkt, daarna een soakvenster, daarna pas de andere node"
    if _ha_result is None:
        return Finding(
            subject="volgorde",
            outcome=outcome,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="config/hanode",
            reason=_HA_ABSENT,
            subject_is_name=False,
        ), []
    result, gaps = _ha_result(export)
    if gaps:
        return Finding(
            subject="volgorde",
            outcome=outcome,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="config/hanode",
            reason=gaps[0].reason,
            subject_is_name=False,
        ), list(gaps)
    if result.node_count < 2:
        return Finding(
            subject="volgorde",
            outcome=outcome,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=f"config/hanode, {result.node_count} node(s)",
            reason=_HA_NO_PAIR,
            subject_is_name=False,
        ), []
    return Finding(
        subject="volgorde",
        outcome=outcome,
        certainty=Certainty.ESTABLISHED,
        evidence=f"config/hanode, {result.node_count} node(s)",
        subject_is_name=False,
    ), []


def _clamped_soak_hours(soak_hours: int) -> int:
    """The ONE place `soak_hours` is clamped to `MINIMUM_SOAK_HOURS`. Both
    `_soak_finding` (what the plan SAYS) and `upgrade_plan` (the window it
    hands to `preflight_checks`) call this - a second, independent `max(...)`
    at each call site is exactly the copy-instead-of-call drift this
    workstream has already paid for elsewhere: two numbers that
    happen to agree today and silently stop agreeing the moment one of them
    is edited alone.
    """
    return max(int(soak_hours), MINIMUM_SOAK_HOURS)


# This module receives
# `soak_hours` as a plain argument and has no way to know from HERE whether
# a caller's value came from configuration or not - the one thing it CAN
# say honestly is that IT never reads `onderhoud.soak_uren` itself. The OLD
# text went further and claimed that field "does not exist on this branch"
# (true only before `onderhoud` landed; check 8's same defect
# class, a claim of a read that never happened, this time about the
# CONFIGURATION rather than the export) - `mcp_server._soak_hours()` now
# passes `onderhoud.soak_uren` through whenever `onderhoud` is configured,
# so the sentence describes what the CALLER does today, not what a section
# used to be missing.
_SOAK_HOURS_EVIDENCE = (
    "argument soak_hours (geen configuratielezing in deze module: onderhoud.soak_uren wordt "
    "gelezen door de aanroeper, mcp_server.py, en hier alleen doorgegeven - wanneer onderhoud "
    "is ingesteld is dat onderhoud.soak_uren, anders het product-default MINIMUM_SOAK_HOURS)"
)


def _soak_finding(soak_hours: int) -> Finding:
    venster = _clamped_soak_hours(soak_hours)
    onder_minimum = (
        ""
        if int(soak_hours) >= MINIMUM_SOAK_HOURS
        else (f"; ingesteld op {int(soak_hours)} uur, en dat is minder dan minimaal {MINIMUM_SOAK_HOURS} uur")
    )
    return Finding(
        subject="soakvenster",
        outcome=(
            f"{venster} uur wandkloktijd tussen deze node en de volgende handeling op hetzelfde doel{onder_minimum}"
        ),
        certainty=Certainty.ESTABLISHED,
        evidence=_SOAK_HOURS_EVIDENCE,
        subject_is_name=False,
    )


# The current build and the target build against the security floor: the
# four plan lines after the soak line, and the three lines at the end of
# every phase proposal. The VERDICT is not judged here a second time: it is
# R0's own `floor_gate` (nsmcp.upgrade), over the current build and the floor
# exactly as the server hands them to the runner (`runner_current_build`,
# `runner_floor`), so the plan cannot promise what R0 then refuses.
CURRENT_BUILD_SUBJECT = "huidige build"
TARGET_BUILD_EVIDENCE = "de enige bundel in onderhoud.firmwaremap ({naam}, {mb} MB)"
TARGET_BUILD_NOT_READ = "onderhoud.firmwaremap is niet meegegeven; de doelbuild is de enige bundel in die map"
FLOOR_VERDICT_SUBJECT = "doelbuild tegenover vloer"
FLOOR_VERDICT_ABOVE = "op of boven de vloer; R0 opent de vloerpoort op bewijs"
FLOOR_VERDICT_BELOW = "ONDER de vloer; blijven open: {open}; R0 sluit tenzij doelbuild_geaccepteerd=true"
FLOOR_VERDICT_BRANCH = "andere tak dan de vloer; R0 sluit, ook met doelbuild_geaccepteerd=true"
FLOOR_VERDICT_LINE = "andere releaselijn dan de huidige build; R0 sluit, ook met doelbuild_geaccepteerd=true"
_NOT_HIGHER_WORDS = "niet hoger dan de huidige build (herinstallatie of downgrade binnen de releaselijn)"
FLOOR_VERDICT_NOT_HIGHER = f"{_NOT_HIGHER_WORDS}; R0 sluit tenzij doelbuild_geaccepteerd=true"
FLOOR_VERDICT_NO_TARGET = (
    "de doelbuild is niet vastgesteld; zonder eenduidige bundel in onderhoud.firmwaremap start geen enkele fase"
)
FLOOR_VERDICT_NO_CURRENT = (
    "de huidige build is niet vastgesteld; zonder huidige build sluit R0 de vloerpoort "
    "tenzij doelbuild_geaccepteerd=true"
)
FLOOR_ABSENT_CONSEQUENCE = "zonder vloer sluit R0 de vloerpoort tenzij doelbuild_geaccepteerd=true"
FLOOR_VERDICT_NO_FLOOR = f"de vloer is niet vastgesteld; {FLOOR_ABSENT_CONSEQUENCE}"
FLOOR_VERDICT_FORM = (
    "de doelbuild, de huidige build of de vloer heeft niet de vorm <tak>-<build> die de faserunner aanneemt; "
    "R0 sluit de vloerpoort, ook met doelbuild_geaccepteerd=true"
)
# An R0 proposal whose own call carries doelbuild_geaccepteerd=true, and whose
# acceptance reaches the runner: "tenzij doelbuild_geaccepteerd=true" would
# ask for what the call already gave, so these say what R0 then does.
FLOOR_ACCEPTED_IN_THIS_CALL = "als mens: doelbuild_geaccepteerd=true is in deze aanroep meegegeven"
FLOOR_VERDICT_BELOW_ACCEPTED = (
    f"ONDER de vloer; blijven open: {{open}}; R0 opent de vloerpoort {FLOOR_ACCEPTED_IN_THIS_CALL}"
)
FLOOR_ABSENT_ACCEPTED = f"zonder vloer opent R0 de vloerpoort {FLOOR_ACCEPTED_IN_THIS_CALL}"
FLOOR_VERDICT_NO_FLOOR_ACCEPTED = f"de vloer is niet vastgesteld; {FLOOR_ABSENT_ACCEPTED}"
FLOOR_VERDICT_NO_CURRENT_ACCEPTED = (
    f"de huidige build is niet vastgesteld; zonder huidige build opent R0 de vloerpoort {FLOOR_ACCEPTED_IN_THIS_CALL}"
)
FLOOR_VERDICT_NOT_HIGHER_ACCEPTED = f"{_NOT_HIGHER_WORDS}; R0 opent de vloerpoort {FLOOR_ACCEPTED_IN_THIS_CALL}"
_NOT_ESTABLISHED_WORD = "niet vastgesteld"
_NO_OPEN_BULLETIN = "geen leesbaar bulletin"


def _target_build_read(doelbuild) -> bool:
    """`doelbuild` is a `handelen.FirmwareBundle` when the one bundle was
    read, the honest reason (`str`) when it was not, or `None` when no
    firmware directory was handed in at all."""
    return doelbuild is not None and not isinstance(doelbuild, str)


def target_build_finding(doelbuild: FirmwareBundle | str | None) -> Finding:
    """The target build: the one bundle in `onderhoud.firmwaremap`, or
    `niet vastgesteld` with the reason there is no unique one. A build
    number is not an object name, so it shows at every disclosure level."""
    if not _target_build_read(doelbuild):
        return Finding(
            subject="doelbuild",
            outcome=_NOT_ESTABLISHED_WORD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="onderhoud.firmwaremap",
            reason=TARGET_BUILD_NOT_READ if doelbuild is None else doelbuild,
            subject_is_name=False,
        )
    return Finding(
        subject="doelbuild",
        outcome=doelbuild.build,
        certainty=Certainty.ESTABLISHED,
        evidence=TARGET_BUILD_EVIDENCE.format(naam=doelbuild.naam, mb=doelbuild.mb),
        subject_is_name=False,
    )


def current_build_finding(huidig: CurrentBuild) -> Finding:
    """The build the appliance runs according to the export
    (`update_advice.export_current_build`), or `niet vastgesteld` with the
    reason. A build number is not an object name, so it shows at every
    disclosure level."""
    if huidig.build is None:
        return Finding(
            subject=CURRENT_BUILD_SUBJECT,
            outcome=_NOT_ESTABLISHED_WORD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=huidig.evidence,
            reason=huidig.reason,
            subject_is_name=False,
        )
    return Finding(
        subject=CURRENT_BUILD_SUBJECT,
        outcome=huidig.build,
        certainty=Certainty.ESTABLISHED,
        evidence=huidig.evidence,
        subject_is_name=False,
    )


def floor_finding(vloer: Floor) -> Finding:
    """The security floor of the appliance's own branch, or `niet
    vastgesteld` with the reason (`update_advice.export_floor`)."""
    if vloer.build is None:
        return Finding(
            subject="vloer",
            outcome=_NOT_ESTABLISHED_WORD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=vloer.evidence,
            reason=vloer.reason,
            subject_is_name=False,
        )
    return Finding(
        subject="vloer",
        outcome=vloer.build,
        certainty=Certainty.ESTABLISHED,
        evidence=vloer.evidence,
        subject_is_name=False,
    )


def floor_verdict_finding(
    doelbuild: FirmwareBundle | str | None,
    vloer: Floor,
    knowledge,
    *,
    huidig: CurrentBuild,
    geaccepteerd: bool = False,
) -> Finding:
    """What R0's floor gate will say about this target build, and - below
    the floor - which bulletins then stay open. A target build in another
    release line than the current build is named first, floor or no floor:
    R0 closes on it with or without acceptance.

    `geaccepteerd`: the acceptance is in THIS call and reaches the runner
    (an R0 proposal); the verdicts that would say "tenzij
    doelbuild_geaccepteerd=true" then say that R0 opens as a human. The plan
    never passes it."""
    # Imported here: nsmcp.upgrade imports this module for the phase names.
    from nsmcp.upgrade import (
        FLOOR_BELOW_REASON,
        FLOOR_BRANCH_REASON,
        FLOOR_LINE_REASON,
        FLOOR_NOT_HIGHER_REASON,
        floor_gate,
        runner_current_build,
        runner_floor,
    )

    def niet(evidence: str, reason: str) -> Finding:
        return Finding(
            subject=FLOOR_VERDICT_SUBJECT,
            outcome=_NOT_ESTABLISHED_WORD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=evidence,
            reason=reason,
            subject_is_name=False,
        )

    def wel(outcome: str, evidence: str) -> Finding:
        return Finding(
            subject=FLOOR_VERDICT_SUBJECT,
            outcome=outcome,
            certainty=Certainty.ESTABLISHED,
            evidence=evidence,
            subject_is_name=False,
        )

    if not _target_build_read(doelbuild):
        return niet("onderhoud.firmwaremap", FLOOR_VERDICT_NO_TARGET)
    grens, bulletin = runner_floor(vloer.build, vloer.bulletin)
    nu = runner_current_build(huidig.build)
    poort = floor_gate(doelbuild.build, grens, bulletin, False, huidig=nu)
    if poort.reason == FLOOR_LINE_REASON:
        return wel(FLOOR_VERDICT_LINE, poort.evidence)
    if huidig.build is None:
        return niet(huidig.evidence, FLOOR_VERDICT_NO_CURRENT_ACCEPTED if geaccepteerd else FLOOR_VERDICT_NO_CURRENT)
    if not nu:
        # A current build without the runner's form does not travel, and
        # the acceptance stays behind with it: R0 closes either way.
        return niet(huidig.evidence, FLOOR_VERDICT_FORM)
    if vloer.build is None:
        return niet(vloer.evidence, FLOOR_VERDICT_NO_FLOOR_ACCEPTED if geaccepteerd else FLOOR_VERDICT_NO_FLOOR)
    if poort.outcome == "open":
        return wel(FLOOR_VERDICT_ABOVE, poort.evidence)
    if poort.reason == FLOOR_NOT_HIGHER_REASON:
        return wel(FLOOR_VERDICT_NOT_HIGHER_ACCEPTED if geaccepteerd else FLOOR_VERDICT_NOT_HIGHER, poort.evidence)
    if poort.reason == FLOOR_BELOW_REASON:
        build = as_pair(doelbuild.build.split("-", 1)[1])
        open_ = open_bulletins(grens.rsplit("-", 1)[0], build, knowledge) if build is not None else []
        lijst = ", ".join(f"{naam} (fix {fix})" for naam, fix in open_) or _NO_OPEN_BULLETIN
        zin = FLOOR_VERDICT_BELOW_ACCEPTED if geaccepteerd else FLOOR_VERDICT_BELOW
        return wel(zin.format(open=lijst), poort.evidence)
    if poort.reason == FLOOR_BRANCH_REASON:
        return wel(FLOOR_VERDICT_BRANCH, poort.evidence)
    return niet(poort.evidence, FLOOR_VERDICT_FORM)


def proposal_floor_findings(
    doelbuild: FirmwareBundle | str | None,
    vloer: Floor,
    knowledge,
    *,
    huidig: CurrentBuild,
    geaccepteerd: bool = False,
) -> list[Finding]:
    """The three lines every phase proposal ends with: the current build,
    the target build, and the floor WITH R0's verdict on it - before the
    window, so a target build below the floor is a choice made up front,
    not a closed gate read afterwards. Without a floor the floor line still
    carries a release-line verdict: that one closes R0 with acceptance too,
    so "tenzij doelbuild_geaccepteerd=true" would promise what R0 refuses.
    `geaccepteerd` as in `floor_verdict_finding`."""
    oordeel = floor_verdict_finding(doelbuild, vloer, knowledge, huidig=huidig, geaccepteerd=geaccepteerd)
    if vloer.build is None:
        if oordeel.outcome == FLOOR_VERDICT_LINE:
            gevolg = f"doelbuild {oordeel.outcome}"
        else:
            gevolg = FLOOR_ABSENT_ACCEPTED if geaccepteerd else FLOOR_ABSENT_CONSEQUENCE
        vloer_regel = Finding(
            subject="vloer",
            outcome=_NOT_ESTABLISHED_WORD,
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=vloer.evidence,
            reason=f"{vloer.reason}; {gevolg}",
            subject_is_name=False,
        )
    elif oordeel.certainty is Certainty.ESTABLISHED:
        vloer_regel = Finding(
            subject="vloer",
            outcome=f"{vloer.build}; doelbuild {oordeel.outcome}",
            certainty=Certainty.ESTABLISHED,
            evidence=vloer.evidence,
            subject_is_name=False,
        )
    else:
        vloer_regel = Finding(
            subject="vloer",
            outcome=f"{vloer.build}; oordeel {_NOT_ESTABLISHED_WORD}",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=vloer.evidence,
            reason=oordeel.reason,
            subject_is_name=False,
        )
    return [current_build_finding(huidig), target_build_finding(doelbuild), vloer_regel]


def _phase_findings() -> list[Finding]:
    findings: list[Finding] = []
    for fase in PHASE_NAMES:
        findings.append(
            Finding(
                subject=f"{fase} {PHASE_TITLES[fase]}",
                outcome="poorten: " + "; ".join(PHASE_GATES[fase]),
                certainty=Certainty.ESTABLISHED,
                evidence="ontwerp 3.5, de faserunner",
                subject_is_name=False,
            )
        )
        findings.append(
            Finding(
                subject=f"{fase} terugrolpad",
                outcome=PHASE_ROLLBACK[fase],
                certainty=Certainty.ESTABLISHED,
                evidence=ROLLBACK_RULE,
                subject_is_name=False,
            )
        )
    return findings


def _preflight_findings(export, knowledge, cert_horizon_days: int) -> list[Finding]:
    """Every one of B3's nine checks that is NOT `geen blokkade`, in B3's own
    words - called, not copied (see the module docstring).

    `preflight._heading_finding` already OWNS the one
    sentence that may say "all nine checks pass" - called here, never
    rewritten. Without it, a plan on an export where all nine checks pass
    contributed ZERO lines from this function (the loop below skips every
    `geen blokkade` check), indistinguishable from a plan where the
    pre-flight never ran at all - the standing rule "never an empty list
    without a sentence" applies here just as much as it does in B3.
    """
    checks = preflight_checks(
        export,
        knowledge,
        free_var_mb=None,
        bundle_mb=None,
        cert_horizon_days=cert_horizon_days,
    )
    findings: list[Finding] = []
    heading = _heading_finding(checks)
    if heading is not None:
        findings.append(heading)
    for check in checks:
        if check.word == NO_BLOCKER:
            continue
        reason = check.reason
        evidence = check.evidence
        if check.number == _PREFLIGHT_CHECK_8_NUMBER:
            reason = _CHECK_8_REASON
            evidence = _CHECK_8_EVIDENCE
        findings.append(
            Finding(
                subject=f"{check.number}. {check.name}",
                outcome=check.word,
                certainty=(
                    Certainty.NOT_ESTABLISHED if check.word == PREFLIGHT_NOT_ASSESSED else Certainty.ESTABLISHED
                ),
                evidence=evidence,
                reason=reason,
                subject_is_name=False,
            )
        )
    return findings


def upgrade_plan(export, knowledge, soak_hours: int, doelbuild: FirmwareBundle | str | None = None) -> Answer:
    """`doelbuild`: the one bundle in `onderhoud.firmwaremap`
    (`handelen.firmware_target_build`), the reason there is none, or `None`
    when the caller has no firmware directory to read."""
    findings: list[Finding] = []
    volgorde, ha_gaps = _volgorde_finding(export)
    findings.append(volgorde)
    findings.append(_soak_finding(soak_hours))
    vloer = export_floor(export, knowledge)
    huidig = export_current_build(export)
    findings.append(current_build_finding(huidig))
    findings.append(target_build_finding(doelbuild))
    findings.append(floor_finding(vloer))
    findings.append(floor_verdict_finding(doelbuild, vloer, knowledge, huidig=huidig))
    findings.extend(_phase_findings())
    findings.append(
        Finding(
            subject="regel",
            outcome=ROLLBACK_RULE,
            certainty=Certainty.ESTABLISHED,
            evidence="ontwerp 2.3 en 2.8",
            subject_is_name=False,
        )
    )

    # The planned window, in whole days, rounded up - the soak is the one
    # duration this plan actually spans (design 3.5: every other phase
    # proceeds once its gate opens, with no built-in wait). `_clamped_soak_
    # hours` is the SAME clamp `_soak_finding` used above: the horizon below
    # must use the SAME window the soak line prints, not the raw (possibly
    # too-low) argument - a second, uncoordinated number here would
    # contradict the soak line above it in the very same answer.
    venster_dagen = math.ceil(_clamped_soak_hours(soak_hours) / _HOURS_PER_DAY)
    findings.extend(_preflight_findings(export, knowledge, CERT_MARGIN_DAYS + venster_dagen))

    findings.append(
        Finding(
            subject="daarna",
            outcome=HUMAN_STEPS,
            certainty=Certainty.ESTABLISHED,
            evidence="ontwerp 3.5",
            subject_is_name=False,
        )
    )
    return Answer(
        question="wat is het plan voor deze upgrade",
        findings=findings,
        read_gaps=ha_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
