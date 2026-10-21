"""Which build belongs on this appliance - three builds side by side.

Three numbers answer that question, and they come from three different
places: what is ON the box (the export), what the security knowledge demands
as a MINIMUM (the highest fix build of the branch, from the bulletins), and
what the vendor OFFERS today (the release notes, from the `aangeboden` field
of the knowledge package). Printing only one of them turns an upgrade
decision into a guess: the floor says what may not stay, the offered build
says what is available, and only the two together say what to plan.

Nothing is derived that was not read. An unreadable build is a read gap, and
a read gap yields `niet vastgesteld` - never a verdict on a build this
product did not see (`config/nsversion` is the source, never
`/flash/.version`, which lies demonstrably: design chapter 7).

THE KNOWLEDGE PACKAGE IS SUPPLIED INPUT, and this module reads four fields of
it that no loader shapes for it. The rule of this codebase applies to all
four: name what you cannot use, never repeat it raw.

- The branch KEYS of `offered_builds` are checked for printability by
  `knowledge._offered_problem()` but never for SHAPE, so a forged
  "[vastgesteld]" marker can sit MID-LINE inside one. This module therefore
  never iterates over those keys and never prints one: it LOOKS UP the branch
  it parsed out of the export. A key the export's branch does not equal
  simply does not match, and stays outside the answer entirely.
- The `bulletin` identifier is never type- or shape-checked at load time at
  all, and it travels here as the provenance of the floor. It passes
  `answer.repeatable_token()` - the one shape gate this product already uses
  for exactly this - before it is printed.
- `offered_date` and `knowledge.date` are only checked to be PARSEABLE, and
  `date.fromisoformat` also accepts the basic form: a JSON number `20260901`
  loads as the string `'20260901'`. Every date this module writes into a
  FINDING goes through `day()`, so it is FORMATTED there, never echoed, and
  an unusable one is named ("datum niet vastgelegd"). ONE EXCEPTION, named
  rather than claimed away: `Answer.knowledge_date` carries `knowledge.date`
  RAW to the footer, where `to_text()` renders it verbatim - a `20260901`
  prints raw there. That footer is the shared path of every tool in this
  product, not a gate of this module, so it is not closed here.
- `offered_source` and `version` are free text. Both go through `!r`, the
  same idiom `knowledge.py` uses for attacker-supplied text in a refusal
  reason: it escapes the line break that would otherwise forge a whole
  finding line. Their LENGTH stays unbounded on this branch -
  `limits.capped_text()` is the sanctioned cap and `knowledge.py` already
  carries the merge obligation for it; inventing a second cap here would
  give this product two competing mechanisms for one rule.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, repeatable_token
from nsmcp.cve import (
    FIPS_SUFFIX,
    PLATFORM_FIPS,
    PLATFORM_PLAIN,
    PLATFORM_UNKNOWN,
    PLATFORM_UNKNOWN_REASON,
    build_echo,
    fips_platform,
    parse_build,
)
from nsmcp.knowledge import OFFERED_ABSENT, Knowledge

ON_OFFERED = "op de aangeboden build"
ABOVE_FLOOR = "onder aangeboden maar op-of-boven de vloer"
BELOW_FLOOR = "onder de vloer"
BRANCH_UNKNOWN = "tak niet bekend"
NOT_ESTABLISHED_WORD = "niet vastgesteld"
UPDATE_WORDS: tuple[str, ...] = (ON_OFFERED, ABOVE_FLOOR, BELOW_FLOOR, BRANCH_UNKNOWN, NOT_ESTABLISHED_WORD)

VERSION_RESOURCE = "config/nsversion"

# What the answer says instead of a date it cannot format, and instead of a
# bulletin identifier it may not repeat. Both are the honest absence of a
# fact, never a guess and never the raw value.
DATE_UNRECORDED = "datum niet vastgelegd"
_UNREADABLE_ID = "(bulletin-id niet leesbaar)"
_VERSION_UNRECORDED = "niet vastgelegd"


def as_pair(build) -> tuple[int, int] | None:
    """The two numbers of an "X.Y" build, or None for anything else.

    Also THE gate on a build out of the knowledge package: a value this
    function cannot read is a value this module may neither compare nor
    print.

    PUBLIC because `preflight.py` (B3, checks 6 and 9) needs the exact same
    gate on the exact same shape and used to carry a byte-for-byte copy of
    this function - the copy-instead-of-call
    class this module's own docstring already argues against for
    `_package_names_the_fips_train()`. One rule, one owner: `preflight.py`
    imports this instead.
    """
    if not isinstance(build, str):
        return None
    parts = build.split(".")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1])


def day(value) -> str:
    """A date FORMATTED, never a date echoed.

    `knowledge.py` only checks that a date PARSES, and `date.fromisoformat`
    accepts the basic form too - so `20260901` out of a JSON number arrives
    here as the string '20260901'. Rendering that raw would put a form in the
    answer that appears nowhere else in this product.

    PUBLIC for the same reason as `as_pair()` above: `preflight.py` used to
    carry its own byte-for-byte copy of this function AND of `DATE_UNRECORDED`;
    it imports both from here instead now.
    """
    if value is None:
        return DATE_UNRECORDED
    try:
        return date.fromisoformat(str(value)).isoformat()
    except (TypeError, ValueError):
        return DATE_UNRECORDED


def public_bulletin_id(value) -> str:
    """A bulletin identifier, through the ONE shape gate this product has for
    text out of untrusted input that may be REPEATED in an answer.

    PUBLIC because `floor_for()` hands the identifier out RAW and OBLIGES its
    consumers (`upgrade_plan.py` and `rapport_na_upgrade`) to pass it through this gate
    before printing it. An obligation that points at a private name is not one
    a consumer can meet without copying the gate.

    `knowledge.py` never checks this field - not its type, not its shape - and
    an answer line here reads "- <onderwerp>: <uitkomst> [vastgesteld]". A
    line break in the identifier writes a second, indistinguishable line; the
    same forgery this codebase already measured through a status. A real
    bulletin identifier ("CTX696604") passes this gate untouched; anything
    else is NAMED, so the floor build itself stays established while only its
    label falls away.
    """
    token = repeatable_token(value, max_words=1, max_len=32)
    return token if token is not None else _UNREADABLE_ID


def _ruleset(version) -> str:
    """The ruleset version, which design 2.3 (B2) requires IN the answer.

    `raw.get("versie")` is never validated, so this is free text out of a
    supplied package. `!r` is the idiom `knowledge.py` already uses for
    exactly that: it escapes the line break that would forge a finding line.
    """
    return _VERSION_UNRECORDED if version is None else repr(str(version))


def floor_for(branch: str, knowledge: Knowledge) -> tuple[str, str] | None:
    """The HIGHEST fix build the knowledge package names for this branch, with
    the bulletin it came from. Highest, not first: two bulletins on one branch
    each set their own floor, and only the highest of them is a floor at all.

    The identifier travels out RAW here on purpose - this is an interface, not
    an answer, and B7/B5 read it. Every caller that PRINTS it puts it through
    `public_bulletin_id()` first - a PUBLIC name, so that obligation is one a
    consumer can meet without copying the gate - the way `update_advice()`
    below does.
    """
    best: tuple[str, str] | None = None
    best_pair: tuple[int, int] | None = None
    for bulletin in knowledge.cve:
        if not isinstance(bulletin, dict):
            continue
        fix = bulletin.get("fix")
        if not isinstance(fix, dict) or branch not in fix:
            continue
        pair = as_pair(fix[branch])
        if pair is None:
            continue
        if best_pair is None or pair > best_pair:
            best_pair = pair
            best = (str(fix[branch]), str(bulletin.get("bulletin", "(naamloos)")))
    return best


def open_bulletins(branch: str, build: tuple[int, int], knowledge: Knowledge) -> list[tuple[str, str]]:
    """Every bulletin whose fix build for `branch` lies ABOVE `build` - what
    stays open on that build - as `(public id, fix build)`, lowest fix
    first. The same iteration and the same `as_pair()` gate as `floor_for()`
    above; the identifier goes through `public_bulletin_id()` and the fix
    build is rebuilt from the two numbers read, never echoed."""
    gevonden: list[tuple[tuple[int, int], str]] = []
    for bulletin in knowledge.cve:
        if not isinstance(bulletin, dict):
            continue
        fix = bulletin.get("fix")
        if not isinstance(fix, dict) or branch not in fix:
            continue
        pair = as_pair(fix[branch])
        if pair is not None and pair > build:
            gevonden.append((pair, public_bulletin_id(bulletin.get("bulletin", "(naamloos)"))))
    return [(naam, f"{pair[0]}.{pair[1]}") for pair, naam in sorted(gevonden)]


def _current(export) -> tuple[str, tuple[int, int], str, object] | ReadGap:
    """(tak, build, echo, de ruwe versietekst) of the build that is RUNNING.

    The fourth value is passed on to `cve.fips_platform()`, which weighs it
    together with `config/nshardware` and `config/systemparameter`. It is
    never PRINTED: `echo` is what the answer shows, and that one is rebuilt
    from what the regex matched (see `cve.build_echo`).
    """
    row, gap = export.single(VERSION_RESOURCE)
    if gap is not None:
        return gap
    if not isinstance(row, dict):
        return ReadGap(source=VERSION_RESOURCE, reason="geen versieobject in de export")
    text = row.get("version") or row.get("Version") or ""
    parsed = parse_build(text)
    if parsed is None:
        return ReadGap(
            source=VERSION_RESOURCE,
            reason=f"de versietekst draagt geen herkenbare buildvorm {build_echo(text)}",
        )
    branch, pair = parsed
    return branch, pair, build_echo(text), text


def _package_names_the_fips_train(fips_branch: str, knowledge: Knowledge, offered) -> bool:
    """Does the knowledge package know the FIPS train of THIS branch family?

    THE PACKAGE HALF of the question `cve_check` asks, and only that half.
    The PLATFORM half - is this appliance FIPS/NDcPP? - belongs to
    `cve.fips_platform()`, which weighs `config/nsversion`,
    `config/nshardware: hwdescription` and
    `config/systemparameter: fipsusermode` together.

    THIS MODULE USED TO CARRY ITS OWN, NARROWER COPY: a train marker in
    the version string, or a `<tak>-FIPS` key in
    the package. It therefore missed an appliance whose FIPS read comes from
    the HARDWARE description - and then judged it against the ORDINARY
    branch's floor, while `status_cve_controle` on the same export had
    already read it as FIPS. A false established verdict, advice to install a
    build that train does not have, and two tools contradicting each other on
    one export. One rule, one owner.

    Why the package half exists at all: a package that never mentions this
    branch's FIPS train leaves the question silent, exactly as it does for
    the CVE verdicts. The real bulletins name 13.1-FIPS and never 14.1-FIPS,
    so a 14.1 appliance keeps its ordinary answer with no platform line.
    """
    if fips_branch in offered:
        return True
    for bulletin in knowledge.cve:
        if not isinstance(bulletin, dict):
            continue
        for half in ("getroffen", "fix"):
            value = bulletin.get(half)
            if isinstance(value, dict) and fips_branch in value:
                return True
    return False


def _package_label(knowledge: Knowledge) -> str:
    """Which knowledge package a floor came from, in the one wording both
    the advice and `export_floor()` print."""
    return f"kennispakket {_ruleset(knowledge.version)} van {day(knowledge.date)}"


def _no_bulletin_reason(rule_branch: str) -> str:
    return f"tak {rule_branch} komt in geen enkel bulletin met een leesbare fix-build voor"


@dataclass(frozen=True)
class Floor:
    """The security floor of the branch THIS appliance runs, or the named
    reason there is none.

    `build` is `<tak>-<build>` (the tak of the rule: `13.1-FIPS` on a FIPS
    appliance) or `None`; `bulletin` is the identifier AFTER
    `public_bulletin_id()`, so it may be printed; `evidence` names the
    package and the bulletin; `reason` is empty exactly when `build` is
    set."""

    build: str | None
    bulletin: str
    evidence: str
    reason: str = ""


@dataclass(frozen=True)
class CurrentBuild:
    """The build the appliance RUNS according to the export, or the named
    reason it is not known.

    `build` is `<tak>-<build>` (`14.1-72.57`) or `None`; `evidence` names the
    source with only the parsed part of the version string (`build_echo`),
    so it may be printed; `reason` is empty exactly when `build` is set."""

    build: str | None
    evidence: str
    reason: str = ""


def export_current_build(export) -> CurrentBuild:
    """The current build for the upgrade plan, the phase proposals and R0's
    floor gate: `config/nsversion`, the source `status_overzicht` shows as
    its build line, over `_current()` - the same read `export_floor()`
    derives the floor from, so the floor and the current build can never
    come from two different reads. A read gap or an unparsable version
    string is a current build that is NOT there, with its reason."""
    current = _current(export)
    if isinstance(current, ReadGap):
        return CurrentBuild(None, VERSION_RESOURCE, current.reason)
    branch, pair, echo, _version_text = current
    return CurrentBuild(f"{branch}-{pair[0]}.{pair[1]}", f"{VERSION_RESOURCE}: {echo}")


def export_floor(export, knowledge: Knowledge) -> Floor:
    """The floor `status_update_advies` prints for this export, for the
    other consumers of that same number: the upgrade plan and the R0 gate
    of the phase runner.

    THE SAME ROUTE as `update_advice()` below, never a second copy of it:
    the running build from `_current()`, the train from
    `cve.fips_platform()` (the one owner of that rule), the floor from
    `floor_for()`. A read gap, a missing package, an undecidable platform
    or a branch no bulletin names is a floor that is NOT there, with its
    reason - never a guessed one."""
    current = _current(export)
    if isinstance(current, ReadGap):
        return Floor(None, "", VERSION_RESOURCE, current.reason)
    branch, _pair, _echo, version_text = current
    if knowledge.missing:
        return Floor(None, "", "kennispakket", knowledge.reason or "kennispakket ontbreekt")
    package = _package_label(knowledge)
    if knowledge.unpinned_reason:
        # A floor out of a package the configuration does not pin is no
        # floor: the upgrade plan says `niet vastgesteld`, and R0's floor
        # gate closes unless a human accepts the target build.
        return Floor(None, "", package, knowledge.unpinned_reason)
    fips_branch = f"{branch}{FIPS_SUFFIX}"
    platform, platform_evidence, _platform_gap = fips_platform(export, version_text, branch)
    if platform == PLATFORM_UNKNOWN:
        return Floor(
            None,
            "",
            platform_evidence,
            f"{PLATFORM_UNKNOWN_REASON}; de vloer verschilt per tak ({branch} of {fips_branch})",
        )
    rule_branch = fips_branch if platform == PLATFORM_FIPS else branch
    floor = floor_for(rule_branch, knowledge)
    if floor is None or as_pair(floor[0]) is None:
        return Floor(None, "", package, _no_bulletin_reason(rule_branch))
    bulletin = public_bulletin_id(floor[1])
    return Floor(f"{rule_branch}-{floor[0]}", bulletin, f"{package}, bulletin {bulletin}")


def update_advice(export, knowledge: Knowledge) -> Answer:
    question = "welke build moet erop"
    current = _current(export)
    if isinstance(current, ReadGap):
        return Answer(
            question=question,
            findings=[
                Finding(
                    subject="oordeel",
                    outcome=NOT_ESTABLISHED_WORD,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=VERSION_RESOURCE,
                    reason=current.reason,
                    subject_is_name=False,
                )
            ],
            read_gaps=[current],
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )
    branch, pair, echo, version_text = current
    findings = [
        Finding(
            subject="huidige build",
            outcome=echo,
            certainty=Certainty.ESTABLISHED,
            evidence=VERSION_RESOURCE,
            subject_is_name=False,
        )
    ]

    if knowledge.missing:
        findings.append(
            Finding(
                subject="oordeel",
                outcome=NOT_ESTABLISHED_WORD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence="kennispakket",
                reason=knowledge.reason or "kennispakket ontbreekt",
                subject_is_name=False,
            )
        )
        return Answer(question=question, findings=findings)

    package = _package_label(knowledge)
    # THE LOOKUP MAP - never iterated (see the module docstring), and never
    # assumed to BE a map either. `knowledge.py` does not type-check this
    # field, and every neighbouring field here has an isinstance net for a
    # `Knowledge` that skipped that loader; without one, `.get()` on a string
    # raises out of the tool instead of becoming an absence with a name.
    offered_map = knowledge.offered_builds if isinstance(knowledge.offered_builds, dict) else {}

    # WHICH TRAIN THIS APPLIANCE RUNS. The product's rule, not this module's:
    # `cve.fips_platform()` weighs all three sources. Asked OUT LOUD only when
    # it is at stake, the same condition `cve_check` uses - anything that
    # reads FIPS, or a package that names the FIPS branch of this family.
    fips_branch = f"{branch}{FIPS_SUFFIX}"
    platform, platform_evidence, platform_gap = fips_platform(export, version_text, branch)
    if platform != PLATFORM_PLAIN or _package_names_the_fips_train(fips_branch, knowledge, offered_map):
        if platform == PLATFORM_FIPS:
            platform_outcome = f"FIPS/NDcPP-appliance; tak {fips_branch} geldt"
        elif platform == PLATFORM_PLAIN:
            platform_outcome = f"geen FIPS/NDcPP-appliance; tak {branch} geldt"
        else:
            platform_outcome = PLATFORM_UNKNOWN_REASON
        findings.append(
            Finding(
                subject="platform",
                outcome=platform_outcome,
                certainty=(Certainty.NOT_ESTABLISHED if platform == PLATFORM_UNKNOWN else Certainty.ESTABLISHED),
                evidence=platform_evidence,
                reason="" if platform != PLATFORM_UNKNOWN else platform_evidence,
                subject_is_name=False,
            )
        )

    if platform == PLATFORM_UNKNOWN:
        # No floor and no offered build are shown here EITHER: both would be
        # the numbers of a train that may well not be this appliance's, and a
        # number next to the wrong label is what this guard exists to
        # prevent. The FIPS train's fix builds sit far BELOW the ordinary
        # branch's (13.1-FIPS 37.272 against 13.1 63.18), so a guess costs a
        # false verdict AND wrong upgrade advice.
        findings.append(
            Finding(
                subject="oordeel",
                outcome=NOT_ESTABLISHED_WORD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=platform_evidence,
                reason=f"{PLATFORM_UNKNOWN_REASON}; vloer en aangeboden build verschillen"
                f" per tak ({branch} of {fips_branch})",
                subject_is_name=False,
            )
        )
        return Answer(
            question=question,
            findings=findings,
            read_gaps=[platform_gap] if platform_gap is not None else [],
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    # The train is settled, and this is the branch `cve_check` would use for
    # the same export - one derivation, two consumers.
    rule_branch = fips_branch if platform == PLATFORM_FIPS else branch

    floor = floor_for(rule_branch, knowledge)
    floor_pair = as_pair(floor[0]) if floor is not None else None
    if floor_pair is None:
        findings.append(
            Finding(
                subject="vloer",
                outcome="geen bulletin noemt deze tak",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=package,
                reason=_no_bulletin_reason(rule_branch),
                subject_is_name=False,
            )
        )
    else:
        findings.append(
            Finding(
                subject="vloer",
                outcome=f"{rule_branch}-{floor[0]}",
                certainty=Certainty.ESTABLISHED,
                evidence=f"{package}, bulletin {public_bulletin_id(floor[1])}",
                subject_is_name=False,
            )
        )

    # THE LOOKUP, not an iteration: the branch comes out of the EXPORT and is
    # used as the key. See the module docstring for why no key of the package
    # may ever be printed.
    offered_raw = offered_map.get(rule_branch)
    offered_pair = as_pair(offered_raw)
    if offered_raw is None:
        offered_absence = (
            f"de aangeboden build voor tak {rule_branch} is niet vastgelegd, dus"
            " 'onder aangeboden' is niet vastgesteld; het oordeel staat op de vloer"
        )
        findings.append(
            Finding(
                subject="aangeboden build",
                outcome=OFFERED_ABSENT,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=package,
                reason="het pakket draagt geen aangeboden build voor deze tak",
                subject_is_name=False,
            )
        )
    elif offered_pair is None:
        # `load_knowledge` refuses such a package, so this is the runtime net
        # for a Knowledge that never passed that loader - the same second-net
        # discipline cve.py applies to a half rule. The value is NAMED, never
        # repeated, and it may not become an established fact either.
        offered_absence = (
            f"de aangeboden build voor tak {rule_branch} heeft niet de vorm X.Y, dus"
            " 'onder aangeboden' is niet vastgesteld; het oordeel staat op de vloer"
        )
        findings.append(
            Finding(
                subject="aangeboden build",
                outcome=NOT_ESTABLISHED_WORD,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=package,
                reason=f"de aangeboden build voor tak {rule_branch} heeft niet de vorm X.Y",
                subject_is_name=False,
            )
        )
    else:
        offered_absence = ""
        findings.append(
            Finding(
                subject="aangeboden build",
                outcome=f"{rule_branch}-{offered_raw}",
                certainty=Certainty.ESTABLISHED,
                evidence=f"bron {knowledge.offered_source!r} van {day(knowledge.offered_date)}",
                subject_is_name=False,
            )
        )

    verdict, reason = _verdict(pair, floor_pair, offered_pair, offered_absence, rule_branch)
    findings.append(
        Finding(
            subject="oordeel",
            outcome=verdict,
            certainty=Certainty.NOT_ESTABLISHED if reason else Certainty.ESTABLISHED,
            evidence=_weighed(echo, floor_pair, offered_pair, rule_branch, package),
            reason=reason,
            subject_is_name=False,
        )
    )
    if knowledge.unpinned_reason:
        findings = _unpinned(findings, knowledge.unpinned_reason)
    return Answer(
        question=question,
        findings=findings,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


# The findings of this answer that come out of the EXPORT, not the package.
_FROM_THE_EXPORT = frozenset({"huidige build", "platform"})


def _unpinned(findings: list[Finding], reason: str) -> list[Finding]:
    """Every statement the package carries - the floor, the offered build and
    the verdict that weighs them - demoted to `[niet vastgesteld]`, because
    the configuration does not pin the package: whoever can write the
    knowledge path could have lowered them. The numbers stay visible; the
    running build and the platform, read from the export, keep their own
    certainty."""
    return [
        replace(finding, certainty=Certainty.NOT_ESTABLISHED, reason=reason)
        if finding.certainty is Certainty.ESTABLISHED and finding.subject not in _FROM_THE_EXPORT
        else finding
        for finding in findings
    ]


def _weighed(echo: str, floor_pair, offered_pair, branch: str, package: str) -> str:
    """The evidence line of the verdict: what was ACTUALLY weighed.

    This used to be a constant - "vergelijking van {echo} met vloer en
    aangeboden build" - printed unchanged for `tak niet bekend`, where nothing
    was compared at all, and for the offered-absent case, where one side was.
    A constant is not a description, and an
    evidence line that names a comparison that did not happen is the same
    false green as a `[vastgesteld]` without a read.
    """
    weighed = []
    if floor_pair is not None:
        weighed.append("de vloer")
    if offered_pair is not None:
        weighed.append("de aangeboden build")
    if not weighed:
        return f"{package}: noemt geen vloer en geen aangeboden build voor tak {branch}"
    return f"vergelijking van {echo} met {' en '.join(weighed)}"


def _verdict(
    pair: tuple[int, int],
    floor_pair: tuple[int, int] | None,
    offered_pair: tuple[int, int] | None,
    offered_absence: str,
    branch: str,
) -> tuple[str, str]:
    """(woord, reden). A reason means the word is NOT established.

    THE SECURITY FLOOR BEATS THE VENDOR OFFERING (MEASURED: 13.1 build 60.5, bulletin fix 63.18,
    offered build 58.32). The floor check therefore runs FIRST: a build
    below the floor is `onder de vloer`, full stop, regardless of what the
    vendor happens to offer today. The alternative - keeping
    `op de aangeboden build` and only dropping `[vastgesteld]` - was
    rejected: that word would still tell an operator scanning for the
    can-word that this build is fine, on the one export where
    `status_cve_controle` says GERAAKT with a CVSS 9.8 RCE. A word this
    product prints as reassuring may never be the one that survives on a
    vulnerable appliance, established or not.

    Two halves are missing in two different directions, and they are NOT
    symmetrical - which is why they do not get the same answer:

    - FLOOR known, OFFERED unknown. The security-critical half IS
      established, so the VERDICT stays on the floor and the answer says
      `aangeboden build niet vastgelegd` next to it (design 2.3, B1/B2,
      literally). But `onder aangeboden maar op-of-boven de vloer` NAMES the
      offered build, two lines under a `[niet vastgesteld]` for exactly that
      field - so the word stays and the MARKER goes, with `offered_absence`
      as the reason. `onder de vloer` claims
      nothing about an offered build at all and stays established; that is
      the whole difference between the two.
    - OFFERED known, FLOOR unknown. Then `onder aangeboden maar op-of-boven
      de vloer` would assert a relation to a floor that was never
      established - a green statement about the very half that decides
      whether this build may stay. So it speaks with the "niet"-word of its
      own vocabulary plus a reason (design 2.1.1, "Hoe een leesgat spreekt":
      a read gap never gets a green word and never a silence).

    `op de aangeboden build` needs no floor at all, but ONLY when the floor
    is either unknown or already cleared: it says the build is at or above
    what the vendor offers, and makes no claim about the floor. There is
    nothing higher to plan towards either.
    """
    if floor_pair is not None and pair < floor_pair:
        return BELOW_FLOOR, ""
    if offered_pair is not None and pair >= offered_pair:
        return ON_OFFERED, ""
    if floor_pair is not None:
        return ABOVE_FLOOR, offered_absence
    if offered_pair is None:
        return BRANCH_UNKNOWN, ""
    return NOT_ESTABLISHED_WORD, (
        f"de build ligt onder de aangeboden build, maar geen bulletin noemt tak {branch};"
        " zonder vloer is niet vast te stellen of deze build mag blijven staan"
    )
