"""What was DOWN at the moment of the scan. A snapshot, and it says so.

Mirrors backend/readonly/NshcHealthStateTruth.ps1 (Get-NshcHealthStateTruth):
PASS when everything measured is up, PARTIAL with reason `down-objects` when
something is DOWN, PARTIAL with reason `state-unreadable` when not every state
was readable, NotApplicable at zero objects in scope. Those last two are the
distinction this whole module exists for, and they get SEPARATE findings
here, never blurred into one "gedeeltelijk":

- STORING: something is DOWN. A statement about the appliance.
- DEKKINGSUITSPRAAK: a state could not be read. A statement about this export.

Roll them into one and an administrator cannot tell whether a service is
broken or whether we simply did not look - and those two lead to opposite
actions.

THIS IS NOT MONITORING, and the answer says so in as many words. The `stat/*`
resources NSHC reads live (stat/ns, stat/system, stat/lbvserver) are NOT in
the collector export; what is here is a snapshot with a data age, and the
answer OPENS with it. The words "alarm" and "monitoring" do not occur in this
module's output, guarded by a test - because using them would promise
something this product does not do.

TWO NAME-SAFETY DEFECTS closed here - both belong to the class this
workstream keeps rediscovering: a raw export value reaching a rendered
line unguarded.

- A family row's own NAME (lbvserver/csvserver/vpnvserver/service) is
  echoed through `export.safe_name_label`:
  real text on one line, no control character or line break, bounded in
  length - a positional label plus the SHAPE otherwise, never the value. A
  multi-line name used to forge a second, byte-identical "verdict" line.
- A servicegroup MEMBER's identity (servername/ip) is never printed at all
  (see `snapshot()` below): a
  member is counted and positioned ("positie N"), never named, regardless of
  disclosure level - the same choice `expiry.py` made for a certificate's
  cert-side binding. It was made while the
  masking table read this file's aggregate shape and this module its list
  shape; both now read through the shared reader, and the choice stands
  unchanged.

DEVIATIONS FROM THE ORIGINAL SAMPLE, measured, not guessed (this module
deviates in two places):

1. "OUT OF SERVICE" moved OUT of the fault vocabulary - "OUT OF SERVICE is
   geen fout" (parity with the Healthcheck), stated twice, verbatim, in this
   task's own instructions. Pinned by
   `test_out_of_service_is_not_a_fault_parity_with_the_healthcheck`.
2. "ENABLED" dropped from the recognized-state vocabulary - not a
   `curstate`/`svrstate` value anywhere in this product's measured evidence,
   and carrying it forward unmeasured is exactly the invented vocabulary wet
   2026-005 forbids. Falls into `unreadable` like any other unknown token.
3. State reading goes through `export.field_gap()` (the shared shape-gate
   helper that was promoted into export.py) rather than
   `ssl_precedence.field_text()` alone, so the SHAPE of an unreadable state
   is available to name instead of discarded.
4. An unreadable/absent NAME field falls back to a POSITION, never a fixed
   "(naamloos)" literal - `names.py`'s own family reader set this precedent
   on the exact same resources and field.

THE MEMBER FILE IN BOTH SHAPES: `MEMBER_BINDING` is read through
`Export.binding_rows()` with `MEMBER_CHILD`. The real
`servicegroup_binding.by-parent.json` is written with shape 'aggregate'
(measured on the real collector output, 2026-09-02, and carried by the
synthetic DoH fixture); before the shared reader existed that
shape was a read gap here, so member-level storing detection did not work on
a real appliance. It does now, and the coverage statement is a real one.

`STORING_WORDS`/`COVERAGE_WORDS`: the closed vocabulary this module's two
judgments are built from, pinned in `tests/test_health.py` - the same
discipline every
sibling module already applies to its own verdict words
(`chain.CHAIN_WORDS`, `expiry.USAGE_WORDS`, `hidden_rules.RULE_WORDS`,
`ha.STATE_WORDS`, `collect.PHASE_WORDS`).
"""

from __future__ import annotations

from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.export import field_gap as _field_gap, safe_name_label as _safe_name_label
from nsmcp.knowledge import Knowledge
from nsmcp.ssl_precedence import field_text

# (label, resource, name field, state field). The labels are deliberately the
# same as names.py/overzicht.py ("one appliance, one vocabulary");
# `test_families_use_the_same_labels_as_overzicht_and_names`
# pins it. None of the labels sits inside another, or inside "storing"/
# "dekkingsuitspraak" - guarded by
# `test_no_family_label_sits_inside_another_or_inside_the_new_subjects`
# (disclosure.py replaces a masked subject by plain substring in 'beperkt').
FAMILIES = (
    ("Loadbalancing-vservers", "config/lbvserver", "name", "curstate"),
    ("Contentswitching-vservers", "config/csvserver", "name", "curstate"),
    ("Gateway-vservers", "config/vpnvserver", "name", "curstate"),
    ("Services", "config/service", "name", "svrstate"),
)
MEMBER_BINDING = "servicegroup_binding.by-parent.json"
MEMBER_CHILD = "servicegroup_servicegroupmember_binding"

# Recognized DOWN/fault tokens. "OUT OF SERVICE" is deliberately NOT here -
# see deviation 1 in the module docstring above.
_DOWN = ("DOWN", "GOING OUT OF SERVICE", "DOWN WHEN GOING OUT OF SERVICE")
# Recognized, established states that are NOT a storing: a confirmed "UP",
# and "OUT OF SERVICE" (an administrator's deliberate choice, not a fault -
# the parity rule this module exists to honour). "ENABLED" deliberately NOT
# here - see deviation 2 above. An appliance state outside BOTH tuples is
# not a favourable silence - `_classify_state` below routes it to
# "unreadable", a coverage gap, never a guess.
_NOT_DOWN = ("UP", "OUT OF SERVICE")

SNAPSHOT_LINE = "Dit is een momentopname uit de export, geen bewaking - dit is geen alarm."

# The closed vocabulary the "storing" finding is built from.
# Both words are already what this module's outcome
# text was built from before this constant existed - naming them here only
# makes that vocabulary a pinned, gated one instead of an inline literal a
# rename could drift past unnoticed (`tests/test_product_surface.py:518-525`
# states why, for `PHASE_WORDS`; the same reasoning applies here).
# `STORING_WORDS[0]` is the WHOLE outcome when nothing is down;
# `STORING_WORDS[1]` is the marker the DOWN-branch outcome is built around
# ("N object DOWN: ..."). Deliberately not a "storing: ..." prefix on that
# branch - the finding's own SUBJECT already reads "storing", and repeating
# the word there read as "storing: storing: ...". Both texts are exactly
# what this module rendered before this constant existed, on both branches -
# the real fixture never exercises the DOWN branch (measured: nothing is
# DOWN there), so this is unchanged either way.
STORING_WORDS = ("geen object DOWN gezien", "object DOWN")

# The closed vocabulary the "dekkingsuitspraak" finding is built from (same
# adjudication). Three established outcomes, each already what this
# module's outcome text was before this constant existed:
# `COVERAGE_WORDS[0]` when every state was read, `COVERAGE_WORDS[1]` when a
# source could not be read at all (a ReadGap), `COVERAGE_WORDS[2]` as the
# suffix of a count when specific rows were read but their state was not.
# Deliberately its own, differently-worded vocabulary rather than reusing
# `coverage.COVERAGE_WORDS` (a bare same-named import would collide, and
# that tuple answers a different question - whether the EXPORT AS A WHOLE
# was read, not whether these specific state FIELDS were).
COVERAGE_WORDS = ("elke stand is gelezen", "bronnen niet volledig gelezen", "object zonder leesbare stand")

NOT_ASSESSED = (
    NotAssessed(
        subject="doorlopende bewaking",
        reason=(
            "de live tellers van de appliance zitten niet in deze export; wat hier staat is"
            " de stand op het moment van de scan"
        ),
    ),
)


@dataclass(frozen=True)
class HealthAnswer(Answer):
    """An `Answer` whose rendered text OPENS with the data age, through
    `Answer._leading_lines()` rather than a `to_text()` override. No new
    fields: this exists only so `health_answer()` can opt into that seam
    without changing `Answer` itself for every other tool - see the seam's
    own docstring for why nothing else moves.
    """

    def _leading_lines(self) -> list[str]:
        return [self._data_age_line(), ""]


@dataclass(frozen=True)
class FamilyHealth:
    label: str
    resource: str
    measured: int = 0
    down: tuple[str, ...] = ()
    unreadable: tuple[str, ...] = ()
    gap: ReadGap | None = None
    # Additive: one "<label>: <field> draagt
    # <shape>" clause per entry of `unreadable` above, position-paired with
    # it - the VORM `_classify_state` established for that row, never the
    # raw value. `names.py:161-172`'s own per-row unreadable clause is the
    # precedent this follows.
    unreadable_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class HealthSnapshot:
    families: tuple[FamilyHealth, ...] = ()
    down: tuple[str, ...] = ()
    unreadable: tuple[str, ...] = ()
    gaps: tuple[ReadGap, ...] = ()
    # Additive, same reason as `FamilyHealth.unreadable_reasons` above -
    # the family-row clauses PLUS the member-row ones, position-paired with
    # `unreadable`.
    unreadable_reasons: tuple[str, ...] = ()


def _classify_state(row: dict, field: str) -> tuple[str, str | None]:
    """(state, shape) for one row's state field. `state` is exactly one of
    "down"/"not_down"/"unreadable" - never the raw value, and never a
    favourable classification for anything this version cannot positively
    confirm. `shape` is the VORM of the field
    when `state == "unreadable"`, None otherwise - it used to be computed by
    `field_gap` and then thrown away; now it travels with the classification
    so a caller can name it instead of only saying "unreadable".

    Goes through `export.field_gap()` first - the shared shape-gate helper
    that was promoted into export.py so this module would not need a third
    copy of it. `field_gap(..., required=True)` returns None ONLY when the
    field holds genuinely readable, non-empty text; a non-None result covers
    an absent key AND every unreadable shape (bool/int/list/dict/null/empty/
    whitespace) alike - both land in "unreadable" here, and `field_gap`'s
    own return value IS the shape clause, so no separate shape lookup is
    needed for that half.

    For text that IS genuinely readable but not a token this version
    recognizes, the binding rule stays "never the raw value echoed; the
    SHAPE is named" - unlike a NAME (`safe_name_label`), a STATE has a
    closed, small vocabulary, and an unrecognized value earns no exception
    to that rule just because it happens to look token-shaped. `VERZONNEN`
    (this module's own pinned "an unknown value is never echoed" case,
    `tests/test_health.py`) is named only by category, never repeated.
    """
    gap = _field_gap(row, field, required=True)
    if gap is not None:
        return "unreadable", gap
    text = field_text(row, field).upper()
    if text in _DOWN:
        return "down", None
    if text in _NOT_DOWN:
        return "not_down", None
    return "unreadable", "een waarde zonder de vorm van een herkende toestand"


def _row_label(row: dict, field: str, position: int) -> str:
    """The row's name when it is SAFE to echo verbatim on its own rendered
    line, "positie N (<shape>)" otherwise - through `export.safe_name_label`
    (see the module docstring's "TWO
    NAME-SAFETY DEFECTS" section). Never a fixed placeholder like
    "(naamloos)" either - `names.py`'s own family reader, on the exact same
    resources and field, already established the position-fallback
    precedent this follows.
    """
    return _safe_name_label(row, field, position)


def _one_family(export, label, resource, name_field, state_field) -> FamilyHealth:
    rows, gap = export.objects(resource)
    if gap is not None:
        return FamilyHealth(label=label, resource=resource, gap=gap)
    down: list[str] = []
    unreadable: list[str] = []
    unreadable_reasons: list[str] = []
    for position, row in enumerate(rows, start=1):
        name = _row_label(row, name_field, position)
        state, shape = _classify_state(row, state_field)
        if state == "down":
            down.append(name)
        elif state == "unreadable":
            unreadable.append(name)
            unreadable_reasons.append(f"{name}: {state_field} draagt {shape}")
        # "not_down" (a confirmed UP, or a deliberate OUT OF SERVICE):
        # recognized, not a fault, not counted anywhere - the same silence
        # overzicht.py gives a confirmed UP row.
    return FamilyHealth(
        label=label,
        resource=resource,
        measured=len(rows),
        down=tuple(down),
        unreadable=tuple(unreadable),
        unreadable_reasons=tuple(unreadable_reasons),
    )


def snapshot(export) -> HealthSnapshot:
    families = tuple(_one_family(export, *entry) for entry in FAMILIES)
    gaps = [family.gap for family in families if family.gap is not None]
    down: list[str] = []
    unreadable: list[str] = []
    unreadable_reasons: list[str] = []
    for family in families:
        down.extend(family.down)
        unreadable.extend(family.unreadable)
        unreadable_reasons.extend(family.unreadable_reasons)
    # Both shapes, through the shared reader: the real collector writes this
    # file as 'aggregate' (one document per servicegroup, the members under
    # MEMBER_CHILD); the list shape carries the member rows directly.
    grouped, member_gap = export.binding_rows(MEMBER_BINDING, children=(MEMBER_CHILD,))
    members = [row for pairs in grouped.values() if pairs for _kind, row in pairs]
    if member_gap is not None:
        gaps.append(member_gap)
    else:
        # A member is counted and
        # POSITIONED, never named - by position across all servicegroups, in
        # reading order. Measured: the lab fixture carries no member file (a
        # ReadGap); the synthetic DoH fixture carries one in the aggregate shape.
        for position, row in enumerate(members, start=1):
            label = f"positie {position}"
            state, shape = _classify_state(row, "svrstate")
            if state == "down":
                down.append(label)
            elif state == "unreadable":
                unreadable.append(label)
                unreadable_reasons.append(f"{label}: svrstate draagt {shape}")
    return HealthSnapshot(
        families=families,
        down=tuple(down),
        unreadable=tuple(unreadable),
        gaps=tuple(gaps),
        unreadable_reasons=tuple(unreadable_reasons),
    )


def health_answer(export, knowledge: Knowledge) -> Answer:
    result = snapshot(export)
    findings: list[Finding] = [
        Finding(
            subject="storing",
            outcome=(
                f"{len(result.down)} {STORING_WORDS[1]}: " + ", ".join(result.down) if result.down else STORING_WORDS[0]
            ),
            certainty=Certainty.ESTABLISHED,
            evidence=SNAPSHOT_LINE,
            subject_is_name=False,
        )
    ]
    for family in result.families:
        if family.gap is not None:
            findings.append(
                Finding(
                    subject=family.label,
                    outcome="niet beoordeeld",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=family.resource,
                    reason=family.gap.reason,
                    subject_is_name=False,
                )
            )
            continue
        base_outcome = f"{family.measured} gemeten, {len(family.down)} DOWN"
        if family.unreadable:
            # `names.py:161-172`'s own
            # precedent for the identical situation - any unreadable row
            # downgrades the WHOLE family finding to NOT_ESTABLISHED, named
            # by position and shape, never a count left standing as
            # `[vastgesteld]` over rows that were never actually read.
            findings.append(
                Finding(
                    subject=family.label,
                    outcome=f"{base_outcome}, {len(family.unreadable)} {COVERAGE_WORDS[2]}",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{family.resource}: {family.measured} objecten",
                    reason=f"{family.resource} - " + "; ".join(family.unreadable_reasons),
                    subject_is_name=False,
                )
            )
            continue
        findings.append(
            Finding(
                subject=family.label,
                outcome=base_outcome,
                certainty=Certainty.ESTABLISHED,
                evidence=f"{family.resource}"
                + (" - manifest: EMPTY" if not family.measured and export.status(family.resource) == "EMPTY" else ""),
                subject_is_name=False,
            )
        )
    # Each gap reason gets its SOURCE attributed
    # (`names.py:170`'s own precedent) - without it, several gaps with the
    # same reason text ("resource staat niet in het manifest van deze
    # export") concatenate identically and the reader cannot tell which
    # source each belongs to.
    coverage_reasons = [f"{gap.source}: {gap.reason}" for gap in result.gaps]
    if result.unreadable:
        coverage_reasons.append("; ".join(result.unreadable_reasons))
    findings.append(
        Finding(
            subject="dekkingsuitspraak",
            outcome=(
                f"{len(result.unreadable)} {COVERAGE_WORDS[2]}"
                if result.unreadable
                else (COVERAGE_WORDS[1] if result.gaps else COVERAGE_WORDS[0])
            ),
            certainty=Certainty.NOT_ESTABLISHED if (result.unreadable or result.gaps) else Certainty.ESTABLISHED,
            evidence=", ".join(f.resource for f in result.families) + f", {MEMBER_BINDING}",
            reason="; ".join(coverage_reasons),
            subject_is_name=False,
        )
    )
    return HealthAnswer(
        question="wat stond er DOWN op het moment van de scan",
        findings=findings,
        read_gaps=list(result.gaps),
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
