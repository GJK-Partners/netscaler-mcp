"""Which names does this appliance actually know - per family, with its age.

Why this exists (measured in a full agent session against 2.0.0, issue #11):
`status_overzicht` gives counts and no names, so the only way to LEARN a name
was to call `dienst_status` with a wrong one and read the candidate list out
of the refusal. That works, and it is an implicit trick that stands in no
tool description. An agent that does not know it either gets stuck on "which
name do I use" or starts inventing names.

This module adds no source and no verdict. It unlocks what already lies in
the export - and it applies the same three rules the rest of this product
applies:

1. An unreadable family is `niet beoordeeld`, never a list of zero. A list
   of zero reads as "there are none", which is a statement about the world.
2. A read emptiness (the manifest says EMPTY) IS an established zero, and it
   says on which source.
3. A row without a readable name is counted apart and makes the family
   line non-established - never silently dropped.

WHAT THIS MODULE DELIBERATELY DOES NOT DO, stated here so no reader has to
rediscover it: it builds NO file path out of supplied text. Every resource
key it reads is a module constant in `FAMILIES` below, so the hole the shape
gates in coverage.py exist for - a supplied manifest KEY becoming a file name
outside the export directory - has no counterpart here. The only SUPPLIED
strings this module puts into an answer are appliance object NAMES, and those
are the one carve-out of that discipline: they travel through the masking
seam, delivered to `disclosure.names_from_export()` by
`names_in_name_sources()` below. Everything else out of a row is named by its
SHAPE (`export.shape_of`) and by its POSITION, never by its value.
"""

from __future__ import annotations

from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.export import MISSING, shape_or_missing
from nsmcp.knowledge import Knowledge

# This module was the one whose own `row.get(field)`
# collapsed an ABSENT key with a JSON null into the same `None`, so
# `shape_of(None)` named both "een lege waarde (JSON null)" - a statement
# about CONTENT that cannot be made about a key that does not exist at all.
# It used to carry its own `_MISSING` sentinel for that (the same discipline
# export.py, ha.py, hidden_rules.py, impact.py and overzicht.py already
# drew); an earlier task consolidated all five copies into export.py, so this
# module now imports the shared sentinel and helper instead of defining its
# own.

# (label, resource, name field). The label is customer copy; the field is the
# PRIMARY name field of that resource, read at the same place the analysis
# modules read it (expiry.py reads "certkey", dienst.py reads
# "servicegroupname"). Deliberately a table: a seventh family is one line.
#
# The labels are written out in full and none of them sits inside another -
# guarded by a test, for the reason measured in overzicht.py: the disclosure
# seam replaces by plain substring.
FAMILIES = (
    ("Loadbalancing-vservers", "config/lbvserver", "name"),
    ("Contentswitching-vservers", "config/csvserver", "name"),
    ("Gateway-vservers", "config/vpnvserver", "name"),
    ("Servicegroups", "config/servicegroup", "servicegroupname"),
    ("Services", "config/service", "name"),
    ("Certificaten", "config/sslcertkey", "certkey"),
)


@dataclass(frozen=True)
class FamilyNames:
    """What one family of the table above yielded.

    `names` is DEDUPLICATED (a list that prints the same name twice helps
    nobody), `row_count` is not - and that difference is why the field
    exists. MEASURED on 2026-09-06 on a synthetic export whose
    `config/servicegroup` carried TWO rows with the same `servicegroupname`:
    the evidence line said `config/servicegroup: 1 objecten` under
    `[vastgesteld]` while the file carried two, and the second row left no
    trace at all - an untrue number on an established verdict, and a row
    silently gone. `row_count` is the number of rows the source really
    carried, and it is what the evidence line states; the printed LIST stays
    deduplicated.

    The field is APPENDED, with a default: `label`, `resource`, `names` and
    `gap` are the binding interface the comparison engine reads, and their
    order does not move.
    """

    label: str
    resource: str
    names: tuple[str, ...] = ()
    gap: ReadGap | None = None
    unreadable_rows: tuple[str, ...] = ()
    row_count: int = 0


def _label_finding(**fields) -> Finding:
    """A Finding whose subject is a family LABEL of this product, not an
    appliance object name. Same reason as overzicht._label_finding."""
    return Finding(subject_is_name=False, **fields)


def _one_family(export, label: str, resource: str, field: str) -> FamilyNames:
    rows, gap = export.objects(resource)
    if gap is not None:
        return FamilyNames(label=label, resource=resource, gap=gap)
    names: list[str] = []
    unreadable: list[str] = []
    for position, row in enumerate(rows, start=1):
        raw = row.get(field, MISSING)
        if isinstance(raw, str) and raw.strip():
            names.append(raw.strip())
        else:
            # The POSITION, never the value: a field that is not text is not a
            # name, and repeating it would put unmasked export content in
            # front of the model. An ABSENT key gets the ONE pinned
            # read-gap sentence (export.KEY_MISSING_TEXT), never the shape of
            # a JSON null it never carried - delegated to
            # `export.shape_or_missing`.
            shape = shape_or_missing(raw)
            unreadable.append(f"positie {position}: {field} draagt {shape}")
    return FamilyNames(
        label=label,
        resource=resource,
        names=tuple(sorted(set(names))),
        unreadable_rows=tuple(unreadable),
        row_count=len(rows),
    )


def names_by_family(export) -> tuple[FamilyNames, ...]:
    return tuple(_one_family(export, label, resource, field) for label, resource, field in FAMILIES)


def entity_names(export, knowledge: Knowledge) -> Answer:
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []
    for family in names_by_family(export):
        if family.gap is not None:
            read_gaps.append(family.gap)
            findings.append(
                _label_finding(
                    subject=family.label,
                    outcome="niet beoordeeld",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=family.resource,
                    reason=family.gap.reason,
                )
            )
            continue
        if not family.names and export.status(family.resource) == "EMPTY":
            findings.append(
                _label_finding(
                    subject=family.label,
                    outcome="0 namen",
                    certainty=Certainty.ESTABLISHED,
                    evidence=f"{family.resource} - manifest: EMPTY",
                )
            )
            continue
        listed = ", ".join(family.names)
        outcome = f"{len(family.names)} namen" + (f" - {listed}" if listed else "")
        if family.unreadable_rows:
            findings.append(
                _label_finding(
                    subject=family.label,
                    outcome=f"{outcome}, {len(family.unreadable_rows)} rij zonder leesbare naam",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{family.resource}: {family.row_count} objecten",
                    reason=f"{family.resource} - " + "; ".join(family.unreadable_rows),
                )
            )
            continue
        findings.append(
            _label_finding(
                subject=family.label,
                outcome=outcome,
                certainty=Certainty.ESTABLISHED,
                evidence=f"{family.resource}: {family.row_count} objecten",
            )
        )
    return Answer(
        question="welke namen kent deze NetScaler",
        findings=findings,
        read_gaps=read_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_name_sources(export) -> tuple[str, ...]:
    """Every appliance object name `entity_names()` can print - the EIGHTH
    family of disclosure.names_from_export().

    THE reason this family exists: this is the tool that prints entity names
    ON PURPOSE and UNCONDITIONALLY, so every name it can print must be
    maskable at `beperkt`/`minimaal`. It reads through `names_by_family()` -
    the very derivation `entity_names()` prints from (one source, two
    consumers) - so the collection here and the text there cannot drift
    apart. Fail-closed by construction: an unreadable source yields no names,
    and a name this export could not read can never reach a text either.

    MEASURED (2026-09-06, and it corrects the plan this module was built
    from, which expected `config/csvserver` and `config/vpnvserver` to be
    known to none of the seven families above): they ARE. Probed on
    single-resource synthetic exports, `cve.names_in_predicate_sources` reads
    FIVE of the six resources in `FAMILIES` through its reference rules
    (config/lbvserver, csvserver, vpnvserver, servicegroup, service), and the
    sixth, config/sslcertkey, is the first family. On
    tests/fixtures/lab-export-vpx-20260826 every one of the six names this
    tool prints is therefore already collected without this family.

    That does NOT make this family decoration, for two measured reasons:

    - The collections DIVERGE where the FIELDS diverge. This tool prints a
      servicegroup by its PRIMARY field `servicegroupname` (the field
      dienst.py reads); the cve harvest takes the first readable of its own
      field list and lands on `name`. A supplied row carrying both prints one
      name and masks the other - the leak, proven end to end in
      tests/test_names.py.
    - This is the ONLY family that reads through THIS tool's own derivation.
      A seventh line added to `FAMILIES` is masked the same day it is added;
      relying on cve.py's reference rules to happen to cover it is exactly
      the drift the "one source, two consumers" rule exists to prevent.

    Over-collecting is not free (see `coverage.names_in_coverage_sources` for
    that cost), but it is the right side of the trade: a name too few is a
    leak.
    """
    names: set[str] = set()
    for family in names_by_family(export):
        names.update(family.names)
    return tuple(sorted(names))
