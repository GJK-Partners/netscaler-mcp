"""One comparison engine, four uses. Mirrors NSHC's Invoke-NshcCompare.ps1.

    "Een engine, vier gebruiken (kies via -Mode label): HA-parity | drift |
     run-diff | pre/post"  (Invoke-NshcCompare.ps1, lines 9-10)

THE SEPARATION THIS MODULE EXISTS FOR - three kinds of difference, three
blocks, never mixed:

- CONFIGURATION: an object present on one side and not the other, a changed
  version, certificate binding, target, lb method or persistence.
- STATE: curstate and svrstate. At HA parity a state difference is NORMAL -
  the secondary node is not serving - and reporting it as a finding would
  bury the configuration difference that IS the point.
- COVERAGE: a source usable on one side and not on the other - or unusable
  on BOTH (see "EQUAL FAILURE" below). That is neither of the above: it says
  something about the two EXPORTS, not about the two appliances. Without
  this block a read gap on one side reads as drift, and an administrator
  goes looking for a change that never happened.

WHAT THIS CANNOT SAY: which of the two sides is "good". That is a human
judgement, and this answer does not pretend otherwise.

WHAT THIS ALSO CANNOT SAY: anything about a binding, a monitor, an SSL
profile, a policy or the running config - `COMPARED` below names exactly
which resources and fields are in scope, and `compare_answer()` says so in
its own `not_assessed`. An empty block is a statement about THAT scope, not
about the appliance's whole configuration.

EQUAL FAILURE IS NOT A SUCCESSFUL COMPARISON: a source unreadable on BOTH sides used to
disappear entirely - no coverage line (the asymmetry check `a_ok != b_ok`
is False when both fail the same way), no configuration/state line (the
resource is skipped), and the answer said "geen [vastgesteld]" three times
about two appliances it never actually compared. The coverage block below
therefore reports EVERY resource unreadable on AT LEAST ONE side - an
ESTABLISHED difference when only one side failed (a real, known fact: A
read, B did not), a NOT_ESTABLISHED one when both failed the same way (we
know only that neither side proves anything here). `SourceState.reason`
(coverage.py) travels with it either way - never the word alone.

A FOURTH KIND OF IGNORANCE THIS MODULE MUST NOT SWALLOW: a field that WAS
read but is not a plain, comparable value - a bool, a list, JSON null - is
neither "equal" nor "different". `_comparable()` below is this module's own gate for that
(a superset of `export.field_gap()`'s contract - see its docstring for
exactly where it widens it), and only a field that is comparable on BOTH
sides may become an ESTABLISHED equality or difference. Everything else
becomes a NOT_ESTABLISHED entry in the SAME block (configuration or state -
it is still about that field), named only by its SHAPE (`export.shape_of`),
never by the raw value. An earlier version compared fields with
`ssl_precedence.field_text()` alone, which returns "" for both "absent" and
"present but unreadable" alike - collapsing exactly the distinction this
product exists to keep apart (see export.py's module docstring: "an empty
list because there was nothing is a finding; an empty list because the read
failed is a read gap").

THE SUMMARY LINE MAY NEVER CLAIM MORE CERTAINTY THAN ITS OWN BLOCK HOLDS:
"N verschillen" or "geen" is an ESTABLISHED claim
about the WHOLE block, and a block that carries even one NOT_ESTABLISHED
entry, or that skipped a resource entirely (a read gap or an unreliable
identity - see below), cannot honestly make it. `compare_answer()` below
downgrades a block's own summary finding to NOT_ESTABLISHED the moment
either condition holds, with a reason naming how many fields/objects were
not established and how many resources were excluded - "geen [vastgesteld]"
is reserved for a block this answer could actually finish reading.

A PLAIN NUMBER IS NOT AN UNCLEAR SHAPE (MEASURED: `port` and
`publickeysize` are JSON ints on the real export -
`tests/fixtures/lab-export-vpx-20260826` - not strings, so comparing that
export with ITSELF through `field_gap()`/`field_text()` alone reported six
fields NOT_ESTABLISHED for no real reason). `_comparable()` therefore
accepts a non-bool `int` as readable too, rendered through `str()` - `bool`
is deliberately excluded even though `isinstance(x, int)` is True for it in
Python (`bool` subclasses `int`): `True`/`False` are not the kind of value
`port` carries, and letting a bool through this branch would swallow the
exact class of unclear value this module exists to catch.

An OPTIONAL FIELD simply absent on both sides is a real, honest EQUALITY,
never a gap (`required=False` for every configuration field - deliberate,
reviewed and kept: `persistencetype` on a vserver without persistence,
`targetlbvserver` on a csvserver without an explicit target, `port`/
`ipv46` on a row this product otherwise reads fine, are all legitimately
absent on a real appliance; treating that absence as unclear would turn an
ordinary configuration into a permanent NOT_ESTABLISHED). STATE fields keep
`required=True` (health.py's own `_classify_state` precedent: a real
vserver/service row always carries a curstate/svrstate, so its absence IS
a read problem, not a shape of appliance).

RESOURCE-LEVEL READ GAPS get the same discipline, structurally rather than
by rescue: `_index()` below is told, per resource, whether it is a genuine
LIST resource (`export.objects()`) or a genuine SINGLETON resource
(`export.single()`, `config/nsversion` - NITRO answers this one as a bare
object, not a list of one). An earlier version tried `objects()` first and
fell back to `single()` whenever it reported a gap - which cannot tell a
real singleton apart from a genuinely malformed list, because `single()`
fails identically on both (same underlying `_object_payload()` gap). Picking
the read path from a per-resource table instead removes the ambiguity: a
resource that was not read comes back with a real `ReadGap` and contributes
NO objects to either block - "elk niet gelezen bronbestand wordt een echte
ReadGap; vergelijk voor die bron geen objecten." That `ReadGap` travels into
`Answer.read_gaps` - `coverage_of()`'s own OK verdict only
proves the manifest hash matched, never that `objects()`/`single()` can make
SHAPE of the content (an object instead of a list, a non-object element, a
singleton with more than one row): a form gap behind an OK manifest status
is exactly as much a read failure as a manifest-level RBAC_DENIED, and this
module's own read produces its own gap instead of trusting the coverage
verdict for it.

IDENTITY ITSELF CAN BE UNRELIABLE: two objects with the
SAME name on one side, or a row whose name is not usable text, used to be
silently resolved by a plain dict comprehension (last one wins; an unnamed
row simply never entered the index) - a real difference could then hide
behind a name that was never checked for uniqueness. `_index()` below
reports both cases as their own NOT_ESTABLISHED entry in the configuration
block (subject = the resource, never a row that might not even be the one
the caller expects) and skips the rest of that resource's per-object
comparison - matching a rows a name cannot be trusted for.

Identity fields (which field names an object of each resource) are NOT
retyped here: they are read from `names.FAMILIES` - the same table
`names_by_family()` already builds the appliance's own name listing from -
so the two can never name an object differently. `config/nsversion` has no
name field of its own (there is exactly one row); it is added separately,
compared by its own `version` value.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.coverage import coverage_of
from nsmcp.export import KEY_MISSING_TEXT, shape_of
from nsmcp.knowledge import Knowledge
from nsmcp.names import FAMILIES as _NAME_FAMILIES
from nsmcp.ssl_precedence import field_text

# The four modes, pinned to the NSHC healthcheck's OWN labels (dispatch
# ruling, binding over the preflight's Dutch sample): parity with the tool
# this module mirrors, not a translation of it. The Dutch words this module
# used to accept as API values now live only in customer-facing prose (the
# tool description in mcp_server.py, the handleiding) - never in `MODES`
# itself, and never echoed as if they were still valid input.
MODES = ("HA-parity", "drift", "run-diff", "pre/post")

# The fields that count as CONFIGURATION and as STATE, per resource -
# additive to `names.FAMILIES` above, which already carries (label,
# resource, identity field) for the same six resources. Deliberately a
# table: a fifth resource's fields are one line, and its identity field
# still comes from ONE place (names.py), not a second copy here.
_FIELDS_BY_RESOURCE = {
    "config/lbvserver": (("servicetype", "lbmethod", "persistencetype", "port", "ipv46"), ("curstate",)),
    "config/csvserver": (("servicetype", "targetlbvserver", "port", "ipv46"), ("curstate",)),
    "config/vpnvserver": (("servicetype", "port", "ipv46"), ("curstate",)),
    "config/servicegroup": (("servicetype",), ("state",)),
    "config/service": (("servicetype", "port"), ("svrstate",)),
    "config/sslcertkey": (("linkcertkeyname", "publickeysize", "signaturealg"), ()),
}

# The compared configuration fields that NAME another appliance object: the
# default LB vserver of a csvserver and the issuer certificate a certificate
# is linked to. A difference line writes both values ("targetlbvserver:
# A=<naam>, B=<naam>") - also when the object named is absent from the
# export, and then no other family of `disclosure.names_from_export()` knows
# that name: MEASURED, it reached the answer of `rapport_vergelijk` and
# `rapport_wat_is_er_veranderd` verbatim at 'beperkt'. So these fields are
# harvested on their own (`names_in_compare_sources()`). Every other field
# in `_FIELDS_BY_RESOURCE` carries a value, not a name: a word of the
# appliance's own vocabulary (servicetype, lbmethod, persistencetype,
# signaturealg, the state fields), a number (port, publickeysize), an
# address (ipv46) or the build (version). tests/test_compare.py keeps that
# second list and fails on a compared field that is in neither.
REFERENCE_FIELDS = {
    "config/csvserver": ("targetlbvserver",),
    "config/sslcertkey": ("linkcertkeyname",),
}

# (resource, identity field, config fields, state fields, is a SINGLE
# object). The six list resources are built straight from
# `names.FAMILIES` so the identity field can never drift from the one
# `names_by_family()` itself reads; `config/nsversion` is the one resource
# outside that table (no separate name field - the version IS the subject),
# added on its own line.
COMPARED = tuple((resource, key, *_FIELDS_BY_RESOURCE[resource], False) for _, resource, key in _NAME_FAMILIES) + (
    ("config/nsversion", "version", ("version",), (), True),
)

# The full scope of COMPARED, in customer copy - what `compare_answer()`
# names in its own `not_assessed` so an empty block is never mistaken
# for "the whole configuration is identical".
_SCOPE_NOTE = (
    "vergeleken worden alleen loadbalancing-, contentswitching- en Gateway-vservers,"
    " servicegroups, services, certificaten en de NetScaler-versie, met hun eigen"
    " configuratie- en standvelden (zie compare.COMPARED); bindingen, monitors,"
    " SSL-profielen, policies en de running config vallen buiten dit antwoord - een"
    " leeg blok zegt daar niets over"
)

# The two `coverage.SourceState.word` values that mean "read into something
# usable" - the same pair `coverage._READ_WORDS` is built from. Kept as its
# own tuple rather than importing the private one: this module compares two
# EXPORTS against each other, coverage.py's compares sources within one.
_READABLE_WORDS = ("OK", "LEEG")

# The three words that mean a genuine coverage LOSS - the same set
# `coverage._verdict()` itself uses to decide "gedeeltelijk" (coverage.py's
# `_LOST_WORDS`). "OPTIONEEL AFWEZIG" (NOT_SUPPORTED) is deliberately NOT
# here, exactly as it is not there: a resource this collector version does
# not even attempt is not a read failure - MEASURED on the real fixture
# compared with itself, four such resources exist and would otherwise turn
# permanent, unresolvable noise into "niet vastgesteld" on every comparison
# ever made with this collector, burying the real signal (a genuine RBAC
# denial or hash mismatch) under a fixed background hum.
_LOST_WORDS = ("MISLUKT", "GEWEIGERD", "ONTBREEKT")

HA_PARITY_NOTE = (
    "standverschillen zijn bij HA-pariteit normaal: de secondary node bedient geen verkeer."
    " Het configuratieverschil is hier het punt."
)


class DifferenceKind(Enum):
    """Which of the three strictly separated blocks a `Difference` belongs
    to - never a fourth, and never inferred from its text."""

    CONFIGURATION = "configuratie"
    STATE = "stand"
    COVERAGE = "dekking"


@dataclass(frozen=True)
class Difference:
    kind: DifferenceKind
    subject: str
    detail: str
    # ESTABLISHED: `detail` states a real, read equality-or-difference (or,
    # for COVERAGE, a real asymmetry - one side read, the other not).
    # NOT_ESTABLISHED: either a field read but not usable text/number, an
    # unreliable identity for a whole resource, or (COVERAGE) a source
    # unusable on BOTH sides - `detail`/`reason` name only the SHAPE or the
    # underlying coverage reason, never a raw value; see the module
    # docstring's "fourth kind of ignorance" and "equal failure" sections.
    certainty: Certainty = Certainty.ESTABLISHED
    reason: str = ""
    # Is `subject` a real appliance object name (masked at 'beperkt'/
    # 'minimaal')? True for the six `names.FAMILIES` resources - False for
    # a coverage difference or an identity-issue difference (subject is a
    # RESOURCE KEY, this product's own vocabulary, exactly the class
    # `answer.Finding.subject_is_name` documents for cve.py/overzicht.py)
    # and for `config/nsversion` (subject is a version STRING, not an
    # object identity).
    subject_is_name: bool = True

    def __post_init__(self) -> None:
        if self.certainty is Certainty.NOT_ESTABLISHED and not self.reason.strip():
            raise ValueError("a not-established difference requires a reason")


@dataclass(frozen=True)
class ComparisonResult:
    mode: str
    configuration: tuple[Difference, ...] = ()
    state: tuple[Difference, ...] = ()
    coverage: tuple[Difference, ...] = ()
    # Real ReadGaps - a resource-level shape failure
    # `_index()` met while building configuration/state, one entry per
    # affected side ("<resource> (A)"/"(B)"). `compare_answer()` puts these
    # straight into `Answer.read_gaps`.
    gaps: tuple[ReadGap, ...] = ()
    # How many COMPARED resources were excluded from the configuration/
    # state block respectively - a real ReadGap OR an unreliable identity
    # both count, because both mean the same thing for that block:
    # this resource's comparison never happened. Used by `compare_answer()`
    # to decide whether a block's summary may still say "geen"/"N", or must
    # say "niet vastgesteld" instead.
    configuration_excluded: int = 0
    state_excluded: int = 0


def _index(export, resource: str, key: str, *, single: bool) -> tuple[dict[str, dict], ReadGap | None, tuple[str, ...]]:
    """Every object of `resource` on this side, indexed by its identity
    field; the `ReadGap` when this resource could not be read AT ALL (None
    otherwise); and, only for a genuine read, a tuple of Dutch identity-shape
    problems (duplicate identities, rows without a readable one) that make
    the index itself UNRELIABLE for this side even though the file read
    cleanly.

    `single` picks the read PATH structurally instead of trying `objects()`
    first and rescuing a shape mismatch through `single()` - see the module
    docstring for why that rescue cannot tell a real singleton apart from a
    genuinely malformed list.
    """
    if single:
        one, gap = export.single(resource)
        if gap is not None:
            return {}, gap, ()
        if one is None:
            return {}, None, ()  # an established emptiness, not a gap
        return {field_text(one, key) or resource: one}, None, ()
    rows, gap = export.objects(resource)
    if gap is not None:
        return {}, gap, ()
    by_name: dict[str, dict] = {}
    duplicate_names: set[str] = set()
    unreadable_rows = 0
    for row in rows:
        name = field_text(row, key)
        if not name:
            unreadable_rows += 1
            continue
        if name in by_name:
            duplicate_names.add(name)
        by_name[name] = row
    issues: list[str] = []
    if duplicate_names:
        issues.append(f"{len(duplicate_names)} naam/namen komt/komen dubbel voor: {', '.join(sorted(duplicate_names))}")
    if unreadable_rows:
        plural = "rij" if unreadable_rows == 1 else "rijen"
        issues.append(f"{unreadable_rows} {plural} zonder leesbare naam")
    return by_name, None, tuple(issues)


def _comparable(row: dict, field: str, *, required: bool) -> tuple[str, str | None]:
    """(text, gap) for one field of one row - the same all-or-nothing
    contract `export.field_gap()` has (`text` is "" exactly when `gap` is
    None too - a legitimate absence, never a gap when `required` is False;
    `gap` is a SHAPE, never a raw value, when it is not None), WIDENED by
    exactly one case: a plain (non-bool) `int` is readable, rendered
    through `str()` - see the module docstring's "a plain number is not an
    unclear shape". `bool` is checked BEFORE `int` on purpose (Python's
    `bool` subclasses `int`): a bool never takes the int branch.

    Kept local rather than widening `export.field_gap()` itself: that
    primitive is shared by headers.py/health.py, and neither of those
    reads a field this module widens - int support belongs to the one
    caller that measurably needs it, not to the shared gate every other
    caller also goes through.
    """
    lowered = field.lower()
    for key, raw in row.items():
        if not (isinstance(key, str) and key.lower() == lowered):
            continue
        if isinstance(raw, bool):
            return "", shape_of(raw)
        if isinstance(raw, int):
            return str(raw), None
        if isinstance(raw, str) and raw.strip():
            return raw.strip(), None
        return "", shape_of(raw)
    return ("", None) if not required else ("", KEY_MISSING_TEXT)


def names_in_compare_sources(export) -> tuple[str, ...]:
    """Every name a difference line can print out of a reference field
    (`REFERENCE_FIELDS`), on this one export - a family of
    `disclosure.names_from_export()`; the two compare tools pass that
    collection for both exports.

    Read the way `compare_exports()` reads them: the same resources through
    `export.objects()`, the field name matched case-insensitively as
    `_comparable()` matches it, the value stripped as it is printed. From
    EVERY row, also a row whose identity the comparison cannot trust (it
    then prints no field line for that resource), and every key that
    matches: collecting more than a line can print is the safe direction.
    Only text counts as a name, the discipline of every family - a number
    or another shape is never a NetScaler object name. Fail-closed like the
    others: an unreadable resource yields no names, and the comparison then
    writes no field line for it either."""
    names: set[str] = set()
    for resource, fields in REFERENCE_FIELDS.items():
        rows, gap = export.objects(resource)
        if gap is not None:
            continue
        wanted = {field.lower() for field in fields}
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key, raw in row.items():
                if isinstance(key, str) and key.lower() in wanted and isinstance(raw, str) and raw.strip():
                    names.add(raw.strip())
    return tuple(sorted(names))


def _field_difference(
    left_row: dict,
    right_row: dict,
    subject: str,
    field: str,
    *,
    required: bool,
    kind: DifferenceKind,
    subject_is_name: bool,
) -> Difference | None:
    """One field's comparison, or None when there is nothing to report.

    `required` is forwarded to `_comparable()` unchanged - state fields pass
    True (health.py's own `_classify_state` treats an absent curstate/
    svrstate as just as unreadable as a garbled one: a real vserver/service
    row always carries one), configuration fields pass False (many are
    legitimately absent, and absence on both sides is then a real, honest
    equality, never a gap - see the module docstring's "an optional field").

    Only when NEITHER side's field trips `_comparable()`'s gap does this
    compare the actual text - "alleen twee bruikbaar gelezen velden mogen
    een vastgesteld verschil of gelijkheid opleveren." Otherwise this
    becomes a NOT_ESTABLISHED entry naming only the shape(s) it returned -
    never the value, on EITHER side, even the readable one: mixing a real
    value with an unreadable sibling in one line would still let content
    leak past the shape-only rule for the unreadable side.
    """
    left_text, left_gap = _comparable(left_row, field, required=required)
    right_text, right_gap = _comparable(right_row, field, required=required)
    if left_gap is not None or right_gap is not None:
        return Difference(
            kind,
            subject,
            f"{field}: niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            reason=f"{field} - A: {left_gap or 'leesbaar'}, B: {right_gap or 'leesbaar'}",
            subject_is_name=subject_is_name,
        )
    if left_text == right_text:
        return None
    return Difference(
        kind,
        subject,
        f"{field}: A={left_text or '-'}, B={right_text or '-'}",
        subject_is_name=subject_is_name,
    )


def compare_exports(left, right, mode: str) -> ComparisonResult:
    if mode not in MODES:
        raise ValueError(f"onbekende vergelijkingsmodus {mode!r}; geldig is: {', '.join(MODES)}")
    configuration: list[Difference] = []
    state: list[Difference] = []
    coverage: list[Difference] = []
    gaps: list[ReadGap] = []
    configuration_excluded = 0
    state_excluded = 0

    # COVERAGE: every resource unreadable on AT LEAST ONE side -
    # an equal failure on both sides is reported too, as NOT_ESTABLISHED,
    # never silently skipped because the two sides happen to agree on
    # being unreadable.
    left_states = {s.resource: s for s in coverage_of(left).sources}
    right_states = {s.resource: s for s in coverage_of(right).sources}
    for resource in sorted(set(left_states) | set(right_states)):
        left_state, right_state = left_states.get(resource), right_states.get(resource)
        a = left_state.word if left_state else "ONTBREEKT"
        b = right_state.word if right_state else "ONTBREEKT"
        a_ok, b_ok = a in _READABLE_WORDS, b in _READABLE_WORDS
        if a_ok and b_ok:
            continue
        if a_ok == b_ok and not (a in _LOST_WORDS or b in _LOST_WORDS):
            # Both sides equally NOT read, and neither word is a genuine
            # loss (both "OPTIONEEL AFWEZIG", say) - this collector version
            # simply does not attempt the resource on either appliance, on
            # every comparison it will ever make. Not worth a line.
            continue
        a_reason = (left_state.reason if left_state else "") or "geen aanvullende reden"
        b_reason = (right_state.reason if right_state else "") or "geen aanvullende reden"
        if a_ok != b_ok:
            coverage.append(
                Difference(
                    DifferenceKind.COVERAGE,
                    resource,
                    f"A: {a}, B: {b}",
                    reason=f"A: {a_reason}; B: {b_reason}",
                    subject_is_name=False,
                )
            )
        else:
            coverage.append(
                Difference(
                    DifferenceKind.COVERAGE,
                    resource,
                    f"A: {a}, B: {b}",
                    certainty=Certainty.NOT_ESTABLISHED,
                    reason=f"beide kanten onleesbaar - A: {a_reason}; B: {b_reason}",
                    subject_is_name=False,
                )
            )

    for resource, key, config_fields, state_fields, single in COMPARED:
        left_rows, left_gap, left_issues = _index(left, resource, key, single=single)
        right_rows, right_gap, right_issues = _index(right, resource, key, single=single)
        if left_gap is not None or right_gap is not None:
            # A real read failure: everything here would come out as a
            # difference, and not one of them would be true. The coverage
            # block above already said so; this feeds Answer.read_gaps and
            # downgrades the affected block summaries instead.
            if left_gap is not None:
                gaps.append(ReadGap(source=f"{resource} (A)", reason=left_gap.reason))
            if right_gap is not None:
                gaps.append(ReadGap(source=f"{resource} (B)", reason=right_gap.reason))
            if config_fields:
                configuration_excluded += 1
            if state_fields:
                state_excluded += 1
            continue
        if left_issues or right_issues:
            # Identity itself is unreliable on at least one side - the
            # per-object comparison below would match rows by a name that
            # cannot be trusted, so it does not run for this resource.
            parts = []
            if left_issues:
                parts.append("A: " + "; ".join(left_issues))
            if right_issues:
                parts.append("B: " + "; ".join(right_issues))
            configuration.append(
                Difference(
                    DifferenceKind.CONFIGURATION,
                    resource,
                    "identiteit niet vastgesteld",
                    certainty=Certainty.NOT_ESTABLISHED,
                    reason="; ".join(parts),
                    subject_is_name=False,
                )
            )
            if config_fields:
                configuration_excluded += 1
            if state_fields:
                state_excluded += 1
            continue
        subject_is_name = not single
        for name in sorted(set(left_rows) | set(right_rows)):
            if name not in right_rows:
                configuration.append(
                    Difference(
                        DifferenceKind.CONFIGURATION,
                        name,
                        "aanwezig in A, niet in B",
                        subject_is_name=subject_is_name,
                    )
                )
                continue
            if name not in left_rows:
                configuration.append(
                    Difference(
                        DifferenceKind.CONFIGURATION,
                        name,
                        "aanwezig in B, niet in A",
                        subject_is_name=subject_is_name,
                    )
                )
                continue
            left_row, right_row = left_rows[name], right_rows[name]
            for field in config_fields:
                diff = _field_difference(
                    left_row,
                    right_row,
                    name,
                    field,
                    required=False,
                    kind=DifferenceKind.CONFIGURATION,
                    subject_is_name=subject_is_name,
                )
                if diff is not None:
                    configuration.append(diff)
            for field in state_fields:
                diff = _field_difference(
                    left_row,
                    right_row,
                    name,
                    field,
                    required=True,
                    kind=DifferenceKind.STATE,
                    subject_is_name=subject_is_name,
                )
                if diff is not None:
                    state.append(diff)
    return ComparisonResult(
        mode,
        tuple(configuration),
        tuple(state),
        tuple(coverage),
        tuple(gaps),
        configuration_excluded,
        state_excluded,
    )


def _block_finding(
    label: str,
    differences: tuple[Difference, ...],
    mode: str,
    note: str,
    *,
    excluded: int,
    unit: str,
) -> Finding:
    """The one summary line for a block ("- configuratieverschillen: N
    [vastgesteld]") - NOT_ESTABLISHED the moment the block itself
    cannot honestly claim otherwise: a NOT_ESTABLISHED entry inside it, or
    a resource excluded entirely (a read gap or an unreliable identity,
    `excluded`). Never counted a second time at 'minimaal'
    alongside the findings it summarizes (`counted_at_minimal=False`).
    """
    established = [d for d in differences if d.certainty is Certainty.ESTABLISHED]
    not_established_count = len(differences) - len(established)
    if not_established_count or excluded:
        parts = []
        if not_established_count:
            parts.append(f"{not_established_count} {unit} niet vastgesteld")
        if excluded:
            noun = "bron" if excluded == 1 else "bronnen"
            parts.append(f"{excluded} {noun} niet in de vergelijking meegenomen (leesgat of onbetrouwbare identiteit)")
        if note:
            parts.append(note)
        return Finding(
            subject=label,
            outcome="niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=f"modus {mode}",
            reason="; ".join(parts),
            subject_is_name=False,
            counted_at_minimal=False,
        )
    return Finding(
        subject=label,
        outcome=str(len(established)) if established else "geen",
        certainty=Certainty.ESTABLISHED,
        evidence=f"modus {mode}",
        reason=note,
        subject_is_name=False,
        counted_at_minimal=False,
    )


def compare_answer(left, right, knowledge: Knowledge, mode: str) -> Answer:
    result = compare_exports(left, right, mode)
    blocks = (
        ("configuratieverschillen", result.configuration, "", result.configuration_excluded, "veld/object(en)"),
        (
            "standverschillen",
            result.state,
            HA_PARITY_NOTE if mode == "HA-parity" else "",
            result.state_excluded,
            "veld/object(en)",
        ),
        (
            "dekkingsverschillen",
            result.coverage,
            "een bron die aan een kant niet gelezen is levert geen drift op",
            0,
            "bron(nen)",
        ),
    )
    findings: list[Finding] = []
    for label, differences, note, excluded, unit in blocks:
        findings.append(_block_finding(label, differences, mode, note, excluded=excluded, unit=unit))
        for difference in differences:
            findings.append(
                Finding(
                    subject=difference.subject,
                    outcome=difference.detail,
                    certainty=difference.certainty,
                    evidence=f"{label}, modus {mode}",
                    reason=difference.reason,
                    subject_is_name=difference.subject_is_name,
                )
            )
    return Answer(
        question=f"wat is het verschil tussen deze twee standen ({mode})",
        findings=findings,
        read_gaps=list(result.gaps),
        not_assessed=[
            NotAssessed(
                subject="welke van de twee standen goed is",
                reason="dat is een menselijk oordeel; dit antwoord noemt alleen het verschil",
            ),
            NotAssessed(
                subject="objecten en velden buiten deze vergelijking",
                reason=_SCOPE_NOTE,
            ),
        ],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def two_newest(export_dir: Path) -> tuple[Path | None, Path]:
    """(the previous export, the current one) for the run-diff shell that
    answers "what changed since the last scan".

    Returns `(None, export_dir)` when nothing was kept. The caller must then
    say "there is nothing to compare with" and NOT "no differences" - those
    two read the same to a hurried reader and mean the opposite (issue #28).

    No second sort here: `retention.newest_kept()` already IS this product's
    ranking of "the most recent kept scan" - ranked by each kept sibling's
    OWN manifest `collectedAtUtc`, not by its directory name. A second sort
    in this module could rank differently and the two doctrines would
    silently disagree about which export is "newest". Imported INSIDE the
    function on purpose: `retention.py` does not know about `compare.py`,
    and a module-level import here could tempt that direction to reverse
    itself the day one of the two grows.
    """
    from nsmcp.retention import newest_kept

    return newest_kept(export_dir), export_dir
