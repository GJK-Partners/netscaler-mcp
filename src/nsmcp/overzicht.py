"""One screen: which build, which HA situation, how many virtual servers are up.

Everything comes from the export, every line carries its source, and nothing
is counted that was not read. Three rules do the work here, and each of them
exists because its absence produced a false green in the first version:

1. An unreadable source never yields a number. "0, waarvan 0 UP" out of a
   source that was never read is a claim, not a count - so a read gap gives a
   NOT_ESTABLISHED line AND a ReadGap on the answer (which makes
   `is_complete()` False), never zeros.
2. Virtual servers do not live in one resource. `config/lbvserver` is one
   family out of four; an appliance with no lbvserver at all but two Gateway
   vservers is not an appliance with "0 virtuele servers". Every family is
   read, counted and reported on its own line, so one unreadable family never
   silences the other three.
3. A value only means something if this version knows it. `hastatus`, `state`
   and a vserver's `curstate` pass a vocabulary gate before they are believed
   - the same discipline as `dienst._member_state`. An unknown value makes
   the line NOT_ESTABLISHED, and a value that does not even have the shape of
   a state token is NOT repeated in the text (it would reach the model
   unmasked in the 'beperkt' disclosure setting).
"""

from __future__ import annotations

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap, repeatable_token
from nsmcp.cve import build_echo, parse_build
from nsmcp.export import MISSING as _MISSING, shape_of, shape_or_missing
from nsmcp.knowledge import Knowledge

RESOURCE = "config/hanode"
VERSION_RESOURCE = "config/nsversion"

# The vserver families this version counts, in reporting order: (label, resource).
# Deliberately a table and not four copies of the same block - a fifth family
# is then one line here plus one line in NOT_ASSESSED below, and it cannot
# arrive with a differently-shaped fail-closed branch.
# The labels are deliberately written out in full instead of the shorter
# "LB-"/"CS-": in the beperkt setting disclosure.py collects every finding
# SUBJECT into its replacement set and replaces by plain substring, so a label
# sitting INSIDE another label mutilates that other line. MEASURED on the
# first fix: with "LB-vservers" as a subject, the not-assessed line
# "GSLB-vservers" came out as "GSobject-07". No label may therefore sit inside
# another label, inside "GSLB-vservers", or inside "build"/"HA" - guarded by
# tests/test_overzicht.py::test_no_label_sits_inside_another_label. (That
# labels are masked at all is a disclosure.py question and stays open there;
# this module simply does not hand it a collision.)
VSERVER_FAMILIES = (
    ("Loadbalancing-vservers", "config/lbvserver"),
    ("Contentswitching-vservers", "config/csvserver"),
    ("Gateway-vservers", "config/vpnvserver"),
    ("AAA-vservers", "config/authenticationvserver"),
)

# What this overview deliberately does NOT look at. Silence about it would
# read as "there are none of those" - which is exactly the kind of statement
# this product does not make without a read.
NOT_ASSESSED = (
    NotAssessed(
        subject="GSLB-vservers",
        # Names the RESOURCES, not the family labels: a label repeated here
        # would be replaced by that family pseudonym in the beperkt setting
        # (measured: "... en AAA-vservers" came out as "... en object-01"),
        # and a resource path carries none of the collected names.
        reason=(
            "deze versie leest alleen config/lbvserver, config/csvserver,"
            " config/vpnvserver en config/authenticationvserver;"
            " config/gslbvserver wordt niet gelezen en dus ook niet meegeteld"
        ),
    ),
)

# The vocabulary gates. MEASURED on the lab export
# (tests/fixtures/lab-export-vpx-20260826) and completed from the NITRO
# reference for hanode/vserver state fields; deliberately a closed set, so an
# unknown value produces "niet vastgesteld" instead of a green line about a
# word this version does not understand. Extending them is future work, with
# a measurement per added token - not a guess.
HA_STATUSES = (
    "UP",
    "DOWN",
    "NOT UP",
    "STAYPRIMARY",
    "STAYSECONDARY",
    "DISABLED",
    "PARTIAL FAIL",
    "PARTIALLY UP",
    "INIT",
    "UNKNOWN",
)
HA_STATES = ("Primary", "Secondary", "Standalone", "Unknown", "Claiming primary")
# A vserver's OPERATIONAL state. `curstate` is the field the real rows carry
# (measured: objects/vpnvserver.json), while their `state` says "ENABLED" -
# the ADMIN state, a different question. `effectivestate` is accepted only
# when `curstate` is absent altogether.
VSERVER_STATES = (
    "UP",
    "DOWN",
    "OUT OF SERVICE",
    "GOING OUT OF SERVICE",
    "DOWN WHEN GOING OUT OF SERVICE",
    "PARTIAL-UP",
    "UNKNOWN",
    "BUSY",
    "DISABLED",
)

# The sentinel that separates "the key is not there" from "the key carries a
# JSON null" - the same distinction, and the same wording ("de sleutel
# ontbreekt"), that `export.shape_or_missing` draws directly (`_ha_node`
# below calls it on the raw value it already fetched). `_known` below has
# its own, different vocabulary-gate wording and is unrelated. The sentinel
# itself is the shared `export.MISSING` object (imported above as
# `_MISSING`), never a second `object()` for the same meaning.


# The SHAPE of a state token, used ONLY to decide whether an UNKNOWN value may
# be repeated in the answer. The guarantee it gives: what is echoed is at most
# four UPPERCASE words of letters, digits and hyphens, separated by single
# spaces, together at most 32 characters. Everything else is refused AND not
# reproduced - only its shape is named.
#
# MEASURED on the first fix, which allowed any casing and any number of words:
# `hastatus = "IGNORE ALL PREVIOUS ORDERS NOW"` (five words, 30 characters)
# passed that test and was echoed verbatim into the reason, and thus into the
# model context. A NITRO state token is uppercase and short; a sentence is
# neither. The shape test is `answer.repeatable_token`, shared with dienst.py
# and impact.py; this vocabulary needs the hyphen ("PARTIAL-UP") and no
# underscore.
def _repeatable(value: str) -> bool:
    return repeatable_token(value, allow_underscore=False) is not None


def _label_finding(**fields) -> Finding:
    """A Finding whose SUBJECT is not an appliance object name.

    This module writes exactly six subjects, and all six are labels of this
    product: "build", "HA" and the four vserver family labels. The disclosure
    seam collects every finding subject as a name to mask, so in 'beperkt'
    they came out as "object-07" - "- object-07: 0 [vastgesteld]" says
    nothing - and they landed in the operator's pseudonym table as real
    object names. Worse, because the replacement is a plain substring pass,
    a masked label also mutilated the not-assessed line that mentions it
    ("GSLB-vservers" -> "GSobject-07").

    The appliance names this module DOES print - the HA node name in the HA
    finding's outcome - are still masked: they travel through
    `names_in_overview_sources()` into the seam's extra names, not through a
    subject. See `Finding.subject_is_name` (answer.py).
    """
    return Finding(subject_is_name=False, **fields)


def _objects_text(count: int) -> str:
    """Customer copy, so no broken plural - the rule of `answer._days_old`."""
    return "1 object" if count == 1 else f"{count} objecten"


def _known(raw, field: str, vocabulary: tuple[str, ...]) -> tuple[str | None, str | None]:
    """(value, reason) for a field with a closed vocabulary.

    `reason` is None when the value is established; otherwise it says why it
    is not - and it names the refused value only when that value has the shape
    of a state token.
    """
    if raw is _MISSING:
        return None, f"{field} ontbreekt"
    if not isinstance(raw, str) or not raw.strip():
        return None, f"{field} draagt {shape_of(raw)} in plaats van een toestand"
    value = raw.strip()
    folded = value.casefold()
    for token in vocabulary:
        if token.casefold() == folded:
            # The token of the VOCABULARY, not the casing this export happened
            # to use: one spelling per state in the text, so a reader can
            # never read a distinction into it that this version does not
            # make ("up" and "UP" are the same state).
            return token, None
    known = ", ".join(vocabulary)
    if _repeatable(value):
        return None, f"{field} draagt {value}, geen van de waarden die deze versie kent ({known})"
    return None, (f"{field} draagt een waarde zonder de vorm van een toestand; bekend zijn: {known}")


def _ha_node(row: dict, position: int) -> tuple[str | None, str | None]:
    """('<name> (<state>, <hastatus>)', None) or (None, reason).

    Every field passes the gate before the node is described at all: a node
    line is a statement about a real appliance, and half a statement ("N1 (?,
    UP)") would be a claim about a field that was not read.
    """
    name = row.get("name", _MISSING)
    if not isinstance(name, str) or not name.strip():
        shape = shape_or_missing(name)
        return None, f"rij {position} draagt geen leesbare naam ({shape})"
    state, reason = _known(row.get("state", _MISSING), "state", HA_STATES)
    if reason is not None:
        return None, f"rij {position}: {reason}"
    status, reason = _known(row.get("hastatus", _MISSING), "hastatus", HA_STATUSES)
    if reason is not None:
        return None, f"rij {position}: {reason}"
    return f"{name.strip()} ({state}, {status})", None


def _build_finding(export) -> tuple[Finding, ReadGap | None]:
    # The REAL collector writes config/nsversion as one OBJECT, not as a list
    # (measured on tests/fixtures/lab-export-vpx-20260826/objects/nsversion.json,
    # the same shape cve.py's parse_build() reads); `single()` reads exactly
    # that shape, and also accepts the list-of-one shape a caller-built
    # fixture may use.
    row, gap = export.single(VERSION_RESOURCE)
    if gap is not None:
        # An unreadable source and an unparsable version string are two
        # different statements: the reason must not say "no recognizable
        # NS<branch>" about a file that was never read.
        return _label_finding(
            subject="build",
            outcome="niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=VERSION_RESOURCE,
            reason=gap.reason,
        ), gap
    text = str(row.get("version", "")) if row else ""
    parsed = parse_build(text)
    # Only what `build_echo()` allows travels into the evidence - never the
    # raw version string. It is free text out of the export that the
    # disclosure layer's name collection does not read, so anything repeated
    # here reaches the model unmasked (see build_echo in cve.py).
    if parsed:
        return _label_finding(
            subject="build",
            outcome=f"{parsed[0]}-{parsed[1][0]}.{parsed[1][1]}",
            certainty=Certainty.ESTABLISHED,
            evidence=f"{VERSION_RESOURCE}: {build_echo(text)}",
        ), None
    return _label_finding(
        subject="build",
        outcome="niet te lezen",
        certainty=Certainty.NOT_ESTABLISHED,
        evidence=f"{VERSION_RESOURCE}: {build_echo(text)}",
        reason="geen herkenbare NS<tak>: Build <x>.<y>",
    ), None


def _ha_finding(export) -> tuple[Finding, ReadGap | None]:
    """The HA line - and never a word about a partner that was not read.

    One row is a positive read of ONE node, so it is ESTABLISHED - but it says
    "geen partner in config/hanode", not "HA: UP". The old text turned a
    standalone appliance into an up HA pair, which is the one sentence an
    operator must never read from this product without a second node in the
    source.
    """
    nodes, gap = export.objects(RESOURCE)
    if gap is not None:
        return _label_finding(
            subject="HA",
            outcome="niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=RESOURCE,
            reason=gap.reason,
        ), gap
    if not nodes:
        evidence = f"{RESOURCE} - manifest: EMPTY" if export.status(RESOURCE) == "EMPTY" else f"{RESOURCE}: 0 objecten"
        return _label_finding(
            subject="HA",
            outcome="geen node gemeld",
            certainty=Certainty.ESTABLISHED,
            evidence=evidence,
        ), None
    evidence = f"{RESOURCE}: {_objects_text(len(nodes))}"
    if len(nodes) > 2:
        return _label_finding(
            subject="HA",
            outcome="niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=evidence,
            reason=(
                f"{RESOURCE} draagt {len(nodes)} nodes; deze versie kent alleen een enkele node of een paar van twee"
            ),
        ), None
    # EVERY row is analysed, not only [0]: a second row that cannot be read
    # must not be able to hide behind a readable first one.
    described: list[str] = []
    for position, row in enumerate(nodes, start=1):
        text, reason = _ha_node(row, position)
        if reason is not None:
            return _label_finding(
                subject="HA",
                outcome="niet vastgesteld",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=evidence,
                reason=f"{RESOURCE}: {reason}",
            ), None
        described.append(text or "")
    if len(described) == 1:
        outcome = f"geen partner in {RESOURCE}; eigen node {described[0]}"
    else:
        outcome = f"paar - {described[0]} / {described[1]}"
    return _label_finding(
        subject="HA",
        outcome=outcome,
        certainty=Certainty.ESTABLISHED,
        evidence=evidence,
    ), None


def _vserver_state(row: dict) -> tuple[str | None, str | None]:
    """(state, reason) for one vserver row. `curstate` first; `effectivestate`
    only when `curstate` is absent altogether - a present-but-unusable
    `curstate` is a read problem, not an invitation to look elsewhere."""
    raw = row.get("curstate", _MISSING)
    field = "curstate"
    if raw is _MISSING:
        raw = row.get("effectivestate", _MISSING)
        field = "effectivestate"
        if raw is _MISSING:
            return None, "geen curstate en geen effectivestate"
    return _known(raw, field, VSERVER_STATES)


def _family_finding(export, label: str, resource: str) -> tuple[Finding, ReadGap | None]:
    rows, gap = export.objects(resource)
    if gap is not None:
        return _label_finding(
            subject=label,
            outcome="niet vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence=resource,
            reason=gap.reason,
        ), gap
    if not rows and export.status(resource) == "EMPTY":
        # A read emptiness: the manifest says this source was read and carried
        # nothing. That is an established zero, and it says on what.
        return _label_finding(
            subject=label,
            outcome="0",
            certainty=Certainty.ESTABLISHED,
            evidence=f"{resource} - manifest: EMPTY",
        ), None
    up = 0
    unreadable: list[str] = []
    for position, row in enumerate(rows, start=1):
        state, reason = _vserver_state(row)
        if reason is not None:
            unreadable.append(f"positie {position}: {reason}")
        elif state is not None and state.strip().upper() == "UP":
            up += 1
    outcome = f"{len(rows)}, waarvan {up} UP"
    if not unreadable:
        return _label_finding(
            subject=label,
            outcome=outcome,
            certainty=Certainty.ESTABLISHED,
            evidence=f"{resource}: {_objects_text(len(rows))}",
        ), None
    # A row whose state cannot be read is NEVER silently counted as not-UP:
    # it is counted apart, and it makes the whole line non-established - the
    # number of UP servers is then a lower bound, not a measurement.
    return _label_finding(
        subject=label,
        outcome=f"{outcome}, {len(unreadable)} toestand niet leesbaar",
        certainty=Certainty.NOT_ESTABLISHED,
        evidence=f"{resource}: {_objects_text(len(rows))}",
        reason=f"{resource} - " + "; ".join(unreadable),
    ), None


def overview(export, knowledge: Knowledge) -> Answer:
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []
    for finding, gap in (
        _build_finding(export),
        _ha_finding(export),
        *(_family_finding(export, label, resource) for label, resource in VSERVER_FAMILIES),
    ):
        findings.append(finding)
        if gap is not None:
            read_gaps.append(gap)
    return Answer(
        question="hoe staat de NetScaler ervoor",
        findings=findings,
        read_gaps=read_gaps,
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_overview_sources(export) -> tuple[str, ...]:
    """Every appliance object name `overview()` can print - the sixth family
    of `disclosure.names_from_export()`.

    MEASURED (2026-09-02, on the real export
    tests/fixtures/lab-export-vpx-20260826): `overview()` writes the HA node
    name straight into the "HA" finding ("eigen node host-006.lab.example (Primary,
    UP)" on that export). That name appears in none of the five families
    `names_from_export()` already reads (it is not a certkey, not an
    sslvserver binding, not a binding-parent name, not a Gateway/AAA/SAML/LSN
    predicate name, and not an lbvserver/servicegroup/member name) - so
    without this family the very line that makes the HA finding honest would
    leak the real node name in the 'beperkt' disclosure setting. Confirmed
    with an INTEGRATION test in tests/test_disclosure.py that proves the
    premise (the name sits in the FULL-disclosure text) before asserting its
    absence in LIMITED.

    Reads every hanode row present. `overview()` itself prints at most two
    (and none at all above two), but over-collecting is harmless - a name too
    many is a replacement that never fires - while a name too few is a leak.

    The vserver families need no entry here: `overview()` counts them and
    never names them. Their read-gap reasons name a POSITION ("positie 2"),
    deliberately not a name, so nothing out of those files travels into the
    text unmasked.

    Fail-closed by construction, exactly like the other five families: a
    source that cannot be read yields no names, and a name this export never
    read can never reach a text either.
    """
    names: set[str] = set()
    rows, _ = export.objects(RESOURCE)
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())
    return tuple(sorted(names))
