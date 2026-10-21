"""The rules only a seasoned administrator knows - as declarative checks.

Mirrors backend/hiddenrules/NshcHiddenRules.ps1 of GJK NetScaler Healthcheck
1.0.1: 29 rules with stable IDs NSHC-HR-<DOMAIN>-NNN, 16 high and 13 medium
(MEASURED against that PowerShell source itself - the design table's older
draft says 14/15). Every rule carries the SAME id, the SAME
severity and the SAME whyItMatters FIRST SENTENCE as its NSHC counterpart
(two exceptions noted at NSHC-HR-LB-001 and NSHC-HR-RW-001 below);
tests/test_parity_nshc.py fails as soon as either side moves (design 1.3,
requirements 5 and 6).

FAIL-CLOSED PER RULE, exactly as NSHC does it at check level:
- a required source that could not be read usably -> `niet beoordeeld`. The
  rule cannot count as healthy: the source data was unreadable.
- a required source that was read and is legitimately empty -> `niet geraakt`.
  There is nothing to judge, and that is a positive read, not a gap. NSHC
  calls that SKIPPED; this product has three words, so the NSHC status
  travels in the evidence instead of inventing a fourth word.
- all required sources read -> run the detect.

WHAT THESE RULES DO NOT PROVE: they read configuration fields, not behaviour.
"Spillover without a backup vserver" says the configuration is like that, not
that a connection was dropped today.

CATALOG measured: 22 unique config/ resources plus 1 binding file
(`sslvserver_sslcertkey_binding.by-parent.json`) - not the plan's "21
config-resources plus 2 bindingsbestanden";
`service_binding.by-parent.json` does not exist on the real export. See
tests/test_hidden_rules.py::test_the_catalog_needs_twenty_two_config_resources_and_one_binding_file.

VOCABULARY correction on the plan (spec 2.1.1 is binding, not the plan text):
the confidence word for a finding is one of exactly FOUR rungs - `hoog` /
`gemiddeld` / `laag` / `niet vastgesteld` - mapping `high` / `medium` / `low`
/ `none`. NSHC itself writes `beperkt` in one place for the `medium` rung
(same rung, different word); this product accepts that spelling as INPUT and
always PRINTS `gemiddeld`. An unrecognized rung is a read gap and becomes
`niet vastgesteld` - never a `.get(x, "beperkt")`-style default landing on a
MORE FAVORABLE word than what was actually established (hardening rule 6).
See `_confidence_word()` below - the one place this decision is made.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, repeatable_token
from nsmcp.export import MISSING as _MISSING, shape_or_missing
from nsmcp.knowledge import Knowledge
from nsmcp.rulesets import HIDDEN_RULES, ruleset_line
from nsmcp.ssl_precedence import field_text, field_token, profile_index, resolve

RULE_WORDS = ("geraakt", "niet geraakt", "niet beoordeeld")

# How an NSHC check status maps onto this product's three words. Pinned by
# tests/test_parity_nshc.py so the mapping is a decision, not an accident.
NSHC_STATUS_TO_WORD = {
    "FINDING": "geraakt",
    "PASS": "niet geraakt",
    "SKIPPED": "niet geraakt",
    "NOT_ASSESSABLE": "niet beoordeeld",
    "ERROR": "niet beoordeeld",
}

SEVERITY_WORDS = {"high": "hoog", "medium": "midden"}

# The confidence vocabulary, spec 2.1.1: FOUR rungs, `high`/`medium`/`low`/
# `none` mapping onto `hoog`/`gemiddeld`/`laag`/`niet vastgesteld`. `beperkt`
# is accepted as an INPUT alias for `medium` (the spelling NSHC itself uses
# in one place for the same rung; see spec 2.1.1's own note) and always
# PRINTS as `gemiddeld` - never as `beperkt`, which is not a word of this
# product's vocabulary.
CONFIDENCE_WORDS = {
    "high": "hoog",
    "medium": "gemiddeld",
    "beperkt": "gemiddeld",
    "low": "laag",
    "none": "niet vastgesteld",
}


def _confidence_word(confidence: str) -> str:
    """The confidence word for `confidence`, fail-closed.

    THE one place this mapping happens - so a rung added tomorrow (or a typo
    in a detect function) cannot silently print a MORE FAVORABLE word than
    what was actually established. `CONFIDENCE_WORDS.get(x, "beperkt")` was
    the plan's original text and is precisely the defect hardening rule 6
    names: an unrecognized key would have landed on a word that reads as an
    actual (if modest) assessment. The fail-closed default here is
    `"niet vastgesteld"` - already the LEAST favorable rung in this
    vocabulary, so an unknown value reads exactly as what it is: nothing was
    established, loudly, not a quiet "gemiddeld".
    """
    return CONFIDENCE_WORDS.get(confidence, "niet vastgesteld")


BINDING_CERTKEY = "sslvserver_sslcertkey_binding.by-parent.json"


@dataclass(frozen=True)
class Hit:
    instance: str
    evidence: str
    confidence: str = "high"
    confidence_reason: str = ""
    not_assessable: bool = False
    # Every name/address this hit's OWN evidence supplies - not the
    # instance (that is covered separately by `Rule.instance_is_name`), but
    # a SECOND name that lives only in the evidence string (a bound
    # profile's name, an action a policy points at, a syslog destination
    # address, a certkey bound to a vserver). None of the ten disclosure
    # families read evidence text, so a name that only ever appears here
    # would otherwise reach `beperkt`/`minimaal` verbatim. Filled by the
    # detect that puts the name in the evidence; harvested by
    # `names_in_hidden_rule_sources()` below, unconditionally (unlike the
    # instance, this is never a product-vocabulary label - a detect must
    # only ever put a REAL appliance name/address in here).
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    requires: tuple[str, ...]
    why: str
    detect: Callable[[Context], list[Hit]]
    instance_is_name: bool = True


@dataclass(frozen=True)
class Outcome:
    word: str
    hits: tuple[Hit, ...] = ()
    # The not-assessable hits carried ALONGSIDE `hits` when a rule has
    # BOTH real and blocked hits (word stays "geraakt" - a real violation
    # outranks an unresolved object, same as NSHC's realHits/naHits split).
    # Kept separate from `hits` so the weakest-confidence computation for
    # "zekerheid" only ever looks at REAL hits, exactly like NSHC's
    # `$confs = @($realHits | ...)` - a blocked object's confidence
    # describes the unresolved READ, not the violation, and must never pull
    # the printed confidence down (or up).
    blocked_hits: tuple[Hit, ...] = ()
    evidence: str = ""
    reason: str = ""


class Context:
    """The read layer the detects work on. One export, one pass per source."""

    def __init__(self, export) -> None:
        self.export = export
        self._rows: dict[str, tuple[list[dict], ReadGap | None]] = {}

    def read(self, resource: str) -> tuple[list[dict], ReadGap | None]:
        if resource not in self._rows:
            if resource.endswith(".by-parent.json"):
                self._rows[resource] = self.export.bindings(resource)
            else:
                rows, gap = self.export.objects(resource)
                if gap is not None:
                    # A singleton resource (nsparam, sslparameter, ...) is one
                    # OBJECT, not a list of one - `objects()` rightly refuses
                    # that shape, so try the singleton road before calling it
                    # a gap. Same two shapes `single()` documents.
                    one, single_gap = self.export.single(resource)
                    if single_gap is None:
                        self._rows[resource] = ([one] if one else [], None)
                        return self._rows[resource]
                self._rows[resource] = (rows, gap)
        return self._rows[resource]

    def rows(self, resource: str) -> list[dict]:
        return [row for row in self.read(resource)[0] if isinstance(row, dict)]

    def one(self, resource: str) -> dict | None:
        rows = self.rows(resource)
        return rows[0] if rows else None

    def gap(self, resource: str) -> ReadGap | None:
        return self.read(resource)[1]

    def status(self, resource: str) -> str:
        if resource.endswith(".by-parent.json"):
            return "OK" if self.gap(resource) is None else "MISLUKT"
        return self.export.status(resource)


def _num(row: dict, field: str) -> int | None:
    """The whole number at `field`, case-insensitively, or None.

    A bool is NOT a number here (True would silently become 1 and make a
    timeout of 0 look set). Same fail-closed discipline as expiry._to_days.
    """
    if not isinstance(row, dict):
        return None
    lowered = field.lower()
    for key, raw in row.items():
        if not isinstance(key, str) or key.lower() != lowered:
            continue
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str):
            try:
                return int(raw.strip())
            except ValueError:
                return None
        return None
    return None


def _raw_field(row: dict, field: str):
    """The raw value at `field`, case-insensitively, or _MISSING if absent.

    Does a case-insensitive key lookup on the row dict and returns the raw
    value as stored (which may be None, a number, a boolean, a list, a string,
    or any JSON type), exactly mirroring the pattern from _num() but without
    type conversion. Returns the _MISSING sentinel if the key is not found,
    to distinguish "key absent" from "key carries JSON null".
    """
    if not isinstance(row, dict):
        return _MISSING
    lowered = field.lower()
    for key, raw in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            return raw
    return _MISSING


def _shape_or_missing(container: dict, field: str) -> str:
    """Names what is at `field`: absent key, or the shape of what is there.

    Delegates to `export.shape_or_missing` (the shared consolidation of
    what used to be this module's own copy of the idiom) on the raw value
    `_raw_field` already resolved case-insensitively - `_raw_field` alone
    cannot tell "the key is not present" from "the key carries JSON null"
    apart, since both would otherwise produce the same None value.
    """
    return shape_or_missing(_raw_field(container, field))


def _is(value: str, *words: str) -> bool:
    return value.strip().upper() in words


def _gate(row: dict, field: str, *words: str) -> tuple[bool, str | None]:
    """The one three-way read every closed-vocabulary field in this module
    goes through: `matched` is True when
    the value at `field` is one of `words` (the same strip/upper rule
    `_is()` always used); `unreadable_evidence` is None whenever the raw
    value is a genuine STRING - even an empty one, and even one that is not
    one of `words` (a plain miss is the caller's own business logic, never
    a shape problem) - and otherwise names the raw value's SHAPE via
    `_shape_or_missing`, NEVER its content (a caller must never
    reach for the raw value to render it either - render on `field_text`,
    which already returns "" for exactly the values this gate calls
    unreadable).

    A bool/int/list/dict/null, AND a genuinely ABSENT key, all count as
    unreadable. That absence rule is a DELIBERATE, MEASURED choice and it
    is the one thing in this helper that can move a verdict, so it is
    written out here:

    - MEASURED on the real fixture (2026-09-07, every row of every
      non-empty resource this module reads): every field routed through
      `_gate` is PRESENT and carries a non-empty string. So absence is not
      a shape this export produces for a gated field at all.
    - Hardening rule 6 is explicit about the alternative: "geen default die
      op het positievere woord landt ... onbekend is een leesgat". A key we
      did not read cannot establish the favourable word, so absence is a
      read gap, not a silent pass.
    - The counter-examples are real and they all live OUTSIDE this helper,
      each with its own measurement: `_lb001`'s `somethod` (an optional
      spillover attribute; NSHC's own PowerShell reads a null soMethod as
      "", a legitimate no-op - that call site checks absence BEFORE calling
      `_gate`, on purpose), `_rsp001`'s `builtin` (MEASURED absent on 1 of
      7 real responderpolicy rows, where absence IS the documented "not a
      built-in policy" state) and the numeric fields, which have their own
      three-way reader `_num_gate` below precisely because absence there is
      a documented "not configured" default too.

    So: for a `_gate`-routed field, absence is a read gap. Callers that
    need the other answer say so at the call site and are listed in
    tests/test_hidden_rules.py::_NON_GATE_ROUTED_GATES with a reason.

    `_gate` only reports whether the read succeeded and, if so, whether it
    matched `words` - it does not decide what a match MEANS. An ordinary
    gate fires when `matched`; an INVERTED gate ("skip this
    row when the field equals WORD", e.g. `_mgmt001`'s `type` against
    NSIP) skips when `matched`. Either way, `unreadable_evidence` is never
    silently folded into a match OR a non-match: every call site below
    routes a non-None `unreadable_evidence` straight to a NOT ASSESSABLE
    hit, before it looks at `matched` at all - so an unreadable value can
    never land on the FAVOURABLE branch of either kind of gate.
    """
    raw = _raw_field(row, field)
    if not isinstance(raw, str):
        return False, (
            f"{field} niet gelezen als {'/'.join(words) if words else 'tekst'}"
            f" (gelezen: {_shape_or_missing(row, field)})"
        )
    return _is(raw, *words), None


def _vocab(row: dict, field: str, *words: str) -> tuple[str, str | None]:
    """`_gate` for a field whose vocabulary is CLOSED and fully known.

    One idiom, no fourth copy. `_gate`
    answers "was this value READ at all", which leaves the caller with a
    second question every closed-vocabulary field asks in the same words:
    a value that IS a genuine string but is none of `words` is just as
    unusable, and used to be written out by hand at every such site.

    That second question has TWO
    distinct answers, not one. `export.shape_of()` names EVERY string "een
    lege of alleen-witruimte tekstwaarde" - it was written for the case
    where the string really is empty or whitespace-only, and used to be
    called here unconditionally, so a genuinely readable value like
    `expirymonitor="MAYBE"` was reported as if it had been empty, which is
    simply false. `_log002`'s own `transport` field already forbids exactly
    this false claim, with its own test
    (`test_log002_unrecognized_transport_not_empty_statement`); this now
    applies the same two-way split here, once, for every `_vocab` caller:
    - the string IS empty/whitespace (`field_text` gives "") -> the shape
      claim is TRUE, keep the `_shape_or_missing` sentence.
    - the string is readable and non-empty but outside `words` -> the
      `_log002` wording ("heeft niet de vorm van ..."), without the shape
      claim and without echoing the value itself.

    Returns the matched word UPPER-CASED (so the caller compares against a
    literal, never against supplied text), or "" plus an unreadable-
    evidence line. Use `_gate` directly - not this - when a readable
    non-matching string is a legitimate business outcome rather than a read
    problem: an INVERTED gate (`_mgmt001`'s `type` against NSIP,
    `_mon002`'s `type` against PING/ARP) or an open-ended reference field.
    """
    matched, unreadable = _gate(row, field, *words)
    if unreadable:
        return "", unreadable
    if not matched:
        text = field_text(row, field)
        if not text:
            return "", (f"{field} niet gelezen als {'/'.join(words)} (gelezen: {_shape_or_missing(row, field)})")
        return "", f"{field} heeft niet de vorm van {'/'.join(words)}"
    return field_text(row, field).strip().upper(), None


def _num_gate(row: dict, field: str) -> tuple[int | None, str | None]:
    """The three-way read for a NUMERIC field - `_gate`'s counterpart.

    `_num()` returns None for BOTH "the
    key is absent" and "the key is there but is a bool/list/dict/unparsable
    string", and every numeric guard in this module used to treat that one
    None as "nothing to judge" - a value we could not read landing on the
    FAVOURABLE word, silently, which is hardening rule 6's defect.

    The two cases are NOT the same and are measured apart here:
    - ABSENT -> `(None, None)`, the caller's documented "not configured"
      default. MEASURED on the real fixture: `aaaparameter.maxloginattempts`
      is absent (no lockout configured), and `systemparameter.timeout`
      absent means NetScaler's own 900-second default - neither is a read
      failure.
    - PRESENT but not a whole number -> `(None, <evidence>)`, a read gap
      with its SHAPE named, never its value.
    """
    if _raw_field(row, field) is _MISSING:
        return None, None
    value = _num(row, field)
    if value is None:
        return None, (f"{field} niet gelezen als een geheel getal (gelezen: {_shape_or_missing(row, field)})")
    return value, None


def _enum_text(row: dict, field: str) -> str:
    """A display-only NITRO ENUMERATION rendered for evidence: the token, or "?".

    This is a CLASS of defect, not just the two sites it was first found at. A
    field like `svrstate`, `servicetype`, `persistencetype`, `state`,
    `status` or a monitor `type` is printed next to an established finding
    WITHOUT any vocabulary match having been made - so whatever string the
    supplied export put there reached the answer verbatim. It is not a
    NAME, so `disclosure.names_from_export()` neither collects nor should
    collect it: the masking seam can never reach it, exactly like
    `_ha001`'s hastatus and `_lb001`'s somethod.

    Those two could be closed against their own small vocabulary. These
    cannot: `lbmonitor.type` alone has dozens of documented values, and
    inventing a vocabulary this product cannot verify is precisely the
    question left OUT of scope for `sslprofiletype`. So this uses
    the SHAPE gate the product already owns for exactly this situation -
    `answer.repeatable_token`, hardening rule 1's positive shape test, the
    same one `coverage._state_for` applies to a manifest status - narrowed
    to ONE bare NITRO token. A real enumeration passes untouched (MEASURED:
    every `type`, `state`, `status`, `svrstate` and `servicetype` value on
    the real fixture is one such token); a sentence, a path or a paragraph
    becomes "?" instead of reaching the reader.

    Fields whose value was ESTABLISHED by a `_gate`/`_vocab` match do NOT
    go through here: what they print is one of this module's own literals,
    not supplied text.
    """
    # `max_words=1` swallowed the
    # documented MULTI-WORD NITRO states this helper exists to render -
    # MEASURED: service.svrstate="OUT OF SERVICE" (a real, documented
    # value) printed "svrstate=?", the finding losing exactly the field an
    # operator needs. `service`/`servicegroup` are EMPTY on the real
    # fixture, so this was never exercised there - the byte-identical
    # fixture answer is unaffected. This product already has its own
    # calibration for a member-state token (`answer.repeatable_token`'s own
    # docstring: "dienst._STATE_TOKEN - a member state, up to four words"),
    # so this reuses that number rather than inventing a stricter one.
    token = repeatable_token(field_text(row, field), max_words=4)
    return token if token else "?"


def _num_text(row: dict, field: str) -> str:
    """A numeric field rendered for EVIDENCE: the number, or "?".

    These sites used to render through
    `field_token`, which is PowerShell's `[string]` cast and therefore joins
    a JSON list into supplied TEXT - `serverport: ["RAW-PORT-LEAK"]` printed
    `serverport=RAW-PORT-LEAK` under `[vastgesteld]`, straight past the
    masking seam. `field_token` exists to reproduce that cast for a
    COMPARISON against a known word, never to build displayed text (see its
    own docstring); rendering is `_num`'s job here, and `_num` is already
    fail-closed for every shape that is not a whole number.

    The fallback is `"?"`, the module's existing spelling for an
    unrenderable decorator (`field_text(r, 'status') or '?'`), not a shape
    sentence: every field read through this helper is DECORATION next to an
    already-established finding (an HA node id, a port, a hit count, a day
    count) and never gates a verdict. The "name the SHAPE" rule governs
    verdict-driving fields, and those go through `_gate`/`_vocab`/
    `_num_gate` above, all three of which do name it.
    """
    value = _num(row, field)
    return "?" if value is None else str(value)


def _hit(instance: str, evidence: str, confidence: str, reason: str, names: tuple[str, ...] = ()) -> Hit:
    return Hit(
        instance=instance or "?",
        evidence=evidence,
        confidence=confidence,
        confidence_reason=reason,
        names=names,
    )


def _cs001(ctx):
    # _gate: stateupdate against DISABLED (closed ENABLED/DISABLED
    # vocabulary that feeds an `_is()` comparison - see `_gate`'s docstring
    # for why a non-string/absent value can never land on the silent
    # "not disabled" branch).
    hits = []
    for r in ctx.rows("config/csvserver"):
        matched, unreadable = _gate(r, "stateupdate", "DISABLED")
        name = field_text(r, "name")
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if matched:
            hits.append(
                _hit(name, f"stateupdate={field_text(r, 'stateupdate')}", "high", "expliciet veld uit config/csvserver")
            )
    return hits


_HA_MAINTENANCE_STATES = ("STAYSECONDARY", "STAYPRIMARY")


def _ha001(ctx):
    # _gate (no words: used purely for the readability check - the actual
    # comparison stays the substring test NSHC parity already used, not an
    # exact `_is()` match). `id` is a small HA-node NUMBER (0/1) used only
    # in the instance label - `_num_text`, not `field_token`
    # (field_token would print a supplied list verbatim).
    #
    # The substring test matches a value that CONTAINS
    # the maintenance word, so `hastatus=<status>` used to echo
    # `STAYSECONDARY<anything the export supplied>` verbatim into the
    # answer - a supplied string reaching the reader outside the masking
    # seam, the same class of leak. `hastatus` is not a NAME (it is
    # an appliance state word, and `disclosure.names_from_export()` neither
    # collects nor should collect it), so it cannot be fixed at the seam:
    # it is suppressed by SHAPE instead. The value is printed only when it
    # IS exactly one of the two words; a longer string that merely contains
    # one still FIRES the rule (NSHC parity, unchanged) but says so without
    # quoting itself.
    hits = []
    for r in ctx.rows("config/hanode"):
        _, unreadable = _gate(r, "hastatus")
        if unreadable:
            hits.append(
                Hit(
                    instance=f"node {_num_text(r, 'id')}",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        status = field_text(r, "hastatus").upper()
        if not any(word in status for word in _HA_MAINTENANCE_STATES):
            continue
        shown = (
            status
            if _is(status, *_HA_MAINTENANCE_STATES)
            else (
                "een waarde die "
                + "/".join(_HA_MAINTENANCE_STATES)
                + " bevat (waarde niet getoond - onvertrouwde exportinvoer)"
            )
        )
        hits.append(_hit(f"node {_num_text(r, 'id')}", f"hastatus={shown}", "high", "expliciet veld uit config/hanode"))
    return hits


# The documented NetScaler spillover methods. Used ONLY to decide whether
# `somethod`'s own value may be printed, never to decide whether
# NSHC-HR-LB-001 fires - that stays the existing "set, and not NONE" test,
# so narrowing this vocabulary can never silently drop a finding.
_SO_METHODS = ("CONNECTION", "DYNAMICCONNECTION", "BANDWIDTH", "HEALTH", "NONE")


def _lb001(ctx):
    # somethod is the ONE exception to `_gate`'s "absence is unreadable"
    # rule (see `_gate`'s own docstring): it is an OPTIONAL NetScaler
    # attribute, present only once spillover is configured, and NSHC's own
    # PowerShell reads a null/absent soMethod as "" - a legitimate no-op,
    # not a read failure. So absence is checked BEFORE `_gate`; a PRESENT
    # but non-string value is still routed through `_gate` against NONE.
    # `backupvserver` stays field_text: a VSERVER NAME reference, always a
    # string by the NetScaler object model.
    hits = []
    for r in ctx.rows("config/lbvserver"):
        if _raw_field(r, "somethod") is _MISSING:
            continue
        matched, unreadable = _gate(r, "somethod", "NONE")
        name = field_text(r, "name")
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        so = field_text(r, "somethod")
        backup = field_text(r, "backupvserver")
        if so and not matched and not backup:
            # `soMethod=<so>` used to echo whatever
            # string the export supplied - and `somethod` is not a NAME, so
            # `disclosure.names_from_export()` neither collects nor should
            # collect it, which means the masking seam can never reach it.
            # Same treatment as `_ha001`'s hastatus and `_cs002`'s policy
            # expression: printed only when it IS one of the documented
            # spillover methods, otherwise named by what it is not. The
            # rule still FIRES either way (unchanged: any non-empty,
            # non-NONE method with an empty backupvserver).
            shown = (
                so
                if _is(so, *_SO_METHODS)
                else (
                    "een waarde buiten het gedocumenteerde vocabulaire"
                    " (waarde niet getoond - onvertrouwde exportinvoer)"
                )
            )
            hits.append(
                _hit(name, f"soMethod={shown}, backupvserver=<leeg>", "high", "soMethod gezet, backupvserver leeg")
            )
    return hits


def _mgmt001(ctx):
    # `type` (MEASURED) is
    # an INVERTED gate: skip this row when it IS the NSIP/management
    # address. An unreadable type must never be treated as
    # "skip" - we cannot tell a management address from a data-plane one
    # without it, so it becomes NOT ASSESSABLE instead, before gui/ssh are
    # even looked at (the row's own `type` never reaches the
    # label as a raw/unvalidated token either way - only a confirmed
    # string does, via field_text).
    #
    # gui/ssh: `_vocab` over their FULL closed vocabulary - a readable
    # string that is neither an ON-word nor DISABLED is ALSO not assessable
    # (the three-way read this rule already had, moved into the shared
    # `_vocab` helper, so the sentence and the shape naming are now
    # identical at every closed-vocabulary site instead of copied per
    # site). Real and blocked hits
    # for the SAME address coexist (this module's own rule for that case).
    hits = []
    for r in ctx.rows("config/nsip"):
        is_nsip, type_unreadable = _gate(r, "type", "NSIP")
        if type_unreadable:
            hits.append(
                Hit(
                    instance=f"{field_text(r, 'ipaddress') or '?'} (?)",
                    evidence=type_unreadable,
                    confidence="medium",
                    confidence_reason="type kan niet vastgesteld worden zonder een tekstwaarde",
                    not_assessable=True,
                )
            )
            continue
        if is_nsip:
            continue
        label = f"{field_text(r, 'ipaddress') or '?'} ({_enum_text(r, 'type')})"
        on = []
        unreadable = []
        gui_word, gui_unreadable = _vocab(r, "gui", "ENABLED", "SECUREONLY", "DISABLED")
        if gui_unreadable:
            unreadable.append(gui_unreadable)
        elif gui_word in ("ENABLED", "SECUREONLY"):
            on.append(f"gui={field_text(r, 'gui')}")
        ssh_word, ssh_unreadable = _vocab(r, "ssh", "ENABLED", "DISABLED")
        if ssh_unreadable:
            unreadable.append(ssh_unreadable)
        elif ssh_word == "ENABLED":
            on.append(f"ssh={field_text(r, 'ssh')}")
        if on:
            hits.append(_hit(label, ", ".join(on), "medium", "beheerprotocol aan op een niet-NSIP-adres"))
        if unreadable:
            hits.append(
                Hit(
                    instance=label,
                    evidence="; ".join(unreadable),
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
    return hits


def _ha002(ctx):
    # _gate: syncstatusstrictmode against DISABLED, same class as _cs001.
    hits = []
    for r in ctx.rows("config/hanode"):
        matched, unreadable = _gate(r, "syncstatusstrictmode", "DISABLED")
        if unreadable:
            hits.append(
                Hit(
                    instance=f"node {_num_text(r, 'id')}",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if matched:
            hits.append(
                _hit(
                    f"node {_num_text(r, 'id')}",
                    f"syncstatusstrictmode={field_text(r, 'syncstatusstrictmode')}",
                    "high",
                    "expliciet veld uit config/hanode",
                )
            )
    return hits


def _ha003(ctx):
    # _gate: haprop against DISABLED, same class as _cs001.
    hits = []
    for r in ctx.rows("config/hanode"):
        matched, unreadable = _gate(r, "haprop", "DISABLED")
        if unreadable:
            hits.append(
                Hit(
                    instance=f"node {_num_text(r, 'id')}",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if matched:
            hits.append(
                _hit(
                    f"node {_num_text(r, 'id')}",
                    f"haprop={field_text(r, 'haprop')}",
                    "high",
                    "expliciet veld uit config/hanode",
                )
            )
    return hits


_BUILTIN_CMD_POLICIES = (
    "operator",
    "read-only",
    "network",
    "sysadmin",
    "superuser",
    "partition-operator",
    "partition-read-only",
    "partition-network",
    "partition-admin",
)


def _rbac001(ctx):
    # _gate: action against ALLOW (closed ALLOW/DENY vocabulary).
    # `policyname`/`cmdspec` stay field_text: a policy name and a
    # command-match spec are always strings by the NetScaler object model.
    hits = []
    for r in ctx.rows("config/systemcmdpolicy"):
        name = field_text(r, "policyname")
        if name.lower() in _BUILTIN_CMD_POLICIES:
            continue
        matched, unreadable = _gate(r, "action", "ALLOW")
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not matched:
            continue
        spec = field_text(r, "cmdspec")
        if "shell" not in spec.lower() or "(?!" in spec:
            continue
        hits.append(
            _hit(
                name,
                "action=ALLOW, cmdspec staat 'shell' toe",
                "medium",
                "eigen (niet-ingebouwde) policy met ALLOW op 'shell'",
            )
        )
    return hits


def _ssl001(ctx):
    hits = []
    for b in ctx.rows(BINDING_CERTKEY):
        certkey = field_text(b, "certkeyname")
        if "ns-server-certificate" not in certkey.lower():
            continue
        hits.append(
            _hit(
                field_text(b, "vservername"),
                f"certkeyname={certkey}",
                "high",
                "ingebouwd default-cert gebonden aan een vserver",
                names=(certkey,),
            )
        )
    return hits


_TEXT_COMPARE = re.compile(r"\.(CONTAINS|EQ|STARTSWITH|ENDSWITH)\s*\(\s*\"", re.IGNORECASE)


def _cs002(ctx):
    # `rule` is a raw, CALLER-SUPPLIED policy expression (untrusted
    # export input) that the masking seam never reads - it is not a name of
    # any of the ten disclosure families, so echoing even a slice of it
    # would put whatever it contains (a hostname, a URL, an internal path)
    # in front of the model at every disclosure level, `volledig` included.
    # Fix: never print the expression, only the fact that it lacks explicit
    # IGNORECASE. A name that must still be printable reaches the answer
    # through `Hit.names`, never through raw evidence text like this.
    hits = []
    for r in ctx.rows("config/cspolicy"):
        rule = field_text(r, "rule")
        if not rule or not _TEXT_COMPARE.search(rule):
            continue
        if "set_text_mode(ignorecase" in rule.lower().replace(" ", ""):
            continue
        hits.append(
            _hit(
                field_text(r, "policyname"),
                "tekstvergelijking zonder expliciete IGNORECASE (expressie niet getoond - onvertrouwde exportinvoer)",
                "medium",
                "tekstmodus niet expliciet gezet",
            )
        )
    return hits


def _ssl002(ctx):
    # _gate: denysslreneg against NO (closed vocabulary).
    row = ctx.one("config/sslparameter")
    if row is None:
        return []
    matched, unreadable = _gate(row, "denysslreneg", "NO")
    if unreadable:
        return [
            Hit(
                instance="sslparameter",
                evidence=unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if not matched:
        return []
    value = field_text(row, "denysslreneg")
    return [
        _hit(
            "sslparameter",
            f"denySSLReneg={value} (client-geinitieerde renegotiation toegestaan)",
            "high",
            "expliciete globale SSL-parameter",
        )
    ]


def _mgmt002(ctx):
    # _gate: strongpassword against DISABLED (closed vocabulary).
    row = ctx.one("config/systemparameter")
    if row is None:
        return []
    matched, unreadable = _gate(row, "strongpassword", "DISABLED")
    if unreadable:
        return [
            Hit(
                instance="systemparameter",
                evidence=unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if not matched:
        return []
    value = field_text(row, "strongpassword")
    return [_hit("systemparameter", f"strongpassword={value}", "medium", "expliciete globale instelling")]


def _mgmt003(ctx):
    # telnet/ftp: _gate against ENABLED, each an independent fire-gate (same
    # field pattern as _mgmt001's gui/ssh - real and blocked hits for the
    # SAME address coexist). `type`/`mgmtaccess` are DIFFERENT: they never
    # gate whether this rule fires (telnet/ftp alone do that) - they only
    # refine the SEVERITY of an already-established finding. So an
    # unreadable type/mgmtaccess does not block the real hit (the cleartext
    # exposure is established regardless); it only means "actively
    # reachable" cannot be determined, which prints as confidence "none" ->
    # "niet vastgesteld" (`_confidence_word`'s own fail-closed default),
    # never a silent "medium" guess (hardening rule 6). `ipaddress` stays
    # field_text (address).
    hits = []
    for r in ctx.rows("config/nsip"):
        on = []
        unreadable = []
        telnet_on, telnet_bad = _gate(r, "telnet", "ENABLED")
        if telnet_bad:
            unreadable.append(telnet_bad)
        elif telnet_on:
            on.append("telnet")
        ftp_on, ftp_bad = _gate(r, "ftp", "ENABLED")
        if ftp_bad:
            unreadable.append(ftp_bad)
        elif ftp_on:
            on.append("FTP")
        label = f"{field_text(r, 'ipaddress') or '?'} ({_enum_text(r, 'type')})"
        if on:
            type_nsip, type_bad = _gate(r, "type", "NSIP")
            mgmt_on, mgmt_bad = _gate(r, "mgmtaccess", "ENABLED")
            if type_bad or mgmt_bad:
                confidence = "none"
                # `_gate` already produced the line
                # that names WHICH field was unreadable and in WHAT SHAPE
                # (`_shape_or_missing`); throwing it away for a generic
                # sentence dropped exactly what the Global Constraint
                # requires ("een gelezen maar onduidbaar veld is NIET
                # VASTGESTELD met zijn VORM benoemd"). It travels with the
                # confidence reason now, so the reader sees the field and
                # the shape - still never the value.
                reason = "actief bereikbaar (type/mgmtaccess) kon niet vastgesteld worden: " + "; ".join(
                    e for e in (type_bad, mgmt_bad) if e
                )
            else:
                active = type_nsip or mgmt_on
                confidence = "high" if active else "medium"
                reason = (
                    "cleartext beheerprotocol actief bereikbaar"
                    if active
                    else "service-vlag staat aan terwijl beheertoegang nu uit is - latente blootstelling"
                )
            hits.append(
                _hit(
                    label,
                    f"{'+'.join(on)} ingeschakeld; mgmtaccess={_enum_text(r, 'mgmtaccess')}",
                    confidence,
                    reason,
                )
            )
        if unreadable:
            hits.append(
                Hit(
                    instance=label,
                    evidence="; ".join(unreadable),
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
    return hits


def _mgmt004(ctx):
    # `_num_gate`: a PRESENT but unreadable timeout (a bool, a list, an
    # unparsable string) used to collapse to None via `_num` and land on
    # `value != 0` -> "niets aan de hand", the FAVOURABLE word, silently
    # (hardening rule 6). It is a read gap now, named by shape. An ABSENT
    # timeout stays the documented default: NetScaler's own 900-second idle
    # timeout applies, which is not 0 and therefore not a finding.
    row = ctx.one("config/systemparameter")
    if row is None:
        return []
    value, unreadable = _num_gate(row, "timeout")
    if unreadable:
        return [
            Hit(
                instance="systemparameter",
                evidence=unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if value != 0:
        return []
    return [
        _hit(
            "systemparameter", "timeout=0 (beheersessie verloopt niet)", "high", "expliciete globale idle-timeout op 0"
        )
    ]


def _ha005(ctx):
    # _gate: failsafe against OFF, same class as _cs001.
    hits = []
    for r in ctx.rows("config/hanode"):
        matched, unreadable = _gate(r, "failsafe", "OFF")
        if unreadable:
            hits.append(
                Hit(
                    instance=f"node {_num_text(r, 'id')}",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if matched:
            hits.append(
                _hit(
                    f"node {_num_text(r, 'id')}",
                    f"failsafe={field_text(r, 'failsafe')}",
                    "high",
                    "expliciet veld; zonder failsafe kan een dubbele degradatie beide nodes secondary laten",
                )
            )
    return hits


def _aaa001(ctx):
    # _gate: sectype against SSL/TLS, then validateservercert against YES
    # (an inverted gate here: the hit fires when it is NOT "YES" - but only
    # once we have confirmed it is a readable, non-empty string; empty
    # stays a normal skip, unreadable becomes NOT ASSESSABLE, never treated
    # as "not YES" by default). Checked in sequence so a row whose sectype
    # is definitively out of scope (a readable string that just is not
    # SSL/TLS) never raises an unrelated validateservercert read problem.
    hits = []
    for r in ctx.rows("config/authenticationldapaction"):
        name = field_text(r, "name")
        sectype_matched, sectype_unreadable = _gate(r, "sectype", "SSL", "TLS")
        if sectype_unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=sectype_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not sectype_matched:
            continue
        validate_yes, validate_unreadable = _gate(r, "validateservercert", "YES")
        if validate_unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=validate_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        validate = field_text(r, "validateservercert")
        if validate_yes or not validate:
            continue
        # serverport is a port NUMBER, so not
        # field_text (which returns "" for any non-string and would print
        # "serverport=?" even when the port was read successfully).
        # `_num_text`, not `field_token` - the
        # `[string]` cast joins a supplied JSON list into the answer text.
        hits.append(
            _hit(
                name,
                f"sectype={field_text(r, 'sectype')}, serverport={_num_text(r, 'serverport')},"
                f" validateservercert={_enum_text(r, 'validateservercert')}"
                f" (TLS zonder cert-verificatie)",
                "high",
                "validateservercert expliciet niet YES",
            )
        )
    return hits


def _aaa003(ctx):
    # `_num_gate`: MEASURED on the real fixture, `maxloginattempts` is
    # ABSENT (no account lockout configured at all) - the documented "not
    # configured, nothing to judge" default, which is why absence stays a
    # skip here. A PRESENT but unreadable value is a different thing and is
    # a read gap now, named by shape, instead of collapsing to None and
    # skipping just like the absent case did.
    row = ctx.one("config/aaaparameter")
    if row is None:
        return []
    attempts, attempts_unreadable = _num_gate(row, "maxloginattempts")
    if attempts_unreadable:
        return [
            Hit(
                instance="aaaparameter",
                evidence=attempts_unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if attempts is None or attempts <= 0:
        return []
    # _gate: persistentloginattempts against DISABLED (closed vocabulary).
    matched, unreadable = _gate(row, "persistentloginattempts", "DISABLED")
    if unreadable:
        return [
            Hit(
                instance="aaaparameter",
                evidence=unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if not matched:
        return []
    persistent = field_text(row, "persistentloginattempts")
    return [
        _hit(
            "aaaparameter",
            f"maxloginattempts={attempts} (lockout actief), persistentloginattempts={persistent}",
            "medium",
            "teller niet persistent over een herstart",
        )
    ]


def _svc001(ctx):
    # _gate: healthmonitor against NO (closed vocabulary). `svrstate`/
    # `servicetype` stay field_text: display-only status/type enums, never
    # compared, always strings by the NetScaler object model.
    hits = []
    for r in ctx.rows("config/service"):
        matched, unreadable = _gate(r, "healthmonitor", "NO")
        name = field_text(r, "name")
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not matched:
            continue
        hits.append(
            _hit(
                name,
                f"healthmonitor=NO; svrstate={_enum_text(r, 'svrstate')}; servicetype={_enum_text(r, 'servicetype')}",
                "high",
                "healthmonitor=NO betekent: altijd UP",
            )
        )
    return hits


def _svc002(ctx):
    # _gate: usip against YES (closed vocabulary). `servicetype`/`state`
    # stay field_text (display-only, same reason as _svc001).
    hits = []
    for r in ctx.rows("config/servicegroup"):
        matched, unreadable = _gate(r, "usip", "YES")
        name = field_text(r, "servicegroupname") or field_text(r, "name")
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not matched:
            continue
        hits.append(
            _hit(
                name,
                f"usip=YES; servicetype={_enum_text(r, 'servicetype')}; state={_enum_text(r, 'state')}",
                "medium",
                "USIP=YES expliciet",
            )
        )
    return hits


def _glob001(ctx):
    # _gate: internaluserlogin against ENABLED (closed vocabulary).
    row = ctx.one("config/nsparam")
    if row is None:
        return []
    matched, unreadable = _gate(row, "internaluserlogin", "ENABLED")
    if unreadable:
        return [
            Hit(
                instance="nsparam",
                evidence=unreadable,
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
            )
        ]
    if not matched:
        return []
    value = field_text(row, "internaluserlogin")
    return [
        _hit(
            "nsparam",
            f"internaluserlogin={value} (interne gebruiker mag inloggen; standaardwaarde)",
            "medium",
            "expliciet veld",
        )
    ]


_BUILTIN_SSL_PROFILES = (
    "ns_default_ssl_profile_frontend",
    "ns_default_ssl_profile_backend",
    "ns_default_ssl_profile_secure_frontend",
    "ns_default_ssl_profile_internal_frontend_service",
)


def _ssl003(ctx):
    # MEASURED: sslprofiletype is a ROW FILTER (only FrontEnd profiles are
    # in scope for the weak-TLS check below) - a bare field_token swap does
    # not fix it: MEASURED on the real fixture, sslprofiletype is a STRING
    # with FOUR distinct values (FrontEnd, BackEnd, QUIC-FrontEnd,
    # QUIC-BackEnd), so "not FRONTEND" is the CORRECT, deliberate, existing
    # skip for three of those four - narrowing that vocabulary is a
    # SEPARATE, out-of-scope question (this task fixes non-string JSON, not
    # enum completeness). What silently skipped before AND after a bare
    # swap is a NON-STRING sslprofiletype (bool/int/list/null/absent): the
    # old gate could never tell "genuinely BackEnd" apart from "unreadable",
    # both landing on the same silent skip (hardening rule 6). So the
    # readability check happens FIRST, before any string-vocabulary
    # decision: a real string keeps EXACTLY today's FRONTEND/not-FRONTEND
    # behaviour; anything else becomes NOT ASSESSABLE, named by shape.
    hits = []
    for r in ctx.rows("config/sslprofile"):
        name = field_text(r, "name")
        if name.lower() in _BUILTIN_SSL_PROFILES:
            continue
        # The hand-written `isinstance` copy of the
        # three-way read is gone - `_gate` IS that read, and it happens to
        # fit a ROW FILTER without any change of meaning: `matched` selects
        # the FrontEnd rows, a readable non-matching string is the existing
        # deliberate skip (BackEnd/QUIC-*, out of scope, see above), and a
        # non-string/absent value is the read gap it always should have been.
        is_frontend, kind_unreadable = _gate(r, "sslprofiletype", "FRONTEND")
        if kind_unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=kind_unreadable,
                    confidence="medium",
                    confidence_reason="FrontEnd/BackEnd kan niet vastgesteld worden zonder een tekstwaarde",
                    not_assessable=True,
                )
            )
            continue
        if not is_frontend:
            continue
        # `field_text(r, f) or "DISABLED"` was the one
        # guard in this module whose UNREADABLE case landed on the PASSING
        # word - a bool, a number or an absent key all collapse to "" via
        # `field_text`, and the `or` then silently supplied "DISABLED",
        # never firing this rule and never leaving a trace.
        # `field_token` was NOT the right reader
        # either. It reproduces PowerShell's `[string]` cast, so
        # `ssl3: ["ENABLED"]` read back as the WORD "ENABLED" - a value
        # that was never a string produced a `[vastgesteld]` verdict (and
        # `["DISABLED"]` a silent pass), which is exactly the shape the
        # an earlier `builtin` measurement found on real data. `_vocab` is the
        # closed-vocabulary read: ENABLED/DISABLED and nothing else, any
        # other shape a read gap with its OWN shape named (the old text
        # named the field but not the shape).
        weak = []
        unreadable = []
        for f in ("ssl3", "tls1", "tls11"):
            word, f_unreadable = _vocab(r, f, "ENABLED", "DISABLED")
            if f_unreadable:
                unreadable.append(f_unreadable)
            elif word == "ENABLED":
                weak.append(f)
        if unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence="FrontEnd profiel: " + "; ".join(unreadable),
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde ENABLED/DISABLED-vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not weak:
            continue
        hits.append(
            _hit(
                name,
                f"FrontEnd profiel met {'+'.join(weak)} ENABLED (overschrijft de vserver-instelling indien gebonden)",
                "high",
                "expliciete profielvelden",
            )
        )
    return hits


def _log001(ctx):
    row = ctx.one("config/auditsyslogparams")
    if row is None:
        return []
    ip = field_text(row, "serverip")
    if not ip or not (ip.startswith("127.") or ip == "0.0.0.0"):
        return []
    return [
        _hit(
            "auditsyslogparams",
            f"serverip={ip} (globale syslog-route blijft on-box)",
            "high",
            "expliciet veld; loopback of unset betekent dat niets de doos verlaat",
            names=(ip,),
        )
    ]


def _log002(ctx):
    hits = []
    for r in ctx.rows("config/auditsyslogaction"):
        name = field_text(r, "name") or "?"
        ip = field_text(r, "serverip")
        # Not field_text - same port-number reasoning
        # as _aaa001 above. `_num`, not
        # `field_token` - `serverport: ["RAW-PORT-LEAK"]` used to print the
        # supplied text verbatim as `naar 10.1.1.1:RAW-PORT-LEAK` under
        # `[vastgesteld]`. A port that is not a whole number simply does not
        # get spelled out; the destination address still does (it is a NAME
        # and travels through `Hit.names` to the masking seam).
        port = _num(r, "serverport")
        where = "doel niet gelezen" if not ip else f"naar {ip}" + (f":{port}" if port is not None else "")
        # The destination address is a NAME (of this syslog target's
        # server), only ever spelled out in this evidence text - no other
        # family reads config/auditsyslogaction's serverip.
        target_names = (ip,) if ip else ()
        # The "one idiom, no private copies" half:
        # `transport`'s three-way read was already fully fail-closed and its
        # two refusal SENTENCES are pinned byte-for-byte by three dedicated
        # tests (test_log002_raw_field_shape_determination and the two
        # around it), so the sentences stay exactly as they were - but the
        # READ itself now goes through `_gate` like every other closed-
        # vocabulary field, which is what puts this field inside the derived
        # six-shape sweep instead of beside it. `_gate` and the `_is()`
        # calls below agree by construction: when `transport_unreadable` is
        # set, the raw value is not a string and `field_text` is "" anyway.
        _, transport_unreadable = _gate(r, "transport", "TCP", "UDP", "HTTP")
        transport = field_text(r, "transport")
        if not transport_unreadable and _is(transport, "UDP"):
            hits.append(
                _hit(
                    name,
                    f"transport=UDP ({where}); verbindingsloos - geen afleverbewijs",
                    "high",
                    "expliciet transportveld",
                    names=target_names,
                )
            )
        elif not transport_unreadable and _is(transport, "TCP", "HTTP"):
            continue
        else:
            if not transport:
                shown = _shape_or_missing(r, "transport")
                evidence = (
                    f"transport niet vastgesteld (gelezen waarde: {shown}; {where});"
                    " gedocumenteerd zijn TCP, UDP en HTTP met default UDP"
                )
            else:
                evidence = (
                    f"transport heeft niet de vorm van TCP, UDP of HTTP ({where});"
                    " gedocumenteerd zijn TCP, UDP en HTTP met default UDP"
                )
            hits.append(
                Hit(
                    instance=name,
                    evidence=evidence,
                    confidence="medium",
                    confidence_reason="een afwezig veld bewijst de default niet",
                    not_assessable=True,
                    names=target_names,
                )
            )
    return hits


_BUILTIN_REWRITE_ACTIONS = ("NOREWRITE", "RESET", "DROP")


def _rw001(ctx):
    known = {field_text(a, "name").casefold() for a in ctx.rows("config/rewriteaction") if field_text(a, "name")}
    known.update(name.casefold() for name in _BUILTIN_REWRITE_ACTIONS)
    hits = []
    for r in ctx.rows("config/rewritepolicy"):
        # `isdefault` is a JSON BOOL on the real fixture (and on any
        # NITRO export) - `field_text` returns "" for a bool, which used to
        # make this guard never skip. `field_token` reproduces PowerShell's
        # own [string] cast (True/False), matching NSHC's comparison.
        if _is(field_token(r, "isdefault") or "False", "TRUE"):
            continue
        action = field_text(r, "action")
        if not action or action.casefold() in known:
            continue
        # undefhits is a hit COUNT, not text (a string
        # "0" on the real fixture today, but a NITRO hit count is a
        # plausible JSON int on another export/API version).
        # `_num_text`, not `field_token` - the
        # `[string]` cast printed `undefhits=RAW-UNDEFHITS-LEAK` for a
        # supplied list. The `or '0'` default went with it: a count we could
        # not read is "?", never a claimed zero (hardening rule 6).
        hits.append(
            _hit(
                field_text(r, "name"),
                f"action='{action}' bestaat niet in config/rewriteaction en is geen"
                f" ingebouwde noop; undefhits={_num_text(r, 'undefhits')}",
                "high",
                "naamverwijzing zonder doel",
                names=(action,),
            )
        )
    return hits


def _rsp001(ctx):
    hits = []
    for r in ctx.rows("config/responderpolicy"):
        # `builtin` is a JSON LIST on the real fixture (e.g.
        # ['IMMUTABLE']) - `field_text` returns "" for a list, which used to
        # make this guard never skip. `field_token` space-joins it exactly
        # as PowerShell's [string] cast would ("IMMUTABLE").
        builtin = field_token(r, "builtin").upper()
        if "IMMUTABLE" in builtin or "MODIFIABLE" in builtin:
            continue
        # _gate: action against RESET/DROP (closed vocabulary).
        matched, unreadable = _gate(r, "action", "RESET", "DROP")
        if unreadable:
            hits.append(
                Hit(
                    instance=field_text(r, "name") or "?",
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not matched:
            continue
        action = field_text(r, "action")
        rule = field_text(r, "rule")
        if rule.strip().lower() != "true":
            continue
        hits.append(
            _hit(
                field_text(r, "name"),
                f"action={action} op rule='{rule}' (matcht altijd)",
                "high",
                "expliciete regel die altijd waar is",
            )
        )
    return hits


def _lb003(ctx):
    # _gate: sessionless against ENABLED, then persistencetype against NONE
    # (an inverted gate: skip when it IS "NONE"). `servicetype` stays
    # field_text (display-only, same reason as _svc001).
    hits = []
    for r in ctx.rows("config/lbvserver"):
        sessionless_on, sessionless_unreadable = _gate(r, "sessionless", "ENABLED")
        name = field_text(r, "name")
        if sessionless_unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=sessionless_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if not sessionless_on:
            continue
        persistence_none, persistence_unreadable = _gate(r, "persistencetype", "NONE")
        if persistence_unreadable:
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=persistence_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        persistence = field_text(r, "persistencetype")
        if not persistence:
            # This branch was written for an ABSENT
            # persistencetype and said "nothing configured, skip". Absence
            # is a read gap now (see `_gate`), so what is left here is a
            # PRESENT but EMPTY string - a value that states no persistence
            # type at all. Treating that as "no persistence configured" is
            # the same silent landing on the favourable word, so it is a
            # read gap too, named by shape. The code now says ONE thing
            # about an unstated persistencetype instead of two.
            hits.append(
                Hit(
                    instance=name or "?",
                    evidence=(f"persistencetype niet vastgesteld (gelezen: {_shape_or_missing(r, 'persistencetype')})"),
                    confidence="medium",
                    confidence_reason="een lege waarde noemt geen persistentietype",
                    not_assessable=True,
                )
            )
            continue
        if persistence_none:
            continue
        hits.append(
            _hit(
                name,
                f"sessionless=ENABLED; persistencetype={_enum_text(r, 'persistencetype')};"
                f" servicetype={_enum_text(r, 'servicetype')}",
                "high",
                "twee instellingen die elkaar uitsluiten",
            )
        )
    return hits


def _ssl004(ctx):
    # MEASURED: expirymonitor feeds an `_is()` comparison - field_token.
    # `certkey`/`status` stay field_text (name, and a display-only status
    # enum - same reason as _svc001). Same reasoning as _mgmt001's guard above: the
    # old `if not monitor or not _is(monitor, "DISABLED"): continue` landed
    # ANY unreadable value (bool/int/list, or an absent key) on the
    # FAVORABLE "not disabled, nothing to flag" branch - hardening rule 6.
    # `field_token` did not fix that either, it moved
    # it - MEASURED, `expirymonitor: ["ENABLED"]` read back as the WORD
    # "ENABLED" and passed silently, and `["DISABLED"]` produced a
    # `[vastgesteld]` finding quoting a word the field never carried. The
    # read is `_vocab` now, the same closed-vocabulary helper every other
    # ENABLED/DISABLED field in this module goes through: ENABLED -> fine;
    # DISABLED -> the existing hit; anything else, string or not, -> NOT
    # ASSESSABLE, named by shape.
    hits = []
    for r in ctx.rows("config/sslcertkey"):
        name = field_text(r, "certkey") or "?"
        if "ns-sftrust" in name.lower():
            continue
        monitor, monitor_unreadable = _vocab(r, "expirymonitor", "ENABLED", "DISABLED")
        if monitor_unreadable:
            hits.append(
                Hit(
                    instance=name,
                    evidence=monitor_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if monitor == "ENABLED":
            continue
        # NSHC gives this check confidence 'high' (SEVERITY is 'medium'
        # - a different axis; SEVERITY_WORDS[rule.severity] handles that one).
        # `daystoexpiration` is a JSON INT on the real
        # fixture (817, 1817, 3642, 999902, measured) - `field_text` returns
        # "" for any non-string, so this printed "daystoexpiration=?" for
        # EVERY hit, including ones where the value was read successfully.
        # `_num_text`, not `field_token` - the
        # `[string]` cast printed `daystoexpiration=RAW-DAYS-LEAK` for a
        # supplied list. A day count that is not a whole number is "?".
        hits.append(
            _hit(
                name,
                f"expirymonitor=DISABLED; daystoexpiration={_num_text(r, 'daystoexpiration')};"
                f" status={_enum_text(r, 'status')}",
                "high",
                "expliciet veld per certificaat",
            )
        )
    return hits


_DEFAULT_MONITOR = re.compile(
    r"^(ping-default|tcp-default|http-default|https-default|dns-default|ns_default|__ns_)", re.IGNORECASE
)


def _mon001(ctx):
    # units3/units4 are compared to EACH OTHER, not to a fixed vocabulary
    # word - `_gate` is called with no `words` purely for the readability
    # check (a non-string, absent OR empty unit is NOT ASSESSABLE, never
    # silently "SEC"). `interval`/`resptimeout` go through `_num_gate` for
    # the same reason: a present-but-unreadable number used to collapse to
    # None and skip the row on the FAVOURABLE side, silently. `type` is
    # evidence-only HERE (the actual gate on it lives in
    # _mon002 below) - rendered via field_text, never field_token, so an
    # unreadable value prints as "?" instead of a raw stringified token.
    # `monitorname` stays field_text (name).
    hits = []
    for r in ctx.rows("config/lbmonitor"):
        name = field_text(r, "monitorname") or "?"
        if _DEFAULT_MONITOR.match(name):
            continue
        interval, interval_unreadable = _num_gate(r, "interval")
        timeout, timeout_unreadable = _num_gate(r, "resptimeout")
        unreadable = [e for e in (interval_unreadable, timeout_unreadable) if e]
        if unreadable:
            hits.append(
                Hit(
                    instance=name,
                    evidence="; ".join(unreadable),
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if interval is None or timeout is None or interval <= 0:
            continue
        units = {}
        unreadable = []
        for f in ("units3", "units4"):
            _, f_unreadable = _gate(r, f)
            value = field_text(r, f)
            if not f_unreadable and not value:
                # `(field_text(r, f) or "SEC")` was
                # written for an ABSENT key. Absence is a read gap now (see
                # `_gate`), so what is left is a PRESENT but EMPTY string -
                # and supplying "SEC" for it is literally hardening rule 6's
                # example: a value we did not read landing on one specific
                # documented word, here one that can make the two units
                # compare EQUAL and let the rule fire. MEASURED before the
                # change: units3="" with units4="SEC" produced `geraakt`.
                f_unreadable = f"{f} niet vastgesteld (gelezen: {_shape_or_missing(r, f)})"
            if f_unreadable:
                unreadable.append(f_unreadable)
            else:
                units[f] = value.upper()
        if unreadable:
            hits.append(
                Hit(
                    instance=name,
                    evidence="; ".join(unreadable),
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if units["units3"] != units["units4"]:
            continue
        if timeout < interval:
            continue
        hits.append(
            _hit(
                name,
                f"type={_enum_text(r, 'type')}, interval={interval}, resptimeout={timeout}",
                "medium",
                "resptimeout hoort kleiner te zijn dan interval",
            )
        )
    return hits


def _ssl005(ctx):
    # RESIDUAL RISK: `tls13` is read
    # exclusively through `ssl_precedence.resolve()`, which calls
    # `field_text()` internally (ssl_precedence.py:132) - the SAME
    # dead-guard class closed everywhere else in THIS
    # module, but `ssl_precedence.py` is pinned "do not touch" (design: one
    # shared resolver for NSHC-HR-SSL-005 and the SSL-baseline tool,
    # kept byte-identical on purpose), so this call site cannot
    # be converted to `_gate` here. It is not silently unsafe: `resolve()`
    # returning "" for a bool/int/list `tls13` still fails BOTH the
    # ENABLED and DISABLED checks below, and the `else` branch already
    # treats that as NOT ASSESSABLE (never a silent pass) - so an
    # unrecognized shape fails CLOSED today, just without the SHAPE named
    # in its evidence the way every other gate in this module now does.
    # See tests/test_hidden_rules.py::_RESOLVER_ROUTED_FUNCTIONS for the
    # test-side half of this same note.
    index = profile_index(ctx.rows("config/sslprofile"))
    hits = []
    for vserver in ctx.rows("config/sslvserver"):
        found = resolve(vserver, index, "tls13")
        # The bound profile's NAME lives in `found.profile_name` and
        # inside `found.source` ("profiel <naam>") - neither is the
        # instance (the VSERVER name), and no other family reads
        # config/sslvserver's sslprofile field.
        profile_names = (found.profile_name,) if found.profile_bound and found.profile_name else ()
        if found.profile_bound and not found.profile_read:
            hits.append(
                Hit(
                    instance=found.vserver,
                    evidence=(
                        f"TLS 1.3 niet vastgesteld - het gebonden SSL-profiel {found.profile_name}"
                        " staat niet in de gelezen profiellijst"
                    ),
                    confidence="medium",
                    confidence_reason="een gebonden profiel overschrijft de vserver-instelling",
                    not_assessable=True,
                    names=profile_names,
                )
            )
            continue
        if _is(found.value, "ENABLED"):
            continue
        if _is(found.value, "DISABLED"):
            hits.append(
                _hit(
                    found.vserver,
                    f"tls13=DISABLED (bron: {found.source})",
                    "high",
                    "expliciet gelezen veld",
                    names=profile_names,
                )
            )
            continue
        hits.append(
            Hit(
                instance=found.vserver,
                evidence=(f"TLS 1.3 niet vastgesteld (bron: {found.source}; gedocumenteerd zijn ENABLED en DISABLED)"),
                confidence="medium",
                confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                not_assessable=True,
                names=profile_names,
            )
        )
    return hits


_MON002_SKIP_TYPES = ("PING", "ARP")


def _mon002(ctx):
    # _gate: type against PING/ARP - an INVERTED gate (skip this row when
    # type IS one of the skip types). An unreadable type must
    # never be treated as "skip", it becomes NOT ASSESSABLE instead.
    # `state` stays field_text (display-only, same reason as _svc001).
    hits = []
    for r in ctx.rows("config/lbmonitor"):
        name = field_text(r, "monitorname") or "?"
        if _DEFAULT_MONITOR.match(name):
            continue
        skip, unreadable = _gate(r, "type", *_MON002_SKIP_TYPES)
        if unreadable:
            hits.append(
                Hit(
                    instance=name,
                    evidence=unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if skip:
            continue
        # `_num_gate`: a PRESENT but unreadable
        # retries used to collapse to None via `_num` and land on
        # `retries != 0` -> skip, the FAVOURABLE side, silently. An ABSENT
        # retries stays the documented default (NetScaler's own 3, not 0,
        # so not a finding).
        retries, retries_unreadable = _num_gate(r, "retries")
        if retries_unreadable:
            hits.append(
                Hit(
                    instance=name,
                    evidence=retries_unreadable,
                    confidence="medium",
                    confidence_reason="waarde buiten het gedocumenteerde vocabulaire",
                    not_assessable=True,
                )
            )
            continue
        if retries != 0:
            continue
        hits.append(
            _hit(
                name,
                f"type={_enum_text(r, 'type')}, retries=0, state={_enum_text(r, 'state')}",
                "medium",
                "geen marge voor een enkele gemiste probe",
            )
        )
    return hits


CATALOG = (
    Rule(
        "NSHC-HR-CS-001",
        "medium",
        ("config/csvserver",),
        "Met stateupdate=DISABLED (de default) weerspiegelt de CS-vserver de staat van zijn"
        " target-LB niet: gaat een backend DOWN, dan blijft de CS-vserver UP en stuurt verkeer"
        " naar een dode dienst.",
        _cs001,
    ),
    Rule(
        "NSHC-HR-HA-001",
        "high",
        ("config/hanode",),
        "STAYSECONDARY is een onderhoudsstand die routinematig blijft staan na een upgrade of troubleshooting.",
        _ha001,
        instance_is_name=False,
    ),
    # CORRECTION: the plan's why-text here was a
    # paraphrase that does not byte-match NSHC's first sentence. Taken
    # verbatim from NshcHiddenRules.ps1:113 up to the FIRST real sentence
    # break - not the break a naive `re.split(r"(?<=[.!?]) ", why)` would
    # find, which lands mid-abbreviation on "i.p.v." This is the full,
    # well-formed first sentence.
    Rule(
        "NSHC-HR-LB-001",
        "high",
        ("config/lbvserver",),
        "Staat er een spillover-methode (soMethod) ingesteld maar geen backup-vserver, dan wordt"
        " elke overflow-gebeurtenis een STILLE connectie-drop i.p.v. dat verkeer naar een backup"
        " gaat.",
        _lb001,
    ),
    Rule(
        "NSHC-HR-MGMT-001",
        "high",
        ("config/nsip",),
        "Wanneer GUI of SSH op een SNIP/VIP (data-plane) is aangezet, is het beheervlak"
        " bereikbaar via het netwerk waar gebruikersverkeer loopt.",
        _mgmt001,
    ),
    Rule(
        "NSHC-HR-HA-002",
        "medium",
        ("config/hanode",),
        'Met syncstatusstrictmode=DISABLED rapporteert een node "in sync" ook als niet elke feature strikt gesynct is.',
        _ha002,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-HA-003",
        "high",
        ("config/hanode",),
        "Met haprop=DISABLED worden config-wijzigingen op de primary NIET automatisch naar de secondary gepropageerd.",
        _ha003,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-RBAC-001",
        "high",
        ("config/systemcmdpolicy",),
        'Een command-policy met ALLOW op een spec die "shell" matcht laat de gebruiker uit de'
        " NetScaler-CLI naar de onderliggende FreeBSD-shell springen - feitelijk een"
        " RBAC-sandbox-escape met volledige OS-toegang.",
        _rbac001,
    ),
    Rule(
        "NSHC-HR-SSL-001",
        "high",
        (BINDING_CERTKEY,),
        "De ingebouwde self-signed ns-server-certificate hoort alleen voor het beheer-GUI, niet voor productieverkeer.",
        _ssl001,
    ),
    Rule(
        "NSHC-HR-CS-002",
        "medium",
        ("config/cspolicy",),
        "Bij NetScaler advanced-policy bepaalt de tekstmodus of hoofdletters meetellen bij CONTAINS/EQ/STARTSWITH.",
        _cs002,
    ),
    Rule(
        "NSHC-HR-SSL-002",
        "high",
        ("config/sslparameter",),
        "De globale SSL-parameter denySSLReneg bepaalt of clients een TLS-heronderhandeling mogen starten.",
        _ssl002,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-MGMT-002",
        "medium",
        ("config/systemparameter",),
        "systemparameter.strongpassword dwingt complexiteitseisen af op lokale system-accounts"
        " (nsroot en maatwerkbeheerders).",
        _mgmt002,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-MGMT-003",
        "high",
        ("config/nsip",),
        "Telnet en FTP versturen inloggegevens en configuratie ONVERSLEUTELD over het netwerk.",
        _mgmt003,
    ),
    Rule(
        "NSHC-HR-MGMT-004",
        "medium",
        ("config/systemparameter",),
        "systemparameter.timeout is de globale inactiviteits-timeout voor CLI- en GUI-beheersessies.",
        _mgmt004,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-HA-005",
        "high",
        ("config/hanode",),
        "HA failsafe garandeert dat er altijd EEN node primary blijft, ook als beide nodes hun"
        " health-check niet halen.",
        _ha005,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-AAA-001",
        "high",
        ("config/authenticationldapaction",),
        "Een LDAP-action met sectype=SSL of sectype=TLS EN validateservercert=NO bouwt wel een"
        " TLS-verbinding naar de directory op, maar controleert het servercertificaat niet.",
        _aaa001,
    ),
    Rule(
        "NSHC-HR-AAA-003",
        "medium",
        ("config/aaaparameter",),
        "aaaparameter.maxloginattempts begrenst mislukte inlogpogingen voor een account wordt"
        " geblokkeerd - brute-force-mitigatie.",
        _aaa003,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-SVC-001",
        "high",
        ("config/service",),
        "Een config/service met healthmonitor=NO krijgt geen probes: de appliance toont de"
        " dienst dan te allen tijde als UP.",
        _svc001,
    ),
    Rule(
        "NSHC-HR-SVC-002",
        "medium",
        ("config/servicegroup",),
        "USIP=YES (Use Source IP) laat de NetScaler het originele client-IP als source gebruiken naar de backend.",
        _svc002,
    ),
    Rule(
        "NSHC-HR-GLOB-001",
        "medium",
        ("config/nsparam",),
        "nsparam.internaluserlogin bepaalt of de interne gebruiker op de appliance mag inloggen;"
        " NetScaler-functies gebruiken dat account voor interne communicatie.",
        _glob001,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-SSL-003",
        "high",
        ("config/sslprofile",),
        "Bind een beheerder een eigen SSL-profiel aan een vserver, dan overschrijven de"
        " profielwaarden de per-vserver-instellingen.",
        _ssl003,
    ),
    Rule(
        "NSHC-HR-LOG-001",
        "high",
        ("config/auditsyslogparams",),
        "config/auditsyslogparams is de globale, ingebouwde syslog-route van NetScaler: alles wat"
        " niet door een benoemde auditsyslog-policy wordt afgevangen, gaat hierlangs.",
        _log001,
        instance_is_name=False,
    ),
    Rule(
        "NSHC-HR-LOG-002",
        "medium",
        ("config/auditsyslogaction",),
        "UDP-syslog is verbindingsloos: bij netwerksaturatie, een hoge log-rate of een tijdelijk"
        " onbereikbare server kunnen berichten stilzwijgend verdwijnen - geen fout, geen retry,"
        " geen gat dat opvalt.",
        _log002,
    ),
    # CORRECTION: the plan's why-text here was a
    # paraphrase that does not byte-match NSHC's first sentence. Taken
    # verbatim from NshcHiddenRules.ps1:663 up to the first real sentence
    # break (no abbreviation issue in this one - the naive splitter finds
    # the correct break on its own).
    Rule(
        "NSHC-HR-RW-001",
        "high",
        ("config/rewritepolicy", "config/rewriteaction"),
        "Verwijst een niet-default rewritepolicy naar een action-naam die niet in de"
        " action-lijst staat en geen ingebouwde rewrite-policy-action is"
        " (NOREWRITE/RESET/DROP), dan heeft NetScaler bij een match geen geldige actie:"
        " het pad wordt een UNDEF-event (niet herschreven, niet netjes doorgelaten).",
        _rw001,
    ),
    Rule(
        "NSHC-HR-RSP-001",
        "high",
        ("config/responderpolicy",),
        "RESET (stuurt TCP-RST) en DROP (gooit weg, geen antwoord) zijn harde responder-acties.",
        _rsp001,
    ),
    Rule(
        "NSHC-HR-LB-003",
        "high",
        ("config/lbvserver",),
        "sessionless=ENABLED (gebruikt voor doorvoer/DSR) houdt geen sessietabel bij.",
        _lb003,
    ),
    Rule(
        "NSHC-HR-SSL-004",
        "medium",
        ("config/sslcertkey",),
        "Per certificaat bepaalt expirymonitor of NetScaler een melding geeft als het certificaat"
        " bijna verloopt; notificationperiod bepaalt hoeveel dagen van tevoren.",
        _ssl004,
    ),
    Rule(
        "NSHC-HR-MON-001",
        "medium",
        ("config/lbmonitor",),
        "Een monitor hoort binnen het probe-interval een antwoord te krijgen: resptimeout moet"
        " KLEINER zijn dan interval.",
        _mon001,
    ),
    Rule(
        "NSHC-HR-SSL-005",
        "medium",
        ("config/sslvserver", "config/sslprofile"),
        "TLS 1.3 staat op NetScaler standaard uit.",
        _ssl005,
    ),
    Rule(
        "NSHC-HR-MON-002",
        "medium",
        ("config/lbmonitor",),
        "retries bepaalt hoeveel probes NetScaler stuurt om de staat van een dienst vast te"
        " stellen nadat een probe mislukte.",
        _mon002,
    ),
)


def evaluate(export) -> dict[str, Outcome]:
    ctx = Context(export)
    result: dict[str, Outcome] = {}
    for rule in CATALOG:
        unreadable = []
        empty = []
        for resource in rule.requires:
            gap = ctx.gap(resource)
            if gap is not None:
                unreadable.append(f"{resource}: {gap.reason}")
            elif ctx.status(resource) == "EMPTY":
                empty.append(resource)
        if unreadable:
            result[rule.id] = Outcome(
                word="niet beoordeeld",
                evidence=", ".join(rule.requires),
                reason="; ".join(unreadable),
            )
            continue
        if empty:
            # NSHC sets SKIPPED (-> "niet geraakt" here) on ANY required
            # source that is EMPTY and does NOT run the detect - a
            # multi-source rule (RW-001, SSL-005) with one EMPTY source must
            # not evaluate the other source alone, or an object there can
            # produce a hit NSHC would never report for this check.
            result[rule.id] = Outcome(
                word="niet geraakt",
                evidence=", ".join(rule.requires) + " - manifest: EMPTY (NSHC: SKIPPED)",
            )
            continue
        hits = tuple(rule.detect(ctx))
        blocked = tuple(hit for hit in hits if hit.not_assessable)
        real = tuple(hit for hit in hits if not hit.not_assessable)
        if blocked and not real:
            result[rule.id] = Outcome(
                word="niet beoordeeld",
                hits=blocked,
                evidence=", ".join(rule.requires),
                reason="; ".join(f"{h.instance}: {h.evidence}" for h in blocked),
            )
            continue
        if real:
            # A real hit no longer makes a BLOCKED (not-assessable) hit
            # on the same rule vanish. NSHC's Invoke-NshcHiddenRules keeps
            # both explicitly: evidence = realHit lines + naLines, plus the
            # sentence below - a not-assessed object never silently counts
            # as "in orde" just because a different object on the same rule
            # was a real, established hit.
            evidence_lines = [f"{h.instance}: {h.evidence}" for h in real]
            reason = ""
            if blocked:
                evidence_lines += [f"{h.instance}: {h.evidence}" for h in blocked]
                reason = (
                    f"Let op: {len(blocked)} object(en) konden niet worden beoordeeld en tellen NIET mee als in orde."
                )
            result[rule.id] = Outcome(
                word="geraakt",
                hits=real,
                blocked_hits=blocked,
                evidence=", ".join(rule.requires) + ": " + "; ".join(evidence_lines),
                reason=reason,
            )
            continue
        result[rule.id] = Outcome(word="niet geraakt", evidence=", ".join(rule.requires))
    return result


# Weakest-to-strongest rank of a confidence rung. NSHC takes the
# weakest confidence across the REAL hits of a check explicitly
# (`if ($confs -contains 'low') {'low'} elseif ($confs -contains 'medium')
# {'medium'} else {'high'}`), never the first hit's - printing the first
# hit's confidence lets the ROW ORDER in the export decide the printed word.
# An unrecognized value ranks BELOW every named rung (fail-closed, hardening
# rule 6): a typo or a future rung must never sort as if already strong.
_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "beperkt": 2, "high": 3}


def _weakest_confidence_word(hits: tuple[Hit, ...]) -> str:
    """The zekerheid word for the WEAKEST confidence across `hits`."""
    weakest = min(hits, key=lambda h: _CONFIDENCE_RANK.get(h.confidence, -1))
    return _confidence_word(weakest.confidence)


def hidden_rules_answer(export, knowledge: Knowledge) -> Answer:
    outcomes = evaluate(export)
    tally = {word: 0 for word in RULE_WORDS}
    for outcome in outcomes.values():
        tally[outcome.word] += 1
    findings = [
        Finding(
            subject="verstopte regels",
            outcome=f"{len(CATALOG)} regels - " + ", ".join(f"{tally[word]} {word}" for word in RULE_WORDS),
            certainty=Certainty.ESTABLISHED,
            evidence="catalogus NSHC-HR, 16 hoog en 13 midden",
            subject_is_name=False,
        )
    ]
    read_gaps: list[ReadGap] = []
    for rule in CATALOG:
        outcome = outcomes[rule.id]
        detail = ""
        if outcome.word in ("geraakt", "niet beoordeeld"):
            detail = (
                f"{rule.why} [ernst: {SEVERITY_WORDS[rule.severity]},"
                f" zekerheid: {_weakest_confidence_word(outcome.hits)}]"
                if outcome.hits
                else f"{rule.why} [ernst: {SEVERITY_WORDS[rule.severity]}]"
            )
        if outcome.word == "niet beoordeeld":
            detail = f"{outcome.reason}. {detail}"
            read_gaps.append(ReadGap(source=rule.id, reason=outcome.reason))
        elif outcome.word == "geraakt" and outcome.reason:
            # The blocked hits that survived alongside a real one - same
            # visibility a fully-blocked rule already gets, plus a ReadGap
            # PER unestablished object (not one combined gap for the rule).
            detail = f"{detail} {outcome.reason}"
            for h in outcome.blocked_hits:
                read_gaps.append(ReadGap(source=f"{rule.id}: {h.instance}", reason=h.evidence))
        findings.append(
            Finding(
                subject=rule.id,
                outcome=outcome.word,
                certainty=Certainty.NOT_ESTABLISHED if outcome.word == "niet beoordeeld" else Certainty.ESTABLISHED,
                evidence=outcome.evidence,
                reason=detail,
                subject_is_name=False,
            )
        )
    # The ruleset version, exactly as
    # tls_baseline.tls_baseline() already prints it for SSL_BASELINE - one
    # formatter (rulesets.ruleset_line), so a verdict that follows a ruleset
    # always says its version the same way.
    findings.append(
        Finding(
            subject="regelset",
            outcome=f"{HIDDEN_RULES.name} {HIDDEN_RULES.version}",
            certainty=Certainty.ESTABLISHED,
            evidence=ruleset_line(HIDDEN_RULES),
            subject_is_name=False,
        )
    )
    return Answer(
        question="wat zit hier verstopt dat niemand ziet",
        findings=findings,
        read_gaps=read_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_hidden_rule_sources(export) -> tuple[str, ...]:
    """Every appliance object name and address this answer can print - the
    TENTH family of disclosure.names_from_export().

    Runs the CATALOG itself and harvests TWO things from every hit of every
    rule:
    - the `instance`, but only for a rule whose instance IS a name
      (`instance_is_name`);
    - `hit.names`, UNCONDITIONALLY - every name/address a detect put in
      its EVIDENCE text lives here, and evidence is never gated by
      `instance_is_name` (that flag is only ever about the instance).
    One source (this function), two consumers (`names_from_export()` and
    every detect's own `Hit(...)` call) - so a rule added tomorrow cannot
    leak a name because somebody forgot a second list here.

    MEASURED (2026-09-06, on the real export): NSHC-HR-MGMT-001 and
    NSHC-HR-MGMT-003 print IP ADDRESSES (192.0.2.6, 198.51.100.5,
    192.0.2.3) as their INSTANCE, and NSHC-HR-SSL-005 prints sslvserver
    names as its instance. Measured on a synthetic export, premise
    proven first: NSHC-HR-SSL-005 ALSO prints the bound SSL-profile's name
    in its evidence, NSHC-HR-RW-001 the rewrite action name a policy points
    at, NSHC-HR-LOG-002 the syslog destination address, and NSHC-HR-SSL-001
    the certkeyname from the binding file - none of those four are the
    instance of their rule, and none of the other nine disclosure families
    reads that evidence text, so before `Hit.names` existed all four reached
    'beperkt'/'minimaal' verbatim.

    Rules whose instance is a LABEL of the appliance-wide object
    ("sslparameter", "systemparameter", "nsparam", "aaaparameter",
    "auditsyslogparams", "node 0") set `instance_is_name=False`: masking
    those costs the reader the answer and writes product vocabulary into the
    operator's pseudonym table as if it were a real object. `hit.names` is
    NOT gated by this flag - a detect must only ever put a real name/address
    there, regardless of what its instance represents.
    """
    ctx = Context(export)
    names: set[str] = set()
    for rule in CATALOG:
        if any(ctx.gap(resource) is not None for resource in rule.requires):
            continue
        for hit in rule.detect(ctx):
            if rule.instance_is_name:
                text = hit.instance.strip()
                if text and text != "?":
                    names.add(text)
                    # The instance of MGMT-001/-003 is "<address> (<type>)";
                    # the bare address must be maskable too, or the
                    # parenthesis form is the only spelling ever replaced.
                    if " (" in text:
                        names.add(text.split(" (", 1)[0].strip())
            for extra in hit.names:
                clean = extra.strip()
                if clean and clean != "?":
                    names.add(clean)
    return tuple(sorted(names))
