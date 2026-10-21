"""Shared answer shape.

Every outcome of this product travels in this shape. The rules live here in
code and not in an agreement, because an agreement does not enforce: a finding
without evidence cannot be constructed, and neither can a non-established
finding without a reason. A reader must always be able to see WHY something
is not established.

There are THREE kinds of ignorance, and they do not belong on one pile:

1. A NOT_ESTABLISHED finding - we looked, but what we found allowed no
   conclusion (for example a ca flag in an unrecognizable form).
2. A ReadGap - a source we tried to read and could not get usable (hash does
   not match, RBAC_DENIED, file missing). This rightly blocks what comes
   after it: `what_to_do` gives no advice while a read gap is open.
3. NotAssessed - a dimension this version deliberately does NOT look at.

The third exists because the first two cannot carry it: a ReadGap would block
the whole chain forever (the product would never propose an action again),
and a NOT_ESTABLISHED finding has the same effect. "I could not read this
source" and "this version does not look at this" are also two different
statements: the first says something is wrong with the export, the second
says something about the boundary of the product. Hence a concept of its own,
with the same discipline: no statement without a subject and without a reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from enum import Enum
from functools import cache

from nsmcp.limits import capped_text

# The character class per vocabulary, keyed by (allow_underscore, allow_hyphen).
_TOKEN_CHARS = {
    (True, True): "A-Z0-9_-",
    (True, False): "A-Z0-9_",
    (False, True): "A-Z0-9-",
    (False, False): "A-Z0-9",
}


@cache
def _token_pattern(max_words: int, allow_underscore: bool, allow_hyphen: bool) -> re.Pattern[str]:
    chars = _TOKEN_CHARS[(allow_underscore, allow_hyphen)]
    return re.compile(rf"[A-Z][{chars}]*(?: [{chars}]+){{0,{max_words - 1}}}")


def repeatable_token(
    value,
    *,
    max_words: int = 4,
    max_len: int = 32,
    allow_underscore: bool = True,
    allow_hyphen: bool = True,
) -> str | None:
    """The token, when this value may be REPEATED in an answer; None otherwise.

    THE one shape gate for values an export carries that this version does
    not recognize. Three modules used to hold their own copy of it -
    `impact._ENUM_TOKEN` (a NITRO enumeration such as ROOT_CERT),
    `dienst._STATE_TOKEN` (a member state, up to four words) and
    `overzicht._TOKEN_SHAPE` (an HA/vserver state, hyphen instead of
    underscore) - and the copies had drifted: the dienst one carried NO
    length bound, so a single 232-character "state" out of a supplied export
    matched the shape and was echoed verbatim into an answer.

    Why a positive shape test at all: an export can be SUPPLIED (see
    export.py), the disclosure layer's name collection does not read these
    fields, and text in them therefore reaches the model UNMASKED. A NITRO
    token is uppercase, short and at most a handful of words; a sentence is
    none of those. Naming only the SHAPE of anything else (`shape_of`) is
    the rule everywhere else in this product, and this function is what lets
    the three call sites keep applying it identically.

    The switches carry the differences the three vocabularies really have -
    a state token has no hyphen, an HA status has no underscore, an
    enumeration is one word - so the gate stays exactly as tight as it was
    per call site, with one implementation instead of three.

    Returns the STRIPPED text, so a caller can echo what it just approved
    instead of re-normalizing the raw value itself.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > max_len:
        return None
    if _token_pattern(max_words, allow_underscore, allow_hyphen).fullmatch(text) is None:
        return None
    return text


def _safe(value: str) -> str:
    """Every piece of text that came from OUTSIDE and is rendered into an
    answer goes through here.

    SECURITY 17, the export half. Object names and field values come out of a
    file nobody authenticated and travel verbatim into the model's context.
    Two things matter and neither is about content: a value with a line break
    can draw what looks like an extra section of the answer, and a value
    without a ceiling can fill the context. `to_text()` is the ONE place where
    all of that text comes together - putting the ceiling in six analysis
    modules would be six places to forget it.

    This is not a filter on meaning, and nothing here claims it is. The
    prompt-injection paragraph in docs/klant/SECURITY.md says so in as many
    words.

    The `str()` is the RENDERING step and belongs here, not inside
    `capped_text()`: every call site below already interpolated its value into
    an f-string, so a field that is somehow not a string keeps rendering
    exactly as it did before instead of raising inside the text builder. It is
    also why this is the only place `capped_text()` may be handed a value that
    was not confirmed to be a string first - there the truncation flag matters
    and here it is deliberately dropped, because a rendered answer says it was
    cut in the text itself.
    """
    text, _ = capped_text(str(value))
    return text.replace("\n", " ")


def safe_text(value: str) -> str:
    """Public name for `_safe`, for the one reading tool outside the
    `Answer.to_text()` seam (mcp_server.py's kennis_uitleg, and
    `_with_explanation`'s appended `uitleg`) that must interpolate an
    untrusted package value straight into an f-string instead of through a
    `Finding`/`ReadGap`/`NotAssessed`. Same ceiling, same newline
    flattening, called through `_safe` so there is one implementation, not
    two."""
    return _safe(value)


# What an answer says when there is genuinely nothing to report. Product copy,
# pinned in tests/test_product_surface.py. The sentence names BOTH halves on
# purpose: the doctrine of this product is that an empty list because there was
# nothing differs from an empty list because a read failed, and an empty body
# showed neither.
NO_FINDINGS = "Geen bevindingen: binnen deze vraag is niets gevonden, en er is geen enkele bron onleesbaar gebleven."


class Certainty(Enum):
    ESTABLISHED = "vastgesteld"
    NOT_ESTABLISHED = "niet vastgesteld"


@dataclass(frozen=True)
class ReadGap:
    """A source that could not be read into something usable. Never silently empty."""

    source: str
    reason: str

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("a read gap without a source is meaningless")
        if not self.reason.strip():
            raise ValueError("a read gap without a reason is meaningless")


@dataclass(frozen=True)
class NotAssessed:
    """A dimension this version deliberately does not assess. Never silently gone.

    Unlike a ReadGap this does not block the chain: nothing went wrong with
    the export, there is only something this version does not look at. Still
    visible, always with the reason attached - staying silent would be the
    same as claiming it was assessed.
    """

    subject: str
    reason: str

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ValueError("not-assessed without a subject is meaningless")
        if not self.reason.strip():
            raise ValueError("not-assessed without a reason is meaningless")


@dataclass(frozen=True)
class Finding:
    subject: str
    outcome: str
    certainty: Certainty
    evidence: str
    reason: str = ""
    # Is this subject an APPLIANCE OBJECT NAME? The disclosure seam collects
    # every finding subject as a name to mask (disclosure._collect_names), and
    # for expiry/impact/dienst that is exactly right - those subjects are
    # certificates, services, servicegroups and members. But cve.py and
    # overzicht.py write this product's OWN vocabulary in there ("build",
    # "HA", the vserver family labels, "CVE-oordeel") and public bulletin and
    # CVE identifiers. Masking those costs the reader the answer AND writes
    # them into the operator's pseudonym table as if they were real objects on
    # their appliance - the one file that decodes the real names, polluted
    # with words that never came off an appliance.
    #
    # Default True, so the fail-closed behaviour is unchanged: a new finding
    # is masked unless its author states that the subject is not a name.
    subject_is_name: bool = True
    # May this finding exist BELOW 'volledig'? The disclosure seam drops it
    # entirely at 'beperkt' and 'minimaal' when this is True.
    #
    # For one measured class of statement, masking is not enough: a finding
    # that ANSWERS A QUESTION ABOUT THE CALLER'S OWN INPUT ("which names
    # contain the term you typed") turns the seam into an adaptive substring
    # oracle. The pseudonyms are stable, so a, ab, abc ... reads off per step
    # whether a real name continues that way, and the caller reconstructs the
    # name it was never shown. The COUNT is the same oracle, so a version
    # that only hid the names would not close it either.
    #
    # Default False, so nothing that exists today changes: a finding is
    # rendered at every level unless its author states that it may only be
    # said when real names may be said anyway.
    #
    # ONE INVARIANT an author of such a finding must keep: an answer whose
    # ONLY content is findings flagged here renders below 'volledig' as
    # genuinely empty, and would then pick up NO_FINDINGS - which would be
    # untrue, because something WAS found and deliberately withheld. Measured
    # today: no producer does that. `impact.what_breaks` always carries the
    # two not-assessed dimensions, and `dienst.service_status` always writes
    # the "niet gevonden" finding beside the candidate line. Add a flagged
    # finding without such a companion and that stops holding.
    only_in_full: bool = False
    # Does this finding count toward the "N vastgestelde bevinding(en)"
    # tally `disclosure._minimal()` reports? Default True, so nothing
    # existing changes. False is for a finding whose own outcome IS a
    # SUMMARY of other findings already in this same answer - counting
    # both would tally the same fact twice: `compare.py`'s
    # three block-header findings ("configuratieverschillen: N
    # [vastgesteld]") are the first, and so far only, producer that sets
    # this - they exist to be READ at 'volledig'/'beperkt', not to be
    # counted a second time at 'minimaal' next to the N findings they
    # already summarize.
    counted_at_minimal: bool = True

    def __post_init__(self) -> None:
        if not self.evidence.strip():
            raise ValueError("a finding without evidence must not exist")
        if self.certainty is Certainty.NOT_ESTABLISHED and not self.reason.strip():
            raise ValueError("a non-established finding requires a reason")


def _days_old(days: int) -> str:
    """'1 dag oud', otherwise '<n> dagen oud' - customer copy, so no broken plural."""
    return "1 dag oud" if days == 1 else f"{days} dagen oud"


def knowledge_age_line(knowledge_date: str | None, knowledge_age_days: int | None) -> str:
    """The one line describing a knowledge package's age.

    Extracted out of `Answer.stamp_lines()` below so the fact has ONE
    builder with TWO callers instead of two independent renderings that
    could drift apart: `stamp_lines()` (every answer built from an
    `Answer`) and `kennis_uitleg`'s handler (`mcp_server.py`), the one
    reading tool that builds no `Answer` and calls no `render()`.
    `kennis_uitleg` carries the knowledge-base age line only, never the
    data/export line - that one does not apply to a tool that reads no
    export. Takes plain values, not an `Answer`, so a caller with no
    `Answer` to build can still produce the identical text.
    """
    if knowledge_date is None or knowledge_age_days is None:
        return "Kennisbasis: ONBEKEND - er is geen kennispakket geladen."
    return f"Kennisbasis van {knowledge_date}, {_days_old(knowledge_age_days)}."


@dataclass(frozen=True)
class Answer:
    question: str
    findings: list[Finding] = field(default_factory=list)
    read_gaps: list[ReadGap] = field(default_factory=list)
    not_assessed: list[NotAssessed] = field(default_factory=list)
    knowledge_age_days: int | None = None
    knowledge_date: str | None = None
    data_age_days: int | None = None
    data_date: str | None = None
    data_age_reason: str | None = None
    # The SUBJECT next to the data age: which target produced the export.
    # Set by stamp_data() below, like the three fields above it. None
    # honestly means "niet vastgelegd" (a supplied export has no scan file)
    # - never a guess.
    data_target: str | None = None
    # WHERE the export came from, next to the target it claims: "verzameld
    # door deze server op <tijd>" when this server's own provenance record
    # carries this export, "niet vastgesteld (aangeleverde export)" when none
    # does. Set by the server at the same stamp as the three fields above;
    # None (a unit answer, or no readable manifest) leaves the line as it was.
    data_provenance: str | None = None

    def __post_init__(self) -> None:
        # The stamped state is all-or-nothing, exactly as _age() promises:
        # precisely one of (date+days) or (reason), or - before stamping -
        # none of the three. A reason therefore cannot coexist with a date or
        # with a known age (otherwise an answer says "1 dag oud" and
        # "onleesbaar" at the same time), and date/days are only valid
        # together (otherwise it is half a stamp: a date without an age or
        # the other way around).
        has_reason = self.data_age_reason is not None
        has_date = self.data_date is not None
        has_days = self.data_age_days is not None
        if has_reason and (has_date or has_days):
            raise ValueError("a data age combined with a reason is contradictory")
        if has_date != has_days:
            raise ValueError("data_date and data_age_days must only occur together")

    def is_complete(self) -> bool:
        """Complete means: every source this answer needed was read into something usable.

        A read gap therefore never lets an answer be complete. A dimension
        deliberately not assessed (`not_assessed`) does NOT count here:
        nothing went wrong reading there, this version simply does not look
        at it. It is visible in the text, and that is where it belongs -
        were it to make an answer incomplete, `what_to_do` would never
        propose an action again and the product would be broken instead of
        honest.
        """
        return not self.read_gaps

    def _extra_lines(self) -> list[str]:
        """Extension point for a subclass that needs to add lines just
        before the trailing Kennisbasis/Gegevens stamps. Default: none.

        `ImpactAnswer.usage` is the one override today - it replaces a
        `len(lines) - 3` magic index into a SPLIT `to_text()` result, and a
        `not self.not_assessed` proxy for "am I `disclosure._minimal()`'s
        synthetic stripped copy", with this named seam instead. `_minimal()`'s
        copy clears `findings`/`read_gaps`/`not_assessed` together to borrow
        this exact tail via a fixed-length slice; a subclass override can key
        on that real, observable state instead of a single coincidental
        proxy.
        """
        return []

    def _leading_lines(self) -> list[str]:
        """Extension point for a subclass that wants its answer to OPEN
        with a line, before "Vraag: ...". Default: none - every existing
        tool's rendered text is therefore unchanged; only a subclass that
        overrides this (`health.HealthAnswer`) opens with anything.

        Symmetric to `_extra_lines()` above, and for the same reason: a
        cross-cutting change to `Answer` (here, "this one tool's answer
        opens with its data age") belongs at a named seam on the shared
        shape, not a `to_text()` override in the one module that needs it.
        """
        return []

    def _data_age_line(self) -> str:
        """The one line describing this answer's data age and target -
        shared by the CLOSE of every answer (`stamp_lines()` below, the
        footer `to_text()` and `disclosure._minimal()` both build from) and,
        for a subclass that opts in via `_leading_lines()`, its OPEN as well.
        Extracted so the renderings of the
        same fact cannot drift apart. The two values that come from the
        EXPORT go through `_safe` HERE - the one builder - so every caller
        is covered by construction (merged 14-9-2026).
        """
        target_text = _safe(self.data_target) if self.data_target else "niet vastgelegd"
        # Product copy, never text from outside: the server builds it from a
        # parsed moment of its own record.
        provenance = f", herkomst: {self.data_provenance}" if self.data_provenance else ""
        if self.data_date is None or self.data_age_days is None:
            reason = _safe(self.data_age_reason) if self.data_age_reason else "dit antwoord is niet gestempeld"
            return f"Gegevens: ONBEKEND - {reason}; doel: {target_text}{provenance}."
        return f"Gegevens van {self.data_date}, {_days_old(self.data_age_days)}, doel: {target_text}{provenance}."

    def stamp_lines(self) -> list[str]:
        """The two age stamps - the knowledge line and the data line - as the
        lines they render as. Always exactly two; never empty.

        Public on purpose, and the ONE place these two lines are assembled
        together for an `Answer`. The knowledge line itself is built by the
        module-level `knowledge_age_line()` above (its own builder now,
        shared with `kennis_uitleg`); the data line stays `_data_age_line()`
        below, an `Answer` method because it also reads `data_target`.
        `to_text()` builds its own footer from this, and so does
        `disclosure._minimal()`, which writes its own body of counts and needs
        the same footer under it. That seam used to harvest the stamps by
        rendering an artificially EMPTIED copy of the answer and slicing the
        result at a magic index. The copy was empty by construction, so every
        line `to_text()` gained landed in EVERY minimal answer - which is how
        the empty-answer sentence below reached answers reporting findings and
        read gaps. One builder, two callers: the two cannot drift.

        It is also why the gate on export text sits HERE and not in
        `to_text()`: two of the values in these lines come out of the export,
        and putting `_safe` in the builder covers both callers by
        construction instead of leaving `_minimal()` to remember it.
        """
        lines = [knowledge_age_line(self.knowledge_date, self.knowledge_age_days)]
        # The target sits in the SAME place and in the SAME way as the data
        # age - unconditionally. "niet vastgelegd" is the honest text for a
        # supplied export (no scan file); that is not a guess, it is the
        # absence of a fact that deserves to be as visible as the fact
        # itself.
        #
        # `data_target` and `data_age_reason` are the only two values in this
        # footer that come from the EXPORT, so they are the only two that go
        # through `_safe` - the VALUES, never the Dutch around them, which is
        # product copy. That happens in `_data_age_line()` above, the ONE
        # builder of this line: this footer, `_minimal()`'s footer and a
        # subclass's opening line (`_leading_lines()`) all read it, so the
        # renderings of the same fact cannot drift apart. `data_target` is
        # the first line of the target file, and `data_age_reason` quotes the
        # manifest's own `collectedAtUtc` verbatim when it does not parse (see
        # `_age`); neither is bounded by anything but the 32 MB file ceiling.
        # The rest of this footer is not from outside: `data_date` is built
        # here from a parsed datetime, the day counts are ints, and
        # `knowledge_date` only exists after `date.fromisoformat()` accepted it.
        lines.append(self._data_age_line())
        return lines

    def to_text(self) -> str:
        lines = list(self._leading_lines())
        lines.append(f"Vraag: {self.question}")
        lines.append("")
        for b in self.findings:
            lines.append(f"- {_safe(b.subject)}: {_safe(b.outcome)} [{b.certainty.value}]")
            lines.append(f"    bewijs: {_safe(b.evidence)}")
            if b.reason:
                lines.append(f"    reden: {_safe(b.reason)}")
        if self.read_gaps:
            lines.append("")
            lines.append("NIET VASTGESTELD (geen stille aanname):")
            for g in self.read_gaps:
                lines.append(f"- {_safe(g.source)}: {_safe(g.reason)}")
        if self.not_assessed:
            lines.append("")
            lines.append("NIET BEOORDEELD IN DEZE VERSIE (bewust buiten bereik, geen aanname):")
            for n in self.not_assessed:
                lines.append(f"- {_safe(n.subject)}: {_safe(n.reason)}")
        # A silence is not an outcome: an empty body left the reader guessing
        # between "there was nothing" and "nothing could be read". Note what
        # this sentence can NOT do: it cannot turn an unread source into a
        # claim, because an unread source is a ReadGap and this branch is then
        # not taken at all.
        if not self.findings and not self.read_gaps and not self.not_assessed:
            lines.append(NO_FINDINGS)
        lines.extend(self._extra_lines())
        lines.append("")
        lines.extend(self.stamp_lines())
        return "\n".join(lines)


def _age(collected_at: str | None, today: date) -> tuple[str | None, int | None, str | None]:
    """(date, days, reason) - precisely one of (date+days) or (reason) is filled."""
    if collected_at is None or not str(collected_at).strip():
        return None, None, "de export draagt geen tijdstempel"
    try:
        # From Python 3.11 onward fromisoformat reads the 'o' format of the
        # collect script directly: 7 fractional digits plus Z. That is the
        # reason pyproject.toml pins >=3.11; lowering it breaks this silently.
        moment = datetime.fromisoformat(str(collected_at))
    except ValueError:
        return None, None, f"tijdstempel onleesbaar: {collected_at}"
    # Both sides in the SAME frame. The manifest field is called
    # collectedAtUtc, so a stamp without a zone is UTC; and `today` must be a
    # UTC day. Compare a UTC day against a local day here and an export five
    # minutes old in CEST reports "1 dagen oud" as soon as it was made after
    # 02:00 local - precisely the number this field exists for.
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    utc_day = moment.astimezone(UTC).date()
    days = (today - utc_day).days
    if days < 0:
        return None, None, f"tijdstempel ligt in de toekomst: {collected_at}"
    return utc_day.isoformat(), days, None


def export_age(collected_at: str | None, today: date) -> tuple[int | None, str | None]:
    """(days, None) or (None, reason): the age of an export on `today`, by
    the SAME rule as the data line under every answer (`_age`), so a count
    corrected for the age of the export can never disagree with that line."""
    _stamp_date, days, reason = _age(collected_at, today)
    return days, reason


def stamp_data(
    answer: Answer,
    collected_at: str | None,
    today: date,
    target_name: str | None = None,
    *,
    provenance: str | None = None,
) -> Answer:
    """Sets the age of the DATA on an answer, separate from that of the knowledge.

    Deliberately here and not in expiry/impact/action: the analysis stays
    untouched, and because every tool passes through this function at the
    server boundary, no answer can leave unstamped.

    `today` MUST be a UTC day (`datetime.now(timezone.utc).date()`), because
    the timestamp in the export is UTC. Pass `date.today()` here and you
    compare a local day against a UTC day and the age is wrong.

    `target_name` is the subject next to the age: which target produced the
    export, or None when that was not recorded (a supplied export). Default
    None, so callers that know no target need to do nothing -
    `Answer.to_text()` itself turns that into the honest text
    "niet vastgelegd", not an assumption. `provenance` is the server's own
    sentence about where the export came from (see `Answer.data_provenance`).
    """
    stamp_date, days, reason = _age(collected_at, today)
    return replace(
        answer,
        data_date=stamp_date,
        data_age_days=days,
        data_age_reason=reason,
        data_target=target_name,
        data_provenance=provenance,
    )
