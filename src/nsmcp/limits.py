"""The ceilings on everything this product reads from outside itself.

Why ceilings at all. Neither the export nor the knowledge package is
authenticated; both are trusted inputs (see docs/klant/SECURITY.md,
"Vertrouwensmodel en scope"). Trusted is not the same as unbounded: measured,
100.000 objects loaded out of one file without a murmur, a 20 MB `uitleg`
field travelled to the model, and 60.000 levels of nesting raised a
RecursionError that escaped the fail-closed handling.

The rule these ceilings follow, and it differs per kind of content:

* a ceiling on something a VERDICT rests on is fail-CLOSED - it becomes a read
  gap with a named reason, never a truncated verdict;
* a ceiling on TEXT that only informs a human is fail-VISIBLE - it is cut and
  says in the text that it was cut.

Never silent, in either direction.
"""

from __future__ import annotations

import unicodedata

# 32 MB. The real lab export carries a 34 KB manifest and a 181 KB largest
# object file; this is three orders above it and still read in well under a
# second.
MAX_FILE_BYTES = 32 * 1024 * 1024

# The real export carries at most 31 objects in one source. 50.000 lets any
# imaginable large customer through and stops the 100.000 of the probe.
MAX_OBJECTS_PER_FILE = 50000

# The real running config is 333 lines.
#
# Measured (2026-09-07). The old comment here
# ("the tokenizer did 200.000 lines in 1,85 s, so this ceiling stays under
# five seconds of work") was measured before the credential filter
# (redact.py) existed and only ever priced ONE pass. Measured fresh on this
# machine, on 200.000 lines built from the real fixture running config
# (tests/fixtures/lab-export-vpx-20260826/parsed/runningconfig.txt, repeated
# to length): redact_config_lines() alone costs about 3,0 s per 200.000
# lines (1,5 s at 100.000) - a SECOND full Python-level pass on top of
# cve.py's own tokenizer (_tokens), which costs about 2,4 s per 200.000
# lines by itself. Both scale with whatever `running_config_lines()`
# returns, and that call is uncached: cve.py calls it six times per CVE
# answer, so the real per-answer cost is six of these passes, not one.
# 500.000 priced only the old single pass at "under five seconds"; at
# today's two-pass cost (about 3,0 s + 2,4 s per 200.000 lines, so
# roughly 13 s at 500.000) that ceiling is worth roughly a dozen
# seconds of work, times six per answer. Lowered to 100.000: about
# 1,5 s of redaction for one call (well under the original
# five-second target for a single pass), and still about two and a
# half orders of magnitude (100.000 / 333 is roughly 300) above the
# real 333-line config. The six-calls-per-answer multiplier is a real,
# separate cost
# this ceiling does not remove - memoising `running_config_lines()` would,
# but that trade (weaker mid-answer swap detection) is its own design
# round, not this ceiling.
MAX_TEXT_LINES = 100000

# The deepest real structure is three levels.
MAX_JSON_DEPTH = 100

# About 1200 words - more than any real bulletin text.
MAX_FREE_TEXT_CHARS = 8192

# The whole package together, so many small fields cannot do what one large
# field may not.
MAX_KNOWLEDGE_TEXT_CHARS = 65536

# Dutch, because it is read by the operator inside an answer. Product copy.
# "de bron", not "het kennispakket": the same note is used for free text from
# the export (see answer._safe).
TRUNCATION_NOTE = " [...] (tekst afgekapt: de bron droeg hier meer dan het plafond)"


class PackageShapeDefeatsCap(Exception):
    """Raised by `shrink_to_package_cap` when cutting every field in the
    fixed order still cannot bring the sum under `cap`.

    This is NOT "one long note": every field has already been cut as far as
    it can go (down to `TRUNCATION_NOTE` alone, or to nothing at all for a
    field too short to carry even that), and the sum STILL does not fit. That
    only happens when the package's SHAPE defeats the ceiling - many fields,
    each barely above `TRUNCATION_NOTE`'s own length, so that even their
    fully-cut floor (one note per field) adds up past `cap`. A single large
    field can never cause this: it can always be cut all the way down to the
    note. The caller refuses the whole package here, fail-CLOSED, with a
    reason a human can read - the same discipline `knowledge.py` already
    applies to an absent or unreadable package.
    """

    def __init__(self, total: int, cap: int) -> None:
        self.total = total
        self.cap = cap
        super().__init__(
            f"kennispakket: de vrije tekstvelden samen zijn na volledige afkap"
            f" nog steeds {total} tekens en overschrijden het plafond van {cap}"
            f" - dit pakket bevat te veel velden om het plafond ooit te halen"
        )


def exceeds_depth(value, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when `value` nests deeper than `limit`.

    Walks with its OWN stack and never recurses: a recursive check would blow
    up on exactly the input it exists to refuse, and the caller would get a
    RecursionError instead of an answer. Stops at the first level past the
    limit, so a hostile document costs bounded work.
    """
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(current, dict):
            for item in current.values():
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))
    return False


# SR-9 (1.0.2). The Unicode categories that are invisible or that move text
# around without being text: control characters (Cc - ESC, NUL, NEL, ...),
# format characters (Cf - zero-width space, the bidi overrides and isolates,
# a byte-order mark), the line and paragraph separators (Zl, Zp) and lone
# surrogates (Cs). Measured in the security review of 1.0.0: a right-to-left
# override, a line separator and an ESC sequence in an object name all
# reached the model verbatim. Each one becomes a visible "?" (a tab a
# space); the newline is the one Cc character kept, because the line
# endings are normalised above and the renderer flattens it itself.
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})
HIDDEN_CHARACTER_MARK = "?"

# The longest a NAME may be when it is echoed in an answer. Moved here from
# `export.py` (which still exports it under the same name) so `answer.py`
# can apply it without importing `export.py`. See the measurement there.
NAME_ECHO_MAX_LEN = 128


def is_hidden_character(character: str) -> bool:
    """True for a character `neutralise_hidden` replaces (a newline too)."""
    return unicodedata.category(character) in _HIDDEN_CATEGORIES


def neutralise_hidden(text: str) -> str:
    """`text` with every invisible or text-moving character made visible:
    `HIDDEN_CHARACTER_MARK` for each, a space for a tab, and the newline
    kept. Plain printable text comes back unchanged."""
    if text.isprintable():
        return text
    return "".join(
        character
        if character == "\n" or not is_hidden_character(character)
        else (" " if character == "\t" else HIDDEN_CHARACTER_MARK)
        for character in text
    )


def capped_text(value: str, cap: int = MAX_FREE_TEXT_CHARS) -> tuple[str, bool]:
    """Returns (text, truncated) for a free text field from outside.

    Two things happen, and both are about the same risk: a field from a file
    nobody authenticated ends up verbatim in the model's context. Line endings
    are normalized (CRLF and a bare CR become LF) so a field cannot forge what
    looks like a new answer line, and the length is capped with a visible
    sentence - never a silent cut.
    """
    text = neutralise_hidden(str(value).replace("\r\n", "\n").replace("\r", "\n"))
    if len(text) <= cap:
        return text, False
    return text[:cap] + TRUNCATION_NOTE, True


def shrink_to_package_cap(
    fields: list[tuple[str, str]], cap: int = MAX_KNOWLEDGE_TEXT_CHARS
) -> tuple[dict[str, str], list[str]]:
    """Cuts free text fields until their SUM fits under `cap`, or refuses.

    `fields` is already in the fixed order the design lays down (design 3.6
    unit 3): begrippen values first, then advies, extraStapNaUpgrade, kern,
    and uitleg last - uitleg last because that field IS the answer of
    kennis_uitleg, while the other four are a note beside a verdict.

    Deterministic on purpose: same package, same result, on every install. It
    walks the list in the given order and takes what it needs from each field
    before moving to the next, so a package that is a little too large loses a
    little of the first group instead of a bit of everything.

    Returns the changed fields by name and the names that were cut. A field
    that was already within the cap is not in either.

    Two shapes of field, and each is cut differently because a `TRUNCATION_NOTE`
    (`note_len` characters) always travels back in with a cut:

    * A field LONGER than the note (`len(text) > note_len`): cutting `take`
      characters off its tail only shrinks the SUM by `take - note_len`, so
      the loop targets a `reduction` in the sum directly and derives `take`
      from it. Its floor is the note alone (`note_len` characters) - it can
      never be cut to less than that and still carry a note.
    * A field AT OR BELOW the note's own length (`len(text) <= note_len`):
      appending the note here could only ever grow the field, never shrink
      it, so instead of leaving it untouched (the pre-fix defect: SKIPPED,
      meaning a package made entirely of such fields was never touched at
      all) it is emptied outright - reduction equals its full length, no
      note. A partial silent cut here was rejected on purpose: a fragment
      too short to explain itself is worse than no fragment.

    Both shapes are budgeted into the SAME `overshoot` counter, so a residual
    check after the loop is exact: if every field has been cut as far as it
    can go (every long field down to its note, every short field to nothing)
    and the sum STILL exceeds `cap`, no further cutting can ever close the
    gap - the package's SHAPE defeats the ceiling, not one long field. That
    is refused here, fail-CLOSED, by raising `PackageShapeDefeatsCap`: this
    function returns `(changed, truncated)` only when the sum it leaves
    behind is `cap` or under - never `cap` plus a note per field, and never
    silently over it either.
    """
    total = sum(len(text) for _, text in fields)
    overshoot = total - cap
    if overshoot <= 0:
        return {}, []
    note_len = len(TRUNCATION_NOTE)
    changed: dict[str, str] = {}
    truncated: list[str] = []
    for name, text in fields:
        if overshoot <= 0:
            break
        if not text:
            continue
        max_reduction = len(text) - note_len
        if max_reduction > 0:
            reduction = min(overshoot, max_reduction)
            cut = reduction + note_len
            changed[name] = text[: len(text) - cut] + TRUNCATION_NOTE
        else:
            # Cannot pay for its own note: emptied outright (never a partial
            # cut without a note - that would be exactly the silent
            # truncation this module refuses everywhere else).
            reduction = len(text)
            changed[name] = ""
        truncated.append(name)
        overshoot -= reduction
    if overshoot > 0:
        # Every field has been cut to its floor (a note, or nothing) and the
        # sum still does not fit under `cap`. `cap + overshoot` is the exact
        # final sum without a second pass: each `reduction` above already
        # equals the real shrink in total length, so the invariant
        # `final_total == total - sum(reductions) == cap + overshoot` holds
        # all the way through the loop.
        raise PackageShapeDefeatsCap(cap + overshoot, cap)
    return changed, truncated
