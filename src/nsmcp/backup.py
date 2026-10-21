"""The backup this product asks the appliance to make of itself.

The FIRST writing tool outside the demo allowlist, and the one the rollback
point of an upgrade rests on. Two things live here and nowhere else: how the
name is formed (this side, in UTC, because the NetScaler CLI has no
`$(date)`), and how the read-back is judged.

The read-back is on the COLLECTION and never a GET on the name. Measured on
the lab: a removed object answered a GET-by-name with 599 instead of 404
(lab lesson `nitro-readback-599-vs-404`), so an error on that route cannot be
told apart from an absence. A backup that cannot be FOUND in the list is a
FAILED action, not a warning - the whole point of this tool is that a later
phase may lean on it.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from nsmcp.upgrade import cli_time_text, config_state

BACKUP_LEVEL = "full"
_NAME_PREFIX = "gjk_preupgrade_"
_STAMP_FORMAT = "%Y%m%d_%H%M%S"

# HARDENING requirement: "config strings ... never used raw as paths". `target`
# comes straight from the configuration and lands, unfiltered otherwise,
# inside a name the write script hands to the appliance as an object/file
# name. Letters, digits, dot, hyphen, underscore - the same shape
# `handelen._NAME` already requires of every OTHER object name this product
# hands to a write script.
#
# That precedent is not only the charset - `_NAME` also caps the WHOLE name
# it grammar-checks at 63 characters (`[A-Za-z][A-Za-z0-9._-]{0,62}`), and
# the name `backup_name()` forms below is exactly that kind of name too: an
# object/file name handed to the same write script. So the same 63-character
# ceiling applies to it, and the budget left for `target` (`MAX_TARGET_LENGTH`
# below) is DERIVED from that ceiling, not invented (
# an earlier version of this fix cited `_NAME` as the model for the charset
# and then dismissed it for the length, as "a different grammar" - it cannot
# be the precedent for one and not the other).
#
# PUBLIC on purpose: start.py's `_allowlist()`
# imports `valid_target_name()` below and applies it at STARTUP, to the same
# doelnamen this module refuses at CALL TIME. Before that fix, `_allowlist()`
# only checked for a non-empty stripped string - so "lab noord" and "../x"
# both passed startup, and only failed here, mid-proposal, as an uncaught
# `ValueError` that `_act()` does not catch (masked to "Onverwachte fout").
# The grammar therefore lives here ONCE and both call sites import it, so
# they can never drift apart again.
TARGET_CHARSET = "A-Za-z0-9._-"
VALID_TARGET_PATTERN = re.compile(rf"^[{TARGET_CHARSET}]+$")

# The two values the character class above cannot exclude by itself: both
# are made only of dots, and both mean "this directory" or "the parent
# directory" - a path instruction, not a name, even though a pure charset
# check lets them through. Design 2.3's export path makes a doelnaam
# exactly that: a path segment (`<exportmap>\<doelnaam>\`), so "." is
# equally a path instruction as ".." is - the
# repo's own precedent already lists both together
# (the regression coverage below,
# `name in ("", ".", "..")`). Refusing both once, in the shared predicate,
# keeps every caller from having to reason about the case on its own.
_RESERVED_TARGET_NAMES = frozenset({".", ".."})

# `handelen._NAME`'s own ceiling: `[A-Za-z][A-Za-z0-9._-]{0,62}` is 1 first
# character plus up to 62 more, 63 total. Cannot be imported here -
# `handelen.py` already imports from this module, so the reverse import
# would be circular - so the number is pinned as a comment and cross-checked
# against the REAL `handelen._NAME` regex by a test instead
# (`tests/test_backup.py::test_the_handelen_name_ceiling_this_module_assumes_has_not_drifted`),
# so the two cannot silently drift apart.
_HANDELEN_NAME_MAX_LENGTH = 63

# The part of the formed name that is NOT `target`: the fixed prefix, the
# underscore that joins it to the stamp, and the stamp itself. Computed from
# the actual constants above (not retyped as a literal number) so a future
# change to `_NAME_PREFIX` or `_STAMP_FORMAT` moves this budget with it
# instead of quietly going stale. The stamp format always produces a
# fixed-width string (zero-padded), so any reference instant gives the
# real width.
_STAMP_WIDTH = len(datetime(2000, 1, 1, tzinfo=UTC).strftime(_STAMP_FORMAT))
_FIXED_NAME_OVERHEAD = len(_NAME_PREFIX) + len("_") + _STAMP_WIDTH

# What `target` may spend of `handelen._NAME`'s 63-character ceiling once the
# fixed prefix and the stamp have taken their share - not a number invented
# for this fix, see the comment on `VALID_TARGET_PATTERN` above.
MAX_TARGET_LENGTH = _HANDELEN_NAME_MAX_LENGTH - _FIXED_NAME_OVERHEAD


def target_name_rules() -> str:
    """The Dutch clause every refusal of a bad `target` shares, built from
    the actual constants above (not retyped) so this text, `backup_name()`'s
    own `ValueError` and `start._allowlist()`'s `ConfigError` can never say
    three different things about the same predicate.
    """
    gereserveerd = " of ".join(repr(n) for n in sorted(_RESERVED_TARGET_NAMES, key=len))
    return (
        f"alleen tekens uit [{TARGET_CHARSET}], niet de gereserveerde waarde {gereserveerd}, "
        f"en ten hoogste {MAX_TARGET_LENGTH} tekens (de gevormde appliance-naam mag zelf niet "
        f"langer zijn dan {_HANDELEN_NAME_MAX_LENGTH} tekens - dezelfde grens als handelen._NAME)"
    )


def valid_target_name(target) -> bool:
    """Whether `target` is an acceptable backup target name: a non-empty
    string made only of letters, digits, dot, hyphen, underscore
    (`VALID_TARGET_PATTERN`), not one of the reserved values "." or ".."
    and, since `target` ends up inside a NAME that must itself satisfy
    `handelen._NAME` (see `MAX_TARGET_LENGTH` above), no longer than
    `MAX_TARGET_LENGTH`. The single source of truth `backup_name()` and
    `start._allowlist()` both call, so a doelnaam accepted at startup can
    never be refused later, mid-proposal, by this module.
    """
    return (
        isinstance(target, str)
        and bool(VALID_TARGET_PATTERN.fullmatch(target))
        and target not in _RESERVED_TARGET_NAMES
        and len(target) <= MAX_TARGET_LENGTH
    )


# What the write script prints when it found the object again. The product
# does not compose this sentence - it READS it, and it refuses to call an
# action successful without it. Only a POSITIVE line counts: it starts (after
# whitespace) with `[OK]` directly followed by the phrase. The phrase alone is
# not enough, because a line that reports the object as missing
# (`[FOUT] teruggelezen ...: <naam> ontbreekt`) or only warns about it names
# the object too.
_READBACK = re.compile(
    r"^\s*\[OK\]\s*teruggelezen op de collectie config/systembackup:\s*(?P<detail>.+)$", re.IGNORECASE
)

# A line that carries one of these is never a positive read-back, whatever
# it starts with. Checked on the line in lower case with its whitespace
# folded to single spaces, so `niet  gevonden` or `niet<TAB>gevonden` counts
# as well.
_NEGATIVE_READBACK_WORDS = ("[fout]", "[waarschuwing]", "ontbreekt", "niet gevonden")

# A line that starts (after whitespace) with `[FOUT]`. When it names the
# object, the whole read-back fails, also next to a positive line: the
# script itself reports that something went wrong with this object, and its
# own success path never prints such a line. A `[WAARSCHUWING]` line does
# NOT do this - the script's success path prints one when the create call
# returned an error but the object is there.
_FAILURE_LINE = re.compile(r"^\s*\[FOUT\]", re.IGNORECASE)


def backup_name(target: str, now: datetime) -> str:
    """`gjk_preupgrade_<doel>_<jjjjmmdd_hhmmss>`, always in UTC.

    Design 2.3 row B4 fixes this form. UTC because the ledger, the action
    register and the export names use it too, and because a local time exists
    twice a year - a backup with an ambiguous name is a backup you cannot
    order.

    `target` is refused, not sanitized, when it fails `valid_target_name()`:
    this name becomes an appliance-side object/file name, and a config
    string is untrusted until proven otherwise (HARDENING requirement).
    Silently stripping characters would still hand the script a name nobody
    asked for; refusing tells the operator their configuration needs a look.
    """
    if not valid_target_name(target):
        raise ValueError(
            f"doelnaam {target!r} voldoet niet aan de eisen ({target_name_rules()}); een "
            "backupnaam voor de appliance mag dat niet dragen"
        )
    stamp = now.astimezone(UTC).strftime(_STAMP_FORMAT)
    return f"{_NAME_PREFIX}{target}_{stamp}"


def readback_ok(text: str, name: str | None) -> tuple[bool, str]:
    """Did the write script find the object back in the collection?

    Returns (True, the detail line) or (False, the reason). Fail closed: no
    positive `[OK]` line, a line without the name, a line that carries a
    negative word (`_NEGATIVE_READBACK_WORDS`), an empty detail, or any
    `[FOUT]` line that names the object all mean NOT found, also at exit 0 -
    and so does a `name` that is not a string,
    is empty, or does not carry
    the `gjk_preupgrade_` prefix this product always forms. That last check
    is what keeps this function from ever raising on a bad `name`: an
    unchecked `name in detail` on a non-string `name` throws `TypeError`
    instead of failing closed (measured on the shipped code before this
    fix), and an unchecked EMPTY `name` matches any non-empty detail line -
    two different ways the gate used to say yes when it should say no.
    """
    if not isinstance(name, str) or not name or not name.startswith(_NAME_PREFIX):
        return False, (
            f"de gevormde backupnaam ({name!r}) is ongeldig of ontbreekt; de teruglezing kan "
            "niet worden getoetst en de handeling telt daarmee als mislukt"
        )
    lines = str(text).splitlines()
    if any(_FAILURE_LINE.match(line) and name in line for line in lines):
        return False, (
            f"het schrijfscript meldt een [FOUT]-regel over het object {name}; het telt daarmee als "
            "niet gevonden in de teruglezing op de collectie config/systembackup en de handeling als mislukt"
        )
    for line in lines:
        match = _READBACK.match(line)
        folded = " ".join(line.lower().split())
        if match is None or any(word in folded for word in _NEGATIVE_READBACK_WORDS):
            continue
        detail = match.group("detail").strip()
        if name in detail and detail:
            return True, detail
    return False, (
        f"het object {name} is niet gevonden in de teruglezing op de collectie "
        "config/systembackup; de handeling telt daarmee als mislukt"
    )


# `config_opslaan`: the save script (scripts/Invoke-GjkConfigOpslaan.ps1)
# prints the raw answer of `show ns config`, read right after `save ns config`
# in the same SSH session, one line per line behind this prefix, and one
# status line with the exit code of that read. The script judges nothing; the
# judgement is `save_readback_ok()` below.
SAVE_MEASUREMENT_PREFIX = "[METING] show ns config: "
SAVE_MEASUREMENT_STATUS_PREFIX = "[METINGSTATUS] show ns config: "


def save_readback_ok(text: str) -> tuple[bool, str]:
    """Is the last save, read back after `save ns config`, not older than the
    last change? Returns (True, the sentence that says so) or (False, the
    reason). Fail closed: no measurement lines, not exactly one status line
    saying `exitcode=0`, or any shape `upgrade.config_state()` does not
    know, all mean NOT saved - never a silent success.

    The text is split on `\\n` alone. `str.splitlines()` also splits on a
    carriage return inside a line, and appliance text after one could then
    start a measurement line of its own. Only lines that START with the
    prefix count, and the script prints every appliance-derived line behind
    a prefix of its own.

    Neither sentence quotes the appliance: the two moments are parsed and
    written back in this product's own format (`upgrade.cli_time_text`)."""
    regels = [regel.rstrip("\r") for regel in str(text or "").split("\n")]
    metingen = [r[len(SAVE_MEASUREMENT_PREFIX) :] for r in regels if r.startswith(SAVE_MEASUREMENT_PREFIX)]
    statussen = [
        r[len(SAVE_MEASUREMENT_STATUS_PREFIX) :].strip() for r in regels if r.startswith(SAVE_MEASUREMENT_STATUS_PREFIX)
    ]
    mislukt = "; de handeling telt als mislukt"
    if not metingen:
        return False, "de teruglezing (show ns config) ontbreekt in de uitvoer van het opslagscript" + mislukt
    if statussen != ["exitcode=0"]:
        return False, "de teruglezing (show ns config) is niet aantoonbaar geslaagd gelezen" + mislukt
    stand = config_state("\n".join(metingen))
    if not stand.readable:
        return False, f"de teruglezing van show ns config heeft een onbekende vorm ({stand.reason})" + mislukt
    opslag, wijziging = cli_time_text(stand.saved), cli_time_text(stand.changed)
    if not stand.saved_after_change:
        return False, (
            "de teruglezing toont dat de configuratie is gewijzigd na de laatste opslag (laatste opslag "
            f"{opslag}, laatste wijziging {wijziging})" + mislukt
        )
    return True, f"laatste opslag {opslag} is niet ouder dan laatste wijziging {wijziging}"
