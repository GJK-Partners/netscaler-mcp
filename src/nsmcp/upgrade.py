"""Which gate opens which phase - and nothing about SSH.

The runner is a separate process and it SPEAKS to the appliance; this module
JUDGES what that process measured. The split is deliberate (design
decision 3): design chapter 6 requires a mutation proof per new gate, and a
proof that only runs on a Windows workbench proves nothing on the CI runner
this gate leans on. So the script measures and Python decides - one
implementation of every rule, with a named test around it.

Everything here is fail closed. A gate has exactly three outcomes and only
`open` lets a phase through; `niet beoordeeld` never counts as `open`. The
one exception is the vendor pre-check, which has no `niet beoordeeld` at all:
an unread vendor verdict at a firmware installation is not an open question
but a no (design 3.5).

THE LEDGER IS THE TRUTH, not a log line and not a script's own exit code.
`read_ledger()` is the only reader; `phase_state()` and `soak_state()` build
every verdict a caller may see from what it returns, never from anything a
runner printed. `append_line()` is the only writer, and it is append-only
and fsynced before the next action begins - the same discipline the action
register and the ledger's own field list (`tijd`, `run`, `doel`, `fase`,
`gebeurtenis`, `poort`, `uitkomst`, `bewijs`, `actieid`, `bevestiger`,
`gestart`, `geeindigd`) both assume.

HARDENING: every string this module reads back out of a ledger file, or
receives as a measurement from the runner's JSON, is UNTRUSTED - a ledger a
future version reads was written by a process this module does not control.
`Path` objects otherwise only ever come from the CALLER (`read_ledger`,
`append_line`, `wait_for_start`), never assembled out of ledger content. The
one deliberate exception is `run` - it names the ledger FILE itself
(`<ledgermap>/<run>.jsonl`), so it cannot stay an opaque string the way
every other ledger field does. `is_safe_run_name()` and `ledger_path_for()`
below are the belt and the braces around that one exception: the first
refuses anything that is not a safe path SEGMENT before it is used for
anything, the second resolves the path either caller (an operator-supplied
`run`, or one ADOPTED straight out of a ledger row) would build from it and
refuses unless it still sits inside `ledgermap`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import warnings
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.preflight import (
    ASSUMED_BUNDLE_MB,
    BACKUP_RESOURCE,
    BUILD_TREE_LOCATION,
    BUILD_TREE_RESOURCE,
    VENDOR_FLOOR_MB,
    build_tree_entries,
)
from nsmcp.upgrade_plan import MINIMUM_SOAK_HOURS, PHASE_NAMES, PHASE_TITLES

GATE_TYPES: tuple[str, ...] = ("voorwaarde", "bewijs", "mens", "tijd")
GATE_OUTCOMES: tuple[str, ...] = ("open", "dicht", "niet beoordeeld")
PHASE_OUTCOMES: tuple[str, ...] = ("gestart", "poort dicht", "geslaagd", "mislukt", "niet beoordeeld")
SOAK_WORDS: tuple[str, ...] = ("loopt", "verstreken")

# The eight families R0 and R5 count, pinned once and in this order. A ninth
# or a missing eighth is a change of the design: before and after would then
# no longer be comparable (design 3.5).
FAMILIES: tuple[str, ...] = (
    "lbvserver",
    "csvserver",
    "vpnvserver",
    "authenticationvserver",
    "service",
    "servicegroup",
    "sslcertkey",
    "lbmonitor",
)

# Design ceilings, not measurements - they exist to make a hanging session
# fall over, not to reject a slow box. The measurements of 6-9 (upload 460 s,
# precheck 17.4 s, installns 50 s, return 87 s) fit inside them with room.
PHASE_LIMITS_S: dict[str, int] = {"R0": 0, "R1": 3600, "R2": 900, "R3": 1800, "R4": 1800, "R5": 300, "R6": 0}
START_WAIT_S = 20

# The ceiling `open_phases()` below uses for a phase whose OWN ceiling is 0.
# R0 and R6 carry no duration gate at all (`_duration_verdict`: "a phase
# whose limit is 0 carries no ceiling and gets no gate") - which is right for
# JUDGING a phase, and wrong for deciding how long an UNCLOSED one may keep a
# target locked: a zero there would mean "forever". DERIVED, not invented:
# the widest ceiling this product knows, so no phase is ever called
# over-time sooner than the longest phase is allowed to take.
NO_CEILING_FALLBACK_S = max(PHASE_LIMITS_S.values())

# The absolute lower bound under the formula, design 3.5.
ABSOLUTE_FLOOR_MB = 6144

# The three kinds of line that carry a blob which is re-encrypted on every
# read (measured: three reads of an unchanged config gave three hashes).
_BLOB_PREFIXES = ("set ns encryptionParams", "set ns rpcNode")
_BLOB_MARKER = "-encrypted"

# HARDENING: `global_status` and the failed-check names in `precheck_gate`
# come straight from the vendor's own JSON - UNTRUSTED - and land in
# evidence/reason and thence the ledger. Bounded rather than raw, the same
# discipline `collect._short_report`/`_scrub_error_text` already apply to
# the SSH-script's stderr; a deliberate deviation from the earlier verbatim
# approach.
_UNTRUSTED_ECHO_LIMIT = 200
_MAX_GEZAKTE_CHECKS_GETOOND = 20
# A LIST of untrusted names needs a ceiling on the
# COUNT as well as on each name - bounding only the elements still lets an
# export with hundreds of `build-*` rows write an unbounded evidence string.
_MAX_BUILDBOMEN_GETOOND = 20
_NAAM_ECHO_LIMIT = 80

# The ledger vocabulary: which `gebeurtenis` value closes a phase, and what
# `phase_state()` calls that closed phase. R0 closes with `voormeting_vast`
# and R6 with `soak_open` - neither is `fase_geslaagd` by name, but both ARE
# the phase succeeding (design: "de ledger, letterlijk" - R0's and R6's own
# rows in that table). `terugrolpunt_vast` is the EXTRA evidence row R0
# writes before its closing row; it closes nothing by itself and is not in
# this map.
_CLOSING_EVENTS: dict[str, str] = {
    "fase_geslaagd": "geslaagd",
    "fase_mislukt": "mislukt",
    "poort_dicht": "poort dicht",
    "voormeting_vast": "geslaagd",
    "soak_open": "geslaagd",
}

# Rows that carry EVIDENCE and no phase state at all - today just R0's
# `terugrolpunt_vast`. `phase_state()` skips them: they neither start nor
# close a phase, so letting one be "the last row" would misreport a running
# R0 as `niet beoordeeld`.
_EVIDENCE_EVENTS: tuple[str, ...] = ("terugrolpunt_vast", "voorpoort")


@dataclass(frozen=True)
class Gate:
    name: str
    type: str
    outcome: str
    evidence: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.type not in GATE_TYPES:
            raise ValueError(f"unknown gate type: {self.type}")
        if self.outcome not in GATE_OUTCOMES:
            raise ValueError(f"unknown gate outcome: {self.outcome}")
        if self.outcome != "open" and not self.reason.strip():
            raise ValueError("a gate that is not open must say why")


@dataclass(frozen=True)
class PhaseVerdict:
    phase: str
    outcome: str
    gates: tuple[Gate, ...]
    evidence: str
    reason: str = ""


def _iso_z(dt: datetime) -> str:
    """UTC ISO-8601 with a bare `Z` suffix - the same shape `ledger_line()`
    already writes. Never `f"{dt.isoformat()}Z"`: an AWARE datetime's own
    `isoformat()` already ends in `+00:00`, so appending another `Z` on top
    produces `+00:00Z`, a string `datetime.fromisoformat` cannot parse
    back.

    `dt` MUST be aware, the same discipline `run_id()` applies. A NAIVE
    datetime's `isoformat()` carries no `+00:00` for the replace to hit, so
    this function used to promise "a bare Z" and silently hand back a
    string WITHOUT one - a timestamp that reads as local time to whoever
    gets it next. An aware non-UTC value is converted rather than refused;
    only the unanswerable case fails closed.
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("_iso_z: a naive datetime carries no UTC promise - pass an aware one")
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _read_moment(waarde) -> datetime | None:
    """One timestamp from stdin, a ledger row or an export manifest, as an
    AWARE UTC `datetime`, or `None` when it cannot be read. A NAIVE value is
    read as UTC - the ledger's and the export's own timestamps are UTC by
    contract - so a naive one is judged instead of raising.

    Moved here from `upgrade_gate.py`: that module
    already imports from this one, never the other way round, so a helper
    every gate-forming function in THIS file also needs (`export_age_gate`)
    cannot stay a private copy one layer up - `upgrade_gate.py` now imports
    this same function instead of keeping its own, so there is one
    implementation, not two that can drift apart (the same discipline
    `_bounded` above is held to).
    """
    if waarde is None or not str(waarde).strip():
        return None
    try:
        moment = datetime.fromisoformat(str(waarde).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _bounded(text, limiet: int = _UNTRUSTED_ECHO_LIMIT) -> str:
    """Caps an UNTRUSTED string before it is echoed into a gate's evidence
    or reason - never raw and unbounded into the ledger."""
    tekst = str(text)
    if len(tekst) <= limiet:
        return tekst
    return tekst[:limiet] + "...(afgekapt)"


def _bounded_or(value, fallback: str, limiet: int = _UNTRUSTED_ECHO_LIMIT) -> str:
    """`_bounded()`, but a value that is empty OR ALL WHITESPACE falls back
    to `fallback` instead of surviving as blank text.

    `stand_answer()`: a ledger's own
    `bewijs`/`reden` field is UNTRUSTED, and the `laatste.get("bewijs") or
    "..."` idiom this replaces treats a lone space as truthy - Python does
    too - so a `bewijs` of `"   "` survived `_bounded()` unchanged and
    `Finding.__post_init__` then raised `ValueError` on blank evidence (or,
    for a NOT_ESTABLISHED finding, on a blank reason). Stripping before the
    truthiness test closes that without changing what a REAL value renders
    as - `_bounded()` still runs on the untouched (unstripped) text."""
    tekst = str(value) if value is not None else ""
    if not tekst.strip():
        return fallback
    return _bounded(tekst, limiet)


def _bounded_run_echo(value: str, limiet: int = _UNTRUSTED_ECHO_LIMIT) -> str:
    """A `run` value read out of the LEDGER, made safe to put into an
    operator-facing `Finding.outcome`.

    `limiet` is optional, defaulting to the
    same `_UNTRUSTED_ECHO_LIMIT` this function always bounded to, so its
    two existing callers (`mcp_server.py`'s adopted-`run` findings) are
    unchanged. `code_channel.SsoCodeChannel` passes a larger one for the
    `voorstel` field of its JSON payload - that field is a value in a JSON
    document a presenter PARSES, not a line printed to a terminal, and 200
    characters cut a 748-character real proposal off inside its own FIRST
    finding, before the phase being approved ever appeared. The sanitising
    (line-collapse, control-character scrub) is unchanged either way - only
    the LENGTH this is cut to becomes the caller's choice.

    `onderhoud_upgrade_stand`
    (`mcp_server.py`) ADOPTS `run` from the ledger (`latest_run_name()`)
    when the caller did not supply one, and, unlike a caller-SUPPLIED
    `run` (checked with `is_safe_run_name()` before it is used anywhere -
    `mcp_server.py`, right above this call), the adopted value reached
    `Finding(outcome=...)` with no bound and no check at all. `_bounded()`
    alone caps LENGTH, not CONTENT: a single ledger row with a `run` field
    carrying an embedded newline and a fabricated finding line
    (`"r1\\n- R0: geslaagd [vastgesteld]\\n    bewijs: ..."`) rendered as
    though that finding were real, verbatim, in `Answer.to_text()`'s
    newline-joined output - forging a finding an operator would read as
    the tool's own.

    `str.splitlines()` collapses every line-boundary character Python's
    own `"\\n".join()` would treat as a new line - not only `\\n`/`\\r`,
    also the same `U+2028`/`U+0085` `read_ledger()`'s own docstring already
    singles out - so a payload built around either of those alone does not
    slip past a plain `.replace("\\n", " ")`. `_bounded()` still runs
    afterwards, on the now-single-line text, for length.

    HARDENING (this is now the ONE implementation
    of this sanitiser - `knowledge_refresh.py` used to carry a verbatim
    duplicate, `_safe_echo()`, and now imports this function instead):
    collapsing line breaks alone still let through every OTHER non-
    printable character - a raw ESC byte (an ANSI cursor-up/erase-line
    pair), BEL or NUL among them. A crafted value ending in
    `\\x1b[1A\\x1b[2K` rewrites the line an operator already `type`d in a
    terminal the moment this text is printed, which defeats the audit
    visibility a sanitiser exists to buy in the first place - collapsing
    the NEWLINE that would have started a fake second line is not enough
    if the terminal can be told to erase the real one instead. Every
    character `str.isprintable()` itself refuses (the C0/C1 control
    range, plus the same line/paragraph separators `splitlines()` above
    already treats as a break) is replaced with a plain space next - the
    same `.isprintable()` idiom `knowledge._offered_problem()` already
    applies to `aangeboden.bron`, there to REJECT a package outright,
    here to SANITISE a value that is only ever echoed, never judged."""
    collapsed = " ".join(str(value).splitlines())
    printable = "".join(char if char.isprintable() else " " for char in collapsed)
    return _bounded(printable, limiet)


def _bounded_tail(text, limiet: int = _UNTRUSTED_ECHO_LIMIT) -> str:
    """`_bounded`, but keeping the END of an untrusted string instead of the
    start.

    `installns`'s own progress output is long and its `END_TIME` line, the
    ONE thing the "installatie voltooid" gate judges on, is the LAST thing
    it prints. Bounding that from the head guarantees the ledger evidence
    can never show the fact the gate decided on; the evidence would describe
    a different part of the output than the judgement. The old PowerShell
    code took the last 200 characters by hand for exactly this reason - the
    reason survives the move into Python, the hand-rolled truncation does
    not."""
    tekst = str(text)
    if len(tekst) <= limiet:
        return tekst
    return "(afgekapt)..." + tekst[-limiet:]


def run_id(doel: str, now) -> str:
    """`<UTC-tijdstempel>-<doel>`, the run's own name and the ledger file's
    stem (`<ledgermap>/<run-id>.jsonl`). Time first, so a directory listing
    sorts runs chronologically without reading a single file.

    `now` MUST be an aware datetime. `datetime.astimezone()` silently reads
    a NAIVE datetime as SYSTEM LOCAL TIME before converting it to UTC - a
    caller that means "this is already UTC" and passes a naive value would
    get a run id shifted by the local UTC offset, silently. Fail closed
    instead of guessing.
    """
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError(
            "run_id: 'now' must be an aware datetime - a naive one would be "
            "read as system local time by astimezone(), silently"
        )
    return f"{now.astimezone(UTC).strftime('%Y%m%dT%H%M%S')}Z-{doel}"


# A safe RUN NAME: one path segment, nothing else. Unlike an appliance
# object name (`handelen._NAME`, which the real NetScaler API already
# requires to start with a letter), a run name may legitimately start with
# a DIGIT - `run_id()` above forms one as `<UTC-tijdstempel>Z-<doel>`, and
# R1..R6 expect that value copied back verbatim as their own `run` argument.
#
# The character class alone already excludes a path separator (neither '/'
# nor '\\' is in it), a drive letter or UNC prefix and an alternate-data-
# stream marker (all three need a ':', not in it either), '..' as the
# WHOLE value (it would have to start with a '.', and the class requires
# the first character to be alphanumeric) and a control character. 128 is
# generous headroom over the longest value `run_id()` itself ever produces
# (a 17-character timestamp prefix plus up to 63 characters of `doel`).
_RUN_NAME_MAX = 128
_RUN_NAME_RE = re.compile(rf"[A-Za-z0-9][A-Za-z0-9._-]{{0,{_RUN_NAME_MAX - 1}}}")

# What the character class above does NOT exclude: a reserved Windows
# device name. Opening "CON", "CON.jsonl" or "con.anything" does not create
# a file at all - it targets the device, silently, regardless of case or
# extension. Windows itself compares only the part BEFORE THE FIRST '.',
# which is what `is_safe_run_name()` below checks against this set.
_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)


def is_safe_run_name(value: str) -> bool:
    """True for a `run` value safe to use as ONE filesystem path SEGMENT -
    never a path itself, and never trusted to be one just because it looks
    like one.

    Two callers rely on this: `handelen.validate_phase_arguments()`, for
    the OPERATOR-supplied `run` argument on R1..R6, and
    `mcp_server._upgrade_work()`, for a run name ADOPTED straight out of a
    ledger row on R0 - a value from a file this product does not control
    (module docstring above: "Nothing here echoes such a string into a
    path"), and the harder-to-typo-into, more interesting attack of the
    two.

    A reserved Windows device name and a value ending in '.' (Windows
    strips a trailing dot itself, silently turning it into a different
    name) are refused on top of the character class - see the comments on
    `_RUN_NAME_RE` and `_RESERVED_DEVICE_NAMES` above for why the class
    alone does not already cover them.
    """
    if not value or not _RUN_NAME_RE.fullmatch(value):
        return False
    if value.endswith("."):
        return False
    return value.split(".", 1)[0].upper() not in _RESERVED_DEVICE_NAMES


def ledger_path_for(ledgermap, run_name: str) -> Path:
    """The ONE construction that turns a run name into a ledger file path -
    `<ledgermap>/<run_name>.jsonl` - BELT AND BRACES around whichever gate
    already checked `run_name` safe (`handelen.validate_phase_arguments()`
    for an operator-supplied one, `is_safe_run_name()` above, called
    directly, for one ADOPTED out of a ledger row): resolves the path this
    would build and refuses unless it still sits inside `ledgermap` and
    nowhere else - so a value that somehow got past validation still
    cannot escape it. Raises `ValueError`, the same bare exception
    `run_id()` above raises on its own misuse; the caller turns that into
    whatever refusal shape its own surface uses.
    """
    base = Path(ledgermap).resolve()
    candidate = (base / f"{run_name}.jsonl").resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError("ledger_path_for: run_name resolves outside ledgermap") from None
    return candidate


def precheck_gate(json_text) -> Gate:
    """The ONE vendor gate, and the only one without `niet beoordeeld`.

    Measured 6-9: `installns --pre_check` exits 0 while its own JSON says
    `global_status: failed`. The exit code is therefore used NOWHERE in this
    function - it is not even a parameter. The gate opens only when BOTH hold:
    `global_status` is not `failed`, AND no individual check has status
    `failed`. One of the two is not enough.
    """
    if not json_text or not str(json_text).strip():
        return Gate(
            "vendor-precheck",
            "bewijs",
            "dicht",
            "geen precheck-JSON",
            "de vendor-precheck leverde geen leesbaar oordeel",
        )
    # Strip only the MEASURED wrapper (lab-02, 8-9-2026: 'Warning: [ One or
    # more RPC nodes are configured with default passwords. For enhanced
    # security, you must change the default RPC node password. ]', then the
    # CLI's own ' Done') and require the entire remaining text to be ONE
    # JSON document. Extra objects, unknown preambles and trailing
    # diagnostics refuse. Anchored on the first sentence and tolerant up to
    # the closing bracket: the vendor's second sentence has been seen with
    # and without line breaks, and a stricter pin would silently stop
    # stripping on the very box it was measured on.
    tekst = str(json_text).strip()
    banner = re.match(
        r"\AWarning:\s*\[\s*One or more RPC nodes are configured with default passwords\."
        r".*?\](?:\r?\n[ \t]*Done[ \t]*)?(?:\r?\n|\Z)",
        tekst,
        re.S,
    )
    if banner:
        tekst = tekst[banner.end() :].strip()
    tekst = re.sub(r"\r?\n[ \t]*Done[ \t]*\Z", "", tekst).strip()
    try:
        data = json.loads(tekst)
    except json.JSONDecodeError:
        data = None
    if data is None:
        return Gate(
            "vendor-precheck",
            "bewijs",
            "dicht",
            "precheck-JSON onleesbaar",
            "de vendor-precheck leverde geen leesbaar oordeel",
        )
    if not isinstance(data, dict) or "global_status" not in data:
        return Gate(
            "vendor-precheck",
            "bewijs",
            "dicht",
            "precheck-JSON zonder global_status",
            "de vendor-precheck leverde geen leesbaar oordeel",
        )
    global_status_ruw = str(data.get("global_status"))
    global_status = _bounded(global_status_ruw)
    gezakt = [
        _bounded(str(c.get("name", "(naamloos)")))
        for c in data.get("checks", []) or []
        if isinstance(c, dict) and str(c.get("status", "")).lower() == "failed"
    ]
    bewijs = f"global_status={global_status}; gezakte checks={len(gezakt)}"
    if global_status_ruw.lower() == "failed" or gezakt:
        if len(gezakt) > _MAX_GEZAKTE_CHECKS_GETOOND:
            genoemd = gezakt[:_MAX_GEZAKTE_CHECKS_GETOOND]
            namen = f"{', '.join(genoemd)}, en {len(gezakt) - _MAX_GEZAKTE_CHECKS_GETOOND} meer"
        else:
            namen = ", ".join(gezakt)
        return Gate(
            "vendor-precheck",
            "bewijs",
            "dicht",
            bewijs,
            "de vendor-precheck meldt een blokkade" + (f": {namen}" if gezakt else ""),
        )
    return Gate("vendor-precheck", "bewijs", "open", f"{bewijs}; de exitstatus telt NIET mee")


def disk_gate(free_mb, bundle_mb, unpack_mb, *, bundle_present: bool = False) -> Gate:
    """`vrij_nu - bundel - uitpakkosten >= 4004 MB`, met 6 GB als ondergrens.

    The old house rule (`>= 2 x bundle`) was wrong in FORM and in NUMBER, and
    that is measured: run (a) passed it with 6429 MB free and a threshold of
    2162 MB, after which `installns` refused anyway. The vendor keeps
    4_100_000 blocks of 1k free on /var and tests that AFTER unpacking.

    The refusal names the THREE TERMS separately - vendor floor, bundle size,
    unpack cost - next to the measured value, so an administrator can see how
    much has to go. "Too little space" forces guessing, and guessing while
    clearing /var costs the rollback path.

    An UNMEASURED bundle or unpack size is never silently 0 MB - that would
    collapse the requirement to the bare vendor floor and OPEN the gate on a
    box that has not actually been checked. `preflight._check_8_free_space`
    already has the correct pattern (`preflight.py`, `own_floor_mb`'s own
    caller): substitute `ASSUMED_BUNDLE_MB` and NAME the assumption in the
    evidence. "Unmeasured" is that same function's FALSY test and not `is
    None`: an empty string used to raise a `ValueError` straight out of
    this gate, and a literal `0` used to count as a MEASURED zero - which
    with both sizes at zero left only the absolute floor standing. A
    missing `free_mb` stays honestly `niet beoordeeld`; a measured `0` MB
    free is a real measurement and closes the gate.

    `bundle_present`: true when the CALLER already
    knows the bundle needs no further transfer space at all - measured to
    be on the box already, with a matching hash (R1's own upload-skip)
    - and the bundle term is therefore a DELIBERATE zero, never
    "unmeasured". Without this flag, a falsy `bundle_mb` of `0` was
    indistinguishable from a size that was simply never read, and this
    function substituted `ASSUMED_BUNDLE_MB` for it regardless - the exact
    opposite of "no second copy is coming", and the evidence claimed the
    size "ontbrak" for a number the runner measured moments earlier and
    chose to omit on purpose. `unpack_mb` keeps its EXISTING falsy-is-
    unmeasured rule either way - only the bundle term's meaning changes.
    """
    if bundle_present:
        bundel_aangenomen = False
        bundel = 0
    else:
        bundel_aangenomen = not bundle_mb
        bundel = ASSUMED_BUNDLE_MB if bundel_aangenomen else int(bundle_mb)
    uitpak_aangenomen = not unpack_mb
    uitpak = ASSUMED_BUNDLE_MB if uitpak_aangenomen else int(unpack_mb)
    eis = VENDOR_FLOOR_MB + bundel + uitpak
    drempel = max(eis, ABSOLUTE_FLOOR_MB)
    aanname = (
        f" (aangenomen bundelgrootte {ASSUMED_BUNDLE_MB} MB waar de gemeten grootte ontbrak)"
        if bundel_aangenomen or uitpak_aangenomen
        else ""
    )
    # Only the SUBSTITUTED numbers are printed: the raw `bundle_mb` used to
    # leak a Python `None` into customer-facing Dutch, and the assumption
    # used to sit INSIDE the refusal's own parenthetical (which left it
    # unbalanced). The assumption follows the closing bracket instead.
    bundel_zin = "bundel al op de doos: 0 MB nog te ontvangen" if bundle_present else f"bundel {bundel} MB"
    bewijs = (
        f"df -k /var in de eigen SSH-sessie; vendorvloer {VENDOR_FLOOR_MB} MB + {bundel_zin} "
        f"+ uitpakkosten {uitpak} MB = {eis} MB, ondergrens "
        f"{ABSOLUTE_FLOOR_MB} MB, drempel {drempel} MB{aanname}"
    )
    if free_mb is None:
        return Gate(
            "vrije ruimte op /var", "bewijs", "niet beoordeeld", bewijs, "df -k /var leverde geen bruikbare waarde"
        )
    if int(free_mb) < drempel:
        return Gate(
            "vrije ruimte op /var",
            "bewijs",
            "dicht",
            f"{bewijs}; gemeten {free_mb} MB",
            f"gemeten {free_mb} MB is minder dan {drempel} MB "
            f"(vendorvloer {VENDOR_FLOOR_MB} MB, {bundel_zin}, "
            f"uitpakkosten {uitpak} MB){aanname}",
        )
    return Gate("vrije ruimte op /var", "bewijs", "open", f"{bewijs}; gemeten {free_mb} MB")


_NODE_ZERO_BLOCK_RE = re.compile(
    r"node\s*id\s*:\s*0\b(?P<blok>.*?)(?=node\s*id\s*:\s*\d|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_MASTER_STATE_RE = re.compile(r"master\s*state\s*:\s*(?P<staat>\S+)", re.IGNORECASE)
_NODE_IP_RE = re.compile(r"\bip\s*:\s*(?P<ip>\S+)", re.IGNORECASE)
# Every node block in `show ha node` starts with `Node ID: <n>`; a standalone box
# lists exactly one (Node ID 0), an HA pair two. Measured on lab-02 (8-9-2026).
_NODE_ID_RE = re.compile(r"node\s*id\s*:\s*\d+", re.IGNORECASE)


def secondary_gate(
    show_ha_node_output,
    doel_adres: str | None = None,
    *,
    standalone_accepted: bool = False,
) -> Gate:
    """A FRESH `show ha node` in the runner's own SSH session, never `hanode`
    from the last scan: that scan can be hours old, and a failover in between
    is exactly what this gate is for.

    A later fix: `show ha node` on a real HA pair lists BOTH nodes, each with its own
    `Master State:` line. The earlier implementation searched `"secondary"`
    across the WHOLE output, so the PEER's `Secondary` line opened this gate
    while running on the PRIMARY - exactly backwards for the one gate this
    entire phased route exists to enforce. This judges ONLY the LOCAL node's
    own block: `Node ID: 0` is the local node in NetScaler HA output, so this
    isolates the text from that marker up to the next `Node ID: <n>` (or the
    end of the text) and reads `Master State:` from inside THAT block alone.

    `doel_adres` (OPTIONAL - a caller that does not yet pass it keeps the
    pre-fix, state-only judgement, so this stays backward compatible for any
    direct caller): when given and non-empty, the block's own `IP:` field
    must match it (case-insensitive, trimmed) or this is `niet beoordeeld` -
    a session that somehow answers for the wrong box must never be read as
    either open or dicht on ITS data. STATED LIMITATION: this is a literal
    string comparison, so a `-Adres` configured as a HOSTNAME rather than the
    NSIP this field always carries will never match and always reads `niet
    beoordeeld` when a target is given - a real gap this function does not
    hide, not a claim of DNS-aware verification.

    Both "the Node ID: 0 block cannot be isolated at all" and "its IP does
    not match the target" are `niet beoordeeld`, never `open` and never
    `dicht` - either case means this function does not actually know whose
    role it is looking at, and `dicht` with "een fase raakt nooit de primary
    node" would claim a fact (this IS the primary) that was never
    established."""
    tekst = str(show_ha_node_output or "")
    blok_match = _NODE_ZERO_BLOCK_RE.search(tekst)
    if blok_match is None:
        return Gate(
            "doel is secondary",
            "bewijs",
            "niet beoordeeld",
            "show ha node leverde geen leesbaar blok voor Node ID 0",
            "de rolverdeling van de lokale node (Node ID 0) is niet gelezen",
        )
    blok = blok_match.group("blok")

    verwacht = str(doel_adres or "").strip()
    if verwacht:
        ip_match = _NODE_IP_RE.search(blok)
        gemeten_ip = ip_match.group("ip").strip() if ip_match else ""
        if not gemeten_ip or gemeten_ip.casefold() != verwacht.casefold():
            return Gate(
                "doel is secondary",
                "bewijs",
                "niet beoordeeld",
                f"Node ID 0 draagt IP {_bounded_or(gemeten_ip, '(geen)')!r}, doel is {_bounded(verwacht)!r}",
                "de identiteit van Node ID 0 komt niet aantoonbaar overeen met het doel",
            )

    staat_match = _MASTER_STATE_RE.search(blok)
    if staat_match is None:
        return Gate(
            "doel is secondary",
            "bewijs",
            "niet beoordeeld",
            "show ha node leverde geen leesbare Master State voor Node ID 0",
            "de rolverdeling van de lokale node (Node ID 0) is niet gelezen",
        )
    staat = staat_match.group("staat").strip().casefold()
    if staat == "secondary":
        return Gate("doel is secondary", "bewijs", "open", "show ha node (Node ID 0): Master State Secondary")
    if staat == "primary":
        # A STANDALONE appliance (no peer: exactly one `Node ID:` block) is
        # always Primary - measured on lab-02, 8-9-2026. There is no secondary
        # to upgrade first; the upgrade means downtime, and only a human may
        # accept that (`standalone_geaccepteerd`, a `mens` decision carried
        # into this gate). With a peer present, Primary stays `dicht`: the one
        # rule this whole route exists for.
        if len(_NODE_ID_RE.findall(tekst)) == 1:
            if standalone_accepted is True:
                # A count from an incomplete
                # transcript cannot establish peer absence, and unknown or
                # failed local health cannot authorize this exception either.
                # Only the ACCEPTED path can OPEN, so only that path demands
                # the complete, unambiguous and healthy transcript; without
                # acceptance a Primary stays `dicht` below whatever the
                # transcript's shape - the refusal the operator must read.
                complete = re.search(r"(?m)^\s*Done\s*\Z", tekst) is not None
                headers = re.findall(r"(?im)^\s*(?:\d+\)\s*)?Node ID:\s*(\d+)\s*$", tekst)
                header_lines = re.findall(r"(?im)^.*Node ID:.*$", tekst)
                states = re.findall(r"(?im)^\s*Node State:\s*(\S+)\s*$", blok)
                roles = list(_MASTER_STATE_RE.finditer(blok))
                addresses = list(_NODE_IP_RE.finditer(blok))
                errors = re.search(r"(?im)^\s*(?:ERROR|Warning)\s*[:\[]", tekst)
                if (
                    not complete
                    or headers != ["0"]
                    or len(header_lines) != 1
                    or states != ["UP"]
                    or len(roles) != 1
                    or len(addresses) != 1
                    or errors is not None
                ):
                    return Gate(
                        "doel is secondary",
                        "bewijs",
                        "niet beoordeeld",
                        "show ha node: standalone topologie niet volledig vastgesteld",
                        "een volledig, eenduidig en gezond lokaal HA-antwoord is vereist",
                    )
                return Gate(
                    "doel is secondary",
                    "bewijs",
                    "open",
                    "show ha node: standalone (alleen Node ID 0, geen peer), Master State "
                    "Primary; downtime bewust geaccepteerd (standalone_geaccepteerd)",
                )
            return Gate(
                "doel is secondary",
                "bewijs",
                "dicht",
                "show ha node: standalone (alleen Node ID 0, geen peer), Master State Primary",
                "standalone appliance: er is geen secondary en de upgrade betekent downtime; "
                "alleen te starten met standalone_geaccepteerd=true",
            )
        return Gate(
            "doel is secondary",
            "bewijs",
            "dicht",
            "show ha node (Node ID 0): Master State Primary",
            "een fase raakt nooit de primary node",
        )
    return Gate(
        "doel is secondary",
        "bewijs",
        "niet beoordeeld",
        f"show ha node (Node ID 0): onherkende Master State {_bounded(staat_match.group('staat'))!r}",
        "de rolverdeling van de lokale node (Node ID 0) is niet eenduidig gelezen",
    )


SAVE_ROLE_GATE = "doel is primary of standalone"
SAVE_ON_SECONDARY_REASON = "opslaan op een secondary propageert niet; sla op op de primary"
# A CLI answer that carries an error or a warning is not a reading of a role
# or a configuration state, whatever else it carries.
_CLI_ERROR_RE = re.compile(r"(?im)^\s*(?:ERROR|Warning)\s*[:\[]")
# The CLI closes every answer with a line ` Done`; without it the transcript
# may be cut off (measured on lab-02: `show ha node` and `show ns config`).
_CLI_DONE_RE = re.compile(r"(?m)^\s*Done\s*\Z")
_NODE_STATE_RE = re.compile(r"(?im)^\s*Node State:\s*(\S+)\s*$")


def save_role_gate(show_ha_node_output, doel_adres: str | None) -> Gate:
    """May `save ns config` run on this node? The mirror of `secondary_gate`:
    the upgrade route never touches the primary, and saving is meaningful
    ONLY there - a save on a secondary does not propagate (lab lesson:
    configdrift en twee save-momenten in HA). A standalone box reports
    itself as `Master State: Primary` too (measured on lab-02), so Primary
    is open with or without a peer.

    Reads the SAME local block `secondary_gate` reads (`Node ID: 0`, up to
    the next `Node ID:`), and is stricter than it, because only `open`
    leads to a write: the answer must be complete (` Done`), carry no error
    or warning line, name exactly one IP and exactly one Master State in
    the local block, the IP must be the target's own address, and the
    local node must be `UP`. Anything else is `niet beoordeeld` - and
    that is never `open`, so nothing is saved."""
    tekst = str(show_ha_node_output or "")
    naam = SAVE_ROLE_GATE
    blok_match = _NODE_ZERO_BLOCK_RE.search(tekst)
    if blok_match is None:
        return Gate(
            naam,
            "bewijs",
            "niet beoordeeld",
            "show ha node leverde geen leesbaar blok voor Node ID 0",
            "de rol van de lokale node (Node ID 0) is niet gelezen; er wordt niet opgeslagen",
        )
    blok = blok_match.group("blok")
    verwacht = str(doel_adres or "").strip()
    adressen = [m.group("ip").strip() for m in _NODE_IP_RE.finditer(blok)]
    if not verwacht or len(adressen) != 1 or adressen[0].casefold() != verwacht.casefold():
        return Gate(
            naam,
            "bewijs",
            "niet beoordeeld",
            f"Node ID 0 draagt {len(adressen)} IP-regel(s); doel is {_bounded_or(verwacht, '(geen)')!r}",
            "de identiteit van Node ID 0 komt niet aantoonbaar overeen met het doel; er wordt niet opgeslagen",
        )
    staten = list(_MASTER_STATE_RE.finditer(blok))
    if (
        len(staten) != 1
        or _CLI_DONE_RE.search(tekst) is None
        or _CLI_ERROR_RE.search(tekst) is not None
        or _NODE_STATE_RE.findall(blok) != ["UP"]
    ):
        return Gate(
            naam,
            "bewijs",
            "niet beoordeeld",
            "show ha node: geen volledig, eenduidig en gezond antwoord voor Node ID 0",
            "de rol van de lokale node is niet eenduidig gelezen; er wordt niet opgeslagen",
        )
    staat = staten[0].group("staat").strip().casefold()
    peers = len(_NODE_ID_RE.findall(tekst)) - 1
    topologie = "standalone (alleen Node ID 0)" if peers == 0 else "HA-paar, lokale node Node ID 0"
    if staat == "primary":
        return Gate(
            naam,
            "bewijs",
            "open",
            f"show ha node: {topologie}, Master State Primary; IP {_bounded(verwacht)}",
        )
    if staat == "secondary":
        return Gate(
            naam,
            "bewijs",
            "dicht",
            f"show ha node: {topologie}, Master State Secondary",
            SAVE_ON_SECONDARY_REASON,
        )
    return Gate(
        naam,
        "bewijs",
        "niet beoordeeld",
        f"show ha node (Node ID 0): onherkende Master State {_bounded(staten[0].group('staat'))!r}",
        "de rol van de lokale node is niet eenduidig gelezen; er wordt niet opgeslagen",
    )


# `show ns config`, measured on lab-02 (14.1, standalone): among other lines
# three that say whether the running configuration has been saved -
#     Last Config Changed Time: Sun Sep  6 10:50:08 2026
#     Last Config Saved Time: Sun Sep  6 10:49:58 2026
#     Config Changed since Last Saved Config: TRUE
# - each once, the labels right-aligned behind a tab, closed by ` Done`. The
# time carries no time zone; the two are only ever compared with EACH OTHER,
# never with this server's clock.
_CHANGED_LABEL = "Last Config Changed Time"
_SAVED_LABEL = "Last Config Saved Time"
_FLAG_LABEL = "Config Changed since Last Saved Config"
_CLI_TIME_RE = re.compile(r"[A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}")
_CLI_TIME_FORMAT = "%a %b %d %H:%M:%S %Y"


@dataclass(frozen=True)
class ConfigState:
    """What `show ns config` says about saving, or why it says nothing.

    `saved_after_change` is True when the last save is not older than the
    last change AND the appliance's own flag says nothing changed since;
    False when the flag says changed (it wins over two equal timestamps,
    which the CLI writes to the second) or the save is older than the
    change; None when the answer could not be read - `reason` says why, in
    this product's words, never quoting the appliance."""

    changed: datetime | None
    saved: datetime | None
    saved_after_change: bool | None
    reason: str = ""

    @property
    def readable(self) -> bool:
        return self.saved_after_change is not None


def cli_time_text(moment: datetime) -> str:
    """A CLI timestamp as THIS product writes it back: the parsed value,
    re-formatted - never the appliance's own text."""
    return moment.strftime(_CLI_TIME_FORMAT)


def config_state(show_ns_config_output) -> ConfigState:
    """Reads the three saving fields of `show ns config`, fail-closed: every
    shape this function does not know is unreadable, never a guess. Known
    means: a complete answer (` Done` last), no error or warning line, each
    of the three fields EXACTLY once, both times in the CLI's own format and
    the flag TRUE or FALSE. A flag of FALSE next to a save older than the
    change contradicts itself and is unreadable too."""

    def onleesbaar(reden: str) -> ConfigState:
        return ConfigState(None, None, None, reden)

    tekst = str(show_ns_config_output or "")
    if not tekst.strip():
        return onleesbaar("show ns config gaf geen uitvoer")
    if _CLI_DONE_RE.search(tekst) is None:
        return onleesbaar("show ns config is niet volledig (de afsluitende regel Done ontbreekt)")
    if _CLI_ERROR_RE.search(tekst) is not None:
        return onleesbaar("show ns config meldt een fout of waarschuwing")
    velden: dict[str, list[str]] = {_CHANGED_LABEL: [], _SAVED_LABEL: [], _FLAG_LABEL: []}
    for regel in tekst.split("\n"):
        label, scheiding, waarde = regel.partition(":")
        sleutel = " ".join(label.split())
        if scheiding and sleutel in velden:
            velden[sleutel].append(" ".join(waarde.split()))
    for label, waarden in velden.items():
        if len(waarden) != 1:
            return onleesbaar(f"het veld {label} staat er {len(waarden)} keer in, verwacht is precies een keer")
    momenten: dict[str, datetime] = {}
    for label in (_CHANGED_LABEL, _SAVED_LABEL):
        waarde = velden[label][0]
        if not _CLI_TIME_RE.fullmatch(waarde):
            return onleesbaar(f"het veld {label} draagt geen tijdstip in de vorm van de CLI")
        try:
            momenten[label] = datetime.strptime(waarde, _CLI_TIME_FORMAT)
        except ValueError:
            return onleesbaar(f"het veld {label} draagt geen geldig tijdstip")
    vlag = velden[_FLAG_LABEL][0]
    if vlag not in ("TRUE", "FALSE"):
        return onleesbaar(f"het veld {_FLAG_LABEL} is niet TRUE of FALSE")
    gewijzigd, opgeslagen = momenten[_CHANGED_LABEL], momenten[_SAVED_LABEL]
    if vlag == "TRUE" or opgeslagen < gewijzigd:
        if vlag == "FALSE":
            return onleesbaar(
                f"{_FLAG_LABEL} is FALSE terwijl de laatste opslag ouder is dan de laatste wijziging; tegenstrijdig"
            )
        return ConfigState(gewijzigd, opgeslagen, False)
    return ConfigState(gewijzigd, opgeslagen, True)


DRIFT_GATE = "drift afwezig of bewust geaccepteerd"
DRIFT_OPSLAAN_REASON = (
    "de configuratie is gewijzigd na de laatste opslag (show ns config); kies eerst opslaan met "
    "config_opslaan op de primary of het standalone-doel, of zet drift_geaccepteerd=true"
)
DRIFT_ONGELEZEN_REASON = (
    "de configuratiestand is niet vastgesteld; sla eerst op met config_opslaan of zet drift_geaccepteerd=true"
)


def _config_state_phrase(stand: ConfigState) -> str:
    """The measured state, in this product's words: the parsed moments,
    re-formatted, never the appliance's own text."""
    if not stand.readable:
        return f"niet gelezen ({stand.reason})"
    opslag, wijziging = cli_time_text(stand.saved), cli_time_text(stand.changed)
    if stand.saved_after_change:
        return f"laatste opslag {opslag} is niet ouder dan laatste wijziging {wijziging}"
    return f"gewijzigd na de laatste opslag (laatste opslag {opslag}, laatste wijziging {wijziging})"


def drift_live_gate(show_ns_config_output, exitcode, *, drift_geaccepteerd: bool) -> Gate:
    """R1's drift gate, read LIVE in R1's own pre-write session (`show ns
    config`), with the human acceptance as the second way open. Three
    dispositions, as the HA lesson names them: provably nothing changed
    since the last save (open, `bewijs`), saved first with `config_opslaan`
    (the same `bewijs` on the next R1), or accepted on purpose (open,
    `mens`, with the measured state in the evidence so the ledger says
    WHAT was accepted).

    Without acceptance a change after the last save closes the gate with
    the three choices, and anything this product cannot read - a failed
    read, an unknown shape - is `niet beoordeeld`, never open. The name
    stays the gate name R1 already carried, so REQUIRED_GATES and
    PRE_REQUIRED_GATES do not move."""
    gelezen = type(exitcode) is int and exitcode == 0
    stand = (
        config_state(show_ns_config_output)
        if gelezen
        else ConfigState(None, None, None, f"show ns config gaf exitcode {exitcode!r}")
    )
    if stand.readable and stand.saved_after_change:
        return Gate(DRIFT_GATE, "bewijs", "open", f"show ns config: {_config_state_phrase(stand)}")
    if drift_geaccepteerd is True:
        return Gate(
            DRIFT_GATE,
            "mens",
            "open",
            f"drift_geaccepteerd=true; gemeten stand (show ns config): {_config_state_phrase(stand)}",
        )
    if not stand.readable:
        return Gate(
            DRIFT_GATE,
            "bewijs",
            "niet beoordeeld",
            f"show ns config: {_config_state_phrase(stand)}",
            DRIFT_ONGELEZEN_REASON,
        )
    return Gate(
        DRIFT_GATE,
        "bewijs",
        "dicht",
        f"show ns config: {_config_state_phrase(stand)}",
        DRIFT_OPSLAAN_REASON,
    )


def disk_read_gate(free_mb, bundle_mb, unpack_mb, exitcode, stderr="", *, bundle_present: bool = False) -> Gate:
    if type(exitcode) is not int or exitcode != 0:
        return Gate(
            "vrije ruimte op /var",
            "bewijs",
            "niet beoordeeld",
            f"df -k /var: exitcode={exitcode!r}; stderr={_bounded(stderr)}",
            "de vrije ruimte is niet aantoonbaar geslaagd gelezen",
        )
    gate = disk_gate(free_mb, bundle_mb, unpack_mb, bundle_present=bundle_present)
    return Gate(gate.name, gate.type, gate.outcome, gate.evidence + "; df exitcode=0", gate.reason)


def target_build_gate(version_text, target_build, exitcode=None, stderr="") -> Gate:
    """A successful version read and an exact branch/build pair are required."""
    from nsmcp.cve import parse_build

    evidence = f"show ns version: {_bounded(version_text)}; exitcode={exitcode!r}"
    if type(exitcode) is not int or exitcode != 0:
        return Gate(
            "doelbuild bereikt",
            "bewijs",
            "niet beoordeeld",
            evidence,
            "show ns version is niet aantoonbaar geslaagd gelezen: " + _bounded(stderr),
        )
    expected = re.fullmatch(r"(\d+\.\d+)-(\d+)\.(\d+)", str(target_build or ""))
    actual = parse_build(version_text)
    if expected is None or actual is None:
        return Gate(
            "doelbuild bereikt",
            "bewijs",
            "niet beoordeeld",
            evidence,
            "doelbuild of teruggelezen tak/build is niet volledig leesbaar",
        )
    wanted = (expected[1], (int(expected[2]), int(expected[3])))
    if actual != wanted:
        return Gate(
            "doelbuild bereikt",
            "bewijs",
            "dicht",
            evidence,
            "teruggelezen tak/build wijkt af van de bevestigde doelbuild",
        )
    return Gate("doelbuild bereikt", "bewijs", "open", evidence)


# R0's gate on the target build against the current build and the security
# floor. The current build is what the appliance runs according to the
# export (`config/nsversion`, `update_advice.export_current_build`); the
# floor is the highest fix build of the appliance's own branch in the
# knowledge package (`update_advice.export_floor`); the target build is the
# one bundle in `onderhoud.firmwaremap`. The server computes all three and
# hands them to the runner; the runner hands them back here through
# `upgrade_measure`, so every value arrives as UNTRUSTED text and is checked
# on form before it is compared or repeated.
FLOOR_GATE = "doelbuild op of boven de vloer, of bewust geaccepteerd"
FLOOR_BELOW_REASON = (
    "de doelbuild ligt onder de vloer; zet een bundel op of boven de vloer in onderhoud.firmwaremap, "
    "of zet doelbuild_geaccepteerd=true"
)
FLOOR_ABSENT_REASON = "geen vloer bekend in het kennispakket voor deze tak"
FLOOR_BRANCH_REASON = (
    "de doelbuild en de vloer liggen op een andere tak en zijn niet te vergelijken, "
    "ook niet met doelbuild_geaccepteerd=true"
)
FLOOR_LINE_REASON = (
    "de doelbuild ligt in een andere releaselijn dan de huidige build; "
    "dit gereedschap doet geen overstap tussen releaselijnen"
)
FLOOR_CURRENT_ABSENT_REASON = (
    "de huidige build is niet bekend uit de export; een overstap tussen releaselijnen is dan niet uit te "
    "sluiten; ververs de export, of zet doelbuild_geaccepteerd=true"
)
FLOOR_UNREADABLE_REASON = (
    "doelbuild, huidige build, vloer of bulletin heeft niet de verwachte vorm; de vloer is niet getoetst"
)
# A target build at or below the current build on the same line: a reinstall
# of the running build, or a downgrade within the line. At or above the floor
# it breaks no floor promise, but a tool that upgrades does not do it on
# evidence alone.
FLOOR_NOT_HIGHER_REASON = (
    "doelbuild niet hoger dan de huidige build (herinstallatie of downgrade): menselijke "
    "acceptatie vereist; zet doelbuild_geaccepteerd=true als dat bewust is"
)
FLOOR_NOT_HIGHER_EVIDENCE = "doelbuild niet hoger dan de huidige build"

# `<tak>-<build>` with both halves X.Y, ASCII digits only (`re.ASCII`: `\d`
# would also accept other scripts' digits, which `int()` then happily
# reads). The same shape `target_build_gate` requires above.
_TAK_BUILD_RE = re.compile(r"([0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+)", re.ASCII)
# The runner's own form for -VloerBulletin; empty is allowed.
_BULLETIN_FORM_RE = re.compile(r"[A-Za-z0-9-]{0,32}", re.ASCII)
# A branch-qualified build as this product writes it (`14.1-72.57`): what the
# server hands the runner as `-Vloerbuild`, and the form of the target build
# R0's start row records for the run binding below.
_TAK_BUILD_FORM_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*-[0-9]+(?:\.[0-9]+)*", re.ASCII)


def runner_floor(build, bulletin) -> tuple[str, str]:
    """The floor and its bulletin as the runner takes them
    (`-Vloerbuild`, `-VloerBulletin`), or `''` for what has no such form.

    A floor of another shape - a FIPS train (`13.1-FIPS-37.272`), digits of
    another script - is not handed over at all: R0's floor gate then closes
    on "no floor" instead of the runner refusing to bind. A bulletin label
    travels only with a floor, and only in the runner's own form (the
    placeholder `public_bulletin_id()` prints for an unreadable identifier
    does not)."""
    vloer = build if isinstance(build, str) and _TAK_BUILD_FORM_RE.fullmatch(build) else ""
    label = bulletin if vloer and isinstance(bulletin, str) and _BULLETIN_FORM_RE.fullmatch(bulletin) else ""
    return vloer, label


def runner_current_build(build) -> str:
    """The current build as the runner takes it (`-Huidigebuild`), or `''`
    when there is none or it has no such form. The caller that holds a
    current build WITHOUT that form must not let the acceptance travel: the
    runner reads an absent current build as "not known", which the
    acceptance opens (`handelen.build_upgrade_arguments`)."""
    return build if isinstance(build, str) and _TAK_BUILD_FORM_RE.fullmatch(build) else ""


# The knowledge package the floor came from, as the runner takes it
# (`-VloerPakket`, `-VloerPakketDatum`): the package's own version text and
# its date, both in a form that can travel on a command line and be repeated
# in the ledger. Only with a floor and only in this form; anything else does
# not travel, and R0's evidence then says the package was not handed over.
_PACKAGE_FORM_RE = re.compile(r"[A-Za-z0-9._-]{1,64}", re.ASCII)
_PACKAGE_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)
# From this age on, R0's floor evidence WARNS that the floor may be out of
# date. A warning, never a closed gate: the operator pinned the package, and
# its age alone does not make the floor wrong - but an old package can name a
# floor below the vendor's current one, and the gate then opens on evidence.
KNOWLEDGE_WARN_AGE_DAYS = 30


def runner_package(version, date_text) -> tuple[str, str]:
    """The package version and date as the runner takes them, or `('', '')`
    when either has no such form. The date is normalized to `YYYY-MM-DD`
    (`knowledge.py` accepts every form `date.fromisoformat` reads)."""
    if not isinstance(version, str) or not isinstance(date_text, str):
        return "", ""
    versie = version.strip()
    if _PACKAGE_FORM_RE.fullmatch(versie) is None:
        return "", ""
    try:
        dag = date.fromisoformat(date_text.strip())
    except ValueError:
        return "", ""
    return versie, dag.isoformat()


def _package_evidence(pakket, pakket_datum, vandaag) -> str | None:
    """What R0's floor evidence says about the package the floor came from,
    or `None` when the caller handed neither field over. Both fields are
    runner input, so UNTRUSTED: a value of the wrong shape is named, never
    repeated, and never closes the gate."""
    if pakket is None and pakket_datum is None:
        return None
    if pakket == "" and pakket_datum == "":
        return "kennispakket niet meegegeven"
    vorm_ok = (
        isinstance(pakket, str)
        and _PACKAGE_FORM_RE.fullmatch(pakket) is not None
        and isinstance(pakket_datum, str)
        and _PACKAGE_DATE_RE.fullmatch(pakket_datum) is not None
    )
    try:
        dag = date.fromisoformat(pakket_datum) if vorm_ok else None
    except ValueError:
        dag = None
    if dag is None:
        return "kennispakket niet in de verwachte vorm"
    deel = f"kennispakket {pakket} van {pakket_datum}"
    if isinstance(vandaag, date):
        leeftijd = (vandaag - dag).days
        if leeftijd > KNOWLEDGE_WARN_AGE_DAYS:
            deel += (
                f"; WAARSCHUWING: het kennispakket is {leeftijd} dagen oud (ouder dan {KNOWLEDGE_WARN_AGE_DAYS} "
                "dagen), de vloer kan lager liggen dan wat de leverancier nu voorschrijft - ververs het kennispakket"
            )
    return deel


def _tak_build(value) -> tuple[str, tuple[int, int]] | None:
    if not isinstance(value, str):
        return None
    match = _TAK_BUILD_RE.fullmatch(value)
    if match is None:
        return None
    return match[1], (int(match[2]), int(match[3]))


def floor_gate(
    doelbuild, vloer, bulletin, geaccepteerd, *, huidig, pakket=None, pakket_datum=None, vandaag=None
) -> Gate:
    """R0's floor gate, in this order:

    1. A value of the wrong shape is `niet beoordeeld`, never open, and is
       never repeated: the evidence then names only WHICH field was
       unreadable. `huidig` (the current build) and `vloer` may be `''`
       (not known); `None` is a field that was not handed over at all.
    2. A target build in another release line than the CURRENT build closes,
       also with acceptance: this tool does no line change. The line comes
       from the current build, never from the floor - without a floor the
       gate used to have no line to compare with at all.
    3. A floor on another branch than the target build closes, also with
       acceptance: two branches are not comparable.
    4. Open on evidence when the target build is at or above the floor,
       the current build is known, and the target build is HIGHER than the
       current build. Otherwise - below the floor, no floor known, no
       current build known, or a target build not higher than the current
       one (a reinstall, or a downgrade within the line) - open as a HUMAN
       decision when `geaccepteerd` is a real `True`
       (`doelbuild_geaccepteerd`), closed without it. Without a current
       build the gate cannot rule out a line change, so even a target build
       above the floor does not open on evidence; that gap is named in the
       evidence and, closed, is the reason. A target build that is both
       below the floor and not higher keeps the floor's reason, which names
       the way out; "not higher" is named in the evidence only where it is
       the one shortfall.
    5. With a floor, the evidence names the knowledge package it came from
       (`pakket`, `pakket_datum`: version and date, runner input) and, when
       that package is more than `KNOWLEDGE_WARN_AGE_DAYS` older than
       `vandaag`, a warning. Only a WARNING: it never changes the outcome.
       `None` for both is a caller that hands no package over, and then the
       evidence says nothing about it."""
    doel = _tak_build(doelbuild)
    vloer_tekst = vloer if isinstance(vloer, str) else None
    vloer_leeg = vloer_tekst == ""
    grens = _tak_build(vloer_tekst) if vloer_tekst else None
    huidig_tekst = huidig if isinstance(huidig, str) else None
    huidig_leeg = huidig_tekst == ""
    nu = _tak_build(huidig_tekst) if huidig_tekst else None
    bulletin_ok = isinstance(bulletin, str) and _BULLETIN_FORM_RE.fullmatch(bulletin) is not None
    onleesbaar = [
        naam
        for naam, fout in (
            ("doelbuild", doel is None),
            ("huidige build", not huidig_leeg and nu is None),
            ("vloer", not vloer_leeg and grens is None),
            ("bulletin", not bulletin_ok),
        )
        if fout
    ]
    if onleesbaar:
        return Gate(
            FLOOR_GATE,
            "bewijs",
            "niet beoordeeld",
            "niet in de verwachte vorm: " + ", ".join(onleesbaar),
            FLOOR_UNREADABLE_REASON,
        )
    if nu is not None and doel[0] != nu[0]:
        return Gate(
            FLOOR_GATE,
            "bewijs",
            "dicht",
            f"doelbuild {doelbuild} (releaselijn {doel[0]}), huidige build {huidig} (releaselijn {nu[0]})",
            FLOOR_LINE_REASON,
        )
    herkomst = f" ({bulletin})" if bulletin else " (bulletin niet meegegeven)"
    if grens is not None and doel[0] != grens[0]:
        return Gate(
            FLOOR_GATE,
            "bewijs",
            "dicht",
            f"doelbuild {doelbuild} (tak {doel[0]}), vloer {vloer}{herkomst} (tak {grens[0]})",
            FLOOR_BRANCH_REASON,
        )
    geaccepteerd = geaccepteerd is True
    if grens is None:
        vloerdeel = f"doelbuild {doelbuild}; geen vloer {'bekend' if geaccepteerd else 'meegegeven'}"
        tekort = FLOOR_ABSENT_REASON
    elif doel[1] >= grens[1]:
        vloerdeel = f"doelbuild {doelbuild} op of boven vloer {vloer}{herkomst}"
        tekort = None
    else:
        vloerdeel = f"doelbuild {doelbuild} onder vloer {vloer}{herkomst}"
        tekort = FLOOR_BELOW_REASON
    pakketdeel = _package_evidence(pakket, pakket_datum, vandaag) if grens is not None else None
    if pakketdeel:
        vloerdeel = f"{vloerdeel}; {pakketdeel}"
    if nu is None:
        tekort = FLOOR_CURRENT_ABSENT_REASON
    bewijs = f"{vloerdeel}; huidige build {huidig if nu is not None else 'niet bekend'}"
    if tekort is None and doel[1] <= nu[1]:
        tekort = FLOOR_NOT_HIGHER_REASON
        bewijs = f"{bewijs}; {FLOOR_NOT_HIGHER_EVIDENCE}"
    if tekort is None:
        return Gate(FLOOR_GATE, "bewijs", "open", bewijs)
    if geaccepteerd:
        return Gate(FLOOR_GATE, "mens", "open", f"{bewijs}; bewust geaccepteerd")
    return Gate(FLOOR_GATE, "bewijs", "dicht", bewijs, tekort)


# The run binding. The target build is read from `onderhoud.firmwaremap` afresh
# for every phase; a bundle swapped after R0 would have R3 install something
# R0 never judged. R0's `fase_gestart` row records the build it started with
# (`upgrade_measure._start`), and R1..R6 of the same run must carry that same
# build. The field is ledger content, so UNTRUSTED: checked on form, compared,
# and never repeated.
RUN_DOELBUILD_AFWIJKEND_TEXT = (
    "de doelbuild van deze run (R0) wijkt af van de bundel in onderhoud.firmwaremap; start een nieuwe run"
)
RUN_DOELBUILD_ONLEESBAAR_TEXT = "de doelbuild van deze run (R0) staat niet leesbaar in het ledger; start een nieuwe run"


def run_binding_refusal(rows, run: str, doel: str, current_build: str, *, strict: bool) -> str | None:
    """`None` when `current_build` is the target build the LAST R0 start of
    this run on this target recorded; otherwise the refusal sentence.

    `strict` is the execution: a run without a readable R0 target build is
    refused there. At the proposal (`strict=False`) only a READABLE,
    DIFFERENT build refuses - an absent or unreadable one is left to the
    execution, the same split the soak window has (the execution is the
    truth; the proposal refuses early only what it can establish)."""
    start = None
    for row in rows:
        if (
            isinstance(row, dict)
            and row.get("run") == run
            and row.get("doel") == doel
            and row.get("fase") == PHASE_NAMES[0]
            and row.get("gebeurtenis") == "fase_gestart"
        ):
            start = row
    vastgelegd = start.get("doelbuild") if start is not None else None
    if not isinstance(vastgelegd, str) or _TAK_BUILD_FORM_RE.fullmatch(vastgelegd) is None:
        return RUN_DOELBUILD_ONLEESBAAR_TEXT if strict else None
    if vastgelegd != current_build:
        return RUN_DOELBUILD_AFWIJKEND_TEXT
    return None


def precheck_result_path(run: str, action: str, attempt: str) -> str:
    if not isinstance(run, str) or not is_safe_run_name(run):
        raise ValueError("ongeldige runnaam voor precheck-resultaatpad")
    if not isinstance(action, str) or not action.strip() or not re.fullmatch(r"[0-9a-f]{32}", str(attempt)):
        raise ValueError("precheck-resultaatpad mist de bevestigde actie of poging")
    action_digest = hashlib.sha256(action.encode("utf-8")).hexdigest()[:16]
    return f"/var/tmp/gjk_pre_check_{run}_{action_digest}_{attempt}.json"


def precheck_path_gate(path, exitcode, stdout) -> Gate:
    # Measured on lab-02 (8-9-2026): the appliance prefixes EVERY shell answer with a
    # banner ("Warning: [ One or more RPC nodes are configured with default
    # passwords ...]"), so the marker is judged as a WHOLE LINE of the output, never
    # as the entire output. The marker word itself only ever comes from our own echo.
    regels = [r.strip() for r in str(stdout or "").splitlines()]
    absent = type(exitcode) is int and exitcode == 0 and "AFWEZIG" in regels
    return Gate(
        "precheck-resultaatpad nieuw",
        "bewijs",
        "open" if absent else "niet beoordeeld",
        f"pad={_bounded(path)}; afwezigheidslezing exitcode={exitcode!r}; {_bounded(stdout)}",
        "" if absent else "het resultaatpad is niet aantoonbaar afwezig voor deze poging",
    )


def local_bundle_gate(vendor_sha, local_sha) -> Gate:
    valid = all(re.fullmatch(r"[0-9a-fA-F]{64}", str(v or "")) for v in (vendor_sha, local_sha))
    ok = valid and str(vendor_sha).lower() == str(local_sha).lower()
    return Gate(
        "lokale bundel en sidecar",
        "bewijs",
        "open" if ok else "dicht",
        "lokale sha256 vergeleken met de vendor-sidecar",
        "" if ok else "vendor-sidecar ontbreekt, is ongeldig of wijkt af van de lokale bundel",
    )


def hash_gate(vendor_sha, box_sha) -> Gate:
    """The box compared with the VENDOR value from `<bundelnaam>.sha256`, never
    with itself. Without that file there is no gate, and design 3.5 then says
    `dicht`."""
    if not vendor_sha:
        return Gate(
            "firmware-hash",
            "bewijs",
            "dicht",
            "geen vendorwaarde",
            "naast de bundel ontbreekt <bundelnaam>.sha256 met de vendorwaarde",
        )
    if not box_sha:
        return Gate("firmware-hash", "bewijs", "dicht", "geen hash van de doos", "de sha256 op de doos is niet gelezen")
    if str(vendor_sha).strip().lower() != str(box_sha).strip().lower():
        return Gate(
            "firmware-hash",
            "bewijs",
            "dicht",
            "hashes verschillen",
            "de overgezette bundel is niet de bundel van de vendor",
        )
    return Gate("firmware-hash", "bewijs", "open", "sha256 op de doos gelijk aan de vendorwaarde")


# ---------------------------------------------------------------------------
# hostkey_gate / presence_gate / anchor_evidence_gate - MOVED here from
# `upgrade_measure.py`: they are gate
# FUNCTIONS exactly like `disk_gate`/`secondary_gate`/`hash_gate` above, and
# splitting them into the CLI-adapter module is what let `presence_gate`
# skip `_bounded` while every neighbour here used it - one place for "every
# poortuitspraak komt uit Python", not two. `upgrade_measure.py` keeps
# re-exporting these names (`from nsmcp.upgrade import ...`) so nothing that
# already calls `upgrade_measure.hostkey_gate(...)` breaks.
# ---------------------------------------------------------------------------


def hostkey_gate(measured, expected) -> Gate:
    """A literal fingerprint comparison, as a `Gate`. Kept for a caller that
    genuinely HAS an independently measured fingerprint to compare - which,
    measured against Posh-SSH's real cmdlet surface,
    the runner never does: `New-SSHSession -ErrorOnUntrusted` validates the
    offered key internally and does not hand the byte value back on a
    successful connect. The runner's own "hostsleutel gepind" gate therefore
    uses `hostkey_session_gate` below, not this function - see that
    function's docstring for why. This one stays: it is still the honest
    building block for the day a real measurement IS available (a direct
    `Renci.SshNet` `HostKeyReceived` probe, say), and it is still exercised
    directly by its own tests.

    A missing `expected` (no `-HostsleutelVingerafdruk` reached this
    process) is `dicht`, never `open`: an unpinned target is not a target
    this design considers trustworthy by default. A missing `measured` (no
    key was ever read - the TCP connection itself never completed) is `niet
    beoordeeld`: the comparison was never actually made.
    """
    if not str(expected or "").strip():
        return Gate(
            "hostsleutel gepind",
            "voorwaarde",
            "dicht",
            "geen gepinde vingerafdruk mee gegeven",
            "de fase draait nooit zonder een gepinde hostsleutel",
        )
    if not str(measured or "").strip():
        return Gate(
            "hostsleutel gepind",
            "voorwaarde",
            "niet beoordeeld",
            "geen hostsleutel gemeten tijdens het verbinden",
            "de aangeboden hostsleutel is niet gelezen",
        )
    if str(measured).strip().casefold() != str(expected).strip().casefold():
        return Gate(
            "hostsleutel gepind",
            "voorwaarde",
            "dicht",
            f"gemeten {_bounded(measured)!r} tegenover gepind {_bounded(expected)!r}",
            "hostsleutel wijkt af",
        )
    return Gate(
        "hostsleutel gepind", "voorwaarde", "open", "de aangeboden hostsleutel komt overeen met de gepinde vingerafdruk"
    )


def hostkey_session_gate(
    sessie_geopend, hostsleutelfout, foutmelding: str = "", gepinde_vingerafdruk: str = ""
) -> Gate:
    """The pinned-host-key gate the runner ACTUALLY feeds today, told
    honestly.

    The old wiring called `hostkey_gate(gemeten, verwacht)` with the SAME
    value on both sides - PowerShell had no independently measured
    fingerprint to hand in (see `hostkey_gate`'s own docstring), so the gate
    opened by construction and the ledger's evidence claimed a comparison
    that was never made. This function asserts what WAS actually
    established instead: `New-GjkSshSession` pins the EXPECTED fingerprint
    into Posh-SSH's own known-hosts store before connecting and then
    connects with `-ErrorOnUntrusted`, so a session that opens at all is
    proof the offered key matched the pin, and a session that fails to open
    specifically on a host-key mismatch is proof it did not - PowerShell
    tells this function WHICH of those two happened (and, for every other
    connection failure, that it does not know), never a value that only
    ever equals itself.

    `hostsleutelfout` is meaningless when `sessie_geopend` is true and is
    not read in that case. A connection failure that is NOT a host-key
    mismatch (timeout, wrong password, host down) is `niet
    beoordeeld`, never `dicht` with the pinned reason: that reason is
    reserved for a failure this module was actually told was a key
    mismatch, so an administrator reading the ledger is never sent to
    compare host keys while the real problem was that the box was down.

    NO pin at all (an empty or whitespace-only
    `-HostsleutelVingerafdruk`) is `dicht`, the word `hostkey_gate` already
    used for it - not `niet beoordeeld`. An absent pin is an ESTABLISHED
    absence and therefore a refusal: nobody named a key to compare against,
    so a session that opens proves nothing about which box answered. `niet
    beoordeeld` is for a measurement that could not be taken, and this one
    was never asked for. Checked FIRST, before `sessie_geopend`: a session
    that opened on an empty pin is exactly the case this must not wave
    through.
    """
    if not str(gepinde_vingerafdruk or "").strip():
        return Gate(
            "hostsleutel gepind",
            "voorwaarde",
            "dicht",
            "er is geen gepinde vingerafdruk meegegeven; een geopende sessie bewijst dan niets "
            "over welke doos antwoordde",
            "geen gepinde vingerafdruk mee gegeven",
        )
    if sessie_geopend:
        return Gate(
            "hostsleutel gepind",
            "voorwaarde",
            "open",
            "de sessie is geopend; Posh-SSH's -ErrorOnUntrusted vergeleek de aangeboden "
            "hostsleutel al met de gepinde vingerafdruk voordat deze sessie tot stand kwam "
            "(geen tweede, onafhankelijke Python-vergelijking van de bytewaarden)",
        )
    bewijs = f"kon geen sessie openen: {_bounded(foutmelding)}" if foutmelding else "kon geen sessie openen"
    if hostsleutelfout:
        return Gate("hostsleutel gepind", "voorwaarde", "dicht", bewijs, "hostsleutel wijkt af")
    return Gate(
        "hostsleutel gepind",
        "voorwaarde",
        "niet beoordeeld",
        bewijs,
        "geen hostsleutelfout herkend; de verbinding mislukte om een andere reden en de "
        "hostsleutel is dus niet beoordeeld",
    )


def presence_gate(naam: str, soort: str, aanwezig, bewijs: str, reden_dicht: str, kant: str = "kop") -> Gate:
    """A bare "was this fact established" gate - R0's backup/build-tree/
    snapshot-reference checks and R1's drift-acceptance flag are each a
    presence test, not a computed threshold, but they stay a Python call
    like every other gate so the outcome is never a PowerShell `if` (design
    decision 3: elke poortuitspraak komt uit Python).

    `bewijs` is UNTRUSTED appliance/export text in more than one caller
    (R1's `ls -la <buildboom>`, R5's `show ns version`) and is bounded here,
    ONCE, the same discipline `precheck_gate` and `hostkey_gate` already
    apply: this was the one gate here
    that fed the ledger raw and unbounded, and PowerShell hand-bounded ONE
    caller (R3) by itself instead of leaning on this single place.

    `kant` says WHICH end of an over-long `bewijs` survives.
    `"kop"` (the default, and what every caller but one wants) keeps
    the start; `"staart"` keeps the end, for the one caller whose deciding
    fact is printed LAST (R3's `installns` output, where `END_TIME` - the
    literal thing this gate judges on - is the final line). Bounding is not
    optional either way: it is only the DIRECTION that differs, so no caller
    can use this to get raw appliance text into the ledger. An unknown
    `kant` is refused rather than silently treated as `"kop"`.
    """
    if soort not in GATE_TYPES:
        raise ValueError(f"onbekend poorttype: {soort!r}")
    if kant not in ("kop", "staart"):
        raise ValueError(f"onbekende afkapkant: {kant!r}")
    kort = _bounded_tail(bewijs) if kant == "staart" else _bounded(bewijs)
    if aanwezig:
        return Gate(naam, soort, "open", kort)
    return Gate(naam, soort, "dicht", kort, reden_dicht)


def anchor_evidence_gate(regels) -> Gate:
    """The R0/R5 configuration anchor and family counts, as an ALWAYS-OPEN
    evidence gate: `rapport_na_upgrade` (a later task) reads R0's and R5's
    ledger rows and does the actual BEFORE/AFTER comparison itself; this
    gate only carries the computed anchor into the ledger so that
    comparison has something to read. `normalised_anchor()` never raises on
    its own (design: it only sorts and hashes strings), so this wrapper
    never needs a `dicht` branch."""
    anker, tellingen = normalised_anchor(regels)
    volgorde = ", ".join(f"{naam}={aantal}" for naam, aantal in sorted(tellingen.items()))
    bewijs = f"anker={anker}" + (f"; {volgorde}" if volgorde else "")
    return Gate("configuratie-anker", "bewijs", "open", bewijs)


def backup_register_gate(register_lines, doel, *, onleesbare_reden: str = "") -> Gate:
    """R0's "backupobject aanwezig" gate, from the ACTIEREGISTER - never the
    appliance: R0 does NOTHING on the
    appliance; the backup evidence is what `onderhoud_backup_maken` already
    established and wrote to the action log, with its own read-back on the
    `config/systembackup` COLLECTION, never a GET-by-name - the mechanism
    an earlier fix corrected.

    `register_lines` is `None` for "the register could not be read at all"
    (no path given, the file is missing, or it could not be opened) - the
    caller (`upgrade_measure`'s CLI layer, which owns file I/O) makes that
    distinction, this function only judges what it is handed. That case is
    `niet beoordeeld`, never `dicht`: the absence has not been established,
    only the reading failed. A register that WAS read but carries no
    matching, successful row for `doel` is a positive statement the design
    already names ("Ontbreekt die registerregel, of hoort hij bij een ander
    doel, dan is R0 dicht") - `dicht`, an established absence.

    A row counts only when its `tool` is `onderhoud_backup_maken`, its
    `doel` matches (case- and whitespace-insensitive, never a different
    target's backup), and its own `uitkomst` is `geslaagd` - a row for a
    FAILED backup attempt is not evidence of a rollback point.

    The register is plain JSONL without integrity: nothing here signs a
    row, checks its age, ties it to a run or an action id, or asks the
    appliance whether the backup object still exists. Whoever can write the
    register file can therefore add a row with those three fields and open
    this gate. That boundary is the operator's to keep: the register belongs
    in a directory only the administrator can write, like the ledger map
    (docs/klant/SECURITY.md, "Die startcontrole vergelijkt paden, geen
    rechten").
    """
    if register_lines is None:
        reden = onleesbare_reden or "het actieregister kon niet gelezen worden"
        return Gate("backupobject aanwezig", "bewijs", "niet beoordeeld", _bounded(reden), _bounded(reden))
    doel_kaal = str(doel or "").strip().casefold()
    treffers = [
        r
        for r in register_lines
        if isinstance(r, dict)
        and str(r.get("tool", "")) == "onderhoud_backup_maken"
        and str(r.get("doel", "")).strip().casefold() == doel_kaal
        and str(r.get("uitkomst", "")) == "geslaagd"
    ]
    if not treffers:
        return Gate(
            "backupobject aanwezig",
            "bewijs",
            "dicht",
            f"actieregister gelezen ({len(register_lines)} regel(s)), geen geslaagde "
            "onderhoud_backup_maken-regel voor dit doel",
            "onderhoud_backup_maken moet eerst gedraaid zijn voor dit doel en teruggelezen "
            "op de collectie config/systembackup",
        )
    actieid = _bounded(str(treffers[-1].get("actieid") or "(geen actie-id)"))
    return Gate(
        "backupobject aanwezig",
        "bewijs",
        "open",
        f"actieregister: onderhoud_backup_maken geslaagd voor dit doel, actieid={actieid}",
    )


def build_tree_gate(export) -> Gate:
    """R0's "vorige buildboom aanwezig" gate, from the EXPORT's own
    `config/systemfile` rows with `filelocation` on `/var/nsinstall` - never
    a live SSH read. Same resource and
    location `preflight._check_9_rollback` already reads; imported from
    there rather than re-typed so the two can never name a different path.

    `export` is `None` for "no export root was given" - `niet beoordeeld`,
    the same distinction `backup_register_gate` makes. A GIVEN export whose
    manifest is missing or does not carry this resource already comes back
    as a `ReadGap` from `Export.objects()` itself, which this function
    turns into the same `niet beoordeeld` - it never guesses a build tree
    exists on an export it could not read.
    """
    if export is None:
        return Gate(
            "vorige buildboom aanwezig",
            "bewijs",
            "niet beoordeeld",
            "geen exportpad meegegeven",
            "de vorige buildboom is niet gelezen: geen export beschikbaar",
        )
    rows, gap = export.objects(BUILD_TREE_RESOURCE)
    if gap is not None:
        return Gate(
            "vorige buildboom aanwezig", "bewijs", "niet beoordeeld", _bounded(gap.reason), _bounded(gap.reason)
        )
    bomen = [pad[len(BUILD_TREE_LOCATION) + 1 :] for pad, _ in build_tree_entries(rows)]
    if not bomen:
        return Gate(
            "vorige buildboom aanwezig",
            "bewijs",
            "dicht",
            f"{len(rows)} object(en) onder {BUILD_TREE_RESOURCE}, geen buildboom onder {BUILD_TREE_LOCATION}",
            f"geen buildboom gevonden onder {BUILD_TREE_LOCATION} in de export",
        )
    # `_bounded` per NAME bounded each name but not
    # how MANY names there are - an export carrying hundreds of `build-*`
    # rows still wrote an unbounded string into the ledger, and
    # `upgrade_gate._gates_from_measurements()` re-bounds nothing when it
    # merges. Both the count and the joined result are capped here.
    getoond = bomen[:_MAX_BUILDBOMEN_GETOOND]
    staart = "" if len(bomen) <= _MAX_BUILDBOMEN_GETOOND else f", ...(+{len(bomen) - _MAX_BUILDBOMEN_GETOOND} meer)"
    return Gate(
        "vorige buildboom aanwezig",
        "bewijs",
        "open",
        _bounded(
            f"{len(bomen)} buildbo(o)m(en) onder {BUILD_TREE_LOCATION}: "
            + ", ".join(_bounded(b, _NAAM_ECHO_LIMIT) for b in getoond)
            + staart
        ),
    )


def export_age_gate(export) -> Gate:
    """The AGE of the export R0 reads its rollback-point evidence from -
    informational, so `rapport_na_upgrade` and an administrator can see how
    fresh that evidence is (design: "hij schrijft de leeftijd van die
    export in de ledgerregel, zodat zichtbaar is hoe vers het bewijs is").
    This gate did not exist before an earlier fix.
    Always `open` when the age is measurable - no threshold is
    defined anywhere in this design, the same restraint `anchor_evidence_
    gate` already applies - and `niet beoordeeld` only when it genuinely is
    not, never a manufactured age.
    """
    if export is None:
        return Gate(
            "leeftijd van de export",
            "bewijs",
            "niet beoordeeld",
            "geen exportpad meegegeven",
            "de leeftijd van de export is niet gelezen: geen export beschikbaar",
        )
    moment = _read_moment(getattr(export, "collected_at", None))
    if moment is None:
        return Gate(
            "leeftijd van de export",
            "bewijs",
            "niet beoordeeld",
            "de export draagt geen leesbare collectedAtUtc",
            "de leeftijd van de export waaruit R0 zijn bewijs haalt is niet gelezen",
        )
    ouderdom_dagen = (datetime.now(UTC) - moment).total_seconds() / 86400
    return Gate(
        "leeftijd van de export",
        "bewijs",
        "open",
        f"export verzameld op {_iso_z(moment)}, {ouderdom_dagen:.1f} dag(en) oud",
    )


def family_counts_gate(export) -> Gate:
    """The "tellingen van de acht families" R0 and R5 both carry into the
    ledger (design 3.5) - object counts per `FAMILIES` resource. This
    function is R0's export-sourced route; R5's live-SSH route is unchanged
    and does not call this. Always
    `open` when computable - this is evidence for a LATER before/after
    comparison (`rapport_na_upgrade`, a later task), not a threshold, same
    restraint as `anchor_evidence_gate`. A family this export cannot read
    is named in the evidence rather than silently dropped or counted as 0 -
    a genuine zero and an unread family are different statements.

    An export in which NOT ONE of the eight families
    could be read is `niet beoordeeld` - never `open`. R0 exists to make the
    pre-measurement R5 is later compared against, and `order_gate` passes R0
    unconditionally (it has no predecessor), so an `open` on an empty
    reading closed R0 as `geslaagd`/`voormeting_vast` carrying an EMPTY
    pre-measurement: a gate recording a judgement it never measured. Eight
    families that genuinely hold zero objects and eight families that could
    not be read are different statements - the first still fills
    `tellingen`, the second leaves it empty.
    """
    if export is None:
        return Gate(
            "familietellingen",
            "bewijs",
            "niet beoordeeld",
            "geen exportpad meegegeven",
            "de familietellingen zijn niet gelezen: geen export beschikbaar",
        )
    tellingen: dict[str, int] = {}
    leesgaten: list[str] = []
    for familie in FAMILIES:
        rows, gap = export.objects(f"config/{familie}")
        if gap is not None:
            leesgaten.append(f"{familie}: {gap.reason}")
            continue
        tellingen[familie] = len(rows)
    volgorde = ", ".join(f"{naam}={tellingen[naam]}" for naam in FAMILIES if naam in tellingen)
    if not tellingen:
        reden = (
            f"geen enkele van de {len(FAMILIES)} families is uit deze export gelezen; er is dus "
            "geen voormeting om R5 straks tegen af te zetten"
        )
        bewijs = "familietellingen: geen enkele familie leesbaar"
        if leesgaten:
            bewijs += "; onleesbaar: " + _bounded("; ".join(leesgaten))
        return Gate("familietellingen", "bewijs", "niet beoordeeld", bewijs, reden)
    bewijs = f"familietellingen: {volgorde}"
    if leesgaten:
        bewijs += "; onleesbaar: " + _bounded("; ".join(leesgaten))
    return Gate("familietellingen", "bewijs", "open", bewijs)


def _soak_opens(lines, now: datetime) -> tuple[list[datetime], int]:
    """Every `soak_open` row's own `gestart` as an AWARE UTC `datetime`,
    plus the COUNT of `soak_open` rows whose `gestart` could not be read.

    Never "the row that came last". A target's rows are concatenated out of
    every run file in a ledger DIRECTORY, and that directory was written by
    processes this module does not control: file order is not time order. A
    file name that does not start with a digit sorts AFTER every
    `<UTC>Z-<doel>.jsonl`, so dropping an old copy of a ledger next to the
    live one used to make its stale window "the newest" and shortened the
    24 hours to nothing - the one window this design promises no parameter,
    key or flag can shorten. The binding window is picked on the PARSED
    timestamp instead, and nothing here reads a file name.

    A row whose `gestart` is missing or unparseable is COUNTED rather than
    raised (it used to `KeyError`/`ValueError` out to the CLI's exit 2) and
    rather than ignored: an unread start time can be the newest one, so the
    caller turns a counted row into `niet beoordeeld` - never into `open`.

    A naive `gestart` is read as UTC: the ledger's own timestamps are UTC
    by contract, and guessing system local time would move the window.

    A `gestart` LATER THAN `now` is also counted rather than trusted:
    a ledger a future version reads was
    written by a process this module does not control, and a `gestart` of
    `9999-12-31` deterministically binds the window forever AND raises
    `OverflowError` out of `soak_gate` the moment `+ timedelta(hours=...)`
    is added to it (`datetime.max` is already `9999-12-31`) - the CLI then
    reports "onleesbare invoer op stdin" over perfectly readable stdin, and
    every R0/R6 on that target is blocked permanently. A soak window cannot
    begin in the future, so a `gestart` that claims to is not a window this
    module can trust - it is treated exactly like an unparseable one.
    """
    begintijden: list[datetime] = []
    onleesbaar = 0
    for regel in lines:
        if regel.get("gebeurtenis") != "soak_open":
            continue
        rauw = regel.get("gestart")
        if rauw is None or not str(rauw).strip():
            onleesbaar += 1
            continue
        try:
            begin = datetime.fromisoformat(str(rauw).replace("Z", "+00:00"))
        except ValueError:
            onleesbaar += 1
            continue
        if begin.tzinfo is None or begin.tzinfo.utcoffset(begin) is None:
            begin = begin.replace(tzinfo=UTC)
        begin = begin.astimezone(UTC)
        if begin > now:
            onleesbaar += 1
            continue
        begintijden.append(begin)
    return begintijden, onleesbaar


def _soak_start(lines, now: datetime):
    """The NEWEST `soak_open` row's `gestart`, as an AWARE UTC `datetime`,
    or `None` when this target carries no readable open soak window. See
    `_soak_opens` for why "newest" is measured on the timestamp and not on
    the order the rows happened to arrive in."""
    begintijden, _ = _soak_opens(lines, now)
    return max(begintijden) if begintijden else None


def soak_gate(lines, now, soak_hours: int) -> Gate:
    """Wall-clock time between phases on the SAME target, on the LEDGER's own
    UTC timestamps.

    Minimum 24 hours, and `onderhoud.soak_uren` can only make it longer -
    `start.py` refuses a lower value outright. There is deliberately no
    parameter, key or flag that shortens this: a phase inside the window is
    refused, and that includes R0 of a next run on the same target. The
    refusal names the earliest end time.

    Nor does a FILE shorten it. The binding window is the one with the
    newest `gestart` (`_soak_opens`), and a `soak_open` row whose start
    time cannot be read leaves the gate `niet beoordeeld` rather than
    `open`: that row could be the newest window, and nothing here is
    `[vastgesteld]` without a successful reading.
    """
    uren = max(int(soak_hours), MINIMUM_SOAK_HOURS)
    begintijden, onleesbaar = _soak_opens(lines, now)
    if not begintijden and not onleesbaar:
        return Gate("soakvenster", "tijd", "open", "geen open soakvenster op dit doel")
    if begintijden:
        begin = max(begintijden)
        einde = begin + timedelta(hours=uren)
        if now < einde:
            return Gate(
                "soakvenster",
                "tijd",
                "dicht",
                f"soak begon {_iso_z(begin)}, vroegste eindtijd {_iso_z(einde)}",
                f"het soakvenster loopt nog tot {_iso_z(einde)}",
            )
    if onleesbaar:
        return Gate(
            "soakvenster",
            "tijd",
            "niet beoordeeld",
            f"{onleesbaar} soak_open-regel(s) op dit doel zonder leesbare begintijd",
            "de begintijd van het soakvenster is niet gelezen; een niet gelezen venster telt niet als verstreken",
        )
    return Gate("soakvenster", "tijd", "open", f"soak begon {_iso_z(begin)} en is verstreken sinds {_iso_z(einde)}")


def soak_state(lines, now, soak_hours) -> tuple[str | None, str | None]:
    """`(woord, vroegste_eindtijd)` uit `SOAK_WORDS`, voor `onderhoud_upgrade_stand`
    - dezelfde poort als `soak_gate`, maar in de twee woorden van het
    ontwerp in plaats van `open`/`dicht`. `vroegste_eindtijd` is `None` zolang
    er geen open soakvenster op dit doel staat.

    `woord` is dan ook `None`, niet `verstreken`: het ontwerp staat voor het
    soakvenster maar twee woorden toe (`loopt`/`verstreken`, "geen ander
    woord"), en geen van beide is eerlijk voor een venster dat nooit
    geopend is - `verstreken` beweert dat er een venster GEWEEST is. Een
    aanroeper toont dan geen soakstand, in plaats van een venster te melden
    dat nooit bestaan heeft. Datzelfde geldt voor een `soak_open`-regel
    waarvan de begintijd NIET gelezen is: `verstreken` zou dan beweren dat
    een venster voorbij is dat nooit gemeten is (`_soak_opens`)."""
    uren = max(int(soak_hours), MINIMUM_SOAK_HOURS)
    begintijden, onleesbaar = _soak_opens(lines, now)
    if not begintijden:
        return None, None
    einde = max(begintijden) + timedelta(hours=uren)
    einde_tekst = _iso_z(einde)
    if now < einde:
        return SOAK_WORDS[0], einde_tekst
    if onleesbaar:
        return None, None
    return SOAK_WORDS[1], einde_tekst


def _last_phase_row(lines, phase: str) -> dict | None:
    """The last row in `lines` for this phase, skipping EVIDENCE rows
    (`_EVIDENCE_EVENTS`) - the same row `phase_state()` bases its word on.

    Factored out for `onderhoud_upgrade_stand`: `stand_answer()` needs
    that SAME row's own `poort`/`bewijs` fields, not only the word
    `phase_state()` derives from it - one reader of "the row that decides
    this phase", not two that could disagree about which row that is.
    """
    laatste = None
    for regel in lines:
        if regel.get("fase") == phase and regel.get("gebeurtenis") not in _EVIDENCE_EVENTS:
            laatste = regel
    return laatste


def latest_run_name(rows) -> str:
    """The `run` of the row with the latest READABLE `tijd` in `rows`, or
    `""` when no row qualifies.

    The naive
    `rows[-1]["run"]` this replaces crashed outright on a row without a
    `run` key (a plain subscript on UNTRUSTED content), and it silently
    picked the WRONG run the moment one row's `tijd` could not be read -
    `_rows_for_target`'s own ordering (`upgrade_gate._row_time`) sorts such
    a row LAST so a caller's loop keeps a sane relative position for it, but
    "sorts last" is not "is the latest", and a caller that trusted
    `rows[-1]` was redirected to a DIFFERENT run with nothing in the answer
    saying so. Every row here is UNTRUSTED (module docstring): a row
    without a usable `run` STRING, or without a readable `tijd`,
    contributes nothing to this choice - `.get()`, never `[...]`. Ties keep
    the LATER row in `rows`' own order (rows already arrive time-ordered
    from `_rows_for_target`). A caller decides what "no run could be
    determined" (an empty return) means to it; this function does not
    guess."""
    beste_tijd = None
    beste_run = ""
    for regel in rows:
        if not isinstance(regel, dict):
            continue
        run_naam = regel.get("run")
        if not isinstance(run_naam, str) or not run_naam.strip():
            continue
        moment = _read_moment(regel.get("tijd"))
        if moment is None:
            continue
        if beste_tijd is None or moment >= beste_tijd:
            beste_tijd = moment
            beste_run = run_naam
    return beste_run


def phase_state(lines, phase: str) -> str:
    """The verdict FOR THIS PHASE, uit `PHASE_OUTCOMES`, gebouwd op de laatste
    ledgerregel met `fase == phase` - nooit op een logregel (design: de
    ledger is de waarheid). Geen regel voor deze fase -> `niet beoordeeld`.
    Wel een `fase_gestart`-regel maar nog geen afsluitregel -> `gestart`. Een
    afsluitregel -> het woord dat `_CLOSING_EVENTS` daarvoor geeft.

    Een BEWIJSREGEL (`terugrolpunt_vast`, R0's extra
    regel) is geen toestandsregel en wordt hier overgeslagen. Zonder die
    uitzondering zou een R0 die net zijn terugrolpunt heeft vastgelegd maar
    nog niet gesloten is, `niet beoordeeld` heten in plaats van `gestart` -
    en dat is precies de fase die WEL bezig is.
    """
    laatste = _last_phase_row(lines, phase)
    if laatste is None:
        return "niet beoordeeld"
    gebeurtenis = laatste.get("gebeurtenis")
    if gebeurtenis == "fase_gestart":
        return "gestart"
    return _CLOSING_EVENTS.get(gebeurtenis, "niet beoordeeld")


# The sentence design 2.1.1 pins VERBATIM behind `verstreken`: a soak
# window that has elapsed is never mistaken for permission to move on. Named
# once here so `stand_answer()` cannot drift from the tests that pin it.
SOAK_VERSTREKEN_SENTENCE = (
    "Het soakvenster is verstreken. Dat is geen goedkeuring: de volgende stap - de failover "
    "en de tweede node - is een menselijke handeling."
)

# This new customer-visible product copy
# was asserted only by substring
# (`"iets_anders" in tekst`/`"raar" in tekst`) - named here, the same
# discipline `SOAK_VERSTREKEN_SENTENCE` above already gets, so
# `tests/test_product_surface.py` can pin the WHOLE reason text
# byte-for-byte instead of a fragment of it. The two "PREFIX" constants
# carry a `!r`-repr of the untrusted ledger word after them - never a fixed
# string on their own - so a test pins prefix + a KNOWN word's repr, not
# the prefix alone.
ONBEKENDE_GEBEURTENIS_PREFIX = "onbekende gebeurtenis in de ledgerregel: "
ONBEKEND_UITKOMST_WOORD_PREFIX = "onbekend uitkomst-woord in de ledgerregel: "
GEEN_REDEN_OPGEGEVEN_TEXT = "geen reden opgegeven in de ledgerregel"


def _render_or(value, fallback: str, limiet: int = _UNTRUSTED_ECHO_LIMIT) -> str:
    """Single render boundary for untrusted ledger values; never use for parsing."""
    rendered = _bounded_run_echo(str(value) if value is not None else "", limiet)
    return rendered if rendered.strip() else fallback


def stand_answer(
    lines,
    now,
    soak_hours,
    *,
    target_lines=None,
    read_gaps: list[ReadGap] | None = None,
) -> Answer:
    """`onderhoud_upgrade_stand`: waar een upgraderun staat, uit het
    ledger en NERGENS anders - nooit uit het `.log`-bestand dat er in de
    ledgermap naast staat (dat is diagnostiek, geen waarheid), en de
    aanroeper heeft `lines` al tot de juiste run/het juiste doel beperkt
    (deze functie filtert zelf niet op `run` of `doel`).

    Per fase in `PHASE_NAMES` (R0..R6) een finding met een van
    `PHASE_OUTCOMES` als `outcome`, gebouwd op dezelfde regel `phase_state()`
    zou kiezen (`_last_phase_row()`) - nooit een tweede, mogelijk afwijkende
    lezing. Een fase zonder ledgerregel is `Certainty.NOT_ESTABLISHED` met
    reden "geen ledgerregel voor deze fase": niets is `[vastgesteld]` zonder
    een geslaagde lezing. Vlak onder de fase, een finding per poort die de
    sluitende (of gestart-)regel droeg, met zijn eigen `open`/`dicht`/
    `niet beoordeeld` en bewijs - een fasenaam en een poortnaam zijn geen
    appliance-objecten, dus elke finding hier krijgt `subject_is_name=False`.

    Een ONBEKEND `gebeurtenis`- of
    `uitkomst`-woord uit het ledger (untrusted) valt terug op `niet
    beoordeeld` zoals altijd, maar dat woord krijgt nu ook
    `Certainty.NOT_ESTABLISHED` met een reden die het onbekende woord noemt
    - dezelfde conventie `preflight.py`/`upgrade_plan.py` al toepassen
    (`niet beoordeeld` -> `NOT_ESTABLISHED`). Voorheen kreeg de FALLBACK
    dezelfde `Certainty.ESTABLISHED` als een echte uitkomst: "niet
    beoordeeld [vastgesteld]", zonder reden - een schending van "niets is
    `[vastgesteld]` zonder een geslaagde lezing" die uit onvertrouwde
    ledgerinhoud alleen bereikbaar was.

    `target_lines`: het soakvenster bindt het DOEL, over elk
    runbestand heen - net als `onderhoud_upgrade_fase` zijn eigen
    kruistoolpoort leest (`mcp_server.py`, `_rows_for_target` zonder
    `run`-filter). Zonder deze parameter (`None`) valt de soaklezing terug
    op `lines` zelf, zodat de drie bestaande tests die deze functie met alleen
    `(lines, now, soak_hours)` aanroepen ongewijzigd blijven werken; de
    aanroeper die de rijen al per RUN filtert (`onderhoud_upgrade_stand`
    in `mcp_server.py`) geeft hier expliciet de doelbrede rijen mee.

    `read_gaps`: de rijen die `read_ledger()` overslaat
    (kapotte JSON, verkeerde codering, geen object) verdwijnen vandaag in
    een `RuntimeWarning` die niemand vangt - een antwoord op een ledger met
    drie kapotte regels was byte-identiek aan een antwoord op een schoon
    ledger. Deze functie bouwt de leesgaten niet zelf (zij leest niet van
    schijf), maar geeft door wat de aanroeper ving.

    Daarna de leeftijd van de laatste ledgerregel (over alle fasen heen), en
    - alleen als er een soakvenster op dit doel staat (`soak_state()`; geen
    venster is geen finding, nooit een venster melden dat nooit bestaan
    heeft) - `loopt` met de vroegste eindtijd, of `verstreken` met de
    vroegste eindtijd, met `SOAK_VERSTREKEN_SENTENCE` letterlijk als REDEN
    erbij (niet in dezelfde zin als de uitkomst: het
    woord "verstreken" hoeft dan niet twee keer in een lopende zin).

    Elke tekst die uit het ledger komt is UNTRUSTED (module-docstring) en
    wordt hier `_bounded_run_echo()`/`_render_or()` voor hij in een finding
    belandt - dezelfde discipline als elke andere poortfunctie in dit
    bestand, nu ook voor een `bewijs`/`reden` die uit niets dan spaties
    bestaat (`"   "` is truthy in
    Python, dus `x.get(...) or "standaardtekst"` liet zo'n waarde eerder
    ongemoeid door, en een lege `evidence`/`reason` op een
    `Finding` verbrijzelt deze functie via `Finding.__post_init__`).
    """
    findings: list[Finding] = []
    for fase in PHASE_NAMES:
        laatste = _last_phase_row(lines, fase)
        if laatste is None:
            findings.append(
                Finding(
                    subject=fase,
                    outcome="niet beoordeeld",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence="geen ledgerregels voor deze fase in dit ledger",
                    reason="geen ledgerregel voor deze fase",
                    subject_is_name=False,
                )
            )
            continue
        gebeurtenis = laatste.get("gebeurtenis")
        if gebeurtenis == "fase_gestart":
            stand = "gestart"
        elif gebeurtenis in _CLOSING_EVENTS:
            stand = _CLOSING_EVENTS[gebeurtenis]
        else:
            stand = "niet beoordeeld"
        if stand == "niet beoordeeld":
            stand_certainty = Certainty.NOT_ESTABLISHED
            stand_reason = f"{ONBEKENDE_GEBEURTENIS_PREFIX}{_bounded_run_echo(str(gebeurtenis), 60)!r}"
        else:
            stand_certainty = Certainty.ESTABLISHED
            stand_reason = ""
        findings.append(
            Finding(
                subject=fase,
                outcome=stand,
                certainty=stand_certainty,
                evidence=_render_or(laatste.get("bewijs"), "(geen bewijs op deze ledgerregel)"),
                reason=stand_reason,
                subject_is_name=False,
            )
        )
        for poort in laatste.get("poort") or []:
            if not isinstance(poort, dict):
                continue
            naam = _bounded_run_echo(str(poort.get("naam") or "(naamloze poort)"), 120)
            ruwe_uitkomst = str(poort.get("uitkomst") or "")
            if ruwe_uitkomst in GATE_OUTCOMES:
                uitkomst = ruwe_uitkomst
                onbekend_reden = ""
            else:
                uitkomst = "niet beoordeeld"
                onbekend_reden = f"{ONBEKEND_UITKOMST_WOORD_PREFIX}{_bounded_run_echo(ruwe_uitkomst, 60)!r}"
            if uitkomst == "niet beoordeeld":
                poort_certainty = Certainty.NOT_ESTABLISHED
                poort_reason = onbekend_reden or _render_or(
                    poort.get("reden"),
                    GEEN_REDEN_OPGEGEVEN_TEXT,
                )
            else:
                poort_certainty = Certainty.ESTABLISHED
                poort_reason = _bounded_run_echo(str(poort.get("reden") or ""))
            findings.append(
                Finding(
                    subject=f"{fase} poort: {naam}",
                    outcome=uitkomst,
                    certainty=poort_certainty,
                    evidence=_render_or(poort.get("bewijs"), "(geen bewijs)"),
                    reason=poort_reason,
                    subject_is_name=False,
                )
            )

    laatste_tijd = None
    for regel in lines:
        moment = _read_moment(regel.get("tijd"))
        if moment is not None and (laatste_tijd is None or moment > laatste_tijd):
            laatste_tijd = moment
    if laatste_tijd is None:
        reden = (
            "het ledger draagt geen regels voor deze run/dit doel"
            if not lines
            else "geen ledgerregel met een leesbare tijd"
        )
        findings.append(
            Finding(
                subject="laatste ledgerregel",
                outcome="niet vastgesteld",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=reden,
                reason=reden,
                subject_is_name=False,
            )
        )
    else:
        ouderdom_dagen = (now - laatste_tijd).total_seconds() / 86400
        findings.append(
            Finding(
                subject="laatste ledgerregel",
                outcome=f"{ouderdom_dagen:.1f} dag(en) oud",
                certainty=Certainty.ESTABLISHED,
                evidence=f"tijd van de laatste ledgerregel: {_iso_z(laatste_tijd)}",
                subject_is_name=False,
            )
        )

    soak_lines = lines if target_lines is None else target_lines
    woord, eindtijd = soak_state(soak_lines, now, soak_hours)
    if woord == SOAK_WORDS[0]:
        findings.append(
            Finding(
                subject="soakvenster",
                outcome=f"loopt; vroegste eindtijd {eindtijd}",
                certainty=Certainty.ESTABLISHED,
                evidence=f"soak_open-regel gelezen op dit doel; vroegste eindtijd {eindtijd}",
                subject_is_name=False,
            )
        )
    elif woord == SOAK_WORDS[1]:
        findings.append(
            Finding(
                subject="soakvenster",
                outcome=f"verstreken; vroegste eindtijd was {eindtijd}",
                certainty=Certainty.ESTABLISHED,
                evidence=f"soak_open-regel gelezen op dit doel; vroegste eindtijd was {eindtijd}",
                reason=SOAK_VERSTREKEN_SENTENCE,
                subject_is_name=False,
            )
        )

    return Answer(
        question="stand van de upgraderun",
        findings=findings,
        read_gaps=list(read_gaps) if read_gaps else [],
    )


def order_gate(phase: str, lines) -> Gate:
    """`R<n> gesloten (voorwaarde)`: de vorige fase in `PHASE_NAMES` moet
    `geslaagd` staan voor deze fase mag beginnen. R0 heeft geen voorganger en
    staat hier altijd `open`."""
    index = PHASE_NAMES.index(phase)
    if index == 0:
        return Gate(f"{phase} gesloten", "voorwaarde", "open", "R0 heeft geen voorganger")
    vorige = PHASE_NAMES[index - 1]
    titel = PHASE_TITLES[vorige]
    stand = phase_state(lines, vorige)
    if stand == "geslaagd":
        return Gate(f"{vorige} gesloten", "voorwaarde", "open", f"{vorige} ({titel}) sloot met geslaagd")
    return Gate(
        f"{vorige} gesloten",
        "voorwaarde",
        "dicht",
        f"{vorige} ({titel}) staat op {stand} in het ledger",
        f"fase {vorige} is niet gesloten; deze fase kan niet starten",
    )


# The JUDGING half had no per-phase required-
# gate set of its own - `evaluate_phase()` judged only whichever gates
# happened to arrive in `context["gates"]`, and WHICH gates a phase carries
# is decided entirely in PowerShell, in `$verzoeken`
# (`Invoke-GjkUpgradeFase.ps1`). Delete one unconditional `$verzoeken` entry
# there (the 'secondary' request, say) and the whole test suite stayed
# green while the phase it belongs to closed `geslaagd` on data it never
# measured - the ONE seam no per-task review could see, because every task
# delivered its own correct gate set and none of them re-checked that the
# SET ITSELF was complete.
#
# Deliberately a STATIC set per phase, not a dynamic/conditional one: a
# gate whose absence is sometimes LEGITIMATE (R2's `vendor-precheck`, sent
# only when the buildboom supports a pre-check; R4's `SSH-auth terug na
# reboot`, sent only on a FAILED post-reboot reconnect) stays OUT of this
# set - making it required would refuse a genuinely successful, correctly-
# measured phase. What belongs here is only a gate name a phase carries on
# EVERY real invocation, success or failure alike (`Invoke-GjkUpgradeFase.
# ps1`'s own switch block, read phase by phase). `order_gate`/`soak_gate`/
# the duration gate are NOT in this set either - those are Python-derived,
# added by `_build_context` (`upgrade_gate.py`) independently of anything
# PowerShell sends, so they can never be the OMITTED half of this seam.
REQUIRED_GATES: dict[str, frozenset[str]] = {
    "R0": frozenset(
        {
            "backupobject aanwezig",
            "vorige buildboom aanwezig",
            "leeftijd van de export",
            "familietellingen",
            "configuratie-anker",
            "hypervisor-snapshotverwijzing ingevoerd",
            FLOOR_GATE,
        }
    ),
    "R1": frozenset(
        {
            "hostsleutel gepind",
            "doel is secondary",
            "vrije ruimte op /var",
            "firmware-hash",
            "lokale bundel-sha256 (informatief)",
            "buildboom staat er nog",
            "drift afwezig of bewust geaccepteerd",
            "lokale bundel en sidecar",
        }
    ),
    "R2": frozenset(
        {"hostsleutel gepind", "pre-check-ondersteuning aanwezig", "doel is secondary", "precheck-resultaatpad nieuw"}
    ),
    "R3": frozenset({"hostsleutel gepind", "installatie voltooid (END_TIME)", "doel is secondary"}),
    "R4": frozenset({"hostsleutel gepind", "doel is secondary", "SSH-auth terug na reboot"}),
    "R5": frozenset(
        {
            "hostsleutel gepind",
            "doel is secondary",
            "configuratie-anker",
            "doelbuild bereikt",
        }
    ),
    "R6": frozenset({"hostsleutel gepind"}),
}


PRE_REQUIRED_GATES = {
    "R1": frozenset(
        {
            "hostsleutel gepind",
            "doel is secondary",
            "vrije ruimte op /var",
            "lokale bundel en sidecar",
            "R0 gesloten",
            "drift afwezig of bewust geaccepteerd",
        }
    ),
    "R2": frozenset({"hostsleutel gepind", "doel is secondary", "precheck-resultaatpad nieuw", "R1 gesloten"}),
    "R3": frozenset({"hostsleutel gepind", "doel is secondary", "R2 gesloten"}),
    "R4": frozenset({"hostsleutel gepind", "doel is secondary", "R3 gesloten"}),
}


def prior_write_gates(phase: str, context: dict) -> tuple[Gate, ...]:
    """Require the pre-write evidence after THIS attempt's most recent start."""
    if phase not in PRE_REQUIRED_GATES:
        return ()
    missing = Gate(
        "voorpoort van deze poging",
        "voorwaarde",
        "niet beoordeeld",
        "geen volledige voorafgaande voorpoort van dezelfde run/fase/actie/poging",
        "de voorpoort is niet aantoonbaar voor deze schrijfpoging vastgelegd",
    )
    identity = ("run", "doel", "actieid", "poging", "gestart")
    if any(not context.get(k) for k in identity):
        return (missing,)
    started = False
    pre = None
    for row in context.get("lines", ()):
        if row.get("run") != context["run"] or row.get("fase") != phase:
            continue
        if row.get("gebeurtenis") == "fase_gestart":
            started = all(row.get(k) == context[k] for k in identity)
            pre = None
        elif row.get("gebeurtenis") == "voorpoort" and started:
            pre = row if all(row.get(k) == context[k] for k in identity) else None
        elif row.get("gebeurtenis") in _CLOSING_EVENTS:
            started = False
            pre = None
    if pre is None or not isinstance(pre.get("poort"), list):
        return (missing,)
    raw = pre["poort"]
    names = [g.get("naam") for g in raw if isinstance(g, dict)]
    if (
        any(not isinstance(n, str) for n in names)
        or len(names) != len(raw)
        or len(names) != len(set(names))
        or not PRE_REQUIRED_GATES[phase] <= set(names)
    ):
        return (missing,)
    gates = []
    for g in raw:
        if g.get("type") not in GATE_TYPES or g.get("uitkomst") not in GATE_OUTCOMES:
            return (missing,)
        try:
            gates.append(Gate(g["naam"], g["type"], g["uitkomst"], str(g.get("bewijs", "")), str(g.get("reden", ""))))
        except ValueError:
            return (missing,)
    allowed = pre.get("uitkomst") == "open" and all(g.outcome == "open" for g in gates)
    binding = Gate(
        "voorpoort van deze poging",
        "voorwaarde",
        "open" if allowed else "dicht",
        "voorpoort gelezen na de start van dezelfde run/fase/actie/poging",
        "" if allowed else "een of meer voorpoorten staan niet open",
    )
    return (binding, *gates)


def evaluate_phase(phase: str, measurements: dict, context: dict) -> PhaseVerdict:
    """Bouwt het oordeel voor deze fase uit de poorten die de aanroeper al
    heeft laten meten (`context["gates"]`) en de twee metingen die VOOR elke
    poort gaan - in precies deze volgorde en geen andere:

    0. Elke naam in `REQUIRED_GATES.get(phase, frozenset())` die NIET in de
       aangeleverde poorten voorkomt, wordt hier gesynthetiseerd als een
       eigen poort op `niet beoordeeld` ("deze poort ontbreekt in de meting
       van deze fase") en aan `gates` toegevoegd VOORDAT de rest van deze
       functie draait - nooit `open`, dus regel 3 hieronder sluit de fase
       er automatisch door (zie `REQUIRED_GATES`
       hierboven voor waarom dit een STATISCHE set per fase is).
    1. `measurements["tijdslimiet_overschreden"]` waar -> `mislukt`,
       reden `tijdslimiet` (design: PHASE_LIMITS_S maakt een hangende sessie
       vallen, niet een trage doos afwijzen).
    2. `measurements["actieid_uit_script"]` wijkt af van `context["actieid"]`
       -> `mislukt`: het ledger en het bevestigde doel zijn dan over TWEE
       verschillende handelingen aan het praten.
    3. Een poort `dicht` of `niet beoordeeld` -> `poort dicht`. `niet
       beoordeeld` telt hier NOOIT als `open` (dezelfde regel als op elke
       losse poort hierboven).
    4. Anders `geslaagd`.
    """
    gates = tuple(context.get("gates", ()))
    pre_gates = prior_write_gates(phase, context)
    # A later reading (notably the host key after R4's reboot) must remain
    # visible and must still be judged. Keep both observations when names
    # overlap, explicitly naming the earlier one as pre-write evidence.
    # The binding gate itself is derived from the ledger, never from stdin.
    binding_name = "voorpoort van deze poging"
    gates = tuple(g for g in gates if g.name != binding_name)
    closing_names = {g.name for g in gates}
    gates += tuple(
        Gate(f"voorpoort: {g.name}", g.type, g.outcome, g.evidence, g.reason) if g.name in closing_names else g
        for g in pre_gates
    )
    aanwezige_namen = {g.name for g in gates}
    ontbrekend = REQUIRED_GATES.get(phase, frozenset()) - aanwezige_namen
    if ontbrekend:
        gates = gates + tuple(
            Gate(
                naam,
                "bewijs",
                "niet beoordeeld",
                "deze poort ontbreekt in de meting van deze fase",
                "een verplichte poort voor deze fase is niet aangeleverd",
            )
            for naam in sorted(ontbrekend)
        )
    if measurements.get("tijdslimiet_overschreden"):
        return PhaseVerdict(
            phase,
            "mislukt",
            gates,
            f"fase {phase}: gemeten duur overschreed de tijdslimiet van {PHASE_LIMITS_S.get(phase)} s",
            "tijdslimiet",
        )
    actieid_script = measurements.get("actieid_uit_script")
    actieid_context = context.get("actieid")
    if actieid_script != actieid_context:
        return PhaseVerdict(
            phase,
            "mislukt",
            gates,
            f"fase {phase}: actieid uit het ledger vergeleken met het bevestigde doel",
            "het actie-id in het ledger en het bevestigde doel komen niet overeen",
        )
    niet_open = [g for g in gates if g.outcome != "open"]
    if niet_open:
        return PhaseVerdict(
            phase,
            "poort dicht",
            gates,
            "poorten niet open: " + ", ".join(g.name for g in niet_open),
            "een of meer poorten staan niet open",
        )
    return PhaseVerdict(phase, "geslaagd", gates, "alle poorten van deze fase staan open")


ROLLBACK_EVENT = "terugrolpunt_vast"

# The register field carrying the backup name THIS PRODUCT FORMED for an
# `onderhoud_backup_maken` action (`handelen.ActionResult.object_name`, read
# by `perform()` off the argument list it built - never parsed back out of
# the script's stdout, a mechanism an earlier fix corrected). Named here once so the
# runner, this module and `scripts/README.md` cannot drift apart on it.
REGISTER_OBJECT_FIELD = "objectnaam"

_ROLLBACK_ONBEKEND = "niet gelezen"

REGISTER_OUTCOMES = ("geslaagd", "mislukt")


def register_line(
    *,
    tool: str,
    doel: str,
    actieid,
    uitkomst: str,
    bevestiger,
    objectnaam,
    now=None,
) -> dict:
    """ONE row of the action register - the WRITER side of the contract that
    `_backup_row_from_register()`, `backup_register_gate()` and
    `rollback_point_evidence()` read (and that `upgrade_measure.
    _read_register_or_none()` parses with the ledger's own tolerant JSONL
    reader). `mcp_server._act()` writes it after every EXECUTED write
    action - never for a proposal or a -WatIs preview - so R0's backup
    gate opens on evidence this product itself established (the read-back
    on the `config/systembackup` collection), never on a value typed in.

    Until 8-9-2026 no writer of this register existed anywhere (the
    readers said so themselves), which meant R0 could never close
    `geslaagd` on a real appliance: the whole route was unreachable. This
    function is that writer, kept next to the field name it shares with
    the readers so the two cannot drift apart.

    `uitkomst` is `geslaagd` or `mislukt` - a failed attempt is recorded
    too (the readers ignore it for the rollback point, an operator reading
    the register should still see the attempt). `objectnaam` is present
    only when the action formed one (a backup name), under
    `REGISTER_OBJECT_FIELD`. Times are UTC, second precision, `Z`.
    """
    if uitkomst not in REGISTER_OUTCOMES:
        raise ValueError("uitkomst van een registerregel is geslaagd of mislukt")
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    row = {
        "tijd": moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "tool": str(tool),
        "doel": str(doel),
        "actieid": None if actieid is None else str(actieid),
        "uitkomst": uitkomst,
        "bevestiger": None if bevestiger is None else str(bevestiger),
    }
    if objectnaam:
        row[REGISTER_OBJECT_FIELD] = str(objectnaam)
    return row


def _backup_row_from_register(register_lines, doel) -> dict | None:
    """The most recent SUCCESSFUL `onderhoud_backup_maken` row for `doel`, or
    `None`. The same match `backup_register_gate` makes, factored out so the
    gate and the rollback-point row can never disagree about WHICH backup
    they are talking about."""
    if not register_lines:
        return None
    doel_kaal = str(doel or "").strip().casefold()
    treffers = [
        r
        for r in register_lines
        if isinstance(r, dict)
        and str(r.get("tool", "")) == "onderhoud_backup_maken"
        and str(r.get("doel", "")).strip().casefold() == doel_kaal
        and str(r.get("uitkomst", "")) == "geslaagd"
    ]
    return treffers[-1] if treffers else None


def _backup_size_and_time(export, naam: str) -> tuple[str, str]:
    """`(grootte, tijd)` for the backup called `naam`, looked up in the
    export's `config/systembackup` COLLECTION - never a GET on the name.

    Measured on the lab, and the reason this scan uses the collection instead of a GET: a
    removed object answers a GET-by-name with 599 rather than 404 (lab lesson
    `nitro-readback-599-vs-404`), so on that route an error and an absence
    are the same answer. Scanning the collection for the name has no such
    ambiguity. The export writes the file name WITH its `.tgz` suffix while
    the product forms the name without one, so the suffix is stripped before
    comparing - the one difference between the two spellings of the same
    object.

    Both halves are `niet gelezen` rather than guessed when the export is
    absent, unreadable, or simply does not carry this backup."""
    if export is None or not naam:
        return _ROLLBACK_ONBEKEND, _ROLLBACK_ONBEKEND
    rows, gap = export.objects(BACKUP_RESOURCE)
    if gap is not None:
        return _ROLLBACK_ONBEKEND, _ROLLBACK_ONBEKEND
    gezocht = naam.strip().casefold()
    for row in rows:
        if not isinstance(row, dict):
            continue
        bestand = str(row.get("filename") or "").strip()
        stam = bestand[:-4] if bestand.lower().endswith(".tgz") else bestand
        if stam.casefold() != gezocht:
            continue
        grootte = str(row.get("size") or "").strip()
        try:
            grootte_bytes = int(grootte)
        except (TypeError, ValueError):
            grootte = _bounded(grootte, _NAAM_ECHO_LIMIT) or _ROLLBACK_ONBEKEND
        else:
            # Gemeten - een backup van 4855 bytes rondde
            # hier af op "0 MB", een bewering die eenvoudigweg onwaar is
            # (er is wel degelijk een backup). Onder 1 MB toont dit KB met
            # een decimaal (komma, zoals de rest van dit product) in plaats
            # van een MB-afronding die alles onder 512 KB tot nul maakt.
            #
            # Een NEGATIEVE grootte uit de
            # (onvertrouwde) export gaf "-0,0 KB" - net zo onwaar als de
            # oude "0 MB" voor een echte, positieve backup. Geen enkele
            # backup is negatief van grootte; dat is een leesgat, geen
            # cijfer.
            if grootte_bytes < 0:
                grootte = _ROLLBACK_ONBEKEND
            elif grootte_bytes < 1024 * 1024:
                grootte = f"{grootte_bytes / 1024:.1f}".replace(".", ",") + " KB"
            else:
                grootte = f"{round(grootte_bytes / (1024 * 1024))} MB"
        tijd = _bounded(str(row.get("creationtime") or "").strip(), _NAAM_ECHO_LIMIT) or _ROLLBACK_ONBEKEND
        return grootte, tijd
    return _ROLLBACK_ONBEKEND, _ROLLBACK_ONBEKEND


def rollback_point_evidence(register_lines, export, snapshotverwijzing, doel) -> str:
    """The `bewijs` of R0's EXTRA `terugrolpunt_vast` ledger row: the six
    things design 3.5 names by name - "backupnaam, grootte, tijd, het pad van
    de vorige buildboom, de leeftijd van de export waaruit dat pad komt, en
    de snapshotverwijzing letterlijk".

    This row was named in the design, in the ledger
    fixtures downstream consumers read, and in this module's own comment on
    `_CLOSING_EVENTS` - and written by no code at all. `backup_register_gate`
    echoed only the register row's `actieid`, so the IDENTITY of the thing an
    operator would restore reached no ledger row. R0 is not complete without
    it: this row IS the recorded rollback point for the whole upgrade.

    Every component comes from a source R0 ALREADY reads - the action
    register and the export - and nothing here opens a session or invents a
    value. A component that cannot be read says `niet gelezen` in the row
    rather than being dropped: a rollback point missing its size is a
    different (and much more useful) statement than a rollback point that
    silently never mentions size at all.
    """
    regel = _backup_row_from_register(register_lines, doel)
    naam_ruw = "" if regel is None else str(regel.get(REGISTER_OBJECT_FIELD) or "").strip()
    naam = _bounded(naam_ruw, _NAAM_ECHO_LIMIT) if naam_ruw else _ROLLBACK_ONBEKEND
    grootte, tijd = _backup_size_and_time(export, naam_ruw)

    pad = _build_tree_paths(export)
    leeftijd = _export_age_phrase(export)

    snapshot_ruw = str(snapshotverwijzing or "").strip()
    snapshot = _bounded(snapshot_ruw, _NAAM_ECHO_LIMIT) if snapshot_ruw else _ROLLBACK_ONBEKEND

    return _bounded(
        f"backup {naam}, grootte {grootte}, tijd {tijd}; "
        f"vorige buildboom {pad} (export {leeftijd}); "
        f"snapshotverwijzing {snapshot}",
        _UNTRUSTED_ECHO_LIMIT * 4,
    )


def _build_tree_paths(export) -> str:
    """The PATH of the previous build tree - `<filelocation>/<filename>` -
    rather than the sentence `build_tree_gate` writes for its own evidence.
    Design 3.5 asks this row for "het pad van de vorige buildboom", and a
    path is what an operator restoring the box would actually type."""
    if export is None:
        return _ROLLBACK_ONBEKEND
    rows, gap = export.objects(BUILD_TREE_RESOURCE)
    if gap is not None:
        return _ROLLBACK_ONBEKEND
    paden = [_bounded(pad, _NAAM_ECHO_LIMIT * 2) for pad, _ in build_tree_entries(rows)]
    if not paden:
        return _ROLLBACK_ONBEKEND
    getoond = paden[:_MAX_BUILDBOMEN_GETOOND]
    staart = "" if len(paden) <= _MAX_BUILDBOMEN_GETOOND else f", ...(+{len(paden) - _MAX_BUILDBOMEN_GETOOND} meer)"
    return ", ".join(getoond) + staart


def _export_age_phrase(export) -> str:
    """ "`<n> dag(en) oud`" for the export the build-tree path came from, or
    `niet gelezen`. The AGE, not the whole sentence `export_age_gate` writes
    - this row names six things and each one has to stay readable."""
    if export is None:
        return _ROLLBACK_ONBEKEND
    moment = _read_moment(getattr(export, "collected_at", None))
    if moment is None:
        return _ROLLBACK_ONBEKEND
    dagen = (datetime.now(UTC) - moment).total_seconds() / 86400
    return f"{dagen:.1f} dag(en) oud, verzameld op {_iso_z(moment)}"


def rollback_point_line(gates, bewijs, *, run, doel, actieid, bevestiger, started) -> dict:
    """R0's EXTRA evidence row, in the ledger's own shape.

    NOT a closing row: `gebeurtenis` is `terugrolpunt_vast`, which is absent
    from `_CLOSING_EVENTS` on purpose, and `uitkomst` stays `gestart` - the
    phase is still running when this is written. `geeindigd` is `None` for
    the same reason. `upgrade_gate` writes the ONE closing row afterwards, so
    the "exactly one `fase_gestart` and one closing row per phase" rule is
    untouched; this row sits between them."""
    return {
        "tijd": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "run": run,
        "doel": doel,
        "fase": PHASE_NAMES[0],
        "gebeurtenis": ROLLBACK_EVENT,
        "poort": [
            {"naam": g.name, "type": g.type, "uitkomst": g.outcome, "bewijs": g.evidence, "reden": g.reason}
            for g in gates
        ],
        "uitkomst": "gestart",
        "bewijs": bewijs,
        "actieid": actieid,
        "bevestiger": bevestiger,
        "gestart": started,
        "geeindigd": None,
    }


def ledger_line(verdict, *, run, doel, actieid, bevestiger, started, ended, event) -> dict:
    """One ledger row. `event` is the `gebeurtenis` this row gets - R0
    (`voormeting_vast`) and R6 (`soak_open`) name a different word than
    `verdict.outcome` would suggest, so the caller supplies it rather than
    this function inventing it from the outcome (design: "de ledger,
    letterlijk", the table naming each phase's own closing event)."""
    return {
        "tijd": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "run": run,
        "doel": doel,
        "fase": verdict.phase,
        "gebeurtenis": event,
        "poort": [
            {"naam": g.name, "type": g.type, "uitkomst": g.outcome, "bewijs": g.evidence, "reden": g.reason}
            for g in verdict.gates
        ],
        "uitkomst": verdict.outcome,
        "bewijs": verdict.evidence,
        "actieid": actieid,
        "bevestiger": bevestiger,
        "gestart": started,
        "geeindigd": ended,
    }


def append_line(path, line) -> None:
    """Append-only, one JSON object per line, fsynced before the next action
    begins - not "eventually flushed": a crash right after this call must
    not lose the line.

    When this call CREATES the file (the first line of a new run), the
    file's own fsync durably persists its CONTENT but not the new
    directory ENTRY that names it - a crash right after could still lose
    the file itself even though every byte inside it was synced. `_fsync_dir`
    closes that gap, best-effort: `os.fsync` on a directory file descriptor
    is a POSIX operation with no Windows equivalent, so a platform that
    cannot do this simply keeps the file's own fsync, unchanged from
    before."""
    pad = Path(path)
    nieuw = not pad.exists()
    tekst = json.dumps(line, ensure_ascii=False)
    with open(pad, "a", encoding="utf-8", newline="\n") as f:
        f.write(tekst + "\n")
        f.flush()
        os.fsync(f.fileno())
    if nieuw:
        _fsync_dir(pad.parent)


def _fsync_dir(map_pad: Path) -> None:
    """Best-effort fsync of a directory's own entry list, POSIX-only - see
    `append_line`'s docstring for why this exists and why it swallows every
    `OSError` (including on Windows, where opening a directory this way is
    simply not supported)."""
    try:
        fd = os.open(str(map_pad), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def read_ledger(path, *, skipped: list | None = None) -> tuple[dict, ...]:
    """Every line of `path`, in file order, as a `dict`. A blank trailing
    line (or a missing file's caller passing an empty string) is simply
    skipped - never a parse error.

    Every line is UNTRUSTED: a ledger a future version reads was written by
    a process this module does not control, and `append_line()` guarantees
    fsync per line but NOT that a process cannot die mid-write. A line that
    fails to parse as JSON, or that parses to something other than a JSON
    object (a truncated trailing line, a stray array), is SKIPPED and
    recorded with a `RuntimeWarning` instead of raising - one bad line must
    never make every correctly closed phase written before it disappear.

    That guard is per LINE, and so is the DECODE. `read_text(encoding=
    "utf-8")` decodes the whole file in one go, so a single trailing line
    cut in the middle of a multi-byte character raised a
    `UnicodeDecodeError` for the entire file and hid every correctly closed
    phase behind it - fail closed, but it bricks a run mid-upgrade. Vendor
    strings reach `bewijs`/`reden` and `append_line()` writes them with
    `ensure_ascii=False`, so those bytes are really there. Reading bytes
    and decoding per line also keeps a `U+2028`/`U+0085` inside a vendor
    string from splitting one ledger row in two, which `str.splitlines()`
    did and `bytes.splitlines()` does not.

    `skipped`: an OPTIONAL list this
    call appends one entry to per skipped line, IN ADDITION TO the
    `warnings.warn()` above - never instead of it, so every existing
    `pytest.warns(RuntimeWarning)` caller keeps working unchanged. A caller
    that wants to know "how many lines could not be read" without going
    through the warnings module gets it here directly: `warnings.
    catch_warnings(record=True)` is PROCESS-GLOBAL, not thread-safe, and a
    caller (`onderhoud_upgrade_stand`, `mcp_server.py`) that opened such a
    window while ANOTHER thread (`status_ververs`'s `collect()`, run via
    `asyncio.to_thread`) happened to raise its own warning captured that
    unrelated warning as if it were about THIS ledger - and an
    argument-less `RuntimeWarning` raised in that same window blanked the
    joined reason text, crashing `ReadGap.__post_init__`. `skipped` needs
    none of that: it is a plain list, local to this call, nothing global to
    race."""
    rauw = Path(path).read_bytes()
    regels = []
    for volgnummer, regelbytes in enumerate(rauw.splitlines(), start=1):
        try:
            regel = regelbytes.decode("utf-8")
        except UnicodeDecodeError:
            warnings.warn(
                f"read_ledger: regel {volgnummer} in {path} is geen geldige UTF-8 en is overgeslagen",
                RuntimeWarning,
                stacklevel=2,
            )
            if skipped is not None:
                skipped.append(volgnummer)
            continue
        if not regel.strip():
            continue
        try:
            geparsed = json.loads(regel)
        except json.JSONDecodeError:
            warnings.warn(
                f"read_ledger: regel {volgnummer} in {path} is geen geldige JSON en is overgeslagen",
                RuntimeWarning,
                stacklevel=2,
            )
            if skipped is not None:
                skipped.append(volgnummer)
            continue
        if not isinstance(geparsed, dict):
            warnings.warn(
                f"read_ledger: regel {volgnummer} in {path} is geen object en is overgeslagen",
                RuntimeWarning,
                stacklevel=2,
            )
            if skipped is not None:
                skipped.append(volgnummer)
            continue
        regels.append(geparsed)
    return tuple(regels)


@dataclass(frozen=True)
class OpenPhase:
    """One phase with a `fase_gestart` row and no closing row for that same
    phase - and whether its own time ceiling has passed since.

    `started` is the row's own `tijd` (always written, by
    `upgrade_measure._start()`), falling back to its `gestart` field; `None`
    when neither can be read. `limit_s` is `PHASE_LIMITS_S[phase]`, or
    `NO_CEILING_FALLBACK_S` for the two phases that carry no ceiling of
    their own.

    `phase` is a LEDGER string and therefore untrusted - unbounded in the
    row, and echoed into an operator-facing refusal by every caller of
    `blocking_phase()`. It is bounded here, at the one place it is read,
    rather than at each of those callers. A real phase
    name is two characters, so the bound changes nothing a correct ledger
    ever carries.

    `run` on THIS dataclass still needs no bound of its own: no caller of
    `blocking_phase()`/`open_phases()` echoes `OpenPhase.run` - it is only
    ever read to pick an EXPIRED R0's run for adoption (`mcp_server.py`'s
    R0-adoption comment) or reused to build a run's own ledger path, which
    is `is_safe_run_name()`-checked before that construction runs (same
    comment: "`run_name` is NEVER echoed here"). That claim used to read as a
    blanket one - "no caller echoes `run`", full stop - which is now
    FALSE: `onderhoud_upgrade_stand` (`mcp_server.py`) echoes a
    ledger-derived `run` into its own `Finding.outcome` today, off a
    SEPARATE read (`latest_run_name()`, not this dataclass). That value is
    bounded and sanitised at its own call site (`_bounded_run_echo()`
    above) precisely because, unlike `OpenPhase.run`, it reaches an
    operator-facing answer.
    """

    run: str
    phase: str
    started: datetime | None
    limit_s: int
    expired: bool


def phase_ceiling_s(phase) -> int:
    """How long an unclosed `phase` may hold a target: its own
    `PHASE_LIMITS_S` entry, or `NO_CEILING_FALLBACK_S` for the two phases
    that carry no ceiling of their own (R0, R6) - never 0, which would mean
    "no block at all", and never unbounded. The ONE place that derivation
    lives: `open_phases()` below and the register of undecided starts
    (`UndecidedStart`) both ask it, so a phase that holds a target through
    the ledger and one that holds it through the register lift at the same
    moment. Read at call time, so a shortened limit in a test applies to
    both."""
    return PHASE_LIMITS_S.get(str(phase), 0) or NO_CEILING_FALLBACK_S


def _open_phase_start(row: dict) -> datetime | None:
    """When the open phase began, from the row that says it began. `tijd` is
    written by this product on EVERY ledger row; `gestart` is optional
    (`upgrade_measure._start()` copies whatever the runner handed in), so it
    is the fallback and not the other way round."""
    return _read_moment(row.get("tijd")) or _read_moment(row.get("gestart"))


def open_phases(lines, now=None) -> tuple[OpenPhase, ...]:
    """Every (run, phase) pair in `lines` whose LAST state-changing row is a
    `fase_gestart` - the same LAST-ROW question `phase_state()`/
    `_last_phase_row()` already ask for one pair, asked here for every pair
    `lines` carries, in the order each pair is first seen.

    This used to ask a DIFFERENT question - "is
    there ANY closing row anywhere in this run for this phase" - which
    treated a phase as permanently closed the instant one closing row
    existed, so a RETRY (a fresh `fase_gestart` row written AFTER an earlier
    `poort_dicht`/`fase_mislukt` for the same run+phase - exactly what the
    runner writes before every real invocation) went invisible to this
    scan, and therefore to `blocking_phase()`, while a second upload
    genuinely ran. Settled retry semantics (also documented at
    `phase_has_closing_row()` below, which the JUDGING guard uses instead -
    a DIFFERENT question with a DIFFERENT answer, on purpose): a phase that
    already carries a closing row in its run should never be re-run in
    practice, but IF a fresh start row for it appears anyway, this function
    must still treat it as blocking - the single-writer lock errs towards
    refusing, never towards waving through a second writer because an
    earlier attempt happened to close first.

    WHY the ceiling is part of this: a phase that
    never got a closing row is reachable along a DOCUMENTED path - exit code
    3 in `scripts/README.md` ("de runner kon zijn werk niet eens proberen te
    voltooien ... er komt geen sluitregel in het ledger") happens AFTER this
    row is written, and so does a killed detached runner, which this product
    admits it cannot stop. Reading such a row as "still open" forever locks
    every writing tool on that target with no way back. An open phase whose
    ceiling has passed without a closing row is not open: it is `mislukt`
    with reason `tijdslimiet`, exactly the word `evaluate_phase()` already
    writes for a phase that ran past `PHASE_LIMITS_S`.

    A row whose start time cannot be read is NOT declared expired
    (`expired=False`): the ceiling cannot be measured against it, and this
    gate errs towards refusing. `niet beoordeeld` counts nowhere as `open`
    and nowhere as a pass - here that means it keeps the refusal standing,
    and the caller says so in words rather than letting it look like a
    running phase.

    `now` may be `None` (no clock available to judge against); every phase
    then comes back `expired=False`, the same fail-closed direction.
    """
    laatste: dict[tuple, dict] = {}
    volgorde: list[tuple] = []
    for row in lines:
        gebeurtenis = row.get("gebeurtenis")
        if gebeurtenis in _EVIDENCE_EVENTS:
            continue
        if gebeurtenis != "fase_gestart" and gebeurtenis not in _CLOSING_EVENTS:
            continue
        sleutel = (row.get("run"), row.get("fase"))
        if sleutel not in laatste:
            volgorde.append(sleutel)
        laatste[sleutel] = row  # `lines` arrives time-ordered - last one wins
    found: list[OpenPhase] = []
    for run, phase in volgorde:
        row = laatste[(run, phase)]
        if row.get("gebeurtenis") != "fase_gestart":
            continue
        started = _open_phase_start(row)
        limit_s = phase_ceiling_s(phase)
        expired = now is not None and started is not None and now - started > timedelta(seconds=limit_s)
        found.append(
            OpenPhase(
                run=run,
                phase=_bounded(phase),
                started=started,
                limit_s=limit_s,
                expired=expired,
            )
        )
    return tuple(found)


def phase_has_closing_row(lines, phase: str) -> bool:
    """Whether `lines` carries ANY closing row for `phase` - regardless of
    whether a LATER `fase_gestart` row for it also exists).

    A DIFFERENT question from `phase_state()`'s (deliberately - see
    `open_phases()` above for the other half of this split): `phase_state()`
    answers "what does this phase look like RIGHT NOW", off the LAST row,
    which is exactly right for ordinary status reporting
    (`order_gate()`/`stand_answer()`). It is WRONG for the question
    `upgrade_gate.main()`'s re-judge guard actually needs, because the
    runner always writes a FRESH `fase_gestart` row into a run's own file
    before ever calling `python -m nsmcp.upgrade_gate`
    (`Invoke-GjkUpgradeFase.ps1`'s own step 4) - so on the real path the
    LAST row for a phase is, by construction, always that fresh start row.
    A `phase_state()`-based guard therefore NEVER saw a closed phase as
    closed once judged again, even when an earlier closing row for it
    genuinely existed - the guard "never fired on the real path".

    Settled retry semantics: a phase that already carries a closing row in
    its run may not be re-run at all; a retry is a NEW RUN, never a second
    `fase_gestart` for the same run+phase. This function is the ONE place
    that rule is checked before a NEW closing row is ever appended."""
    return any(
        isinstance(regel, dict) and regel.get("fase") == phase and regel.get("gebeurtenis") in _CLOSING_EVENTS
        for regel in lines
    )


def blocking_phase(lines, now) -> OpenPhase | None:
    """The open phase that still BLOCKS: the first one whose ceiling has not
    passed. `None` when every open phase in `lines` is over its ceiling (or
    when there is none at all) - that is the exit the refusal needs.

    NO EXEMPTION for the caller's own run (this function USED to take an
    `except_run` parameter that skipped
    every non-expired open phase of the run being called). This product
    cannot stop a detached faserunner, and it cannot even OBSERVE whether
    one is still genuinely running - so "the caller's own run" and "some
    other process" are indistinguishable from here, and the only retry this
    product can safely allow is one whose ceiling has already passed
    (`phase.expired`, still checked below). Dropping the exemption closed a
    real hole: `fase=R1 run=A` while A's own R1 was still mid-upload used to
    start a SECOND runner against the same appliance and the same ledger
    file, simply by being invoked again with the SAME run name - R0's own
    adoption rule already only ever adopts an EXPIRED open R0 of its own
    kind (`mcp_server.py`'s R0-adoption comment), and R1..R6 now get exactly
    that same discipline, via the one path every phase already shares.
    """
    for phase in open_phases(lines, now):
        if phase.expired:
            continue
        return phase
    return None


def expired_phases(lines, now) -> tuple[OpenPhase, ...]:
    """The open phases whose ceiling HAS passed - what the caller names when
    it lets a refusal lift, so the operator learns why it is gone."""
    return tuple(phase for phase in open_phases(lines, now) if phase.expired)


def wait_for_start(path, run, phase, deadline_s=START_WAIT_S, skip_existing: int = 0) -> dict | None:
    """Polls the ledger for the `fase_gestart` row of `run`/`phase` and
    returns it the moment it appears - never waits for the phase to finish
    (design 3.5: R1 alone measured 460 s of upload, and a writing tool's own
    timeout is 300 s). `None` once `deadline_s` passes without that row.

    `skip_existing` is how many matching rows were ALREADY in the file before
    this attempt was started; only row number `skip_existing + 1` onwards
    counts as this attempt's own start. Without it a RETRY of a phase on the
    same run - the documented escape from a phase that never closed, and the
    only escape a stale R0 has - matched the PREVIOUS attempt's row
    immediately and reported FASE GESTART for a runner that never wrote a
    line. Counting rows rather than comparing timestamps keeps this
    independent of any clock the runner writes with.
    """
    einde = time.monotonic() + deadline_s
    while True:
        if Path(path).exists():
            matches = [
                row
                for row in read_ledger(path)
                if row.get("run") == run and row.get("fase") == phase and row.get("gebeurtenis") == "fase_gestart"
            ]
            if len(matches) > skip_existing:
                return matches[-1]
        if time.monotonic() >= einde:
            return None
        time.sleep(0.2)


def started_rows(path, run, phase) -> int:
    """How many `fase_gestart` rows for `run`/`phase` the file already
    carries - `wait_for_start`'s `skip_existing`, counted BEFORE the runner
    is started so a retry cannot read the previous attempt as its own."""
    if not Path(path).exists():
        return 0
    return sum(
        1
        for row in read_ledger(path)
        if row.get("run") == run and row.get("fase") == phase and row.get("gebeurtenis") == "fase_gestart"
    )


@dataclass(frozen=True)
class UndecidedStart:
    """A confirmed phase whose detached runner was launched, but whose own
    `fase_gestart` row the server did not see within the wait
    (`START_WAIT_S`) - or whose wait broke off (`broke_off`: the wait itself
    raised or was cancelled) - or whose wait still runs (`waiting_until`:
    the moment the confirmed call stops waiting; `None` once the wait has
    ended one of the other two ways). The runner may still be starting: this
    product cannot stop or observe a detached process, and an empty ledger
    is exactly what a SLOW runner leaves behind. Measured: a runner that
    wrote its row after the wait let a new proposal and confirmation for the
    same phase and run start a SECOND runner against the same appliance.

    `ledger_path` is the run file the runner was told to write to;
    `already_started` is the count of matching `fase_gestart` rows in it
    BEFORE this launch (`started_rows()`), so a later row - the one that
    decides the start - is told apart from an earlier attempt's. `limit_s`
    and `deadline` follow `phase_ceiling_s()`: the same ceiling the ledger
    would give this phase once its row is there."""

    target: str
    run: str
    phase: str
    launched: datetime
    ledger_path: Path
    already_started: int
    wait_s: int
    broke_off: bool
    waiting_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.broke_off and self.waiting_until is not None:
            raise ValueError("een start waarvan het wachten afbrak, wacht niet meer")

    @property
    def limit_s(self) -> int:
        return phase_ceiling_s(self.phase)

    @property
    def deadline(self) -> datetime:
        return self.launched + timedelta(seconds=self.limit_s)

    def landed(self, rows) -> bool:
        """Whether `rows` - the target's rows as the CALLER read them,
        strictly, for its own open-phase gate - carry a `fase_gestart` row
        for this run and phase beyond the ones that were there before the
        launch. The same snapshot decides both questions on purpose: had
        the register read the file again by itself, a row landing between
        the caller's read and this one would drop the hold while the
        caller's open-phase gate, on its older rows, still saw nothing
        open - the very window this register closes."""
        count = sum(
            1
            for row in rows
            if isinstance(row, dict)
            and row.get("run") == self.run
            and row.get("fase") == self.phase
            and row.get("gebeurtenis") == "fase_gestart"
        )
        return count > self.already_started


class UndecidedStarts:
    """The register of undecided starts: per SERVER PROCESS, per target,
    at most one entry. It lives in memory only - after a restart of the
    server the ledger alone decides again (docs/klant/SECURITY.md says so
    where it promises one writer at a time).

    "Per target" means per target NAME, in the one spelling the open-phase
    gate compares targets on (`_key()`): the configuration accepts two names
    that differ only in capitalisation or in the domain part of an FQDN, and
    the ledger's gate holds both to one open phase. Measured when the
    register keyed on the exact name: inside the window such a second
    configured name proposed AND ran a backup, which the ledger gate refused
    on that very name the moment the runner's row had landed. A name with
    another first label is another target here, as it is to that gate - the
    register knows names, not appliances. That two targets never carry one
    address is the start's check on the targets file
    (`start._require_one_target_per_address`, the address compared as text,
    never resolved); only through that check is a target name one address.

    Every writing tool asks `check()` for its target before anything else
    that could reach the appliance, next to the open-phase gate and with
    the rows that gate reads (strictly - an unreadable ledger has already
    refused by then). An entry RESOLVES ITSELF at that moment:

    - the runner's row has landed in those rows: the entry is dropped and
      the ordinary open-phase gate (`blocking_phase()`) takes over, with its
      own refusal and its own lift;
    - the deadline (launch + the phase's own ceiling) has passed without
      that row: the entry no longer blocks and is returned as LAPSED, so the
      answer that is let through says so - the same "no refusal disappears
      silently" rule `expired_phases()` follows. It stays until a decided
      start on that target replaces or clears it, exactly as an expired
      open phase keeps being named until its run closes it;
    - otherwise it BLOCKS.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, UndecidedStart] = {}

    @staticmethod
    def _key(target: str) -> str:
        """The register's key for `target`: `upgrade_gate._normalised_target()`,
        the very rule `_rows_for_target()` - and so `blocking_phase()` - binds
        ledger rows to a target with. Reused, never re-implemented: the hold
        in the window must never be narrower than the gate it stands in for."""
        # Imported here, not at the top: `nsmcp.upgrade_gate` imports this
        # module.
        from nsmcp.upgrade_gate import _normalised_target

        return _normalised_target(target)

    def record(self, entry: UndecidedStart) -> UndecidedStart | None:
        """Hold `entry`'s target; returns the entry it replaced (a hold that
        already lapsed, or `None`), for `withdraw()`."""
        key = self._key(entry.target)
        with self._lock:
            previous = self._entries.get(key)
            self._entries[key] = entry
        return previous

    def withdraw(self, entry: UndecidedStart, previous: UndecidedStart | None) -> None:
        """Take back `record(entry)` for a start that provably launched
        nothing (no child process exists): the register holds `previous`
        again - a lapsed hold stays audible, as it would have without the
        attempt - or nothing. Only while `entry` is still the one held."""
        key = self._key(entry.target)
        with self._lock:
            if self._entries.get(key) is not entry:
                return
            if previous is None:
                del self._entries[key]
            else:
                self._entries[key] = previous

    def discard(self, target: str) -> None:
        with self._lock:
            self._entries.pop(self._key(target), None)

    def check(self, target: str, now: datetime, rows) -> tuple[UndecidedStart | None, UndecidedStart | None]:
        """`(blocking, lapsed)` for `target` at `now`, judged against
        `rows` (the target's ledger rows as the caller read them) - at most
        one of the two is not `None`. See the class docstring for how an
        entry resolves."""
        key = self._key(target)
        with self._lock:
            entry = self._entries.get(key)
        if entry is None:
            return None, None
        if entry.landed(rows):
            with self._lock:
                if self._entries.get(key) is entry:
                    del self._entries[key]
            return None, None
        if now > entry.deadline:
            return None, entry
        return entry, None


def normalised_anchor(lines) -> tuple[str, dict[str, int]]:
    """The R0/R5 comparison anchor: (1) drop blank lines and `#`-lines; (2)
    drop lines that start with `set ns encryptionParams` or `set ns rpcNode`,
    or that carry `-encrypted`, and COUNT them per kind; (3) sort what is
    left ORDINALLY (`sorted()` on the bare string - Python sorts ordinally,
    unlike PowerShell's `Sort-Object`); (4) sha256 over the rest. Returns
    `(hexdigest, {soort: aantal})`. A changed COUNT is itself a difference -
    dropping a blob line without counting it would hide a real change.
    """
    tellingen: dict[str, int] = {}
    overgebleven: list[str] = []
    for regel in lines:
        kale = regel.strip()
        if not kale or kale.startswith("#"):
            continue
        soort = None
        for prefix in _BLOB_PREFIXES:
            if kale.startswith(prefix):
                soort = prefix
                break
        if soort is None and _BLOB_MARKER in kale:
            soort = _BLOB_MARKER
        if soort is not None:
            tellingen[soort] = tellingen.get(soort, 0) + 1
            continue
        overgebleven.append(kale)
    overgebleven.sort()
    anker = hashlib.sha256("\n".join(overgebleven).encode("utf-8")).hexdigest()
    return anker, tellingen
