"""Nine checks that can stop an upgrade within 14.1 - and nothing more.

This is NOT a vendor pre-check. `installns --pre_check` is the vendor's own
judgement, it needs a shell, and it belongs in phase R2 of the runner
(design 2.3, 2.8). This tool answers the question days BEFORE the window:
what would stop us, so it can be arranged in time.

Eight of the nine read from the export. The ninth - free space on `/var` -
is read LIVE in a separate process: over SSH (the small read script next to
the faserunner, `df -k /var` with the pinned host key) when `onderhoud` is
configured and the target carries a pinned host key, otherwise through the
same separate process the scan uses, with the same `doelen` credential. The
server chooses the route on configuration and names it in the evidence
(`FREE_SPACE_ROUTE_SSH` / `FREE_SPACE_ROUTE_COLLECTOR`). That is the one
documented exception in this module, it is named in README.md and in
tests/test_no_network.py, and it exists because a free-space figure from last
week's scan says nothing about the moment of the attempt.

THE EXPORT AND THE KNOWLEDGE PACKAGE ARE SUPPLIED INPUT. Every field read
here is attacker-controllable text, and `Answer.to_text()` renders a finding
as "- <onderwerp>: <uitkomst> [vastgesteld]": one line break in a value
writes a second, indistinguishable line. Measured elsewhere in this codebase
(a forged status, a path traversal through a manifest key), so the rule is
applied here from the start and not after the fact:

- NOTHING out of the export is echoed. Not `hwdescription`, not `licensetype`,
  not a backup filename, not a running-config line. The answer names the
  FIELD and this product's OWN word for what it read there - "VPX", "FIPS",
  "add filter" - never the value.
- The branch KEYS of `knowledge.offered_builds` are printable but NOT
  shape-checked, so this module LOOKS UP the branch it parsed out of
  the export and never iterates over those keys.
- A bulletin identifier goes through `update_advice.public_bulletin_id()`,
  the PUBLIC gate that `floor_for()` obliges its consumers to use.
- Dates are FORMATTED (`update_advice.day()`), never echoed:
  `date.fromisoformat` also accepts the basic form, so a JSON number
  20260901 arrives here as the string '20260901'.

THREE OF THE NINE reach beyond a plain export read for their source.
`ha.ha_result` and `expiry.usage_per_certificate` are both available on
this branch and read for real (the HA check still goes through a guarded
import, kept as a defensive fallback rather than an unconditional one);
the live read of the free space needs a configured target instead. All
three yield `niet beoordeeld` WITH A NAMED REASON - never `geen
blokkade` - whenever their source is unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime

from nsmcp.answer import Answer, Certainty, Finding
from nsmcp.classic import (
    CANDIDATE_PARAMETERS_NOTE,
    MARKERS_SEARCHED,
    NOT_EXAMINED_ROWS,
    SET_BLOCKING,
    SET_DEPRECATED,
    SET_LABELS,
    SET_UNBOUND,
    SET_UNDECIDED,
    classify,
    classify_markers,
    markers_bound,
)
from nsmcp.config_drift import comparison_evidence, read_comparison, undecided_reason
from nsmcp.cve import (
    FIPS_SUFFIX,
    PLATFORM_FIPS,
    PLATFORM_UNKNOWN,
    fips_platform,
    parse_build,
)
from nsmcp.expiry import THRESHOLDS, age_of, bucket_from_today, counted_from_today, usage_per_certificate
from nsmcp.export import KEY_MISSING_TEXT, RUNNING_CONFIG_FILE, SAVED_CONFIG_FILE, SAVED_CONFIG_RESOURCE, shape_of
from nsmcp.update_advice import as_pair, day, floor_for, public_bulletin_id

NO_BLOCKER = "geen blokkade"
BLOCKER = "blokkade"
ATTENTION = "aandachtspunt"
NOT_ASSESSED = "niet beoordeeld"
PREFLIGHT_WORDS: tuple[str, ...] = (NO_BLOCKER, BLOCKER, ATTENTION, NOT_ASSESSED)

# Measured 6-9-2026 on the lab VPX: installns_legacy line 93 keeps
# 4_100_000 blocks of 1k free on /var, and it tests that AFTER unpacking.
VENDOR_FLOOR_MB = 4004
# The bundle size to assume when `onderhoud.firmwaremap` names none.
# Measured: a 14.1 bundle is 1081 MB; 1100 is the conservative round-up.
ASSUMED_BUNDLE_MB = 1100

# The heading, and it is only allowed to appear when all nine say so.
CONCLUSIVE_HEADING = "negen toetsen, geen blokkade"

# The one branch an upgrade may happen within (design, decision 2).
TARGET_BRANCH = "14.1"

LICENSE_RESOURCE = "config/nslicense"
LICENSE_SERVER_RESOURCE = "config/nslicenseserver"
VERSION_RESOURCE = "config/nsversion"
HARDWARE_RESOURCE = "config/nshardware"
CONFIG_RESOURCE = "config/nsconfig"
BACKUP_RESOURCE = "config/systembackup"
# A14 pins this key literally, query string included: the collector reads
# `config/systemfile` twice, and only the read with `filelocation` on
# `/var/nsinstall` is the build tree. `export._object_payload` strips the
# query string again when it builds the file name (`objects/systemfile.json`).
BUILD_TREE_RESOURCE = "config/systemfile?args=filelocation:%2Fvar%2Fnsinstall"
BUILD_TREE_LOCATION = "/var/nsinstall"
FREE_SPACE_RESOURCE = "stat/system"
# The field of `stat/system` that carries the free space on `/var` in MB.
# On a NetScaler disk0 is `/flash` and disk1 is `/var`; the pre-flight is
# about `/var`, so disk1 it is. Named here rather than inside the reader, so
# the one place that has to change if that ever proves otherwise is visible.
FREE_SPACE_FIELD = "disk1avail"
# The two routes of the live read, chosen on CONFIGURATION by the server
# (`mcp_server._free_var_mb`): over SSH when `onderhoud` is configured and the
# target carries a pinned host key, otherwise through the collector. The
# evidence line of check 8 names the route that was taken.
FREE_SPACE_ROUTE_SSH = "df -k /var over SSH"
FREE_SPACE_ROUTE_COLLECTOR = f"{FREE_SPACE_RESOURCE} via het verzamelscript"
# The one line the read script (scripts/Invoke-GjkLiveMeting.ps1) prints for
# a measured value: a whole number of MB, nothing else on the line.
_FREE_MB_LINE = re.compile(r"\[VRIJ_MB\] (?P<mb>[0-9]{1,9})")
_SCRIPT_ERROR_PREFIX = "[FOUT] "
_SCRIPT_REASON_LIMIT = 200
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]")

# "The field is not there" against "the field is there and carries something
# this product cannot read". Only the second says anything about the
# appliance - the same distinction `cve.py` makes with the same sentinel.
_NO_FIELD = object()


@dataclass(frozen=True)
class Check:
    number: int
    name: str
    word: str  # uit PREFLIGHT_WORDS
    evidence: str
    reason: str = ""

    def __post_init__(self) -> None:
        if self.word not in PREFLIGHT_WORDS:
            raise ValueError(f"unknown preflight word: {self.word}")
        if self.word != NO_BLOCKER and not self.reason.strip():
            raise ValueError("a check that is not 'geen blokkade' must say why")


# ---------------------------------------------------------------------------
# Reading helpers. Everything here answers the same question: is this value
# usable, and if not, what do we SAY about it - never what does it contain.
# ---------------------------------------------------------------------------


def _text(value) -> str | None:
    """The stripped text of a value, or None when there is none.

    Deliberately not `str(value)`: `str(None)` is the non-empty text "None",
    so a bare truthiness test would let a JSON null through as a readable
    value. A boolean is refused for the same reason - `True` is not a licence
    model.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _field(row, name):
    """The raw value of a field, or `_NO_FIELD` when the row does not carry it."""
    if not isinstance(row, dict):
        return _NO_FIELD
    return row.get(name, _NO_FIELD)


# The shape in which a NetScaler writes a timestamp on `nsconfig` and
# `systembackup`: "Sat Sep  5 08:30:00 2026". Read POSITIVELY - anything this
# format does not match is unreadable, never a guess - and the parsed value is
# used only for a COMPARISON: the text itself never reaches an answer.
_APPLIANCE_TIME = "%a %b %d %H:%M:%S %Y"


def _moment(value) -> datetime | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return datetime.strptime(text, _APPLIANCE_TIME)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 1. Licence mode and licence server
# ---------------------------------------------------------------------------

NAME_1 = "licentiemodus en licentieserver"

# The field that names the licence MODEL. `licensetype` is what design 2.3
# names; `licensingmode` is what the released collector actually writes on the
# lab export (measured on `tests/fixtures/lab-export-vpx-20260826/`). Both are
# read, in this order, and a field that is PRESENT but unusable stops the
# search: "present and empty" is a statement about the appliance, "absent" is
# not, and falling through from the first to the second would turn the empty
# `licensetype` design 2.3 calls an `aandachtspunt` into a silent green.
_LICENSE_MODEL_FIELDS = ("licensetype", "licensingmode")
# The edition flags. At least one of them true is what "there is a valid
# licence" means on this object; all of them readable and false is the
# `blokkade`. None of them readable at all is NOT a blocker - claiming "no
# valid licence" from a field nobody read is the same false verdict in the
# other direction.
_LICENSE_EDITION_FIELDS = (
    "isstandardlic",
    "isenterpriselic",
    "isplatinumlic",
    "issgwylic",
    "isswglic",
)


def _check_1_license(export) -> Check:
    row, gap = export.single(LICENSE_RESOURCE)
    if gap is not None:
        return Check(1, NAME_1, NOT_ASSESSED, LICENSE_RESOURCE, gap.reason)
    if row is None:
        return Check(
            1,
            NAME_1,
            NOT_ASSESSED,
            LICENSE_RESOURCE,
            f"{LICENSE_RESOURCE} is gelezen en droeg geen licentieobject; zonder object is er"
            " geen licentiemodel om over te oordelen",
        )

    model_field = None
    model_readable = False
    for name in _LICENSE_MODEL_FIELDS:
        raw = _field(row, name)
        if raw is _NO_FIELD:
            continue
        model_field = name
        model_readable = _text(raw) is not None
        break

    editions = [_field(row, name) for name in _LICENSE_EDITION_FIELDS]
    readable_editions = [value for value in editions if isinstance(value, bool)]

    evidence = (
        f"{LICENSE_RESOURCE}: licentiemodel uit veld"
        f" {model_field if model_field else 'geen van ' + '/'.join(_LICENSE_MODEL_FIELDS)},"
        f" geldigheid uit {len(readable_editions)} van {len(_LICENSE_EDITION_FIELDS)} leesbare"
        f" editievelden; {LICENSE_SERVER_RESOURCE} voor de licentieserver"
    )

    if readable_editions and not any(readable_editions):
        return Check(
            1,
            NAME_1,
            BLOCKER,
            evidence,
            "geen enkel editieveld staat aan; er is geen geldige licentie, en een upgrade loopt daar op vast",
        )
    if not readable_editions:
        return Check(
            1,
            NAME_1,
            NOT_ASSESSED,
            evidence,
            f"{LICENSE_RESOURCE} draagt geen leesbaar editieveld"
            f" ({', '.join(_LICENSE_EDITION_FIELDS)}); of de licentie geldig is, is niet vast"
            " te stellen",
        )
    if model_field is None:
        return Check(
            1,
            NAME_1,
            ATTENTION,
            evidence,
            f"{LICENSE_RESOURCE} draagt geen veld met het licentiemodel"
            f" ({' of '.join(_LICENSE_MODEL_FIELDS)}); het model staat niet vast",
        )
    if not model_readable:
        return Check(
            1,
            NAME_1,
            ATTENTION,
            evidence,
            f"het veld {model_field} is leeg of onleesbaar; het licentiemodel staat niet vast",
        )

    server_word, server_reason = _license_server_word(export)
    if server_word is not NO_BLOCKER:
        return Check(1, NAME_1, server_word, evidence, server_reason)
    return Check(1, NAME_1, NO_BLOCKER, evidence)


# What a reachable licence server says about itself. A positive test: a status
# this product does not recognize is not a reachable server.
_LICENSE_SERVER_UP = {"UP", "ACTIVE", "REACHABLE", "CONNECTED"}


def _license_server_word(export) -> tuple[str, str]:
    """The licence-server half of check 1: `geen blokkade`, `aandachtspunt`,
    or `niet beoordeeld` when a read gap makes a verdict impossible.

    Design 2.3 puts "a CONFIGURED but UNREACHABLE licence server" at
    `aandachtspunt` - but that describes a server this product actually READ.
    Two different things can make that impossible:

    - A read gap on `config/nslicenseserver` ITSELF (RBAC, a missing object
      file, a manifest status outside OK/EMPTY, ...): nothing was read at
      all, so this follows the same rule as every other read gap in this
      module and answers `niet beoordeeld`.
    - A server object that WAS read, but whose "status" field is not
      readable text - JSON null, an int, a bool, a list, a dict, an empty or
      whitespace-only string, or the field absent entirely. This is the same
      fact one level deeper: the FIELD, not the resource, is the read gap. A
      verdict on a field nobody could interpret is exactly the
      false-established shape this product exists to prevent, so it answers
      `niet beoordeeld` too, never `aandachtspunt` - the earlier code let
      this field-level gap fall into `aandachtspunt`, which claimed a
      certainty ("the appliance says this is unreachable") that was never
      established. The reason names the SHAPE of what was found, via the
      canonical `export.py::shape_of()` and its `KEY_MISSING_TEXT`
      idiom for the absent-field case - the same helper and phrasing already
      used in export.py, impact.py and overzicht.py, and NEVER the value
      itself, for the same reason those call sites give it: a list or dict
      status is attacker-controlled text and could otherwise forge a
      certainty marker or inject a line break into the rendered answer (see
      the module docstring on `Answer.to_text()`).

    Both are the false-established direction of the same rule the empty-list
    branch below guards in the false-empty direction: neither a gap nor an
    unreadable field may present itself as a value that was actually read.

    MIXED case (some servers unreachable, some unreadable): `aandachtspunt`
    wins, because at least one server really WAS read and really did report
    a status this product does not recognise - that finding is genuinely
    established. But the reason then also names how many servers could not
    be assessed at all; staying silent about them would hide that some of
    the configured servers were never actually judged, the same hole one
    level over.
    """
    servers, gap = export.objects(LICENSE_SERVER_RESOURCE)
    if gap is not None:
        return NOT_ASSESSED, (
            f"{LICENSE_SERVER_RESOURCE} was niet te lezen ({gap.reason}); of er een"
            " licentieserver geconfigureerd staat en of die bereikbaar is, is niet vast te"
            " stellen"
        )
    if not servers:
        # A READ emptiness: there is no licence server configured, so there is
        # nothing here that can hold an upgrade up.
        return NO_BLOCKER, ""
    unreachable = 0
    unknown = 0
    shapes: list[str] = []
    for server in servers:
        raw = _field(server, "status")
        status = _text(raw)
        if status is None:
            unknown += 1
            shape = KEY_MISSING_TEXT if raw is _NO_FIELD else shape_of(raw)
            if shape not in shapes:
                shapes.append(shape)
        elif status.upper() not in _LICENSE_SERVER_UP:
            unreachable += 1
    if unreachable:
        meldt_meerv = "meldt" if unreachable == 1 else "melden"
        reason = (
            f"{unreachable} van de {len(servers)} geconfigureerde licentieservers {meldt_meerv} geen bereikbare status"
        )
        if unknown:
            shapes_text = ", ".join(shapes)
            draagt_meerv = "draagt" if unknown == 1 else "dragen"
            is_zijn = "is" if unknown == 1 else "zijn"
            reason += (
                f"; daarnaast {draagt_meerv} {unknown} ervan geen leesbare status"
                f" ({shapes_text}) en {is_zijn} dus niet te beoordelen"
            )
        return ATTENTION, reason
    if unknown:
        shapes_text = ", ".join(shapes)
        draagt_meerv = "draagt" if unknown == 1 else "dragen"
        return NOT_ASSESSED, (
            f"{unknown} van de {len(servers)} geconfigureerde licentieservers {draagt_meerv} geen"
            f" leesbare status ({shapes_text}); de bereikbaarheid is niet vast te stellen"
        )
    return NO_BLOCKER, ""


# ---------------------------------------------------------------------------
# 2. Classic markers in the running config
# ---------------------------------------------------------------------------

NAME_2 = "classic-markers in de running config"

# The classic tables and both classifications live in `nsmcp.classic` (spec
# 1.1 A.5.1, one owner per rule). Within the line this check calls the moved
# 1.0.3 marker table and nothing else, so it says byte for byte what it said
# before; the transition check below calls the four-set classification.


def _markers(lines: list[str]) -> tuple[list[int], list[int], list[int]]:
    """(removed, deprecated, bound) - LINE NUMBERS, never text (`classic.classify_markers`)."""
    return classify_markers(lines)


def _is_bound(lines: list[str], marker_lines: list[int]) -> bool:
    """Does any `bind` line name an object one of these marker lines declares (`classic.markers_bound`)?"""
    return markers_bound(lines, marker_lines)


def _check_2_classic_markers(export) -> Check:
    lines, gap = export.running_config_lines()
    if gap is not None:
        return Check(2, NAME_2, NOT_ASSESSED, RUNNING_CONFIG_FILE, gap.reason)
    boundary = (
        f"{RUNNING_CONFIG_FILE}, {len(lines)} regels; gezocht op de markers die in 14.1"
        f" verwijderd zijn: {MARKERS_SEARCHED}; een classic policy die geen van deze markers draagt"
        " valt buiten deze toets, en van een regel wordt nooit de tekst herhaald"
    )
    removed, deprecated, bound_lines = _markers(lines)
    if not removed and not deprecated:
        return Check(2, NAME_2, NO_BLOCKER, boundary)
    evidence = (
        f"{boundary}; verwijderde markers op regel"
        f" {', '.join(str(n) for n in removed) or '-'}; alleen deprecated op regel"
        f" {', '.join(str(n) for n in deprecated) or '-'}"
    )
    if removed and (bound_lines or _is_bound(lines, removed)):
        return Check(
            2,
            NAME_2,
            BLOCKER,
            evidence,
            f"{len(removed)} regel(s) dragen een marker die in 14.1 verwijderd is en die aan een entiteit gebonden is",
        )
    if removed:
        return Check(
            2,
            NAME_2,
            ATTENTION,
            evidence,
            f"{len(removed)} regel(s) dragen een marker die in 14.1 verwijderd is, maar geen"
            " bind-regel noemt het object; ongebonden houdt de upgrade niet tegen, maar de"
            " regel blijft dan onnodig in de configuratie staan",
        )
    return Check(
        2,
        NAME_2,
        ATTENTION,
        evidence,
        f"{len(deprecated)} regel(s) dragen een marker die alleen deprecated is (classic"
        " gateway-authenticatie); dat houdt de upgrade niet tegen",
    )


# Check 2 in TRANSITION mode (13.1 -> 14.1, spec 1.1 A.5.1 and A.9). Not one
# of the nine checks: the step that adds the configuration key
# `onderhoud.overstappen` puts it in the place of `_check_2_classic_markers`
# for a 13.1 appliance in transition mode, and nowhere else. Within 14.1 the
# check above stays the only check 2.
#
# It reads the RUNNING and the SAVED configuration (ruling R1): classic of the
# features in CTX296948 tables 1 and 2 no longer loads from 13.1 on, so on a
# running 13.1 such a command survives only in the saved configuration - and
# that is the file the vendor check reads. Sets 1 and 2 both block (ruling R2):
# the vendor check refuses every command of a removed feature, bound or not.
NAME_2_TRANSITION = "classic-configuratie in de draaiende en de opgeslagen configuratie"
TRANSITION_NOT_A_VENDOR_PRECHECK = "dit is geen vendor-precheck; R2 laat de vendor beslissen met check_invalid_config"
SAVED_CONFIG_ABSENT_REASON = "opgeslagen configuratie niet in de export"
_TRANSITION_SETS = (SET_BLOCKING, SET_UNBOUND, SET_DEPRECATED, SET_UNDECIDED)
_CUT = ", ...(afgekapt)"
_ADJECTIVE = {"draaiend": "draaiende", "opgeslagen": "opgeslagen"}


def _bounded_numbers(numbers) -> str:
    """The line numbers, bounded at whole numbers: a configuration can hold
    thousands of such lines and the evidence is one line in front of an
    operator. The count next to it stays exact."""
    from nsmcp.upgrade import _UNTRUSTED_ECHO_LIMIT

    if not numbers:
        return "-"
    text = ", ".join(str(n) for n in numbers)
    if len(text) <= _UNTRUSTED_ECHO_LIMIT:
        return text
    return text[: text.rfind(", ", 0, _UNTRUSTED_ECHO_LIMIT + 1)] + _CUT


def _source_evidence(file_name: str, label: str, lines, gap, classification) -> str:
    if gap is not None:
        return f"{file_name} ({label}): niet gelezen ({gap.reason})"
    sets = "; ".join(
        f"verzameling {v} ({SET_LABELS[v]}): {len(classification.lines(v))} op regel"
        f" {_bounded_numbers(classification.lines(v))}"
        for v in _TRANSITION_SETS
    )
    return f"{file_name} ({label}), {len(lines)} regels: {sets}"


def _check_2_classic_transition(export) -> Check:
    """Check 2 for the transition: the four sets of `classic.classify` over
    the running AND the saved configuration. `blokkade` when set 1 or 2 is not
    empty in either; `niet beoordeeld` when either cannot be read (the saved
    configuration absent from the export has its own fixed reason) or set 4 is
    not empty; `aandachtspunt` when only set 3 holds something; `geen
    blokkade` when all are empty in both. Counts and line numbers per file,
    never the text of a line."""
    running, running_gap = export.running_config_lines()
    saved, saved_gap = export.saved_config_lines()
    saved_absent = export.status(SAVED_CONFIG_RESOURCE) == "NIET_IN_MANIFEST"
    sources = (
        (RUNNING_CONFIG_FILE, "draaiend", running, running_gap),
        (SAVED_CONFIG_FILE, "opgeslagen", saved, saved_gap),
    )
    classified = [
        (name, label, lines, gap, classify(lines) if gap is None else None) for name, label, lines, gap in sources
    ]
    evidence = (
        "; ".join(_source_evidence(*source) for source in classified)
        + f"; {NOT_EXAMINED_ROWS}; {CANDIDATE_PARAMETERS_NOTE}"
        + f"; van een regel wordt nooit de tekst herhaald; {TRANSITION_NOT_A_VENDOR_PRECHECK}"
    )
    readable = [c for _, _, _, gap, c in classified if gap is None]
    removed = [len(c.removed) for c in readable]
    if any(removed):
        counts = " en ".join(
            f"{len(c.removed)} in de {_ADJECTIVE[label]} configuratie"
            for _, label, _, gap, c in classified
            if gap is None
        )
        return Check(
            2,
            NAME_2_TRANSITION,
            BLOCKER,
            evidence,
            f"regels van een feature waaruit classic vanaf 13.1 verwijderd is ({counts}), gebonden of niet; de"
            " vendorcheck keurt elk commando van zo'n feature af, dus de overstap loopt daarop vast tot ze naar"
            " advanced omgezet zijn",
        )
    if saved_absent:
        return Check(2, NAME_2_TRANSITION, NOT_ASSESSED, evidence, SAVED_CONFIG_ABSENT_REASON)
    for _, _, _, gap, _ in classified:
        if gap is not None:
            return Check(2, NAME_2_TRANSITION, NOT_ASSESSED, evidence, gap.reason)
    undecided = sum(len(c.undecided) for c in readable)
    if undecided:
        # Review K-3: a probable parameter of a row without a known form is
        # "not examined", never "no vendor row or not proven".
        not_examined = sum(len(c.not_examined) for c in readable)
        rows = sorted({row for c in readable for row in c.not_examined_rows()})
        parts = []
        if undecided - not_examined:
            parts.append(
                f"{undecided - not_examined} regel(s) zijn onbeslist: de feature heeft geen vendorrij in dit"
                " product, of de vorm is niet bewezen classic en niet bewezen advanced; een onbesliste regel is"
                " geen groen"
            )
        if not_examined:
            parts.append(f"{not_examined} regel(s) niet onderzocht (tabel 1 rij {', '.join(str(r) for r in rows)})")
        return Check(2, NAME_2_TRANSITION, NOT_ASSESSED, evidence, "; ".join(parts))
    deprecated = sum(len(c.deprecated) for c in readable)
    if deprecated:
        return Check(
            2,
            NAME_2_TRANSITION,
            ATTENTION,
            evidence,
            f"{deprecated} regel(s) alleen deprecated; dat houdt de overstap niet tegen: deprecated omzetten is een"
            " ontwerpkeuze, geen upgradevoorwaarde",
        )
    return Check(2, NAME_2_TRANSITION, NO_BLOCKER, evidence)


# ---------------------------------------------------------------------------
# 3. HA state and sync - GUARDED, kept defensive around `nsmcp.ha`
# ---------------------------------------------------------------------------

NAME_3 = "HA-stand en sync"

# GUARDED IMPORT, kept as a defensive fallback: `nsmcp.ha` is always
# present on this branch, so this import always succeeds today.
try:
    from nsmcp.ha import ha_result as _ha_result
except ImportError:
    _ha_result = None

_HA_ABSENT = (
    "de HA-bron (nsmcp.ha.ha_result) bestaat niet in deze bouw; de rolverdeling en de sync"
    " zijn daarmee niet gelezen en dus niet beoordeeld"
)

# The blockers `ha_result` names, mapped onto this vocabulary. Design 2.3:
# `blokkade` when the target is not demonstrably secondary or the sync failed,
# `aandachtspunt` on a forced state (wanted during an upgrade, but it has to
# be a deliberate choice). `config-drift` is check 4's subject and never
# decides here - two checks that judge one fact would contradict each other.
_HA_BLOCKING = {"rolverdeling", "sync en propagatie"}
_HA_ATTENTION = {"geforceerde stand"}


def _ha_word(blockers) -> tuple[str, str]:
    """The judgement of check 3, separate from the READ of check 3.

    A pure function over the `blockers` tuple `ha.HaResult` carries, so this
    mapping is measured today - with real values, not a mocked module.
    """
    names = tuple(blockers or ())
    blocking = [name for name in names if name in _HA_BLOCKING]
    if blocking:
        return BLOCKER, (
            f"de HA-stand is niet op orde: {', '.join(blocking)}; het doel is dan niet"
            " aantoonbaar secondary of de sync is mislukt"
        )
    attention = [name for name in names if name in _HA_ATTENTION]
    if attention:
        return ATTENTION, (f"{', '.join(attention)}: tijdens een upgrade gewenst, maar het moet een bewuste keuze zijn")
    return NO_BLOCKER, ""


def _check_3_ha(export) -> Check:
    if _ha_result is None:
        return Check(3, NAME_3, NOT_ASSESSED, "config/hanode", _HA_ABSENT)
    result, gaps = _ha_result(export)
    if gaps:
        return Check(
            3,
            NAME_3,
            NOT_ASSESSED,
            "config/hanode",
            f"{gaps[0].source}: {gaps[0].reason}",
        )
    # 1.0.2: the state WORD of each dimension, never the dataclass itself.
    evidence = (
        f"config/hanode, {result.node_count} node(s); rolverdeling {result.roles.state}, sync {result.sync.state}"
    )
    word, reason = _ha_word(result.blockers)
    return Check(3, NAME_3, word, evidence, reason)


# ---------------------------------------------------------------------------
# 4. Drift: running against saved
# ---------------------------------------------------------------------------

NAME_4 = "drift running tegenover saved"

# The judgement of check 4 when it rests on the CONTENT of the two config
# texts instead of on the two timestamps. Product copy, pinned in
# tests/test_product_surface.py. Never a blocker, for the same reason as the
# timestamp branch: design 2.3 calls this a human trade-off.
CHECK_4_CONTENT_DRIFT_REASON = (
    "de draaiende configuratie wijkt af van de opgeslagen configuratie; een herstart tijdens de"
    " upgrade verliest wat alleen in running staat (config_drift toont welke regels)"
)

# The same judgement when EVERY difference sits in the part the credential
# filter withholds (`Export.withheld_only_difference`): a credential changed
# and not saved. `config_drift` counts those lines and shows none of them, so
# the sentence above ("toont welke regels") would promise a line that never
# comes. Product copy, pinned in tests/test_product_surface.py.
CHECK_4_WITHHELD_DRIFT_REASON = (
    "de draaiende configuratie wijkt af van de opgeslagen configuratie in een deel dat een geheim kan"
    " dragen; een herstart tijdens de upgrade verliest die wijziging (config_drift telt deze regels"
    " maar toont ze niet)"
)

# Check 4 when the comparison is `undecided` (`config_drift.Comparison`): no
# difference found, but lines whose value the collector already withheld on
# both sides could carry the change the headers report. Not `geen blokkade`
# and not a guess either way: `niet beoordeeld`, with this in front of the
# comparison's own reason. Product copy, pinned in tests/test_product_surface.py.
CHECK_4_UNDECIDED_PREFIX = "config-drift is onbevestigd: "


def _check_4_drift(export) -> Check:
    """Running against saved, in a fixed order of sources.

    `config/nsconfig` first whenever the manifest names it: its two
    timestamps carry the judgement, and a manifest entry that cannot be read
    stays a read gap on THAT source rather than quietly becoming another
    measurement. The released collector does not collect that resource at
    all (measured on both real lab manifests), so on a real export the check
    compares the running and the saved config themselves instead - through
    `config_drift.read_comparison`, the one comparison `config_drift` and
    `ha_stand` make too, so all three print the same counts.
    """
    if export.status(CONFIG_RESOURCE) == "NIET_IN_MANIFEST":
        return _check_4_content(export)
    row, gap = export.single(CONFIG_RESOURCE)
    if gap is not None:
        return Check(4, NAME_4, NOT_ASSESSED, CONFIG_RESOURCE, gap.reason)
    if row is None:
        return Check(
            4,
            NAME_4,
            NOT_ASSESSED,
            CONFIG_RESOURCE,
            f"{CONFIG_RESOURCE} is gelezen en droeg geen object; zonder de twee tijdstempels is"
            " drift niet vast te stellen",
        )
    changed = _moment(_field(row, "lastconfigchangedtime"))
    saved = _moment(_field(row, "lastconfigsavetime"))
    evidence = f"{CONFIG_RESOURCE}: lastconfigchangedtime tegenover lastconfigsavetime"
    if changed is None or saved is None:
        unreadable = [
            name for name, value in (("lastconfigchangedtime", changed), ("lastconfigsavetime", saved)) if value is None
        ]
        return Check(
            4,
            NAME_4,
            NOT_ASSESSED,
            evidence,
            f"{' en '.join(unreadable)} ontbreekt of draagt geen leesbaar tijdstempel; de"
            " tijdstempels dragen het oordeel, dus zonder hen is er geen oordeel",
        )
    if saved >= changed:
        return Check(4, NAME_4, NO_BLOCKER, evidence)
    # Never a blocker: design 2.3 calls this a human trade-off.
    return Check(
        4,
        NAME_4,
        ATTENTION,
        evidence,
        "de configuratie is gewijzigd na de laatste keer opslaan; een herstart tijdens de"
        " upgrade verliest die wijzigingen",
    )


def _check_4_content(export) -> Check:
    """Check 4 on the content of the two config texts. Counts only - never a
    configuration line, the rule of this whole module."""
    comparison, gaps = read_comparison(export)
    if comparison is None:
        return Check(
            4,
            NAME_4,
            NOT_ASSESSED,
            f"{RUNNING_CONFIG_FILE} en {SAVED_CONFIG_FILE}",
            "; ".join(f"{gap.source}: {gap.reason}" for gap in gaps),
        )
    evidence = comparison_evidence(comparison)
    if comparison.undecided:
        return Check(4, NAME_4, NOT_ASSESSED, evidence, CHECK_4_UNDECIDED_PREFIX + undecided_reason(comparison))
    if not comparison.drift:
        return Check(4, NAME_4, NO_BLOCKER, evidence)
    if not (comparison.only_running or comparison.only_saved):
        return Check(4, NAME_4, ATTENTION, evidence, CHECK_4_WITHHELD_DRIFT_REASON)
    return Check(4, NAME_4, ATTENTION, evidence, CHECK_4_CONTENT_DRIFT_REASON)


# ---------------------------------------------------------------------------
# 5. Certificate horizon across the window - the usage read is direct
# ---------------------------------------------------------------------------

NAME_5 = "certificaathorizon over het venster heen"

# The usage reader is `expiry.usage_per_certificate` (merged on the
# release 14-9-2026); this check reads it for real. The module-level name
# stays a seam: a test sets it to None to prove the check fails CLOSED when
# the reader is unavailable, instead of judging on expiry alone.
_usage_per_certificate = usage_per_certificate

_USAGE_ABSENT = (
    "de gebruiksbron (nsmcp.expiry.usage_per_certificate) is niet beschikbaar; welke"
    " certificaten GEBONDEN zijn is daarmee niet gelezen, en de horizon van een ongebonden"
    " certificaat zegt niets over deze upgrade"
)

# The margin design 2.3 puts on top of the window: thirty days. Taken from
# `expiry.THRESHOLDS`, where NSHC's threshold ladder already lives, instead of
# writing a second 30 that can drift away from the first.
CERT_MARGIN_DAYS = THRESHOLDS["warning"]
# The buckets `expiry.bucket()` returns for a certificate inside that margin.
_WITHIN_MARGIN = {"critical", "warning"}
_EXPIRED = "expired"
_UNKNOWN_HORIZON = "unknown"
# The usage states that make a certificate's horizon matter for an upgrade:
# a BOUND certificate serves traffic, an ISSUING one signs the chain of
# one that does (`expiry.USAGE_WORDS`). `onbekend` is the state the
# reader gives a certificate whose binding sources it could NOT read - that
# is not "unbound", it is "not established", and a horizon inside the margin
# then cannot be called free (integration on the release, 14-9-2026).
_BOUND = "gebonden"
_ISSUER = "uitgever"
_USAGE_UNKNOWN = "onbekend"
_MATTERS = {_BOUND, _ISSUER}


def _certificate_word(pairs) -> tuple[str, str]:
    """The judgement of check 5, separate from the READ of check 5.

    `pairs` are `(usage state, expiry bucket)` tuples. A pure function, so
    this mapping is measured with real values, apart from the reading.

    Fail-closed on the usage side too: a certificate whose usage is
    `onbekend` (the binding sources were not readable) and whose horizon
    lies inside the margin, is expired, or has no numeric horizon at all,
    makes this check NOT ASSESSED - never `geen blokkade` on a certificate
    nobody could prove unbound. Only a certificate that is safely far from
    expiry needs no usage reading to be harmless.
    """
    bound = [horizon for state, horizon in pairs if state in _MATTERS]
    if any(horizon == _EXPIRED for horizon in bound):
        return BLOCKER, (
            "een gebonden certificaat is nu al verlopen; dat is geen horizon meer maar een"
            " storing die het onderhoudsvenster in gaat"
        )
    within = [horizon for horizon in bound if horizon in _WITHIN_MARGIN]
    if within:
        return ATTENTION, (
            f"{len(within)} gebonden certifica(a)t(en) verlop(t)(en) binnen"
            f" {CERT_MARGIN_DAYS} dagen; vervang ze voor of tijdens het venster"
        )
    unknown = [horizon for horizon in bound if horizon == _UNKNOWN_HORIZON]
    if unknown:
        return NOT_ASSESSED, (
            f"van {len(unknown)} gebonden certifica(a)t(en) is de resterende looptijd niet"
            " numeriek te lezen; de horizon is daarmee niet vast te stellen"
        )
    unresolved = [
        horizon
        for state, horizon in pairs
        if state == _USAGE_UNKNOWN and (horizon == _EXPIRED or horizon in _WITHIN_MARGIN or horizon == _UNKNOWN_HORIZON)
    ]
    if unresolved:
        return NOT_ASSESSED, (
            f"van {len(unresolved)} certifica(a)t(en) met een horizon binnen de marge (of zonder"
            " numerieke horizon) is niet vastgesteld of ze gebonden zijn: de gebruiksbron is niet"
            " gelezen, dus hun horizon telt niet als vrij"
        )
    return NO_BLOCKER, ""


def _check_5_certificates(export, cert_horizon_days: int = CERT_MARGIN_DAYS, *, today: date | None = None) -> Check:
    """`cert_horizon_days` is the BINDING INTERFACE DECISION between this
    module and `upgrade_plan.py`: `preflight_checks` itself
    carries no window, so its default reproduces today's behaviour exactly -
    a horizon of `CERT_MARGIN_DAYS` (30) from the moment of the read, and the
    evidence below says the window is unknown. `upgrade_plan.py` DOES know the planned
    window (the soak, in whole days) and passes
    `CERT_MARGIN_DAYS + venster_dagen` in - the ADDITION stays owned here,
    never duplicated in `upgrade_plan.py` (one rule, one owner). Any caller
    that supplies a horizon other than the default is, by construction, one
    that knows the window, so the evidence sentence below only has to test
    for that - not carry a second flag for it.

    The widened (non-default) sentence used to name the wider
    horizon without saying that the JUDGEMENT below it - `_certificate_word`,
    over `bucket()`'s fixed 14/30/60/90 ladder - still classifies against the
    unwidened `CERT_MARGIN_DAYS` (that ladder belongs to `expiry.py` to make
    horizon-aware, and stays untouched here). Left as it was, a certificate
    expiring on day 31 could read "horizon 31 dagen" as evidence next to
    "geen blokkade" as the word - a contradiction the widened sentence
    introduced. The sentence now says explicitly which horizon today's
    judgement actually uses.
    """
    if cert_horizon_days == CERT_MARGIN_DAYS:
        evidence = (
            f"config/sslcertkey: daystoexpiration, horizon {cert_horizon_days} dagen vanaf nu; het"
            " GEPLANDE venster is deze leestool niet bekend, dus de marge loopt vanaf het moment"
            " van dit antwoord"
        )
    else:
        evidence = (
            f"config/sslcertkey: daystoexpiration, horizon {cert_horizon_days} dagen vanaf nu"
            f" ({CERT_MARGIN_DAYS} dagen marge plus het opgegeven onderhoudsvenster); het"
            " GEPLANDE venster is nu wel bekend, meegegeven door de aanroeper - het oordeel"
            f" hieronder toetst vandaag nog tegen de vaste marge van {CERT_MARGIN_DAYS} dagen,"
            " niet tegen dit venster"
        )
    # 1.0.2: `daystoexpiration` counts from the SCAN. "Vanaf nu" is
    # only true once the age of the export is taken off - the same age as
    # the data line under the answer (`expiry.age_of`).
    age_days, age_reason = age_of(export, today)
    if age_days is not None:
        evidence = f"{evidence}; {counted_from_today(age_days)}"
    if _usage_per_certificate is None:
        return Check(5, NAME_5, NOT_ASSESSED, evidence, _USAGE_ABSENT)
    usage = {u.certkey: u.state for u in _usage_per_certificate(export)}
    certs, gap = export.objects("config/sslcertkey")
    if gap is not None:
        return Check(5, NAME_5, NOT_ASSESSED, evidence, gap.reason)
    if age_days is None and certs:
        return Check(
            5,
            NAME_5,
            NOT_ASSESSED,
            evidence,
            f"de leeftijd van de export is niet vast te stellen ({age_reason}); daystoexpiration telt vanaf"
            " de scan, dus hoeveel dagen er vanaf nu resten is niet vast te stellen",
        )
    pairs = [
        (
            usage.get(str(row.get("certkey") or row.get("name") or ""), "onbekend"),
            bucket_from_today(row.get("daystoexpiration"), age_days),
        )
        for row in certs
    ]
    word, reason = _certificate_word(pairs)
    return Check(5, NAME_5, word, evidence, reason)


# ---------------------------------------------------------------------------
# 6. Build and branch against the target build
# ---------------------------------------------------------------------------

NAME_6 = "build en tak tegenover de doelbuild"


def _target_build(branch: str, knowledge) -> tuple[tuple[int, int], str, str] | None:
    """(build, tekst, herkomst) of the build this upgrade is heading for.

    The OFFERED build first - that is what the vendor actually hands out - and
    the floor from the bulletins behind it, because a floor without an offered
    build is still a target worth planning towards. The branch is the one
    parsed OUT OF THE EXPORT and used as a lookup key: the keys of
    `offered_builds` are printable but never shape-checked, so this
    module never iterates over them and never prints one.
    """
    offered_map = knowledge.offered_builds if isinstance(knowledge.offered_builds, dict) else {}
    offered = offered_map.get(branch)
    pair = as_pair(offered)
    if pair is not None:
        return (
            pair,
            f"{branch}-{offered}",
            (f"aangeboden build, bron {knowledge.offered_source!r} van {day(knowledge.offered_date)}"),
        )
    floor = floor_for(branch, knowledge)
    floor_pair = as_pair(floor[0]) if floor is not None else None
    if floor_pair is not None:
        return floor_pair, f"{branch}-{floor[0]}", (f"vloer uit bulletin {public_bulletin_id(floor[1])}")
    return None


def _check_6_build(export, knowledge) -> Check:
    row, gap = export.single(VERSION_RESOURCE)
    if gap is not None:
        return Check(6, NAME_6, NOT_ASSESSED, VERSION_RESOURCE, gap.reason)
    version_text = _field(row, "version") if row is not None else _NO_FIELD
    parsed = parse_build(version_text if version_text is not _NO_FIELD else "")
    if parsed is None:
        return Check(
            6,
            NAME_6,
            NOT_ASSESSED,
            VERSION_RESOURCE,
            "de versietekst draagt geen herkenbare buildvorm; er is geen build om tegen een doelbuild af te zetten",
        )
    branch, pair = parsed
    if branch != TARGET_BRANCH:
        return Check(
            6,
            NAME_6,
            BLOCKER,
            f"{VERSION_RESOURCE}: tak {branch}",
            f"deze appliance staat op tak {branch}; het besluit is dat een upgrade uitsluitend"
            f" BINNEN tak {TARGET_BRANCH} gebeurt",
        )
    # WHICH TRAIN, asked of the ONE owner of that rule. A second, narrower
    # copy here would let this check judge against another train's builds than
    # `status_cve_controle` and `status_update_advies` use on the same export.
    platform, platform_evidence, _platform_gap = fips_platform(export, version_text, branch)
    if platform == PLATFORM_UNKNOWN:
        return Check(
            6,
            NAME_6,
            NOT_ASSESSED,
            f"{VERSION_RESOURCE}; {platform_evidence}",
            "welke tak geldt (gewoon of FIPS/NDcPP) staat niet vast, en de doelbuild verschilt per tak",
        )
    rule_branch = f"{branch}{FIPS_SUFFIX}" if platform == PLATFORM_FIPS else branch
    unpinned = getattr(knowledge, "unpinned_reason", "")
    if unpinned:
        # The target build is the offered build or the floor, both out of a
        # package the configuration does not pin - no target to judge by.
        return Check(6, NAME_6, NOT_ASSESSED, f"{VERSION_RESOURCE}: tak {rule_branch}", unpinned)
    target = _target_build(rule_branch, knowledge)
    if target is None:
        return Check(
            6,
            NAME_6,
            NOT_ASSESSED,
            f"{VERSION_RESOURCE}: tak {rule_branch}",
            f"het kennispakket noemt voor tak {rule_branch} geen aangeboden build en geen"
            " vloer; er is dan geen doelbuild om tegen af te zetten",
        )
    target_pair, target_text, origin = target
    evidence = (
        f"{VERSION_RESOURCE}: tak {rule_branch}, build {branch}-{pair[0]}.{pair[1]} tegenover"
        f" doelbuild {target_text} ({origin})"
    )
    if target_pair > pair:
        return Check(6, NAME_6, NO_BLOCKER, evidence)
    if target_pair < pair:
        return Check(
            6,
            NAME_6,
            BLOCKER,
            evidence,
            "de doelbuild ligt LAGER dan de build die er nu op staat; dat is geen upgrade",
        )
    return Check(
        6,
        NAME_6,
        NOT_ASSESSED,
        evidence,
        "de doelbuild is gelijk aan de build die er nu op staat; er is dan geen upgrade om op"
        " vast te lopen, en ook geen hogere doelbuild om tegen af te zetten",
    )


# ---------------------------------------------------------------------------
# 7. Form factor
# ---------------------------------------------------------------------------

NAME_7 = "vormfactor"

# Positive shape tests on `hwdescription`, in this order. The VALUE is never
# repeated - `hwdescription` is free text out of the export and the disclosure
# seam does not collect it as a name - only this product's own word for what
# matched. "SDX" first: an SDX description may well also carry "MPX".
_FORM_FACTORS = (
    ("SDX", ("sdx",)),
    ("MPX", ("mpx",)),
    ("VPX", ("vpx", "virtual appliance")),
)
# The SVM layer of an SDX falls outside this product (design 2.8), and a VPX
# instance ON an SDX describes itself as a VPX. Said out loud instead of
# implied, so nobody reads "VPX" here as "definitely not on an SDX".
_SDX_BOUNDARY = (
    "een VPX-instantie op een SDX is vanaf de instantie zelf niet van een gewone VPX te"
    " onderscheiden; de SVM-laag valt buiten dit product"
)


def _check_7_form_factor(export) -> Check:
    row, gap = export.single(HARDWARE_RESOURCE)
    if gap is not None:
        return Check(7, NAME_7, NOT_ASSESSED, HARDWARE_RESOURCE, gap.reason)
    description = _text(_field(row, "hwdescription")) if row is not None else None
    version_row, _version_gap = export.single(VERSION_RESOURCE)
    version_text = _field(version_row, "version") if version_row is not None else _NO_FIELD
    # THE ONE owner of the FIPS question in this product. Check 7 asks it
    # rather than writing a second, narrower copy: a measured contradiction
    # between two tools on one export is exactly what that fix removed.
    branch = ""
    parsed = parse_build(version_text if version_text is not _NO_FIELD else "")
    if parsed is not None:
        branch = parsed[0]
    platform, platform_evidence, _gap = fips_platform(
        export, version_text if version_text is not _NO_FIELD else "", branch
    )
    factor = None
    if description is not None:
        lowered = description.lower()
        for name, needles in _FORM_FACTORS:
            if any(needle in lowered for needle in needles):
                factor = name
                break
    evidence = (
        f"{HARDWARE_RESOURCE}: hwdescription leest als"
        f" {factor if factor else 'geen bekende vormfactor'}; {platform_evidence}"
    )
    if platform == PLATFORM_FIPS:
        return Check(
            7,
            NAME_7,
            ATTENTION,
            evidence,
            "een FIPS/NDcPP-appliance heeft een eigen upgradeprocedure, en die tak is in deze"
            " versie alleen op fixtures beproefd",
        )
    if factor is None:
        return Check(
            7,
            NAME_7,
            NOT_ASSESSED,
            evidence,
            f"{HARDWARE_RESOURCE} draagt geen hwdescription waarin een bekende vormfactor"
            f" ({', '.join(name for name, _ in _FORM_FACTORS)}) te herkennen is",
        )
    if platform == PLATFORM_UNKNOWN:
        return Check(
            7,
            NAME_7,
            NOT_ASSESSED,
            evidence,
            "of dit een FIPS/NDcPP-appliance is, staat niet vast; zonder dat is de vormfactor niet beoordeeld",
        )
    if factor == "SDX":
        return Check(
            7,
            NAME_7,
            ATTENTION,
            evidence,
            "op een SDX loopt de upgrade ook over de SVM-laag, en die valt buiten dit product",
        )
    return Check(7, NAME_7, NO_BLOCKER, f"{evidence}; {_SDX_BOUNDARY}")


# ---------------------------------------------------------------------------
# 8. Free space on /var - the LIVE read
# ---------------------------------------------------------------------------

NAME_8 = "vrije ruimte op /var"


def own_floor_mb(bundle_mb: int) -> int:
    """The floor THIS product adds on top of the vendor's own: the bundle
    itself plus its unpacked size, both at `bundle_mb`.

    PUBLIC because `upgrade_plan.py` (B7) needs this exact number for a
    build it never reads live, and used to carry a second, independent copy
    of this FORMULA: the numbers
    (`VENDOR_FLOOR_MB`, `ASSUMED_BUNDLE_MB`) were imported, the arithmetic
    was retyped - so the two modules could state different `/var` floors the
    moment a real bundle size ever made the retyped copy diverge from this
    one. One rule, one owner: B7 imports and calls this instead.
    """
    return VENDOR_FLOOR_MB + bundle_mb + bundle_mb


def free_space_from_script(exit_code, stdout) -> tuple[int | None, str]:
    """The free space on `/var` out of the read script's output, or `None`
    with the reason.

    Strict on purpose, because the number decides a check: exit code 0 AND
    exactly one line that is `[VRIJ_MB] <whole number>` and nothing else. A
    decimal, a sign, a unit, a second value line, leading whitespace: all no
    number. The text is split on `\\n` alone - `str.splitlines()` would also
    split on a carriage return INSIDE a line and could turn appliance text
    after one into a line of its own.

    The reason of a failed read quotes the script's own first `[FOUT]` line,
    reduced to printable ASCII and bounded. Masking the target's known values
    out of it is the caller's job (it knows the target)."""
    lines = [line.rstrip("\r") for line in str(stdout or "").split("\n")]
    if type(exit_code) is not int or exit_code != 0:
        fout = next((line for line in lines if line.startswith(_SCRIPT_ERROR_PREFIX)), "")
        detail = _UNPRINTABLE.sub("?", fout[len(_SCRIPT_ERROR_PREFIX) :].strip())
        if len(detail) > _SCRIPT_REASON_LIMIT:
            detail = detail[:_SCRIPT_REASON_LIMIT] + "...(afgekapt)"
        return None, (
            f"het meetscript stopte met exitcode {exit_code!r}"
            + (f": {detail}" if detail else "; het meldde geen fout")
        )
    matches = [_FREE_MB_LINE.fullmatch(line) for line in lines if line.startswith("[VRIJ_MB]")]
    if len(matches) != 1 or matches[0] is None:
        return None, (
            "het meetscript gaf niet precies een regel [VRIJ_MB] met een geheel getal; de vrije ruimte is niet vast"
            " te stellen"
        )
    return int(matches[0].group("mb")), ""


def _check_8_free_space(
    free_var_mb, bundle_mb, route: str | None = FREE_SPACE_ROUTE_COLLECTOR, gap_reason: str = ""
) -> Check:
    """Check 8 on the value the caller read live, or did not.

    1.0.2: the evidence says what really happened. `route` is None when
    no read ran at all (no target, no collect script, more than one target
    without a name): then "niet gelezen: <reden>" and no route. A read that
    ran without a usable value names its route and "geen bruikbare waarde";
    only a measurement says "gemeten"."""
    bundle = bundle_mb if bundle_mb else ASSUMED_BUNDLE_MB
    aanname = "" if bundle_mb else f" (aangenomen bundelgrootte {ASSUMED_BUNDLE_MB} MB)"
    eigen_vloer = own_floor_mb(bundle)
    vloer = (
        f"vendorvloer {VENDOR_FLOOR_MB} MB + bundel {bundle} MB + uitpakkosten {bundle} MB = {eigen_vloer} MB{aanname}"
    )
    if route is None:
        reden = gap_reason or "er is geen live lezing gedaan"
        return Check(
            8,
            NAME_8,
            NOT_ASSESSED,
            f"niet gelezen: {reden}; {vloer}",
            f"geen lezing gedaan: {reden}",
        )
    if free_var_mb is None:
        return Check(
            8,
            NAME_8,
            NOT_ASSESSED,
            f"live gelezen via {route}, geen bruikbare waarde; {vloer}",
            f"de live lezing via {route} leverde geen bruikbare waarde" + (f": {gap_reason}" if gap_reason else ""),
        )
    bewijs = f"live gelezen via {route}; {vloer}"
    if free_var_mb < VENDOR_FLOOR_MB:
        return Check(
            8, NAME_8, BLOCKER, f"{bewijs}; gemeten {free_var_mb} MB", f"onder de vendorvloer van {VENDOR_FLOOR_MB} MB"
        )
    if free_var_mb < eigen_vloer:
        return Check(
            8,
            NAME_8,
            ATTENTION,
            f"{bewijs}; gemeten {free_var_mb} MB",
            f"tussen de vendorvloer en {eigen_vloer} MB; er moet ruimte vrijgemaakt worden",
        )
    return Check(8, NAME_8, NO_BLOCKER, f"{bewijs}; gemeten {free_var_mb} MB")


# ---------------------------------------------------------------------------
# 9. Backup and previous build tree - the rollback path
# ---------------------------------------------------------------------------

NAME_9 = "backup en vorige buildboom"

# What a build tree under /var/nsinstall is called. A positive test, so a log
# file or an unpacked kernel that happens to live there is not counted as a
# rollback point.
_BUILD_TREE_PREFIX = "build-"
# Measured on the appliance (lab-02, 8-9-2026): installns lays a build tree out NESTED as
# `/var/nsinstall/<tak>/build_<build>` (underscore), e.g. `/var/nsinstall/14.1/build_66.59`,
# and the runner itself uploads to that same nested path. The flat `build-...` form under
# `/var/nsinstall` is what a manually unpacked bundle directory looks like. Both are a build
# tree; a gate that only knew the flat form said `dicht` on every real box.
_BUILD_TREE_PREFIXES = ("build-", "build_")
_BRANCH_DIR = re.compile(r"^[0-9]+\.[0-9]+$")


def build_tree_entries(rows) -> list[tuple[str, dict]]:
    """The build trees among `config/systemfile` rows: `(path, row)` per tree, in row
    order. A tree is a `build-`/`build_` entry directly under `/var/nsinstall` (flat) or
    under one branch directory `/var/nsinstall/<tak>` (nested, the measured layout).
    Rows without a readable `filelocation`/`filename` are skipped here; callers that
    must count them as unreadable do so themselves. The ONE definition shared by
    preflight check 9, R0's build-tree gate and the rollback-point evidence."""
    found = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        location = row.get("filelocation")
        name = row.get("filename")
        if not isinstance(location, str) or not isinstance(name, str):
            continue
        # Recognize only documented directory shapes, never a filename prefix.
        # Missing type is unknown evidence and cannot count as a directory.
        modes = row.get("filemode")
        if isinstance(modes, str):
            modes = [modes]
        if modes != ["DIRECTORY"]:
            continue
        if location != location.strip() or name != name.strip():
            continue
        location = location.removesuffix("/")
        flat = re.fullmatch(r"build-[0-9]+\.[0-9]+-[0-9]+\.[0-9]+(?:_nc_64)?", name)
        nested = re.fullmatch(r"build_[0-9]+\.[0-9]+", name)
        if (location == BUILD_TREE_LOCATION and flat is None) or (location != BUILD_TREE_LOCATION and nested is None):
            continue
        if location == BUILD_TREE_LOCATION:
            found.append((f"{location}/{name}", row))
        elif location.startswith(BUILD_TREE_LOCATION + "/") and _BRANCH_DIR.fullmatch(
            location[len(BUILD_TREE_LOCATION) + 1 :]
        ):
            found.append((f"{location}/{name}", row))
    return found


def _check_9_rollback(export) -> Check:
    backups, backup_gap = export.objects(BACKUP_RESOURCE)
    files, file_gap = export.objects(BUILD_TREE_RESOURCE)
    evidence = (
        f"{BACKUP_RESOURCE} voor de backup, {BUILD_TREE_RESOURCE} voor een boom onder"
        f" {BUILD_TREE_LOCATION}, {CONFIG_RESOURCE} voor het moment van de laatste wijziging"
    )
    unreadable = [
        f"{source}: {failed.reason}"
        for source, failed in ((BACKUP_RESOURCE, backup_gap), (BUILD_TREE_RESOURCE, file_gap))
        if failed is not None
    ]
    if unreadable:
        return Check(
            9,
            NAME_9,
            NOT_ASSESSED,
            evidence,
            "; ".join(unreadable) + "; zonder beide bronnen is het terugrolpad niet vast te stellen",
        )

    config_row, config_gap = export.single(CONFIG_RESOURCE)
    changed = _moment(_field(config_row, "lastconfigchangedtime")) if config_row else None
    if backups and changed is None:
        return Check(
            9,
            NAME_9,
            NOT_ASSESSED,
            evidence,
            f"er is wel een backup, maar {CONFIG_RESOURCE} levert geen leesbaar"
            " lastconfigchangedtime"
            + (f" ({config_gap.reason})" if config_gap is not None else "")
            + "; of de backup JONGER is dan de laatste wijziging is dan niet vast te stellen",
        )

    # A backup whose `creationtime` cannot be read (absent, empty, or not the
    # appliance's own time shape) is neither fresh nor stale - it is a read
    # gap on the ONE field this half of the check judges on. Folding it into
    # "not fresh" was measured to produce a `blokkade [vastgesteld]` about a
    # backup that genuinely exists, on a field nobody read: the same false
    # verdict checks 1 and 4 both refuse, in a list instead of a single row.
    fresh = []
    unreadable_backups = []
    for row in backups:
        moment = _moment(_field(row, "creationtime"))
        if moment is None:
            unreadable_backups.append(row)
        elif moment >= changed:
            fresh.append(row)

    # Same rule, the build-tree half: a `config/systemfile` row whose
    # `filelocation` or `filename` cannot be read as text is neither
    # confirmed to be the build tree nor confirmed not to be it.
    tree = [row for _, row in build_tree_entries(files)]
    unreadable_tree_rows = []
    for row in files:
        location = _text(_field(row, "filelocation"))
        name = _text(_field(row, "filename"))
        if location is None or name is None:
            unreadable_tree_rows.append(row)

    counted = (
        f"{evidence}; {len(fresh)} van {len(backups)} backup(s) jonger dan de laatste"
        f" wijziging, {len(tree)} buildbo(o)m(en) onder {BUILD_TREE_LOCATION}"
    )
    if fresh and tree:
        return Check(9, NAME_9, NO_BLOCKER, counted)

    # A NEGATIVE claim ("geen fris(e) backup"/"geen buildboom") may not rest
    # on a row this product could not read - that is the categorical claim
    # about an unread field that was measured. Only when the
    # unreadable half is the one keeping the answer from a clean NO_BLOCKER
    # does it matter; a stale-but-readable backup or an unrelated file is an
    # established absence and stays exactly that.
    fresh_unknown = not fresh and unreadable_backups
    tree_unknown = not tree and unreadable_tree_rows
    if fresh_unknown or tree_unknown:
        parts = []
        if fresh_unknown:
            parts.append(f"{len(unreadable_backups)} backup(s) dragen geen leesbaar creationtime")
        if tree_unknown:
            parts.append(
                f"{len(unreadable_tree_rows)} object(en) onder {BUILD_TREE_RESOURCE} dragen"
                " geen leesbare filelocation of filename"
            )
        return Check(
            9,
            NAME_9,
            NOT_ASSESSED,
            counted,
            "; ".join(parts) + "; zonder deze velden is niet vast te stellen of er een terugrolpad is",
        )

    if fresh or tree:
        missing = "een buildboom" if fresh else "een backup jonger dan de laatste wijziging"
        return Check(
            9,
            NAME_9,
            ATTENTION,
            counted,
            f"er ontbreekt {missing}; het terugrolpad rust dan op een halve voorziening",
        )
    return Check(
        9,
        NAME_9,
        BLOCKER,
        counted,
        "er is geen backup jonger dan de laatste wijziging en geen buildboom onder"
        f" {BUILD_TREE_LOCATION}; er bestaat dan geen terugrolpad",
    )


# ---------------------------------------------------------------------------
# The nine together, and the answer
# ---------------------------------------------------------------------------


def preflight_checks(
    export,
    knowledge,
    free_var_mb,
    bundle_mb,
    *,
    cert_horizon_days: int = CERT_MARGIN_DAYS,
    free_space_route: str | None = FREE_SPACE_ROUTE_COLLECTOR,
    free_space_gap_reason: str = "",
    today: date | None = None,
) -> tuple[Check, ...]:
    """`cert_horizon_days` is keyword-only and defaults to `CERT_MARGIN_DAYS`,
    so every existing caller (B3/`status_update_preflight`, and every test in
    `tests/test_preflight.py`) keeps today's behaviour unchanged. See
    `_check_5_certificates` for the full reasoning - this is the one seam
    B7 (`upgrade_plan.py`) uses to hand in the planned window.

    `free_space_route` names how check 8 was read live
    (`FREE_SPACE_ROUTE_SSH` or `FREE_SPACE_ROUTE_COLLECTOR`); the server
    that chose the route passes it, so the evidence line says which one.
    """
    return (
        _check_1_license(export),
        _check_2_classic_markers(export),
        _check_3_ha(export),
        _check_4_drift(export),
        _check_5_certificates(export, cert_horizon_days, today=today),
        _check_6_build(export, knowledge),
        _check_7_form_factor(export),
        _check_8_free_space(free_var_mb, bundle_mb, free_space_route, free_space_gap_reason),
        _check_9_rollback(export),
    )


def _heading_finding(checks) -> Finding | None:
    """The conclusive heading, and ONLY when all nine say so.

    A separate function because that is the one rule of this tool a reader
    will want to check without reading the whole answer builder - and because
    the conditional test on it would otherwise never take its positive leg on
    a branch where three of the nine have no source.
    """
    if not all(c.word == NO_BLOCKER for c in checks):
        return None
    return Finding(
        subject="kop",
        outcome=CONCLUSIVE_HEADING,
        certainty=Certainty.ESTABLISHED,
        evidence="alle negen toetsen",
        subject_is_name=False,
    )


def preflight_answer(
    export, knowledge, free_var_mb, bundle_mb, gap, *, free_space_route: str | None = FREE_SPACE_ROUTE_COLLECTOR
) -> Answer:
    checks = preflight_checks(
        export,
        knowledge,
        free_var_mb,
        bundle_mb,
        free_space_route=free_space_route,
        free_space_gap_reason=gap.reason if gap is not None else "",
    )
    findings = [
        Finding(
            subject=f"{c.number}. {c.name}",
            outcome=c.word,
            certainty=Certainty.ESTABLISHED if c.word != NOT_ASSESSED else Certainty.NOT_ESTABLISHED,
            evidence=c.evidence,
            reason=c.reason,
            subject_is_name=False,
        )
        for c in checks
    ]
    heading = _heading_finding(checks)
    if heading is not None:
        findings.insert(0, heading)
    return Answer(
        question="loopt de upgrade ergens op vast",
        findings=findings,
        read_gaps=[gap] if gap is not None else [],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
