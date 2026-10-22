"""The knowledge package: which CVE base, cipher baseline and expiry rules apply here.

Why age is a first-class concept here: an outdated knowledge base is itself a
false-green mechanism. A tool that says "no known vulnerabilities" with
knowledge four months old does not lie, but it does mislead. That is why every
answer carries the age, and a missing package is a visible fact instead of an
empty default.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

from nsmcp.limits import (
    MAX_FILE_BYTES,
    MAX_JSON_DEPTH,
    PackageShapeDefeatsCap,
    capped_text,
    exceeds_depth,
    shrink_to_package_cap,
)

PREDICATES = frozenset(
    {
        "altijd",
        "heeft_gateway_vserver",
        "heeft_aaa_vserver",
        "heeft_saml_action",
        "is_saml_idp",
        "heeft_lsn_sip_alg",
        # The conditions CTX696604 and CTX696939 really state, rather
        # than the nearest single object this product happened to be able to
        # find. A bulletin that says "Gateway (SSL VPN, ICA Proxy, CVPN, RDP
        # Proxy) OR AAA virtual server" is not answered by either half alone.
        "heeft_gateway_of_aaa_vserver",
        "heeft_gateway_of_aaa_met_saml_action",
        # 1.0.2: "SAML SP or IdP" (CTX697174, CTX697191).
        "heeft_saml_action_of_idp",
        "heeft_http2_profiel",
        "heeft_tcp_timestamp_profiel",
        "heeft_lb_oracle_of_dns",
    }
)
_TOP_FIELDS = {"versie", "datum", "toelichting", "bron", "cve", "uitleg", "begrippen", "aangeboden"}
_OFFERED_FIELDS = {"datum", "bron", "builds"}
_BULLETIN_FIELDS = {"bulletin", "datum", "getroffen", "fix", "cves", "advies", "extraStapNaUpgrade"}
_CVE_FIELDS = {"id", "cvss", "kern", "voorwaarde"}
# 1.0.3: optional per CVE. `true` says firmware alone does not complete the
# vendor remedy for this CVE: the bulletin also asks a configuration step
# after the upgrade (the bulletin's `extraStapNaUpgrade` names it). Per CVE
# and not per bulletin on purpose: CTX697096 carries eight CVEs and only one
# of them needs such a step. Absent means false, so an older package loads
# and behaves unchanged; a value that is not a JSON boolean is refused.
POST_UPGRADE_CONFIG_FIELD = "naconfiguratieVerplicht"

# The three fields of a BUILD-DEPENDENT condition, and nothing else.
# CTX696939 states CVE-2026-19490 differently per build: from 14.1-43.56 and
# 13.1-61.28 the Gateway/AAA virtual server only counts WITH a SAML action,
# below those builds it counts without one. Leaving that to the reader would
# be exactly the reasoning this product exists to replace with a computation.
_CHOICE_FIELDS = {"vanaf", "predicaat", "anders"}

# What a `vanaf` entry must look like per branch: the SAME shape as a
# fix-build ("X.Y"), because it is compared against the same parsed build.
# Deliberately not the "< X.Y" shape of `getroffen`: this is a threshold the
# build is compared to, not a range it falls in, and accepting both forms
# would make one field mean two things.
_BUILD_FORM = re.compile(r"\d+\.\d+")

# What an affected range must look like per branch: "< X.Y", every build
# below X.Y. THE one owner of that shape - cve.py parses the range with this
# same pattern, so the loader and the verdict can never disagree about what
# a range says.
AFFECTED_FORM = re.compile(r"<\s*(\d+)\.(\d+)")

# What a customer answer says when the package does not carry the field.
# Product copy (design 2.3, B1), pinned byte for byte in
# tests/test_knowledge.py::test_the_absent_wording_is_pinned.
OFFERED_ABSENT = "aangeboden build niet vastgelegd"


def _condition_problem(condition) -> str:
    """The reason this `voorwaarde` is unusable, or "" when it is fine.

    Strict on purpose, and at LOAD time: a condition that cannot be judged
    produces a verdict for a CVE, and a wrong verdict about a CVE is worse
    than no knowledge package at all. cve.py keeps its own runtime net for a
    Knowledge that never came through here.
    """
    if isinstance(condition, str):
        if condition not in PREDICATES:
            return f"onbekend predicaat {condition!r}; toegestaan: {', '.join(sorted(PREDICATES))}"
        return ""
    if not isinstance(condition, dict):
        return (
            f"'voorwaarde' moet tekst zijn of een object met {', '.join(sorted(_CHOICE_FIELDS))};"
            f" gevonden: {type(condition).__name__}"
        )
    if condition.keys() != _CHOICE_FIELDS:
        # HARDENING, same class as _offered_problem() below: `condition`'s
        # keys are attacker-supplied, so the joined list is wrapped in !r
        # rather than pasted raw - otherwise a key such as
        # "topgek\n- kennispakket: in orde [vastgesteld]" would forge a
        # second, indistinguishable line into this refusal reason.
        found = ", ".join(sorted(condition)) or "(geen)"
        return (
            "'voorwaarde' als object draagt precies de sleutels"
            f" {', '.join(sorted(_CHOICE_FIELDS))}; gevonden: {found!r}"
        )
    since = condition["vanaf"]
    if not isinstance(since, dict) or not since:
        return "'vanaf' moet een niet-leeg object van tak naar buildnummer zijn"
    for branch, build in since.items():
        if not isinstance(build, str) or not _BUILD_FORM.fullmatch(build.strip()):
            # HARDENING, same class: `branch` is an attacker-supplied dict
            # key too, and unlike the analogous message in
            # _offered_problem() there is no prior .isprintable() check on it
            # here - so it is wrapped in !r, same as `build!r` right next to
            # it, rather than pasted raw.
            return f"'vanaf' draagt voor tak {branch!r} geen buildnummer van de vorm X.Y: {build!r}"
    for key in ("predicaat", "anders"):
        if condition[key] not in PREDICATES:
            return f"onbekend predicaat {condition[key]!r} in '{key}'; toegestaan: {', '.join(sorted(PREDICATES))}"
    return ""


# The fixed kinds a `truncated_fields` entry can be -
# never the untrusted glossary/explanation KEY or the bulletin/CVE INDEX that
# comes with it. `_field_kind` reads only the part of the path this module
# built itself; the part after it (a caller-controlled string, or a bare
# integer) is dropped. Order matches the fixed cut order (design 3.6 unit 3).
_FIELD_KINDS = ("begrippen", "advies", "extraStapNaUpgrade", "kern", "uitleg")


def _field_kind(name: str) -> str:
    """The KIND behind one `truncated_fields` entry - always one of
    `_FIELD_KINDS`.

    `name` is one of the paths this module builds itself, never a raw
    package value: `"begrippen.<key>"`, `"uitleg.<key>"`, or a
    `"cve[<i>]..."` path ending in `.advies`, `.extraStapNaUpgrade` or
    `.cves[<j>].kern`. The glossary/explanation key and the bulletin/CVE
    index are exactly the untrusted or positional parts this function throws
    away - only the fixed suffix survives, which is what makes the result
    safe to put in front of an operator.
    """
    if name.startswith("begrippen."):
        return "begrippen"
    if name.startswith("uitleg."):
        return "uitleg"
    if name.endswith(".advies"):
        return "advies"
    if name.endswith(".extraStapNaUpgrade"):
        return "extraStapNaUpgrade"
    return "kern"


def _offered_problem(block) -> str:
    """The reason this `aangeboden` block is unusable, or "" when it is fine.

    Strict, and at LOAD time, for the same reason as `_condition_problem`
    above it: this field steers a verdict (B2 says whether the appliance is
    on the build the vendor offers), and a verdict on an unreadable field is
    worse than no knowledge package at all. ABSENT is a different thing and
    is allowed: then there simply is no offered build, and B2 says so with
    OFFERED_ABSENT.

    Untrusted input, so two of the checks below are about the ANSWER rather
    than about the shape. `bron` and the branch NAMES leave here verbatim
    into a B2/B7 answer, and answer.py renders one finding per line
    ("- onderwerp: uitkomst [vastgesteld]"): a line break inside either
    string is enough to forge a whole finding - the same attack already
    measured elsewhere in this product as a forged [vastgesteld] line
    through a newline in a status. Both must therefore be printable. For the
    same reason, the shape/key-set messages below do not quote a rejected
    key set back raw either: the joined key list is wrapped in `!r`, which
    escapes any line break or control character a key name might carry (a
    refusal reason is an answer line too). The one exception is the
    build-form message further down, which interpolates `{branch}` directly,
    unescaped - that stays safe ONLY because the `.isprintable()` check on
    `branch` already ran and refused before that message can be built. That
    ordering - printability check BEFORE the message that interpolates the
    branch - is load-bearing; do not move the build-form check above it.
    """
    if not isinstance(block, dict):
        return f"'aangeboden' moet een object zijn; gevonden: {type(block).__name__}"
    if block.keys() != _OFFERED_FIELDS:
        found = ", ".join(sorted(block.keys())) or "(geen)"
        return f"'aangeboden' draagt precies de sleutels {', '.join(sorted(_OFFERED_FIELDS))}; gevonden: {found!r}"
    if not isinstance(block["bron"], str) or not block["bron"].strip():
        return "'aangeboden.bron' moet een niet-lege tekst zijn"
    if not block["bron"].isprintable():
        return "'aangeboden.bron' draagt een regeleinde of een stuurteken"
    if not isinstance(block["builds"], dict) or not block["builds"]:
        return "'aangeboden.builds' moet een niet-leeg object van tak naar build zijn"
    for branch, build in block["builds"].items():
        if not isinstance(branch, str) or not branch.strip():
            return "'aangeboden.builds' draagt een takkenaam die geen tekst is"
        if not branch.isprintable():
            return "'aangeboden.builds' draagt een takkenaam met een regeleinde of een stuurteken"
        # LOAD-BEARING ORDER: this message pastes `branch` in raw, unescaped.
        # That is safe only because the `.isprintable()` check above already
        # ran and refused any branch that could forge a line break or
        # control character. Do not reorder these two checks.
        if not isinstance(build, str) or not _BUILD_FORM.fullmatch(build):
            return f"'aangeboden.builds' draagt voor tak {branch} geen build in de vorm X.Y; gevonden: {build!r}"
    try:
        date.fromisoformat(str(block["datum"]))
    except (TypeError, ValueError):
        return f"'aangeboden.datum' is onbruikbaar: {block['datum']!r}"
    return ""


def _rule_problem(affected, fixed) -> str:
    """The reason one branch's rule contradicts itself, or "" when it is fine.

    `getroffen` and `fix` are two halves of ONE rule: "every build below X.Y
    is hit" and "fixed from build Z.W". A fix-build BELOW the affected bound
    says a build is hit and fixed at the same time - and the verdict and the
    floor both read the fix-build, so such a package lowers both while
    calling the result established (measured: a fix-build of 66.00 next to
    "< 73.37" turned 6 hit / 3 not hit into 0 / 9, and the floor from 73.37
    into 66.00). A fix-build AT or ABOVE the bound is a rule the verdict can
    only err on the careful side of, so it stays valid.

    A rule this loader cannot compare is refused too, not waved through to
    the runtime: cve.py would call such a bulletin unreadable, but the floor
    reads the fix-build ALONE - so an unreadable range next to a low fix-build
    would still become the floor.
    """
    if not isinstance(affected, str) or not isinstance(fixed, str):
        return "een getroffen reeks of fix-build die geen tekst is"
    bound = AFFECTED_FORM.fullmatch(affected.strip())
    if bound is None:
        return "een getroffen reeks die niet de vorm '< X.Y' heeft"
    if _BUILD_FORM.fullmatch(fixed.strip()) is None:
        return "een fix-build die niet de vorm 'X.Y' heeft"
    major, minor = fixed.strip().split(".")
    if (int(major), int(minor)) < (int(bound.group(1)), int(bound.group(2))):
        return "een fix-build onder de getroffen reeks; een build zou dan tegelijk geraakt en verholpen heten"
    return ""


def _identity(value) -> str:
    """The comparable identity of a bulletin or CVE identifier: case and
    surrounding spaces carry no meaning, so " ctx696604 " is the same
    bulletin as "CTX696604". Such a spelling is refused anyway (see
    `_identity_problem`); this fold only decides that the refusal names the
    duplicate it is, rather than the spelling."""
    return str(value).strip().upper()


# The form of a real identifier, ASCII only - `[0-9]`, not `\d`, which also
# matches fullwidth and other non-ASCII digits. Measured: CVE-2026-8451 a
# second time, with its hyphens replaced by the Unicode hyphen (U+2010),
# passed the loader of an unpinned package; to the duplicate check it was
# another identity, to a reader the same CVE.
_BULLETIN_ID = re.compile(r"CTX[0-9]+")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_BULLETIN_FORM = "CTX gevolgd door cijfers (alleen ASCII, zonder spaties)"
_CVE_FORM = "CVE-, vier cijfers, een koppelteken en vier of meer cijfers (alleen ASCII, zonder spaties)"


def _identity_problem(value, grammar: re.Pattern, form: str, field_path: str) -> str:
    """The reason `value` is no identifier of this form, or "" when it is.
    The reason names the field and the form, never the value: a value
    outside the grammar is exactly the text a reader cannot trust to look
    like what it is."""
    if isinstance(value, str) and grammar.fullmatch(value):
        return ""
    return f"kennispakket: {field_path} heeft niet de vorm {form}"


@dataclass(frozen=True)
class Knowledge:
    version: str | None
    date: str | None
    age_days: int | None
    missing: bool
    reason: str = ""
    cve: tuple = ()
    explanations: dict = field(default_factory=dict)
    glossary: dict = field(default_factory=dict)
    # Which free text fields were cut against the ceiling. An answer that uses
    # such a field can say so; a silent cut would be exactly the false
    # completeness this product refuses everywhere else.
    truncated_fields: tuple = ()

    def truncation_note(self) -> str:
        """A safe, aggregate Dutch sentence for `truncated_fields`, or "" when
        nothing was cut.

        Before this, the ONLY operator-visible
        signal was the inline `TRUNCATION_NOTE` inside a field's own text -
        and that surfaces only if THAT SPECIFIC field renders in THIS
        answer. `begrippen` is cut first in the fixed order (most likely to
        be shortened) and only ever renders on an exact-term lookup (least
        likely to be seen) - so a truncated package could go unnoticed on
        every answer that never happens to touch the cut field.

        This reports the COUNT and the KIND of every cut field - "3x
        begrippen, 1x kern" - never the glossary/explanation key or the
        bulletin/CVE index behind it (`_field_kind` above throws those away).
        Both are untrusted strings (or positions) out of a file nobody
        authenticated; a key echoed here would be exactly the raw-string
        leak the rest of this module's hardening refuses.
        """
        if not self.truncated_fields:
            return ""
        counts: dict[str, int] = {}
        for name in self.truncated_fields:
            kind = _field_kind(name)
            counts[kind] = counts.get(kind, 0) + 1
        parts = [f"{counts[kind]}x {kind}" for kind in _FIELD_KINDS if kind in counts]
        total = len(self.truncated_fields)
        plural = "veld" if total == 1 else "velden"
        # No "kennispakket:" prefix here: every caller so far renders this
        # as a Finding's OUTCOME next to the subject "kennispakket" (see
        # cve.py's cve_check), which already supplies that word - prefixing
        # it here too produced a doubled "kennispakket: kennispakket: ..."
        # in the rendered answer.
        return f"{total} {plural} afgekapt tegen het pakketplafond ({', '.join(parts)})"

    offered_builds: dict = field(default_factory=dict)
    offered_date: str | None = None
    offered_source: str | None = None
    # Why this package is NOT the one the operator approved, or "" when that
    # question does not stand: the configuration pinned it and it matched,
    # or the caller applies no pin at all (a unit or library call). Set to
    # UNPINNED_REASON when the configuration carries no `kennispin`; every
    # floor and CVE statement built on the package then carries
    # `[niet vastgesteld]` with this reason.
    unpinned_reason: str = ""


# THE PIN. Whoever can write the knowledge path can otherwise change the
# knowledge itself: a coherently lowered package (affected range AND
# fix-build both at 66.00) or one with the last bulletin removed passes every
# shape check in this module, and was measured to lower the floor and shrink
# the CVE count while calling both established. Shape cannot tell a changed
# package from a real one; only a fingerprint the operator recorded OUTSIDE
# the knowledge path can.
UNPINNED_REASON = "kennispakket niet gepind in de configuratie"


@dataclass(frozen=True)
class KnowledgePin:
    """The package the operator approved: its `versie` and the sha256 of its
    canonical content (`canonical_digest`). Read from the configuration field
    `kennispin` by start.py."""

    version: str
    digest: str


def canonical_digest(document) -> str:
    """The sha256 (lowercase hex) of a parsed package in ONE canonical form:
    sorted keys, no whitespace, ASCII escapes, as UTF-8. The parsed content is
    what the product uses, so the parsed content is what is fingerprinted -
    CRLF against LF, indentation and key order do not change it."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pin_problem(raw: dict, pin: KnowledgePin) -> str:
    """Which half of the pin this package does not match, or "" when both do.

    Names WHICH half differs and never repeats the expected digest (nor the
    package's own version, which is attacker-supplied text): an answer that
    printed the approved digest would hand a forger the one value to aim at.
    """
    version = raw.get("versie")
    version_differs = not isinstance(version, str) or version.strip() != pin.version
    digest_differs = canonical_digest(raw) != pin.digest
    if version_differs and digest_differs:
        differs = "de versie en de inhoud (digest) wijken af"
    elif version_differs:
        differs = "de versie wijkt af"
    elif digest_differs:
        differs = "de inhoud (digest) wijkt af"
    else:
        return ""
    return f"kennispakket wijkt af van de kennispin in de configuratie: {differs}; dit pakket geldt niet"


# The default of `load_knowledge(pin=...)`: the caller takes no position on
# pinning (a unit or library call). The server always passes one: the
# configured KnowledgePin, or None when the configuration carries none.
PIN_NOT_APPLIED = object()


def _absent(reason: str) -> Knowledge:
    return Knowledge(version=None, date=None, age_days=None, missing=True, reason=reason)


def load_knowledge(path: Path, today: date, *, pin=PIN_NOT_APPLIED) -> Knowledge:
    # `pin`: a KnowledgePin the package must match (else it is refused with
    # the half that differs), None when the configuration pins nothing (the
    # package loads, carrying UNPINNED_REASON), or PIN_NOT_APPLIED.
    #
    # The knowledge path is loaded lazily (on the first tool call, not while
    # building the server), so exists() (also true for a directory) would let
    # a directory through until read_text() blew up on an OSError
    # (IsADirectoryError on Linux, PermissionError on Windows - both uncaught
    # here). That error would then reach mcp_server.py's mask_error() and be
    # replaced by the generic "onverwachte fout" message, far from where the
    # operator configured the knowledge path. is_dir()/is_file() catch this
    # EARLY, as the same kind of read gap as any other unreadable knowledge
    # package - the same, pre-existing _absent() route, no new branch.
    # The semantics for a TRULY missing (optional) knowledge package stay
    # deliberately unchanged: a read gap, not an error.
    if path.is_dir():
        return _absent(f"kennispad wijst naar een map, geen bestand: {path}")
    if not path.is_file():
        return _absent(f"kennispakket niet gevonden op {path}")
    # SECURITY 9. The ceiling comes BEFORE the read, the same place every
    # reader in export.py puts it: the decode, the parse and the depth walk all
    # scale with the size of a file nobody authenticated. The PACKAGE ceiling
    # further down does not compensate - measured: it is applied to text that
    # is ALREADY capped per field, so seven `uitleg` fields of 20 MB each are
    # read (140 MB), parsed, and only then cut to about 57.800 characters,
    # which is UNDER MAX_KNOWLEDGE_TEXT_CHARS - such a package is accepted, not
    # refused, and MemoryError never fires. stat() is used rather than a read,
    # so an oversized package costs no bytes at all.
    try:
        size = path.stat().st_size
    except OSError as exc:
        # TOCTOU, the same shape export.py handles around its own reads:
        # is_file() still saw a file, the size check no longer can. Fail closed
        # with a named reason, exactly like the read below - never a silently
        # accepted package.
        return _absent(f"kennispakket onleesbaar: {exc.__class__.__name__}")
    if size > MAX_FILE_BYTES:
        return _absent(f"kennispakket is groter dan het plafond ({size} bytes tegen {MAX_FILE_BYTES}); niet gelezen")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (RecursionError, MemoryError, ValueError) as exc:
        # SECURITY 8. ONE clause on purpose. json.JSONDecodeError and
        # UnicodeDecodeError are both ValueError subclasses, so listing them in
        # a separate tuple above this one was decorative: a name could be
        # dropped from it and the exception fell through to here and produced
        # the SAME message, because the message is built from the class name.
        # Two clauses with byte-identical bodies also defused the two guard
        # tests that exist to keep this branch honest. RecursionError and
        # MemoryError are NOT ValueError subclasses; those two are what a
        # hostile package really used to raise past the fail-closed wall into
        # the generic masked server error.
        return _absent(f"kennispakket onleesbaar: {exc.__class__.__name__}")
    if not isinstance(raw, dict):
        return _absent("kennispakket moet een object zijn")
    if exceeds_depth(raw):
        return _absent(f"kennispakket is te diep genest (meer dan {MAX_JSON_DEPTH} niveaus)")
    # The pin is checked on the SAME parsed document everything below reads -
    # never on a second read of the file, which could already hold other bytes.
    if isinstance(pin, KnowledgePin):
        problem = _pin_problem(raw, pin)
        if problem:
            return _absent(problem)
    unknown = raw.keys() - _TOP_FIELDS
    if unknown:
        return _absent(f"kennispakket bevat onbekend veld: {', '.join(sorted(unknown))!r}")
    # SECURITY 12. `cve` is REQUIRED. A package without the key used to load as
    # valid and fresh with zero bulletins - measured: missing=False, four days
    # old, no bulletins at all. That is the one defect shape that produced a
    # silent "geen bulletins" instead of an honest refusal.
    if "cve" not in raw:
        return _absent("kennispakket mist verplicht veld: cve")
    bulletins = raw["cve"]
    if not isinstance(bulletins, list):
        return _absent("kennispakket: 'cve' moet een lijst zijn")
    # Every bulletin and every CVE counts ONCE. A package that lists one
    # twice was measured to count it twice - 7 hit / 4 not hit / 11 unknown
    # instead of 6 / 3 / 7, the bulletin shown twice, all established - so a
    # duplicate identity is refused here rather than de-duplicated: which of
    # two copies is the real one is not something this loader can know.
    seen_bulletins: set[str] = set()
    seen_cves: set[str] = set()
    for index, entry in enumerate(bulletins):
        if not isinstance(entry, dict):
            return _absent("kennispakket: elk cve-record moet een object zijn")
        missing_fields = _BULLETIN_FIELDS - entry.keys()
        if missing_fields:
            return _absent(f"kennispakket: cve-record mist veld: {', '.join(sorted(missing_fields))}")
        if entry.keys() - _BULLETIN_FIELDS:
            # HARDENING, same class: cve-record keys are attacker-supplied
            # too, so !r on the joined list, not a raw paste - see the
            # top-level unknown-field message above.
            return _absent(
                f"kennispakket: cve-record bevat onbekend veld: {', '.join(sorted(entry.keys() - _BULLETIN_FIELDS))!r}"
            )
        # The identifier is attacker-supplied text, so !r: a line break in it
        # would otherwise forge a second line into this refusal reason.
        if _identity(entry["bulletin"]) in seen_bulletins:
            return _absent(
                f"kennispakket: bulletin {entry['bulletin']!r} komt meer dan eens voor; het zou dubbel meetellen"
            )
        # After the duplicate check, which names a copy for what it is; before
        # anything else echoes the identifier into a reason.
        problem = _identity_problem(entry["bulletin"], _BULLETIN_ID, _BULLETIN_FORM, f"cve[{index}].bulletin")
        if problem:
            return _absent(problem)
        seen_bulletins.add(_identity(entry["bulletin"]))
        # "getroffen" and "fix" are two halves of ONE rule per branch: which
        # builds are affected, and from which build it is fixed. A branch that
        # appears in only one of the two is a half rule - and a half rule
        # produces a verdict for a branch whose fixed build (or whose affected
        # range) is simply not there. Refused here, at load time, so no answer
        # can ever be built on it; cve.py keeps its own runtime guard as the
        # second net.
        for field_name in ("getroffen", "fix"):
            if not isinstance(entry[field_name], dict):
                return _absent(f"kennispakket: '{field_name}' moet een object van tak naar tekst zijn")
        only_affected = sorted(entry["getroffen"].keys() - entry["fix"].keys())
        only_fixed = sorted(entry["fix"].keys() - entry["getroffen"].keys())
        if only_affected or only_fixed:
            # HARDENING, same class as the unknown-field messages above: both
            # the branch names (attacker-supplied dict keys under
            # 'getroffen'/'fix') and 'bulletin' itself (an attacker-supplied
            # field, never type- or shape-checked) are echoed into this
            # refusal reason, so both go through !r rather than a raw paste -
            # otherwise a branch name or bulletin id carrying a line break
            # could forge a second, indistinguishable line into this reason.
            parts = []
            if only_affected:
                parts.append(f"alleen in 'getroffen': {', '.join(only_affected)!r}")
            if only_fixed:
                parts.append(f"alleen in 'fix': {', '.join(only_fixed)!r}")
            return _absent(
                f"kennispakket: bulletin {entry['bulletin']!r} draagt in 'getroffen' en 'fix'"
                f" niet dezelfde takken ({'; '.join(parts)})"
            )
        for branch, affected in entry["getroffen"].items():
            problem = _rule_problem(affected, entry["fix"][branch])
            if problem:
                # Branch name and identifier are attacker-supplied: !r, as above.
                return _absent(f"kennispakket: bulletin {entry['bulletin']!r} draagt voor tak {branch!r} {problem}")
        if not isinstance(entry["cves"], list):
            return _absent("kennispakket: 'cves' moet een lijst zijn")
        for position, cve in enumerate(entry["cves"]):
            if not isinstance(cve, dict) or (_CVE_FIELDS - cve.keys()):
                return _absent(
                    "kennispakket: cve mist veld: "
                    + ", ".join(sorted(_CVE_FIELDS - (cve.keys() if isinstance(cve, dict) else set())))
                )
            if _identity(cve["id"]) in seen_cves:
                return _absent(f"kennispakket: CVE {cve['id']!r} komt meer dan eens voor; het zou dubbel meetellen")
            problem = _identity_problem(cve["id"], _CVE_ID, _CVE_FORM, f"cve[{index}].cves[{position}].id")
            if problem:
                return _absent(problem)
            seen_cves.add(_identity(cve["id"]))
            problem = _condition_problem(cve["voorwaarde"])
            if problem:
                return _absent(f"kennispakket: {problem}")
            if POST_UPGRADE_CONFIG_FIELD in cve and type(cve[POST_UPGRADE_CONFIG_FIELD]) is not bool:
                # The identifier was checked above; the value is never echoed.
                return _absent(
                    f"kennispakket: '{POST_UPGRADE_CONFIG_FIELD}' van CVE {cve['id']!r} moet true of false zijn"
                )
    # B1. Absent is allowed and stays backwards compatible; a wrong shape is
    # not - see _offered_problem() for why this one field is refused at load
    # time rather than judged later.
    offered = raw.get("aangeboden")
    offered_builds: dict = {}
    offered_date = None
    offered_source = None
    if offered is not None:
        problem = _offered_problem(offered)
        if problem:
            return _absent(f"kennispakket: {problem}")
        offered_builds = dict(offered["builds"])
        offered_date = str(offered["datum"])
        # `capped_text()` bounds the offered source; retain the separate printability gate.
        # capped_text() NORMALISES line endings (\r\n / \r -> \n); it does
        # NOT remove them, so applying it alone does not close the forged
        # "[vastgesteld]" hole. It must be applied ALONGSIDE the
        # `.isprintable()` check in _offered_problem() above, never INSTEAD
        # of it - the cap bounds length, the printability check stops
        # forgery, and dropping the latter "because the cap is here now"
        # would reopen the hole this task closed.
        offered_source, _ = capped_text(offered["bron"])
    explanations = raw.get("uitleg", {})
    glossary = raw.get("begrippen", {})
    for name, value in (("uitleg", explanations), ("begrippen", glossary)):
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
            return _absent(f"kennispakket: '{name}' moet een object van tekst naar tekst zijn")
    # SECURITY 17. Five free text paths travel verbatim into the model's
    # context out of a file nobody authenticated: the `uitleg` values, the
    # `begrippen` values, and - inside the cve list - each bulletin's `advies`
    # and `extraStapNaUpgrade` and each CVE's `kern`. All five are normalized
    # on line endings and capped per field with a visible sentence.
    # The shape check above runs FIRST on purpose: capped_text() does str() on
    # whatever it gets, so a JSON null or an object would silently become the
    # operator-facing text "None" or a Python repr, with nothing flagged. Only
    # confirmed strings reach it; anything else is refused with a reason.
    truncated: list[str] = []
    capped_explanations: dict[str, str] = {}
    capped_glossary: dict[str, str] = {}
    for name, source, sink in (
        ("uitleg", explanations, capped_explanations),
        ("begrippen", glossary, capped_glossary),
    ):
        for key, value in source.items():
            text, was_cut = capped_text(value)
            if was_cut:
                truncated.append(f"{name}.{key}")
            sink[key] = text

    # The bulletins are dicts out of the same file; they are copied rather
    # than mutated, so a caller that kept the raw document keeps it.
    capped_bulletins: list = []
    for index, bulletin in enumerate(bulletins):
        if not isinstance(bulletin, dict):
            capped_bulletins.append(bulletin)
            continue
        copy = dict(bulletin)
        for field_name in ("advies", "extraStapNaUpgrade"):
            value = copy.get(field_name)
            if isinstance(value, str):
                text, was_cut = capped_text(value)
                if was_cut:
                    truncated.append(f"cve[{index}].{field_name}")
                copy[field_name] = text
        entries = copy.get("cves")
        if isinstance(entries, list):
            new_entries = []
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    new_entries.append(entry)
                    continue
                entry_copy = dict(entry)
                kern = entry_copy.get("kern")
                if isinstance(kern, str):
                    text, was_cut = capped_text(kern)
                    if was_cut:
                        truncated.append(f"cve[{index}].cves[{position}].kern")
                    entry_copy["kern"] = text
                new_entries.append(entry_copy)
            copy["cves"] = new_entries
        capped_bulletins.append(copy)

    # THE PACKAGE CEILING (design 3.6 unit 3): the field ceiling goes first,
    # and if the sum is still above the package ceiling the fields are cut in
    # ONE fixed order until it fits. Not a refusal: a ceiling on text is
    # fail-VISIBLE - it is cut and says so - while a ceiling a verdict rests on
    # is fail-closed. Throwing away a whole knowledge package over a long note
    # would be the wrong one of the two.
    ordered: list[tuple[str, str]] = []
    ordered.extend((f"begrippen.{k}", v) for k, v in capped_glossary.items())
    for index, bulletin in enumerate(capped_bulletins):
        if isinstance(bulletin, dict) and isinstance(bulletin.get("advies"), str):
            ordered.append((f"cve[{index}].advies", bulletin["advies"]))
    for index, bulletin in enumerate(capped_bulletins):
        if isinstance(bulletin, dict) and isinstance(bulletin.get("extraStapNaUpgrade"), str):
            ordered.append((f"cve[{index}].extraStapNaUpgrade", bulletin["extraStapNaUpgrade"]))
    for index, bulletin in enumerate(capped_bulletins):
        entries = bulletin.get("cves") if isinstance(bulletin, dict) else None
        if isinstance(entries, list):
            for position, entry in enumerate(entries):
                if isinstance(entry, dict) and isinstance(entry.get("kern"), str):
                    ordered.append((f"cve[{index}].cves[{position}].kern", entry["kern"]))
    ordered.extend((f"uitleg.{k}", v) for k, v in capped_explanations.items())

    try:
        shrunk, extra = shrink_to_package_cap(ordered)
    except PackageShapeDefeatsCap as exc:
        # The field ceiling already ran above, and the package-level shrink
        # just cut every one of these fields as far as it can go (down to
        # `TRUNCATION_NOTE` alone, or to nothing for a field too short to
        # carry even that) and the sum STILL exceeds the ceiling. That is no
        # longer "one long note" - a single large field can always be cut
        # down to the note - it is a package whose SHAPE (many fields, each
        # barely above the note's own length) defeats the ceiling. This is
        # the one case where the base commit's refusal was right: fail
        # CLOSED, the same named-reason route as any other unusable package.
        return _absent(str(exc))
    for name, text in shrunk.items():
        group, _, rest = name.partition(".")
        if group == "begrippen":
            capped_glossary[rest] = text
        elif group == "uitleg":
            capped_explanations[rest] = text
        else:
            # A cve[<i>]... name. Walk it back to the dict it came from; the
            # names are built above, so there is exactly one shape to parse.
            index = int(name[name.index("[") + 1 : name.index("]")])
            bulletin = capped_bulletins[index]
            if name.endswith(".advies"):
                bulletin["advies"] = text
            elif name.endswith(".extraStapNaUpgrade"):
                bulletin["extraStapNaUpgrade"] = text
            else:
                tail = name[name.index("cves[") + len("cves[") :]
                position = int(tail[: tail.index("]")])
                bulletin["cves"][position]["kern"] = text
    # A membership test against a growing LIST is quadratic - measured end to
    # end: 5.000 fields 0,14 s, 20.000 fields 2,16 s, 40.000 fields 8,46 s (of
    # which 8,43 s was this one line), and load_knowledge runs uncached on
    # every tool call. `already_truncated` turns the test into a set lookup;
    # `truncated` itself stays a list, so the order the fixed-order cut
    # produced is unchanged.
    already_truncated = set(truncated)
    for name in extra:
        if name not in already_truncated:
            truncated.append(name)
            already_truncated.add(name)
    date_value = raw.get("datum")
    if not date_value:
        return _absent("kennispakket draagt geen datum; leeftijd is niet vast te stellen")
    try:
        created = date.fromisoformat(str(date_value))
    except ValueError:
        return _absent(f"kennispakket draagt een onbruikbare datum: {date_value!r}")
    age_days = (today - created).days
    # Without a lower bound this would render "-1 dagen oud" for a knowledge
    # package dated in the future - the same kind of error that
    # answer.py::_age already refuses outright for the DATA age
    # ("tijdstempel ligt in de toekomst"). One text must not follow two
    # different rules for the same kind of error.
    if age_days < 0:
        return _absent(f"kennispakket is gedateerd in de toekomst: {date_value!r}")
    # SECURITY 17 continued. `versie` is shown on kennis_uitleg's NOT-FOUND
    # branch - the common case, at every disclosure level - so it gets the
    # same isinstance(str) pre-check and the same capped_text() the other
    # five free text fields above already get. A non-string value (or None)
    # is left untouched, exactly like a non-string advies/extraStapNaUpgrade/
    # kern value is above: only a confirmed string is capped.
    version_value = raw.get("versie")
    if isinstance(version_value, str):
        version_value, _ = capped_text(version_value)
    return Knowledge(
        version=version_value,
        date=str(date_value),
        age_days=age_days,
        missing=False,
        cve=tuple(capped_bulletins),
        explanations=capped_explanations,
        glossary=capped_glossary,
        truncated_fields=tuple(truncated),
        offered_builds=offered_builds,
        offered_date=offered_date,
        offered_source=offered_source,
        unpinned_reason=UNPINNED_REASON if pin is None else "",
    )


_DIGEST_USAGE = "Gebruik: python -m nsmcp.knowledge --digest <pad-naar-kennispakket>"


def main(argv: list[str] | None = None) -> int:
    """`python -m nsmcp.knowledge --digest <pad>`: the `kennispin` block for
    this package, ready to paste into the configuration.

    The package is loaded through `load_knowledge` first, with the same
    checks the server applies: a package the server would refuse gets no pin,
    so an operator cannot approve a broken one by accident. The computed pin
    is then loaded AGAINST the file once more, so a file that changed between
    the reads is refused rather than pinned.
    """
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2 or arguments[0] != "--digest":
        print(_DIGEST_USAGE, file=sys.stderr)
        return 2
    path = Path(arguments[1])
    today = datetime.now(UTC).date()
    knowledge = load_knowledge(path, today=today)
    if knowledge.missing:
        print(f"Fout: {knowledge.reason}; geen kennispin berekend", file=sys.stderr)
        return 1
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, RecursionError, MemoryError, ValueError) as exc:
        print(f"Fout: kennispakket onleesbaar: {exc.__class__.__name__}; geen kennispin berekend", file=sys.stderr)
        return 1
    version = raw.get("versie") if isinstance(raw, dict) else None
    if not isinstance(version, str) or not version.strip():
        print("Fout: kennispakket draagt geen versie als tekst; geen kennispin berekend", file=sys.stderr)
        return 1
    pin = KnowledgePin(version=version.strip(), digest=canonical_digest(raw))
    confirmed = load_knowledge(path, today=today, pin=pin)
    if confirmed.missing:
        print(f"Fout: {confirmed.reason}; geen kennispin berekend", file=sys.stderr)
        return 1
    print(json.dumps({"kennispin": {"versie": pin.version, "digest": pin.digest}}, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised in a subprocess test
    raise SystemExit(main())
