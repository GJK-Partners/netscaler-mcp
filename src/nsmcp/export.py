"""Read an NSHC collector export, with the manifest as the source of truth.

The manifest decides whether a source was read USABLY. That distinction is the
core of this product: an empty list because there was nothing is a finding; an
empty list because the read failed is a read gap. Whoever equates those two
builds a tool that silently says green.

The by-parent binding files bundle many reads into one file and therefore do
not appear in the per-resource outcomes; their integrity hangs on the hashes
in manifest.files. A manipulated binding file could otherwise change an entire
impact chain unnoticed.

A hash proves only that the file is the file the collector wrote - never that
the collector wrote down EVERYTHING. `_flatten_by_parent` catches a parent
that is PRESENT with an unusable outcome, but a parent that is ABSENT
altogether leaves no trace in the file at all: the flat list simply comes out
shorter and looks complete. That is a third state, and `binding_parents()`
below is the cross-check that makes it visible - against the object source of
those same parents, in this same manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from nsmcp.answer import ReadGap, repeatable_token
from nsmcp.limits import (
    MAX_FILE_BYTES,
    MAX_JSON_DEPTH,
    MAX_OBJECTS_PER_FILE,
    MAX_TEXT_LINES,
    exceeds_depth,
)
from nsmcp.redact import redact_config_line, redact_config_lines

USABLE = {"OK", "EMPTY"}


def payload_digest(raw_bytes: bytes) -> str:
    """The digest the collector writes for an object file, a binding file and
    a parsed JSON projection: sha256 over the raw bytes on disk, upper case.
    Every reader below compares against this function, and so does the
    fixture generator (scripts/make_doh_fixture.py) - one definition, so a
    manifest written for a test can never drift from the one the product
    reads."""
    return hashlib.sha256(raw_bytes).hexdigest().upper()


def config_text_digest(raw_bytes: bytes) -> str:
    """The digest the collector writes for parsed/runningconfig.txt and
    parsed/savedconfig.txt: sha256 over the UTF-8 text with CRLF folded to
    LF and without a byte order mark (see `Export.running_config_lines`),
    upper case. Raises UnicodeDecodeError on bytes that are not UTF-8."""
    text = raw_bytes.decode("utf-8-sig").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


# The shape a NITRO object name has, and the ONLY shape that may become part
# of a file name under this export directory.
#
# Measured on 2026-08-27: `binding_parents()` builds `config/<parentResource>`
# from a field that sits in the CONTENT of a binding file, and `objects()`
# sanitized that with `resource.split("/")[-1]`. That split does not split on
# the backslash - and on Windows the backslash IS a path separator. A supplied
# export with `parentResource = "..\\..\\geheim"` therefore opened, decoded and
# parsed a file OUTSIDE the export directory. The content did not leak, but the
# difference between "missing", "could not be read" and "no list under the key"
# betrays the existence and readability of an arbitrary path - and that text
# travels into the answer. A large file would also be parsed into memory in
# full.
#
# The repair is a POSITIVE test instead of sanitization: a name either has this
# shape, or nothing is opened with it. Sanitizing means enumerating everything
# that is dangerous (and this round proved that enumeration incomplete);
# validating positively means enumerating what is allowed. All 58 resources of
# the live export (`tests/fixtures/lab-export-vpx-20260826/`) match this shape,
# query string excluded.
#
# `fullmatch` deliberately, never `re.match(... + "$")`: in Python `$` also
# matches BEFORE a trailing newline, so "geheim\n" would slip through an
# anchored allowlist - a bypass this codebase has been bitten by before.
_OBJECT_NAME = re.compile(r"[A-Za-z0-9_]+")


def plain_path(path: Path, *, directory: bool) -> bool:
    """Refuse a symlink or Windows reparse point ANYWHERE in `path`,
    including every ancestor - True only for a REAL, plain file or
    directory reached by no such indirection.

    Promoted here from `retention.py`: that module owns
    the containment discipline for a KEPT sibling
    (`_owned_manifest`/`kept_exports`), and `compare.py`'s `mcp_server.
    _inside_export_root()` (a caller-supplied neighbour directory NAME,
    never a path) needs the exact same discipline for the exact same
    reason - a junction can look like a plain sibling directory while
    pointing anywhere. `export.py` is the bottom layer both callers
    already depend on, so this lives here once instead of twice.

    Kept intentionally narrow: a boolean shape gate, not a path resolver -
    the caller still does its own `resolve().parent` containment check
    afterwards; this only refuses the indirection that would make that
    check meaningless.
    """
    try:
        path = path.absolute()
        for entry in (path, *path.parents):
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return False
            if entry != path and not stat.S_ISDIR(info.st_mode):
                return False
        info = path.lstat()
        return stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    except (OSError, ValueError):
        return False


def _is_object_name(value) -> bool:
    # The isinstance gate sits BEFORE the pattern, the same discipline as
    # `_usable_text` below: first establish WHAT something is, then test it.
    # A caller that hands in None or a list gets an honest False here, never a
    # TypeError from deep inside the regex engine.
    return isinstance(value, str) and _OBJECT_NAME.fullmatch(value) is not None


# ---------------------------------------------------------------------------
# THE BOUNDARY GATE
#
# An export is SUPPLIED to this product. Every key in `export-manifest.json`,
# every line of `scan-doel.txt` and every value in either is therefore
# untrusted input that either reaches the model or becomes a file path.
# `load_export()` at the bottom of this file is the ONE place where such a
# manifest becomes an `Export`, so the shape gate sits HERE - once, on the
# boundary - instead of in whichever tool happened to be written last. Tasks
# 2 and 3 each rediscovered the same defect class one field further along;
# this closes it for the whole journey of the field.
#
# The idiom is the one this codebase already holds twice
# (`coverage._resource_key` and `coverage._binding_file_name`): a POSITIVE
# shape test, never a sanitizer. Sanitizing means enumerating everything that
# is dangerous - an enumeration those rounds proved incomplete; validating
# positively means enumerating what is allowed. `fullmatch` deliberately,
# never `re.match(... + "$")`: in Python `$` also matches BEFORE a trailing
# newline (see the comment at `_OBJECT_NAME` above).
#
# DELIBERATELY STRICTER THAN NITRO MAY BE. Both grammars below are derived
# from the keys of the real export (`tests/fixtures/lab-export-vpx-20260826/`,
# measured 2026-09-06: 58 resource keys, longest 67 characters; 9 file keys,
# longest 57). A future collector that introduces a key shape this version
# does not know therefore lands fail-closed - the entry stays visible, named
# by its SHAPE, and costs the verdict - instead of slipping through. That is
# the intended trade: a shape we have never seen is a shape we cannot vouch
# for, and a product that says "niet vastgesteld" one release too long is
# honest, while one that opens an unknown path once is not.
#
# PUBLIC, and the ONLY length cap for a manifest key anywhere in this product.
# `coverage.py` imports it rather than holding a copy: it used to carry its own
# 120, so a well-shaped key of 121-160 characters passed this boundary and was
# then refused at that seam as "een sleutel zonder de vorm van een
# NITRO-resourcepad" - untrue of its shape, and a second wording for a refusal
# this gate had never made. The layering allows `coverage` to import from
# `export` and not the other way round, so the constant lives here.
MANIFEST_KEY_MAX_LEN = 160

# A `resources` key: two lower-case segments ("config/sslvserver"), optionally
# with the query the collector appends ("?bulkbindings=yes",
# "?args=filename:iprep.log,filelocation:%2Fvar%2Flog" - hence `%`, `:`, `,`,
# `.` and upper case INSIDE THE QUERY only, for percent-encoding). All 58 keys
# of the real export pass; pinned by tests/test_export_boundary.py against
# that fixture, not against a copy of the list.
_RESOURCE_KEY = re.compile(r"[a-z][a-z0-9_]*/[a-z][a-z0-9_]*(?:\?[A-Za-z0-9_=:,.%-]+)?")

# A `files` key: one lower-case directory segment and one file name under it
# ("bindings/sslcertkey_binding.by-parent.json", "parsed/runningconfig.txt").
# The name may carry dots, underscores and hyphens - `by-parent` is a HYPHEN
# inside a dot-separated segment, and a grammar allowing only [a-z0-9_] falls
# over on all seven binding files - but it may not START with a dot, so `..`
# can never be a segment, and it carries no separator of its own, so such a
# key names exactly one file directly under exactly one directory. All 9 keys
# of the real export pass; pinned against that same fixture.
_FILE_KEY = re.compile(r"[a-z][a-z0-9_]*/[a-z0-9][a-z0-9_.-]*")


def _is_manifest_key(value, pattern: re.Pattern[str]) -> bool:
    """Does this manifest key have a shape this version knows?

    The isinstance gate sits BEFORE the pattern, the same discipline as
    `_is_object_name` above and `_usable_text` below: first establish WHAT
    something is, then test it. A caller that hands in None or a list gets an
    honest False, never a TypeError from deep inside the regex engine.
    """
    return isinstance(value, str) and len(value) <= MANIFEST_KEY_MAX_LEN and pattern.fullmatch(value) is not None


def _gate_manifest_map(raw: dict, pattern) -> tuple[dict, tuple]:
    """Splits a manifest map into the entries whose KEY has a shape this
    version knows, and the keys that were refused.

    A refused entry does NOT disappear - a silently vanishing entry is
    exactly the mistake that turns an uninterpretable export
    into a green one. It travels on in the second tuple, so a consumer counts
    it, names its SHAPE and lets it cost the verdict (see
    `Export.refused_resource_keys`). What it may no longer do is reach a
    consumer as if it were usable: the last segment of such a key becomes a
    FILE NAME, and every consumer would otherwise have to remember that by
    itself. That is exactly what this gate exists to stop.
    """
    kept: dict = {}
    refused: list = []
    for key, value in raw.items():
        if _is_manifest_key(key, pattern):
            kept[key] = value
        else:
            refused.append(key)
    return kept, tuple(refused)


# The refusal for a path that would leave the export directory. Deliberately
# CONSTANT and deliberately silent about the name: a refusal that varied with
# what happens to exist at the path would be the filesystem existence oracle
# the gate exists to close (measured: whether a file outside the
# export existed flipped the verdict to `volledig [vastgesteld]`).
_REFUSED_PATH_REASON = (
    "de opgevraagde naam levert geen pad binnen de exportmap op; er wordt niets geopend"
    " buiten de export, en de naam zelf wordt hier niet herhaald"
)


def _within(directory: Path, *parts: str) -> Path | None:
    """The path `parts` names under `directory`, or None when it lands
    outside it.

    EVERY path this module builds runs through here, so a caller that
    composes a name from supplied text tomorrow cannot open a new hole with
    it. Measured twice already (August, on `parentResource`; 2026-09-06, on a
    manifest key): `split("/")` does not split on a backslash, on Windows the
    backslash IS a separator, and a value carrying `..` therefore opened,
    hashed and JSON-decoded a file OUTSIDE the export directory.

    BOTH sides are resolved before they are compared: `resolve()` normalizes
    `..`, symlinks and Windows 8.3 short names, and an unresolved directory
    would not match a resolved candidate. The containment test is
    `root in candidate.parents`, which also refuses the export directory
    itself - that is not a file this module reads.
    """
    try:
        root = directory.resolve()
        candidate = root.joinpath(*parts).resolve()
    except (OSError, ValueError):
        # A path the operating system will not even normalize (a NUL byte, a
        # name past the platform limit) is refused like any other: no path, so
        # nothing is opened.
        return None
    return candidate if root in candidate.parents else None


def _read_error_kind(exc: OSError) -> str:
    """The KIND of a file-read failure - never the exception itself.

    `OSError.__str__()` carries the full absolute
    local path on Windows (MEASURED: an ACL-locked object file put the
    whole export directory's path into a ReadGap.reason, at `volledig` AND
    `beperkt` - no name family collects a filesystem path, so nothing masks
    it). This names the failure by TYPE only - permission, "not a file" (a
    directory or a bad path component sits where a file was expected), or
    anything else - so a caller can build an honest sentence that never
    echoes the OS message or the path. The same idiom as
    `collect._phase_file_read_error_kind` - this
    file cannot import that one (`collect.py` imports FROM `export.py`), so
    it gets its own copy instead of a second, differently-shaped one.
    """
    if isinstance(exc, PermissionError):
        return "geen toegang"
    if isinstance(exc, (IsADirectoryError, NotADirectoryError)):
        return "geen bestand"
    return "onbekende leesfout"


# The shape of a scan TARGET NAME, and the text that replaces one without it.
#
# Why this cannot borrow `answer.repeatable_token`, the shape gate this
# product uses for every other supplied value: that function demands a leading
# CAPITAL, and the target name of the real export
# (`tests/fixtures/lab-export-vpx-20260826/scan-doel.txt`, line 1) is `lab` -
# three lower-case letters. A gate that refuses `lab` breaks the closing line
# of every tool on the real fixture. Measured, not assumed.
#
# What travels: `Export.target_name` -> `answer.stamp_data` ->
# `Answer.data_target` -> the closing line `doel: <naam>` of EVERY tool, on
# all three disclosure levels, plus a finding of `coverage.coverage_answer`.
# `disclosure.names_from_export()` collects this field as its twelfth family
# and masks it at `beperkt`/`minimaal` - but this
# shape gate stays the FIRST line of defence regardless: it is what stands
# between a supplied export and the model at `volledig`, where the target
# name is shown deliberately and in full.
#
# A WORD of a target name: the shape of a host name or an address - letters,
# digits and the separators a host name and an IPv4/IPv6 address carry. Note
# what is NOT in the class: `[` and `]`, so a supplied name can never mimic
# this product's own certainty marker (`[vastgesteld]`); no control character
# of any kind, so nothing can forge a line; no whitespace, so a word is a word.
_TARGET_NAME_WORD = r"[A-Za-z0-9][A-Za-z0-9_.:-]*"

# The name itself: up to FOUR such words, separated by ONE interior space each.
#
# Why the space is admitted at all. `Export.target_name` originates in
# `scan-doel.txt`, which `collect.collect()` writes from `Target.name`, which
# is the operator's own `doelen.json` field `naam` - and `target.py` puts NO
# shape rule on that field. A target legitimately named `ns01 productie` was
# therefore printing a permanent, visible refusal in the closing line of every
# answer: a product defect, not hardening. The recorder applies no matching
# rule, so THIS gate is deliberately the stricter of the two - it is the last
# thing between a supplied export and the model, and it stays a positive shape
# test rather than becoming a pass-through.
#
# What the widening keeps, all of it: the name still begins and ends on a word
# character (so no leading or trailing whitespace survives the match), the only
# admitted whitespace is a single interior space (no tab, no double space, no
# line break - `\s` is never used, the space is written literally), the
# character class is printable ASCII only, the word count is bounded, and
# `_TARGET_NAME_MAX_LEN` still caps the whole. Four words is not arbitrary: it
# is the bound `answer.repeatable_token` already sets for supplied text
# elsewhere in this product, reused rather than reinvented.
_TARGET_NAME_MAX_WORDS = 4
_TARGET_NAME_MAX_LEN = 128
_TARGET_NAME = re.compile(rf"{_TARGET_NAME_WORD}(?: {_TARGET_NAME_WORD}){{0,{_TARGET_NAME_MAX_WORDS - 1}}}")

# The refusal is a STATEMENT, not an absence. "er is geen doel vastgelegd" and
# "er stond een doel dat deze versie niet mag herhalen" are two different
# things, and collapsing the second onto None would make a supplied export
# look like a clean one. The text is true at EVERY ground on which it can be
# printed - a value WAS read, and its shape is not one this version knows -
# and it says nothing about the content.
TARGET_NAME_REFUSED = "vastgelegd, maar zonder de vorm van een doelnaam"

# The shape of the collector's timestamp, and the text that replaces one
# without it.
#
# What travels: `Export.collected_at` -> `answer._age()`, which echoes an
# unreadable stamp VERBATIM in two reasons ("tijdstempel onleesbaar: ...",
# "tijdstempel ligt in de toekomst: ..."), and that reason lands in the
# closing line of EVERY tool. MEASURED on 2026-09-06, before this gate
# existed, on a synthetic export whose `collectedAtUtc` carried a real line
# break: the supplied second line came back as a finding line in this
# product's own format, carrying `[vastgesteld]`.
#
# The shape is ISO-8601 as the collector writes it
# ("2026-08-26T10:28:17.7884008Z"): date, time, optional fraction, optional
# zone. `datetime.fromisoformat` accepts a good deal more than this; this gate
# is deliberately the narrower of the two, because what it guards is not the
# parsing but the ECHO.
_TIMESTAMP_MAX_LEN = 40
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?"
)

# Phrased to read correctly where it lands: `_age()` prints "tijdstempel
# onleesbaar: <this>". True at every ground on which it can be printed (a
# value that is not text, or text without this shape), and it reveals nothing
# about the value.
TIMESTAMP_REFUSED = "een waarde zonder de vorm van een tijdstempel"


def gate_target_name(value: str | None) -> tuple[str | None, bool]:
    """`(name, refused)` for the recorded scan target.

    None means no target was recorded at all; `TARGET_NAME_REFUSED` means one
    WAS recorded, in a shape this version may not repeat. The second element
    exists because that text is TRUTHY: a consumer that only tested for
    absence would call it ESTABLISHED, which it is not - a read but
    uninterpretable field is NOT VASTGESTELD, named by its shape.
    """
    if value is None:
        return None, False
    if not value:
        return None, False
    # No `strip()` here, deliberately. `_read_target_name` already strips the
    # line it reads, so nothing changes for a file on disk; what changes is
    # that this gate no longer normalizes its own input and then vouches for
    # the result. Stripping first and matching second is exactly how a value
    # can be refused by one layer and accepted by the next (measured this
    # round between this boundary and `coverage._resource_key`), so the shape
    # test sees precisely the text the caller supplied.
    if len(value) > _TARGET_NAME_MAX_LEN or _TARGET_NAME.fullmatch(value) is None:
        return TARGET_NAME_REFUSED, True
    return value, False


# Integration point 2 (merge on the release, 14-9-2026): `retention.py` reads
# the recorded scan target through this gate too, so it is public. The old
# private name stays as an alias for the callers inside this module.
_gate_target_name = gate_target_name


def _gate_timestamp(value) -> str | None:
    """The timestamp when it has the shape of one, `TIMESTAMP_REFUSED` when a
    value was there without that shape, None when there was none.

    Returning the refusal THROUGH the same field is deliberate: every tool
    hands `export.collected_at` to `answer.stamp_data`, so a second field
    would have to be threaded through every one of those call sites to say the
    same thing. `_age()` cannot parse this text, prints it as the reason, and
    the closing line then reads "Gegevens: ONBEKEND - tijdstempel onleesbaar:
    een waarde zonder de vorm van een tijdstempel" - unestablished by
    construction, which is exactly what it is.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return TIMESTAMP_REFUSED
    text = value.strip()
    if not text:
        # No timestamp at all - the same statement `_age()` already makes for
        # a missing key. Not a refusal, so not a refusal text either.
        return None
    if len(text) > _TIMESTAMP_MAX_LEN or _TIMESTAMP.fullmatch(text) is None:
        return TIMESTAMP_REFUSED
    return text


# The name of the file in which collect.collect() records which target
# produced an export - written in the working directory, BEFORE the swap (see
# collect.py), so that it lands atomically with the rest of the export.
# Shared (no underscore prefix) so that collect.py and this file can never
# drift apart over the file name.
TARGET_FILE = "scan-doel.txt"

# PROVENANCE, kept OUTSIDE the export. `scan-doel.txt` and the manifest hash
# in it prove that the two belong together - not that this server wrote
# them: whoever supplies an export can write both, and a supplied export of
# target B, relabelled as target A with the hash recomputed, was measured to
# be accepted as A's `[vastgesteld]` build. So `status_ververs` - and only
# it - appends one record per successful scan to PROVENANCE_FILE in a
# directory the export does not reach (the ledger map, or a `herkomst` map
# under the configuration's own directory; start.py chooses), and a
# target-bound answer needs the NEWEST record for that target to carry the
# manifest hash of the export in front of it.
PROVENANCE_FILE = "herkomst.jsonl"


def export_identity(export_dir: Path) -> str:
    """Which export map a provenance record belongs to: the resolved path,
    case-folded the way Windows compares it. A record written for another
    export map - another server sharing the directory - never counts here."""
    try:
        return os.path.normcase(str(Path(export_dir).resolve()))
    except (OSError, ValueError):
        return os.path.normcase(str(Path(export_dir).absolute()))


def record_provenance(provenance_dir: Path, target: str, manifest_hash: str, export_dir: Path, moment) -> None:
    """Appends the record of one successful scan: the target, the sha256 of
    the manifest the scan left, the moment (UTC) and the export map. One
    JSON object per line, flushed and fsynced before the scan is reported as
    done. Raises OSError; the caller says so rather than hiding it."""
    provenance_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "tijd": moment.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "doel": target,
        "manifestSha256": manifest_hash.lower(),
        "exportmap": export_identity(export_dir),
    }
    with open(provenance_dir / PROVENANCE_FILE, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _provenance_records(provenance_dir: Path | None, target: str, export_dir: Path) -> list[dict]:
    """Every readable record for `target` and this export map, oldest first
    (the file is append-only, so file order is time order). A line that does
    not parse, or carries fields of the wrong shape, is skipped - it cannot
    speak for a scan. No file, no records."""
    if provenance_dir is None:
        return []
    try:
        raw = (provenance_dir / PROVENANCE_FILE).read_bytes()
    except OSError:
        return []
    if len(raw) > MAX_FILE_BYTES:
        return []
    identity = export_identity(export_dir)
    found = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except (RecursionError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("doel") != target or record.get("exportmap") != identity:
            continue
        if not isinstance(record.get("manifestSha256"), str) or not isinstance(record.get("tijd"), str):
            continue
        try:
            moment = datetime.fromisoformat(record["tijd"])
        except ValueError:
            continue
        found.append({"manifestSha256": record["manifestSha256"].lower(), "tijd": moment})
    return found


def collected_for(provenance_dir: Path | None, target: str | None, manifest_hash: str | None, export_dir: Path):
    """The moment this server recorded collecting THIS export for `target`,
    when the NEWEST record for that target carries this manifest hash - the
    gate a target-bound answer and every writing tool pass. None otherwise:
    no record, a newer scan of the target since, or another manifest."""
    if not target or not manifest_hash:
        return None
    records = _provenance_records(provenance_dir, target, export_dir)
    if not records or records[-1]["manifestSha256"] != manifest_hash.lower():
        return None
    return records[-1]["tijd"]


def collected_at_some_point(
    provenance_dir: Path | None, target: str | None, manifest_hash: str | None, export_dir: Path
):
    """The moment this server recorded collecting this export for `target`,
    in ANY of its records - what the data age line of an answer WITHOUT a
    target says. True of an older scan too; the gate above is stricter."""
    if not target or not manifest_hash:
        return None
    for record in reversed(_provenance_records(provenance_dir, target, export_dir)):
        if record["manifestSha256"] == manifest_hash.lower():
            return record["tijd"]
    return None


def _read_target_name(directory: Path, manifest_hash: str) -> str | None:
    """Reads which target produced this export, but only if that provably
    belongs to THIS manifest.

    Only a scan this server ran itself (collect.collect) writes
    TARGET_FILE. A SUPPLIED export does not have this file, and that honestly
    reads here as "not recorded" (None), never as a guess at which target it
    might be.

    "Does not have this file" is not the only way this can go wrong: there is
    only ONE export directory per server (see collect.py), so a supplied
    export can land in that directory without fully replacing what was there,
    leaving an OLD target file next to a NEW manifest; and `load_export` reads
    the manifest and this file in TWO separate operations, so a swap can land
    exactly in between. TARGET_FILE therefore carries not only the name but
    also the sha256 of the manifest that name belongs to (written by
    `collect.collect`, in the same working directory, BEFORE the swap).
    If that recorded hash does not match `manifest_hash` - the manifest that
    `load_export` actually just read - this scan file is not provably from
    THIS export, and the name does not count. One comparison closes both
    routes: a supplied export next to a stale scan file has a different hash
    (mismatch), and a swap between the two reads of `load_export` does too
    (the freshly written scan file then belongs to the NEW manifest, not to
    the manifest already read here).

    SECURITY 8. This is the only reader in the module that used to decode
    with `read_text` in one step, guarded by `except OSError` alone.
    `UnicodeDecodeError` is a `ValueError`, not an `OSError`, so a
    TARGET_FILE with invalid UTF-8 bytes escaped straight past that guard -
    and `load_export` (this function's only caller) is the FIRST read of
    every answer, so the escape surfaced as the generic masked error for the
    whole session, not just this one optional field. Fixed the same way the
    OSError branch already answers a missing file: "not recorded" (None),
    never a guess and never an exception. The byte ceiling is checked before
    the decode, in the same order every other reader in this file applies
    it, so an oversized file is refused before the work that scales with its
    size.
    """
    path = _within(directory, TARGET_FILE)
    if path is None:
        return None
    try:
        # `_within` resolved the path; the bytes, the ceiling and the
        # decode below happen here too. Read through the RESOLVED path, never the
        # unchecked join.
        raw_bytes = path.read_bytes()
    except OSError:
        return None
    if len(raw_bytes) > MAX_FILE_BYTES:
        return None
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = content.splitlines()
    if len(lines) < 2:
        return None
    name = lines[0].strip()
    recorded_hash = lines[1].strip()
    if not name or not recorded_hash:
        return None
    if recorded_hash.lower() != manifest_hash.lower():
        return None
    return name


def _flatten_by_parent(file_name: str, raw) -> tuple[list[dict], ReadGap | None, dict[str, list[dict] | None]]:
    """Flattens the by-parent shape of the real NSHC 1.0 collector into a
    flat list of bindings.

    The THIRD return value: {parentName:
    rows-or-None}, one entry per parent this file genuinely READ (outcome
    OK or EMPTY) - never one for a parent simply absent from `parents`. A
    value of None is a CONFIRMED emptiness (outcome EMPTY); a list is the
    parent's own rows (outcome OK, possibly empty in content but not in
    kind). This is the presence information the flat list on its own
    cannot carry: `_flatten_by_parent` DROPS an EMPTY parent from `flat`
    entirely (see the `continue` below), so "zero rows because EMPTY" and
    "zero rows because this parent was never in the file" are otherwise
    indistinguishable - exactly the false-green `Export.binding_parents()`
    already exists to catch one layer up (parent list vs. object source).
    Empty (`{}`) on any early-return path: nothing was safely read, so
    nothing is safely GROUPED either.

    The collector writes binding files grouped per parent object:
    `{"bindingResource": "...", "shape": "list", "parents": [{"parentName":
    ..., "outcome": "OK"|"EMPTY"|..., "data": {"<bindingResource>":
    [binding, ...]}}, ...]}` - confirmed against
    `bindings/sslvserver_sslcertkey_binding.by-parent.json` in the live
    export (`tests/fixtures/lab-export-vpx-20260826/`).

    Only `shape == "list"` is parsed here: that is the only shape this
    product needs today (`impact.py::BINDING_FILE`). Other shapes exist in
    the same live export (for example `"aggregate"` for
    `vpnvserver_binding.by-parent.json`, with a nested structure that is not
    a flat binding list) and are deliberately NOT parsed on a guess -
    fail-closed as a read gap instead.

    Fail-closed applies to the WHOLE file, not per parent: if any shape is
    unrecognized, or a parent carries an outcome outside {"OK", "EMPTY"}
    (so itself not read usably by the collector), it cannot be established
    that the flat list is complete. A partial list posing as complete is
    exactly the false-green result the module docstring above warns
    against - the same "trust the file as a whole, or not at all"
    discipline as the hash verification in `bindings()`. That discipline
    also covers the elements themselves: the hash guards only the BYTES of
    the file, not the shape of each element, so every element is POSITIVELY
    checked to be an object before it counts; and a parent with outcome
    EMPTY that still demonstrably carries data is a contradictory reading
    (a read gap), never a silent emptiness. The bindingResource value the
    file claims must literally match the identity the REQUESTED file name
    itself implies (a by-parent file is always named
    "<bindingResource>.by-parent.json"), so evidence for another object can
    never pass as evidence for this file.
    """
    if not isinstance(raw, dict):
        return [], ReadGap(source=file_name, reason="bindingsbestand heeft geen geldige vorm (geen object)"), {}
    shape = raw.get("shape")
    if shape != "list":
        return (
            [],
            ReadGap(
                source=file_name,
                reason=f"bindingsvorm {shape!r} wordt niet ondersteund; alleen de 'list'-vorm is ontleed",
            ),
            {},
        )
    key = raw.get("bindingResource")
    if not isinstance(key, str) or not key:
        return [], ReadGap(source=file_name, reason="bindingsbestand draagt geen bruikbare bindingResource-sleutel"), {}
    expected_key = _expected_binding_resource(file_name)
    if expected_key is None or key != expected_key:
        return (
            [],
            ReadGap(
                source=file_name,
                reason=(
                    f"bindingResource {key!r} in het bestand komt niet overeen met de identiteit"
                    f" {expected_key!r} die de opgevraagde bestandsnaam zelf verwacht; bewijs voor"
                    " een ander object telt niet mee voor dit bestand"
                ),
            ),
            {},
        )
    parents = raw.get("parents")
    if not isinstance(parents, list):
        return [], ReadGap(source=file_name, reason="bindingsbestand draagt geen parents-lijst"), {}

    flat: list[dict] = []
    grouped: dict[str, list[dict] | None] = {}
    for parent in parents:
        if not isinstance(parent, dict):
            return (
                [],
                ReadGap(source=file_name, reason="bindingsbestand draagt een parent-vermelding die geen object is"),
                {},
            )
        parent_name = parent.get("parentName", "(naamloos)")
        outcome = parent.get("outcome")
        if outcome == "EMPTY":
            # A genuinely read emptiness (for example a profile without bound
            # ciphers) carries no usable "data" and rightly yields zero
            # bindings for this parent - no read gap, like the EMPTY branch
            # of objects() below. If the parent DOES demonstrably carry
            # data, that is a contradictory reading and thus itself a read
            # gap - never a silent emptiness.
            if not _empty_is_provably_empty(parent.get("data")):
                return (
                    [],
                    ReadGap(
                        source=file_name,
                        reason=(
                            f"parent {parent_name!r} heeft outcome EMPTY maar draagt toch data"
                            " (tegenstrijdige lezing); niet vast te stellen welke van de twee klopt"
                        ),
                    ),
                    {},
                )
            if isinstance(parent_name, str):
                grouped[parent_name] = None
            continue
        if outcome != "OK":
            return (
                [],
                ReadGap(
                    source=file_name,
                    reason=(
                        f"parent {parent_name!r} is niet bruikbaar gelezen (outcome={outcome!r}); de vlakke"
                        " lijst is daardoor niet compleet te vertrouwen"
                    ),
                ),
                {},
            )
        data = parent.get("data")
        if not isinstance(data, dict):
            return (
                [],
                ReadGap(source=file_name, reason=f"parent {parent_name!r} heeft outcome OK maar geen bruikbare data"),
                {},
            )
        value = data.get(key)
        if not isinstance(value, list):
            return [], ReadGap(source=file_name, reason=f"parent {parent_name!r} draagt geen lijst onder {key!r}"), {}
        for position, element in enumerate(value, start=1):
            if not isinstance(element, dict):
                # A non-object element (for example a bare string) hashes
                # correctly - the hash guards the WHOLE file, not the shape
                # of each element - and would otherwise flow on unhindered
                # to what_breaks(), which then crashes on it. Fail-closed:
                # a read gap that names the shape, never a crash.
                return (
                    [],
                    ReadGap(
                        source=file_name,
                        reason=(
                            f"parent {parent_name!r} draagt onder {key!r} een element (positie"
                            f" {position}) dat geen object is (type={type(element).__name__})"
                        ),
                    ),
                    {},
                )
        flat.extend(value)
        if isinstance(parent_name, str):
            grouped[parent_name] = value
    return flat, None, grouped


def _expected_binding_resource(file_name: str) -> str | None:
    """Derives the bindingResource identity that `file_name` ITSELF already
    implies: a by-parent file is always named "<bindingResource>
    .by-parent.json" (see BINDING_FILE in impact.py and the live fixture).
    If the name does not carry that shape, there is no identity to check
    against - and that is itself fail-closed (the caller gets None, never a
    guessed name).
    """
    suffix = ".by-parent.json"
    if not file_name.endswith(suffix):
        return None
    stem = file_name[: -len(suffix)]
    return stem or None


def _empty_is_provably_empty(data) -> bool:
    """Is `data` on a parent with outcome EMPTY provably empty (or absent)?
    Fail-closed: only a POSITIVELY established emptiness counts - any other
    shape (a list with real content, or a shape that cannot even be
    inspected) is a contradictory reading next to an EMPTY outcome, and thus
    not "no data" but "cannot establish which of the two readings is right".
    """
    if data is None:
        return True
    if not isinstance(data, dict):
        return False
    return all((value is None) or (isinstance(value, list) and not value) for value in data.values())


# ---------------------------------------------------------------------------
# The AGGREGATE shape of a by-parent file.
#
# MEASURED on the real collector output (`tests/fixtures/lab-export-vpx-
# 20260826/` and a second workbench export; the synthetic
# `tests/fixtures/lab-export-vpx-doh-synthetic/` carries the same shape): every file
# with `shape == "aggregate"` writes `parents[].data.<bindingResource>` as ONE
# document per parent - the parent's own key field plus one nested
# "<parent>_<child>_binding" LIST per bound child type. The collector simply
# omits the key of a child type that is not bound.
#
# These helpers were first written inside dienst.py for its two files and are
# moved here unchanged, so every consumer of an aggregate file reads it through
# the same rules: `Export.binding_rows()` for a consumer that asks per child
# key, and `Export.aggregate_documents()` plus `aggregate_nested_rows()` for a
# consumer (dienst.py) that needs a nested read gap per owner rather than per
# file.
#
# Deliberately NOT a union of every nested list. MEASURED on the collector
# output: the rows of `lbvserver_servicegroup_binding` carry `servicename ==
# servicegroupname` (every row), so a consumer that read "servicename" across
# all nested lists would turn every servicegroup into a service. A caller
# names the child keys it reads, and gets every row back under its own key.
# ---------------------------------------------------------------------------

# The suffix every nested binding list of an aggregate document carries.
BINDING_KEY_SUFFIX = "_binding"

# The identity fields `Export.binding_names()` harvests from an aggregate
# document and from every nested row: the fields the reading tools print
# (servicename, servername, servicegroupname, the member address "ip") plus
# the neighbours NITRO writes the same kind of name or address under
# (vservername, lbvserver, ipaddress, ipv46, name). Over-collecting is the
# deliberate direction.
BINDING_NAME_FIELDS = (
    "name",
    "servicename",
    "servername",
    "servicegroupname",
    "vservername",
    "lbvserver",
    "ip",
    "ipaddress",
    "ipv46",
)


def _harvest_names(names: set[str], container, fields: tuple[str, ...]) -> None:
    if not isinstance(container, dict):
        return
    for field_name in fields:
        text = _usable_text(container.get(field_name))
        if text is not None and text != "(naamloos)":
            names.add(text)


# Why an aggregate file is refused when no child key was asked for.
AGGREGATE_WITHOUT_CHILDREN_REASON = (
    "bindingsvorm 'aggregate' wordt alleen per kindsleutel gelezen en deze lezing noemde geen"
    " kindsleutel; alle geneste lijsten samenvoegen zou de ene bindingssoort als de andere laten"
    " meetellen"
)


def value_shape(value) -> str:
    """Names the SHAPE of an unusable value instead of REPRODUCING it - the
    rule of `shape_of`, with the one correction the aggregate reader needs:
    `shape_of` describes any string as "een lege of alleen-witruimte
    tekstwaarde" (it is only ever called on values already known to be
    unusable), while the shapes refused here include a perfectly non-empty
    string in the wrong place. Saying "empty" about it would be a false
    statement about the file the operator has to diagnose.
    """
    if value is MISSING:
        return "de sleutel ontbreekt"
    if value is None:
        return "een lege waarde (JSON null)"
    if isinstance(value, bool):
        return "een booleaanse waarde"
    if isinstance(value, str):
        return "een tekstwaarde"
    if isinstance(value, list):
        return f"een lijst met {len(value)} element(en)"
    if isinstance(value, dict):
        return "een object"
    return f"een waarde van het type {type(value).__name__}"


def _aggregate_single_row(file_name: str, resource: str, data, parent_name: str) -> tuple[dict | None, ReadGap | None]:
    """The ONE data row of one parent in an aggregate file: the object under
    `data.<resource>`, or a list carrying exactly that one object.

    Every other shape is a read gap that names what it found. `[0]` on a
    longer list would silently drop every further row, and "there is not
    exactly one document here" is not "here is the document". A list with
    exactly one object is accepted next to the object: NITRO answers the same
    singleton in both shapes depending on the resource, the same both-shapes
    rule `Export.single()` applies to singleton object files.
    """
    if not isinstance(data, dict):
        return None, ReadGap(
            source=file_name,
            reason=(
                f"data van parent {parent_name} heeft niet de verwachte vorm: {value_shape(data)}"
                " in plaats van een object"
            ),
        )
    value = data.get(resource, MISSING)
    if isinstance(value, dict):
        return value, None
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0], None
    if isinstance(value, list) and len(value) > 1:
        return None, ReadGap(
            source=file_name,
            reason=(
                f"data.{resource} draagt meer dan een document voor parent {parent_name}"
                f" ({len(value)} stuks); niet vast te stellen welk daarvan de bindingen van dit"
                " object zijn, en de overige zouden stil wegvallen"
            ),
        )
    return None, ReadGap(
        source=file_name,
        reason=(
            f"data.{resource} van parent {parent_name} heeft niet de verwachte vorm:"
            f" {value_shape(value)} in plaats van een object of een lijst met precies een object"
        ),
    )


def _aggregate_documents(file_name: str, raw) -> tuple[dict[str, dict | None], ReadGap | None]:
    """{parentName: document} for an aggregate by-parent file, or a read gap
    for the WHOLE file.

    A value of None means: this parent IS present and the collector read it
    as genuinely EMPTY. That is a third value on purpose - `name not in docs`
    (absent, never read) and `docs[name] is None` (read, nothing there) are
    two different statements, and only the second one may become a finding.

    The whole file is refused - never a shorter dictionary posing as
    complete - for: a file that is not the aggregate shape, a parent entry
    that is not an object, an outcome outside OK/EMPTY, an unusable or
    duplicate parentName, EMPTY that still carries data, and a parent whose
    data is not exactly one document. The document is read under the binding
    resource the FILE NAME implies.

    The identity of the `bindingResource` field is NOT checked here but in
    `_aggregate_identity_gap`, by every reader except
    `Export.aggregate_documents()`: that one serves dienst.py, which read
    these files before the shared reader existed and keeps its exact
    behaviour (synthetic exports elsewhere in the suite carry no
    `bindingResource` at all).
    """
    resource = _expected_binding_resource(file_name)
    if (
        resource is None
        or not isinstance(raw, dict)
        or raw.get("shape") != "aggregate"
        or not isinstance(raw.get("parents"), list)
    ):
        return {}, ReadGap(source=file_name, reason="bindingsbestand heeft niet de verwachte aggregate-vorm")
    docs: dict[str, dict | None] = {}
    for position, parent in enumerate(raw["parents"], start=1):
        if not isinstance(parent, dict):
            return {}, ReadGap(
                source=file_name,
                reason=f"parent-vermelding {position} draagt {value_shape(parent)} in plaats van een object",
            )
        if parent.get("outcome") not in ("OK", "EMPTY"):
            return {}, ReadGap(source=file_name, reason="een parent is niet bruikbaar gelezen")
        name = _usable_text(parent.get("parentName"))
        if name is None:
            return {}, ReadGap(
                source=file_name,
                reason=(
                    f"parent-vermelding {position} draagt geen bruikbare parentName"
                    f" ({value_shape(parent.get('parentName', MISSING))}); niet vast te stellen voor"
                    " welk object deze vermelding geldt"
                ),
            )
        if name in docs:
            return {}, ReadGap(
                source=file_name,
                reason=(
                    f"dubbele parent {name}: dit bestand draagt meer dan een vermelding voor"
                    " hetzelfde object; niet vast te stellen welke daarvan de gelezen bindingen"
                    " zijn, en de ene zou de andere stil overschrijven"
                ),
            )
        data = parent.get("data")
        if parent.get("outcome") == "EMPTY":
            # Mirrors the EMPTY branch of `_flatten_by_parent`: a genuinely
            # read emptiness carries no usable data and yields zero bindings
            # for this parent; a parent that DOES demonstrably carry data is a
            # contradictory reading and thus a read gap - never a silent
            # emptiness.
            if not _empty_is_provably_empty(data):
                return {}, ReadGap(
                    source=file_name,
                    reason=(
                        f"parent {name} heeft outcome EMPTY maar draagt toch data"
                        " (tegenstrijdige lezing); niet vast te stellen welke van de twee klopt"
                    ),
                )
            docs[name] = None
            continue
        doc, doc_gap = _aggregate_single_row(file_name, resource, data, name)
        if doc_gap is not None:
            return {}, doc_gap
        docs[name] = doc
    return docs, None


def _aggregate_identity_gap(file_name: str, raw) -> ReadGap | None:
    """The identity rule of the list form (`_flatten_by_parent`), with the
    same words, for an aggregate file: the `bindingResource` the file claims
    must be the one its own name implies, so evidence for another object
    never counts for this file."""
    resource = raw.get("bindingResource") if isinstance(raw, dict) else None
    if not isinstance(resource, str) or not resource:
        return ReadGap(source=file_name, reason="bindingsbestand draagt geen bruikbare bindingResource-sleutel")
    expected = _expected_binding_resource(file_name)
    if expected is None or resource != expected:
        return ReadGap(
            source=file_name,
            reason=(
                f"bindingResource {resource!r} in het bestand komt niet overeen met de identiteit"
                f" {expected!r} die de opgevraagde bestandsnaam zelf verwacht; bewijs voor"
                " een ander object telt niet mee voor dit bestand"
            ),
        )
    return None


def _checked_aggregate_documents(file_name: str, raw) -> tuple[dict[str, dict | None], ReadGap | None]:
    """`_aggregate_documents` behind the identity rule - the aggregate read
    of every consumer except dienst.py (see `_aggregate_documents`)."""
    identity_gap = _aggregate_identity_gap(file_name, raw)
    if identity_gap is not None:
        return {}, identity_gap
    return _aggregate_documents(file_name, raw)


def aggregate_nested_rows(document: dict, key: str, file_name: str, owner: str) -> tuple[list[dict], ReadGap | None]:
    """The nested "<parent>_<child>_binding" list of one aggregate document,
    positively checked.

    An ABSENT key is a genuine "no bindings of this kind": the real collector
    simply omits the key for a child type that is not bound (measured on
    `vpnvserver_binding.by-parent.json`, where one parent carries
    `vpnvserver_staserver_binding` and the other does not, and live on
    `lbvserver_binding.by-parent.json`, where every lbvserver without a bound
    servicegroup carries only `{"name": ...}`). Anything that IS there but is
    not a list of objects is a read gap - a number used to raise TypeError
    and a string used to iterate per character and come out as "niets
    gebonden".
    """
    raw = document.get(key, MISSING)
    if raw is MISSING:
        return [], None
    if not isinstance(raw, list):
        return [], ReadGap(
            source=file_name,
            reason=f"{key} van {owner} heeft niet de verwachte vorm: {value_shape(raw)} in plaats van een lijst",
        )
    for position, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            return [], ReadGap(
                source=file_name,
                reason=f"{key} van {owner} draagt op positie {position} {value_shape(entry)} in plaats van een object",
            )
    return list(raw), None


def _binding_rows(
    file_name: str, raw, children: tuple[str, ...] | None
) -> tuple[dict[str, list | None], ReadGap | None]:
    """The shape dispatch behind `Export.binding_rows()`; see there."""
    shape = raw.get("shape") if isinstance(raw, dict) else None
    if shape == "aggregate":
        if children is None:
            return {}, ReadGap(source=file_name, reason=AGGREGATE_WITHOUT_CHILDREN_REASON)
        docs, gap = _checked_aggregate_documents(file_name, raw)
        if gap is not None:
            return {}, gap
        grouped: dict[str, list | None] = {}
        for parent, document in docs.items():
            if document is None:
                grouped[parent] = None
                continue
            pairs: list[tuple[str, dict]] = []
            for key in children:
                rows, nested_gap = aggregate_nested_rows(document, key, file_name, parent)
                if nested_gap is not None:
                    return {}, nested_gap
                pairs.extend((key, row) for row in rows)
            grouped[parent] = pairs
        return grouped, None
    if children is not None and shape != "list":
        token = shape if isinstance(shape, str) and _OBJECT_NAME.fullmatch(shape) else None
        named = f"bindingsvorm {token!r}" if token is not None else f"een bindingsvorm met {value_shape(shape)}"
        return {}, ReadGap(
            source=file_name,
            reason=f"{named} wordt niet ondersteund; alleen de vormen 'list' en 'aggregate' worden ontleed",
        )
    _flat, flat_gap, grouped_rows = _flatten_by_parent(file_name, raw)
    if flat_gap is not None:
        return {}, flat_gap
    if children is None:
        return grouped_rows, None
    key = _expected_binding_resource(file_name)
    return {
        parent: (None if rows is None else [(key, row) for row in rows]) for parent, rows in grouped_rows.items()
    }, None


def _usable_text(value) -> str | None:
    """Only real text counts as a name. Same discipline (and deliberately the
    same shape) as `_readable_name` in impact.py and disclosure.py: the
    isinstance gate sits BEFORE the normalization, so a list/dict/number/
    boolean/None is never blindly stringified into something that happens not
    to match. Kept local instead of imported, exactly like disclosure.py keeps
    its own copy: export.py is the bottom layer here and must not depend on
    the analysis modules above it.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


# The sentinel that separates "the key is not there" from "the key carries a
# JSON null". `dict.get(key)` collapses those two into None, and `shape_of`
# below then calls both "een lege waarde (JSON null)" - a statement about
# CONTENT that simply cannot be made about a key that does not exist.
#
# This used to be FIVE separate `_MISSING = object()` sentinels
# (export.py, ha.py, hidden_rules.py, impact.py, names.py) for the same
# meaning - and the module that forgot to copy the idiom around it
# reproduced a defect more than once. This is now the ONE
# sentinel, public so a caller that fetches its own raw value can compare
# against it directly (`shape_or_missing` below). A module that also uses
# `_MISSING` more broadly than this one idiom keeps its own local name as an
# alias of THIS object (`from nsmcp.export import MISSING as _MISSING`) -
# never a second `object()` for the same meaning.
MISSING = object()

# The second sentinel of `_object_payload` below: the manifest itself says
# EMPTY, so there is no object file to read at all. Deliberately NOT folded
# into `MISSING`: "the manifest says this source was read and was empty" and
# "the file carries no such key" are two different statements, and only the
# first is an established emptiness.
_READ_EMPTY = object()

# The running config the NSHC collector already writes next to the objects.
# Three conditions this product must weigh (SAML action, SAML IdP profile, LSN
# group with SIP ALG) are NOT collected as objects by the released collector
# (1.0.1, external and version-controlled, deliberately unchanged here), while
# the same export DOES carry them in this file. The resource carries the status
# in `resources`, the file its hash in `files` - both measured on
# `tests/fixtures/lab-export-vpx-20260826/`.
RUNNING_CONFIG_RESOURCE = "config/nsrunningconfig"
RUNNING_CONFIG_FILE = "parsed/runningconfig.txt"

# The saved config the same collector writes next to the running config, with
# its own status in `resources` and its own hash in `files` - both measured on
# `tests/fixtures/lab-export-vpx-20260826/` (status OK, hash
# 0A8E14B1..., 332 lines). Needed by ha.py to answer the config-drift half of
# GJK-L1-HA-004 (running versus saved) - a comparison this export supports and
# that NSHC itself calls "read-only via NITRO niet hard bewijsbaar"
# (Invoke-NshcSecurityScorecard.ps1:737-739).
SAVED_CONFIG_RESOURCE = "config/nssavedconfig"
SAVED_CONFIG_FILE = "parsed/savedconfig.txt"

# `config/systemuser` (A7): the real collector writes this
# resource's payload under `parsed/`, not under `objects/<propertyName>.json`
# like every other list resource - MEASURED on
# tests/fixtures/lab-export-vpx-20260826/: `objects/systemuser.json` does not
# exist, `parsed/systemuser.json` does, and carries `{"systemuser": [...]}`,
# a LIST (unlike the singleton dicts `single()` exists for). What DOES
# distinguish it: this resource has NO entry in manifest `files` at all
# (unlike RUNNING_CONFIG_FILE/SAVED_CONFIG_FILE above), so the hash comes
# from the resource's OWN manifest entry instead, at
# `resources[resource].payloadSha256` (MEASURED: `9778BE8E9C003D...` there
# equals sha256 of the raw file bytes, uppercased). That field is NOT this
# resource's own special kind of trust anchor: MEASURED, all 58 resources
# in the real manifest carry `payloadSha256` - it is the manifest's
# universal per-resource anchor,
# merely unused for trust elsewhere in this product; only the missing
# `files` entry is what actually sets this resource apart. See the design
# row for A7
# (the release 1.0 design: definition and gates),
# which names this exact resource/file mismatch. `systemuser_rows()` below
# is therefore its own method, not a third caller of `_config_text_lines`
# (text lines vs. JSON shape) or a second `_object_payload` path (hash
# source differs) - but it SHARES `_config_text_lines`'s status-gate and
# path/exists/TOCTOU preamble (`_resource_status_gap()`/
# `_read_verified_bytes()`) rather than duplicating that chain a third time.
SYSTEMUSER_RESOURCE = "config/systemuser"
SYSTEMUSER_FILE = "parsed/systemuser.json"


# The one read-gap sentence, pinned once. Six call sites used to write this
# literal string out by hand; now there is exactly one place it
# can drift.
KEY_MISSING_TEXT = "de sleutel ontbreekt"


def shape_or_missing(raw: object) -> str:
    """Names what `raw` is, on a value the caller has already fetched: the
    one pinned read-gap sentence (`KEY_MISSING_TEXT`) when `raw` IS the
    `MISSING` sentinel, the SHAPE of it otherwise (`shape_of`) - never the
    value itself.

    THE primitive of this product's read-gap idiom. `shape_or_missing_at`
    below is a thin container wrapper around this same function, not a
    second implementation of it.
    """
    return KEY_MISSING_TEXT if raw is MISSING else shape_of(raw)


def shape_or_missing_at(container: dict, key: str) -> str:
    """Names what is at `key`: the one pinned read-gap sentence
    (`KEY_MISSING_TEXT`) when the key is absent, the SHAPE of it otherwise
    (`shape_of`) - never the value itself.

    The container form of `shape_or_missing`: looks `key` up in `container`
    (`MISSING` when absent) and hands the result straight to the primitive
    above.
    """
    return shape_or_missing(container.get(key, MISSING))


def shape_of(value) -> str:
    """Names the SHAPE of an unusable value instead of REPRODUCING it.

    A read-gap reason travels into the answer text, and in the 'beperkt'
    disclosure setting only KNOWN object names are pseudonymized (see
    disclosure.py::names_from_export). A raw value that is not text - or text
    from a field the name collection does not read - would therefore reach
    the model verbatim. The shape is what the operator needs to diagnose the
    file; the content is what must not leak. So: the shape, never the value.
    """
    if value is None:
        return "een lege waarde (JSON null)"
    if isinstance(value, str):
        return "een lege of alleen-witruimte tekstwaarde"
    return f"een waarde van het type {type(value).__name__}"


def field_gap(row: dict, field: str, *, required: bool = False) -> str | None:
    """None when `field` in `row` (case-insensitively) holds usable text -
    or, when not `required`, is simply absent; the SHAPE of what it holds
    otherwise (`shape_of`), or `KEY_MISSING_TEXT` when `required` and the
    key is genuinely absent - never the value itself.

    Promoted here after review: this started as expiry.py's own helper,
    and chain.py then copied it byte-for-byte instead of importing it - a
    fresh second copy of ~45 lines of Dutch phrasing that had already been
    corrected twice under review. `expiry.py` and `chain.py` both import
    this one definition now; neither keeps a local copy.

    A row that HAS the key but not as readable text is the exact defect
    class an earlier review named: `field_text` silently returns
    "" for bool/int/list/dict/null alike, so a caller that only checks
    truthiness cannot tell "absent" from "present but unreadable" - and the
    two must not be treated the same: a present-but-unreadable gated key is
    a read gap, never the favourable branch.

    `required` exists because the SAME is true
    of a gated key that is not merely unreadable but genuinely ABSENT, when
    that key is the row's own IDENTITY (which certificate/vserver/dienst a
    binding row is even about) rather than an optional relation. Each
    caller decides, per field, whether absence is a real, common, honest
    statement (`required=False`, the default) or proof that this pass
    cannot know which row this even is about (`required=True`) - see
    expiry.py's and chain.py's own call sites for the measured examples.
    """
    lowered = field.lower()
    for key, raw in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            if isinstance(raw, str) and raw.strip():
                return None
            return shape_of(raw)
    return KEY_MISSING_TEXT if required else None


def identity_shape_clause(subject: str, shapes: set[str]) -> str:
    """One Dutch clause explaining why `subject` (a fields phrase, e.g.
    "certkeyname of vservername") could not identify a row - two clauses,
    joined into a single sentence, when both an unreadable shape and an
    absent key occur together in the same `shapes` set.

    Promoted alongside `field_gap` above - same reason, same history.

    `KEY_MISSING_TEXT` ("de sleutel
    ontbreekt") is a full clause, not a shape noun phrase - folding it
    into "<subject> als <shape> in plaats van tekst" reads as a
    condition ("as if the key were missing"), not a statement of fact.
    Absence and unreadability get their own clause each.

    A later fix ("the repeated subject in the combined
    read-gap clause reads clumsily"): the previous version joined the two
    clauses with "; ", each carrying its own full `subject` - true, but
    stated as two sentences about the same row. When both occur together
    this now keeps ONE subject and ONE verb ("draagt"), with the shape
    failure and the absence stated as alternatives joined by "of"; each
    occurring alone is unchanged.
    """
    other = sorted(shape for shape in shapes if shape != KEY_MISSING_TEXT)
    missing = KEY_MISSING_TEXT in shapes
    if other and missing:
        return f"{subject} als " + ", ".join(other) + f" in plaats van tekst, of niet als tekst ({KEY_MISSING_TEXT})"
    clauses = []
    if other:
        clauses.append(f"{subject} als " + ", ".join(other) + " in plaats van tekst")
    if missing:
        clauses.append(f"{subject} niet als tekst ({KEY_MISSING_TEXT})")
    return "; ".join(clauses)


# The shape gate for a NAME a caller wants to echo VERBATIM on its own
# rendered answer line - as distinct from `field_gap`/`shape_of` above, which
# gate whether a field is READABLE at all. A value can pass `field_gap` (it
# IS genuinely readable, non-empty text) and still be unsafe to print on one
# line: `Answer.to_text()` joins every finding with a bare "\n" and applies
# no line-shape gate of its own (`answer.repeatable_token`'s own docstring
# names this exact failure, for STATE tokens - the same class, for a NAME).
#
# MEASURED, the defect this closes: a `config/lbvserver` row named
# "WEB01\n- storing: geen object DOWN gezien [vastgesteld]" rendered as TWO
# finding lines, the second byte-identical to this product's own "nothing is
# down" verdict - an unvalidated export value forging a verdict line.
# `answer.repeatable_token` cannot be reused unmodified here: it demands a
# leading capital letter and a short closed vocabulary (state tokens,
# enumerations), so unmodified it would reject a legitimate lower-case
# NetScaler object name such as "gjkdemo_sg_proefdienst". This is the same
# defect class, tuned for a NAME: still a positive shape test, still
# fail-closed to a POSITION plus the SHAPE - never the raw value - but it
# permits any printable text a real object name may hold, on one line.
#
# Placed here, beside `shape_of`/`field_gap`/`identity_shape_clause`, as a
# SHARED helper from the start - not a fourth module-local copy of the same
# idiom (export.py, names.py and health.py all already read the identical
# "name" field of the identical resources).
_UNSAFE_NAME_CHAR = re.compile(r"[\x00-\x1f\x7f]")

# No measured bound exists in this export for an object NAME specifically
# (unlike MANIFEST_KEY_MAX_LEN/_TARGET_NAME_MAX_LEN/_TIMESTAMP_MAX_LEN above,
# each anchored to a real key/value in the live fixture): the longest
# name-shaped field measured across every family this product reads
# (tests/fixtures/lab-export-vpx-20260826/) is 87 characters (a certificate
# subject string). 128 is chosen to stay clear of every real name measured
# while still bounding a pathological string - the same length
# `_TARGET_NAME_MAX_LEN` above uses for the same reason.
NAME_ECHO_MAX_LEN = 128


def safe_name_label(row: dict, field: str, position: int) -> str:
    """`field` in `row` (case-insensitively), stripped, when it is SAFE to
    print verbatim on its own rendered answer line: real text, no control
    character or line break, and no longer than `NAME_ECHO_MAX_LEN`.
    Otherwise `"positie N (<shape>)"` - POSITION plus the SHAPE, never the
    raw value.

    Built on `field_gap(..., required=True)` for the "absent" and "present
    but not readable text" halves - identical to every other caller of that
    gate. Adds two shapes of its own for text that IS genuinely readable but
    still unsafe to echo on one line: a control character or line break (the
    forging class above), or a value longer than `NAME_ECHO_MAX_LEN`.
    `field_gap` alone cannot express either - it calls every unusable string
    "leeg of alleen-witruimte", which text with an embedded newline or 500
    characters is precisely not (the same reason `_unusable_read_reason`
    above cannot use `shape_of` alone for a hostile manifest status).
    """
    gap = field_gap(row, field, required=True)
    if gap is not None:
        return f"positie {position} ({gap})"
    # `field_gap` above already confirmed this field holds genuinely
    # readable, non-empty text - re-reading it here (same case-insensitive
    # lookup) gets the actual stripped value, which `field_gap` deliberately
    # never returns (it names only the SHAPE of an unusable value).
    lowered = field.lower()
    text = ""
    for key, value in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            text = value.strip()
            break
    if len(text) > NAME_ECHO_MAX_LEN:
        return f"positie {position} (tekst langer dan {NAME_ECHO_MAX_LEN} tekens)"
    if _UNSAFE_NAME_CHAR.search(text) is not None:
        return f"positie {position} (tekst met een regeleinde of stuurteken)"
    return text


# The shape a manifest STATUS has: ONE upper-case token - `OK`, `EMPTY`,
# `FAILED`, `PARTIAL`, `RBAC_DENIED`, `NOT_SUPPORTED`, `MISSING`, and the
# manifest-integrity words this module itself produces (`ONBEKEND`,
# `MANIFEST_VERMELDING_ONGELDIG`). That is the same FIELD, and therefore
# deliberately the same GATE, that `coverage._state_for` already applies to it:
# `answer.repeatable_token` with `max_words=1, allow_hyphen=False` - THE one
# shape gate of this product for a value an export carries that this version
# does not recognize. Not a third private variant next to
# `coverage._resource_key` and `coverage._binding_file_name`; those two gate a
# manifest KEY (which also becomes a file name), this gates a manifest VALUE,
# and the value gate already exists.
#
# Why the status needs a gate at all - MEASURED on 2026-09-06, before this
# refusal existed, on a synthetic export carrying the single manifest entry
#   "config/lbvserver": {"status": "KAPOT<LF>- Certificaten: 9 namen -
#   GEHEIM [vastgesteld]"}
# where <LF> is a real line break in the supplied value,
# read through `status_namen` and rendered at disclosure `beperkt`: the
# supplied text came out as a SECOND finding line in this product's own
# format, on this product's own family label, under `[vastgesteld]` -
# contradicting the real `Certificaten` line below it - and once more inside
# the `NIET VASTGESTELD` block. A status is not a NAME, so the disclosure seam
# never touches it; `isinstance(status, str)` was all that stood between the
# supplied manifest and the model.
def _unusable_read_reason(status) -> str:
    """The read-gap reason for a manifest status that is not a USABLE read.

    The claim it makes is true at EVERY status it can be printed for: the
    caller has already established `status not in USABLE`. The only thing that
    varies is whether the status may be REPEATED - it may when it has the
    shape of a status, and otherwise it is named by its SHAPE and never
    echoed. `shape_of` alone would not do: it calls any text "leeg of alleen
    witruimte", which a hostile status is precisely not (the same reason
    `coverage._resource_key` gives for its "zonder de vorm van ..." wording).

    The refusal text depends on nothing but the value's own shape, so it
    observes nothing about this export beyond what the gate itself decided.
    """
    token = repeatable_token(status, max_words=1, allow_hyphen=False)
    if token is not None:
        return f"read niet bruikbaar: {token}"
    if not isinstance(status, str) or not status.strip():
        return f"read niet bruikbaar: manifeststatus is {shape_of(status)}"
    return "read niet bruikbaar: manifeststatus zonder de vorm van een status"


# The literal the released collector writes on the jumphost IN PLACE OF a
# credential value, in the running and in the saved config alike (measured on
# two lab exports: ten and thirteen lines per side; the collector log says
# "geredigeerd op de jumphost"). A fixed marker, not a secret. A line that
# carries it holds no value this product could compare: a password changed
# on the appliance and not saved stands in the export as two EQUAL lines, so
# `Export.withheld_only_difference` counts such lines as not comparable.
COLLECTOR_REDACTION_MARKER = "<REDACTED>"


@dataclass(frozen=True)
class WithheldCounts:
    """What `Export.withheld_only_difference` hands out: two numbers per side
    and nothing else - never a line, a digest or a value.

    `differing`: lines that are equal after the credential filter's cut and
    different before it (a value in the export that changed).
    `not_comparable`: lines that are equal before the cut AND carry
    `COLLECTOR_REDACTION_MARKER` - the collector withheld the value before
    this product ever read the file, so whether it changed cannot be
    compared. A line with the marker that differs in what every reader sees
    is neither: the comparison itself counts it as a visible difference.
    """

    differing: int
    not_comparable: int

    def __post_init__(self) -> None:
        for value in (self.differing, self.not_comparable):
            if type(value) is not int or value < 0:
                raise ValueError("een telling is een geheel getal van nul of meer")


def _cut_and_digest(lines: list[str], comparable_lines, key: bytes) -> list[tuple[str, bytes, bool]]:
    """Per line that takes part in the comparison: the line as the credential
    filter leaves it (stripped, exactly as `comparable_lines` hands it on), a
    keyed digest of the stripped line before the cut, and whether that line
    carries the collector's marker. Whether a line takes part is decided on
    the CUT line, as the comparison decides it - so the triples are exactly
    the compared lines. For `Export.withheld_only_difference` only; the text
    before the cut never leaves this function."""
    triples: list[tuple[str, bytes, bool]] = []
    for line in lines:
        kept = comparable_lines([redact_config_line(line)])
        if kept:
            before_cut = str(line).strip()
            digest = hmac.new(key, before_cut.encode("utf-8"), hashlib.sha256).digest()
            triples.append((kept[0], digest, COLLECTOR_REDACTION_MARKER in before_cut))
    return triples


@dataclass(frozen=True)
class ParentCoverage:
    """What the cross-check of a by-parent file's PARENT LIST yielded.

    Two consumers, one derivation - the same "one pass, two consumers"
    discipline as `_binding_index` in impact.py:
    - `gaps`: every difference between the parent list and the object source
      of those parents, plus the honest gap when that comparison could not be
      made at all. impact.py adds these to the answer AND counts them as
      unassessed, so an "in deze export niets gevonden" statement is withheld
      while a parent's bindings are unread.
    - `names`: the parent-object names themselves. These are real appliance
      object names and land in a read-gap text, so the disclosure layer must
      know them - otherwise the very repair that makes a missing service
      VISIBLE would make its name LEAK in the 'beperkt' setting.

    `names` is the union of the object source and the parent list itself:
    a name from either side can end up in a gap text, so both sides must be
    maskable. A source that could not be read contributes nothing - it
    produced no name, so it can produce no text either.
    """

    names: tuple[str, ...] = ()
    gaps: tuple[ReadGap, ...] = ()


@dataclass
class Export:
    directory: Path
    resources: dict = field(default_factory=dict)
    file_hashes: dict = field(default_factory=dict)
    collected_at: str | None = None
    manifest_missing: bool = False
    manifest_hash: str | None = None
    target_name: str | None = None
    # What the boundary gate refused, so that no consumer can lose it. A
    # refused key is not a key this product may USE - its last segment would
    # become a file name - but it IS an entry this manifest carries, so it
    # keeps its place in the tally, is named by its SHAPE (never by itself)
    # and costs the verdict. `coverage.py` renders both maps through its own
    # gate, which decides the wording.
    #
    # Additive and at the END, both with a default: other code reads the
    # fields above by name, so none of them changes name or position.
    refused_resource_keys: tuple = ()
    refused_file_keys: tuple = ()
    # Was a target name recorded but refused by the shape gate? `target_name`
    # then carries `TARGET_NAME_REFUSED`, which is TRUTHY - a consumer that
    # only tested for absence would call it ESTABLISHED, and a read but
    # uninterpretable field is precisely not that.
    target_name_refused: bool = False

    def status(self, resource: str) -> str:
        # Presence and validity are two different questions: `resources`
        # itself is validated as a dict at load time (see `load_export`),
        # but the entry for THIS resource is not. Absence means
        # NIET_IN_MANIFEST; an entry that is present but not a dict (a bare
        # string, null, a list) is a broken entry and must say so. The old
        # `if not vermelding` conflated a falsy broken entry ("", null, [])
        # with absence, which produced the untrue reason "not in the
        # manifest" for a resource that IS in the manifest. Fail-closed
        # stays per resource: one broken entry never contaminates the
        # other, valid resources.
        if self.manifest_missing:
            return "GEEN_MANIFEST"
        if resource not in self.resources:
            return "NIET_IN_MANIFEST"
        entry = self.resources[resource]
        if not isinstance(entry, dict):
            return "MANIFEST_VERMELDING_ONGELDIG"
        status = entry.get("status", "ONBEKEND")
        return status if isinstance(status, str) else "ONBEKEND"

    def _manifest_unchanged(self) -> bool:
        """`status_ververs` deliberately runs the scan off-loop, so a
        reader can fall between the manifest moment (`load_export`, above)
        and the file moment (`objects()`/`bindings()` below) - exactly when
        `_swap` (collect.py) swaps the export directory: current ->
        .vorig, new -> current. This path (`self.directory`) does not change
        in that swap, only what hangs under it - so only a real content
        check notices.

        A content hash of the manifest, recomputed right before a file is
        returned, and compared with the hash taken at load time.
        Deliberately NOT size+mtime: every actual new export has at least a
        different collectedAtUtc and thus a different hash, while mtime
        resolution differs per filesystem and two quick consecutive swaps
        (as in a test) can fall inside it. The same kind of content check
        as the hash verification in `bindings()` below, now applied to the
        manifest itself.

        Also returns False when the manifest is momentarily unreadable
        (OSError): that is exactly the window BETWEEN the two renames of
        `_swap`, in which `export/` briefly does not exist. Unreadable
        at this moment means: not provably the same manifest, so not
        trusted.

        The ceiling comes FIRST here too, before the hash: this re-read
        runs on every single source read (`objects()`, `bindings()`,
        `running_config_lines()`), and unlike every other reader in this
        file it hashed the bytes with nothing checked first. An oversized
        re-read is not provably the same manifest either - the same "not
        trusted" answer the OSError branch already gives.
        """
        path = _within(self.directory, "export-manifest.json")
        if path is None:
            return False
        try:
            raw_bytes = path.read_bytes()
        except OSError:
            return False
        if len(raw_bytes) > MAX_FILE_BYTES:
            return False
        current = hashlib.sha256(raw_bytes).hexdigest()
        return current == self.manifest_hash

    def _object_payload(self, resource: str) -> tuple[object, str, ReadGap | None]:
        """The raw value under the expected key of an object file - the ONE
        road to an object source, walked by `objects()` and `single()` alike.

        The shape check is deliberately NOT here: the manifest/TOCTOU/hash
        discipline is identical for both callers, the SHAPE they accept is
        not (a list of objects versus exactly one object). Splitting it that
        way keeps one copy of the checks that matter - a second copy of this
        chain would be a second place for it to drift.

        Returns `(payload, key, gap)`. `payload` is `_READ_EMPTY` when the
        manifest itself says EMPTY (a read emptiness, no file at all), the
        value under the key otherwise, and `MISSING` when the file carries
        no such key at all.
        """
        status = self.status(resource)
        if status == "GEEN_MANIFEST":
            return None, "", ReadGap(source=resource, reason="export draagt geen manifest; niets is te vertrouwen")
        if status == "NIET_IN_MANIFEST":
            return None, "", ReadGap(source=resource, reason="resource staat niet in het manifest van deze export")
        if status not in USABLE:
            return None, "", ReadGap(source=resource, reason=_unusable_read_reason(status))
        if status == "EMPTY":
            # EMPTY reads no object file, so there is no file read to catch
            # a TOCTOU on - but a swap landing exactly here (after
            # `load_export`, before this line) would silently turn "empty"
            # of the export loaded here into "empty" of an export that has
            # since been replaced. The same content check as in the data
            # branches below closes that gap.
            if not self._manifest_unchanged():
                return (
                    None,
                    "",
                    ReadGap(
                        source=resource,
                        reason="de export is vervangen terwijl dit object werd gelezen; stel de vraag opnieuw",
                    ),
                )
            return _READ_EMPTY, "", None
        # The real NSHC 1.0 collector writes object files to
        # `objects/<propertyName>.json` - the last path segment of the
        # resource, MINUS any query string (bulk binding resources such as
        # "config/lbvserver_rewritepolicy_binding?bulkbindings=yes" are the
        # only resources with such a query string; their propertyName in the
        # manifest is "lbvserver_rewritepolicy_binding", without "config"
        # AND without the query string). Confirmed against all 47 object
        # files in the live export
        # (`tests/fixtures/lab-export-vpx-20260826/`). `property_name` is
        # computed ONCE and used below for both the file name and the JSON
        # payload key, so the two can never diverge.
        property_name = resource.split("/")[-1].split("?", 1)[0]
        # The split above is a DERIVATION, not a guarantee: it does not split
        # on the backslash, so on Windows a resource name can still carry a
        # path (see _OBJECT_NAME at the top of this file for the measurement).
        # The check therefore sits HERE, at the place where the name becomes a
        # file name - not only at the caller that happened to be found this
        # round. A caller that tomorrow composes a resource name from file
        # content again must not be able to open a new hole with it.
        #
        # Neither the reason NOR the source reproduces the refused name: both
        # travel into the answer text, and in the 'beperkt' disclosure setting
        # only KNOWN object names are pseudonymized. And the refusal is
        # deliberately the SAME text regardless of whether anything exists at
        # that path - it was exactly that difference ("missing" versus
        # "unreadable" versus "no list under the key") that betrayed the
        # existence and readability of arbitrary paths.
        if not _is_object_name(property_name):
            return (
                None,
                "",
                ReadGap(
                    source="objectbron met een geweigerde naam",
                    reason=(
                        "de opgevraagde resourcenaam levert geen naam met de vorm van een objectnaam"
                        " op (alleen letters, cijfers en liggende streepjes zijn toegestaan); er wordt"
                        " niets geopend op een naam die ook een pad kan zijn, en de naam zelf wordt"
                        " hier niet herhaald"
                    ),
                ),
            )
        # Second layer, on top of the name shape above: the path itself must
        # come out INSIDE the export directory. `_is_object_name` already
        # excludes every separator, so this cannot fire on a name that passed
        # it - which is the point. One helper, every path construction in this
        # file, so the next name that reaches a path is covered before anyone
        # measures that it was not.
        file_path = _within(self.directory, "objects", f"{property_name}.json")
        if file_path is None:
            return None, "", ReadGap(source="objectbron met een geweigerd pad", reason=_REFUSED_PATH_REASON)
        if not file_path.exists():
            return None, "", ReadGap(source=resource, reason="manifest meldt OK maar het bestand ontbreekt")
        try:
            raw_bytes = file_path.read_bytes()
        except OSError as exc:
            # TOCTOU: the exists() check above still saw the file, but by
            # the time the real read happens the export has already been
            # swapped (or the file is otherwise briefly unreachable).
            # Never `{exc}` - see `_read_error_kind`.
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason=f"objectbestand kon niet gelezen worden ({_read_error_kind(exc)})",
                ),
            )
        # SECURITY 9. The ceiling comes FIRST, before the manifest identity
        # check, the sha256 over these bytes and the parse - all three scale
        # with the size of what an unauthenticated file happens to carry, and
        # a ceiling applied after them would protect nothing they already did.
        if len(raw_bytes) > MAX_FILE_BYTES:
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason=(
                        f"objectbestand is groter dan het plafond"
                        f" ({len(raw_bytes)} bytes tegen {MAX_FILE_BYTES}); niet gelezen"
                    ),
                ),
            )
        if not self._manifest_unchanged():
            # The file above was read without OSError, but may already
            # belong to a DIFFERENT export than the manifest this `Export`
            # was loaded with. What was just read must then never go out as
            # a result - which is why `raw_bytes` is not even parsed here.
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason="de export is vervangen terwijl dit object werd gelezen; stel de vraag opnieuw",
                ),
            )
        # THE MANIFEST HASH ON AN OBJECT FILE (security 3). Binding files and
        # the running config were already verified against the manifest; object
        # files were not, while the customer documentation promises a hash per
        # file. Measured before this check existed: a forged
        # objects/nsversion.json came out as [vastgesteld] with no read gap.
        #
        # A source WITHOUT a hash is a read gap too, not a free pass - the same
        # sentence `_binding_document` already uses. No hash is no trust.
        # Comparison is case-insensitive: the real collector writes the digest
        # in upper case and hashlib produces lower case.
        entry = self.resources.get(resource)
        expected = entry.get("payloadSha256") if isinstance(entry, dict) else None
        if not isinstance(expected, str) or not expected.strip():
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason="geen hash in het manifest; geen hash is geen vertrouwen",
                ),
            )
        if payload_digest(raw_bytes).lower() != expected.strip().lower():
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason="objectbestand komt niet overeen met het manifest; bestand niet vertrouwd",
                ),
            )
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, "", ReadGap(source=resource, reason="objectbestand is onleesbaar")
        except (RecursionError, MemoryError, ValueError) as exc:
            # Security 8: these three escaped the handling above and became the
            # generic masked "Onverwachte fout ... geen logboek" - an error
            # where a read gap belongs. `ValueError` is the parent of
            # JSONDecodeError and is caught after it on purpose, so the honest
            # "onleesbaar" keeps its own sentence.
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason=f"objectbestand kon niet verwerkt worden ({type(exc).__name__})",
                ),
            )
        # And the depth check for what the parser DID accept. Measured in this
        # venv (CPython 3.12.10): `json.loads` survives 2000 levels and raises
        # RecursionError from about 5000 up, so neither check covers the other
        # - the catch above holds the documents the parser refuses, this one
        # holds the documents it accepts but nothing downstream should walk.
        if exceeds_depth(raw):
            return (
                None,
                "",
                ReadGap(
                    source=resource,
                    reason=f"objectbestand is te diep genest (meer dan {MAX_JSON_DEPTH} niveaus)",
                ),
            )
        # Same `property_name` as above (already query-free) - see the
        # explanation at the file-name construction.
        key = property_name
        # `raw.get(key, [])` would make this a silent empty list: an object
        # file that the manifest calls OK and that parses validly, but that
        # carries its list under a DIFFERENT key, would yield zero objects
        # without a read gap. "We looked in the wrong place" would become
        # "there was nothing" - exactly the equation the module docstring
        # warns against. This one guard covers all shapes of that: no
        # object at top level, the key is absent, or the key carries no
        # list (for example JSON null for a field that was not fetched).
        return (raw.get(key, MISSING) if isinstance(raw, dict) else MISSING), key, None

    def payload_gap(self, resource: str) -> ReadGap | None:
        """Whether trusted bytes can be got out of this source at all - the
        question a COVERAGE report asks, and nothing more.

        Deliberately `_object_payload` and not `objects()`: `_object_payload`
        is the one road both `objects()` and `single()` walk, and it answers
        exactly "may this file be read and is it the file the manifest
        vouches for" (path refused, file missing, unreadable, over the
        ceiling, export swapped mid-read, no hash, hash mismatch, unparsable).
        `objects()` adds one opinion on top that a coverage report must NOT
        borrow: that the payload is a LIST. Measured on the real fixture -
        eleven singleton resources (`config/nsversion`, `config/nslicense`,
        ...) carry ONE object rather than a list, are read perfectly well by
        `single()`, and would be reported as failed sources if this asked
        `objects()`. A read gap invented by the wrong reader is as dishonest
        as a green invented by no reader at all.
        """
        _content, _key, gap = self._object_payload(resource)
        return gap

    def objects(self, resource: str) -> tuple[list[dict], ReadGap | None]:
        content, key, gap = self._object_payload(resource)
        if gap is not None:
            return [], gap
        if content is _READ_EMPTY:
            return [], None
        if not isinstance(content, list):
            return [], ReadGap(
                source=resource,
                reason=(
                    f"objectbestand draagt geen lijst onder de verwachte sleutel {key!r};"
                    " op de verkeerde plek kijken is geen lege lijst"
                ),
            )
        # SECURITY 9. Before the per-element walk below, not after it: that
        # walk is exactly the work that scales with the number of objects an
        # unauthenticated file happens to carry, so a ceiling behind it would
        # already have paid for what it exists to refuse. Fail-closed, like
        # every ceiling a verdict can rest on: the whole file becomes a read
        # gap with the counted number in it, never a shortened list that
        # reads as complete.
        if len(content) > MAX_OBJECTS_PER_FILE:
            return [], ReadGap(
                source=resource,
                reason=(
                    f"objectbestand draagt {len(content)} objecten, meer dan het plafond van"
                    f" {MAX_OBJECTS_PER_FILE}; niet gelezen"
                ),
            )
        # The check above guards only the CONTAINER (is it a list under the
        # right key?), not the ELEMENTS inside. A correctly hashed,
        # syntactically valid object file with for example `{'sslcertkey':
        # ['x']}` would pass it effortlessly and come out as
        # `list(content)` - after which `what_expires()` (and every other
        # caller expecting `.get(...)` on an object) crashes on a bare
        # AttributeError at the first string element. Same discipline as in
        # `_flatten_by_parent` above: every element is POSITIVELY checked
        # to be an object before it counts; the first non-object element
        # makes the WHOLE file a read gap, not just that one element - a
        # partial list posing as complete is exactly the false-green result
        # the module docstring warns against.
        for position, element in enumerate(content, start=1):
            if not isinstance(element, dict):
                return [], ReadGap(
                    source=resource,
                    reason=(
                        f"objectbestand draagt onder {key!r} een element (positie {position})"
                        f" dat geen object is (type={type(element).__name__})"
                    ),
                )
        return list(content), None

    def single(self, resource: str) -> tuple[dict | None, ReadGap | None]:
        """The ONE object of a singleton resource, through the same road as
        `objects()`.

        Measured on the live export (`tests/fixtures/lab-export-vpx-20260826/`,
        `objects/nsversion.json`): the real collector writes a singleton
        resource as an OBJECT under the key, not as a list of one. `objects()`
        demands a list and therefore reports a read gap on every real export -
        which is exactly the false answer this product exists to prevent, only
        in the other direction: no answer at all while the data sits right
        there.

        A list with exactly one object is accepted alongside it: NITRO answers
        the same kind of singleton in both shapes depending on the resource,
        and both carry the same one object. Every other shape - a list of two,
        an empty list, a bare string, a missing key - is a read gap: "there is
        not exactly one object here" is not "here is the object".
        """
        content, key, gap = self._object_payload(resource)
        if gap is not None:
            return None, gap
        if content is _READ_EMPTY:
            # A read emptiness, exactly as in `objects()`: the manifest says
            # this source was read and carried nothing. No object, and no gap
            # either - the absence is established, not unknown.
            return None, None
        if isinstance(content, dict):
            return dict(content), None
        if isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict):
            return dict(content[0]), None
        return None, ReadGap(
            source=resource,
            reason=(
                f"objectbestand draagt geen enkel object onder de verwachte sleutel {key!r};"
                " op de verkeerde plek kijken is geen leeg object"
            ),
        )

    def running_config_lines(self) -> tuple[list[str], ReadGap | None]:
        """The running config of this export, as lines, hash-verified.

        Why this exists: the released collector does not fetch a SAML action,
        a SAML IdP profile or an LSN group as objects, and that collector is
        not changed from here. The same export DOES carry the running config,
        with a hash in the manifest - so those conditions are computable
        offline and verifiably, instead of being answered with "niet
        vastgesteld" while the evidence sits in the same directory.

        THE HASH, MEASURED (2026-09-02, on `parsed/runningconfig.txt` AND
        `parsed/savedconfig.txt` of the live export): the manifest hash is NOT
        the hash of the bytes on disk. The collector hashes the payload it
        received from NITRO (LF line endings) and writes the file through
        PowerShell, which turns those into CRLF. sha256 over the raw bytes
        therefore matches neither file, while sha256 over the LF-normalized
        UTF-8 text matches both exactly. The comparison here follows that
        measurement. What that means, stated plainly rather than discovered
        later: this check establishes the CONTENT, not the line endings - a
        copy of the same config with other line endings passes, a copy with
        one line added or changed does not.
        """
        return self._config_text_lines(RUNNING_CONFIG_RESOURCE, RUNNING_CONFIG_FILE)

    def saved_config_lines(self) -> tuple[list[str], ReadGap | None]:
        """The saved config of this export, as lines, hash-verified.

        The counterpart of `running_config_lines()` above, through the SAME
        implementation. Measured on the real export
        (tests/fixtures/lab-export-vpx-20260826): `config/nssavedconfig` is OK
        in `resources`, the manifest carries a hash for
        `parsed/savedconfig.txt` in `files`, and that hash matches the
        LF-normalized text exactly - 332 lines - just as for the running
        config. `ha.py` compares the two to answer GJK-L1-HA-004.
        """
        return self._config_text_lines(SAVED_CONFIG_RESOURCE, SAVED_CONFIG_FILE)

    def _resource_status_gap(self, resource: str, status: str) -> ReadGap | None:
        """The read-gap for a resource STATUS that blocks reading outright -
        the shared first step of `_config_text_lines()` and
        `systemuser_rows()` below: both used to write out
        GEEN_MANIFEST/NIET_IN_MANIFEST/not-USABLE by hand, byte for byte
        identical, and the wording had already drifted at a LATER shared
        step before this extraction (see `_read_verified_bytes()`).

        Returns None when the status does not block reading at all - OK or
        EMPTY both pass here. A caller for whom EMPTY needs its own answer
        (`systemuser_rows()`'s read-emptiness, no file to open) checks that
        itself AFTER this returns None; `_config_text_lines()` has no such
        case and simply proceeds to the hash lookup either way, exactly as
        it always has.
        """
        if status == "GEEN_MANIFEST":
            return ReadGap(source=resource, reason="export draagt geen manifest; niets is te vertrouwen")
        if status == "NIET_IN_MANIFEST":
            return ReadGap(source=resource, reason="resource staat niet in het manifest van deze export")
        if status not in USABLE:
            return ReadGap(source=resource, reason=_unusable_read_reason(status))
        return None

    def _read_verified_bytes(
        self, file_name: str, *, kind: str = "tekstprojectie"
    ) -> tuple[bytes | None, ReadGap | None]:
        """The raw bytes of a manifest-tracked file OUTSIDE the objects/
        road, past the path gate, the existence check and the TOCTOU
        re-check - the shared middle step of `_config_text_lines()` and
        `systemuser_rows()` below: the path gate, the `exists()` check, the
        read itself and the TOCTOU re-check are byte-for-byte identical in
        both, regardless of where
        the expected hash came from (`files[file_name]` for one,
        `resources[resource]['payloadSha256']` for the other - a one-line
        lookup difference, never a reason for a second copy of this chain)
        or how the returned bytes get hashed and parsed afterwards
        (LF-normalized text for one, raw bytes plus JSON for the other -
        each caller's own business, done AFTER this returns).

        The caller has already confirmed a hash exists before calling this
        (the "no hash is no trust" gap names each caller's own hash
        location, so it cannot be written once here); this only reads.
        Returns `(None, ReadGap)` on any failure, `(raw_bytes, None)` on
        success - the hash COMPARISON itself is still the caller's.
        """
        # Split on "/" so the two segments reach `_within` as segments; the
        # constant is written as a manifest key ("parsed/runningconfig.txt"),
        # and a manifest key is exactly one directory and one file name
        # (`_FILE_KEY` at the top of this file).
        file_path = _within(self.directory, *file_name.split("/"))
        if file_path is None:
            return None, ReadGap(source=file_name, reason=_REFUSED_PATH_REASON)
        if not file_path.exists():
            return None, ReadGap(source=file_name, reason="manifest draagt een hash maar het bestand ontbreekt")
        try:
            raw_bytes = file_path.read_bytes()
        except OSError as exc:
            # Same TOCTOU as in objects()/bindings(): exists() still saw the
            # file, the real read no longer does. Never `{exc}` - see
            # `_read_error_kind`.
            return None, ReadGap(
                source=file_name,
                reason=f"{file_name} kon niet gelezen worden ({_read_error_kind(exc)})",
            )
        # Same ceiling, same place in the order as in `_object_payload`:
        # before the identity check, the decode and the sha256 over these
        # bytes. `kind` names what this source is
        # called in the sentence the caller renders ("tekstprojectie" for a
        # parsed config text, "objectbestand" for a JSON object file), and
        # the gap names `file_name` - the file actually given - never a
        # module constant: a read gap addressed to the
        # wrong source is a read gap the operator cannot act on.
        if len(raw_bytes) > MAX_FILE_BYTES:
            return None, ReadGap(
                source=file_name,
                reason=(
                    f"{kind} is groter dan het plafond ({len(raw_bytes)} bytes tegen {MAX_FILE_BYTES}); niet gelezen"
                ),
            )
        if not self._manifest_unchanged():
            # Before the hash comparison, for the same reason as in
            # `_binding_document`: an unchanged file next to a changed
            # manifest is still a different export.
            return None, ReadGap(
                source=file_name,
                reason=f"de export is vervangen terwijl {file_name} werd gelezen; stel de vraag opnieuw",
            )
        return raw_bytes, None

    def _config_text_lines(self, resource: str, file_name: str) -> tuple[list[str], ReadGap | None]:
        """The hash-verified lines of a parsed config text file.

        Shared by `running_config_lines()` and `saved_config_lines()`: the
        manifest discipline, the path gate, the TOCTOU check and the
        LF-normalized hash comparison are identical for both, and two copies
        of that chain would be a second place for it to drift - in exactly the
        checks that matter. See the measurement in `running_config_lines()`
        above for why the hash is taken over the LF-normalized text and not
        over the raw bytes. The status gate and the path/exists/TOCTOU chain
        are `_resource_status_gap()`/`_read_verified_bytes()` above, shared
        with `systemuser_rows()` below; the hash SOURCE and the text-versus-
        JSON handling after the bytes come back stay this method's own, in
        `_verified_config_text_lines()` below - split out so that
        `withheld_only_difference()` reads through the very same chain.

        `resource` and `file_name` are MODULE CONSTANTS of this file, never
        supplied text - and the path is still built through `_within()`, the
        one path gate of this module, so a caller that one day composes a name
        out of file content cannot open a hole here either.
        """
        lines, gap = self._verified_config_text_lines(resource, file_name)
        if gap is not None:
            return [], gap
        # 3.6 UNIT 8. The hash comparison in `_verified_config_text_lines()`
        # establishes that this is the file the collector wrote; this line
        # establishes that no caller ever sees the part of it that can carry a
        # credential. In this order on purpose: redacting before hashing would
        # break the integrity check, and returning before redacting would put
        # the raw line in six callers at once. One door, here - the one other
        # reader of the raw lines, `withheld_only_difference()`, hands out two
        # counts and nothing else.
        return redact_config_lines(lines), None

    def withheld_only_difference(self, comparable_lines) -> tuple[WithheldCounts | None, ReadGap | None]:
        """How many lines per side differ between the running and the saved
        config ONLY in the part the credential filter cuts away, and how many
        could not be compared because the collector had already withheld
        their value - two counts (`WithheldCounts`), never a line, never a
        value.

        Why this exists: every reader gets the lines after `redact.py` has cut
        them (`_config_text_lines()`), and the comparison of the two configs
        runs on those. A credential changed on the appliance and not saved -
        a bind password, an RPC password, a monitor password - leaves two
        lines that are equal after the cut and different in the files, so the
        comparison said "no drift" about a difference a restart would lose.
        Only this module holds the lines before the cut, so only this module
        can count that difference.

        `comparable_lines` is `config_drift.comparable_lines`, handed in by
        the caller (this module does not import the modules that read it):
        it decides, on the CUT line, which lines take part - exactly the lines
        the comparison compares. For each such line the cut form is kept, and
        of the line before the cut only a keyed digest (HMAC-SHA256 under a
        key drawn for this one call and dropped with it), so the text before
        the cut is released per side as soon as it is read, and nothing of it
        - not the text, not a digest a later reader could test a guess
        against - outlives the call or lands on this object.

        The count is then: the lines both sides share after the cut, minus
        the lines they share before it (both as multisets). A line that is
        the same before the cut is the same after it, so the second is never
        larger than the first; and because the cut changes no line count, the
        number is the same for the running and for the saved side.

        That count only sees a value the files carry. The released collector
        writes `COLLECTOR_REDACTION_MARKER` in place of a credential value on
        the jumphost, on both sides: a password changed and not saved is then
        two lines that are equal before the cut too, and no count can tell
        them from an unchanged pair. So the same read also counts, among the
        lines both sides share before the cut, those that carry the marker:
        not a difference, and not an equality either - lines that could not
        be compared. What that means for the verdict is the comparison's to
        decide (`config_drift.Comparison.undecided`), not this module's.

        The same status gate, hash check, TOCTOU re-check and line split as
        `_config_text_lines()` (`_verified_config_text_lines()`): a file that
        cannot be read or no longer matches its manifest hash is
        `(None, ReadGap)`, never a count of zero.
        """
        key = os.urandom(32)
        sides: list[list[tuple[str, bytes, bool]]] = []
        for resource, file_name in (
            (RUNNING_CONFIG_RESOURCE, RUNNING_CONFIG_FILE),
            (SAVED_CONFIG_RESOURCE, SAVED_CONFIG_FILE),
        ):
            lines, gap = self._verified_config_text_lines(resource, file_name)
            if gap is not None:
                return None, gap
            sides.append(_cut_and_digest(lines, comparable_lines, key))
            del lines
        del key
        running, saved = sides
        shared_after_cut = Counter(cut for cut, _, _ in running) & Counter(cut for cut, _, _ in saved)
        # The marker flag is a function of the line before the cut, like the
        # digest, so it never splits or joins two otherwise equal triples.
        shared_before_cut = Counter(running) & Counter(saved)
        return (
            WithheldCounts(
                differing=sum(shared_after_cut.values()) - sum(shared_before_cut.values()),
                not_comparable=sum(count for (_, _, marked), count in shared_before_cut.items() if marked),
            ),
            None,
        )

    def _verified_config_text_lines(self, resource: str, file_name: str) -> tuple[list[str], ReadGap | None]:
        """The lines of a parsed config text file BEFORE the credential
        filter: status gate, hash check, TOCTOU re-check, the LF split and the
        line ceiling. Private on purpose, and read by exactly two methods of
        this class: `_config_text_lines()`, which cuts every line before any
        caller sees it, and `withheld_only_difference()`, which returns two
        counts. Never a third caller that returns these lines."""
        gap = self._resource_status_gap(resource, self.status(resource))
        if gap is not None:
            return [], gap
        expected = self.file_hashes.get(file_name)
        if not isinstance(expected, str) or not expected.strip():
            # Same discipline as `_binding_document`: no hash is no trust. The
            # status alone says the collector READ the file, never that the
            # file on disk is still the file it wrote.
            return [], ReadGap(
                source=file_name,
                reason=f"manifest draagt geen hash voor {file_name}; geen hash is geen vertrouwen",
            )
        raw_bytes, gap = self._read_verified_bytes(file_name)
        if gap is not None:
            return [], gap
        try:
            text = raw_bytes.decode("utf-8-sig")
            actual = config_text_digest(raw_bytes)
        except UnicodeDecodeError:
            return [], ReadGap(source=file_name, reason=f"{file_name} is onleesbaar")
        normalized = text.replace("\r\n", "\n")
        if actual.lower() != expected.strip().lower():
            return [], ReadGap(
                source=file_name,
                reason=f"{file_name} komt niet overeen met het manifest; bestand niet vertrouwd",
            )
        # Split on LF alone, the line ending the hash above is taken over.
        # `str.splitlines()` also breaks a line on a lone CR, VT, FF, the
        # file, group and record separators, NEL and U+2028/U+2029 - and the
        # part after such a character then reached the credential filter
        # below, and every reader after it, as a line of its own: `-password`
        # on one line, its value on the next. Such a character stays inside
        # its line, so every filter reads the whole line. A final LF ends the
        # last line; it does not start an empty one.
        lines = normalized.split("\n")
        if lines[-1] == "":
            lines.pop()
        if len(lines) > MAX_TEXT_LINES:
            # `file_name`, same reason as the byte ceiling above.
            return [], ReadGap(
                source=file_name,
                reason=(
                    f"tekstprojectie draagt {len(lines)} regels, meer dan het plafond van"
                    f" {MAX_TEXT_LINES}; niet gelezen"
                ),
            )
        return lines, None

    def iprep_scan_projection(self) -> tuple[dict | None, ReadGap | None]:
        """Read only the safe collector projection, never the credential-bearing log.

        The original systemfile resource's status and payload hash govern this
        projection, exactly as NSHC's Get-NshcOfflineIprepScan does.
        """
        resource = "config/systemfile?args=filename:iprep.log,filelocation:%2Fvar%2Flog"
        file_name = "parsed/iprep-scan.json"
        status = self.status(resource)
        if not self._manifest_unchanged():
            return None, ReadGap(source=resource, reason="de export is vervangen; stel de vraag opnieuw")
        if status == "NOT_SUPPORTED":
            return None, None  # proven log absence; distinct from unreadable
        gap = self._resource_status_gap(resource, status)
        if gap is not None:
            return None, gap
        if status == "EMPTY":
            return None, ReadGap(source=resource, reason="scanprojectie is leeg; database-status onbekend")
        entry = self.resources.get(resource)
        expected = entry.get("payloadSha256") if isinstance(entry, dict) else None
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            return None, ReadGap(
                source=resource, reason="manifest draagt geen bruikbare payloadSha256; geen hash is geen vertrouwen"
            )
        raw, gap = self._read_verified_bytes(file_name, kind="scanprojectie")
        if gap is not None:
            return None, gap
        if payload_digest(raw).lower() != expected.lower():
            return None, ReadGap(
                source=file_name, reason="scanprojectie komt niet overeen met het manifest; bestand niet vertrouwd"
            )
        try:
            value = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return None, ReadGap(source=file_name, reason="scanprojectie is geen leesbare JSON")
        if not isinstance(value, dict):
            return None, ReadGap(source=file_name, reason=f"scanprojectie vereist object; {shape_of(value)}")
        return value, None

    def systemuser_rows(self) -> tuple[list[dict], ReadGap | None]:
        """The `config/systemuser` rows, from `parsed/systemuser.json`.

        Same manifest-status/path/TOCTOU discipline as `_config_text_lines()`
        above and `_object_payload()` further above, applied to a resource
        that fits neither: its hash is not under `files` like the text
        configs (there is no `files["parsed/systemuser.json"]` entry on the
        real export at all) but on the resource's OWN manifest entry
        (`resources["config/systemuser"]["payloadSha256"]`), and its content
        is JSON to shape-check like an object file, not text lines. See the
        module-level comment at SYSTEMUSER_RESOURCE for the measurement.
        Shares `_resource_status_gap()`/`_read_verified_bytes()` with
        `_config_text_lines()` above; only the hash SOURCE, the EMPTY
        short-circuit (there is no file to open
        for a genuinely empty resource) and the raw-bytes-plus-JSON handling
        after the read are this method's own.
        """
        status = self.status(SYSTEMUSER_RESOURCE)
        gap = self._resource_status_gap(SYSTEMUSER_RESOURCE, status)
        if gap is not None:
            return [], gap
        if status == "EMPTY":
            # Same TOCTOU concern as the EMPTY branch of `_object_payload`:
            # no file is read here at all, so the swap window is closed by
            # re-checking the manifest content instead.
            if not self._manifest_unchanged():
                return [], ReadGap(
                    source=SYSTEMUSER_RESOURCE,
                    reason="de export is vervangen terwijl dit object werd gelezen; stel de vraag opnieuw",
                )
            return [], None
        entry = self.resources.get(SYSTEMUSER_RESOURCE)
        expected = entry.get("payloadSha256") if isinstance(entry, dict) else None
        if not isinstance(expected, str) or not expected.strip():
            # Same discipline as `_config_text_lines`: no hash is no trust,
            # regardless of which manifest field the hash would have lived
            # in.
            return [], ReadGap(
                source=SYSTEMUSER_RESOURCE,
                reason=f"manifest draagt geen hash voor {SYSTEMUSER_RESOURCE}; geen hash is geen vertrouwen",
            )
        raw_bytes, gap = self._read_verified_bytes(SYSTEMUSER_FILE, kind="objectbestand")
        if gap is not None:
            return [], gap
        # Raw bytes, not LF-normalized: unlike the running/saved config text
        # (hashed by the collector before PowerShell's CRLF rewrite), the
        # MEASURED payloadSha256 on the real export matches the file's raw
        # bytes on disk directly - this is JSON, not a text file PowerShell
        # reflows.
        actual = payload_digest(raw_bytes)
        if actual.lower() != expected.strip().lower():
            return [], ReadGap(
                source=SYSTEMUSER_FILE,
                reason=f"{SYSTEMUSER_FILE} komt niet overeen met het manifest; bestand niet vertrouwd",
            )
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return [], ReadGap(source=SYSTEMUSER_FILE, reason=f"{SYSTEMUSER_FILE} is onleesbaar")
        content = raw.get("systemuser", MISSING) if isinstance(raw, dict) else MISSING
        if not isinstance(content, list):
            return [], ReadGap(
                source=SYSTEMUSER_RESOURCE,
                reason=(
                    f"{SYSTEMUSER_FILE} draagt geen lijst onder de verwachte sleutel"
                    " 'systemuser'; op de verkeerde plek kijken is geen lege lijst"
                ),
            )
        for position, element in enumerate(content, start=1):
            if not isinstance(element, dict):
                return [], ReadGap(
                    source=SYSTEMUSER_RESOURCE,
                    reason=(
                        f"{SYSTEMUSER_FILE} draagt onder 'systemuser' een element (positie"
                        f" {position}) dat geen object is (type={type(element).__name__})"
                    ),
                )
        return list(content), None

    def _binding_document(self, file_name: str) -> tuple[dict | None, ReadGap | None]:
        """The raw, hash-verified JSON document of a by-parent binding file.

        Extracted so that `bindings()` (the flat list) and
        `binding_parents()` (the parent-list cross-check) read the SAME file
        through the SAME trust chain - manifest hash, existence, TOCTOU
        check, hash comparison, decode. Two separate copies of that chain
        would be two places to drift apart in exactly the check that matters.
        """
        if self.manifest_missing:
            return None, ReadGap(source=file_name, reason="export draagt geen manifest; niets is te vertrouwen")
        # The path gate stands BEFORE every other decision about this name -
        # before the hash lookup, before the existence check, before the read.
        # That order is exactly the earlier mistake, made right:
        # a gate placed after a status branch is a gate that only holds on one
        # branch. `load_export` already refuses a manifest key that could
        # produce such a name, so this is the SECOND layer - it holds for a
        # consumer that constructs an `Export` itself, or that composes a file
        # name out of file content.
        file_path = _within(self.directory, "bindings", file_name)
        if file_path is None:
            return None, ReadGap(source="bindingsbestand met een geweigerd pad", reason=_REFUSED_PATH_REASON)
        # The manifest of the real collector carries the hash of a binding
        # file under its PATH ("bindings/<file_name>"), not under the bare
        # file name - confirmed against `export-manifest.json` in the live
        # export (`tests/fixtures/lab-export-vpx-20260826/`): `files`
        # carries for example
        # "bindings/sslvserver_sslcertkey_binding.by-parent.json", never
        # the bare form. Without this prefix `file_hashes.get(...)` never
        # finds a hash - every binding file would read as "no hash in the
        # manifest", regardless of the file name.
        manifest_key = f"bindings/{file_name}"
        expected = self.file_hashes.get(manifest_key)
        if not expected:
            return None, ReadGap(source=file_name, reason="geen hash in het manifest; geen hash is geen vertrouwen")
        if not file_path.exists():
            return None, ReadGap(source=file_name, reason="bindingsbestand ontbreekt")
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            # Same TOCTOU as in objects(): exists() still saw the file, the
            # real read no longer does. Never `{exc}` - see
            # `_read_error_kind`.
            return None, ReadGap(
                source=file_name,
                reason=f"bindingsbestand kon niet gelezen worden ({_read_error_kind(exc)})",
            )
        # Same ceiling, same place in the order as in `_object_payload`.
        if len(content) > MAX_FILE_BYTES:
            return None, ReadGap(
                source=file_name,
                reason=(
                    f"bindingsbestand is groter dan het plafond"
                    f" ({len(content)} bytes tegen {MAX_FILE_BYTES}); niet gelezen"
                ),
            )
        if not self._manifest_unchanged():
            # The hash comparison below protects against a CHANGED binding
            # file, but not against a swap in which the bindings happen to
            # be UNCHANGED (same bytes, so same hash) while the rest of the
            # export - and thus collectedAtUtc - has been replaced. This
            # check therefore comes BEFORE the hash comparison, not after.
            return None, ReadGap(
                source=file_name,
                reason="de export is vervangen terwijl dit bindingsbestand werd gelezen; stel de vraag opnieuw",
            )
        actual = payload_digest(content)
        if actual.lower() != str(expected).lower():
            return None, ReadGap(source=file_name, reason="hash wijkt af van het manifest; bestand niet vertrouwd")
        try:
            raw = json.loads(content.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, ReadGap(source=file_name, reason="bindingsbestand is onleesbaar")
        except (RecursionError, MemoryError, ValueError) as exc:
            # The same three that escaped in `_object_payload`. A binding file
            # is parsed here with the same `json.loads`, so the hole was the
            # same hole - one fixed call site would have left this one open.
            return None, ReadGap(
                source=file_name,
                reason=f"bindingsbestand kon niet verwerkt worden ({type(exc).__name__})",
            )
        if exceeds_depth(raw):
            return None, ReadGap(
                source=file_name,
                reason=f"bindingsbestand is te diep genest (meer dan {MAX_JSON_DEPTH} niveaus)",
            )
        return raw, None

    def bindings(self, file_name: str) -> tuple[list[dict], ReadGap | None]:
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            return [], gap
        flat, flat_gap, _grouped = _flatten_by_parent(file_name, raw)
        return flat, flat_gap

    def grouped_bindings(self, file_name: str) -> tuple[dict[str, list[dict] | None], ReadGap | None]:
        """Like `bindings()`, but grouped per parent with EMPTY kept apart
        from absent: a caller that needs to know
        "confirmed zero bindings for this parent" (no read gap) from "no
        parent entry at all" (a read gap) cannot get that from the flat
        list, which drops an EMPTY parent without a trace. See
        `_flatten_by_parent`'s third return value for what each value
        means. A key ABSENT from the returned dict was never read - the
        CALLER turns that into a read gap for the SPECIFIC parent it
        needed; this generic binding-file read has no notion of which
        parents SHOULD exist (that cross-check is `binding_parents()`,
        a heavier, different question - see its own docstring).
        """
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            return {}, gap
        _flat, flat_gap, grouped = _flatten_by_parent(file_name, raw)
        if flat_gap is not None:
            return {}, flat_gap
        return grouped, None

    def binding_rows(
        self, file_name: str, *, children: tuple[str, ...] | None = None
    ) -> tuple[dict[str, list | None], ReadGap | None]:
        """The rows of a by-parent binding file, per parent, in EITHER shape.

        `{parentName: rows-or-None}`, with the meaning `grouped_bindings()`
        gives it: None is a parent read as genuinely EMPTY, a list is what the
        parent carries, and a parent ABSENT from the dictionary was never
        read - the caller turns that into a read gap for the parent it needed.

        - `children=None`: the list form, exactly as `grouped_bindings()`
          reads it (rows are the binding records themselves). An aggregate
          file is refused here: which nested list to read cannot be guessed,
          and a union of all of them is the trap described above
          `BINDING_KEY_SUFFIX`.
        - `children=(key, ...)`: every row comes back as a `(child key, row)`
          pair, so a consumer reads each kind through its own field. An
          aggregate file yields the requested nested lists of each parent's
          document (an absent key is no binding of that kind; a list of the
          wrong shape is a read gap for the whole file). A list-form file
          yields its rows under the file's own binding resource, so a
          consumer that must read both shapes asks one way.

        Every other decision - hash, manifest, path gate, identity of the
        binding resource, outcomes, EMPTY with data, duplicate parents - is
        the same trust chain as `bindings()`.
        """
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            return {}, gap
        return _binding_rows(file_name, raw, children)

    def aggregate_documents(self, file_name: str) -> tuple[dict[str, dict | None], ReadGap | None]:
        """`{parentName: document-or-None}` of an aggregate by-parent file,
        for a consumer that reads the nested lists itself with
        `aggregate_nested_rows()` - and therefore can give a nested read gap
        to the one parent it belongs to instead of to the whole file. This is
        dienst.py's read, unchanged from before the shared reader existed:
        it does not apply the `bindingResource` identity rule the other
        readers apply (see `_aggregate_documents`)."""
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            return {}, gap
        return _aggregate_documents(file_name, raw)

    def binding_child_keys(self, file_name: str) -> tuple[dict[str, tuple[str, ...]], ReadGap | None]:
        """Which nested binding kinds each parent's document carries, sorted.

        For a consumer that must know about a kind it does not read: a
        certificate whose document carries a binding kind this version has no
        rule for is not provably unused. The list form carries no nested
        kinds, so every parent it read maps to `()`. A parent read as EMPTY
        carries none either. Same file-level refusals as `binding_rows()`.
        """
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            return {}, gap
        if isinstance(raw, dict) and raw.get("shape") == "aggregate":
            docs, docs_gap = _checked_aggregate_documents(file_name, raw)
            if docs_gap is not None:
                return {}, docs_gap
            return {
                parent: ()
                if document is None
                else tuple(sorted(k for k in document if isinstance(k, str) and k.endswith(BINDING_KEY_SUFFIX)))
                for parent, document in docs.items()
            }, None
        grouped, list_gap = _binding_rows(file_name, raw, None)
        if list_gap is not None:
            return {}, list_gap
        return {parent: () for parent in grouped}, None

    def binding_names(self, file_names: tuple[str, ...]) -> tuple[str, ...]:
        """Every name the given AGGREGATE by-parent files carry: the parent
        names, the value of each file's own parent key, and the identity
        fields of every nested row (`BINDING_NAME_FIELDS`).

        A family for `disclosure.names_from_export()`, over the aggregate
        files the tools READ (`disclosure.AGGREGATE_BINDING_FILES`) - never
        every aggregate file in the manifest. MEASURED: the parent list of
        `lbmonitor_binding.by-parent.json` is the appliance's built-in
        monitors ("sta", "ping", "http", "tcp"), which no tool prints; a name
        is replaced as a substring at 'beperkt', so collecting "sta" turned
        "geforceerde stand" into a pseudonym fragment in every answer.

        The tools that read these files print names out of them - a service a
        certificate is bound to, a servicegroup, a member - and a gap text
        names a parent. The harvest is deliberately MORE TOLERANT than the
        analysis, the same choice as `dienst.names_in_service_sources`: it
        exists to make names maskable, never to establish a fact, so it walks
        the raw, hash-verified document whether or not the file as a whole is
        usable. Fail-closed by construction: a file that cannot be read at
        all yields no names, and a name this export never read can reach no
        text either.

        A file in the LIST shape is harvested the same way: its rows sit
        where an aggregate document sits (`parents[].data.<resource>`), so the
        same walk reaches the parent names and the identity fields of every
        row. The certificate tools read one such file this way (the SSL
        servicegroup bindings, `cert_usage.names_in_cert_usage_sources`).
        """
        names: set[str] = set()
        for file_name in file_names:
            raw, gap = self._binding_document(file_name)
            if gap is not None or not isinstance(raw, dict) or raw.get("shape") not in ("aggregate", "list"):
                continue
            parents = raw.get("parents")
            if not isinstance(parents, list):
                continue
            parent_key = _usable_text(raw.get("parentKey"))
            for parent in parents:
                if not isinstance(parent, dict):
                    continue
                _harvest_names(names, parent, ("parentName",))
                data = parent.get("data")
                if not isinstance(data, dict):
                    continue
                for value in data.values():
                    for document in (value,) if isinstance(value, dict) else (value if isinstance(value, list) else ()):
                        if not isinstance(document, dict):
                            continue
                        if parent_key is not None:
                            _harvest_names(names, document, (parent_key,))
                        _harvest_names(names, document, BINDING_NAME_FIELDS)
                        for key, entries in document.items():
                            if not (isinstance(key, str) and key.endswith(BINDING_KEY_SUFFIX)):
                                continue
                            if not isinstance(entries, list):
                                continue
                            for entry in entries:
                                _harvest_names(names, entry, BINDING_NAME_FIELDS)
        return tuple(sorted(names))

    def binding_parents(self, file_name: str) -> ParentCoverage:
        """Cross-checks the PARENT LIST of a by-parent binding file against
        the object source of those parents.

        The measured hole this closes (2026-08-27, on the live lab export in
        `tests/fixtures/lab-export-vpx-20260826/`): `objects/sslvserver.json`
        carries three virtual servers, `bindings/sslvserver_sslcertkey_binding
        .by-parent.json` carries two parents. The third one (an
        authentication vserver) has no parent entry at all, so its
        certificate bindings were never read - while the flat list came out
        looking complete and the impact answer reported `read_gaps: []`.
        `bindings/sslcertkey_binding.by-parent.json` in that same export
        confirms independently that this third service does hang on the
        certificate in question. That is a false-green answer with the
        counter-evidence sitting in the same directory.

        WHAT IS COMPARED, and why this cannot invent an expectation: the
        binding file DECLARES against which object source its parents come
        from - `parentResource` ("sslvserver") and `parentKey`
        ("vservername"), both written by the real collector and both already
        relied upon elsewhere in this format. This function reads those two
        fields from the file itself and compares against
        `config/<parentResource>` in the SAME manifest, on the field the file
        itself names. Nothing here is a guess about what a collector "ought
        to" have written; both sides are declared in the export.

        WHY THIS DOES NOT FLOOD OTHER EXPORTS WITH GAPS: three distinct
        outcomes, with three distinct reasons, and only the first is a
        statement that something is MISSING.
        - Both sources readable and equal: no gap at all. The healthy case
          stays silent (pinned by a test, so an over-eager version cannot
          pass).
        - Both sources readable and DIFFERENT: one gap per differing name -
          a measured contradiction between two files of one manifest, in
          either direction.
        - The comparison cannot be made (the file declares no parent source,
          or that source is not usably in this manifest): one gap that says
          exactly that. It never claims a parent is missing on evidence it
          does not have.

        A gap here is deliberately NOT the whole file falling over: what WAS
        read stays established, the gap sits next to it. Losing two true
        findings to report a third unknown would be fail-closed applied so
        bluntly it destroys the answer.
        """
        raw, gap = self._binding_document(file_name)
        if gap is not None:
            # The caller that also asks for `bindings()` already receives
            # this same gap there; impact.py therefore only reaches this
            # method when that read was clean, and a gap here is then new
            # information (an export swapped between the two reads).
            return ParentCoverage(gaps=(gap,))
        if isinstance(raw, dict) and raw.get("shape") == "aggregate":
            shape_gap = _checked_aggregate_documents(file_name, raw)[1]
        else:
            shape_gap = _flatten_by_parent(file_name, raw)[1]
        if shape_gap is not None:
            # One shape authority per form: whatever the reader of that form
            # refuses (`_flatten_by_parent` for the list form,
            # `_aggregate_documents` for the aggregate form) is refused here
            # too, with its wording, instead of a second validator that can
            # drift away from it. Only the parent list and the file-level
            # rules are validated here; which nested lists a document carries
            # is a question for the consumer that reads them.
            return ParentCoverage(gaps=(shape_gap,))

        parent_resource = _usable_text(raw.get("parentResource"))
        parent_key = _usable_text(raw.get("parentKey"))
        present: list[str] = []
        gaps: list[ReadGap] = []
        for position, parent in enumerate(raw.get("parents", []), start=1):
            name = _usable_text(parent.get("parentName"))
            if name is None:
                gaps.append(
                    ReadGap(
                        source=f"{file_name} (parent {position})",
                        reason=(
                            f"parentName is niet bruikbaar: {shape_or_missing_at(parent, 'parentName')};"
                            " niet vast te stellen voor welk object deze vermelding geldt, en dus ook"
                            " niet of de parentlijst compleet is"
                        ),
                    )
                )
            elif name not in present:
                present.append(name)

        if parent_resource is None or parent_key is None:
            missing_field = "parentResource" if parent_resource is None else "parentKey"
            gaps.append(
                ReadGap(
                    source=f"{file_name} (parentlijst)",
                    reason=(
                        f"dit bindingsbestand draagt geen bruikbare {missing_field}, dus tegen welke"
                        " objectbron de parentlijst compleet zou moeten zijn is niet vast te stellen;"
                        " de parentlijst is niet te kruiscontroleren"
                    ),
                )
            )
            return ParentCoverage(names=tuple(present), gaps=tuple(gaps))

        if not _is_object_name(parent_resource):
            # `parent_resource` comes from the CONTENT of a binding file, and
            # an export can be SUPPLIED (see _read_target_name above). A value
            # that is not an object name is refused HERE, at the source, on top
            # of the same check in `objects()` - so this file's content never
            # even reaches the layer that turns a name into a path. The value
            # itself is not repeated: it would otherwise travel unmasked into
            # the answer.
            gaps.append(
                ReadGap(
                    source=f"{file_name} (parentlijst)",
                    reason=(
                        "dit bindingsbestand noemt in parentResource geen waarde met de vorm van"
                        " een objectnaam (alleen letters, cijfers en liggende streepjes zijn"
                        " toegestaan); er wordt niets geopend op een naam die uit de inhoud van een"
                        " bestand komt, en de waarde zelf wordt hier niet herhaald, dus de"
                        " parentlijst is niet te kruiscontroleren"
                    ),
                )
            )
            return ParentCoverage(names=tuple(present), gaps=tuple(gaps))

        resource = f"config/{parent_resource}"
        objects, object_gap = self.objects(resource)
        if object_gap is not None:
            gaps.append(
                ReadGap(
                    source=f"{file_name} (parentlijst)",
                    reason=(
                        f"de parentlijst is niet te kruiscontroleren tegen {resource}:"
                        f" {object_gap.reason}; of elk object daar een parent-vermelding in dit"
                        " bestand heeft, is daarmee niet vast te stellen"
                    ),
                )
            )
            return ParentCoverage(names=tuple(present), gaps=tuple(gaps))

        expected: list[str] = []
        for position, o in enumerate(objects, start=1):
            if not isinstance(o, dict):
                # `objects()` already refuses a non-object element for the
                # whole file, so this is unreachable through that path - but
                # the guard is positive here too rather than trusting a
                # caller's guarantee, the same rule the rest of this module
                # follows.
                gaps.append(
                    ReadGap(
                        source=f"{resource} (object {position})",
                        reason=(
                            f"dit object draagt {shape_of(o)}; niet vast te stellen of het een"
                            f" parent-vermelding heeft in {file_name}"
                        ),
                    )
                )
                continue
            name = _usable_text(o.get(parent_key))
            if name is None:
                # Fail-closed applies to the IDENTITY field on which the
                # comparison runs, not only to verdict-bearing fields: an
                # object whose name cannot be established cannot be laid
                # against the parent list either way.
                gaps.append(
                    ReadGap(
                        source=f"{resource} (object {position})",
                        reason=(
                            f"{parent_key} is niet bruikbaar: {shape_or_missing_at(o, parent_key)};"
                            f" niet vast te stellen of dit object een parent-vermelding heeft in"
                            f" {file_name}"
                        ),
                    )
                )
                continue
            if name not in expected:
                expected.append(name)

        for name in expected:
            if name not in present:
                gaps.append(
                    ReadGap(
                        source=f"{file_name} (parentlijst)",
                        reason=(
                            f"{resource} kent {name}, maar dit bestand draagt daarvoor geen"
                            f" parent-vermelding; de bindingen van {name} zijn niet gelezen en het"
                            " is dus niet vast te stellen welk certificaat daaraan hangt"
                        ),
                    )
                )
        for name in present:
            if name not in expected:
                gaps.append(
                    ReadGap(
                        source=f"{file_name} (parentlijst)",
                        reason=(
                            f"dit bestand draagt een parent-vermelding voor {name}, maar {resource}"
                            " kent dat object niet; niet vast te stellen welke van de twee bronnen"
                            " klopt"
                        ),
                    )
                )

        names = list(expected)
        for name in present:
            if name not in names:
                names.append(name)
        return ParentCoverage(names=tuple(names), gaps=tuple(gaps))


def load_export(directory: Path) -> Export:
    manifest = _within(directory, "export-manifest.json")
    if manifest is None:
        return Export(directory=directory, manifest_missing=True)
    try:
        raw_bytes = manifest.read_bytes()
    except OSError:
        # Covers both the ordinary "does not exist" and the TOCTOU race
        # with _swap (collect.py): if the read falls inside the
        # window in which `export/` briefly does not exist, it must never
        # leak out as a bare FileNotFoundError - it is the same missing
        # manifest as every other case here.
        return Export(directory=directory, manifest_missing=True)
    # The ceiling comes FIRST, same shape as `_read_target_name` above and
    # every other reader in this file: the decode and the parse below both
    # scale with the size of a file nobody authenticated, and the manifest
    # is the TRUST ANCHOR every other read in this module checks against,
    # read FIRST on every answer. An oversized manifest is no more
    # trustworthy than a missing one - the same honest branch.
    if len(raw_bytes) > MAX_FILE_BYTES:
        return Export(directory=directory, manifest_missing=True)
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Export(directory=directory, manifest_missing=True)
    except (RecursionError, MemoryError, ValueError):
        # An unparseable manifest is no more trustworthy than a missing one -
        # the same honest branch, never an escaping exception. This is the
        # first read of every answer, so an exception escaping HERE masks the
        # whole session instead of one source.
        return Export(directory=directory, manifest_missing=True)
    # Valid JSON is not the same as a manifest with the SHAPE the rest of
    # this file assumes. Without this gate every caller below would
    # uncritically `.get(...)` whatever the manifest happened to carry - a
    # top-level LIST, or a `resources`/`files` that is itself not an
    # object, all gave a bare AttributeError at the next `.get()`,
    # somewhere further down the chain, far from where the manifest was
    # read. Honesty belongs at the SOURCE, not caught after the fact: a
    # manifest whose basic shape is wrong is no more trustworthy than a
    # manifest that does not exist - `manifest_missing=True`, the same
    # honest "nothing can be trusted" branch that already exists elsewhere.
    if not isinstance(raw, dict):
        return Export(directory=directory, manifest_missing=True)
    raw_resources = raw.get("resources")
    if raw_resources is None:
        raw_resources = {}
    elif not isinstance(raw_resources, dict):
        return Export(directory=directory, manifest_missing=True)
    raw_files = raw.get("files")
    if raw_files is None:
        raw_files = {}
    elif not isinstance(raw_files, dict):
        return Export(directory=directory, manifest_missing=True)
    # Content hash of the raw manifest bytes: the identity that
    # `_manifest_unchanged()` above later rereads and compares to detect a
    # swap during reading, and that `_read_target_name` below uses to
    # anchor the target name to the SAME manifest - computed for both
    # purposes from the same bytes, so they can never diverge.
    manifest_hash = hashlib.sha256(raw_bytes).hexdigest()
    # THE BOUNDARY GATE, applied once, here. Everything below this line that
    # leaves this function has had its SHAPE established; nothing that has
    # not is handed on. See the block at the top of this file for the
    # measurements and the reasoning.
    #
    # `manifestVersion` and `collectorVersion` are deliberately absent from
    # this list. MEASURED on 2026-09-06: neither is read by `load_export` or
    # by any module under `src/nsmcp/`, so neither reaches an answer and
    # neither becomes a path. There is nothing to gate, and inventing a
    # consumer to have something to gate would be the opposite of this task.
    resources, refused_resource_keys = _gate_manifest_map(raw_resources, _RESOURCE_KEY)
    file_hashes, refused_file_keys = _gate_manifest_map(raw_files, _FILE_KEY)
    target_name, target_name_refused = _gate_target_name(
        # Which target produced this export, if that was recorded AND
        # provably belongs to this manifest. See
        # TARGET_FILE/_read_target_name above.
        _read_target_name(directory, manifest_hash)
    )
    return Export(
        directory=directory,
        resources=resources,
        file_hashes=file_hashes,
        collected_at=_gate_timestamp(raw.get("collectedAtUtc")),
        manifest_hash=manifest_hash,
        target_name=target_name,
        refused_resource_keys=refused_resource_keys,
        refused_file_keys=refused_file_keys,
        target_name_refused=target_name_refused,
    )
