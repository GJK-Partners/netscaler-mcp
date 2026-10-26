"""How complete is this answer - the coverage of the export it stands on.

Mirrors NSHC's `reportTruth` layer (backend/deep/NshcReportTruth.ps1:152-181,
where complete/partial/unreadable/unknown are set and each gets its sentence,
and backend/offline/Invoke-NshcOfflineInventory.ps1:1291-1310, where an
unusable export is fail-closed onto 'error'). The four Dutch words are this
product's vocabulary (design chapter 2.2, row A2); the mapping to the NSHC
words sits in COVERAGE_FROM_NSHC below, so a reader can check it instead of
having to believe it.

Three things this module refuses to do, each because its absence produced a
false statement about a real export:

1. Call a coverage complete while a by-parent binding file could not be
   cross-checked against its object source. A parent that is missing
   ENTIRELY leaves no trace in the binding file (see
   export.binding_parents), so silence there is not evidence.
2. Turn a resource this build legitimately cannot serve (NOT_SUPPORTED)
   into a failure. That is OPTIONEEL AFWEZIG: the collector asked, the
   appliance said no. A fact about the build, not about the read.
3. Report the three resources the collector writes under `parsed/` as
   missing object files. Measured on the real export: config/systemuser,
   config/nsrunningconfig and config/nssavedconfig are OK in the manifest
   and have no file under objects/ at all, by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, repeatable_token
from nsmcp.cert_usage import REFUSED_KEY_REASON, UNREADABLE, coverage_findings as cert_usage_findings, other_usage
from nsmcp.chain import route_source_gaps
from nsmcp.export import MANIFEST_KEY_MAX_LEN, shape_of
from nsmcp.knowledge import Knowledge
from nsmcp.limits import MAX_FILE_BYTES, MAX_JSON_DEPTH, MAX_OBJECTS_PER_FILE, MAX_TEXT_LINES

# Integration point 1 (merge on the release, 14-9-2026): the numbers come from
# the one place for input ceilings (`nsmcp.limits`), so this watch and the
# Export reader cannot drift apart. The module-level names stay: they are
# what the tests monkeypatch to prove each ceiling trips. Never change the
# older tool's verdicts or globally patch pathlib to give this watch its
# input limits.
MAX_WATCH_BYTES = MAX_FILE_BYTES
MAX_WATCH_DEPTH = MAX_JSON_DEPTH
MAX_WATCH_OBJECTS = MAX_OBJECTS_PER_FILE
MAX_WATCH_TEXT_LINES = MAX_TEXT_LINES


class _WatchPath(type(Path())):
    """The directory of a RETAINED export, as the watch reads it: the
    watch's own ceilings on every read the Export parser makes in it. No
    export-format parsing lives here, and no read either.

    1.1 B: every read of the Export parser is a `localpath` walk from the
    export map (`export._read_export_file`), which refuses a link or reparse
    point anywhere in the export map - the link gate this adapter used to
    apply by overriding `resolve`/`read_bytes` is that walk now. What stays
    is `gate_read`: the parser hands it the bytes it read on the held handle,
    and an `OSError` from here is the parser's own unreadable route. Since
    the merge on the release (14-9-2026) the size and depth ceilings duplicate
    what the Export reader already enforces; they stay because the watch
    applies its own numbers (`MAX_WATCH_*`, and the target file's
    `retention.MAX_TARGET_BYTES`). Both draw their numbers from
    `nsmcp.limits`, so there is still one source of truth for them.
    """

    def gate_read(self, path_text: str, data: bytes) -> bytes:
        from nsmcp.export import TARGET_FILE
        from nsmcp.retention import MAX_TARGET_BYTES

        name = Path(path_text).name
        limit = MAX_TARGET_BYTES if name == TARGET_FILE else MAX_WATCH_BYTES
        if len(data) > limit:
            raise OSError("bestand overschrijdt leesgrens")
        if name.endswith(".json"):
            # Count JSON containers outside strings before the existing JSON
            # parser runs. Escaped quotes/brackets are content, not nesting.
            depth = 0
            quoted = escaped = False
            for byte in data:
                if quoted:
                    if escaped:
                        escaped = False
                    elif byte == 92:
                        escaped = True
                    elif byte == 34:
                        quoted = False
                elif byte == 34:
                    quoted = True
                elif byte in (91, 123):
                    depth += 1
                    if depth > MAX_WATCH_DEPTH:
                        raise OSError("JSON overschrijdt dieptegrens")
                elif byte in (93, 125):
                    depth -= 1
        return data


@dataclass(frozen=True)
class CoverageChange:
    """A read-coverage message; it never establishes appliance health.

    resource remains the source identity for callers. Print with to_text(),
    which gates that identity and only renders controlled words and reasons.
    """

    resource: str
    was: str
    now: str
    reason: str = "bron is niet meer bruikbaar gelezen"

    def to_text(self) -> str:
        key, shape = _resource_key(self.resource, False)
        subject = key or shape
        if self.resource == "dekkingsvergelijking":
            subject = "dekkingsvergelijking"
        was = self.was if self.was in SOURCE_WORDS else "ONBEKEND"
        now = self.now if self.now in SOURCE_WORDS else "ONBEKEND"
        # Even manually constructed instances cannot print supplied reasons.
        reason = self.reason if self.reason in _WATCH_REASONS else _WATCH_SOURCE_GAP
        return f"{subject}: leesdekking {was} -> {now}; {reason}. Toestand van de appliance: niet vastgesteld."


_WATCH_SOURCE_GAP = "bronvorm of bronbestand niet bruikbaar gelezen"
_WATCH_MANIFEST_GAP = "manifest ontbreekt, is onleesbaar of is tijdens het lezen vervangen"
_WATCH_PAIR_GAP = "geen strikt eerdere scan met dezelfde geverifieerde doelidentiteit vastgesteld"
_WATCH_SHAPES = ("tekst", "JSON null", "lijst", "getal", "boolean", "ontbrekende sleutel")
_WATCH_SHAPE_REASONS = {
    shape: f"objectbron heeft de vorm {shape}; verwacht een object of een lijst van objecten binnen de leesgrens"
    for shape in _WATCH_SHAPES
}
_WATCH_REASONS = frozenset(
    (
        "bron is niet meer bruikbaar gelezen",
        _WATCH_SOURCE_GAP,
        _WATCH_MANIFEST_GAP,
        _WATCH_PAIR_GAP,
    )
) | frozenset(_WATCH_SHAPE_REASONS.values())


def _watch_unknown(reason: str) -> tuple[CoverageChange, ...]:
    return (CoverageChange("dekkingsvergelijking", "ONBEKEND", "MISLUKT", reason),)


def _watch_manifest_matches(export) -> bool:
    from nsmcp.retention import _manifest_snapshot

    snapshot = _manifest_snapshot(Path(export.directory))
    return (
        not export.manifest_missing
        and snapshot is not None
        and snapshot[1] == export.manifest_hash
        and export._manifest_unchanged()
    )


def _watch_source(export, resource: str) -> SourceState:
    from nsmcp.export import _READ_EMPTY, MISSING

    key, shape = _resource_key(resource, resource in export.refused_resource_keys)
    if key is None:
        return SourceState(resource, shape, "MISLUKT", _WATCH_SOURCE_GAP)
    word = _STATUS_WORDS.get(export.status(resource), "MISLUKT")
    if word not in _READ_WORDS:
        return SourceState(resource, key, word)
    if word == "LEEG":
        # A successful empty read has no payload, on any source road. The
        # parsed text readers require a file/hash for their own consumers;
        # coverage instead trusts the EMPTY status of this unchanged scan.
        if export._manifest_unchanged():
            return SourceState(resource, key, word)
        return SourceState(resource, key, "MISLUKT", _WATCH_MANIFEST_GAP)
    # Three explicit parsed roads; the object road accepts the real generic
    # dict-singleton and list-of-dicts containers. No appliance field verdicts.
    readers = {
        "config/nsrunningconfig": export.running_config_lines,
        "config/nssavedconfig": export.saved_config_lines,
        "config/systemuser": export.systemuser_rows,
    }
    reason = _WATCH_SOURCE_GAP
    if key in readers:
        rows, gap = readers[key]()
        limit = MAX_WATCH_OBJECTS if key == "config/systemuser" else MAX_WATCH_TEXT_LINES
        usable = gap is None and len(rows) <= limit
    else:
        payload, _, gap = export._object_payload(key)
        usable = gap is None and (
            payload is _READ_EMPTY
            or isinstance(payload, dict)
            or (
                isinstance(payload, list)
                and len(payload) <= MAX_WATCH_OBJECTS
                and all(isinstance(row, dict) for row in payload)
            )
        )
        if gap is None and not usable:
            shape = (
                "ontbrekende sleutel"
                if payload is MISSING
                else "JSON null"
                if payload is None
                else {str: "tekst", list: "lijst", int: "getal", float: "getal", bool: "boolean"}.get(type(payload))
            )
            reason = _WATCH_SHAPE_REASONS.get(shape, _WATCH_SOURCE_GAP)
    return SourceState(resource, key, word if usable else "MISLUKT", "" if usable else reason)


def coverage_changes(previous, current) -> tuple[CoverageChange, ...]:
    """Report previously readable sources that now have a read gap.

    Empty reads, resumed reads and already unreadable sources remain silent.
    Preserve the caller's manifest snapshot; reloading could hide a swap.
    """
    previous = replace(previous, directory=_WatchPath(previous.directory))
    current = replace(current, directory=_WatchPath(current.directory))
    if not _watch_manifest_matches(previous) or not _watch_manifest_matches(current):
        return _watch_unknown(_WATCH_MANIFEST_GAP)
    changes = []
    for resource in sorted(previous.resources):
        before = _watch_source(previous, resource)
        if before.word not in _READ_WORDS:
            continue
        after = _watch_source(current, resource)
        if after.word in _LOST_WORDS:
            changes.append(
                CoverageChange(resource, before.word, after.word, after.reason or "bron is niet meer bruikbaar gelezen")
            )
    # Also protects status-only transitions: those do not read a payload.
    if not _watch_manifest_matches(previous) or not _watch_manifest_matches(current):
        return _watch_unknown(_WATCH_MANIFEST_GAP)
    return tuple(changes)


def coverage_watch(export_dir) -> tuple[CoverageChange, ...]:
    """Compare with a strictly earlier kept scan of the same verified target.

    No kept export yields (), which does not prove unchanged coverage.
    Invalid current data or unprovable pairing produces an unknown message.
    """
    from nsmcp.export import load_export
    from nsmcp.retention import _owned_manifest, _read_manifest, _scan_moment, kept_exports, target_identity

    directory = Path(export_dir)
    current = load_export(_WatchPath(directory))
    identity = target_identity(directory)
    moment = _scan_moment(_read_manifest(directory))
    if not _watch_manifest_matches(current):
        return _watch_unknown(_WATCH_MANIFEST_GAP)
    if identity is None or moment is None:
        return _watch_unknown(_WATCH_PAIR_GAP)
    candidates = kept_exports(directory)
    if not candidates:
        return ()
    for candidate in candidates:
        raw = _owned_manifest(candidate, directory)
        earlier = _scan_moment(raw)
        if earlier is None or earlier >= moment or target_identity(candidate) != identity:
            continue
        previous = load_export(_WatchPath(candidate))
        # Anchor the metadata used for pairing to these exact Export snapshots.
        # Revalidate after the source reads as well, so a swap cannot silently
        # substitute another scan or target during automatic selection.
        changes = coverage_changes(previous, current)
        if not _watch_manifest_matches(previous) or not _watch_manifest_matches(current):
            return _watch_unknown(_WATCH_MANIFEST_GAP)
        if (
            target_identity(candidate) != identity
            or target_identity(directory) != identity
            or _scan_moment(_owned_manifest(candidate, directory)) != earlier
            or _scan_moment(_read_manifest(directory)) != moment
        ):
            return _watch_unknown(_WATCH_PAIR_GAP)
        return changes
    return _watch_unknown(_WATCH_PAIR_GAP)


COVERAGE_WORDS = ("volledig", "gedeeltelijk", "onbruikbaar", "niet vastgelegd")
SOURCE_WORDS = ("OK", "LEEG", "MISLUKT", "GEWEIGERD", "ONTBREEKT", "OPTIONEEL AFWEZIG")

# The NSHC status this product's coverage verdict corresponds to. Not used by
# the code - used by tests/test_parity_nshc.py and by a reader who
# wants to check the claim.
COVERAGE_FROM_NSHC = {
    "volledig": "complete",
    "gedeeltelijk": "partial",
    "onbruikbaar": "unreadable",
    "niet vastgelegd": "unknown",
}

# Manifest status -> product word. Every status the released collector writes
# is here; anything else falls through to the fail-closed branch in
# `_state_for()` below, which never lands on OK or LEEG.
_STATUS_WORDS = {
    "OK": "OK",
    "EMPTY": "LEEG",
    "FAILED": "MISLUKT",
    "PARTIAL": "MISLUKT",
    "RBAC_DENIED": "GEWEIGERD",
    "NOT_SUPPORTED": "OPTIONEEL AFWEZIG",
    "MISSING": "ONTBREEKT",
    "NIET_IN_MANIFEST": "ONTBREEKT",
    "GEEN_MANIFEST": "ONTBREEKT",
    "MANIFEST_VERMELDING_ONGELDIG": "MISLUKT",
}

# The words that mean "this source was read into something usable".
_READ_WORDS = ("OK", "LEEG")

# The words that COST coverage - they get their own line in the answer.
_LOST_WORDS = ("MISLUKT", "GEWEIGERD", "ONTBREEKT")

# How a read gap bound to ONE certificate (`cert_usage.CertGap`) names that
# certificate here: this report is about every certificate at once, so it
# does not name the one an object without a usable name refers to. Pinned in
# tests/test_product_surface.py.
CERT_GAP_SUBJECT = "een certificaat"

LOG_FILE = "collect-log.txt"

# The three OK resources whose payload the collector writes under `parsed/`
# instead of `objects/`. Measured on tests/fixtures/lab-export-vpx-20260826.
PARSED_SOURCES = ("config/systemuser", "config/nsrunningconfig", "config/nssavedconfig")

# The shape of a NITRO resource path - the KEY an export manifest hangs a
# status on, and the only part of that manifest this module echoes verbatim.
# Two lowercase segments ("config/sslvserver"), optionally with the query the
# collector appends ("?bulkbindings=yes", "?args=filename:iprep.log,
# filelocation:%2Fvar%2Flog" - hence `%`, `:`, `,`, `.` and uppercase in the
# query only, for percent-encoding). Measured: all 58 keys of the real export
# pass, pinned by tests/test_coverage.py.
_RESOURCE_PATH = re.compile(r"[a-z][a-z0-9_]*/[a-z][a-z0-9_]*(?:\?[A-Za-z0-9_=:,.%-]+)?")

# Why a key that fails that shape can never be OK, even when the manifest says
# so. The last segment of a resource key becomes the name of a file under
# `objects/`, so an ungated key is a file name. MEASURED here on 2026-09-06,
# before this refusal existed, on two exports identical but for one file
# OUTSIDE the export directory, with a manifest key
# `config/..\..\buiten\geheim` at status OK:
# - the probed path resolved to `<tmp>\buiten\geheim.json`, outside the export;
# - with that file present the answer said `dekking: volledig [vastgesteld]`,
#   without it `dekking: gedeeltelijk [vastgesteld]`.
# So: a filesystem existence oracle for arbitrary paths driven by supplied
# text, AND an ESTABLISHED "complete" resting on a file that was never part of
# the read. Same hole as `_binding_file_name` below closed one field over, and
# as `export.py::_OBJECT_NAME` closed for `parentResource` in August; same
# repair, a POSITIVE test on the shape.
#
# The text is deliberately CONSTANT: a refusal that varied with what happens to
# exist at the path would be the very oracle this gate closes.
_REFUSED_RESOURCE_KEY = (
    "deze manifestsleutel heeft niet de vorm van een NITRO-resourcepad; er wordt niets"
    " geopend op een sleutel die ook een pad kan zijn, en de sleutel zelf wordt hier niet"
    " herhaald"
)

# The directory an export manifest hangs a by-parent binding file under, and
# the suffix by which a manifest key ANNOUNCES that it is one. `export.py`
# resolves such a file as `<export>/bindings/<name>` and nowhere else, so a
# key that does not sit directly under this directory names nothing this
# product can open.
BINDING_DIR = "bindings"
BINDING_SUFFIX = ".by-parent.json"

# The shape of the FILE NAME in such a key. Lower-case identifier characters
# and nothing else - no separator, no dot, no space - so the name cannot also
# be a path. Measured: all seven binding files of the real export pass, pinned
# by tests/test_coverage.py.
# The length cap is `export.MANIFEST_KEY_MAX_LEN`, the one this product holds
# for a manifest key - the name is a PART of that key, so a separate, lower
# cap here could only refuse a name whose key the boundary had accepted, and
# would say "zonder de vorm van bindings/<naam>.by-parent.json" about a name
# whose shape is exactly that. One constant, imported, never copied.
_BINDING_FILE_NAME = re.compile(r"[a-z][a-z0-9_]*\.by-parent\.json")

# Why a refused key does not name itself, and does not distinguish between
# "nothing is there" and "something is there": the same reason as the object
# name refusal in export.py::_object_payload. This text travels into the
# answer, and a refusal that varied with what happens to exist at the path
# would be the read oracle the gate exists to close.
_REFUSED_BINDING_KEY = (
    "deze manifestsleutel kondigt een bindingsbestand aan maar levert geen bestandsnaam"
    f" direct onder {BINDING_DIR}/ op; er wordt niets geopend op een sleutel die ook een pad"
    " kan zijn, en de sleutel zelf wordt hier niet herhaald"
)


@dataclass(frozen=True)
class SourceState:
    """What one manifest key yielded.

    Two fields where an earlier version had one, because they answer two questions.
    `resource` is the raw manifest KEY: the IDENTITY of this source, what a
    caller compares, keys a dict on, or diffs against another export.
    `subject` is what may be PRINTED: that same key when it has the shape of
    a NITRO resource path, its SHAPE otherwise (see `_resource_key`).

    That earlier version put the shape sentence in `resource` itself, and that cost the
    identity: every refused key collapsed onto ONE identical string, so two
    different unusable keys became one line in the answer, a
    `{s.resource: s.word}` dict silently merged them, and the coverage
    difference of `rapport_vergelijk` would compare Dutch sentences
    instead of resource keys.
    """

    resource: str
    subject: str
    word: str
    reason: str = ""


@dataclass(frozen=True)
class BindingFiles:
    """The by-parent binding files of a manifest, and the keys that announced
    one without naming a file this product can open.

    `refused` is deliberately a read gap and not a silent drop: a manifest
    entry that cannot be interpreted is a piece of this export that was NOT
    cross-checked, and the one thing this module never does is leave that out
    of the answer.
    """

    names: tuple[str, ...] = ()
    refused: tuple[ReadGap, ...] = ()


@dataclass(frozen=True)
class Coverage:
    verdict: str
    sources: tuple[SourceState, ...] = ()
    parent_gaps: tuple[ReadGap, ...] = ()
    log_lines: int | None = None
    binding_files: int = 0
    # How many of those files could not be fully cross-checked. Counted where
    # the association between a file and its gaps still EXISTS - in
    # `coverage_of()` below, which loops file by file. It used to be
    # reconstructed afterwards by splitting each gap's `source` text, and that
    # was wrong: `export.binding_parents()` emits gaps whose source names the
    # OBJECT SOURCE ("config/sslvserver (object 2)"), not the binding file, so
    # the three files cross-checked against config/sslvserver collapsed onto
    # one source and the answer stated an ESTABLISHED "1 van de 7" where three
    # files were unchecked. A false-optimistic established number is exactly
    # what this module exists to prevent.
    binding_files_with_a_gap: int = 0
    # The manifest keys that announced a binding file without naming one.
    # Carried here rather than recomputed, so the answer cannot forget them.
    refused_binding_files: tuple[ReadGap, ...] = ()
    # Whether the manifest of this export was read at all. Carried because
    # `_cross_check_finding()` needs it and used to take it as a SECOND
    # parameter next to this object: a caller could hand in a Coverage and a
    # flag that disagree, and the branch that decides whether a cross-check
    # may be called ESTABLISHED is the last place for two truths.
    manifest_missing: bool = False
    # The policy sources a contentswitching route of this export asks for and
    # cannot read (`chain.route_source_gaps`). They cost coverage like a lost
    # source: `dienst_keten` cannot establish that route, so the verdict may
    # not say "volledig".
    route_source_gaps: tuple[ReadGap, ...] = ()
    # The read gaps of the sources of certificate use outside the bindings
    # (`cert_usage.other_usage`: the SAML objects and the SSL-servicegroup
    # bindings) - shared ones and those bound to one certificate. They cost
    # coverage like a lost source: a use of a certificate was not read, so
    # "every use was seen" may not follow from "volledig".
    cert_usage_gaps: tuple[ReadGap, ...] = ()


# Why a policy source that a contentswitching route asks for matters, in the
# same "niet vastgesteld: bron ... niet in de export; ..." form the certificate
# sources use (`cert_usage.absent_reason`).
_CS_ROUTE_CLAUSE = (
    "waarheen een contentswitchingbeleid zonder eigen doel routeert, is met deze export niet vast te stellen"
)


def _route_source_lines(result: Coverage, manifest_keys, refused_keys=()) -> tuple[list[Finding], list[ReadGap]]:
    """A line and a read gap for each policy source a contentswitching route
    asks for that is not in the manifest at all - the tally does not know it,
    so without this line it would be silent. A source the manifest does carry
    already has its tally line; it gets only the read gap, and not even that
    when the tally already made one (MISLUKT, GEWEIGERD, ONTBREEKT).

    A source whose key the export boundary refused IS in the manifest, so it
    is "niet bruikbaar gelezen", never "niet in de export" - with the refusal
    as the reason, as the certificate sources say it. Its tally line names
    the key's shape, not this source, and already carries the read gap: the
    line only."""
    words = {state.resource: state.word for state in result.sources}
    lines: list[Finding] = []
    gaps: list[ReadGap] = []
    for gap in result.route_source_gaps:
        if any(isinstance(key, str) and key.strip() == gap.source for key in refused_keys):
            lines.append(
                _label_finding(
                    subject=gap.source,
                    outcome=UNREADABLE,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence="export-manifest.json",
                    reason=f"{REFUSED_KEY_REASON}; {_CS_ROUTE_CLAUSE}",
                )
            )
        elif gap.source not in manifest_keys:
            reason = f"niet vastgesteld: bron {gap.source} niet in de export; {_CS_ROUTE_CLAUSE}"
            lines.append(
                _label_finding(
                    subject=gap.source,
                    outcome="niet in de export",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence="export-manifest.json",
                    reason=reason,
                )
            )
            gaps.append(ReadGap(source=gap.source, reason=reason))
        elif words.get(gap.source) not in _LOST_WORDS:
            gaps.append(ReadGap(source=gap.source, reason=f"{gap.reason}; {_CS_ROUTE_CLAUSE}"))
    return lines, gaps


def _label_finding(**fields) -> Finding:
    """A Finding whose subject is a LABEL of this product, not an appliance
    object name. Same reason as overzicht._label_finding: the disclosure seam
    collects every finding subject as a name to mask, and masking "dekking"
    costs the reader the answer and pollutes the operator's pseudonym table.

    NITRO resource paths ("config/mgmtparam") are labels too: they are what
    the collector asked for, not what the appliance is called.
    """
    return Finding(subject_is_name=False, **fields)


def _resource_key(resource, refused_at_the_boundary: bool) -> tuple[str | None, str]:
    """`(the key, "")` when a manifest resource key has the shape of a NITRO
    resource path, `(None, its SHAPE sentence)` otherwise. THE one place this
    module decides whether such a key is USABLE - for what may be PRINTED
    (the finding subject, the read-gap source) and for what may become a FILE
    NAME (`objects/<naam>.json` in `_state_for`) alike.

    `refused_at_the_boundary` is the EXPORT BOUNDARY's verdict on this key
    (`export.refused_resource_keys`), and when it is set this gate does not
    get a second opinion: it only names the shape. REQUIRED, never a keyword
    with a default, because the default would have to be "nothing was
    refused" - the more favourable answer, at the one seam where landing
    favourable is worst.

    Why the boundary's verdict has to be honoured rather than re-derived.
    MEASURED on 2026-09-06: the boundary matches the RAW key, this function
    stripped FIRST, so a key with surrounding whitespace fell BETWEEN the two.
    `"config/hanode "` was refused at the boundary, removed from
    `export.resources`, then stripped back in here and printed as
    `- config/hanode: ONTBREEKT [vastgesteld]` with the reason
    `status NIET_IN_MANIFEST` - a `[vastgesteld]` line on an entry that was
    never read, and a reason that was UNTRUE, since the key IS in the manifest
    and only the boundary's own refusal had taken it out of `resources`. Two
    layers deriving the same verdict independently can disagree; one layer
    deciding and the other honouring it cannot.

    An earlier version gated only what is printed; a later measurement
    found what that left
    open: the RAW key still reached a filesystem path (see
    `_REFUSED_RESOURCE_KEY` above for the measurement). One gate, two
    consumers, so the next consumer cannot quietly be the third hole.

    Why a gate on a KEY at all: an export can be SUPPLIED (the threat is
    stated at `answer.repeatable_token`), so every byte of it reaches the
    model unless something stops it. `_state_for` already gates the manifest
    VALUE (the status) on `repeatable_token`; the key that value hangs on had
    no gate at all and was printed verbatim as a finding subject, explicitly
    exempt from the disclosure seam (`subject_is_name=False`). Same discipline
    as `overzicht._known`: `shape_of` for anything that is not usable text,
    and "zonder de vorm van ..." for text that IS usable but has the wrong
    shape - because `shape_of` would call such a value empty, which it is not.

    A refused key keeps its place in the tally: it is a source this manifest
    lists, so it is counted; only its name is withheld.
    """
    if not isinstance(resource, str) or not resource.strip():
        return None, f"een bron met {shape_of(resource)} als sleutel"
    text = resource.strip()
    if refused_at_the_boundary or len(text) > MANIFEST_KEY_MAX_LEN or _RESOURCE_PATH.fullmatch(text) is None:
        # ONE wording for the refusal, whichever of the two layers made it:
        # this sentence is true of a key the boundary refused for its shape
        # just as it is of one this pattern refuses, and inventing a second
        # sentence for the boundary's verdict would put two names on one
        # refusal.
        return None, "een bron met een sleutel zonder de vorm van een NITRO-resourcepad"
    return text, ""


def _state_for(export, resource: str) -> SourceState:
    # The boundary's verdict is read DIRECTLY, not through `getattr` with a
    # default: `Export` is a dataclass and the field always exists, so the
    # default was dead code that could only ever fire for a duck-typed stub -
    # and there it would land on "nothing was refused", the more favourable
    # answer, which is exactly the case where a favourable landing is worst.
    # An attribute error is loud; a silent green is not.
    key, shape = _resource_key(resource, resource in export.refused_resource_keys)
    subject = key if key is not None else shape
    if key is None:
        # The manifest names a source on a key this product cannot
        # interpret. It may not silently earn a READ word (`OK` or `LEEG`) -
        # that would be `[vastgesteld]` on a source nothing was ever read
        # from - and it may not quietly vanish either: it stays VISIBLE as a
        # source that could not be interpreted, on a non-read word, named by
        # its shape. Nothing is opened on it, so nothing about the filesystem
        # can be observed.
        #
        # Gated HERE, before the manifest status is even looked at, and
        # deliberately so: this used to sit after the `word != "OK"` branch
        # below, reachable only when the manifest claimed status OK. A
        # refused key at any OTHER status (measured: EMPTY) fell through
        # that branch untouched, landed on `LEEG` - a read word - and
        # vanished from the tally as a successfully read source. The refusal
        # must hold regardless of the status the manifest hangs on the key,
        # so it is checked before status is even consulted.
        return SourceState(resource=resource, subject=subject, word="MISLUKT", reason=_REFUSED_RESOURCE_KEY)
    status = export.status(resource)
    word = _STATUS_WORDS.get(status)
    if word is None:
        # An unknown status is never a read. The status itself is echoed only
        # when it has the shape of a token (answer.repeatable_token, the one
        # shape gate of this product); otherwise only its shape is named.
        token = repeatable_token(status, max_words=1, allow_hyphen=False)
        detail = f"onbekende manifeststatus {token}" if token else "manifeststatus zonder de vorm van een status"
        return SourceState(resource=resource, subject=subject, word="MISLUKT", reason=detail)
    if word != "OK":
        return SourceState(
            resource=resource,
            subject=subject,
            word=word,
            reason=f"export-manifest.json: status {status}",
        )
    if key in PARSED_SOURCES:
        # Read, and written under parsed/. See the module docstring.
        return SourceState(resource=resource, subject=subject, word="OK")
    # `key` and never `resource`: only a key that PASSED the gate above may
    # become a file name. The gate guarantees the shape
    # `<segment>/<segment>[?query]` with lower-case identifier segments, so
    # the split below yields a bare name and can no longer yield a path.
    name = key.split("/")[-1].split("?", 1)[0]
    if not (export.directory / "objects" / f"{name}.json").exists():
        return SourceState(
            resource=resource,
            subject=subject,
            word="ONTBREEKT",
            reason="manifest meldt OK maar het objectbestand ontbreekt",
        )
    # ONE layer decides, the other follows - the same lesson as the resource
    # key above. File EXISTENCE was the whole test here, and since the hash
    # gate (`Export._object_payload`) that is no longer the same question as
    # "can this source be read": a manifest row without a `payloadSha256` has
    # its file on disk and is still refused by every reader.
    #
    # MEASURED on the real fixture (merge C-1): `config/lbmonitor` stands
    # `status: OK` with 31 objects and an EMPTY `payloadSha256`, so
    # `beveiliging_verstopte_regels` reports the two rules that read it as
    # `niet beoordeeld` while this report called the same source `OK`. Two
    # tools, two answers, one export. `objects()` is asked instead, and its
    # refusal is relayed verbatim - never softened into a read word.
    # `payload_gap` and not `objects()`: the LIST opinion of `objects()` is
    # not this report's business (see its docstring in export.py), only
    # whether trusted bytes exist at all.
    gap = export.payload_gap(resource)
    if gap is not None:
        return SourceState(resource=resource, subject=subject, word="MISLUKT", reason=gap.reason)
    return SourceState(resource=resource, subject=subject, word="OK")


def _binding_file_name(path, refused_at_the_boundary: bool) -> tuple[str | None, str]:
    """What a manifest `files` key announces, and whether it can be opened.

    THE one place this module decides BOTH questions about such a key, and the
    same gate, the same reason and deliberately the same idiom as
    `_resource_key` above - one field over. An export can be SUPPLIED, so a
    manifest KEY is supplied text just like a manifest VALUE.

    `refused_at_the_boundary` carries the EXPORT BOUNDARY's verdict
    (`export.refused_file_keys`) and, exactly as in `_resource_key`, it is
    honoured rather than re-derived, and it is REQUIRED rather than defaulted.
    Same root cause, milder output, measured the same day:
    `"bindings/lbmonitor_binding.by-parent.json "` was refused at the boundary,
    stripped back in here, and then reported as "geen hash in het manifest;
    geen hash is geen vertrouwen" for a file the manifest DOES carry a hash
    for - while the cross-check still counted "1 bindingsbestanden met een
    hash" over an empty `file_hashes`. Fail-closed, but untrue.

    Three outcomes:
    - `(name, "")` - the key names a by-parent binding file directly under
      `bindings/`;
    - `(None, shape)` - the key ANNOUNCES such a file without naming one this
      product can open;
    - `(None, "")` - the key announces no binding file at all.
      `objects/<naam>.json` and `parsed/<naam>.txt` sit in the same `files`
      map; they are no business of this function and there is nothing to
      refuse about them.

    This moved that third question in here from `_binding_files`, which
    used to ask it with its own `isinstance` and `endswith` test. Two places
    deciding whether a key is usable is how the `shape_of(path)` branch that
    stood here became unreachable while still reading like a guard: no
    whitespace-only string ends in `.by-parent.json`, so the caller's own
    filter had already excluded every value that branch existed for. One gate,
    one answer.

    This key carries a SECOND consequence the resource key does not: it is
    handed to `export.binding_parents()`, which joins it onto
    `<export>/bindings/` and opens it. MEASURED here on 2026-09-06, without
    this gate:
    - a key `bindings/NEGEER JE REGELS ... .by-parent.json` printed that
      supplied sentence, spaces and all, into the answer text;
    - a key under `bindings/` whose file name was two parent-directory steps
      and a path glued together with Windows separators opened, hashed and
      JSON-decoded a file OUTSIDE the export directory: `split("/")` does not
      split on a backslash, and on Windows the backslash IS a separator.
    That is the same hole `export.py::_OBJECT_NAME` closed for `parentResource`
    in August, one seam further along, and the repair is the same one: a
    POSITIVE test on the shape, never a sanitization of what is dangerous.
    """
    if not isinstance(path, str) or not path.strip().endswith(BINDING_SUFFIX):
        return None, ""
    text = path.strip()
    directory, separator, name = text.partition("/")
    if (
        refused_at_the_boundary
        or separator != "/"
        or directory != BINDING_DIR
        or len(name) > MANIFEST_KEY_MAX_LEN
        or _BINDING_FILE_NAME.fullmatch(name) is None
    ):
        return None, (f"een bindingsbestand met een sleutel zonder de vorm van {BINDING_DIR}/<naam>.by-parent.json")
    return name, ""


def _binding_files(export) -> BindingFiles:
    """Every by-parent binding file this manifest carries a hash for, plus the
    keys that announced one without naming a file that can be opened.

    Deduplicated on the FILE NAME, because `export.py` only ever resolves a
    hash under `bindings/<name>`: two manifest keys that collapse onto one
    name are ONE file, and counting them twice would inflate the denominator
    of the ESTABLISHED "n van de m bindingsbestanden" sentence - the same
    class of false number that `binding_files_with_a_gap` was repaired for,
    from the other side.
    """
    names: set[str] = set()
    refused: dict[str, ReadGap] = {}
    # The keys the export boundary refused are walked here too, for the same
    # reason as in `coverage_of` above: a manifest entry that announces a
    # binding file must not vanish because a layer below already said it
    # could not be interpreted. Which of the two lists a key came from IS the
    # boundary's verdict, so it is passed on rather than re-derived, and the
    # attribute is read directly rather than through a `getattr` default that
    # could only ever land on "nothing was refused" (see `_state_for`).
    for path, refused_at_the_boundary in [(p, False) for p in export.file_hashes] + [
        (p, True) for p in export.refused_file_keys
    ]:
        name, shape = _binding_file_name(path, refused_at_the_boundary)
        if name is not None:
            names.add(name)
        elif shape:
            # Keyed on the shape sentence, so two equally unusable keys are
            # one line in the answer instead of two identical ones. An empty
            # shape is not a refusal but a key that announced no binding file
            # at all - see `_binding_file_name`.
            refused[shape] = ReadGap(source=shape, reason=_REFUSED_BINDING_KEY)
    return BindingFiles(
        names=tuple(sorted(names)),
        refused=tuple(refused[shape] for shape in sorted(refused)),
    )


def _log_lines(export) -> int | None:
    """The number of non-empty lines of the scan log in the export map, or
    None when it cannot be read (1.1 B: walked from the export map with
    `localpath`; a link or reparse point on the way is a refusal, which is
    unreadable here too)."""
    from nsmcp.export import _read_export_file, _within

    path = _within(export.directory, LOG_FILE)
    if path is None:
        return None
    try:
        got = _read_export_file(export.directory, path)
    except OSError:
        return None
    if not got.exists or got.over_cap:
        return None
    text = got.data.decode("utf-8", errors="replace")
    return len([line for line in text.splitlines() if line.strip()])


def _verdict(
    sources: tuple[SourceState, ...],
    parent_gaps: tuple[ReadGap, ...],
    refused_binding_files: tuple[ReadGap, ...],
    manifest_missing: bool,
    route_source_gaps: tuple[ReadGap, ...] = (),
    cert_usage_gaps: tuple[ReadGap, ...] = (),
) -> str:
    if manifest_missing:
        return "onbruikbaar"
    if not sources:
        return "niet vastgelegd"
    if not any(s.word in _READ_WORDS for s in sources):
        return "onbruikbaar"
    # A refused binding key costs coverage for the same reason a parent gap
    # does: this manifest announces a file that was never cross-checked, so
    # the read is not complete - only the reason differs. A policy source a
    # contentswitching route asks for and cannot read costs it too, and so
    # does a use of a certificate that was not read.
    if (
        parent_gaps
        or refused_binding_files
        or route_source_gaps
        or cert_usage_gaps
        or any(s.word in _LOST_WORDS for s in sources)
    ):
        return "gedeeltelijk"
    return "volledig"


def coverage_of(export) -> Coverage:
    # `export.resources` carries only the keys the EXPORT BOUNDARY
    # (export.py::load_export) accepted; the ones it refused travel in
    # `refused_resource_keys` so that no consumer can lose them. They are
    # walked here TOO, through the same `_state_for`, for two reasons: an
    # entry this manifest lists must keep its place in the tally and cost the
    # verdict ("nooit stil weg"), and the wording of a refusal stays in ONE
    # place - this module's `_resource_key`, which is TOLD the boundary
    # refused them and names their shape without re-deriving that verdict.
    # Two layers, one decision, one vocabulary. Read directly rather than
    # through `getattr`: see `_state_for`.
    refused_keys = tuple(export.refused_resource_keys)
    sources = tuple(_state_for(export, resource) for resource in sorted(set(export.resources) | set(refused_keys)))
    files = _binding_files(export)
    gaps: list[ReadGap] = []
    files_with_a_gap = 0
    for file_name in files.names:
        file_gaps = export.binding_parents(file_name).gaps
        if file_gaps:
            files_with_a_gap += 1
        gaps.extend(file_gaps)
    parent_gaps = tuple(gaps)
    route_gaps = route_source_gaps(export)
    usage_gaps = _cert_usage_gaps(export)
    return Coverage(
        verdict=_verdict(sources, parent_gaps, files.refused, export.manifest_missing, route_gaps, usage_gaps),
        sources=sources,
        parent_gaps=parent_gaps,
        log_lines=_log_lines(export),
        binding_files=len(files.names),
        binding_files_with_a_gap=files_with_a_gap,
        refused_binding_files=files.refused,
        manifest_missing=export.manifest_missing,
        route_source_gaps=route_gaps,
        cert_usage_gaps=usage_gaps,
    )


def _cert_usage_gaps(export) -> tuple[ReadGap, ...]:
    """The read gaps the certificate-use reader found, once each: the shared
    ones (a source, a field or a binding that could hide a use of any
    certificate) and the ones bound to one certificate, named here by
    `CERT_GAP_SUBJECT`.

    Without a refusal at the export boundary (`REFUSED_KEY_REASON`): that key
    already costs coverage through the tally and the refused binding keys,
    under its shape, and the same refusal under the source name would be the
    same gap twice."""
    usage = other_usage(export)
    gaps = [gap for gap in usage.shared_gaps if gap.reason != REFUSED_KEY_REASON]
    gaps += [gap.gap(CERT_GAP_SUBJECT) for gap in usage.cert_gaps]
    return tuple(dict.fromkeys(gaps))


def _tally(sources: tuple[SourceState, ...]) -> str:
    counts = {word: 0 for word in SOURCE_WORDS}
    for state in sources:
        counts[state.word] = counts.get(state.word, 0) + 1
    parts = [f"{counts[word]} {word}" for word in SOURCE_WORDS if counts[word]]
    return ", ".join(parts) if parts else "geen bron vastgelegd"


def _cross_check_finding(result: Coverage) -> tuple[Finding, ReadGap | None]:
    """The "kruiscontrole bindingen" line, and the read gap it may owe.

    Three branches, because "not read" and "read and empty" are different
    statements. This used to be ESTABLISHED unconditionally, which on an
    export whose manifest could not be read printed "alle 0 bindingsbestanden
    zijn kruisgecontroleerd [vastgesteld]": nothing was read, and the answer
    said the cross-check came out fine. That is the one thing this product
    never does (`niets [vastgesteld] zonder een geslaagde lezing`).

    Whether the manifest was read is taken from `result` and no longer from a
    second parameter next to it: `coverage_of()` has already consumed that
    flag, so a caller could hand in a Coverage and a flag that disagree - and
    this is the branch that decides whether a cross-check may be called
    ESTABLISHED.
    """
    if result.manifest_missing:
        reason = (
            "het manifest van deze export is niet gelezen, dus welke bindingsbestanden zij"
            " draagt is niet bekend en er is geen enkel bestand kruisgecontroleerd"
        )
        return (
            _label_finding(
                subject="kruiscontrole bindingen",
                outcome="niet vast te stellen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence="export-manifest.json",
                reason=reason,
            ),
            ReadGap(source="export-manifest.json (bindingsbestanden)", reason=reason),
        )
    refused = len(result.refused_binding_files)
    if not result.binding_files:
        if refused:
            # "deze export draagt geen bindingsbestanden [vastgesteld]" would
            # be established AND wrong here: the manifest DOES carry such an
            # entry, it just does not name a file that can be opened. The gap
            # itself already travels with `refused_binding_files`.
            return (
                _label_finding(
                    subject="kruiscontrole bindingen",
                    outcome="niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence="export-manifest.json",
                    reason=(
                        "dit manifest kondigt wel bindingsbestanden aan, maar geen van die"
                        " sleutels levert een bestandsnaam op, dus er is niets kruisgecontroleerd"
                    ),
                ),
                None,
            )
        # The manifest WAS read; that it lists no by-parent file is a fact
        # about a read manifest, so ESTABLISHED - but the fact is that there
        # is nothing to cross-check, not that a cross-check succeeded.
        return (
            _label_finding(
                subject="kruiscontrole bindingen",
                outcome="deze export draagt geen bindingsbestanden",
                certainty=Certainty.ESTABLISHED,
                evidence="export-manifest.json: geen bindingsbestand met een hash",
            ),
            None,
        )
    with_gap = result.binding_files_with_a_gap
    # "duidbare" wherever a manifest entry could not be interpreted at all,
    # and in EVERY branch: `result.binding_files` excludes the refused entry
    # either way, so the qualifier that says so belongs on every sentence that
    # quotes that number. It used to be added only in the middle branch, so an
    # export with BOTH a refused key and a real gap silently dropped it.
    files_word = "duidbare bindingsbestanden" if refused else "bindingsbestanden"
    if with_gap:
        outcome = f"{with_gap} van de {result.binding_files} {files_word} dragen een gat"
    elif refused:
        # Never "alle" while a manifest entry could not be interpreted at all:
        # a complete cross-check is exactly what cannot be claimed then. What
        # WAS cross-checked stays established, next to the gap.
        outcome = f"de {result.binding_files} {files_word} zijn kruisgecontroleerd"
    else:
        outcome = f"alle {result.binding_files} {files_word} zijn kruisgecontroleerd"
    return (
        _label_finding(
            subject="kruiscontrole bindingen",
            outcome=outcome,
            certainty=Certainty.ESTABLISHED,
            evidence=f"export-manifest.json: {result.binding_files} bindingsbestanden met een hash",
        ),
        None,
    )


def coverage_answer(export, knowledge: Knowledge) -> Answer:
    result = coverage_of(export)
    findings: list[Finding] = [
        _label_finding(
            subject="dekking",
            outcome=result.verdict,
            certainty=Certainty.ESTABLISHED,
            evidence=(f"export-manifest.json: {len(result.sources)} bronnen - {_tally(result.sources)}"),
        )
    ]
    read_gaps: list[ReadGap] = []
    for state in result.sources:
        if state.word in _READ_WORDS:
            continue
        findings.append(
            _label_finding(
                subject=state.subject,
                outcome=state.word,
                certainty=Certainty.ESTABLISHED,
                evidence=state.reason or "export-manifest.json",
            )
        )
        if state.word in _LOST_WORDS:
            read_gaps.append(ReadGap(source=state.subject, reason=state.reason or state.word))
    cross_check, cross_check_gap = _cross_check_finding(result)
    findings.append(cross_check)
    if cross_check_gap is not None:
        read_gaps.append(cross_check_gap)
    # The three sources of the certificate use outside the bindings: read, not
    # in the export, or not usably read. A source an older collector did not
    # fetch is named "niet in de export" and costs no coverage - the verdict
    # above is about what this manifest carries - but it is never silent.
    findings.extend(cert_usage_findings(export))
    route_lines, route_gaps = _route_source_lines(result, set(export.resources), tuple(export.refused_resource_keys))
    findings.extend(route_lines)
    read_gaps.extend(route_gaps)
    read_gaps.extend(result.refused_binding_files)
    read_gaps.extend(result.parent_gaps)
    # The certificate-use gaps, after every other: a source the list already
    # names (a lost source in the tally, a binding parent the cross-check
    # found missing) is not named a second time with the reader's own words.
    named = {gap.source for gap in read_gaps}
    read_gaps.extend(gap for gap in result.cert_usage_gaps if gap.source not in named)
    # A target name that the export boundary REFUSED is truthy (it carries a
    # sentence naming its shape, because "er is geen doel vastgelegd" and "er
    # stond een doel dat deze versie niet mag herhalen" are two different
    # statements). Truthy is not established: a read but uninterpretable field
    # is NIET VASTGESTELD with its shape named, so the flag decides here, not
    # the mere presence of text.
    # Read directly, not through a `getattr` default of False - which is the
    # ESTABLISHED answer, and so the one a missing field must never buy.
    target_refused = bool(export.target_name_refused)
    target_established = bool(export.target_name) and not target_refused
    if target_established:
        target_reason = ""
    elif target_refused:
        target_reason = (
            "deze export legt wel een doel vast, maar in een vorm die deze versie niet mag"
            " herhalen; de vastgelegde tekst wordt hier dus niet herhaald"
        )
    else:
        target_reason = "deze export draagt geen scan-doel.txt bij dit manifest"
    findings.append(
        _label_finding(
            subject="doel van de scan",
            outcome=export.target_name or "niet vastgelegd",
            certainty=Certainty.ESTABLISHED if target_established else Certainty.NOT_ESTABLISHED,
            evidence="scan-doel.txt, gebonden aan het manifest van deze export",
            reason=target_reason,
        )
    )
    findings.append(
        _label_finding(
            subject="logboek van de scan",
            outcome=f"{result.log_lines} regels" if result.log_lines is not None else "niet leesbaar",
            certainty=Certainty.ESTABLISHED if result.log_lines is not None else Certainty.NOT_ESTABLISHED,
            evidence=LOG_FILE,
            reason="" if result.log_lines is not None else f"{LOG_FILE} kon niet gelezen worden",
        )
    )
    return Answer(
        question="hoe compleet is dit antwoord",
        findings=findings,
        read_gaps=read_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_coverage_sources(export) -> tuple[str, ...]:
    """Every appliance object name `coverage_answer()` can print - the SEVENTH
    family of disclosure.names_from_export().

    The parent gaps NAME the object whose bindings were never read
    ("config/sslvserver kent VSRV-001, maar dit bestand draagt daarvoor geen
    parent-vermelding"). MEASURED (2026-09-06, on the real export): SIX of
    the seven by-parent files carried such a gap before the aggregate files
    were cross-checked (four since), and three of them name
    VSRV-001 - but all three derive that name from config/sslvserver, the
    same object source impact.BINDING_FILE is cross-checked against, so
    THAT name the third family of names_from_export() already knows.

    What this family adds is the parent names of the by-parent files whose
    object source no other family reads at all - for example
    sslprofile_sslcipher_binding.by-parent.json, cross-checked against
    config/sslprofile: the day that file carries a gap, the gap text names an
    sslprofile none of the other families has ever read.

    Over-collecting is NOT free: `names_from_export()` is handed to
    `render()` as `extra_names` by EVERY tool, so every name here is
    pseudonymised in every tool's output at `beperkt` and `minimaal` and
    lands in the operator's pseudonym table. This family used to take every
    parent name of every file - nine vendor-default ns_default_ssl_profile_*
    names among them, collected and never printed. Fail-closed by
    construction: an unreadable file yields no names.

    MEASURED once the aggregate files were cross-checked as well: the parent
    list of lbmonitor_binding is the appliance's built-in monitors ("sta",
    "ping", "http", "tcp"), returned as names although that file's gap (its
    object source has no hash) names no monitor. Every name is replaced as a
    substring at 'beperkt', so "sta" turned "geforceerde stand" into a
    pseudonym fragment in every tool's answer. The family therefore collects
    the parent names a gap of this tool actually CARRIES, standing on their
    own (`_stands_in`) - exactly what `rapport_dekking` can print, and no
    vendor default besides.
    """
    names: set[str] = set()
    for file_name in _binding_files(export).names:
        coverage = export.binding_parents(file_name)
        texts = [f"{gap.source} {gap.reason}" for gap in coverage.gaps]
        for name in coverage.names:
            if not (isinstance(name, str) and name.strip() and name.strip() != "(naamloos)"):
                continue
            clean = name.strip()
            if any(_stands_in(clean, text) for text in texts):
                names.add(clean)
    return tuple(sorted(names))


def _stands_in(name: str, text: str) -> bool:
    """Does `name` occur in `text` on its own - not inside a longer word?
    A side of the name that is itself a word character must not have a word
    character next to it; a side that is not carries no guard (the per-side
    rule the disclosure seam uses for a name typed into a question)."""
    before = r"(?<!\w)" if re.match(r"\w", name[0]) else ""
    after = r"(?!\w)" if re.match(r"\w", name[-1]) else ""
    return re.search(f"{before}{re.escape(name)}{after}", text) is not None
