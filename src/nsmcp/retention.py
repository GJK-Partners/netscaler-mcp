"""Keep prior scans in owned sibling directories, outside the recovery slot.

The current export and its fixed .vorig recovery slot retain their existing
meaning. Keeping runs only after both swap renames have succeeded. A failed
keep must never be reported as a failed swap or remove the new current export.
Manifest text supplies scan time only, never a filesystem path.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from nsmcp.export import TARGET_FILE, gate_target_name, plain_path as _plain_path
from nsmcp.limits import MAX_FILE_BYTES, MAX_JSON_DEPTH

KEPT_SUFFIX = ".bewaard-"
UNKNOWN_STAMP = "onbekend"
# Integration point 1 (merge on the release, 14-9-2026): the manifest ceiling
# and the JSON depth come from `nsmcp.limits`; the local name stays for the
# tests that monkeypatch it.
MAX_MANIFEST_BYTES = MAX_FILE_BYTES
MAX_TARGET_BYTES = 1024
_OWN_STAMP = re.compile(r"(?:[0-9]{8}T[0-9]{6}Z|onbekend)(?:-[0-9a-f]{32})?")
_SCAN_TIME = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,7}))?(Z|[+-][0-9]{2}:[0-9]{2})"
)
# Integration point 4 (merge on the release, 14-9-2026): one predictable stderr
# shape for the operator, next to the action log (`mcp_server.ACTION_LOG_PREFIX`,
# one JSON line per write action): a retention event is one JSON line with
# its own prefix, never a `logging` record whose visibility depends on the
# host's logging configuration. The text is this product's own fixed sentence;
# no path, name or input value ever travels in it.
RETENTION_LOG_PREFIX = "[nsmcp-bewaren]"


def _emit(event: str) -> None:
    row = {
        "tijd": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gebeurtenis": event,
    }
    try:
        print(
            f"{RETENTION_LOG_PREFIX} {json.dumps(row, ensure_ascii=True, sort_keys=True)}", file=sys.stderr, flush=True
        )
    except (OSError, ValueError):
        pass  # a closed stderr never changes what happened on disk


@dataclass(frozen=True)
class Retention:
    """Opt-in keeping policy; count zero also disables keeping."""

    enabled: bool = False
    count: int = 5
    floor_mb: int = 2048

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise ValueError("bewaren.enabled moet een boolean zijn")
        for name, value in (("exports_per_doel", self.count), ("vrije_ruimte_vloer_mb", self.floor_mb)):
            if type(value) is not int or value < 0:
                raise ValueError(f"bewaren.{name} moet een geheel getal van 0 of hoger zijn")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("dubbel manifestveld")
        result[key] = value
    return result


def _refuse_constant(value):
    raise ValueError("ongeldig JSON-getal")


def _manifest_snapshot(directory: Path) -> tuple[dict, str] | None:
    """Bounded structural ownership gate, without following manifest paths."""
    manifest = directory / "export-manifest.json"
    if not _plain_path(directory, directory=True) or not _plain_path(manifest, directory=False):
        return None
    try:
        if manifest.resolve().parent != directory.resolve():
            return None
        with manifest.open("rb") as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(data) > MAX_MANIFEST_BYTES:
            return None
        raw = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_object, parse_constant=_refuse_constant)
        stack = [(raw, 1)]
        while stack:
            value, depth = stack.pop()
            if depth > MAX_JSON_DEPTH:
                return None
            if isinstance(value, float) and not math.isfinite(value):
                return None
            if isinstance(value, dict):
                stack.extend((v, depth + int(isinstance(v, (dict, list)))) for v in value.values())
            elif isinstance(value, list):
                stack.extend((v, depth + int(isinstance(v, (dict, list)))) for v in value)
        if not isinstance(raw, dict) or raw.get("manifestVersion") not in ("1.0", "1.1"):
            return None
        if not isinstance(raw.get("resources"), dict) or not isinstance(raw.get("files"), dict):
            return None
        if not all(isinstance(value, dict) for value in raw["resources"].values()):
            return None
        if not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in raw["files"].values()
        ):
            return None
        return raw, hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError):
        return None


def _read_manifest(directory: Path) -> dict | None:
    snapshot = _manifest_snapshot(directory)
    return snapshot[0] if snapshot is not None else None


def target_identity(directory: Path) -> str | None:
    """Bounded, shape-gated target name bound to this exact valid manifest.

    None is no identity evidence, never a name inferred from the directory.
    The hash binds two local files; it is not an authenticity signature.
    Read only the two fixed files, refusing links, reparse points and escapes.
    """
    snapshot = _manifest_snapshot(directory)
    path = directory / TARGET_FILE
    if snapshot is None or not _plain_path(path, directory=False):
        return None
    try:
        if path.resolve().parent != directory.resolve():
            return None
        with path.open("rb") as stream:
            data = stream.read(MAX_TARGET_BYTES + 1)
        if len(data) > MAX_TARGET_BYTES:
            return None
        lines = data.decode("utf-8").splitlines()
        if len(lines) != 2 or lines[1].strip().lower() != snapshot[1]:
            return None
        name, refused = gate_target_name(lines[0].strip())
        return name if not refused else None
    except (OSError, ValueError, UnicodeError):
        return None


def _scan_moment(raw: dict | None) -> tuple[datetime, int] | None:
    """UTC seconds plus 100 ns fraction; unknown time cannot establish order."""
    value = raw.get("collectedAtUtc") if raw else None
    if not isinstance(value, str) or len(value) > 40:
        return None
    match = _SCAN_TIME.fullmatch(value.strip())
    if match is None:
        return None
    offset = match[3]
    # fromisoformat normalizes malformed offsets such as +00:60 to +01:00.
    # Gate the components before parsing so unreadable time stays unknown.
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        return None
    try:
        moment = datetime.fromisoformat(match[1] + offset.replace("Z", "+00:00"))
        return moment.astimezone(UTC), int((match[2] or "").ljust(7, "0"))
    except (ValueError, OverflowError):
        return None


def _owned_manifest(candidate: Path, export_dir: Path) -> dict | None:
    """Revalidate before using or deleting a kept sibling; never trust a list."""
    prefix = export_dir.name + KEPT_SUFFIX
    if not candidate.name.startswith(prefix) or _OWN_STAMP.fullmatch(candidate.name[len(prefix) :]) is None:
        return None
    if not _plain_path(export_dir.parent, directory=True) or not _plain_path(candidate, directory=True):
        return None
    try:
        if candidate.resolve().parent != export_dir.parent.resolve():
            return None
    except (OSError, ValueError):
        return None
    return _read_manifest(candidate)


def _discard_previous(previous: Path, export_dir: Path) -> None:
    """Only the fixed recovery sibling is eligible for legacy swap cleanup."""
    if previous != export_dir.parent / (export_dir.name + ".vorig"):
        return
    if not _plain_path(previous, directory=True):
        return
    try:
        shutil.rmtree(previous)
    except OSError:
        _emit("opruimen van .vorig is niet gelukt; de nieuwe export blijft geldig")


def keep(previous: Path, export_dir: Path, policy: Retention) -> Path | None:
    """Rename the fixed prior slot; failures never turn a committed scan back."""
    if previous != export_dir.parent / (export_dir.name + ".vorig"):
        return None
    if not _plain_path(previous, directory=True):
        return None
    if not policy.enabled or policy.count == 0:
        _discard_previous(previous, export_dir)
        return None
    moment = _scan_moment(_read_manifest(previous))
    stamp = moment[0].strftime("%Y%m%dT%H%M%SZ") if moment else UNKNOWN_STAMP
    target = export_dir.parent / f"{export_dir.name}{KEPT_SUFFIX}{stamp}"
    # Existing copies, even invalid ones, are never removed on a collision.
    # The per-export collector lock serializes this normal rename operation.
    try:
        if target.exists() or target.is_symlink():
            target = target.with_name(target.name + "-" + uuid4().hex)
        if target.exists() or target.is_symlink():
            raise FileExistsError()
        previous.rename(target)
        return target
    except OSError:
        _emit("vorige export kon niet worden bewaard; de nieuwe export blijft geldig")
        _discard_previous(previous, export_dir)
        return None


def kept_exports(export_dir: Path) -> tuple[Path, ...]:
    """Owned valid siblings, newest scan first; unknown times follow last."""
    if not _plain_path(export_dir.parent, directory=True):
        return ()
    try:
        found = []
        for candidate in export_dir.parent.iterdir():
            raw = _owned_manifest(candidate, export_dir)
            if raw is not None:
                moment = _scan_moment(raw)
                key = moment or (datetime.min.replace(tzinfo=UTC), -1)
                found.append((key, candidate.name, candidate))
        return tuple(row[2] for row in sorted(found, reverse=True))
    except OSError:
        return ()


def newest_kept(export_dir: Path) -> Path | None:
    for candidate in kept_exports(export_dir):
        if _scan_moment(_owned_manifest(candidate, export_dir)) is not None:
            return candidate
    return None


def free_mb(path: Path) -> int | None:
    """Free whole MiB on the export's parent filesystem, or unknown.

    Exact nonnegative integers only. Unknown space must close cleanup, not
    authorize deleting history via a large sentinel or a boolean-as-integer.
    """
    try:
        free = shutil.disk_usage(path.parent).free
        return free // (1024 * 1024) if type(free) is int and free >= 0 else None
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        return None


def _space_stop(export_dir: Path, policy: Retention, removed: bool) -> str | None:
    available = free_mb(export_dir)
    if type(available) is not int or available < 0:
        reason = "vrije ruimte niet vastgesteld"
    elif available < policy.floor_mb:
        reason = "vrije ruimte onder de ingestelde vloer"
    else:
        return None
    action = "geen verdere exports worden opgeruimd" if removed else "er wordt NIETS opgeruimd"
    return f"bewaarbeleid: {reason}; {action}"


def prune(export_dir: Path, policy: Retention) -> tuple[str, ...]:
    """Keep N known-time exports per verified target, plus unknown-time ones.

    Unidentified targets share a separate bucket for this export directory.
    Disabled keeping (also count zero) leaves existing history untouched.
    Cleanup requires measured space before ANY removal and before EACH one.
    Current, recovery, foreign and unowned paths never qualify. Every candidate
    is revalidated at the deletion boundary, under the collector's export lock.
    """
    if not policy.enabled or policy.count == 0:
        return ()
    stop = _space_stop(export_dir, policy, False)
    if stop:
        return (stop,)
    lines: list[str] = []
    groups: dict[str | None, list] = {}
    unknown_time = False
    for candidate in kept_exports(export_dir):
        raw = _owned_manifest(candidate, export_dir)
        if raw is None:
            continue
        identity = target_identity(candidate)
        moment = _scan_moment(raw)
        groups.setdefault(identity, [])
        if moment is None:
            unknown_time = True
            continue
        groups[identity].append((moment, candidate.name, candidate, raw, identity))
    if None in groups:
        lines.append("bewaarbeleid: doelidentiteit niet vastgesteld; aparte groep zonder identiteitsbewijs")
    if unknown_time:
        lines.append("bewaarbeleid: scanmoment niet vastgesteld; deze exports blijven bewaard")
    candidates = []
    for group in groups.values():
        candidates.extend(sorted(group, key=lambda row: row[:2], reverse=True)[policy.count :])
    removed = False
    for _, _, candidate, snapshot, identity in sorted(candidates, key=lambda row: row[:2]):
        stop = _space_stop(export_dir, policy, removed)
        if stop:
            lines.append(stop)
            break
        # Recheck identity before the final ownership check. A stale list is
        # never authority to delete a path or a changed export.
        if target_identity(candidate) != identity or _owned_manifest(candidate, export_dir) != snapshot:
            lines.append("bewaarbeleid: bewaarde export niet opnieuw bevestigd; opruimen gestopt")
            break
        try:
            shutil.rmtree(candidate)
        except OSError:
            lines.append("bewaarbeleid: verwijderen niet gelukt; opruimen gestopt")
            break
        removed = True
        # Only the just-validated owned stamp/UUID, never the target prefix.
        suffix = candidate.name[len(export_dir.name + KEPT_SUFFIX) :]
        lines.append(f"bewaarbeleid: bewaarde export {suffix} verwijderd")
    return tuple(lines)
