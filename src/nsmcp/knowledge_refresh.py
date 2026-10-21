"""`python -m nsmcp.knowledge_refresh` - the monthly knowledge-package refresh.

The rule this module exists for, and there is only one: a candidate package
that does not pass LOAD VALIDATION never replaces the current one. `THE`
validator is `knowledge.load_knowledge()` - this module never reimplements
any part of what makes a knowledge package readable; it only decides what
happens to the FILES around a verdict `load_knowledge()` already gave.

Being rejected is made visible three ways at once, always together:

- the candidate is kept, unmodified, beside the current package as
  `<current>.afgekeurd-<UTC>.json`;
- a line is appended to `<beheer_dir>/kennisverversing.log`, whether the
  refresh succeeded or not - a silent success is as wrong as a silent
  failure;
- `main()` (the CLI) exits non-zero, so a scheduled task notices.

What is deliberately OUT of scope, and why: the scheduled task itself, the
export of a candidate out of the knowledge source, and the journal line
that records a successful refresh are not product code - an MCP server is
no more a scheduler than it is a cron daemon. Those three live as a
procedure in `docs/klant/AUTOMATISERING.md`. What this module DOES own is
the half that can actually go wrong: judging the candidate, and never
replacing the current package silently.

HARDENING, the same class already found and fixed three times elsewhere in
this workstream: a candidate package is UNTRUSTED input. Nothing read out
of it (a version string, `load_knowledge()`'s own reason text, an
exception message) is ever pasted into a log line or a path unbounded and
unescaped - `upgrade._bounded_run_echo()` collapses any embedded line
break (so a crafted version string cannot forge a second, fake log line -
the same attack this product's own `Answer.to_text()` has to defend
`[vastgesteld]` lines against), strips any other non-printable character
(a raw ANSI escape, BEL or NUL - collapsing line breaks alone does not
stop a payload that rewrites the PRECEDING line instead of forging a new
one) and bounds the length. This module used to carry its own copy of
that sanitiser (`_safe_echo()`) - a verbatim duplicate that could only
drift from the original the next time one of the two was hardened and
not the other, which is exactly what happened here - so it now imports
`upgrade._bounded_run_echo()` instead, the same cross-module reuse of a
private helper `upgrade_gate.py` already relies on for `_read_moment()`.
No content read FROM a candidate is ever used to build a filesystem path
either - every path this module writes to is built from the CALLER-
supplied `current` path and a name this module picks itself
(`_sibling_path()`), never from anything inside the package.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

from nsmcp.knowledge import load_knowledge
from nsmcp.upgrade import _bounded_run_echo

LOG_FILE_NAME = "kennisverversing.log"

# The three outcome words this module's own log/CLI surface uses. Only
# REJECTED_LABEL and INSTALLED_LABEL come from this module's own tests
# (`tests/test_knowledge_refresh.py`); FAILED_LABEL is a later
# addition for the one outcome the original rule does not name - an
# unexpected I/O failure DURING an otherwise-valid install (see
# `install_package()`'s docstring, "Edge case: an interrupted replace").
# Calling that AFGEKEURD would misreport it as a judged rejection it never
# was; "always log a line, succeeded or not" does not say every line must
# use only two words, and an inaccurate audit trail is worse than a third
# one.
REJECTED_LABEL = "AFGEKEURD"
INSTALLED_LABEL = "GEINSTALLEERD"
FAILED_LABEL = "MISLUKT"


@dataclass(frozen=True)
class RefreshResult:
    """`installed` is the one fact a caller acts on; `reason` is the Dutch
    sentence this module already wrote to the log for it (never rebuilt
    twice). `logged` says whether the log write ITSELF succeeded - see
    `install_package()`'s docstring on why a failure there does not also
    fail the install/reject decision. `kept` says the same thing for the
    OTHER visibility leg, preservation: whether `_keep_rejected()` managed
    to write the rejected candidate beside `current`. It stays `True` on
    every path that never calls `_keep_rejected()` at all (an install, or
    an install failure) - there was nothing to preserve, so there is
    nothing to have failed at."""

    installed: bool
    reason: str
    logged: bool = True
    kept: bool = True


def _sibling_path(current: Path, kind: str, moment: datetime) -> Path:
    """`<current>.<kind>-<UTC>.json`, built ENTIRELY from the caller-
    supplied `current` path and a timestamp this module generates itself -
    never from anything read out of a package. Two calls that land in the
    same UTC second (two runs of this CLI close together, or two calls
    within one process) get a numbered suffix instead of one silently
    overwriting the other's file - a kept package is exactly the thing
    this module promises never to lose."""
    stamp = moment.strftime("%Y%m%dT%H%M%SZ")
    candidate_path = current.with_name(f"{current.name}.{kind}-{stamp}.json")
    counter = 2
    while candidate_path.exists():
        candidate_path = current.with_name(f"{current.name}.{kind}-{stamp}-{counter}.json")
        counter += 1
    return candidate_path


def _write_log_line(beheer_dir: Path, label: str, current: Path, reason: str) -> bool:
    """Appends one line to `<beheer_dir>/kennisverversing.log`, creating
    the directory if needed. Returns whether the write itself succeeded -
    a `_beheer` directory that cannot be created or written to must not
    take down the install/reject decision this module already made (that
    decision, and the CLI's exit code built on it, is the primary signal -
    "de CLI eindigt met een niet-nul exitcode zodat de
    geplande taak het merkt"); it is instead surfaced to whoever is
    watching the CLI run, via `RefreshResult.logged` and main()'s own
    `[WAARSCHUWING]` line."""
    beheer_dir = Path(beheer_dir)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{timestamp} {label} {current.name}: {reason}\n"
    try:
        beheer_dir.mkdir(parents=True, exist_ok=True)
        with (beheer_dir / LOG_FILE_NAME).open("a", encoding="utf-8") as stream:
            stream.write(line)
        return True
    except OSError:
        return False


def _keep_rejected(candidate: Path, current: Path) -> bool:
    """Preserves the rejected candidate, unmodified, as
    `<current>.afgekeurd-<UTC>.json` - the first of the three ways a
    rejection stays visible. `shutil.copyfile()` follows a symlink
    candidate to its real content, so what is kept is always real bytes,
    never a dangling link.

    Returns whether the copy itself succeeded - the same pattern
    `_write_log_line()` one function up already uses for the SAME reason:
    a read-only export root, a full disk, a locked candidate or a path-
    length limit must not vanish silently. This used to swallow every
    `OSError` outright; it now hands the
    outcome to `install_package()`, which carries it in
    `RefreshResult.kept`, and `main()` surfaces a failure here as a
    `[WAARSCHUWING]` line, the same way it already does for `logged`. The
    judged AFGEKEURD decision and its non-zero exit code - the primary
    signal `_write_log_line()`'s own docstring names - do not change
    because of this; a candidate that cannot be copied AT ALL (the
    directory case `load_knowledge()` already refused it for) is simply
    one more case this same bool now reports, not a second, different
    kind of failure."""
    destination = _sibling_path(current, "afgekeurd", datetime.now(UTC))
    try:
        shutil.copyfile(candidate, destination)
        return True
    except OSError:
        return False


def _install(candidate: Path, current: Path) -> None:
    """The atomic half: current's own existing content (if any) is kept
    beside it first as `<current>.vervangen-<UTC>.json`, then the
    candidate is copied into a temporary file IN THE SAME DIRECTORY as
    `current` (so the swap below is atomic regardless of which volume
    `candidate` itself lives on) and swapped in with `os.replace()` -
    atomic on the same volume, the same idiom this product already uses
    elsewhere (`collect._swap()`) for a directory-level version of the
    same problem.

    Edge case, decided: an interrupted replace. `os.replace()` itself
    either fully renames or raises - it never leaves `current` half
    written, by the OS's own contract, so nothing extra is needed to
    protect `current` itself. What DOES need protecting is the orphaned
    temporary file a raised `os.replace()` leaves behind: left in place,
    it would be a half-installed artifact sitting next to the target
    forever. It is removed here before the exception is re-raised to
    `install_package()`, which turns it into a `FAILED_LABEL` log line
    and a `RefreshResult(installed=False, ...)` rather than an uncaught
    exception - "always log a line" covers this path too, not only a
    judged rejection."""
    if current.exists():
        backup_path = _sibling_path(current, "vervangen", datetime.now(UTC))
        shutil.copyfile(current, backup_path)
    current.parent.mkdir(parents=True, exist_ok=True)
    temp_path = current.with_name(f"{current.name}.tmp-{uuid4().hex}")
    shutil.copyfile(candidate, temp_path)
    try:
        os.replace(temp_path, current)
    except OSError:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def install_package(candidate: Path, current: Path, today: date, beheer_dir: Path) -> RefreshResult:
    """The one entry point. Loads `candidate` through `load_knowledge()` -
    the only validator - and either installs it in place of `current` or
    rejects it, always logging exactly one line to
    `<beheer_dir>/kennisverversing.log` before returning.

    Fail-closed rule, in order:

    1. `candidate` must pass `load_knowledge()` - `missing` is the one
       word for "did not load", covering an unreadable file, a directory,
       a package with an unusable shape, or one dated in the future.
    2. `candidate`'s own `datum` must not be OLDER than the CURRENT
       package's `datum` - a refresh that goes back in time is not a
       refresh. Decided edge case: when `current` itself does not load
       (missing, corrupt, or simply not there yet on a first install),
       there is no date to be older THAN, so this check is skipped rather
       than blocking an otherwise-valid candidate on a current package
       that is already broken.

    Anything that fails either gate is rejected: the candidate is kept
    beside `current` (`_keep_rejected()`) and `current` itself is never
    touched. Otherwise `_install()` performs the atomic swap.

    Decided edge case: a candidate byte-identical to the current package.
    Nothing above tests content equality, only validity and recency - an
    identical candidate has the same date as `current` (not OLDER), so it
    installs normally. Detecting "nothing actually changed" is not part
    of the one rule this module implements, and adding it would be
    untested scope beyond what this module promises.
    """
    candidate = Path(candidate)
    current = Path(current)
    beheer_dir = Path(beheer_dir)

    candidate_knowledge = load_knowledge(candidate, today)
    if candidate_knowledge.missing:
        reason = _bounded_run_echo(candidate_knowledge.reason)
        kept = _keep_rejected(candidate, current)
        logged = _write_log_line(beheer_dir, REJECTED_LABEL, current, reason)
        return RefreshResult(installed=False, reason=reason, logged=logged, kept=kept)

    current_knowledge = load_knowledge(current, today)
    if not current_knowledge.missing:
        if date.fromisoformat(candidate_knowledge.date) < date.fromisoformat(current_knowledge.date):
            reason = (
                "kandidaat is ouder dan het huidige pakket "
                f"(kandidaat: {candidate_knowledge.date}, huidig: {current_knowledge.date})"
            )
            kept = _keep_rejected(candidate, current)
            logged = _write_log_line(beheer_dir, REJECTED_LABEL, current, reason)
            return RefreshResult(installed=False, reason=reason, logged=logged, kept=kept)

    try:
        _install(candidate, current)
    except OSError as exc:
        reason = f"installatie mislukt: {_bounded_run_echo(exc)}"
        logged = _write_log_line(beheer_dir, FAILED_LABEL, current, reason)
        return RefreshResult(installed=False, reason=reason, logged=logged)

    if candidate_knowledge.version is None:
        version_text = "(geen versie)"
    else:
        version_text = _bounded_run_echo(candidate_knowledge.version)
    reason = f"versie {version_text} geinstalleerd"
    logged = _write_log_line(beheer_dir, INSTALLED_LABEL, current, reason)
    return RefreshResult(installed=True, reason=reason, logged=logged)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m nsmcp.knowledge_refresh",
        description=(
            "Ververs het kennispakket: een kandidaat die niet door de "
            "laadvalidatie komt vervangt het huidige pakket nooit."
        ),
    )
    parser.add_argument("kandidaat", type=Path, help="pad naar het nieuwe kennispakket")
    parser.add_argument("huidig", type=Path, help="pad naar het huidige kennispakket")
    parser.add_argument(
        "--beheer",
        type=Path,
        required=True,
        help="pad naar de _beheer-map waarin kennisverversing.log komt",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """The CLI: `python -m nsmcp.knowledge_refresh <kandidaat> <huidig>
    --beheer <map>`. Exit 0 for an installed package, 1 for anything else
    - a judged rejection and an unexpected install failure both leave the
    old package untouched, and `docs/klant/AUTOMATISERING.md` tells the
    operator to treat any non-zero exit the same way: read the log, the
    old package is still there. Never runs silently: every call prints a
    `[START]` line, ends with exactly one `[EINDSTATUS]` line, and both a
    preservation failure and a log write that itself failed are surfaced
    as their own `[WAARSCHUWING]` line rather than swallowed (for the
    former; the `logged` case already worked this
    way).

    `install_package()` itself can only fail the two
    ways its own docstring names (a judged rejection, or an `OSError`
    during `_install()`) - anything ELSE it does not anticipate (a
    `ValueError` out of `_sibling_path()` for a `huidig` path with no
    name, e.g. `.`) used to escape as a bare traceback, skipping the
    `MISLUKT` log line and the `[EINDSTATUS]` line this docstring
    promises. The `try` below is the top-level guard for exactly that -
    an unanticipated exception still ends in a logged line, `[FOUT]`,
    `[EINDSTATUS]` and a non-zero exit, the same contract as a judged
    rejection."""
    args = _parse_args(argv)
    print(f"[START] kennisverversing: kandidaat={args.kandidaat} huidig={args.huidig}")
    today = datetime.now(UTC).date()
    try:
        result = install_package(args.kandidaat, args.huidig, today, args.beheer)
    except Exception as exc:  # noqa: BLE001 - the top-level guard this docstring promises
        reason = f"onverwachte fout tijdens installatie: {_bounded_run_echo(exc)}"
        logged = _write_log_line(args.beheer, FAILED_LABEL, args.huidig, reason)
        if not logged:
            log_path = Path(args.beheer) / LOG_FILE_NAME
            print(f"[WAARSCHUWING] kon geen regel wegschrijven naar {log_path}", file=sys.stderr)
        print(f"[FOUT] {reason}", file=sys.stderr)
        print("[EINDSTATUS] kennispakket afgekeurd - het oude pakket staat er nog", file=sys.stderr)
        return 1
    if not result.kept:
        print(
            f"[WAARSCHUWING] kon de afgekeurde kandidaat niet bewaren naast {args.huidig}",
            file=sys.stderr,
        )
    if not result.logged:
        log_path = Path(args.beheer) / LOG_FILE_NAME
        print(f"[WAARSCHUWING] kon geen regel wegschrijven naar {log_path}", file=sys.stderr)
    if result.installed:
        print(f"[OK] {result.reason}")
        print("[EINDSTATUS] kennispakket geinstalleerd")
        return 0
    print(f"[FOUT] {result.reason}", file=sys.stderr)
    print("[EINDSTATUS] kennispakket afgekeurd - het oude pakket staat er nog", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
