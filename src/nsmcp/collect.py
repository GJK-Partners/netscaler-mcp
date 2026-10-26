"""The boundary between Python and the NSHC collector script.

This is the only place where this product touches an appliance, and it does
not do so itself: it invokes the released, independently reviewed read path
of NSHC 1.0. Two rules govern everything here:

1. A scan NEVER runs over the top of the current export. A scan goes to a
   fresh directory; that directory is verified; only then is it swapped in.
   A failed or partial scan therefore leaves the previous data intact, and
   the data age in the answer shows by itself that nothing was refreshed.
2. There is no escape from certificate verification. `-AcceptSelfSignedCert`
   is not in this code and must never be added.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from nsmcp import localpath
from nsmcp.answer import ReadGap, repeatable_token
from nsmcp.export import MISSING as _MISSING, TARGET_FILE, USABLE, load_export, shape_of
from nsmcp.limits import MAX_FILE_BYTES, neutralise_hidden
from nsmcp.localpath import PathRefused
from nsmcp.powershell import (
    ChildWorkingDirectoryUnusable,
    PowerShellMissing,
    ScriptPinMismatch,
    script_policy,
    start_powershell,
)
from nsmcp.retention import Retention, _discard_previous, keep, prune
from nsmcp.target import CertAgreement, Target

# The fixed phrase that takes the place of the collector script's own output
# below openheid 'volledig' - see `CollectError.without_script_output()`. The
# same words as the closing stamp at 'minimaal' (`disclosure.py`,
# `_TARGET_NOT_SHOWN_AT_MINIMAL`): one vocabulary for "withheld on this
# setting", never a second one.
SCRIPT_OUTPUT_NOT_SHOWN = "scriptuitvoer niet getoond op deze stand"


class CollectError(Exception):
    """The scan did not succeed. Never silent, never as an empty export.

    `evidence_dir` names the directory that holds evidence of THIS
    specific attempt - the work directory `_preserve_as_failed` moved to
    the fixed `.mislukt` slot next to `export_dir` - or `None` when this
    attempt never produced a directory of its own (refused before a work
    directory existed at all: a missing script, a concurrent scan already
    holding the lock, a full disk on `mkdir`/`mkdtemp`).

    A caller building a phase diagnosis (`phase_report` below, design 2.2
    row A16) reads THIS field instead of guessing from a directory's mere
    existence: a `.mislukt` slot left behind by an earlier, UNRELATED
    attempt must never be read as if it were about the attempt that just
    failed - see the docstring of `phase_report`.

    `script_output` carries the ONE part of a message that is not this
    product's own text: the summarized tail of the collector script's
    output (`_short_report` below), present only on the failed-script
    exit path. `_scrub_error_text` masks the three values this product
    knows as "of the target" in it and nothing else - so below openheid
    'volledig' that tail must not reach the model at all, and
    `without_script_output()` is how the caller (`status_ververs`,
    mcp_server.py) obtains the same error without it. Every other
    CollectError (a held lock, a timeout, an OS error KIND, a failed
    manifest check) carries `None` here: those are classified product
    texts that pass through unchanged at every level.
    """

    def __init__(
        self,
        message: str,
        *,
        evidence_dir: Path | None = None,
        script_output: str | None = None,
    ) -> None:
        super().__init__(message)
        self.evidence_dir = evidence_dir
        self.script_output = script_output

    def without_script_output(self) -> CollectError:
        """The same error with the collector script's own output replaced
        by the fixed `SCRIPT_OUTPUT_NOT_SHOWN` phrase; `evidence_dir` is
        kept, so the phase diagnosis (`phase_report`) is unaffected.

        An error without script output is returned as-is: withholding is
        about the other product's raw text, never about this product's
        own classified reasons.

        The tail sits at ONE known place: directly after this product's
        own prefix, which ends in the first ": " of the message
        (`het verzamelscript stopte met exitcode <n>: `); whatever
        `collect()` wraps around it later is appended BEHIND the tail
        (`(bewaard voor onderzoek in ...)`). So the replacement is
        positional, not a substring search: a free `str.replace` hit the
        prefix itself whenever the script happened to print a word the
        prefix contains (`exitcode`) - leak-safe, but garbled, and the
        exit code was gone (review finding on the first version). Fail-
        closed when the tail is NOT at that place: then the WHOLE message
        becomes the fixed phrase rather than a guess about which part of
        it was safe.
        """
        if not self.script_output:
            return self
        text = str(self)
        start = text.find(": ") + 2
        if start >= 2 and text.startswith(self.script_output, start):
            text = text[:start] + SCRIPT_OUTPUT_NOT_SHOWN + text[start + len(self.script_output) :]
        else:
            text = SCRIPT_OUTPUT_NOT_SHOWN
        return CollectError(text, evidence_dir=self.evidence_dir)


# 1.0.2: how a reason starts when the collector process never ran.
NOT_STARTED = "het verzamelscript is niet gestart: "


class CollectNotStarted(CollectError):
    """1.0.2: the collector process never started - a script that does not
    match its pin, no PowerShell, an OS error at the start. A subclass, so
    every caller of `CollectError` keeps its behaviour; `read_single_resource`
    tells it apart from a run that started and then failed."""


def build_arguments(target: Target, out_dir: Path, script_path: Path) -> list[str]:
    arguments = [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        script_policy().execution_policy,
        "-File",
        str(script_path),
        "-NetScaler",
        target.address,
        "-OutDir",
        str(out_dir),
        "-CredentialTarget",
        target.credential_target,
        "-SkipTransport",
    ]
    if target.agreement is CertAgreement.FINGERPRINT:
        arguments += ["-ExpectedCertThumbprint", str(target.fingerprint)]
    return arguments


_POLL_INTERVAL_S = 0.2


def _stop_child_process(process: subprocess.Popen[str], grace_s: float = 5.0) -> None:
    """Ends a running child process: terminate() (on Windows that is
    already TerminateProcess(), the same as kill() - see the Python
    documentation of subprocess.Popen.terminate()), and if it does not
    stop within `grace_s` an explicit kill() attempt follows. Best-effort:
    a process that just exited on its own (OSError/ProcessLookupError on
    the signal, or still alive after the second wait) must never crash
    this function - it always runs while a CollectError is about to be
    raised anyway.
    """
    for action in (process.terminate, process.kill):
        try:
            action()
        except OSError:
            pass
        try:
            process.wait(timeout=grace_s)
            break
        except subprocess.TimeoutExpired:
            continue
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def _run_powershell(arguments: list[str], timeout_s: int, stop: SwapGate | None = None) -> tuple[int, str]:
    """Starts the collector script as a REAL child process and POLLS the
    result, instead of blocking once in `subprocess.run` - a cancelled
    call would otherwise leave the child process quietly running (found in
    review: measured, not assumed).

    `Popen.communicate(timeout=...)` is the pattern Python documents for
    this: when the poll interval expires it is SAFE to call
    `communicate()` again - output already read is not lost (cpython
    buffers it internally between attempts). Every poll round checks two
    things: has `stop` been set (a cancellation by the caller, see
    `status_ververs` in mcp_server.py) and has the total time limit
    passed (the existing guarantee, now measured across separate poll
    rounds instead of in a single blocking call - the behavior toward the
    caller is unchanged). In both cases the child process is REALLY ended
    (`_stop_child_process`) before the CollectError is raised: never an
    "aborted" scan whose child process secretly keeps running.

    Both output streams are held on to and returned TOGETHER: the real
    NSHC 1.0 collector logs via `Write-Host` - that is stdout, not stderr
    (see NshcCollector-PlakEditie.ps1, `Log { ... Write-Host ... }`) - so
    a stderr-only capture would structurally report "geen foutregel"
    against this collector even when the script logged clearly why it
    stopped. The caller passes the combined text, unchanged for the rest
    of the chain, to `_short_report`/`_scrub_error_text`. stdout comes
    first (the usual content on an explicit `exit <code>`) with stderr
    behind it (the content of an unhandled .NET exception) - so the tail
    of the combined text keeps carrying the most meaningful material,
    whichever stream the script actually filled.
    """
    # 1.0.2: the three ways the process never starts raise
    # `CollectNotStarted`, so a live read can say "niet gestart" instead of
    # naming a route that never ran.
    try:
        process = start_powershell(arguments)
    except ScriptPinMismatch as exc:
        # 1.0.2: the message names the file name only.
        raise CollectNotStarted(f"{NOT_STARTED}{exc}") from None
    except ChildWorkingDirectoryUnusable as exc:
        # 1.0.3 (R3-5): the real reason, not "PowerShell niet gevonden"; the
        # message names the kind of problem, never the local path.
        raise CollectNotStarted(f"kon PowerShell niet starten: {exc}") from None
    except PowerShellMissing:
        # The merge keeps the absolute starter AND the masking of the OS error: the
        # PowerShellMissing text names the absolute install path, which is a
        # local machine path an answer must never carry, so the kind is
        # stated instead of the exception - see `_os_error_kind`.
        raise CollectNotStarted("kon PowerShell niet starten (Windows PowerShell niet gevonden)") from None
    except OSError as exc:
        # Never `{exc}` - see `_os_error_kind`.
        raise CollectNotStarted(f"kon PowerShell niet starten ({_os_error_kind(exc)})") from None

    elapsed_s = 0.0
    while True:
        try:
            stdout_text, stderr_text = process.communicate(timeout=_POLL_INTERVAL_S)
            break
        except subprocess.TimeoutExpired:
            elapsed_s += _POLL_INTERVAL_S
            if stop is not None and stop.is_set():
                _stop_child_process(process)
                raise CollectError(
                    "de scan is afgebroken door de aanroeper; de vorige gegevens blijven gelden"
                ) from None
            if elapsed_s >= timeout_s:
                _stop_child_process(process)
                raise CollectError(
                    f"de scan is na {timeout_s} seconden afgebroken; de vorige gegevens blijven gelden"
                ) from None
    combined = "\n".join(part for part in (stdout_text or "", stderr_text or "") if part)
    return process.returncode, combined


def _scrub_error_text(error_text: str, target: Target) -> str:
    """Removes the KNOWN values of `target` from an error line, regardless
    of upper/lower case.

    All three known values are masked: not only the credential-target
    name, but also the address and the fingerprint - they sit just as much
    on the command line (see `build_arguments` above) and thus just as
    much within reach of a collector error: a DNS error names the address
    literally ("The remote name could not be resolved: 'ns01...'"), a pin
    mismatch names the expected fingerprint.

    This remains a masking of KNOWN values, not a guarantee about the
    whole error output: see the docstring of `_short_report` below and the
    module docstring of mcp_server.py for what is explicitly NOT covered
    here.

    A bare `str.replace` misses every spelling other than exactly the
    casing the value happens to have; the comparison must therefore be
    case-insensitive.

    Replacement runs from LONG to SHORT (whichever field happens to carry
    the longer value): a fixed replacement order is unsafe as soon as two
    known values OVERLAP - for example an address "ns01.example" whose
    credential-target name "ns01" happens to be a substring. Replacing the
    SHORTER name first would leave the remainder of the LONGER value
    (".example") standing unreplaced: a piece of a known value would still
    leak, despite the full masking that docs/klant/SECURITY.md and the module
    docstring of mcp_server.py promise. Replacing the longer value as a
    whole, before a shorter value contained in it gets the chance to break
    that replacement, closes this.
    """
    replacements = [
        (target.credential_target, "<credential-target>"),
        (target.address, "<adres>"),
        (target.fingerprint, "<vingerafdruk>"),
    ]
    result = error_text
    for value, placeholder in sorted(
        (item for item in replacements if item[0]), key=lambda item: len(item[0]), reverse=True
    ):
        result = re.sub(re.escape(value), placeholder, result, flags=re.IGNORECASE)
    return result


_STDERR_TAIL_LINES = 10
# 1.0.2: one line of the tail is cut at this many characters, with a
# visible note - the review probe put 3000 characters in one line.
_STDERR_LINE_CHARS = 400
_NO_ERROR_LINE = "geen foutregel"


def _short_report(error_text: str, target: Target) -> str:
    """Builds a readable summary of the script error.

    Takes the last `_STDERR_TAIL_LINES` non-empty lines: in a PowerShell
    stack trace the informative line is rarely at the very bottom (that is
    often a decorative `at <ScriptBlock>, line 1`), but not reliably just
    above it either - a real error usually drags an "At <path>:line"
    context, +-pointers, CategoryInfo/FullyQualifiedErrorId and sometimes
    PSComputerName along before the call stack begins. This window is
    chosen wide enough to cover such a realistic PowerShell error, but
    remains a BOUNDED heuristic, not a guarantee: with an unusually long
    stack trace (for example a deep .NET InnerException chain) the
    informative line can still fall outside this window.

    The masking above (`_scrub_error_text`) covers only what `target`
    itself knows (address, credential-target name, fingerprint).
    Everything beyond that - up to ten lines of raw PowerShell stderr -
    goes through UNFILTERED. A value this product does not know as "of
    the target" (for example the actual certificate thumbprint the
    appliance returns on a pin mismatch, or an entirely different address
    in a redirect or DNS error message) can therefore simply appear in
    this report. See the module docstring of mcp_server.py for the same
    boundary, phrased for the reader of the answer.

    That is why this report reaches the model only at openheid 'volledig'.
    It travels as `CollectError.script_output`, and `status_ververs`
    (mcp_server.py) swaps it for the fixed `SCRIPT_OUTPUT_NOT_SHOWN` phrase
    below that level (`CollectError.without_script_output()`): the seam
    that cannot mask this text never has to see it there.
    """
    scrubbed = _scrub_error_text(error_text, target)
    lines = [line.strip() for line in scrubbed.splitlines() if line.strip()]
    if not lines:
        return _NO_ERROR_LINE
    # 1.0.2: every character that is invisible or moves text around
    # (ESC, a bidi override, a zero-width space) becomes visible, a long line
    # is cut with a note, and the lines left out are COUNTED - the same
    # "... (N regels ingekort)" the writing tools say (`_from_script`); the
    # cut used to be silent.
    shown = [
        line if len(line) <= _STDERR_LINE_CHARS else line[:_STDERR_LINE_CHARS] + " ...(regel afgekapt)"
        for line in (neutralise_hidden(line) for line in lines[-_STDERR_TAIL_LINES:])
    ]
    cut = len(lines) - _STDERR_TAIL_LINES
    if cut > 0:
        shown.insert(0, f"... ({cut} regels ingekort)")
    return " | ".join(shown)


def _has_usable_resource(resources: dict) -> bool:
    """Is there at least one resource with a status from `nsmcp.export.USABLE`?

    Deliberately not "all resources usable": a scan in which part could
    not be read is an honest partial result - the read path itself turns
    those resources into a read gap (see `nsmcp.export.USABLE`, from which
    this function reuses its definition of "usable", so the two can never
    drift apart). This gate only refuses the scan in which nothing at all
    could be read.
    """
    for entry in resources.values():
        if not isinstance(entry, dict):
            continue
        status = entry.get("status")
        if isinstance(status, str) and status in USABLE:
            return True
    return False


def _work_read(work_dir: Path, name: str, *, allow_missing: bool = True) -> localpath.LocalRead:
    """One file the collect script left in the work export map, read through
    `localpath` with the work export map as the root (1.1 B): a link or a
    reparse point on the way is a `PathRefused` (an OSError) for the
    caller's own typed unreadable route; nothing is followed."""
    root = localpath.absolute_text(work_dir)
    return localpath.read_local(
        localpath.under(root, name), root=root, max_bytes=MAX_FILE_BYTES, allow_missing=allow_missing
    )


def _verify(out_dir: Path) -> None:
    # Reading and parsing are two separate steps: each step gets its own,
    # contextual CollectError. A shared catch would cover the one error and
    # accidentally not the other - an OSError from the read
    # (PermissionError on an ACL conflict, a network path dropping away)
    # must never leak raw past the CollectError contract (see the class
    # docstring above).
    try:
        got = _work_read(out_dir, "export-manifest.json")
    except PathRefused as exc:
        raise CollectError(f"het export-manifest kon niet gelezen worden: {exc.reason}") from exc
    except OSError as exc:
        # never `{exc}` - see `_os_error_kind`.
        raise CollectError(f"het export-manifest kon niet gelezen worden ({_os_error_kind(exc)})") from exc
    if not got.exists:
        raise CollectError("de scan liep af zonder export-manifest; dat is een mislukte scan, geen lege omgeving")
    if got.over_cap:
        raise CollectError(
            f"het export-manifest is groter dan het plafond ({got.size} bytes tegen {MAX_FILE_BYTES}); niet gelezen"
        )
    try:
        manifest_text = localpath.as_text(got.data)
    except UnicodeDecodeError as exc:
        raise CollectError(f"het export-manifest is onleesbaar: {exc}") from None
    try:
        raw = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        raise CollectError(f"het export-manifest is onleesbaar: {exc}") from None
    # Valid JSON is not automatically an object: a list or bare value has
    # no .get() and would leak below as a raw AttributeError instead of a
    # CollectError - exactly the silent crash this design rules out.
    if not isinstance(raw, dict):
        raise CollectError(
            f"het export-manifest heeft geen geldige vorm (kreeg {type(raw).__name__} in plaats van een object)"
        )
    # isinstance, not str(x): str(None) becomes the text "None", which is
    # non-empty, so a bare `.strip()` check would let a JSON null timestamp
    # through unnoticed.
    timestamp = raw.get("collectedAtUtc")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise CollectError(
            "het export-manifest draagt geen tijdstempel; zonder collectedAtUtc kan geen antwoord "
            "zijn gegevensleeftijd melden"
        )
    # Not just PRESENCE but READABILITY: the error message above literally
    # promises that this gate covers "zonder collectedAtUtc kan geen
    # antwoord zijn gegevensleeftijd melden" - so it must actually be able
    # to PARSE it, with the same parsing answer.py::_age uses further down
    # the chain. Otherwise a manifest with "collectedAtUtc": "gisteren"
    # would pass this gate and be swapped in, and only the answer itself
    # would report the timestamp as unreadable.
    try:
        datetime.fromisoformat(timestamp)
    except ValueError:
        # The SHAPE, never the value (same idiom as `_phase_shape` below
        # and `export.shape_of`): this string was written by the collector
        # script and reaches `status_ververs`'s answer at every disclosure
        # level, outside every masking - so a manifest whose timestamp
        # field happens to carry a name, an address or a thumbprint would
        # otherwise be echoed verbatim. The length is enough to diagnose the file.
        raise CollectError(
            "het export-manifest draagt een onleesbaar tijdstempel (zonder de vorm van een "
            f"ISO 8601-tijdstempel, {len(timestamp)} tekens); zonder een leesbaar "
            "collectedAtUtc kan geen antwoord zijn gegevensleeftijd melden"
        ) from None
    resources = raw.get("resources")
    if not isinstance(resources, dict) or not resources:
        raise CollectError("het export-manifest bevat geen resources; er is niets gelezen om op te antwoorden")
    if not _has_usable_resource(resources):
        raise CollectError(
            "het export-manifest heeft geen enkele bruikbare resource (alles Error of onbekend); "
            "dat is een mislukte scan, geen resultaat om op te antwoorden"
        )


def _recover_interrupted_swap(export_dir: Path) -> bool:
    """Repairs the one window the swap leaves open.

    The swap is two renames: current -> .vorig, new -> current. If the
    process dies in between, the current export sits as .vorig and there
    is no export. That is exactly the case in which the server would
    otherwise answer on nothing. The next scan puts it back.

    Runs BEFORE `_acquire_lock` (see `collect()` below), so it also
    reaches the case the docstring above literally describes: the process
    dies BETWEEN the two renames, AND the lock file of that same scan
    stays behind because the finally that releases it never ran. With the
    lock first, `_acquire_lock` would refuse the call before recovery
    ever got a chance - permanently, since takeover of a stale lock is
    deliberately absent (see `_acquire_lock`).

    Two callers reaching this concurrently (without the protection of the
    lock) is harmless as long as the SECOND, when its own rename fails,
    still checks whether the FIRST has completed it in the meantime: there
    is nothing left to recover then and this simply returns False. Without
    that extra check the second caller would wrongly report its own,
    failed rename (`previous` no longer exists) as a real recovery error,
    while the export is in fact already in order - exactly the gap that
    check closes.

    If the rename fails for real (an open file handle, an ACL - so not
    because another caller just won), that must no more leak as a bare
    OSError than the swap itself - the same contract breach, now on the
    recovery step.

    Returns whether THIS call performed the rename itself - the caller
    uses that to give context to a possible subsequent lock refusal (see
    `_acquire_lock`).
    """
    previous = export_dir.parent / f"{export_dir.name}.vorig"
    if export_dir.exists() or not previous.exists():
        return False
    try:
        _rename_beside(previous, export_dir.name, export_dir)
    except OSError as exc:
        if export_dir.exists():
            # Another caller won the race between the check above and this
            # rename: the export is already in place, there is nothing left
            # to recover. See the docstring above.
            return False
        # never `{exc}` - a rename failure's
        # OSError.__str__() carries BOTH absolute paths. See
        # `_os_error_kind`.
        raise CollectError(f"het herstellen van de onderbroken omwisseling is mislukt ({_os_error_kind(exc)})") from exc
    return True


def _rename_beside(path: Path, new_name: str, export_dir: Path) -> None:
    """Renames a directory beside the export map (the export map itself, its
    recovery slot, a work map) within the map around the export, by handle,
    never onto an existing name (`localpath.rename_local`, 1.1 B). The root
    is the map around the export, as configured; what is renamed is opened
    as itself and refused when it is a link or reparse point. Raises
    OSError (a refusal included) for the caller's own route."""
    root = localpath.absolute_text(export_dir.parent)
    localpath.rename_local(localpath.under(root, path.name), new_name, root=root)


def _preserve_as_failed(work_dir: Path, export_dir: Path) -> Path | None:
    """Sets a work directory that failed validation aside in a fixed place,
    instead of throwing it away.

    The error message of `_verify` literally says this is a failed scan;
    what the script actually wrote is then evidence, not junk. The slot is
    fixed (not unique per attempt) so it does not grow without bound on
    repeated failures: every new failure replaces the previous one. If
    even the rename to the slot fails, this falls back to plain cleanup -
    that is no worse than the existing situation.
    """
    failed = export_dir.parent / f"{export_dir.name}.mislukt"
    if failed.exists():
        shutil.rmtree(failed, ignore_errors=True)
    try:
        _rename_beside(work_dir, failed.name, export_dir)
    except OSError:
        shutil.rmtree(work_dir, ignore_errors=True)
        return None
    return failed


def _retention_log(line: str) -> None:
    """Fixed retention messages go to visible stderr, never MCP stdout.

    Even a broken external logging handler cannot invalidate a committed scan.
    The fallback repeats only our safe message, never the logging exception.
    """
    try:
        logging.getLogger(__name__).warning(line)
    except Exception:
        try:
            sys.stderr.write(line + "\n")
        except Exception:
            pass


def _swap(work_dir: Path, export_dir: Path, retention: Retention | None = None) -> None:
    """Swaps the validated work directory in for the current export.

    Two renames, in the same parent directory (which keeps the second
    rename atomic on the same filesystem): current -> .vorig,
    work directory -> current.

    If that swap itself fails (for example a still-open file handle on
    Windows), that must never break the CollectError contract as a bare
    OSError. There is no unconditional recovery to promise then - only
    what actually happens: if .vorig is still there, the next scan for
    this target tries to put it back via `_recover_interrupted_swap`.
    """
    previous = export_dir.parent / f"{export_dir.name}.vorig"
    try:
        if previous.exists():
            shutil.rmtree(previous)
        if export_dir.exists():
            _rename_beside(export_dir, previous.name, export_dir)
        _rename_beside(work_dir, export_dir.name, export_dir)
    except OSError as exc:
        # Look at the ACTUAL state before naming it, instead of assuming
        # it: in the normal failure (only the last rename fails) .vorig is
        # still there, but in the race with `_recover_interrupted_swap`
        # (see the call site in `collect()`) ANOTHER, concurrent caller
        # may already have cleaned .vorig up again (put it back as the
        # export directory) before this except branch runs. At that moment
        # .vorig no longer exists, and the message would send a person to
        # a file that is not there.
        if previous.exists():
            state = (
                "; de vorige export staat nog als .vorig naast de exportmap; de "
                "eerstvolgende scan voor dit doel probeert die terug te zetten"
            )
        elif export_dir.exists():
            state = (
                "; er staat alweer een export op de gebruikelijke plek (vermoedelijk "
                "net teruggezet door een andere aanroeper); de gegevens van DEZE "
                "mislukte poging zijn niet bewaard"
            )
        else:
            state = "; er is op dit moment geen bruikbare export op deze plek"
        # never `{exc}` - `rmtree`/`rename` failures
        # carry absolute paths in OSError.__str__(). See `_os_error_kind`.
        raise CollectError(f"het omwisselen naar de nieuwe export is mislukt ({_os_error_kind(exc)}){state}") from exc
    # This is AFTER the commit. A keep failure cannot undo a successful scan
    # or enter the swap-error branch and claim that current needs recovery.
    try:
        keep(previous, export_dir, retention or Retention())
    except Exception:
        _retention_log("bewaren: vorige export kon niet worden bewaard; de nieuwe export blijft geldig")
        try:
            _discard_previous(previous, export_dir)
        except Exception:
            _retention_log("bewaren: opruimen van .vorig is niet gelukt; de nieuwe export blijft geldig")
    try:
        lines = prune(export_dir, retention or Retention())
    except Exception:
        lines = ("bewaarbeleid: opruimen niet afgerond; de nieuwe export blijft geldig",)
    for line in lines:
        _retention_log(line)


class SwapGate:
    """Commit gate for the export swap.

    The stop check under `_lock` is the commit boundary: the one moment
    that irrevocably decides whether the swap still happens. `decide()`
    takes the lock, reads the stop flag, and - still under that same lock -
    either performs the swap (`swap()`, which may include an unbounded
    `shutil.rmtree` of a stale `.vorig` directory) or refuses it.

    Writer and reader are deliberately asymmetric:
    - `request_cancellation()` sets the stop flag with a bare, atomic
      `threading.Event.set()` - lock-free, so a saturated executor can
      never delay the stop signal itself. A cancellation may therefore
      land while the swap is already running; it can no longer change the
      decision taken at the commit boundary.
    - `decide()` is the only lock taker; `learn_outcome()` reads the
      outcome under the same lock and is the only part that may block
      (which is why production offloads + shields exactly that call, see
      `status_ververs` in mcp_server.py).

    Two honest outcomes, no third: "aborted" when the stop flag was
    already set at the commit boundary, "committed" otherwise - and
    "committed" by construction means any cancellation arrived AFTER the
    boundary, not that the swap had already finished when it arrived.
    `stop_set_at_commit_boundary` records which of the two held AT the
    boundary, so callers report the causal order instead of deriving it
    from the outcome alone.

    Measured via targeted probes of the commit boundary, not merely
    assumed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.outcome: str | None = None  # None, "committed" or "aborted"
        # None until decide() ran; then True when the stop was already set
        # AT the commit boundary (-> "aborted"), False when it was not
        # (-> "committed": any cancellation provably arrived after the
        # boundary). Recorded under the same lock as the check itself.
        self.stop_set_at_commit_boundary: bool | None = None
        # The sha256 of the manifest `collect()` wrote the scan target next
        # to in its work map, set only when that export was swapped in. The
        # caller records THIS hash as collected - never a second reading of
        # the export map after the swap, which anyone who can write that map
        # could have replaced in between.
        self.manifest_hash: str | None = None

    def is_set(self) -> bool:
        """Unsynchronized view of the stop flag, for the PowerShell poll
        loop: it only needs to know whether a cancellation is under way to
        terminate the child process. Not a commit decision, so no lock."""
        return self._stop.is_set()

    def request_cancellation(self) -> None:
        """Set the stop flag lock-free (atomic `threading.Event.set()`).
        Never waits and must never run via an executor. The worker reads
        the flag under `_lock` in `decide()` - that is where the commit
        decision is synchronized, not here. Once set, every FUTURE
        `decide()` reads True and refuses the swap; a decision already
        taken at the boundary is not changed."""
        self._stop.set()

    def learn_outcome(self) -> str | None:
        """Read the outcome under the same lock `decide()` commits under -
        may block while the worker holds the lock during the swap, so
        production offloads + shields this call. None means the worker has
        not decided yet; its eventual decision is then guaranteed
        "aborted", because `_stop` is already set. Read
        `stop_set_at_commit_boundary` for the causal order; never derive
        it from the outcome alone."""
        with self._lock:
            return self.outcome

    def cancel(self) -> str | None:
        """Composed form for direct, synchronous callers (unit tests, the
        `set` alias below): first `request_cancellation()`, lock-free,
        then `learn_outcome()` under the lock. Production
        (`status_ververs`, mcp_server.py) calls the two steps separately
        so the event loop never blocks."""
        self.request_cancellation()
        return self.learn_outcome()

    # Alias: existing callers that use the bare `threading.Event` form
    # `stop.set()` (for example tests that only want the child process to
    # stop) keep working without change.
    set = cancel

    def decide(self, swap, manifest_hash: str | None = None) -> str:
        """Called by the worker as the last step before the swap would
        happen. Performs the stop check and the swap in one critical
        section, and records in `stop_set_at_commit_boundary` whether the
        stop was already set at the commit boundary, so the caller can
        report the causal order instead of guessing it. On a committed swap
        it also records `manifest_hash`, under the same lock."""
        with self._lock:
            self.stop_set_at_commit_boundary = self._stop.is_set()
            if self.stop_set_at_commit_boundary:
                self.outcome = "aborted"
            else:
                swap()
                self.manifest_hash = manifest_hash
                self.outcome = "committed"
            return self.outcome


def _lock_path(export_dir: Path) -> Path:
    return export_dir.parent / f"{export_dir.name}.lock"


# A pid is a few digits; the lock file is never read past this.
_LOCK_PID_MAX_BYTES = 64


def _read_lock_pid(lock: Path) -> str:
    """Best-effort: purely for a readable error message, never a reason to
    fail on its own when the lock file happens to be unreadable."""
    root = localpath.absolute_text(lock.parent)
    try:
        got = localpath.read_local(localpath.under(root, lock.name), root=root, max_bytes=_LOCK_PID_MAX_BYTES)
        content = localpath.as_text(got.data).strip() if not got.over_cap else ""
    except (OSError, UnicodeDecodeError):
        # 1.1 B: a refusal (a link in the place of the lock file) is an
        # OSError too: unreadable, never followed.
        return "onbekend"
    return content or "onbekend"


def _acquire_lock(export_dir: Path, *, recovered_this_call: bool = False) -> Path:
    """Refuses a concurrent scan on the same target, instead of trying to
    make two simultaneous scans safe.

    A scan takes minutes and loads the appliance; two at once is
    undesirable in itself, and the design already refuses it ("never over
    the top of the current export"). Hence: refuse, not try to save both.

    The lock is a plain file with our own pid in it, created atomically
    with O_CREAT|O_EXCL so a race between two processes can never conclude
    "I have it" twice (the filesystem decides, not two separate checks in
    Python code).

    If the lock already exists, the call is refused - outright, without an
    age check and without takeover of an "expired" lock. Such a takeover
    existed once, but produced two races of its own in practice (the
    check-unlink-create triplet was atomic only for the create, and the
    age limit protected only the subprocess, not the rest of the critical
    section around it). A crashed process is a situation an operator
    solves with one command, not a situation this code should guess for
    him; the error message therefore names the full lock path and the pid
    it contains, so that command is obvious.

    `recovered_this_call` comes from `_recover_interrupted_swap`, which
    runs BEFORE this lock (see `collect()`). If it is True and the call is
    still refused here, this lock file is almost certainly the corpse of
    that same crash - not a genuine concurrent scan - and the person
    reading this error message should be told that directly, instead of
    having to combine on their own that the export is suddenly back AND
    the scan is refused.
    """
    lock = _lock_path(export_dir)
    root = localpath.absolute_text(lock.parent)
    created = False
    try:
        # 1.1 B: created exclusively (`FILE_CREATE`) relative to the held
        # map around the export, and the pid written on that same handle.
        with localpath.open_local(localpath.under(root, lock.name), root=root, mode="create") as handle:
            created = True
            handle.write(str(os.getpid()).encode("ascii"))
    except FileExistsError:
        pid = _read_lock_pid(lock)
        context = ""
        if recovered_this_call:
            context = (
                "; let op: een onderbroken omwisseling van een vorige scan is zojuist "
                "hersteld (de export is weer bruikbaar) - dit slotbestand is vermoedelijk "
                "het lijk van diezelfde afgebroken scan, geen scan die nu echt loopt"
            )
        # the bare NAME only, never the absolute path
        # - same rule as the `failed.name` precedent above.
        raise CollectError(
            f"er loopt al een scan voor {export_dir.name}: het slotbestand {lock.name} "
            f"bestaat al (pid {pid}); loopt er geen scan meer, dan mag dit bestand "
            f"handmatig worden verwijderd{context}"
        ) from None
    except PathRefused as exc:
        if not created:
            # A link or reparse point in the place of the lock file, or on
            # the way to it: the scan refuses, with the kind, never following it.
            raise CollectError(f"kon geen slot aanmaken voor de scan: {exc.reason}") from exc
        write_error: OSError | None = exc
    except OSError as exc:
        if not created:
            # Never `{exc}` - see `_os_error_kind`.
            raise CollectError(f"kon geen slot aanmaken voor de scan ({_os_error_kind(exc)})") from exc
        write_error = exc
    else:
        write_error = None
    if write_error is not None:
        exc = write_error
        # If the write itself fails (for example a full disk), the brand
        # new, empty lock file must not stay behind: without takeover
        # (deliberately absent, see above) it would refuse every next scan
        # forever.
        #
        # This cleanup attempt can itself hit an OSError too (for example
        # the same ACL that already blocked the write). Best-effort, like
        # _release_lock further down this file: the original error counts,
        # a failing cleanup does not - a SECOND OSError here must never
        # replace the intended, informative CollectError below with a bare
        # OSError that loses the original write error without trace.
        try:
            lock.unlink(missing_ok=True)
        except OSError:
            pass
        # the bare NAME, never the path; never `{exc}`.
        raise CollectError(
            f"kon de pid niet in het slotbestand {lock.name} wegschrijven ({_os_error_kind(exc)})"
        ) from exc
    return lock


def _release_lock(lock: Path) -> None:
    """Best-effort: a failing release must never overwrite a successful (or
    an already correctly-as-CollectError-reported failed) scan with a bare
    OSError from the finally.
    """
    try:
        lock.unlink(missing_ok=True)
    except OSError:
        pass


def _clean_stale_work_dirs(export_dir: Path) -> None:
    """Cleans up work directories of a scan that never reached its finally
    (process killed, machine off) - otherwise every aborted scan leaves a
    full copy behind that nobody ever cleans up.

    Called while our own lock is already held: no other scan can still
    have such a directory in use, so this is safe. Without the lock this
    would be exactly the leak the lock is meant to prevent.

    Walks the directory contents with an explicit name and `is_dir()`
    check, no `Path.glob`: `export_dir.name` can contain glob
    metacharacters that are perfectly valid in a Windows directory name
    (for example `[` and `]`). Such a pattern could then silently match
    the work directory of an entirely different export (protected by a
    different lock) while missing its own work directory.

    Both `iterdir()` and `is_dir()` can raise an OSError (an ACL on the
    parent directory, a path dropping away while this runs) - each gets
    its own contextual CollectError instead of leaking raw past the
    CollectError contract as a bare crash.
    """
    prefix = f"{export_dir.name}.nieuw-"
    try:
        candidates = list(export_dir.parent.iterdir())
    except OSError as exc:
        # the bare NAME, never the path; never `{exc}`.
        raise CollectError(
            f"kon de oude werkmappen naast {export_dir.name} niet opsommen om op te ruimen ({_os_error_kind(exc)})"
        ) from exc
    for candidate in candidates:
        try:
            is_directory = candidate.is_dir()
        except OSError as exc:
            raise CollectError(
                f"kon niet vaststellen of {candidate.name} een map is tijdens het opruimen ({_os_error_kind(exc)})"
            ) from exc
        if is_directory and candidate.name.startswith(prefix):
            shutil.rmtree(candidate, ignore_errors=True)


def collect(
    target: Target,
    export_dir: Path,
    script_path: Path,
    *,
    timeout_s: int = 900,
    run=None,
    stop: SwapGate | None = None,
    retention: Retention | None = None,
) -> Path:
    """Scans `target` and puts the result at `export_dir`. Returns the export dir.

    `run` exists for the tests: a callable (arguments, timeout_s) ->
    (exitcode, stderr). In production that is PowerShell
    (`_run_powershell`).

    `stop` is the optional channel through which a caller can abort a
    RUNNING scan - a `SwapGate` (see that class above) that
    `status_ververs` (mcp_server.py) cancels as soon as the MCP call
    itself is cancelled. It is honored in TWO places here: (1)
    `_run_powershell` polls it while the child process is still running
    and really ends that process as soon as it is set (see there) - the
    mechanism that stops a RUNNING child process; (2) below, as the very
    last step just before the swap, via `stop.decide(...)`: the stop
    check under the gate's lock is the commit boundary. A cancellation
    can still land lock-free during `_swap()` afterwards, but can no
    longer change the decision recorded at the commit boundary - see the
    SwapGate class docstring. A loose `stop.is_set()` check before the
    swap only NARROWS that window instead of closing it (measured).

    Refuses a second scan on the same `export_dir` while one is already
    running (see `_acquire_lock`): a deliberate choice, not a
    shortcoming - making two simultaneous scans safe never succeeded
    without a new gap elsewhere, so this design no longer tries.
    """
    if not script_path.exists():
        # the bare NAME, never the absolute path.
        raise CollectError(f"het verzamelscript is niet gevonden ({script_path.name})")
    if run is not None:
        runner = run
    else:
        # Only the REAL runner receives `stop` - the test injection
        # (`run`) keeps its existing, simpler signature (see the docstring
        # above). `_run_powershell` accepts `stop` as a third, optional
        # argument.
        def runner(arguments, timeout_s):
            return _run_powershell(arguments, timeout_s, stop)

    # Must exist for both the lock file below and mkdtemp further down: on
    # a fresh installation export_dir.parent is not there yet, and without
    # this mkdtemp(dir=...) raises a bare OSError - the same contract
    # breach as elsewhere in this function, now on the very first scan.
    try:
        export_dir.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # the bare NAME, never the path; never `{exc}`.
        raise CollectError(
            f"kon de bovenliggende map van {export_dir.name} niet aanmaken ({_os_error_kind(exc)})"
        ) from exc

    # Deliberately BEFORE the lock. If a process dies between the two
    # renames of _swap, not only does the export stay behind as .vorig,
    # but (because the finally below it never ran) so does the lock file
    # of that same scan. With recovery AFTER the lock, _acquire_lock would
    # refuse every next call before recovery could ever run - permanently,
    # because stale-lock takeover is deliberately absent (see
    # _acquire_lock). See the docstring of _recover_interrupted_swap for
    # why this is still safe here, without the protection of the lock.
    #
    # Known, tolerated race: "before the lock" also means THIS recovery
    # can run while ANOTHER caller (elsewhere, midway through its own
    # _swap) already holds the lock. If this caller then sees "no export
    # dir + .vorig present" - the window the other caller itself just
    # opened by renaming the export dir to .vorig, right before its own
    # last rename - it restores the OLD .vorig back to the export dir, and
    # the other caller's last rename (work dir -> export dir) then fails
    # because the export dir exists again. That is NOT a new data leak:
    # fail-closed stands (the old, valid export ends up back in place,
    # never anything half or fabricated); the only damage is a wasted scan
    # and an error message for the caller whose swap failed that way (see
    # the state-dependent text in `_swap` above). Deliberately NO new lock
    # or double bookkeeping is built around this call to close that window
    # too: the scan is cheap to repeat, and every extra interlock here
    # adds exactly the kind of second race condition this file got rid of
    # elsewhere (see _acquire_lock: stale-lock takeover was deliberately
    # not brought back for that reason).
    recovered = _recover_interrupted_swap(export_dir)

    # Outside the try/finally below: if the lock is already taken, we
    # acquired nothing and the finally must not try to release it either.
    lock = _acquire_lock(export_dir, recovered_this_call=recovered)
    try:
        # While our own lock is held, so safe: clean up work directories
        # of a scan that never reached its own finally (see
        # _clean_stale_work_dirs).
        _clean_stale_work_dirs(export_dir)

        # Unique per call, no fixed ".nieuw" name: this is also what
        # _clean_stale_work_dirs recognizes as "from an earlier, aborted
        # attempt". The same parent (export_dir.parent) additionally keeps
        # the later rename to export_dir atomic (same filesystem).
        try:
            work_dir = Path(tempfile.mkdtemp(prefix=f"{export_dir.name}.nieuw-", dir=export_dir.parent))
        except OSError as exc:
            # the bare NAME, never the path; never
            # `{exc}`.
            raise CollectError(f"kon geen werkmap aanmaken naast {export_dir.name} ({_os_error_kind(exc)})") from exc

        cleaned_up = False
        try:
            # MEASURED: deliberately OUTSIDE the
            # inner try/except below that calls `_preserve_as_failed`.
            # `_run_powershell` itself raises CollectError for three things
            # that never produce a scan attempt of this call's own: caller
            # cancellation (its poll loop), the timeout, and "kon
            # PowerShell niet starten" (the process could not even be
            # spawned). Routing those into the SAME
            # `except CollectError: _preserve_as_failed(...)` as the
            # POST-run failures below FIRST `rmtree`s any existing
            # `.mislukt` (see `_preserve_as_failed`) and THEN renames this
            # attempt's still-empty work directory into that fixed slot -
            # destroying a PREVIOUS, genuine failure's evidence and
            # replacing it with an empty directory that the answer then
            # claims was "bewaard voor onderzoek". None of the three ever
            # produces evidence of its own to preserve, so none of them may
            # reach `_preserve_as_failed`: the plain `finally` further down
            # cleans up the (empty or partial) work directory exactly as it
            # does for every other refusal in this function, and the
            # existing, unrelated `.mislukt` (if any) is left untouched.
            code, error_text = runner(build_arguments(target, work_dir, script_path), timeout_s)
            # Deliberately NO loose stop check here: a bare `stop.is_set()`
            # at this point would only narrow the cancellation window
            # instead of closing it. The ONE place that still checks
            # `stop` before anything is swapped is `stop.decide(...)` just
            # before the swap below - see the docstring of `collect()` and
            # the SwapGate class docstring. What happens first here
            # (`_verify()`, writing the scan-target file) never touches
            # the CURRENT export - it all happens in the work directory -
            # so nothing is lost by postponing the stop check to the only
            # moment something irrevocable actually happens.
            try:
                if code != 0:
                    # The script itself has already reported what is wrong
                    # (its output, summarized below in `summary`) - but that
                    # is NOT the only thing worth keeping any more. Design
                    # 2.2 (`phase_report`, near the bottom of this
                    # file): the collect script MAY also have written a typed
                    # `scan-fasen.json` into `work_dir` before deciding to
                    # exit non-zero - the ordinary way a script reports "I
                    # got as far as phase X and it failed there". MEASURED:
                    # before this fix, this branch
                    # let the `finally` below delete `work_dir` unconditionally
                    # (this except did not yet exist), so that phase file was
                    # destroyed before anyone could ever read it - the single
                    # most common real failure shape left the phase report with nothing.
                    # The shared `except CollectError` right below now
                    # preserves this directory exactly like a validation
                    # failure always has - `runner()` above already returned
                    # normally here (a produced, non-zero exit), never a
                    # cancellation/timeout/start-failure (see above).
                    summary = _short_report(error_text, target)
                    raise CollectError(
                        f"het verzamelscript stopte met exitcode {code}: {summary}",
                        # "geen foutregel" is this product's own text, not
                        # the script's: nothing to withhold below 'volledig'.
                        script_output=None if summary == _NO_ERROR_LINE else summary,
                    )

                _verify(work_dir)

                # Records WHICH target produced this export - in the work
                # directory, so BEFORE the swap, landing atomically with the
                # rest (the same rename that makes the directory current makes
                # this file current too - from the WRITER's point of view
                # there is no window in which the export is swapped in but
                # this file is not). Without this, a later reader
                # (export.load_export) never knows which target a given
                # export describes.
                #
                # That atomicity claim holds only for the WRITER here, not for
                # the READER. `load_export` (export.py) reads the manifest and
                # this file in TWO separate operations - a swap can land
                # exactly in between - and there is moreover only ONE export
                # directory per server: a supplied export can simply leave
                # this file from an earlier scan lying next to a very
                # different manifest. This file therefore carries, next to the
                # name, the sha256 of the manifest above (which `_verify`
                # already found usable and which stays unchanged until the
                # swap): `_read_target_name` (export.py) returns the name only
                # when that hash matches the manifest actually loaded, not
                # because this file happens to sit next to it.
                try:
                    # 1.1 B: the manifest `_verify` judged, read again
                    # through `localpath` from the work export map, and the
                    # target file written there by handle (`replace_local`).
                    got = _work_read(work_dir, "export-manifest.json", allow_missing=False)
                    if got.over_cap:
                        raise OSError("het export-manifest is groter dan het plafond")
                    manifest_hash = hashlib.sha256(got.data).hexdigest()
                    work_root = localpath.absolute_text(work_dir)
                    localpath.replace_local(
                        localpath.under(work_root, TARGET_FILE),
                        f"{target.name}\n{manifest_hash}\n".encode(),
                        root=work_root,
                    )
                except PathRefused as exc:
                    raise CollectError(f"kon het scandoel niet vastleggen in de werkmap: {exc.reason}") from exc
                except OSError as exc:
                    # never `{exc}` - see
                    # `_os_error_kind`.
                    raise CollectError(
                        f"kon het scandoel niet vastleggen in de werkmap ({_os_error_kind(exc)})"
                    ) from exc
            except CollectError as error:
                # Every failure in THIS inner try happens AFTER `runner()`
                # above already returned normally: `work_dir` still holds
                # exactly what THIS attempt produced, and (design 2.2 row
                # A16) that is potential phase evidence, not junk - see
                # `_preserve_as_failed`. Covers a non-zero exit code, a
                # failed `_verify`, and a failed scan-target-file write -
                # equally "this attempt's own data", so A16 needs the SAME
                # preservation from all three. Deliberately NOT shared with
                # the `runner()` call above (see the comment there):
                # cancellation, the timeout, and a PowerShell start failure
                # never reach this except. `evidence_dir` on the re-raised
                # error is exactly the directory `phase_report` (near the
                # bottom of this file) is meant to read; `None` here would
                # wrongly claim there is nothing to diagnose when there
                # plainly is.
                failed = _preserve_as_failed(work_dir, export_dir)
                cleaned_up = True
                if failed is not None:
                    # The DIRECTORY NAME only,
                    # never the absolute path - `failed` sits under this
                    # product's own export directory, so the full path
                    # carries this machine's directory layout (and, once
                    # embedded in a CollectError, reaches `status_ververs`'s
                    # answer text, which never passes through the
                    # disclosure seam - see mcp_server.py).
                    raise CollectError(
                        f"{error} (bewaard voor onderzoek in {failed.name})",
                        evidence_dir=failed,
                        script_output=error.script_output,
                    ) from error
                raise

            # The commit gate. Without `stop` (most tests, and every
            # caller that does not need to be cancellable) nobody can
            # cancel, so just swap. WITH `stop`, the check and the swap go
            # through `SwapGate.decide()`: the stop check under the lock
            # is the commit boundary; a later cancellation no longer
            # changes that decision. See the class docstring.
            if stop is None:
                _swap(work_dir, export_dir, **({"retention": retention} if retention is not None else {}))
            else:
                outcome = stop.decide(
                    lambda: _swap(work_dir, export_dir, **({"retention": retention} if retention is not None else {})),
                    manifest_hash,
                )
                if outcome == "aborted":
                    raise CollectError("de scan is afgebroken door de aanroeper; de vorige gegevens blijven gelden")
            return export_dir
        finally:
            if not cleaned_up and work_dir.exists():
                shutil.rmtree(work_dir, ignore_errors=True)
    finally:
        _release_lock(lock)


# ---------------------------------------------------------------------------
# The phased scan diagnosis (design 2.2, row A16). Mirrors the stage names of
# NSHC's connection doctor (backend/readonly/NshcConnectionDoctor.ps1): DNS,
# TCP_443, TLS, NITRO_LOGIN, IDENTITY - MEASURED against that script: its
# `New-NshcStage` helper writes exactly `{name, ok, ms, detail}` per stage,
# no outcome WORD of its own. NSHC leaves classification to the boolean
# `ok`; this product does the same.
#
# THE RULE THIS EXISTS FOR: the classification runs on a TYPE, never on an
# error TEXT. An error message is written by whatever layer happened to fail
# and changes with a library upgrade; a phase is a fact about how far the
# scan got. So the collect script MAY write this file, typed, and this
# product reads it. Where the file is absent, this product establishes only
# what it can see in the ARTEFACTS it holds - and says "niet vastgesteld"
# about the rest. Nothing here parses stderr.
PHASE_FILE = "scan-fasen.json"

# Vocabulary provenance (design 2.1 - 2.1.1 calls itself "the only index" for
# assessment vocabulary; a plan may not invent a product word). Kept to the
# MINIMUM this feature cannot express any other way - three words, not the
# four originally proposed:
#
#   - "niet vastgesteld": the existing Certainty.NOT_ESTABLISHED word
#     (nsmcp.answer), used product-wide. Covers FOUR situations here: no
#     phase evidence at all for this attempt; a phase this product cannot
#     read from artefacts alone (DNS/TCP/TLS - the child process knows them,
#     this process does not); a phase never attempted because an earlier one
#     failed (it genuinely was not tested, so "not established" is exact,
#     not a euphemism for an invented "niet bereikt (eerdere fase
#     faalde)"); and a malformed phase entry (the file mentions the phase,
#     but its shape makes no outcome readable from it either).
#   - "mislukt": REUSED from 2.1.1's own table, where it already exists for
#     B8 ("a runner phase is finished and its closing gate is shut"). A16
#     reuses the same word for "this specific scan phase was attempted and
#     did not succeed" - the same underlying idea (a phase within a larger
#     sequential process ended negatively), applied to a different concrete
#     subject. The two never share a sentence: B8's word describes an
#     upgrade runner's phase in `onderhoud_upgrade_stand`, this one a scan's
#     transport/login/identity phase in `status_ververs`, and the phase name
#     printed right next to the word (a runner phase name vs. one of
#     DNS/TCP/TLS/NITRO-login/identiteit) always disambiguates which is
#     meant. This is the same kind of dual use the design already accepts
#     for "beperkt" (an NSHC confidence-level alias in one place, the
#     openness-level word in another, never confused because context
#     disambiguates).
#   - "bereikt": the one word this feature genuinely cannot borrow. Neither
#     2.1.1's general index nor 2.2's own row for it names a word for "this
#     individual scan phase completed" - PASS/OK/geslaagd/open all exist,
#     but each for a different subject (a control, a manifest source, an
#     upgrade runner phase, a runner gate), and reusing any of them here
#     would be exactly the cross-subject ambiguity 2.1 exists to prevent.
#     NEEDS A DESIGN UPDATE for this one word.
#
# This tuple used to be dead - nothing imported
# it, nothing gated on it, so any of the three words could be renamed here
# with the suite staying green. It is now load-bearing on two sides:
# `PhaseReport.__post_init__` (below) refuses to construct a report whose
# `word` is not a member, and `tests/test_product_surface.py` pins the
# tuple's exact value plus the five phase names - the ONE index design 2.1
# requires for assessment vocabulary.
PHASE_WORDS = ("bereikt", "mislukt", "niet vastgesteld")

# NSHC stage name -> the Dutch phase name of this product. A name outside this
# table is REPORTED as unknown, never silently dropped: a phase this product
# does not know is exactly the thing an operator needs to hear about.
PHASE_NAMES = {
    "DNS": "DNS",
    "TCP_443": "TCP",
    "TLS": "TLS",
    "NITRO_LOGIN": "NITRO-login",
    "IDENTITY": "identiteit",
}
PHASE_ORDER = ("DNS", "TCP", "TLS", "NITRO-login", "identiteit")

# Same discipline as export.MISSING: separates "the key is absent" from
# "the key carries a value this product cannot use" - a phase entry is
# SUPPLIED input (written by a collect script this product does not
# control), so both cases need their own, honest wording instead of one
# collapsing into the other. `_phase_shape` below is a deliberate, measured
# CORRECTION of `export.shape_of` (FAMILY B)
# - not a copy of the FAMILY A one-liner - so it keeps its own name and
# body; only the sentinel itself is the shared `export.MISSING` object
# (imported above as `_MISSING`), never a second `object()` for the same
# meaning.


def _phase_shape(value, expected: str) -> str:
    """The SHAPE of a supplied phase-file value that failed a positive gate
    at its call site - never the raw value itself (a malformed phase
    entry is SUPPLIED input and must never be echoed).

    Same idiom as `export._unusable_read_reason` and
    `rulesets._ruleset_field`: `_MISSING` is named
    apart ("de sleutel ontbreekt"), and `export.shape_of` is correct for
    everything IT correctly names - `None`, a blank/whitespace-only string,
    or a value of the wrong TYPE - but calls ANY string "een lege of
    alleen-witruimte tekstwaarde", which is false for a non-blank string
    that simply has the wrong shape (`"true"` where a boolean is expected,
    `"kapot"` where an object is expected - both MEASURED). That case gets
    `expected`'s "zonder de vorm van ..." wording instead: true at every
    call site, and never claiming more than `expected` names.
    """
    if value is _MISSING:
        return "de sleutel ontbreekt"
    if isinstance(value, str) and value.strip():
        return f"zonder de vorm van {expected}"
    return shape_of(value)


@dataclass(frozen=True)
class PhaseReport:
    phase: str
    word: str
    detail: str = ""

    def __post_init__(self) -> None:
        # PHASE_WORDS existed but nothing read it
        # - the vocabulary could be renamed with the suite green. This makes
        # it load-bearing: every PhaseReport this module constructs is
        # checked against the SAME tuple test_product_surface.py pins, so
        # code and pin can never quietly drift apart.
        if self.word not in PHASE_WORDS:
            raise ValueError(f"onbekend fasewoord {self.word!r}; toegestaan zijn {PHASE_WORDS}")


def _not_established(phase: str, detail: str) -> PhaseReport:
    """A PhaseReport that could not be established, with the reason - never
    a bare word without why (same discipline as `ReadGap`, nsmcp.answer)."""
    return PhaseReport(phase=phase, word="niet vastgesteld", detail=detail)


@dataclass(frozen=True)
class _PhaseFacts:
    """The NAMED facts `_PHASE_PRECEDENCE` decides between, for ONE
    canonical phase at one point in the walk in `_phases_from_file`.

    `own_ok` is `None` when this phase has no boolean the file gave it
    directly - either it is ABSENT, or its entry is MALFORMED
    (`malformed_detail` tells the two apart; `_phases_from_file` only ever
    puts a name in one of `named`/`named_bad`, never both, so exactly one
    of `malformed_detail is not None` / `own_ok is not None` can hold).
    `True`/`False` means this phase's own outcome was genuinely read.
    """

    malformed_detail: str | None
    own_ok: bool | None
    earlier_real_failure: bool
    unattributed_gap: bool


# THE PRECEDENCE. Three fixes in a row each
# found a sibling of the SAME defect in this walk - a fact this product
# had actually established getting silently outranked by a lower-priority
# one - in a different pair of branches each time (once: an unnamed
# entry vs. a named one; another time: the DETAIL text vs. the WORD). Rather
# than add a fourth `elif`, the decision for one canonical phase is this
# single, explicit, ORDERED table. Walked top to bottom, the FIRST rung
# whose `matches(facts)` fires DECIDES the report; every rung below it is
# moot for that phase. Checking the decision means reading this list, not
# simulating the loop that calls `_decide_phase_report`.
#
#   1. malformed             - this phase's own entry exists but its `ok`
#                              could not be classified (`named_bad`).
#   2. earlier_real_failure  - a REAL earlier PHASE_ORDER phase already
#                              failed (malformed, or genuinely `ok: false`).
#   3. own_ok_false          - THIS phase's own `ok` was genuinely read as
#                              False: an established failure.
#   4. unattributed_gap      - the file also holds an entry no phase could
#                              be attributed to, AND this phase has some
#                              entry of its own (`own_ok is not None`) -
#                              reached only when rungs 1-3 did not already
#                              establish something REAL about this phase.
#   5. own_ok_true           - THIS phase's own `ok` was genuinely read as
#                              True: an established success.
#   6. absent                - catch-all: this phase has no entry in the
#                              file at all.
#
# Rung 3 sits ABOVE rung 4 ON PURPOSE - the exact rule the previous three
# rounds each broke in a new spot: a fact established by a successful read
# (rungs 2, 3, 5) outranks an unrelated gap (rung 4). Rung 4 can only ever
# withhold rung 5's "bereikt" - the one word this product prints only when
# NOTHING in the file casts doubt (see PHASE_WORDS above: "bereikt" is the
# hardest-earned word here; the original choice to withhold it next
# to a gap is kept, unchanged). Rung 4 must never reach rung 3's "mislukt":
# that was already established by a real read, and downgrading an
# established failure to "niet vastgesteld" would suppress a genuine alarm
# - precisely the defect measured repeatedly across this cascade,
# each time in a different pair of branches.
_PHASE_PRECEDENCE = (
    (
        "malformed",
        lambda f: f.malformed_detail is not None,
        lambda dutch, f: _not_established(dutch, f.malformed_detail),
    ),
    (
        "earlier_real_failure",
        lambda f: f.earlier_real_failure,
        lambda dutch, f: _not_established(dutch, "niet getest: een eerdere fase faalde"),
    ),
    (
        "own_ok_false",
        lambda f: f.own_ok is False,
        lambda dutch, f: PhaseReport(phase=dutch, word="mislukt"),
    ),
    (
        "unattributed_gap",
        lambda f: f.unattributed_gap and f.own_ok is not None,
        lambda dutch, f: _not_established(
            dutch,
            "het fasebestand meldt deze fase, maar bevat ook een fase-invoer "
            "die niet aan een fase kon worden toegewezen",
        ),
    ),
    (
        "own_ok_true",
        lambda f: f.own_ok is True,
        lambda dutch, f: PhaseReport(phase=dutch, word="bereikt"),
    ),
    (
        "absent",
        lambda f: True,
        lambda dutch, f: _not_established(dutch, "het fasebestand meldt deze fase niet"),
    ),
)


def _decide_phase_report(dutch: str, facts: _PhaseFacts) -> PhaseReport:
    """Apply `_PHASE_PRECEDENCE`, in order, to ONE canonical phase's facts.

    The exhaustive matrix test over this function
    generates its cells by crossing every fact combination, for every
    phase position, against the SAME `_PHASE_PRECEDENCE` this function
    walks - so a future reordering, insertion, or removal of a rung is
    exercised by re-running that one test, never by hand-updating
    individual cases.
    """
    for _name, matches, build in _PHASE_PRECEDENCE:
        if matches(facts):
            return build(dutch, facts)
    raise AssertionError("_PHASE_PRECEDENCE must end in a catch-all rung")


def _unreadable_phase_reports(detail: str) -> list[PhaseReport]:
    """A phase file that EXISTS but cannot be
    read - bad JSON, a non-dict root, a `phases` that is not a list, exactly
    what a killed or timed-out collect script can leave - is a THIRD state,
    distinct from "absent" (fall back to `_phases_from_artefacts`) and
    "found" (use its content). All five phases are honestly "niet
    vastgesteld" with the file's own SHAPE as the reason; the caller must
    NEVER fall through to the artefact fallback here - its detail line says
    "dit fasebestand ontbreekt", which would be an outright lie about a file
    that plainly exists and was plainly read (MEASURED).
    """
    return [_not_established(dutch, detail) for dutch in PHASE_ORDER]


def _os_error_kind(exc: OSError) -> str:
    """The KIND of a filesystem failure - never the exception itself.

    `OSError.__str__()` carries the full absolute
    local path on Windows (MEASURED: a `PermissionError` on a directory
    standing in for the file put the whole temp-directory path into the
    answer, at every disclosure level - exactly the leak this classifier
    exists to prevent). This names the failure by TYPE only -
    permission, "not a file" (a directory or a bad path component sits
    where a file was expected), or anything else - so the caller can build
    an honest sentence that never echoes the OS message or the path.

    Originally written for the phase file; a later fix
    generalised it to every OSError this module turns into a CollectError -
    one classifier, not a copy per call site.
    """
    if isinstance(exc, PermissionError):
        return "geen toegang"
    if isinstance(exc, (IsADirectoryError, NotADirectoryError)):
        return "geen bestand"
    return "onbekende leesfout"


def _phases_from_file(work_dir: Path) -> tuple[list[PhaseReport], str]:
    """The typed phase file, when the collect script wrote one.

    Returns `(reports, state)`; `state` is one of:
    - "absent": no such file - the caller falls back to
      `_phases_from_artefacts`.
    - "unreadable": the file exists but its own shape defeats reading
      it - `reports` is already the final, five-phase answer; the caller
      must use it as-is and never fall back.
    - "found": the file parsed cleanly - `reports` is the final answer.
    """
    try:
        got = _work_read(work_dir, PHASE_FILE)
        if got.over_cap:
            return (
                _unreadable_phase_reports(
                    f"het fasebestand is groter dan het plafond ({got.size} bytes tegen {MAX_FILE_BYTES})"
                ),
                "unreadable",
            )
        if not got.exists:
            return [], "absent"
        # `utf-8-sig`, not `utf-8` - a real
        # collect script writing this file from Windows PowerShell 5.1
        # writes a UTF-8 BOM by default (`export.py:1083` already uses
        # `utf-8-sig` for exactly this reason). Plain `utf-8` would have
        # turned every real, BOM-prefixed phase file into a "read gap" on
        # every scan; `utf-8-sig` reads both a BOM-prefixed and a bare
        # UTF-8 file identically.
        text = localpath.as_text(got.data, "utf-8-sig")
    except FileNotFoundError:
        return [], "absent"
    except PathRefused as exc:
        # 1.1 B: a link or reparse point on the way to the phase file.
        return _unreadable_phase_reports(f"het fasebestand is onleesbaar: {exc.reason}"), "unreadable"
    except OSError as exc:
        # Never `{exc}` - `OSError.__str__()` on
        # Windows carries the full absolute local path (MEASURED: a
        # `PermissionError` on a directory standing in for the file put
        # `C:\Users\<user>\...\export.mislukt\scan-fasen.json` into the
        # answer at every disclosure level). Exactly the same leak this
        # classifier exists to prevent, reinstated one branch over.
        # Classify BY TYPE only - permission / not a file / anything else -
        # never the OS message, never the path.
        return (
            _unreadable_phase_reports(f"het fasebestand is onleesbaar ({_os_error_kind(exc)})"),
            "unreadable",
        )
    except UnicodeDecodeError as exc:
        # Safe to keep: `UnicodeDecodeError.__str__()` names the codec and
        # the byte offset, never a filesystem path.
        return _unreadable_phase_reports(f"het fasebestand is onleesbaar: {exc}"), "unreadable"
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        # Safe to keep: `JSONDecodeError.__str__()` is a fixed message
        # (e.g. "Expecting value") plus a line/column/char position it
        # computed itself - never a filesystem path, never the document's
        # own content echoed back.
        return (
            _unreadable_phase_reports(f"het fasebestand bevat geen geldige JSON: {exc}"),
            "unreadable",
        )
    if not isinstance(raw, dict):
        return (
            _unreadable_phase_reports(
                # `_phase_shape`, never bare
                # `shape_of` - the exact defect one line over. A
                # non-blank string root (`"kapot"`, MEASURED) is not "een
                # lege of alleen-witruimte tekstwaarde"; `_phase_shape` is
                # the one already-proved helper for this, not a new one.
                f"het fasebestand heeft niet de vorm van een object ({_phase_shape(raw, 'een object')})"
            ),
            "unreadable",
        )
    phase_entries = raw.get("phases", _MISSING)
    if phase_entries is _MISSING or not isinstance(phase_entries, list):
        return (
            _unreadable_phase_reports(
                f"het fasebestand mist een bruikbare fasenlijst ({_phase_shape(phase_entries, 'een lijst')})"
            ),
            "unreadable",
        )

    known = ", ".join(PHASE_NAMES)
    # Two tiers. `loose`: entries with NO
    # phase attribution at all - this product cannot place them in
    # PHASE_ORDER, so it never guesses at their position and they never
    # disturb the cascade below. `named`/`named_bad`: entries WITH a
    # recognized name, collected here in ARRAY order but evaluated in
    # CANONICAL order further down - the cascade can therefore no longer be
    # fooled by array order (`[{"IDENTITY", ok:true}, {"DNS", ok:false}]`
    # used to yield the self-contradictory "identiteit: bereikt" behind
    # "De scan strandde in fase DNS").
    loose: list[PhaseReport] = []
    named: dict[str, bool] = {}
    named_bad: dict[str, str] = {}
    # An entry this product cannot attribute to
    # ANY phase, and whose own `ok` cannot be classified true/false either
    # (a bare non-dict entry with nothing to read at all, or a genuine
    # read gap on `ok`) is not the same as "nothing was mentioned" - the
    # file plainly supplied SOMETHING here. Reusing `named_bad`'s own
    # mechanism (never a second one): seeding `failed` with this flag
    # before the canonical cascade below taints every phase exactly as an
    # outright unclassifiable NAMED entry already does, instead of
    # silently landing on the more favourable "bereikt" for phases that
    # merely happen to sit elsewhere in the same file (MEASURED, all four
    # unattributable shapes: missing name, blank name, an unrecognised
    # name with an unusable `ok`, and a bare non-dict entry).
    unattributed_gap = False

    for index, entry in enumerate(phase_entries, start=1):
        if not isinstance(entry, dict):
            # A malformed entry is reported AS malformed - never
            # silently dropped, and never with the (untrue) claim that the
            # file "does not report" a phase it plainly contains something
            # for.
            loose.append(
                _not_established(
                    "(fase-invoer)",
                    f"een fase-invoer in het fasebestand is misvormd: {_phase_shape(entry, 'een object')}",
                )
            )
            unattributed_gap = True
            continue
        name = entry.get("name", _MISSING)
        if name is _MISSING or not isinstance(name, str) or not name.strip():
            # `ok` used to be discarded here by a
            # `continue` BEFORE it was ever read - so a genuinely reported
            # failure (`{"ok": false}`, no name at all) silently vanished
            # and left "Geen fase meldde een mislukking" standing as an
            # untrue heading (MEASURED). Read `ok` first, exactly like the
            # unrecognised-name branch below already does.
            detail = (
                f"een fase-invoer in het fasebestand mist een bruikbare naam ({_phase_shape(name, 'een fasenaam')})"
            )
            ok = entry.get("ok", _MISSING)
            if ok is _MISSING or not isinstance(ok, bool):
                loose.append(_not_established("(fase-invoer)", detail))
                unattributed_gap = True
            else:
                loose.append(PhaseReport(phase="(fase-invoer)", word="bereikt" if ok else "mislukt", detail=detail))
            continue
        dutch = PHASE_NAMES.get(name.strip().upper())
        if dutch is None:
            # A supplied name outside our table
            # must NEVER be echoed - not even the part of it that happens to
            # pass a shape gate. `status_ververs` answers OUTSIDE the
            # disclosure seam (no render() pass - see mcp_server.py), and
            # `answer.repeatable_token`'s own docstring says it returns "the
            # text a caller can echo" for exactly this shape - which is
            # precisely how a real, name-shaped credential-target/object
            # name (`PROD_NS01_GEHEIM`, MEASURED) passed it and reached the
            # answer unmasked at EVERY disclosure level. A shape gate proves
            # the text is safe to PRINT (no control characters, a bounded
            # length); it does not prove it is safe to REVEAL. So: report
            # this entry by its POSITION in the file only, never by any part
            # of its content.
            if repeatable_token(name, max_words=1, allow_hyphen=False) is not None:
                label = f"fase-invoer {index}"
                detail = f"onbekende fase in het fasebestand; deze versie kent alleen {known}"
            else:
                label = "(onbekende fase)"
                detail = (
                    f"het fasebestand noemt een fase zonder de vorm van een fase-naam; deze versie kent alleen {known}"
                )
            ok = entry.get("ok", _MISSING)
            if ok is _MISSING or not isinstance(ok, bool):
                # An unrecognised name with an
                # unusable `ok` is a genuine read gap - this product
                # cannot say it succeeded OR failed, so it must not be
                # left to silently taint nothing while the file's other,
                # independently-reported "bereikt" entries stand unchallenged
                # (MEASURED: `{"name": "PROD_NS01_GEHEIM", "ok": "kapot"}`
                # alongside five genuinely-true entries still read "Geen
                # fase meldde een mislukking" with all five bereikt).
                loose.append(_not_established(label, detail))
                unattributed_gap = True
            else:
                # The name is unrecognised, but `ok` is still a
                # genuine, readable fact this file explicitly reports -
                # reporting it as "niet vastgesteld" would silently drop a
                # real failure and leave "Geen fase meldde een mislukking"
                # standing as an untrue heading (MEASURED, with
                # {"name": "PROD_NS01_GEHEIM", "ok": false}).
                loose.append(PhaseReport(phase=label, word="bereikt" if ok else "mislukt", detail=detail))
            continue
        ok = entry.get("ok", _MISSING)
        if ok is _MISSING or not isinstance(ok, bool):
            # `"ok": "true"` (a JSON string, not a
            # boolean). The file DOES mention this phase - the detail below
            # must say so is malformed, never the untrue "does not report".
            # An entry this product cannot classify taints every
            # LATER phase in canonical order too (the cascade below) -
            # exactly like an outright "mislukt" always has.
            named_bad[dutch] = (
                f"fase {dutch}: het fasebestand meldt deze fase, maar de uitkomst is onbruikbaar "
                f"({_phase_shape(ok, 'een boolean')})"
            )
            continue
        if dutch in named or dutch in named_bad:
            # A duplicate is malformed, not "first/last value wins" -
            # two contradicting reports for the same phase cannot both be
            # trusted, and picking one over the other would dress up a coin
            # flip as [vastgesteld].
            named.pop(dutch, None)
            named_bad[dutch] = f"fase {dutch}: het fasebestand meldt deze fase meer dan eens"
            continue
        named[dutch] = ok

    # The cascade, walked in CANONICAL order - never array
    # order. A phase this product cannot classify (named_bad) OR that has
    # no entry at all taints every phase AFTER it in THIS walk, exactly as
    # an outright "mislukt" always has: a later phase cannot honestly be
    # "bereikt" while an earlier one is not established. The per-phase
    # DECISION itself is `_PHASE_PRECEDENCE` (above `_phases_from_file`)
    # - this loop only builds that phase's facts and
    # threads `earlier_phase_failed` forward from the REAL `ok`.
    reports: list[PhaseReport] = []
    # `earlier_phase_failed` tracks ONLY a REAL canonical PHASE_ORDER
    # failure - a `named_bad` entry, or a phase whose own `ok` was
    # genuinely read as False - `_PhaseFacts.earlier_real_failure` above.
    # Starts `False`; only ever becomes `True` from a fact this walk
    # itself establishes (never seeded from `unattributed_gap` - a fix
    # for the sibling defect that produced).
    earlier_phase_failed = False
    for dutch in PHASE_ORDER:
        facts = _PhaseFacts(
            malformed_detail=named_bad.get(dutch),
            own_ok=named.get(dutch),
            earlier_real_failure=earlier_phase_failed,
            unattributed_gap=unattributed_gap,
        )
        reports.append(_decide_phase_report(dutch, facts))
        # Threaded from the REAL fact, regardless of which rung just
        # decided the printed report: a phase that genuinely failed (or
        # whose own entry is malformed) taints every LATER phase in
        # canonical order even when its OWN report above was decided by a
        # higher-precedence rung rather than printed as "mislukt".
        if dutch in named_bad:
            earlier_phase_failed = True
        elif dutch in named:
            earlier_phase_failed = earlier_phase_failed or not named[dutch]
    # `reports` (canonical PHASE_ORDER, always all five) precedes `loose`
    # (entries with no phase attribution) - the same "known phases first,
    # oddities after" order the previous single-list sort already gave.
    return reports + loose, "found"


def _phases_from_artefacts(work_dir: Path) -> list[PhaseReport]:
    """What this product can establish WITHOUT the collect script's help.

    Three facts, all types and no text: does a manifest exist, does it carry a
    usable resource, and does it carry config/nsversion. The transport phases
    (DNS, TCP, TLS) are honestly 'niet vastgesteld': the child process knows
    them and this process does not, and inventing them from an error sentence
    is exactly what A16 forbids.
    """
    try:
        got = _work_read(work_dir, "export-manifest.json", allow_missing=False)
        raw = json.loads(localpath.as_text(got.data)) if not got.over_cap else None
        resources = raw.get("resources") if isinstance(raw, dict) else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        # 1.1 B: a refusal of the walk is an OSError too: not established.
        resources = None
    if not isinstance(resources, dict):
        login = "niet vastgesteld"
        identity = "niet vastgesteld"
    else:
        login = "bereikt" if _has_usable_resource(resources) else "mislukt"
        version = resources.get("config/nsversion")
        identity = (
            "bereikt"
            if isinstance(version, dict) and version.get("status") in USABLE
            else ("niet vastgesteld" if login == "mislukt" else "mislukt")
        )
    detail = "deze fase wordt door het verzamelscript gemeld; dit fasebestand ontbreekt"
    return [
        PhaseReport(phase="DNS", word="niet vastgesteld", detail=detail),
        PhaseReport(phase="TCP", word="niet vastgesteld", detail=detail),
        PhaseReport(phase="TLS", word="niet vastgesteld", detail=detail),
        PhaseReport(phase="NITRO-login", word=login),
        PhaseReport(phase="identiteit", word=identity),
    ]


def phase_report(work_dir: Path | None, export_dir: Path) -> list[PhaseReport]:
    """The phased diagnosis of the last scan attempt.

    `work_dir` is the directory holding evidence of THIS specific attempt:
    `CollectError.evidence_dir` from `collect()` above (the `.mislukt` slot
    `_preserve_as_failed` moved a failed attempt's own data to), or the
    export directory itself for a caller diagnosing a directory that is not
    a fresh failure. `None` means this attempt produced no evidence of its
    own (refused before a work directory ever existed - a missing script, a
    concurrent scan, a full disk): reporting a STALE directory from an
    unrelated, earlier attempt as if it were about THIS one would assert
    more than this attempt established, so this deliberately reports every
    phase as "niet vastgesteld" instead of guessing at a directory.

    `export_dir` is accepted and deliberately not read when `work_dir` is
    given: the caller knows which directory the attempt belonged to, and a
    future version that falls back onto the swapped-in export needs it in
    the signature already - see the pre-flight tool (`status_update_preflight`),
    which reuses this same classification.

    `_phases_from_file`'s "unreadable" state is
    returned AS THE ANSWER, never as a reason to fall back to
    `_phases_from_artefacts`: a phase file that exists but cannot be parsed
    is not the same as no phase file at all, and the artefact fallback's own
    detail text ("dit fasebestand ontbreekt") would be untrue about it.
    """
    if work_dir is None:
        return [
            _not_established(dutch, "deze scanpoging leverde geen eigen gegevens op om te beoordelen")
            for dutch in PHASE_ORDER
        ]
    reports, state = _phases_from_file(work_dir)
    if state == "absent":
        return _phases_from_artefacts(work_dir)
    return reports


def phase_summary(reports: list[PhaseReport]) -> str:
    """One line per phase, plus the phase it stranded on as the heading."""
    stranded = next((r.phase for r in reports if r.word == "mislukt"), None)
    if stranded:
        head = f"De scan strandde in fase {stranded}."
    elif any(r.word == "niet vastgesteld" and r.phase not in PHASE_ORDER for r in reports):
        # A report outside PHASE_ORDER is always
        # an unattributable entry the file itself supplied (`loose` in
        # `_phases_from_file`) - never a canonical phase this product
        # simply never heard about. "niet vastgesteld" there means a
        # genuine read gap (an unclassifiable `ok`, or none at all - never
        # a classified true/false, which would already have set `stranded`
        # above). "Geen fase meldde een mislukking" would assert more than
        # this attempt established; this heading asserts only what the
        # gate found (something it could not read), true at every status
        # where it can print.
        head = "Niet elke fase-invoer in het fasebestand kon vastgesteld worden."
    else:
        head = "Geen fase meldde een mislukking."
    lines = [f"- {r.phase}: {r.word}" + (f" ({r.detail})" if r.detail else "") for r in reports]
    return head + "\n" + "\n".join(lines)


def read_single_resource(
    target: Target, resource: str, script_path: Path, timeout_s: int, run=None
) -> tuple[dict | None, ReadGap | None, bool]:
    """ONE resource, live, through the SAME separate process as a scan.

    Not a second scan route and not a second credential: the same script, the
    same `doelen` credential, a temporary output directory that is removed
    afterwards, and nothing swapped into the export directory. The product
    process opens no socket - the script does.

    Fail closed in every direction. A script that does not accept
    `-OnlyResources`, a non-zero exit code, an empty or unreadable object
    file: all of them are a ReadGap with the reason named, never a value.

    WHY THIS EXISTS: `status_update_preflight` (design 2.3)
    is the SECOND documented exception to "a reading tool never opens a
    socket" (design 2.10 row 13, 3.1). Check 8 of that pre-flight is the free
    space on `/var`, and a free-space figure from last week's scan says
    nothing about the moment of the attempt. A THIRD name on that exception
    list is a change of the design, not test maintenance.

    The result of the run is read back through `load_export(...).single(...)`
    - the SAME manifest/status/shape discipline every other read in this
    product passes - rather than by parsing the object file here. A second
    reader would be a second place for that discipline to drift.

    1.0.2: the third value says whether a process RAN. A missing script, a
    temporary directory that could not be made and a process that never
    started (`CollectNotStarted`: a pin that does not match, no PowerShell)
    give False and a reason that starts with `NOT_STARTED`; the caller then
    names no route. A timeout, an exit code or an unusable result ran.
    """
    if not script_path.exists():
        return (
            None,
            ReadGap(
                source=resource,
                reason=f"het verzamelscript is niet gevonden op {script_path}; er is niet live gelezen",
            ),
            False,
        )
    if run is not None:
        runner = run
    else:

        def runner(arguments, seconds):
            return _run_powershell(arguments, seconds)

    try:
        work_dir = Path(tempfile.mkdtemp(prefix="nsmcp-live-"))
    except OSError as exc:
        # The kind, never `{exc}`: that names the local temporary directory.
        return (
            None,
            ReadGap(
                source=resource,
                reason=f"{NOT_STARTED}kon geen tijdelijke uitvoermap aanmaken ({_os_error_kind(exc)})",
            ),
            False,
        )
    try:
        arguments = build_arguments(target, work_dir, script_path) + ["-OnlyResources", resource]
        try:
            code, error_text = runner(arguments, timeout_s)
        except CollectNotStarted as exc:
            text = _short_report(str(exc), target)
            reason = text if text.startswith(NOT_STARTED) else f"{NOT_STARTED}{text}"
            return None, ReadGap(source=resource, reason=reason), False
        except CollectError as exc:
            # A timeout, a cancelled child process: an absence with a reason
            # here, never an exception the caller has to catch. The pre-flight
            # would lose its other eight checks over one that raised.
            return None, ReadGap(source=resource, reason=_short_report(str(exc), target)), True
        except OSError as exc:
            return (
                None,
                ReadGap(source=resource, reason=f"{NOT_STARTED}{_scrub_error_text(str(exc), target)}"),
                False,
            )
        if code != 0:
            # The one place a script that does not know `-OnlyResources` ends
            # up: PowerShell refuses an unknown parameter with a non-zero exit
            # code. The scan script is CONFIGURED and sits outside this
            # product, so the product cannot force that support - what it does
            # is never make a silent green of it.
            return (
                None,
                ReadGap(
                    source=resource,
                    reason=(f"de live lezing stopte met exitcode {code}: {_short_report(error_text, target)}"),
                ),
                True,
            )
        export = load_export(work_dir)
        if export.manifest_missing:
            return (
                None,
                ReadGap(
                    source=resource,
                    reason=(
                        "de live lezing liep af zonder bruikbaar export-manifest; dat is een"
                        " mislukte lezing, geen lege waarde"
                    ),
                ),
                True,
            )
        row, gap = export.single(resource)
        if gap is not None:
            return None, gap, True
        if row is None:
            return (
                None,
                ReadGap(
                    source=resource,
                    reason=(
                        "de live lezing meldt deze resource als gelezen maar droeg er geen object"
                        " voor; een lege lezing is geen waarde"
                    ),
                ),
                True,
            )
        return row, None, True
    finally:
        # Nothing of this run survives the call: the temporary directory goes,
        # and the export directory was never touched.
        shutil.rmtree(work_dir, ignore_errors=True)
