"""The ONE place this product starts Windows PowerShell.

Why absolute and why fail-closed. `subprocess.Popen(["powershell.exe", ...])`
lets Windows search for the program, and CreateProcess searches the WORKING
DIRECTORY before System32. Whoever can drop a file in the working directory of
the server process therefore executes code with the server's rights - and that
touches the READING path (`status_ververs` starts the collector) as much as the
writing path, so the read-only promise hangs on it. Measured: a copy of
`hostname.exe` named `powershell.exe` in the working directory answered instead
of PowerShell.

Why one starter for both call sites. `collect.py` and `handelen.py` carried two
near-identical Popen calls of which only one set `encoding="utf-8",
errors="replace"`. What this module guarantees is narrow, and it is stated
narrowly on purpose: ONE starter and ONE encoding for both paths, and
`errors="replace"`, so a byte that cannot be decoded becomes a replacement
character instead of an exception.

That last part is the property the change really bought, and it is measured
rather than assumed (`tests/test_powershell.py`,
`test_undecodable_child_output_becomes_a_replacement_character_not_an_exception`
starts a real child that emits bytes which are not valid UTF-8). The old
`collect.py` call passed `text=True` with no `errors=`, so such a byte raised
`UnicodeDecodeError` inside `communicate()` - where only `TimeoutExpired` is
caught. The READING path crashed on it. It no longer can.

What is NOT claimed here: that the text now comes through CORRECTLY. Windows
PowerShell 5.1 writes a redirected stream in `[Console]::OutputEncoding`, which
on a Dutch installation is an OEM code page and not UTF-8, so reading it as
UTF-8 can still be the wrong reading - it is simply a wrong reading that no
longer raises. Getting the encoding right is a separate question from getting
the crash out, and only the second is settled here.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from nsmcp import localpath
from nsmcp.limits import MAX_FILE_BYTES


class PowerShellMissing(Exception):
    """Windows PowerShell is not where Windows says it is. Never silent."""


class ScriptPinMismatch(PowerShellMissing):
    """1.0.2: a script this product would start does not match its
    pin, or carries none while pins are configured. A subclass of
    `PowerShellMissing` on purpose: every caller already turns that into
    "no process was started" with a reason, and that is what this is. The
    message names the FILE NAME only, never a local path."""


class ChildWorkingDirectoryUnusable(PowerShellMissing):
    """1.0.3 (R3-5): the fixed working directory of a child process
    (`child_working_directory`) is not usable. A subclass of
    `PowerShellMissing` for the same reason as `ScriptPinMismatch`: every
    caller already turns that into "no process was started". Its own class so
    a caller can say the REAL reason instead of "PowerShell niet gevonden"
    (MEASURED before: a scan said exactly that). The message names the kind
    of problem, never the local path."""


# The execution policies a configuration may name (`uitvoeringsbeleid`).
# `Bypass` is the default because the product's own scripts are not signed;
# `AllSigned`/`RemoteSigned` hand the decision back to Windows for an operator
# who signs them. Never `Unrestricted` or `Undefined`: those say nothing.
EXECUTION_POLICIES = ("Bypass", "AllSigned", "RemoteSigned")
DEFAULT_EXECUTION_POLICY = "Bypass"


@dataclass(frozen=True)
class ScriptPolicy:
    """How this product starts its PowerShell scripts (1.0.2).

    `pins`: file name (case-folded) -> sha256 of the bytes, or None when the
    configuration carries no `scriptpin` - then nothing is checked, as
    before, and the documentation says so. With pins, a script is started
    only when its own bytes AND those of every script in the same
    directory (`SCRIPT_SUFFIXES`; the runner, the live measurement and
    config_opslaan dot-source their transport by name from there) match
    their pins. A script without a pin - the started one or any script
    beside it - refuses the start.

    Process state on purpose: one server per process, and the ONE place that
    starts PowerShell (`start_powershell`, `handelen.upgrade_command`) reads
    it right before the start. `build_server` sets it for every server it
    builds."""

    pins: Mapping[str, str] | None = None
    execution_policy: str = DEFAULT_EXECUTION_POLICY


_policy = ScriptPolicy()


def set_script_policy(policy: ScriptPolicy) -> None:
    global _policy
    _policy = policy


def script_policy() -> ScriptPolicy:
    return _policy


def file_sha256(path: Path) -> str:
    """The sha256 of the script's bytes, read through `localpath` (1.1 B)
    with the script's own directory as the root: a link or reparse point in
    its place or on the way raises `PathRefused` (an OSError), the caller's
    `ScriptPinMismatch`. The pin proves the bytes hashed now, not the bytes
    PowerShell will execute (SECURITY.md, the execution-identity boundary)."""
    text = localpath.absolute_text(path)
    got = localpath.read_local(text, root=localpath.parent_text(text), max_bytes=MAX_FILE_BYTES)
    if got.over_cap:
        raise OSError("het script is groter dan het plafond")
    return hashlib.sha256(got.data).hexdigest()


# What counts as a script beside the started one: what PowerShell can
# dot-source or import from that directory. Compared case-insensitively.
SCRIPT_SUFFIXES = (".ps1", ".psm1")


def _is_script(path: Path) -> bool:
    return path.suffix.casefold() in SCRIPT_SUFFIXES


def check_script_pins(script: Path) -> None:
    """Raises `ScriptPinMismatch` unless `script` may be started under the
    current policy. Reads the bytes now, right before the start.

    1.0.2: every script in the same directory needs a pin as well, not only
    the ones that happen to carry one. The runner, the live measurement and
    config_opslaan dot-source their SSH transport BY NAME from their own
    directory; a pin on the runner alone let a replaced, unpinned transport
    through without a word. A directory that cannot be listed refuses too:
    what cannot be seen cannot be checked."""
    pins = _policy.pins
    if pins is None:
        return
    script = Path(script)
    name = script.name
    expected = pins.get(name.casefold())
    if expected is None:
        raise ScriptPinMismatch(
            f"het script {name} heeft geen pin in scriptpin, terwijl scriptpin is ingesteld; er wordt geen"
            " proces gestart"
        )
    to_check = [(name, script, expected)]
    map_tekst = localpath.parent_text(localpath.absolute_text(script))
    try:
        # 1.1 B: the names on the held script directory, never `iterdir()`.
        siblings = sorted(
            (Path(localpath.under(map_tekst, naam)) for naam in localpath.list_local(map_tekst, root=map_tekst)),
            key=lambda path: path.name.casefold(),
        )
    except OSError as exc:
        raise ScriptPinMismatch(
            f"de map van het script {name} kon niet gelezen worden voor de pincontrole"
            f" ({localpath.describe(exc)}); er wordt geen proces gestart"
        ) from None
    for sibling in siblings:
        folded = sibling.name.casefold()
        if folded == name.casefold() or not _is_script(sibling) or not localpath.is_local_file(sibling, root=map_tekst):
            continue
        pinned = pins.get(folded)
        if pinned is None:
            raise ScriptPinMismatch(
                f"het script {sibling.name} naast {name} heeft geen pin in scriptpin; PowerShell kan het op naam"
                " inlezen, dus er wordt geen proces gestart (pin de hele map met python -m nsmcp.powershell"
                " --pin <map>)"
            )
        to_check.append((sibling.name, sibling, pinned))
    for shown, path, pinned in to_check:
        try:
            measured = file_sha256(path)
        except OSError as exc:
            raise ScriptPinMismatch(
                f"het script {shown} kon niet gelezen worden voor de pincontrole ({localpath.describe(exc)});"
                " er wordt geen proces gestart"
            ) from None
        if measured != pinned:
            raise ScriptPinMismatch(
                f"het script {shown} wijkt af van zijn pin in scriptpin (sha256 {measured[:12]}... in plaats"
                f" van {pinned[:12]}...); er wordt geen proces gestart"
            )


def _file_argument(arguments: list[str]) -> Path | None:
    for index, argument in enumerate(arguments[:-1]):
        if argument == "-File":
            return Path(arguments[index + 1])
    return None


def powershell_path() -> Path:
    """The absolute path to Windows PowerShell, derived from %SystemRoot%.

    `%SystemRoot%` and not a hard-coded `C:\\Windows`: a Windows install on
    another volume is ordinary, and reading the variable is not a weakening -
    an attacker who can set the environment of the server process already owns
    that process. The fallback exists so a missing variable becomes an honest
    "not found" below instead of a TypeError here.
    """
    system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
    return Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def child_working_directory() -> Path:
    """1.0.3: the ONE working directory of every child process this product
    starts (PowerShell, a `.py` runner, a presenter), set explicitly instead
    of inherited from the server.

    MEASURED before: the server's children inherited its working directory,
    and the PowerShell bridge then started `& $GatePython -m <module>` there.
    `-m` searches the working directory first, so a planted `nsmcp` package in
    a supplier-writable directory the server was started in replaced the gate
    module. The bridge now runs in isolated mode (`-I`); this directory is the
    second half: fixed, absolute and not writable by a supplier - the
    System32 directory of the same `%SystemRoot%` `powershell_path()` reads
    (the directory Windows itself starts services in), or `/` elsewhere.
    Fail-closed: a relative or absent directory raises, no process starts."""
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
        directory = Path(system_root) / "System32"
    else:
        directory = Path("/")
    if not directory.is_absolute():
        raise ChildWorkingDirectoryUnusable(
            "de vaste werkmap voor kindprocessen is niet bruikbaar (het pad is niet absoluut);"
            " er wordt geen proces gestart"
        )
    if not localpath.is_local_dir(directory):
        raise ChildWorkingDirectoryUnusable(
            "de vaste werkmap voor kindprocessen is niet bruikbaar (de map bestaat niet); er wordt geen proces gestart"
        )
    return directory


def start_powershell(arguments: list[str]) -> subprocess.Popen[str]:
    """Starts Windows PowerShell with `arguments`, or raises.

    Fail-closed on purpose: no PowerShell means no process. A fallback to the
    bare program name would restore exactly the search order this function
    exists to remove, and so would a repair of a bad path - neither exists.

    Two refusals, and the order between them is deliberate. Absoluteness is
    checked FIRST, before the filesystem is consulted at all: `is_file()`
    resolves a relative path against the WORKING DIRECTORY, so a relative
    `%SystemRoot%` could pass an existence check precisely because an
    attacker-planted file sits in the working directory - and `Popen` would
    then hand Windows a command line whose first token is relative, which
    CreateProcess resolves against that same directory. Checking existence
    first would mean asking the working directory a question this module
    exists to stop asking.
    """
    script = _file_argument(arguments)
    if script is not None:
        check_script_pins(script)
    executable = powershell_path()
    if not executable.is_absolute():
        raise PowerShellMissing(f"Windows PowerShell-pad {executable} is niet absoluut; er wordt geen proces gestart")
    if not localpath.is_local_file(executable):
        raise PowerShellMissing(f"Windows PowerShell niet gevonden op {executable}; er wordt geen proces gestart")
    return subprocess.Popen(
        [str(executable), *arguments],
        cwd=child_working_directory(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main(argv: list[str] | None = None) -> int:
    """`python -m nsmcp.powershell --pin <script-of-map> ...`: the `scriptpin`
    object for the given scripts, to paste into the configuration. A
    directory stands for every script in it (`SCRIPT_SUFFIXES`) - with
    `scriptpin` set, every script beside a started one needs a pin."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) < 2 or arguments[0] != "--pin":
        print("Gebruik: python -m nsmcp.powershell --pin <script.ps1 of map> [...]", file=sys.stderr)
        return 2
    paths: list[Path] = []
    for name in arguments[1:]:
        path = Path(name)
        if localpath.is_local_dir(path):
            try:
                map_tekst = localpath.absolute_text(path)
                found = sorted(
                    (
                        Path(localpath.under(map_tekst, naam))
                        for naam in localpath.list_local(map_tekst, root=map_tekst)
                        if _is_script(Path(naam)) and localpath.is_local_file(localpath.under(map_tekst, naam))
                    ),
                    key=lambda p: p.name.casefold(),
                )
            except OSError as exc:
                print(f"Fout: de map {path.name} kon niet gelezen worden ({localpath.describe(exc)})", file=sys.stderr)
                return 1
            paths.extend(found)
        else:
            paths.append(path)
    pins = {}
    for path in paths:
        try:
            pins[path.name] = file_sha256(path)
        except OSError as exc:
            print(f"Fout: {path.name} kon niet gelezen worden ({localpath.describe(exc)})", file=sys.stderr)
            return 1
    print(json.dumps({"scriptpin": pins}, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main() in the tests
    raise SystemExit(main())
