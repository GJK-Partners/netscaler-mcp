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


class PowerShellMissing(Exception):
    """Windows PowerShell is not where Windows says it is. Never silent."""


class ScriptPinMismatch(PowerShellMissing):
    """1.0.2: a script this product would start does not match its
    pin, or carries none while pins are configured. A subclass of
    `PowerShellMissing` on purpose: every caller already turns that into
    "no process was started" with a reason, and that is what this is. The
    message names the FILE NAME only, never a local path."""


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
    only when its own bytes AND those of every pinned script in the same
    directory (the runner dot-sources its transport by name) match, and a
    script without a pin is refused.

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
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_script_pins(script: Path) -> None:
    """Raises `ScriptPinMismatch` unless `script` may be started under the
    current policy. Reads the bytes now, right before the start."""
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
    try:
        siblings = list(script.parent.iterdir())
    except OSError:
        siblings = []
    for sibling in siblings:
        pinned = pins.get(sibling.name.casefold())
        if pinned is not None and sibling.name.casefold() != name.casefold() and sibling.is_file():
            to_check.append((sibling.name, sibling, pinned))
    for shown, path, pinned in to_check:
        try:
            measured = file_sha256(path)
        except OSError as exc:
            raise ScriptPinMismatch(
                f"het script {shown} kon niet gelezen worden voor de pincontrole ({exc.__class__.__name__});"
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
    if not executable.is_file():
        raise PowerShellMissing(f"Windows PowerShell niet gevonden op {executable}; er wordt geen proces gestart")
    return subprocess.Popen(
        [str(executable), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def main(argv: list[str] | None = None) -> int:
    """`python -m nsmcp.powershell --pin <script> ...`: the `scriptpin`
    object for the given scripts, to paste into the configuration."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) < 2 or arguments[0] != "--pin":
        print("Gebruik: python -m nsmcp.powershell --pin <script.ps1> [...]", file=sys.stderr)
        return 2
    pins = {}
    for name in arguments[1:]:
        path = Path(name)
        try:
            pins[path.name] = file_sha256(path)
        except OSError as exc:
            print(f"Fout: {path.name} kon niet gelezen worden ({exc.__class__.__name__})", file=sys.stderr)
            return 1
    print(json.dumps({"scriptpin": pins}, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main() in the tests
    raise SystemExit(main())
