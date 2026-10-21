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

import os
import subprocess
from pathlib import Path


class PowerShellMissing(Exception):
    """Windows PowerShell is not where Windows says it is. Never silent."""


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
