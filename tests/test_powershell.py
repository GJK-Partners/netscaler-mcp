"""The one place this product starts Windows PowerShell.

`nsmcp.powershell` is the single starter: `powershell_path()` resolves an
absolute path (never a bare `"powershell.exe"`, which lets Windows search
the working directory - the CreateProcess behaviour the module docstring
measures), and `start_powershell()` wraps that path with the process
invocation both `collect.py` and `handelen.default_runner()` call. This
test file covers `powershell_path()`, `PowerShellMissing`, and the
guarantee that neither `collect.py` nor `handelen.py` still names the bare
program. See `nsmcp.powershell`'s own module docstring for the full
measurement behind the design.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from nsmcp import collect as collect_module, handelen as handelen_module
from nsmcp.powershell import PowerShellMissing, powershell_path, start_powershell


def test_the_powershell_starter_uses_the_absolute_system_path(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert powershell_path() == Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def test_the_path_follows_a_windows_install_on_another_volume(monkeypatch):
    """The first test pins SystemRoot to the very value that is also the
    hard-coded fallback, so it would stay green even if the function
    ignored the environment altogether. A Windows install on another
    volume is the case that tells those two apart."""
    monkeypatch.setenv("SystemRoot", r"D:\Windows")
    assert powershell_path() == Path(r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


@pytest.mark.parametrize("system_root", ["Windows", " "])
def test_a_relative_system_root_starts_nothing(monkeypatch, system_root):
    """A relative `%SystemRoot%` yields a RELATIVE executable path - exactly
    the working-directory search this module exists to remove. `is_file()`
    is forced to True: the refusal must be because the path is relative,
    not because nothing happens to sit there."""
    monkeypatch.setenv("SystemRoot", system_root)
    monkeypatch.setattr(Path, "is_file", lambda self: True)

    def never(*args, **kwargs):
        raise AssertionError("no process may be started for a relative path")

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", never)
    with pytest.raises(PowerShellMissing) as exc:
        start_powershell(["-NoProfile"])
    assert "niet absoluut" in str(exc.value)


def test_a_missing_powershell_fails_closed(monkeypatch):
    monkeypatch.setattr(Path, "is_file", lambda self: False)

    def never(*args, **kwargs):
        raise AssertionError("no process may be started when PowerShell is absent")

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", never)
    with pytest.raises(PowerShellMissing) as exc:
        start_powershell(["-NoProfile"])
    assert "niet gevonden" in str(exc.value)


def test_the_starter_never_hands_a_bare_program_name_to_the_operating_system(monkeypatch):
    seen = {}

    class Spy:
        def __init__(self, argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", Spy)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    start_powershell(["-NoProfile"])
    assert seen["argv"][0].lower().endswith(r"\system32\windowspowershell\v1.0\powershell.exe")
    assert seen["argv"][0] != "powershell.exe"
    assert Path(seen["argv"][0]).is_absolute()


def test_both_call_sites_use_the_same_starter_and_the_same_encoding(monkeypatch):
    """The reading path (collect) and the writing path (handelen) went through
    two near-identical Popen calls, of which only handelen set
    encoding="utf-8". The collector branch therefore read Dutch error text
    from the NSHC script with the locale code page. One starter, one encoding.

    Measured: there are
    TWO real call sites, collect.py:121 and handelen.py:227, both through
    `start_powershell`. `handelen.py`'s later `cmd=list(process.args)` is
    not a third one - it labels a `subprocess.TimeoutExpired` this module
    re-raises after a timed-out run, using the command line the started
    process actually reports (`process.args`), not a fresh call. No
    process is started there and there is no encoding to set."""
    seen = []

    class Spy:
        returncode = 0
        args = ["x"]

        def __init__(self, argv, **kwargs):
            seen.append(kwargs)

        def communicate(self, timeout=None):
            return "", ""

    monkeypatch.setattr(subprocess, "Popen", Spy)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    start_powershell(["-NoProfile"])
    assert seen[-1]["encoding"] == "utf-8"
    assert seen[-1]["errors"] == "replace"
    assert seen[-1]["text"] is True

    # And neither module still names the bare program.
    for module_file in (collect_module.__file__, handelen_module.__file__):
        source = Path(module_file).read_text(encoding="utf-8")
        assert '"powershell.exe"' not in source


def test_a_timed_out_write_reports_the_command_line_that_really_ran(monkeypatch):
    """`default_runner` used to rebuild the command line it
    reports on a timeout from the bare program name, so the report named a
    command that was never executed. It now passes on `process.args`: the
    absolute path the starter really handed to Windows.
    """

    class SpyProcess:
        returncode = None

        def __init__(self, argv, **kwargs):
            self.args = argv
            self._answered = False

        def communicate(self, timeout=None):
            if not self._answered:
                self._answered = True
                raise subprocess.TimeoutExpired(cmd=self.args, timeout=timeout)
            return "[START] actie\n", ""

        def terminate(self):
            return None

    monkeypatch.setattr(subprocess, "Popen", SpyProcess)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    with pytest.raises(subprocess.TimeoutExpired) as exc:
        handelen_module.default_runner(["-NoProfile"], 1)
    assert exc.value.cmd[0] != "powershell.exe"
    assert Path(exc.value.cmd[0]).is_absolute()
    assert exc.value.cmd[1:] == ["-NoProfile"]


def test_undecodable_child_output_becomes_a_replacement_character_not_an_exception():
    """THE test for the no-crash property - the one thing the encoding change
    really bought, proved by decoding rather than by inspecting kwargs.

    An earlier encoding test only checked which keyword arguments reached
    `Popen`. That is a tautology:
    nothing in it decodes a single byte. This test starts a REAL Windows
    PowerShell and reads what actually comes back.

    The child sets `[Console]::OutputEncoding` to code page 1252 and writes
    A, U+00E9, B. That is the shape of the real problem: Windows PowerShell
    5.1 writes a redirected stream in `[Console]::OutputEncoding`, which on a
    Dutch installation is an OEM code page and not UTF-8. On the wire the
    child emits 0x41 0xE9 0x42, and 0xE9 announces a three-byte UTF-8 sequence
    that 0x42 does not continue - so those bytes are not valid UTF-8 under any
    reading.

    What this proves: the call RETURNS TEXT instead of raising, and the
    undecodable byte arrives as U+FFFD. Before the shared starter, `collect.py`
    passed `text=True` with no `errors=`, so such a byte raised
    `UnicodeDecodeError` inside `communicate()` - where only `TimeoutExpired`
    is caught, so the READING path crashed on it.

    What this does NOT prove, and is deliberately not asserted: that the text
    is decoded CORRECTLY. It is not. It is a wrong reading that no longer
    raises, and the module docstring says exactly that.
    """
    command = (
        "[Console]::OutputEncoding = [Text.Encoding]::GetEncoding(1252); [Console]::Out.Write('A' + [char]0xE9 + 'B')"
    )
    process = start_powershell(["-NoProfile", "-NonInteractive", "-Command", command])
    stdout, stderr = process.communicate(timeout=60)
    assert process.returncode == 0, f"het kind faalde: {ascii(stderr)}"
    assert stdout == "A\ufffdB", ascii(stdout)


def test_the_timeout_label_names_the_same_absolute_path(monkeypatch, tmp_path):
    """Design 3.6 unit 1. `handelen.py` re-raises a TimeoutExpired with a
    command label. That label starts no process and carries no encoding, but it
    IS what a human reads afterwards - so it has to name the command that
    really ran, absolute path and all, instead of the bare program name the
    starter exists to remove."""

    class Hanging:
        def __init__(self, argv, **kwargs):
            self.args = list(argv)
            self.stdout = None
            self.stderr = None

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd=self.args, timeout=timeout)

        def terminate(self):
            return None

        def kill(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", Hanging)
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    with pytest.raises(subprocess.TimeoutExpired) as exc:
        handelen_module.default_runner(["-NoProfile"], timeout_s=1)
    label = " ".join(str(part) for part in exc.value.cmd)
    assert label.lower().endswith("-noprofile")
    assert "system32\\windowspowershell\\v1.0\\powershell.exe" in label.lower()
    assert not label.lower().startswith("powershell.exe")
