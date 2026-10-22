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


# ---------------------------------------------------------------------------
# 1.0.2: a hash pin per script, checked on the bytes right before the
# process starts, and the execution policy as an explicit setting.
# ---------------------------------------------------------------------------


@pytest.fixture
def restore_policy(monkeypatch):
    """The script policy is process state (one server per process); every
    test here puts the previous one back."""
    from nsmcp import powershell as powershell_module

    monkeypatch.setattr(powershell_module, "_policy", powershell_module._policy)
    return powershell_module


def _scripts(tmp_path: Path) -> tuple[Path, Path]:
    main = tmp_path / "scripts" / "Verzamel.ps1"
    main.parent.mkdir()
    main.write_bytes(b"Write-Host 'verzamel'\r\n")
    sibling = tmp_path / "scripts" / "Transport.ps1"
    sibling.write_bytes(b"function Transport { }\r\n")
    return main, sibling


def _sha(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _spy_popen(monkeypatch):
    started = []

    class _Process:
        pass

    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: started.append(argv) or _Process())
    return started


def test_sr5_a_script_that_differs_from_its_pin_is_never_started(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": "0" * 64, "transport.ps1": _sha(sibling)}))
    started = _spy_popen(monkeypatch)
    with pytest.raises(ScriptPinMismatch) as refused:
        start_powershell(["-NoProfile", "-File", str(main)])
    assert started == []
    message = str(refused.value)
    assert "Verzamel.ps1" in message and str(tmp_path) not in message, message


def test_sr5_an_unpinned_script_is_refused_once_pins_are_configured(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"transport.ps1": _sha(sibling)}))
    started = _spy_popen(monkeypatch)
    with pytest.raises(ScriptPinMismatch, match="geen pin"):
        start_powershell(["-File", str(main)])
    assert started == []


def test_sr5_a_changed_pinned_sibling_refuses_the_start_too(tmp_path, monkeypatch, restore_policy):
    """The runner dot-sources its transport by NAME from its own directory;
    a pinned sibling that changed stops the start as well."""
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main), "transport.ps1": _sha(sibling)}))
    sibling.write_bytes(b"function Transport { Write-Host 'anders' }\r\n")
    started = _spy_popen(monkeypatch)
    with pytest.raises(ScriptPinMismatch, match="Transport.ps1"):
        start_powershell(["-File", str(main)])
    assert started == []


def test_sr5_matching_pins_start_the_script(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main), "transport.ps1": _sha(sibling)}))
    started = _spy_popen(monkeypatch)
    start_powershell(["-File", str(main)])
    assert len(started) == 1


def test_sr5_without_pins_the_start_is_unchanged(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPolicy, set_script_policy

    main, _sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy())
    started = _spy_popen(monkeypatch)
    start_powershell(["-File", str(main)])
    assert len(started) == 1


@pytest.mark.parametrize("policy", ["Bypass", "AllSigned", "RemoteSigned"])
def test_sr5_every_script_head_carries_the_configured_execution_policy(tmp_path, restore_policy, policy):
    from nsmcp.handelen import script_command
    from nsmcp.powershell import ScriptPolicy, set_script_policy
    from nsmcp.target import CertAgreement, Target

    set_script_policy(ScriptPolicy(execution_policy=policy))
    target = Target(name="lab", address="192.0.2.10", credential_target="T/x", agreement=CertAgreement.CHAIN)
    for head in (
        collect_module.build_arguments(target, tmp_path, tmp_path / "v.ps1"),
        script_command(tmp_path / "s.ps1", []),
    ):
        index = head.index("-ExecutionPolicy")
        assert head[index + 1] == policy, head


def test_sr5_the_pin_command_prints_the_pins_of_the_given_scripts(tmp_path, capsys):
    import json

    from nsmcp.powershell import main as pin_main

    main_script, sibling = _scripts(tmp_path)
    assert pin_main(["--pin", str(main_script), str(sibling)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == {"scriptpin": {"Verzamel.ps1": _sha(main_script), "Transport.ps1": _sha(sibling)}}


# ---------------------------------------------------------------------------
# 1.0.2, second round: with `scriptpin` set, an UNPINNED script beside the
# started one refuses the start as well. Measured on the first 1.0.2 build:
# the runner pinned and its transport (dot-sourced by name from the same
# directory) not pinned -> the start went ahead and the transport was never
# read. A pin that leaves the dot-sourced sibling out suggests a certainty
# it does not give.
# ---------------------------------------------------------------------------

_REPO_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def test_rh1_an_unreadable_script_directory_refuses_the_start(tmp_path, monkeypatch, restore_policy):
    """1.0.3 RH-1: the refusal when the script's own directory cannot be
    listed. Every pin present and matching, so ONLY the unreadable directory
    can refuse: a version that treats an unlistable directory as "no
    siblings" lets the start through and fails here."""
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main), "transport.ps1": _sha(sibling)}))
    real_iterdir = Path.iterdir

    def unreadable(self):
        if self == main.parent:
            raise PermissionError("geen leesrecht op de map")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", unreadable)
    started = _spy_popen(monkeypatch)
    for start in (
        lambda: start_powershell(["-NoProfile", "-File", str(main)]),
        lambda: handelen_module.upgrade_command(main, ["-Fase", "R0"]),
    ):
        with pytest.raises(ScriptPinMismatch) as refused:
            start()
        message = str(refused.value)
        assert "kon niet gelezen worden voor de pincontrole" in message and "PermissionError" in message, message
        assert str(tmp_path) not in message, message
    assert started == []


def test_sr5_an_unpinned_sibling_script_refuses_the_start(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, _sibling = _scripts(tmp_path)
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main)}))
    started = _spy_popen(monkeypatch)
    with pytest.raises(ScriptPinMismatch) as refused:
        start_powershell(["-File", str(main)])
    assert started == []
    message = str(refused.value)
    assert "Transport.ps1" in message and "geen pin" in message, message
    assert str(tmp_path) not in message, message


def test_sr5_an_unpinned_module_beside_the_script_refuses_the_start(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPinMismatch, ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    module = main.parent / "Helpers.psm1"
    module.write_bytes(b"function Help { }\r\n")
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main), "transport.ps1": _sha(sibling)}))
    started = _spy_popen(monkeypatch)
    with pytest.raises(ScriptPinMismatch, match="Helpers.psm1"):
        start_powershell(["-File", str(main)])
    assert started == []


def test_sr5_a_file_that_is_no_script_beside_it_does_not_need_a_pin(tmp_path, monkeypatch, restore_policy):
    from nsmcp.powershell import ScriptPolicy, set_script_policy

    main, sibling = _scripts(tmp_path)
    (main.parent / "README.md").write_text("uitleg\n", encoding="ascii")
    (main.parent / "instellingen.json").write_text("{}\n", encoding="ascii")
    (main.parent / "oud.ps1.bak").write_text("# oud\n", encoding="ascii")
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(main), "transport.ps1": _sha(sibling)}))
    started = _spy_popen(monkeypatch)
    start_powershell(["-File", str(main)])
    assert len(started) == 1


def _product_scripts_but_the_transport_pinned(tmp_path: Path) -> Path:
    """The product's own scripts directory, copied, with every script
    pinned EXCEPT the SSH transport the three SSH scripts dot-source."""
    import shutil

    from nsmcp.powershell import ScriptPolicy, set_script_policy

    directory = tmp_path / "scripts"
    directory.mkdir()
    for script in _REPO_SCRIPTS.glob("*.ps1"):
        shutil.copyfile(script, directory / script.name)
    assert (directory / "GjkUpgrade-Ssh.ps1").is_file()
    pins = {p.name.casefold(): _sha(p) for p in directory.glob("*.ps1") if p.name != "GjkUpgrade-Ssh.ps1"}
    set_script_policy(ScriptPolicy(pins=pins))
    return directory


@pytest.mark.parametrize("script", ["Invoke-GjkLiveMeting.ps1", "Invoke-GjkConfigOpslaan.ps1"])
def test_sr5_the_ssh_scripts_refuse_to_start_beside_an_unpinned_transport(
    tmp_path, monkeypatch, restore_policy, script
):
    from nsmcp.handelen import ActionError, script_command

    directory = _product_scripts_but_the_transport_pinned(tmp_path)
    started = _spy_popen(monkeypatch)
    with pytest.raises(ActionError, match="GjkUpgrade-Ssh.ps1") as refused:
        handelen_module.default_runner(script_command(directory / script, ["-WatIs"]), 5)
    assert started == []
    assert str(tmp_path) not in str(refused.value)


def test_sr5_the_faserunner_refuses_to_start_beside_an_unpinned_transport(tmp_path, monkeypatch, restore_policy):
    from nsmcp.handelen import upgrade_command
    from nsmcp.powershell import ScriptPinMismatch

    directory = _product_scripts_but_the_transport_pinned(tmp_path)
    with pytest.raises(ScriptPinMismatch, match="GjkUpgrade-Ssh.ps1"):
        upgrade_command(directory / "Invoke-GjkUpgradeFase.ps1", ["-WatIs"])


def test_sr5_the_write_script_refuses_to_start_beside_an_unpinned_script(tmp_path, monkeypatch, restore_policy):
    from nsmcp.handelen import ActionError, script_command
    from nsmcp.powershell import ScriptPolicy, set_script_policy

    film = tmp_path / "film"
    film.mkdir()
    write = film / "Invoke-GjkLabWrite.ps1"
    write.write_bytes(b". (Join-Path $PSScriptRoot 'Hulp.ps1')\r\n")
    (film / "Hulp.ps1").write_bytes(b"function Hulp { }\r\n")
    set_script_policy(ScriptPolicy(pins={write.name.casefold(): _sha(write)}))
    started = _spy_popen(monkeypatch)
    with pytest.raises(ActionError, match="Hulp.ps1"):
        handelen_module.default_runner(script_command(write, ["-Actie", "x"]), 5)
    assert started == []


def test_sr5_the_collector_refuses_to_start_beside_an_unpinned_script(tmp_path, monkeypatch, restore_policy):
    from nsmcp.collect import CollectError, collect
    from nsmcp.powershell import ScriptPolicy, set_script_policy
    from nsmcp.target import CertAgreement, Target

    beheer = tmp_path / "beheer"
    beheer.mkdir()
    script = beheer / "verzamel.ps1"
    script.write_bytes(b". (Join-Path $PSScriptRoot 'Nitro.ps1')\r\n")
    (beheer / "Nitro.ps1").write_bytes(b"function Nitro { }\r\n")
    set_script_policy(ScriptPolicy(pins={"verzamel.ps1": _sha(script)}))
    started = _spy_popen(monkeypatch)
    target = Target(name="lab", address="192.0.2.10", credential_target="T/x", agreement=CertAgreement.CHAIN)
    with pytest.raises(CollectError) as refused:
        collect(target, tmp_path / "export", script)
    assert started == []
    message = str(refused.value)
    assert "Nitro.ps1" in message and "niet gestart" in message, message
    assert str(tmp_path) not in message, message


def test_sr5_the_pin_command_pins_every_script_in_a_directory(tmp_path, capsys):
    import json

    from nsmcp.powershell import main as pin_main

    main_script, sibling = _scripts(tmp_path)
    module = main_script.parent / "Helpers.psm1"
    module.write_bytes(b"function Help { }\r\n")
    (main_script.parent / "README.md").write_text("uitleg\n", encoding="ascii")
    assert pin_main(["--pin", str(main_script.parent)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == {
        "scriptpin": {
            "Helpers.psm1": _sha(module),
            "Transport.ps1": _sha(sibling),
            "Verzamel.ps1": _sha(main_script),
        }
    }
