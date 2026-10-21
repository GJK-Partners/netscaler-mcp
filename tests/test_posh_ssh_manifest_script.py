"""scripts/Get-GjkPoshSshManifest.ps1: the content check behind the Posh-SSH pin.

The transport pins the VERSION of Posh-SSH (`$vereist` in
scripts/GjkUpgrade-Ssh.ps1); this script checks the CONTENT of an installed
copy against a manifest measured over that version from the PowerShell
Gallery. CI runs it right after `Install-Module`. These tests drive the real
script under Windows PowerShell 5.1 against a synthetic module map, and
compute the expected manifest in Python by the method the script documents
- a second, independent implementation of the same rule.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import posh_ssh_pin

pytestmark = pytest.mark.skipif(
    shutil.which("powershell.exe") is None, reason="het script vraagt Windows PowerShell 5.1"
)

REPO = Path(__file__).parent.parent
SCRIPT = REPO / "scripts" / "Get-GjkPoshSshManifest.ps1"


def _manifest(base: Path) -> tuple[list[str], str]:
    """The documented method: every file except PSGetModuleInfo.xml in the
    map itself, sha256 per file, relative path with '/', ordinal order, one
    line '<sha256>  <path>' each ending in LF, and the sha256 over those
    lines as UTF-8."""
    paths = sorted(
        p.relative_to(base).as_posix()
        for p in base.rglob("*")
        if p.is_file() and p.relative_to(base).as_posix().lower() != "psgetmoduleinfo.xml"
    )
    lines = [f"{hashlib.sha256((base / rel).read_bytes()).hexdigest()}  {rel}" for rel in paths]
    return lines, hashlib.sha256("".join(line + "\n" for line in lines).encode("utf-8")).hexdigest()


def _module(tmp_path: Path) -> Path:
    base = tmp_path / "Posh-SSH" / "3.2.7"
    (base / "Assembly").mkdir(parents=True)
    (base / "en-US").mkdir()
    (base / "Posh-SSH.psd1").write_bytes(b"@{ ModuleVersion = '3.2.7' }\r\n")
    (base / "Posh-SSH.psm1").write_bytes(b"# module\r\n")
    (base / "Assembly" / "Renci.SshNet.dll").write_bytes(bytes(range(256)))
    (base / "en-US" / "Posh-SSH-help.xml").write_bytes(b"<helpItems/>")
    # Written by Install-Module per installation (path and time), hidden, and
    # the one file the manifest leaves out.
    info = base / "PSGetModuleInfo.xml"
    info.write_bytes(b"<Objs>installed here, now</Objs>")
    subprocess.run(["attrib", "+h", str(info)], check=True, capture_output=True)
    return base


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_the_script_is_ascii_and_parses_on_windows_powershell_5_1():
    SCRIPT.read_text(encoding="ascii")  # fails on any non-ASCII character
    out = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$fout = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile('{SCRIPT}', [ref]$null, [ref]$fout); "
            "if ($fout.Count -gt 0) { $fout | ForEach-Object { Write-Output $_.ToString() } } else { 'ok' }",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.stdout.strip() == "ok", out.stdout + out.stderr


def test_the_script_checks_the_version_the_transport_pins_against_one_measured_value():
    text = SCRIPT.read_text(encoding="ascii")
    assert re.findall(r"^\$versie = '([^']*)'$", text, re.MULTILINE) == [posh_ssh_pin()]
    assert len(re.findall(r"^\$gemeten = '[0-9a-f]{64}'$", text, re.MULTILINE)) == 1


def test_a_module_map_with_the_expected_manifest_passes_and_prints_every_line(tmp_path):
    base = _module(tmp_path)
    lines, value = _manifest(base)
    proc = _run("-Pad", str(base), "-Verwacht", value)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    printed = proc.stdout.splitlines()
    assert [line for line in printed if re.match(r"^[0-9a-f]{64}  ", line)] == lines
    assert f"[MANIFEST] {value}" in printed
    assert any(line.startswith("[OK] manifest gelijk aan de gemeten waarde voor Posh-SSH 3.2.7") for line in printed)
    assert "[EINDSTATUS] GELIJK (1)" in printed
    assert "PSGetModuleInfo.xml  " not in proc.stdout and "4 bestanden" in proc.stdout


def test_one_changed_byte_fails_with_exit_1_and_the_full_list_in_the_output(tmp_path):
    base = _module(tmp_path)
    _, value = _manifest(base)
    (base / "Assembly" / "Renci.SshNet.dll").write_bytes(bytes(range(255)) + b"\x00")
    lines, changed = _manifest(base)
    proc = _run("-Pad", str(base), "-Verwacht", value)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert [line for line in proc.stdout.splitlines() if re.match(r"^[0-9a-f]{64}  ", line)] == lines
    refusal = f"[FOUT] manifest wijkt af van de gemeten waarde voor Posh-SSH 3.2.7: verwacht {value}, gemeten {changed}"
    assert refusal in proc.stdout
    assert "[EINDSTATUS] AFWIJKEND (1 van 1)" in proc.stdout


def test_an_added_file_counts_also_when_hidden_and_psgetmoduleinfo_does_not(tmp_path):
    base = _module(tmp_path)
    _, value = _manifest(base)
    (base / "PSGetModuleInfo.xml").unlink()
    (base / "PSGetModuleInfo.xml").write_bytes(b"<Objs>installed elsewhere, later</Objs>")
    assert _run("-Pad", str(base), "-Verwacht", value).returncode == 0
    extra = base / "Assembly" / "extra.dll"
    extra.write_bytes(b"MZ")
    subprocess.run(["attrib", "+h", str(extra)], check=True, capture_output=True)
    proc = _run("-Pad", str(base), "-Verwacht", value)
    assert proc.returncode == 1, proc.stdout
    assert "  Assembly/extra.dll" in proc.stdout
    # Only the one in the module map itself is left out; a file of that name
    # deeper down is content like any other.
    extra.unlink()
    (base / "en-US" / "PSGetModuleInfo.xml").write_bytes(b"<Objs/>")
    assert _run("-Pad", str(base), "-Verwacht", value).returncode == 1


def test_the_order_is_ordinal_whatever_the_culture(tmp_path):
    base = _module(tmp_path)
    for name in ("a.txt", "B.txt", "_x.txt"):
        (base / name).write_bytes(name.encode("ascii"))
    lines, value = _manifest(base)
    proc = _run("-Pad", str(base), "-Verwacht", value)
    assert proc.returncode == 0, proc.stdout
    top = [line.split("  ", 1)[1] for line in lines if "/" not in line.split("  ", 1)[1]]
    assert top.index("B.txt") < top.index("_x.txt") < top.index("a.txt")


def test_a_missing_map_or_a_malformed_expected_value_is_exit_3(tmp_path):
    missing = _run("-Pad", str(tmp_path / "nergens"))
    assert missing.returncode == 3 and "[FOUT] modulemap niet gevonden" in missing.stdout
    base = _module(tmp_path)
    malformed = _run("-Pad", str(base), "-Verwacht", "ABC")
    assert malformed.returncode == 3 and "[FOUT] -Verwacht is geen sha256-waarde" in malformed.stdout
