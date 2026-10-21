"""Direct tests of GjkUpgrade-Ssh.ps1's own hostkey pin/detection functions -
NOT through the NEP-transport `tests/test_runner_script.py` uses for the
session and SFTP functions, but the REAL transport script itself, dot-sourced
and called directly.

These open a real Posh-SSH session and store, not just load the module:
`tests/test_runner_script.py` also needs Posh-SSH 3.2.7 physically present -
the runner's own `Assert-GjkPoshSsh` is real there too, never stubbed by the
NEP-transport - but its faked session and SFTP functions never call into
Posh-SSH itself. This file does, so it SKIPS (never fails) unless Posh-SSH is
installed at precisely 3.2.7, the same shape `test_runner_script.py` already
uses for `powershell.exe` itself.
"""

from __future__ import annotations

import functools
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
TRANSPORT = REPO / "scripts" / "GjkUpgrade-Ssh.ps1"

# A TEST-NET-3 address (RFC 5737): reserved for documentation, never a real
# host, and used nowhere else in this suite or product - a hostkey pin for
# it can never collide with a real target the operator's global known-hosts
# store already carries.
NIET_ROUTEERBAAR_ADRES = "203.0.113.55"


@functools.lru_cache(maxsize=1)
def _posh_ssh_available() -> bool:
    if shutil.which("powershell.exe") is None:
        return False
    try:
        r = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (Get-Module -ListAvailable -Name Posh-SSH | Where-Object { $_.Version -eq "
                "[version]'3.2.7' }) { 'JA' } else { 'NEE' }",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and "JA" in r.stdout


pytestmark = pytest.mark.skipif(
    not _posh_ssh_available(),
    reason="deze tests draaien alleen met het echte Posh-SSH-3.2.7-package geinstalleerd",
)


def _run_ps(body: str, timeout: int = 30) -> dict:
    script = f"Import-Module -Name Posh-SSH -RequiredVersion 3.2.7\n. '{TRANSPORT}'\n" + body
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    # The JSON is the last line. On an operator machine that has never
    # connected anywhere, ~/.poshssh/hosts.json does not exist and Posh-SSH's
    # Get-SSHTrustedHost writes "WARNING: No known host file found" on the
    # warning stream, which a captured stdout carries in front of the JSON
    # (measured on a fresh hosted runner). Only such warnings may precede it;
    # anything else is unexpected output and fails the test.
    lines = [line for line in r.stdout.splitlines() if line.strip()]
    assert lines, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    noise = [line for line in lines[:-1] if not line.startswith("WARNING:")]
    assert not noise, f"onverwachte uitvoer voor de JSON-regel: {noise!r}"
    return json.loads(lines[-1])


def test_key_exchange_negotiation_failed_is_recognized_as_a_hostkey_error():
    """C1: SSH.NET throws exactly this text when `-ErrorOnUntrusted` refuses
    an offered key (`CanTrust=false`) - the failure mode the padded-vs-
    unpadded fingerprint bug (this same finding) actually produced. Before
    this fix, `_GjkIsHostsleutelfout` matched none of its three strings for
    this message, so a real mismatch read as 'niet beoordeeld' instead of
    'poort dicht: hostsleutel wijkt af'."""
    uit = _run_ps(
        "$r1 = _GjkIsHostsleutelfout 'Key exchange negotiation failed.'\n"
        "$r2 = _GjkIsHostsleutelfout 'KEY EXCHANGE NEGOTIATION FAILED'\n"
        "[pscustomobject]@{ kex=$r1; kexUpper=$r2 } | ConvertTo-Json -Compress\n"
    )
    assert uit["kex"] is True
    assert uit["kexUpper"] is True


def test_a_plain_network_error_is_still_not_recognized():
    """The broadening this fix makes is deliberate and stated honestly in
    the script's own comment - not unbounded: a message that matches none
    of the four strings (untrusted/fingerprint/known host/key exchange
    negotiation failed) still reads as an ordinary connection failure."""
    uit = _run_ps(
        "$r = _GjkIsHostsleutelfout 'Connection timed out'\n[pscustomobject]@{ r=$r } | ConvertTo-Json -Compress\n"
    )
    assert uit["r"] is False


def test_the_unambiguous_detector_excludes_key_exchange_negotiation_failed():
    """`_GjkIsOndubbelzinnigeHostsleutelfout` is
    the same match as `_GjkIsHostsleutelfout` MINUS the one branch that is
    honestly documented as broader than strictly correct - 'key exchange
    negotiation failed' also fires for a pure algorithm-negotiation
    failure that has nothing to do with the host key. The other three
    stay recognized; only the ambiguous one does not."""
    uit = _run_ps(
        "$r1 = _GjkIsOndubbelzinnigeHostsleutelfout 'Key exchange negotiation failed.'\n"
        "$r2 = _GjkIsOndubbelzinnigeHostsleutelfout 'host key for 10.0.0.2 is untrusted'\n"
        "$r3 = _GjkIsOndubbelzinnigeHostsleutelfout 'fingerprint mismatch'\n"
        "$r4 = _GjkIsOndubbelzinnigeHostsleutelfout 'not a known host'\n"
        "$r5 = _GjkIsOndubbelzinnigeHostsleutelfout 'Connection timed out'\n"
        "[pscustomobject]@{ kex=$r1; untrusted=$r2; fingerprint=$r3; knownHost=$r4; plain=$r5 } "
        "| ConvertTo-Json -Compress\n"
    )
    assert uit["kex"] is False
    assert uit["untrusted"] is True
    assert uit["fingerprint"] is True
    assert uit["knownHost"] is True
    assert uit["plain"] is False


# ---------------------------------------------------------------------------
# H4: Wait-GjkTerug's own retry behaviour after a reboot (R4). A real TCP
# listener on 127.0.0.1:22 stands in for "port 22 is back" - Windows does
# not reserve that port to admins the way POSIX does, so a plain
# TcpListener.Start() is enough and needs nothing external. New-GjkSshSession
# and Invoke-GjkSsh are then overridden AFTER dot-sourcing the real script:
# PowerShell resolves a function call by name at CALL time, so a function
# redefined later in the same session shadows the real one for every
# caller in that session, including Wait-GjkTerug itself - no mocking
# framework needed.
# ---------------------------------------------------------------------------


def _run_ps_with_listening_port_22(body: str, timeout: int = 60) -> dict:
    omhulsel = (
        "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 22)\n"
        "$listener.Start()\n"
        "try {\n" + body + "\n} finally {\n"
        "    $listener.Stop()\n"
        "}\n"
    )
    return _run_ps(omhulsel, timeout=timeout)


def test_an_ambiguous_kex_failure_during_reboot_is_retried_not_reported_immediately():
    """H4. Before this fix, the FIRST 'key exchange negotiation failed' -
    exactly what SSH.NET also raises for a pure algorithm-negotiation
    failure while a rebooting appliance's sshd is still coming up - aborted
    the whole wait loop and reported a host-key mismatch. Two ambiguous
    failures followed by a real success must now still reach `ok = true`:
    the loop kept retrying instead of giving up on the first one."""
    uit = _run_ps_with_listening_port_22(
        "$global:pogingen = 0\n"
        "function New-GjkSshSession {\n"
        "    param($Adres, $Gebruiker, $CredentialTarget, $Vingerafdruk, [int] $TimeoutSec = 30)\n"
        "    $global:pogingen++\n"
        "    if ($global:pogingen -le 2) { throw 'Key exchange negotiation failed.' }\n"
        "    return [pscustomobject]@{ Nep = $true }\n"
        "}\n"
        "function Invoke-GjkSsh {\n"
        "    param($Sessie, $Commando, [int] $TimeoutSec = 30)\n"
        "    return [pscustomobject]@{ exitcode = 0; stdout = 'NetScaler NS14.1: Build 72.57.nc' }\n"
        "}\n"
        "$r = Wait-GjkTerug -Adres '127.0.0.1' -Gebruiker nsroot -CredentialTarget x "
        "-Vingerafdruk 'aa:bb' -TimeoutSec 30 -IntervalSec 1\n"
        "[pscustomobject]@{ ok = $r.ok; reden = $r.reden; pogingen = $global:pogingen } "
        "| ConvertTo-Json -Compress\n"
    )
    assert uit["ok"] is True
    assert uit["pogingen"] == 3


def test_an_unambiguous_hostkey_failure_during_reboot_still_stops_immediately():
    """H4's other half: the fix must not weaken the case it is NOT about.
    A message that unambiguously means a host-key mismatch still aborts on
    the very first attempt, exactly as before - proven by `pogingen == 1`,
    not just by the outcome."""
    uit = _run_ps_with_listening_port_22(
        "$global:pogingen = 0\n"
        "function New-GjkSshSession {\n"
        "    param($Adres, $Gebruiker, $CredentialTarget, $Vingerafdruk, [int] $TimeoutSec = 30)\n"
        "    $global:pogingen++\n"
        "    throw 'hostsleutel wijkt af: host key for 127.0.0.1 is untrusted'\n"
        "}\n"
        "function Invoke-GjkSsh { param($Sessie, $Commando, [int] $TimeoutSec = 30) }\n"
        "$r = Wait-GjkTerug -Adres '127.0.0.1' -Gebruiker nsroot -CredentialTarget x "
        "-Vingerafdruk 'aa:bb' -TimeoutSec 30 -IntervalSec 1\n"
        "[pscustomobject]@{ ok = $r.ok; reden = $r.reden; pogingen = $global:pogingen } "
        "| ConvertTo-Json -Compress\n"
    )
    assert uit["ok"] is False
    assert uit["pogingen"] == 1
    assert uit["reden"].startswith("hostsleutel wijkt af")


def test_a_kex_failure_that_never_clears_is_reported_as_a_hostkey_reason_at_the_deadline():
    """H4's own stated fix, second half: 'only report the host-key reason
    if it is still failing that way when the deadline expires'. The
    ambiguous message here persists for the WHOLE (short) auth deadline -
    proving both that the loop did not give up early (multiple attempts)
    and that it still ends by naming a host-key reason once genuinely
    exhausted, so `Invoke-GjkUpgradeFase.ps1`'s own
    `-like 'hostsleutel wijkt af*'` test keeps working."""
    uit = _run_ps_with_listening_port_22(
        "$global:pogingen = 0\n"
        "function New-GjkSshSession {\n"
        "    param($Adres, $Gebruiker, $CredentialTarget, $Vingerafdruk, [int] $TimeoutSec = 30)\n"
        "    $global:pogingen++\n"
        "    throw 'Key exchange negotiation failed.'\n"
        "}\n"
        "function Invoke-GjkSsh { param($Sessie, $Commando, [int] $TimeoutSec = 30) }\n"
        "$r = Wait-GjkTerug -Adres '127.0.0.1' -Gebruiker nsroot -CredentialTarget x "
        "-Vingerafdruk 'aa:bb' -TimeoutSec 3 -IntervalSec 1\n"
        "[pscustomobject]@{ ok = $r.ok; reden = $r.reden; pogingen = $global:pogingen } "
        "| ConvertTo-Json -Compress\n"
    )
    assert uit["ok"] is False
    assert uit["pogingen"] >= 2, "de lus moet meer dan een keer geprobeerd hebben"
    assert uit["reden"].startswith("hostsleutel wijkt af")
    assert "Key exchange negotiation failed" in uit["reden"]


def test_pinning_a_hostsleutel_no_longer_touches_the_operators_global_known_hosts_store():
    """C1: `_GjkPinHostsleutel` used to run Remove-SSHTrustedHost/
    New-SSHTrustedHost with NO `-KnownHostStore`, which write straight into
    the operator's GLOBAL known-hosts file (`~/.poshssh/hosts.json`) on
    EVERY connect. This proves the fixed version instead returns an
    in-memory store (`New-SSHMemoryKnownHost` + `-KnownHostStore`) that
    carries the pinned fingerprint, while the address stays entirely absent
    from the global store both before and after the call."""
    uit = _run_ps(
        f"$adres = '{NIET_ROUTEERBAAR_ADRES}'\n"
        "$voor = @(Get-SSHTrustedHost -HostName $adres -ErrorAction SilentlyContinue)\n"
        "$opslag = _GjkPinHostsleutel -Adres $adres -Vingerafdruk 'aa:bb:cc'\n"
        "$na = @(Get-SSHTrustedHost -HostName $adres -ErrorAction SilentlyContinue)\n"
        "$inGeheugen = Get-SSHTrustedHost -HostName $adres -KnownHostStore $opslag\n"
        "[pscustomobject]@{\n"
        "    voorAantal = $voor.Count\n"
        "    naAantal = $na.Count\n"
        "    inGeheugenFingerprint = $inGeheugen.Fingerprint\n"
        "    opslagType = $opslag.GetType().FullName\n"
        "} | ConvertTo-Json -Compress\n"
    )
    assert uit["voorAantal"] == 0
    assert uit["naAantal"] == 0
    assert uit["inGeheugenFingerprint"] == "aa:bb:cc"
    assert "MemoryStore" in uit["opslagType"]


def test_new_gjk_ssh_session_passes_the_pinned_store_as_knownhost_not_force():
    """Regression guard, plain text search of the script source rather than
    a live connection (`tests/test_runner_script.py` already covers the "no
    -Force/-AcceptKey anywhere" contract for both scripts together): the
    fixed `New-GjkSshSession`/`Copy-GjkFile` must call `New-SSHSession`/
    `New-SFTPSession` with `-KnownHost $opslag`, not the old bare
    `-ErrorOnUntrusted` against the (removed) global-store write."""
    tekst = TRANSPORT.read_text(encoding="ascii")
    assert "-KnownHost $opslag -ErrorOnUntrusted" in tekst
    assert "New-SSHMemoryKnownHost" in tekst
    assert "-KnownHostStore $opslag" in tekst


def test_the_appliance_banner_is_stripped_at_the_transport_boundary():
    """Measured on lab-02 (8-9-2026): every `shell` answer starts with
    'Warning: [' ... ']' and ' Done'. That vendor noise never reaches a gate."""
    uit = _run_ps(
        "$banner = 'Warning: [' + [char]10 + 'One or more RPC nodes are configured with default passwords.' + [char]10 + ']' + [char]10 + ' Done' + [char]10\n"
        "$r1 = _GjkZonderBanner ($banner + 'AFWEZIG' + [char]10)\n"
        "$r2 = _GjkZonderBanner ('geen banner' + [char]10 + 'tweede regel')\n"
        "$r3 = _GjkZonderBanner ('Warning: [' + [char]10 + 'zonder sluithaak')\n"
        "$r4 = _GjkZonderBanner $banner\n"
        # The MEASURED two-sentence banner (lab-02, 8-9-2026) - note 'default'
        # in the second sentence - and a DIFFERENT warning that is output.
        "$gemeten = 'Warning: [' + [char]10 + 'One or more RPC nodes are configured with default passwords. "
        "For enhanced security, you must change the default RPC node password.' + [char]10 + ']' + [char]10 + ' Done' + [char]10\n"
        "$r5 = _GjkZonderBanner ($gemeten + 'AFWEZIG' + [char]10)\n"
        "$r6 = _GjkZonderBanner ('Warning: [' + [char]10 + 'iets anders' + [char]10 + ']' + [char]10 + ' Done' + [char]10 + 'AFWEZIG')\n"
        "@{ r1 = $r1; r2 = $r2; r3 = $r3; r4 = $r4; r5 = $r5; r6 = $r6 } | ConvertTo-Json -Compress"
    )
    assert uit["r1"].strip() == "AFWEZIG"
    assert uit["r2"] == "geen banner\ntweede regel"
    assert uit["r3"].startswith("Warning: [")
    assert uit["r4"] == ""
    assert uit["r5"].strip() == "AFWEZIG"
    assert uit["r6"].startswith("Warning: [") and uit["r6"].endswith("AFWEZIG")


# ---------------------------------------------------------------------------
# The free-space measurement on /var lives in the transport, so the runner's
# R1 and the separate read script measure it the same way. Invoke-GjkSsh is
# overridden after dot-sourcing, the same technique as the reboot tests above.
# ---------------------------------------------------------------------------


def _free_space(stdout: str, exitcode: int = 0, stderr: str = "") -> dict:
    return _run_ps(
        "$global:gezien = @()\n"
        "function Invoke-GjkSsh {\n"
        "    param($Sessie, $Commando, [int] $TimeoutSec = 30)\n"
        "    $global:gezien += $Commando\n"
        f"    return [pscustomobject]@{{ exitcode = {exitcode}; stdout = {json.dumps(stdout)}; "
        f"stderr = {json.dumps(stderr)} }}\n"
        "}\n"
        "$r = Get-GjkVrijeRuimteVar -Sessie ([pscustomobject]@{ Nep = $true })\n"
        "[pscustomobject]@{ vrijMb = $r.vrijMb; exitcode = $r.exitcode; stderr = $r.stderr; "
        "regel = $r.regel; commando = ($global:gezien -join '|') } | ConvertTo-Json -Compress\n"
    )


def test_the_free_space_on_var_is_measured_by_the_transport():
    uit = _free_space("Filesystem  1K-blocks Used Avail Use% Mounted on`n/dev/md0s1a 10000000 100000 9000000 2% /var`n")
    assert uit["commando"] == "shell df -k /var"
    assert uit["vrijMb"] == 8789
    assert uit["exitcode"] == 0
    assert "/var" in uit["regel"]


@pytest.mark.parametrize(
    "stdout,exitcode",
    [
        ("Filesystem 1K-blocks Used Avail Use% Mounted on`n/dev/x 10000000 100000 9000000 2% /var", 1),
        ("Filesystem 1K-blocks Used Avail Use% Mounted on`n/dev/x 10000000 100000 9000000 2% /flash", 0),
        ("Filesystem 1K-blocks Used Avail Use% Mounted on`n/dev/x 10000000 100000 veel 2% /var", 0),
        ("", 0),
    ],
)
def test_an_unusable_df_answer_yields_no_number(stdout, exitcode):
    uit = _free_space(stdout, exitcode, "df: synthetische fout" if exitcode else "")
    assert uit["vrijMb"] is None
    assert uit["exitcode"] == exitcode
