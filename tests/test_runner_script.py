"""Het runnerscript, gedreven met een NEP-transport.

Deze tests draaien alleen waar `powershell.exe` bestaat. Dat is bewust en het
is geen gat: elke POORTUITSPRAAK wordt in `tests/test_upgrade.py` (en de
scriptonafhankelijke vormlaag in `tests/test_upgrade_measure.py`) getest, en
die draaien overal. Wat hier getest wordt is het SCRIPT: dat het de etiketten
afdrukt, dat het de metingen goed doorgeeft, dat het bij -WatIs geen sessie
opent, en dat het op een afwijkende hostsleutel stopt.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import posh_ssh_pin

from nsmcp.upgrade import append_line

pytestmark = pytest.mark.skipif(
    shutil.which("powershell.exe") is None, reason="het runnerscript vraagt Windows PowerShell 5.1"
)

REPO = Path(__file__).parent.parent
SCRIPT = REPO / "scripts" / "Invoke-GjkUpgradeFase.ps1"
TRANSPORT_ECHT = REPO / "scripts" / "GjkUpgrade-Ssh.ps1"
TRANSPORT_NEP = Path(__file__).parent / "fixtures" / "runner" / "GjkUpgrade-NepTransport.ps1"
TRANSPORT_KAPOT = Path(__file__).parent / "fixtures" / "runner" / "GjkUpgrade-NepTransportKapot.ps1"
# Dezelfde synthetische, hash-geverifieerde export als tests/test_preflight.py
# gebruikt - R0's export-gebonden poorten lezen exact dezelfde
# bronnen als check 9 daar.
EXPORT_FIXTURE = Path(__file__).parent / "fixtures" / "preflight-export"
# De export die R0's voormeting ECHT oplevert - de acht
# families, de backup, de buildboom en een hash-geverifieerde running config.
# `preflight-export` draagt geen enkele familie en levert dus, terecht, een
# `niet beoordeeld` op de familietellingen.
R0_EXPORT_FIXTURE = Path(__file__).parent / "fixtures" / "r0-export"

GOEDE_VINGERAFDRUK = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
KAPOT_VERBINDING_SENTINEL = "KAPOT-VERBINDING"


# Sinds een latere fix meet R1 de firmwarehash OP DE
# DOOS ('shell sha256 -q ...'), nooit meer de lokale bytehash van de bundel -
# een afgebroken/beschadigde SFTP-overzet mag niet langer ongemerkt door de
# hashpoort komen. De NEP-transport (GjkUpgrade-NepTransport.ps1) antwoordt
# op die SSH-opdracht met deze letterlijke waarde, dus de vendorwaarde hier
# moet DEZELFDE waarde dragen wil het gelukkige pad 'open' blijven zien.
NEP_DOOS_SHA = "1997e2585c3ea0e412f90b343c4e9d90f1f96d02f54cdbe9a024fb5c89e4fb22"


def _firmwaremap(tmp_path: Path, *, extra_bestanden: dict[str, bytes] | None = None) -> Path:
    """Een minimale firmwaremap: de bundel EN zijn .sha256 met de vendorwaarde
    erin - zonder dat bestand is R1 'dicht' (zie docs/klant/HANDLEIDING.md).

    `extra_bestanden`: optionele extra .tgz-stand-ins in dezelfde map (een
    andere build, een stray bestand) - om te bewijzen dat de bundelselectie
    (finding C2) de EXACTE verwachte naam kiest en nooit een eerste treffer
    op een willekeurige sortering van de map."""
    map_ = tmp_path / "firmware"
    map_.mkdir(exist_ok=True)
    bundel = map_ / "build-14.1-72.57_nc_64.tgz"
    bundel.write_bytes(b"nep-bundel-inhoud")
    (map_ / (bundel.name + ".sha256")).write_text(NEP_DOOS_SHA + "  " + bundel.name + "\n", encoding="ascii")
    if extra_bestanden:
        for naam, inhoud in extra_bestanden.items():
            (map_ / naam).write_bytes(inhoud)
    return map_


def _run(
    tmp_path: Path,
    fase: str,
    *,
    watis: bool = False,
    vingerafdruk: str = GOEDE_VINGERAFDRUK,
    oude_buildbomen_opruimen: bool = False,
    ledger: Path | None = None,
    markerdir: Path | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 60,
    adres: str = "127.0.0.1",
    doel: str = "lab-02-test",
    doelbuild: str = "72.57",
    transport: Path = TRANSPORT_NEP,
    actieregister: Path | None = None,
    export_root: Path | None = None,
    actieid: str | None = None,
    firmwaremap: Path | None = None,
    extra_env: dict[str, str] | None = None,
    seed_previous: bool = False,
    shell: str = "powershell.exe",
    run: str = "test-run-1",
    bevestiger: str = "u-test",
) -> subprocess.CompletedProcess:
    ledger = ledger or (tmp_path / "ledger.jsonl")
    firmwaremap_pad = firmwaremap if firmwaremap is not None else _firmwaremap(tmp_path)
    if seed_previous and not watis:
        previous = "R" + str(int(fase[1:]) - 1)
        append_line(
            ledger,
            {
                "run": "test-run-1",
                "doel": doel,
                "fase": previous,
                "gebeurtenis": "voormeting_vast" if previous == "R0" else "fase_geslaagd",
                "uitkomst": "geslaagd",
            },
        )
    argumenten = [
        shell,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCRIPT),
        "-Doel",
        doel,
        "-Adres",
        adres,
        "-Fase",
        fase,
        "-Run",
        run,
        "-Gebruiker",
        "gjktestgebruiker",
        "-CredentialTarget",
        "GJK/Test/upgrade-runner",
        "-HostsleutelVingerafdruk",
        vingerafdruk,
        "-Doelbuild",
        doelbuild,
        "-Firmwaremap",
        str(firmwaremap_pad),
        "-Ledger",
        str(ledger),
        "-GatePython",
        sys.executable,
        "-Actieid",
        ("upgrade-" + fase + "-20260907-000000") if actieid is None else actieid,
        "-Bevestiger",
        bevestiger,
        "-Transport",
        str(transport),
    ]
    if actieregister is not None:
        argumenten += ["-Actieregister", str(actieregister)]
    if export_root is not None:
        argumenten += ["-ExportRoot", str(export_root)]
    if watis:
        argumenten.append("-WatIs")
    if oude_buildbomen_opruimen:
        argumenten.append("-OudeBuildbomenOpruimen")
    if extra_args:
        argumenten += extra_args
    env = None
    if markerdir is not None or extra_env:
        import os

        env = dict(os.environ)
        if markerdir is not None:
            env["GJK_TEST_MARKERDIR"] = str(markerdir)
        if extra_env:
            env.update(extra_env)
    return subprocess.run(argumenten, capture_output=True, text=True, timeout=timeout, cwd=str(REPO), env=env)


def _actieregister(tmp_path: Path, *rijen: dict) -> Path:
    """Een minimale, echte actieregisterregel per rij - hetzelfde JSONL-
    formaat als het ledger (een JSON-object per regel), zie
    `nsmcp.upgrade.backup_register_gate`."""
    pad = tmp_path / "actieregister.jsonl"
    pad.write_text("\n".join(json.dumps(r) for r in rijen) + "\n", encoding="utf-8")
    return pad


# ---------------------------------------------------------------------------
# -WatIs: beide etiketten, geen sessie
# ---------------------------------------------------------------------------


def test_the_preview_prints_both_labels_and_opens_no_session(tmp_path):
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R1", watis=True, markerdir=markers)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[TARGET]" in proc.stdout
    assert "[ACTIEID]" in proc.stdout
    # -WatIs eindigt niet met [EINDSTATUS] (dat kanaal draagt
    # uitsluitend de vijf fase-uitkomstwoorden van ontwerp 2.1.1) - een eigen
    # [VOORVERTONING]-regel in plaats daarvan.
    assert "[VOORVERTONING]" in proc.stdout
    assert "[EINDSTATUS]" not in proc.stdout
    assert not markers.exists() or not any(markers.iterdir()), (
        f"-WatIs raakte het transport aan: {list(markers.iterdir()) if markers.exists() else []}"
    )


def test_watis_never_touches_the_ledger(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R2", watis=True, ledger=ledger)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not ledger.exists()


# ---------------------------------------------------------------------------
# Het [TARGET]-etiket
# ---------------------------------------------------------------------------


def test_the_target_label_names_box_address_phase_and_target_build(tmp_path):
    proc = _run(tmp_path, "R3", watis=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    regel = next(line for line in proc.stdout.splitlines() if line.startswith("[TARGET]"))
    assert regel == "[TARGET] lab-02-test (127.0.0.1) - fase R3 naar build 72.57"


def test_the_actieid_label_has_the_pinned_shape(tmp_path):
    proc = _run(tmp_path, "R0", watis=True)
    regel = next(line for line in proc.stdout.splitlines() if line.startswith("[ACTIEID]"))
    assert regel == "[ACTIEID] upgrade-R0-20260907-000000"


def test_the_cleanup_argument_appears_in_the_target_label(tmp_path):
    proc_met = _run(tmp_path, "R1", watis=True, oude_buildbomen_opruimen=True)
    regel_met = next(line for line in proc_met.stdout.splitlines() if line.startswith("[TARGET]"))
    assert regel_met.endswith(", oude buildbomen opruimen")

    proc_zonder = _run(tmp_path, "R1", watis=True, oude_buildbomen_opruimen=False)
    regel_zonder = next(line for line in proc_zonder.stdout.splitlines() if line.startswith("[TARGET]"))
    assert "oude buildbomen opruimen" not in regel_zonder


# ---------------------------------------------------------------------------
# MUTATIEPROEF 9, scriptkant
# ---------------------------------------------------------------------------


def test_a_differing_host_key_stops_the_phase_before_any_command(tmp_path):
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        "R1",
        vingerafdruk="00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        ledger=ledger,
        markerdir=markers,
    )
    # De etiketten staan er nog (die hangen aan de fase, niet aan de sessie),
    # maar er ging NOOIT een commando naar "de appliance".
    assert not (markers / "ssh-commando.txt").exists()
    assert not (markers / "sftp-upload.txt").exists()
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ledger.exists()
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    assert sluitregel["uitkomst"] == "poort dicht"
    poortnamen_en_redenen = [(p["naam"], p["reden"]) for p in sluitregel["poort"]]
    assert any(reden == "hostsleutel wijkt af" for _, reden in poortnamen_en_redenen), poortnamen_en_redenen


def test_a_differing_host_key_still_gets_exactly_one_fase_gestart_row(tmp_path):
    """De ledgerregel 'fase_gestart' hoort er nog steeds te staan: de fase IS
    gestart, alleen de sessie kon niet met de gepinde sleutel worden geopend."""
    ledger = tmp_path / "ledger.jsonl"
    _run(tmp_path, "R1", vingerafdruk="00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", ledger=ledger)
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    gestart_regels = [r for r in regels if r.get("gebeurtenis") == "fase_gestart"]
    assert len(gestart_regels) == 1


def test_the_fase_gestart_row_records_the_target_build_of_this_phase(tmp_path):
    """De runbinding van R1..R6 vergelijkt de huidige bundel met de doelbuild
    waarmee R0 van dezelfde run startte; die staat in de fase_gestart-regel."""
    ledger = tmp_path / "ledger.jsonl"
    _run(tmp_path, "R0", ledger=ledger, doelbuild="14.1-72.57")
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    (start,) = [r for r in regels if r.get("gebeurtenis") == "fase_gestart"]
    assert start["doelbuild"] == "14.1-72.57"


# ---------------------------------------------------------------------------
# Nooit -AcceptKey, nooit StrictHostKeyChecking
# ---------------------------------------------------------------------------


def test_the_script_never_passes_accept_key_or_disables_host_key_checking():
    bron = SCRIPT.read_text(encoding="ascii")
    bron += TRANSPORT_ECHT.read_text(encoding="ascii")
    for verboden in ("-AcceptKey", "StrictHostKeyChecking", "accept-new"):
        assert verboden not in bron, verboden


def test_new_session_calls_never_carry_force_which_disables_host_key_validation_entirely():
    """Posh-SSH's eigen -Force op New-SSHSession/New-SFTPSession ('Do not
    perform any host key validation of the host') is even gevaarlijk als de
    optie die een nieuwe sleutel automatisch vertrouwt, en staat niet met
    opzet in de taakopdracht genoemd - deze test pint hem toch, om dezelfde
    reden. Set-SFTPItem's EIGEN -Force ('overwrite item on remote host') is
    een ander, onschuldig ding en blijft toegestaan - dus dit test regelniveau,
    niet de kale string."""
    for regel in TRANSPORT_ECHT.read_text(encoding="ascii").splitlines():
        if "New-SSHSession" in regel or "New-SFTPSession" in regel:
            assert "-Force" not in regel, regel


# ---------------------------------------------------------------------------
# ASCII + 5.1-parseerbaarheid
# ---------------------------------------------------------------------------


def test_both_scripts_are_ascii_and_parse_on_windows_powershell_5_1():
    for pad in ("scripts/GjkUpgrade-Ssh.ps1", "scripts/Invoke-GjkUpgradeFase.ps1"):
        (REPO / pad).read_text(encoding="ascii")  # valt om op elk niet-ASCII teken
        uit = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$fout = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile('{pad}', [ref]$null, [ref]$fout); "
                "if ($fout.Count -gt 0) { $fout | ForEach-Object { Write-Output $_.ToString() } } else { 'ok' }",
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(REPO),
        )
        assert "ok" in uit.stdout, uit.stdout + uit.stderr


# ---------------------------------------------------------------------------
# Posh-SSH: precies de versie waartegen de hostsleutelpin gemeten is. Het
# transport laadde de module op naam, dus de eerste of hoogste versie in het
# modulepad - en liet een al geladen module van elke versie door.
#
# De NEP-transport (GjkUpgrade-NepTransport.ps1) laat Assert-GjkPoshSsh
# ongemoeid: die komt hier, net als op de echte doos, uit de echte
# GjkUpgrade-Ssh.ps1 en vraagt Posh-SSH 3.2.7 echt geinstalleerd. Alleen de
# sessie- en SFTP-functies erna zijn nep, dus deze tests openen zelf geen
# echte SSH-sessie - dat verschil, niet de aanwezigheid van Posh-SSH, is wat
# `tests/test_ssh_transport_pins.py` apart houdt.
# ---------------------------------------------------------------------------

_NEP_POSH_SSH_VERSIE = "9.9.9"


def _nep_posh_ssh_module(tmp_path: Path) -> Path:
    """A module named Posh-SSH of another version, exporting nothing."""
    root = tmp_path / "nep-modules"
    map_ = root / "Posh-SSH" / _NEP_POSH_SSH_VERSIE
    map_.mkdir(parents=True)
    (map_ / "Posh-SSH.psd1").write_text(
        "@{ RootModule = 'Posh-SSH.psm1'; ModuleVersion = '"
        + _NEP_POSH_SSH_VERSIE
        + "'; GUID = '00000000-0000-4000-8000-000000000001'; FunctionsToExport = @() }\n",
        encoding="ascii",
    )
    (map_ / "Posh-SSH.psm1").write_text("# nep-module: exporteert niets\n", encoding="ascii")
    return root


def _transport_command(body: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            f". '{TRANSPORT_ECHT}'\n" + body,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO),
    )


def test_the_transport_loads_only_the_pinned_posh_ssh_even_when_another_version_comes_first(tmp_path):
    modules = _nep_posh_ssh_module(tmp_path)
    proc = _transport_command(
        f"$env:PSModulePath = '{modules};' + $env:PSModulePath\n"
        "Assert-GjkPoshSsh\n"
        "Write-Host ('GELADEN ' + ((Get-Module -Name Posh-SSH | ForEach-Object { $_.Version.ToString() }) -join ','))\n"
    )
    assert f"GELADEN {posh_ssh_pin()}" in proc.stdout, proc.stdout + proc.stderr
    assert _NEP_POSH_SSH_VERSIE not in proc.stdout


def test_the_transport_refuses_a_posh_ssh_of_another_version_that_is_already_loaded(tmp_path):
    modules = _nep_posh_ssh_module(tmp_path)
    psd1 = modules / "Posh-SSH" / _NEP_POSH_SSH_VERSIE / "Posh-SSH.psd1"
    proc = _transport_command(f"Import-Module -Name '{psd1}'\nAssert-GjkPoshSsh\nWrite-Host 'DOORGELATEN'\n")
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "[FOUT]" in proc.stdout and posh_ssh_pin() in proc.stdout
    assert "DOORGELATEN" not in proc.stdout


def _nep_posh_ssh_327(tmp_path: Path) -> Path:
    """A module named Posh-SSH with the PINNED version, but other content:
    the case the version pin cannot see (1.0.2)."""
    root = tmp_path / "nep-327"
    map_ = root / "Posh-SSH" / posh_ssh_pin()
    map_.mkdir(parents=True)
    (map_ / "Posh-SSH.psd1").write_text(
        "@{ RootModule = 'Posh-SSH.psm1'; ModuleVersion = '"
        + posh_ssh_pin()
        + "'; GUID = '00000000-0000-4000-8000-000000000002'; FunctionsToExport = @() }\n",
        encoding="ascii",
    )
    (map_ / "Posh-SSH.psm1").write_text("# nep-module met de gepinde versie, andere inhoud\n", encoding="ascii")
    return root


def test_sr6_a_posh_ssh_of_the_pinned_version_with_other_content_is_refused(tmp_path):
    modules = _nep_posh_ssh_327(tmp_path)
    proc = _transport_command(
        f"$env:PSModulePath = '{modules};' + $env:PSModulePath\nAssert-GjkPoshSsh\nWrite-Host 'DOORGELATEN'\n"
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "[FOUT]" in proc.stdout and "manifest" in proc.stdout, proc.stdout
    assert "DOORGELATEN" not in proc.stdout
    assert str(tmp_path) not in proc.stdout


def test_sr6_an_already_loaded_posh_ssh_of_the_pinned_version_with_other_content_is_refused(tmp_path):
    psd1 = _nep_posh_ssh_327(tmp_path) / "Posh-SSH" / posh_ssh_pin() / "Posh-SSH.psd1"
    proc = _transport_command(f"Import-Module -Name '{psd1}'\nAssert-GjkPoshSsh\nWrite-Host 'DOORGELATEN'\n")
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "manifest" in proc.stdout, proc.stdout
    assert "DOORGELATEN" not in proc.stdout


def test_sr6_the_transport_and_the_manifest_script_carry_the_same_measured_value():
    manifest = (REPO / "scripts" / "Get-GjkPoshSshManifest.ps1").read_text(encoding="ascii")
    transport = TRANSPORT_ECHT.read_text(encoding="ascii")
    gemeten = re.search(r"\$gemeten = '([0-9a-f]{64})'", manifest).group(1)
    assert f"$script:GjkPoshSshManifestGemeten = '{gemeten}'" in transport


def test_every_posh_ssh_import_in_the_transport_names_the_exact_version():
    bron = TRANSPORT_ECHT.read_text(encoding="ascii")
    imports = [regel for regel in bron.splitlines() if "Import-Module" in regel and "Posh-SSH" in regel]
    assert imports
    for regel in imports:
        assert "-RequiredVersion" in regel, regel
    # The version itself is read from this same line by `posh_ssh_pin()`
    # (tests/conftest.py); the documents are held to it in
    # tests/test_docs_claims.py.
    assert f"$vereist = '{posh_ssh_pin()}'" in bron


# ---------------------------------------------------------------------------
# Geen secret ooit op stdout of in het ledger - scriptkant
# ---------------------------------------------------------------------------


def test_no_secret_ever_reaches_stdout_or_the_ledger(tmp_path):
    """MUTATIEPROEF-achtige controle op de invariant: alleen targetnamen.
    De NEP-transport geeft een HERKENBAAR testwachtwoord terug uit
    Get-GjkCredential; dit bewijst dat het nergens in stdout of het ledger
    belandt, voor een fase die de credential ook echt gebruikt (R1: opent een
    sessie EN doet een SFTP-upload)."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R1", ledger=ledger)
    geheim = "TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a"
    assert geheim not in proc.stdout
    assert geheim not in proc.stderr
    if ledger.exists():
        assert geheim not in ledger.read_text(encoding="utf-8")
    # `... or True` maakte deze regel onvoorwaardelijk waar -
    # een assertie die niet kan falen. De targetnaam is toegestaan om te
    # verschijnen (het is geen geheim), maar verschijnt vandaag NERGENS in
    # stdout - dit is dus een echte, op dit moment waargebeurde bewering, en
    # een regressie (de naam onbedoeld op een vreemde plek printen) valt hier
    # nu echt op, ook al is dat op zichzelf geen geheimlek.
    assert "GJK/Test/upgrade-runner" not in proc.stdout


def test_no_secret_reaches_the_ledger_even_on_a_host_key_mismatch(tmp_path):
    """Dezelfde controle op het pad waarin New-GjkSshSession faalt VOORDAT er
    iets gedaan wordt - Get-GjkCredential is dan al aangeroepen (nodig om de
    PSCredential te bouwen), dus dit is niet triviaal waar."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        "R1",
        vingerafdruk="00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        ledger=ledger,
    )
    geheim = "TOPSECRET-MOET-NOOIT-LEKKEN-9f8e7d6c3b2a"
    assert geheim not in proc.stdout
    assert geheim not in proc.stderr
    if ledger.exists():
        assert geheim not in ledger.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Een volledige, geslaagde fase-aanroep (R6 - de eenvoudigste: meet en doet
# niets op de appliance) - bewijst dat de hele keten (start-markering, vorm,
# oordeel) echt aan elkaar hangt.
# ---------------------------------------------------------------------------


def test_a_full_phase_run_closes_with_a_real_verdict_from_the_judging_half(tmp_path):
    """`proc.returncode in (0, 1, 2)` accepted every
    documented exit code and tested nothing. On a FRESH ledger R6's own
    predecessor (R5) never ran, so `order_gate` is deterministically
    'dicht' and this run closes as 'poort dicht' (exitcode 1) - pinned
    exactly, not accepted as a range."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R6", ledger=ledger)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ledger.exists()
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert regels[0]["gebeurtenis"] == "fase_gestart"
    assert regels[-1]["fase"] == "R6"
    assert regels[-1]["uitkomst"] == "poort dicht"
    poortnamen = [p["naam"] for p in regels[-1]["poort"]]
    assert "R5 gesloten" in poortnamen
    assert "[EINDSTATUS]" in proc.stdout


def test_the_eindstatus_channel_after_a_normal_run_carries_only_the_pinned_vocabulary(tmp_path):
    """Sluitstuk: [EINDSTATUS] draagt na een normale
    beoordeelde run uitsluitend een van de vijf woorden van ontwerp 2.1.1 -
    nooit GEWEIGERD/WAT-IS (die staan op hun eigen kanaal, zie hierboven)."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R6", ledger=ledger)
    eindstatusregel = next(line for line in proc.stdout.splitlines() if line.startswith("[EINDSTATUS]"))
    assert any(
        woord in eindstatusregel for woord in ("gestart", "poort dicht", "geslaagd", "mislukt", "niet beoordeeld")
    )
    assert "GEWEIGERD" not in eindstatusregel
    assert "WAT-IS" not in eindstatusregel


def test_r6_closes_geslaagd_end_to_end_once_r5_already_closed(tmp_path):
    """Both R6 tests above prove `poort
    dicht` on a FRESH ledger - `order_gate` fires before `REQUIRED_GATES`
    ever gets a chance to matter, so R6's own required-gate set (just
    `hostsleutel gepind`) is exercised only at `evaluate_phase()`'s unit
    level, never end to end through the real runner script and the real
    judging half together. This is the missing other half: with R5 already
    closed `geslaagd` in the SAME run's ledger (so `order_gate` opens) and
    a valid pinned hostkey (the NEP-transport's default fingerprint, which
    `_run()` already uses unless told otherwise), a real R6 call closes
    `geslaagd`."""
    ledger = tmp_path / "ledger.jsonl"
    nu = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    append_line(
        ledger,
        {
            "tijd": nu,
            "run": "test-run-1",
            "doel": "lab-02-test",
            "fase": "R5",
            "gebeurtenis": "fase_geslaagd",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "test-fixture: R5 al gesloten",
            "actieid": "upgrade-R5-20260907-000000",
            "bevestiger": "u-test",
            "gestart": nu,
            "geeindigd": nu,
        },
    )
    proc = _run(tmp_path, "R6", ledger=ledger)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    assert sluitregel["fase"] == "R6"
    assert sluitregel["uitkomst"] == "geslaagd", sluitregel
    assert sluitregel["gebeurtenis"] == "soak_open"
    eindstatusregel = next(line for line in proc.stdout.splitlines() if line.startswith("[EINDSTATUS]"))
    assert "geslaagd" in eindstatusregel


def test_r1_measurements_reach_the_ledger_as_shaped_gates(tmp_path):
    """R1 meet schijfruimte, HA-rol en firmware-hash; deze test bewijst dat die
    metingen ECHT als poorten in het ledger belanden (via upgrade_measure),
    niet alleen dat het script draait."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], ledger=ledger)
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    namen = {p["naam"] for p in sluitregel["poort"]}
    assert "vrije ruimte op /var" in namen
    assert "doel is secondary" in namen
    assert "firmware-hash" in namen
    # De nep-firmwaremap draagt een kloppend .sha256, dus de hashpoort staat open.
    hash_poort = next(p for p in sluitregel["poort"] if p["naam"] == "firmware-hash")
    assert hash_poort["uitkomst"] == "open"
    # Het script geeft -Adres nu mee als
    # doel_adres, en de 'IP:' die de nep-transport meldt komt overeen met
    # het standaard testadres (127.0.0.1) - de poort staat dus ECHT open,
    # niet toevallig 'niet beoordeeld' geworden door de nieuwe identiteitstoets.
    secondary_poort = next(p for p in sluitregel["poort"] if p["naam"] == "doel is secondary")
    assert secondary_poort["uitkomst"] == "open", secondary_poort


def test_the_secondary_gate_is_not_assessed_when_the_target_address_does_not_match(tmp_path):
    """C3: -Adres gaat mee als doel_adres naar secondary_gate(). Draait de
    fase tegen een adres dat niet overeenkomt met de 'IP:' in de gemeten
    'show ha node'-uitvoer (hier altijd 127.0.0.1, zie de nep-transport),
    dan is de identiteit van Node ID 0 niet aantoonbaar vastgesteld - 'niet
    beoordeeld', nooit een gok op 'open' of 'dicht'."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R1", ledger=ledger, adres="10.99.99.99")
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    secondary_poort = next(p for p in sluitregel["poort"] if p["naam"] == "doel is secondary")
    assert secondary_poort["uitkomst"] == "niet beoordeeld", secondary_poort


# ---------------------------------------------------------------------------
# De hashpoort meet de doos, niet het lokale
# bestand, en de bundelselectie kiest de EXACTE naam, nooit een eerste
# treffer.
# ---------------------------------------------------------------------------


def test_the_firmware_hash_gate_closes_on_a_box_measurement_that_differs_from_the_vendor_value(tmp_path):
    """C2, de bevinding zelf: een afgebroken/beschadigde SFTP-overzet mag
    niet ongemerkt door de hashpoort komen. GJK_TEST_DOOS_SHA laat de
    NEP-transport een AFWIJKENDE 'op de doos gemeten' waarde teruggeven,
    terwijl het LOKALE bestand en de vendorwaarde ongewijzigd blijven - voor
    deze fix bepaalde de LOKALE bytehash de uitkomst (altijd gelijk aan
    zichzelf), dus deze afwijking op de doos werd nooit gezien."""
    ledger = tmp_path / "ledger.jsonl"
    andere_doos_sha = "11" * 32
    assert andere_doos_sha != NEP_DOOS_SHA
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        ledger=ledger,
        extra_env={"GJK_TEST_DOOS_SHA": andere_doos_sha},
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    hash_poort = next(p for p in sluitregel["poort"] if p["naam"] == "firmware-hash")
    assert hash_poort["uitkomst"] == "dicht", hash_poort
    assert "verschillen" in hash_poort["bewijs"], hash_poort


@pytest.mark.parametrize("long_path", [False, True], ids=["short-path", "long-path"])
def test_the_local_hash_is_recorded_under_its_own_gate_never_as_firmware_hash(tmp_path, long_path):
    """C2: 'de lokale hash blijft bestaan, maar onder een apart benoemde
    poort - nooit meer voor firmware-hash zelf'. Bewijst dat beide poorten
    ECHT gescheiden zijn: de informatieve poort draagt de lokale sha256 van
    de nep-bundelinhoud, en firmware-hash draagt daar NOOIT die waarde in -
    zijn eigen bewijstekst gaat over de vendorvergelijking."""
    import hashlib

    ledger = tmp_path / "ledger.jsonl"
    firmware_root = tmp_path
    if long_path:
        firmware_root = tmp_path / ("long-firmware-directory-" + "x" * 20)
        firmware_root.mkdir()
    firmwaremap = _firmwaremap(firmware_root)
    proc = _run(
        tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], ledger=ledger, firmwaremap=firmwaremap
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    poorten = {p["naam"]: p for p in sluitregel["poort"]}
    lokale_sha = hashlib.sha256(b"nep-bundel-inhoud").hexdigest()
    assert "lokale bundel-sha256 (informatief)" in poorten
    lokale_poort = poorten["lokale bundel-sha256 (informatief)"]
    assert lokale_poort["uitkomst"] == "open"
    assert lokale_sha in lokale_poort["bewijs"]
    assert lokale_poort["bewijs"].startswith("lokaal sha256 " + lokale_sha)
    assert lokale_sha not in poorten["firmware-hash"]["bewijs"]


# ---------------------------------------------------------------------------
# Design row A4: een hertest van R1 uploadde de bundel altijd opnieuw,
# ook als een vorige poging hem al met de juiste hash op de doos had staan -
# een hertest vereiste dan handmatig opruimen van de buildboom.
# ---------------------------------------------------------------------------


def test_r1_skips_the_upload_when_the_bundle_is_already_present_with_the_same_sha(tmp_path):
    """Staat de bundel al op het doelpad EN klopt de SHA-256 op de doos met
    de vendor-SHA (dezelfde hashpoort R1 al heeft: de NEP-transport
    antwoordt op 'sha256 -q ...' standaard al met NEP_DOOS_SHA, gelijk aan
    de vendorwaarde die _firmwaremap() wegschrijft), dan slaat R1 de upload
    over - geen upload-commando in het transportlog, poort open met dat
    bewijs."""
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    env = _responses(tmp_path, {"match": "echo AANWEZIG", "stdout": "AANWEZIG", "exitcode": 0})
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        ledger=ledger,
        markerdir=markers,
        extra_env=env,
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    assert not (markers / "sftp-upload.txt").exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    assert sluitregel["uitkomst"] == "geslaagd", sluitregel
    poort = next(p for p in sluitregel["poort"] if p["naam"] == "upload overgeslagen")
    assert poort["uitkomst"] == "open", poort
    assert "bundel aanwezig met gelijke SHA: upload overgeslagen" in poort["bewijs"]
    # De vrije-ruimtepoort moet de bundelterm als een
    # BEWUSTE nul lezen (bundel_al_aanwezig), nooit als ongemeten - anders
    # beweert het bewijs dat de gemeten grootte "ontbrak" terwijl hij lokaal
    # wel degelijk gemeten is en bewust overgeslagen.
    poort_ruimte = next(p for p in sluitregel["poort"] if p["naam"] == "vrije ruimte op /var")
    assert "0 MB nog te ontvangen" in poort_ruimte["bewijs"], poort_ruimte


def test_r1_still_uploads_when_the_bundle_present_on_the_box_has_a_different_sha(tmp_path):
    """Tegenprobe: de bundel staat er al, maar de hash op de doos wijkt af
    van de vendor-SHA (bijvoorbeeld een eerdere, afgebroken overzet) - dan
    wordt gewoon geupload, zoals altijd."""
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    andere_doos_sha = "22" * 32
    assert andere_doos_sha != NEP_DOOS_SHA
    env = _responses(tmp_path, {"match": "echo AANWEZIG", "stdout": "AANWEZIG", "exitcode": 0})
    env["GJK_TEST_DOOS_SHA"] = andere_doos_sha
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        ledger=ledger,
        markerdir=markers,
        extra_env=env,
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    assert (markers / "sftp-upload.txt").exists(), proc.stdout + proc.stderr
    # Expliciet maken dat de skip-beslissing en de
    # firmware-hash-gate dezelfde lezing delen - een afwijkende SHA op de
    # doos moet de hashpoort ook echt sluiten, niet alleen de upload triggeren.
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    hash_poort = next(p for p in regels[-1]["poort"] if p["naam"] == "firmware-hash")
    assert hash_poort["uitkomst"] == "dicht", hash_poort


def test_r1_selects_the_bundle_by_its_exact_expected_name_ignoring_a_stray_tgz(tmp_path):
    """C2: 'vandaag wordt een stray .tgz in de firmwaremap geupload,
    uitgepakt en geinstalleerd'. Zet een stray bestand (alfabetisch EERST)
    naast de echte bundel, draai met een tak-gekwalificeerde -Doelbuild (het
    pad waarop de naam letterlijk bekend is), en bewijs via de
    SFTP-broncontrole in de NEP-transport dat het geuploade bestand de
    ECHTE bundel is - nooit de stray."""
    markers = tmp_path / "markers"
    firmwaremap = _firmwaremap(
        tmp_path,
        extra_bestanden={
            "aaa-stray-oude-build.tgz": b"stray-inhoud-die-nooit-gekozen-mag-worden",
        },
    )
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        doelbuild="14.1-72.57",
        firmwaremap=firmwaremap,
        markerdir=markers,
    )
    assert "[EINDSTATUS]" in proc.stdout, proc.stdout + proc.stderr
    bron_pad = markers / "sftp-upload-bron.txt"
    assert bron_pad.exists(), proc.stdout + proc.stderr
    bron = bron_pad.read_text(encoding="ascii").strip()
    assert bron.endswith("build-14.1-72.57_nc_64.tgz"), bron
    assert "stray" not in bron


def test_r2_extracts_the_bundle_by_its_exact_name_never_a_wildcard(tmp_path):
    """A later fix removed the wildcard from every
    OTHER bundle-selection site in this script - R2's own 'tar -xvzf' still
    read '*.tgz'. Fixed to use the exact name `_GjkVindBundel` already
    resolved, the same way the SHA-on-the-box command a few lines above it
    already does. A stray, alphabetically-earlier .tgz in the firmware
    directory proves this is not merely cosmetic: a bare '*.tgz' glob in
    that build directory would have silently matched whichever .tgz
    happened to be there, not necessarily the one this run just uploaded."""
    markers = tmp_path / "markers"
    firmwaremap = _firmwaremap(
        tmp_path,
        extra_bestanden={
            "aaa-stray-oude-build.tgz": b"stray-inhoud-die-nooit-gekozen-mag-worden",
        },
    )
    proc = _run(tmp_path, "R2", seed_previous=True, firmwaremap=firmwaremap, markerdir=markers)
    assert "[EINDSTATUS]" in proc.stdout, proc.stdout + proc.stderr
    commando_pad = markers / "ssh-tar-commando.txt"
    assert commando_pad.exists(), proc.stdout + proc.stderr
    commando = commando_pad.read_text(encoding="ascii").strip()
    assert "build-14.1-72.57_nc_64.tgz" in commando, commando
    assert "*.tgz" not in commando, commando
    assert "stray" not in commando, commando


def test_more_than_one_candidate_for_a_bare_doelbuild_pattern_is_refused_not_guessed(tmp_path):
    """C2: zonder tak in -Doelbuild (de losse-scriptvorm) zoekt de selectie
    op patroon (build-*-<nummer>_nc_64.tgz) - en bij meer dan een kandidaat
    is dat een GEWEIGERDE, geen gegokte eerste treffer. Twee bundels delen
    hier hetzelfde bare buildnummer (72.57) met een verschillende tak."""
    firmwaremap = _firmwaremap(
        tmp_path,
        extra_bestanden={
            "build-99.9-72.57_nc_64.tgz": b"een-andere-tak-zelfde-buildnummer",
        },
    )
    proc = _run(tmp_path, "R1", doelbuild="72.57", firmwaremap=firmwaremap)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "GEWEIGERD" in proc.stdout, proc.stdout + proc.stderr
    assert "[EINDSTATUS]" not in proc.stdout


def test_a_missing_expected_bundle_under_a_branch_qualified_doelbuild_is_refused(tmp_path):
    """C2: draagt -Doelbuild een tak, dan is de verwachte naam letterlijk
    bekend - ontbreekt precies dat bestand (ook al staat er een ANDER,
    onschuldig ogend .tgz-bestand), dan is dat een weigering, nooit een
    stilzwijgende keuze voor het andere bestand."""
    firmwaremap = tmp_path / "firmware"
    firmwaremap.mkdir()
    (firmwaremap / "build-14.1-99.99_nc_64.tgz").write_bytes(b"verkeerde-build")
    proc = _run(tmp_path, "R1", doelbuild="14.1-72.57", firmwaremap=firmwaremap)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "GEWEIGERD" in proc.stdout, proc.stdout + proc.stderr


# A file name that fits the bare-build pattern build-*-72.57_nc_64.tgz but not
# the bundle form build-<tak>-<build>_nc_64.tgz. Windows allows every one of
# these characters in a file name; in a remote `shell sh -c '...'` the quote
# closes the string and `reboot` runs on the appliance.
_KWAADAARDIGE_BUNDELNAAM = "build-x';reboot;echo '-72.57_nc_64.tgz"


def _kwaadaardige_firmwaremap(tmp_path: Path) -> Path:
    map_ = tmp_path / "firmware-kwaad"
    map_.mkdir()
    bundel = map_ / _KWAADAARDIGE_BUNDELNAAM
    bundel.write_bytes(b"nep-bundel-inhoud")
    (map_ / (bundel.name + ".sha256")).write_text(NEP_DOOS_SHA + "\n", encoding="ascii")
    return map_


def _geen_commando_met_de_naam(markers: Path) -> None:
    commandos = markers / "commands.txt"
    if commandos.exists():
        assert "reboot" not in commandos.read_text(encoding="ascii")
    assert not (markers / "writes.txt").exists()
    assert not (markers / "sftp-upload-bron.txt").exists()


@pytest.mark.parametrize("fase", ["R1", "R2", "R3"])
def test_a_bare_doelbuild_refuses_a_bundle_name_outside_the_bundle_form_before_any_command(tmp_path, fase):
    """Without a branch in -Doelbuild the runner finds the bundle through a
    wildcard over the firmware directory, and the name it finds went
    unfiltered into `shell sh -c`. A name outside the bundle form is refused
    with its own exit code before the session opens: no command, no ledger
    row for this phase, and the name itself is never echoed."""
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        fase,
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"] if fase == "R1" else None,
        doelbuild="72.57",
        firmwaremap=_kwaadaardige_firmwaremap(tmp_path),
        markerdir=markers,
        ledger=ledger,
    )
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "[FOUT]" in proc.stdout and "[GEWEIGERD]" in proc.stdout, proc.stdout + proc.stderr
    assert "[EINDSTATUS]" not in proc.stdout
    assert "reboot" not in proc.stdout + proc.stderr
    assert not (markers / "commands.txt").exists(), (markers / "commands.txt").read_text(encoding="ascii")
    assert not (markers / "ssh-sessie-geopend.txt").exists()
    _geen_commando_met_de_naam(markers)
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r for r in regels if r["fase"] == fase] == []


def test_the_preview_refuses_a_bundle_name_outside_the_bundle_form_too(tmp_path):
    proc = _run(tmp_path, "R1", watis=True, doelbuild="72.57", firmwaremap=_kwaadaardige_firmwaremap(tmp_path))
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[VOORVERTONING]" not in proc.stdout
    assert "reboot" not in proc.stdout + proc.stderr


def test_a_bundle_name_that_changes_after_the_first_check_is_refused_where_it_is_used(tmp_path):
    """The first check runs before the session; the name is checked again
    where the bundle is chosen, so a file renamed in between (here: during
    R1's free-space reading) never reaches a command either."""
    markers = tmp_path / "markers"
    firmwaremap = _firmwaremap(tmp_path)
    goed = firmwaremap / "build-14.1-72.57_nc_64.tgz"
    transport = tmp_path / "rename-midway.ps1"
    nieuwe_naam = _KWAADAARDIGE_BUNDELNAAM.replace("'", "''")
    transport.write_text(
        f". '{TRANSPORT_NEP}'\n"
        "$script:GjkTestEchteDf = ${function:Get-GjkVrijeRuimteVar}\n"
        "function Get-GjkVrijeRuimteVar {\n"
        "    param($Sessie)\n"
        f"    Rename-Item -LiteralPath '{goed}' -NewName '{nieuwe_naam}'\n"
        "    & $script:GjkTestEchteDf -Sessie $Sessie\n"
        "}\n",
        encoding="ascii",
    )
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        doelbuild="72.57",
        firmwaremap=firmwaremap,
        markerdir=markers,
        transport=transport,
    )
    assert (firmwaremap / _KWAADAARDIGE_BUNDELNAAM).exists(), proc.stdout + proc.stderr
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[EINDSTATUS]" not in proc.stdout
    assert "reboot" not in proc.stdout + proc.stderr
    _geen_commando_met_de_naam(markers)


def test_the_buildboom_gate_also_checks_size_not_only_the_name(tmp_path):
    """A complete filename with a SHORT remote size must still close the gate."""
    ledger = tmp_path / "ledger.jsonl"
    env = _responses(
        tmp_path,
        {
            "match": "ls -la",
            "stdout": "total 4\n-rw-r--r-- 1 root wheel 16 Sep 8 00:00 build-14.1-72.57_nc_64.tgz",
            "exitcode": 0,
        },
    )
    proc = _run(tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], ledger=ledger, extra_env=env)
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    poort = next(p for p in sluitregel["poort"] if p["naam"] == "buildboom staat er nog")
    assert poort["uitkomst"] == "dicht"
    assert "grootte" in poort["reden"], poort
    assert "lokale grootte" in poort["bewijs"], poort


def test_the_runner_never_writes_a_ledger_line_of_its_own_shape():
    """De scriptkant van 'het script schrijft geen ledgerregel': geen
    Add-Content/Set-Content/System.IO-schrijfactie naar een pad met '.jsonl'
    komt voor in het script zelf - alleen append_line() (Python) mag dat."""
    bron = SCRIPT.read_text(encoding="ascii")
    for verboden in ("Add-Content", "Out-File", "[System.IO.File]::AppendAllText", "[System.IO.File]::WriteAllText"):
        assert verboden not in bron, verboden


# ---------------------------------------------------------------------------
# Een verboden-adreslijst, getoetst VOOR
# elke transportaanraking. De naam 'lab-01' blijft statisch in het script;
# adresvormen komen sinds een latere wijziging ALTIJD van de aanroeper mee via
# -VerbodenAdressen (nooit meer als letterlijke waarde in dit bestand - een
# eerdere ronde liet de fixture-pseudonimisering het echte lab-01-adres
# stilzwijgend vervangen door een TEST-NET-alias, waarna de adreshelft van
# deze guard een doos bewaakte die niet bestond). Een synthetisch adres
# hieronder bewijst de mechaniek zonder dat er ooit een echt adres in deze
# test hoeft te staan.
# ---------------------------------------------------------------------------

_SYNTHETISCH_VERBODEN_ADRES = "203.0.113.42"


def test_a_forbidden_address_refuses_before_any_transport_call(tmp_path):
    markers = tmp_path / "markers"
    proc = _run(
        tmp_path,
        "R3",
        adres=_SYNTHETISCH_VERBODEN_ADRES,
        markerdir=markers,
        extra_args=["-VerbodenAdressen", _SYNTHETISCH_VERBODEN_ADRES],
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert not markers.exists() or not any(markers.iterdir()), (
        f"een verboden adres raakte het transport aan: {list(markers.iterdir()) if markers.exists() else []}"
    )


def test_without_the_parameter_only_the_name_is_guarded(tmp_path):
    """Zonder -VerbodenAdressen weigert de guard uitsluitend op naam - het
    synthetische adres hierboven komt dan gewoon door (tot aan het punt waar
    het nep-transport het overneemt), precies zoals bedoeld:
    'guard met lijst weigert, zonder lijst alleen de naam'."""
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R3", adres=_SYNTHETISCH_VERBODEN_ADRES, markerdir=markers)
    assert "[GEWEIGERD]" not in proc.stdout, proc.stdout + proc.stderr


def test_a_forbidden_target_name_refuses_too(tmp_path):
    """Dezelfde lijst geldt op -Doel, niet alleen op -Adres - een andere
    schrijfwijze van dezelfde doos mag niet stilzwijgend langskomen. De
    naamguard staat statisch in het script en heeft geen -VerbodenAdressen
    nodig."""
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R3", doel="LAB-01", markerdir=markers)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_a_forbidden_address_refuses_even_on_watis(tmp_path):
    """Ook -WatIs (dat op zichzelf al geen sessie opent) weigert - een
    voorstel tegen een verboden doos wordt niet eens getoond."""
    proc = _run(
        tmp_path,
        "R3",
        adres=_SYNTHETISCH_VERBODEN_ADRES,
        watis=True,
        extra_args=["-VerbodenAdressen", _SYNTHETISCH_VERBODEN_ADRES],
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[VOORVERTONING]" not in proc.stdout


@pytest.mark.parametrize("adres", ["198.51.100.7", _SYNTHETISCH_VERBODEN_ADRES])
def test_two_forbidden_addresses_in_one_argument_are_both_refused(tmp_path, adres):
    """Twee adressen reizen als EEN komma-argument: `powershell.exe -File`
    bindt van twee losse waarden alleen de eerste aan een [string[]]-
    parameter. Beide adressen moeten daarna geweigerd worden, ook het
    tweede."""
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        "R3",
        adres=adres,
        ledger=ledger,
        markerdir=markers,
        extra_args=["-VerbodenAdressen", "198.51.100.7," + _SYNTHETISCH_VERBODEN_ADRES],
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert not ledger.exists()
    assert not markers.exists() or not any(markers.iterdir())


def test_a_second_loose_forbidden_address_is_refused_not_bound_to_another_parameter(tmp_path):
    """De oude vorm (`-VerbodenAdressen a b`) gaf het tweede adres stil aan
    de eerste vrije positionele parameter - bij R0 de snapshotverwijzing,
    waardoor de mensenpoort op een adres opende. Een losse positionele
    waarde wordt nu geweigerd voordat er een ledgerregel bestaat."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        "R0",
        ledger=ledger,
        extra_args=["-VerbodenAdressen", "198.51.100.7", "198.51.100.8"],
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert not ledger.exists(), ledger.read_text(encoding="utf-8")


@pytest.mark.parametrize("veld", ["doel", "adres"])
@pytest.mark.parametrize("teken", ["\r\n", "\n", "\r", "\t"], ids=["crlf", "lf", "cr", "tab"])
@pytest.mark.parametrize("watis", [True, False], ids=["watis", "echt"])
def test_a_control_character_in_doel_or_adres_is_refused_before_any_label_or_transport(tmp_path, veld, teken, watis):
    """-Doel and -Adres were checked for ASCII only. A CR or LF in either
    split the [TARGET] line and let a value print a second [ACTIEID] line,
    which the server reads first on -WatIs."""
    ledger = tmp_path / "ledger.jsonl"
    markers = tmp_path / "markers"
    waarde = {"doel": "lab-02-test", "adres": "127.0.0.1"}[veld] + teken + "[ACTIEID] vals x"
    proc = _run(tmp_path, "R1", watis=watis, ledger=ledger, markerdir=markers, **{veld: waarde})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[TARGET]" not in proc.stdout and "[ACTIEID]" not in proc.stdout
    assert "vals" not in proc.stdout
    assert not ledger.exists()
    assert not markers.exists() or not any(markers.iterdir())


def _control_character_argument(veld: str, waarde: str) -> dict:
    """The `_run` keywords that carry `waarde` in `veld`; the others keep
    their ordinary values."""
    if veld == "Snapshotverwijzing":
        return {"extra_args": ["-Snapshotverwijzing", waarde]}
    return {{"Actieid": "actieid", "Run": "run", "Bevestiger": "bevestiger", "Doelbuild": "doelbuild"}[veld]: waarde}


_ORDINARY = {
    "Actieid": "upgrade-R1-20260907-000000",
    "Run": "test-run-1",
    "Bevestiger": "u-test",
    "Snapshotverwijzing": "checkpoint-1",
    "Doelbuild": "72.57",
}


@pytest.mark.parametrize("veld", ["Actieid", "Run", "Bevestiger", "Snapshotverwijzing", "Doelbuild"])
@pytest.mark.parametrize("teken", ["\r\n", "\n", "\t"], ids=["crlf", "lf", "tab"])
def test_a_control_character_in_any_value_that_reaches_a_label_a_ledger_row_or_a_log_line_is_refused(
    tmp_path, veld, teken
):
    """The control-character check covered -Doel and -Adres only. -Actieid
    is printed in the [ACTIEID] line the code binds to, -Run in a log line
    and every ledger row, -Bevestiger and -Snapshotverwijzing in ledger rows,
    -Doelbuild in the [TARGET] line: a CR or LF in any of them splits that
    line. Refused with [FOUT]/[GEWEIGERD] and exit code 1 before any label,
    transport or ledger row, without repeating the value."""
    ledger = tmp_path / "ledger.jsonl"
    markers = tmp_path / "markers"
    waarde = _ORDINARY[veld] + teken + "[ACTIEID] vals x"
    proc = _run(tmp_path, "R1", ledger=ledger, markerdir=markers, **_control_character_argument(veld, waarde))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "[TARGET]" not in proc.stdout and "[ACTIEID]" not in proc.stdout
    assert "vals" not in proc.stdout
    assert not ledger.exists()
    assert not markers.exists() or not any(markers.iterdir())


def test_ordinary_values_in_those_parameters_still_run(tmp_path):
    """The positive side: the same five parameters with ordinary values - a
    snapshot reference with spaces included - reach the labels as before."""
    proc = _run(
        tmp_path,
        "R0",
        watis=True,
        actieid=_ORDINARY["Actieid"],
        run=_ORDINARY["Run"],
        bevestiger=_ORDINARY["Bevestiger"],
        doelbuild=_ORDINARY["Doelbuild"],
        extra_args=["-Snapshotverwijzing", "checkpoint voor de upgrade 1"],
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[TARGET] lab-02-test (127.0.0.1) - fase R0 naar build 72.57" in proc.stdout
    assert "[ACTIEID] upgrade-R1-20260907-000000" in proc.stdout


def test_the_forbidden_address_list_names_lab_01_but_no_real_address():
    """Statische regressie: lab-01 zelf staat op de lijst, en - de kern van
    de latere fix - er staat GEEN adresvorm meer statisch in dit
    bestand; grep in plaats van een run, zodat dit ook zonder powershell.exe
    zou kunnen (het bestand blijft ASCII-scanbaar)."""
    bron = SCRIPT.read_text(encoding="ascii")
    assert "lab-01" in bron
    assert "-VerbodenAdressen" in bron
    assert "192.0.2.2" not in bron


# ---------------------------------------------------------------------------
# -Doelbuild is de enige configuratiestring die ongefilterd in een
# remote shell-commando en een remote pad terechtkwam.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwaad",
    [
        "72.57; rm -rf /tmp",
        "72.57 && cat /flash/nsconfig/ns.conf",
        "72.57`whoami`",
        "72.57$(id)",
        "../../etc",
        "72.57/../../..",
        "72 57",
        "14.1-72.57-extra-deel",
    ],
)
def test_doelbuild_with_shell_metacharacters_is_rejected_by_validation(tmp_path, kwaad):
    """Blijft dicht: geen puntkomma, ampersand, backtick, $(...),
    schuine streep, spatie of tweede koppelteken komt door de poort - en dus
    nooit in `cd <buildDir> && tar ...`, in `./installns -Y -n` of in
    `/var/tmp/gjk_pre_check_<n>.json`."""
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R3", doelbuild=kwaad, markerdir=markers)
    assert proc.returncode != 0
    # De validatie weigert VOOR de scriptbody ooit start - geen etiket, geen
    # transportaanraking.
    assert "[TARGET]" not in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_a_rejected_doelbuild_still_prints_geweigerd_and_not_a_bare_binding_error(tmp_path):
    """Een bindingsweigering gaf voorheen NIETS op het
    [FOUT]/[GEWEIGERD]-kanaal - de scriptbody start immers nooit - en een
    operator zag alleen een kale PowerShell-bindingsfout."""
    proc = _run(tmp_path, "R3", doelbuild="72.57; rm -rf /tmp")
    assert "[GEWEIGERD]" in proc.stdout, proc.stdout + proc.stderr
    assert "[FOUT]" in proc.stdout
    # de untrusted waarde zelf wordt NIET geechood door dit script
    assert "rm -rf /tmp" not in proc.stdout


def test_the_branch_qualified_doelbuild_the_product_needs_is_accepted_end_to_end(tmp_path):
    """De bevinding zelf: een gemeten upgrade draaide 66.59 ->
    14.1-72.57 op de labdoos, en de rest van dit product schrijft een
    buildidentiteit altijd in die tak-gekwalificeerde vorm. Het oude patroon
    weigerde precies die waarde, en een bindingsweigering produceert geen
    [TARGET]-regel om dat aan te zien."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], doelbuild="14.1-72.57", ledger=ledger
    )
    assert "[TARGET]" in proc.stdout, proc.stdout + proc.stderr
    assert "naar build 14.1-72.57" in proc.stdout
    assert "[EINDSTATUS]" in proc.stdout
    assert ledger.exists()
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    poorten = {p["naam"]: p for p in regels[-1]["poort"]}
    # de TAK is uit -Doelbuild gestript: het remote pad is
    # /var/nsinstall/14.1/build_72.57 en NOOIT .../build_14.1-72.57
    boom = poorten["buildboom staat er nog"]["bewijs"]
    assert "/var/nsinstall/14.1/build_72.57" in boom, boom
    assert "build_14.1-72.57" not in boom


def test_a_valid_multi_component_doelbuild_is_accepted(tmp_path):
    """De poort mag niet zo strak staan dat een echt buildnummer (meerdere
    puntgescheiden delen) geweigerd wordt."""
    proc = _run(tmp_path, "R3", doelbuild="14.1.72.57", watis=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[TARGET]" in proc.stdout


def test_a_doelbuild_with_a_trailing_newline_is_rejected(tmp_path):
    """Een eerder overgenomen defect, inmiddels gesloten: .NET-regex laat
    '$' standaard ook matchen vlak voor een AFSLUITENDE '\\n' - '72.57\\n'
    voldeed dus zowel aan de -Doelbuild-validatie (het oude patroon eindigde
    op '$') als aan de ASCII-toets (Assert-GjkAsciiWaarde weigert alleen
    tekens boven 127, geen stuurtekens). Zo'n waarde zou de NetScaler-CLI-
    regel splitsen die dit product bouwt. `_run()` geeft `doelbuild` door
    als EEN argv-element in een lijst aan `subprocess.run` (geen shell erin
    betrokken), precies zoals `mcp_server.py`/`handelen.upgrade_command()`
    dat ook doet - de ingebedde newline komt dus ongewijzigd aan bij de
    ValidateScript."""
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R3", markerdir=markers, doelbuild="72.57\n")
    assert proc.returncode != 0
    assert "[TARGET]" not in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_the_doelbuild_parameter_is_validated_before_the_body_runs():
    bron = SCRIPT.read_text(encoding="ascii")
    # het ATTRIBUUT zelf, niet het woord in een toelichting erboven
    assert "[ValidateScript({" in bron
    blok = bron.split("[ValidateScript({", 1)[1].split("[string] $Doelbuild", 1)[0]
    # de tak-gekwalificeerde vorm komt erdoor, injectietekens niet
    assert "-[0-9]+" in blok
    # en een weigering meldt zichzelf op het [GEWEIGERD]-kanaal
    assert "[GEWEIGERD]" in blok
    assert "[FOUT]" in blok


# ---------------------------------------------------------------------------
# -Actieid weglaten sloot ELKE fase 'mislukt'
# ---------------------------------------------------------------------------


def test_a_real_run_without_actieid_is_refused_before_any_ledger_row(tmp_path):
    """Zonder -Actieid ging een leeg 'actieid' naar upgrade_gate terwijl
    'actieid_uit_script' het zelf gegenereerde id droeg; evaluate_phase
    vergelijkt die twee met != , dus elke fase sloot 'mislukt' met een
    ledgerregel die een echt oordeel LEEK. Nu expliciet geweigerd."""
    ledger = tmp_path / "ledger.jsonl"
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R1", ledger=ledger, markerdir=markers, actieid="")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert "-Actieid" in proc.stdout
    assert not ledger.exists(), "er is een ledgerregel geschreven voor een geweigerde aanroep"
    assert not markers.exists() or not any(markers.iterdir())


def test_watis_without_actieid_is_still_allowed(tmp_path):
    """Bij -WatIs is er nog niets bevestigd; het script vormt dan zelf het
    etiket waaraan de mens de code straks bindt."""
    proc = _run(tmp_path, "R1", watis=True, actieid="")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[ACTIEID] upgrade-R1-" in proc.stdout


# ---------------------------------------------------------------------------
# R0 schrijft zijn terugrolpunt-regel
# ---------------------------------------------------------------------------


def test_r0_writes_the_rollback_point_row_once_before_the_closing_row(tmp_path):
    """Ontwerp 3.5 noemt voor R0 TWEE regels. De extra bewijsregel
    `terugrolpunt_vast` draagt de zes componenten en staat VOOR de sluitregel
    `voormeting_vast` - hij sluit zelf niets."""
    ledger = tmp_path / "ledger.jsonl"
    register = _actieregister(
        tmp_path,
        {
            "tool": "onderhoud_backup_maken",
            "doel": "lab-02-test",
            "uitkomst": "geslaagd",
            "actieid": "a-9",
            "objectnaam": "gjk_preupgrade_lab-02-test_20260906_071500",
        },
    )
    proc = _run(
        tmp_path,
        "R0",
        ledger=ledger,
        actieregister=register,
        export_root=R0_EXPORT_FIXTURE,
        # R0 sluit alleen geslaagd met een doelbuild op of boven de vloer.
        doelbuild="14.1-72.57",
        extra_args=[
            "-Snapshotverwijzing",
            "hv-snap-20260907-1",
            "-Huidigebuild",
            "14.1-66.59",
            "-Vloerbuild",
            "14.1-72.57",
            "-VloerBulletin",
            "CTX696604",
        ],
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    gebeurtenissen = [r["gebeurtenis"] for r in regels]
    assert gebeurtenissen == ["fase_gestart", "terugrolpunt_vast", "voormeting_vast"], gebeurtenissen

    terugrol = regels[1]
    assert terugrol["fase"] == "R0"
    assert terugrol["uitkomst"] == "gestart"
    assert terugrol["geeindigd"] is None
    bewijs = terugrol["bewijs"]
    assert "gjk_preupgrade_lab-02-test_20260906_071500" in bewijs  # 1 naam
    assert "812 MB" in bewijs  # 2 grootte
    assert "Sun Sep  6 07:15:00 2026" in bewijs  # 3 tijd
    assert "/var/nsinstall/build-14.1-66.59_nc_64" in bewijs  # 4 pad
    assert "dag(en) oud" in bewijs  # 5 leeftijd
    assert "hv-snap-20260907-1" in bewijs  # 6 snapshot


def test_r0_still_writes_the_rollback_point_row_when_a_component_is_unreadable(tmp_path):
    """Een onleesbare component wordt GENOEMD ('niet gelezen'), niet
    stilzwijgend weggelaten - en de regel verschijnt nog steeds precies een
    keer."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R0", ledger=ledger)
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    terugrol = [r for r in regels if r["gebeurtenis"] == "terugrolpunt_vast"]
    assert len(terugrol) == 1
    assert regels.index(terugrol[0]) < len(regels) - 1, "de bewijsregel staat na de sluitregel"
    assert "niet gelezen" in terugrol[0]["bewijs"]


def test_no_other_phase_writes_a_rollback_point_row(tmp_path):
    """`terugrolpunt_vast` is R0's regel en die van niemand anders."""
    ledger = tmp_path / "ledger.jsonl"
    _run(tmp_path, "R1", ledger=ledger)
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert not any(r["gebeurtenis"] == "terugrolpunt_vast" for r in regels)


# ---------------------------------------------------------------------------
# De verboden lijst dekt ook een andere schrijfwijze
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schrijfwijze",
    [
        "lab-01",
        "LAB-01",
        "lab-01.intern.example",
        "lab-01.intern.example.",
        "beheer@lab-01",
        "lab-01:22",
        "  lab-01  ",
    ],
)
def test_an_alternate_spelling_of_a_forbidden_box_is_refused_too(tmp_path, schrijfwijze):
    markers = tmp_path / "markers"
    proc = _run(tmp_path, "R3", adres=schrijfwijze, markerdir=markers)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" in proc.stdout
    assert not markers.exists() or not any(markers.iterdir())


def test_an_ip_address_is_never_split_into_a_first_label(tmp_path):
    """De label-splitsing geldt alleen voor een NAAM. '192.0.2.2' mag nooit
    tot '10' verkort worden - anders zou elk adres dat met 10. begint
    geweigerd worden."""
    proc = _run(tmp_path, "R1", adres="10.1.2.3", watis=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[GEWEIGERD]" not in proc.stdout


# ---------------------------------------------------------------------------
# R0 raakt de appliance NIET aan. Zijn bronnen zijn het
# actieregister en de export - allebei nieuwe parameters.
# ---------------------------------------------------------------------------


def test_r0_never_touches_the_appliance(tmp_path):
    """Geen enkel transport-marker (credential gelezen, sessie geopend, een
    commando, een SFTP-upload, wachten na reboot) mag verschijnen voor R0 -
    zelfs geen sessie-openpoging."""
    markers = tmp_path / "markers"
    ledger = tmp_path / "ledger.jsonl"
    register = _actieregister(
        tmp_path,
        {
            "tool": "onderhoud_backup_maken",
            "doel": "lab-02-test",
            "uitkomst": "geslaagd",
            "actieid": "a-1",
        },
    )
    proc = _run(
        tmp_path,
        "R0",
        ledger=ledger,
        markerdir=markers,
        actieregister=register,
        export_root=EXPORT_FIXTURE,
    )
    assert "[EINDSTATUS]" in proc.stdout, proc.stdout + proc.stderr
    for marker in (
        "credential-gelezen.txt",
        "ssh-sessie-geopend.txt",
        "ssh-commando.txt",
        "sftp-upload.txt",
        "wait-gjkterug.txt",
    ):
        assert not (markers / marker).exists(), marker + " bestaat - R0 raakte het transport aan"


def test_r0_measures_the_action_register_and_the_export(tmp_path):
    """R0's poorten komen uit het actieregister en de export, en zijn ECHT
    'open' wanneer beide bronnen een geslaagde/aanwezige regel dragen - geen
    appliance nodig."""
    ledger = tmp_path / "ledger.jsonl"
    register = _actieregister(
        tmp_path,
        {
            "tool": "onderhoud_backup_maken",
            "doel": "lab-02-test",
            "uitkomst": "geslaagd",
            "actieid": "a-9",
            "objectnaam": "gjk_preupgrade_lab-02-test_20260906_071500",
        },
    )
    proc = _run(
        tmp_path,
        "R0",
        ledger=ledger,
        actieregister=register,
        export_root=R0_EXPORT_FIXTURE,
        extra_args=["-Snapshotverwijzing", "hv-snap-20260907-1"],
    )
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    poorten = {p["naam"]: p for p in sluitregel["poort"]}
    assert poorten["backupobject aanwezig"]["uitkomst"] == "open"
    assert poorten["vorige buildboom aanwezig"]["uitkomst"] == "open"
    assert poorten["leeftijd van de export"]["uitkomst"] == "open"
    assert poorten["familietellingen"]["uitkomst"] == "open"
    assert poorten["configuratie-anker"]["uitkomst"] == "open"
    assert poorten["hypervisor-snapshotverwijzing ingevoerd"]["uitkomst"] == "open"
    # R0 draagt GEEN 'hostsleutel gepind'-poort - er is nooit een sessie
    # geopend om er een te vormen (R0 raakt de appliance niet aan).
    assert "hostsleutel gepind" not in poorten


def test_r0_is_not_assessed_without_actieregister_or_exportroot(tmp_path):
    """Zonder de twee paden (bijvoorbeeld omdat de aanroeper ze niet
    bedraad heeft) is elke R0-poort 'niet beoordeeld', nooit 'open' - een
    ontbrekende bron mag nooit als aanwezig doorgaan."""
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R0", ledger=ledger)
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    poorten = {p["naam"]: p for p in sluitregel["poort"]}
    for naam in (
        "backupobject aanwezig",
        "vorige buildboom aanwezig",
        "leeftijd van de export",
        "familietellingen",
        "configuratie-anker",
    ):
        assert poorten[naam]["uitkomst"] == "niet beoordeeld", (naam, poorten[naam])


# ---------------------------------------------------------------------------
# R0: de doelbuild tegenover de huidige build en de vloer. De runner oordeelt
# niet zelf; hij stuurt verzoek 'doelbuild-vloer' naar upgrade_measure, en de
# poort staat daarna in de sluitregel en in terugrolpunt_vast.
# ---------------------------------------------------------------------------

_VLOERPOORT = "doelbuild op of boven de vloer, of bewust geaccepteerd"
_HUIDIG = ("-Huidigebuild", "14.1-66.59")


def _r0_vloerpoorten(tmp_path: Path, *extra: str) -> tuple[dict, dict, subprocess.CompletedProcess]:
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R0", ledger=ledger, doelbuild="14.1-72.57", extra_args=list(extra))
    assert ledger.exists(), proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluit = {p["naam"]: p for p in regels[-1]["poort"]}
    terugrol = next(r for r in regels if r["gebeurtenis"] == "terugrolpunt_vast")
    return sluit[_VLOERPOORT], {p["naam"]: p for p in terugrol["poort"]}[_VLOERPOORT], proc


def test_r0_closes_the_floor_gate_below_the_floor_and_says_why_in_both_rows(tmp_path):
    sluit, terugrol, _proc = _r0_vloerpoorten(
        tmp_path, *_HUIDIG, "-Vloerbuild", "14.1-73.32", "-VloerBulletin", "CTX696939"
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "dicht")
    # The runner always hands the package fields over; without -VloerPakket
    # the evidence says so instead of staying silent about the floor's source.
    assert sluit["bewijs"] == (
        "doelbuild 14.1-72.57 onder vloer 14.1-73.32 (CTX696939); kennispakket niet meegegeven; "
        "huidige build 14.1-66.59"
    )
    assert "doelbuild_geaccepteerd=true" in sluit["reden"]
    assert terugrol == sluit


def test_r0_names_the_package_of_the_floor_and_warns_when_it_is_old_without_closing(tmp_path):
    oud = (datetime.now(UTC).date() - timedelta(days=45)).isoformat()
    sluit, terugrol, _proc = _r0_vloerpoorten(
        tmp_path,
        *_HUIDIG,
        "-Vloerbuild",
        "14.1-72.57",
        "-VloerBulletin",
        "CTX696604",
        "-VloerPakket",
        "2026.09",
        "-VloerPakketDatum",
        oud,
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "open")
    # 45, or 46 when the run crosses midnight UTC between here and the gate.
    assert re.search(
        rf"\(CTX696604\); kennispakket 2026\.09 van {oud}; WAARSCHUWING: het kennispakket is 4[56] dagen oud",
        sluit["bewijs"],
    ), sluit["bewijs"]
    assert terugrol == sluit


def test_r0_names_a_fresh_package_without_a_warning(tmp_path):
    vandaag = datetime.now(UTC).date().isoformat()
    sluit, _terugrol, _proc = _r0_vloerpoorten(
        tmp_path,
        *_HUIDIG,
        "-Vloerbuild",
        "14.1-72.57",
        "-VloerBulletin",
        "CTX696604",
        "-VloerPakket",
        "2026.09",
        "-VloerPakketDatum",
        vandaag,
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "open")
    assert sluit["bewijs"] == (
        f"doelbuild 14.1-72.57 op of boven vloer 14.1-72.57 (CTX696604); kennispakket 2026.09 van {vandaag}; "
        "huidige build 14.1-66.59"
    )


def test_r0_opens_the_floor_gate_as_a_human_decision_when_accepted(tmp_path):
    sluit, _terugrol, _proc = _r0_vloerpoorten(
        tmp_path, *_HUIDIG, "-Vloerbuild", "14.1-73.32", "-VloerBulletin", "CTX696939", "-DoelbuildGeaccepteerd"
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("mens", "open")
    assert sluit["bewijs"].endswith("; huidige build 14.1-66.59; bewust geaccepteerd")


def test_r0_opens_the_floor_gate_on_evidence_at_the_floor(tmp_path):
    sluit, _terugrol, _proc = _r0_vloerpoorten(
        tmp_path, *_HUIDIG, "-Vloerbuild", "14.1-72.57", "-VloerBulletin", "CTX696604"
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "open")


def test_r0_without_a_floor_closes_the_floor_gate_and_names_the_missing_floor(tmp_path):
    sluit, terugrol, _proc = _r0_vloerpoorten(tmp_path, *_HUIDIG)
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "dicht")
    assert "geen vloer" in sluit["bewijs"]
    assert sluit["reden"] == "geen vloer bekend in het kennispakket voor deze tak"
    assert terugrol == sluit


def test_r0_without_a_floor_opens_the_floor_gate_as_a_human_decision_when_accepted(tmp_path):
    sluit, _terugrol, _proc = _r0_vloerpoorten(tmp_path, *_HUIDIG, "-DoelbuildGeaccepteerd")
    assert (sluit["type"], sluit["uitkomst"]) == ("mens", "open")
    assert sluit["bewijs"] == "doelbuild 14.1-72.57; geen vloer bekend; huidige build 14.1-66.59; bewust geaccepteerd"


def test_r0_closes_a_branch_difference_even_when_accepted(tmp_path):
    sluit, _terugrol, _proc = _r0_vloerpoorten(
        tmp_path, *_HUIDIG, "-Vloerbuild", "13.1-63.18", "-VloerBulletin", "CTX696604", "-DoelbuildGeaccepteerd"
    )
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "dicht")
    assert "andere tak" in sluit["reden"]


def test_r0_closes_a_target_build_in_another_release_line_than_the_current_build_even_when_accepted(tmp_path):
    """Without a floor, a target build in another release line used to open
    on the acceptance: the gate knew the line only through the floor."""
    sluit, terugrol, _proc = _r0_vloerpoorten(tmp_path, "-Huidigebuild", "13.1-63.18", "-DoelbuildGeaccepteerd")
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "dicht")
    assert sluit["reden"] == (
        "de doelbuild ligt in een andere releaselijn dan de huidige build; "
        "dit gereedschap doet geen overstap tussen releaselijnen"
    )
    assert sluit["bewijs"] == "doelbuild 14.1-72.57 (releaselijn 14.1), huidige build 13.1-63.18 (releaselijn 13.1)"
    assert terugrol == sluit


def test_r0_without_a_current_build_closes_the_floor_gate_without_acceptance(tmp_path):
    sluit, terugrol, _proc = _r0_vloerpoorten(tmp_path, "-Vloerbuild", "14.1-72.57", "-VloerBulletin", "CTX696604")
    assert (sluit["type"], sluit["uitkomst"]) == ("bewijs", "dicht")
    assert sluit["bewijs"].endswith("; huidige build niet bekend")
    assert sluit["reden"].startswith("de huidige build is niet bekend uit de export")
    assert terugrol == sluit


def test_r0_without_a_current_build_opens_the_floor_gate_as_a_human_decision_when_accepted(tmp_path):
    sluit, _terugrol, _proc = _r0_vloerpoorten(tmp_path, "-DoelbuildGeaccepteerd")
    assert (sluit["type"], sluit["uitkomst"]) == ("mens", "open")
    assert sluit["bewijs"] == (
        "doelbuild 14.1-72.57; geen vloer bekend; huidige build niet bekend; bewust geaccepteerd"
    )


@pytest.mark.parametrize(
    "extra",
    [
        ["-Vloerbuild", "14.1-73.32; reboot"],
        ["-Vloerbuild", "14.1-73.32\n"],
        ["-VloerBulletin", "CTX 696939"],
        ["-VloerBulletin", "CTX696939;reboot"],
        ["-Huidigebuild", "14.1-66.59; reboot"],
        ["-Huidigebuild", "14.1-66.59\n"],
        ["-Huidigebuild", "13.1-FIPS-37.272"],
        ["-VloerPakket", "2026.09; reboot"],
        ["-VloerPakket", "2026.09\n"],
        ["-VloerPakketDatum", "2026-09-06; reboot"],
        ["-VloerPakketDatum", "2026-09-06\n"],
    ],
)
def test_a_floor_argument_of_the_wrong_shape_is_refused_at_binding(tmp_path, extra):
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(tmp_path, "R0", ledger=ledger, doelbuild="14.1-72.57", extra_args=extra)
    assert proc.returncode != 0
    assert "[GEWEIGERD]" in proc.stdout, proc.stdout + proc.stderr
    assert "[TARGET]" not in proc.stdout
    assert "reboot" not in proc.stdout
    assert not ledger.exists()


# ---------------------------------------------------------------------------
# Een KAPOT nep-transport - een generieke verbindingsfout
# en een onverwachte meetfout, zonder appliance.
# ---------------------------------------------------------------------------


def test_a_non_host_key_connection_failure_gets_its_own_reason_not_the_pinned_one(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    proc = _run(
        tmp_path,
        "R1",
        ledger=ledger,
        transport=TRANSPORT_KAPOT,
        vingerafdruk=KAPOT_VERBINDING_SENTINEL,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    sluitregel = regels[-1]
    hostpoort = next(p for p in sluitregel["poort"] if p["naam"] == "hostsleutel gepind")
    assert hostpoort["uitkomst"] == "niet beoordeeld"
    assert hostpoort["reden"] != "hostsleutel wijkt af"
    assert "hostsleutel wijkt af" not in hostpoort["reden"]


def test_an_unexpected_measurement_error_never_exits_1_and_logs_a_clear_reason(tmp_path):
    """De sessie gaat wel open (een goede vingerafdruk), maar
    Copy-GjkFile in R1 gooit een onverwachte fout. Voorheen: stilzwijgend
    exitcode 1 (hetzelfde woord als een GEOORDEELDE poort-dicht). Nu:
    exitcode 3, gelogd, en geen ledgerregel die een oordeel VEINST."""
    ledger = tmp_path / "ledger.jsonl"
    transport = tmp_path / "upload-failure.ps1"
    transport.write_text(
        f". '{TRANSPORT_NEP}'\nfunction Copy-GjkFile {{ throw 'synthetic SFTP-upload failure' }}", encoding="ascii"
    )
    proc = _run(
        tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], ledger=ledger, transport=transport
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert proc.returncode != 1
    assert "[FOUT]" in proc.stdout
    assert "[GEWEIGERD]" in proc.stdout
    assert "[EINDSTATUS]" not in proc.stdout
    # De fase_gestart-regel staat er nog (die is VOOR de meting geschreven),
    # maar er is GEEN sluitregel - dit script beweert geen oordeel dat de
    # oordeelshelft nooit gaf.
    regels = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["gebeurtenis"] for r in regels][-2:] == ["fase_gestart", "voorpoort"]
    assert regels[-2]["gebeurtenis"] == "fase_gestart"


# ---------------------------------------------------------------------------
# -OudeBuildbomenOpruimen is inert.
# ---------------------------------------------------------------------------


def test_the_cleanup_flag_never_deletes_or_touches_anything_extra(tmp_path):
    """De vlag mag NERGENS in het script naast het etiket voorkomen - geen
    verwijderregel is eraan gekoppeld."""
    bron = SCRIPT.read_text(encoding="ascii")
    regels_met_vlag = [r for r in bron.splitlines() if "OudeBuildbomenOpruimen" in r]
    assert regels_met_vlag, "de vlag moet ergens voorkomen (parameter + etiket)"
    for regel in regels_met_vlag:
        for verboden in ("Remove-Item", "rm ", "rm-rf", "del ", "Remove-SSHSession", "shell rm"):
            assert verboden not in regel, (verboden, regel)


def test_the_cleanup_flag_produces_the_exact_same_transport_markers(tmp_path):
    """Gedragsbewijs naast de statische grep hierboven: met en zonder de
    vlag raakt R1 exact dezelfde transportfuncties aan - de vlag verandert
    niets anders dan het [TARGET]-etiket."""
    markers_met = tmp_path / "markers-met"
    markers_zonder = tmp_path / "markers-zonder"
    _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        markerdir=markers_met,
        oude_buildbomen_opruimen=True,
    )
    _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        markerdir=markers_zonder,
        oude_buildbomen_opruimen=False,
        ledger=tmp_path / "second.jsonl",
    )
    assert markers_met.exists() and markers_zonder.exists()
    namen_met = sorted(p.name for p in markers_met.iterdir())
    namen_zonder = sorted(p.name for p in markers_zonder.iterdir())
    assert namen_met == namen_zonder


@pytest.mark.parametrize("phase", ["R1", "R2", "R3", "R4"])
def test_primary_role_is_blocked_before_any_write(tmp_path, phase):
    transport = tmp_path / "primary.ps1"
    transport.write_text(
        TRANSPORT_NEP.read_text().replace("Master State: Secondary", "Master State: Primary"), encoding="ascii"
    )
    markers = tmp_path / "markers"
    proc = _run(
        tmp_path, phase, seed_previous=True, extra_args=["-DriftGeaccepteerd"], transport=transport, markerdir=markers
    )
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert rows[-1]["uitkomst"] == "poort dicht", proc.stdout + proc.stderr
    assert not (markers / "sftp-upload.txt").exists()
    assert not (markers / "ssh-tar-commando.txt").exists()
    assert any(row.get("gebeurtenis") == "voorpoort" for row in rows)


@pytest.mark.parametrize(
    "version",
    ["NetScaler NS14.1: Build 172.570.nc", "NetScaler NS14.1: Build 72.570.nc", "NetScaler NS114.1: Build 72.57.nc"],
)
def test_r5_never_accepts_substring_build(tmp_path, version):
    transport = tmp_path / "version.ps1"
    source = TRANSPORT_NEP.read_text().replace("NetScaler NS14.1: Build 72.57.nc, Date: Jan  1 2026, 00:00:00", version)
    transport.write_text(source, encoding="ascii")
    proc = _run(tmp_path, "R5", transport=transport, doelbuild="14.1-72.57")
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    gate = next(g for g in rows[-1]["poort"] if g["naam"] == "doelbuild bereikt")
    assert gate["uitkomst"] != "open", proc.stdout + proc.stderr


def _responses(tmp_path, *rows):
    path = tmp_path / "responses.json"
    path.write_text(json.dumps(list(rows)), encoding="ascii")
    return {"GJK_TEST_RESPONSES": str(path)}


def test_precheck_stale_success_is_not_read_and_no_write_occurs(tmp_path):
    markers = tmp_path / "markers"
    env = _responses(tmp_path, {"match": "test ! -e", "stdout": "BESTAAT", "exitcode": 0})
    proc = _run(tmp_path, "R2", seed_previous=True, markerdir=markers, extra_env=env)
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert rows[-1]["uitkomst"] == "poort dicht", proc.stdout
    assert not (markers / "writes.txt").exists()
    assert "shell cat /var/tmp" not in (markers / "commands.txt").read_text()


def test_precheck_result_path_is_unique_per_attempt_and_proved_absent(tmp_path):
    paths = []
    for attempt in range(2):
        case = tmp_path / str(attempt)
        case.mkdir()
        markers = case / "markers"
        proc = _run(case, "R2", seed_previous=True, markerdir=markers)
        commands = (markers / "commands.txt").read_text().splitlines()
        absence = next((c for c in commands if "test ! -e" in c), None)
        assert absence is not None, proc.stdout
        check = next(c for c in commands if "--pre_check_output" in c)
        read = next(c for c in commands if c.startswith("shell cat /var/tmp/"))
        path = read.split()[-1]
        assert path in absence and path in check
        assert commands.index(absence) < commands.index(check) < commands.index(read)
        paths.append(path)
    assert paths[0] != paths[1]


@pytest.mark.parametrize("phase", ["R1", "R2", "R3", "R4"])
@pytest.mark.parametrize("kind", ["failed", "wrong-ip", "missing-state"])
def test_write_phases_stop_before_effects_without_valid_fresh_ha(tmp_path, phase, kind):
    output = "Node ID: 0\n IP: 127.0.0.1\n Master State: Secondary"
    status = 0
    if kind == "failed":
        status = 1
    elif kind == "wrong-ip":
        output = output.replace("127.0.0.1", "192.0.2.99")
    else:
        output = "unreadable"
    markers = tmp_path / "markers"
    env = _responses(tmp_path, {"match": "show ha node", "stdout": output, "exitcode": status})
    proc = _run(
        tmp_path, phase, seed_previous=True, extra_args=["-DriftGeaccepteerd"], markerdir=markers, extra_env=env
    )
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert rows[-1]["uitkomst"] == "poort dicht"
    assert not (markers / "writes.txt").exists()
    assert next(g for g in rows[-1]["poort"] if g["naam"] == "doel is secondary")["uitkomst"] == "niet beoordeeld"


@pytest.mark.parametrize("condition", ["low-space", "failed-df", "missing-sidecar", "bad-sidecar"])
def test_r1_stops_before_mkdir_and_upload_when_space_or_local_hash_is_bad(tmp_path, condition):
    firmware = _firmwaremap(tmp_path)
    env = {}
    sidecar = next(firmware.glob("*.sha256"))
    if condition == "missing-sidecar":
        sidecar.unlink()
    elif condition == "bad-sidecar":
        sidecar.write_text("f" * 64, encoding="ascii")
    else:
        env = _responses(
            tmp_path,
            {
                "match": "df -k",
                "stdout": "Filesystem 1K-blocks Used Avail Use% Mounted on\n/dev/x 10000000 100000 100 90% /var",
                "exitcode": 1 if condition == "failed-df" else 0,
            },
        )
    markers = tmp_path / "markers"
    proc = _run(
        tmp_path,
        "R1",
        seed_previous=True,
        extra_args=["-DriftGeaccepteerd"],
        firmwaremap=firmware,
        extra_env=env,
        markerdir=markers,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not (markers / "writes.txt").exists()


def test_r3_rechecks_role_after_successful_r2_and_refuses_failover(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    append_line(
        ledger,
        {
            "run": "test-run-1",
            "doel": "lab-02-test",
            "fase": "R1",
            "gebeurtenis": "fase_geslaagd",
            "uitkomst": "geslaagd",
        },
    )
    r2 = _run(tmp_path, "R2", ledger=ledger, markerdir=tmp_path / "r2-markers")
    assert r2.returncode == 0, r2.stdout + r2.stderr
    markers = tmp_path / "r3-markers"
    env = _responses(
        tmp_path,
        {"match": "show ha node", "stdout": "Node ID: 0\n IP: 127.0.0.1\n Master State: Primary", "exitcode": 0},
    )
    r3 = _run(tmp_path, "R3", ledger=ledger, markerdir=markers, extra_env=env)
    assert r3.returncode == 1, r3.stdout + r3.stderr
    assert not (markers / "writes.txt").exists()
    assert "show ha node" in (markers / "commands.txt").read_text()


@pytest.mark.parametrize(
    "status,stdout,expected", [(1, "", "niet beoordeeld"), (-1, "", "niet beoordeeld"), (0, "", "open")]
)
def test_r5_config_anchor_depends_on_successful_read_including_empty(tmp_path, status, stdout, expected):
    env = _responses(tmp_path, {"match": "show ns runningConfig", "stdout": stdout, "exitcode": status})
    proc = _run(tmp_path, "R5", extra_env=env)
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    gate = next(g for g in rows[-1]["poort"] if g["naam"] == "configuratie-anker")
    assert gate["uitkomst"] == expected, proc.stdout + proc.stderr
    if expected == "open":
        assert "leeg gelezen" in gate["bewijs"]
    else:
        assert "anker=" not in gate["bewijs"]


def test_real_adapter_preserves_df_ls_and_running_config_lines_end_to_end(tmp_path):
    import hashlib

    r1 = _run(tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"], ledger=tmp_path / "r1.jsonl")
    row = json.loads((tmp_path / "r1.jsonl").read_text().splitlines()[-1])
    gates = {g["naam"]: g for g in row["poort"]}
    assert gates["vrije ruimte op /var"]["uitkomst"] == "open", r1.stdout
    assert gates["buildboom staat er nog"]["uitkomst"] == "open", r1.stdout
    r5 = _run(tmp_path, "R5", seed_previous=True, ledger=tmp_path / "r5.jsonl")
    row = json.loads((tmp_path / "r5.jsonl").read_text().splitlines()[-1])
    gate = next(g for g in row["poort"] if g["naam"] == "configuratie-anker")
    expected = hashlib.sha256(b"add lb vserver example SSL 192.0.2.1 443\nset ns param -timezone GMT").hexdigest()
    assert expected in gate["bewijs"], r5.stdout


_CONFIGSTAND = Path(__file__).parent / "fixtures" / "configstand"


def _voorpoort_drift(ledger: Path) -> dict:
    rijen = [json.loads(r) for r in ledger.read_text(encoding="utf-8").splitlines() if r.strip()]
    voorpoort = next(r for r in rijen if r.get("gebeurtenis") == "voorpoort")
    return next(g for g in voorpoort["poort"] if g["naam"] == "drift afwezig of bewust geaccepteerd")


def test_r1_measures_the_config_state_and_closes_on_a_change_without_acceptance(tmp_path):
    """R1 reads `show ns config` in its own pre-write session. A change after
    the last save, without acceptance, closes the drift gate with the three
    choices - before mkdir or upload."""
    markers = tmp_path / "markers"
    env = _responses(
        tmp_path,
        {
            "match": "show ns config",
            "stdout": (_CONFIGSTAND / "show-ns-config-gewijzigd.txt").read_text(encoding="ascii"),
            "exitcode": 0,
        },
    )
    proc = _run(tmp_path, "R1", seed_previous=True, markerdir=markers, extra_env=env)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    poort = _voorpoort_drift(tmp_path / "ledger.jsonl")
    assert poort["uitkomst"] == "dicht"
    assert "config_opslaan" in poort["reden"]
    assert "show ns config" in (markers / "commands.txt").read_text()
    assert not (markers / "writes.txt").exists()


def test_r1_opens_the_drift_gate_on_evidence_after_a_save(tmp_path):
    env = _responses(
        tmp_path,
        {
            "match": "show ns config",
            "stdout": (_CONFIGSTAND / "show-ns-config-opgeslagen.txt").read_text(encoding="ascii"),
            "exitcode": 0,
        },
    )
    proc = _run(tmp_path, "R1", seed_previous=True, extra_env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    poort = _voorpoort_drift(tmp_path / "ledger.jsonl")
    assert (poort["type"], poort["uitkomst"]) == ("bewijs", "open")


def test_r1_drift_acceptance_opens_the_gate_as_a_human_decision_with_the_measured_state(tmp_path):
    proc = _run(tmp_path, "R1", seed_previous=True, extra_args=["-DriftGeaccepteerd"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    poort = _voorpoort_drift(tmp_path / "ledger.jsonl")
    assert (poort["type"], poort["uitkomst"]) == ("mens", "open")
    assert "gemeten stand" in poort["bewijs"]


def test_r1_measures_free_space_through_the_shared_transport_function():
    """One measuring path for /var: the runner's R1 and the separate read
    script call the same transport function; the runner keeps no df parse
    of its own."""
    tekst = SCRIPT.read_text(encoding="ascii")
    assert "Get-GjkVrijeRuimteVar -Sessie $sessie" in tekst
    assert "df -k" not in tekst
    assert "function Get-GjkVrijeRuimteVar" in TRANSPORT_ECHT.read_text(encoding="ascii")


def test_precheck_vendor_exit_is_not_verdict_but_result_read_exit_is_required(tmp_path):
    env = _responses(tmp_path, {"match": "./installns --pre_check", "stdout": "synthetic vendor status", "exitcode": 1})
    proc = _run(tmp_path, "R2", seed_previous=True, extra_env=env)
    row = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[-1])
    assert next(g for g in row["poort"] if g["naam"] == "vendor-precheck")["uitkomst"] == "open", proc.stdout


@pytest.mark.parametrize("phase", ["R1", "R2", "R3", "R4"])
@pytest.mark.parametrize("previous_outcome", [None, "poort_dicht"])
def test_missing_or_failed_previous_phase_prevents_all_writes(tmp_path, phase, previous_outcome):
    if previous_outcome:
        append_line(
            tmp_path / "ledger.jsonl",
            {
                "run": "test-run-1",
                "doel": "lab-02-test",
                "fase": "R" + str(int(phase[1:]) - 1),
                "gebeurtenis": previous_outcome,
                "uitkomst": "poort dicht",
            },
        )
    markers = tmp_path / "markers"
    proc = _run(tmp_path, phase, markerdir=markers, extra_args=["-DriftGeaccepteerd"])
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not (markers / "writes.txt").exists()


def test_r5_qualified_target_needs_no_local_firmware_file(tmp_path):
    firmware = tmp_path / "empty-firmware"
    firmware.mkdir()
    proc = _run(tmp_path, "R5", doelbuild="14.1-72.57", firmwaremap=firmware)
    row = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[-1])
    assert next(g for g in row["poort"] if g["naam"] == "doelbuild bereikt")["uitkomst"] == "open", proc.stdout


def test_r5_bare_target_without_unique_bundle_branch_is_not_assessed(tmp_path):
    firmware = tmp_path / "empty-firmware"
    firmware.mkdir()
    proc = _run(tmp_path, "R5", doelbuild="72.57", firmwaremap=firmware)
    row = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[-1])
    assert next(g for g in row["poort"] if g["naam"] == "doelbuild bereikt")["uitkomst"] == "niet beoordeeld", (
        proc.stdout
    )


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell 7 ontbreekt")
@pytest.mark.parametrize("phase", ["R1", "R2", "R3", "R4", "R5"])
def test_fresh_gate_and_array_adapter_pipeline_also_runs_on_powershell7(tmp_path, phase):
    proc = _run(
        tmp_path, phase, seed_previous=True, shell="pwsh", doelbuild="14.1-72.57", extra_args=["-DriftGeaccepteerd"]
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rows = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert rows[-1]["uitkomst"] == "geslaagd"


def test_r3_keeps_the_deciding_end_time_fragment_as_evidence():
    """The END_TIME gate's evidence is the DECIDING
    fragment itself - the last END_TIME line of installns, from the marker
    onward - never the head or the tail of the vendor's output. The run-8
    fixture (tests/fixtures/runner-ledger-lab-02-20260908) shows how a tail
    cut lost the very line the gate judged on. Pinned against the runner's
    source: the NEP transport of these tests does not run installns itself."""
    tekst = (Path(__file__).parent.parent / "scripts" / "Invoke-GjkUpgradeFase.ps1").read_text(encoding="utf-8")
    assert "-match 'END_TIME' } | Select-Object -Last 1" in tekst
    assert "bewijs = ('installns -Y -n; gemeten markerfragment: ' + $markerBewijs)" in tekst
    assert "bewijs_kant = 'kop'" in tekst
