"""Tests for `nsmcp.upgrade_measure` - the shaping/marker bridge the runner
(`Invoke-GjkUpgradeFase.ps1`) calls alongside `python -m nsmcp.upgrade_gate`.
Runs everywhere (no PowerShell, no
SSH, no Windows dependency) because every gate this module produces is a
Python function call - the same "elke poortuitspraak komt uit Python, niet
uit PowerShell" discipline `tests/test_upgrade.py` already proves for
`disk_gate`/`secondary_gate`/`hash_gate`/`precheck_gate`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from nsmcp import upgrade_measure
from nsmcp.export import load_export
from nsmcp.upgrade import (
    FAMILIES,
    backup_register_gate,
    build_tree_gate,
    export_age_gate,
    family_counts_gate,
    hostkey_session_gate,
    read_ledger,
    rollback_point_evidence,
)

FIXTURES = Path(__file__).parent / "fixtures"
# The same small, synthetic, hash-verified export `tests/test_preflight.py`
# already uses (`config/systemfile` under /var/nsinstall, a real
# collectedAtUtc, a real running config) - reused here rather than a second
# fixture: R0's export-sourced gates read exactly the same sources check 9
# already reads.
EXPORT_FIXTURE = FIXTURES / "preflight-export"
# De R0-fixture DRAAGT wel de acht families, plus de
# backup, de buildboom en een running config - de positieve R0-kant kan
# daarmee voor het eerst tegen een export die echt een voormeting oplevert.
# `preflight-export` blijft in gebruik voor de LEESGAT-kant (nul families).
R0_EXPORT_FIXTURE = FIXTURES / "r0-export"

# Een gepinde vingerafdruk, zoals de runner er een meegeeft. Geen echte doos,
# geen secret - een vingerafdruk is publiek.
PIN = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"


# ---------- hostkey_gate ----------


def test_hostkey_gate_opens_on_a_matching_fingerprint():
    poort = upgrade_measure.hostkey_gate("AA:BB:CC", "aa:bb:cc")
    assert poort.outcome == "open"


def test_hostkey_gate_closes_on_a_differing_fingerprint_with_the_pinned_reason():
    poort = upgrade_measure.hostkey_gate("AA:BB:CC", "11:22:33")
    assert poort.outcome == "dicht"
    assert poort.reason == "hostsleutel wijkt af"


def test_hostkey_gate_closes_when_nothing_was_pinned():
    poort = upgrade_measure.hostkey_gate("AA:BB:CC", None)
    assert poort.outcome == "dicht"


def test_hostkey_gate_is_not_assessed_when_no_key_was_ever_measured():
    poort = upgrade_measure.hostkey_gate(None, "AA:BB:CC")
    assert poort.outcome == "niet beoordeeld"


def test_hostkey_gate_never_writes_a_bare_expected_value_as_open_by_accident():
    """A caller that forgets -Vingerafdruk cannot silently sail through: an
    empty string on either side is treated as missing, not as a match."""
    assert upgrade_measure.hostkey_gate("", "").outcome == "dicht"


# ---------- presence_gate ----------


def test_presence_gate_opens_when_present():
    poort = upgrade_measure.presence_gate("backupobject aanwezig", "bewijs", True, "gevonden in show system backup", "")
    assert poort.outcome == "open"


def test_presence_gate_closes_with_the_supplied_reason_when_absent():
    poort = upgrade_measure.presence_gate(
        "backupobject aanwezig", "bewijs", False, "niet gevonden", "geen backupregel voor dit doel"
    )
    assert poort.outcome == "dicht"
    assert poort.reason == "geen backupregel voor dit doel"


def test_presence_gate_rejects_an_unknown_gate_type():
    with pytest.raises(ValueError):
        upgrade_measure.presence_gate("iets", "onbekend-type", True, "", "")


def test_presence_gate_bounds_untrusted_evidence_in_python():
    """`presence_gate` is fed raw appliance/export text
    (R1's `ls -la <buildboom>`, R5's `show ns version`) and used to pass it
    through unfiltered. Bounded here, once - never hand-truncated in
    PowerShell for one caller only (R3's old `.Substring(...)`, DRY)."""
    lang = "x" * 500
    poort = upgrade_measure.presence_gate("iets", "bewijs", True, lang, "")
    assert len(poort.evidence) < 500
    assert poort.evidence.endswith("...(afgekapt)")


# ---------- anchor_evidence_gate ----------


def test_anchor_evidence_gate_is_always_open_and_carries_the_hash():
    poort = upgrade_measure.anchor_evidence_gate(["add lb vserver x", "# comment", ""])
    assert poort.outcome == "open"
    assert "anker=" in poort.evidence


# ---------- hostkey_session_gate ----------


def test_hostkey_session_gate_opens_when_the_session_opened():
    poort = hostkey_session_gate(True, False, "", PIN)
    assert poort.outcome == "open"
    assert poort.name == "hostsleutel gepind"


def test_hostkey_session_gate_never_claims_a_python_side_comparison_it_never_made():
    """De regressie zelf: de oude wiring vergeleek `gemeten == verwacht` met
    hetzelfde argument aan beide kanten. Deze poort mag dat woord niet meer
    beweren."""
    poort = hostkey_session_gate(True, False, "", PIN)
    assert "onafhankelijke" in poort.evidence or "-ErrorOnUntrusted" in poort.evidence


def test_hostkey_session_gate_closes_with_the_pinned_reason_on_a_real_mismatch():
    poort = hostkey_session_gate(False, True, "hostsleutel wijkt af: nep-doos", PIN)
    assert poort.outcome == "dicht"
    assert poort.reason == "hostsleutel wijkt af"


def test_hostkey_session_gate_is_not_assessed_on_a_non_host_key_failure():
    """Een timeout/verkeerd wachtwoord/host-down is GEEN
    hostsleutelfout en mag nooit als zodanig gemeld worden."""
    poort = hostkey_session_gate(False, False, "time-out na 30s", PIN)
    assert poort.outcome == "niet beoordeeld"
    assert poort.reason != "hostsleutel wijkt af"
    assert "hostsleutel wijkt af" not in poort.reason


# ---------- backup_register_gate ----------


def test_backup_register_gate_is_not_assessed_when_the_register_could_not_be_read():
    poort = backup_register_gate(None, "lab-02")
    assert poort.outcome == "niet beoordeeld"


def test_backup_register_gate_closes_when_the_register_carries_no_matching_row():
    regels = [{"tool": "onderhoud_backup_maken", "doel": "een-ander-doel", "uitkomst": "geslaagd", "actieid": "a-1"}]
    poort = backup_register_gate(regels, "lab-02")
    assert poort.outcome == "dicht"


def test_backup_register_gate_closes_on_a_failed_backup_attempt():
    regels = [{"tool": "onderhoud_backup_maken", "doel": "lab-02", "uitkomst": "mislukt", "actieid": "a-1"}]
    poort = backup_register_gate(regels, "lab-02")
    assert poort.outcome == "dicht"


def test_backup_register_gate_opens_on_a_succeeded_row_for_this_target():
    regels = [
        {"tool": "iets-anders", "doel": "lab-02", "uitkomst": "geslaagd"},
        {"tool": "onderhoud_backup_maken", "doel": "LAB-02 ", "uitkomst": "geslaagd", "actieid": "upgrade-R0-x"},
    ]
    poort = backup_register_gate(regels, "lab-02")
    assert poort.outcome == "open"
    assert "upgrade-R0-x" in poort.evidence


# ---------- build_tree_gate / export_age_gate / family_counts_gate ----------
# (R0's export-sourced gates, against the real,
# hash-verified fixture `tests/fixtures/preflight-export/`.)


def test_build_tree_gate_is_not_assessed_without_an_export():
    assert build_tree_gate(None).outcome == "niet beoordeeld"


def test_build_tree_gate_opens_on_the_real_fixture():
    export = load_export(EXPORT_FIXTURE)
    poort = build_tree_gate(export)
    assert poort.outcome == "open"
    assert "build-14.1-64.19_nc_64" in poort.evidence


def test_export_age_gate_is_not_assessed_without_an_export():
    assert export_age_gate(None).outcome == "niet beoordeeld"


def test_export_age_gate_opens_and_names_the_age_on_the_real_fixture():
    export = load_export(EXPORT_FIXTURE)
    poort = export_age_gate(export)
    assert poort.outcome == "open"
    assert "dag" in poort.evidence


def test_family_counts_gate_is_not_assessed_without_an_export():
    assert family_counts_gate(None).outcome == "niet beoordeeld"


def test_family_counts_gate_is_not_assessed_when_no_family_could_be_read():
    """Deze test pinde het VERKEERDE gedrag.

    `preflight-export` draagt geen enkele van de acht families. Dat leverde
    `open` op met het bewijs "geen enkele familie leesbaar" - en omdat
    `order_gate` R0 onvoorwaardelijk doorlaat (R0 heeft geen voorganger),
    sloot R0 daarmee `geslaagd`/`voormeting_vast` met een LEGE voormeting.
    Precies waar R5 straks tegen afgezet moet worden. Een poort die een
    oordeel opschrijft dat ze niet gemeten heeft: `niet beoordeeld`, en de
    reden noemt dat er niets leesbaar was."""
    export = load_export(EXPORT_FIXTURE)
    poort = family_counts_gate(export)
    assert poort.outcome == "niet beoordeeld"
    assert "geen enkele familie leesbaar" in poort.evidence
    assert "geen enkele van de 8 families is uit deze export gelezen" in poort.reason
    assert "onleesbaar" in poort.evidence


def test_family_counts_gate_opens_on_an_export_that_really_carries_families():
    """De positieve kant, tegen een fixture die de acht families ECHT draagt -
    inclusief twee families die legitiem NUL objecten hebben. Een echte nul en
    een ongelezen familie zijn verschillende uitspraken: deze telt er acht."""
    export = load_export(R0_EXPORT_FIXTURE)
    poort = family_counts_gate(export)
    assert poort.outcome == "open"
    assert "onleesbaar" not in poort.evidence
    for familie in FAMILIES:
        assert f"{familie}=" in poort.evidence, familie
    # de twee legitiem lege families staan er als een echte nul in
    assert "vpnvserver=0" in poort.evidence
    assert "lbvserver=2" in poort.evidence


# ---------- _vorm / "actie": "vorm" ----------


def test_vorm_shapes_disk_gate_from_raw_fields():
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "schijfruimte", "vrij_mb": 9000, "bundel_mb": 1081, "uitpak_mb": 1673}],
            }
        )
    )
    assert code == 0
    assert uitvoer["poort"][0]["naam"] == "vrije ruimte op /var"
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_passes_bundle_al_aanwezig_through_to_disk_gate():
    """R1's upload-skip stuurt bundel_al_aanwezig
    mee in het schijfruimte-live-verzoek, met de GEMETEN bundelgrootte
    gewoon aanwezig (nooit een verzonnen 0) - disk_gate leest die term dan
    als een BEWUSTE nul, niet als ongemeten, en het bewijs zegt dat met
    zoveel woorden in plaats van een aangenomen grootte te claimen."""
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "schijfruimte-live",
                        "vrij_mb": 6200,
                        "bundel_mb": 1097,
                        "uitpak_mb": 1673,
                        "exitcode": 0,
                        "bundel_al_aanwezig": True,
                    }
                ],
            }
        )
    )
    assert code == 0
    poort = uitvoer["poort"][0]
    assert poort["uitkomst"] == "open"
    assert "aangenomen bundelgrootte" not in poort["bewijs"]
    assert "0 MB nog te ontvangen" in poort["bewijs"]


def test_vorm_shapes_secondary_gate_from_raw_ssh_output():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "secondary",
                        "exitcode": 0,
                        "doel_adres": "127.0.0.1",
                        "ha_node_uitvoer": "Node ID: 0\n IP: 127.0.0.1\n Master State: Secondary\n",
                    }
                ],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "open"
    assert uitvoer["poort"][0]["naam"] == "doel is secondary"


def test_vorm_shapes_firmware_hash_gate():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "firmware-hash", "vendor_sha": "aa", "doos_sha": "bb"}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "dicht"


def test_vorm_shapes_the_firmware_hash_gate_on_the_local_hash_too():
    def vorm(**verzoek):
        uitvoer, _ = upgrade_measure.main(
            json.dumps({"actie": "vorm", "verzoeken": [{"soort": "firmware-hash", **verzoek}]})
        )
        return uitvoer["poort"][0]["uitkomst"]

    assert vorm(vendor_sha="aa", doos_sha="aa", lokale_sha="aa") == "open"
    assert vorm(vendor_sha="aa", doos_sha="aa", lokale_sha="bb") == "dicht"
    assert vorm(vendor_sha="aa", doos_sha="aa") == "dicht", "zonder lokale hash geen open firmware-hash"


def test_vorm_shapes_vendor_precheck_gate_and_ignores_no_exit_code_field():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {"soort": "vendor-precheck", "precheck_json": json.dumps({"global_status": "done", "checks": []})}
                ],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_shapes_hostkey_gate_open_when_the_session_opened():
    """The runner feeds `sessie_geopend`, never a
    fingerprint pair that only ever equals itself."""
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "hostsleutel", "sessie_geopend": True, "gepinde_vingerafdruk": PIN}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "open"
    assert uitvoer["poort"][0]["naam"] == "hostsleutel gepind"


def test_vorm_shapes_hostkey_gate_closed_on_a_real_mismatch():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "hostsleutel",
                        "sessie_geopend": False,
                        "gepinde_vingerafdruk": PIN,
                        "hostsleutelfout": True,
                        "foutmelding": "hostsleutel wijkt af: nep",
                    }
                ],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "dicht"
    assert uitvoer["poort"][0]["reden"] == "hostsleutel wijkt af"


def test_vorm_shapes_hostkey_gate_not_assessed_on_a_non_host_key_connection_failure():
    """A connection failure that is NOT a host-key
    mismatch must never be reported with the pinned reason."""
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "hostsleutel",
                        "sessie_geopend": False,
                        "gepinde_vingerafdruk": PIN,
                        "hostsleutelfout": False,
                        "foutmelding": "time-out na 30s",
                    }
                ],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"
    assert uitvoer["poort"][0]["reden"] != "hostsleutel wijkt af"


def test_vorm_shapes_multiple_requests_in_order():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {"soort": "hostsleutel", "sessie_geopend": True, "gepinde_vingerafdruk": PIN},
                    {"soort": "secondary", "ha_node_uitvoer": "Master State: Primary"},
                ],
            }
        )
    )
    namen = [p["naam"] for p in uitvoer["poort"]]
    assert namen == ["hostsleutel gepind", "doel is secondary"]


def test_vorm_with_an_empty_request_list_shapes_nothing():
    uitvoer, code = upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": []}))
    assert code == 0
    assert uitvoer["poort"] == []


def test_vorm_rejects_an_unknown_soort():
    with pytest.raises(ValueError):
        upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": [{"soort": "onbekend"}]}))


def test_vorm_requires_verzoeken_to_be_a_list():
    with pytest.raises(ValueError):
        upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": "niet een lijst"}))


# ---------- "vorm" - R0's nieuwe soorten ----------


def test_vorm_shapes_backupregister_gate_from_a_real_register_file(tmp_path):
    register = tmp_path / "actieregister.jsonl"
    register.write_text(
        json.dumps({"tool": "onderhoud_backup_maken", "doel": "lab-02", "uitkomst": "geslaagd", "actieid": "a-9"})
        + "\n",
        encoding="utf-8",
    )
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "backupregister", "pad": str(register), "doel": "lab-02"}],
            }
        )
    )
    assert code == 0
    assert uitvoer["poort"][0]["naam"] == "backupobject aanwezig"
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_shapes_backupregister_gate_not_assessed_without_a_path():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "backupregister", "pad": "", "doel": "lab-02"}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"


def test_vorm_shapes_export_buildboom_gate_from_the_real_fixture():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "export-buildboom", "export_root": str(EXPORT_FIXTURE)}],
            }
        )
    )
    assert uitvoer["poort"][0]["naam"] == "vorige buildboom aanwezig"
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_shapes_export_leeftijd_gate_from_the_real_fixture():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "export-leeftijd", "export_root": str(EXPORT_FIXTURE)}],
            }
        )
    )
    assert uitvoer["poort"][0]["naam"] == "leeftijd van de export"
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_shapes_familietellingen_gate_from_the_real_fixture():
    """Tegen de fixture die de families ECHT draagt.
    De oude versie wees naar `preflight-export` (nul families) en pinde daar
    `open` op - de bevinding zelf."""
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "familietellingen", "export_root": str(R0_EXPORT_FIXTURE)}],
            }
        )
    )
    assert uitvoer["poort"][0]["naam"] == "familietellingen"
    assert uitvoer["poort"][0]["uitkomst"] == "open"


def test_vorm_shapes_familietellingen_not_assessed_on_an_export_without_families():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "familietellingen", "export_root": str(EXPORT_FIXTURE)}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"


def test_vorm_shapes_configuratie_anker_export_gate_from_the_real_fixture():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "configuratie-anker-export", "export_root": str(EXPORT_FIXTURE)}],
            }
        )
    )
    assert uitvoer["poort"][0]["naam"] == "configuratie-anker"
    assert uitvoer["poort"][0]["uitkomst"] == "open"
    assert "anker=" in uitvoer["poort"][0]["bewijs"]


def test_vorm_shapes_configuratie_anker_export_gate_not_assessed_without_a_path():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "configuratie-anker-export", "export_root": ""}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"


def test_vorm_shapes_export_gates_not_assessed_on_a_nonexistent_export_root(tmp_path):
    """Een pad dat niet bestaat mag nooit als 'dicht' of 'open' terugkomen -
    dat zou een export SUGGEREREN die er niet is."""
    nergens = tmp_path / "bestaat-niet"
    for soort, naam in (
        ("export-buildboom", "vorige buildboom aanwezig"),
        ("export-leeftijd", "leeftijd van de export"),
        ("familietellingen", "familietellingen"),
    ):
        uitvoer, _ = upgrade_measure.main(
            json.dumps(
                {
                    "actie": "vorm",
                    "verzoeken": [{"soort": soort, "export_root": str(nergens)}],
                }
            )
        )
        assert uitvoer["poort"][0]["naam"] == naam
        assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"


# ---------- _start / "actie": "start" ----------


def test_start_writes_exactly_one_fase_gestart_row(tmp_path):
    ledger = tmp_path / "r1.jsonl"
    regel, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "start",
                "run": "r1",
                "doel": "lab-02",
                "fase": "R1",
                "actieid": "a-1",
                "bevestiger": "u-1",
                "gestart": "2026-09-06T00:00:00Z",
                "ledger": str(ledger),
            }
        )
    )
    assert code == 0
    assert regel["gebeurtenis"] == "fase_gestart"
    assert regel["uitkomst"] == "gestart"
    assert regel["poort"] == []
    assert regel["geeindigd"] is None
    opgeslagen = read_ledger(ledger)
    assert len(opgeslagen) == 1
    assert opgeslagen[0] == regel


def test_start_never_writes_a_poort_or_a_closing_event(tmp_path):
    """A 'fase_gestart' row must never be mistaken for a judged phase:
    `phase_state()` (nsmcp.upgrade) reads exactly this shape as 'gestart',
    never as a closing outcome."""
    ledger = tmp_path / "r1.jsonl"
    regel, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "start",
                "run": "r1",
                "doel": "lab-02",
                "fase": "R1",
                "ledger": str(ledger),
            }
        )
    )
    from nsmcp.upgrade import phase_state

    assert phase_state((regel,), "R1") == "gestart"


def test_start_records_the_target_build_the_phase_started_with(tmp_path):
    """The run binding: R1..R6 compare the bundle of THEIR start with the
    one R0 of the same run started with, so the start row carries it.

    Each of the three starts writes into a ledger directory of its own:
    `start` refuses a second `fase_gestart` on a target that still carries
    an open phase within its time limit, and all three would be the same
    target in one directory."""

    def basis(naam: str) -> dict:
        (tmp_path / naam).mkdir()
        return {
            "actie": "start",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R0",
            "ledger": str(tmp_path / naam / "r1.jsonl"),
        }

    met = basis("met")
    regel, code = upgrade_measure.main(json.dumps(dict(met, doelbuild="14.1-72.57")))
    assert code == 0
    assert regel["doelbuild"] == "14.1-72.57"
    assert read_ledger(met["ledger"])[0]["doelbuild"] == "14.1-72.57"
    zonder, _ = upgrade_measure.main(json.dumps(basis("zonder")))
    assert zonder["doelbuild"] is None
    vreemd, _ = upgrade_measure.main(json.dumps(dict(basis("vreemd"), doelbuild=["14.1-72.57"])))
    assert vreemd["doelbuild"] is None


def test_start_requires_run_doel_fase_and_ledger():
    with pytest.raises(ValueError):
        upgrade_measure.main(json.dumps({"actie": "start", "run": "r1"}))


# ---------- "start" on a target that already carries an open phase ----------


def _start_via_run(invoer: dict) -> int:
    """`upgrade_measure.run()` on `invoer`, the way the runner calls it: the
    exit code is what the runner acts on."""
    import io

    real_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(json.dumps(invoer))
        return upgrade_measure.run()
    finally:
        sys.stdin = real_stdin


def _started(ledgermap: Path) -> list[dict]:
    return [
        regel
        for bestand in sorted(ledgermap.glob("*.jsonl"))
        for regel in read_ledger(bestand)
        if regel.get("gebeurtenis") == "fase_gestart"
    ]


def test_start_refuses_with_exit_2_while_the_target_carries_an_open_phase_within_its_limit(tmp_path, capsys):
    """The one writer of `fase_gestart` excludes a second runner by itself:
    a start on a target whose ledger directory already carries a
    `fase_gestart` without a closing row, within that phase's time limit,
    is refused with exit 2 - for the same run and phase (a slow first runner
    and a second one behind it) and for another run on the same target
    alike. Nothing is written; the runner turns exit 2 into its own
    [FOUT]/[GEWEIGERD] lines and stops before any transport."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    eerste = {
        "actie": "start",
        "run": "run-a",
        "doel": "lab-02",
        "fase": "R1",
        "ledger": str(ledgermap / "run-a.jsonl"),
    }
    assert _start_via_run(eerste) == 0
    capsys.readouterr()

    assert _start_via_run(dict(eerste, actieid="tweede-runner")) == 2
    fout = capsys.readouterr().err
    assert "[GEWEIGERD]" in fout
    assert "er staat op dit doel al een fase open" in fout
    assert "fase R1" in fout

    ander = dict(eerste, run="run-b", fase="R0", ledger=str(ledgermap / "run-b.jsonl"))
    assert _start_via_run(ander) == 2
    assert len(_started(ledgermap)) == 1

    # Another target in the same directory is not held by it.
    elders = dict(eerste, doel="lab-03", run="run-c", ledger=str(ledgermap / "run-c.jsonl"))
    assert _start_via_run(elders) == 0


def test_start_lets_a_retry_through_after_a_closing_row_or_past_the_time_limit(tmp_path):
    """The legitimate retries stay open: a phase with a closing row, or a
    `fase_gestart` older than its time limit, does not block (the same
    `blocking_phase()` rule the server applies)."""
    from nsmcp.upgrade import append_line

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    gesloten = ledgermap / "run-a.jsonl"
    basis = {"run": "run-a", "doel": "lab-02", "fase": "R1", "poort": [], "bewijs": "test"}
    append_line(gesloten, dict(basis, tijd="2026-09-30T10:00:00Z", gebeurtenis="fase_gestart", uitkomst="gestart"))
    append_line(gesloten, dict(basis, tijd="2026-09-30T10:05:00Z", gebeurtenis="fase_mislukt", uitkomst="mislukt"))
    assert (
        _start_via_run(
            {"actie": "start", "run": "run-b", "doel": "lab-02", "fase": "R0", "ledger": str(ledgermap / "run-b.jsonl")}
        )
        == 0
    )

    verlopen = tmp_path / "ledger-verlopen"
    verlopen.mkdir()
    append_line(
        verlopen / "run-x.jsonl",
        dict(basis, run="run-x", tijd="2020-01-01T00:00:00Z", gebeurtenis="fase_gestart", uitkomst="gestart"),
    )
    assert (
        _start_via_run(
            {"actie": "start", "run": "run-x", "doel": "lab-02", "fase": "R1", "ledger": str(verlopen / "run-x.jsonl")}
        )
        == 0
    )


def test_start_refuses_when_the_ledger_directory_cannot_be_read(tmp_path, capsys):
    """Fail-closed like the server: a ledger directory that does not exist
    is not an empty one, so the start is refused rather than written."""
    missing = tmp_path / "bestaat-niet"
    assert (
        _start_via_run(
            {"actie": "start", "run": "r1", "doel": "lab-02", "fase": "R1", "ledger": str(missing / "r1.jsonl")}
        )
        == 2
    )
    assert "[GEWEIGERD]" in capsys.readouterr().err
    assert not missing.exists()


# ---------- unknown actie / unreadable stdin ----------


def test_an_unknown_actie_is_rejected():
    with pytest.raises(ValueError):
        upgrade_measure.main(json.dumps({"actie": "iets-anders"}))


def test_run_exits_2_on_unreadable_json(capsys):
    import io

    real_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO("{niet json")
        code = upgrade_measure.run()
    finally:
        sys.stdin = real_stdin
    assert code == 2


# ---------- the real CLI process ----------


def _run_cli(invoer: str, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "nsmcp.upgrade_measure"],
        input=invoer,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_cli_vorm_round_trips_through_a_real_process():
    proc = _run_cli(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "hostsleutel",
                        "sessie_geopend": False,
                        "gepinde_vingerafdruk": PIN,
                        "hostsleutelfout": True,
                        "foutmelding": "hostsleutel wijkt af: nep",
                    }
                ],
            }
        )
    )
    assert proc.returncode == 0, proc.stderr
    uitvoer = json.loads(proc.stdout)
    assert uitvoer["poort"][0]["uitkomst"] == "dicht"


def test_cli_start_round_trips_through_a_real_process(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    proc = _run_cli(
        json.dumps(
            {
                "actie": "start",
                "run": "r0",
                "doel": "lab-02",
                "fase": "R0",
                "ledger": str(ledger),
            }
        )
    )
    assert proc.returncode == 0, proc.stderr
    assert read_ledger(ledger)[0]["gebeurtenis"] == "fase_gestart"


def test_cli_exits_2_and_never_prints_a_traceback_on_garbage_stdin():
    proc = _run_cli("dit is geen json")
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr


def test_cli_never_prints_a_secret_placeholder_word():
    """Nothing this module handles is a credential, but the invariant this
    whole feature is built around is pinned here too: no run of this CLI,
    on any input, may ever mention a password/secret literally."""
    for invoer in (
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "hostsleutel",
                        "sessie_geopend": False,
                        "hostsleutelfout": False,
                        "foutmelding": "x",
                    }
                ],
            }
        ),
        "garbage",
    ):
        proc = _run_cli(invoer)
        laag = (proc.stdout + proc.stderr).lower()
        assert "wachtwoord" not in laag and "password" not in laag


# ---------------------------------------------------------------------------
# R0's EXTRA bewijsregel `terugrolpunt_vast`
# ---------------------------------------------------------------------------


def _r0_register(pad: Path, *, objectnaam="gjk_preupgrade_lab-02-test_20260906_071500") -> Path:
    rij = {
        "tool": "onderhoud_backup_maken",
        "doel": "lab-02-test",
        "uitkomst": "geslaagd",
        "actieid": "a-9",
    }
    if objectnaam is not None:
        rij["objectnaam"] = objectnaam
    pad.write_text(json.dumps(rij) + "\n", encoding="utf-8")
    return pad


def test_the_rollback_point_evidence_names_all_six_components():
    """Ontwerp 3.5 noemt er zes met naam: backupnaam, grootte, tijd, het pad
    van de vorige buildboom, de leeftijd van de export waaruit dat pad komt,
    en de snapshotverwijzing letterlijk."""
    export = load_export(R0_EXPORT_FIXTURE)
    regels = [
        {
            "tool": "onderhoud_backup_maken",
            "doel": "lab-02-test",
            "uitkomst": "geslaagd",
            "actieid": "a-9",
            "objectnaam": "gjk_preupgrade_lab-02-test_20260906_071500",
        }
    ]
    bewijs = rollback_point_evidence(regels, export, "hv-snap-20260907-1", "lab-02-test")
    assert "gjk_preupgrade_lab-02-test_20260906_071500" in bewijs  # 1 naam
    assert "812 MB" in bewijs  # 2 grootte
    assert "Sun Sep  6 07:15:00 2026" in bewijs  # 3 tijd
    assert "/var/nsinstall/build-14.1-66.59_nc_64" in bewijs  # 4 pad
    assert "dag(en) oud" in bewijs  # 5 leeftijd
    assert "hv-snap-20260907-1" in bewijs  # 6 snapshot
    assert "niet gelezen" not in bewijs


def test_the_rollback_point_evidence_shows_kb_with_one_decimal_under_1_mb():
    """Design row A3: gemeten - een backup van 4855 bytes rondde af op
    "0 MB", een uitspraak die eenvoudigweg onwaar is (er IS een backup).
    Onder 1 MB toont dit nu KB met een decimaal, nooit "0 MB".

    De 4855 bytes zijn geen testsample uit deze hand: het is het BEWIJS op
    schijf, `tests/fixtures/a14-export/objects/systembackup.json` - dezelfde
    gemeten export die test_cve.py en test_parity_nshc.py al "het echte
    export" noemen."""
    export = load_export(FIXTURES / "a14-export")
    regels = [
        {
            "tool": "onderhoud_backup_maken",
            "doel": "lab-02-test",
            "uitkomst": "geslaagd",
            "actieid": "a-9",
            "objectnaam": "gjk_pre_72_57_20260906_105247",
        }
    ]
    bewijs = rollback_point_evidence(regels, export, "hv-snap-20260907-1", "lab-02-test")
    assert "4,7 KB" in bewijs
    assert "0 MB" not in bewijs
    assert " MB" not in bewijs


def test_a_negative_backup_size_is_niet_gelezen_not_a_negative_kb():
    """Een negatieve `size` uit de (onvertrouwde)
    export gaf "-0,0 KB" - was voor de A3-fix "0 MB" - allebei een
    bewering die niet klopt met een echte, positieve backup. Een export
    die zoiets teruggeeft is niet te vertrouwen op dit veld: dat is een
    leesgat, geen "0 MB"/"-0,0 KB"-cijfer."""
    from nsmcp.upgrade import _backup_size_and_time

    class _NepExport:
        def objects(self, resource):
            return [{"filename": "gjk_neg.tgz", "size": "-1000", "creationtime": "Sun Sep  6 10:52:47 2026"}], None

    grootte, tijd = _backup_size_and_time(_NepExport(), "gjk_neg")
    assert grootte == "niet gelezen"
    assert tijd == "Sun Sep  6 10:52:47 2026"


def test_the_rollback_point_evidence_says_niet_gelezen_instead_of_omitting():
    """Een component die niet te lezen is wordt GENOEMD, niet weggelaten - een
    terugrolpunt zonder grootte is een andere uitspraak dan een terugrolpunt
    dat de grootte nooit ter sprake brengt."""
    bewijs = rollback_point_evidence(None, None, "", "lab-02-test")
    assert bewijs.count("niet gelezen") == 6
    for kop in ("backup ", "grootte ", "tijd ", "vorige buildboom ", "snapshotverwijzing "):
        assert kop in bewijs, kop


def test_the_rollback_point_backup_size_comes_from_the_collection_not_a_get_by_name():
    """Het mechanisme: de naam komt uit de argumentlijst die het product
    vormde (hier: het actieregister), grootte en tijd uit de COLLECTIE
    config/systembackup. Een register zonder objectnaam kan dus niets in die
    collectie opzoeken - en zegt dat, in plaats van de eerste de beste rij te
    pakken."""
    export = load_export(R0_EXPORT_FIXTURE)
    zonder_naam = [{"tool": "onderhoud_backup_maken", "doel": "lab-02-test", "uitkomst": "geslaagd"}]
    bewijs = rollback_point_evidence(zonder_naam, export, "snap-x", "lab-02-test")
    assert "backup niet gelezen" in bewijs
    assert "grootte niet gelezen" in bewijs
    assert "812 MB" not in bewijs
    # het pad en de leeftijd komen uit dezelfde export en zijn WEL leesbaar
    assert "/var/nsinstall/build-14.1-66.59_nc_64" in bewijs


def test_the_terugrolpunt_action_writes_one_evidence_row_that_closes_nothing(tmp_path):
    from nsmcp.upgrade import phase_state

    ledger = tmp_path / "ledger.jsonl"
    register = _r0_register(tmp_path / "reg.jsonl")
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "terugrolpunt",
                "run": "r-1",
                "doel": "lab-02-test",
                "ledger": str(ledger),
                "actieid": "a-9",
                "bevestiger": "u-1",
                "gestart": "2026-09-07T08:00:00Z",
                "actieregister": str(register),
                "export_root": str(R0_EXPORT_FIXTURE),
                "snapshotverwijzing": "hv-snap-1",
                "poort": [
                    {
                        "naam": "backupobject aanwezig",
                        "type": "bewijs",
                        "uitkomst": "open",
                        "bewijs": "actieregister: ...",
                        "reden": "",
                    }
                ],
            }
        )
    )
    assert code == 0
    regels = [json.loads(r) for r in ledger.read_text(encoding="utf-8").splitlines() if r.strip()]
    assert len(regels) == 1
    assert regels[0]["gebeurtenis"] == "terugrolpunt_vast"
    assert regels[0]["uitkomst"] == "gestart"
    assert regels[0]["geeindigd"] is None
    assert regels[0]["fase"] == "R0"
    assert uitvoer == regels[0]
    # sluit NIETS: een bewijsregel is geen toestandsregel
    assert phase_state(regels, "R0") == "niet beoordeeld"


def test_the_terugrolpunt_action_fails_closed_on_a_missing_field():
    with pytest.raises(Exception):  # noqa: B017 - fails-closed is the property under test, not a specific type
        upgrade_measure.main(json.dumps({"actie": "terugrolpunt", "run": "r-1"}))


def test_the_terugrolpunt_action_bounds_gates_built_from_stdin_too(tmp_path):
    """The IDENTICAL construction in
    `upgrade_gate._gates_from_measurements()` was hardened against
    unbounded stdin (see `test_the_judging_half_re_bounds_a_gate_that_
    arrives_through_stdin` above) - this one, building the SAME `poort`
    shape for the `terugrolpunt_vast` row, was not. Everything on stdin is
    UNTRUSTED, whichever action reads it."""
    ledger = tmp_path / "ledger.jsonl"
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "terugrolpunt",
                "run": "r-1",
                "doel": "lab-02-test",
                "ledger": str(ledger),
                "poort": [
                    {
                        "naam": "n" * 500,
                        "type": "bewijs",
                        "uitkomst": "dicht",
                        "bewijs": "b" * 5000,
                        "reden": "r" * 5000,
                    }
                ],
            }
        )
    )
    assert code == 0
    poort = uitvoer["poort"][0]
    assert len(poort["naam"]) < 200
    assert len(poort["bewijs"]) < 1100
    assert len(poort["reden"]) < 1100


# ---------------------------------------------------------------------------
# Begrenzing
# ---------------------------------------------------------------------------


def test_presence_gate_keeps_the_tail_when_the_deciding_fact_is_last():
    """END_TIME staat ACHTERAAN installns' uitvoer. Een kop-afkapping
    zou het ledgerbewijs laten eindigen voor het feit waarop geoordeeld is."""
    from nsmcp.upgrade import presence_gate

    lang = "voortgang " * 200 + "END_TIME Sun Sep  6 09:12:00 2026"
    kop = presence_gate("x", "bewijs", True, lang, "n.v.t.")
    staart = presence_gate("x", "bewijs", True, lang, "n.v.t.", "staart")
    assert "END_TIME" not in kop.evidence
    assert "END_TIME" in staart.evidence
    assert staart.evidence.startswith("(afgekapt)...")
    assert len(staart.evidence) < len(lang)


def test_presence_gate_refuses_an_unknown_truncation_side():
    from nsmcp.upgrade import presence_gate

    with pytest.raises(ValueError):
        presence_gate("x", "bewijs", True, "a", "n.v.t.", "midden")


def test_build_tree_gate_bounds_the_count_of_names_not_just_each_name():
    """`_bounded` per naam begrensde elke naam maar niet HOEVEEL er
    waren. Een export met honderden build-* rijen schreef zo alsnog een
    onbegrensde bewijsstring in het ledger."""
    from nsmcp.upgrade import build_tree_gate

    class NepExport:
        def objects(self, resource):
            return (
                [
                    {"filelocation": "/var/nsinstall", "filename": f"build-14.{n}-1.0_nc_64", "filemode": "DIRECTORY"}
                    for n in range(400)
                ],
                None,
            )

    poort = build_tree_gate(NepExport())
    assert poort.outcome == "open"
    assert len(poort.evidence) < 1000
    assert "400 buildbo(o)m(en)" in poort.evidence
    # de TELLING wordt genoemd, de lijst zelf is begrensd (op het aantal EN op
    # de lengte) - niet 400 namen in een ledgerregel
    assert poort.evidence.count("build-14.") <= 20
    assert poort.evidence.endswith("...(afgekapt)")


def test_the_judging_half_re_bounds_a_gate_that_arrives_through_stdin():
    """Tweede helft: `upgrade_gate` begrensde zelf niets bij het
    samenvoegen. Alles op stdin is UNTRUSTED, ook als het van
    `upgrade_measure` kwam - deze module kan dat niet weten."""
    from nsmcp.upgrade_gate import _gates_from_measurements

    poorten = _gates_from_measurements(
        {
            "poort": [
                {
                    "naam": "n" * 500,
                    "type": "bewijs",
                    "uitkomst": "dicht",
                    "bewijs": "b" * 5000,
                    "reden": "r" * 5000,
                }
            ]
        }
    )
    assert len(poorten[0].name) < 200
    assert len(poorten[0].evidence) < 1100
    assert len(poorten[0].reason) < 1100


def test_the_judging_half_never_re_cuts_a_tail_bounded_gate():
    """De begrenzing hierboven mag `_bounded_tail` niet ongedaan maken: een
    tweede afkapping VANAF DE KOP zou END_TIME alsnog wegsnijden."""
    from nsmcp.upgrade import presence_gate
    from nsmcp.upgrade_gate import _gates_from_measurements

    lang = "voortgang " * 200 + "END_TIME Sun Sep  6 09:12:00 2026"
    poort = presence_gate("installatie voltooid (END_TIME)", "bewijs", True, lang, "n.v.t.", "staart")
    samengevoegd = _gates_from_measurements(
        {
            "poort": [
                {
                    "naam": poort.name,
                    "type": poort.type,
                    "uitkomst": poort.outcome,
                    "bewijs": poort.evidence,
                    "reden": poort.reason,
                }
            ]
        }
    )
    assert "END_TIME" in samengevoegd[0].evidence


# ---------------------------------------------------------------------------
# Een AFWEZIGE pin is een weigering, geen leesgat
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pin", ["", "   "])
def test_hostkey_session_gate_closes_when_no_fingerprint_was_pinned_at_all(pin):
    poort = hostkey_session_gate(True, False, "", pin)
    assert poort.outcome == "dicht"
    assert poort.reason == "geen gepinde vingerafdruk mee gegeven"


def test_vorm_shapes_hostkey_gate_closed_when_the_request_carries_no_pin():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [{"soort": "hostsleutel", "sessie_geopend": True}],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "dicht"
    assert uitvoer["poort"][0]["reden"] == "geen gepinde vingerafdruk mee gegeven"


# ---------- the role check before saving (config_opslaan) ----------

_CONFIGSTAND = Path(__file__).parent / "fixtures" / "configstand"


def _rol(uitvoer_naam: str, **overrides) -> dict:
    verzoek = {
        "soort": "rol-voor-opslaan",
        "ha_node_uitvoer": (_CONFIGSTAND / uitvoer_naam).read_text(encoding="ascii"),
        "doel_adres": "192.0.2.10",
        "exitcode": 0,
        "stderr": "",
    }
    verzoek.update(overrides)
    uitvoer, code = upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": [verzoek]}))
    assert code == 0
    assert len(uitvoer["poort"]) == 1
    return uitvoer["poort"][0]


def test_vorm_shapes_the_save_role_gate_open_on_a_standalone_primary():
    poort = _rol("show-ha-node-standalone-primary.txt")
    assert poort["naam"] == "doel is primary of standalone"
    assert poort["uitkomst"] == "open"
    assert "exitcode=0" in poort["bewijs"]


def test_vorm_shapes_the_save_role_gate_closed_on_a_secondary():
    poort = _rol("show-ha-node-paar-secondary.txt")
    assert poort["uitkomst"] == "dicht"


@pytest.mark.parametrize(
    "stand,geaccepteerd,verwacht",
    [
        ("show-ns-config-opgeslagen.txt", False, ("bewijs", "open")),
        ("show-ns-config-gewijzigd.txt", False, ("bewijs", "dicht")),
        ("show-ns-config-gewijzigd.txt", True, ("mens", "open")),
    ],
)
def test_vorm_shapes_the_r1_drift_gate_from_the_live_config_state(stand, geaccepteerd, verwacht):
    uitvoer, code = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "configstand",
                        "uitvoer": (_CONFIGSTAND / stand).read_text(encoding="ascii"),
                        "exitcode": 0,
                        "stderr": "",
                        "drift_geaccepteerd": geaccepteerd,
                    }
                ],
            }
        )
    )
    assert code == 0
    poort = uitvoer["poort"][0]
    assert poort["naam"] == "drift afwezig of bewust geaccepteerd"
    assert (poort["type"], poort["uitkomst"]) == verwacht


def test_the_drift_acceptance_counts_only_as_a_real_true():
    uitvoer, _ = upgrade_measure.main(
        json.dumps(
            {
                "actie": "vorm",
                "verzoeken": [
                    {
                        "soort": "configstand",
                        "uitvoer": (_CONFIGSTAND / "show-ns-config-gewijzigd.txt").read_text(encoding="ascii"),
                        "exitcode": 0,
                        "drift_geaccepteerd": "True",
                    }
                ],
            }
        )
    )
    assert uitvoer["poort"][0]["uitkomst"] == "dicht"


@pytest.mark.parametrize("overrides", [{"exitcode": 1}, {"exitcode": -1}, {"exitcode": "0"}, {"doel_adres": ""}])
def test_a_failed_or_unbound_role_read_is_not_assessed(overrides):
    assert _rol("show-ha-node-standalone-primary.txt", **overrides)["uitkomst"] == "niet beoordeeld"


# ---------- R0: de doelbuild tegenover de vloer ----------


def _vloer(**velden) -> dict:
    verzoek = {
        "soort": "doelbuild-vloer",
        "doelbuild": "14.1-72.57",
        "huidig": "14.1-66.59",
        "vloer": "14.1-73.32",
        "bulletin": "CTX696939",
    }
    verzoek.update(velden)
    uitvoer, code = upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": [verzoek]}))
    assert code == 0
    assert len(uitvoer["poort"]) == 1
    return uitvoer["poort"][0]


@pytest.mark.parametrize(
    "velden,verwacht",
    [
        ({}, ("bewijs", "dicht")),
        ({"geaccepteerd": True}, ("mens", "open")),
        ({"doelbuild": "14.1-73.32"}, ("bewijs", "open")),
        ({"vloer": ""}, ("bewijs", "dicht")),
        ({"vloer": "", "bulletin": "", "geaccepteerd": True}, ("mens", "open")),
        ({"vloer": "13.1-63.18"}, ("bewijs", "dicht")),
        ({"vloer": "13.1-63.18", "geaccepteerd": True}, ("bewijs", "dicht")),
        ({"huidig": "13.1-63.18", "vloer": "", "bulletin": "", "geaccepteerd": True}, ("bewijs", "dicht")),
        ({"huidig": "", "doelbuild": "14.1-73.32"}, ("bewijs", "dicht")),
        ({"huidig": "", "vloer": "", "bulletin": "", "geaccepteerd": True}, ("mens", "open")),
        ({"huidig": "66.59"}, ("bewijs", "niet beoordeeld")),
        ({"doelbuild": "72.57"}, ("bewijs", "niet beoordeeld")),
    ],
)
def test_vorm_shapes_the_floor_gate(velden, verwacht):
    poort = _vloer(**velden)
    assert poort["naam"] == "doelbuild op of boven de vloer, of bewust geaccepteerd"
    assert (poort["type"], poort["uitkomst"]) == verwacht


def test_vorm_hands_the_current_build_to_the_floor_gate():
    poort = _vloer(huidig="13.1-63.18", vloer="", bulletin="", geaccepteerd=True)
    assert poort["reden"] == (
        "de doelbuild ligt in een andere releaselijn dan de huidige build; "
        "dit gereedschap doet geen overstap tussen releaselijnen"
    )


def test_a_floor_request_without_the_current_build_field_is_not_assessed_never_open():
    verzoek = {"soort": "doelbuild-vloer", "doelbuild": "14.1-72.57", "vloer": "", "bulletin": "", "geaccepteerd": True}
    uitvoer, code = upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": [verzoek]}))
    assert code == 0
    assert (uitvoer["poort"][0]["uitkomst"], uitvoer["poort"][0]["bewijs"]) == (
        "niet beoordeeld",
        "niet in de verwachte vorm: huidige build",
    )


@pytest.mark.parametrize("nep", ["True", "true", 1])
def test_the_floor_acceptance_counts_only_as_a_real_true(nep):
    assert _vloer(geaccepteerd=nep)["uitkomst"] == "dicht"


def test_a_floor_request_without_its_fields_is_not_assessed_never_open():
    uitvoer, code = upgrade_measure.main(json.dumps({"actie": "vorm", "verzoeken": [{"soort": "doelbuild-vloer"}]}))
    assert code == 0
    assert uitvoer["poort"][0]["uitkomst"] == "niet beoordeeld"
