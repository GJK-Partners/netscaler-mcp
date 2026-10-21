"""Tests for `nsmcp.upgrade_gate` - the CLI bridge (`main()`/`run()`).

An earlier test suite (`test_upgrade.py`) never called this module: every
gate function was tested directly. That left `main()` - and with it the
wiring for order/soak, the exit-code discipline, the identity binding and
the phase-timeout ceiling - completely uncovered. Each of the regression
tests below is named after the behavior it guards and FAILS on the
pre-fix code.
"""

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from upgrade_gate_harness import seed_pre_gate

from nsmcp import upgrade_gate
from nsmcp.upgrade import append_line, read_ledger


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _volledige_poorten(fase: str) -> list[dict]:
    """De volledige, verplichte poortenlijst voor `fase` (`REQUIRED_GATES`),
    allemaal `open` - zodat een test
    die iets ANDERS test (volgorde, soak, tijdslimiet, identiteit) niet
    toevallig ook op de nieuwe verplichte-poortentoets struikelt."""
    from nsmcp.upgrade import REQUIRED_GATES

    return [
        {"naam": naam, "type": "bewijs", "uitkomst": "open", "bewijs": "gemeten", "reden": ""}
        for naam in sorted(REQUIRED_GATES.get(fase, ()))
    ]


def _stdin(**overrides) -> str:
    fase = overrides.get("fase", "R1")
    basis = {
        "fase": fase,
        "run": "r1",
        "doel": "lab-02",
        "actieid": "a-1",
        "bevestiger": "u-1",
        "gestart": "2026-09-06T00:00:00Z",
        "geeindigd": "2026-09-06T00:01:00Z",
        "ledger": None,
        "soak_uren": 24,
        "metingen": {"actieid_uit_script": "a-1", "poort": _volledige_poorten(fase)},
    }
    basis.update(overrides)
    return json.dumps(basis)


# ---------- algemene dekking: main() end-to-end ----------


def test_main_writes_the_ledger_line_and_returns_geslaagd(tmp_path):
    ledger = tmp_path / "r1.jsonl"
    ledger.write_text(
        json.dumps(
            {
                "tijd": "2026-09-06T08:05:00Z",
                "run": "r1",
                "doel": "lab-02",
                "fase": "R0",
                "gebeurtenis": "voormeting_vast",
                "poort": [],
                "uitkomst": "geslaagd",
                "bewijs": "",
                "actieid": "a-0",
                "bevestiger": "u-1",
                "gestart": "2026-09-06T08:00:00Z",
                "geeindigd": "2026-09-06T08:05:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    attempt = seed_pre_gate(ledger, "R1")
    regel, code = upgrade_gate.main(_stdin(ledger=str(ledger), poging=attempt))
    assert code == 0
    assert regel["uitkomst"] == "geslaagd"
    assert read_ledger(ledger)[-1] == regel


def test_main_exits_1_for_a_closed_gate(tmp_path):
    ledger = tmp_path / "r1.jsonl"
    ledger.write_text("", encoding="utf-8")  # R0 nooit gestart
    regel, code = upgrade_gate.main(_stdin(ledger=str(ledger)))
    assert code == 1
    assert regel["uitkomst"] == "poort dicht"
    assert regel["gebeurtenis"] == "poort_dicht"


def test_main_exits_2_for_a_failed_phase(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            metingen={"actieid_uit_script": "a-1", "poort": [], "tijdslimiet_overschreden": True},
        )
    )
    assert code == 2
    assert regel["uitkomst"] == "mislukt"
    assert regel["gebeurtenis"] == "fase_mislukt"


def test_main_uses_the_phase_specific_closing_event_for_r0_and_r6(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            metingen={"actieid_uit_script": "a-1", "poort": _volledige_poorten("R0")},
        )
    )
    assert code == 0
    assert regel["gebeurtenis"] == "voormeting_vast"


# ---------- append_line / ledger_line / wait_for_start ----------


def test_append_line_is_append_only_and_readable_back(tmp_path):
    pad = tmp_path / "ledger.jsonl"
    append_line(pad, {"a": 1})
    append_line(pad, {"a": 2})
    assert read_ledger(pad) == ({"a": 1}, {"a": 2})


def test_ledger_line_uses_the_supplied_event_not_a_guess_from_the_outcome():
    from nsmcp.upgrade import PhaseVerdict, ledger_line

    verdict = PhaseVerdict("R0", "geslaagd", (), "alle poorten van deze fase staan open")
    regel = ledger_line(
        verdict,
        run="r1",
        doel="lab-02",
        actieid="a-0",
        bevestiger="u-1",
        started="2026-09-06T08:00:00Z",
        ended="2026-09-06T08:05:00Z",
        event="voormeting_vast",
    )
    assert regel["gebeurtenis"] == "voormeting_vast"
    assert regel["uitkomst"] == "geslaagd"
    assert regel["fase"] == "R0"
    assert regel["run"] == "r1"
    assert regel["doel"] == "lab-02"


def test_wait_for_start_returns_the_row_once_it_appears(tmp_path):
    from nsmcp.upgrade import wait_for_start

    pad = tmp_path / "ledger.jsonl"
    pad.write_text("", encoding="utf-8")
    append_line(pad, {"run": "r1", "fase": "R1", "gebeurtenis": "fase_gestart"})
    regel = wait_for_start(pad, "r1", "R1", deadline_s=2)
    assert regel is not None
    assert regel["fase"] == "R1"


def test_wait_for_start_gives_up_after_the_deadline(tmp_path):
    from nsmcp.upgrade import wait_for_start

    pad = tmp_path / "ledger.jsonl"
    assert wait_for_start(pad, "r1", "R1", deadline_s=0.3) is None


# ---------- Een gesloten fase mag niet herbeoordeeld worden ----------


def test_a_closed_phase_cannot_be_rejudged(tmp_path):
    """Regressie: een tweede CLI-aanroep voor dezelfde fase
    mag het ledger niet nog een sluitregel geven, ook niet als de
    tussentijds gewijzigde ledgerstand een ander oordeel zou geven.

    De FRISSE `fase_gestart`-regel die de
    runner ALTIJD schrijft vlak voordat hij `upgrade_gate` aanroept
    (`Invoke-GjkUpgradeFase.ps1`'s eigen stap 4) staat hier nu ook echt in
    het ledger voor de tweede `main()`-aanroep - zonder die regel kon deze
    test nooit voor de juiste reden falen: `phase_state()` (laatste-regel)
    zag de sluitregel gewoon, met of zonder deze fix, want er stond niets
    NA die sluitregel. MET de startregel ertussen ziet `phase_state()`
    alleen nog 'gestart' - het is `phase_has_closing_row()` (ELKE sluitregel,
    niet de laatste) die de weigering hier moet dragen."""
    ledger = tmp_path / "r1.jsonl"
    ledger.write_text("", encoding="utf-8")  # R0 nooit gestart -> R1 = poort dicht
    stdin = _stdin(ledger=str(ledger))

    regel1, code1 = upgrade_gate.main(stdin)
    assert regel1["uitkomst"] == "poort dicht"
    assert code1 == 1

    # R0 sluit alsnog tussen de twee CLI-aanroepen in.
    append_line(
        ledger,
        {
            "tijd": "2026-09-06T00:00:30Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R0",
            "gebeurtenis": "voormeting_vast",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": "a-0",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T00:00:00Z",
            "geeindigd": "2026-09-06T00:00:30Z",
        },
    )
    # De runner schrijft ALTIJD eerst een fase_gestart-regel voor R1, voor
    # hij upgrade_gate ooit aanroept - ook op een herhaalde aanroep. Die
    # regel staat er hier dus ook, VOOR de tweede main()-aanroep, precies
    # zoals op het echte pad.
    append_line(
        ledger,
        {
            "tijd": "2026-09-06T00:01:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R1",
            "gebeurtenis": "fase_gestart",
            "uitkomst": "gestart",
        },
    )

    with pytest.raises(ValueError):
        upgrade_gate.main(stdin)

    r1_regels = [r for r in read_ledger(ledger) if r.get("fase") == "R1"]
    afsluitregels = [r for r in r1_regels if r.get("gebeurtenis") != "fase_gestart"]
    assert len(afsluitregels) == 1, "een fase mag maar EEN sluitregel hebben"
    assert afsluitregels[0]["uitkomst"] == "poort dicht", "de eerste sluitregel blijft de waarheid"


def test_a_corrupt_row_in_the_runs_own_file_forces_niet_beoordeeld_not_a_silent_geslaagd(tmp_path):
    """`main()` used to read this run's
    own ledger file WITHOUT collecting skipped-line markers, so a corrupt
    row - which might itself have been the closing row
    `phase_has_closing_row()` needs to see - vanished without a trace, and
    this phase would close `geslaagd` as if nothing were wrong. With the
    corrupt row present it must close `poort dicht` instead, carrying its
    own 'ledger leesbaar' gate at `niet beoordeeld` - proven against the
    SAME setup without the corrupt line, which closes `geslaagd`."""

    def _ledger_text(*, met_corrupte_regel: bool) -> str:
        regels = [
            json.dumps(
                {
                    "tijd": "2026-09-06T00:00:00Z",
                    "run": "r1",
                    "doel": "lab-02",
                    "fase": "R0",
                    "gebeurtenis": "voormeting_vast",
                    "poort": [],
                    "uitkomst": "geslaagd",
                    "bewijs": "",
                    "actieid": "a-0",
                    "bevestiger": "u-1",
                    "gestart": "2026-09-06T00:00:00Z",
                    "geeindigd": "2026-09-06T00:00:30Z",
                }
            ),
            json.dumps(
                {
                    "tijd": "2026-09-06T00:00:31Z",
                    "run": "r1",
                    "doel": "lab-02",
                    "fase": "R1",
                    "gebeurtenis": "fase_gestart",
                    "uitkomst": "gestart",
                }
            ),
        ]
        tekst = "\n".join(regels) + "\n"
        if met_corrupte_regel:
            tekst += "dit is geen json\n"
        return tekst

    schoon = tmp_path / "schoon.jsonl"
    schoon.write_text(_ledger_text(met_corrupte_regel=False), encoding="utf-8")
    attempt = seed_pre_gate(schoon, "R1")
    regel_schoon, code_schoon = upgrade_gate.main(_stdin(ledger=str(schoon), poging=attempt))
    assert regel_schoon["uitkomst"] == "geslaagd", regel_schoon
    assert code_schoon == 0

    kapot = tmp_path / "kapot.jsonl"
    kapot.write_text(_ledger_text(met_corrupte_regel=True), encoding="utf-8")
    attempt = seed_pre_gate(kapot, "R1")
    with pytest.warns(RuntimeWarning):
        regel_kapot, code_kapot = upgrade_gate.main(_stdin(ledger=str(kapot), poging=attempt))
    assert regel_kapot["uitkomst"] == "poort dicht", regel_kapot
    assert code_kapot == 1
    leesgat = next(p for p in regel_kapot["poort"] if p["naam"] == "ledger leesbaar")
    assert leesgat["uitkomst"] == "niet beoordeeld"


def test_a_phase_still_open_can_be_judged(tmp_path):
    """De weigering raakt alleen een AL GESLOTEN fase - 'gestart' en 'niet
    beoordeeld' mogen gewoon beoordeeld worden."""
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            metingen={"actieid_uit_script": "a-1", "poort": _volledige_poorten("R0")},
        )
    )
    assert code == 0


# ---------- Het soakvenster geldt per DOEL, niet per run-bestand ----------


def test_a_next_runs_first_phase_is_refused_within_the_soak_window(tmp_path):
    """Regressie: R6 van een eerdere run op hetzelfde doel
    opende een soakvenster dat nog loopt; R0 van een VOLGENDE run op
    hetzelfde doel moet dat venster zien, ook al staat het in een ander
    run-bestand."""
    doel = "lab-02"
    now = datetime.now(UTC)
    soak_begin = now - timedelta(hours=6)  # binnen de 24 uur

    eerdere_run = tmp_path / "eerdere-run.jsonl"
    append_line(
        eerdere_run,
        {
            "tijd": _iso(soak_begin),
            "run": "eerdere-run",
            "doel": doel,
            "fase": "R6",
            "gebeurtenis": "soak_open",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": "a-r6",
            "bevestiger": "u-1",
            "gestart": _iso(soak_begin),
            "geeindigd": _iso(soak_begin + timedelta(hours=24)),
        },
    )

    volgende_run = tmp_path / "volgende-run.jsonl"
    volgende_run.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende-run",
            doel=doel,
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende_run),
            metingen={"actieid_uit_script": "a-r0", "poort": []},
        )
    )
    assert regel["uitkomst"] == "poort dicht"
    assert code == 1
    assert any(p["naam"] == "soakvenster" for p in regel["poort"])


def test_a_next_runs_first_phase_opens_once_the_soak_window_elapsed(tmp_path):
    doel = "lab-02"
    now = datetime.now(UTC)
    soak_begin = now - timedelta(hours=30)  # ruim voorbij de 24 uur

    eerdere_run = tmp_path / "eerdere-run.jsonl"
    append_line(
        eerdere_run,
        {
            "tijd": _iso(soak_begin),
            "run": "eerdere-run",
            "doel": doel,
            "fase": "R6",
            "gebeurtenis": "soak_open",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": "a-r6",
            "bevestiger": "u-1",
            "gestart": _iso(soak_begin),
            "geeindigd": _iso(soak_begin + timedelta(hours=24)),
        },
    )

    volgende_run = tmp_path / "volgende-run.jsonl"
    volgende_run.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende-run",
            doel=doel,
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende_run),
            metingen={"actieid_uit_script": "a-r0", "poort": _volledige_poorten("R0")},
        )
    )
    assert regel["uitkomst"] == "geslaagd"
    assert code == 0


def test_a_soak_window_on_a_different_target_does_not_refuse(tmp_path):
    now = datetime.now(UTC)
    soak_begin = now - timedelta(hours=6)

    ander_doel_run = tmp_path / "ander-doel.jsonl"
    append_line(
        ander_doel_run,
        {
            "tijd": _iso(soak_begin),
            "run": "ander-doel",
            "doel": "lab-01",
            "fase": "R6",
            "gebeurtenis": "soak_open",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": "a-r6",
            "bevestiger": "u-1",
            "gestart": _iso(soak_begin),
            "geeindigd": _iso(soak_begin + timedelta(hours=24)),
        },
    )

    volgende_run = tmp_path / "volgende-run.jsonl"
    volgende_run.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende-run",
            doel="lab-02",
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende_run),
            metingen={"actieid_uit_script": "a-r0", "poort": _volledige_poorten("R0")},
        )
    )
    assert regel["uitkomst"] == "geslaagd"
    assert code == 0


# ---------- Een crash en een dichte poort delen geen exitcode ----------


def _run_cli(invoer: str, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "nsmcp.upgrade_gate"],
        input=invoer,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_a_ledger_directory_that_does_not_exist_exits_2_not_1(tmp_path):
    ledger = tmp_path / "no-such-dir" / "run.jsonl"
    proc = _run_cli(_stdin(ledger=str(ledger)))
    assert proc.returncode == 2, proc.stderr
    assert "Traceback" not in proc.stderr


def test_a_ledger_path_that_is_a_directory_exits_2_not_1(tmp_path):
    ledger = tmp_path / "is-a-directory.jsonl"
    ledger.mkdir()
    proc = _run_cli(_stdin(ledger=str(ledger)))
    assert proc.returncode == 2, proc.stderr
    assert "Traceback" not in proc.stderr


def test_a_bad_ledger_line_no_longer_crashes_the_cli(tmp_path):
    """Vloeit voort uit een eerdere fix (`read_ledger` slaat een misvormde regel
    over): dezelfde invoer die vroeger een AttributeError gaf, geeft nu een
    normaal - niet gecrashed - oordeel."""
    ledger = tmp_path / "bad.jsonl"
    ledger.write_text("[1, 2, 3]\n", encoding="utf-8")
    proc = _run_cli(_stdin(ledger=str(ledger)))
    assert proc.returncode in (0, 1, 2)
    assert "Traceback" not in proc.stderr


# ---------- De identiteitsbinding mag niet stilzwijgend verdwijnen ----------


def test_a_missing_identity_on_both_sides_is_a_failure_not_a_pass(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid=None,
            bevestiger=None,
            metingen={"poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


def test_a_missing_actieid_alone_is_also_a_failure(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid=None,
            metingen={"actieid_uit_script": "a-0", "poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


def test_a_real_mismatch_still_fails_with_the_same_reason(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid="a-1",
            metingen={"actieid_uit_script": "a-2", "poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


def test_a_matched_identity_still_passes(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid="a-0",
            metingen={"actieid_uit_script": "a-0", "poort": _volledige_poorten("R0")},
        )
    )
    assert regel["uitkomst"] == "geslaagd"
    assert code == 0


# ---------- PHASE_LIMITS_S moet zelf meewegen ----------


def _sluit_fase(ledger, fase, vorige_gestart, vorige_geeindigd, event="fase_geslaagd"):
    append_line(
        ledger,
        {
            "tijd": vorige_gestart,
            "run": "r1",
            "doel": "lab-02",
            "fase": fase,
            "gebeurtenis": "fase_gestart",
            "poort": [],
            "uitkomst": "gestart",
            "bewijs": "",
            "actieid": f"a-{fase.lower()}",
            "bevestiger": "u-1",
            "gestart": vorige_gestart,
            "geeindigd": None,
        },
    )
    append_line(
        ledger,
        {
            "tijd": vorige_geeindigd,
            "run": "r1",
            "doel": "lab-02",
            "fase": fase,
            "gebeurtenis": event,
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": f"a-{fase.lower()}",
            "bevestiger": "u-1",
            "gestart": vorige_gestart,
            "geeindigd": vorige_geeindigd,
        },
    )


def test_main_derives_the_phase_timeout_from_its_own_timestamps(tmp_path):
    """Regressie, met de exacte meting: R2
    gestart 09:05, geeindigd 23:05 - 14 uur tegen een limiet van 900 s."""
    ledger = tmp_path / "r0r1.jsonl"
    _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
    _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")

    regel, code = upgrade_gate.main(
        _stdin(
            fase="R2",
            ledger=str(ledger),
            actieid="a-r2",
            gestart="2026-09-06T09:05:00Z",
            geeindigd="2026-09-06T23:05:00Z",
            metingen={"actieid_uit_script": "a-r2", "poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


def test_main_still_passes_when_within_the_limit(tmp_path):
    ledger = tmp_path / "r0r1.jsonl"
    _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
    _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")

    attempt = seed_pre_gate(ledger, "R2", action="a-r2", started="2026-09-06T09:05:00Z")
    regel, code = upgrade_gate.main(
        _stdin(
            poging=attempt,
            fase="R2",
            ledger=str(ledger),
            actieid="a-r2",
            gestart="2026-09-06T09:05:00Z",
            geeindigd="2026-09-06T09:10:00Z",
            metingen={"actieid_uit_script": "a-r2", "poort": _volledige_poorten("R2")},
        )
    )
    assert regel["uitkomst"] == "geslaagd"
    assert code == 0


def test_main_still_honors_a_script_reported_timeout_within_the_limit(tmp_path):
    """Het OR met de eigen melding van het script mag niet verloren gaan."""
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid="a-0",
            gestart="2026-09-06T08:00:00Z",
            geeindigd="2026-09-06T08:00:05Z",
            metingen={"actieid_uit_script": "a-0", "poort": [], "tijdslimiet_overschreden": True},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


def test_main_ignores_a_zero_limit_phase_even_when_slow(tmp_path):
    """R0 en R6 hebben PHASE_LIMITS_S 0 - geen ceiling - dus een lange duur
    op R0 mag zelf geen tijdslimiet-mislukking veroorzaken."""
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid="a-0",
            gestart="2026-09-06T08:00:00Z",
            geeindigd="2026-09-07T08:00:00Z",
            metingen={"actieid_uit_script": "a-0", "poort": _volledige_poorten("R0")},
        )
    )
    assert regel["uitkomst"] == "geslaagd"
    assert code == 0


# ---------- Bestandsnaam-volgorde is geen tijdvolgorde ----------


def _soak_open_bestand(pad: Path, doel: str, begin: datetime, run: str) -> None:
    append_line(
        pad,
        {
            "tijd": _iso(begin),
            "run": run,
            "doel": doel,
            "fase": "R6",
            "gebeurtenis": "soak_open",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "",
            "actieid": "a-r6",
            "bevestiger": "u-1",
            "gestart": _iso(begin),
            "geeindigd": _iso(begin + timedelta(hours=24)),
        },
    )


def test_a_stray_ledger_file_cannot_shorten_the_soak_window(tmp_path):
    """Regressie, de gemeten probe:
    een correct genoemd `<UTC>Z-<doel>.jsonl` met een soakvenster van 6 uur
    geleden, plus een STRAY `archief-<doel>.jsonl` met er een van 200 uur
    geleden. `sorted(glob('*.jsonl'))` zet de stray ACHTERAAN (een naam die
    niet met een cijfer begint sorteert na elke tijdstempelnaam), en
    `_soak_start` nam de laatste die hij tegenkwam - dus opende de poort.
    Mutatieproef 11 was daarmee te omzeilen door een oude ledger naast de
    levende te kopieren."""
    doel = "lab-02"
    now = datetime.now(UTC)
    _soak_open_bestand(
        tmp_path / "20260907T000000Z-lab-02.jsonl", doel, now - timedelta(hours=6), "20260907T000000Z-lab-02"
    )
    _soak_open_bestand(tmp_path / "archief-lab-02.jsonl", doel, now - timedelta(hours=200), "archief")

    volgende = tmp_path / "20260907T120000Z-lab-02.jsonl"
    volgende.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="20260907T120000Z-lab-02",
            doel=doel,
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende),
            metingen={"actieid_uit_script": "a-r0", "poort": []},
        )
    )
    assert regel["uitkomst"] == "poort dicht"
    assert code == 1
    soak = [p for p in regel["poort"] if p["naam"] == "soakvenster"]
    assert soak and soak[0]["uitkomst"] == "dicht"


# ---------- Het doel wordt genormaliseerd vergeleken ----------


def test_a_differently_spelled_target_still_finds_its_own_soak_window(tmp_path):
    """`doel` werd op exacte string vergeleken: een FQDN, andere kapitalen
    of spatie eromheen gaf 'geen open soakvenster op dit doel' - niet te
    onderscheiden van een echt vers doel."""
    now = datetime.now(UTC)
    _soak_open_bestand(
        tmp_path / "20260907T000000Z-lab-02.jsonl",
        "lab-02.lab.example",
        now - timedelta(hours=6),
        "20260907T000000Z-lab-02",
    )

    for volgnummer, spelling in enumerate(("lab-02", " LAB-02 ", "lab-02.lab.example", "Lab-02.LAB.example.")):
        volgende = tmp_path / f"20260907T12000{volgnummer}Z-lab-02.jsonl"
        volgende.write_text("", encoding="utf-8")
        regel, code = upgrade_gate.main(
            _stdin(
                fase="R0",
                run="volgende",
                doel=spelling,
                actieid="a-r0",
                gestart=_iso(now),
                geeindigd=_iso(now),
                ledger=str(volgende),
                metingen={"actieid_uit_script": "a-r0", "poort": []},
            )
        )
        assert regel["uitkomst"] == "poort dicht", f"{spelling!r} hoort hetzelfde doel te zijn"
        assert code == 1


def test_an_ipv4_target_is_not_split_at_its_first_octet(tmp_path):
    """Carried defect, since closed: `_normalised_target` used to
    treat an IPv4 literal like a domain name and keep only the first
    label - `10.0.0.5` became `10`, so every appliance in `10/8` shared
    ONE soak window. This FAILS on the pre-fix code: `10.0.0.9`'s R0
    would have read `10.0.0.5`'s still-open window as its own and been
    refused, even though the two are different boxes."""
    now = datetime.now(UTC)
    _soak_open_bestand(
        tmp_path / "20260907T000000Z-10.0.0.5.jsonl", "10.0.0.5", now - timedelta(hours=1), "20260907T000000Z-10.0.0.5"
    )

    volgende = tmp_path / "20260907T120000Z-10.0.0.9.jsonl"
    volgende.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende",
            doel="10.0.0.9",
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende),
            metingen={"actieid_uit_script": "a-r0", "poort": _volledige_poorten("R0")},
        )
    )
    assert regel["uitkomst"] == "geslaagd", "10.0.0.9 is een ANDER doel dan 10.0.0.5"
    assert code == 0

    # The same IP, spelled twice, IS one target - the fix narrows the
    # match to "not a domain strip on an IP literal", it does not turn the
    # soak gate exact-string again.
    volgende2 = tmp_path / "20260907T120001Z-10.0.0.5.jsonl"
    volgende2.write_text("", encoding="utf-8")
    regel2, code2 = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende2",
            doel="10.0.0.5",
            actieid="a-r0b",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende2),
            metingen={"actieid_uit_script": "a-r0b", "poort": []},
        )
    )
    assert regel2["uitkomst"] == "poort dicht", "10.0.0.5 zelf staat nog in zijn eigen soakvenster"
    assert code2 == 1


def test_the_soak_refusal_names_the_matched_target(tmp_path):
    """Carried defect, since closed: the soak gate's evidence
    named an earliest end time without saying WHICH target's window that
    was - the exact gap that made the IP-truncation bug above silent."""
    now = datetime.now(UTC)
    _soak_open_bestand(
        tmp_path / "20260907T000000Z-lab-02.jsonl", "lab-02", now - timedelta(hours=1), "20260907T000000Z-lab-02"
    )
    volgende = tmp_path / "20260907T120000Z-lab-02.jsonl"
    volgende.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            run="volgende",
            doel="lab-02",
            actieid="a-r0",
            gestart=_iso(now),
            geeindigd=_iso(now),
            ledger=str(volgende),
            metingen={"actieid_uit_script": "a-r0", "poort": []},
        )
    )
    assert code == 1
    soak = [p for p in regel["poort"] if p["naam"] == "soakvenster"]
    assert soak and "lab-02" in soak[0]["bewijs"]


# ---------- Een onleesbare eindtijd zet geen plafond uit ----------


def test_an_unreadable_end_time_never_counts_as_within_the_limit(tmp_path):
    """Regressie: de oude duurmeting gaf
    `False` (= binnen het plafond) op een onparseerbare `geeindigd`. De
    metende helft kon `PHASE_LIMITS_S` daarmee uitzetten met
    `"geeindigd": "n/a"`, en niets in het bewijs meldde dat de duur niet te
    beoordelen was."""
    for volgnummer, geeindigd in enumerate(("n/a", "", None, "gisteren")):
        ledger = tmp_path / f"r2-{volgnummer}.jsonl"
        _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
        _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")
        regel, code = upgrade_gate.main(
            _stdin(
                fase="R2",
                ledger=str(ledger),
                actieid="a-r2",
                gestart="2026-09-06T09:05:00Z",
                geeindigd=geeindigd,
                metingen={"actieid_uit_script": "a-r2", "poort": []},
            )
        )
        assert regel["uitkomst"] != "geslaagd", f"{geeindigd!r} is geen gelezen eindtijd"
        assert code != 0
        tijdpoorten = [p for p in regel["poort"] if p["type"] == "tijd" and p["uitkomst"] == "niet beoordeeld"]
        assert tijdpoorten, "het bewijs moet melden dat de duur niet beoordeeld is"
        assert "eindtijd" in tijdpoorten[0]["bewijs"] or "begintijd" in tijdpoorten[0]["bewijs"]


def test_an_unreadable_start_time_also_leaves_the_ceiling_unjudged(tmp_path):
    ledger = tmp_path / "r2-start.jsonl"
    _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
    _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R2",
            ledger=str(ledger),
            actieid="a-r2",
            gestart="n/a",
            geeindigd="2026-09-06T09:10:00Z",
            metingen={"actieid_uit_script": "a-r2", "poort": []},
        )
    )
    assert regel["uitkomst"] != "geslaagd"
    assert code != 0


def test_a_naive_timestamp_next_to_an_aware_one_is_still_judged_not_a_crash(tmp_path):
    """Gemengd aware/naive gaf een TypeError die tot in `run()` doorliep.
    Het ledger schrijft UTC, dus een naive tijd wordt als UTC gelezen en de
    14 uur wordt gewoon geoordeeld."""
    ledger = tmp_path / "r2-naive.jsonl"
    _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
    _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R2",
            ledger=str(ledger),
            actieid="a-r2",
            gestart="2026-09-06T09:05:00",
            geeindigd="2026-09-06T23:05:00Z",
            metingen={"actieid_uit_script": "a-r2", "poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


# ---------- Een crash is nooit exit 1 ----------


def test_a_crash_on_deeply_nested_json_exits_2_not_1():
    """Regressie, de gemeten probe: diep
    geneste JSON op stdin geeft een RecursionError, die niet in de
    opgesomde except-tuple zat. Exit 1 is het EIGEN woord van deze module
    voor `poort dicht`; een crash mag daar nooit op lijken."""
    diep = "[" * 100000 + "]" * 100000
    proc = _run_cli(diep)
    assert proc.returncode == 2, (proc.returncode, proc.stderr[:400])
    assert "Traceback" not in proc.stderr
    assert proc.stdout.strip() == ""


# ---------- Exit 2 spreekt niet altijd over onleesbare invoer ----------


def test_a_closed_phase_refusal_does_not_claim_the_input_was_unreadable(tmp_path):
    """De weigering van een AL GESLOTEN fase is een OORDEEL op perfect
    leesbare invoer - 'onleesbare invoer op stdin' beschrijft die verkeerd."""
    ledger = tmp_path / "r1.jsonl"
    _sluit_fase(ledger, "R0", "2026-09-06T08:00:00Z", "2026-09-06T08:05:00Z", event="voormeting_vast")
    _sluit_fase(ledger, "R1", "2026-09-06T08:05:00Z", "2026-09-06T09:05:00Z")
    proc = _run_cli(_stdin(ledger=str(ledger)))
    assert proc.returncode == 2, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "onleesbare invoer op stdin" not in proc.stderr
    assert "R1" in proc.stderr


# ---------- Een ONTBREKEND actie-id heet geen mismatch ----------


def test_a_missing_identity_says_it_is_missing_not_that_it_mismatched(tmp_path):
    """De override hergebruikte 'komen niet overeen' voor het geval waarin
    een van beide kanten ONTBREEKT - het ledger beweerde dan een
    vergelijking die nooit gemaakt is."""
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid=None,
            bevestiger=None,
            metingen={"poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2
    assert "ontbreekt" in regel["bewijs"]
    assert "komen niet overeen" not in regel["bewijs"]


def test_a_real_mismatch_keeps_the_designs_mismatch_wording(tmp_path):
    ledger = tmp_path / "r0.jsonl"
    ledger.write_text("", encoding="utf-8")
    regel, code = upgrade_gate.main(
        _stdin(
            fase="R0",
            ledger=str(ledger),
            actieid="a-1",
            metingen={"actieid_uit_script": "a-2", "poort": []},
        )
    )
    assert regel["uitkomst"] == "mislukt"
    assert code == 2


# ---------- exit 2 mag nooit als
# geoordeeld gemeld worden - de ClosedPhaseError-tak dekken ----------


def test_a_phase_that_already_carries_a_closing_row_exits_2_and_appends_nothing(tmp_path):
    """`main()` weigert een AL GESLOTEN fase (ClosedPhase
    Error), exact het pad waar `run()`'s subtiele
    `ExitCode == 2 and lege stdout`-conditie op moet reageren - en dat pad
    had geen enkele test. Dit is een GEOORDEELDE weigering op leesbare
    invoer, niet een crash: het onderscheid met de "onleesbare invoer"-tak
    van exit 2 zit in de STDERR-tekst, niet in de exitcode zelf."""
    ledger = tmp_path / "r1.jsonl"
    append_line(
        ledger,
        {
            "tijd": "2026-09-06T00:00:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R1",
            "gebeurtenis": "fase_gestart",
            "poort": [],
            "uitkomst": "gestart",
            "bewijs": "",
            "actieid": "a-1",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T00:00:00Z",
            "geeindigd": None,
        },
    )
    append_line(
        ledger,
        {
            "tijd": "2026-09-06T00:01:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R1",
            "gebeurtenis": "fase_mislukt",
            "poort": [],
            "uitkomst": "mislukt",
            "bewijs": "eerder al mislukt",
            "actieid": "a-1",
            "bevestiger": "u-1",
            "gestart": "2026-09-06T00:00:00Z",
            "geeindigd": "2026-09-06T00:01:00Z",
        },
    )
    voor = read_ledger(ledger)
    assert len(voor) == 2

    proc = _run_cli(_stdin(ledger=str(ledger)))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert proc.stdout == "", "een geweigerde, al-gesloten fase mag GEEN ledgerregel als stdout tonen"
    assert "al" in proc.stderr and "beoordeeld" not in proc.stderr.lower() or "staat al op" in proc.stderr
    assert "Traceback" not in proc.stderr

    na = read_ledger(ledger)
    assert len(na) == 2, "een gesloten fase krijgt nooit een derde regel - geen herbeoordeling"
    assert na == voor


def test_closed_phase_error_is_a_value_error_and_never_names_unreadable_input():
    """`run()` vangt `ClosedPhaseError` in een EIGEN except-tak, apart van de
    generieke Exception-tak ("onleesbare invoer op stdin") - dit IS
    leesbare invoer, geoordeeld als een weigering. De twee stderr-teksten
    mogen elkaar dus nooit overschrijven."""
    from nsmcp.upgrade_gate import ClosedPhaseError

    assert issubclass(ClosedPhaseError, ValueError)
    fout = ClosedPhaseError("fase 'R1' staat al op 'mislukt' in het ledger")
    assert "onleesbare invoer" not in str(fout)


# --- Strict reading for the cross-tool gate -----


def test_an_unreadable_ledger_directory_raises_in_strict_mode(tmp_path, monkeypatch):
    import pathlib as _pathlib

    from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    real_glob = _pathlib.Path.glob

    def unreadable(self, pattern, *a, **kw):
        if self.name == "ledger":
            raise PermissionError(13, "toegang geweigerd")
        return real_glob(self, pattern, *a, **kw)

    monkeypatch.setattr(_pathlib.Path, "glob", unreadable)
    assert _rows_for_target(ledgermap / "_.jsonl", "lab-02") == ()
    with pytest.raises(LedgerUnreadable):
        _rows_for_target(ledgermap / "_.jsonl", "lab-02", strict=True)


def test_a_missing_ledger_directory_raises_in_strict_mode(tmp_path):
    """`pathlib.Path.glob()` on a directory
    that does not exist at all returns an EMPTY iterator, silently - it
    raises no `OSError`, unlike a directory that exists but cannot be
    LISTED (permission denied, the case the previous test already covers).
    `_rows_for_target(..., strict=True)` used to read that empty result as
    "nothing open", exactly the same answer as a genuinely empty target -
    so a dropped network share or a renamed ledger directory made the
    cross-tool gate, the phase tool's open-phase/soak checks and
    `onderhoud_upgrade_stand` all read "nothing open" instead of refusing.
    A safety gate that cannot read its evidence must refuse."""
    from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target

    ledgermap = tmp_path / "deze-map-bestaat-niet"
    assert not ledgermap.exists()
    assert _rows_for_target(ledgermap / "_.jsonl", "lab-02") == ()
    with pytest.raises(LedgerUnreadable):
        _rows_for_target(ledgermap / "_.jsonl", "lab-02", strict=True)


def test_an_unreadable_run_file_raises_in_strict_mode(tmp_path, monkeypatch):
    import pathlib as _pathlib

    from nsmcp.upgrade_gate import LedgerUnreadable, _rows_for_target

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    (ledgermap / "run-a.jsonl").write_text("{}\n", encoding="utf-8")
    real_read_bytes = _pathlib.Path.read_bytes

    def unreadable(self, *a, **kw):
        if self.suffix == ".jsonl":
            raise PermissionError(13, "toegang geweigerd")
        return real_read_bytes(self, *a, **kw)

    monkeypatch.setattr(_pathlib.Path, "read_bytes", unreadable)
    assert _rows_for_target(ledgermap / "_.jsonl", "lab-02") == ()
    with pytest.raises(LedgerUnreadable):
        _rows_for_target(ledgermap / "_.jsonl", "lab-02", strict=True)


def test_a_corrupt_line_stays_tolerated_even_in_strict_mode(tmp_path):
    """The tolerance that must NOT change: `read_ledger` skips a bad LINE."""
    from nsmcp.upgrade_gate import _rows_for_target

    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    (ledgermap / "run-a.jsonl").write_text(
        'dit is geen json\n{"doel": "lab-02", "fase": "R1"}\n',
        encoding="utf-8",
    )
    with pytest.warns(RuntimeWarning):
        rows = _rows_for_target(ledgermap / "_.jsonl", "lab-02", strict=True)
    assert [r["fase"] for r in rows] == ["R1"]
