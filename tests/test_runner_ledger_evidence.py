"""Het ledger van de echte run, als fixture EN als test.

Deze tests lezen het bewaarde ledger van de labrun 66.59 -> 72.57 (8-9-2026,
standalone VPX-labappliance) en controleren dat het draagt wat het moet dragen:
de tien metingen uit het plan, voor zover een ledger ze kan dragen. Verandert
de ledgervorm later, dan vallen deze tests om in plaats van dat het bewijs
stilletjes onleesbaar wordt.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from nsmcp.upgrade import (
    FAMILIES,
    GATE_OUTCOMES,
    GATE_TYPES,
    PHASE_OUTCOMES,
    phase_state,
    read_ledger,
    soak_gate,
    soak_state,
)

FIXTURES = Path(__file__).parent / "fixtures" / "runner-ledger-lab-02-20260908"
GESLAAGD = FIXTURES / "run-geslaagd-R0-R6.jsonl"
DICHT = FIXTURES / "run-R1-poort-dicht-vrije-ruimte.jsonl"
PHASES = ("R0", "R1", "R2", "R3", "R4", "R5", "R6")


def _rows(path: Path) -> list[dict]:
    skipped: list = []
    rows = list(read_ledger(path, skipped=skipped))
    assert skipped == [], skipped
    return rows


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


# --- meting 1: de zeven fasen lopen een keer echt door ---------------------------------


def test_the_run_carries_all_seven_phases_each_started_once_and_closed_geslaagd():
    rows = _rows(GESLAAGD)
    assert {r["fase"] for r in rows} == set(PHASES)
    for fase in PHASES:
        vanfase = [r for r in rows if r["fase"] == fase]
        assert sum(1 for r in vanfase if r["gebeurtenis"] == "fase_gestart") == 1, fase
        assert phase_state(rows, fase) == "geslaagd", fase


def test_the_phases_closed_in_order_on_the_ledgers_own_utc_clock():
    rows = _rows(GESLAAGD)
    sluit = {}
    for r in rows:
        if r["fase"] in PHASES and r["gebeurtenis"] in ("voormeting_vast", "fase_geslaagd", "soak_open"):
            sluit[r["fase"]] = _utc(r["tijd"])
    tijden = [sluit[f] for f in PHASES]
    assert tijden == sorted(tijden)
    assert timedelta(minutes=5) < tijden[-1] - tijden[0] < timedelta(minutes=30)


# --- meting 2: elke poort is getypt en heeft een uitkomst --------------------------------


def test_every_gate_is_typed_and_has_an_outcome_and_evidence():
    for path in (GESLAAGD, DICHT):
        for regel in _rows(path):
            assert regel["uitkomst"] in PHASE_OUTCOMES or regel["gebeurtenis"] in ("voorpoort", "terugrolpunt_vast"), (
                regel["gebeurtenis"]
            )
            for poort in regel.get("poort", []):
                assert poort["type"] in GATE_TYPES, poort
                assert poort["uitkomst"] in GATE_OUTCOMES, poort
                assert poort["bewijs"], poort


# --- meting 3 + C1: de voorpoort meet per poging opnieuw, VOOR de neveneffecten --------


def test_r1_measured_free_space_before_uploading_and_refused_once_on_it():
    open_run = [r for r in _rows(GESLAAGD) if r["fase"] == "R1"]
    voorpoort = [r for r in open_run if r["gebeurtenis"] == "voorpoort"]
    assert len(voorpoort) == 1 and voorpoort[0]["uitkomst"] == "open"
    ruimte = [g for g in voorpoort[0]["poort"] if g["naam"] == "vrije ruimte op /var"]
    assert ruimte and ruimte[0]["uitkomst"] == "open" and "df -k /var" in ruimte[0]["bewijs"]

    dicht = [r for r in _rows(DICHT) if r["fase"] == "R1"]
    sluit = [r for r in dicht if r["gebeurtenis"] == "poort_dicht"]
    assert sluit, "de run zonder ruimte sloot R1 met poort_dicht"
    namen = {g["naam"]: g for g in sluit[0]["poort"]}
    assert namen["vrije ruimte op /var"]["uitkomst"] == "dicht"
    # nul neveneffecten: de poorten die pas NA een upload gemeten kunnen worden ontbreken
    assert namen["firmware-hash"]["uitkomst"] == "niet beoordeeld"


# --- meting 4: de firmware-hashpoort vergelijkt met de VENDORwaarde ---------------------


def test_the_hash_gate_compared_the_box_with_the_vendor_value():
    r1 = [r for r in _rows(GESLAAGD) if r["fase"] == "R1" and r["gebeurtenis"] == "fase_geslaagd"]
    namen = {g["naam"]: g for g in r1[0]["poort"]}
    assert namen["firmware-hash"]["uitkomst"] == "open"
    assert "vendorwaarde" in namen["firmware-hash"]["bewijs"]
    assert namen["lokale bundel en sidecar"]["uitkomst"] == "open"


# --- meting 5: R4 oordeelt op SSH-auth, niet op poort 22 --------------------------------


def test_the_return_gate_carries_both_times_and_judged_on_ssh_auth():
    r4 = [r for r in _rows(GESLAAGD) if r["fase"] == "R4" and r["gebeurtenis"] == "fase_geslaagd"]
    poort = [g for g in r4[0]["poort"] if g["naam"] == "SSH-auth terug na reboot"]
    assert poort and poort[0]["uitkomst"] == "open"
    assert "poort 22 terug 2026-" in poort[0]["bewijs"] and "SSH-auth terug 2026-" in poort[0]["bewijs"]
    assert "niet op poort 22" in poort[0]["bewijs"]
    duur = _utc(r4[0]["geeindigd"]) - _utc(r4[0]["gestart"])
    assert timedelta(seconds=30) < duur < timedelta(minutes=15)


# --- meting 6: de vendor-precheck beslist op global_status --------------------------------


def test_the_vendor_precheck_evidence_names_global_status_and_ignores_the_exit_code():
    r2 = [r for r in _rows(GESLAAGD) if r["fase"] == "R2" and r["gebeurtenis"] == "fase_geslaagd"]
    poort = [g for g in r2[0]["poort"] if g["naam"] == "vendor-precheck"][0]
    assert poort["uitkomst"] == "open"
    assert "global_status=" in poort["bewijs"]
    assert "telt NIET mee" in poort["bewijs"]
    assert "resultaatpad=/var/tmp/gjk_pre_check_" in poort["bewijs"]


# --- meting 7: de gelezen build na afloop is de doelbuild ---------------------------------


def test_r5_read_back_the_target_build_exactly():
    r5 = [r for r in _rows(GESLAAGD) if r["fase"] == "R5" and r["gebeurtenis"] == "fase_geslaagd"]
    poort = [g for g in r5[0]["poort"] if g["naam"] == "doelbuild bereikt"][0]
    assert poort["uitkomst"] == "open"
    assert "Build 72.57" in poort["bewijs"]


# --- meting 8: de familietellingen en het genormaliseerde anker van R0 en R5 --------------


def test_the_family_counts_and_both_anchors_are_in_the_ledger():
    rows = _rows(GESLAAGD)
    r0 = [g for r in rows if r["fase"] == "R0" for g in r.get("poort", []) if g["naam"] == "familietellingen"]
    assert r0 and r0[0]["uitkomst"] == "open"
    for familie in FAMILIES:
        assert f"{familie}=" in r0[0]["bewijs"]
    ankers = [
        g for r in rows for g in r.get("poort", []) if g["naam"] == "configuratie-anker" and g["uitkomst"] == "open"
    ]
    assert {
        r["fase"] for r in rows for g in r.get("poort", []) if g is not None and g["naam"] == "configuratie-anker"
    } >= {"R0", "R5"}
    assert all("anker=" in g["bewijs"] and len(g["bewijs"].split("anker=")[1][:64]) == 64 for g in ankers)


# --- meting 9: het soakvenster opent en is niet te verkorten ------------------------------


def test_the_soak_window_opened_and_blocks_a_next_phase_for_24_hours():
    rows = _rows(GESLAAGD)
    soak = [r for r in rows if r["gebeurtenis"] == "soak_open"]
    assert len(soak) == 1 and soak[0]["fase"] == "R6" and soak[0]["gestart"]
    begin = _utc(soak[0]["gestart"])
    woord, einde = soak_state(rows, begin + timedelta(hours=1), 24)
    assert woord == "loopt" and einde == (begin + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    gate = soak_gate(rows, begin + timedelta(hours=23, minutes=59), 24)
    assert gate.outcome == "dicht" and "vroegste eindtijd" in gate.evidence
    assert soak_gate(rows, begin + timedelta(hours=24, seconds=1), 24).outcome == "open"
    assert soak_state(rows, begin + timedelta(hours=1), 1)[1] == einde, "een korter soak_uren verkort het venster niet"


# --- meting 10 + hardening: geen code, geen secret, geen appliance-identiteit -------------


def test_the_ledgers_carry_no_confirmation_code_no_secret_and_no_appliance_identity():
    for path in (GESLAAGD, DICHT):
        tekst = path.read_text(encoding="ascii").lower()
        for verboden in (
            "wachtwoord",
            "password",
            "passphrase",
            "bevestigingscode",
            "encodedserialno",
            "hostid",
            "netscaleruuid",
            "10.252.",
            "gjk-ns",
            "lab-02",
        ):
            assert verboden not in tekst, (path.name, verboden)


def test_the_confirmer_is_named_honestly_as_the_mechanical_lab_driver():
    rows = _rows(GESLAAGD)
    labels = {r.get("bevestiger") for r in rows if r["gebeurtenis"] == "fase_gestart"}
    assert labels == {"labproef-driver (bestandsrelay, geen mens)"}


# Review patch: these assertions validate retained evidence, not lab authenticity.
def _closed_evidence_phase(rows, phase):
    candidates = [
        row
        for row in rows
        if row["fase"] == phase and row["gebeurtenis"] in ("voormeting_vast", "fase_geslaagd", "soak_open")
    ]
    assert len(candidates) == 1, phase
    return candidates[0]


def _evidence_gate(row, name):
    candidates = [gate for gate in row["poort"] if gate["naam"] == name]
    assert len(candidates) == 1, (row["fase"], name)
    assert candidates[0]["uitkomst"] == "open", (row["fase"], name)
    return candidates[0]


def test_retained_success_evidence_is_consistent_with_the_measured_values():
    import re

    rows = _rows(GESLAAGD)
    vendor = _evidence_gate(_closed_evidence_phase(rows, "R2"), "vendor-precheck")
    assert re.search(r"\bglobal_status=warning; gezakte checks=0;", vendor["bewijs"])
    target = _evidence_gate(_closed_evidence_phase(rows, "R5"), "doelbuild bereikt")
    assert re.search(r"\bNS14\.1: Build 72\.57\.nc(?:,|\s|$)", target["bewijs"])
    for phase in ("R0", "R5"):
        anchor = _evidence_gate(_closed_evidence_phase(rows, phase), "configuratie-anker")
        assert re.search(r"(?:^|;)\s*anker=[0-9a-f]{64}(?:;|$)", anchor["bewijs"])


def test_retained_precondition_belongs_to_the_same_attempt_and_precedes_completion():
    rows = _rows(GESLAAGD)
    for phase in ("R1", "R2", "R3", "R4"):
        started = [row for row in rows if row["fase"] == phase and row["gebeurtenis"] == "fase_gestart"]
        before = [row for row in rows if row["fase"] == phase and row["gebeurtenis"] == "voorpoort"]
        assert len(started) == len(before) == 1, phase
        closed = _closed_evidence_phase(rows, phase)
        for field in ("run", "doel", "fase", "actieid", "poging", "gestart"):
            assert started[0][field] == before[0][field] == closed[field], (phase, field)
        assert _utc(started[0]["tijd"]) <= _utc(before[0]["tijd"]) <= _utc(closed["tijd"]), phase


def test_retained_auth_measurements_are_ordered_inside_the_reboot_phase():
    import re

    r4 = _closed_evidence_phase(_rows(GESLAAGD), "R4")
    evidence = _evidence_gate(r4, "SSH-auth terug na reboot")["bewijs"]
    match = re.search(r"poort 22 terug (\S+); SSH-auth terug (\S+);", evidence)
    assert match, evidence
    tcp, auth = (_utc(value) for value in match.groups())
    assert _utc(r4["gestart"]) <= tcp <= auth <= _utc(r4["geeindigd"])


# NOT pinned here, on purpose: the run-8 fixture's R3 gate 'installatie voltooid
# (END_TIME)' kept the TAIL of the vendor output as evidence, and that tail does
# not contain the END_TIME line the gate judged on (it sat on stderr, before the
# tail). Historical evidence is never rewritten (LEESMIJ.md); the runner now
# keeps the deciding fragment itself - pinned against the runner's source in
# tests/test_runner_script.py::test_r3_keeps_the_deciding_end_time_fragment_as_evidence.
