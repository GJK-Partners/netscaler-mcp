"""Golden-fixture parity tests against a REAL NSHC 1.0 collector export.

`tests/fixtures/lab-export-vpx-20260826/` is the export the first live lab
proof (2026-08-26, a VPX in GJK's OWN lab - no customer data)
actually had the
released NSHC 1.0 collector write. Before this file existed, every fixture in
`tests/test_export.py` built its own JSON with the same (by now outdated)
naming and shape assumption as the production code it tested - so no
existing unit test could ever catch the defect where the object file was
named `config_sslcertkey.json` instead of the real `sslcertkey.json`, or the
one where the binding file was named `sslvserver_sslcertkey_binding.json`
instead of the real `...by-parent.json`, in a completely different shape.
This file runs the
REAL engine (`what_expires`, `what_breaks`, `what_to_do`) against files the
collector itself really wrote - the parallel anchor the textual grep in
`test_export_format_boundary.py` could not be.

The numbers below are the cross-check from the proof report of that same
session: `objects/sslcertkey.json` carries 4 certificates, 3 of which fall
within a horizon of 3650 days (817/1817/3642 days); the fourth
(999902 days, ns-sftrust-certificate) falls well outside it.
`bindings/sslvserver_sslcertkey_binding.by-parent.json` carries 2 parents
(VSRV-003, VSRV-002), both `outcome: OK`, both a binding on
`CERT-009`.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from nsmcp.action import what_to_do
from nsmcp.answer import Certainty, stamp_data
from nsmcp.expiry import what_expires
from nsmcp.export import load_export
from nsmcp.impact import what_breaks
from nsmcp.knowledge import Knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"

# Fixed "today", derived from the collectedAtUtc of THIS fixture
# (2026-08-26T10:28:17.7884008Z) - NEVER the system date of whatever day the
# tests happen to run. That keeps "0 dagen oud" (as the proof report of the
# live run states) true forever, even years after this fixture was captured.
TODAY = date(2026, 8, 26)

_KNOWLEDGE = Knowledge(version="pariteitstest", date="2026-08-26", age_days=0, missing=False)


def _load():
    export = load_export(FIXTURE)
    assert not export.manifest_missing, "de gouden fixture moet een leesbaar manifest dragen"
    return export


def test_export_carries_the_real_provenance_of_the_lab_scan():
    export = _load()
    assert export.target_name == "lab"
    assert export.collected_at == "2026-08-26T10:28:17.7884008Z"


def test_what_expires_finds_the_three_real_lab_certificates_and_reads_the_cert_side_file():
    """The engine must read the object file the real collector writes
    (`objects/sslcertkey.json`, last path segment of the resource) - not a
    derived name that never existed on disk, which would turn EVERY
    `config/*` target of this collector into a read gap while the data sits
    right there (see the table in the proof report).

    This test reads `bindings/sslcertkey_binding.by-parent.json` for the
    usage state, and that file carries the 'aggregate' shape on this real
    export. That shape used to be a read gap on this fixture; it is read per
    child kind now (`Export.binding_rows`), so the gap is gone - and with it
    the "onbekend" of ns-server-certificate, which this file binds to eight
    services."""
    export = _load()
    answer = what_expires(export, _KNOWLEDGE, 3650)
    answer = stamp_data(answer, export.collected_at, TODAY, export.target_name)

    assert answer.read_gaps == [], "sslcertkey_binding.by-parent.json is gelezen in de aggregate-vorm"
    assert answer.is_complete()

    by_name = {b.subject: b for b in answer.findings}
    assert set(by_name) == {"ns-server-certificate", "CERT-004", "CERT-009"}, (
        "ns-sftrust-certificate (999902 dagen) hoort NIET mee te doen: dat valt ruim buiten de horizon van 3650 dagen"
    )
    expected_days = {
        "ns-server-certificate": 3642,
        "CERT-004": 1817,
        "CERT-009": 817,
    }
    for name, days in expected_days.items():
        b = by_name[name]
        assert b.certainty is Certainty.ESTABLISHED
        # The parsed day count lives in
        # `outcome`, not echoed a second time from the raw export value into
        # `evidence` - a raw value must never reach the rendered evidence
        # line ungated.
        assert f"{days} dagen" in b.outcome
        assert "daystoexpiration" not in b.evidence

    assert answer.data_date == "2026-08-26"
    assert answer.data_age_days == 0
    assert answer.data_target == "lab"


def test_what_breaks_finds_the_two_real_bindings_on_CERT_009():
    """The engine must find the binding file under the manifest key the real
    collector uses (`bindings/sslvserver_sslcertkey_binding.by-parent.json`,
    by-parent shape) - the wrong name or the wrong shape yields a read gap
    ('geen hash in het manifest') for EVERY certificate on this collector,
    and thus never a change proposal through `what_to_do`. Fail-closed is not
    lying, but it must not overlook data that sits right on disk.

    Deze test eiste tot 2026-08-27 `read_gaps == []`. Dat pinde de VERKEERDE
    werkelijkheid vast: deze export draagt DRIE virtuele servers en TWEE
    parents, dus er hoort hier een leesgat te staan. Wat de test bewaakt -
    dat de twee gelezen bindingen echt gevonden worden en de naam/vorm dus
    klopt - staat er onveranderd; wat erbij komt is dat het leesgat over de
    derde er NIET tussenuit mag vallen.
    """
    export = _load()
    answer = what_breaks(export, _KNOWLEDGE, "CERT-009")
    answer = stamp_data(answer, export.collected_at, TODAY, export.target_name)

    naam_of_vormgaten = [g for g in answer.read_gaps if "hash" in g.reason or "ontbreekt" in g.reason]
    assert naam_of_vormgaten == [], f"naam/vorm van de bestanden klopt niet: {naam_of_vormgaten}"
    assert set(answer.affected_vservers) == {"VSRV-003", "VSRV-002"}
    assert len(answer.findings) == 2
    for b in answer.findings:
        assert b.certainty is Certainty.ESTABLISHED
        assert b.outcome == "servercertificaat; TLS valt uit voor deze dienst"
    assert len(answer.read_gaps) == 1
    assert "VSRV-001" in answer.read_gaps[0].reason


def test_the_withheld_proposal_rests_on_the_unread_service_and_not_on_a_file_name():
    """Sluitstuk van de keten, in de vorm die deze export toelaat.

    De oorspronkelijke test eiste hier een voorstel met beide vservernamen,
    om te bewijzen dat de verkeerde bestandsnaam/vorm ("geen hash in het
    manifest") geen weigering meer afdwingt. Die bewaking blijft, maar de
    uitkomst is nu een ANDERE weigering, om een echte reden: de bindingen
    van VSRV-001 zijn nooit gelezen, dus een omkoppeladvies dat alleen
    VSRV-003 en VSRV-002 noemt zou die dienst kapot achterlaten. De test
    scheidt die twee weigeringen expliciet - dat is precies het verschil dat
    hij moet bewaken."""
    export = _load()
    impact = what_breaks(export, _KNOWLEDGE, "CERT-009")
    answer = what_to_do(impact, _KNOWLEDGE, "CERT-009")
    answer = stamp_data(answer, export.collected_at, TODAY, export.target_name)

    redenen = " ".join(g.reason for g in answer.read_gaps)
    assert "hash" not in redenen, "de naam/vorm van de bestanden mag geen weigering meer veroorzaken"
    assert "VSRV-001" in redenen, "de weigering hoort te rusten op de ongelezen dienst"
    assert len(answer.findings) == 1
    assert answer.findings[0].certainty is Certainty.NOT_ESTABLISHED
    # De vastgestelde diensten staan wel degelijk in het IMPACTantwoord - het
    # advies wordt ingehouden, de meting niet.
    assert set(impact.affected_vservers) == {"VSRV-003", "VSRV-002"}


def test_the_lab_ca_is_recognized_as_the_issuer_of_CERT_009():
    """Het gemeten labgeval, op de echte export: CERT-004 geeft
    CERT-009 uit (`objects/sslcertkey.json`, veld `linkcertkeyname`).
    Voor de reparatie meldde de motor over CERT-004 uitsluitend "geen
    gebonden virtuele servers gevonden in deze export".
    """
    export = _load()
    answer = what_breaks(export, _KNOWLEDGE, "CERT-004")

    assert answer.issued_certificates == ("CERT-009",)
    text = answer.to_text()
    assert "CERT-009" in text
    assert "linkcertkeyname" in text


def test_CERT_009_itself_issues_nothing_in_the_lab_export():
    """Tegenproef op dezelfde echte export: CERT-009 geeft niets uit,
    dus de uitgifteroute levert daar niets op. Zonder deze test zou een
    mutatie die ELK certificaat als uitgever bestempelt groen blijven.
    """
    export = _load()
    answer = what_breaks(export, _KNOWLEDGE, "CERT-009")
    assert answer.issued_certificates == ()


def test_the_lab_ca_reaches_both_real_services_through_the_chain():
    """De volle keten op de echte export: CERT-004 geeft CERT-009 uit,
    en CERT-009 hangt aan VSRV-003 en VSRV-002. Precies het geval
    waarover de motor eerder uitsluitend "geen gebonden virtuele servers
    gevonden in deze export" meldde.

    Deze test gebruikte `<=` op de onderwerpen en `read_gaps == []`. Daarmee
    pinde hij het VERKEERDE aantal als verwachte waarheid vast: VSRV-001 hangt
    volgens `bindings/sslcertkey_binding.by-parent.json` ook aan CERT-009,
    maar draagt geen parent-vermelding in het bindingsbestand dat deze motor
    leest. Met `<=` bleef de test groen ongeacht wat er ontbrak. Nu wordt de
    werkelijkheid gepind: DRIE onderwerpen, exact, en de vierde dienst staat
    als leesgat - niet als bevinding, want welk certificaat VSRV-001 draagt
    staat nergens in deze export.
    """
    export = _load()
    answer = what_breaks(export, _KNOWLEDGE, "CERT-004")

    subjects = {b.subject for b in answer.findings}
    assert subjects == {"CERT-009", "VSRV-003", "VSRV-002"}
    assert "VSRV-001" not in subjects, (
        "welk certificaat VSRV-001 draagt is niet gelezen; dat als bevinding melden zou verzonnen bewijs zijn"
    )
    assert any("VSRV-001" in g.reason for g in answer.read_gaps)
    text = answer.to_text()
    assert "geen gebonden virtuele servers en geen uitgegeven certificaten" not in text.lower()


def test_the_lab_ca_no_longer_reads_as_nothing_hangs_on_it():
    """Sluitstuk op de echte export. De oorspronkelijke test eiste hier een
    voorstel met CERT-009 erin, in plaats van "Koppel het om op: (geen
    gebonden virtuele servers)". Die uitspraak - dat er WEL iets aan hangt -
    blijft staan en wordt hier op het impactantwoord gemeten. Het VOORSTEL
    zelf wordt ingehouden zolang de bindingen van VSRV-001 ongelezen zijn;
    een advies dat doet alsof het beeld compleet is, is gevaarlijker dan geen
    advies."""
    export = _load()
    impact = what_breaks(export, _KNOWLEDGE, "CERT-004")
    answer = what_to_do(impact, _KNOWLEDGE, "CERT-004")

    tekst = impact.to_text()
    assert "CERT-009" in tekst
    assert "linkcertkeyname" in tekst
    assert impact.issued_certificates == ("CERT-009",)
    assert "(geen gebonden virtuele servers)" not in answer.to_text()
    assert answer.findings[0].certainty is Certainty.NOT_ESTABLISHED


# ---------------------------------------------------------------------------
# De gemeten vals-compleet-bevinding (2026-08-27).
#
# `objects/sslvserver.json` draagt DRIE virtuele servers (VSRV-001,
# VSRV-003, VSRV-002); `bindings/sslvserver_sslcertkey_binding
# .by-parent.json` draagt er TWEE (VSRV-003, VSRV-002). VSRV-001 heeft
# dus geen parent-vermelding: zijn certificaatbindingen zijn nooit gelezen.
# `bindings/sslcertkey_binding.by-parent.json` bevestigt onafhankelijk dat
# VSRV-001 wel degelijk aan CERT-009 hangt. Het antwoord op CERT-004
# meldde niettemin twee diensten, met `read_gaps: []` en
# `is_complete: True` - een compleet ogend antwoord met het tegenbewijs in
# dezelfde export.
# ---------------------------------------------------------------------------


def test_the_lab_export_carries_a_third_sslvserver_without_a_binding_entry():
    """Eerst de meting zelf, zonder motor: dit is de brondata waar de rest
    van deze sectie op steunt."""
    import json

    objects = json.loads((FIXTURE / "objects" / "sslvserver.json").read_text(encoding="utf-8-sig"))
    bindings = json.loads(
        (FIXTURE / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").read_text(encoding="utf-8-sig")
    )
    assert {o["vservername"] for o in objects["sslvserver"]} == {
        "VSRV-001",
        "VSRV-003",
        "VSRV-002",
    }
    assert {p["parentName"] for p in bindings["parents"]} == {"VSRV-003", "VSRV-002"}


def test_the_unread_third_sslvserver_appears_as_a_read_gap_in_every_impact_answer():
    """Van wie VSRV-001's certificaat is, staat nergens in het bindingsbestand.
    Voor ELK certificaat geldt daarmee dat niet uit te sluiten is dat VSRV-001
    er aan hangt - dus draagt elk impactantwoord dit leesgat."""
    export = _load()
    for certnaam in ("CERT-004", "CERT-009", "een-naam-die-hier-niet-bestaat"):
        answer = what_breaks(export, _KNOWLEDGE, certnaam)
        assert answer.read_gaps, f"{certnaam}: het ongelezen VSRV-001 hoort zichtbaar te zijn"
        tekst = " ".join(f"{g.source} {g.reason}" for g in answer.read_gaps)
        assert "VSRV-001" in tekst, f"{certnaam}: het leesgat moet de ongelezen dienst benoemen"
        assert answer.is_complete() is False, f"{certnaam}: dit antwoord is niet compleet"


def test_the_lab_ca_answer_no_longer_claims_a_complete_picture():
    """De blokkerende bevinding, op de kop: het antwoord op CERT-004 noemt
    twee diensten, maar mag niet langer compleet ogen zolang de bindingen
    van de derde virtuele server ongelezen zijn."""
    export = _load()
    answer = what_breaks(export, _KNOWLEDGE, "CERT-004")
    assert answer.is_complete() is False
    subjects = {b.subject for b in answer.findings}
    assert {"CERT-009", "VSRV-003", "VSRV-002"} <= subjects, (
        "wat WEL vastgesteld is blijft staan; het leesgat komt ernaast, niet ervoor in de plaats"
    )


def test_no_change_proposal_while_a_service_binding_is_unread():
    """Sluitstuk: een omkoppeladvies dat alleen VSRV-003 en VSRV-002
    noemt, laat VSRV-001 kapot achter. Zolang die binding ongelezen is, hoort
    er geen voorstel te komen."""
    export = _load()
    impact = what_breaks(export, _KNOWLEDGE, "CERT-009")
    answer = what_to_do(impact, _KNOWLEDGE, "CERT-009")
    assert answer.read_gaps, "het leesgat uit het impactantwoord moet meereizen"
    assert answer.findings[0].certainty is Certainty.NOT_ESTABLISHED
    assert "geen wijzigingsvoorstel" in answer.findings[0].outcome
