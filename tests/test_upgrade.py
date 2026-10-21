import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from nsmcp.preflight import ASSUMED_BUNDLE_MB
from nsmcp.upgrade import (
    _CLOSING_EVENTS,
    ABSOLUTE_FLOOR_MB,
    FAMILIES,
    GATE_OUTCOMES,
    GATE_TYPES,
    PHASE_LIMITS_S,
    PHASE_OUTCOMES,
    SOAK_WORDS,
    START_WAIT_S,
    _bounded_run_echo,
    append_line,
    disk_gate,
    evaluate_phase,
    hash_gate,
    is_safe_run_name,
    ledger_path_for,
    normalised_anchor,
    order_gate,
    phase_state,
    precheck_gate,
    read_ledger,
    run_id,
    secondary_gate,
    soak_gate,
    soak_state,
)

FIXTURES = Path(__file__).parent / "fixtures"
NU = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def test_the_vocabulary_is_the_designs_vocabulary():
    assert GATE_TYPES == ("voorwaarde", "bewijs", "mens", "tijd")
    assert GATE_OUTCOMES == ("open", "dicht", "niet beoordeeld")
    assert PHASE_OUTCOMES == ("gestart", "poort dicht", "geslaagd", "mislukt", "niet beoordeeld")
    assert SOAK_WORDS == ("loopt", "verstreken")
    assert FAMILIES == (
        "lbvserver",
        "csvserver",
        "vpnvserver",
        "authenticationvserver",
        "service",
        "servicegroup",
        "sslcertkey",
        "lbmonitor",
    )
    assert PHASE_LIMITS_S == {"R0": 0, "R1": 3600, "R2": 900, "R3": 1800, "R4": 1800, "R5": 300, "R6": 0}
    assert START_WAIT_S == 20


def test_the_run_id_is_time_then_target():
    assert run_id("lab-02", NU) == "20260906T120000Z-lab-02"


def test_run_id_rejects_a_naive_datetime_instead_of_guessing_local_time():
    """Regressie: `astimezone()` op een NAIEVE datetime leest
    hem stilzwijgend als systeem-lokale tijd. Fail closed, niet gokken."""
    naief = datetime(2026, 9, 6, 12, 0, 0)
    with pytest.raises(ValueError):
        run_id("lab-02", naief)


# ---------- is_safe_run_name / ledger_path_for (run as a filesystem path) ----------


def test_bounded_run_echo_collapses_embedded_line_breaks():
    forged = "r1\n- R0: geslaagd [vastgesteld]\n    bewijs: forged evidence, not real"
    assert "\n" not in _bounded_run_echo(forged)


def test_bounded_run_echo_strips_control_characters_and_ansi_escapes():
    """`splitlines()` alleen collapt
    regeleinden - een ESC-byte (ANSI-terugloop/-wis), BEL of NUL overleeft
    dat ongemoeid en kan de vorige regel laten herschrijven zodra een
    operator het bestand `type`t. Dit is de ENE gedeelde sanitiser
    (`knowledge_refresh._safe_echo` was hier een letterlijke kopie van en
    is verwijderd); deze test hoort dus ook bij dezelfde hardening."""
    kwaadaardig = "2026.09\x1b[1A\x1b[2K  GEINSTALLEERD gefaked\x07\x00"
    schoon = _bounded_run_echo(kwaadaardig)
    for stuurteken in ("\x1b", "\x07", "\x00"):
        assert stuurteken not in schoon
    assert "2026.09" in schoon
    assert "GEINSTALLEERD gefaked" in schoon


def test_bounded_run_echo_still_bounds_the_length():
    lang = "r" * 5000
    assert "...(afgekapt)" in _bounded_run_echo(lang)
    assert lang not in _bounded_run_echo(lang)


def test_run_id_itself_is_always_a_safe_run_name():
    """What `run_id()` produces - a timestamp that starts with a DIGIT -
    must pass its own neighbour function; otherwise R1..R6 would refuse
    every retry of an R0 the product itself just formed."""
    assert is_safe_run_name(run_id("lab-02", NU))
    assert is_safe_run_name("run-a")
    assert is_safe_run_name("een-vorige-run")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "..",
        "../evil",
        "..\\evil",
        "a/b",
        "a\\b",
        "sub/../../evil",
        "C:evil",
        "C:\\evil",
        "\\\\server\\share",
        "a:b",
        "a:stream",
        "CON",
        "con",
        "Con",
        "CON.jsonl",
        "con.foo",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "com9",
        "LPT1",
        "lpt9",
        "run.",
        "run..",
        "run ",
        " run",
        "run\x00evil",
        "run\nevil",
        ".hidden",
        "a" * 129,
    ],
)
def test_an_unsafe_run_name_is_refused(value):
    assert not is_safe_run_name(value)


@pytest.mark.parametrize(
    "value",
    [
        "run-a",
        "run_b",
        "run.b",
        "20260906T120000Z-lab-02",
        "1abc",
        "a" * 128,
        "myrun.CON",  # CON is not the FIRST dot-component - Windows only looks at that one
    ],
)
def test_a_safe_run_name_is_accepted(value):
    assert is_safe_run_name(value)


def test_ledger_path_for_builds_the_expected_path(tmp_path):
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    path = ledger_path_for(ledgermap, "run-a")
    assert path == (ledgermap / "run-a.jsonl").resolve()


@pytest.mark.parametrize(
    "value",
    [
        "../evil",
        "..\\evil",
        "../../evil",
        "..\\..\\evil",
    ],
)
def test_ledger_path_for_refuses_a_run_name_that_escapes_ledgermap(tmp_path, value):
    """BRACES: even a `run_name` that somehow got past the grammar gate
    (BELT) must not let the built path end up outside `ledgermap`. Proves
    the refusal happens BEFORE anything is read or written -
    `ledger_path_for` never touches disk, it only computes
    `Path.resolve()`."""
    ledgermap = tmp_path / "ledger"
    ledgermap.mkdir()
    outside_file = tmp_path / "outside-marker.txt"
    assert not outside_file.exists()
    with pytest.raises(ValueError):
        ledger_path_for(ledgermap, value)
    # Still nothing written or read outside ledgermap - the refusal fell
    # before any file operation ever happened.
    assert not outside_file.exists()
    assert list(ledgermap.iterdir()) == []


# ---------- de vendor-precheckpoort (MUTATIEPROEF 12) ----------


def test_the_vendor_precheck_gate_ignores_the_exit_code():
    """Gemeten: exit 0 bij global_status failed. Wie $? gebruikt, bouwt de
    stille groene poort die dit product zegt te voorkomen."""
    poort = precheck_gate((FIXTURES / "precheck-json" / "global-failed.json").read_text())
    assert poort.outcome == "dicht"
    assert "global_status" in poort.evidence


def test_a_failed_individual_check_closes_the_gate_even_when_global_says_success():
    poort = precheck_gate((FIXTURES / "precheck-json" / "deelcheck-failed.json").read_text())
    assert poort.outcome == "dicht"


def test_an_unreadable_precheck_json_closes_the_gate():
    for tekst in (None, "", "geen json", (FIXTURES / "precheck-json" / "onleesbaar.json").read_text()):
        assert precheck_gate(tekst).outcome == "dicht"


def test_the_precheck_gate_has_no_not_assessed_outcome():
    """De enige poort in dit ontwerp zonder 'niet beoordeeld': een niet-gelezen
    vendoroordeel is bij een firmware-installatie een nee."""
    for tekst in (None, "", "{}", (FIXTURES / "precheck-json" / "geslaagd.json").read_text()):
        assert precheck_gate(tekst).outcome in ("open", "dicht")


def test_the_precheck_gate_opens_only_when_both_conditions_hold():
    poort = precheck_gate((FIXTURES / "precheck-json" / "geslaagd.json").read_text())
    assert poort.outcome == "open"


def test_the_precheck_gate_bounds_an_untrusted_global_status_string():
    """`global_status` en de gezakte checknamen komen recht
    uit de vendor-JSON - UNTRUSTED - en mogen niet raw en onbegrensd in het
    bewijs/de reden landen (patroon: `collect._short_report`). Een gezakte
    check dwingt de `dicht`-tak af, zodat `global_status` zelf niet
    letterlijk "failed" hoeft te zijn om de begrenzing te raken."""
    tekst = json.dumps(
        {
            "global_status": "X" * 5000,
            "checks": [{"name": "disk_space", "status": "failed"}],
        }
    )
    poort = precheck_gate(tekst)
    assert poort.outcome == "dicht"
    assert len(poort.evidence) < 1000


def test_the_precheck_gate_bounds_many_failed_check_names():
    checks = [{"name": f"check-{i}", "status": "failed"} for i in range(500)]
    tekst = json.dumps({"global_status": "success", "checks": checks})
    poort = precheck_gate(tekst)
    assert poort.outcome == "dicht"
    assert len(poort.reason) < 2000
    assert "meer" in poort.reason


# ---------- de schijfruimtepoort van R1 (MUTATIEPROEF 10) ----------


def test_free_space_below_the_vendor_floor_closes_the_gate():
    poort = disk_gate(free_mb=5000, bundle_mb=1081, unpack_mb=1673)
    assert poort.outcome == "dicht"
    for term in ("4004", "1081", "1673"):
        assert term in poort.reason, "de weigering noemt de drie termen apart"


def test_free_space_above_the_requirement_opens_the_gate():
    assert disk_gate(free_mb=9000, bundle_mb=1081, unpack_mb=1673).outcome == "open"


def test_the_absolute_floor_holds_even_for_a_tiny_bundle():
    assert ABSOLUTE_FLOOR_MB == 6144
    assert disk_gate(free_mb=6000, bundle_mb=1, unpack_mb=1).outcome == "dicht"


def test_a_missing_measurement_is_not_assessed_and_never_open():
    assert disk_gate(free_mb=None, bundle_mb=1081, unpack_mb=1673).outcome == "niet beoordeeld"


def test_a_missing_bundle_size_uses_the_assumption_not_zero():
    """Regressie (mutatieproef 10): `int(bundle_mb or 0)`
    liet een missende meting stilzwijgend 0 MB wegen, en dat opende de
    poort waar `ASSUMED_BUNDLE_MB` hem dicht moet houden. Exacte meting:
    free_mb=6200 met bundle_mb/unpack_mb beide None."""
    poort = disk_gate(free_mb=6200, bundle_mb=None, unpack_mb=None)
    assert poort.outcome == "dicht"
    assert str(ASSUMED_BUNDLE_MB) in poort.evidence, "de aanname staat met naam in het bewijs"


def test_a_missing_bundle_size_is_named_as_an_assumption_in_the_reason():
    poort = disk_gate(free_mb=6200, bundle_mb=None, unpack_mb=None)
    assert "aangenomen" in poort.reason


def test_a_partially_missing_bundle_size_only_assumes_the_missing_half():
    """Alleen de ONTBREKENDE meting wordt aangenomen; de wel-gemeten helft
    telt gewoon mee."""
    volledig_aangenomen = disk_gate(free_mb=6200, bundle_mb=None, unpack_mb=None)
    half_aangenomen = disk_gate(free_mb=6200, bundle_mb=1081, unpack_mb=None)
    assert half_aangenomen.outcome == "open"  # 4004+1081+1100=6185 <= 6200
    assert volledig_aangenomen.outcome == "dicht"  # 4004+1100+1100=6204 > 6200


def test_free_space_above_the_assumed_requirement_still_opens():
    assert disk_gate(free_mb=6204, bundle_mb=None, unpack_mb=None).outcome == "open"


def test_a_present_bundle_counts_as_a_deliberate_zero_not_an_unmeasured_assumption():
    """R1 overslaat de upload als de bundel al
    met de juiste SHA op de doos staat - er is dan geen tweede kopie meer
    nodig, dus de bundelterm is een BEWUSTE nul. Gemeten (reviewrapport):
    `disk_gate(6200, 0, None)` was byte-identiek aan het upload-geval
    `disk_gate(6200, 1100, None)` - de falsy `bundle_mb=0` werd gelezen als
    ONGEMETEN en kreeg `ASSUMED_BUNDLE_MB` (1100), terwijl de eis "telt dan
    alleen de uitpakruimte" letterlijk in A4 staat en het bewijs beweerde
    dat de grootte "ontbrak" over een bundel die wel degelijk lokaal
    gemeten is. `bundle_present=True` maakt dat verschil expliciet: de
    drempel daalt naar de absolute vloer (geen assumptie meer nodig voor
    de bundelterm), en het bewijs noemt "0 MB nog te ontvangen" in plaats
    van een aangenomen grootte."""
    # unpack_mb krijgt een ECHTE meting die NIET toevallig gelijk is aan
    # ASSUMED_BUNDLE_MB (1100), zodat alleen het effect van bundle_present
    # wordt getoetst - de uitpakterm blijft, terecht, apart aan te nemen
    # zolang die zelf niet gemeten is (zie de tegenprobe hieronder met
    # unpack_mb=None).
    assert 1673 != ASSUMED_BUNDLE_MB
    aangenomen = disk_gate(free_mb=6200, bundle_mb=0, unpack_mb=1673)
    bewust_aanwezig = disk_gate(free_mb=6200, bundle_mb=0, unpack_mb=1673, bundle_present=True)
    assert aangenomen.outcome == "dicht"
    assert bewust_aanwezig.outcome == "open"
    assert ABSOLUTE_FLOOR_MB == 6144
    assert "aangenomen" not in bewust_aanwezig.evidence
    assert str(ASSUMED_BUNDLE_MB) not in bewust_aanwezig.evidence
    assert "0 MB nog te ontvangen" in bewust_aanwezig.evidence
    assert bewust_aanwezig.evidence != aangenomen.evidence

    # De uitpakkosten blijven wel gewoon een aparte, mogelijk aangenomen
    # term - bundle_present verandert alleen de BUNDEL, nooit de uitpak.
    beide_bewust = disk_gate(free_mb=6200, bundle_mb=0, unpack_mb=None, bundle_present=True)
    assert "aangenomen" in beide_bewust.evidence
    assert "0 MB nog te ontvangen" in beide_bewust.evidence


# ---------- de primary-node-weigering (MUTATIEPROEF 13) ----------
#
# De body
# van dit mutatiebewijs komt uit het plan van record, maar het plan zelf eist
# expliciet "mutatieproof 13 = primary-node refusal" - dat is precies wat de
# ENKELE-node-fixture hieronder NOOIT kon bewijzen, want ze bevat de peer
# helemaal niet. Op een echt HA-paar somt 'show ha node' BEIDE nodes op, elk
# met zijn EIGEN 'Master State:' - de oude implementatie zocht 'secondary'
# over de VOLLEDIGE tekst, dus de PEER's regel opende de poort terwijl deze
# fase op de PRIMARY draaide. Dat is precies de poort waar deze hele route
# voor bestaat. De striktere lezing (alleen het blok van de LOKALE node,
# Node ID: 0) implementeert dus de bedoeling die het plan zelf al uitsprak;
# alleen de voorbeeld-body van het plan is vervangen door een fixture die de
# fout echt kan vangen.
#
# Een GENUINE two-node 'show ha node'-tekst (NetScaler CLI-vorm). A later
# fix: the comment here used to claim "publiek
# gedocumenteerd, geen klant-/labdata" while the IP's below were the REAL
# lab appliance's own addresses - false the moment it was written. They are
# now RFC 5737 TEST-NET-1 (192.0.2.0/24, reserved for documentation and
# guaranteed never a real host), so the comment is true now instead of
# corrected to admit otherwise. Node ID 0 draagt GEEN nummerprefix (de
# lokale node), Node ID 1 draagt '1)' - de scheiding tussen blokken komt
# uit 'Node ID:' zelf, niet uit die prefix.
_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL = """\
        Node ID:                        0
        IP:                             192.0.2.11
        Node State:                     UP
        Master State:                   Primary
        Fail-Safe Mode:                 OFF
        INC State:                      DISABLED
        Sync State:                     ENABLED
        Propagation:                    ENABLED
        Enabled Interfaces :            0/1,0/2
        Disabled Interfaces :           None
        HA MON ON Interfaces :          0/1,0/2
        HA MON OFF Interfaces:          None
        RPC Node Password:              Not Set (Default password in use)
        Critical Interfaces:

1)      Node ID:                        1
        IP:                             192.0.2.12
        Node State:                     UP
        Master State:                   Secondary
        Fail-Safe Mode:                 OFF
        INC State:                      DISABLED
        Sync State:                     SUCCESS
        Propagation:                    ENABLED
        Enabled Interfaces :            0/1,0/2
        Disabled Interfaces :           None
        HA MON ON Interfaces :          0/1,0/2
        HA MON OFF Interfaces:          None
        RPC Node Password:              Not Set (Default password in use)
        Critical Interfaces:

 Done
"""

# Hetzelfde paar, maar vanaf de SECONDARY node bekeken: Node ID 0 (lokaal,
# geen prefix) is nu Secondary, Node ID 1 (de peer, '1)') is Primary - de
# rollen zijn precies omgedraaid t.o.v. hierboven, de IP's staan vast per
# node (de doos met .11 is en blijft de doos met .11).
_HA_NODE_TWEE_NODES_SECONDARY_LOKAAL = """\
        Node ID:                        0
        IP:                             192.0.2.12
        Node State:                     UP
        Master State:                   Secondary
        Fail-Safe Mode:                 OFF
        INC State:                      DISABLED
        Sync State:                     SUCCESS
        Propagation:                    ENABLED
        Critical Interfaces:

1)      Node ID:                        1
        IP:                             192.0.2.11
        Node State:                     UP
        Master State:                   Primary
        Fail-Safe Mode:                 OFF
        INC State:                      DISABLED
        Sync State:                     ENABLED
        Propagation:                    ENABLED
        Critical Interfaces:

 Done
"""


def test_a_phase_on_the_primary_node_is_refused():
    """De ENKELE-node vorm blijft bestaan ('keep a single-node
    case too') - dit is de simpelste, degenererende vorm van dezelfde regel:
    een tekst met precies een 'Node ID:'-blok."""
    poort = secondary_gate("Node ID: 0\n Master State: Primary\n")
    assert poort.outcome == "dicht"
    assert secondary_gate("Node ID: 0\n Master State: Secondary\n").outcome == "open"


def test_a_phase_on_the_primary_node_of_a_real_ha_pair_is_refused_despite_the_peers_secondary_line():
    """DE KERN VAN C3: op een echt HA-paar draagt de PEER (Node ID 1, hier
    Secondary) een 'Master State: Secondary'-regel, ergens verderop in
    DEZELFDE 'show ha node'-uitvoer. Deze fase draait op de LOKALE node
    (Node ID 0), die hier Primary is - de poort moet dus DICHT staan, ook al
    bevat de volledige tekst het woord 'secondary'. De oude implementatie
    ("secondary" in de hele, verlaagde tekst) opende deze poort ten onrechte:
    precies de fout die deze fix sluit."""
    poort = secondary_gate(_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL)
    assert poort.outcome == "dicht", poort
    assert poort.reason == "een fase raakt nooit de primary node"


def test_a_phase_on_the_secondary_node_of_a_real_ha_pair_still_opens():
    """De spiegeling van de vorige test: draait deze fase op de node die
    ECHT Secondary is (Node ID 0 hier), dan opent de poort - ook al bevat de
    tekst nu een 'Master State: Primary'-regel voor de PEER."""
    poort = secondary_gate(_HA_NODE_TWEE_NODES_SECONDARY_LOKAAL)
    assert poort.outcome == "open", poort


def test_the_ip_of_node_zero_must_match_the_target_when_a_target_is_given():
    """C3: 'Return niet beoordeeld (never open) when ... its IP does not
    match the target.' Node ID 0 in de primary-lokaal-fixture draagt IP
    192.0.2.11 - vraag je de poort te toetsen tegen een ANDER adres, dan
    is dat een niet-vastgestelde identiteit, nooit een stille 'dicht' of
    'open' op de gegevens van de verkeerde doos."""
    juist = secondary_gate(_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL, doel_adres="192.0.2.11")
    onjuist = secondary_gate(_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL, doel_adres="192.0.2.99")
    assert juist.outcome == "dicht"
    assert onjuist.outcome == "niet beoordeeld", onjuist
    assert onjuist.outcome != "open"


def test_no_target_address_given_skips_the_ip_check_and_still_judges_on_state():
    """Zonder een meegegeven doelwit-adres (het optionele geval - een
    aanroeper die dat nog niet doorgeeft) blijft de poort op de rolverdeling
    alleen oordelen, precies zoals voor deze fix - geen stille regressie naar
    'niet beoordeeld' voor elke aanroeper die het adres nog niet meegeeft."""
    assert secondary_gate(_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL, doel_adres=None).outcome == "dicht"
    assert secondary_gate(_HA_NODE_TWEE_NODES_PRIMARY_LOKAAL, doel_adres="").outcome == "dicht"


def test_a_node_zero_block_that_cannot_be_isolated_is_not_assessed():
    """Geen enkel 'Node ID:' in de tekst: het blok van de lokale node kan
    niet geisoleerd worden, dus 'niet beoordeeld' - nooit een gok op de
    ongestructureerde rest van de tekst."""
    assert secondary_gate("Master State: Secondary (geen Node ID te vinden)").outcome == "niet beoordeeld"


def test_an_unreadable_ha_state_is_not_assessed_and_never_open():
    for uitvoer in (None, "", "onleesbaar"):
        assert secondary_gate(uitvoer).outcome == "niet beoordeeld"


# ---------- de soakpoort (MUTATIEPROEF 11) ----------


def test_the_soak_window_cannot_be_shortened_by_a_tool():
    regels = read_ledger(FIXTURES / "ledger" / "soak-open.jsonl")
    poort = soak_gate(regels, NU, soak_hours=24)
    assert poort.outcome == "dicht"
    assert poort.type == "tijd"
    # geen argument, geen sleutel, geen vlag verkort dit
    with pytest.raises(TypeError):
        soak_gate(regels, NU, soak_hours=24, overslaan=True)


def test_a_soak_shorter_than_twenty_four_hours_is_lifted_to_twenty_four():
    regels = read_ledger(FIXTURES / "ledger" / "soak-open.jsonl")
    assert soak_gate(regels, NU, soak_hours=1).outcome == "dicht"


def test_the_soak_window_is_measured_on_the_ledger_timestamps_in_utc():
    regels = read_ledger(FIXTURES / "ledger" / "soak-open.jsonl")
    begin = datetime.fromisoformat(regels[-1]["gestart"].replace("Z", "+00:00"))
    assert soak_gate(regels, begin + timedelta(hours=23, minutes=59), 24).outcome == "dicht"
    assert soak_gate(regels, begin + timedelta(hours=24, seconds=1), 24).outcome == "open"


def test_a_gestart_in_the_far_future_never_binds_the_window_or_crashes(tmp_path):
    """Carried defect, since closed: a `soak_open` row with a
    `gestart` of `9999-12-31` used to bind the window DETERMINISTICALLY
    (the newest timestamp always wins) and raise `OverflowError` the
    moment `soak_gate` added `timedelta(hours=...)` to it - `datetime.max`
    IS `9999-12-31`. That OverflowError surfaced at the CLI as "onleesbare
    invoer op stdin" over perfectly readable stdin (upgrade_gate.run()'s
    catch-all), and blocked every R0/R6 on that target permanently. A soak
    window cannot begin in the future, so it now reads exactly like an
    unparseable `gestart`: counted, never trusted, never `open`.
    """
    pad = tmp_path / "toekomst.jsonl"
    append_line(
        pad,
        {
            "tijd": "2026-09-06T08:00:00Z",
            "run": "r1",
            "doel": "lab-02",
            "fase": "R6",
            "gebeurtenis": "soak_open",
            "poort": [],
            "uitkomst": "geslaagd",
            "bewijs": "test",
            "actieid": "a-1",
            "bevestiger": "tester",
            "gestart": "9999-12-31T00:00:00Z",
            "geeindigd": "2026-09-06T08:05:00Z",
        },
    )
    regels = read_ledger(pad)

    poort = soak_gate(regels, NU, soak_hours=24)  # mag niet raises (OverflowError)
    assert poort.outcome == "niet beoordeeld"

    woord, eindtijd = soak_state(regels, NU, 24)  # mag niet raises
    assert woord is None
    assert eindtijd is None


def test_the_state_word_is_loopt_then_verstreken():
    open_regels = read_ledger(FIXTURES / "ledger" / "soak-open.jsonl")
    weg_regels = read_ledger(FIXTURES / "ledger" / "soak-verstreken.jsonl")
    assert soak_state(open_regels, NU, 24)[0] == "loopt"
    assert soak_state(weg_regels, NU, 24)[0] == "verstreken"


def test_the_soak_evidence_is_parseable_iso8601_not_double_z():
    """Regressie: `f'{begin.isoformat()}Z'` op een AWARE
    datetime geeft `+00:00Z`, onparseerbaar. Gemeten: soak_state gaf
    ('loopt', '...+00:00Z')."""
    regels = read_ledger(FIXTURES / "ledger" / "soak-open.jsonl")
    _, eindtijd = soak_state(regels, NU, 24)
    assert eindtijd is not None
    datetime.fromisoformat(eindtijd.replace("Z", "+00:00"))  # mag niet raises

    poort = soak_gate(regels, NU, soak_hours=24)
    assert "+00:00Z" not in poort.evidence
    assert "+00:00Z" not in poort.reason


def test_a_never_opened_soak_window_reports_no_word_not_verstreken():
    """Regressie: `lopend.jsonl` heeft nooit een R6 gehad -
    `verstreken` zou beweren dat er een venster GEWEEST is."""
    regels = read_ledger(FIXTURES / "ledger" / "lopend.jsonl")
    woord, eindtijd = soak_state(regels, NU, 24)
    assert woord is None
    assert eindtijd is None


def test_a_second_run_on_the_same_target_is_refused_while_one_is_open():
    """Asked of `open_phases()`, which is what the product
    itself asks. `open_run()` used to wrap it and had no production caller
    left after an earlier fix - a kept function nothing ships against."""
    from nsmcp.upgrade import open_phases

    lopend = read_ledger(FIXTURES / "ledger" / "lopend.jsonl")
    assert open_phases(lopend) != ()
    klaar = read_ledger(FIXTURES / "ledger" / "geslaagd.jsonl")
    assert open_phases(klaar) == ()


# ---------- volgorde, ledger als waarheid, tijdslimiet ----------


def test_a_phase_whose_predecessor_did_not_close_is_refused():
    regels = read_ledger(FIXTURES / "ledger" / "poort-dicht.jsonl")
    assert order_gate("R2", regels).outcome == "dicht"


def test_a_phase_whose_predecessor_closed_with_geslaagd_opens():
    """`order_gate` had alleen een negatief geval - een
    implementatie die altijd 'dicht' geeft, haalde de rest van de suite."""
    regels = read_ledger(FIXTURES / "ledger" / "geslaagd.jsonl")
    assert order_gate("R2", regels).outcome == "open"


def test_the_closing_events_map_only_to_real_phase_outcomes():
    """`_CLOSING_EVENTS`' VALUES werden nergens direct
    gecontroleerd (alleen incidenteel via de `open_phases`-test)."""
    assert set(_CLOSING_EVENTS.values()) <= set(PHASE_OUTCOMES)
    assert _CLOSING_EVENTS == {
        "fase_geslaagd": "geslaagd",
        "fase_mislukt": "mislukt",
        "poort_dicht": "poort dicht",
        "voormeting_vast": "geslaagd",
        "soak_open": "geslaagd",
    }


def test_the_ledger_and_not_the_log_decides_the_verdict(tmp_path):
    leeg = tmp_path / "leeg.jsonl"
    leeg.write_text("", encoding="utf-8")
    assert phase_state(read_ledger(leeg), "R3") == "niet beoordeeld"


def test_a_gate_that_was_not_assessed_never_counts_as_open():
    from nsmcp.upgrade import Gate

    poorten = (Gate("x", "bewijs", "niet beoordeeld", "geen meting", "de meting ontbrak"),)
    verdict = evaluate_phase("R1", {}, {"gates": poorten})
    assert verdict.outcome == "poort dicht"


# ---------- een verplichte poortenset per fase ----------
#
# `evaluate_phase()` oordeelde eerder alleen over de poorten die de aanroeper
# TOEVALLIG had laten meten - WELKE poorten een fase draagt, wordt volledig
# in PowerShell beslist, in `$verzoeken` (`Invoke-GjkUpgradeFase.ps1`).
# Verwijder daar EEN regel (de 'secondary'-aanvraag, bijvoorbeeld) en de hele
# testsuite bleef groen terwijl de fase 'geslaagd' sloot op een primary node
# - de naad die geen enkele taakgebonden review kon zien, omdat elke taak
# zijn EIGEN poortenset correct afleverde. `REQUIRED_GATES` pint nu, per
# fase, welke poortnamen een echte aanroep ALTIJD draagt; een ontbrekende
# verplichte poort wordt een gesynthetiseerde `niet beoordeeld`-poort (nooit
# `open`), die de fase via de bestaande regel 3 op `poort dicht` sluit.


def _open_gates(namen) -> tuple:
    from nsmcp.upgrade import Gate

    return tuple(Gate(naam, "bewijs", "open", "gemeten") for naam in sorted(namen))


def _assert_missing_required_gate_closes_the_phase(fase: str, alle_namen, ontbrekende_naam: str):
    from nsmcp.upgrade import evaluate_phase

    aanwezig = tuple(g for g in _open_gates(alle_namen) if g.name != ontbrekende_naam)
    verdict = evaluate_phase(fase, {}, {"gates": aanwezig})
    assert verdict.outcome == "poort dicht", (fase, ontbrekende_naam, verdict)
    synthetisch = next((g for g in verdict.gates if g.name == ontbrekende_naam), None)
    assert synthetisch is not None, (
        f"{fase}: ontbrekende verplichte poort {ontbrekende_naam!r} verschijnt niet in het oordeel"
    )
    assert synthetisch.outcome == "niet beoordeeld"


def test_the_full_required_gate_set_still_closes_geslaagd_for_every_phase():
    """Bewijst dat de testopstelling zelf klopt: met ELKE verplichte poort
    aanwezig en open, sluit iedere fase gewoon `geslaagd` - de fix mag de
    normale, complete meting niet raken."""
    from nsmcp.upgrade import REQUIRED_GATES, evaluate_phase

    for fase, namen in REQUIRED_GATES.items():
        from upgrade_gate_harness import pre_gate_context

        context = pre_gate_context(fase)
        context["gates"] = _open_gates(namen)
        verdict = evaluate_phase(fase, {"actieid_uit_script": "a-1"}, context)
        assert verdict.outcome == "geslaagd", (fase, verdict)


def test_r0_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R0"]:
        _assert_missing_required_gate_closes_the_phase("R0", REQUIRED_GATES["R0"], naam)


def test_r1_closes_poort_dicht_when_any_required_gate_is_missing():
    """Verwijder 'doel is secondary' (wat het
    verwijderen van Invoke-GjkUpgradeFase.ps1's 'secondary'-aanvraag zou
    doen) en R1 mag nooit meer stilzwijgend 'geslaagd' sluiten op een
    primary node - de poort die nooit gemeten werd, telt nu als niet
    beoordeeld, en niet beoordeeld sluit nooit geslaagd."""
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R1"]:
        _assert_missing_required_gate_closes_the_phase("R1", REQUIRED_GATES["R1"], naam)


def test_r2_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R2"]:
        _assert_missing_required_gate_closes_the_phase("R2", REQUIRED_GATES["R2"], naam)


def test_r2_vendor_precheck_is_not_required_because_it_is_legitimately_conditional():
    """'vendor-precheck' wordt alleen gestuurd als de buildboom een
    pre-check ondersteunt - het ONTBREKEN ervan is een echte, geldige
    uitkomst en mag R2 niet weigeren die anders zou slagen."""
    from nsmcp.upgrade import REQUIRED_GATES, evaluate_phase

    assert "vendor-precheck" not in REQUIRED_GATES["R2"]
    zonder_precheck = tuple(
        g for g in _open_gates(REQUIRED_GATES["R2"]) if g.name != "pre-check-ondersteuning aanwezig"
    ) + _open_gates({"pre-check-ondersteuning aanwezig"})
    from upgrade_gate_harness import pre_gate_context

    context = pre_gate_context("R2")
    context["gates"] = zonder_precheck
    verdict = evaluate_phase("R2", {"actieid_uit_script": "a-1"}, context)
    assert verdict.outcome == "geslaagd", verdict


def test_r3_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R3"]:
        _assert_missing_required_gate_closes_the_phase("R3", REQUIRED_GATES["R3"], naam)


def test_r4_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R4"]:
        _assert_missing_required_gate_closes_the_phase("R4", REQUIRED_GATES["R4"], naam)


def test_r5_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R5"]:
        _assert_missing_required_gate_closes_the_phase("R5", REQUIRED_GATES["R5"], naam)


def test_r6_closes_poort_dicht_when_any_required_gate_is_missing():
    from nsmcp.upgrade import REQUIRED_GATES

    for naam in REQUIRED_GATES["R6"]:
        _assert_missing_required_gate_closes_the_phase("R6", REQUIRED_GATES["R6"], naam)


def test_a_phase_timeout_writes_a_failed_ledger_line():
    verdict = evaluate_phase("R1", {"tijdslimiet_overschreden": True}, {})
    assert verdict.outcome == "mislukt"
    assert verdict.reason == "tijdslimiet"


def test_the_actieid_in_the_ledger_must_match_the_confirmed_target():
    verdict = evaluate_phase("R1", {"actieid_uit_script": "a-2"}, {"actieid": "a-1"})
    assert verdict.outcome == "mislukt"
    assert "komen niet overeen" in verdict.reason


def test_the_hash_gate_compares_with_the_vendor_value_and_not_with_itself():
    assert hash_gate("aa", "aa").outcome == "open"
    assert hash_gate("aa", "bb").outcome == "dicht"
    assert hash_gate(None, "aa").outcome == "dicht", (
        "zonder de vendorwaarde is er geen hashpoort; ontwerp 3.5 zegt dicht"
    )


# ---------- het genormaliseerde anker ----------


def test_the_anchor_drops_comments_blank_lines_and_blob_lines_and_counts_them():
    regels = [
        "# NS14.1 Build 72.57",
        "",
        "add lb vserver a HTTP 1.1.1.1 80",
        "set ns encryptionParams -method AES256 -keyValue abc",
        "set ns rpcNode 1.1.1.1 -password xyz -encrypted -encryptmethod ENCMTHD_3",
        "add lb monitor m HTTP -password geheim -encrypted",
    ]
    anker, tellingen = normalised_anchor(regels)
    assert len(anker) == 64
    assert tellingen == {"set ns encryptionParams": 1, "set ns rpcNode": 1, "-encrypted": 1}


def test_the_anchor_is_order_independent():
    a = ["add lb vserver a HTTP", "add lb vserver b HTTP"]
    assert normalised_anchor(a)[0] == normalised_anchor(list(reversed(a)))[0]


def test_the_anchor_is_culture_independent():
    """Ordinaal sorteren, niet cultuurgevoelig (Sort-Object in de spike was dat wel)."""
    a = ["add x A", "add x a", "add x B"]
    assert normalised_anchor(a)[0] == normalised_anchor(sorted(a, key=str.lower))[0]


def test_a_changed_blob_count_is_itself_a_difference():
    een = ["set ns rpcNode 1 -password x -encrypted"]
    twee = een + ["set ns rpcNode 2 -password y -encrypted"]
    assert normalised_anchor(een)[1] != normalised_anchor(twee)[1]


# ---------- Het ledger vertrouwt geen enkele regelvorm ----------


def test_a_non_dict_line_is_skipped_not_a_crash(tmp_path):
    """Regressie: een regel die naar een lijst parseert
    kwam ongefilterd terug uit `read_ledger` en gaf een AttributeError
    verderop (`phase_state`/`open_phases`)."""
    pad = tmp_path / "ledger.jsonl"
    goed = {
        "tijd": "2026-09-06T08:00:00Z",
        "run": "r1",
        "doel": "lab-02",
        "fase": "R0",
        "gebeurtenis": "fase_gestart",
        "poort": [],
        "uitkomst": "gestart",
        "bewijs": "",
        "actieid": "a-0",
        "bevestiger": "u-1",
        "gestart": "2026-09-06T08:00:00Z",
        "geeindigd": None,
    }
    pad.write_text(json.dumps(goed) + "\n[1, 2, 3]\n", encoding="utf-8")
    with pytest.warns(RuntimeWarning):
        regels = read_ledger(pad)
    assert regels == (goed,)
    assert phase_state(regels, "R0") == "gestart"  # geen crash


def test_an_unparseable_trailing_line_does_not_hide_the_lines_before_it(tmp_path):
    """Een afgekapte laatste regel gaf voorheen een JSONDecodeError voor het
    HELE bestand - elke correct gesloten fase ervoor werd dan onzichtbaar."""
    pad = tmp_path / "ledger.jsonl"
    goed = {
        "tijd": "2026-09-06T08:00:00Z",
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
    pad.write_text(json.dumps(goed) + '\n{"tijd": "2026-09-06T09:00', encoding="utf-8")
    with pytest.warns(RuntimeWarning):
        regels = read_ledger(pad)
    assert regels == (goed,)
    assert phase_state(regels, "R0") == "geslaagd"


def test_open_phases_survives_a_row_without_a_fase_field(tmp_path):
    """Regressie: de open-fase-zoeker gebruikte `r["fase"]` naast
    `.get("gebeurtenis")` in dezelfde comprehension - een KeyError bij een
    rij zonder `fase`."""
    from nsmcp.upgrade import open_phases

    regels = (
        {"run": "r1", "gebeurtenis": "fase_gestart"},  # geen "fase"-sleutel
    )
    assert [f.run for f in open_phases(regels)] == ["r1"]


# ---------- append_line: de nieuw aangemaakte ledgermap is ook gefsynct ----------


def test_append_line_creates_a_readable_file_in_a_fresh_directory(tmp_path):
    """`_fsync_dir` is POSIX-only en best-effort; deze test bewijst alleen
    dat het niets breekt op dit platform, niet de fsync zelf (die is met
    een crashscenario niet in een unit test te meten)."""
    map_pad = tmp_path / "vers"
    map_pad.mkdir()
    pad = map_pad / "run.jsonl"
    append_line(pad, {"a": 1})
    assert read_ledger(pad) == ({"a": 1},)


# ---------- Het soakvenster kiest de NIEUWSTE begintijd ----------


def _iso_utc(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _soak_open_regel(gestart: str, run: str = "eerdere-run", doel: str = "lab-02") -> dict:
    return {
        "tijd": gestart,
        "run": run,
        "doel": doel,
        "fase": "R6",
        "gebeurtenis": "soak_open",
        "poort": [],
        "uitkomst": "geslaagd",
        "bewijs": "",
        "actieid": "a-r6",
        "bevestiger": "u-1",
        "gestart": gestart,
        "geeindigd": None,
    }


def test_the_soak_window_takes_the_newest_start_not_the_last_row_it_walked_past():
    """Regressie: `_soak_start` gaf de LAATSTE
    `soak_open` die het tegenkwam, niet die met de nieuwste `gestart`. De
    volgorde van de regels wordt bepaald door de BESTANDSNAMEN in de
    ledgermap, en die zijn niet te vertrouwen - een oude kopie ernaast
    verkortte het venster tot nul."""
    vers = _soak_open_regel(_iso_utc(NU - timedelta(hours=6)))
    oud = _soak_open_regel(_iso_utc(NU - timedelta(hours=200)), run="archief")
    # de OUDE regel komt als laatste binnen (bestandsnaam-volgorde)
    poort = soak_gate((vers, oud), NU, soak_hours=24)
    assert poort.outcome == "dicht", "het nieuwste venster bindt, niet het laatst gelezen"
    assert soak_state((vers, oud), NU, 24)[0] == "loopt"


def test_a_soak_row_without_a_readable_start_is_never_silently_open():
    """Een `soak_open` zonder leesbare `gestart` gaf een KeyError/ValueError
    (exit 2 op de CLI). Hij mag ook niet stil `open` worden: zonder gelezen
    begintijd is het venster NIET beoordeeld."""
    kapot = _soak_open_regel("n/a")
    zonder = _soak_open_regel(_iso_utc(NU))
    zonder.pop("gestart")
    for regels in ((kapot,), (zonder,)):
        poort = soak_gate(regels, NU, soak_hours=24)
        assert poort.outcome == "niet beoordeeld"
        assert poort.outcome != "open"
        assert soak_state(regels, NU, 24)[0] is None


def test_an_unreadable_soak_row_next_to_a_readable_one_never_opens_the_gate():
    """Een leesbaar, al verstreken venster naast een onleesbare regel mag
    de poort niet openen: die onleesbare regel kan het nieuwere venster
    zijn."""
    verstreken = _soak_open_regel(_iso_utc(NU - timedelta(hours=200)))
    kapot = _soak_open_regel("n/a", run="archief")
    assert soak_gate((verstreken,), NU, 24).outcome == "open"
    assert soak_gate((verstreken, kapot), NU, 24).outcome == "niet beoordeeld"


# ---------- Een afgekapt multibyte-teken ----------


def test_a_line_truncated_mid_multibyte_character_does_not_hide_the_lines_before_it(tmp_path):
    """Regressie: `read_text(encoding='utf-8')`
    liet EEN afgekapt teken in de laatste regel het HELE bestand
    onleesbaar maken (UnicodeDecodeError) - elke correct gesloten fase
    ervoor verdween. `append_line` schrijft met `ensure_ascii=False`, dus
    vendorteksten met accenten landen echt zo in het ledger."""
    pad = tmp_path / "ledger.jsonl"
    goed = {
        "tijd": "2026-09-06T08:00:00Z",
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
    afgekapt = json.dumps({"bewijs": "gecontroleerd\xe9"}, ensure_ascii=False).encode("utf-8")
    # afkappen MIDDEN in de tweebyte-`\xe9`: de laatste byte is een kale leadbyte
    pad.write_bytes(json.dumps(goed).encode("utf-8") + b"\n" + afgekapt[:-3])
    with pytest.warns(RuntimeWarning):
        regels = read_ledger(pad)
    assert regels == (goed,)
    assert phase_state(regels, "R0") == "geslaagd"


def test_a_readable_multibyte_ledger_line_still_reads_back_whole(tmp_path):
    pad = tmp_path / "ledger.jsonl"
    regel = {"fase": "R1", "bewijs": "vendormelding: \xe9\xe9n schijf vol \u2014 caf\xe9"}
    append_line(pad, regel)
    assert read_ledger(pad) == (regel,)


# ---------- _iso_z eist een aware datetime ----------


def test_iso_z_refuses_a_naive_datetime_instead_of_dropping_the_z():
    """`_iso_z` beloofde 'UTC ISO-8601 met een kale Z' maar gaf voor een
    NAIVE datetime stil een string ZONDER Z terug (`isoformat()` heeft dan
    geen `+00:00` om te vervangen). Dezelfde discipline als `run_id`."""
    from nsmcp.upgrade import _iso_z

    with pytest.raises(ValueError):
        _iso_z(datetime(2026, 9, 6, 12, 0, 0))
    assert _iso_z(NU).endswith("Z")
    # een AWARE niet-UTC datetime wordt eerst naar UTC gebracht
    anders = datetime(2026, 9, 6, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert _iso_z(anders) == "2026-09-06T12:00:00Z"


# ---------- De weigeringstekst van disk_gate ----------


def test_the_disk_refusal_reason_is_balanced_and_names_no_python_literal():
    """De aanname stond BINNEN de eigen tussenzin en liet `None` als
    Python-literal in klantgerichte tekst staan:
    '...uitpakkosten None MB (aangenomen bundelgrootte 1100 MB ...))'."""
    poort = disk_gate(free_mb=1000, bundle_mb=None, unpack_mb=None)
    assert poort.outcome == "dicht"
    assert "None" not in poort.reason
    assert "None" not in poort.evidence
    assert poort.reason.count("(") == poort.reason.count(")")
    assert poort.evidence.count("(") == poort.evidence.count(")")
    assert str(ASSUMED_BUNDLE_MB) in poort.reason
    # de aanname staat NA de afsluitende haak van de drie termen
    assert poort.reason.index(")") < poort.reason.index("aangenomen")


def test_an_empty_or_zero_bundle_size_is_treated_as_unmeasured_like_preflight():
    """`is None` weekt af van `preflight._check_8_free_space` (`if bundle_mb
    else`): `bundle_mb=''` gooide een ValueError de poort uit en
    `bundle_mb=0` telde als een GEMETEN nul, waardoor alleen de absolute
    ondergrens overbleef."""
    for leeg in ("", 0):
        poort = disk_gate(free_mb=6200, bundle_mb=leeg, unpack_mb=leeg)
        assert poort.outcome == "dicht", f"{leeg!r} is geen gemeten bundelgrootte"
        assert "aangenomen" in poort.reason
    # nul vrije ruimte blijft wel een echte meting
    assert disk_gate(free_mb=0, bundle_mb=1081, unpack_mb=1673).outcome == "dicht"


def test_an_evidence_row_does_not_change_a_phase_state():
    """`terugrolpunt_vast` is R0's EXTRA bewijsregel,
    geen toestandsregel. Hij mag een lopende fase niet als `niet beoordeeld`
    laten lezen, en hij sluit niets."""
    regels = [
        {"fase": "R0", "gebeurtenis": "fase_gestart"},
        {"fase": "R0", "gebeurtenis": "terugrolpunt_vast"},
    ]
    assert phase_state(regels, "R0") == "gestart"
    regels.append({"fase": "R0", "gebeurtenis": "voormeting_vast"})
    assert phase_state(regels, "R0") == "geslaagd"
    # en een bewijsregel NA de sluitregel maskeert die sluitregel niet
    regels.append({"fase": "R0", "gebeurtenis": "terugrolpunt_vast"})
    assert phase_state(regels, "R0") == "geslaagd"


# --- An open phase has a time ceiling -----------


def _started_row(*, run="r", fase="R1", doel="lab-02", tijd):
    return {"tijd": tijd, "run": run, "doel": doel, "fase": fase, "gebeurtenis": "fase_gestart", "uitkomst": "gestart"}


def test_no_ceiling_fallback_is_the_widest_ceiling_this_product_knows():
    from nsmcp.upgrade import NO_CEILING_FALLBACK_S, PHASE_LIMITS_S

    assert NO_CEILING_FALLBACK_S == max(PHASE_LIMITS_S.values()) == 3600


def test_an_open_phase_within_its_ceiling_is_not_expired():
    from nsmcp.upgrade import open_phases

    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    rows = [_started_row(tijd="2026-09-07T11:30:00Z")]
    (open_phase,) = open_phases(rows, now)
    assert open_phase.phase == "R1"
    assert open_phase.limit_s == 3600
    assert open_phase.expired is False


def test_an_open_phase_past_its_ceiling_is_expired():
    from nsmcp.upgrade import blocking_phase, expired_phases, open_phases

    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    rows = [_started_row(tijd="2026-09-07T10:30:00Z")]
    (open_phase,) = open_phases(rows, now)
    assert open_phase.expired is True
    assert blocking_phase(rows, now) is None
    assert [f.phase for f in expired_phases(rows, now)] == ["R1"]


def test_a_phase_without_a_ceiling_of_its_own_borrows_the_widest_one():
    from nsmcp.upgrade import NO_CEILING_FALLBACK_S, open_phases

    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    (open_phase,) = open_phases([_started_row(fase="R0", tijd="2026-09-07T11:59:00Z")], now)
    assert open_phase.limit_s == NO_CEILING_FALLBACK_S
    assert open_phase.expired is False
    (expired_phase,) = open_phases([_started_row(fase="R0", tijd="2026-09-07T10:00:00Z")], now)
    assert expired_phase.expired is True


def test_an_unreadable_start_time_keeps_the_phase_blocking():
    """Fail-closed: the ceiling cannot be measured against a row whose time
    cannot be read, and `niet beoordeeld` counts nowhere as `open`."""
    from nsmcp.upgrade import blocking_phase, open_phases

    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    rows = [
        {
            "tijd": "n/a",
            "run": "r",
            "doel": "lab-02",
            "fase": "R1",
            "gebeurtenis": "fase_gestart",
            "uitkomst": "gestart",
        }
    ]
    (open_phase,) = open_phases(rows, now)
    assert open_phase.started is None
    assert open_phase.expired is False
    assert blocking_phase(rows, now) is not None


def test_a_closed_phase_is_no_open_phase_at_all():
    from nsmcp.upgrade import open_phases

    rows = [
        _started_row(fase="R0", tijd="2026-09-07T10:00:00Z"),
        {
            "tijd": "2026-09-07T10:05:00Z",
            "run": "r",
            "doel": "lab-02",
            "fase": "R0",
            "gebeurtenis": "voormeting_vast",
            "uitkomst": "geslaagd",
        },
    ]
    assert open_phases(rows, datetime(2026, 9, 7, 12, 0, tzinfo=UTC)) == ()
    assert open_phases(rows) == ()


def test_a_start_row_after_a_closing_row_is_visible_as_open_again(tmp_path):
    """A later fix: `open_phases()` used to treat a phase as
    permanently closed the moment ANY closing row for it existed anywhere
    in the run - so a retry (a FRESH `fase_gestart` row written AFTER a
    `poort_dicht` row for the same run+phase, exactly what the runner
    writes before every real invocation, C4's own retry path) was invisible
    to the single-writer lock while a second upload genuinely ran. This
    asks the LAST-ROW question instead - the same one `phase_state()`
    already answers correctly for one (run, phase) pair - so a start row
    that comes AFTER a closing row reads as open again, and blocks."""
    from nsmcp.upgrade import blocking_phase, open_phases

    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    rows = [
        _started_row(run="r", fase="R1", tijd="2026-09-07T10:00:00Z"),
        {
            "tijd": "2026-09-07T10:05:00Z",
            "run": "r",
            "doel": "lab-02",
            "fase": "R1",
            "gebeurtenis": "poort_dicht",
            "uitkomst": "poort dicht",
        },
        _started_row(run="r", fase="R1", tijd="2026-09-07T11:55:00Z"),
    ]
    (open_phase,) = open_phases(rows, now)
    assert open_phase.run == "r"
    assert open_phase.phase == "R1"
    assert open_phase.expired is False
    assert blocking_phase(rows, now) is not None


def test_wait_for_start_ignores_the_rows_that_were_already_there(tmp_path):
    """The retry escape walks straight into this: the PREVIOUS attempt's
    `fase_gestart` matches run/phase exactly."""
    from nsmcp.upgrade import append_line, started_rows, wait_for_start

    path = tmp_path / "run.jsonl"
    append_line(path, _started_row(run="run-a", fase="R0", tijd="2026-09-07T10:00:00Z"))
    assert started_rows(path, "run-a", "R0") == 1
    assert wait_for_start(path, "run-a", "R0", 0.1, 1) is None
    assert wait_for_start(path, "run-a", "R0", 0.1, 0) is not None

    append_line(path, _started_row(run="run-a", fase="R0", tijd="2026-09-07T11:00:00Z"))
    second = wait_for_start(path, "run-a", "R0", 0.1, 1)
    assert second is not None and second["tijd"] == "2026-09-07T11:00:00Z"


def test_started_rows_counts_nothing_for_a_file_that_does_not_exist(tmp_path):
    from nsmcp.upgrade import started_rows

    assert started_rows(tmp_path / "er-is-niets.jsonl", "run-a", "R0") == 0


# ---------------------------------------------------------------------------
# Saving the configuration: the role check before `save ns config`, and the
# reading of `show ns config` both the read-back and R1's drift gate use.
# ---------------------------------------------------------------------------

CONFIGSTAND = FIXTURES / "configstand"
DOEL_ADRES = "192.0.2.10"


def _stand(naam: str) -> str:
    return (CONFIGSTAND / naam).read_text(encoding="ascii")


@pytest.mark.parametrize("naam", ["show-ha-node-standalone-primary.txt", "show-ha-node-paar-primary.txt"])
def test_saving_is_open_on_the_primary_or_a_standalone_box(naam):
    from nsmcp.upgrade import save_role_gate

    poort = save_role_gate(_stand(naam), DOEL_ADRES)
    assert poort.outcome == "open", poort
    assert poort.name == "doel is primary of standalone"
    assert "Master State Primary" in poort.evidence


def test_saving_on_a_secondary_is_closed_with_the_reason_to_save_on_the_primary():
    from nsmcp.upgrade import save_role_gate

    poort = save_role_gate(_stand("show-ha-node-paar-secondary.txt"), DOEL_ADRES)
    assert poort.outcome == "dicht"
    assert poort.reason == "opslaan op een secondary propageert niet; sla op op de primary"


@pytest.mark.parametrize(
    "mutatie",
    [
        lambda t: t.replace("192.0.2.10", "192.0.2.99"),  # een andere doos antwoordt
        lambda t: t.replace(" Done", ""),  # onvolledig antwoord
        lambda t: t.replace("Master State: Primary", "Master State: Claiming"),
        lambda t: t.replace("Node State: UP", "Node State: DOWN"),
        lambda t: t.replace("Master State: Primary", "Master State: Primary\n\tMaster State: Secondary"),
        lambda t: "ERROR: iets ging mis\n" + t,
        lambda t: t.replace("Node ID:      0", "Node ID:      3"),
        lambda t: "",
    ],
)
def test_every_other_shape_is_not_assessed_and_therefore_never_saves(mutatie):
    from nsmcp.upgrade import save_role_gate

    poort = save_role_gate(mutatie(_stand("show-ha-node-standalone-primary.txt")), DOEL_ADRES)
    assert poort.outcome == "niet beoordeeld", poort
    assert poort.reason


def test_without_a_target_address_the_role_is_not_assessed():
    from nsmcp.upgrade import save_role_gate

    assert save_role_gate(_stand("show-ha-node-standalone-primary.txt"), "").outcome == "niet beoordeeld"


def test_the_config_state_reads_the_three_fields_of_show_ns_config():
    from nsmcp.upgrade import config_state

    opgeslagen = config_state(_stand("show-ns-config-opgeslagen.txt"))
    assert opgeslagen.readable and opgeslagen.saved_after_change is True
    assert opgeslagen.changed == datetime(2026, 9, 24, 10, 12, 3)
    assert opgeslagen.saved == datetime(2026, 9, 24, 10, 14, 40)
    gewijzigd = config_state(_stand("show-ns-config-gewijzigd.txt"))
    assert gewijzigd.readable and gewijzigd.saved_after_change is False
    assert gewijzigd.changed == datetime(2026, 9, 6, 10, 50, 8)


def test_the_explicit_changed_flag_wins_over_equal_timestamps():
    from nsmcp.upgrade import config_state

    tekst = _stand("show-ns-config-opgeslagen.txt").replace("10:14:40", "10:12:03").replace("FALSE", "TRUE")
    stand = config_state(tekst)
    assert stand.readable and stand.saved_after_change is False


@pytest.mark.parametrize(
    "mutatie",
    [
        lambda t: t.replace(" Done", ""),
        lambda t: t.replace("Last Config Saved Time", "Laatste opslag"),
        lambda t: t + "\n\tLast Config Saved Time: Thu Sep 24 10:14:41 2026\n Done",
        lambda t: t.replace("Thu Sep 24 10:14:40 2026", "24-09-2026 10:14:40"),
        lambda t: t.replace("FALSE", "MISSCHIEN"),
        lambda t: t.replace("\tConfig Changed since Last Saved Config: FALSE\n", ""),
        lambda t: "ERROR: No such command\n" + t,
        lambda t: "Warning: [ iets ]\n" + t,
        # flag FALSE while the saved time is older than the change: contradictory
        lambda t: t.replace("10:14:40", "10:11:00"),
        lambda t: "",
    ],
)
def test_the_config_state_refuses_every_shape_it_does_not_know(mutatie):
    from nsmcp.upgrade import config_state

    stand = config_state(mutatie(_stand("show-ns-config-opgeslagen.txt")))
    assert not stand.readable
    assert stand.saved_after_change is None
    assert stand.reason


# ---------------------------------------------------------------------------
# R1's drift gate: measured live (`show ns config` in R1's own session), with
# the human acceptance as the second way open.
# ---------------------------------------------------------------------------

DRIFT_GATE = "drift afwezig of bewust geaccepteerd"


def test_the_drift_gate_opens_on_evidence_when_nothing_changed_since_the_last_save():
    from nsmcp.upgrade import drift_live_gate

    poort = drift_live_gate(_stand("show-ns-config-opgeslagen.txt"), 0, drift_geaccepteerd=False)
    assert poort.name == DRIFT_GATE
    assert (poort.type, poort.outcome) == ("bewijs", "open")
    assert "laatste opslag Thu Sep 24 10:14:40 2026 is niet ouder dan laatste wijziging" in poort.evidence


def test_the_drift_gate_closes_with_the_three_choices_when_the_configuration_changed():
    from nsmcp.upgrade import drift_live_gate

    poort = drift_live_gate(_stand("show-ns-config-gewijzigd.txt"), 0, drift_geaccepteerd=False)
    assert poort.outcome == "dicht"
    assert poort.reason == (
        "de configuratie is gewijzigd na de laatste opslag (show ns config); kies eerst opslaan met "
        "config_opslaan op de primary of het standalone-doel, of zet drift_geaccepteerd=true"
    )


def test_a_human_acceptance_opens_the_drift_gate_with_the_measured_state_as_evidence():
    from nsmcp.upgrade import drift_live_gate

    poort = drift_live_gate(_stand("show-ns-config-gewijzigd.txt"), 0, drift_geaccepteerd=True)
    assert (poort.type, poort.outcome) == ("mens", "open")
    assert "drift_geaccepteerd=true" in poort.evidence
    assert "gewijzigd na de laatste opslag" in poort.evidence


@pytest.mark.parametrize(
    "uitvoer,exitcode",
    [
        ("", 0),
        ("ERROR: No such command", 0),
        ("<fixture>", 1),
        ("<fixture>", -1),
        ("<fixture>", "0"),
    ],
)
def test_an_unread_state_is_not_assessed_without_acceptance_and_open_only_with_it(uitvoer, exitcode):
    from nsmcp.upgrade import drift_live_gate

    tekst = _stand("show-ns-config-opgeslagen.txt") if uitvoer == "<fixture>" else uitvoer
    zonder = drift_live_gate(tekst, exitcode, drift_geaccepteerd=False)
    assert zonder.outcome == "niet beoordeeld"
    assert zonder.reason
    met = drift_live_gate(tekst, exitcode, drift_geaccepteerd=True)
    assert (met.type, met.outcome) == ("mens", "open")
    assert "niet gelezen" in met.evidence


# ---------- R0: de doelbuild tegenover de huidige build en de vloer ----------
#
# De huidige build komt uit de export (config/nsversion); de vloer is de
# hoogste fix-build van de eigen tak uit het kennispakket; de doelbuild is de
# ene bundel in onderhoud.firmwaremap. Een doelbuild in een andere releaselijn
# dan de huidige build sluit altijd, ook met doelbuild_geaccepteerd. Binnen de
# lijn: open op bewijs bij doelbuild >= vloer; open als menselijke beslissing
# met doelbuild_geaccepteerd bij een doelbuild ONDER de vloer, zonder bekende
# vloer of zonder bekende huidige build, en anders dicht; dicht bij een
# takverschil met de vloer, ook met acceptatie; niet beoordeeld bij een waarde
# van de verkeerde vorm - en die waarde wordt nooit herhaald.

_HUIDIG = "14.1-66.59"


def test_a_target_build_above_the_floor_opens_on_evidence():
    from nsmcp.upgrade import FLOOR_GATE, floor_gate

    poort = floor_gate("14.1-74.10", "14.1-73.32", "CTX696939", False, huidig=_HUIDIG)
    assert (poort.name, poort.type, poort.outcome) == (FLOOR_GATE, "bewijs", "open")
    assert poort.evidence == "doelbuild 14.1-74.10 op of boven vloer 14.1-73.32 (CTX696939); huidige build 14.1-66.59"


def test_a_target_build_equal_to_the_floor_opens_on_evidence_and_acceptance_changes_nothing():
    from nsmcp.upgrade import floor_gate

    for geaccepteerd in (False, True):
        poort = floor_gate("14.1-73.32", "14.1-73.32", "CTX696939", geaccepteerd, huidig=_HUIDIG)
        assert (poort.type, poort.outcome) == ("bewijs", "open")


def test_a_target_build_below_the_floor_closes_with_the_way_out():
    from nsmcp.upgrade import FLOOR_BELOW_REASON, floor_gate

    poort = floor_gate("14.1-72.57", "14.1-73.32", "CTX696939", False, huidig=_HUIDIG)
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.evidence == "doelbuild 14.1-72.57 onder vloer 14.1-73.32 (CTX696939); huidige build 14.1-66.59"
    assert poort.reason == FLOOR_BELOW_REASON
    assert "doelbuild_geaccepteerd=true" in poort.reason


def test_a_target_build_below_the_floor_opens_as_a_human_decision_when_accepted():
    from nsmcp.upgrade import floor_gate

    poort = floor_gate("14.1-72.57", "14.1-73.32", "CTX696939", True, huidig=_HUIDIG)
    assert (poort.type, poort.outcome) == ("mens", "open")
    assert poort.evidence == (
        "doelbuild 14.1-72.57 onder vloer 14.1-73.32 (CTX696939); huidige build 14.1-66.59; bewust geaccepteerd"
    )


def test_the_build_comparison_is_numeric_not_textual():
    from nsmcp.upgrade import floor_gate

    assert floor_gate("14.1-100.3", "14.1-99.10", "CTX1", False, huidig=_HUIDIG).outcome == "open"
    assert floor_gate("14.1-9.10", "14.1-10.2", "CTX1", False, huidig=_HUIDIG).outcome == "dicht"


def test_no_floor_closes_without_acceptance_and_names_the_missing_floor():
    from nsmcp.upgrade import FLOOR_ABSENT_REASON, floor_gate

    poort = floor_gate("14.1-72.57", "", "", False, huidig=_HUIDIG)
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.evidence == "doelbuild 14.1-72.57; geen vloer meegegeven; huidige build 14.1-66.59"
    assert poort.reason == FLOOR_ABSENT_REASON == "geen vloer bekend in het kennispakket voor deze tak"


def test_no_floor_is_not_a_branch_difference_and_opens_as_a_human_decision_when_accepted():
    """No floor known for the appliance's own branch leaves nothing to
    compare the target build with - unlike a branch difference, which is a
    comparison that fails. With the current build in the same release line,
    the operator may accept that consciously."""
    from nsmcp.upgrade import floor_gate

    poort = floor_gate("14.1-72.57", "", "", True, huidig=_HUIDIG)
    assert (poort.type, poort.outcome) == ("mens", "open")
    assert poort.evidence == "doelbuild 14.1-72.57; geen vloer bekend; huidige build 14.1-66.59; bewust geaccepteerd"


@pytest.mark.parametrize("nep", ["True", "true", 1])
def test_without_a_floor_the_acceptance_counts_only_as_a_real_true(nep):
    from nsmcp.upgrade import floor_gate

    assert floor_gate("14.1-72.57", "", "", nep, huidig=_HUIDIG).outcome == "dicht"


@pytest.mark.parametrize("geaccepteerd", [False, True])
def test_a_branch_difference_closes_even_when_accepted(geaccepteerd):
    from nsmcp.upgrade import FLOOR_BRANCH_REASON, floor_gate

    poort = floor_gate("14.1-72.57", "13.1-63.18", "CTX696604", geaccepteerd, huidig=_HUIDIG)
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.reason == FLOOR_BRANCH_REASON
    assert "tak 14.1" in poort.evidence and "tak 13.1" in poort.evidence


@pytest.mark.parametrize(
    "doelbuild,vloer,bulletin",
    [
        ("14.1-72.57", "", ""),
        ("14.1-72.57", "13.1-63.18", "CTX696604"),
        ("13.1-37.1", "14.1-73.32", "CTX696939"),
    ],
    ids=["zonder-vloer", "vloer-in-de-huidige-lijn", "terug-naar-een-oudere-lijn"],
)
@pytest.mark.parametrize("geaccepteerd", [False, True])
def test_a_target_build_in_another_release_line_than_the_current_build_always_closes(
    doelbuild, vloer, bulletin, geaccepteerd
):
    """The line of the appliance comes from its current build, not from the
    floor: without a known floor, a target build in another release line
    used to open on the acceptance. This tool does no line change at all, so
    no acceptance opens it."""
    from nsmcp.upgrade import FLOOR_LINE_REASON, floor_gate

    huidig = "14.1-66.59" if doelbuild.startswith("13.1") else "13.1-63.18"
    poort = floor_gate(doelbuild, vloer, bulletin, geaccepteerd, huidig=huidig)
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.reason == FLOOR_LINE_REASON
    lijn_doel, lijn_nu = doelbuild.split("-", 1)[0], huidig.split("-", 1)[0]
    assert poort.evidence == (
        f"doelbuild {doelbuild} (releaselijn {lijn_doel}), huidige build {huidig} (releaselijn {lijn_nu})"
    )


@pytest.mark.parametrize(
    "doelbuild,vloer,bulletin,vloerdeel",
    [
        ("14.1-72.57", "", "", "doelbuild 14.1-72.57; geen vloer meegegeven"),
        ("14.1-74.10", "14.1-73.32", "CTX696939", "doelbuild 14.1-74.10 op of boven vloer 14.1-73.32 (CTX696939)"),
    ],
    ids=["zonder-vloer", "boven-de-vloer"],
)
def test_an_unknown_current_build_closes_without_acceptance(doelbuild, vloer, bulletin, vloerdeel):
    """Without the current build the gate cannot rule out a line change -
    not even at or above a floor - so it does not open on evidence."""
    from nsmcp.upgrade import FLOOR_CURRENT_ABSENT_REASON, floor_gate

    poort = floor_gate(doelbuild, vloer, bulletin, False, huidig="")
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.evidence == f"{vloerdeel}; huidige build niet bekend"
    assert poort.reason == FLOOR_CURRENT_ABSENT_REASON
    assert "doelbuild_geaccepteerd=true" in poort.reason


@pytest.mark.parametrize(
    "doelbuild,vloer,bulletin,bewijs",
    [
        (
            "14.1-72.57",
            "",
            "",
            "doelbuild 14.1-72.57; geen vloer bekend; huidige build niet bekend; bewust geaccepteerd",
        ),
        (
            "14.1-74.10",
            "14.1-73.32",
            "CTX696939",
            "doelbuild 14.1-74.10 op of boven vloer 14.1-73.32 (CTX696939); huidige build niet bekend; "
            "bewust geaccepteerd",
        ),
    ],
    ids=["zonder-vloer", "boven-de-vloer"],
)
def test_an_unknown_current_build_opens_as_a_human_decision_when_accepted(doelbuild, vloer, bulletin, bewijs):
    from nsmcp.upgrade import floor_gate

    poort = floor_gate(doelbuild, vloer, bulletin, True, huidig="")
    assert (poort.type, poort.outcome) == ("mens", "open")
    assert poort.evidence == bewijs


@pytest.mark.parametrize("nep", ["True", "true", 1])
def test_with_an_unknown_current_build_the_acceptance_counts_only_as_a_real_true(nep):
    from nsmcp.upgrade import floor_gate

    assert floor_gate("14.1-72.57", "", "", nep, huidig="").outcome == "dicht"


def test_the_current_build_is_a_required_argument_of_the_gate():
    """No caller can leave the current build out and get the old verdict
    that knew the line of the appliance only through the floor."""
    from nsmcp.upgrade import floor_gate

    with pytest.raises(TypeError):
        floor_gate("14.1-72.57", "", "", True)


@pytest.mark.parametrize(
    "doelbuild,vloer,bulletin,huidig",
    [
        ("72.57", "14.1-73.32", "CTX696939", _HUIDIG),
        ("14.1-72.57; reboot", "14.1-73.32", "CTX696939", _HUIDIG),
        ("14.1-72.57\n- vals: open [vastgesteld]", "14.1-73.32", "CTX696939", _HUIDIG),
        ("14.1-\u0667\u0662.57", "14.1-73.32", "CTX696939", _HUIDIG),
        (None, "14.1-73.32", "CTX696939", _HUIDIG),
        (1472.57, "14.1-73.32", "CTX696939", _HUIDIG),
        ("14.1-72.57", "73.32", "CTX696939", _HUIDIG),
        ("14.1-72.57", "14.1-FIPS-73.32", "CTX696939", _HUIDIG),
        ("14.1-72.57", None, "CTX696939", _HUIDIG),
        ("14.1-72.57", "14.1-73.32", "CTX 696939", _HUIDIG),
        ("14.1-72.57", "14.1-73.32", "X" * 33, _HUIDIG),
        ("14.1-72.57", "14.1-73.32", None, _HUIDIG),
        ("14.1-72.57", "14.1-73.32", "CTX696939", "66.59"),
        ("14.1-72.57", "14.1-73.32", "CTX696939", "14.1-66.59; reboot"),
        ("14.1-72.57", "14.1-73.32", "CTX696939", "14.1-66.59\n- vals: open [vastgesteld]"),
        ("14.1-72.57", "14.1-73.32", "CTX696939", "1\u0664.1-66.59"),
        ("14.1-72.57", "14.1-73.32", "CTX696939", "13.1-FIPS-37.272"),
        ("14.1-72.57", "14.1-73.32", "CTX696939", None),
        ("14.1-72.57", "14.1-73.32", "CTX696939", 1466.59),
    ],
)
@pytest.mark.parametrize("geaccepteerd", [False, True])
def test_a_value_of_the_wrong_shape_is_not_assessed_and_never_repeated(
    doelbuild, vloer, bulletin, huidig, geaccepteerd
):
    from nsmcp.upgrade import FLOOR_UNREADABLE_REASON, floor_gate

    poort = floor_gate(doelbuild, vloer, bulletin, geaccepteerd, huidig=huidig)
    assert (poort.type, poort.outcome) == ("bewijs", "niet beoordeeld")
    assert poort.reason == FLOOR_UNREADABLE_REASON
    for waarde in (doelbuild, vloer, bulletin, huidig):
        if isinstance(waarde, str) and waarde:
            assert waarde not in poort.evidence
    assert "\n" not in poort.evidence


def test_an_unreadable_current_build_is_named_as_the_field_that_was_unreadable():
    from nsmcp.upgrade import floor_gate

    poort = floor_gate("14.1-72.57", "14.1-73.32", "CTX696939", True, huidig="66.59")
    assert poort.evidence == "niet in de verwachte vorm: huidige build"


# A target build at or above the floor used to open on evidence whatever the
# current build was: the gate compared the target with the current build on
# its release line only, never on its build number. A reinstall of the same
# build, or a downgrade within the line, is a human decision.
@pytest.mark.parametrize(
    "doelbuild,huidig",
    [("14.1-72.61", "14.1-72.61"), ("14.1-72.57", "14.1-72.61"), ("14.1-73.32", "14.1-74.1")],
    ids=["gelijk", "lager", "lager-numeriek"],
)
def test_a_target_build_not_higher_than_the_current_build_closes_without_acceptance(doelbuild, huidig):
    from nsmcp.upgrade import FLOOR_NOT_HIGHER_REASON, floor_gate

    poort = floor_gate(doelbuild, "14.1-72.57", "CTX696604", False, huidig=huidig)
    assert (poort.type, poort.outcome) == ("bewijs", "dicht")
    assert poort.reason == FLOOR_NOT_HIGHER_REASON
    assert FLOOR_NOT_HIGHER_REASON == (
        "doelbuild niet hoger dan de huidige build (herinstallatie of downgrade): menselijke "
        "acceptatie vereist; zet doelbuild_geaccepteerd=true als dat bewust is"
    )
    assert poort.evidence == (
        f"doelbuild {doelbuild} op of boven vloer 14.1-72.57 (CTX696604); huidige build {huidig}; "
        "doelbuild niet hoger dan de huidige build"
    )


@pytest.mark.parametrize("doelbuild,huidig", [("14.1-72.61", "14.1-72.61"), ("14.1-72.57", "14.1-72.61")])
def test_a_target_build_not_higher_than_the_current_build_opens_as_a_human_decision_when_accepted(doelbuild, huidig):
    from nsmcp.upgrade import floor_gate

    poort = floor_gate(doelbuild, "14.1-72.57", "CTX696604", True, huidig=huidig)
    assert (poort.type, poort.outcome) == ("mens", "open")
    assert poort.evidence.endswith("; doelbuild niet hoger dan de huidige build; bewust geaccepteerd")


def test_a_target_build_higher_than_the_current_build_still_opens_on_evidence():
    from nsmcp.upgrade import floor_gate

    poort = floor_gate("14.1-72.62", "14.1-72.57", "CTX696604", False, huidig="14.1-72.61")
    assert (poort.type, poort.outcome, poort.reason) == ("bewijs", "open", "")
    assert poort.evidence == "doelbuild 14.1-72.62 op of boven vloer 14.1-72.57 (CTX696604); huidige build 14.1-72.61"


def test_the_floor_evidence_names_the_package_version_and_date():
    from datetime import date

    from nsmcp.upgrade import floor_gate

    poort = floor_gate(
        "14.1-74.10",
        "14.1-73.32",
        "CTX696939",
        False,
        huidig=_HUIDIG,
        pakket="2026.09",
        pakket_datum="2026-09-06",
        vandaag=date(2026, 9, 20),
    )
    assert (poort.type, poort.outcome, poort.reason) == ("bewijs", "open", "")
    assert poort.evidence == (
        "doelbuild 14.1-74.10 op of boven vloer 14.1-73.32 (CTX696939); kennispakket 2026.09 van 2026-09-06; "
        "huidige build 14.1-66.59"
    )


@pytest.mark.parametrize("geaccepteerd,verwacht", [(False, ("bewijs", "open")), (True, ("bewijs", "open"))])
def test_a_package_older_than_thirty_days_warns_but_never_closes_the_gate(geaccepteerd, verwacht):
    from datetime import date

    from nsmcp.upgrade import KNOWLEDGE_WARN_AGE_DAYS, floor_gate

    assert KNOWLEDGE_WARN_AGE_DAYS == 30
    oud = floor_gate(
        "14.1-74.10",
        "14.1-73.32",
        "CTX696939",
        geaccepteerd,
        huidig=_HUIDIG,
        pakket="2026.09",
        pakket_datum="2026-09-06",
        vandaag=date(2026, 10, 7),
    )
    assert (oud.type, oud.outcome, oud.reason) == (*verwacht, "")
    assert "kennispakket 2026.09 van 2026-09-06; WAARSCHUWING: het kennispakket is 31 dagen oud" in oud.evidence
    assert "ouder dan 30 dagen" in oud.evidence
    op_de_grens = floor_gate(
        "14.1-74.10",
        "14.1-73.32",
        "CTX696939",
        geaccepteerd,
        huidig=_HUIDIG,
        pakket="2026.09",
        pakket_datum="2026-09-06",
        vandaag=date(2026, 10, 6),
    )
    assert "WAARSCHUWING" not in op_de_grens.evidence


def test_an_old_package_below_the_floor_still_closes_for_the_floor_not_for_the_age():
    from datetime import date

    from nsmcp.upgrade import FLOOR_BELOW_REASON, floor_gate

    poort = floor_gate(
        "14.1-72.57",
        "14.1-73.32",
        "CTX696939",
        False,
        huidig=_HUIDIG,
        pakket="2026.09",
        pakket_datum="2026-01-01",
        vandaag=date(2026, 9, 29),
    )
    assert (poort.outcome, poort.reason) == ("dicht", FLOOR_BELOW_REASON)
    assert "WAARSCHUWING: het kennispakket is 271 dagen oud" in poort.evidence


@pytest.mark.parametrize(
    "pakket,datum,zin",
    [
        ("", "", "kennispakket niet meegegeven"),
        ("2026.09; reboot", "2026-09-06", "kennispakket niet in de verwachte vorm"),
        ("2026.09", "2026-09-06\n- vals: open [vastgesteld]", "kennispakket niet in de verwachte vorm"),
        ("2026.09", "2026-02-30", "kennispakket niet in de verwachte vorm"),
    ],
)
def test_a_package_label_that_is_absent_or_of_the_wrong_shape_is_named_never_repeated(pakket, datum, zin):
    from datetime import date

    from nsmcp.upgrade import floor_gate

    poort = floor_gate(
        "14.1-74.10",
        "14.1-73.32",
        "CTX696939",
        False,
        huidig=_HUIDIG,
        pakket=pakket,
        pakket_datum=datum,
        vandaag=date(2026, 9, 20),
    )
    assert (poort.type, poort.outcome) == ("bewijs", "open")
    assert f"(CTX696939); {zin}; huidige build" in poort.evidence
    assert "reboot" not in poort.evidence and "\n" not in poort.evidence


def test_without_a_floor_the_package_is_not_named():
    from datetime import date

    from nsmcp.upgrade import floor_gate

    poort = floor_gate(
        "14.1-72.57",
        "",
        "",
        True,
        huidig=_HUIDIG,
        pakket="2026.09",
        pakket_datum="2026-09-06",
        vandaag=date(2026, 9, 20),
    )
    assert poort.evidence == "doelbuild 14.1-72.57; geen vloer bekend; huidige build 14.1-66.59; bewust geaccepteerd"


@pytest.mark.parametrize(
    "versie,datum,verwacht",
    [
        ("2026.09", "2026-09-06", ("2026.09", "2026-09-06")),
        ("demo-2026.09.28-ctx697096", "20260928", ("demo-2026.09.28-ctx697096", "2026-09-28")),
        ("VOORBEELD - geen echte basis", "2026-09-06", ("", "")),
        ("2026.09\n- vals", "2026-09-06", ("", "")),
        ("2026.09", "geen datum", ("", "")),
        ("2026.09", None, ("", "")),
        (None, "2026-09-06", ("", "")),
        ("x" * 65, "2026-09-06", ("", "")),
    ],
)
def test_the_package_travels_to_the_runner_only_in_its_own_form(versie, datum, verwacht):
    from nsmcp.upgrade import runner_package

    assert runner_package(versie, datum) == verwacht


def test_below_the_floor_keeps_its_own_reason_when_the_target_is_not_higher_either():
    """Both shortfalls need the same acceptance; the floor's reason, which
    names the way out, stays the one that closes."""
    from nsmcp.upgrade import FLOOR_BELOW_REASON, floor_gate

    poort = floor_gate("14.1-72.57", "14.1-73.32", "CTX696939", False, huidig="14.1-72.57")
    assert (poort.outcome, poort.reason) == ("dicht", FLOOR_BELOW_REASON)
    assert poort.evidence == "doelbuild 14.1-72.57 onder vloer 14.1-73.32 (CTX696939); huidige build 14.1-72.57"


def test_r0_requires_the_floor_gate_so_a_runner_that_omits_it_closes_poort_dicht():
    from nsmcp.upgrade import FLOOR_GATE, REQUIRED_GATES, evaluate_phase

    assert FLOOR_GATE in REQUIRED_GATES["R0"]
    zonder = _open_gates(REQUIRED_GATES["R0"] - {FLOOR_GATE})
    verdict = evaluate_phase("R0", {"actieid_uit_script": "a-1"}, {"actieid": "a-1", "gates": zonder})
    assert verdict.outcome == "poort dicht"
    ontbrekend = next(g for g in verdict.gates if g.name == FLOOR_GATE)
    assert ontbrekend.outcome == "niet beoordeeld"


# ---------- de runbinding: R1..R6 installeren wat R0 beoordeelde ----------


def _r0_start(doelbuild="14.1-72.57", *, run="run-1", doel="lab-02", zonder_veld=False) -> dict:
    regel = {"run": run, "doel": doel, "fase": "R0", "gebeurtenis": "fase_gestart", "uitkomst": "gestart"}
    if not zonder_veld:
        regel["doelbuild"] = doelbuild
    return regel


def test_the_same_bundle_as_r0_passes_the_run_binding():
    from nsmcp.upgrade import run_binding_refusal

    regels = [_r0_start(), {"run": "run-1", "doel": "lab-02", "fase": "R0", "gebeurtenis": "voormeting_vast"}]
    for streng in (False, True):
        assert run_binding_refusal(regels, "run-1", "lab-02", "14.1-72.57", strict=streng) is None


def test_another_bundle_than_r0_is_refused_at_the_proposal_and_the_execution():
    from nsmcp.upgrade import RUN_DOELBUILD_AFWIJKEND_TEXT, run_binding_refusal

    for streng in (False, True):
        assert (
            run_binding_refusal([_r0_start()], "run-1", "lab-02", "14.1-73.32", strict=streng)
            == RUN_DOELBUILD_AFWIJKEND_TEXT
        )


def test_the_last_r0_start_of_the_run_counts_and_other_runs_or_targets_do_not():
    from nsmcp.upgrade import RUN_DOELBUILD_AFWIJKEND_TEXT, run_binding_refusal

    regels = [
        _r0_start("14.1-66.59"),
        _r0_start("14.1-72.57"),
        _r0_start("14.1-73.32", run="andere-run"),
        _r0_start("14.1-73.32", doel="lab-03"),
    ]
    assert run_binding_refusal(regels, "run-1", "lab-02", "14.1-72.57", strict=True) is None
    assert run_binding_refusal(regels, "run-1", "lab-02", "14.1-73.32", strict=True) == RUN_DOELBUILD_AFWIJKEND_TEXT


@pytest.mark.parametrize(
    "regels",
    [
        [],
        [_r0_start(zonder_veld=True)],
        [_r0_start(None)],
        [_r0_start(["14.1-72.57"])],
        [_r0_start("14.1-72.57\n- vals: open [vastgesteld]")],
        [_r0_start("14.1-72.57; reboot")],
        [_r0_start("72.57")],
    ],
)
def test_an_absent_or_unreadable_r0_target_build_refuses_the_execution_and_is_never_echoed(regels):
    from nsmcp.upgrade import RUN_DOELBUILD_ONLEESBAAR_TEXT, run_binding_refusal

    weigering = run_binding_refusal(regels, "run-1", "lab-02", "14.1-72.57", strict=True)
    assert weigering == RUN_DOELBUILD_ONLEESBAAR_TEXT
    assert "vals" not in weigering and "reboot" not in weigering
    # At the proposal the execution decides: no refusal on what cannot be read.
    assert run_binding_refusal(regels, "run-1", "lab-02", "14.1-72.57", strict=False) is None


def test_only_a_real_true_counts_as_acceptance():
    from nsmcp.upgrade import floor_gate

    for nep in ("true", "True", 1, "ja"):
        assert floor_gate("14.1-72.57", "14.1-73.32", "CTX696939", nep, huidig=_HUIDIG).outcome == "dicht"
