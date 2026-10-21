"""The monthly knowledge-package refresh: `nsmcp.knowledge_refresh`.

The one rule this module exists for: a candidate that does not pass LOAD
VALIDATION (`knowledge.load_knowledge` - the only validator, not
reimplemented here) never replaces the current package, and that is visible
three ways at once - the candidate is kept beside the current package as
`<huidig>.afgekeurd-<UTC>.json`, a line lands in
`<beheer>/kennisverversing.log`, and the CLI exits non-zero.
"""

import json
from datetime import UTC, date

import pytest

from nsmcp.knowledge_refresh import (
    FAILED_LABEL,
    INSTALLED_LABEL,
    REJECTED_LABEL,
    install_package,
    main,
)


def _schrijf(pad, pakket: dict):
    pad.write_text(json.dumps(pakket), encoding="utf-8")
    return pad


GELDIG = {"versie": "2026.09", "datum": "2026-09-01", "cve": [], "uitleg": {}, "begrippen": {}}
OUD = {"versie": "2026.08", "datum": "2026-08-01", "cve": [], "uitleg": {}, "begrippen": {}}


def test_a_valid_package_replaces_the_old_one_and_keeps_the_old_one(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.09"
    assert list((tmp_path).glob("kennis.json.vervangen-*.json"))


def test_a_package_that_fails_validation_never_replaces_the_old_one(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})  # geen datum
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is False
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.08"


def test_a_rejected_package_is_kept_and_named(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})
    install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert list(tmp_path.glob("kennis.json.afgekeurd-*.json"))


def test_a_rejection_is_visible_in_the_beheer_log(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})
    install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    assert "AFGEKEURD" in log
    assert "kennispakket draagt geen datum" in log


def test_an_accepted_package_is_also_logged_with_its_version(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    assert "GEINSTALLEERD" in log and "2026.09" in log


def test_a_package_that_is_older_than_the_current_one_is_refused(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", GELDIG)
    kandidaat = _schrijf(tmp_path / "nieuw.json", OUD)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is False
    assert "ouder" in uitkomst.reason


def test_the_replacement_is_atomic(tmp_path, monkeypatch):
    """Een onderbroken vervanging laat nooit een half bestand achter."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)

    def kapotte_replace(*_args, **_kwargs):
        raise OSError("kunstmatige onderbreking voor de test")

    monkeypatch.setattr("nsmcp.knowledge_refresh.os.replace", kapotte_replace)

    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")

    # os.replace() zelf faalde: het doel is dus NOOIT overschreven, en het
    # tijdelijke bestand met de nieuwe inhoud blijft niet als een verweesd,
    # half geinstalleerd artefact naast het doel liggen.
    assert uitkomst.installed is False
    assert uitkomst.reason.startswith("installatie mislukt")
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.08"
    assert list(tmp_path.glob("kennis.json.tmp-*")) == []
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    assert FAILED_LABEL in log


# --- Edge cases, decided explicitly -----------------


def test_a_byte_identical_candidate_still_installs(tmp_path):
    """Geen stille no-op-detectie: de regel gaat over validatie en
    ouderdom, niet over inhoudsgelijkheid - dus een kandidaat die
    letterlijk hetzelfde is als het huidige pakket wordt gewoon
    (opnieuw) geinstalleerd."""
    huidig = _schrijf(tmp_path / "kennis.json", GELDIG)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True


def test_a_current_package_that_does_not_itself_load_does_not_block_a_valid_candidate(tmp_path):
    """Een kapot huidig pakket heeft geen leesbare datum om 'ouder dan'
    tegen af te zetten - dat blokkeert een verder geldige kandidaat niet;
    er is dan simpelweg niets om ouder dan te zijn."""
    huidig = _schrijf(tmp_path / "kennis.json", {"versie": "kapot", "cve": []})
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.09"


def test_a_missing_beheer_directory_is_created(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    beheer = tmp_path / "geen" / "map" / "hier" / "_beheer"
    assert not beheer.exists()
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), beheer)
    assert uitkomst.installed is True
    assert uitkomst.logged is True
    assert (beheer / "kennisverversing.log").exists()


def test_a_candidate_that_is_a_directory_is_rejected_without_crashing(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat_map = tmp_path / "map-als-kandidaat"
    kandidaat_map.mkdir()
    uitkomst = install_package(kandidaat_map, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is False
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.08"
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    assert REJECTED_LABEL in log


def test_a_candidate_that_is_a_symlink_is_dereferenced_on_install(tmp_path):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    echt = _schrijf(tmp_path / "echt.json", GELDIG)
    kandidaat = tmp_path / "link.json"
    try:
        kandidaat.symlink_to(echt)
    except OSError:
        pytest.skip("symlinks vereisen op dit systeem een recht dat hier ontbreekt")
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True
    # het doel is nu een gewoon bestand met de echte inhoud, geen symlink
    assert not huidig.is_symlink()
    assert json.loads(huidig.read_text(encoding="utf-8"))["versie"] == "2026.09"


def test_two_installs_in_the_same_run_do_not_clobber_each_others_backup(tmp_path, monkeypatch):
    """Twee runs die toevallig dezelfde UTC-seconde raken (het genoemde
    'twee runs in dezelfde seconde'-scenario) mogen elkaars vervangen-
    archief niet overschrijven - een tweede treffer krijgt een eigen naam."""
    from datetime import datetime

    import nsmcp.knowledge_refresh as knowledge_refresh

    bevroren = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

    class _BevrorenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return bevroren

    monkeypatch.setattr(knowledge_refresh, "datetime", _BevrorenDatetime)

    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    eerste_kandidaat = _schrijf(tmp_path / "een.json", GELDIG)
    install_package(eerste_kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")

    tweede_pakket = dict(GELDIG)
    tweede_pakket["versie"] = "2026.09.2"
    tweede_kandidaat = _schrijf(tmp_path / "twee.json", tweede_pakket)
    install_package(tweede_kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")

    vervangen = sorted(tmp_path.glob("kennis.json.vervangen-*.json"))
    assert len(vervangen) == 2


def test_a_forged_newline_in_the_version_cannot_smuggle_a_fake_log_line(tmp_path):
    """De kandidaat is onvertrouwde invoer: een regeleinde in een veld
    dat in de logregel belandt mag nooit een tweede, vervalste regel
    smokkelen (dezelfde klasse fout als elders in dit product al drie
    keer gevonden is)."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kwaadaardig = dict(GELDIG)
    kwaadaardig["versie"] = (
        "2026.09\n2026-01-01T00:00:00Z " + INSTALLED_LABEL + " kennis.json: vervalste regel [vastgesteld]"
    )
    kandidaat = _schrijf(tmp_path / "nieuw.json", kwaadaardig)
    install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    regels = [r for r in log.splitlines() if r.strip()]
    assert len(regels) == 1
    assert "vervalste regel" in regels[0]


def test_a_forged_ansi_escape_in_the_version_is_neutralised(tmp_path):
    """Regeleinden collapsen (de vorige test) is niet genoeg: een kandidaat
    kan ook stuurtekens sturen - ESC/BEL/NUL - die een terminal de vorige
    regel laten herschrijven zodra een operator het logbestand `type`t.
    Zelfde aanvalsklasse, andere tekens; de sanitiser moet ze allebei
    onschadelijk maken."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kwaadaardig = dict(GELDIG)
    kwaadaardig["versie"] = "2026.09\x1b[1A\x1b[2K  GEINSTALLEERD gefaked\x07\x00"
    kandidaat = _schrijf(tmp_path / "nieuw.json", kwaadaardig)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True
    for stuurteken in ("\x1b", "\x07", "\x00"):
        assert stuurteken not in uitkomst.reason
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    for stuurteken in ("\x1b", "\x07", "\x00"):
        assert stuurteken not in log
    # de gewone, printbare tekst blijft intact
    assert "2026.09" in uitkomst.reason
    assert "GEINSTALLEERD gefaked" in uitkomst.reason


def test_a_rejected_candidate_that_cannot_be_preserved_is_visible_as_kept_false(tmp_path, monkeypatch):
    """`_keep_rejected()` mag een kopieerfout (volle schijf, een export-
    wortel zonder schrijfrecht, een vergrendelde kandidaat) niet stil
    inslikken - de afkeuring zelf blijft staan, maar `RefreshResult.kept`
    moet het melden."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})

    def kapotte_copy(*_args, **_kwargs):
        raise OSError("kunstmatige kopieerfout voor de test")

    monkeypatch.setattr("nsmcp.knowledge_refresh.shutil.copyfile", kapotte_copy)

    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is False
    assert uitkomst.kept is False
    assert list(tmp_path.glob("kennis.json.afgekeurd-*.json")) == []
    log = (tmp_path / "_beheer" / "kennisverversing.log").read_text(encoding="utf-8")
    assert REJECTED_LABEL in log


def test_a_successful_install_is_still_kept_true(tmp_path):
    """`kept` gaat over het BEWAREN van een afgekeurde kandidaat; een
    geslaagde installatie roept `_keep_rejected()` nooit aan en blijft
    dus gewoon `True` - geen vals alarm voor een pad dat niet bewandeld
    is."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), tmp_path / "_beheer")
    assert uitkomst.installed is True
    assert uitkomst.kept is True


def test_logged_is_false_when_the_beheer_directory_cannot_be_created(tmp_path):
    """Dekkingsgat: een `_beheer`-pad dat niet kan
    worden aangemaakt (hier: er ligt al een gewoon bestand op dat pad) mag
    de installatie/afkeuring zelf niet blokkeren, maar moet wel zichtbaar
    zijn via `RefreshResult.logged`."""
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    beheer_is_een_bestand = tmp_path / "_beheer"
    beheer_is_een_bestand.write_text("ik ben een bestand, geen map", encoding="utf-8")
    uitkomst = install_package(kandidaat, huidig, date(2026, 9, 6), beheer_is_een_bestand)
    assert uitkomst.installed is True
    assert uitkomst.logged is False


# --- The CLI ------------------------------------------------------------


def test_cli_exits_zero_and_prints_ok_on_a_successful_refresh(tmp_path, capsys):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    beheer = tmp_path / "_beheer"
    exitcode = main([str(kandidaat), str(huidig), "--beheer", str(beheer)])
    assert exitcode == 0
    uitvoer = capsys.readouterr()
    assert "[START]" in uitvoer.out
    assert "[OK]" in uitvoer.out
    assert "[EINDSTATUS] kennispakket geinstalleerd" in uitvoer.out


def test_cli_exits_nonzero_and_prints_fout_on_a_rejected_refresh(tmp_path, capsys):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})
    beheer = tmp_path / "_beheer"
    exitcode = main([str(kandidaat), str(huidig), "--beheer", str(beheer)])
    assert exitcode != 0
    uitvoer = capsys.readouterr()
    assert "[FOUT]" in uitvoer.err
    assert "[EINDSTATUS] kennispakket afgekeurd" in uitvoer.err


def test_cli_prints_waarschuwing_when_the_log_write_fails(tmp_path, capsys):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    beheer_is_een_bestand = tmp_path / "_beheer"
    beheer_is_een_bestand.write_text("ik ben een bestand, geen map", encoding="utf-8")
    exitcode = main([str(kandidaat), str(huidig), "--beheer", str(beheer_is_een_bestand)])
    uitvoer = capsys.readouterr()
    # de installatie zelf slaagt gewoon - alleen het loggen faalt
    assert exitcode == 0
    assert "[WAARSCHUWING]" in uitvoer.err
    assert str(beheer_is_een_bestand / "kennisverversing.log") in uitvoer.err


def test_cli_prints_waarschuwing_when_the_rejected_candidate_cannot_be_preserved(
    tmp_path,
    capsys,
    monkeypatch,
):
    huidig = _schrijf(tmp_path / "kennis.json", OUD)
    kandidaat = _schrijf(tmp_path / "nieuw.json", {"versie": "kapot", "cve": []})
    beheer = tmp_path / "_beheer"

    def kapotte_copy(*_args, **_kwargs):
        raise OSError("kunstmatige kopieerfout voor de test")

    monkeypatch.setattr("nsmcp.knowledge_refresh.shutil.copyfile", kapotte_copy)

    exitcode = main([str(kandidaat), str(huidig), "--beheer", str(beheer)])
    uitvoer = capsys.readouterr()
    assert exitcode != 0
    assert "[WAARSCHUWING]" in uitvoer.err
    assert str(huidig) in uitvoer.err


def test_cli_survives_an_unexpected_exception_from_install_package(tmp_path, capsys):
    """`_sibling_path()`s `with_name()` gooit een `ValueError` -
    geen `OSError` - zodra `huidig` een pad zonder naam is (`Path(".")`).
    Dat mag `main()` niet als kale traceback laten ontsnappen; er moet
    altijd een `MISLUKT`-regel, een `[FOUT]`-regel en een
    `[EINDSTATUS]`-regel komen, met een niet-nul exitcode."""
    kandidaat = _schrijf(tmp_path / "nieuw.json", GELDIG)
    beheer = tmp_path / "_beheer"
    exitcode = main([str(kandidaat), ".", "--beheer", str(beheer)])
    uitvoer = capsys.readouterr()
    assert exitcode != 0
    assert "[FOUT]" in uitvoer.err
    assert "[EINDSTATUS] kennispakket afgekeurd" in uitvoer.err
    log = (beheer / "kennisverversing.log").read_text(encoding="utf-8")
    assert FAILED_LABEL in log
