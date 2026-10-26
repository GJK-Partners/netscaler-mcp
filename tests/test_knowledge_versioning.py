"""1.1 D: the knowledge package names the engine it needs, and the loader
refuses what it does not know instead of dropping it in silence.

MEASURED before (1.0.3): `load_knowledge` refused an unknown field at the top
level and in a bulletin record, but in a CVE record it only checked for
MISSING fields. A 1.0.2 engine therefore loaded a package with
`naconfiguratieVerplicht` and dropped the field without a word. Values were
untyped too: an object on `extraStapNaUpgrade` loaded, also with a hidden
`naconfiguratieVerplicht` inside it, and gave `NIET GERAAKT` without a read
gap where the flag in its proper place gives `NIET VASTGESTELD`.

Two package lines follow (spec D.2 rule 4): the EXISTING line without
`minimaleEngine`, loadable on 1.0.x and 1.1 (also with
`naconfiguratieVerplicht`), and the NEW line with `minimaleEngine` >= 1.1.0.
Every 1.0.x engine refuses `minimaleEngine` as an unknown top-level field,
so no package may declare a value below 1.1.0.
"""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path

import pytest

import nsmcp
from nsmcp import knowledge
from nsmcp.cve import NIET_GERAAKT, NIET_VASTGESTELD, cve_verdicts
from nsmcp.knowledge import FIELD_INTRODUCED, load_knowledge, main

TODAY = date(2026, 10, 26)
NEEDLE = "naald-7c1e-pakketinhoud"

_BULLETIN = {
    "bulletin": "CTX697096",
    "datum": "2026-09-27",
    "getroffen": {"14.1": "< 73.37", "13.1": "< 64.23"},
    "fix": {"14.1": "73.37", "13.1": "64.23"},
    "cves": [
        {"id": "CVE-2026-88771", "cvss": 9.5, "kern": "geen extra feature", "voorwaarde": "altijd"},
        {
            "id": "CVE-2026-88778",
            "cvss": 8.8,
            "kern": "TCP en ISN",
            "voorwaarde": "altijd",
            "naconfiguratieVerplicht": True,
        },
    ],
    "advies": "Upgrade naar 14.1-73.37 of 13.1-64.23.",
    "extraStapNaUpgrade": "Na de upgrade Enhanced ISN Generation inschakelen.",
}
_CHOICE = {"vanaf": {"14.1": "43.56"}, "predicaat": "heeft_saml_action", "anders": "heeft_gateway_vserver"}


def _package(**top) -> dict:
    document = {
        "versie": "2026.10",
        "datum": "2026-10-20",
        "toelichting": "Proefpakket.",
        "bron": "Vendorbulletins",
        "cve": [copy.deepcopy(_BULLETIN)],
        "uitleg": {"status_cve_controle": "Uitleg."},
        "begrippen": {"vserver": "Een virtuele server."},
        "aangeboden": {"datum": "2026-10-01", "bron": "release notes", "builds": {"14.1": "73.37"}},
    }
    document.update(top)
    return document


def _write(tmp_path: Path, document: dict, name: str = "kennis.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _load(tmp_path: Path, document: dict):
    return load_knowledge(_write(tmp_path, document), TODAY)


def _set(document: dict, path: str, value) -> dict:
    """Set a value on a dotted path with [i] indexes, on a copy."""
    document = copy.deepcopy(document)
    node = document
    parts = path.replace("]", "").replace("[", ".").split(".")
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value
    return document


# ---------------------------------------------------------------------------
# minimaleEngine
# ---------------------------------------------------------------------------


def test_package_requiring_newer_engine_is_refused(tmp_path):
    for wanted in ("1.1.1", "1.2.0", "2.0.0", "999.0.0"):
        loaded = _load(tmp_path, _package(minimaleEngine=wanted))
        assert loaded.missing, wanted
        assert loaded.reason == (
            f"kennispakket vraagt engine {wanted} of nieuwer; deze engine is 1.1.0; werk eerst de engine bij"
        )
    # The engine names the need even when the package also carries a field
    # this engine does not know: that is exactly the package a newer engine
    # is for, and "werk eerst de engine bij" is the sentence that helps.
    loaded = _load(tmp_path, _package(minimaleEngine="1.2.0", overstappen=[]))
    assert loaded.reason.startswith("kennispakket vraagt engine 1.2.0 of nieuwer")
    # Equal is enough.
    assert not _load(tmp_path, _package(minimaleEngine="1.1.0")).missing


def test_the_engine_comparison_is_numeric_not_textual(tmp_path, monkeypatch):
    # As text "1.10.0" < "1.9.0"; as numbers it is the newer one.
    monkeypatch.setattr(nsmcp, "__version__", "1.10.0")
    assert not _load(tmp_path, _package(minimaleEngine="1.9.0")).missing
    monkeypatch.setattr(nsmcp, "__version__", "1.9.0")
    assert _load(tmp_path, _package(minimaleEngine="1.10.0")).missing
    # Leading zeros are the same number.
    monkeypatch.setattr(nsmcp, "__version__", "1.1.0")
    assert not _load(tmp_path, _package(minimaleEngine="01.01.000")).missing


def test_an_unreadable_engine_version_refuses_a_package_with_a_minimum(tmp_path, monkeypatch):
    monkeypatch.setattr(nsmcp, "__version__", "1.1.0rc1")
    loaded = _load(tmp_path, _package(minimaleEngine="1.1.0"))
    assert loaded.missing
    assert "\n" not in loaded.reason
    # The existing line does not depend on the engine version at all.
    assert not _load(tmp_path, _package()).missing


@pytest.mark.parametrize("value", ["1.0.3", "1.0.0", "0.9.9", "1.0.99", "0.0.0"])
def test_minimum_engine_below_1_1_0_is_refused(tmp_path, value):
    loaded = _load(tmp_path, _package(minimaleEngine=value))
    assert loaded.missing
    assert loaded.reason == (
        "minimaleEngine kan niet lager zijn dan 1.1.0: oudere engines kennen dit veld niet en weigeren het pakket"
    )


_BAD_FORMS = [
    "1.1",
    "1.1.0.0",
    "v1.1.0",
    " 1.1.0",
    "1.1.0 ",
    "1.1.0\n",
    "1.1.0-rc1",
    "1234.0.0",
    "1..0",
    "",
    "\uff11.1.0",  # fullwidth digit one
    "1\u200b.1.0",
    "1.1.0\n- kennispakket: in orde [vastgesteld]",
]


@pytest.mark.parametrize("value", _BAD_FORMS)
def test_minimum_engine_form(tmp_path, value):
    loaded = _load(tmp_path, _package(minimaleEngine=value))
    assert loaded.missing
    assert loaded.reason == (
        "kennispakket: minimaleEngine heeft niet de vorm MAJOR.MINOR.PATCH"
        " (drie getallen van een tot drie ASCII-cijfers, gescheiden door een punt)"
    )
    assert "\n" not in loaded.reason


@pytest.mark.parametrize("value", [110, 1.1, None, True, [], {}, ["1.1.0"], {"versie": "1.1.0"}])
def test_minimum_engine_must_be_text(tmp_path, value):
    loaded = _load(tmp_path, _package(minimaleEngine=value))
    assert loaded.missing
    assert loaded.reason == "kennispakket: minimaleEngine moet tekst zijn"


def test_the_pin_covers_the_minimum_engine(tmp_path):
    from nsmcp.knowledge import KnowledgePin, canonical_digest

    document = _package(minimaleEngine="1.1.0")
    pin = KnowledgePin(version="2026.10", digest=canonical_digest(document))
    assert not load_knowledge(_write(tmp_path, document), TODAY, pin=pin).missing
    changed = _package(minimaleEngine="1.1.1")
    assert canonical_digest(changed) != pin.digest


# ---------------------------------------------------------------------------
# FIELD_INTRODUCED
# ---------------------------------------------------------------------------


def test_the_introduction_table_is_pinned():
    assert FIELD_INTRODUCED == {
        "cve[].cves[].naconfiguratieVerplicht": "1.0.3",
        "minimaleEngine": "1.1.0",
    }
    # Every introduced field has a recorded type: an introduction without a
    # type would be a field the loader cannot check.
    assert set(FIELD_INTRODUCED) <= set(knowledge._FIELD_TYPES)


def test_naconfiguratie_without_minimum_still_loads(tmp_path):
    """The existing line: a 1.0.3 field, no minimaleEngine, loads on 1.1."""
    document = _package()
    assert "minimaleEngine" not in document
    loaded = _load(tmp_path, document)
    assert not loaded.missing, loaded.reason
    assert loaded.cve[0]["cves"][1]["naconfiguratieVerplicht"] is True


def _with_trial_field(monkeypatch, introduced: str, engine: str):
    """A field from a LATER engine, with its own type and introduction: the
    shape every new structured field takes (spec D.2 rule 3)."""
    monkeypatch.setattr(nsmcp, "__version__", engine)
    monkeypatch.setitem(knowledge._FIELD_TYPES, "cve[].cves[].proefveld", knowledge._TEXT)
    monkeypatch.setitem(knowledge.FIELD_INTRODUCED, "cve[].cves[].proefveld", introduced)


def test_field_newer_than_declared_minimum_is_refused(tmp_path, monkeypatch):
    # The example of the design: `overstappen` (a 1.1.0 field of the 13.1 transition) with
    # minimaleEngine 1.0.3. In this engine `overstappen` is not yet known,
    # and 1.0.3 is below the floor of the field itself: refused either way.
    assert _load(tmp_path, _package(minimaleEngine="1.0.3", overstappen=[])).missing

    # The rule itself, on a field from a later engine.
    _with_trial_field(monkeypatch, introduced="1.2.0", engine="1.2.0")
    with_field = _set(_package(), "cve[0].cves[0].proefveld", "x")
    loaded = _load(tmp_path, {**with_field, "minimaleEngine": "1.1.0"})
    assert loaded.missing
    assert loaded.reason == (
        "het pakket gebruikt cve[].cves[].proefveld (sinds engine 1.2.0) maar zegt minimaleEngine 1.1.0;"
        " een oudere engine zou het veld stil negeren of het pakket weigeren"
    )
    loaded = _load(tmp_path, with_field)
    assert loaded.missing
    assert loaded.reason == (
        "het pakket gebruikt cve[].cves[].proefveld (sinds engine 1.2.0) maar zegt geen minimaleEngine;"
        " een oudere engine zou het veld stil negeren of het pakket weigeren"
    )
    assert not _load(tmp_path, {**with_field, "minimaleEngine": "1.2.0"}).missing


def test_a_field_up_to_1_0_3_needs_no_minimum(tmp_path, monkeypatch):
    _with_trial_field(monkeypatch, introduced="1.0.3", engine="1.1.0")
    assert not _load(tmp_path, _set(_package(), "cve[0].cves[0].proefveld", "x")).missing


# ---------------------------------------------------------------------------
# Strict on keys at every level
# ---------------------------------------------------------------------------


def test_unknown_cve_field_is_refused(tmp_path):
    loaded = _load(tmp_path, _set(_package(), "cve[0].cves[1].ernst", "hoog"))
    assert loaded.missing
    assert loaded.reason == (
        "kennispakket: cve[0].cves[1] bevat onbekend veld; deze engine laadt geen veld dat ze niet kent"
    )


def test_safety_flag_moved_to_bulletin_level_is_refused(tmp_path):
    document = _set(_package(), "cve[0].naconfiguratieVerplicht", True)
    loaded = _load(tmp_path, document)
    assert loaded.missing
    assert loaded.reason == ("kennispakket: cve[0] bevat onbekend veld; deze engine laadt geen veld dat ze niet kent")


def test_unknown_top_level_field_is_refused_without_naming_it(tmp_path):
    for name in ("overstappen", "levenscyclus", NEEDLE):
        loaded = _load(tmp_path, _package(**{name: []}))
        assert loaded.missing
        assert loaded.reason == (
            "kennispakket bevat onbekend veld op topniveau; deze engine laadt geen veld dat ze niet kent"
        )


# ---------------------------------------------------------------------------
# Strict on types (S-7)
# ---------------------------------------------------------------------------


def test_extra_step_object_is_refused(tmp_path):
    for value in ({"onbekend": {"genest": "x"}}, {"naconfiguratieVerplicht": True}):
        loaded = _load(tmp_path, _set(_package(), "cve[0].extraStapNaUpgrade", value))
        assert loaded.missing
        assert loaded.reason == "kennispakket: cve[0].extraStapNaUpgrade moet tekst zijn"


_TEXT_PATHS = [
    "versie",
    "datum",
    "toelichting",
    "bron",
    "cve[0].bulletin",
    "cve[0].datum",
    "cve[0].advies",
    "cve[0].extraStapNaUpgrade",
    "cve[0].cves[0].id",
    "cve[0].cves[0].kern",
    "aangeboden.datum",
    "aangeboden.bron",
    "cve[0].cves[1].voorwaarde.predicaat",
    "cve[0].cves[1].voorwaarde.anders",
]
_NOT_TEXT = [{"x": NEEDLE}, [NEEDLE], None, 7, 7.5, True, False]


def _with_choice() -> dict:
    return _set(_package(), "cve[0].cves[1].voorwaarde", copy.deepcopy(_CHOICE))


@pytest.mark.parametrize("path", _TEXT_PATHS)
def test_text_fields_refuse_every_non_text_type(tmp_path, path):
    for value in _NOT_TEXT:
        loaded = _load(tmp_path, _set(_with_choice(), path, value))
        assert loaded.missing, (path, value)
        assert loaded.reason == f"kennispakket: {path} moet tekst zijn", (path, value)


_MAP_VALUES = [
    ("uitleg", "status_cve_controle", "een object van tekst naar tekst"),
    ("begrippen", "vserver", "een object van tekst naar tekst"),
    ("aangeboden.builds", "14.1", "een object van tak naar tekst"),
    ("cve[0].getroffen", "14.1", "een object van tak naar tekst"),
    ("cve[0].fix", "14.1", "een object van tak naar tekst"),
    ("cve[0].cves[1].voorwaarde.vanaf", "14.1", "een object van tak naar tekst"),
]


def _node(document: dict, path: str):
    node = document
    for part in path.replace("]", "").replace("[", ".").split("."):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


@pytest.mark.parametrize(("parent", "key", "expected"), _MAP_VALUES)
def test_map_values_refuse_every_non_text_type(tmp_path, parent, key, expected):
    for value in _NOT_TEXT:
        document = _with_choice()
        _node(document, parent)[key] = value
        loaded = _load(tmp_path, document)
        assert loaded.missing, (parent, value)
        assert loaded.reason == f"kennispakket: {parent} moet {expected} zijn", (parent, value)


_WRONG = {
    "een lijst": [NEEDLE, 3, None, True, {"x": NEEDLE}],
    "een object": [NEEDLE, 3, None, True, [NEEDLE]],
    "een object van tekst naar tekst": [NEEDLE, 3, None, True, [NEEDLE]],
    "een object van tak naar tekst": [NEEDLE, 3, None, True, [NEEDLE]],
    "tekst of een object": [3, 2.5, None, True, [NEEDLE]],
    "true of false": ["true", 1, 0, None, [True], {"x": NEEDLE}],
}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("cve", "een lijst"),
        ("cve[0]", "een object"),
        ("cve[0].cves", "een lijst"),
        ("cve[0].cves[0]", "een object"),
        ("uitleg", "een object van tekst naar tekst"),
        ("begrippen", "een object van tekst naar tekst"),
        ("aangeboden", "een object"),
        ("aangeboden.builds", "een object van tak naar tekst"),
        ("cve[0].getroffen", "een object van tak naar tekst"),
        ("cve[0].fix", "een object van tak naar tekst"),
        ("cve[0].cves[0].voorwaarde", "tekst of een object"),
        ("cve[0].cves[1].voorwaarde.vanaf", "een object van tak naar tekst"),
        ("cve[0].cves[1].naconfiguratieVerplicht", "true of false"),
    ],
)
def test_structured_fields_refuse_a_wrong_type(tmp_path, path, expected):
    base = _with_choice() if "voorwaarde.vanaf" in path else _package()
    for value in _WRONG[expected]:
        loaded = _load(tmp_path, _set(base, path, value))
        assert loaded.missing, (path, value)
        assert loaded.reason == f"kennispakket: {path} moet {expected} zijn", (path, value)


def test_cvss_type_is_a_finite_number(tmp_path):
    expected = "kennispakket: cve[0].cves[0].cvss moet een getal van 0 tot en met 10 zijn"
    for value in (True, False, "9.3", None, [9.3], {"score": 9.3}, -0.1, 10.01, 11, float("inf")):
        loaded = _load(tmp_path, _set(_package(), "cve[0].cves[0].cvss", value))
        assert loaded.missing, value
        assert loaded.reason == expected, value
    # NaN and Infinity are not JSON, but Python's parser reads them.
    for literal in ("NaN", "Infinity", "-Infinity"):
        text = json.dumps(_package()).replace("9.5", literal, 1)
        path = tmp_path / "nan.json"
        path.write_text(text, encoding="utf-8")
        loaded = load_knowledge(path, TODAY)
        assert loaded.missing, literal
        assert loaded.reason == expected, literal
    for value in (0, 10, 9.3, 7, 0.0, 10.0):
        assert not _load(tmp_path, _set(_package(), "cve[0].cves[0].cvss", value)).missing, value


# A refusal reason is a fixed sentence: it names a path, the expected form
# and at most the engine's own vocabulary. Never longer than this, whatever
# the package carries - the reason is printed by --controleer and carried
# into every answer that says the package does not load.
REASON_MAX_CHARS = 500
LONG_NEEDLE = NEEDLE * 3000
_PREDICATE_LIST = ", ".join(sorted(knowledge.PREDICATES))


def _two_bulletins() -> dict:
    document = _package()
    twin = copy.deepcopy(_BULLETIN)
    twin["bulletin"] = "ctx697096"
    document["cve"].append(twin)
    return document


# Every route of the loader that used to repeat package content (1.0.3: the
# predicate text, the branch names of `getroffen`/`fix`/`vanaf`/
# `aangeboden.builds`, a build, a date, the spelling of a duplicate
# identifier), with the fixed sentence it gives now.
_CONTENT_ROUTES = [
    (
        _set(_package(), "cve[0].cves[0].voorwaarde", LONG_NEEDLE),
        f"kennispakket: cve[0].cves[0].voorwaarde noemt een onbekend predicaat; toegestaan: {_PREDICATE_LIST}",
    ),
    (
        _set(_package(), "cve[0].cves[1].voorwaarde", {**_CHOICE, "predicaat": LONG_NEEDLE}),
        "kennispakket: cve[0].cves[1].voorwaarde.predicaat noemt een onbekend predicaat;"
        f" toegestaan: {_PREDICATE_LIST}",
    ),
    (
        _set(_package(), "cve[0].cves[1].voorwaarde", {**_CHOICE, "anders": LONG_NEEDLE}),
        f"kennispakket: cve[0].cves[1].voorwaarde.anders noemt een onbekend predicaat; toegestaan: {_PREDICATE_LIST}",
    ),
    (
        _set(_package(), "cve[0].cves[1].voorwaarde", {**_CHOICE, "vanaf": {LONG_NEEDLE: "geen build"}}),
        "kennispakket: cve[0].cves[1].voorwaarde.vanaf draagt voor een tak geen buildnummer van de vorm X.Y",
    ),
    (
        _set(_package(), "cve[0].cves[1].voorwaarde", {**_CHOICE, "vanaf": {"14.1": LONG_NEEDLE}}),
        "kennispakket: cve[0].cves[1].voorwaarde.vanaf draagt voor een tak geen buildnummer van de vorm X.Y",
    ),
    (
        _set(_package(), "cve[0].getroffen", {"14.1": "< 73.37", "13.1": "< 64.23", LONG_NEEDLE: "< 1.0"}),
        "kennispakket: cve[0].getroffen en cve[0].fix noemen niet dezelfde takken; elke tak hoort in beide",
    ),
    (
        _set(_package(), "cve[0].fix", {"14.1": "73.37", "13.1": "64.23", LONG_NEEDLE: "1.0"}),
        "kennispakket: cve[0].getroffen en cve[0].fix noemen niet dezelfde takken; elke tak hoort in beide",
    ),
    (
        _set(
            _set(_package(), "cve[0].getroffen", {"14.1": "< 73.37", "13.1": "< 64.23", LONG_NEEDLE: "< 9.0"}),
            "cve[0].fix",
            {"14.1": "73.37", "13.1": "64.23", LONG_NEEDLE: "1.0"},
        ),
        "kennispakket: cve[0] draagt voor een tak in getroffen en fix een fix-build onder de getroffen reeks;"
        " een build zou dan tegelijk geraakt en verholpen heten",
    ),
    (
        _set(_package(), "cve[0].getroffen", {"14.1": LONG_NEEDLE, "13.1": "< 64.23"}),
        "kennispakket: cve[0] draagt voor een tak in getroffen en fix een getroffen reeks die niet de vorm"
        " '< X.Y' heeft",
    ),
    (
        _set(_package(), "aangeboden.builds", {LONG_NEEDLE: "geen build"}),
        "kennispakket: 'aangeboden.builds' draagt voor een tak geen build in de vorm X.Y",
    ),
    (
        _set(_package(), "aangeboden.builds", {"14.1": LONG_NEEDLE}),
        "kennispakket: 'aangeboden.builds' draagt voor een tak geen build in de vorm X.Y",
    ),
    (
        _set(_package(), "aangeboden.datum", LONG_NEEDLE),
        "kennispakket: 'aangeboden.datum' is geen ISO-datum (JJJJ-MM-DD)",
    ),
    (
        _package(datum=LONG_NEEDLE),
        "kennispakket draagt een onbruikbare datum; verwacht een ISO-datum (JJJJ-MM-DD)",
    ),
    (_package(datum="2999-12-31"), "kennispakket is gedateerd in de toekomst"),
    (
        _two_bulletins(),
        "kennispakket: cve[1].bulletin noemt een bulletin dat meer dan eens voorkomt; het zou dubbel meetellen",
    ),
    (
        _set(_package(), "cve[0].cves[1].id", "cve-2026-88771"),
        "kennispakket: cve[0].cves[1].id noemt een CVE die meer dan eens voorkomt; het zou dubbel meetellen",
    ),
]


_CONTENT_ROUTE_IDS = [
    "predicaat-tekst",
    "predicaat-object",
    "anders-object",
    "vanaf-tak",
    "vanaf-build",
    "tak-alleen-getroffen",
    "tak-alleen-fix",
    "tak-regel",
    "getroffen-reeks",
    "aangeboden-tak",
    "aangeboden-build",
    "aangeboden-datum",
    "datum",
    "datum-toekomst",
    "bulletin-dubbel",
    "cve-dubbel",
]


@pytest.mark.parametrize(("document", "reason"), _CONTENT_ROUTES, ids=_CONTENT_ROUTE_IDS)
def test_an_existing_refusal_route_names_the_place_not_the_content(tmp_path, capsys, document, reason):
    """1.1 D, sectie 2 regel 3: the loader's refusals of 1.0.3 repeated
    package content - unbounded (a predicate of 60.000 characters came back
    whole) - and --controleer printed it. Each of them now names the place
    and the expected form, never what the package says there."""
    path = _write(tmp_path, document)
    loaded = load_knowledge(path, TODAY)
    assert loaded.missing
    assert loaded.reason == reason
    for content in (NEEDLE, "2999", "697096", "88771"):
        assert content not in loaded.reason
    assert len(loaded.reason) <= REASON_MAX_CHARS
    assert main(["--controleer", str(path)]) == 1
    printed = capsys.readouterr()
    assert NEEDLE not in printed.out + printed.err
    assert len(printed.err) <= REASON_MAX_CHARS + 100


def test_type_refusal_never_echoes_the_value(tmp_path, capsys):
    cases = [
        _set(_package(), "cve[0].extraStapNaUpgrade", {"x": NEEDLE}),
        _set(_package(), "cve[0].advies", [NEEDLE]),
        _set(_package(), "cve[0].cves[0].kern", {NEEDLE: True}),
        _set(_package(), "cve[0].cves[0].cvss", NEEDLE),
        _set(_package(), "uitleg", {"a": [NEEDLE]}),
        _set(_package(), "cve[0].getroffen", {"14.1": {"x": NEEDLE}, "13.1": "< 64.23"}),
        _set(_package(), "cve[0].cves[0]." + NEEDLE, 1),
        _set(_package(), "cve[0]." + NEEDLE, 1),
        _package(**{NEEDLE: 1}),
        _package(minimaleEngine=NEEDLE),
        _package(minimaleEngine={"x": NEEDLE}),
    ]
    for document in cases:
        path = _write(tmp_path, document)
        loaded = load_knowledge(path, TODAY)
        assert loaded.missing
        assert NEEDLE not in loaded.reason
        assert "\n" not in loaded.reason
        assert len(loaded.reason) <= REASON_MAX_CHARS
        assert main(["--controleer", str(path)]) == 1
        printed = capsys.readouterr()
        assert NEEDLE not in printed.out + printed.err


def test_json_looking_text_is_plain_text(tmp_path):
    """Text that looks like JSON stays text: never parsed, never a rule."""
    from test_cve_post_upgrade_config import _isn

    looks_like = '{"naconfiguratieVerplicht": true}'
    plain = _package()
    for cve in plain["cve"][0]["cves"]:
        cve.pop("naconfiguratieVerplicht", None)
    dressed = copy.deepcopy(plain)
    dressed["cve"][0]["extraStapNaUpgrade"] = looks_like
    for cve in dressed["cve"][0]["cves"]:
        cve["kern"] = looks_like
    loaded_plain = load_knowledge(_write(tmp_path, plain, "plain.json"), TODAY)
    loaded_dressed = load_knowledge(_write(tmp_path, dressed, "dressed.json"), TODAY)
    assert not loaded_dressed.missing, loaded_dressed.reason
    assert loaded_dressed.cve[0]["extraStapNaUpgrade"] == looks_like
    assert loaded_dressed.cve[0]["cves"][1]["kern"] == looks_like
    export = _isn(tmp_path / "export", "73.37")
    plain_verdicts, _ = cve_verdicts(export, loaded_plain)
    dressed_verdicts, _ = cve_verdicts(export, loaded_dressed)
    assert [v.verdict for v in dressed_verdicts] == [v.verdict for v in plain_verdicts] == [NIET_GERAAKT] * 2


def test_correct_per_cve_flag_still_gives_not_established(tmp_path):
    from test_cve_post_upgrade_config import _isn

    loaded = _load(tmp_path, _package())
    assert not loaded.missing
    verdicts, gaps = cve_verdicts(_isn(tmp_path / "export", "73.37"), loaded)
    assert [v.verdict for v in verdicts] == [NIET_GERAAKT, NIET_VASTGESTELD]
    assert verdicts[1].read_gap is not None and "naconfiguratie" in verdicts[1].read_gap.source


def test_a_minimum_engine_changes_no_verdict(tmp_path):
    """The new line judges exactly like the existing line: the field steers
    loading, never a verdict."""
    from test_cve_post_upgrade_config import _isn

    export = _isn(tmp_path / "export", "73.36")
    existing = load_knowledge(_write(tmp_path, _package(), "a.json"), TODAY)
    new = load_knowledge(_write(tmp_path, _package(minimaleEngine="1.1.0"), "b.json"), TODAY)
    assert existing == new
    assert cve_verdicts(export, existing) == cve_verdicts(export, new)


# ---------------------------------------------------------------------------
# The CLI: --controleer next to --digest
# ---------------------------------------------------------------------------


def test_the_check_command_says_whether_this_engine_loads_the_package(tmp_path, capsys):
    good = _write(tmp_path, _package(minimaleEngine="1.1.0"), "goed.json")
    assert main(["--controleer", str(good)]) == 0
    assert capsys.readouterr().out == "deze engine (1.1.0) laadt dit kennispakket\n"
    newer = _write(tmp_path, _package(minimaleEngine="1.4.2"), "nieuwer.json")
    assert main(["--controleer", str(newer)]) == 1
    printed = capsys.readouterr()
    assert printed.out == ""
    assert printed.err == (
        "deze engine (1.1.0) laadt dit kennispakket niet: kennispakket vraagt engine 1.4.2 of nieuwer;"
        " deze engine is 1.1.0; werk eerst de engine bij\n"
    )


def test_the_cli_names_all_its_modes_on_a_wrong_call(capsys):
    for arguments in ([], ["--controleer"], ["--onbekend", "x"], ["--digest", "a", "b"], ["--regressie", "a"]):
        assert main(arguments) == 2
        assert capsys.readouterr().err == (
            "Gebruik: python -m nsmcp.knowledge --digest <pad-naar-kennispakket>\n"
            "         python -m nsmcp.knowledge --controleer <pad-naar-kennispakket>\n"
            "         python -m nsmcp.knowledge --regressie <pad-naar-kennispakket> <pad-naar-matrix>\n"
        )


def test_the_real_shape_of_the_existing_line_still_digests(tmp_path, capsys):
    """--digest is unchanged for a package of the existing line."""
    path = _write(tmp_path, _package())
    assert main(["--digest", str(path)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["kennispin"]["versie"] == "2026.10"
