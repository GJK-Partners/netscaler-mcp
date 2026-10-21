"""Woordkeuspoort: elf termen die een certificaat wegwerpbaar laten lijken.

Een certificaat waarvan DEZE export geen gebruikers laat zien, is geen
certificaat zonder gebruikers. Dat verschil is precies waar dit product op
draait, en het staat of valt met woordkeus: "geen gebonden virtuele servers
gevonden in deze export" is een uitspraak over de export, "ongebruikt" is
een uitspraak over de wereld - en die laatste kan dit product niet waarmaken.

Gemeten op de stand van 2026-08-27: alle elf termen komen nul keer voor.
Deze poort houdt dat zo, over elke module die antwoordtekst PRODUCEERT -
negentien inmiddels: de aanvankelijke vijf, drie toegevoegd na de
2.0.0-review, `rulesets.py` erbij, zeven meer in een latere uitbreiding,
`config_drift.py` en `cert_usage.py`.
`collect.py` stond eerder bewust BUITEN de lijst met als reden dat het
legitiem "opruimen" gebruikt voor het opruimen van een map op schijf - maar
geen van de elf termen is daar ooit gemeten, en de module draagt wel
degelijk antwoordtekst (de scanuitkomst van `status_ververs`, via
`mcp_server.py`). Die uitzondering was dus zelf de blinde vlek; ze staat nu
in de lijst, gemeten schoon.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from nsmcp.action import what_to_do
from nsmcp.answer import stamp_data
from nsmcp.expiry import what_expires
from nsmcp.export import load_export
from nsmcp.impact import what_breaks
from nsmcp.knowledge import Knowledge

FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"
TODAY = date(2026, 8, 26)
_KNOWLEDGE = Knowledge(version="woordkeus", date="2026-08-26", age_days=0, missing=False)

# The eleven terms. Every one of them turns a statement about THIS EXPORT
# into a statement about the world - a claim this product cannot back up.
FORBIDDEN = (
    "ongebruikt",
    "niet in gebruik",
    "kan weg",
    "mag weg",
    "overbodig",
    "kan verwijderd worden",
    "veilig te verwijderen",
    "opgeruimd",
    "weescertificaat",
    "nergens gebruikt",
    "geen impact",
)

# Only the modules that PRODUCE answer text.
ANSWER_MODULES = (
    "impact.py",
    "action.py",
    "expiry.py",
    "answer.py",
    "disclosure.py",
    # Added after the 2.0.0 review: these four also PRODUCE answer text
    # (the CVE verdicts, the service state, the overview and the writing
    # tools' refusals and proposals), and they were outside this gate.
    "cve.py",
    "dienst.py",
    "overzicht.py",
    "handelen.py",
    # `rulesets.py` also PRODUCES answer text - the ruleset line that every
    # verdict following from a ruleset carries - so it belongs inside this
    # gate rather than beside it.
    "rulesets.py",
    # Six more answer-producing modules were outside this gate - three the
    # ledger already recorded (ha.py, tls_baseline.py, collect.py) and three
    # more measured directly (coverage.py, hidden_rules.py, names.py all
    # build `Answer` objects). `mcp_server.py` is added alongside them: it
    # carries the tool set's own headline vocabulary directly in its
    # f-strings, outside every other module's reach.
    # MEASURED: none of the eleven terms occurs in any of the seven before
    # this line was added - this gate widens coverage, it does not report a
    # live hit.
    "ha.py",
    "tls_baseline.py",
    "collect.py",
    "coverage.py",
    "hidden_rules.py",
    "names.py",
    "mcp_server.py",
    # `config_drift.py` builds the answer of `config_drift`.
    "config_drift.py",
    # `cert_usage.py` writes the findings, read gaps and boundaries of the
    # certificate use outside the bindings (SAML, SSL servicegroups).
    "cert_usage.py",
)


def _answer_texts() -> list[str]:
    """Every answer the three engines produce on the real lab export, for
    three deliberately different certificates: the issuing CA (chain), the
    issued certificate (direct bindings), and a name that this export knows
    nothing about (the case that most tempts a 'nothing hangs on it'
    wording).
    """
    export = load_export(FIXTURE)
    texts: list[str] = []
    expiry = stamp_data(what_expires(export, _KNOWLEDGE, 3650), export.collected_at, TODAY, export.target_name)
    texts.append(expiry.to_text())
    for name in ("CERT-004", "CERT-009", "een-naam-die-hier-niet-bestaat"):
        impact = what_breaks(export, _KNOWLEDGE, name)
        texts.append(stamp_data(impact, export.collected_at, TODAY, export.target_name).to_text())
        action = what_to_do(impact, _KNOWLEDGE, name)
        texts.append(stamp_data(action, export.collected_at, TODAY, export.target_name).to_text())
    return texts


def test_no_answer_presents_a_certificate_as_disposable():
    texts = _answer_texts()
    assert texts, "zonder antwoorden bewijst deze poort niets"
    for text in texts:
        lowered = text.lower()
        for term in FORBIDDEN:
            assert term not in lowered, f"weggooitaal {term!r} in een antwoord:\n{text}"


def test_the_answer_producing_modules_carry_none_of_the_eleven_terms():
    """Tweede net, op de bron: een tekst die alleen op een pad ontstaat dat
    de fixture hierboven niet raakt, wordt hier alsnog gevangen.
    """
    src = Path(__file__).resolve().parent.parent / "src" / "nsmcp"
    for module in ANSWER_MODULES:
        corpus = (src / module).read_text(encoding="utf-8").lower()
        for term in FORBIDDEN:
            assert term not in corpus, f"weggooitaal {term!r} in src/nsmcp/{module}"


def test_the_certificate_without_found_users_still_makes_a_statement():
    """Tegenproef: het verbod op weggooitaal mag niet leiden tot zwijgen.
    Een certificaat waarvan niets gevonden is, krijgt nog steeds een
    uitspraak - alleen een die over DEZE export gaat.

    Tot 2026-08-27 eiste deze test hier `is_complete() is True` op de gouden
    fixture. Die fixture draagt DRIE virtuele servers en TWEE parents in het
    bindingsbestand: van VSRV-001 is nooit gelezen welk certificaat het
    draagt, dus dat het niet aan DIT certificaat hangt is niet vast te
    stellen. Het antwoord is daarmee terecht onvolledig. Wat deze poort
    bewaakt - geen weggooitaal, en geen zwijgen - staat er onveranderd: het
    antwoord benoemt expliciet wat het niet kon vaststellen, in plaats van
    de stilte die als "er hangt niets aan" gelezen wordt.
    """
    export = load_export(FIXTURE)
    answer = what_breaks(export, _KNOWLEDGE, "een-naam-die-hier-niet-bestaat")
    text = answer.to_text()
    assert answer.is_complete() is False
    assert "NIET VASTGESTELD" in text, "zwijgen is geen antwoord"
    assert "VSRV-001" in text, "de dienst waarover niets vaststaat hoort benoemd te worden"


def test_a_fully_covered_export_still_makes_the_established_statement():
    """Tweede helft van dezelfde tegenproef, op een export ZONDER ongelezen
    parent: daar hoort de vastgestelde uitspraak over deze export wel
    degelijk te blijven staan. Zonder deze test zou een versie die altijd
    zwijgt hierboven groen blijven."""
    from nsmcp.answer import ReadGap
    from nsmcp.export import ParentCoverage

    class _Volledig:
        def bindings(self, file_name):
            return ([{"certkeyname": "iets_anders", "vservername": "LB_VS_A"}], None)

        def objects(self, resource):
            return ([], None)

        def binding_parents(self, file_name):
            return ParentCoverage(names=("LB_VS_A",))

        # The certificate-side file is not part of this export.
        def binding_rows(self, file_name, *, children=None):
            return {}, ReadGap(source=file_name, reason="geen hash in het manifest; geen hash is geen vertrouwen")

        def binding_child_keys(self, file_name):
            return {}, ReadGap(source=file_name, reason="geen hash in het manifest; geen hash is geen vertrouwen")

    answer = what_breaks(_Volledig(), _KNOWLEDGE, "een-naam-die-hier-niet-bestaat")
    text = answer.to_text().lower()
    assert "in deze export" in text
    assert answer.is_complete() is True
