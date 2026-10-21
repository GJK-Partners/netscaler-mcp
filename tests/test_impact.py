import hashlib
import json
import shutil
from pathlib import Path

import pytest
from conftest import seal_manifest

from nsmcp.action import what_to_do
from nsmcp.answer import Certainty, ReadGap
from nsmcp.export import ParentCoverage, load_export
from nsmcp.impact import BINDING_FILE, what_breaks
from nsmcp.knowledge import Knowledge

FRESH = Knowledge(version="2026.08", date="2026-08-16", age_days=3, missing=False)
FIXTURE = Path(__file__).parent / "fixtures" / "lab-export-vpx-20260826"


class ExportStub:
    """Stub for the export layer.

    `objects` was added when what_breaks() started reading the issuing
    relation from config/sslcertkey. The default is an EMPTY, successfully
    read list - not a read gap: "read fine, nothing in it" is the neutral
    starting point that leaves every pre-existing binding test measuring
    exactly what it measured before.

    `binding_parents` was added for the same reason one round later, when
    what_breaks() started cross-checking the parent list of the binding file
    against the object source of those parents. Same neutral default: a
    fully covered parent list with no gaps, so every pre-existing test keeps
    measuring exactly what it measured before.

    `binding_rows`/`binding_child_keys` read the certificate-side file
    (`sslcertkey_binding.by-parent.json`). Neutral default: an export that
    does not carry that file, the way a hand-built export without its hash
    reads - so every pre-existing test keeps measuring what it measured.
    `cert_side` gives it content instead: `{certkey: [(kind, row), ...]}`,
    as `Export.binding_rows` returns the aggregate shape.
    """

    def __init__(self, bindings, gap=None, certs=None, cert_gap=None, parents=None, cert_side=None):
        self._b, self._gap = bindings, gap
        self._certs, self._cert_gap = (certs if certs is not None else []), cert_gap
        self._parents = parents if parents is not None else ParentCoverage()
        self._cert_side = cert_side

    def bindings(self, file_name):
        return (self._b, self._gap)

    def objects(self, resource):
        return (self._certs, self._cert_gap)

    def binding_parents(self, file_name):
        return self._parents

    def binding_rows(self, file_name, *, children=None):
        if self._cert_side is None:
            return {}, ReadGap(source=file_name, reason="geen hash in het manifest; geen hash is geen vertrouwen")
        return self._cert_side, None

    def binding_child_keys(self, file_name):
        if self._cert_side is None:
            return {}, ReadGap(source=file_name, reason="geen hash in het manifest; geen hash is geen vertrouwen")
        return {
            parent: tuple(sorted({kind for kind, _row in pairs or ()})) for parent, pairs in self._cert_side.items()
        }, None


def test_bound_vservers_are_named():
    b = [
        {"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False},
        {"certkeyname": "cert_a", "vservername": "CS_VS_B", "snicert": True, "ca": False},
        {"certkeyname": "cert_anders", "vservername": "LB_VS_C", "snicert": False, "ca": False},
    ]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    text = a.to_text()
    assert "LB_VS_A" in text
    assert "CS_VS_B" in text
    assert "LB_VS_C" not in text


def test_sni_binding_is_named_separately():
    b = [{"certkeyname": "cert_a", "vservername": "CS_VS_B", "snicert": True, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert "SNI" in a.to_text()


def test_client_auth_breaks_something_else_and_is_reported_as_such():
    b = [{"certkeyname": "cert_a", "vservername": "GW_X", "snicert": False, "ca": True}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    text = a.to_text()
    assert "client" in text.lower()
    assert "servercertificaat" not in text.lower()


def test_missing_ca_flag_is_not_established_and_not_an_assumption():
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    b0 = a.findings[0]
    assert b0.certainty is Certainty.NOT_ESTABLISHED
    # "ca" also sits inside "certificaat" and "authenticatie" - guards nothing.
    # "ontbreekt" only occurs in the missing-key branch, not in the
    # unrecognizable-shape branch.
    assert "ontbreekt" in b0.reason.lower()


def test_unrecognizable_ca_shape_is_also_not_established_and_not_an_assumption():
    """NITRO returns ca as a JSON bool or string - both shapes are already
    recognized. But a present ca key with a value that is neither shape
    (here: null/None, like a collector writing an unfetched field as JSON
    null) must not silently appear as "False" (and thus server certificate):
    that is the same falsely-certain error as float-shaped days, but without
    the safe retreat to "unknown" - here it would become a wrong ESTABLISHED
    finding instead of a justified NOT_ESTABLISHED.
    """
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": None}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    b0 = a.findings[0]
    assert b0.certainty is Certainty.NOT_ESTABLISHED
    # Unique to this branch (the missing-key branch does not contain this
    # word): pins that the reason really says "unrecognizable shape", not
    # accidentally the other text.
    assert "herkennen" in b0.reason.lower()


def test_unreadable_bindings_never_mean_no_impact():
    # `certs` carries the questioned certificate itself: this test is about
    # the BINDING read gap, and an export that does not know cert_a at all
    # would (rightly) add a candidate statement out of a
    # source that WAS read - a different subject than the one measured here.
    a = what_breaks(
        ExportStub(
            [],
            gap=ReadGap(source="sslvserver_sslcertkey_binding.json", reason="hash wijkt af"),
            certs=[{"certkey": "cert_a"}],
        ),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert "geen impact" not in a.to_text().lower()
    # The outer guard (`if gap is None:`) is the only place shielding this
    # path: with a read gap no finding may arise, not even one that happens
    # to be correct.
    assert a.findings == []


def test_no_binding_found_in_a_read_file_is_still_a_statement():
    a = what_breaks(ExportStub([{"certkeyname": "iets_anders", "vservername": "LB_VS_A"}]), FRESH, "cert_a")
    assert a.is_complete() is True
    assert "geen gebonden" in a.to_text().lower()


def test_no_sni_annotation_when_snicert_is_not_true():
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert "SNI" not in a.to_text()


# ---------------------------------------------------------------------------
# An unreadable certkeyname must never silently become "no impact".
#
# `str(b.get("certkeyname", "")) == certnaam` let every binding whose
# certkeyname the collector wrote as JSON null silently fall out of the
# filter. If that was the only binding, an ESTABLISHED "geen gebonden
# virtuele servers gevonden in deze export" followed with ZERO read gaps -
# the falsely-green answer this product exists to prevent. Shown end-to-end
# through a real MCP session: certificate expires in 9 days, a virtual
# server hangs on it, and the front door answered that nothing did.
#
# On top of that came an asymmetry: mcp_server.py normalizes the USER input
# with .strip(), impact.py did not do that on the SOURCE data - so " cert_a "
# from the export did not match the question "cert_a", and vanished just as
# silently.
# ---------------------------------------------------------------------------


def test_binding_without_usable_certkeyname_is_a_read_gap_not_a_filter_miss():
    """The bare variant: ONE binding, certkeyname is JSON null.

    Without the repair this yielded an ESTABLISHED "geen gebonden virtuele
    servers" with zero read gaps. As long as this binding could not be
    assessed, that statement must not stand - not knowing whether something
    hangs on it is different from knowing that nothing does.
    """
    b = [{"certkeyname": None, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is False, "een onbeoordeelbare binding hoort een leesgat te zijn"
    text = a.to_text()
    assert "geen gebonden virtuele servers" not in text.lower()
    assert "NIET VASTGESTELD" in text
    assert any("certkeyname" in g.reason for g in a.read_gaps)


def test_unassessable_binding_prevents_the_established_no_bindings_statement():
    """Sharper than the test above: even WITH another, readable binding
    that does not match (so no hit) there must be no ESTABLISHED "geen
    gebonden virtuele servers" while a binding remained unassessed. A
    mutation that does add the read gap but leaves the empty-case finding in
    place would slip past the test above on the read-gap assertion alone -
    not here, because then both contradictory statements sit in the same
    answer.
    """
    b = [
        {"certkeyname": "iets_anders", "vservername": "LB_VS_C", "snicert": False, "ca": False},
        {"certkeyname": None, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False},
    ]
    # Same reason as the test above: the questioned certificate exists, so
    # the candidate statement (a different subject, out of a source that was
    # read) stays out of the way of what this test measures.
    a = what_breaks(ExportStub(b, certs=[{"certkey": "cert_a"}]), FRESH, "cert_a")
    assert a.findings == []
    assert a.is_complete() is False


def test_mixed_bindings_do_not_conceal_the_unassessable_ones():
    """The mixed variant: a good binding plus two that cannot be assessed.
    Without the repair the answer named only the good one and stayed silent
    about the other two - the most dangerous case, because the answer looks
    complete.
    """
    b = [
        {"certkeyname": "cert_a", "vservername": "LB_VS_GOED", "snicert": False, "ca": False},
        {"certkeyname": None, "vservername": "LB_VS_NULL", "snicert": False, "ca": False},
        {"certkeyname": "", "vservername": "LB_VS_LEEG", "snicert": False, "ca": False},
    ]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    text = a.to_text()
    assert "LB_VS_GOED" in text
    assert a.is_complete() is False, "twee onbeoordeelbare bindingen mogen niet in stilte verdwijnen"
    assert len(a.read_gaps) == 2


def test_missing_certkeyname_key_is_also_a_read_gap():
    """A binding without a certkeyname key is the same failure class as an
    empty value: we do not know which certificate it belongs to. A separate
    branch from the null value above (b.get() returns None through the
    default there, through the value itself here) - a mutation that only
    checks `is None` of the VALUE lets this one through.
    """
    b = [{"vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is False
    assert "geen gebonden virtuele servers" not in a.to_text().lower()


def test_missing_certkeyname_key_names_the_absent_key_not_a_json_null():
    """Coverage gap: the test above proves this is a read gap,
    not that the SENTENCE is the pinned absent-key one and not shape_of's
    JSON-null wording. Written to prove this call site of the shared
    `export.shape_or_missing` idiom really routes through it."""
    b = [{"vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert any("certkeyname is niet bruikbaar: de sleutel ontbreekt;" in g.reason for g in a.read_gaps), a.read_gaps


def test_certkeyname_with_surrounding_spaces_matches_the_same_name():
    """The asymmetry, SOURCE-data side: mcp_server.py strip()s the user
    input, impact.py did not do that on the export. A binding with
    "  cert_a  " therefore silently fell out of the filter - no hit, no
    read gap, no trace. Both sides are now normalized the same way, so this
    is simply a hit.
    """
    b = [{"certkeyname": "  cert_a  ", "vservername": "LB_VS_SPATIES", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is True, "een genormaliseerde treffer is geen leesgat"
    text = a.to_text()
    assert "LB_VS_SPATIES" in text
    assert "geen gebonden virtuele servers" not in text.lower()


def test_certnaam_with_surrounding_spaces_matches_the_source_data():
    """The same normalization, the other way around: what_breaks() is
    called here directly with an unstripped certnaam (mcp_server.py does
    strip it, but that is an assumption about another module, not a
    guarantee). Without normalization ON BOTH SIDES, a mutation that only
    strip()s the source data does not cover this branch.
    """
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "  cert_a  ")
    assert "LB_VS_A" in a.to_text()
    assert a.is_complete() is True


def test_a_name_that_really_differs_still_is_no_match():
    """Counter-probe to the normalization: strip() must not equate names
    that really differ. "naam met spaties" is a DIFFERENT certificate than
    "cert_a", no read gap and no hit - otherwise the repair would overshoot
    the other way and tie everything together.
    """
    b = [{"certkeyname": "  naam met spaties  ", "vservername": "LB_VS_X", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is True
    assert "LB_VS_X" not in a.to_text()
    assert "geen gebonden virtuele servers" in a.to_text().lower()


# ---------------------------------------------------------------------------
# A promised dimension must not be absent without a read gap.
#
# The spec (docs/ARCHITECTURE.md)
# promises that impact also covers "whether the chain is complete and
# whether the intermediate CA does not itself expire earlier". v1 does not
# need to ASSESS that dimension, but a product that sells itself on
# "uniquely says what it could not establish" must not drop it either.
# ---------------------------------------------------------------------------


def test_the_chain_dimension_is_always_reported_as_not_assessed():
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    text = a.to_text()
    assert "NIET BEOORDEELD" in text
    assert "keten" in text.lower()
    assert any("keten" in n.subject.lower() for n in a.not_assessed)


def test_the_chain_dimension_states_what_is_assessed_and_what_is_not():
    """De niet-beoordeeld-tekst moet kloppen met wat de versie DOET. Sinds
    de ketenronde wordt de rechtstreekse uitgifterelatie wel degelijk
    gelezen; die als "buiten bereik" laten staan zou het product laten
    liegen over zijn eigen grens. Wat er nog steeds buiten valt, moet er
    eerlijk blijven staan - inclusief dat de keten maar een niveau diep
    gevolgd wordt.
    """
    a = what_breaks(ExportStub([]), FRESH, "cert_a")
    reason_text = " ".join(n.reason.lower() for n in a.not_assessed)
    assert "linkcertkeyname" in reason_text, "wat WEL beoordeeld wordt hoort benoemd te zijn"
    assert "root" in reason_text
    assert "ca" in reason_text
    assert "monitors" in reason_text
    assert "niveau" in reason_text, "de dieptegrens van de keten hoort benoemd te zijn"
    assert "v1 beoordeelt de keten niet" not in reason_text, "die uitspraak is niet meer waar en mag niet blijven staan"


def test_the_chain_dimension_does_not_block_the_answer():
    """Deliberately out of scope is not a read gap: the answer stays
    complete and the established findings remain. If this were reported as
    a read gap, what_to_do() would never give an action proposal again -
    then the product is broken instead of honest.
    """
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is True
    assert a.read_gaps == []
    assert "LB_VS_A" in a.to_text()


def test_the_chain_dimension_is_also_reported_when_there_is_a_read_gap():
    """The statement does not hang on the happy path: even when the
    bindings are unreadable, the chain dimension is still not assessed. A
    mutation that puts the statement inside the `if gap is None` branch
    would fall silent here.
    """
    a = what_breaks(
        ExportStub([], gap=ReadGap(source="sslvserver_sslcertkey_binding.json", reason="hash wijkt af")),
        FRESH,
        "cert_a",
    )
    assert a.not_assessed
    assert "NIET BEOORDEELD" in a.to_text()


# ---------------------------------------------------------------------------
# The same failure class as the null-certkeyname above, but through the TYPE
# instead of through null or spaces. `_readable_name()` did
# `str(waarde).strip()` without first checking whether the value already WAS
# text. A certkeyname that is a list, dict, boolean or number is blindly
# converted by str() into a string that happens not to match certnaam - no
# read gap, gone from the filter without a trace, exactly the same
# falsely-green outcome as the null shape above. Proven against the REAL
# _readable_name()/what_breaks(), not against an assumption about what
# isinstance() should do.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "certkeyname_value",
    [
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
        pytest.param(12345, id="number"),
        pytest.param(False, id="boolean"),
    ],
)
def test_certkeyname_with_wrong_type_is_a_read_gap_not_a_silent_filter_miss(certkeyname_value):
    """Four shapes that `str(waarde).strip()` all four blindly rebuilds
    into a valid-looking, non-matching string (`str([])` = "[]", `str({})`
    = "{}", `str(12345)` = "12345", `str(False)` = "False"): without an
    isinstance gate the binding silently falls out of the filter, exactly
    as the JSON-null shape did. A structurally mistyped certkeyname is
    "not establishable whether this belongs to this certificate", never a
    silent "does not belong to it".
    """
    b = [{"certkeyname": certkeyname_value, "vservername": "LB_VS_PORTAAL", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.is_complete() is False, "een structureel verkeerd getypeerde certkeyname hoort een leesgat te zijn"
    assert "geen gebonden virtuele servers" not in a.to_text().lower()
    assert "NIET VASTGESTELD" in a.to_text()
    assert any("certkeyname" in g.reason for g in a.read_gaps)


def test_mixed_wrong_type_certkeyname_next_to_good_binding_blocks_the_action_proposal():
    """The mixed variant, carried through into the real action proposal: a
    good binding (certkeyname="cert_a") plus a second binding on the same
    certificate with certkeyname=[]. Without an isinstance gate the list
    shape does not match, yields no read gap, and what_breaks() delivers a
    "complete" answer with exactly 1 affected vserver - after which
    action.what_to_do() proposes "Koppel het om op: LB_VS_GOED" with full
    conviction, while LB_VS_TWEEDE remained unassessed. Tested into
    what_to_do(), not only on the impact answer: that action proposal is
    what an operator actually follows.
    """
    b = [
        {"certkeyname": "cert_a", "vservername": "LB_VS_GOED", "snicert": False, "ca": False},
        {"certkeyname": [], "vservername": "LB_VS_TWEEDE", "snicert": False, "ca": False},
    ]
    impact = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert impact.is_complete() is False, "de onbeoordeelbare tweede binding hoort de volledigheid te breken"
    assert "LB_VS_GOED" in impact.to_text(), "de goede binding mag niet verdwijnen door de slechte"

    proposal = what_to_do(impact, FRESH, "cert_a")
    text = proposal.to_text()
    assert "Koppel het om op: LB_VS_GOED" not in text, (
        "geen voorstel met volle overtuiging zolang een tweede binding op hetzelfde certificaat"
        " niet beoordeeld kon worden"
    )
    assert "geen wijzigingsvoorstel zolang de impact niet vaststaat" in text.lower()


def test_vservername_with_wrong_type_falls_back_to_naamloos_not_a_literal_repr():
    """The same failure class as certkeyname, now for vservername: the old
    line did `str(b.get("vservername") or "(naamloos)")`. A non-empty list
    is "or"-truthy, so `str(["LB_VS_A"])` = "['LB_VS_A']" landed as vserver
    name in the evidence AND in affected_vservers - a literal Python repr
    that action.py would build a rebind advice on. vservername now runs
    through _readable_name() like certkeyname: a non-text shape falls back
    to "(naamloos)", the same tidy fallback a missing or empty vservername
    already had.
    """
    b = [{"certkeyname": "cert_a", "vservername": ["LB_VS_A"], "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b), FRESH, "cert_a")
    assert a.affected_vservers == ("(naamloos)",)
    assert "['LB_VS_A']" not in a.to_text()


# ---------------------------------------------------------------------------
# Een certificaat dat andere certificaten UITGEEFT is in gebruik.
#
# Gemeten op een echt lab: een CA die via `link ssl certKey` het
# servercertificaat van twee diensten uitgeeft, kreeg "geen gebonden
# virtuele servers gevonden in deze export" - niet onwaar, wel te lezen als
# "er hangt niets aan". De data stond er al: het UITGEGEVEN certificaat
# draagt in objects/sslcertkey.json het veld `linkcertkeyname` met de naam
# van de CA. De gouden fixture draagt exact dat geval: CERT-009 ->
# CERT-004.
# ---------------------------------------------------------------------------


def test_a_certificate_that_issues_another_certificate_is_reported_as_in_use():
    """Het kerngeval. `ca_uitgever` geeft `leaf_cert` uit; er hangt geen
    enkele binding rechtstreeks aan `ca_uitgever`. Voor de reparatie was het
    antwoord uitsluitend "geen gebonden virtuele servers gevonden in deze
    export" - een uitspraak die als "ongebruikt" te lezen valt.
    """
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "los_cert"},
        # De uitgever staat, net als op een echte doos, zelf ook als certKey in
        # de export - `link ssl certKey` wijst naar een certificaat dat er is.
        # Ontbreekt hij, dan is de relatie dangling en meldt de motor dat
        # terecht als afwijking (zie de dangling-tests onderaan dit bestand).
        {"certkey": "ca_uitgever"},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    text = a.to_text()
    assert "leaf_cert" in text, "het uitgegeven certificaat hoort in het antwoord te staan"
    assert a.issued_certificates == ("leaf_cert",)
    assert a.is_complete() is True


def test_the_issued_certificate_finding_carries_field_level_evidence():
    """Bewijsplicht: de bevinding noemt het bestand EN het veld waaruit de
    relatie komt. Zonder deze test zou een bevinding met een vage bewijsregel
    ("afgeleid uit de export") groen blijven.
    """
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    issued = [b for b in a.findings if b.subject == "leaf_cert"]
    assert len(issued) == 1
    assert issued[0].certainty is Certainty.ESTABLISHED
    assert "config/sslcertkey" in issued[0].evidence
    assert "linkcertkeyname" in issued[0].evidence


def test_an_issuing_certificate_never_gets_the_bare_no_bindings_statement():
    """De vastgestelde "niets gevonden"-uitspraak mag NIET naast een
    vastgestelde uitgifterelatie staan: twee tegenstrijdige uitspraken in
    hetzelfde antwoord is precies het beeld dat de operator misleidde.
    """
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert "geen gebonden virtuele servers en geen uitgegeven certificaten" not in a.to_text().lower()


def test_nothing_found_says_so_about_both_routes_at_once():
    """Tegenproef: is er WEL alles gelezen en is er via geen van beide
    routes iets gevonden, dan is dat nog steeds een uitspraak - maar hij
    dekt nu allebei de routes, en blijft een uitspraak over DEZE export.
    """
    a = what_breaks(ExportStub([], certs=[{"certkey": "los_cert"}]), FRESH, "cert_a")
    b0 = a.findings[0]
    assert b0.certainty is Certainty.ESTABLISHED
    assert b0.outcome == ("geen gebonden virtuele servers en geen uitgegeven certificaten gevonden in deze export")
    assert "config/sslcertkey" in b0.evidence
    assert "linkcertkeyname" in b0.evidence
    assert "in deze export" in b0.outcome


def test_a_missing_linkcertkeyname_key_is_not_a_read_gap():
    """Grens naar de andere kant. NITRO schrijft `linkcertkeyname` alleen
    als er echt een link is - in de gouden fixture draagt 1 van de 4
    certificaten het veld. Een ontbrekende sleutel als leesgat behandelen
    maakt van elke export een leesgat en breekt het product; de eerlijkheid
    zit in de formulering ("in deze export"), niet in een leesgat.
    """
    a = what_breaks(ExportStub([], certs=[{"certkey": "los_cert"}]), FRESH, "cert_a")
    assert a.read_gaps == []
    assert a.is_complete() is True


@pytest.mark.parametrize(
    "link_value",
    [
        pytest.param(None, id="json-null"),
        pytest.param("", id="leeg"),
        pytest.param("   ", id="alleen-spaties"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
        pytest.param(12345, id="number"),
        pytest.param(False, id="boolean"),
    ],
)
def test_an_unusable_linkcertkeyname_is_a_read_gap_not_a_filter_miss(link_value):
    """Zelfde faalklasse als een onbruikbare certkeyname op een binding:
    `str(waarde).strip()` zou hier blind een string maken die toevallig niet
    matcht, waarna de relatie spoorloos uit het filter valt. Aanwezig maar
    onbruikbaar is "niet vast te stellen", nooit "hoort er niet bij".
    """
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": link_value}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert a.is_complete() is False
    assert any("linkcertkeyname" in g.reason for g in a.read_gaps)
    assert "geen gebonden virtuele servers en geen uitgegeven certificaten" not in a.to_text().lower()


def test_an_unusable_certkey_on_a_matching_link_is_a_read_gap():
    """We weten DAT er iets uitgegeven wordt, maar niet WAT. Dat is geen
    vastgestelde uitgifte en ook geen niets: het is een leesgat met die
    reden. Een mutatie die hier "(naamloos)" invult zou een verzonnen
    certificaatnaam de bewijsregel in duwen.
    """
    certs = [{"certkey": None, "linkcertkeyname": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert a.is_complete() is False
    assert a.issued_certificates == ()
    assert any("certkey" in g.reason for g in a.read_gaps)


def test_a_missing_certkey_key_on_a_matching_link_names_the_absent_key():
    """Coverage gap: the test above exercises this gate's JSON-
    null branch (certkey=None); a certificate object without ANY certkey
    key at all exercises the OTHER branch of the same gate and must print
    the absent-key sentence, not shape_of's JSON-null wording - proving
    this second call site in impact.py also routes through the shared
    `export.shape_or_missing` idiom."""
    certs = [{"linkcertkeyname": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert a.is_complete() is False
    assert a.issued_certificates == ()
    assert any("certkey is niet bruikbaar: de sleutel ontbreekt;" in g.reason for g in a.read_gaps), a.read_gaps


def test_an_unreadable_certificate_file_never_means_nothing_is_issued():
    """Het leesgat op config/sslcertkey moet net zo hard doorwerken als dat
    op het bindingsbestand: geen vastgestelde "niets gevonden"-uitspraak
    zolang de certificaten niet gelezen konden worden.
    """
    a = what_breaks(
        ExportStub([], cert_gap=ReadGap(source="config/sslcertkey", reason="read niet bruikbaar: RBAC_DENIED")),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert "geen gebonden virtuele servers" not in a.to_text().lower()
    assert a.findings == []


def test_the_issuing_certificate_is_deduplicated_in_reading_order():
    """Twee vermeldingen van hetzelfde uitgegeven certificaat (een export
    kan een certkey herhalen) leveren een naam op in de verzameling, in
    leesvolgorde - dezelfde regel die affected_vservers al volgt.
    """
    certs = [
        {"certkey": "leaf_b", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "leaf_a", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "leaf_b", "linkcertkeyname": "ca_uitgever"},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert a.issued_certificates == ("leaf_b", "leaf_a")


def test_the_issuing_name_is_normalized_on_both_sides():
    """Zelfde asymmetrie-reparatie als bij certkeyname: de gebruikersinvoer
    wordt gestript, dus de brondata moet dat ook worden - en andersom.
    """
    certs = [{"certkey": "  leaf_cert  ", "linkcertkeyname": "  ca_uitgever  "}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    assert a.issued_certificates == ("leaf_cert",)
    assert a.is_complete() is True


def test_the_chain_reaches_the_services_behind_the_issued_certificate():
    """Het volle gemeten geval: de CA geeft een certificaat uit, en aan dat
    certificaat hangen twee diensten. Beide diensten horen in het antwoord,
    met de keten erbij - anders staat er wel dat er een certificaat
    uitgegeven wordt, maar niet wat er kapotgaat.
    """
    bindings = [
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": False, "ca": False},
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_TWEE", "snicert": False, "ca": False},
    ]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(bindings, certs=certs), FRESH, "ca_uitgever")
    text = a.to_text()
    assert "LB_VS_EEN" in text
    assert "LB_VS_TWEE" in text
    assert a.is_complete() is True


def test_the_transitive_finding_names_the_intermediate_certificate_as_evidence():
    """Bewijsplicht op de keten zelf: de bevinding over de dienst moet
    zichtbaar maken VIA WELK certificaat de dienst geraakt wordt, met beide
    bronbestanden erin. Zonder deze test zou een bevinding die de dienst
    noemt maar de schakel verzwijgt groen blijven.
    """
    bindings = [{"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": False, "ca": False}]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(bindings, certs=certs), FRESH, "ca_uitgever")
    hit = [b for b in a.findings if b.subject == "LB_VS_EEN"]
    assert len(hit) == 1
    assert "leaf_cert" in hit[0].outcome
    assert "sslvserver_sslcertkey_binding" in hit[0].evidence
    assert "config/sslcertkey" in hit[0].evidence
    assert hit[0].certainty is Certainty.ESTABLISHED


def test_the_transitive_vservers_do_not_land_in_the_rebind_collection():
    """De twee verzamelingen sturen twee VERSCHILLENDE reparaties aan. Een
    virtuele server wordt omgekoppeld naar een nieuw certificaat; een
    uitgegeven certificaat wordt opnieuw aan de nieuwe CA gekoppeld. Zouden
    de transitieve servers in affected_vservers belanden, dan stelt
    action.py een omkoppeling voor die de storing niet verhelpt.
    """
    bindings = [{"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": False, "ca": False}]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(bindings, certs=certs), FRESH, "ca_uitgever")
    assert a.affected_vservers == ()
    assert a.issued_certificates == ("leaf_cert",)


def test_two_bindings_on_the_same_service_behind_the_chain_are_named_once():
    """Een dienst met een gewone EN een SNI-binding op hetzelfde uitgegeven
    certificaat is een dienst, niet twee. Zonder ontdubbeling staat dezelfde
    regel twee keer in het antwoord.

    Gemeten op de bevindingsregel, niet op elk voorkomen van de naam: de
    bewijsregel noemt vservername ook, dus de naam staat per bevinding twee
    keer in de tekst. Tellen op de kale naam zou dus altijd falen, ook bij
    perfecte ontdubbeling - de regel in het antwoord is wat telt.
    """
    bindings = [
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": False, "ca": False},
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": True, "ca": False},
    ]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(bindings, certs=certs), FRESH, "ca_uitgever")
    assert len([b for b in a.findings if b.subject == "LB_VS_EEN"]) == 1
    assert a.to_text().count("- LB_VS_EEN:") == 1


def test_an_issued_certificate_without_bindings_says_so_about_this_export():
    """Ook hier fail-closed in beide richtingen: dat er achter het
    uitgegeven certificaat geen dienst gevonden is, is een uitspraak over
    DEZE export - en de uitgifterelatie zelf blijft gewoon staan.
    """
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    text = a.to_text()
    assert "leaf_cert" in text
    assert "in deze export" in text
    assert a.is_complete() is True


def test_an_unassessable_binding_withholds_the_statement_behind_the_chain_too():
    """Dezelfde regel als op de rechtstreekse route: zolang een binding niet
    beoordeeld kon worden, is de afwezigheid van treffers niets waard - ook
    niet achter een uitgegeven certificaat.
    """
    bindings = [{"certkeyname": None, "vservername": "LB_VS_ONBEKEND", "snicert": False, "ca": False}]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(bindings, certs=certs), FRESH, "ca_uitgever")
    assert a.is_complete() is False
    behind = [b for b in a.findings if b.subject == "leaf_cert"]
    assert not any("geen gebonden virtuele servers" in b.outcome for b in behind), (
        "geen vastgestelde niets-uitspraak zolang een binding onbeoordeeld bleef"
    )


def test_an_unreadable_binding_file_still_reports_the_issuing_relation():
    """De twee bronnen falen onafhankelijk. Is het bindingsbestand onleesbaar
    maar het certificaatbestand niet, dan is de uitgifterelatie nog steeds
    vast te stellen - het antwoord blijft onvolledig door het leesgat, maar
    verzwijgt de keten niet.
    """
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(
        ExportStub([], gap=ReadGap(source=BINDING_FILE, reason="hash wijkt af"), certs=certs),
        FRESH,
        "ca_uitgever",
    )
    assert a.is_complete() is False
    assert a.issued_certificates == ("leaf_cert",)
    assert "leaf_cert" in a.to_text()


# ---------------------------------------------------------------------------
# Een parent zonder vermelding in het bindingsbestand is een eigen faalklasse.
#
# `_flatten_by_parent` vangt een parent die AANWEZIG is met een onbruikbare
# outcome. Een parent die HELEMAAL ONTBREEKT laat geen spoor na: de vlakke
# lijst komt korter en compleet ogend naar boven. Gemeten op de echte
# labexport (zie tests/test_lab_export_parity.py): drie virtuele servers in
# de objectbron, twee parents in het bindingsbestand, en toch `read_gaps: []`.
# ---------------------------------------------------------------------------


def _unread_parent(name: str = "VSRV-001") -> ParentCoverage:
    return ParentCoverage(
        names=(name,),
        gaps=(
            ReadGap(
                source=f"{BINDING_FILE} (parentlijst)",
                reason=f"config/sslvserver kent {name}, maar dit bestand draagt daarvoor geen parent-vermelding",
            ),
        ),
    )


def test_an_unread_binding_parent_reaches_the_answer_as_a_read_gap():
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b, parents=_unread_parent()), FRESH, "cert_a")
    assert a.is_complete() is False
    assert any("VSRV-001" in g.reason for g in a.read_gaps)


def test_what_was_established_survives_next_to_an_unread_parent():
    """Het leesgat komt ERNAAST, niet ervoor in de plaats: LB_VS_A is
    aantoonbaar geraakt en dat blijft staan. Alles laten vallen om een derde
    onbekende te melden is fail-closed zo bot toegepast dat het antwoord
    stukgaat."""
    b = [{"certkeyname": "cert_a", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    a = what_breaks(ExportStub(b, parents=_unread_parent()), FRESH, "cert_a")
    assert a.affected_vservers == ("LB_VS_A",)
    assert any(x.subject == "LB_VS_A" and x.certainty is Certainty.ESTABLISHED for x in a.findings)


def test_an_unread_binding_parent_withholds_the_nothing_found_statement():
    """De kern: zolang de bindingen van EEN virtuele server ongelezen zijn,
    is 'geen gebonden virtuele servers gevonden' voor GEEN ENKEL certificaat
    vast te stellen - die server kan er immers aan hangen."""
    a = what_breaks(ExportStub([], parents=_unread_parent()), FRESH, "cert_a")
    assert "geen gebonden virtuele servers en geen uitgegeven certificaten" not in a.to_text().lower()
    assert a.is_complete() is False


def test_a_fully_covered_parent_list_changes_nothing():
    """Tegenproef: de gedekte parentlijst is de neutrale stand en mag geen
    enkel leesgat opleveren."""
    a = what_breaks(ExportStub([{"certkeyname": "iets_anders", "vservername": "LB_VS_A"}]), FRESH, "cert_a")
    assert a.read_gaps == []
    assert a.is_complete() is True
    assert "geen gebonden" in a.to_text().lower()


# ---------------------------------------------------------------------------
# Onmogelijke uitgifterelaties: zelfverwijzing, kringverwijzing, dangling.
#
# Route 2 nam `linkcertkeyname` tot nu toe onvoorwaardelijk als vastgesteld
# feit aan. Drie vormen die de export wel toestaat maar die geen geldige
# uitgifterelatie zijn, kwamen daardoor als vastgestelde bevinding naar boven
# - inclusief uitvoerbaar ogende herstelstappen.
# ---------------------------------------------------------------------------


def test_a_certificate_that_names_itself_as_issuer_is_reported_as_such():
    """Gemeten: {"certkey": "SELF_CA", "linkcertkeyname": "SELF_CA"} leverde
    "SELF_CA: wordt uitgegeven door SELF_CA". Op een echte doos is
    `link ssl certKey <root> <root>` voor een zelfondertekende root niet
    ondenkbaar, dus dit is brondata die herkend moet worden - niet
    doorverteld."""
    certs = [{"certkey": "SELF_CA", "linkcertkeyname": "SELF_CA"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "SELF_CA")
    tekst = a.to_text()
    assert "wordt uitgegeven door SELF_CA" not in tekst
    assert "zichzelf" in tekst.lower()


def test_a_self_referencing_certificate_gets_no_relink_advice_to_itself():
    """Actiestap 3 luidde "Koppel de certificaten die dit certificaat
    uitgeeft opnieuw: SELF_CA." - een instructie om een certificaat aan
    zichzelf te hangen."""
    certs = [{"certkey": "SELF_CA", "linkcertkeyname": "SELF_CA"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "SELF_CA")
    assert a.issued_certificates == ()
    voorstel = what_to_do(a, FRESH, "SELF_CA").to_text()
    assert "uitgeeft opnieuw: SELF_CA" not in voorstel


def test_a_self_referencing_certificate_names_a_service_only_once():
    """Met een eigen binding erbij kwam dezelfde virtuele server twee keer
    als apart onderwerp naar boven: een keer via route 1 en een keer via
    route 2 - precies wat het commentaar bij route 2 zegt te voorkomen."""
    b = [{"certkeyname": "SELF_CA", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    certs = [{"certkey": "SELF_CA", "linkcertkeyname": "SELF_CA"}]
    a = what_breaks(ExportStub(b, certs=certs), FRESH, "SELF_CA")
    onderwerpen = [x.subject for x in a.findings]
    assert onderwerpen.count("LB_VS_A") == 1, f"dubbel onderwerp: {onderwerpen}"


def test_a_circular_issuing_relation_is_not_two_established_facts():
    """A zegt door B uitgegeven te zijn en B door A. Er is geen lus en geen
    crash (diepte 1), maar ook geen signaal dat dit onmogelijke brondata is."""
    certs = [
        {"certkey": "CA_A", "linkcertkeyname": "CA_B"},
        {"certkey": "CA_B", "linkcertkeyname": "CA_A"},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "CA_A")
    assert a.is_complete() is False
    assert any("CA_B" in g.reason and "CA_A" in g.reason for g in a.read_gaps)
    assert a.issued_certificates == (), "een tegenstrijdige relatie is geen omkoppeladvies"


def test_a_dangling_issuing_relation_is_reported_as_a_deviation():
    """`linkcertkeyname: "GHOST_CA"` terwijl GHOST_CA niet als certKey in de
    export staat gaf `is_complete: True` en een vastgestelde uitgifterelatie
    naar een uitgever die deze export helemaal niet kent."""
    certs = [{"certkey": "web01", "linkcertkeyname": "GHOST_CA"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "GHOST_CA")
    assert a.is_complete() is False
    assert any("GHOST_CA" in g.reason for g in a.read_gaps)


def test_an_issuer_that_is_in_the_export_gets_no_dangling_report():
    """Tegenproef: de normale stand mag geen afwijking melden."""
    certs = [
        {"certkey": "web01", "linkcertkeyname": "REAL_CA"},
        {"certkey": "REAL_CA"},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "REAL_CA")
    assert a.read_gaps == [], f"onverwachte leesgaten: {a.read_gaps}"
    assert a.issued_certificates == ("web01",)


def test_a_certificate_entry_that_is_not_an_object_is_a_read_gap_not_a_silent_skip():
    """Route 2 deed `c.get(...)` zonder vormcontrole. In productie
    onbereikbaar (export.objects valideert elk element), maar een stille
    overslag is in deze module de faalklasse zelf."""
    certs = ["niet-een-object", {"certkey": "web01", "linkcertkeyname": "cert_a"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "cert_a")
    assert a.is_complete() is False
    assert any("str" in g.reason for g in a.read_gaps)
    assert a.issued_certificates == ("web01",), "wat WEL leesbaar is blijft staan"


# ---------------------------------------------------------------------------
# De ketenuitspraak mag niet sterker zijn dan wat de export draagt.
#
# Wat de export VASTSTELT: linkcertkeyname wijst naar X. Dat de
# ketenvalidatie uitvalt is een TLS-redenering, geen meting - en voor het
# gemeten labgeval de zwakste variant: CERT-004 is certificatetype
# ROOT_CERT met subject == issuer. Voor een root ligt het faalmechanisme in
# de vertrouwensopslag van de client, niet in de keten die deze appliance
# aanbiedt. De uitspraak overlapte bovendien met de eigen grenstekst
# ("volledige ketenvalidatie tot een root blijft buiten bereik").
# ---------------------------------------------------------------------------


def test_the_chain_outcome_states_what_the_export_carries_and_no_more():
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    outcome = [x for x in a.findings if x.subject == "leaf_cert"][0].outcome
    assert "wordt uitgegeven door ca_uitgever" in outcome
    assert "ketenvalidatie" not in outcome, (
        "of validatie uitvalt hangt af van de client; de export draagt die uitspraak niet"
    )
    assert "verlopen certificaat" in outcome


def test_the_service_behind_the_chain_makes_the_same_weaker_claim():
    b = [{"certkeyname": "leaf_cert", "vservername": "LB_VS_A", "snicert": False, "ca": False}]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub(b, certs=certs), FRESH, "ca_uitgever")
    outcome = [x for x in a.findings if x.subject == "LB_VS_A"][0].outcome
    assert "ketenvalidatie" not in outcome
    assert "verlopen certificaat" in outcome


def test_the_issuing_evidence_carries_the_raw_role_fields():
    """De rol niet raden, maar de ruwe rolvelden wel meesturen: dan kan de
    lezer zelf zien of dit een zelfondertekende root is."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "ca_uitgever"},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "certificatetype" in evidence
    assert "subject" in evidence and "issuer" in evidence


def test_the_role_evidence_reproduces_no_distinguished_name():
    """De rolvelden subject/issuer dragen een volledige DN. Die staat niet in
    de naamverzameling van de openheidslaag en mag dus niet gereproduceerd
    worden - alleen het AFGELEIDE feit of ze gelijk zijn."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"},
        # De rolvelden van het BEVRAAGDE certificaat - dat is degene die
        # verloopt, en dus degene wiens rol de lezer nodig heeft om de
        # ketenuitspraak te wegen. Dit is precies het gemeten labgeval:
        # ROOT_CERT met subject == issuer.
        {
            "certkey": "ca_uitgever",
            "certificatetype": ["ROOT_CERT"],
            "subject": " C=NL,O=GEHEIM BV,CN=geheim.intern",
            "issuer": " C=NL,O=GEHEIM BV,CN=geheim.intern",
        },
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "GEHEIM" not in evidence, "een DN hoort niet gereproduceerd te worden"
    assert "subject en issuer zijn gelijk" in evidence
    assert "ROOT_CERT" in evidence


def test_the_role_evidence_reproduces_no_distinguished_name_when_they_differ():
    """Overlevende mutatie (2026-08-27): de test hierboven dekt
    alleen de tak `subject == issuer`. De VERSCHILLEN-tak muteren naar
    `f"subject={subject!r}, issuer={issuer!r}"` hield 551 tests groen - en dat
    is juist het realistische klantgeval: een intermediate, waarvan subject en
    issuer per definitie verschillen. Twee ONDERSCHEIDEN merktekens, zodat een
    versie die maar een van de twee velden reproduceert hier ook valt."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "tussen_ca"},
        {
            "certkey": "tussen_ca",
            "certificatetype": ["INTM_CERT"],
            "subject": " C=NL,O=ONDERWERPGEHEIM BV,CN=tussenca.intern",
            "issuer": " C=NL,O=UITGEVERGEHEIM BV,CN=root.intern",
        },
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "tussen_ca")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "ONDERWERPGEHEIM" not in evidence, "de subject-DN hoort niet gereproduceerd te worden"
    assert "UITGEVERGEHEIM" not in evidence, "de issuer-DN hoort niet gereproduceerd te worden"
    assert "CN=" not in evidence, "ook een DN-fragment is een DN"
    assert "subject en issuer verschillen" in evidence
    assert "INTM_CERT" in evidence


def test_the_role_evidence_reproduces_no_free_text_certificatetype():
    """`shape_of` is deze ronde juist ingevoerd om ruwe waarden uit antwoorden
    te weren, maar certificatetype werd nog integraal gereproduceerd terwijl
    subject en issuer wel afgeleid worden - asymmetrisch. Het is een
    NITRO-opsomming, maar een aangeleverde export bepaalt zelf wat er in dat
    veld staat, en de naamverzameling van de openheidslaag leest dit veld niet:
    vrije tekst reist dus ongemaskeerd het antwoord in.

    Positief toetsen in plaats van vertrouwen: alleen een waarde met de VORM
    van een opsommingsteken (hoofdletters, cijfers, liggende streepjes) wordt
    gereproduceerd."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "ca_uitgever", "certificatetype": ["CN=geheim.klant.intern, O=GEHEIM BV"]},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "geheim.klant.intern" not in evidence, "vrije tekst hoort niet gereproduceerd te worden"
    assert "GEHEIM" not in evidence
    # Zwijgen is geen optie: dat het veld er is en niet herkenbaar is, hoort
    # de lezer wel te zien.
    assert "certificatetype" in evidence


def test_a_real_nitro_certificatetype_is_still_reproduced_as_evidence():
    """Tegenproef, op de vorm die de ECHTE labexport draagt (een lijst met
    twee opsommingstekens). Zonder deze test zou een versie die het veld
    voortaan altijd wegmaskeert hierboven groen blijven - en dan verliest de
    lezer het bewijs waarop hij de rol zelf beoordeelt."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "ca_uitgever", "certificatetype": ["CLNT_CERT", "SRVR_CERT"]},
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "CLNT_CERT" in evidence
    assert "SRVR_CERT" in evidence


def test_the_role_evidence_says_so_when_subject_or_issuer_cannot_be_read():
    """De derde tak van dezelfde ladder, met zijn eigen woorden. Zonder deze
    test kan een versie die bij een onleesbaar veld stilletjes 'verschillen'
    zegt - een uitspraak over een vergelijking die niet gemaakt is - hier
    groen blijven."""
    certs = [
        {"certkey": "leaf_cert", "linkcertkeyname": "tussen_ca"},
        {
            "certkey": "tussen_ca",
            "certificatetype": ["INTM_CERT"],
            "subject": " C=NL,O=ONDERWERPGEHEIM BV,CN=tussenca.intern",
            "issuer": None,
        },
    ]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "tussen_ca")
    evidence = [x for x in a.findings if x.subject == "leaf_cert"][0].evidence
    assert "ONDERWERPGEHEIM" not in evidence
    assert "leesbaar" in evidence, f"onverwacht bewijs: {evidence}"
    assert "verschillen" not in evidence, "een niet-gemaakte vergelijking is geen verschil"
    assert "zijn gelijk" not in evidence


def test_the_boundary_text_and_the_outcome_do_not_contradict_each_other():
    """De grenstekst zei dat volledige ketenvalidatie tot een root buiten
    bereik blijft, terwijl de bevinding er wel een uitspraak over deed."""
    from nsmcp.impact import CHAIN_DIMENSION

    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    outcomes = " ".join(x.outcome for x in a.findings)
    assert "ketenvalidatie" in CHAIN_DIMENSION.reason, "de grens noemt ketenvalidatie nog steeds"
    assert "ketenvalidatie" not in outcomes, "en dan mag een bevinding die uitspraak niet doen"
    assert "vertrouwensopslag" in CHAIN_DIMENSION.reason, (
        "waar het faalmechanisme voor een root wel ligt, hoort in de grenstekst"
    )


# ---------------------------------------------------------------------------
# Certificaten aan SSL-DIENSTEN: de certificaatkant wordt gelezen.
#
# Gemeten op de gouden export (2026-08-27): `ns-server-certificate`
# kreeg een VASTGESTELDE slotzin ("geen gebonden virtuele servers en geen
# uitgegeven certificaten gevonden in deze export"), een volledig antwoord en
# een volledig actievoorstel - terwijl `bindings/sslcertkey_binding
# .by-parent.json` in diezelfde export voor dat certificaat ACHT
# `sslcertkey_service_binding`-vermeldingen draagt. Dat is het beheerpad: wie
# dat certificaat vervangt zonder die bindingen te kennen, legt de
# management-HTTPS plat.
#
# Dat bestand wordt nu gelezen, in de aggregate-vorm, per kindsoort: elke
# dienst wordt een bevinding, een beheerdienst als beheerverkeer van de
# appliance zelf, en de slotzin vervalt. Alleen als het bestand NIET te lezen
# is, blijft de eerlijke grens staan: de niet-gelezen bindingssoorten met naam
# en toenaam, inclusief het bestand dat ze draagt.
# ---------------------------------------------------------------------------


def _repaired_golden_export(tmp_path: Path) -> Path:
    """De GEREPAREERDE gouden export die gemeten werd: dezelfde export,
    maar met de ontbrekende parent-vermelding (VSRV-001) aangevuld, zodat de
    parentlijst compleet is en het antwoord dus VOLLEDIG uitkomt. Precies daar
    viel het gemeten geval op: een vastgestelde slotzin en een compleet
    antwoord, terwijl acht dienstbindingen ongelezen waren."""
    doel = tmp_path / "gerepareerd"
    shutil.copytree(FIXTURE, doel)
    pad = doel / "bindings" / BINDING_FILE
    doc = json.loads(pad.read_text(encoding="utf-8"))
    doc["parents"].append(
        {
            "parentName": "VSRV-001",
            "outcome": "OK",
            "data": {"sslvserver_sslcertkey_binding": []},
        }
    )
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = doel / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"][f"bindings/{BINDING_FILE}"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    return doel


_NS_SERVER_SERVICES = (
    "nsrpcs-127.0.0.1-3008",
    "nshttps-127.0.0.1-443",
    "nshttps-certauth-127.0.0.1-8443",
    "nsrpcs-::1l-3008",
    "nshttps-::1l-443",
    "nshttps-certauth-::1l-8443",
    "nskrpcs-127.0.0.1-3009",
    "nsrnatsip-127.0.0.1-5061",
)


def test_the_service_bindings_of_a_certificate_are_read_and_named(tmp_path):
    export = load_export(_repaired_golden_export(tmp_path))
    # Premisse, uit de export zelf: die acht dienstbindingen bestaan echt.
    ruw = json.loads((FIXTURE / "bindings" / "sslcertkey_binding.by-parent.json").read_text(encoding="utf-8"))
    parent = [p for p in ruw["parents"] if p["parentName"] == "ns-server-certificate"][0]
    diensten = parent["data"]["sslcertkey_binding"]["sslcertkey_service_binding"]
    assert tuple(d["servicename"] for d in diensten) == _NS_SERVER_SERVICES, "zonder die bindingen bewijst dit niets"

    a = what_breaks(export, FRESH, "ns-server-certificate")
    tekst = a.to_text()

    assert a.is_complete() is True, a.read_gaps
    assert a.affected_services == _NS_SERVER_SERVICES
    # A management service (the built-in denylist, handelen.DENIED_PREFIXES)
    # is named for what it is.
    assert (
        "- nshttps-127.0.0.1-443: beheerverkeer van de appliance zelf; TLS op deze beheerdienst valt uit"
        " [vastgesteld]\n"
        "    bewijs: sslcertkey_binding.by-parent.json: sslcertkey_service_binding,"
        " servicename=nshttps-127.0.0.1-443"
    ) in tekst
    # Any other service is a service.
    assert (
        "- nskrpcs-127.0.0.1-3009: raakt deze SSL-dienst (service); TLS valt uit voor deze dienst [vastgesteld]"
    ) in tekst
    # The measured false statement is gone, and so is the boundary: the file
    # it named is read.
    assert "geen gebonden virtuele servers" not in tekst
    # The three boundaries after the chain are the sources of the use outside
    # the bindings, which this export (taken before a collector fetched them)
    # does not carry: niet vastgesteld, never "no use".
    assert [n.subject for n in a.not_assessed] == [
        "volledige certificaatketen buiten deze export",
        "certificaatgebruik door SAML-acties",
        "certificaatgebruik door SAML-IdP-profielen",
        "certificaatgebruik door SSL-servicegroups",
    ]


def test_nothing_on_the_certificate_side_is_part_of_the_closing_statement(tmp_path):
    export = load_export(_repaired_golden_export(tmp_path))
    a = what_breaks(export, FRESH, "ns-sftrust-certificate")
    tekst = a.to_text()
    assert a.is_complete() is True, a.read_gaps
    assert (
        "- ns-sftrust-certificate: geen gebonden virtuele servers, geen gebonden SSL-diensten en geen"
        " uitgegeven certificaten gevonden in deze export [vastgesteld]"
    ) in tekst
    assert ("; sslcertkey_binding.by-parent.json: gelezen en gecontroleerd, geen service-binding op deze naam") in tekst
    assert a.affected_services == ()


def test_a_known_certificate_absent_from_the_certificate_side_file_is_a_read_gap(tmp_path):
    doel = _repaired_golden_export(tmp_path)
    pad = doel / "bindings" / "sslcertkey_binding.by-parent.json"
    doc = json.loads(pad.read_text(encoding="utf-8"))
    doc["parents"] = [p for p in doc["parents"] if p["parentName"] != "ns-sftrust-certificate"]
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = doel / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"]["bindings/sslcertkey_binding.by-parent.json"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")

    a = what_breaks(load_export(doel), FRESH, "ns-sftrust-certificate")
    assert [(g.source, g.reason) for g in a.read_gaps] == [
        (
            "sslcertkey_binding.by-parent.json",
            "sslcertkey_binding.by-parent.json draagt geen parent-vermelding voor ns-sftrust-certificate;"
            " de bindingen van dit certificaat buiten virtuele servers zijn niet gelezen",
        )
    ]
    assert "geen gebonden virtuele servers" not in a.to_text()


def test_an_unread_kind_on_the_certificate_side_is_a_read_gap_not_a_silence(tmp_path):
    a = what_breaks(load_export(_golden_export_with_an_unread_kind(tmp_path)), FRESH, "ns-sftrust-certificate")
    assert (
        "sslcertkey_binding.by-parent.json",
        "sslcertkey_binding.by-parent.json draagt voor ns-sftrust-certificate een bindingssoort die deze"
        " versie niet leest (sslcertkey_crldistribution_binding); of dit certificaat daar ook uitvalt,"
        " is niet vast te stellen",
    ) in [(g.source, g.reason) for g in a.read_gaps]
    assert "geen gebonden virtuele servers" not in a.to_text()


def test_a_service_binding_without_a_readable_servicename_is_a_read_gap():
    a = what_breaks(
        ExportStub(
            [],
            certs=[{"certkey": "cert_a"}],
            cert_side={"cert_a": [("sslcertkey_service_binding", {"certkey": "cert_a", "servicename": ["x"]})]},
        ),
        FRESH,
        "cert_a",
    )
    assert any("servicename" in g.reason and "cert_a" in g.reason for g in a.read_gaps), a.read_gaps
    assert a.affected_services == ()
    assert "['x']" not in a.to_text()


def test_the_boundary_is_reported_whenever_the_certificate_side_is_unread():
    """The stub carries no certificate-side file, the way an export without
    its hash reads. Then the boundary stays - with the kinds that stay unread
    and the file that carries them - and it is not a read gap."""
    a = what_breaks(
        ExportStub([], gap=ReadGap(source=BINDING_FILE, reason="hash wijkt af")),
        FRESH,
        "cert_a",
    )
    grens = " ".join(n.reason for n in a.not_assessed).lower()
    assert "ssl-diensten" in grens
    assert "servicegroep" in grens
    assert "monitors" in grens
    zonder_gelezen_bestand = grens.replace(BINDING_FILE.lower(), "")
    assert "sslcertkey_binding.by-parent.json is niet gelezen" in zonder_gelezen_bestand
    assert "geen hash in het manifest" in grens


# ---------------------------------------------------------------------------
# A half CERTIFICATE name gets CANDIDATES, never a choice.
#
# Measured in the second practice round: `dienst_status` had learned to
# name candidates and the model
# recovered from a half service name in the same turn - but the certificate
# side had no such mechanism, so "het zaakportaal-certificaat" produced an
# answer about a name that does not exist, without a way forward. Same shape,
# same wording and the same discipline as `dienst.service_status`: this names
# what it read and resolves nothing.
# ---------------------------------------------------------------------------


def _certkey(name):
    return {"certkey": name}


def test_an_unknown_certificate_name_names_the_candidates_that_contain_it():
    certs = [
        _certkey("gjk-zaakportaal-2026"),
        _certkey("gjk-zaakportaal-2027"),
        _certkey("gjk-statuspagina-2026"),
    ]
    text = what_breaks(ExportStub([], certs=certs), FRESH, "zaakportaal").to_text()
    assert (
        "kandidaten (naam bevat 'zaakportaal', hoofdletterongevoelig): "
        "gjk-zaakportaal-2026, gjk-zaakportaal-2027 [vastgesteld]"
    ) in text
    assert "gjk-statuspagina-2026" not in text


def test_the_certificate_candidate_search_is_case_insensitive():
    certs = [_certkey("GJK-Zaakportaal-2027")]
    text = what_breaks(ExportStub([], certs=certs), FRESH, "ZAAKportaal").to_text()
    assert ("kandidaten (naam bevat 'ZAAKportaal', hoofdletterongevoelig): GJK-Zaakportaal-2027") in text


def test_at_most_five_certificate_candidates_are_named_and_they_are_sorted():
    certs = [_certkey(f"gjk-web{n}-2026") for n in range(9, 0, -1)]
    text = what_breaks(ExportStub([], certs=certs), FRESH, "web").to_text()
    regel = [r for r in text.splitlines() if r.startswith("- kandidaten")][0]
    assert regel == (
        "- kandidaten (naam bevat 'web', hoofdletterongevoelig): gjk-web1-2026, "
        "gjk-web2-2026, gjk-web3-2026, gjk-web4-2026, gjk-web5-2026 [vastgesteld]"
    )


def test_without_a_single_certificate_candidate_the_answer_says_so():
    certs = [_certkey("gjk-statuspagina-2026")]
    text = what_breaks(ExportStub([], certs=certs), FRESH, "zaakportaal").to_text()
    assert ("kandidaten (naam bevat 'zaakportaal', hoofdletterongevoelig): geen kandidaten") in text


def test_a_known_certificate_gets_no_candidate_line():
    """Counter-probe: candidates belong to a name that was NOT found. A
    resolved question must not be padded with near misses."""
    certs = [_certkey("gjk-zaakportaal-2027")]
    text = what_breaks(ExportStub([], certs=certs), FRESH, "gjk-zaakportaal-2027").to_text()
    assert "kandidaten" not in text


def test_a_read_gap_on_the_certificate_source_names_no_candidates():
    """ESTABLISHED only after a successful read. With config/sslcertkey
    unreadable, whether this certificate exists is simply not established -
    and a list of near misses out of a source that was not read would be a
    claim about something nobody read."""
    a = what_breaks(
        ExportStub([], certs=[], cert_gap=ReadGap(source="config/sslcertkey", reason="hash wijkt af")),
        FRESH,
        "zaakportaal",
    )
    assert "kandidaten" not in a.to_text()


def test_the_real_fixture_names_the_certificates_that_carry_the_term():
    """On the REAL collector export, not a stub: the four certkeys it carries
    are ns-sftrust-certificate, ns-server-certificate, CERT-004 and
    CERT-009 (measured 2026-09-03).

    Ruling na de pseudonimisering van de fixture (addendum 5 van het
    script): zoekterm 'wildcard' bestond alleen in de originele,
    niet-gepseudonimiseerde certificaatnaam en is met de fixture mee vervangen: de
    zoekterm is verlegd naar een deel van de aliasnaam zelf (`rt-009`, in kleine
    letters om de hoofdletterongevoelige match te blijven bewijzen). Het oordeel -
    de motor vindt een kandidaat op een gedeeltelijke naam - blijft ongewijzigd."""
    text = what_breaks(load_export(FIXTURE), FRESH, "rt-009").to_text()
    assert ("kandidaten (naam bevat 'rt-009', hoofdletterongevoelig): CERT-009 [vastgesteld]") in text


def test_what_to_do_carries_the_same_candidate_line():
    """The advice tool takes the same half name, so it needs the same way
    forward. `what_to_do` builds its own answer and carries no findings over,
    so the candidates travel as an EXPLICIT collection on the impact answer -
    the same discipline as affected_vservers and issued_certificates."""
    certs = [_certkey("gjk-zaakportaal-2026"), _certkey("gjk-zaakportaal-2027")]
    impact = what_breaks(ExportStub([], certs=certs), FRESH, "zaakportaal")
    text = what_to_do(impact, FRESH, "zaakportaal").to_text()
    assert (
        "kandidaten (naam bevat 'zaakportaal', hoofdletterongevoelig): gjk-zaakportaal-2026, gjk-zaakportaal-2027"
    ) in text


def test_what_to_do_on_a_known_certificate_gets_no_candidate_line():
    certs = [_certkey("gjk-zaakportaal-2027")]
    impact = what_breaks(ExportStub([], certs=certs), FRESH, "gjk-zaakportaal-2027")
    assert "kandidaten" not in what_to_do(impact, FRESH, "gjk-zaakportaal-2027").to_text()


# ---------------------------------------------------------------------------
# The usage state travels on ImpactAnswer as an explicit
# field, never as a Finding.
#
# An earlier version appended a `Finding(subject="gebruiksstand",
# ...)` to `what_breaks()`'s findings list. Measured consequence ("BLOCKED"):
# action.py's `uncertain = [b for b in
# impact_answer.findings if b.certainty is Certainty.NOT_ESTABLISHED]` turned
# every certificate whose usage state is "onbekend" into a synthetic ReadGap
# and PERMANENTLY BLOCKED `certificaat_wat_moet_ik_doen`'s change proposal for
# it - even when the real impact (bindings, chain) was fully established -
# and disclosure.py's minimal-level finding count/verdict shifted by exactly
# one. Both are read-only consumers of `findings`/`read_gaps` by SHAPE, not by
# subject identity - see action.py::_candidates for the SAME discipline
# already applied to `name_candidates`/`affected_vservers`/
# `issued_certificates`. The usage state follows that established pattern
# instead: an explicit field, read nowhere by action.py or disclosure.py.
# ---------------------------------------------------------------------------


def test_the_usage_state_travels_as_an_explicit_field_not_a_finding():
    """On the real fixture (a measured table): CERT-009 is
    gebonden, CERT-004 is uitgever, ns-server-certificate is gebonden (read
    through the aggregate sslcertkey_binding.by-parent.json: eight service
    bindings). None of the three may add a "gebruiksstand" finding - that is
    exactly the mechanism that blocked action.py."""
    export = load_export(FIXTURE)
    for name, state in (
        ("CERT-009", "gebonden"),
        ("CERT-004", "uitgever"),
        ("ns-server-certificate", "gebonden"),
    ):
        answer = what_breaks(export, FRESH, name)
        assert answer.usage is not None, name
        assert answer.usage.state == state, name
        assert all(b.subject != "gebruiksstand" for b in answer.findings), (
            f"{name}: gebruiksstand mag geen finding zijn - dat blokkeert action.py"
        )


def test_an_onbekend_usage_state_no_longer_blocks_the_change_proposal(tmp_path):
    """The exact regression the WRONG Step 4 caused, reproduced and repaired:
    a certificate with zero bindings (so the impact itself is fully
    established: "(geen gebonden virtuele servers)") whose usage state is
    "onbekend" (the sslcertkey_binding.by-parent.json source is simply never
    written here, the same shape this product measures on the real export)
    must still get a real change proposal - not "geen wijzigingsvoorstel
    zolang de impact niet vaststaat".
    """
    m = tmp_path / "export"
    (m / "objects").mkdir(parents=True)
    (m / "bindings").mkdir()
    (m / "objects" / "sslcertkey.json").write_text(
        json.dumps({"sslcertkey": [{"certkey": "cert_a", "daystoexpiration": 100}]}),
        encoding="utf-8",
    )
    (m / "objects" / "sslvserver.json").write_text(json.dumps({"sslvserver": []}), encoding="utf-8")
    raw = json.dumps(
        {
            "bindingResource": "sslvserver_sslcertkey_binding",
            "parentResource": "sslvserver",
            "parentKey": "vservername",
            "shape": "list",
            "parents": [],
        }
    )
    (m / "bindings" / "sslvserver_sslcertkey_binding.by-parent.json").write_text(raw, encoding="utf-8")
    (m / "export-manifest.json").write_text(
        json.dumps(
            {
                "manifestVersion": "1.1",
                "collectedAtUtc": "2026-08-26T10:00:00.0000000Z",
                "resources": {"config/sslcertkey": {"status": "OK"}, "config/sslvserver": {"status": "OK"}},
                "files": {
                    "bindings/sslvserver_sslcertkey_binding.by-parent.json": hashlib.sha256(
                        raw.encode("utf-8")
                    ).hexdigest()
                },
            }
        ),
        encoding="utf-8",
    )
    seal_manifest(m)  # an object file without its hash is a read gap
    export = load_export(m)
    impact = what_breaks(export, FRESH, "cert_a")
    assert impact.is_complete() is True, impact.read_gaps
    assert impact.usage is not None and impact.usage.state == "onbekend"

    proposal = what_to_do(impact, FRESH, "cert_a")
    text = proposal.to_text()
    assert "geen wijzigingsvoorstel zolang de impact niet vaststaat" not in text.lower()
    assert "(geen gebonden virtuele servers)" in text


def test_the_usage_line_carries_the_established_tag():
    export = load_export(FIXTURE)
    text = what_breaks(export, FRESH, "CERT-009").to_text()
    assert "- gebruiksstand: gebonden [vastgesteld]" in text


def test_the_issuing_usage_line_also_carries_the_established_tag():
    export = load_export(FIXTURE)
    text = what_breaks(export, FRESH, "CERT-004").to_text()
    assert "- gebruiksstand: uitgever [vastgesteld]" in text


def _golden_export_with_an_unread_kind(tmp_path: Path) -> Path:
    """The golden export, with one binding kind this version does not read
    added to the certificate-side document of ns-sftrust-certificate - the
    route to an "onbekend" usage state now that the aggregate file itself is
    read."""
    doel = tmp_path / "onbekende-soort"
    shutil.copytree(FIXTURE, doel)
    pad = doel / "bindings" / "sslcertkey_binding.by-parent.json"
    doc = json.loads(pad.read_text(encoding="utf-8"))
    for parent in doc["parents"]:
        if parent["parentName"] == "ns-sftrust-certificate":
            parent["data"]["sslcertkey_binding"]["sslcertkey_crldistribution_binding"] = [
                {"certkey": "ns-sftrust-certificate"}
            ]
    inhoud = json.dumps(doc)
    pad.write_text(inhoud, encoding="utf-8")
    manifest_pad = doel / "export-manifest.json"
    manifest = json.loads(manifest_pad.read_text(encoding="utf-8"))
    manifest["files"]["bindings/sslcertkey_binding.by-parent.json"] = hashlib.sha256(inhoud.encode("utf-8")).hexdigest()
    manifest_pad.write_text(json.dumps(manifest), encoding="utf-8")
    return doel


def test_the_onbekend_usage_line_carries_no_established_tag_and_names_the_source(tmp_path):
    """Honesty rules on this one line: no [vastgesteld]
    tag on an onbekend state, and the reason names the binding source that
    left it open - never a raw value from the export."""
    export = load_export(_golden_export_with_an_unread_kind(tmp_path))
    text = what_breaks(export, FRESH, "ns-sftrust-certificate").to_text()
    line = [regel for regel in text.splitlines() if regel.startswith("- gebruiksstand:")][0]
    assert "[vastgesteld]" not in line, line
    assert "onbekend" in line
    assert "sslcertkey_binding.by-parent.json" in line, line


def test_the_usage_line_never_names_who_it_is_bound_to():
    """The line names only the STATE, never who the certificate is bound
    to or issues - those are real vserver/certificate names, and
    `disclosure._limit()` does not know about this field
    (action.py/disclosure.py stay untouched), so any name in this line
    would reach 'beperkt' unmasked.

    The leak is closed structurally,
    not just in the renderer - `ImpactAnswer.usage.used_by` is stripped to
    `()` at the source (`what_breaks`), so it cannot leak even through a
    future reader of `.usage` that bypasses `to_text()`."""
    from nsmcp.expiry import usage_per_certificate

    export = load_export(FIXTURE)
    raw = {u.certkey: u for u in usage_per_certificate(export)}
    assert raw["CERT-009"].used_by == ("VSRV-002", "VSRV-003"), "premise: sanity on the source data"
    answer = what_breaks(export, FRESH, "CERT-009")
    assert answer.usage.used_by == (), "ImpactAnswer.usage carries no used_by at all"
    text = answer.to_text()
    assert "VSRV-002" not in text.split("- gebruiksstand:")[1]
    assert "VSRV-003" not in text.split("- gebruiksstand:")[1]


def test_no_certificate_read_at_all_leaves_usage_none_not_fabricated():
    """A failed primary read must not make up a usage state either - `None`
    means "nothing to say here", the same three-state discipline as
    `name_candidates`."""
    a = what_breaks(
        ExportStub([], cert_gap=ReadGap(source="config/sslcertkey", reason="hash wijkt af")),
        FRESH,
        "cert_a",
    )
    assert a.usage is None
    assert "gebruiksstand" not in a.to_text()


def test_an_unknown_certname_gets_no_usage_line():
    """Counter-probe: a name that is not a real certkey in this export gets
    no usage statement - there is nothing established to show."""
    certs = [_certkey("gjk-zaakportaal-2027")]
    a = what_breaks(ExportStub([], certs=certs), FRESH, "een-naam-die-hier-niet-bestaat")
    assert a.usage is None
    assert "gebruiksstand" not in a.to_text()


def test_the_usage_line_lands_directly_before_the_stamps():
    """Pins the exact line order the
    `Answer._extra_lines()` hook promises - the blank separator plus the
    gebruiksstand line, then the unconditional blank-plus-Kennisbasis-plus-
    Gegevens tail. No test asserted this before (`in text`/split-on-marker
    only), so a future line added to that tail could silently move the
    gebruiksstand line without any test noticing."""
    export = load_export(FIXTURE)
    answer = what_breaks(export, FRESH, "CERT-009")
    lines = answer.to_text().splitlines()
    assert lines[-5] == ""
    assert lines[-4] == "- gebruiksstand: gebonden [vastgesteld]"
    assert lines[-3] == ""
    assert lines[-2].startswith("Kennisbasis")
    assert lines[-1].startswith("Gegevens")


def test_minimal_disclosure_is_unaffected_by_the_usage_field():
    """Regression guard: `disclosure._minimal()` borrows its stamp lines
    (Kennisbasis/Gegevens) from `Answer.to_text()` applied to a SYNTHETIC
    copy with findings/read_gaps/not_assessed all cleared
    (`empty.to_text().splitlines()[2:]`, a fixed 3-line slice). A
    `to_text()` override that inserts a line whenever `self.usage is not
    None` - without ALSO checking that this is a real answer and not that
    synthetic copy - corrupts the fixed slice for every certificate with a
    resolvable usage state, i.e. almost every real query. This is exactly
    the class of disclosure.py breakage this design rules out fixing
    by editing disclosure.py, so the override itself must not cause it."""
    from nsmcp.disclosure import Disclosure, render

    export = load_export(FIXTURE)
    answer = what_breaks(export, FRESH, "CERT-009")
    assert answer.usage is not None, "premise: this certificate has a resolvable usage state"
    text = render(answer, Disclosure.MINIMAL, tool="certificaat_wat_breekt_er")
    assert "gebruiksstand" not in text.lower(), (
        "'minimaal' does not render findings prose at all; showing this line there needs"
        " disclosure.py's own help, which ADJUDICATION A8-1 rules out - see the report"
    )
    assert text.count("Kennisbasis") == 1
    assert text.count("Gegevens") == 1
    assert text.rstrip().splitlines()[-1].startswith("Gegevens"), text


def test_limited_disclosure_shows_the_state_without_leaking_the_binding_name(tmp_path):
    """The state word survives 'beperkt' (it is this product's own closed
    vocabulary, not an export value), the bound-to name does not (real
    object name, unmasked by `_limit()` since that function does not know
    this field - see the report's concern on this)."""
    from nsmcp.disclosure import Disclosure, names_from_export, render

    export = load_export(FIXTURE)
    names = names_from_export(export) + ("CERT-009",)
    answer = what_breaks(export, FRESH, "CERT-009")
    text = render(
        answer,
        Disclosure.LIMITED,
        tool="certificaat_wat_breekt_er",
        extra_names=names,
        pseudonym_table_path=tmp_path / "tabel.json",
    )
    assert "gebruiksstand: gebonden" in text
    assert "VSRV-002" not in text
    assert "VSRV-003" not in text
