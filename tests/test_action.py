"""Tests for the action proposal.

This file used to build every impact answer by hand, so `what_to_do` never
saw REAL `what_breaks` output, and the test on the empty-case branch
exercised DEAD code - exactly how an action proposal that invented its own
evidence slipped through the whole suite. Everything that can be made from
real impact output now comes from it: `_real_impact()` calls `what_breaks()`
on an export stub. Only where a shape is deliberately tested that
`impact.py` itself never produces - an empty `subject`, or an answer missing
the explicit collection of affected vservers - does a hand-built answer
remain, with the reason stated in the test itself.
"""

from nsmcp.action import what_to_do
from nsmcp.advice import ADVICE_CAN, ADVICE_MANUAL, ADVICE_NOT_ALLOWED, ADVICE_WORDS
from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.export import ParentCoverage
from nsmcp.handelen import Allowlist
from nsmcp.impact import ImpactAnswer, what_breaks
from nsmcp.knowledge import Knowledge

FRESH = Knowledge(version="2026.08", date="2026-08-16", age_days=3, missing=False)


class ExportStub:
    """Stub for the export layer.

    `objects` was added when what_breaks() started reading the issuing
    relation from config/sslcertkey. The default is an EMPTY, successfully
    read list - not a read gap: "read fine, nothing in it" is the neutral
    starting point that leaves every pre-existing binding test measuring
    exactly what it measured before.

    `binding_parents` was added one round later, when what_breaks() started
    cross-checking the parent list of the binding file against the object
    source of those parents. Same neutral default: a fully covered parent
    list without gaps.

    `binding_rows`/`binding_child_keys` read the certificate-side file.
    Neutral default: an export that does not carry it. `cert_side` gives it
    content: `{certkey: [(kind, row), ...]}`.
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


def _services_on(certkey, *services):
    return {certkey: [("sslcertkey_service_binding", {"certkey": certkey, "servicename": s}) for s in services]}


def _real_impact(bindings, gap=None, certnaam="cert_a"):
    """REAL `what_breaks` output - not a hand-built Answer.

    This is the core of the repair on this file: `what_to_do()` must be
    tested on what `impact.py` actually returns, not on what a test thinks
    it returns.
    """
    return what_breaks(ExportStub(list(bindings), gap), FRESH, certnaam)


def _binding(vserver="LB_VS_A", certkeyname="cert_a", **rest):
    b = {"certkeyname": certkeyname, "vservername": vserver, "snicert": False, "ca": False}
    b.update(rest)
    return b


def _binding_without_ca(vserver="GW_X"):
    """Yields a NOT_ESTABLISHED finding from `impact.py`: the ca flag is
    missing, so server certificate and client authentication cannot be
    distinguished."""
    return {"certkeyname": "cert_a", "vservername": vserver, "snicert": False}


def test_action_names_change_rollback_and_readback_check():
    a = what_to_do(_real_impact([_binding()]), FRESH, "cert_a")
    text = a.to_text().lower()
    assert "vervang" in text
    assert "terugrol" in text
    assert "terugleescontrole" in text


def test_no_action_while_the_impact_is_not_established():
    a = what_to_do(
        _real_impact([], gap=ReadGap(source="binding", reason="hash wijkt af")),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert "vervang" not in a.to_text().lower()


def test_action_names_every_affected_vserver():
    a = what_to_do(_real_impact([_binding("LB_VS_A"), _binding("CS_VS_B")]), FRESH, "cert_a")
    text = a.to_text()
    assert "LB_VS_A" in text and "CS_VS_B" in text


def test_not_established_role_blocks_the_action_for_that_vserver():
    """Sharper than only the outer guard (`is_complete() is False`, also
    guarded through a mutated probe): the derived read gaps carry their own
    vserver name and reason, not a generic text. Proven with a mutation that
    hardcoded source/reason to "x"/"y" - all four original tests stayed
    green under it, so the content was unguarded until then; only the fact
    that SOMETHING was added was covered.
    """
    a = what_to_do(_real_impact([_binding_without_ca("GW_X")]), FRESH, "cert_a")
    assert a.is_complete() is False
    text = a.to_text()
    assert "GW_X" in text
    assert "ca-vlag ontbreekt" in text


def test_multiple_uncertain_findings_are_all_named_as_read_gaps():
    """Symmetric with `test_action_names_every_affected_vserver`: that one
    guards that the success-path loop covers ALL affected vservers, this one
    guards the same for the blocking loop over ALL uncertain findings (if a
    mutation processed only the first item, the second name would be missing
    here). Both uncertain findings come from REAL impact output: two
    bindings without a ca flag.
    """
    a = what_to_do(
        _real_impact([_binding_without_ca("GW_X"), _binding_without_ca("LB_VS_Y")]),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    text = a.to_text()
    assert "GW_X" in text and "LB_VS_Y" in text
    assert text.lower().count("ca-vlag ontbreekt") >= 2


def test_no_affected_vservers_states_that_explicitly_in_the_steps():
    """First half of the fabricated-evidence repair. This test existed
    before, but fed a HAND-BUILT empty answer and thereby exercised dead
    code: on real impact output the findings list is NOT empty in the empty
    case - it then carries a finding with `subject=certnaam`. `action.py`
    used to derive the affected vservers from that list and literally
    produced "2. Koppel het om op: cert_a" - the certificate, not a virtual
    server - which made the fallback text unreachable. Now the answer comes
    from real impact output, and the fallback text must be present.
    """
    a = what_to_do(_real_impact([]), FRESH, "cert_a")
    assert a.is_complete() is True
    text = a.to_text()
    assert "geen gebonden virtuele servers" in text.lower()
    assert "koppel het om op: cert_a" not in text.lower(), "het certificaat is geen virtuele server"


def test_evidence_line_counts_zero_when_nothing_is_affected():
    """Second half: the evidence line. It literally said "afgeleid uit
    1 vastgestelde binding(en)" while `impact.py` had established ZERO - a
    fabricated count, in exactly the field this product sells its integrity
    on. The count now comes from the explicit collection of affected
    vservers instead of from `len(findings)`.
    """
    a = what_to_do(_real_impact([]), FRESH, "cert_a")
    evidence = a.findings[0].evidence
    assert "0" in evidence
    assert "1" not in evidence


def test_evidence_line_counts_the_real_affected_vservers():
    """Counter-probe to the test above: with two really affected vservers,
    a real 2 must appear in the evidence line. Without this test a mutation
    that hardcodes the count to 0 would simply stay green.
    """
    a = what_to_do(_real_impact([_binding("LB_VS_A"), _binding("CS_VS_B")]), FRESH, "cert_a")
    assert "2" in a.findings[0].evidence


def test_two_bindings_on_the_same_vserver_count_as_one_affected_vserver():
    """A vserver can carry two certificate bindings (for example a regular
    and an SNI binding). That is one vserver to rebind, not two: the rebind
    step names it once and the evidence line counts 1. Without deduplication
    it would say "koppel het om op: LB_VS_A, LB_VS_A", with a count that
    does not match the enumeration below it.
    """
    a = what_to_do(
        _real_impact([_binding("LB_VS_A"), _binding("LB_VS_A", snicert=True)]),
        FRESH,
        "cert_a",
    )
    text = a.to_text()
    assert "1" in a.findings[0].evidence
    assert text.count("LB_VS_A") == 1


def test_empty_subject_falls_back_locally_to_a_readable_designation():
    """`Finding.subject` has no emptiness check (`answer.py` is not up for
    change here) and `ReadGap.source` refuses empty with a `ValueError`.
    Without a local fallback in `action.py`, `what_to_do()` crashes hard on
    an empty subject, exactly where it should have reported a fail-closed
    read gap. That this is unreachable today because `impact.py` always
    falls back to "(naamloos)" is an assumption about another module, not a
    guarantee - which is why a hand-built answer deliberately remains here,
    as an `ImpactAnswer` so it reaches the same chain as real impact output.
    Proven with a mutation that reverted the fallback to the bare
    `b.subject`: the test then turned red, not with an assertion error but
    with `ValueError: a read gap without a source is meaningless` as the
    cause.
    """
    uncertain = Finding(
        subject="",
        outcome="rol niet vast te stellen",
        certainty=Certainty.NOT_ESTABLISHED,
        evidence="binding gelezen",
        reason="ca-vlag ontbreekt",
    )
    a = what_to_do(
        ImpactAnswer(question="wat breekt er", findings=[uncertain], affected_vservers=()),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert a.read_gaps[0].source == "(naamloos)"
    text = a.to_text()
    assert "(naamloos)" in text
    assert "ca-vlag ontbreekt" in text


def test_mixed_findings_block_on_the_uncertain_vserver_not_on_the_established_one():
    """Behavior claimed by the commit message of `9465981` but combined by
    no test until then: a single uncertain virtual server blocks the whole
    proposal, even though another vserver in the same impact answer IS
    established. A mutation dropping the `uncertain` filter (certainty is
    NOT_ESTABLISHED) would go unnoticed by every other test.
    """
    a = what_to_do(
        _real_impact([_binding("LB_VS_A"), _binding_without_ca("GW_X")]),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert "vervang" not in a.to_text().lower()
    assert any(g.source == "GW_X" for g in a.read_gaps)
    assert not any(g.source == "LB_VS_A" for g in a.read_gaps)


def test_answer_without_explicit_affected_vservers_gives_no_advice():
    """Fail-closed on the new coupling itself. The fabricated-evidence bug
    arose because `action.py` DERIVED the affected vservers from the
    findings list. If `what_to_do()` now receives an answer that does not
    carry the explicit collection - a bare `Answer`, or a future caller that
    forgets it - it must not fall back to deriving again. Then it does not
    know, and that is what it must say.
    """
    bare = Answer(
        question="wat breekt er",
        findings=[
            Finding(
                subject="LB_VS_A",
                outcome="servercertificaat; TLS valt uit voor deze dienst",
                certainty=Certainty.ESTABLISHED,
                evidence="binding gelezen",
            )
        ],
    )
    a = what_to_do(bare, FRESH, "cert_a")
    assert a.is_complete() is False
    assert "vervang" not in a.to_text().lower()
    assert any("geraakte virtuele servers" in g.reason for g in a.read_gaps)


def test_action_proposal_carries_the_not_assessed_dimensions_of_the_impact():
    """The proposal is derived from the impact picture, so the boundary of
    that picture travels along - like the read gaps. If the chain dimension
    only sat in the impact answer, an operator who only asks
    `certificaat_wat_moet_ik_doen` would never see it, and that operator is exactly the
    one executing the steps.
    """
    a = what_to_do(_real_impact([_binding()]), FRESH, "cert_a")
    text = a.to_text()
    assert "NIET BEOORDEELD" in text
    assert "keten" in text.lower()


def test_blocked_proposal_also_carries_the_not_assessed_dimensions():
    """Separate branch: what_to_do has two returns (blocked and with
    steps). A mutation that puts the pass-through in only one of the two
    would slip past the test above.
    """
    a = what_to_do(
        _real_impact([], gap=ReadGap(source="binding", reason="hash wijkt af")),
        FRESH,
        "cert_a",
    )
    assert a.is_complete() is False
    assert "NIET BEOORDEELD" in a.to_text()


# ---------------------------------------------------------------------------
# Het actieantwoord voor een UITGEVEND certificaat.
#
# Gemeten op een echt lab: voor een CA die het servercertificaat van twee
# diensten uitgeeft, stelde de motor voor "Koppel het om op: (geen gebonden
# virtuele servers)" met "afgeleid uit 0 vastgesteld geraakte virtuele
# server(s)". Formeel juist, praktisch misleidend: er is wel degelijk werk,
# alleen niet op een virtuele server maar op het uitgegeven certificaat.
# ---------------------------------------------------------------------------


def _issuing_impact(certnaam="ca_uitgever"):
    """ECHTE what_breaks-uitvoer voor een uitgevend certificaat: geen
    rechtstreekse bindingen, een uitgegeven certificaat, twee diensten
    daarachter."""
    bindings = [
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_EEN", "snicert": False, "ca": False},
        {"certkeyname": "leaf_cert", "vservername": "LB_VS_TWEE", "snicert": False, "ca": False},
    ]
    certs = [{"certkey": "leaf_cert", "linkcertkeyname": "ca_uitgever"}, {"certkey": "ca_uitgever"}]
    return what_breaks(ExportStub(bindings, certs=certs), FRESH, certnaam)


def test_the_proposal_names_the_certificates_to_relink():
    a = what_to_do(_issuing_impact(), FRESH, "ca_uitgever")
    text = a.to_text()
    assert a.is_complete() is True
    assert "leaf_cert" in text
    assert "opnieuw" in text.lower()


def test_the_proposal_no_longer_reads_as_nothing_hangs_on_it():
    """De kern van de gemeten klacht: de oude fallbacktekst liet een
    onmisbare CA lezen als een certificaat waar niets aan hangt.
    """
    text = what_to_do(_issuing_impact(), FRESH, "ca_uitgever").to_text()
    assert "Koppel het om op: (geen gebonden virtuele servers)" not in text
    assert "geen rechtstreeks gebonden virtuele servers" in text


def test_the_fallback_text_survives_for_a_certificate_without_any_users():
    """Tegenproef: zonder uitgifterelatie blijft de bestaande tekst staan,
    letterlijk. Een mutatie die de fallback altijd vervangt zou hier omvallen.
    """
    text = what_to_do(_real_impact([]), FRESH, "cert_a").to_text()
    assert "Koppel het om op: (geen gebonden virtuele servers)" in text


def test_the_evidence_line_counts_the_issued_certificates_too():
    a = what_to_do(_issuing_impact(), FRESH, "ca_uitgever")
    evidence = a.findings[0].evidence
    # Letterlijk de tekst uit de plantabel: het woord "vastgesteld" hoort
    # ertussen, zodat het aantal niet gelezen kan worden als een telling die
    # ook het onbeoordeelde dekt.
    assert "1 vastgesteld uitgegeven certificaat" in evidence, "enkelvoud hoort enkelvoud te blijven"
    assert "1 vastgesteld uitgegeven certificaten" not in evidence
    assert "0 vastgesteld geraakte virtuele server" in evidence


def test_the_evidence_line_uses_the_plural_for_more_than_one():
    """Klantcopy zonder kapot meervoud, dezelfde regel die answer._days_old
    al volgt."""
    certs = [
        {"certkey": "leaf_a", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "leaf_b", "linkcertkeyname": "ca_uitgever"},
        {"certkey": "ca_uitgever"},
    ]
    impact = what_breaks(ExportStub([], certs=certs), FRESH, "ca_uitgever")
    a = what_to_do(impact, FRESH, "ca_uitgever")
    assert "2 vastgesteld uitgegeven certificaten" in a.findings[0].evidence


def test_the_readback_step_names_the_link_field():
    """Terugleescontrole moet het veld noemen dat de operator echt moet
    terugzien - anders leest hij een binding terug die niet veranderd is en
    concludeert hij ten onrechte dat het goed staat.
    """
    text = what_to_do(_issuing_impact(), FRESH, "ca_uitgever").to_text()
    assert "linkcertkeyname" in text


def test_the_steps_stay_numbered_consecutively_with_the_extra_step():
    """De stappenlijst wordt uitgevoerd door een mens; een dubbele of
    overgeslagen nummering is een echte fout in het voorstel."""
    outcome = what_to_do(_issuing_impact(), FRESH, "ca_uitgever").findings[0].outcome
    nummers = [regel.split(".", 1)[0].strip() for regel in outcome.splitlines()]
    assert nummers == ["1", "2", "3", "4", "5"]


def test_the_steps_stay_four_without_an_issuing_relation():
    """Tegenproef op de nummering: zonder keten blijft het voorstel
    precies vier stappen."""
    outcome = what_to_do(_real_impact([_binding()]), FRESH, "cert_a").findings[0].outcome
    nummers = [regel.split(".", 1)[0].strip() for regel in outcome.splitlines()]
    assert nummers == ["1", "2", "3", "4"]


def test_an_answer_without_the_issued_collection_gives_no_advice():
    """Fail-closed op de nieuwe koppeling zelf, symmetrisch met
    `test_answer_without_explicit_affected_vservers_gives_no_advice`: een
    kaal Answer draagt de verzameling niet, en dan weet dit voorstel het
    niet - dat is wat het moet zeggen, niet iets afleiden.
    """
    bare = Answer(question="wat breekt er", findings=[])
    a = what_to_do(bare, FRESH, "cert_a")
    assert a.is_complete() is False
    assert any("uitgegeven certificaten" in g.reason for g in a.read_gaps)


# ---------------------------------------------------------------------------
# De drie adviesregels op de stappen (C1, tweede helft).
#
# Elke stap van het voorstel zegt over zichzelf of dit product hem kan
# uitvoeren. Dat oordeel komt uit dezelfde validate() als het schrijfpad,
# nooit uit een met de hand geschreven tekst - anders belooft het leesadvies
# iets wat de schrijfkant vervolgens weigert.
#
# HERSCHREVEN. De eerste versie legde het label van de
# klaarzet- en omkoppelstap langs de naam van het VERLOPENDE certificaat,
# terwijl de staptekst de beheerder juist een NIEUWE naam laat uploaden. De
# oude allowlist gaf de verlopende naam ("cert_a") als `certnaam` en
# `nieuwcert`, dus de tests konden dat verschil niet zien. Sindsdien noemt de
# allowlist hier een ANDERE, echte nieuwe naam - precies zoals een beheerder
# hem zou zetten - en is dat het onderscheid waarop deze tests staan of
# vallen.
# ---------------------------------------------------------------------------

EXPIRING = "cert_a"
NEW_NAME = "cert_2027"

LAB = Allowlist(
    per_target={
        "lab": {
            "certificaat_klaarzetten": {"certnaam": (NEW_NAME,)},
            "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME,)},
        }
    }
)


def _steps(answer):
    return answer.findings[0].outcome.splitlines()


def _advice(allowlist=LAB, target="lab", vservers=("LB_VS_A",), offered=True):
    """De stapregels van een voorstel over het VERLOPENDE certificaat.

    Alle adviestests vragen naar `EXPIRING`; wat de allowlist toestaat is de
    nieuwe naam. Dat is de normale situatie op een appliance, en het is de
    situatie waarin het oude label het verkeerde object beoordeelde.
    """
    return _steps(
        what_to_do(
            _real_impact([_binding(v) for v in vservers]),
            FRESH,
            EXPIRING,
            allowlist=allowlist,
            target=target,
            writing_tools_offered=offered,
        )
    )


def test_every_step_carries_exactly_one_of_the_three_advice_words():
    for line in _advice():
        hits = [word for word in ADVICE_WORDS if line.endswith(f"({word})")]
        assert len(hits) == 1, f"stap zonder eenduidige adviesregel: {line}"


def test_a_staging_step_gets_the_can_word_on_an_allowlist_with_only_the_new_name():
    """De kern van die herziening. `LAB` staat ALLEEN `cert_2027` toe - de echte
    nieuwe naam - en het advies gaat over `cert_a`, dat verloopt. Het product
    KAN deze stap hier uitvoeren, dus het can-woord hoort er te staan.

    Het can-woord vraagt daarbij twee dingen: deze server biedt de
    schrijvende gereedschappen aan EN de beheerder heeft voor deze handeling
    op dit doel iets toegestaan. Beide staan hier expliciet in de aanroep.
    """
    step_lines = _advice()
    assert step_lines[0] == (
        f"1. Vervang {EXPIRING}: upload het nieuwe certificaat met sleutel onder een NIEUWE naam. ({ADVICE_CAN})"
    )
    assert step_lines[1] == f"2. Koppel het om op: LB_VS_A. ({ADVICE_CAN})"


def test_the_expiring_certificate_name_no_longer_decides_the_staging_label():
    """Twee allowlists die ALLEEN verschillen in of de naam van het
    verlopende certificaat er ook bij staat. De klaarzetstap zet een NIEUW
    certificaat klaar, waarvan de naam bij het lezen nog niet gekozen is, dus
    dat verschil mag het label niet raken.
    """
    with_the_expiring_name = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": (NEW_NAME, EXPIRING)},
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME, EXPIRING)},
            }
        }
    )
    labels = {_advice(allowlist=lijst)[0] for lijst in (LAB, with_the_expiring_name)}
    assert len(labels) == 1, f"de verlopende naam beslist nog steeds mee: {labels}"
    assert labels.pop().endswith(f"({ADVICE_CAN})")


def test_a_target_that_approves_no_certificate_name_at_all_is_not_allowed():
    """Fail-closed op het argument dat de leeskant niet kent: staat er voor
    `certnaam` geen enkele waarde op de lijst, dan heeft de beheerder hier
    geen schrijfruimte gegeven. De omkoppelstap staat er onveranderd naast,
    dus een mutatie die overal het can-woord zet valt hier om.
    """
    no_staging_values = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": ()},
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME,)},
            }
        }
    )
    step_lines = _advice(allowlist=no_staging_values)
    assert step_lines[0].endswith(f"({ADVICE_NOT_ALLOWED})")
    assert step_lines[1].endswith(f"({ADVICE_CAN})")


def test_a_target_that_does_not_mention_the_staging_tool_is_not_allowed():
    """Dezelfde vraag, andere vorm van 'niets toegestaan': de handeling staat
    helemaal niet in de sectie van dit doel.
    """
    no_staging_tool = Allowlist(
        per_target={
            "lab": {
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME,)},
            }
        }
    )
    step_lines = _advice(allowlist=no_staging_tool)
    assert step_lines[0].endswith(f"({ADVICE_NOT_ALLOWED})")
    assert step_lines[1].endswith(f"({ADVICE_CAN})")


def test_a_rebind_onto_a_vserver_outside_the_allowlist_is_not_allowed():
    """De `dienst` van de omkoppelstap IS bij het lezen bekend en wordt dus
    wel exact beoordeeld. Dezelfde allowlist, een andere virtuele server:
    alleen de omkoppelstap kantelt, de klaarzetstap niet - een mutatie die
    een van beide labels hardcodeert valt hier om.
    """
    step_lines = _advice(vservers=("LB_VS_ANDERS",))
    assert step_lines[0].endswith(f"({ADVICE_CAN})")
    assert step_lines[1] == f"2. Koppel het om op: LB_VS_ANDERS. ({ADVICE_NOT_ALLOWED})"


def test_a_rebind_step_is_not_allowed_when_no_new_certificate_is_approved():
    """Tegenproef op de vorige: de virtuele server staat wel op de lijst,
    maar er is geen enkele nieuwe certificaatnaam toegestaan. Dan is er geen
    omkoppeling die dit product mag doen.
    """
    no_new_cert = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": (NEW_NAME,)},
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": ()},
            }
        }
    )
    step_lines = _advice(allowlist=no_new_cert)
    assert step_lines[0].endswith(f"({ADVICE_CAN})")
    assert step_lines[1].endswith(f"({ADVICE_NOT_ALLOWED})")


def test_a_step_naming_several_vservers_is_executable_only_when_all_of_them_are():
    """Een stap die maar half uitvoerbaar is, is niet uitvoerbaar."""
    assert _advice(vservers=("LB_VS_A", "CS_VS_B"))[1].endswith(f"({ADVICE_NOT_ALLOWED})")

    both = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": (NEW_NAME,)},
                "certificaat_vervangen": {"dienst": ("LB_VS_A", "CS_VS_B"), "nieuwcert": (NEW_NAME,)},
            }
        }
    )
    assert _advice(allowlist=both, vservers=("LB_VS_A", "CS_VS_B"))[1].endswith(f"({ADVICE_CAN})")


def test_a_rebind_step_without_a_single_vserver_fails_closed():
    """De plaatshouder "(geen gebonden virtuele servers)" is geen object dat
    dit product kan omkoppelen. Het can-woord zou hier een uitvoering van
    niets beloven; `all([])` is True, dus dit is precies de plek waar
    fail-closed expliciet moet staan in plaats van uit de lus te volgen.
    """
    assert _advice(vservers=())[1] == (f"2. Koppel het om op: (geen gebonden virtuele servers). ({ADVICE_NOT_ALLOWED})")


def test_the_rollback_and_readback_steps_are_manual_actions():
    """Dit product heeft voor terugrollen en terugleescontrole geen
    schrijvend gereedschap. Dat is een uitspraak over het PRODUCT, niet over
    de allowlist - dus ook met een ruime allowlist blijven ze handwerk.
    """
    step_lines = _advice()
    assert step_lines[2].startswith("3. Terugrol")
    assert step_lines[2].endswith(f"({ADVICE_MANUAL})")
    assert step_lines[3].startswith("4. Terugleescontrole")
    assert step_lines[3].endswith(f"({ADVICE_MANUAL})")


def test_the_relink_step_of_an_issuing_certificate_is_a_manual_action():
    step_lines = _steps(
        what_to_do(
            _issuing_impact(),
            FRESH,
            "ca_uitgever",
            allowlist=LAB,
            target="lab",
            writing_tools_offered=True,
        )
    )
    assert step_lines[2].startswith("3. Koppel de certificaten die dit certificaat uitgeeft opnieuw")
    assert step_lines[2].endswith(f"({ADVICE_MANUAL})")


def test_without_an_allowlist_or_target_the_steps_fail_closed():
    """Het gereedschap wordt hier wel aangeboden, dus de allowlist-vraag is
    aan de beurt - en die is fail-closed. Een leestool die niet weet welk
    doel bedoeld is, weet ook niet of er schrijfruimte is, en mag dan nooit
    stil groen zijn.
    """
    step_lines = _steps(
        what_to_do(
            _real_impact([_binding("LB_VS_A")]),
            FRESH,
            EXPIRING,
            writing_tools_offered=True,
        )
    )
    assert step_lines[0].endswith(f"({ADVICE_NOT_ALLOWED})")
    assert step_lines[1].endswith(f"({ADVICE_NOT_ALLOWED})")
    assert step_lines[3].endswith(f"({ADVICE_MANUAL})")
    assert ADVICE_CAN not in "\n".join(step_lines)


def test_an_allowlist_without_the_named_target_fails_closed():
    """Wel een allowlist, wel een doelnaam, maar niet DIT doel. Zonder deze
    tegenproef blijft een mutatie groen die alleen op `allowlist is None`
    controleert.
    """
    step_lines = _advice(target="ander")
    assert step_lines[0].endswith(f"({ADVICE_NOT_ALLOWED})")
    assert step_lines[1].endswith(f"({ADVICE_NOT_ALLOWED})")


def test_an_unresolvable_target_says_why_instead_of_just_refusing():
    """MEASURED: with TWO allowlist target
    sections, `certificaat_wat_moet_ik_doen` cannot infer which one applies
    and passes `target=None` - `advice_label` then answers "niet in de
    allowlist" for every real step, exactly as it would for a target the
    administrator genuinely never approved anything for. The two causes are
    not the same: editing the allowlist fixes the second and does nothing
    for the first. The word stays the same (design 2.1.1 pins three words,
    not four); the step now says WHY."""
    two_targets = Allowlist(
        per_target={
            "lab": {
                "certificaat_klaarzetten": {"certnaam": (NEW_NAME,)},
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME,)},
            },
            "acc": {
                "certificaat_klaarzetten": {"certnaam": (NEW_NAME,)},
                "certificaat_vervangen": {"dienst": ("LB_VS_A",), "nieuwcert": (NEW_NAME,)},
            },
        }
    )
    step_lines = _advice(allowlist=two_targets, target=None)
    reden = "er zijn 2 doelen ingesteld"
    assert reden in step_lines[0] and step_lines[0].endswith(")")
    assert f"({ADVICE_NOT_ALLOWED}:" in step_lines[0]
    assert reden in step_lines[1]

    # The bare word, with no reason, is what a genuinely single, resolved
    # target (or no allowlist at all) still gets - no regression on the
    # ordinary "not allowed" and "not established" cases.
    assert _advice(target="ander")[0].endswith(f"({ADVICE_NOT_ALLOWED})")
    zonder_allowlist = _steps(
        what_to_do(
            _real_impact([_binding("LB_VS_A")]),
            FRESH,
            EXPIRING,
            writing_tools_offered=True,
        )
    )
    assert zonder_allowlist[0].endswith(f"({ADVICE_NOT_ALLOWED})")


def test_a_blocked_proposal_carries_no_advice_words_at_all():
    """Zolang de impact niet vaststaat zijn er geen stappen, en dus ook geen
    uitspraak over uitvoerbaarheid. Een label op een ingehouden voorstel zou
    suggereren dat er iets uit te voeren valt.
    """
    a = what_to_do(
        _real_impact([], gap=ReadGap(source="binding", reason="hash wijkt af")),
        FRESH,
        EXPIRING,
        allowlist=LAB,
        target="lab",
        writing_tools_offered=True,
    )
    text = a.to_text()
    for word in ADVICE_WORDS:
        assert word not in text


def test_a_server_that_does_not_offer_the_writing_tools_calls_every_step_manual():
    """Het can-woord is een belofte over DIT product op DEZE server. Meldt de
    server de schrijvende gereedschappen niet aan (geen schrijfscript, geen
    fixture-map, geen codekanaal), dan bestaat het gereedschap voor die stap
    hier niet - en dan is `handmatige actie` het eerlijke woord.
    `niet in de allowlist` zou de beheerder een allowlist-regel laten
    schrijven die niets oplost.

    Dezelfde allowlist en hetzelfde doel als
    test_a_staging_step_gets_the_can_word_on_an_allowlist_with_only_the_new_name;
    alleen het aanbieden van de gereedschappen kantelt, dus alleen dat kan het
    verschil verklaren.
    """
    step_lines = _advice(offered=False)
    assert step_lines[0] == (
        f"1. Vervang {EXPIRING}: upload het nieuwe certificaat met sleutel onder een NIEUWE naam. ({ADVICE_MANUAL})"
    )
    assert step_lines[1] == f"2. Koppel het om op: LB_VS_A. ({ADVICE_MANUAL})"
    for line in step_lines:
        assert line.endswith(f"({ADVICE_MANUAL})"), line
    assert ADVICE_NOT_ALLOWED not in "\n".join(step_lines)


def test_the_writing_tools_count_as_not_offered_unless_the_caller_says_so():
    """De standaard is fail-closed: een aanroeper die er niets over zegt,
    krijgt geen can-woord - ook niet met een allowlist die het object
    toestaat.
    """
    a = what_to_do(
        _real_impact([_binding("LB_VS_A")]),
        FRESH,
        EXPIRING,
        allowlist=LAB,
        target="lab",
    )
    assert ADVICE_CAN not in a.findings[0].outcome


# ---------------------------------------------------------------------------
# SSL-diensten (services) aan het certificaat, gelezen uit de
# certificaatkant (sslcertkey_binding.by-parent.json).
# ---------------------------------------------------------------------------


def test_a_certificate_on_a_management_service_gets_no_proposal():
    """The management services of the appliance itself are out of reach by
    the built-in denylist (handelen.DENIED_PREFIXES). A proposal that would
    replace their certificate is refused with the refusal the writing path
    itself gives, never a proposal that leaves management HTTPS behind."""
    impact = what_breaks(
        ExportStub(
            [],
            certs=[{"certkey": "cert_a"}],
            cert_side=_services_on("cert_a", "nshttps-127.0.0.1-443", "SVC_WEB"),
        ),
        FRESH,
        "cert_a",
    )
    text = what_to_do(impact, FRESH, "cert_a").to_text()
    assert (
        "- cert_a: geen wijzigingsvoorstel: dit certificaat draagt beheerverkeer van de appliance zelf [vastgesteld]\n"
        "    bewijs: afgeleid uit het impactantwoord: 1 beheerdienst(en) aan dit certificaat\n"
        "    reden: 'nshttps-127.0.0.1-443' is een beheerdienst van de appliance en blijft buiten bereik"
    ) in text
    assert "Koppel" not in text
    assert "Vervang" not in text


def test_a_certificate_on_a_regular_service_gets_a_manual_step_for_it():
    impact = what_breaks(
        ExportStub(
            [_binding("LB_VS_A")],
            certs=[{"certkey": "cert_a"}],
            cert_side=_services_on("cert_a", "SVC_WEB", "SVC_API"),
        ),
        FRESH,
        "cert_a",
    )
    answer = what_to_do(impact, FRESH, "cert_a")
    steps = answer.findings[0].outcome.splitlines()
    assert steps[1] == f"2. Koppel het om op: LB_VS_A. ({ADVICE_MANUAL})"
    assert steps[2] == f"3. Koppel het ook om op de SSL-diensten (services): SVC_WEB, SVC_API. ({ADVICE_MANUAL})"
    assert steps[3].startswith("4. Terugrol:")
    assert steps[4].startswith("5. Terugleescontrole:")
    assert "Lees daarnaast de certificaatbinding van die SSL-diensten terug." in steps[4]
    assert answer.findings[0].evidence == (
        "afgeleid uit 1 vastgesteld geraakte virtuele server(s), 2 vastgesteld geraakte SSL-dienst(en)"
        " en 0 vastgesteld uitgegeven certificaten"
    )


def test_without_a_service_the_steps_and_the_evidence_stay_as_they_were():
    impact = what_breaks(
        ExportStub([_binding("LB_VS_A")], certs=[{"certkey": "cert_a"}], cert_side={"cert_a": []}),
        FRESH,
        "cert_a",
    )
    answer = what_to_do(impact, FRESH, "cert_a")
    assert "SSL-diensten" not in answer.findings[0].outcome
    assert answer.findings[0].evidence == (
        "afgeleid uit 1 vastgesteld geraakte virtuele server(s) en 0 vastgesteld uitgegeven certificaten"
    )
