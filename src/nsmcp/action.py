"""What should I do - with rollback and read-back verification.

Deliberate restriction: no action is proposed while the impact is not
established. A change proposal on half a picture is more dangerous than no
proposal, because it suggests the consequences are known.

v1 writes nothing to the appliance. This delivers the STEPS an administrator
executes or attaches to their change process.

impact.py passes the affected vservers EXPLICITLY
(`ImpactAnswer.affected_vservers`). This module derives nothing itself,
and refuses fail-closed to advise when an impact answer does not carry that
collection: then it does not know, and that is exactly the answer it should
give.

Since the chain-aware round there is a SECOND explicit collection:
`ImpactAnswer.issued_certificates`. The two drive two different repairs - a
virtual server is REBOUND to a new certificate, an issued certificate is
re-LINKED to the new issuer - so they are read separately and never merged.
Both are read string-based with a fail-closed default, and both refuse to
advise when the impact answer does not carry them.

The uses outside the bindings (`ImpactAnswer.other_uses`: SAML actions, SAML
IdP profiles, SSL servicegroups) get a manual step with an explicit warning:
the writing tool rebinds a virtual server and nothing else.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nsmcp.advice import ADVICE_CAN, ADVICE_NOT_ALLOWED, advice_label
from nsmcp.answer import Answer, Certainty, Finding, ReadGap
from nsmcp.handelen import DENIED_PREFIXES, Refusal
from nsmcp.impact import BINDING_FILE, CHAIN_DIMENSION, candidate_finding, what_breaks
from nsmcp.knowledge import Knowledge

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Typing hygiene, nothing more. This guard does NOT keep the writing side
    # out of the runtime import graph and never did: this module imports
    # `nsmcp.advice` at runtime, and that module imports `nsmcp.handelen`
    # unconditionally - as does the denylist import above, which a proposal
    # on a management service is refused by. What the guard buys is that the
    # annotation stays a string (`from __future__ import annotations`).
    from nsmcp.handelen import Allowlist

# The refusal of a proposal on a certificate that carries the appliance's own
# management traffic. The rule is the built-in denylist of the writing path
# (`handelen.DENIED_PREFIXES`), not a new one; the reason quotes the refusal
# that path gives for such a service (`handelen.Refusal`, code "beheerdienst").
MANAGEMENT_REFUSAL_OUTCOME = "geen wijzigingsvoorstel: dit certificaat draagt beheerverkeer van de appliance zelf"

# The readback clause for the uses outside the virtual servers.
ELSEWHERE_READBACK = (
    " Lees daarnaast bij de objecten buiten de virtuele servers terug dat ze naar het nieuwe certificaat verwijzen."
)


def elsewhere_warning(labels: tuple[str, ...]) -> str:
    """The step for the uses outside the virtual servers (SAML actions, SAML
    IdP profiles, SSL servicegroups): named one by one, with the explicit
    warning that `certificaat_vervangen` leaves them on the old certificate
    and that this product has no writing tool for them."""
    return (
        f"Let op: dit certificaat is ook buiten de virtuele servers in gebruik: {', '.join(labels)}."
        " certificaat_vervangen wisselt alleen de binding op een virtuele server om; zet deze verwijzingen"
        " zelf om, want dit product heeft daarvoor geen schrijfactie."
    )


USED_ELSEWHERE_OUTCOME = (
    "dit certificaat is ook elders in gebruik: {uses}; die gebruiken raakt deze vervanging niet, neem ze zelf mee"
)
USE_NOT_ESTABLISHED_OUTCOME = "gebruik buiten de binding niet vastgesteld"
REPLACED_CERTIFICATE_SUBJECT = "te vervangen certificaat"


def _is_ca_binding(row: dict) -> bool:
    return str(row.get("ca")).strip().lower() in ("true", "yes", "1")


def replacement_findings(export, knowledge: Knowledge, vserver: str) -> list[Finding]:
    """What the proposal of `certificaat_vervangen` adds of its own: the
    certificate that hangs on `vserver` now - the one this replacement
    takes off it - read with the same reader as `certificaat_wat_breekt_er`
    (`impact.what_breaks`), and every use of it OUTSIDE that one binding.

    The replacement rebinds this virtual server and nothing else, so each
    such use keeps the old certificate: another virtual server, an SSL
    service, a certificate it issues, a SAML action, a SAML IdP profile, an
    SSL servicegroup. They are named with object and role. Nothing is added
    when the old certificate is established to have no other use; when that
    cannot be established - a source that is not in the export or not read,
    or no certificate on this virtual server in the export at all - the
    proposal says "gebruik buiten de binding niet vastgesteld" with the
    reason, never nothing.

    A CA binding on the virtual server is not the certificate a
    replacement swaps; every other binding is (an absent or unreadable ca
    flag included - in doubt, look at it).
    """
    rows, gap = export.bindings(BINDING_FILE)
    if gap is not None:
        return [
            Finding(
                subject=REPLACED_CERTIFICATE_SUBJECT,
                outcome=USE_NOT_ESTABLISHED_OUTCOME,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"{BINDING_FILE} in de export",
                reason=f"welk certificaat nu aan {vserver} hangt, is niet te lezen: {gap.reason}",
                subject_is_name=False,
            )
        ]
    old: list[str] = []
    unreadable = 0
    for row in rows:
        owner = row.get("vservername")
        if not (isinstance(owner, str) and owner.strip() == vserver) or _is_ca_binding(row):
            continue
        name = row.get("certkeyname")
        if not (isinstance(name, str) and name.strip()):
            unreadable += 1
        elif name.strip() not in old:
            old.append(name.strip())
    if unreadable:
        # A binding on this virtual server whose certificate cannot be read:
        # which certificate the replacement takes off is then not known.
        return [
            Finding(
                subject=REPLACED_CERTIFICATE_SUBJECT,
                outcome=USE_NOT_ESTABLISHED_OUTCOME,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"{BINDING_FILE} in de export",
                reason=(
                    f"een binding aan {vserver} draagt geen bruikbare certkeyname; welk certificaat deze"
                    " vervanging losmaakt, is niet vast te stellen"
                ),
                subject_is_name=False,
            )
        ]
    if not old:
        return [
            Finding(
                subject=REPLACED_CERTIFICATE_SUBJECT,
                outcome=USE_NOT_ESTABLISHED_OUTCOME,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"{BINDING_FILE} in de export",
                reason=(
                    f"de export noemt geen certificaat aan {vserver}; welk certificaat deze vervanging losmaakt,"
                    " en waar dat verder in gebruik is, is niet vast te stellen"
                ),
                subject_is_name=False,
            )
        ]
    findings: list[Finding] = []
    for cert in old:
        impact = what_breaks(export, knowledge, cert)
        evidence = f"de export, gelezen zoals certificaat_wat_breekt_er: {cert} hangt aan {vserver}"
        uses = [f"virtuele server {v}" for v in impact.affected_vservers if v != vserver]
        uses += [f"SSL-dienst {s}" for s in impact.affected_services]
        uses += [f"certificaat {c} (uitgegeven door dit certificaat)" for c in impact.issued_certificates]
        uses += [use.label for use in impact.other_uses]
        if uses:
            findings.append(
                Finding(
                    subject=cert,
                    outcome=USED_ELSEWHERE_OUTCOME.format(uses=", ".join(uses)),
                    certainty=Certainty.ESTABLISHED,
                    evidence=evidence,
                )
            )
        # What the impact answer could not establish: its read gaps, the
        # boundaries other than the depth of the chain (a source that is not
        # in the export), and a use whose role it could not establish.
        open_items = [g.source for g in impact.read_gaps]
        open_items += [n.subject for n in impact.not_assessed if n is not CHAIN_DIMENSION]
        open_items += [f.subject for f in impact.findings if f.certainty is Certainty.NOT_ESTABLISHED]
        open_items = list(dict.fromkeys(open_items))
        if open_items:
            findings.append(
                Finding(
                    subject=cert,
                    outcome=USE_NOT_ESTABLISHED_OUTCOME,
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=evidence,
                    reason=(
                        "zie certificaat_wat_breekt_er voor dit certificaat; niet gelezen of niet vast te stellen: "
                        + ", ".join(open_items)
                    ),
                )
            )
    return findings


def _candidates(impact_answer: Answer, certname: str) -> list[Finding]:
    """The candidate line, when the impact answer carries one.

    This module builds its OWN answer and carries no finding over from the
    impact answer - deliberately, that is what keeps a proposal from
    inheriting a statement it did not make. But the half name that produced
    the candidates was typed into THIS tool just as well (measured in the
    second practice round), so the way forward has to survive the boundary.
    It travels as an EXPLICIT collection on the impact answer, read
    string-based here with the same fail-closed shape as `affected_vservers`
    and `issued_certificates` below - an answer object without the field
    simply carries no candidate question, which is exactly what None means
    there too (see `impact.ImpactAnswer`).

    NOT a read gap and NOT a NOT_ESTABLISHED finding: naming near misses is
    an established statement about a source that WAS read, and turning it
    into either of those would block the proposal on the strength of a hint.
    """
    candidates = getattr(impact_answer, "name_candidates", None)
    if candidates is None:
        return []
    return [candidate_finding(certname, candidates, getattr(impact_answer, "certificate_count", 0))]


def _issued_count(count: int) -> str:
    """'1 vastgesteld uitgegeven certificaat', otherwise the plural.

    Customer copy, so no broken plural - the same reason `answer._days_old`
    exists. Kept here and not in answer.py: this phrasing belongs to the
    action proposal, and answer.py is the shared shape, not a copy library.
    The word "vastgesteld" is carried explicitly, so the count cannot be read
    as covering anything that stayed unassessed.
    """
    if count == 1:
        return "1 vastgesteld uitgegeven certificaat"
    return f"{count} vastgesteld uitgegeven certificaten"


def what_to_do(
    impact_answer: Answer,
    knowledge: Knowledge,
    certname: str,
    *,
    allowlist: Allowlist | None = None,
    target: str | None = None,
    writing_tools_offered: bool = False,
) -> Answer:
    """The steps, each with the one word it may say about itself.

    Two questions decide that word, in this order.

    First: does THIS server offer the writing tools at all?
    `writing_tools_offered` carries that answer - `build_server()` registers
    them only with a write script, a fixture directory and a code channel,
    and passes that same flag here. Is it False, then this product has no
    tool for the step, which is exactly what `advice.advice_label` means by
    `tool=None`: "handmatige actie", a statement about the PRODUCT. Saying
    "niet in de allowlist" there would send an administrator off to write a
    list entry that changes nothing, and the can-word would promise an
    execution through a tool that is not even registered.

    Only then: does the ADMINISTRATOR allow this on this installation? That
    is `allowlist` and `target`, judged by the same `validate()` the writing
    path runs, so no step can promise what the writing side would refuse.

    Which OBJECT that question is about differs per argument, and the
    difference is the point. The virtual servers of the rebind step are
    known, so they are judged by name. The name of the new certificate is
    not - these steps tell the operator to upload the replacement under a
    NEW name, and `certname` is the certificate that EXPIRES. Passing
    `certname` there judged the wrong object entirely, so `certnaam` and
    `nieuwcert` travel as `None`: unknown to the reading side. The can-word
    then says the administrator has approved at least one certificate name
    for this action on this target (see `advice.advice_label`).

    All three default fail-closed - no allowlist, no target, and no offered
    tools - so a caller that says nothing never gets the can-word.
    """
    uncertain = [b for b in impact_answer.findings if b.certainty is Certainty.NOT_ESTABLISHED]
    read_gaps: list[ReadGap] = list(impact_answer.read_gaps)
    for b in uncertain:
        # Finding.subject has no emptiness check (answer.py is not up
        # for change here), but ReadGap.source refuses empty with a
        # ValueError. Without this local fallback what_to_do() crashes hard
        # exactly where it should have reported a read gap fail-closed. So
        # fall back to a readable placeholder here, instead of leaning on
        # the assumption that a calling module (such as impact.py) always
        # guarantees a non-empty subject.
        source = b.subject.strip() or "(naamloos)"
        read_gaps.append(ReadGap(source=source, reason=f"impact niet vastgesteld: {b.reason}"))

    # No derivation from the findings list. If the impact answer does not
    # carry the collection, it cannot be established what is affected - and
    # then there is no proposal, just as with a read gap. Guessing again is
    # precisely the mistake that was repaired here.
    affected = getattr(impact_answer, "affected_vservers", None)
    if affected is None:
        read_gaps.append(
            ReadGap(
                source="impactantwoord",
                reason=(
                    "draagt geen expliciete verzameling geraakte virtuele servers;"
                    " welke virtuele servers omgekoppeld moeten worden is daarmee niet vast te stellen"
                ),
            )
        )

    # Same string-based, fail-closed coupling as `affected_vservers` above,
    # for the SECOND collection: which certificates this certificate issues.
    # An answer that does not carry it cannot be established to have no
    # issuing relation - and an issuing relation is exactly what turns an
    # apparently idle CA into an indispensable one.
    issued = getattr(impact_answer, "issued_certificates", None)
    if issued is None:
        read_gaps.append(
            ReadGap(
                source="impactantwoord",
                reason=(
                    "draagt geen expliciete verzameling uitgegeven certificaten;"
                    " of dit certificaat andere certificaten uitgeeft is daarmee niet vast te stellen"
                ),
            )
        )

    # What impact deliberately did not assess applies just as much to the
    # proposal built on top of it: these steps are derived from that picture,
    # so its boundary travels along - like the read gaps above. Every Answer
    # carries this field, so no getattr fallback here as for
    # affected_vservers (which exists only on ImpactAnswer).
    not_assessed = list(impact_answer.not_assessed)

    if read_gaps:
        return Answer(
            question=f"wat moet ik doen met {certname}",
            findings=[
                Finding(
                    subject=certname,
                    outcome="geen wijzigingsvoorstel zolang de impact niet vaststaat",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence="afgeleid uit het impactantwoord",
                    reason="een voorstel op een half beeld wekt de indruk dat de gevolgen bekend zijn",
                )
            ]
            + _candidates(impact_answer, certname),
            read_gaps=read_gaps,
            not_assessed=not_assessed,
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    # The SSL services on this certificate (the certificate-side file), read
    # string-based like the collections above. A plain Answer never carries
    # them, and then it cannot have named one either: `()` here, where the
    # vserver collection above already refuses such an answer anyway.
    services = tuple(getattr(impact_answer, "affected_services", ()) or ())
    # The established uses outside the bindings (SAML actions, SAML IdP
    # profiles, SSL servicegroups), read string-based like the collections
    # above. A plain Answer carries none, and then it cannot have named one.
    elsewhere = tuple(getattr(impact_answer, "other_uses", ()) or ())
    management = [service for service in services if service.startswith(DENIED_PREFIXES)]
    if management:
        # The appliance's own management traffic. The writing path refuses
        # such a service by its built-in denylist, so a proposal that would
        # leave it on the old certificate - or tell the operator to move it -
        # is refused here with the same words. An established refusal, not a
        # read gap: the impact IS known, and this is what it says.
        return Answer(
            question=f"wat moet ik doen met {certname}",
            findings=[
                Finding(
                    subject=certname,
                    outcome=MANAGEMENT_REFUSAL_OUTCOME,
                    certainty=Certainty.ESTABLISHED,
                    evidence=f"afgeleid uit het impactantwoord: {len(management)} beheerdienst(en) aan dit certificaat",
                    reason="; ".join(
                        Refusal("beheerdienst", "certificaat_vervangen", field="dienst", value=service).sentence()
                        for service in management
                    ),
                )
            ]
            + _candidates(impact_answer, certname),
            read_gaps=[],
            not_assessed=not_assessed,
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    # The rebind text depends on whether there is a chain: without one,
    # "(geen gebonden virtuele servers)" is the honest and long-standing
    # wording. WITH a chain that same sentence reads as "nothing hangs on
    # it" while the real work sits one step further down - so there it
    # points forward instead.
    if affected:
        rebind = ", ".join(affected)
    elif issued:
        rebind = "(geen rechtstreeks gebonden virtuele servers; zie de volgende stap)"
    else:
        rebind = "(geen gebonden virtuele servers)"

    # MEASURED: with TWO OR MORE allowlist
    # target sections, the caller (a READING tool, `certificaat_wat_moet_ik_
    # doen`) cannot infer which one applies and passes `target=None` - and
    # `advice_label` then answers `ADVICE_NOT_ALLOWED` for every real step,
    # indistinguishable from a target the administrator genuinely approved
    # nothing for. Editing the allowlist changes nothing about THIS cause.
    # The word stays one of the three (design 2.1.1); only a REASON is
    # added, and only when this exact ambiguity is why `target` is None -
    # not when there is no allowlist at all, and not for the OTHER, real
    # reasons a step can be `ADVICE_NOT_ALLOWED` (a genuinely resolved
    # target the administrator did not approve, or a rebind step with no
    # object to act on at all).
    _target_count = len(allowlist.targets()) if allowlist is not None else 0
    _target_unresolvable_reason = (
        (
            f"er zijn {_target_count} doelen ingesteld in handelen.toegestaan; dit"
            " leesgereedschap kan dan niet vaststellen tegen welk doel dit zou lopen"
        )
        if target is None and _target_count > 1
        else ""
    )

    def _with_target_reason(word: str) -> str:
        if word == ADVICE_NOT_ALLOWED and _target_unresolvable_reason:
            return f"{word}: {_target_unresolvable_reason}"
        return word

    def _label(tool: str | None, arguments: dict[str, str | None]) -> str:
        # A server that does not OFFER the writing tools has no tool for
        # this step, whatever the allowlist says - so the tool name drops
        # away here and advice_label answers with the word it already
        # reserves for exactly that case. One place, so no step can forget
        # it.
        if not writing_tools_offered:
            tool = None
        return _with_target_reason(advice_label(tool, arguments, target=target, allowlist=allowlist))

    def _rebind_label(vservers: tuple[str, ...]) -> str:
        """One label for a step that may name SEVERAL virtual servers.

        A step that is only half executable is not executable, so every named
        vserver has to come back allowed. The empty case is spelled out
        instead of left to the loop: `all([])` is True, and a step whose
        object is the placeholder "(geen gebonden virtuele servers)" would
        then promise the execution of nothing.

        Both of those weigh the ALLOWLIST, so they are only the question on a
        server that offers the tool at all - hence the product question
        first, answered through the same `_label` as every other step.
        """
        if not writing_tools_offered:
            return _label(None, {})
        if not vservers:
            return ADVICE_NOT_ALLOWED
        labels = {
            # `nieuwcert=None`: the NEW certificate's name. The reading side
            # does not know it - the operator has not chosen it yet - and it
            # is emphatically not `certname`, which is the certificate that
            # EXPIRES. `dienst` is passed as the real virtual server, because
            # that one IS known and has to keep being judged exactly.
            _label("certificaat_vervangen", {"dienst": v, "nieuwcert": None})
            for v in vservers
        }
        return ADVICE_CAN if labels == {ADVICE_CAN} else _with_target_reason(ADVICE_NOT_ALLOWED)

    # WHICH advice step maps to WHICH writing tool. Deliberately explicit and
    # short: staging is `certificaat_klaarzetten`, rebinding is
    # `certificaat_vervangen` per named virtual server, and relinking,
    # rollback and the read-back check have no writing tool in this product at
    # all - so they are manual, and inventing a tool name for them would make
    # the label lie.
    # `certnaam=None` for the same reason as `nieuwcert` above: the step tells
    # the operator to upload the replacement under a NEW name, and that name
    # is not `certname` - that is the one that expires. See
    # `advice.advice_label` for what the can-word then promises.
    stage_label = _label("certificaat_klaarzetten", {"certnaam": None})
    rebind_label = _rebind_label(tuple(affected))
    manual_label = _label(None, {})

    steps = [
        f"1. Vervang {certname}: upload het nieuwe certificaat met sleutel onder een NIEUWE naam. ({stage_label})",
        f"2. Koppel het om op: {rebind}. ({rebind_label})",
    ]
    if services:
        # No writing tool of this product binds a certificate to a service,
        # so this step is manual - and it is named, never left out: a
        # proposal that rebinds the virtual servers and forgets the services
        # leaves those on the old certificate.
        steps.append(
            f"{len(steps) + 1}. Koppel het ook om op de SSL-diensten (services): {', '.join(services)}. ({manual_label})"
        )
    if elsewhere:
        # The writing tool of this product rebinds a virtual server and
        # nothing else, so a SAML object or an SSL servicegroup that names this
        # certificate keeps naming the old one after `certificaat_vervangen`.
        # Said out loud, as a manual step, never left out.
        steps.append(f"{len(steps) + 1}. {elsewhere_warning(tuple(use.label for use in elsewhere))} ({manual_label})")
    if issued:
        steps.append(
            # Same restraint as the impact finding this step is derived from
            # (see impact.py, route 2): what the appliance PRESENTS is
            # established, whether a client rejects it is not.
            f"{len(steps) + 1}. Koppel de certificaten die dit certificaat uitgeeft opnieuw:"
            f" {', '.join(issued)}. Zolang dat niet gebeurd is, bieden de diensten die aan die"
            " certificaten hangen een keten aan met een verlopen certificaat erin."
            f" ({manual_label})"
        )
    steps.append(
        f"{len(steps) + 1}. Terugrol: koppel terug naar de oude certificaatnaam;"
        f" die blijft tot na de controle staan. ({manual_label})"
    )
    readback = (
        f"{len(steps) + 1}. Terugleescontrole: lees de binding per virtuele server terug en"
        " bevestig de nieuwe naam, en lees daystoexpiration van het nieuwe certificaat terug."
    )
    if services:
        readback += " Lees daarnaast de certificaatbinding van die SSL-diensten terug."
    if elsewhere:
        readback += ELSEWHERE_READBACK
    if issued:
        readback += (
            " Lees daarnaast linkcertkeyname van de opnieuw gekoppelde certificaten terug en"
            " bevestig dat die naar het nieuwe certificaat wijst."
        )
    steps.append(f"{readback} ({manual_label})")
    evidence = (
        f"afgeleid uit {len(affected)} vastgesteld geraakte virtuele server(s),"
        f" {len(services)} vastgesteld geraakte SSL-dienst(en) en {_issued_count(len(issued))}"
        if services
        else f"afgeleid uit {len(affected)} vastgesteld geraakte virtuele server(s) en {_issued_count(len(issued))}"
    )
    if elsewhere:
        evidence += f", plus {len(elsewhere)} vastgesteld gebruik(en) buiten de virtuele servers"

    return Answer(
        question=f"wat moet ik doen met {certname}",
        findings=[
            Finding(
                subject=certname,
                outcome="\n".join(steps),
                certainty=Certainty.ESTABLISHED,
                evidence=evidence,
            )
        ]
        + _candidates(impact_answer, certname),
        read_gaps=[],
        not_assessed=not_assessed,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
