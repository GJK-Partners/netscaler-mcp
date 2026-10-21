"""The state of one service and its members, read from the export.

The member state lives in the collector's aggregate binding files. They are
read through the shared aggregate reader in export.py
(`Export.aggregate_documents` plus `aggregate_nested_rows`, first built here
and moved there so every aggregate consumer reads by the same rules), with
every element positively checked, and anything that does not match is a read
gap - never a shorter list posing as complete. This module reads the nested
lists itself, per owner, so a malformed list of one servicegroup costs that
servicegroup and not the whole answer.

THE AGGREGATE SHAPE, MEASURED (2026-09-02, on the real collector output in
`tests/fixtures/lab-export-vpx-20260826/bindings/`, the only real
aggregate-shape evidence this repo has): all three files that export carries
with `shape == "aggregate"` - `vpnvserver_binding`, `sslcertkey_binding`,
`lbmonitor_binding` - write `parents[].data.<bindingResource>` as an OBJECT
(the parent's own key field plus one nested "<parent>_<child>_binding" LIST
per bound child type), while every `shape == "list"` file writes a bare LIST
there. The first version of this module demanded a list on both, so on every
real aggregate file it produced "data.<resource> heeft niet de verwachte vorm
(lijst)" and never an answer. A list containing exactly one object is
accepted next to the object - NITRO answers the same singleton in both
shapes depending on the resource, the same both-shapes rule
`Export.single()` already applies to singleton object files - and every
other shape is a read gap that names the shape it found, never the value.

MEASURED AGAIN, now on THESE TWO FILES (2026-09-02, live lab
appliance with the demo service built): `lbvserver_binding.by-parent.json`
and `servicegroup_binding.by-parent.json` carry `shape == "aggregate"` with
`data.<bindingResource>` as an OBJECT, exactly as inferred above; the member
records carry `servername`, `port`, `svrstate` and the address field `ip`;
`svrstate` reads "UP" and, with a member disabled, "OUT OF SERVICE" - both
already in MEMBER_STATES. The two files were the only ones this module reads
that the repo had never actually seen; the measured records are now pinned
verbatim in `tests/test_dienst.py` (the live-measured-shape block at the end).

THREE STATES, NOT TWO, per parent. A parent that is PRESENT with an unusable
outcome is refused below; a parent that is ABSENT from the file altogether
leaves no trace in it, so `rows.get(name, {})` would quietly render "0
lid/leden [vastgesteld]" - an unread source posing as an established
emptiness, exactly the false green the module docstring of export.py warns
about. Absence is therefore a read gap here, and a parent the collector read
as genuinely EMPTY is kept apart from it as the one established emptiness.
The same holds one level up for the lbvserver's own parent entry: absent is
never "geen servicegroup gebonden".

NAME MATCHING IS EXACT AND CASE-SENSITIVE on both sides, without folding:
NITRO object names are case-sensitive, so WEB01 and web01 are two different
objects and treating them as one would answer about the wrong one. The only
normalization is the surrounding whitespace `_usable_text` strips, the same
`.strip()` mcp_server.py applies to the argument.
"""

from __future__ import annotations

import re

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, repeatable_token
from nsmcp.export import MISSING as _MISSING, aggregate_nested_rows as _nested_bindings, value_shape as _shape
from nsmcp.knowledge import Knowledge

RESOURCE = "config/lbvserver"
LB_FILE = "lbvserver_binding.by-parent.json"
SG_FILE = "servicegroup_binding.by-parent.json"

LB_BINDING = "lbvserver_binding"
SG_BINDING = "servicegroup_binding"
GROUP_BINDING = "lbvserver_servicegroup_binding"
MEMBER_BINDING = "servicegroup_servicegroupmember_binding"

# A servicegroup member is bound EITHER by server object name OR by IP
# address; the second kind carries no `servername` at all. NITRO writes the
# address field as "ip" on some resources and "ipaddress" on others (both
# occur in the live export's object files: `authenticationvserver.json` and
# `vpnvserver.json` carry "ip", `nsip.json` and `hanode.json` carry
# "ipaddress"). Settled on a live member binding (2026-09-02):
# this resource writes "ip". "ipaddress" stays accepted behind it - one
# measurement on one build is not the whole vocabulary of NITRO, and a
# fallback that never fires costs nothing, while removing it would turn a
# renamed field into an unidentifiable member. The measured record is pinned
# in `test_live_measured_member_address_field_is_ip`.
MEMBER_IP_FIELDS = ("ip", "ipaddress")

# The `svrstate` vocabulary this version maps EXPLICITLY. The appliance's own
# words are kept (not translated), because the write tools of this product
# speak the same vocabulary ("OUT OF SERVICE" in mcp_server.py) and one word
# for one state keeps the read side and the write side talking about the same
# thing. Anything outside this set is NOT established: this version does not
# know what the appliance means by it, and guessing "well, that will be up"
# is precisely the claim this product does not make.
MEMBER_STATES = ("UP", "DOWN", "OUT OF SERVICE", "GOING OUT OF SERVICE")

# The sentinel that separates "the key is not there" from "the key carries a
# JSON null" - the same distinction (and the same wording, "de sleutel
# ontbreekt") that `export.shape_or_missing` draws directly. `_shape` is
# `export.value_shape`, a deliberate, measured CORRECTION of `export.shape_of`
# (it names a non-empty string in the wrong place as a text value, never as
# "empty"). It was defined here first and moved to export.py together with the
# aggregate reader, so the reader's read gaps and this module's own field
# texts keep using the one wording.


# The shape of a NITRO state token, used ONLY to decide whether an unknown
# value may be repeated in the answer. Uppercase, digits, underscores and
# single spaces ("OUT OF SERVICE"), bounded in length - so free text out of a
# supplied export cannot travel through this field into the answer, where the
# disclosure layer would not mask it. The shape test is
# `answer.repeatable_token`, shared with impact.py and overzicht.py; this
# vocabulary needs the space (up to four words) and the underscore, and no
# hyphen. THE LENGTH BOUND IS NEW: the local regex this replaced had none, so
# a single 232-character "state" matched the shape and was echoed verbatim.
def _is_state_token(value) -> bool:
    return repeatable_token(value, allow_hyphen=False) is not None


# A port is a number: NITRO writes it as an integer or as a numeric string.
_PORT_TEXT = re.compile(r"[0-9]{1,5}")


def _usable_text(value) -> str | None:
    """Only real text counts as a name. Same discipline (and deliberately the
    same shape) as `_usable_text` in export.py and `_readable_name` in
    impact.py/disclosure.py: the isinstance gate sits BEFORE the
    normalization, so a list/dict/number/boolean/None is never blindly
    stringified into something that happens not to match - and never into the
    literal string "None", which would both claim a name and pollute the
    disclosure pseudonym table with it.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _member_state(raw) -> tuple[str, str | None]:
    """(text, reason) for a member's `svrstate`. `reason` is None when the
    state is established; otherwise it says why it is not."""
    if raw is _MISSING:
        return "toestand niet leesbaar", f"svrstate: {_shape(raw)}"
    if not isinstance(raw, str) or not raw.strip():
        return "toestand niet leesbaar", f"svrstate draagt {_shape(raw)} in plaats van een toestand"
    value = raw.strip()
    if value in MEMBER_STATES:
        return value, None
    known = ", ".join(MEMBER_STATES)
    if _is_state_token(value):
        return (
            f"toestand {value} niet herkend",
            f"svrstate draagt {value}, geen van de toestanden die deze versie kent ({known})",
        )
    # Not even the shape of a state token: the value itself is not repeated,
    # for the same reason `shape_of` exists - it would reach the answer
    # unmasked in the 'beperkt' setting.
    return (
        "toestand niet herkend",
        f"svrstate draagt een waarde zonder de vorm van een toestand; bekend zijn: {known}",
    )


def _member_port(raw) -> tuple[str, str | None]:
    """(text, reason) for a member's `port`, same contract as `_member_state`."""
    if isinstance(raw, bool):
        return "poort niet leesbaar", f"port draagt {_shape(raw)} in plaats van een poortnummer"
    if isinstance(raw, int):
        return f"poort {raw}", None
    text = _usable_text(raw)
    if text is not None and _PORT_TEXT.fullmatch(text) is not None:
        return f"poort {text}", None
    return "poort niet leesbaar", f"port draagt {_shape(raw)} in plaats van een poortnummer"


def _member_finding(member: dict, group: str, position: int) -> tuple[Finding | None, ReadGap | None]:
    """One member line, or - when the member cannot even be identified - a
    read gap instead of a line about "None"."""
    name = _usable_text(member.get("servername"))
    address = None
    for field in MEMBER_IP_FIELDS:
        address = _usable_text(member.get(field))
        if address is not None:
            break
    if name is not None:
        subject, suffix = name, ""
    elif address is not None:
        subject, suffix = address, ", lid op IP"
    else:
        return None, ReadGap(
            source=SG_FILE,
            reason=(
                f"lid {position} van servicegroup {group} draagt geen bruikbare servername en"
                " geen bruikbaar ip-adres; niet vast te stellen om welk lid het gaat"
            ),
        )
    state_text, state_reason = _member_state(member.get("svrstate", _MISSING))
    port_text, port_reason = _member_port(member.get("port", _MISSING))
    reasons = [r for r in (state_reason, port_reason) if r]
    return (
        Finding(
            subject=subject,
            outcome=f"{state_text} ({port_text}){suffix}",
            certainty=Certainty.ESTABLISHED if not reasons else Certainty.NOT_ESTABLISHED,
            evidence=f"{SG_FILE}: {MEMBER_BINDING}",
            reason="; ".join(reasons),
        ),
        None,
    )


def _vserver_outcome(vserver: dict) -> tuple[str, str | None]:
    """(text, reason) for the vserver's own line. `effectivestate` is a state
    token and `health` a percentage; a field that is not readable is named as
    such instead of travelling into the answer as "?" next to
    "[vastgesteld]".
    """
    raw_state = vserver.get("effectivestate", _MISSING)
    state_text, state_reason = _member_state(raw_state)
    if state_reason is None:
        state_part = f"effectivestate={state_text}"
    else:
        state_part = "effectivestate niet leesbaar"
    raw_health = vserver.get("health", _MISSING)
    health = raw_health if isinstance(raw_health, str) else None
    if isinstance(raw_health, int) and not isinstance(raw_health, bool):
        health = str(raw_health)
    if health is not None and _PORT_TEXT.fullmatch(health.strip()) is not None:
        health_part, health_reason = f"health={health.strip()}", None
    else:
        health_part = "health niet leesbaar"
        health_reason = f"health draagt {_shape(raw_health)} in plaats van een getal"
    reasons = [r for r in (state_reason, health_reason) if r]
    return f"{state_part}, {health_part}", "; ".join(reasons) or None


# At most five, so an answer names a direction instead of dumping a
# catalogue of the appliance into the model's context.
_MAX_CANDIDATES = 5


def _name_candidates(vservers, service: str) -> list[str]:
    """The vserver names that CARRY the asked-for term, case-insensitively,
    sorted and capped. Deduplicated: two entries with the same name are one
    candidate, not two."""
    term = service.lower()
    names = set()
    for vserver in vservers:
        name = _usable_text(vserver.get("name"))
        if name and term in name.lower():
            names.add(name)
    return sorted(names)[:_MAX_CANDIDATES]


def service_status(export, knowledge: Knowledge, service: str) -> Answer:
    question = f"hoe staat dienst {service} ervoor"
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []

    def answer() -> Answer:
        return Answer(
            question=question,
            findings=findings,
            read_gaps=read_gaps,
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    vservers, gap = export.objects(RESOURCE)
    if gap is not None:
        # "Niet gevonden" is a statement about a source that WAS read. With
        # this source unusable, whether this dienst exists is simply not
        # established - the read gap says why.
        read_gaps.append(gap)
        findings.append(
            Finding(
                subject=service,
                outcome="niet vast te stellen of deze dienst bestaat",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=RESOURCE,
                reason=f"{RESOURCE} is niet bruikbaar gelezen: {gap.reason}",
            )
        )
        return answer()
    match = [v for v in vservers if _usable_text(v.get("name")) == service]
    if not match:
        findings.append(
            Finding(
                subject=service,
                outcome="niet gevonden in config/lbvserver",
                certainty=Certainty.ESTABLISHED,
                evidence=f"config/lbvserver: {len(vservers)} virtuele servers",
            )
        )
        # NAMING, never choosing. Measured in the practice runs: a caller
        # who says "proefdienst" got a bare "niet gevonden" and had nowhere to go,
        # while the writing tools' allowlist refusals - which DO name valid
        # names - let the same caller correct itself one turn later. So this
        # answer names what it read: the vserver names that carry the term,
        # case-insensitively. It resolves nothing and picks nothing - that
        # would be this product guessing what was meant.
        hits = _name_candidates(vservers, service)
        findings.append(
            Finding(
                subject=f"kandidaten (naam bevat '{service}', hoofdletterongevoelig)",
                outcome=", ".join(hits) if hits else "geen kandidaten",
                certainty=Certainty.ESTABLISHED,
                evidence=f"config/lbvserver: {len(vservers)} virtuele servers",
                # This subject is THIS product's own vocabulary plus the term the
                # caller typed - not an appliance object name. Collecting it as
                # one would write caller input into the operator's pseudonym
                # table (see disclosure._collect_names). The candidate NAMES in
                # the outcome are masked through the structural export
                # collection, exactly like every other name in an answer.
                subject_is_name=False,
                # ONLY at 'volledig', for the same reason as the certificate
                # candidate line (impact.candidate_finding): below 'volledig'
                # this answers a question about the caller's own term, and
                # stable pseudonyms turn that into an adaptive substring
                # oracle. See `Finding.only_in_full`.
                only_in_full=True,
            )
        )
        return answer()
    outcome, reason = _vserver_outcome(match[0])
    findings.append(
        Finding(
            subject=service,
            outcome=outcome,
            certainty=Certainty.ESTABLISHED if reason is None else Certainty.NOT_ESTABLISHED,
            evidence="config/lbvserver",
            reason=reason or "",
        )
    )

    lb_rows, gap = export.aggregate_documents(LB_FILE)
    if gap is not None:
        read_gaps.append(gap)
        return answer()
    if service not in lb_rows:
        read_gaps.append(
            ReadGap(
                source=LB_FILE,
                reason=(
                    f"{service} ontbreekt in het bindingsbestand; de bindingen van deze dienst zijn"
                    " niet gelezen en het is dus niet vast te stellen aan welke servicegroup hij hangt"
                ),
            )
        )
        findings.append(
            Finding(
                subject=service,
                outcome="gebonden servicegroup niet vast te stellen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=LB_FILE,
                reason=f"{LB_FILE} draagt geen parent-vermelding voor deze dienst",
            )
        )
        return answer()
    lb_row = lb_rows[service]
    if lb_row is None:
        findings.append(
            Finding(
                subject=service,
                outcome="geen servicegroup gebonden",
                certainty=Certainty.ESTABLISHED,
                evidence=f"{LB_FILE}: parent gelezen als EMPTY",
            )
        )
        return answer()

    group_bindings, gap = _nested_bindings(lb_row, GROUP_BINDING, LB_FILE, service)
    if gap is not None:
        read_gaps.append(gap)
        findings.append(
            Finding(
                subject=service,
                outcome="gebonden servicegroup niet vast te stellen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=LB_FILE,
                reason=gap.reason,
            )
        )
        return answer()
    if not group_bindings:
        findings.append(
            Finding(
                subject=service, outcome="geen servicegroup gebonden", certainty=Certainty.ESTABLISHED, evidence=LB_FILE
            )
        )
        return answer()
    group_names: list[str] = []
    for position, binding in enumerate(group_bindings, start=1):
        name = _usable_text(binding.get("servicegroupname"))
        if name is None:
            read_gaps.append(
                ReadGap(
                    source=LB_FILE,
                    reason=(
                        f"{GROUP_BINDING} van {service} draagt op positie {position} geen bruikbare"
                        f" servicegroupname ({_shape(binding.get('servicegroupname', _MISSING))});"
                        " niet vast te stellen welke servicegroup hier hangt"
                    ),
                )
            )
            continue
        if name not in group_names:
            group_names.append(name)
    if not group_names:
        # Every entry was unreadable; the gaps above say so. Falling back to
        # "geen servicegroup gebonden" here would turn an unread binding into
        # an established absence.
        return answer()

    sg_rows, gap = export.aggregate_documents(SG_FILE)
    if gap is not None:
        # Never a member COUNT next to the statement that nothing was
        # counted: the binding itself stays established (it came from the
        # lbvserver file), the members are explicitly not.
        read_gaps.append(gap)
        for group in group_names:
            findings.append(
                Finding(
                    subject=group,
                    outcome="gebonden servicegroup; leden niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{LB_FILE}: {GROUP_BINDING}",
                    reason=f"{SG_FILE} is niet bruikbaar gelezen: {gap.reason}",
                )
            )
        return answer()

    for group in group_names:
        if group not in sg_rows:
            read_gaps.append(
                ReadGap(
                    source=SG_FILE,
                    reason=(
                        f"servicegroup {group} ontbreekt in het bindingsbestand; de leden van deze"
                        " servicegroup zijn niet gelezen en hoeveel het er zijn is dus niet vast te"
                        " stellen"
                    ),
                )
            )
            findings.append(
                Finding(
                    subject=group,
                    outcome="gebonden servicegroup; leden niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{LB_FILE}: {GROUP_BINDING}",
                    reason=f"{SG_FILE} draagt geen parent-vermelding voor deze servicegroup",
                )
            )
            continue
        sg_row = sg_rows[group]
        if sg_row is None:
            findings.append(
                Finding(
                    subject=group,
                    outcome="servicegroup met 0 lid/leden",
                    certainty=Certainty.ESTABLISHED,
                    evidence=f"{SG_FILE}: parent gelezen als EMPTY",
                )
            )
            continue
        members, gap = _nested_bindings(sg_row, MEMBER_BINDING, SG_FILE, group)
        if gap is not None:
            read_gaps.append(gap)
            findings.append(
                Finding(
                    subject=group,
                    outcome="gebonden servicegroup; leden niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=SG_FILE,
                    reason=gap.reason,
                )
            )
            continue
        findings.append(
            Finding(
                subject=group,
                outcome=f"servicegroup met {len(members)} lid/leden",
                certainty=Certainty.ESTABLISHED,
                evidence=SG_FILE,
            )
        )
        for position, member in enumerate(members, start=1):
            finding, member_gap = _member_finding(member, group, position)
            if member_gap is not None:
                read_gaps.append(member_gap)
                continue
            findings.append(finding)
    return answer()


def _harvest(values: set[str], container, fields: tuple[str, ...]) -> None:
    if not isinstance(container, dict):
        return
    for field in fields:
        name = _usable_text(container.get(field))
        if name is not None:
            values.add(name)


def names_in_service_sources(export) -> tuple[str, ...]:
    """Every appliance name `dienst_status` can PRINT or ACCEPT - the fifth
    family of `disclosure.names_from_export()`.

    MEASURED: `dienst_status` passes its
    `dienst` argument to `render()` as `caller_name`, exactly like `certnaam`
    in `certificaat_wat_breekt_er`. That seam classifies a name as
    caller-INVENTED whenever it is absent from `extra_names`
    (disclosure.py, `render()`), and none of the four other families there
    ever reads an lbvserver, servicegroup or member name. Without this family
    a name the export genuinely knows renders in the 'beperkt' setting as the
    fixed "(onbekende naam uit de vraag)" - not a literal leak (the finding
    subjects are replaced anyway by the "second net" in `_collect_names()`),
    but a false "this export does not know this name" about an object it does
    know. The first version of this family read lbvserver names only, so
    asking about a real SERVICEGROUP or a real MEMBER - both perfectly valid
    things to type into `dienst` - still produced that false claim.

    THE HARVEST IS DELIBERATELY MORE TOLERANT THAN THE ANALYSIS. This
    function exists to make names MASKABLE, never to establish a fact, and a
    read gap out of `_aggregate_rows` WRITES a parent name into the answer
    ("dubbele parent X", "servicegroup X ontbreekt..."). Harvesting through
    the strict reader would yield no names for exactly the files that produce
    those gaps - so the very gap that makes an unread servicegroup visible
    would leak its name. It therefore walks the raw document and collects
    whatever sits in the name fields, regardless of whether the file as a
    whole is usable. Over-collecting is harmless here: a name too many is a
    replacement that never fires.

    Fail-closed all the same: a source that cannot be read at all yields no
    names, and a name this export never read can never reach a text either.
    """
    names: set[str] = set()
    rows, _ = export.objects(RESOURCE)
    for row in rows:
        _harvest(names, row, ("name",))

    document = getattr(export, "_binding_document", None)
    if document is None:
        # An export layer without this method is an older or stubbed one; it
        # then also produces no binding-based text, so there is no name to
        # mask either.
        return tuple(sorted(names))
    for file_name, resource, own_fields, nested in (
        (LB_FILE, LB_BINDING, ("name",), ((GROUP_BINDING, ("servicegroupname",)),)),
        (SG_FILE, SG_BINDING, ("servicegroupname",), ((MEMBER_BINDING, ("servername",) + MEMBER_IP_FIELDS),)),
    ):
        raw, gap = document(file_name)
        if gap is not None or not isinstance(raw, dict):
            continue
        parents = raw.get("parents")
        if not isinstance(parents, list):
            continue
        for parent in parents:
            if not isinstance(parent, dict):
                continue
            _harvest(names, parent, ("parentName",))
            data = parent.get("data")
            if not isinstance(data, dict):
                continue
            value = data.get(resource)
            for row in (value,) if isinstance(value, dict) else (value if isinstance(value, list) else ()):
                if not isinstance(row, dict):
                    continue
                _harvest(names, row, own_fields)
                for key, fields in nested:
                    entries = row.get(key)
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        _harvest(names, entry, fields)
    return tuple(sorted(names))
