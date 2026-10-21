"""Where does this service hang - from VIP to backend - and what do I touch?

Mirrors NSHC's `serviceChains`/`relationships` (inventory schema,
backend/deep/New-NshcDeepDiveReport.ps1). Three verdicts and nothing in
between: `keten compleet`, `gat in de keten` (with WHERE), `niet vastgesteld`.

THE ONE RULE THAT MATTERS HERE, and it is the reason issue #8 lists it as a
test: an unreadable binding file is `niet vastgesteld`, NEVER "geen backends".
The second is a statement about the appliance; the first is a statement about
this export. A chain that comes out empty because a file could not be parsed
is exactly the false green this product exists to prevent.

WHY `Export.binding_rows()` AND NOT THE FLAT `Export.bindings()`: the flat
list drops which PARENT a row came from, and with it the difference between
"this vserver's own parent entry is simply absent from the binding file" and
"this vserver was read and genuinely has zero bindings" - exactly the false
green `Export.binding_parents()` exists to catch one layer up (parent list
vs. object source), and export.py's own module docstring warns about
directly. `binding_rows()` keeps that distinction (`{parentName:
rows-or-None}`, a key absent from the dict was never read at all), and reads
the aggregate shape the real collector writes for these files per child key
(`ENTRY_CHILDREN`, `MEMBER_CHILD`), so a servicegroup row is never also read
as a service.

WHAT IS FOLLOWED: a loadbalancing-vserver to its servicegroups and services,
and a servicegroup to its members. A contentswitching-vserver is followed
too, through its OWN two routes (`csvserver_binding.by-parent.json`, read
per child key exactly like the LB binding file above): its standard load
balancer (`csvserver_lbvserver_binding`) and its policies
(`csvserver_cspolicy_binding`, resolved through `cspolicy.action` ->
`csaction.targetlbvserver` when a binding row carries no `targetlbvserver`
of its own) - each continued into the SAME loadbalancing-vserver chain
already computed above it, never a second walk. A policy that cannot be
resolved this way - `cspolicy`/`csaction` not readable in the export
(absent, RBAC_DENIED, a bad hash, ...), or a `policyname`/`action`
reference inside them that leads nowhere, or an action whose target is not
a loadbalancing-vserver (`targetvserver`/`targetvserverexpr`: CS to CS, or
a Unified Gateway action) - makes the WHOLE route `niet vastgesteld` with
the reason, and the answer then names only the standard load balancer and
the policy NAMES: what the binding file itself carries, without the
resolution this version cannot make; the standard load balancer is not
followed further either in that case. A contentswitching-vserver whose own
document carries neither of those two routes but another nested kind (a
GSLB-vserver, a VPN-vserver, or a kind this version has no rule for) is
`niet vastgesteld` with that kind named, never `gat in de keten`: the kind
is the route, and this version does not follow it. Next to a followed route,
such a kind makes the whole route `niet vastgesteld` too - unless it is a
policy binding (responder, rewrite and the like), which routes to no other
vserver and leaves the verdict alone. A Gateway-vserver is `niet
vastgesteld` with the reason in `NOT_FOLLOWED`: its session chain is not
taken in this version. Asked about ALL chains, the answer opens with a
summary line (`_summary_finding`).

Loose objects - a servicegroup nothing points at, an lbvserver without a
backend, a service bound to nothing - get their own block. Never silently
dropped: an object outside every chain is exactly what an administrator wants
to see. And - the same rule, one level up - a "geen" on that block is only
honest when the two sources behind it were actually read; if either failed,
the block says so instead of quietly agreeing with the favourable answer.

WHAT THIS CANNOT SAY: whether traffic really flows this way (that needs a
trace), and what the effective Gateway session policy is (that needs lab
evidence for the priority behaviour, deliberately deferred until after 1.0).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.expiry import binding_kind_names
from nsmcp.export import MISSING as _UNSEEN, field_gap as _field_gap, identity_shape_clause as _identity_shape_clause
from nsmcp.knowledge import Knowledge
from nsmcp.ssl_precedence import field_text

# (label, object resource, identity field, entry's OWN by-parent binding file)
ENTRY_RESOURCES = (
    ("Contentswitching-vserver", "config/csvserver", "name", "csvserver_binding.by-parent.json"),
    ("Loadbalancing-vserver", "config/lbvserver", "name", "lbvserver_binding.by-parent.json"),
    ("Gateway-vserver", "config/vpnvserver", "name", "vpnvserver_binding.by-parent.json"),
)
SERVICEGROUP_RESOURCE = "config/servicegroup"
SERVICE_RESOURCE = "config/service"
SERVICEGROUP_BINDING = "servicegroup_binding.by-parent.json"

CHAIN_WORDS = ("keten compleet", "gat in de keten", "niet vastgesteld")
LINK_LABELS = ("ingang", "backendgroep", "lid", "lb-doel", "beleid")

# The nested lists of the AGGREGATE shape this module reads, each through its
# OWN field (`Export.binding_rows`, asked per child key). MEASURED on the DoH
# fixture: a row of `lbvserver_servicegroup_binding` carries `servicename ==
# servicegroupname`, so reading "servicename" on it would turn every
# servicegroup into a service as well. Under the aggregate shape a row in one
# of these lists IS an attachment of that kind, so its name field is required:
# a row without it attaches to something unnamed, never to nothing.
GROUP_CHILD = "lbvserver_servicegroup_binding"
SERVICE_CHILD = "lbvserver_service_binding"
MEMBER_CHILD = "servicegroup_servicegroupmember_binding"
ENTRY_CHILDREN = (GROUP_CHILD, SERVICE_CHILD)
_CHILD_TARGET_FIELDS = {
    GROUP_CHILD: (("servicegroupname", True),),
    SERVICE_CHILD: (("servicename", True),),
}
# The list shape carries no child type per row: a row names a servicegroup, a
# service, or neither (an honest zero), exactly as this module always read it.
_LIST_TARGET_FIELDS = (("servicegroupname", False), ("servicename", False))

# The two child lists a contentswitching-vserver's OWN by-parent binding file
# carries (measured on the collector output, `csvserver_binding.by-parent.json`,
# aggregate shape, exactly like the LB binding file above): the standard
# load balancer and the bound policies. Each row identifies itself through
# its OWN required field - `lbvserver` for a default-LB row, `policyname`
# for a policy row - so, unlike the LB group/service pair, there is no
# either/or ambiguity per row and no need for `_CHILD_TARGET_FIELDS`' table.
CS_LBVSERVER_CHILD = "csvserver_lbvserver_binding"
CS_POLICY_CHILD = "csvserver_cspolicy_binding"
CS_CHILDREN = (CS_POLICY_CHILD, CS_LBVSERVER_CHILD)

# The reason for a contentswitching-vserver whose binding rows were read but
# are not grouped as either child above: the LIST shape of the same file,
# whose rows the shared reader hands over under the file's own binding
# resource. Which of those rows is a standard load balancer and which a
# policy is not something this version guesses from the fields of a row, so
# the route is not established - never "gat in de keten", which would claim
# a known absence of a route. Pinned in tests/test_product_surface.py.
CS_UNGROUPED_TEXT = (
    "{bestand} draagt voor {naam} bindingen in de lijstvorm, niet gegroepeerd als standaard load balancer"
    " of csbeleid; die vorm volgt deze versie voor een contentswitchingroute niet; niet vast te stellen"
    " waarnaar deze vserver routeert"
)

# The two object sources a policy row resolves through when it carries no
# `targetlbvserver` of its own: `cspolicy` names the ACTION bound to a
# policy (field `action`), `csaction` names the target load balancer of an
# action (field `targetlbvserver`). Neither is an entry-point resource (see
# `ENTRY_RESOURCES`); a CS route only consults them, and only when at least
# one of its policy rows needs the indirection.
CSPOLICY_RESOURCE = "config/cspolicy"
CSACTION_RESOURCE = "config/csaction"

# The one entry kind this version does not follow past the entry, with the
# reason the answer gives. Never "gat in de keten": that claims a KNOWN
# absence of backends, and a Gateway-vserver reaches its backends through
# its session policies - a step this version does not take. A
# contentswitching-vserver used to be here too; it is now followed (see the
# module docstring's "WHAT IS FOLLOWED").
NOT_FOLLOWED = {
    "Gateway-vserver": "een Gateway-vserver hangt niet aan een servicegroup; die keten volgt deze versie niet",
}

NOT_ASSESSED = (
    NotAssessed(
        subject="werkelijk verkeerspad",
        reason="of het verkeer ook echt zo loopt vraagt een trace, geen configuratielezing",
    ),
    NotAssessed(
        subject="prioriteiten van Gateway-sessionpolicies",
        reason=(
            # Deliberately not "labbewijs" (lab-evidence): that word carries
            # "lab" as a literal substring, and the real export's own target
            # name IS "lab" (three lower-case letters, see export.py's
            # _gate_target_name measurement) - disclosure.py's masking
            # replaces that substring WHEREVER it occurs, so "labbewijs"
            # rendered as the garbled "object-19bewijs" at 'beperkt'/
            # 'minimaal'. MEASURED while building this module; "bewijs uit
            # een testomgeving" carries no such collision.
            "het prioriteitsgedrag bij sessionpolicies is zonder bewijs uit een testomgeving"
            " niet sluitend te bepalen; deze versie doet daar geen uitspraak over"
        ),
    ),
)

# The sentinel that separates "this parent has no entry at all in the
# binding file" from "this parent's own value is a real (possibly empty)
# list" or "this parent was read as genuinely EMPTY" (None, see
# `Export.grouped_bindings`). `dict.get(name, _UNSEEN)` is the only honest
# way to draw that line - `.get(name)` alone collapses "unseen" onto "read as
# EMPTY" (both come back None), which is exactly the false green this module
# exists to refuse (export.py's own module docstring, and `binding_parents()`
# one layer up for the same class of hole).
#
# This module reuses the shared `export.MISSING` sentinel under its own,
# more legible local name, rather than minting a second module-local
# "key absent" sentinel: `export.MISSING` is the one idiom for this question
# (export.py:605-614; `collect.py` and `dienst.py` already alias it the same
# way), and the MEANING is identical here - a `dict.get(key, sentinel)` probe
# for an absent key.


@dataclass(frozen=True)
class Link:
    label: str
    name: str
    detail: str = ""


@dataclass(frozen=True)
class Chain:
    entry: str
    kind: str
    verdict: str
    links: tuple[Link, ...] = ()
    gap_at: str = ""
    reason: str = ""


def _usable_text(value) -> str | None:
    """Only real text counts as a name. Same discipline (and deliberately the
    same shape) as `_usable_text` in export.py/dienst.py and `_readable_name`
    in impact.py/disclosure.py: the isinstance gate sits BEFORE the
    normalization, so a list/dict/number/boolean/None is never blindly
    stringified into something that happens not to match.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


# `_field_gap` and `_identity_shape_clause` used to be defined here, a
# byte-for-byte copy of expiry.py's own helpers (~45 lines, including Dutch
# phrasing already corrected twice under review). A later review
# promoted both to
# `nsmcp.export.field_gap` / `nsmcp.export.identity_shape_clause`; both
# `expiry.py` and this module import them under their original local names
# now, so every call site below is unchanged.


# A port is a number: NITRO writes it as an integer or as a numeric string -
# never a bool (which IS an int subclass in Python, and "True"/"False" is not
# a port). Same discipline as dienst.py's `_member_port`/`_PORT_TEXT` (the
# same collector, the same kind of field); kept local and simplified to text-
# or-empty because chain.py's use of a port is purely decorative (it never
# steers a verdict, unlike dienst.py's own rendered failure reason).
_PORT_TEXT = re.compile(r"[0-9]{1,5}")


def _port_text(raw) -> str:
    if isinstance(raw, bool):
        return ""
    if isinstance(raw, int):
        return str(raw)
    text = raw.strip() if isinstance(raw, str) else ""
    return text if _PORT_TEXT.fullmatch(text) else ""


def _endpoint_detail(address: str, port: str) -> str:
    if address and port:
        return f"{address}:{port}"
    if address:
        return address
    if port:
        return f"poort {port}"
    return ""


def _member_identity_gap(row: dict) -> str | None:
    """None when a servicegroup member row names itself (by `servername` OR
    `ip`); the shape clause otherwise. A member with NEITHER is not an
    honest zero - NITRO writes one of the two on every real member binding
    row - so both are `required=True`, the same "row's own identity, no
    excuse" treatment expiry.py gives `certkeyname`/`vservername`.
    """
    if field_text(row, "servername") or field_text(row, "ip"):
        return None
    shapes = {
        s
        for s in (
            _field_gap(row, "servername", required=True),
            _field_gap(row, "ip", required=True),
        )
        if s is not None
    }
    return _identity_shape_clause("een lid draagt servername of ip", shapes) if shapes else None


def _entry_resource_gaps(export) -> tuple[ReadGap, ...]:
    """The read gap, if any, of each entry-point resource's OWN object read.

    `chains_of()` below correctly produces no `Chain` at all for a resource
    it could not even enumerate - there is no vserver name to hang one on.
    But silence is not the same as an honest answer: a resource this version
    could not read (RBAC_DENIED, a bad hash, an absent manifest entry) is not
    "zero Gateway-vservers", it is unknown, and `service_chain()` needs that
    surfaced in `read_gaps` rather than the answer quietly having one fewer
    chapter. Kept separate from `chains_of()` (which only needs to know
    whether a gap exists, in order to skip building chains for that kind) so
    the "produce nothing for an unreadable kind" and "say something happened"
    concerns each stay in the one place they belong.
    """
    gaps: list[ReadGap] = []
    for _kind, resource, _key, _binding_file in ENTRY_RESOURCES:
        _rows, gap = export.objects(resource)
        if gap is not None:
            gaps.append(gap)
    return tuple(gaps)


def _target_fields(child_key: str) -> tuple[tuple[str, bool], ...]:
    """(field, required) per name field a binding row of this kind carries."""
    return _CHILD_TARGET_FIELDS.get(child_key, _LIST_TARGET_FIELDS)


def _lbvserver_chains(export) -> tuple[tuple[Chain, ...], dict[str, Chain], ReadGap | None]:
    """Every Loadbalancing-vserver's own Chain - the entry-to-member walk
    this module has always done, unchanged, only pulled out of `chains_of()`
    so a contentswitching route can look up an already-known verdict for
    its own resolved target (see the module docstring's "WHAT IS FOLLOWED")
    instead of a second derivation.

    Returned three ways: the ORDERED tuple (what `chains_of()` appends for
    the LB chapter, byte-identical to what this function's body produced
    inline before this extraction), a `{entry name: Chain}` dict for a CS
    route's O(1) lookup (last one wins on a duplicate entry name - not a
    real NetScaler configuration, unmeasured, and every OTHER caller still
    sees every entry through the ordered tuple), and the entry SOURCE's own
    read gap. That third value is NOT the same question the dict already
    answers: a target name absent from the dict because `config/lbvserver`
    itself could not even be enumerated is unknown, while a target name
    absent from the dict because that name simply is not among the
    (successfully read) entries is an established gap - the same
    distinction `chains_of()` has always drawn for `_UNSEEN` below.
    """
    members, members_gap = export.binding_rows(SERVICEGROUP_BINDING, children=(MEMBER_CHILD,))
    kind, resource, key, binding_file = next(t for t in ENTRY_RESOURCES if t[0] == "Loadbalancing-vserver")
    entries, entry_gap = export.objects(resource)
    if entry_gap is not None or not entries:
        # A read gap here is `_entry_resource_gaps()`'s job to surface to
        # the answer, not this function's - see its docstring. An honestly
        # EMPTY resource (no gap, zero rows) needs no binding read at all.
        return (), {}, entry_gap
    entry_bindings, binding_gap = export.binding_rows(binding_file, children=ENTRY_CHILDREN)

    chains: list[Chain] = []
    for row in entries:
        name = _usable_text(row.get(key)) or "(naamloos)"
        address = field_text(row, "ipv46")
        port = _port_text(row.get("port"))
        entry_link = Link("ingang", name, _endpoint_detail(address, port))

        if binding_gap is not None:
            chains.append(Chain(name, kind, "niet vastgesteld", (entry_link,), "backendgroep", binding_gap.reason))
            continue

        raw_rows = entry_bindings.get(name, _UNSEEN)
        if raw_rows is _UNSEEN:
            # THE hole `Export.grouped_bindings()` exists to make visible:
            # this vserver's OWN parent entry is simply absent from the
            # binding file. Never "gat in de keten" (that claims a KNOWN
            # absence of backends) - the bindings of this specific vserver
            # were never read at all.
            chains.append(
                Chain(
                    name,
                    kind,
                    "niet vastgesteld",
                    (entry_link,),
                    "backendgroep",
                    f"{binding_file} draagt geen parent-vermelding voor {name}; de bindingen van"
                    " deze dienst zijn niet gelezen",
                )
            )
            continue
        # `None` (a parent read as genuinely EMPTY) and `[]` (a parent read
        # as OK with zero rows) are two different collector signals for the
        # SAME fact - both a confirmed, established zero - and are treated
        # identically from here on.
        rows = raw_rows if raw_rows is not None else []

        groups: list[str] = []
        services: list[str] = []
        unreadable: set[str] = set()
        for child_key, binding_row in rows:
            # Each target field is probed on its OWN absence, independently
            # of the other: a row with ONE readable field and ONE
            # unreadable field (`{"servicegroupname": "SG_A", "servicename":
            # true}`) must not silently drop the unreadable attachment. A
            # field that IS present but unreadable PROVES this row attaches
            # to something, with only its name unreadable - the same
            # distinction expiry.py draws for `_cert_binding_target` - and
            # that proof does not depend on the OTHER field's fate. Under
            # the aggregate shape the row's kind is known, so only that
            # kind's field is read, and it is required (see
            # `_CHILD_TARGET_FIELDS`).
            for field_name, required in _target_fields(child_key):
                value = field_text(binding_row, field_name)
                if value:
                    target = groups if field_name == "servicegroupname" else services
                    if value not in target:
                        target.append(value)
                    continue
                shape = _field_gap(binding_row, field_name, required=required)
                if shape is not None:
                    unreadable.add(shape)

        if unreadable:
            reason = _identity_shape_clause(
                f"een binding van {name} draagt servicegroupname of servicename", unreadable
            )
            chains.append(
                Chain(
                    name,
                    kind,
                    "niet vastgesteld",
                    (entry_link,),
                    "backendgroep",
                    reason + "; niet vast te stellen of, en waaraan, deze dienst hangt",
                )
            )
            continue

        if not groups and not services:
            chains.append(
                Chain(
                    name,
                    kind,
                    "gat in de keten",
                    (entry_link,),
                    "backendgroep",
                    f"{binding_file} draagt voor {name} geen servicegroup en geen service",
                )
            )
            continue

        links = [entry_link]
        gap_at = ""
        reason = ""
        unread = False
        for group in groups:
            links.append(Link("backendgroep", group))
            if members_gap is not None:
                gap_at = gap_at or "lid"
                reason = reason or members_gap.reason
                unread = True
                continue
            member_rows = members.get(group, _UNSEEN)
            if member_rows is _UNSEEN:
                gap_at = gap_at or "lid"
                reason = reason or (
                    f"{SERVICEGROUP_BINDING} draagt geen parent-vermelding voor {group}; de"
                    " leden van deze servicegroup zijn niet gelezen"
                )
                unread = True
                continue
            # `None` (a parent read as genuinely EMPTY) and `[]` (a parent
            # read as OK with zero rows) are two different collector
            # signals for the SAME fact - both a confirmed, established
            # zero members, so neither `continue`s with no gap at all: a
            # servicegroup with a confirmed zero members must not render
            # `keten compleet` - a false-green statement about a VIP that
            # provably reaches no backend. A confirmed zero is `gat in de
            # keten` at `lid` - the SAME word this function already gives,
            # one level up, to the identical established-zero situation on
            # an entry binding row with neither servicegroup nor service -
            # never the favourable `keten compleet`, and never `niet
            # vastgesteld` either: this group WAS read, and it definitively
            # has no members.
            rows = member_rows if member_rows is not None else []
            if not rows:
                gap_at = gap_at or "lid"
                reason = reason or f"{SERVICEGROUP_BINDING} draagt geen lid voor {group}"
                continue
            for position, (_child_key, member_row) in enumerate(rows, start=1):
                identity_gap = _member_identity_gap(member_row)
                if identity_gap is not None:
                    gap_at = gap_at or "lid"
                    reason = reason or f"lid {position} van {group}: {identity_gap}"
                    unread = True
                    continue
                who = field_text(member_row, "servername") or field_text(member_row, "ip")
                links.append(Link("lid", who, _port_text(member_row.get("port"))))
        for service in services:
            links.append(Link("backendgroep", service))

        # `unread` (some part of the chain was never actually read - the
        # whole servicegroup-binding file, a group's own parent entry, or
        # one member row's identity) always wins over a confirmed gap: this
        # tool cannot assert a KNOWN absence while part of the picture is
        # still unknown. Only when everything that WAS read is fully
        # accounted for, and it adds up to a confirmed zero somewhere, does
        # the verdict become `gat in de keten` rather than `niet
        # vastgesteld`.
        if unread:
            chains.append(Chain(name, kind, "niet vastgesteld", tuple(links), gap_at, reason))
        elif gap_at:
            chains.append(Chain(name, kind, "gat in de keten", tuple(links), gap_at, reason))
        else:
            chains.append(Chain(name, kind, "keten compleet", tuple(links)))

    ordered = tuple(chains)
    by_name = {c.entry: c for c in ordered}
    return ordered, by_name, entry_gap


def _cspolicy_index(export) -> tuple[dict[str, str], ReadGap | None]:
    """`policyname -> action`, for every `cspolicy` object with both fields
    readable. Read once per `chains_of()` call; a CS route only consults
    this when one of its `csvserver_cspolicy_binding` rows carries no
    `targetlbvserver` of its own."""
    rows, gap = export.objects(CSPOLICY_RESOURCE)
    if gap is not None:
        return {}, gap
    index: dict[str, str] = {}
    for row in rows:
        policyname = field_text(row, "policyname")
        action = field_text(row, "action")
        if policyname and action:
            index[policyname] = action
    return index, None


def _csaction_index(export) -> tuple[dict[str, str], dict[str, str], ReadGap | None]:
    """`action name -> targetlbvserver`, for every `csaction` object with
    both fields readable - the second half of the policy route
    `_cspolicy_index` above starts.

    The second dict names, for an action whose target is NOT a
    loadbalancing-vserver, why this version cannot follow it there:
    `targetvserver`/`targetvserverexpr` (a real NetScaler action shape -
    content switching straight to another content-switching vserver, or a
    Unified Gateway action from a CS vserver to a VPN vserver) is a
    DIFFERENT, KNOWN fact from `targetlbvserver` simply being unreadable or
    absent - `_cs_chain()` must not describe the one as the other.
    """
    rows, gap = export.objects(CSACTION_RESOURCE)
    if gap is not None:
        return {}, {}, gap
    target_index: dict[str, str] = {}
    nonlb_index: dict[str, str] = {}
    for row in rows:
        action = field_text(row, "name")
        if not action:
            continue
        target = field_text(row, "targetlbvserver")
        if target:
            target_index[action] = target
            continue
        other = field_text(row, "targetvserver") or field_text(row, "targetvserverexpr")
        if other:
            nonlb_index[action] = other
    return target_index, nonlb_index, None


def _cs_chain(
    name: str,
    kind: str,
    entry_link: Link,
    binding_file: str,
    rows,
    lb_by_name: dict[str, Chain],
    lb_entry_gap: ReadGap | None,
    cspolicy_index: dict[str, str],
    cspolicy_gap: ReadGap | None,
    csaction_index: dict[str, str],
    csaction_nonlb_index: dict[str, str],
    csaction_gap: ReadGap | None,
    *,
    other_kinds: tuple[str, ...] = (),
) -> Chain:
    """One contentswitching-vserver's route: its standard load balancer
    (`CS_LBVSERVER_CHILD`) and its policies (`CS_POLICY_CHILD`, resolved to
    a target either directly from the row or through `cspolicy.action` ->
    `csaction.targetlbvserver`), each continued into the SAME
    Loadbalancing-vserver chain `_lbvserver_chains()` already computed -
    never a second walk of servicegroup/member data.

    `other_kinds` are the nested binding kinds this vserver's own document
    carries outside `CS_CHILDREN` (a GSLB-vserver, a VPN-vserver, or a kind
    this version has no rule for). Without a standard load balancer and
    without a policy, such a kind is the route - one this version does not
    follow - so the verdict is "niet vastgesteld", never "gat in de keten".
    Next to a followed route, every such kind except a policy binding
    (`*policy_binding`: responder, rewrite and the like) makes the whole
    route "niet vastgesteld" as well, with the kind named.

    A row that is neither child (`CS_CHILDREN`) - the list shape of the
    binding file - makes the route "niet vastgesteld" too
    (`CS_UNGROUPED_TEXT`): the rows were read, so their absence from the
    two children is no known absence of a route.
    """
    default_lb: list[str] = []
    policy_names: list[str] = []
    policy_direct: dict[str, str] = {}
    identity_unreadable: set[str] = set()
    ungrouped = False

    for child_key, binding_row in rows:
        if child_key not in CS_CHILDREN:
            ungrouped = True
        elif child_key == CS_LBVSERVER_CHILD:
            value = field_text(binding_row, "lbvserver")
            if value:
                if value not in default_lb:
                    default_lb.append(value)
                continue
            shape = _field_gap(binding_row, "lbvserver", required=True)
            if shape is not None:
                identity_unreadable.add(
                    _identity_shape_clause(f"een standaard-LB-binding van {name} draagt lbvserver", {shape})
                )
        elif child_key == CS_POLICY_CHILD:
            pname = field_text(binding_row, "policyname")
            if not pname:
                shape = _field_gap(binding_row, "policyname", required=True)
                if shape is not None:
                    identity_unreadable.add(
                        _identity_shape_clause(f"een beleidsbinding van {name} draagt policyname", {shape})
                    )
                continue
            if pname not in policy_names:
                policy_names.append(pname)
            direct = field_text(binding_row, "targetlbvserver")
            if direct:
                policy_direct[pname] = direct
            else:
                # `targetlbvserver` PRESENT but unreadable (a list, a
                # number, ...) is a genuine identity problem, not "go
                # resolve through cspolicy instead" - the same "present but
                # unreadable proves an attachment, absent does not"
                # distinction `_lbvserver_chains()` draws for its own
                # binding rows. Only `required=False` here: the field is
                # legitimately, commonly ABSENT (most policy rows resolve
                # through cspolicy/csaction, never carrying it at all).
                shape = _field_gap(binding_row, "targetlbvserver", required=False)
                if shape is not None:
                    identity_unreadable.add(
                        _identity_shape_clause(f"een beleidsbinding van {name} draagt targetlbvserver", {shape})
                    )

    if ungrouped:
        return Chain(
            name,
            kind,
            "niet vastgesteld",
            (entry_link,),
            "lb-doel",
            CS_UNGROUPED_TEXT.format(bestand=binding_file, naam=name),
        )

    if identity_unreadable:
        # No further info than the entry itself: unlike the "cspolicy/
        # csaction missing" branch below, this vserver's OWN binding rows
        # did not even identify themselves, so there is no standard-LB name
        # or policy name to show either.
        return Chain(
            name,
            kind,
            "niet vastgesteld",
            (entry_link,),
            "lb-doel",
            "; ".join(sorted(identity_unreadable)) + "; niet vast te stellen waarnaar deze vserver routeert",
        )

    if not default_lb and not policy_names:
        if other_kinds:
            # The same rule the certificate side follows for a kind it does
            # not read (expiry.py, impact.py): seen, so never read as "no
            # route at all".
            return Chain(
                name,
                kind,
                "niet vastgesteld",
                (entry_link,),
                "lb-doel",
                f"{binding_file} draagt voor {name} geen standaard load balancer en geen csbeleid, wel een"
                f" bindingssoort die deze versie niet leest ({binding_kind_names(other_kinds)}); niet vast te"
                " stellen waarnaar deze vserver routeert",
            )
        return Chain(
            name,
            kind,
            "gat in de keten",
            (entry_link,),
            "lb-doel",
            f"{binding_file} draagt voor {name} geen standaard load balancer en geen csbeleid",
        )

    resolved: list[str] = list(default_lb)
    policy_unresolved: set[str] = set()
    for pname in policy_names:
        if pname in policy_direct:
            target = policy_direct[pname]
        elif cspolicy_gap is not None:
            policy_unresolved.add(f"cspolicy is niet vast te stellen: {cspolicy_gap.reason}")
            continue
        else:
            action = cspolicy_index.get(pname)
            if action is None:
                policy_unresolved.add(f"beleid {pname} van {name} heeft geen leesbare actie in cspolicy")
                continue
            if csaction_gap is not None:
                policy_unresolved.add(f"csaction is niet vast te stellen: {csaction_gap.reason}")
                continue
            target = csaction_index.get(action)
            if target is None:
                if action in csaction_nonlb_index:
                    # A KNOWN, different fact from "no leesbaar doel": this
                    # action DOES carry a target, just not a
                    # loadbalancing-vserver (targetvserver/
                    # targetvserverexpr - CS to CS, or Unified Gateway CS to
                    # VPN). Never describe the one as the other.
                    policy_unresolved.add(
                        f"actie {action} van beleid {pname} verwijst naar een vserver die geen"
                        " loadbalancing-vserver is; die stap volgt deze versie niet"
                    )
                else:
                    policy_unresolved.add(f"actie {action} van beleid {pname} heeft geen leesbaar doel in csaction")
                continue
        if target not in resolved:
            resolved.append(target)

    unresolved_at = "beleid" if policy_unresolved else "lb-doel"
    # Next to a followed route, a kind outside CS_CHILDREN that can route
    # elsewhere (a VPN or GSLB vserver, or a kind without a rule here) is the
    # same fact an action with a non-LB target is above: part of the route
    # this version does not follow. A policy binding (responder, rewrite and
    # the like: the kind ends in `policy_binding`) routes to no other
    # vserver, so it leaves the verdict alone.
    routing_kinds = tuple(k for k in other_kinds if not k.endswith("policy_binding"))
    if routing_kinds:
        policy_unresolved.add(
            f"{binding_file} draagt voor {name} ook een bindingssoort die deze versie niet leest"
            f" ({binding_kind_names(routing_kinds)}); die route volgt deze versie niet"
        )

    if policy_unresolved:
        # One policy this vserver's own binding row names could not be
        # resolved to a target - whether because cspolicy/csaction are not
        # in the export, or because a policy/action reference inside them
        # does not lead anywhere - or the document carries a route this
        # version does not follow: either way the final route cannot be
        # established, so the answer shows exactly what the binding file
        # itself carries (the standard load balancer, the policy NAMES) and
        # nothing derived - never a partial route dressed up as complete.
        links = [entry_link]
        links.extend(Link("lb-doel", lb) for lb in default_lb)
        links.extend(Link("beleid", p) for p in policy_names)
        return Chain(
            name,
            kind,
            "niet vastgesteld",
            tuple(links),
            unresolved_at,
            "; ".join(sorted(policy_unresolved))
            + "; alleen de standaard load balancer en de beleidsnamen zijn hier vastgesteld",
        )

    links = [entry_link]
    gap_at = ""
    reason = ""
    unread = False
    for target in resolved:
        links.append(Link("lb-doel", target))
        sub_chain = lb_by_name.get(target)
        if sub_chain is None:
            if lb_entry_gap is not None:
                unread = True
                gap_at = gap_at or "lb-doel"
                reason = reason or f"config/lbvserver is niet gelezen: {lb_entry_gap.reason}"
            else:
                gap_at = gap_at or "lb-doel"
                reason = reason or (
                    f"{name} routeert naar loadbalancing-vserver {target}, die niet voorkomt in config/lbvserver"
                )
            continue
        links.extend(sub_chain.links[1:])  # every link but its own "ingang"
        if sub_chain.verdict == "niet vastgesteld":
            unread = True
            gap_at = gap_at or sub_chain.gap_at or "lb-doel"
            reason = reason or sub_chain.reason
        elif sub_chain.verdict == "gat in de keten":
            gap_at = gap_at or sub_chain.gap_at or "lb-doel"
            reason = reason or sub_chain.reason

    # Same priority as `_lbvserver_chains()` above, one level up: `unread`
    # always wins over a confirmed gap.
    if unread:
        return Chain(name, kind, "niet vastgesteld", tuple(links), gap_at, reason)
    if gap_at:
        return Chain(name, kind, "gat in de keten", tuple(links), gap_at, reason)
    return Chain(name, kind, "keten compleet", tuple(links))


def chains_of(export) -> tuple[Chain, ...]:
    lb_list, lb_by_name, lb_entry_gap = _lbvserver_chains(export)
    cspolicy_index, cspolicy_gap = _cspolicy_index(export)
    csaction_index, csaction_nonlb_index, csaction_gap = _csaction_index(export)
    chains: list[Chain] = []

    for kind, resource, key, binding_file in ENTRY_RESOURCES:
        if kind == "Loadbalancing-vserver":
            # Computed once, above, so a contentswitching route can look up
            # an already-known verdict for its own resolved target - see
            # `_lbvserver_chains()`'s own docstring.
            chains.extend(lb_list)
            continue

        entries, entry_gap = export.objects(resource)
        if entry_gap is not None or not entries:
            # A read gap here is `_entry_resource_gaps()`'s job to surface,
            # not this function's - see its docstring. An honestly EMPTY
            # resource (no gap, zero rows) needs no binding read at all.
            continue
        not_followed = NOT_FOLLOWED.get(kind)
        if not_followed is None:
            entry_bindings, binding_gap = export.binding_rows(binding_file, children=CS_CHILDREN)
            # Which nested kinds each document carries, through the same
            # trust chain: a kind outside CS_CHILDREN is seen, not skipped.
            entry_kinds: dict[str, tuple[str, ...]] = {}
            if binding_gap is None:
                entry_kinds, binding_gap = export.binding_child_keys(binding_file)

        for row in entries:
            name = _usable_text(row.get(key)) or "(naamloos)"
            address = field_text(row, "ipv46")
            port = _port_text(row.get("port"))
            entry_link = Link("ingang", name, _endpoint_detail(address, port))

            if not_followed is not None:
                chains.append(Chain(name, kind, "niet vastgesteld", (entry_link,), "", not_followed))
                continue

            # Only the Contentswitching-vserver kind reaches this point:
            # every other entry kind either short-circuits above
            # (Loadbalancing-vserver) or is a NOT_FOLLOWED kind.
            if binding_gap is not None:
                chains.append(Chain(name, kind, "niet vastgesteld", (entry_link,), "lb-doel", binding_gap.reason))
                continue

            raw_rows = entry_bindings.get(name, _UNSEEN)
            if raw_rows is _UNSEEN:
                # Same hole as `_lbvserver_chains()` draws for its own
                # entries: this vserver's OWN parent entry is simply absent
                # from the binding file, never "gat in de keten".
                chains.append(
                    Chain(
                        name,
                        kind,
                        "niet vastgesteld",
                        (entry_link,),
                        "lb-doel",
                        f"{binding_file} draagt geen parent-vermelding voor {name}; de bindingen van"
                        " deze vserver zijn niet gelezen",
                    )
                )
                continue
            # Same two-different-honest-zeros distinction as everywhere
            # else in this module: `None` and `[]` both mean a confirmed,
            # established zero rows.
            rows = raw_rows if raw_rows is not None else []

            chains.append(
                _cs_chain(
                    name,
                    kind,
                    entry_link,
                    binding_file,
                    rows,
                    lb_by_name,
                    lb_entry_gap,
                    cspolicy_index,
                    cspolicy_gap,
                    csaction_index,
                    csaction_nonlb_index,
                    csaction_gap,
                    other_kinds=tuple(k for k in entry_kinds.get(name, ()) if k not in CS_CHILDREN),
                )
            )
    return tuple(chains)


def route_source_gaps(export) -> tuple[ReadGap, ...]:
    """The policy sources (`config/cspolicy`, `config/csaction`) a
    contentswitching route of THIS export asks for and cannot read.

    A policy row without a `targetlbvserver` of its own is resolved through
    both (`_cs_chain()`); a read gap on either makes that route "niet
    vastgesteld". `rapport_dekking` names the same sources from here, so its
    verdict is never "volledig" where `dienst_keten` could not establish a
    route for that reason. Empty when no route asks for them: a source
    nothing on this export reads costs no coverage. Also empty when the
    entries or their binding file cannot be read - `dienst_keten` then says
    so itself, for that reason, not for this one.
    """
    _kind, resource, _key, binding_file = next(e for e in ENTRY_RESOURCES if e[0] == "Contentswitching-vserver")
    entries, entry_gap = export.objects(resource)
    if entry_gap is not None or not entries:
        return ()
    grouped, binding_gap = export.binding_rows(binding_file, children=CS_CHILDREN)
    if binding_gap is not None:
        return ()
    asks = any(
        child == CS_POLICY_CHILD and field_text(row, "policyname") and not field_text(row, "targetlbvserver")
        for rows in grouped.values()
        if rows
        for child, row in rows
    )
    if not asks:
        return ()
    _policies, cspolicy_gap = _cspolicy_index(export)
    _targets, _other_targets, csaction_gap = _csaction_index(export)
    return tuple(
        ReadGap(source=source, reason=gap.reason)
        for source, gap in ((CSPOLICY_RESOURCE, cspolicy_gap), (CSACTION_RESOURCE, csaction_gap))
        if gap is not None
    )


def _loose_objects(export) -> tuple[tuple[str, ...], tuple[ReadGap, ...]]:
    """Groups and services no chain points at, plus the read gaps of the two
    sources behind that claim.

    An empty result is honest ONLY when both sources were actually read -
    the caller must check the second element before calling the first
    "geen": a resource this version could not read is not "no loose
    objects", it is unknown, and reporting "geen [vastgesteld]" on THAT
    ground is exactly the false green this whole module exists to prevent,
    one block further along than the chain itself.
    """
    used: set[str] = set()
    for chain in chains_of(export):
        for link in chain.links:
            if link.label == "backendgroep":
                used.add(link.name)
    loose: set[str] = set()
    gaps: list[ReadGap] = []
    for resource, key in ((SERVICEGROUP_RESOURCE, "servicegroupname"), (SERVICE_RESOURCE, "name")):
        rows, gap = export.objects(resource)
        if gap is not None:
            gaps.append(gap)
            continue
        for row in rows:
            name = _usable_text(row.get(key)) or "(naamloos)"
            if name not in used:
                loose.add(name)
    return tuple(sorted(loose)), tuple(gaps)


def _summary_finding(chains: tuple[Chain, ...], entry_gaps: tuple[ReadGap, ...]) -> Finding:
    """The line that opens an answer about ALL chains: how many, and how many
    per verdict, in the pinned chain words - only the verdicts that occur, so
    the line never carries a verdict word no chain received. A summary of the
    findings under it, so it does not count again at 'minimaal'. Established
    only when every entry source was read: a count over sources that were not
    all read is not a count of the chains on this appliance."""
    counts = [(sum(1 for c in chains if c.verdict == word), word) for word in CHAIN_WORDS]
    per_verdict = ", ".join(f"{count} {word}" for count, word in counts if count)
    per_kind = ", ".join(
        f"{sum(1 for c in chains if c.kind == kind)} {kind}" for kind, _resource, _key, _file in ENTRY_RESOURCES
    )
    unread = ", ".join(gap.source for gap in entry_gaps)
    total = f"{len(chains)} {'keten' if len(chains) == 1 else 'ketens'}"
    return Finding(
        subject="samenvatting",
        outcome=f"{total}: {per_verdict}" if per_verdict else total,
        certainty=Certainty.NOT_ESTABLISHED if entry_gaps else Certainty.ESTABLISHED,
        evidence=f"ingangen: {per_kind}",
        reason=f"niet elke ingangsbron is gelezen: {unread}" if entry_gaps else "",
        subject_is_name=False,
        counted_at_minimal=False,
    )


def service_chain(export, knowledge: Knowledge, name: str) -> Answer:
    wanted = name.strip()
    chains = chains_of(export)
    if wanted:
        chains = tuple(c for c in chains if c.entry == wanted)

    entry_gaps = _entry_resource_gaps(export)
    findings: list[Finding] = [] if wanted else [_summary_finding(chains, entry_gaps)]
    read_gaps: list[ReadGap] = list(entry_gaps)

    for chain in chains:
        path = " -> ".join(link.name + (f" ({link.detail})" if link.detail else "") for link in chain.links)
        outcome = chain.verdict
        if chain.gap_at and chain.verdict == "gat in de keten":
            outcome = f"{chain.verdict} bij {chain.gap_at}"
        findings.append(
            Finding(
                subject=chain.entry,
                outcome=outcome,
                certainty=Certainty.NOT_ESTABLISHED if chain.verdict == "niet vastgesteld" else Certainty.ESTABLISHED,
                evidence=f"{chain.kind}: {path}",
                reason=chain.reason,
            )
        )
        if chain.verdict == "niet vastgesteld":
            read_gaps.append(ReadGap(source=chain.entry, reason=chain.reason or "keten niet te lezen"))

    loose, loose_gaps = _loose_objects(export)
    read_gaps.extend(loose_gaps)
    if loose_gaps:
        findings.append(
            Finding(
                subject="losse objecten",
                outcome="niet vast te stellen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"{SERVICEGROUP_RESOURCE}, {SERVICE_RESOURCE}",
                reason="; ".join(g.reason for g in loose_gaps),
                subject_is_name=False,
            )
        )
    else:
        findings.append(
            Finding(
                subject="losse objecten",
                outcome=", ".join(loose) if loose else "geen",
                certainty=Certainty.ESTABLISHED,
                evidence=f"{SERVICEGROUP_RESOURCE}, {SERVICE_RESOURCE}",
                subject_is_name=False,
            )
        )

    return Answer(
        question="waar hangt deze dienst aan, van VIP tot backend",
        findings=findings,
        read_gaps=read_gaps,
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_chain_sources(export) -> tuple[str, ...]:
    """Every appliance object name a chain can print - the THIRTEENTH family
    of `disclosure.names_from_export()`.

    The entry points overlap with the names family, but the
    MEMBERS do not always: a member by server name or by IP inside a
    servicegroup binding that `dienst_status` never touched appears in no
    other family. Read through this module's OWN derivation
    (`chains_of()`/`_loose_objects()`), so a chain that starts printing a
    new kind of link cannot leak it - and so a name that surfaces only
    inside a read-gap REASON (a servicegroup this file never recorded, say)
    is covered too: that name reaches a Link (`backendgroep`) before the gap
    is ever raised, never only the gap text.

    An entry vserver's OWN `ipv46` reaches the text too, inside its
    "ingang" link's `detail` - NOT its `name`, so the loop below does not
    see it. On the real fixture that address happens to be masked ANYWAY
    (mgmt_plane.py's own family also reads it, for an unrelated reason), but
    that is a coincidence this module must not depend on: a csvserver or
    lbvserver address no other family happens to read would otherwise leak
    unmasked at 'beperkt'. Harvested here, straight from `export.objects()`,
    independently of whatever `_endpoint_detail()` did with it.

    This field is read the same way `chains_of()` PRINTS it, through
    `field_text()`, which matches the key case-insensitively (NITRO/JSON
    promises no casing) rather than an exact-case `row.get("ipv46")` lookup:
    an export carrying `IPv46` would otherwise render the address into the
    answer text while this loop never saw it, so `render()` could not mask
    it at 'beperkt'/'minimaal' - an unmasked IP address reaching the reader.
    Same field, same accessor as the printing side.
    """
    names: set[str] = set()
    for chain in chains_of(export):
        names.add(chain.entry)
        for link in chain.links:
            if link.name and link.name != "?":
                names.add(link.name)
    for _kind, resource, _key, _binding_file in ENTRY_RESOURCES:
        rows, gap = export.objects(resource)
        if gap is not None:
            continue
        for row in rows:
            address = field_text(row, "ipv46")
            if address:
                names.add(address)

    # A policy or action name can surface inside a read-gap REASON without
    # ever becoming a Link at all - `_cs_chain()`'s own resolution failures
    # name the action ("actie {action} van beleid {pname} heeft geen
    # leesbaar doel in csaction", or the "geen loadbalancing-vserver"
    # clause for a `targetvserver`/`targetvserverexpr`) without printing
    # either as a Link, since the route past them could not be established.
    # Harvested here, straight from `export.objects()`, on the fields
    # `_cs_chain()`/`_cspolicy_index()`/`_csaction_index()` themselves read
    # to resolve a policy - the same over-harvest discipline as `ipv46`
    # above: every name a reason COULD print, not only the ones the current
    # code path happens to.
    for resource, fields in (
        (CSPOLICY_RESOURCE, ("policyname", "action")),
        (CSACTION_RESOURCE, ("name", "targetlbvserver", "targetvserver", "targetvserverexpr")),
    ):
        rows, gap = export.objects(resource)
        if gap is not None:
            continue
        for row in rows:
            for field in fields:
                value = field_text(row, field)
                if value:
                    names.add(value)

    names.update(_loose_objects(export)[0])
    return tuple(sorted(n for n in names if n))
