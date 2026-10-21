"""Derive security-header coverage from the exported response configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.export import field_gap
from nsmcp.knowledge import Knowledge
from nsmcp.ssl_precedence import field_text

ACTION_RESOURCE = "config/rewriteaction"
POLICY_RESOURCE = "config/rewritepolicy"
PROFILE_RESOURCE = "config/sslprofile"
VSERVER_RESOURCE = "config/sslvserver"
BINDING_RESOURCES = (
    "config/lbvserver_rewritepolicy_binding?bulkbindings=yes",
    "config/csvserver_rewritepolicy_binding?bulkbindings=yes",
    "config/vpnvserver_rewritepolicy_binding?bulkbindings=yes",
    "config/rewriteglobal_rewritepolicy_binding",
)

HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
)
HEADER_WORDS = (
    "aanwezig en gebonden",
    "wel gedefinieerd, niet gebonden",
    "afwezig",
    "niet beoordeeld",
)
HSTS = HEADERS[0]
_TARGET_ALIASES = {header.casefold(): header for header in HEADERS}
_TARGET_ALIASES["feature-policy"] = "Permissions-Policy"
# Complete current-release vocabularies from the NITRO rewriteaction and
# rewriteglobal_rewritepolicy_binding resource specifications. Keep these
# separate from the smaller sets that actually prove HTTP response coverage.
_ACTION_TYPES = frozenset(
    {
        "noop",
        "delete",
        "insert_http_header",
        "delete_http_header",
        "corrupt_http_header",
        "insert_before",
        "insert_after",
        "replace",
        "replace_http_res",
        "delete_all",
        "replace_all",
        "insert_before_all",
        "insert_after_all",
        "clientless_vpn_encode",
        "clientless_vpn_encode_all",
        "clientless_vpn_decode",
        "clientless_vpn_decode_all",
        "insert_sip_header",
        "delete_sip_header",
        "corrupt_sip_header",
        "replace_sip_res",
        "replace_diameter_header_field",
        "replace_dns_header_field",
        "replace_dns_answer_section",
        "replace_mqtt",
        "delete_mqtt",
        "insert_mqtt",
        "insert_before_mqtt",
        "insert_after_mqtt",
    }
)
_PROFILE_TYPES = frozenset({"frontend", "backend", "quic-frontend", "quic-backend"})
_HSTS_VALUES = frozenset({"enabled", "disabled"})
_LOCAL_BINDPOINTS = frozenset({"request", "response"})
_GLOBAL_TYPES = frozenset(
    f"{prefix}{direction}_{priority}"
    for prefix in ("", "othertcp_", "sipudp_", "siptcp_", "diameter_", "radius_", "dns_", "httpquic_", "mqtt_")
    for direction in ("req", "res")
    for priority in ("override", "default")
)
_GLOBAL_HTTP_RESPONSES = frozenset({"res_default", "res_override", "httpquic_res_default", "httpquic_res_override"})
_GLOBAL_RESOURCE = BINDING_RESOURCES[-1]


@dataclass(frozen=True)
class HeaderResult:
    header: str
    word: str
    vservers: tuple[str, ...] = ()
    evidence: str = ""
    reason: str = ""
    read_gaps: tuple[ReadGap, ...] = field(default_factory=tuple, repr=False)


def _rows(export, resource: str) -> tuple[list[dict], tuple[ReadGap, ...]]:
    rows, gap = export.objects(resource)
    if gap is not None:
        return [], (gap,)
    return [row for row in rows if isinstance(row, dict)], ()


def _field_read_gap(row: dict, resource: str, name: str) -> ReadGap | None:
    shape = field_gap(row, name)
    if shape is None:
        return None
    return ReadGap(source=f"{resource}.{name}", reason=f"veld is niet als tekst leesbaar: {shape}")


def _required_field_gap(row: dict, resource: str, name: str) -> ReadGap | None:
    shape = field_gap(row, name, required=True)
    if shape is None:
        return None
    return ReadGap(source=f"{resource}.{name}", reason=f"veld is niet als tekst leesbaar: {shape}")


def _vocabulary_gap(row: dict, resource: str, name: str, allowed: frozenset[str]) -> ReadGap | None:
    value = field_text(row, name)
    if not value or value.casefold() in allowed:
        return None
    return ReadGap(
        source=f"{resource}.{name}",
        reason="veld draagt tekst buiten het verwachte vocabulaire",
    )


def _binding_identity_gap(row: dict, resource: str) -> ReadGap | None:
    if field_text(row, "name") or field_text(row, "vservername"):
        return None
    name_shape = field_gap(row, "name", required=True)
    vserver_shape = field_gap(row, "vservername", required=True)
    return ReadGap(
        source=f"{resource}.name/vservername",
        reason=f"bindingsidentiteit niet leesbaar: name {name_shape}; vservername {vserver_shape}",
    )


def _dedupe_gaps(gaps) -> tuple[ReadGap, ...]:
    unique: dict[tuple[str, str], ReadGap] = {}
    for gap in gaps:
        unique.setdefault((gap.source, gap.reason), gap)
    return tuple(unique.values())


def header_coverage(export) -> tuple[HeaderResult, ...]:
    actions, action_source_gaps = _rows(export, ACTION_RESOURCE)
    policies, policy_source_gaps = _rows(export, POLICY_RESOURCE)
    profiles, profile_source_gaps = _rows(export, PROFILE_RESOURCE)
    vservers, vserver_source_gaps = _rows(export, VSERVER_RESOURCE)

    action_field_gaps = _dedupe_gaps(
        gap
        for row in actions
        for gap in (
            _required_field_gap(row, ACTION_RESOURCE, "name"),
            _required_field_gap(row, ACTION_RESOURCE, "type"),
            _vocabulary_gap(row, ACTION_RESOURCE, "type", _ACTION_TYPES),
            _required_field_gap(row, ACTION_RESOURCE, "target")
            if field_text(row, "type").casefold() == "insert_http_header"
            else None,
        )
        if gap is not None
    )
    policy_field_gaps = _dedupe_gaps(
        gap
        for row in policies
        for gap in (
            _required_field_gap(row, POLICY_RESOURCE, "name"),
            _required_field_gap(row, POLICY_RESOURCE, "action"),
        )
        if gap is not None
    )
    profile_field_gaps = _dedupe_gaps(
        gap
        for row in profiles
        for gap in (
            _required_field_gap(row, PROFILE_RESOURCE, "name"),
            _required_field_gap(row, PROFILE_RESOURCE, "sslprofiletype"),
            _vocabulary_gap(row, PROFILE_RESOURCE, "sslprofiletype", _PROFILE_TYPES),
            _required_field_gap(row, PROFILE_RESOURCE, "hsts")
            if field_text(row, "sslprofiletype").casefold() == "frontend"
            else None,
            _vocabulary_gap(row, PROFILE_RESOURCE, "hsts", _HSTS_VALUES)
            if field_text(row, "sslprofiletype").casefold() == "frontend"
            else None,
        )
        if gap is not None
    )

    vserver_field_gaps = _dedupe_gaps(
        gap
        for row in vservers
        for gap in (
            _required_field_gap(row, VSERVER_RESOURCE, "vservername"),
            _required_field_gap(row, VSERVER_RESOURCE, "sslprofile"),
        )
        if gap is not None
    )

    header_by_action: dict[str, str] = {}
    for action in actions:
        if field_text(action, "type").casefold() != "insert_http_header":
            continue
        header = _TARGET_ALIASES.get(field_text(action, "target").casefold())
        name = field_text(action, "name")
        if header and header != HSTS and name:
            header_by_action[name] = header

    policy_header = {
        field_text(policy, "name"): header_by_action[field_text(policy, "action")]
        for policy in policies
        if field_text(policy, "name") and field_text(policy, "action") in header_by_action
    }

    bound: dict[str, set[str]] = {}
    binding_gaps: list[ReadGap] = []
    for resource in BINDING_RESOURCES:
        rows, source_gaps = _rows(export, resource)
        binding_gaps.extend(source_gaps)
        for row in rows:
            if resource == _GLOBAL_RESOURCE:
                direction_field = "type"
                directions = _GLOBAL_TYPES
                identity_gap = None
            else:
                direction_field = "bindpoint"
                directions = _LOCAL_BINDPOINTS
                identity_gap = _binding_identity_gap(row, resource)
            row_gaps = [
                gap
                for gap in (
                    _required_field_gap(row, resource, "policyname"),
                    _required_field_gap(row, resource, direction_field),
                    _vocabulary_gap(row, resource, direction_field, directions),
                    identity_gap,
                )
                if gap is not None
            ]
            binding_gaps.extend(row_gaps)
            direction = field_text(row, direction_field).casefold()
            is_response = direction in (_GLOBAL_HTTP_RESPONSES if resource == _GLOBAL_RESOURCE else {"response"})
            if row_gaps or not is_response:
                continue
            header = policy_header.get(field_text(row, "policyname"))
            if header is None:
                continue
            where = (
                "globaal" if resource == _GLOBAL_RESOURCE else field_text(row, "name") or field_text(row, "vservername")
            )
            bound.setdefault(header, set()).add(where)

    hsts_profiles = {
        field_text(profile, "name").casefold()
        for profile in profiles
        if field_text(profile, "sslprofiletype").casefold() == "frontend"
        and field_text(profile, "hsts").upper() == "ENABLED"
    }
    bound_hsts_vservers = tuple(
        sorted(
            field_text(vserver, "vservername") or field_text(vserver, "name") or "(naamloos)"
            for vserver in vservers
            if field_text(vserver, "sslprofile").casefold() in hsts_profiles
        )
    )

    results: list[HeaderResult] = []
    hsts_gaps = _dedupe_gaps((*profile_source_gaps, *profile_field_gaps))
    if hsts_gaps:
        results.append(_not_assessed(HSTS, hsts_gaps))
    elif hsts_profiles:
        hsts_binding_gaps = _dedupe_gaps((*vserver_source_gaps, *vserver_field_gaps))
        if hsts_binding_gaps:
            binding_evidence = "binding onbekend door een leesgat"
        elif bound_hsts_vservers:
            binding_evidence = f"gebonden aan {len(bound_hsts_vservers)} vserver(s)"
        else:
            binding_evidence = "aan geen vserver gebonden"
        results.append(
            HeaderResult(
                HSTS,
                "aanwezig en gebonden",
                bound_hsts_vservers,
                evidence=f"{PROFILE_RESOURCE}; {binding_evidence}",
                read_gaps=hsts_binding_gaps,
            )
        )
    else:
        results.append(HeaderResult(HSTS, "afwezig", evidence=PROFILE_RESOURCE))

    rewrite_gaps = _dedupe_gaps(
        (*action_source_gaps, *policy_source_gaps, *action_field_gaps, *policy_field_gaps, *binding_gaps)
    )
    for header in HEADERS[1:]:
        if rewrite_gaps:
            results.append(_not_assessed(header, rewrite_gaps))
        elif header in bound:
            vserver_names = tuple(sorted(bound[header]))
            results.append(
                HeaderResult(
                    header,
                    "aanwezig en gebonden",
                    vserver_names,
                    evidence=f"RESPONSE-binding gelezen op {len(vserver_names)} locatie(s)",
                )
            )
        elif header in header_by_action.values():
            results.append(
                HeaderResult(
                    header,
                    "wel gedefinieerd, niet gebonden",
                    evidence=ACTION_RESOURCE,
                    reason="geen effectieve RESPONSE-binding gelezen",
                )
            )
        else:
            results.append(HeaderResult(header, "afwezig", evidence=ACTION_RESOURCE))
    return tuple(results)


def _not_assessed(header: str, gaps: tuple[ReadGap, ...]) -> HeaderResult:
    reason = "; ".join(f"{gap.source}: {gap.reason}" for gap in gaps)
    return HeaderResult(
        header,
        "niet beoordeeld",
        evidence=", ".join(dict.fromkeys(gap.source for gap in gaps)),
        reason=reason,
        read_gaps=gaps,
    )


def headers_answer(export, knowledge: Knowledge) -> Answer:
    results = header_coverage(export)
    findings = [
        Finding(
            subject=result.header,
            outcome=result.word,
            certainty=Certainty.NOT_ESTABLISHED if result.word == "niet beoordeeld" else Certainty.ESTABLISHED,
            evidence=result.evidence,
            reason=result.reason,
            subject_is_name=False,
        )
        for result in results
    ]
    return Answer(
        question="staan de security-headers er echt op",
        findings=findings,
        read_gaps=list(_dedupe_gaps(gap for result in results for gap in result.read_gaps)),
        not_assessed=[
            NotAssessed(
                subject="wat de client werkelijk ontvangt",
                reason=(
                    "configuratiebewijs toont waar een header hoort te worden gezet; wat een client ontvangt"
                    " vraagt een verzoek"
                ),
            )
        ],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_header_sources(export) -> tuple[str, ...]:
    names = {
        name for result in header_coverage(export) for name in result.vservers if name not in {"globaal", "(naamloos)"}
    }
    return tuple(sorted(names))
