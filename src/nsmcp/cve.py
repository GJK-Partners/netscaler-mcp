"""The CVE verdict in two layers, because one layer alone misleads.

Build layer: is this build below the fixed build of a bulletin? Config
layer: is the precondition the bulletin names actually present in the
export? A build below the fix with the precondition absent is a different
situation from the same build with the precondition present, and an
operator deserves to see both. What the export cannot show is 'niet
vastgesteld' - never 'not applicable'. An unknown predicate is a knowledge-
package error, refused at load time (knowledge.py); here it is only
defended once more, fail-closed.

THE VERDICT IS THE CONJUNCTION, AND IT IS WRITTEN OUT. Two layer findings
next to each other still leave the reader to do the reasoning, and the whole
point of this product is that it computes instead of reasons. So every CVE
carries exactly one verdict line - GERAAKT, NIET GERAAKT or NIET VASTGESTELD
- with the two layer findings underneath it as evidence, and the answer opens
with the counts.

WHERE THE CONDITIONS COME FROM, and why not all from one place. The released
collector (NSHC 1.0.1, external and version-controlled, deliberately NOT
changed for this) fetches a Gateway and an AAA vserver as objects, but does
not fetch a SAML action, a SAML IdP profile or an LSN group at all. The same
export DOES carry the running config, hash-verified against the manifest (see
`Export.running_config_lines`). So those three conditions are computed from
the config text instead of being answered with "niet vastgesteld" while the
evidence sits in the same directory - and the ones that ARE objects keep
coming from the objects, because that is the more precise source.

A CONDITION MAY NEED MORE THAN ONE SOURCE, AND MORE THAN ONE OBJECT. The
bulletins do not name single objects; they name situations ("Gateway OR AAA
virtual server", "HTTP/2 enabled in HTTP Profile"). `_Sources` below holds
every source that can establish ONE condition as a disjunction, and
`_COMBINE`/`_combine` states how three-valued outcomes join - a disjunction
is decided by a single PRESENT source, a conjunction by a single ABSENT one,
and everything else stays NOT ESTABLISHED. Read the docstring of `_Sources`
for the measurement (2026-09-03, real export) that made the two-source shape
necessary: a running config records only what DIFFERS from the factory
settings, so a built-in profile with HTTP/2 on is invisible there while the
object source shows it plainly.

AND A CONDITION MAY BE AN ASSOCIATION RATHER THAN AN EXISTENCE. CTX696604
does not ask whether an HTTP profile with HTTP/2 on EXISTS - it asks whether
such a profile is "associated with the virtual server (of type LB, CS, VPN)
or the service". The difference is not academic: MEASURED on the same real
export, a stock 14.1 carries a built-in profile with HTTP/2 on, so the
existence question answers "yes" on every 14.1 appliance in the world and
tells its operator nothing. `_ReferenceRule` computes the association -
which profile carries the setting, which object references it by name, and
which profile the objects without a reference of their own inherit - and
says out loud when that last one is not in the export.

A CONDITION MAY ALSO DEPEND ON THE BUILD. CTX696939 states CVE-2026-19490
differently below and above 14.1-43.56 / 13.1-61.28, so `voorwaarde` may be
an object as well as a string; `_resolve_condition` does that arithmetic and
the verdict line says which condition it applied and why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from nsmcp.answer import Answer, Certainty, Finding, ReadGap, repeatable_token
from nsmcp.export import RUNNING_CONFIG_FILE
from nsmcp.knowledge import AFFECTED_FORM, Knowledge

_VERSION = re.compile(r"NS(\d+\.\d+):\s*Build\s+(\d+)\.(\d+)")
# The loader owns the shape of an affected range; the verdict parses it with
# that same pattern, so the two cannot drift apart.
_BELOW = AFFECTED_FORM
_BUILD = re.compile(r"(\d+)\.(\d+)")


@dataclass(frozen=True)
class _ObjectRule:
    """A condition established by an OBJECT the collector fetched.

    `field`/`values` narrow it: without them the mere EXISTENCE of an object
    carries the condition (a Gateway vserver), with them only an object whose
    field carries one of those values does (an HTTP profile with http2 on).
    Values are compared lowercase, so ENABLED/enabled are one value and not
    two.

    `optional_field` is for a field that a firmware may simply not HAVE
    (`dnsoverhttps` on an lbvserver, added for DNS over HTTPS). Normally a
    row whose deciding field cannot be read leaves the condition NOT
    established - the fail-closed rule everywhere in this module. That rule
    would turn every ordinary vserver on an older firmware into a read gap
    over an attribute that does not exist there. It is safe to relax ONLY
    because the object in question is user-created and therefore complete in
    the running config, where the same rule reads the switch from the line
    that set it; the line source is what keeps this fail-closed.

    `gate_field`/`gate_values` are a SECOND field that must hold as well,
    because a bulletin may name a combination rather than a switch: CTX696604
    names a CS vserver OF TYPE SSL with `dnsOverHttps` on, and the same switch
    on another service type is not the deployment it describes.
    The gate is read fail-closed and `optional_field` does NOT relax it: a row
    that carries the switch but whose TYPE cannot be read is unreadable, never
    a miss - the switch is the thing that makes the type worth deciding.
    """

    resource: str
    name_field: str
    field: str | None = None
    values: tuple[str, ...] = ()
    optional_field: bool = False
    gate_field: str | None = None
    gate_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class _LineRule:
    """A condition established by a RUNNING-CONFIG line.

    `prefix` is compared lowercase against the start of the line; `label` is
    what the evidence calls this shape, because the bare prefix would say
    something untrue as soon as a rule narrows further ("0 regels 'add lsn
    group'" is false in a config that HAS such a group with SIP ALG off).

    `pair` is a flag and its value that must sit next to each other as TOKENS
    on the line, never as a substring: "-sipalg DISABLED" contains "-sipalg"
    just as much as "-sipalg ENABLED" does. `kinds` is the token right after
    the object name - the service type of an `add lb vserver` line.
    `names_object` is False for a line that declares no object at all (`set
    dns parameter` is a global setting); harvesting a "name" there would put
    a flag in the operator's pseudonym table.
    """

    prefix: str
    label: str
    pair: tuple[str, str] | None = None
    kinds: frozenset | None = None
    names_object: bool = True


@dataclass(frozen=True)
class _CorrelatedLineRule:
    """A `set` line that means nothing WITHOUT the object it changes.

    `add cs vserver X SSL ... -dnsOverHttps ENABLED` states the whole
    situation on one line, and a plain `_LineRule` reads it. `set cs vserver X
    -dnsOverHttps ENABLED` states only HALF of it: the service type sits on
    the line that CREATED X, and CTX696604 names the combination (a CS vserver
    OF TYPE SSL with DoH on), not the switch. Counting such a line by itself
    would report a DNS proxy on an appliance whose X is an HTTP vserver, or
    one where X is not in this export at all - over-reporting with nothing
    measured behind it.

    So this rule CORRELATES: the name on the `set` line must belong
    to an object of the required type, established out of the object family
    (`resource`/`name_field`/`type_field`/`type_values`) or out of a matching
    `add` line (`add_line`) - the same two sources this module uses everywhere,
    for the same reason. `correlation_label` is what the evidence calls that
    requirement, because a line this product READ AND DISMISSED deserves a
    sentence of its own rather than silence.
    """

    line: _LineRule
    add_line: _LineRule
    resource: str
    name_field: str
    type_field: str
    type_values: tuple[str, ...]
    correlation_label: str


@dataclass(frozen=True)
class _ReferenceRule:
    """A condition established by a profile that is ACTUALLY IN USE.

    CTX696604 does not say "an HTTP profile with HTTP/2 on exists somewhere";
    it says "HTTP/2 enabled in HTTP Profile AND associated with the virtual
    server (of type LB, CS, VPN) or the service". MEASURED (2026-09-03, real
    export): the built-in profile `nshttp_default_strict_validation_spa_cep`
    carries `http2: ENABLED` on a stock 14.1 appliance, so an existence rule
    fires on EVERY 14.1 export. A condition that is true everywhere says
    nothing about THIS appliance, and a GERAAKT verdict resting on it is
    over-reporting without a read gap to justify it.

    So this rule computes the association itself, out of four things:

    - WHICH PROFILES CARRY THE SETTING: `resource`/`field`/`values` on the
      profile objects, plus `profile_lines` as a second source of the same
      state. A running config records only what DIFFERS from the factory
      settings, so a built-in profile at its factory value is invisible
      there while a custom `add ns httpProfile ... -http2 ENABLED` is
      visible even when the objects could not be read. The line may only
      ADD - it is never the trigger by itself, because it says of that one
      profile that the setting is on, not that anything uses it.
    - WHICH OBJECTS REFERENCE A PROFILE: `referrers` (the families the
      bulletin names) with `reference_field` ("httpprofilename", measured on
      the real export's vpnvserver objects). A referenced profile whose
      state cannot be read leaves the condition NOT established - it is not
      a profile with the setting off.
    - WHAT AN OBJECT WITHOUT ITS OWN PROFILE INHERITS: the global default
      (`default_resource`/`default_field`, with `default_prefix` as the
      running-config second source). An http2 profile in that place is
      associated with every vserver that has no profile of its own.
      `builtin_default` is the name that applies when the parameter names
      none - the appliance's own factory default. It
      is a READ and not an assumption for the same reason the line sources
      are: a running config records what DIFFERS from the factory settings,
      so a global default pointed anywhere else is always in it. Without
      this, an object inheriting a default profile with the setting ON was
      answered "niet gevonden" - under-reporting.
    - `extra_name_fields` because not every family names itself in `name`:
      a servicegroup carries `servicegroupname`.
    """

    resource: str
    field: str
    values: tuple[str, ...]
    referrers: tuple[str, ...]
    reference_field: str
    default_resource: str
    default_field: str
    default_prefix: str
    profile_lines: tuple[_LineRule, ...] = ()
    line_label: str = ""
    name_field: str = "name"
    extra_name_fields: tuple[str, ...] = ()
    builtin_default: str = ""


@dataclass(frozen=True)
class _Sources:
    """Every source that can establish ONE condition, as a DISJUNCTION.

    Two source kinds side by side, because the collector answers the same
    question in two places and neither is complete on its own:

    - the OBJECT is the precise source. MEASURED on the real export
      (2026-09-03): `config/nshttpprofile` carries a built-in profile with
      `http2: ENABLED` while `parsed/runningconfig.txt` carries no httpProfile
      line at all - a running config only records what DIFFERS from the
      factory settings, so a built-in profile at its factory value is
      invisible there. A running-config-only rule would have answered "niet
      aanwezig" about a condition that is demonstrably present, which is
      under-reporting: the one direction this product may not err in.
    - the LINE may only ADD. A custom profile created with `-http2 ENABLED`
      is in the running config even when the object resource could not be
      read, and over-reporting a condition is the safe direction.

    - the REFERENCE (`_ReferenceRule`) is the one that computes a condition
      the bulletin states as an association instead of an existence. It
      carries its own object and line sources inside it, because those only
      establish the profile STATE there, never the condition.

    - the CORRELATED LINE (`_CorrelatedLineRule`) is a line that may only
      count TOGETHER WITH the object it changes: a `set` line whose object
      must be of a certain type before the line means what the bulletin
      describes. It reads both source kinds itself, for that correlation.

    `caveat` is what the evidence must SAY OUT LOUD when the condition is
    present: CTX696604 requires the TCP profile of CVE-2026-10817 to be
    ASSOCIATED with a vserver or service, and this product does not check
    that binding for TCP profiles - the released collector fetches no
    `config/nstcpprofile` at all, so there is nothing to associate against.
    Appended only to a positive outcome - if no profile has the setting at
    all, no bound profile has it either. The HTTP/2 condition of
    CVE-2026-13474 used to carry the same caveat and no longer does: it is
    computed now (see `_ReferenceRule`).
    """

    objects: tuple[_ObjectRule, ...] = ()
    lines: tuple[_LineRule, ...] = ()
    correlated_lines: tuple[_CorrelatedLineRule, ...] = ()
    references: tuple[_ReferenceRule, ...] = ()
    caveat: str = ""


_GATEWAY_VSERVER = _ObjectRule("config/vpnvserver", "name")
_AAA_VSERVER = _ObjectRule("config/authenticationvserver", "name")

_PROFILE_CAVEAT = "binding aan een vserver/service niet gecontroleerd"

# What the evidence says when the association could be computed for every
# object that HAS its own profile, but the export does not carry the
# parameter that names the profile the others inherit. MEASURED
# (2026-09-03): `config/nsparam` of the real export is readable and carries
# no `httpprofilename` field at all, and the running config carries no `set
# ns param -httpProfileName` line either - the global default simply sits at
# its factory value, which a running config does not record. Failing the
# whole condition on that would replace a usable answer with silence on
# EVERY export this collector makes; saying out loud what was not read is
# the honest half-answer.
_NO_GLOBAL_DEFAULT = "globaal standaardprofiel niet in de export; vservers zonder expliciet profiel niet beoordeeld"

# CTX696604/CVE-2026-13474 as the bulletin states it: HTTP/2 on in an HTTP
# profile that hangs on an LB, CS or VPN vserver or on a service. The five
# referrer families are the ones the bulletin names, all of them measured in
# the manifest of the real export.
_HTTP2_IN_USE = _ReferenceRule(
    resource="config/nshttpprofile",
    field="http2",
    values=("enabled",),
    referrers=(
        "config/lbvserver",
        "config/csvserver",
        "config/vpnvserver",
        "config/service",
        "config/servicegroup",
    ),
    reference_field="httpprofilename",
    default_resource="config/nsparam",
    default_field="httpprofilename",
    default_prefix="set ns param",
    profile_lines=(
        _LineRule("add ns httpprofile ", "add ns httpProfile ... -http2 ENABLED", pair=("-http2", "enabled")),
        _LineRule("set ns httpprofile ", "set ns httpProfile ... -http2 ENABLED", pair=("-http2", "enabled")),
    ),
    line_label="add/set ns httpProfile ... -http2 ENABLED",
    extra_name_fields=("servicegroupname",),
    # The factory default of a NetScaler HTTP profile (measured on the live
    # export: `config/nshttpprofile` carries it, with http2 DISABLED).
    builtin_default="nshttp_default_profile",
)

# DNS over HTTPS switched on
# AFTER the vserver was created. The `add` line carries the service type next
# to the switch and is an ordinary line rule; these two do not, so they only
# count against a vserver of type SSL that this export actually knows - out of
# the object family or out of the `add` line that created it.
#
# BOTH FAMILIES, one shape. The lb form landed uncorrelated and the
# cs form correlated separately, and two measures over one and the same
# sentence in the bulletin is a difference the reader cannot explain: the type
# is missing from a `set` line in exactly the same way on both. So the lb form
# correlates too - a `set lb vserver X -dnsOverHttps ENABLED` on an HTTP
# vserver, or on an X this export does not know, is no more a DNS proxy than
# its cs counterpart.
_LB_DOH_SET = _CorrelatedLineRule(
    line=_LineRule(
        "set lb vserver ", "set lb vserver <naam> ... -dnsOverHttps ENABLED", pair=("-dnsoverhttps", "enabled")
    ),
    add_line=_LineRule("add lb vserver ", "add lb vserver <naam> SSL", kinds=frozenset({"ssl"})),
    resource="config/lbvserver",
    name_field="name",
    type_field="servicetype",
    type_values=("ssl",),
    correlation_label="een LB-vserver van type SSL",
)

_CS_DOH_SET = _CorrelatedLineRule(
    line=_LineRule(
        "set cs vserver ", "set cs vserver <naam> ... -dnsOverHttps ENABLED", pair=("-dnsoverhttps", "enabled")
    ),
    add_line=_LineRule("add cs vserver ", "add cs vserver <naam> SSL", kinds=frozenset({"ssl"})),
    resource="config/csvserver",
    name_field="name",
    type_field="servicetype",
    type_values=("ssl",),
    correlation_label="een CS-vserver van type SSL",
)

# Every condition this module computes, and out of WHICH sources. One table,
# so the evidence, the name harvest (`names_in_predicate_sources`) and the
# vocabulary `knowledge.py` accepts can never drift apart.
_SOURCE_PREDICATES = {
    "heeft_gateway_vserver": _Sources(objects=(_GATEWAY_VSERVER,)),
    "heeft_aaa_vserver": _Sources(objects=(_AAA_VSERVER,)),
    # CTX696604/CVE-2026-8452 says "configured as Gateway (SSL VPN, ICA
    # Proxy, CVPN, RDP Proxy) OR AAA virtual server". Either half alone is a
    # different, narrower condition than the bulletin states.
    "heeft_gateway_of_aaa_vserver": _Sources(objects=(_GATEWAY_VSERVER, _AAA_VSERVER)),
    "heeft_saml_action": _Sources(
        lines=(_LineRule("add authentication samlaction ", "add authentication samlaction"),)
    ),
    "is_saml_idp": _Sources(
        lines=(_LineRule("add authentication samlidpprofile ", "add authentication samlidpprofile"),)
    ),
    "heeft_lsn_sip_alg": _Sources(
        lines=(_LineRule("add lsn group ", "add lsn group ... -sipalg ENABLED", pair=("-sipalg", "enabled")),)
    ),
    # CTX696604/CVE-2026-13474: "HTTP/2 enabled in HTTP Profile and
    # associated with the virtual server (LB, CS, VPN) or the service". The
    # second half is a condition, not a footnote: without it this fires on
    # every 14.1 export, because a stock 14.1 carries a built-in profile with
    # http2 ENABLED (see `_ReferenceRule` for that measurement).
    "heeft_http2_profiel": _Sources(references=(_HTTP2_IN_USE,)),
    # CTX696604/CVE-2026-10817: "TCP TimeStamp enabled in TCP Profile and
    # associated with the virtual server (LB, CS, VPN) or the service".
    #
    # The object half is deliberately here even though the RELEASED collector
    # does not fetch `config/nstcpprofile` (measured: it is not in the
    # manifest of the real export). That absence is a read gap, and a read
    # gap is the honest answer: the measurement at `_Sources` above shows
    # that a running config cannot show a built-in profile at its factory
    # setting, so an export without this resource and without an explicit
    # line establishes nothing - and certainly not absence. Should a later
    # collector fetch the resource, this answer becomes established by
    # itself; should it fetch it under a different field name, every row
    # reads as unreadable and the outcome stays "niet vastgesteld" - fail
    # closed either way.
    "heeft_tcp_timestamp_profiel": _Sources(
        objects=(_ObjectRule("config/nstcpprofile", "name", field="timestamp", values=("enabled",)),),
        lines=(
            _LineRule("add ns tcpprofile ", "add ns tcpProfile ... -timestamp ENABLED", pair=("-timestamp", "enabled")),
            _LineRule("set ns tcpprofile ", "set ns tcpProfile ... -timestamp ENABLED", pair=("-timestamp", "enabled")),
        ),
        caveat=_PROFILE_CAVEAT,
    ),
    # CTX696604/CVE-2026-8655: "LB of type Oracle OR DNS Proxy OR DNS
    # recursive resolver". An LB vserver is always user-created, so unlike a
    # profile it IS complete in the running config; the object source sits
    # next to it because it is the more precise one where it is available.
    # The recursive resolver is a global setting, not a vserver, and has its
    # own line shape.
    #
    # A DNS PROXY is not one
    # shape but four, and this rule knew two of them - which made four direct
    # probes come out "niet gevonden" on configurations the bulletin covers.
    # Under-reporting is the one direction this product may not err in, so
    # every official form is here now:
    #   - an LB vserver of type ORACLE, DNS, DNS_TCP or DOT (DNS over TLS);
    #   - a CONTENT SWITCHING vserver of type DNS, DNS_TCP or DOT - a DNS
    #     proxy is as often a cs vserver as an lb vserver;
    #   - DNS over HTTPS: an SSL vserver with the DoH switch on, which reads
    #     as an ordinary HTTPS vserver on its service type alone;
    #     The bulletin names
    #     the COMBINATION on the lb family exactly as it does on the cs one,
    #     and the lb half of that rule gated only its `set` form. So
    #     `config/lbvserver {servicetype: HTTP, dnsoverhttps: ENABLED}` and
    #     `add lb vserver X HTTP ... -dnsOverHttps ENABLED` both counted as a
    #     DNS proxy - over-reporting, and two yardsticks over one sentence.
    #     Both the lb object rule and the lb `add` line now carry the same
    #     SSL gate as their cs counterparts, the object one fail-closed: a row
    #     that carries the switch but whose type cannot be read is unreadable,
    #     never a miss;
    #     The bulletin names a
    #     CONTENT SWITCHING vserver of type SSL with `-dnsOverHttps ENABLED`
    #     just as explicitly as the lb one, and this rule read the switch on
    #     the lb family only - so `add cs vserver CS_DOH SSL ... -dnsOverHttps
    #     ENABLED` and the matching object both came out "niet gevonden" and a
    #     kwetsbare 14.1-72.57 was told "NIET GERAAKT [vastgesteld]". The
    #     object rule gates on servicetype SSL because the bulletin names the
    #     combination, and the `set` form correlates (`_CS_DOH_SET`) because
    #     that line does not carry the type itself - as does the lb `set` form
    #     (`_LB_DOH_SET`), which is the same sentence of the same bulletin and
    #     may not be measured by another yardstick;
    #   - recursive resolution per DNS PROFILE next to the global parameter.
    # All of them user-created (or, for `set`, a change to a built-in), so the
    # running config carries every one of them; the object sources sit next to
    # them where the collector fetched the family. `config/dnsprofile` is
    # deliberately NOT an object source: the released collector does not fetch
    # it, and a resource that is not in the manifest would turn this whole
    # condition into "niet vastgesteld" on every export - while the running
    # config is complete for exactly this kind of object.
    "heeft_lb_oracle_of_dns": _Sources(
        objects=(
            _ObjectRule("config/lbvserver", "name", field="servicetype", values=("oracle", "dns", "dns_tcp", "dot")),
            _ObjectRule("config/csvserver", "name", field="servicetype", values=("dns", "dns_tcp", "dot")),
            _ObjectRule(
                "config/lbvserver",
                "name",
                field="dnsoverhttps",
                values=("enabled",),
                optional_field=True,
                gate_field="servicetype",
                gate_values=("ssl",),
            ),
            _ObjectRule(
                "config/csvserver",
                "name",
                field="dnsoverhttps",
                values=("enabled",),
                optional_field=True,
                gate_field="servicetype",
                gate_values=("ssl",),
            ),
        ),
        lines=(
            _LineRule(
                "add lb vserver ",
                "add lb vserver <naam> ORACLE/DNS/DNS_TCP/DOT",
                kinds=frozenset({"oracle", "dns", "dns_tcp", "dot"}),
            ),
            _LineRule(
                "add cs vserver ", "add cs vserver <naam> DNS/DNS_TCP/DOT", kinds=frozenset({"dns", "dns_tcp", "dot"})
            ),
            _LineRule(
                "add lb vserver ",
                "add lb vserver <naam> SSL ... -dnsOverHttps ENABLED",
                pair=("-dnsoverhttps", "enabled"),
                kinds=frozenset({"ssl"}),
            ),
            _LineRule(
                "add dns profile ",
                "add dns profile ... -recursiveResolution ENABLED",
                pair=("-recursiveresolution", "enabled"),
            ),
            _LineRule(
                "set dns profile ",
                "set dns profile ... -recursiveResolution ENABLED",
                pair=("-recursiveresolution", "enabled"),
            ),
            _LineRule(
                "set dns parameter",
                "set dns parameter ... -recursion ENABLED",
                pair=("-recursion", "enabled"),
                names_object=False,
            ),
            _LineRule(
                "add cs vserver ",
                "add cs vserver <naam> SSL ... -dnsOverHttps ENABLED",
                pair=("-dnsoverhttps", "enabled"),
                kinds=frozenset({"ssl"}),
            ),
        ),
        correlated_lines=(
            _LB_DOH_SET,
            _CS_DOH_SET,
        ),
    ),
}

# Conditions built out of OTHER conditions. CTX696939 makes CVE-2026-19490
# depend on a Gateway/AAA vserver AND a SAML action from 14.1-43.56 /
# 13.1-61.28 onward. 1.0.2: CTX697174 and the older band of CTX697191
# state "SAML SP or IdP" - a SAML action (the appliance as service provider)
# OR a SAML IdP profile (the appliance as identity provider). Both halves
# keep their own evidence in the answer, joined by " OF ".
_COMPOSITE_PREDICATES = {
    "heeft_gateway_of_aaa_met_saml_action": (
        "en",
        ("heeft_gateway_of_aaa_vserver", "heeft_saml_action"),
    ),
    "heeft_saml_action_of_idp": (
        "of",
        ("heeft_saml_action", "is_saml_idp"),
    ),
}

# Every predicate this module can actually evaluate. `knowledge.PREDICATES`
# refuses a knowledge package that names anything else, and a test pins the
# two collections equal: they drift apart into either a package refused for
# nothing, or a condition that can never be established.
EVALUATED_PREDICATES = frozenset({"altijd"} | set(_SOURCE_PREDICATES) | set(_COMPOSITE_PREDICATES))

# The internal three-value outcome of `evaluate_predicate` translated into the
# sentence the customer reads. Deliberately two vocabularies rather than one:
# the function's return value is a pinned interface ("aanwezig", "niet
# gevonden", "niet vastgesteld"), and "niet aanwezig" is the sentence that
# says the same thing about a CONDITION without suggesting that something was
# searched for and merely not found.
_CONDITION_TEXT = {
    "aanwezig": "aanwezig",
    "niet gevonden": "niet aanwezig",
    "niet vastgesteld": "niet vastgesteld",
}

GERAAKT = "GERAAKT"
NIET_GERAAKT = "NIET GERAAKT"
NIET_VASTGESTELD = "NIET VASTGESTELD"


def parse_build(version_text: str) -> tuple[str, tuple[int, int]] | None:
    """Branch and build out of the version string the appliance itself writes.

    `search`, not `match`: the real string starts with "NetScaler " and runs
    on into ".nc, Date: May 21 2026, 18:20:32   (64-bit)" (measured on
    `objects/nsversion.json` of the live export). Anchoring either end makes
    this return None on every real appliance.
    """
    m = _VERSION.search(str(version_text))
    if not m:
        return None
    return m.group(1), (int(m.group(2)), int(m.group(3)))


# THE FIPS/NDcPP TRAIN IS A BRANCH OF ITS OWN (MEASURED).
# CTX696604 and CTX696939 list 13.1-FIPS/NDcPP next to 13.1, with fix
# builds of their own (37.272 / 37.277) that are far BELOW the ordinary
# branch's fix build. A version string carries no platform, so a patched
# 13.1-FIPS appliance on 37.272 used to be judged against the ordinary rule -
# 37.272 < 63.18 - and came out "GERAAKT [vastgesteld]": a false ESTABLISHED
# verdict, and the advice to upgrade something that is already fixed, for a
# whole appliance class the bulletin names.
#
# So the branch follows a POSITIVE READ of the platform, and never a guess.
#
# NARROWED after the re-check of 2026-09-04: the FIPS train
# ships for MPX FIPS, SDX FIPS *and VPX FIPS*, and a VPX FIPS is an ordinary
# virtual appliance - `hwdescription` "Netscaler Remote Licensed Virtual
# Appliance", exactly what the live fixture carries. Reading that description
# as a positive "geen FIPS" therefore CONTRADICTED the version string on
# every VPX FIPS, and a package without FIPS branches then fell back to the
# ordinary rule: the false ESTABLISHED verdict this whole block exists to
# prevent, measured again. What the export can say, and what it cannot:
#   - the version string carries the vendor's own TRAIN MARKER: a FIPS build
#     writes "... (64-bit) (NS13.1-FIPS)" (Citrix release notes 13.1-37.232-
#     FIPS and 13.1-37.259-FIPS). That marker names the branch key and is the
#     authoritative read - it is the appliance saying which train it runs.
#   - `config/nshardware.hwdescription` and `config/systemparameter`
#     `fipsusermode=ENABLED` may only ADD a FIPS read. Neither can negate the
#     marker: a virtual appliance description is no evidence against FIPS
#     (VPX FIPS exists), and `fipsusermode=DISABLED` says nothing about the
#     platform, because a FIPS appliance may run with the mode off.
#   - a readable version string WITHOUT the marker, with nothing else naming
#     FIPS, is the negative read: this is not the FIPS train. The version
#     string is the one field every export carries, and the marker is the
#     vendor's own, so its absence is a read rather than a hole.
#   - the one remaining disagreement is the version string against ITSELF: a
#     marker naming another train than the build it stands next to. That
#     establishes nothing.
# Any FIPS read at all puts the FIPS branch at stake: a bulletin that does
# not name that branch says nothing about it (NIET VASTGESTELD), and the
# ordinary branch is never used as a stand-in.
#
# EVERY ONE of these fields is read as TEXT or not at all (`_readable`).
# `null`, a number, a list or an object is "niet leesbaar" -
# never a positive read in either direction, and a list that happens to
# contain the word FIPS is not a FIPS appliance.
FIPS_SUFFIX = "-FIPS"
_FIPS_WORD = re.compile(r"(?<![A-Za-z0-9])(?:FIPS|NDcPP)(?![A-Za-z0-9])", re.IGNORECASE)
_FIPS_MARKER = re.compile(r"NS(\d+\.\d+)-(?:FIPS|NDcPP)(?![A-Za-z0-9])", re.IGNORECASE)
PLATFORM_FIPS = "fips"
PLATFORM_PLAIN = "geen fips"
PLATFORM_UNKNOWN = "onbekend"
PLATFORM_UNKNOWN_REASON = "platform (FIPS of niet) niet uit de export vast te stellen"

# "the field is not there" against "the field is there and carries something
# this product cannot read". Only the second is worth a word in the evidence.
_NO_FIELD = object()


def fips_marker(version_text) -> str | None:
    """The BRANCH KEY the version string's own train marker names, or None.

    "NetScaler NS13.1: Build 37.272.nc ... (64-bit) (NS13.1-FIPS)" yields
    "13.1-FIPS" - the same key the bulletin carries in `getroffen`/`fix`. The
    vendor writes the train two ways ("FIPS and NDcPP"); both mean the one
    train, and the bulletins name it with the one key.

    The key is REBUILT from the digits the marker matched, never sliced out
    of the string: the version field is free text out of the export (see
    `build_echo`), and nothing raw from it may reach an answer.
    """
    text = _readable(version_text)
    if text is None:
        return None
    m = _FIPS_MARKER.search(text)
    return f"{m.group(1)}{FIPS_SUFFIX}" if m else None


def fips_platform(export, version_text, branch: str) -> tuple[str, str, ReadGap | None]:
    """Is this a FIPS/NDcPP appliance? Three values, and the read behind it.

    Returns `(platform, evidence, gap)`. The evidence names the FIELD and what
    it said about FIPS - never the value itself: `hwdescription` is free text
    out of the export, and the disclosure layer does not collect it as a name,
    so anything repeated from it would reach the model unmasked (the same
    class of defect `build_echo` above exists for).

    `branch` is the train the BUILD belongs to, as `parse_build` read it. It
    is here for one check: a marker naming another train than its own build.

    PUBLIC because this rule has more than one consumer. `update_advice.py`
    (B2) compares a running build against the fix build of a branch - exactly
    the same comparison this guard performs - and briefly carried a second,
    narrower copy of this guard; the two then disagreed about the same
    export. One rule, one owner: every consumer calls THIS.
    """
    version = _readable(version_text)
    says_fips: list[str] = []
    unreadable: list[str] = []

    marker = fips_marker(version)
    if marker is not None:
        says_fips.append(f"config/nsversion: de versietekst noemt tak {marker}")
    elif version is not None and _FIPS_WORD.search(version):
        # No marker, but the string names the train in some other shape. A
        # read that ADDS, like the two fields below - it cannot name a branch
        # key, so it never speaks for a train of its own.
        says_fips.append("config/nsversion: de versietekst noemt FIPS")

    hardware, _gap = export.single("config/nshardware")
    raw = hardware.get("hwdescription", _NO_FIELD) if isinstance(hardware, dict) else _NO_FIELD
    description = _readable(raw)
    if description is not None:
        if _FIPS_WORD.search(description):
            says_fips.append("config/nshardware: hwdescription noemt FIPS")
    elif raw is not _NO_FIELD:
        unreadable.append("config/nshardware: hwdescription draagt geen leesbare tekst")

    parameters, _gap = export.single("config/systemparameter")
    raw_mode = parameters.get("fipsusermode", _NO_FIELD) if isinstance(parameters, dict) else _NO_FIELD
    mode = _readable(raw_mode)
    if mode is not None:
        if mode.upper() == "ENABLED":
            says_fips.append("config/systemparameter: fipsusermode=ENABLED")
    elif raw_mode is not _NO_FIELD:
        unreadable.append("config/systemparameter: fipsusermode draagt geen leesbare tekst")

    def _evidence(reads: list[str]) -> str:
        return "; ".join(reads + unreadable)

    if marker is not None and marker != f"{branch}{FIPS_SUFFIX}":
        reason = (
            "de versietekst spreekt zichzelf tegen over het platform: de tak"
            f" {marker} hoort niet bij de build van tak {branch}"
        )
        return PLATFORM_UNKNOWN, reason, ReadGap(source="config/nsversion", reason=reason)
    if says_fips:
        return PLATFORM_FIPS, _evidence(says_fips), None
    if version is not None:
        return PLATFORM_PLAIN, _evidence(["config/nsversion: de versietekst noemt geen FIPS-tak"]), None
    # Unreachable through `cve_check`, which reads the branch out of this same
    # string first: the runtime net for any other caller. Without a readable
    # version string there is no read at all, and that is not a platform.
    reason = (
        f"{PLATFORM_UNKNOWN_REASON}: geen leesbare aanwijzing (de versietekst,"
        " config/nshardware: hwdescription, config/systemparameter: fipsusermode)"
    )
    return PLATFORM_UNKNOWN, reason, ReadGap(source="config/nsversion", reason=reason)


def _named_branches(bulletin) -> set:
    """Every branch this bulletin names, on either half of its rule. The
    runtime net around a package that never came through `knowledge.py`,
    where the two halves are pinned equal."""
    names: set = set()
    for field_name in ("getroffen", "fix"):
        value = bulletin.get(field_name)
        if isinstance(value, dict):
            names |= set(value)
    return names


# What is said about a version string that carries no recognizable build AND
# no repeatable token shape either. A fixed constant, so it can never carry
# content by construction.
NO_BUILD_ECHO = "(zonder herkenbare buildvorm)"
# And what is said about a version FIELD that carries no text at all:
# `null`, a number, a list, an object. Also a constant - there is
# nothing here to echo, and `str()` of such a value is a conversion, not a
# read (a list carrying the version string would otherwise hand both a build
# and a train marker to the check).
NO_TEXT_ECHO = "(geen leesbare tekst)"


def build_echo(version_text) -> str:
    """What may be REPEATED of the version string `config/nsversion` carries.

    The version string is free text out of the export, and the disclosure
    layer's name collection does not read this field - so whatever an answer
    repeats from it reaches the model UNMASKED. A supplied export can put a
    whole sentence in there (measured class of defect: the same one
    `overzicht._repeatable` exists for).

    So only the PARSED part travels: `NS<tak>: Build <x>.<y>`, rebuilt from
    the branch and the two numbers `parse_build()` recognized - never the raw
    string, not even the piece around the match. Does the string not parse at
    all, then there is no parsed part, and only a bounded token shape
    (`answer.repeatable_token`) may still be shown; anything else is named,
    not reproduced.
    """
    parsed = parse_build(version_text)
    if parsed is not None:
        branch, (major, minor) = parsed
        return f"NS{branch}: Build {major}.{minor}"
    token = repeatable_token(version_text)
    return token if token is not None else NO_BUILD_ECHO


def _parse_below(text: str) -> tuple[int, int] | None:
    m = _BELOW.fullmatch(str(text).strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


def _parse_fix(text: str) -> tuple[int, int] | None:
    m = _BUILD.fullmatch(str(text).strip())
    return (int(m.group(1)), int(m.group(2))) if m else None


# De q-vorm (gemeten op een labexport van 6-9-2026). De TWEEDE afbakeningsvorm van de
# NetScaler-CLI: `q` gevolgd door een
# scheidingsteken, waarna de tekenreeks tot datzelfde teken loopt - of tot de
# spiegel ervan bij een haakjespaar. De appliance schrijft er doodgewone
# monitorregels mee: `-recv q/{\"Status\":0}/`.
#
# De lijst is KORT en vast, en dat is de hele voorzichtigheid van deze
# reparatie. "q gevolgd door iets dat geen letter is" zou een object dat `q-1`
# of `q.web` heet in tweeen knippen, en dan draagt het bewijs een naam die de
# lezer niet kan opzoeken - exact de fout die de eerdere reparatie van de
# aanhalingstekens uit dit bestand haalde.
# Deze zes tekens komen in een NetScaler-objectnaam niet voor.
_Q_DELIMITERS = {"/": "/", "{": "}", "(": ")", "[": "]", "<": ">", "|": "|"}


def _tokens(line: str) -> tuple[list[str], bool]:
    """The TOKENS of a running-config line, and whether it could be read
    UNAMBIGUOUSLY.

    A NetScaler name that carries a space stands between double quotes:
    `add service "Mijn Dienst" 10.0.0.9 SSL 443` is an entirely ordinary line
    and the appliance writes it exactly so. Split on whitespace, that name
    became `"Mijn` - a fragment that matches no readback row, that no reader
    can look up on the appliance, and that the reconciliation then reported as
    an EXISTENCE contradiction on an export where nothing is wrong. So the quoting is read HERE, in one place,
    for every consumer of a line: the reduction, the name a line declares and
    the narrowing tests. One tokenisation, or the three drift apart exactly
    where this module compares their results with each other.

    A quote inside a quoted string is escaped with a backslash, the way the
    CLI writes it; the real export carries such lines (the policy
    expressions).

    Naast het dubbele aanhalingsteken kent de CLI een tweede afbakening: `q`
    gevolgd door een scheidingsteken (`q/.../`, `q{...}`). Wat daartussen
    staat is LETTERLIJK - een backslash is daar geen escape maar een gewoon
    teken - en het geheel is een token. Dat is geen randgeval: een gewone
    HTTP-ECV-monitor schrijft `-recv q/{\"Status\":0}/`, en zolang die vorm
    niet gelezen werd, opende de eerste backslash-quote een aanhalingsteken
    dat nooit sloot en viel de hele regel fail-closed weg (gemeten op een
    labexport van 6-9-2026: zes gewone regels, vijf van de acht CVE-regels onnodig op
    "niet vastgesteld").

    The second value is FALSE when a quote never closes. Such a line cannot be
    read unambiguously - this product does not know WHICH object it names -
    and the callers act on that instead of guessing: it establishes no
    existence (`_reduce_config`), it lends no name (`_name_after`), and where
    it is the evidence of a line rule it keeps counting, exactly as a line
    that names no object at all does. The tokens returned then are the plain
    whitespace split, so the SHAPE tests answer exactly what they answered
    before any quoting was read: over-reporting is the safe direction, and
    this module does not dismiss evidence it failed to parse.
    """
    tokens: list[str] = []
    current: list[str] = []
    started = False
    quoted = False
    index = 0
    while index < len(line):
        char = line[index]
        if quoted and char == "\\" and index + 1 < len(line) and line[index + 1] in '"\\':
            current.append(line[index + 1])
            index += 2
            continue
        if not quoted and not started and char == "q" and index + 1 < len(line) and line[index + 1] in _Q_DELIMITERS:
            # `not started` is de bewaker: dit is alleen een afbakening als
            # hij aan het BEGIN van een token staat. Midden in een naam is een
            # `q` gewoon een letter.
            closer = _Q_DELIMITERS[line[index + 1]]
            end = line.find(closer, index + 2)
            if end == -1:
                # Een afbakening die nooit sluit is precies zo onleesbaar als
                # een aanhalingsteken dat nooit sluit: dit product weet niet
                # waar de tekenreeks ophoudt, dus weet het ook niet welke
                # vlaggen erna nog echt vlaggen zijn. Zelfde uitgang als
                # hieronder: de kale splitsing, en `False`.
                return line.split(), False
            tokens.append(line[index + 2 : end])
            index = end + 1
            continue
        if char == '"':
            quoted = not quoted
            started = True
            index += 1
            continue
        if not quoted and char.isspace():
            if started:
                tokens.append("".join(current))
                current = []
                started = False
            index += 1
            continue
        current.append(char)
        started = True
        index += 1
    if quoted:
        return line.split(), False
    if started:
        tokens.append("".join(current))
    return tokens, True


def _name_after(line: str, prefix_length: int) -> str | None:
    """The object name a running-config line declares: the token right after
    the keyword. Returns None when there is no such token - a line that
    matched the keyword but names nothing still establishes the condition,
    it just cannot contribute a name to the evidence.

    A line whose quoting does not close is such a line too (`_tokens`): the
    name it declares cannot be read unambiguously, so this returns none rather
    than a fragment. That fragment used to travel into the evidence and into
    the name harvest, where it was masked as if it were a real object - a
    name the reader cannot place, standing in for one this product never read.
    """
    rest, readable = _tokens(line[prefix_length:])
    if not readable:
        return None
    return rest[0] if rest else None


def _matches(line: str, rule: _LineRule) -> bool:
    """Does this running-config line carry the shape `rule` describes?

    The prefix has already been checked by the caller; what is left are the
    narrowing conditions, both compared as TOKENS on the lowercase line - and
    a token is what `_tokens` says it is, so a quoted name counts as one here
    exactly as it does in the reduction.
    """
    tokens = _tokens(line.lower())[0]
    if rule.pair is not None:
        flag, value = rule.pair
        if not any(token == flag and tokens[index + 1] == value for index, token in enumerate(tokens[:-1])):
            return False
    if rule.kinds is not None:
        # The token right AFTER the object name: `add lb vserver <naam>
        # <servicetype> ...`. Counted from the prefix, so the rule does not
        # have to know how many words its own keyword is.
        rest = _tokens(line[len(rule.prefix) :].lower())[0]
        if len(rest) < 2 or rest[1] not in rule.kinds:
            return False
    return True


# The three-value outcomes, and how a disjunction and a conjunction combine
# them. Written out rather than derived, because the two are NOT each other's
# mirror image in the direction that matters: a disjunction is decided by a
# single PRESENT source, a conjunction by a single ABSENT one, and everything
# that is neither leaves the answer NOT ESTABLISHED. Guessing in either
# direction would be exactly the silent assumption this product refuses.
_PRESENT, _ABSENT, _UNKNOWN = "aanwezig", "niet gevonden", "niet vastgesteld"

# What an answer says about the running-config lines this product
# could not tokenise, and what follows from them. One wording, used for the
# evidence and for the read gap, so the two can never say different things.
_UNREADABLE_LINES = "{count} regel(s) in de running config waren niet te ontleden (onafgesloten aanhalingsteken)"
_UNREADABLE_CONSEQUENCE = "de voorwaarde kan op zo'n regel staan en is daarmee niet vast te stellen"


def _combine(operator: str, outcomes: list[str]) -> str:
    decisive = _PRESENT if operator == "of" else _ABSENT
    if decisive in outcomes:
        return decisive
    if _UNKNOWN in outcomes:
        return _UNKNOWN
    return _PRESENT if operator == "en" else _ABSENT


# ---------------------------------------------------------------------------
# THE EFFECTIVE CONFIGURATION STATE.
#
# A running config is not a list of facts but an IMPERATIVE SCRIPT: `add`,
# `set`, `unset` and `rm` run in order, and the last write wins. This module
# read it as a bag of independent lines, so a line the operator DEMONSTRABLY
# revoked kept counting. MEASURED on exact pins: `add lb
# vserver X SSL ... -dnsOverHttps ENABLED` followed by `set lb vserver X
# -dnsOverHttps DISABLED` stayed "aanwezig" (the cs form too, and the DNS
# profile and global-recursion variants), and a full `cve_check` on a
# 14.1-72.57 export then said "CVE-2026-8655: GERAAKT [vastgesteld]" about a
# switch that is off. A false ESTABLISHED positive is the mirror image of the
# false negatives of tasks 38/41 and just as unusable - the operator upgrades
# on it, or stops believing the answer.
#
# So the config is REDUCED first, in order, into per-(familie, objectnaam,
# veld) effective values, and every line-based predicate is evaluated on that
# state instead of on the raw lines:
#   - `add`    creates the object with the values on its own line (the token
#              right after the name is its type);
#   - `set`    overwrites exactly the named fields, and creates the object
#              when there is none - a built-in profile is `set` without ever
#              being `add`ed, and a running config records only what differs
#              from the factory settings;
#   - `unset`  puts a field back at its default, which is "absent" here: this
#              module never reports a condition on a field it cannot see;
#   - `rm`     takes the whole object away, and an object added AGAIN after
#              that is simply there (a reduction that only ever removes would
#              be the same defect in the other direction).
#
# The families are DERIVED from the rules below rather than listed again, so
# a new rule can never quietly fall outside the reduction; a verb this module
# does not know (`bind`, `enable`, `link`) touches nothing.
# ---------------------------------------------------------------------------

_CONFIG_VERBS = ("add", "set", "unset", "rm", "remove")

# What the evidence calls a disagreement between the two sources of one and
# the same export. One word, in one place, so the reader meets the same term
# everywhere and a test can pin it.
_CONTRADICTION = "brontegenspraak"


@dataclass
class _Effective:
    """ONE object of the running config after every line touching it ran.

    `name` is the name AS WRITTEN on the line (never lowercased): the
    disclosure seam masks names literally, so an evidence sentence carrying a
    case-folded name would travel unmasked. `added` records whether an `add`
    line created this object - a `set` on an object this export does not
    otherwise know states no existence, and may not be read as one.
    """

    name: str = ""
    kind: str | None = None
    added: bool = False
    fields: dict = field(default_factory=dict)


def _family_of(prefix: str) -> str:
    """'lb vserver' out of 'add lb vserver ' - the object family a rule reads,
    without the verb that happens to appear in that one rule."""
    return " ".join(prefix.split()[1:])


def _rule_attributes(rule: _LineRule) -> tuple[str, ...]:
    """EVERY attribute this line rule rests on, as `_source_conflicts` keys
    them: the flag of its `pair`, and the empty string for the TYPE when it
    also carries `kinds`.

    Measured: a rule that reads BOTH ("an SSL vserver WITH DoH on")
    used to be keyed on its flag alone, so a readback that disagreed about the
    service type was never consulted - the conjunction was half-measured, and
    the half that fell away was the one the bulletin narrows on. A rule that
    reads neither keeps the empty string: an existence rule is contested by
    the `*` entry, and dropping the key here would be a silent behaviour
    change in the opposite direction.
    """
    attributes: list[str] = []
    if rule.pair is not None:
        attributes.append(rule.pair[0])
    if rule.kinds is not None or rule.pair is None:
        attributes.append("")
    return tuple(attributes)


# Which OBJECT family carries the CURRENT state of a running-config family,
# and under which field it names itself and its type. The readback is what
# the appliance answers today; the reduced lines are the script that produced
# it. Only families the collector actually fetches are here - a resource that
# is not in the manifest cannot contradict anything (`export.objects` reports
# that as its own read gap, and one unread source may not become two).
#
# The type field is None for a family whose TYPE no rule reads: a profile has
# none, and of a service or a Gateway vserver this module only ever reads the
# profile hanging on it. A None here does not relax anything - it says there
# is no type to disagree about.
#
# Measured: the five REFERRER families of the HTTP/2 rule are
# in this table too. They were absent, so `httpprofilename` - the field that
# decides which profile hangs on an object - had no running-config source at
# all: an operator who moved that binding with `set lb vserver X
# -httpProfileName ...` was invisible, and the condition came out "niet
# gevonden [vastgesteld]" while the running config of the same export
# describes it. With the family here, the ordinary reduction and the ordinary
# reconciliation cover the referring field exactly as they cover every other
# field this module reads.
#
# Measured: and the AAA vserver, the OTHER HALF of
# one and the same bulletin sentence. CTX696604/CVE-2026-8452 names a
# deployment "configured as Gateway ... OR AAA virtual server"; `vpn vserver`
# landed in this table as a referrer of the HTTP/2 rule and thereby got the
# reconciliation, `config/authenticationvserver` did not - so on identical
# export shapes the Gateway half answered "niet vastgesteld" and the AAA half
# "niet gevonden [vastgesteld]", an ESTABLISHED denial over evidence the
# export itself contradicts. One sentence may not be measured with two
# yardsticks, which is the argument every earlier repair here rests on.
_FAMILY_OBJECTS = {
    "lb vserver": ("config/lbvserver", "name", "servicetype"),
    "cs vserver": ("config/csvserver", "name", "servicetype"),
    "vpn vserver": ("config/vpnvserver", "name", None),
    "authentication vserver": ("config/authenticationvserver", "name", None),
    "service": ("config/service", "name", None),
    "servicegroup": ("config/servicegroup", "servicegroupname", None),
    "ns httpprofile": ("config/nshttpprofile", "name", None),
    "ns tcpprofile": ("config/nstcpprofile", "name", None),
}
_OBJECT_FAMILIES = {resource: family for family, (resource, _, _) in _FAMILY_OBJECTS.items()}

# The SINGLETON families: a running-config family that names no object at all
# (`set ns param -httpProfileName ...`), next to the readback resource that
# carries the same state. They cannot sit in `_FAMILY_OBJECTS` - there is no
# name to key a row on - and that is exactly how the global default profile
# fell out of the reconciliation: `_collect_families` declared the attribute
# reconcilable, nothing ever compared it, and the readback won in silence in
# BOTH directions. Their conflicts are filed under
# the empty object name, the same key `_reduce_config` gives them.
_SINGLETON_OBJECTS = {
    "ns param": "config/nsparam",
}

# The families a rule declares RECONCILABLE and that this module deliberately
# does NOT compare, with the readback resource a collector would have to fetch
# before it could. MEASURED on the real export (2026-09-04): none of these
# five is in the manifest of the released collector, and none of them has an
# `_ObjectRule` either - so each of them has exactly ONE source, nothing can
# win in silence, and there is nothing to disagree with.
#
# Written down rather than left implicit, because "declared in `_RECONCILED`,
# compared nowhere" is precisely the shape in which the global default profile
# survived undetected for a while: the attribute was declared reconcilable, no step
# ever compared it, and the readback won in silence in both directions. A
# remainder class that is a DECISION can be checked; one that is a leftover
# turns up on a customer export.
#
# `test_a_reconciled_family_is_compared_or_declared_unreconciled`
# pins this table against `_RECONCILED` and uses the resources as a TRIPWIRE
# against the real export: the day the collector fetches one of them, that
# test goes red and the family has to move into `_FAMILY_OBJECTS` (or
# `_SINGLETON_OBJECTS`) before the export can carry two sources again.
_UNRECONCILED = {
    "authentication samlaction": "config/authenticationsamlaction",
    "authentication samlidpprofile": "config/authenticationsamlidpprofile",
    "dns parameter": "config/dnsparameter",
    "dns profile": "config/dnsprofile",
    "lsn group": "config/lsngroup",
}


def _collect_families() -> tuple[dict[str, bool], dict[str, set]]:
    """Every family the rules below read, and per family which ATTRIBUTES.

    Two derivations out of one pass, for the same reason `_SOURCE_PREDICATES`
    is one table: a family that fell out of the reduction, or an attribute
    that fell out of the reconciliation, would be a silent hole exactly where
    this module claims to be complete.

    The attribute of a rule is its flag (`-dnsoverhttps`), or the empty string
    for a rule that reads the TYPE of the object or its bare existence - and
    a rule that reads both contributes both (`_rule_attributes`), so the
    reconciliation compares everything some rule actually decides on.

    Declared is not the same as COMPARED: only `_FAMILY_OBJECTS` and
    `_SINGLETON_OBJECTS` compare anything, and the families that are in
    neither are named in `_UNRECONCILED` with the reason (the collector
    fetches no readback for them, so there is only one source). That
    remainder is a decision, and a test holds this derivation and that table
    against each other.
    """
    families: dict[str, bool] = {}
    attributes: dict[str, set] = {}

    def note_family(family: str, names_object: bool, attribute: str) -> None:
        families[family] = families.get(family, True) and names_object
        attributes.setdefault(family, set()).add(attribute)

    def note(prefix: str, names_object: bool, attribute: str) -> None:
        if len(prefix.split()) < 2:
            return
        note_family(_family_of(prefix), names_object, attribute)

    def note_rule(rule: _LineRule) -> None:
        for attribute in _rule_attributes(rule):
            note(rule.prefix, rule.names_object, attribute)

    for sources in _SOURCE_PREDICATES.values():
        # An EXISTENCE object rule declares its family too. Without
        # this the family of such a rule reached the reduction only by
        # accident - `vpn vserver` did, as a referrer of the HTTP/2 rule, and
        # `authentication vserver` did not, which is how the two halves of one
        # bulletin sentence came to be measured differently. The attribute is
        # the empty string, the key `_source_conflicts` files an existence
        # disagreement under.
        #
        # Only the existence form. A NARROWED object rule reads a field, and
        # every one of them has a line rule of the same shape beside it that
        # declares exactly that attribute - a test pins that, so widening this
        # would change nothing except which line happens to declare it.
        for rule in sources.objects:
            if rule.field is None:
                family = _OBJECT_FAMILIES.get(rule.resource)
                if family is not None:
                    note_family(family, True, "")
        for rule in sources.lines:
            note_rule(rule)
        for correlated in sources.correlated_lines:
            note_rule(correlated.line)
            note_rule(correlated.add_line)
        for reference in sources.references:
            for line_rule in reference.profile_lines:
                note_rule(line_rule)
            # The global default (`set ns param -httpProfileName ...`) names
            # no object, and its own evaluator reads it off the state below.
            note(reference.default_prefix, False, f"-{reference.default_field}")
            # And the REFERRING field itself. Which profile hangs on
            # an object is a fact like any other here, so the running config
            # is a source for it and the readback has something to be
            # reconciled against. The families come out of `_FAMILY_OBJECTS`
            # rather than out of a second list: a referrer this module cannot
            # key to a family would be a silent hole in exactly the place
            # this derivation exists to close, and a test pins that.
            for resource in reference.referrers:
                family = _OBJECT_FAMILIES.get(resource)
                if family is not None:
                    note_family(family, True, f"-{reference.reference_field}")
    return families, attributes


_LINE_FAMILIES, _RECONCILED = _collect_families()
# Longest family first: 'lb vserver' must win from a hypothetical 'lb', never
# the other way round.
_FAMILY_ORDER = tuple(sorted(_LINE_FAMILIES, key=lambda name: -len(name.split())))


def _is_flag(token: str) -> bool:
    """A NetScaler flag, and not a negative number that happens to sit in the
    value position (`-mss -1`)."""
    return len(token) > 1 and token.startswith("-") and not token[1].isdigit()


def _reduce_config(lines: list[str]) -> tuple[dict[tuple[str, str], _Effective], int]:
    """The running config as EFFECTIVE state: (familie, objectnaam) -> object,
    and HOW MANY of its lines could not be tokenised unambiguously.

    The name is lowercased in the KEY only (NetScaler object names are
    matched case-insensitively throughout this module); what the evidence
    prints comes from `_Effective.name`.

    Measured: the second value exists because
    dropping such a line is not free. Everything this reduction does NOT
    contain reads downstream as "it did not happen" - no existence, no
    field, no name - and a condition that comes out "niet gevonden" over it
    would be an ESTABLISHED denial on a source this product could not read.
    So the count travels with the state, and `_evaluate` says it out loud.

    Counted for EVERY line whose quoting does not close, and not only for
    the ones this reduction would otherwise have used. Which family a line
    belongs to, and whether it carries a config verb at all, is decided on
    the plain whitespace split - the very reading that just failed. Counting
    only what that reading claims to recognise would be trusting a parse
    this function has already declared unusable.
    """
    state: dict[tuple[str, str], _Effective] = {}
    unreadable = 0
    for line in lines:
        tokens, readable = _tokens(line)
        if not readable:
            unreadable += 1
        if len(tokens) < 2:
            continue
        lower = [token.lower() for token in tokens]
        verb = lower[0]
        if verb not in _CONFIG_VERBS:
            continue
        family = next(
            (candidate for candidate in _FAMILY_ORDER if lower[1 : 1 + len(candidate.split())] == candidate.split()),
            None,
        )
        if family is None:
            continue
        if not readable:
            # A quote that never closes. This product does not know which
            # object this line names, and both ways of guessing are wrong: a
            # fabricated name matches no readback row and would be reported as
            # an existence contradiction, and matching it against the readback
            # anyway would count an object as present that was never read. So
            # the line is not reduced at all. It is not dismissed either - a
            # line rule that reads it finds no name (`_name_after`) and keeps
            # counting, the same way it does for a line that declares none.
            continue
        index = 1 + len(family.split())
        if _LINE_FAMILIES[family]:
            if index >= len(tokens):
                # A line that names its family but no object. It establishes
                # nothing here; the rule that reads it keeps its own answer.
                continue
            key, written = (family, lower[index]), tokens[index]
            index += 1
        else:
            key, written = (family, ""), ""
        if verb in ("rm", "remove"):
            state.pop(key, None)
            continue
        if verb == "add":
            record = _Effective(name=written, added=True)
            state[key] = record
        else:
            record = state.get(key)
            if record is None:
                record = _Effective(name=written)
                state[key] = record
        while index < len(tokens):
            token = lower[index]
            if _is_flag(token):
                if verb == "unset":
                    record.fields.pop(token, None)
                    index += 1
                    continue
                if index + 1 < len(tokens) and not _is_flag(lower[index + 1]):
                    # The value as `_tokens` read it: a quoted value is one
                    # token and its quotes are gone with the quoting, so
                    # stripping them again here would eat a quote that is part
                    # of the value itself.
                    record.fields[token] = tokens[index + 1]
                    index += 2
                else:
                    # A flag without a value is still a flag that was set.
                    record.fields[token] = ""
                    index += 1
                continue
            if verb == "add" and record.kind is None:
                # The service type: the first positional token after the name.
                record.kind = token
            index += 1
    return state, unreadable


def _still_holds(state: dict, rule: _LineRule, name: str | None) -> bool:
    """Does the EFFECTIVE state still say what this line said?

    `name is None` on a rule that names an object means the line named none,
    and such a line cannot be reduced at all - it keeps counting, because
    over-reporting is the safe direction and this product does not dismiss
    evidence it failed to parse.

    Measured: a rule that reads a flag AND a type is a CONJUNCTION,
    and this returned on the flag alone - so a vserver removed and re-created
    under another type kept counting on the strength of its switch. Both
    halves are held against the effective state now; either one that no longer
    holds ends the line's claim.
    """
    if rule.names_object:
        if name is None:
            return True
        record = state.get((_family_of(rule.prefix), name.lower()))
    else:
        record = state.get((_family_of(rule.prefix), ""))
    if record is None:
        return False
    if rule.pair is not None:
        value = record.fields.get(rule.pair[0])
        if value is None or value.lower() != rule.pair[1]:
            return False
    if rule.kinds is not None:
        if record.kind is None or record.kind.lower() not in rule.kinds:
            return False
    return True


def _source_conflicts(export, state: dict) -> dict[tuple[str, str, str], str]:
    """Where the readback and the reduced lines DISAGREE about one object.

    The readback is the more authoritative of the two, and where it says
    something the lines do not contradict it simply wins - that is what an
    object source has always been here. But a real disagreement is not a
    precedence question: an export whose two halves say different things
    about the same switch has not been established either way, and picking
    one of them in silence is exactly the assumption this product refuses.
    So a contested (familie, naam, attribuut) is NOT ESTABLISHED, with the
    disagreement itself as the evidence.

    Only attributes some rule actually READS are compared (`_RECONCILED`):
    a difference in a field no condition rests on is not a finding, and
    printing it would be new surface without a question behind it.

    The one-sided case is the existence one: an object the collector did not
    return while the running config ADDS it is a contradiction, an object in
    the readback without a line is not - a running config records only what
    differs from the factory settings, so a built-in object is invisible in
    it by design. A `set` on an object the readback does not know is no
    contradiction either: a `set` states no existence, and the correlated
    rules already say out loud that they read and dismissed such a line.
    """
    conflicts: dict[tuple[str, str, str], str] = {}
    for family, (resource, name_field, kind_field) in _FAMILY_OBJECTS.items():
        attributes = _RECONCILED.get(family)
        if not attributes:
            continue
        rows, gap = export.objects(resource)
        if gap is not None:
            continue
        by_name = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            found = _readable(row.get(name_field))
            if found:
                by_name[found.lower()] = row
        for (line_family, name), record in state.items():
            if line_family != family or not name:
                continue
            row = by_name.get(name)
            if row is None:
                if record.added:
                    conflicts[(family, name, "*")] = (
                        f"{_CONTRADICTION}: {resource} zegt dat object {record.name}"
                        f" er niet is ({len(rows)} object(en) gelezen), running config"
                        " voegt het toe"
                    )
                continue
            actual = _readable(row.get(name_field)) or record.name
            if kind_field and "" in attributes and record.kind is not None:
                value = _readable(row.get(kind_field))
                if value is not None and value.lower() != record.kind.lower():
                    conflicts[(family, name, "")] = (
                        f"{_CONTRADICTION}: object {actual} zegt {kind_field}={value},"
                        f" running config zegt {record.kind}"
                    )
            for flag, written in record.fields.items():
                if flag not in attributes:
                    continue
                value = _readable(row.get(flag[1:]))
                if value is not None and value.lower() != written.lower():
                    conflicts[(family, name, flag)] = (
                        f"{_CONTRADICTION}: object {actual} zegt {flag[1:]}={value},"
                        f" running config zegt {flag[1:]}={written or '(leeg)'}"
                    )
    conflicts.update(_singleton_conflicts(export, state))
    return conflicts


def _singleton_conflicts(export, state: dict) -> dict[tuple[str, str, str], str]:
    """The same reconciliation for a family that names NO object.

    `set ns param -httpProfileName ...` is one global setting, and its
    readback is one object without a name field - so it fits no row of
    `_FAMILY_OBJECTS` and needs its own step. Without it the attribute was
    declared reconcilable and never compared, and `_global_default_profile`
    let the readback win in silence: the same export answered "niet gevonden
    [vastgesteld]" or "aanwezig [vastgesteld]" depending on which half carried
    the http2 profile, and the first of those is an ESTABLISHED denial over
    evidence the export itself contradicts.

    The conflict is keyed on the EMPTY object name, which is the key
    `_reduce_config` already gives a family that names nothing - so the
    lookup side needs no special case beyond knowing the family.

    Only the attributes some rule READS are compared, and only a readback
    this export actually carries: a parameter that is not in the manifest, or
    one that cannot be read, is a read gap where it is read - not a
    contradiction here.
    """
    conflicts: dict[tuple[str, str, str], str] = {}
    for family, resource in _SINGLETON_OBJECTS.items():
        attributes = _RECONCILED.get(family)
        if not attributes:
            continue
        record = state.get((family, ""))
        if record is None:
            continue
        if export.status(resource) in ("NIET_IN_MANIFEST", "GEEN_MANIFEST"):
            continue
        row, gap = export.single(resource)
        if gap is not None or row is None:
            continue
        for flag, written in record.fields.items():
            if flag not in attributes:
                continue
            value = _readable(row.get(flag[1:]))
            if value is not None and value.lower() != written.lower():
                conflicts[(family, "", flag)] = (
                    f"{_CONTRADICTION}: {resource} zegt {flag[1:]}={value},"
                    f" running config zegt {flag[1:]}={written or '(leeg)'}"
                )
    return conflicts


def _conflict(conflicts: dict, family: str | None, name: str | None, attribute: str, *more: str):
    """The disagreement about THIS object and the attributes a rule RESTS ON,
    or None. The `*` entry is the existence one: an object that may not be
    there at all is contested in every attribute at once.

    Measured: more than one attribute, because a rule may rest on
    more than one (`_rule_attributes`). The first disagreement found is the
    evidence; a contested object needs no second sentence to be unestablished.

    The FIRST attribute is required, and that is the whole contract.
    Widened to `*attributes` this accepted none and then quietly asked about
    the `*` key alone - a narrower question than the caller meant, which is
    exactly the shape of every finding of tasks 44 and 46. A caller that
    forgets to say what its rule rests on now fails at the call site instead
    of getting a silent half-answer.
    """
    if not family or not name:
        return None
    key = name.lower()
    found = conflicts.get((family, key, "*"))
    if found is not None:
        return found
    for candidate in (attribute,) + more:
        found = conflicts.get((family, key, candidate))
        if found is not None:
            return found
    return None


def _label_finding(**fields) -> Finding:
    """A Finding whose SUBJECT is not an appliance object name.

    Every subject this module writes is either one of this product's own
    labels ("build", "CVE-oordeel", "CVE-toets", "kennispakket") or a PUBLIC
    identifier out of the knowledge package (the bulletin name, the CVE id).
    None of them is an object on the customer's appliance.

    The disclosure seam collects every finding subject as a name to mask
    (`_collect_names`, disclosure.py), so in the 'beperkt' setting these came
    out as "object-04" - the reader lost the very identifier that makes a CVE
    answer usable - and each of them was written into the operator's pseudonym
    table as if it were a real object they own. This wrapper states the fact
    once, here, instead of repeating `subject_is_name=False` at a dozen call
    sites where a new one would silently forget it.
    """
    return Finding(subject_is_name=False, **fields)


def _evaluate_object_rule(export, rule: _ObjectRule, conflicts: dict | None = None) -> tuple[str, str, ReadGap | None]:
    """One object source: (uitkomst, bewijs, leesgat).

    A row the running config CONTRADICTS is not a hit here either.
    The readback is the more authoritative source and normally simply wins,
    but where the two halves of one export disagree about the same switch
    this product picks neither - in both directions, so a contradiction can
    never be settled by which source happened to be read first.
    """
    rows, gap = export.objects(rule.resource)
    if gap is not None:
        return _UNKNOWN, f"{rule.resource}: {gap.reason}", gap
    # Every object of this family whose EXISTENCE the two halves of
    # the export disagree about - the `*` key of `_source_conflicts`, and only
    # that one: a disagreement about a FIELD of an object that IS there is
    # decided per row below, where it belongs.
    #
    # It matters HERE only for a rule whose condition is the mere existence of
    # such an object, and there it is decisive: this source read the readback,
    # found nothing, and answering "niet gevonden [vastgesteld]" while the
    # running config ADDS exactly such an object is an established negative
    # over evidence the export itself contradicts. A NARROWED rule is a
    # different case and deliberately left alone: the running config that adds
    # the object also states the field this rule narrows on, and the line
    # sources of the same condition read it - so a `add lb vserver X SSL`
    # next to an empty readback stays a decided "no DNS proxy" instead of
    # becoming unanswerable over an object both halves agree is no DNS proxy.
    denied = sorted(
        {
            clash
            for (denied_family, _name, attribute), clash in (conflicts or {}).items()
            if attribute == "*" and denied_family == _OBJECT_FAMILIES.get(rule.resource)
        }
    )

    def _not_established(reason: str) -> tuple[str, str, ReadGap]:
        return _UNKNOWN, f"{rule.resource}: {reason}", ReadGap(source=rule.resource, reason=reason)

    if not rows:
        if denied and rule.field is None:
            return _not_established("; ".join(denied))
        return _ABSENT, f"{rule.resource}: 0 objecten", None

    def _name_of(row) -> str | None:
        value = row.get(rule.name_field)
        return value.strip() if isinstance(value, str) and value.strip() else None

    if rule.field is None:
        # An object IS there, so the mere-existence condition holds whatever
        # else the two halves disagree about: a contradiction about ANOTHER
        # object cannot unmake the ones this readback carries.
        found = sorted({n for n in (_name_of(row) for row in rows) if n})
        evidence = f"{rule.resource}: {len(rows)} object(en)"
        if found:
            evidence += ": " + ", ".join(found)
        return _PRESENT, evidence, None

    # A NARROWED rule, and the third outcome is the point of it. A row whose
    # deciding field cannot be read is not a row with the setting switched
    # off: calling those the same is the silent-green mechanism this product
    # exists to prevent: every verdict-driving field parses fail-closed. So a
    # row counts as a hit, a miss, or as UNREADABLE, and unreadable rows leave
    # the condition not established.
    label = f"{rule.field}={'/'.join(v.upper() for v in rule.values)}"
    if rule.gate_field is not None:
        label += f" en {rule.gate_field}={'/'.join(v.upper() for v in rule.gate_values)}"
    family = _OBJECT_FAMILIES.get(rule.resource)
    kind_field = _FAMILY_OBJECTS[family][2] if family else None

    def _attribute(field_name: str) -> str:
        """The key `_source_conflicts` files a disagreement about this field
        under: the empty string for the object TYPE, the flag for anything
        else."""
        return "" if field_name == kind_field else f"-{field_name}"

    # Measured: BOTH halves of the conjunction, exactly as
    # `_rule_attributes` does for a line rule. This rule may read a switch AND
    # a gate ("an SSL vserver WITH DoH on"), and it asked the reconciliation
    # about the switch only - so a readback carrying the SSL next to a running
    # config saying HTTP counted as a hit and the condition came out
    # "aanwezig [vastgesteld]" over an export that contradicts itself about
    # the very type the bulletin narrows on. The mirror (readback HTTP, line
    # SSL) was already not established, which made the answer to one and the
    # same contradiction depend on which half happened to carry the SSL.
    # Deduplicated, so a rule whose two fields share a key asks about it once.
    attributes = tuple(
        dict.fromkeys([_attribute(rule.field)] + ([_attribute(rule.gate_field)] if rule.gate_field is not None else []))
    )
    hits, unreadable, contested, geen_tekst = [], 0, [], []
    for row in rows:
        value = row.get(rule.field)
        if not isinstance(value, str) or not value.strip():
            if not rule.optional_field:
                unreadable += 1
            elif rule.field in row and not isinstance(value, str):
                # `optional_field` is for a field a
                # firmware does not HAVE - not for a field that IS there and
                # carries something this product cannot read. A JSON boolean,
                # number, list, object or null under the very key the verdict
                # rests on is a source that WAS read and could not be
                # interpreted, and swallowing it printed "niet gevonden
                # [vastgesteld]" - the one _ABSENT exit in this function
                # reachable over an unreadable source, and the same fail-open
                # class here. Its SHAPE travels, never its content.
                #
                # A key that is present and carries an EMPTY string stays
                # swallowed: on NITRO an absent field and an empty one both
                # mean "none set", the reading this module already holds for
                # the profile reference in `_ReferenceRule`.
                unreadable += 1
                geen_tekst.append(f"type={type(value).__name__}")
            continue
        if value.strip().lower() not in rule.values:
            continue
        if rule.gate_field is not None:
            # The row DOES carry the switch, so its type decides - and a type
            # this product cannot read leaves that undecided. Fail-closed
            # regardless of `optional_field`: that relaxation exists for a
            # firmware without the switch at all, not for a row that has it.
            gate = row.get(rule.gate_field)
            if not isinstance(gate, str) or not gate.strip():
                unreadable += 1
                continue
            if gate.strip().lower() not in rule.gate_values:
                continue
        clash = _conflict(conflicts or {}, family, _name_of(row), *attributes)
        if clash is not None:
            contested.append(clash)
            continue
        hits.append(_name_of(row))
    if hits:
        found = sorted({n for n in hits if n})
        evidence = f"{rule.resource}: {len(hits)} van {len(rows)} object(en) met {label}"
        if found:
            evidence += ": " + ", ".join(found)
        if contested:
            evidence += f"; {'; '.join(sorted(set(contested)))}"
        return _PRESENT, evidence, None
    if contested:
        return _not_established("; ".join(sorted(set(contested))))
    if unreadable:
        velden = rule.field if rule.gate_field is None else f"{rule.field}/{rule.gate_field}"
        reason = f"{unreadable} van {len(rows)} object(en) draagt geen leesbaar veld {velden}"
        if geen_tekst:
            reason += (
                f", waarvan {len(geen_tekst)} een veld {rule.field} draagt dat geen"
                f" tekst is ({'/'.join(sorted(set(geen_tekst)))})"
            )
        reason += f"; of {label} geldt is daarmee niet vast te stellen"
        return _not_established(reason)
    return _ABSENT, f"{rule.resource}: 0 van {len(rows)} object(en) met {label}", None


def _evaluate_line_rule(export, rule: _LineRule, state: dict, conflicts: dict) -> tuple[str, str, ReadGap | None]:
    """One running-config source: (uitkomst, bewijs, leesgat).

    A matching line is the START of the answer, not the end of it.
    Every hit is held against the EFFECTIVE state (`_still_holds`) and against
    the readback (`_conflict`), so a line a later `set`/`unset`/`rm` revoked
    stops counting and a line the objects contradict establishes nothing. All
    three outcomes get a sentence of their own: a line read and set aside in
    silence looks exactly like a line never seen.
    """
    lines, gap = export.running_config_lines()
    if gap is not None:
        return _UNKNOWN, f"{RUNNING_CONFIG_FILE}: {gap.reason}", gap
    hits = [line for line in lines if line.lower().startswith(rule.prefix) and _matches(line, rule)]
    if not hits:
        return (
            _ABSENT,
            f"{RUNNING_CONFIG_FILE}: 0 regels '{rule.label}' in {len(lines)} regels",
            None,
        )
    family = _family_of(rule.prefix)
    attributes = _rule_attributes(rule)
    live, undone, contested = [], [], []
    for line in hits:
        name = _name_after(line, len(rule.prefix)) if rule.names_object else None
        clash = _conflict(conflicts, family if family in _FAMILY_OBJECTS else None, name, *attributes)
        if clash is not None:
            contested.append(clash)
        elif _still_holds(state, rule, name):
            live.append(name)
        else:
            undone.append(name)

    def named(bucket) -> str:
        found = sorted({n for n in bucket if n}) if rule.names_object else []
        return ": " + ", ".join(found) if found else ""

    if live:
        evidence = f"{RUNNING_CONFIG_FILE}: {len(live)} regels '{rule.label}' in {len(lines)} regels{named(live)}"
        if undone:
            evidence += f" ({len(undone)} opgeheven door een latere set/unset/rm)"
        if contested:
            evidence += f"; {'; '.join(sorted(set(contested)))}"
        return _PRESENT, evidence, None
    if contested:
        reason = "; ".join(sorted(set(contested)))
        evidence = f"{RUNNING_CONFIG_FILE}: {len(hits)} regels '{rule.label}' in {len(lines)} regels; {reason}"
        return _UNKNOWN, evidence, ReadGap(source=_FAMILY_OBJECTS[family][0], reason=reason)
    evidence = (
        f"{RUNNING_CONFIG_FILE}: {len(hits)} regels '{rule.label}' in {len(lines)}"
        f" regels, opgeheven door een latere set/unset/rm{named(undone)}"
    )
    return _ABSENT, evidence, None


def _correlation_types(
    export, rule: _CorrelatedLineRule, lines: list[str], state: dict, conflicts: dict
) -> tuple[set[str], set[str]]:
    """The correlation as THREE outcomes, delivered as two sets of LOWERCASE
    object names: the names this export PROVES carry the required type, and
    the names it PROVES carry another one. A name in neither set is a name
    whose target or whose type this export does not establish at all.

    Out of the same two sources this module uses everywhere: the object family
    (the precise one) and the `add` line that created the object (the one that
    survives an unreadable object resource).

    This used to return ONE set
    - "correlates" - and everything outside it was treated as a proven
    non-match, so a `set` on a vserver neither source knows came out "niet
    gevonden [vastgesteld]". That is a fail-open false negative: a correlation
    this product could not MAKE is not a correlation it DISPROVED. So the
    refutation is now positive evidence in its own right, and a source that
    cannot be read contributes to neither set - which lands the `set` line in
    the read-gap branch of `_evaluate_correlated_line_rule` instead of in an
    established absence.

    The `add` half reads the EFFECTIVE state, so a vserver that was
    removed (or created under another type after a `rm`) no longer lends its
    name to a `set` line, and a name the two sources disagree about lends
    nothing at all - the disagreement is reported where the `set` line is
    read, not swallowed here.
    """
    matched: set[str] = set()
    refuted: set[str] = set()
    family = _family_of(rule.add_line.prefix)
    known = family if family in _FAMILY_OBJECTS else None
    rows, _ = export.objects(rule.resource)
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = _readable(row.get(rule.name_field))
        kind = _readable(row.get(rule.type_field))
        if not name or _conflict(conflicts, known, name, "") is not None:
            continue
        if kind is None:
            # A row whose TYPE field carries no readable text proves nothing
            # in either direction. Read as "not of the required type" this was
            # an established denial over a field this product never read.
            continue
        (matched if kind.lower() in rule.type_values else refuted).add(name.lower())
    for line in lines:
        if not line.lower().startswith(rule.add_line.prefix):
            continue
        name = _name_after(line, len(rule.add_line.prefix))
        if not name or _conflict(conflicts, known, name, "") is not None:
            continue
        record = state.get((family, name.lower()))
        if record is None or record.kind is None:
            # Removed by a later `rm`, or an `add` whose type token this
            # product could not read: no proof either way.
            continue
        if record.kind.lower() not in rule.type_values:
            # A service type cannot be changed by a `set`, so the EFFECTIVE
            # `add` settles it - this is the one thing a running config states
            # about the type of an object whose readback is missing.
            #
            # Compared lowercase, like every other type
            # comparison in this module (`_still_holds`, and the readback half
            # above). `_reduce_config` already lowercases the token, so this
            # changes no answer today - it removes the one place where the
            # rule was implicit, because a comparison that depends on a
            # promise made elsewhere is where a later reader builds a case bug
            # into a REFUTATION.
            refuted.add(name.lower())
        elif _still_holds(state, rule.add_line, name):
            matched.add(name.lower())
    # A name both halves claim is a name neither of them establishes.
    disputed = matched & refuted
    return matched - disputed, refuted - disputed


def _evaluate_correlated_line_rule(
    export, rule: _CorrelatedLineRule, state: dict, conflicts: dict
) -> tuple[str, str, ReadGap | None]:
    """One correlated running-config source: (uitkomst, bewijs, leesgat).

    A `set` line only counts next to the object it changes, and THAT question
    has three answers, not two:

    - the object is PROVABLY of the required type: the condition is present;
    - it is PROVABLY of another type: "niet gevonden", with the sentence that
      says which line was read and why it was set aside - a line dismissed in
      silence looks like a line never seen;
    - target or type NOT DETERMINABLE: "niet vastgesteld", with a read gap.

    That last one used to fall in with the second, and it is the difference
    between a measurement and a guess: `set lb vserver UNKNOWN -dnsOverHttps
    ENABLED` next to a `config/lbvserver` that was read and is empty means the
    line WAS read and IS effective while only its target's type stayed unknown.
    Reported as an established absence that printed "NIET GERAAKT
    [vastgesteld]" on a vulnerable build - a fail-open false negative, the one
    direction this product may not err in.

    The same three-way reading as `_evaluate_line_rule` - a `set`
    that a later `set`/`unset`/`rm` revoked is no longer a hit, and a `set` on
    an object the readback contradicts establishes nothing either way.
    """
    lines, gap = export.running_config_lines()
    if gap is not None:
        return _UNKNOWN, f"{RUNNING_CONFIG_FILE}: {gap.reason}", gap
    family = _family_of(rule.line.prefix)
    contested_family = family if family in _FAMILY_OBJECTS else None
    # The attributes of BOTH halves. This line rests on its flag,
    # and the CORRELATION it needs rests on the service type the `add` line
    # carries - so a readback that disagrees about that type contests this
    # answer exactly as much as one that disagrees about the flag. Keyed on
    # the flag alone, a contested type fell through the correlation as "no
    # name at all" and the condition came out "niet gevonden [vastgesteld]":
    # an ESTABLISHED negative over evidence the export itself contradicts,
    # which is the one direction this product may not err in. Deduplicated,
    # so two halves that share an attribute ask about it once.
    attributes = tuple(dict.fromkeys(_rule_attributes(rule.line) + _rule_attributes(rule.add_line)))
    raw = [line for line in lines if line.lower().startswith(rule.line.prefix) and _matches(line, rule.line)]
    if not raw:
        return (
            _ABSENT,
            f"{RUNNING_CONFIG_FILE}: 0 regels '{rule.line.label}' in {len(lines)} regels",
            None,
        )
    hits, undone, contested = [], [], []
    for line in raw:
        name = _name_after(line, len(rule.line.prefix))
        clash = _conflict(conflicts, contested_family, name, *attributes)
        if clash is not None:
            contested.append(clash)
        elif _still_holds(state, rule.line, name):
            hits.append(line)
        else:
            undone.append(name)

    def not_established() -> tuple[str, str, ReadGap]:
        """The contradiction IS the answer, wherever the line got stuck: the
        export was read, its two halves disagree about this object, and the
        disagreement travels as the evidence and as the read gap. One shape
        for both stops, so a contested type cannot come out differently from
        a contested value depending on how far the line got."""
        reason = "; ".join(sorted(set(contested)))
        evidence = f"{RUNNING_CONFIG_FILE}: {len(raw)} regels '{rule.line.label}' in {len(lines)} regels; {reason}"
        return _UNKNOWN, evidence, ReadGap(source=_FAMILY_OBJECTS[family][0], reason=reason)

    if not hits:
        if contested:
            return not_established()
        found = sorted({n for n in undone if n})
        evidence = (
            f"{RUNNING_CONFIG_FILE}: {len(raw)} regels '{rule.line.label}' in {len(lines)}"
            f" regels, opgeheven door een latere set/unset/rm"
        )
        if found:
            evidence += ": " + ", ".join(found)
        return _ABSENT, evidence, None
    matched, refuted = _correlation_types(export, rule, lines, state, conflicts)
    correlated, dismissed, uncorrelatable = [], [], []
    for line in hits:
        name = _name_after(line, len(rule.line.prefix))
        key = name.lower() if name else None
        if key is not None and key in matched:
            correlated.append(name)
        elif key is not None and key in refuted:
            dismissed.append(name)
        else:
            # No name at all (a line whose quoting does not close), or a name
            # neither source can place: not determinable, and therefore not
            # disproved either.
            uncorrelatable.append(name)
    if not correlated:
        if contested:
            # NOT "niet gecorreleerd": the correlation could not be made
            # BECAUSE the sources disagree about the very type it rests on.
            # A `set` whose target this export PROVES is of another type -
            # nothing contested - keeps its own stated reason below.
            return not_established()
        if uncorrelatable:
            # The line was read and is effective; what could not be
            # established is the TYPE of the object it changes. A read gap,
            # not an absence.
            found = sorted({n for n in uncorrelatable if n})
            reason = (
                f"regel '{rule.line.label}' is gelezen en effectief, maar niet te"
                f" correleren aan {rule.correlation_label}: doel of type niet vast"
                f" te stellen uit {rule.resource} of een add-regel"
            )
            if found:
                reason += ": " + ", ".join(found)
            evidence = (
                f"{RUNNING_CONFIG_FILE}: {len(uncorrelatable)} regels"
                f" '{rule.line.label}' in {len(lines)} regels; {reason}"
            )
            return _UNKNOWN, evidence, ReadGap(source=rule.resource, reason=reason)
        found = sorted({n for n in dismissed if n})
        evidence = (
            f"{RUNNING_CONFIG_FILE}: {len(dismissed)} regels '{rule.line.label}' in {len(lines)}"
            f" regels, niet gecorreleerd aan {rule.correlation_label}"
        )
        if found:
            evidence += ": " + ", ".join(found)
        return _ABSENT, evidence, None
    found = sorted({n for n in correlated if n})
    evidence = (
        f"{RUNNING_CONFIG_FILE}: {len(correlated)} regels '{rule.line.label}' in {len(lines)}"
        f" regels, gecorreleerd aan {rule.correlation_label}"
    )
    if found:
        evidence += ": " + ", ".join(found)
    if dismissed:
        evidence += f" ({len(dismissed)} niet gecorreleerd)"
    if uncorrelatable:
        # Said out loud next to an established PRESENT too: one proven example
        # answers the question this condition asks, so the answer stands - but
        # a line this product could not place is never silently dropped.
        evidence += f" ({len(uncorrelatable)} niet te correleren)"
    if contested:
        evidence += f"; {'; '.join(sorted(set(contested)))}"
    return _PRESENT, evidence, None


def _readable(value) -> str | None:
    """The trimmed text a field carries, or None when it carries no readable
    text at all. One helper, so "a field this product cannot read" means
    exactly the same thing in every rule here.
    """
    return value.strip() if isinstance(value, str) and value.strip() else None


def _first_readable(row: dict, fields: tuple[str, ...]) -> str | None:
    """The name an object gives itself, out of the first field that carries
    one - a servicegroup names itself in `servicegroupname`, a vserver in
    `name`.
    """
    for field_name in fields:
        found = _readable(row.get(field_name))
        if found is not None:
            return found
    return None


def _global_default_profile(
    export, rule: _ReferenceRule, state: dict, conflicts: dict | None = None
) -> tuple[str | None, str, ReadGap | None]:
    """Which profile an object WITHOUT its own reference inherits.

    Two sources, in this order: the parameter object, and the running-config
    line that sets it. A running config records only what DIFFERS from the
    factory settings, so the line source is exactly the one that catches an
    operator who pointed the global default at an http2 profile - the case a
    caveat would otherwise hide.

    Returns `(profielnaam, bewijs, leesgat)`. `profielnaam` is None when the
    export does not carry the parameter at all, and that is deliberately NOT
    a read gap: MEASURED (2026-09-03), `config/nsparam` of the real export is
    readable and simply carries no such field, so failing the condition on it
    would answer "niet vastgesteld" on every export this collector makes.
    The caller says out loud what was not read instead (`_NO_GLOBAL_DEFAULT`).
    A parameter that IS in the manifest and cannot be READ is a read gap, as
    everywhere else.

    The running config is read WITHOUT its gap here on purpose: the profile
    lines of the same rule already read that file and already report that
    gap, and one unreadable file may not put the same gap on an answer twice.

    The line half reads the EFFECTIVE value of the parameter, so an
    operator who pointed the global default somewhere and later `unset` it
    inherits the built-in default again - which is what the appliance does.

    And the two halves are RECONCILED before either of them wins.
    They are two sources of one export like everywhere else in this module,
    so a disagreement about which profile the global default names is not a
    precedence question but an unestablished fact - in both directions. The
    name harvest calls this without `conflicts` on purpose: it must see every
    name either half could put in a sentence, and a contradiction prints
    both.
    """
    clash = (conflicts or {}).get((_family_of(rule.default_prefix), "", f"-{rule.default_field}"))
    if clash is not None:
        return None, f"{rule.default_resource}: {clash}", ReadGap(source=rule.default_resource, reason=clash)
    if export.status(rule.default_resource) not in ("NIET_IN_MANIFEST", "GEEN_MANIFEST"):
        row, gap = export.single(rule.default_resource)
        if gap is not None:
            return None, f"{rule.default_resource}: {gap.reason}", gap
        found = _readable((row or {}).get(rule.default_field))
        if found is not None:
            return found, f"{rule.default_resource}: standaardprofiel {found}", None
    _, lines_gap = export.running_config_lines()
    record = state.get((_family_of(rule.default_prefix), ""))
    if record is not None:
        found = _readable(record.fields.get(f"-{rule.default_field}"))
        if found is not None:
            return found, f"{RUNNING_CONFIG_FILE}: standaardprofiel {found}", None
    if rule.builtin_default and lines_gap is None:
        # Nothing pointed the global default anywhere else, and the running
        # config was READ - which is what makes this the appliance's factory
        # default rather than a guess (see `_ReferenceRule.builtin_default`).
        return (
            rule.builtin_default,
            f"{RUNNING_CONFIG_FILE}: geen '{rule.default_prefix} -{rule.default_field}';"
            f" ingebouwd standaardprofiel {rule.builtin_default}",
            None,
        )
    return None, "", None


def _evaluate_reference_rule(
    export, rule: _ReferenceRule, state: dict, conflicts: dict
) -> tuple[str, str, ReadGap | None, str]:
    """One 'the profile is IN USE' source: (uitkomst, bewijs, leesgat,
    kanttekening).

    The fourth value is the difference with the other two evaluators: this
    condition can be DECIDED while one thing about it stayed unread (the
    profile the objects without their own reference inherit), and then the
    evidence has to say so - also, and especially, under a negative outcome.
    A caveat that only ever travels with a positive one would leave exactly
    the "niet aanwezig" that this half-knowledge could contradict unqualified.
    """
    label = f"{rule.field}={'/'.join(v.upper() for v in rule.values)}"
    parts: list[str] = []
    # TWO buckets, because not every unread source can change this outcome.
    # `gaps` is decisive by itself: a profile whose state cannot be read, a
    # reference that cannot be classified, an unreadable global default. A
    # `family_gap` is an unread REFERRER family, and that one only matters
    # when some profile carries the setting at all - with every profile read
    # and none of them carrying it, an unread family cannot hold a reference
    # to a profile that does not exist, and answering "niet vastgesteld"
    # over it would be over-reporting without cause.
    gaps: list[ReadGap] = []
    family_gaps: list[ReadGap] = []
    on: set[str] = set()
    off: set[str] = set()
    unreadable = 0
    # This rule reads the profile state TWICE - out of the objects
    # and out of the lines - and in the direction where the LINE carries the
    # ENABLED both halves met the same disagreement and both printed it. One
    # disagreement is one sentence; a reader who meets it twice counts two
    # problems. The read gap is deduplicated with it: only the first travels
    # anyway, and two identical ones say nothing the one does not.
    reported: set[str] = set()

    # 1. The profile STATE, out of the objects.
    rows, gap = export.objects(rule.resource)
    if gap is not None:
        gaps.append(gap)
        parts.append(f"{rule.resource}: {gap.reason}")
    elif not rows:
        parts.append(f"{rule.resource}: 0 objecten")
    else:
        # Measured: the readback half reads the SAME reconciliation
        # as the line half below. A profile the two sources of one export
        # disagree about is not a profile with the setting on, and not one
        # with it off either - it is a profile whose state was not
        # established, and an object referencing it inherits that. Without
        # this the object simply won in silence, in one direction only: the
        # mirror case (object off, line on) was already not established, so
        # the same export could be answered two ways depending on which half
        # happened to carry the ENABLED.
        object_family = _OBJECT_FAMILIES.get(rule.resource)
        contested: list[str] = []
        for row in rows:
            name = _readable(row.get(rule.name_field))
            value = _readable(row.get(rule.field))
            if name is None or value is None:
                unreadable += 1
                continue
            clash = _conflict(conflicts, object_family, name, f"-{rule.field}")
            if clash is not None:
                contested.append(clash)
                continue
            (on if value.lower() in rule.values else off).add(name)
        evidence = f"{rule.resource}: {len(on)} van {len(rows)} object(en) met {label}"
        if on:
            evidence += ": " + ", ".join(sorted(on))
        if unreadable:
            # A row whose deciding field cannot be read is not a row with the
            # setting switched off - the same fail-closed rule as in
            # `_evaluate_object_rule`, and here it also means that an object
            # referencing THAT profile cannot be judged.
            reason = (
                f"{unreadable} van {len(rows)} object(en) draagt geen leesbaar veld"
                f" {rule.field}; of {label} daar geldt is niet vast te stellen"
            )
            evidence += f"; {reason}"
            gaps.append(ReadGap(source=rule.resource, reason=reason))
        parts.append(evidence)
        for clash in sorted(set(contested)):
            gaps.append(ReadGap(source=rule.resource, reason=clash))
            parts.append(f"{rule.resource}: {clash}")
            reported.add(clash)

    # 2. The same state out of the running config, which may only ADD.
    lines, line_gap = export.running_config_lines()
    if line_gap is not None:
        gaps.append(line_gap)
        parts.append(f"{RUNNING_CONFIG_FILE}: {line_gap.reason}")
    else:
        # The same EFFECTIVE reading as everywhere else - a profile
        # line a later `set`/`unset`/`rm` revoked no longer says the setting
        # is on. And where the readback CONTRADICTS the reduced lines about
        # one profile, that profile's state is not established at all: this
        # used to resolve to "on" as the safe direction, which is fine for a
        # line the objects are silent about but not for two sources of one
        # export that say different things.
        named: set[str] = set()
        for line_rule in rule.profile_lines:
            family = _family_of(line_rule.prefix)
            known = family if family in _FAMILY_OBJECTS else None
            attributes = _rule_attributes(line_rule)
            for line in lines:
                if not line.lower().startswith(line_rule.prefix):
                    continue
                if not _matches(line, line_rule):
                    continue
                found = _name_after(line, len(line_rule.prefix))
                if not found:
                    continue
                clash = _conflict(conflicts, known, found, *attributes)
                if clash is not None:
                    if clash not in reported:
                        gaps.append(ReadGap(source=rule.resource, reason=clash))
                        parts.append(f"{rule.resource}: {clash}")
                        reported.add(clash)
                    on.discard(found)
                    off.discard(found)
                    continue
                if _still_holds(state, line_rule, found):
                    named.add(found)
        # A line the objects are SILENT about resolves to "the setting is on":
        # over-reporting one profile's state is the safe direction there.
        off -= named
        on |= named
        evidence = f"{RUNNING_CONFIG_FILE}: {len(named)} profiel(en) '{rule.line_label}' in {len(lines)} regels"
        if named:
            evidence += ": " + ", ".join(sorted(named))
        parts.append(evidence)

    # 3. The ASSOCIATION: who references such a profile.
    #
    # Out of BOTH sources, like every other fact here. The readback
    # says which profile hangs on an object today; the running config says
    # which one an operator hung on it, and a running config records only
    # what differs from the factory settings - so a `set lb vserver X
    # -httpProfileName ...` is exactly the change that used to be invisible.
    # Where the two disagree the binding is not established (the ordinary
    # `brontegenspraak`, filed by `_source_conflicts` because the family is in
    # `_FAMILY_OBJECTS`); where only the line carries one, the line decides;
    # where only the readback does, nothing changes.
    # NetScaler resolves object names case-insensitively, and this module says
    # so everywhere else (`_reduce_config` keys on the lowered name). Here it
    # did not, so a vserver naming `PROF_X` while the profile calls itself
    # `Prof_X` produced a read gap over a reference the appliance resolves
    # without blinking - fail-closed, but an ordinary export turned
    # unanswerable.
    on_lower = {name.lower() for name in on}
    off_lower = {name.lower() for name in off}
    reference_flag = f"-{rule.reference_field}"
    hits: list[str] = []
    referencing = 0
    inheriting = 0
    seen = 0
    for resource in rule.referrers:
        referrer_rows, referrer_gap = export.objects(resource)
        if referrer_gap is not None:
            family_gaps.append(referrer_gap)
            parts.append(f"{resource}: {referrer_gap.reason}")
            continue
        family = _OBJECT_FAMILIES.get(resource)
        seen += len(referrer_rows)
        for row in referrer_rows:
            named = _first_readable(row, (rule.name_field,) + rule.extra_name_fields)
            clash = _conflict(conflicts, family, named, reference_flag)
            if clash is not None:
                gaps.append(ReadGap(source=resource, reason=clash))
                parts.append(f"{resource}: {clash}")
                continue
            written = None
            if family is not None and named is not None:
                record = state.get((family, named.lower()))
                if record is not None:
                    written = _readable(record.fields.get(reference_flag))
            raw = row.get(rule.reference_field)
            if raw is None or (isinstance(raw, str) and not raw.strip()):
                if written is None:
                    # No profile of its own - an absent field and an empty one
                    # mean the same thing on NITRO ("none set"), and both mean
                    # this object runs on the global default, which step 4
                    # decides. Calling an empty value unreadable would turn the
                    # most ordinary vserver on any appliance into a read gap.
                    inheriting += 1
                    continue
                # The line hangs a profile on an object the readback carries
                # none for. Nothing contradicts it, so it decides.
                raw = written
            who = _first_readable(row, (rule.name_field,) + rule.extra_name_fields) or "(naamloos)"
            if not isinstance(raw, str):
                # A field that carries something other than text is broken,
                # not empty - and its raw content is never reproduced, only
                # its shape (the same rule as elsewhere in this product).
                reason = (
                    f"{who} draagt een veld {rule.reference_field} dat geen tekst is"
                    f" (type={type(raw).__name__}); welk profiel eraan hangt is niet"
                    " vast te stellen"
                )
                gaps.append(ReadGap(source=resource, reason=reason))
                parts.append(f"{resource}: {reason}")
                continue
            reference = raw.strip()
            referencing += 1
            if reference.lower() in on_lower:
                hits.append(f"{resource} {who} -> {reference}")
            elif reference.lower() not in off_lower:
                reason = (
                    f"{who} verwijst naar profiel {reference}, waarvan {rule.resource}"
                    f" de stand niet leesbaar draagt; of {label} geldt is daarmee"
                    " niet vast te stellen"
                )
                gaps.append(ReadGap(source=rule.resource, reason=reason))
                parts.append(f"{resource}: {reason}")
        # A referrer the running config ADDS while this readback says
        # it is not there. That is the existence contradiction
        # `_source_conflicts` files for every reconciled family, and the loop
        # above cannot see it: it walks readback rows, and this object has
        # none. Consulted here rather than left computed-and-unread - which is
        # precisely the silent hole the global default fell into.
        #
        # In the FAMILY bucket, because that is what such an object
        # is - a referrer whose reference this export does not know. The
        # header of this function says when that weighs: only where some
        # profile carries the setting at all. Filed among the decisive gaps it
        # contradicted its own rule, and the same ignorance about the same
        # object got two answers depending on whether its family was UNREAD
        # (`family_gap`, "niet gevonden") or READ-AND-EMPTY ("niet
        # vastgesteld"). With every profile read and none of them carrying the
        # setting, an object the readback denies cannot point at a profile
        # that does not exist; where one DOES carry it, this bucket is
        # decisive exactly as an unread family is. The sentence stays either
        # way - a contradiction read and set aside in silence looks like one
        # never read.
        if family is not None:
            for (line_family, key), _record in state.items():
                if line_family != family or not key:
                    continue
                clash = conflicts.get((family, key, "*"))
                if clash is not None:
                    family_gaps.append(ReadGap(source=resource, reason=clash))
                    parts.append(f"{resource}: {clash}")
    reference_part = (
        f"{referencing} van {seen} object(en) in vserver/service draagt een"
        f" {rule.reference_field}; {len(hits)} daarvan wijst naar een profiel met {label}"
    )
    if hits:
        reference_part += ": " + ", ".join(sorted(hits))
    parts.append(reference_part)

    # 4. What the objects WITHOUT their own reference inherit.
    default_name, default_part, default_gap = _global_default_profile(export, rule, state, conflicts)
    if default_gap is not None:
        gaps.append(default_gap)
    # A default profile hangs on the objects that have none of their own -
    # and on nothing else. With every object carrying its own profile the
    # default's state cannot change this condition, so it neither establishes
    # it nor makes it unreadable.
    default_hit = default_name is not None and default_name.lower() in on_lower and inheriting > 0
    if default_part:
        if default_hit:
            default_part += f" draagt {label}; {inheriting} object(en) zonder eigen profiel erven dat"
        elif inheriting == 0:
            default_part += "; geen object zonder eigen profiel, dus niets erft het"
        elif default_name is not None and default_name.lower() not in off_lower:
            reason = (
                f"{rule.resource} draagt de stand van standaardprofiel {default_name}"
                f" niet leesbaar; of {label} geldt voor vservers zonder eigen profiel"
                " is niet vast te stellen"
            )
            gaps.append(ReadGap(source=rule.resource, reason=reason))
            default_part += f"; {reason}"
        elif default_name is not None:
            default_part += f" draagt geen {label}"
        # And with NO default name the sentence stops here. It
        # already says why - the parameter contradicts the running config, or
        # could not be read - and "draagt geen http2=ENABLED" behind that
        # would be a claim about the very thing that was not established.
        parts.append(default_part)

    if hits or default_hit:
        outcome = _PRESENT
    elif gaps or (family_gaps and on):
        outcome = _UNKNOWN
    else:
        outcome = _ABSENT
    # The caveat rides along with a DECIDED absence, and only where the
    # unread half could have contradicted it: a profile that carries the
    # setting has to hang on something, and an unread global default is
    # exactly such a something.
    caveat = _NO_GLOBAL_DEFAULT if (outcome == _ABSENT and on and default_name is None) else ""
    decisive = gaps + family_gaps
    return outcome, "; ".join(parts), (decisive[0] if outcome == _UNKNOWN else None), caveat


def _evaluate(export, name: str) -> tuple[str, str, ReadGap | None]:
    """The three-value outcome, its evidence, and the read gap behind a
    'niet vastgesteld' - so the caller can put that gap on the answer and
    the "NIET VASTGESTELD" block is filled instead of an answer that reports
    an unestablished condition while claiming to be complete.

    And, once per condition, what the running config could NOT be read to
    say. A line whose quote never
    closes is dropped by `_reduce_config`, and until now it was dropped in
    SILENCE: the same export answered "niet vastgesteld" with the quote
    closed and an established "NIET GERAAKT" without it, and no word in
    either answer said a line had been unreadable. Two things follow, and
    they happen here rather than in the individual sources because the count
    is a property of the EXPORT: a reader who meets the same sentence once
    per source counts as many problems as there are sources.

    - The count is NAMED whenever it is not zero, under EVERY outcome. A
      line read and set aside in silence looks exactly like a line that was
      never there - the argument this module makes about every other source.
    - An outcome that would be ABSENT becomes NOT ESTABLISHED. Deliberately
      not narrowed to the families or flags the condition happens to read:
      which family such a line belongs to, and which flags stand in it, can
      only be decided by the tokenisation that just failed - everything
      behind the unclosed quote is one unterminated string in which this
      product cannot tell a flag from comment text. A narrowing that errs in
      the "does not concern this condition" direction restores exactly the
      silent established negative this repair removes, and it would err on
      the strength of a parse this module has already called unusable. The
      price of the wider rule is bounded and visible: a negative becomes an
      unestablished one WITH a stated reason, never a wrong verdict.

    A PRESENT outcome is never downgraded. Over-reporting stays the safe
    direction, exactly as it is for the line rules that keep counting an
    unreadable line as evidence: this module does not dismiss evidence it
    failed to parse, and it does not turn evidence it DID read into a
    non-answer either.

    Inert on what the released collector writes: the real export carries 0
    unreadable lines in 333, and its answer is unchanged byte for byte.
    """
    outcome, evidence, gap, unreadable = _evaluate_condition(export, name)
    if not unreadable:
        return outcome, evidence, gap
    reason = _UNREADABLE_LINES.format(count=unreadable)
    evidence += f"; {reason}"
    if outcome != _ABSENT:
        return outcome, evidence, gap
    reason += f"; {_UNREADABLE_CONSEQUENCE}"
    evidence += f"; {_UNREADABLE_CONSEQUENCE}"
    return _UNKNOWN, evidence, ReadGap(source=RUNNING_CONFIG_FILE, reason=reason)


def _evaluate_condition(export, name: str) -> tuple[str, str, ReadGap | None, int]:
    """The same three values, plus the number of running-config lines that
    could not be tokenised - which `_evaluate` above turns into a sentence
    and, where it matters, into a withheld verdict. Recursion goes through
    HERE, so a composite condition gets that sentence once and not once per
    operand.
    """
    if name == "altijd":
        return "aanwezig", "voorwaarde geldt onvoorwaardelijk", None, 0

    if name in _COMPOSITE_PREDICATES:
        operator, operands = _COMPOSITE_PREDICATES[name]
        parts = [_evaluate_condition(export, operand) for operand in operands]
        outcome = _combine(operator, [p[0] for p in parts])
        joiner = " OF " if operator == "of" else " EN "
        # An operand that is itself a joined evidence gets brackets, so
        # "A OF B EN C" cannot be read as the wrong grouping. Without them
        # the reader has to know which half of the sentence binds tighter,
        # and this product does not hand a reader that kind of homework.
        evidence = joiner.join(f"({p[1]})" if (" OF " in p[1] or " EN " in p[1]) else p[1] for p in parts)
        # The gap only travels when it still MATTERS: a condition that came
        # out decided has no unestablished half left to report, and putting
        # that gap on the answer would make a complete answer look incomplete.
        gap = None
        if outcome == _UNKNOWN:
            gap = next((p[2] for p in parts if p[2] is not None), None)
        # Every operand read the SAME export, so these are the same number;
        # taking the largest keeps that true even for an operand that never
        # reached the running config.
        return outcome, evidence, gap, max((p[3] for p in parts), default=0)

    if name in _SOURCE_PREDICATES:
        sources = _SOURCE_PREDICATES[name]
        # ONE reduction and ONE reconciliation per condition, computed before
        # any source is read: the effective state and the disagreements with
        # the readback are properties of the EXPORT, not of the rule that
        # happens to look at them, and computing them per rule would let two
        # sources of one condition answer by different yardsticks.
        lines, _ = export.running_config_lines()
        state, unreadable = _reduce_config(lines)
        conflicts = _source_conflicts(export, state)
        parts = [_evaluate_object_rule(export, rule, conflicts) for rule in sources.objects]
        parts += [_evaluate_line_rule(export, rule, state, conflicts) for rule in sources.lines]
        parts += [_evaluate_correlated_line_rule(export, rule, state, conflicts) for rule in sources.correlated_lines]
        caveats: list[str] = []
        for rule in sources.references:
            outcome_, evidence_, gap_, caveat_ = _evaluate_reference_rule(export, rule, state, conflicts)
            parts.append((outcome_, evidence_, gap_))
            if caveat_:
                caveats.append(caveat_)
        outcome = _combine("of", [p[0] for p in parts])
        evidence = " OF ".join(p[1] for p in parts)
        if outcome == _PRESENT and sources.caveat:
            # Said out loud, not left to the reader: what this product did
            # NOT check about a condition it reports as present.
            evidence += f" ({sources.caveat})"
        if outcome == _ABSENT and caveats:
            # The other direction, and the one a static caveat cannot carry:
            # a source may have DECIDED "niet aanwezig" while something it
            # needed stayed unread. The gate on the CONDITION outcome (not on
            # the source's own) keeps a caveat from surviving a sibling
            # source that established the condition anyway.
            evidence += f" ({'; '.join(caveats)})"
        gap = None
        if outcome == _UNKNOWN:
            gap = next((p[2] for p in parts if p[2] is not None), None)
        return outcome, evidence, gap, unreadable

    # Unknown predicate. `knowledge.py` refuses such a package at load time,
    # so this is the second net - but a Knowledge built by hand (or a future
    # loader path) must not slip a condition past unevaluated and unseen. The
    # gap is on the KNOWLEDGE source, not on the export: the export is fine,
    # the rule is not.
    return (
        "niet vastgesteld",
        f"kennispakket: onbekend predicaat {name!r}",
        ReadGap(
            source="kennispakket",
            reason=(
                f"het kennispakket noemt de voorwaarde {name!r}, die dit product niet kan"
                " berekenen; de voorwaarde is daarmee niet vast te stellen"
            ),
        ),
        0,
    )


def evaluate_predicate(export, name: str) -> tuple[str, str]:
    """(uitkomst, bewijs), with uitkomst in {"aanwezig", "niet gevonden",
    "niet vastgesteld"}. The read gap behind a "niet vastgesteld" is dropped
    here on purpose: this is the public two-value interface; `cve_check` uses
    `_evaluate` so it can also put that gap on the answer.
    """
    outcome, evidence, _ = _evaluate(export, name)
    return outcome, evidence


def names_in_predicate_sources(export) -> tuple[str, ...]:
    """Every appliance object name the condition evidence above can put into
    an answer text.

    Not decoration: in the 'beperkt' disclosure setting only names the
    collection KNOWS are pseudonymized, and a name it does not know travels
    through verbatim. The Gateway/AAA vserver names and the SAML/LSN object
    names appear in NO other name family (they are neither certificates nor
    ssl-vserver bindings), so without this the very evidence that makes the
    condition honest would leak the real name. Derived from the SAME sources
    and the SAME fields as `_evaluate` above - one derivation, two consumers -
    so the collection and the evidence can never drift apart.

    Fail-closed by construction, exactly like `names_from_export`: an
    unreadable source simply yields fewer names, and a name the export could
    not read can never appear in a text either.
    """
    names: set[str] = set()
    lines, _ = export.running_config_lines()
    state, _unreadable = _reduce_config(lines)
    object_rules = {r for s in _SOURCE_PREDICATES.values() for r in s.objects}
    line_rules = {r for s in _SOURCE_PREDICATES.values() for r in s.lines if r.names_object}
    reference_rules = {r for s in _SOURCE_PREDICATES.values() for r in s.references}
    # A correlated rule writes a name into its evidence in BOTH directions:
    # the vserver it correlated, and - the one no other family here knows -
    # the vserver of a `set` line it read and dismissed as uncorrelated. That
    # second one exists in this export ONLY on that line, so without both its
    # prefixes here the sentence that makes the dismissal honest would leak
    # the real name in the 'beperkt' setting. Harvested WITHOUT the narrowing
    # tests, exactly like the line rules below.
    for rule in (r for s in _SOURCE_PREDICATES.values() for r in s.correlated_lines):
        line_rules |= {r for r in (rule.line, rule.add_line) if r.names_object}
        object_rules.add(_ObjectRule(rule.resource, rule.name_field))
    for rule in reference_rules:
        # A reference rule writes THREE kinds of name into its evidence: the
        # profile, the object that hangs it on itself, and the profile the
        # others inherit. All three are appliance objects, and the last two
        # appear in no other family (a servicegroup is known to the dienst
        # family, an lb/cs vserver too - but a service or a bare csvserver
        # that carries only an httpprofilename is known to none). Harvested
        # WITHOUT the narrowing tests, exactly as with the line rules below:
        # a name this harvest misses travels unmasked, so harvesting more
        # than the evidence can ever print is the safe direction.
        line_rules |= {r for r in rule.profile_lines if r.names_object}
        object_rules.add(_ObjectRule(rule.resource, rule.name_field))
        for resource in rule.referrers:
            rows, _ = export.objects(resource)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                found = _first_readable(row, (rule.name_field,) + rule.extra_name_fields)
                if found:
                    names.add(found)
                referenced = _readable(row.get(rule.reference_field))
                if referenced:
                    names.add(referenced)
            # The RUNNING-CONFIG half of the association. A
            # referrer family has no line rule of its own here, so the profile
            # name on `set lb vserver X -httpProfileName ...` exists in this
            # export only in the reduced state, and any line that points a
            # binding somewhere can end up in a sentence.
            family = _OBJECT_FAMILIES.get(resource)
            if family is None:
                continue
            for (line_family, _key), record in state.items():
                if line_family != family:
                    continue
                written = _readable(record.fields.get(f"-{rule.reference_field}"))
                if written:
                    names.add(written)
        # WITHOUT the conflicts on purpose: a contradiction about the global
        # default prints BOTH profile names, and this harvest must know every
        # name a sentence can carry. So the readback half comes out of the
        # evaluator and the line half straight out of the reduced state.
        default, _, _ = _global_default_profile(export, rule, state)
        if default:
            names.add(default)
        record = state.get((_family_of(rule.default_prefix), ""))
        if record is not None:
            written = _readable(record.fields.get(f"-{rule.default_field}"))
            if written:
                names.add(written)
    for rule in object_rules:
        rows, _ = export.objects(rule.resource)
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get(rule.name_field)
            if isinstance(value, str) and value.strip():
                names.add(value.strip())
    # The object name off an `add` LINE, for EVERY reconciled family.
    # That is the one sentence which prints a name this export may know
    # nowhere else: the existence contradiction of `_source_conflicts`, which
    # is filed for every family in `_FAMILY_OBJECTS` - not only for the
    # referrer families of a reference rule, which is where this harvest used
    # to look. The AAA vserver made the difference visible: its readback can
    # be read and empty while the running config adds one, and then the very
    # sentence that makes the answer honest carried the only mention of that
    # name in the whole export.
    #
    # Only from an `add`: a `set` on an object the readback does not know
    # states no existence and reaches no evidence, and every other sentence
    # names the object as the READBACK spells it - which the loop above
    # already harvested.
    for (family, _key), record in state.items():
        if family in _FAMILY_OBJECTS and record.added and record.name:
            names.add(record.name)
    for rule in line_rules:
        for line in lines:
            if not line.lower().startswith(rule.prefix):
                continue
            # Deliberately WITHOUT the narrowing test (`_matches`): a name
            # this harvest misses travels unmasked, so harvesting more than
            # the evidence can ever print is the safe direction. A profile
            # with the setting switched OFF is still a real object name.
            found = _name_after(line, len(rule.prefix))
            if found:
                names.add(found)
    return tuple(sorted(names))


# The build layer of a bulletin whose branch could not be chosen because the
# PLATFORM could not be read (see `fips_platform`). Its own value rather than
# "onbekend", because the reason is a different one and the sentence the
# customer reads has to say which.
PLATFORM_LAYER = "platform onbekend"


def _verdict(build_layer: str, condition: str) -> str:
    """The conjunction, in one place. `build_layer` is one of "kwetsbaar",
    "gepatcht", "niet genoemd", "onbekend" or "platform onbekend";
    `condition` the three-value predicate outcome.

    "niet genoemd" is its own value on purpose, and the repair of a MEASURED
    untruth (12.1-65.1 against a 14.1/13.1 bulletin): a branch the bulletin
    never names used to be folded into "gepatcht", and the answer then read
    "de build zit op of boven de fix-build" for a branch that HAS no
    fix-build in that bulletin. Worse than untrue in the abstract: such a
    branch is in practice usually an end-of-life one, so the sentence claimed
    the opposite of the likely truth. A silent bulletin is not evidence of
    being patched - it is no evidence at all.
    """
    if build_layer in ("onbekend", "niet genoemd", PLATFORM_LAYER) or condition == "niet vastgesteld":
        return NIET_VASTGESTELD
    if build_layer == "gepatcht":
        return NIET_GERAAKT
    return GERAAKT if condition == "aanwezig" else NIET_GERAAKT


def _resolve_condition(
    condition,
    branch: str | None,
    build: tuple[int, int] | None,
    branch_reason: str = "de build is niet te lezen",
    branch_gap: ReadGap | None = None,
):
    """Which predicate this CVE's `voorwaarde` comes down to, and WHY.

    Returns `(predicate, choice, gap)`. `predicate` is None when the choice
    cannot be made at all; `choice` is the clause the verdict line carries so
    a reader can see how it was made; `gap` is the read gap behind an
    unresolvable choice.

    A plain string is itself the predicate and carries no clause - the
    existing sentences stay exactly as they were. An OBJECT is the
    build-dependent form CTX696939 needs for CVE-2026-19490: from 14.1-43.56
    and 13.1-61.28 the Gateway/AAA vserver only counts WITH a SAML action,
    below those builds it counts without one. That is arithmetic on a number
    this product already reads, so it computes it instead of leaving the
    reader to.

    The gap it can produce is on the KNOWLEDGE, never on the export: a branch
    the rule does not name is a rule that does not cover this appliance, and
    that is a fact about the knowledge package.
    """
    if not isinstance(condition, dict):
        return str(condition), "", None
    if branch is None or build is None:
        # `branch_reason`/`branch_gap`: WHY there is no branch to look up.
        # Without a readable build that is a fact about the export's version
        # string (the default); with a readable build whose PLATFORM is
        # unknown it is a fact about `config/nshardware`, and the caller hands
        # in both the sentence and the gap so neither points at the wrong
        # source.
        reason = (
            f"de voorwaarde hangt af van de build, maar {branch_reason}; welke voorwaarde geldt is niet vast te stellen"
        )
        gap = branch_gap if branch_gap is not None else ReadGap(source="kennispakket", reason=reason)
        return None, reason, gap
    since = condition.get("vanaf")
    threshold = since.get(branch) if isinstance(since, dict) else None
    parsed = _parse_fix(threshold) if isinstance(threshold, str) else None
    if parsed is None:
        named = (
            f"'vanaf' noemt tak {branch} niet"
            if threshold is None
            else f"'vanaf' draagt voor tak {branch} geen leesbaar buildnummer ({threshold!r})"
        )
        reason = f"de voorwaarde hangt af van de build, maar {named}; welke voorwaarde geldt is niet vast te stellen"
        return None, reason, ReadGap(source="kennispakket", reason=reason)
    label = f"{branch}-{build[0]}.{build[1]}"
    if build >= parsed:
        return str(condition["predicaat"]), f"{label} >= {threshold}", None
    return str(condition["anders"]), f"{label} < {threshold}", None


def _verdict_sentence(
    verdict: str,
    build_layer: str,
    predicate: str,
    condition: str,
    branch: str | None = None,
    choice: str = "",
) -> str:
    # `choice` is the build-dependent clause (see `_resolve_condition`): the
    # predicate itself is already named in every sentence below, so this only
    # has to say why THAT one applies. Empty for the plain string form, which
    # keeps those sentences byte for byte what they were.
    since = f" (gekozen op de build: {choice})" if choice else ""
    if verdict == GERAAKT:
        return f"{GERAAKT} - de build is kwetsbaar en de voorwaarde {predicate} is aanwezig{since}"
    if verdict == NIET_GERAAKT and build_layer == "gepatcht":
        return f"{NIET_GERAAKT} - de build zit op of boven de fix-build"
    if verdict == NIET_GERAAKT:
        return f"{NIET_GERAAKT} - de build is kwetsbaar, maar de voorwaarde {predicate} is niet aanwezig{since}"
    if build_layer == PLATFORM_LAYER:
        # Before the other NIET VASTGESTELD sentences for the same reason as
        # "niet genoemd" below: this is the most specific fact about this
        # answer, and the one the operator can do something about (collect
        # config/nshardware).
        return (
            f"{NIET_VASTGESTELD} - {PLATFORM_UNKNOWN_REASON}; welke tak van het bulletin"
            " geldt is daarmee niet vast te stellen"
        )
    if build_layer == "niet genoemd":
        # Deliberately BEFORE the condition-layer sentences: what the
        # bulletin does not say about this branch is the more specific and
        # the more useful fact, whatever the condition layer found.
        return (
            f"{NIET_VASTGESTELD} - tak {branch} wordt in het bulletin niet genoemd;"
            " of deze build geraakt is, is niet vast te stellen"
        )
    if build_layer == "onbekend" and condition == "niet vastgesteld":
        return f"{NIET_VASTGESTELD} - de build en de voorwaarde {predicate} zijn allebei niet vast te stellen"
    if build_layer == "onbekend":
        return f"{NIET_VASTGESTELD} - de buildlaag is niet vast te stellen"
    return f"{NIET_VASTGESTELD} - de voorwaarde {predicate} is niet vast te stellen"


def _cve_findings(
    export,
    bulletin,
    build_layer: str,
    build_evidence: str,
    cache: dict,
    read_gaps: list[ReadGap],
    branch: str | None = None,
    build: tuple[int, int] | None = None,
    branch_reason: str = "de build is niet te lezen",
    branch_gap: ReadGap | None = None,
    records: list | None = None,
) -> tuple[list[Finding], list[str]]:
    """The verdict line plus the condition line, per CVE of one bulletin."""
    findings: list[Finding] = []
    verdicts: list[str] = []
    entries = bulletin.get("cves")
    if not isinstance(entries, list):
        entries = []
    for cve in entries:
        predicate, choice, choice_gap = _resolve_condition(cve["voorwaarde"], branch, build, branch_reason, branch_gap)
        if predicate is None:
            # The RULE could not be applied, so nothing about the condition
            # is established - and the reason is the rule, not the export.
            condition, evidence, gap = "niet vastgesteld", f"kennispakket: {choice}", choice_gap
        else:
            if predicate not in cache:
                cache[predicate] = _evaluate(export, predicate)
            condition, evidence, gap = cache[predicate]
        if gap is not None and gap not in read_gaps:
            read_gaps.append(gap)
        verdict = _verdict(build_layer, condition)
        verdicts.append(verdict)
        if records is not None:
            records.append(CveVerdict(verdict, cve["cvss"], gap))
        identity = str(cve["id"])
        established = verdict != NIET_VASTGESTELD
        reason = "" if established else f"buildlaag: {build_evidence}; voorwaardelaag: {evidence}"
        outcome = (
            f"{NIET_VASTGESTELD} - {choice}"
            if predicate is None
            else _verdict_sentence(verdict, build_layer, predicate, condition, branch, choice)
        )
        findings.append(
            _label_finding(
                subject=identity,
                outcome=outcome,
                certainty=Certainty.ESTABLISHED if established else Certainty.NOT_ESTABLISHED,
                evidence=f"buildlaag: {build_evidence}; voorwaardelaag: {evidence}",
                reason=reason,
            )
        )
        condition_established = condition != "niet vastgesteld"
        condition_outcome = (
            "voorwaarde hangt af van de build en is niet vast te stellen"
            if predicate is None
            else f"voorwaarde {predicate} {_CONDITION_TEXT[condition]}"
        )
        findings.append(
            _label_finding(
                subject=identity,
                outcome=condition_outcome,
                certainty=Certainty.ESTABLISHED if condition_established else Certainty.NOT_ESTABLISHED,
                evidence=f"{evidence} (CVSS {cve['cvss']}, {cve['kern']})",
                reason="" if condition_established else evidence,
            )
        )
    return findings, verdicts


def _summary(verdicts: list[str], bulletin_count: int) -> Finding:
    hit = verdicts.count(GERAAKT)
    clear = verdicts.count(NIET_GERAAKT)
    unknown = verdicts.count(NIET_VASTGESTELD)
    return _label_finding(
        subject="CVE-oordeel",
        outcome=f"{hit} geraakt, {clear} niet geraakt, {unknown} niet vastgesteld",
        certainty=Certainty.ESTABLISHED,
        evidence=f"{len(verdicts)} CVE-regels uit {bulletin_count} bulletins in het kennispakket",
    )


# The subjects of a CVE answer that do NOT come out of the knowledge package:
# the platform line reads the export, and the "kennispakket" line reports on
# the package itself (a truncation, or this very demotion).
_NOT_FROM_THE_PACKAGE = frozenset({"platform", "kennispakket"})


def _unpinned(answer: Answer, reason: str) -> Answer:
    """The same answer, with every statement the package carries demoted to
    `[niet vastgesteld]` because the configuration does not pin the package.

    The verdicts are still computed and still shown - an operator can read
    what this package WOULD say - but none of them is established: whoever
    can write the knowledge path could have written them. One leading line
    says so once, so the reason is not only found repeated on every line.
    """
    findings = [
        _label_finding(
            subject="kennispakket",
            outcome="niet gepind; geen CVE-oordeel uit dit pakket is vastgesteld",
            certainty=Certainty.NOT_ESTABLISHED,
            evidence="configuratie: geen kennispin",
            reason=reason,
        )
    ]
    for finding in answer.findings:
        if finding.certainty is Certainty.ESTABLISHED and finding.subject not in _NOT_FROM_THE_PACKAGE:
            finding = replace(finding, certainty=Certainty.NOT_ESTABLISHED, reason=reason)
        findings.append(finding)
    return replace(answer, findings=findings)


def _cve_check(export, knowledge: Knowledge, records: list) -> Answer:
    answer = _judge_package(export, knowledge, records)
    if knowledge.missing or not knowledge.unpinned_reason:
        return answer
    return _unpinned(answer, knowledge.unpinned_reason)


def _judge_package(export, knowledge: Knowledge, records: list) -> Answer:
    question = "raakt een bekende CVE deze build"
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []

    # `knowledge.truncated_fields` used to have no
    # reader outside tests: the only visible signal was the inline note on
    # whichever specific field happened to render in THIS answer, and
    # `begrippen` - cut FIRST by the package ceiling - never renders here at
    # all (it is `kennis_uitleg`'s vocabulary, not a CVE verdict's). A
    # truncated package could therefore go unnoticed on every CVE answer.
    # `Knowledge.truncation_note()` reports a COUNT and a KIND, never the
    # untrusted glossary/explanation key or bulletin/CVE index behind it - see
    # its docstring and the module's own hardening rule on untrusted package
    # strings. Placed before every return below (including the missing-
    # package one, where it is always empty and this is a no-op), so it
    # applies uniformly instead of being copied at each return point.
    note = knowledge.truncation_note()
    if note:
        findings.append(
            _label_finding(
                subject="kennispakket",
                outcome=note,
                certainty=Certainty.ESTABLISHED,
                evidence="kennispakket",
            )
        )

    if knowledge.missing:
        # A MISSING package is not an empty one. Saying "no CVE
        # rules" here would report the absence of rules where the truth is
        # that nothing could be read at all - and the operator would look for
        # the fault in the wrong place.
        reason = knowledge.reason.strip() or "het kennispakket kon niet geladen worden"
        findings.append(
            _label_finding(
                subject="kennispakket",
                outcome="ontbreekt of is onbruikbaar; er valt niets te toetsen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"kennispakket: {reason}",
                reason=reason,
            )
        )
        read_gaps.append(ReadGap(source="kennispakket", reason=reason))
        return Answer(
            question=question,
            findings=findings,
            read_gaps=read_gaps,
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    if not knowledge.cve:
        findings.append(
            _label_finding(
                subject="CVE-toets",
                outcome="kennispakket draagt geen CVE-regels; er is niets om tegen te toetsen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence="kennispakket: cve = []",
                reason="zonder CVE-regels in het kennispakket kan dit product geen oordeel geven",
            )
        )
        return Answer(
            question=question, findings=findings, knowledge_age_days=knowledge.age_days, knowledge_date=knowledge.date
        )

    # The REAL collector writes config/nsversion as one OBJECT, not as a list
    # (measured on the live export); `single()` reads exactly that shape.
    row, gap = export.single("config/nsversion")
    if gap is not None:
        read_gaps.append(gap)
    # TEXT or nothing: `str()` of a list or an object is a
    # conversion, not a read, and this one field carries both the build and
    # the FIPS train marker that decide every verdict below.
    version_text = _readable(row.get("version")) if row else None
    parsed = parse_build(version_text) if version_text is not None else None

    # `cache` keeps one predicate from being read once per CVE: several
    # bulletins naming the same condition would otherwise re-read (and
    # re-hash) the running config for each of them.
    cache: dict[str, tuple[str, str, ReadGap | None]] = {}
    verdicts: list[str] = []

    if parsed is None:
        echo = build_echo(version_text) if version_text is not None else NO_TEXT_ECHO
        findings.append(
            _label_finding(
                subject="build",
                outcome="buildversie niet te lezen",
                certainty=Certainty.NOT_ESTABLISHED,
                evidence=f"config/nsversion: version={echo}",
                reason="zonder een leesbare build is geen enkel bulletin te toetsen",
            )
        )
        # Still one verdict line per CVE: without a readable build every
        # verdict is NIET VASTGESTELD, and the summary must say so rather
        # than count zero of everything.
        for bulletin in knowledge.cve:
            cve_findings, cve_verdicts = _cve_findings(
                export,
                bulletin,
                "onbekend",
                f"buildversie niet te lezen ({echo})",
                cache,
                read_gaps,
                records=records,
            )
            findings.extend(cve_findings)
            verdicts.extend(cve_verdicts)
        findings.insert(0, _summary(verdicts, len(knowledge.cve)))
        return Answer(
            question=question,
            findings=findings,
            read_gaps=read_gaps,
            knowledge_age_days=knowledge.age_days,
            knowledge_date=knowledge.date,
        )

    branch, build = parsed

    # WHICH BRANCH OF THE BULLETIN APPLIES: the FIPS/NDcPP one or the ordinary
    # one (see `fips_platform`). Only asked out loud when it is at stake -
    # this appliance reads as FIPS, or a bulletin in the package carries the
    # FIPS branch of THIS version. A package that makes no FIPS distinction
    # for this branch is answered exactly as it always was: no platform line,
    # no read gap, the same verdict.
    fips_branch = f"{branch}{FIPS_SUFFIX}"
    platform, platform_evidence, platform_gap = fips_platform(export, version_text, branch)
    # AT STAKE the moment anything in the export reads FIPS, or the export
    # disagrees with itself about its train: only a clean NOT-FIPS read plus
    # a package that never names the FIPS branch keeps the question silent.
    fips_at_stake = platform != PLATFORM_PLAIN or any(fips_branch in _named_branches(b) for b in knowledge.cve)
    if fips_at_stake:
        if platform == PLATFORM_FIPS:
            platform_outcome = f"FIPS/NDcPP-appliance; tak {fips_branch} van het bulletin geldt"
        elif platform == PLATFORM_PLAIN:
            platform_outcome = f"geen FIPS/NDcPP-appliance; tak {branch} van het bulletin geldt"
        else:
            platform_outcome = PLATFORM_UNKNOWN_REASON
        findings.append(
            _label_finding(
                subject="platform",
                outcome=platform_outcome,
                certainty=Certainty.NOT_ESTABLISHED if platform == PLATFORM_UNKNOWN else Certainty.ESTABLISHED,
                evidence=platform_evidence,
                reason="" if platform != PLATFORM_UNKNOWN else platform_evidence,
            )
        )
        if platform_gap is not None and platform_gap not in read_gaps:
            read_gaps.append(platform_gap)

    for bulletin in knowledge.cve:
        name = str(bulletin["bulletin"])
        rule_branch = fips_branch if platform == PLATFORM_FIPS else branch
        if platform == PLATFORM_UNKNOWN:
            # The export does not say which of the two trains this appliance
            # runs. Both branches have a fix build of their own, so judging on
            # either is a coin toss dressed up as a verdict - including on a
            # bulletin that names only the ordinary branch: falling back to
            # THAT is exactly the defect this block exists for.
            findings.append(
                _label_finding(
                    subject=name,
                    outcome=f"welke tak geldt ({branch} of {fips_branch}) is niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"{platform_evidence}; getroffen takken: {', '.join(sorted(_named_branches(bulletin)))}",
                    reason=PLATFORM_UNKNOWN_REASON,
                )
            )
            cve_findings, cve_verdicts = _cve_findings(
                export,
                bulletin,
                PLATFORM_LAYER,
                PLATFORM_UNKNOWN_REASON,
                cache,
                read_gaps,
                None,
                None,
                branch_reason=PLATFORM_UNKNOWN_REASON,
                branch_gap=platform_gap,
                records=records,
            )
            findings.extend(cve_findings)
            verdicts.extend(cve_verdicts)
            continue
        build_label = f"{rule_branch}-{build[0]}.{build[1]}"
        affected = bulletin["getroffen"].get(rule_branch)
        fix = bulletin["fix"].get(rule_branch)
        if affected is None and fix is None:
            findings.append(
                _label_finding(
                    subject=name,
                    outcome=f"tak {rule_branch} staat niet in het bulletin",
                    certainty=Certainty.ESTABLISHED,
                    evidence=f"getroffen takken: {', '.join(sorted(bulletin['getroffen']))}",
                )
            )
            # The bulletin says NOTHING about this branch - which is not the
            # same as saying it is fixed. See `_verdict` for the measured
            # untruth this replaces.
            build_layer, build_evidence = "niet genoemd", f"tak {rule_branch} staat niet in het bulletin"
        elif affected is None or fix is None:
            # Half a rule is no rule. `knowledge.py` refuses such a
            # package at load time; this is the runtime net for a Knowledge
            # that never passed that loader.
            missing = "fix-build" if fix is None else "getroffen reeks"
            findings.append(
                _label_finding(
                    subject=name,
                    outcome=f"bulletin draagt voor tak {rule_branch} geen {missing}",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=f"getroffen takken: {', '.join(sorted(bulletin['getroffen']))};"
                    f" fix-takken: {', '.join(sorted(bulletin['fix']))}",
                    reason="een tak zonder beide helften van de regel levert geen oordeel op",
                )
            )
            build_layer, build_evidence = "onbekend", f"bulletin draagt voor tak {rule_branch} geen {missing}"
        else:
            below = _parse_below(affected)
            fix_build = _parse_fix(fix)
            if below is None:
                findings.append(
                    _label_finding(
                        subject=name,
                        outcome="getroffen reeks niet te lezen",
                        certainty=Certainty.NOT_ESTABLISHED,
                        evidence=f"getroffen[{rule_branch}]={affected!r}",
                        reason="alleen de vorm '< X.Y' wordt ontleed",
                    )
                )
                build_layer, build_evidence = "onbekend", f"getroffen reeks niet te lezen ({affected!r})"
            elif fix_build is None:
                findings.append(
                    _label_finding(
                        subject=name,
                        outcome="fix-build niet te lezen",
                        certainty=Certainty.NOT_ESTABLISHED,
                        evidence=f"fix[{rule_branch}]={fix!r}",
                        reason="alleen de vorm 'X.Y' wordt ontleed",
                    )
                )
                build_layer, build_evidence = "onbekend", f"fix-build niet te lezen ({fix!r})"
            elif build < fix_build:
                # The number COMPARED is the fix-build, because that is
                # the number the sentence names. The affected range is extra
                # evidence next to it, never the deciding number.
                findings.append(
                    _label_finding(
                        subject=name,
                        outcome=f"build {build_label} zit ONDER de fix-build {fix}",
                        certainty=Certainty.ESTABLISHED,
                        evidence=f"config/nsversion: {build_echo(version_text)}; bulletin {name} van {bulletin['datum']};"
                        f" getroffen reeks {affected}",
                    )
                )
                build_layer, build_evidence = "kwetsbaar", f"build {build_label} < fix-build {fix}"
            else:
                findings.append(
                    _label_finding(
                        subject=name,
                        outcome=f"build {build_label} zit op of boven de fix-build {fix}",
                        certainty=Certainty.ESTABLISHED,
                        evidence=f"config/nsversion: {build_echo(version_text)}; getroffen reeks {affected}",
                    )
                )
                build_layer, build_evidence = "gepatcht", f"build {build_label} >= fix-build {fix}"

        cve_findings, cve_verdicts = _cve_findings(
            export,
            bulletin,
            build_layer,
            build_evidence,
            cache,
            read_gaps,
            rule_branch,
            build,
            records=records,
        )
        findings.extend(cve_findings)
        verdicts.extend(cve_verdicts)

        if build_layer == "kwetsbaar":
            advice = str(bulletin["advies"])
            extra = str(bulletin.get("extraStapNaUpgrade", "")).strip()
            if extra:
                advice += f" Na de upgrade is er een extra stap: {extra}"
            findings.append(
                _label_finding(
                    subject=f"{name} advies", outcome=advice, certainty=Certainty.ESTABLISHED, evidence="kennispakket"
                )
            )

    findings.insert(0, _summary(verdicts, len(knowledge.cve)))
    return Answer(
        question=question,
        findings=findings,
        read_gaps=read_gaps,
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


@dataclass(frozen=True)
class CveVerdict:
    """Structured conjunction from the same evaluator that renders cve_check."""

    verdict: str
    cvss: object
    read_gap: ReadGap | None = None


def cve_verdicts(export, knowledge: Knowledge) -> tuple[tuple[CveVerdict, ...], tuple[ReadGap, ...]]:
    records: list[CveVerdict] = []
    answer = _cve_check(export, knowledge, records)
    gaps = list(answer.read_gaps)
    if knowledge.cve and any(r.verdict == NIET_VASTGESTELD for r in records):
        from nsmcp.export import MISSING, shape_or_missing

        row, gap = export.single("config/nsversion")
        if gap is not None and gap not in gaps:
            gaps.append(gap)
        elif gap is None and (row is None or parse_build(_readable(row.get("version")) or "") is None):
            raw = row.get("version", MISSING) if row is not None else MISSING
            gaps.append(
                ReadGap(
                    source="config/nsversion",
                    reason=f"veld version heeft geen leesbare build ({shape_or_missing(raw)})",
                )
            )
    if records and not knowledge.missing and knowledge.unpinned_reason:
        # The structured half of `_unpinned`: a consumer that counts verdicts
        # (the scorecard) may not count one from a package nobody pinned.
        unpinned = ReadGap(source="kennispakket", reason=knowledge.unpinned_reason)
        records = [replace(record, verdict=NIET_VASTGESTELD, read_gap=unpinned) for record in records]
        gaps.append(unpinned)
    return tuple(records), tuple(gaps)


def cve_check(export, knowledge: Knowledge) -> Answer:
    return _cve_check(export, knowledge, [])
