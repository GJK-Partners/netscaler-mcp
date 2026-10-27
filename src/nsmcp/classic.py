"""Classic policy forms in a running or saved configuration - the one owner.

Two readers, two rules, one module (spec 1.1 A.5.1):

- `classify_markers` is the marker table of 1.0.3, moved here from
  `preflight` without changing one outcome. Pre-flight check 2 within 14.1
  uses it and only it, so within 14.1 the check says byte for byte what it
  said before (spec section 2, rule 5).
- `classify` is the classification for the transition 13.1 -> 14.1. FEATURE
  FIRST: the command of a line decides the feature (the policy family, or
  for a named expression the feature that uses it); only within a feature
  from which classic is removed, or a feature whose classic form is merely
  deprecated, does the expression form count. `ns_true` and `ns_false` prove
  the FORM of an expression and nothing else: they never make a line of a
  supported feature blocking, and there is no catch-all on them. A form this
  module cannot name stays undecided (set 4), never green.

THE SOURCES. Every class in sets 1 and 3 carries the vendor row it rests on:
CTX296948 ("Status change announcement for classic policy based features and
functionalities"), read again on 27-10-2026, and the vendor page "Upgrade
considerations for configurations with classic policies" (an upgrade with
classic commands of the features in tables 1 and 2 fails on invalid
configuration unless they are converted first). Table 1 lists the features
converted through vendor support, table 2 the features nspepi converts,
table 3 the classic forms that keep working. A family without a row here is
not guessed at: its classic lines are set 4.

THE OUTPUT is line numbers, the product's own words for the kind of line and
the class, and the source - never a name, an expression or any other text
out of the configuration (design 3.6: the running config passes a credential
filter, and of a line this product gives the verdict and the line number).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nsmcp.cve import line_tokens

# ---------------------------------------------------------------------------
# Within the line: the 1.0.3 marker table, moved unchanged.
# ---------------------------------------------------------------------------

# The markers of features REMOVED in 14.1, measured in the field (the vendor
# removed classic for these features from 13.1 on; the in-line sentences keep
# their 1.0.3 wording, spec section 2 rule 5). This is one
# of two hard blockers that fail a NetScaler upgrade without ever showing up
# in the build number - the other being file-based licensing (EOL
# 15-4-2026, refused by the pre-upgrade check from 14.1-66.x onward). This
# one covers: classic CS/CR/compression, classic AppFW, classic SSL,
# `add filter`, `add cr policy`, `ns_true`/`ns_false`.
#
# Only markers that are TEXTUALLY UNAMBIGUOUS are in this table. Whether an
# `add cs policy` line is classic or advanced cannot be read off the line
# without parsing the expression language, and guessing there would produce a
# blocker on a healthy config just as easily as a silent green on a broken
# one. The evidence line of check 2 therefore SAYS what was searched for and
# what falls outside it - a `geen blokkade` on a partial scan that presents
# itself as a complete one is exactly the false green this product exists to
# prevent.
_REMOVED_PREFIXES = ("add filter action", "add filter policy", "add cr policy")
# The classic default expressions. The advanced engine has neither.
_CLASSIC_EXPRESSIONS = ("ns_true", "ns_false")
# Classic GATEWAY authentication is deprecated but does NOT block the upgrade
# (measured; conversion to nFactor is a design choice, not an upgrade gate).
# Putting it down heavier than it is, is as wrong as missing it. The `bind`
# forms are in here too: a classic gateway policy is BOUND by definition, and
# without them the bind line alone would turn the one marker that provably
# does not block into a blocker.
_DEPRECATED_PREFIXES = (
    "add authentication",
    "add vpn",
    "bind authentication",
    "bind vpn",
)

# What check 2 within the line says it searched for.
MARKERS_SEARCHED = "'add filter', 'add cr policy', ns_true, ns_false"


def classify_markers(lines: list[str]) -> tuple[list[int], list[int], list[int]]:
    """(removed, deprecated, bound) - LINE NUMBERS, never text.

    The 1.0.3 table, byte-identical in outcome; only for pre-flight check 2
    within the line. Design 3.6: the running config passes a credential
    filter, and of a filtered line this product gives the verdict and the
    line number, never the text.
    """
    removed: list[int] = []
    deprecated: list[int] = []
    bound: list[int] = []
    for number, raw in enumerate(lines, start=1):
        lowered = raw.strip().lower()
        hit = any(lowered.startswith(prefix) for prefix in _REMOVED_PREFIXES) or any(
            expression in lowered for expression in _CLASSIC_EXPRESSIONS
        )
        if not hit:
            continue
        if any(lowered.startswith(prefix) for prefix in _DEPRECATED_PREFIXES):
            deprecated.append(number)
            continue
        removed.append(number)
        if lowered.startswith("bind "):
            # A marker ON a bind line is bound by definition.
            bound.append(number)
    return removed, deprecated, bound


def markers_bound(lines: list[str], marker_lines: list[int]) -> bool:
    """Does any `bind` line name an object one of these marker lines declares?

    The 1.0.3 rule, unchanged. The name is used INTERNALLY only - to decide
    the word - and never printed: an object name out of the running config is
    not collected by the disclosure seam, so echoing one would reach the
    model unmasked.
    """
    names = set()
    for number in marker_lines:
        parts = lines[number - 1].strip().split()
        # `add cr policy <naam> ...` / `add filter policy <naam> ...`: the
        # token right after the three-word keyword.
        if len(parts) >= 4 and parts[0].lower() == "add":
            names.add(parts[3].strip('"').lower())
    if not names:
        return False
    for raw in lines:
        lowered = raw.strip().lower()
        if not lowered.startswith("bind "):
            continue
        tokens = {token.strip('"') for token in lowered.split()}
        if names & tokens:
            return True
    return False


# ---------------------------------------------------------------------------
# The transition: four sets.
# ---------------------------------------------------------------------------

SET_BLOCKING = 1  # removed feature, classic form, bound
SET_UNBOUND = 2  # removed feature, classic form, not bound
SET_DEPRECATED = 3  # classic form that keeps working; never blocking
SET_UNDECIDED = 4  # neither proven classic nor proven advanced, or no vendor row

SET_LABELS = {
    SET_BLOCKING: "verwijderd en gebonden",
    SET_UNBOUND: "verwijderd, ongebonden",
    SET_DEPRECATED: "deprecated, blokkeert niet",
    SET_UNDECIDED: "onbeslist",
}

# Expression form (A.5.1 "Expressievorm"). Pinned in a test; extending a list
# is a code change with a source. Compared case-sensitively, the way the
# appliance writes them: a form outside the list is undecided, not quietly
# advanced. `TRUE`/`FALSE` are the one exception: the appliance writes the
# advanced literal in lower case too (measured on the lab export: `add
# responder policy ... true ...`), and the classic engine has no such word.
ADVANCED_PREFIXES = ("HTTP.", "CLIENT.", "SERVER.", "SYS.", "TARGET.", "AAA.", "DNS.", "TCP.", "SSL.", "TEXT.")
CLASSIC_PREFIXES = ("REQ.", "RES.")
_ADVANCED_LITERAL = re.compile(r"(?i:true|false)(?![A-Za-z0-9_.])")
# A classic comparison on URL / METHOD / HEADER without an object prefix.
_CLASSIC_BARE = re.compile(r"(?:URL|METHOD|HEADER)(?![A-Za-z0-9_.])")
# `ns_` at the start of a token: the classic built-in expressions
# (`ns_true`, `ns_false`, `ns_content_type`, ...).
_NS_TOKEN = re.compile(r"(?<![A-Za-z0-9_.])ns_([A-Za-z0-9_]*)")
# `ns_adv_*` are the built-in ADVANCED compression policies; an `ns_` token
# start alone would call them classic. Such a token proves neither form.
_NS_ADVANCED = "adv_"
# Classic client-security (EPA) expressions begin with `CLIENT.` too
# (CTX296948 table 3 row 18): such a head proves no form.
_CLIENT_SECURITY = ("CLIENT.OS", "CLIENT.APPLICATION", "CLIENT.SYSTEM")
# The advanced function that evaluates a classic expression (CTX296948 table 2
# row 9): an expression that calls it is not proven advanced.
_EVAL_CLASSIC = re.compile(r"(?i)SYS\.EVAL_CLASSIC_EXPR")
# A string literal inside an expression (the tokenizer has already removed
# the outer quoting and the escapes): its content is data, not form.
_STRING_LITERAL = re.compile(r'"[^"]*"')
# Characters an object name in an expression is made of.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_#.:@-]+")

FORM_CLASSIC = "classic"
FORM_ADVANCED = "advanced"
FORM_UNDECIDED = "onbeslist"


@dataclass(frozen=True)
class _Family:
    """A policy family A.5.1 names, with the vendor row it rests on."""

    kind: str  # the product's own words for the line, never export text
    verzameling: int  # SET_BLOCKING (removed; 1 or 2 by binding) or SET_DEPRECATED
    klasse: str
    bron: str
    classic_only: bool = False  # the feature has no advanced form at all
    rule_flag_only: bool = False  # the expression is only ever behind `-rule`
    classic_only_flags: tuple[str, ...] = ()  # parameters only the classic form has
    flag_klasse: str = ""
    flag_bron: str = ""


_REMOVED = SET_BLOCKING
_KEPT = SET_DEPRECATED

# Keyed on the two words after `add`, lower case.
_FAMILIES: dict[tuple[str, str], _Family] = {
    # --- set 1/2: classic removed (CTX296948 tables 1 and 2) ---------------
    ("filter", "action"): _Family(
        "add filter action", _REMOVED, "Filter (alleen classic)", "CTX296948 tabel 2 rij 1 (Filter)", classic_only=True
    ),
    ("filter", "policy"): _Family(
        "add filter policy", _REMOVED, "Filter (alleen classic)", "CTX296948 tabel 2 rij 1 (Filter)", classic_only=True
    ),
    ("sc", "policy"): _Family(
        "add sc policy",
        _REMOVED,
        "SureConnect (alleen classic)",
        "CTX296948 tabel 1 rij 1 (SureConnect)",
        classic_only=True,
    ),
    ("cr", "policy"): _Family(
        "add cr policy",
        _REMOVED,
        "Cache Redirection classic policy",
        "CTX296948 tabel 2 rij 5 (Classic Cache Redirection policy)",
    ),
    ("cs", "policy"): _Family(
        "add cs policy",
        _REMOVED,
        "Content Switching classic policy",
        "CTX296948 tabel 2 rij 6 (Content Switching Classic policy)",
        classic_only_flags=("-url", "-domain"),
        flag_klasse="Content Switching met -url of -domain",
        flag_bron="CTX296948 tabel 2 rij 15 (URL and Domain parameters in Content Switching policy)",
    ),
    ("cmp", "policy"): _Family(
        "add cmp policy", _REMOVED, "Compression classic policy", "CTX296948 tabel 2 rij 4 (Compression Classic policy)"
    ),
    ("appfw", "policy"): _Family(
        "add appfw policy",
        _REMOVED,
        "Application Firewall classic policy",
        "CTX296948 tabel 2 rij 3 (Application Firewall Classic policy)",
    ),
    ("ssl", "policy"): _Family(
        "add ssl policy", _REMOVED, "SSL classic policy", "CTX296948 tabel 2 rij 7 (SSL Classic policy)"
    ),
    ("lb", "vserver"): _Family(
        "add lb vserver -rule",
        _REMOVED,
        "classic expressie in een LB-regel",
        "CTX296948 tabel 2 rij 14 (Classic expression in LB rule)",
        rule_flag_only=True,
    ),
    # --- set 3: classic keeps working (CTX296948 table 3) ------------------
    ("authentication", "localpolicy"): _Family(
        "add authentication localPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 5 (Authentication Local policy)",
        classic_only=True,
    ),
    ("authentication", "radiuspolicy"): _Family(
        "add authentication radiusPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 6 (RADIUS Authentication policy)",
        classic_only=True,
    ),
    ("authentication", "ldappolicy"): _Family(
        "add authentication ldapPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 7 (LDAP Authentication policy)",
        classic_only=True,
    ),
    ("authentication", "negotiatepolicy"): _Family(
        "add authentication negotiatePolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 8 (Authentication Negotiate policy)",
        classic_only=True,
    ),
    ("authentication", "samlpolicy"): _Family(
        "add authentication samlPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 9 (SAML Authentication policy)",
        classic_only=True,
    ),
    ("authentication", "dfapolicy"): _Family(
        "add authentication dfaPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 10 (Delegation Forms Authentication policy)",
        classic_only=True,
    ),
    ("authentication", "webauthpolicy"): _Family(
        "add authentication webAuthPolicy",
        _KEPT,
        "classic Gateway-authenticatie",
        "CTX296948 tabel 3 rij 11 (Web Authentication policy)",
        classic_only=True,
    ),
    ("vpn", "sessionpolicy"): _Family(
        "add vpn sessionPolicy",
        _KEPT,
        "classic Gateway-sessie",
        "CTX296948 tabel 3 rij 16 (Classic VPN Session policy)",
    ),
    ("vpn", "trafficpolicy"): _Family(
        "add vpn trafficPolicy",
        _KEPT,
        "classic Gateway-verkeer",
        "CTX296948 tabel 3 rij 15 (Classic VPN Traffic policy)",
    ),
    ("audit", "syslogpolicy"): _Family(
        "add audit syslogPolicy", _KEPT, "classic audit SYSLOG", "CTX296948 tabel 3 rij 2 (Classic Audit SYSLOG policy)"
    ),
    ("audit", "nslogpolicy"): _Family(
        "add audit nslogPolicy", _KEPT, "classic audit NSLOG", "CTX296948 tabel 3 rij 3 (Classic Audit NSLOG policy)"
    ),
    ("tm", "sessionpolicy"): _Family(
        "add tm sessionPolicy",
        _KEPT,
        "classic TM-sessie",
        "CTX296948 tabel 3 rij 13 (Classic Traffic Management Session policy)",
    ),
    ("authorization", "policy"): _Family(
        "add authorization policy",
        _KEPT,
        "classic autorisatie",
        "CTX296948 tabel 3 rij 12 (Classic Authorization policy)",
    ),
}

# The Gateway families whose `bind authentication ...` / `bind vpn ...` lines
# are reported with them in set 3 (A.5.1, set 3, first class).
_GATEWAY_BIND_PREFIXES = (("bind", "authentication"), ("bind", "vpn"))
_GATEWAY_FAMILIES = frozenset(key for key in _FAMILIES if key[0] in ("authentication", "vpn", "authorization"))
_GATEWAY_BIND_KLASSE = "binding van een classic Gateway-policy"

_NAMED = ("policy", "expression")
_NAMED_KIND = "add policy expression"
_NAMED_BRON = "CTX296948 tabel 3 rij 1 (Classic Named (policy) expression); volgt de gebruikende feature"
_UNKNOWN_KIND = "policyregel van een onbekende familie"

# Forms of CTX296948 table 2 outside the class list of A.5.1. Not a class of
# set 1 (that is a spec change): each is at least undecided, with its row.
_ROW_8 = "CTX296948 tabel 2 rij 8 (Pattern function in Rewrite action)"
_ROW_9 = "CTX296948 tabel 2 rij 9 (SYS.EVAL_CLASSIC_EXPR Classic function)"
_ROW_10 = "CTX296948 tabel 2 rij 10 (Patclass)"
_ROW_11 = "CTX296948 tabel 2 rij 11 (BypassSafetyCheck parameter in rewrite action)"
_ROW_12 = "CTX296948 tabel 2 rij 12 (HTTP.REQ.BODY expression with no arguments)"
_ROW_13 = "CTX296948 tabel 2 rij 13 (PolicyType Parameter in set cmp parameter)"
_BODY_WITHOUT_ARGUMENT = re.compile(r"(?i)HTTP\.REQ\.BODY(?!\s*\()")
# A built-in classic policy (`ns_cmp_content_type`, ...) never has an `add`
# line; on a bind line of a removed family it is the only trace.
_BUILTIN_BIND_FAMILIES = {
    "cmp": ("cmp", "policy"),
    "cs": ("cs", "policy"),
    "cr": ("cr", "policy"),
    "appfw": ("appfw", "policy"),
    "ssl": ("ssl", "policy"),
    "filter": ("filter", "policy"),
}
_BUILTIN_KLASSE = "ingebouwde classic-policy alleen op een bindregel"
_NO_SOURCE = "geen vendorrij in deze module"


@dataclass(frozen=True)
class ClassicFinding:
    """One line: where, what kind (own words), which set, which class, which source."""

    line: int
    kind: str
    verzameling: int
    klasse: str
    bron: str


@dataclass(frozen=True)
class Classification:
    findings: tuple[ClassicFinding, ...]

    def lines(self, verzameling: int) -> tuple[int, ...]:
        return tuple(sorted(f.line for f in self.findings if f.verzameling == verzameling))

    @property
    def blocking(self) -> tuple[int, ...]:
        return self.lines(SET_BLOCKING)

    @property
    def unbound(self) -> tuple[int, ...]:
        return self.lines(SET_UNBOUND)

    @property
    def removed(self) -> tuple[int, ...]:
        """Sets 1 and 2: a removed feature in a classic form, bound or not."""
        return tuple(sorted(set(self.blocking) | set(self.unbound)))

    @property
    def deprecated(self) -> tuple[int, ...]:
        return self.lines(SET_DEPRECATED)

    @property
    def undecided(self) -> tuple[int, ...]:
        return self.lines(SET_UNDECIDED)


@dataclass
class _Line:
    number: int
    tokens: list[str]
    readable: bool
    lowered: list[str]


def _read(lines: list[str]) -> list[_Line]:
    read = []
    for number, raw in enumerate(lines, start=1):
        tokens, readable = line_tokens(raw.strip())
        read.append(_Line(number, tokens, readable, [t.lower() for t in tokens]))
    return read


def _bare_form(expression: str) -> str:
    """The form of an expression by its own text only (no named lookups)."""
    text = _STRING_LITERAL.sub(" ", expression)
    head = text.lstrip(" \t!(")
    if head.startswith(_CLIENT_SECURITY) or _EVAL_CLASSIC.search(text):
        return FORM_UNDECIDED
    advanced = head.startswith(ADVANCED_PREFIXES) or bool(_ADVANCED_LITERAL.match(head))
    ns_tokens = [m.group(1) for m in _NS_TOKEN.finditer(text)]
    if any(rest.startswith(_NS_ADVANCED) for rest in ns_tokens):
        return FORM_UNDECIDED
    classic = head.startswith(CLASSIC_PREFIXES) or bool(_CLASSIC_BARE.match(head)) or bool(ns_tokens)
    if advanced and classic:
        return FORM_UNDECIDED
    if advanced:
        return FORM_ADVANCED
    if classic:
        return FORM_CLASSIC
    return FORM_UNDECIDED


def _references(expression: str, named: dict[str, str]) -> set[str]:
    text = _STRING_LITERAL.sub(" ", expression)
    return {token.lower() for token in _IDENTIFIER.findall(text)} & set(named)


def _form(expression: str, named: dict[str, str]) -> str:
    """The form of a family expression: an exact named expression takes the
    form of its content; a reference to a classic or undecided named
    expression counts as that form."""
    exact = expression.strip().lower()
    if exact in named:
        return named[exact]
    form = _bare_form(expression)
    referenced = {named[name] for name in _references(expression, named)}
    if FORM_UNDECIDED in referenced:
        return FORM_UNDECIDED
    if FORM_CLASSIC in referenced:
        return FORM_UNDECIDED if form == FORM_ADVANCED else FORM_CLASSIC
    return form


def _expression(line: _Line, *, rule_flag_only: bool) -> str | None:
    """The value after `-rule`, or the positional rule argument; None when
    the line carries neither."""
    for index, token in enumerate(line.lowered):
        if token == "-rule":
            return line.tokens[index + 1] if index + 1 < len(line.tokens) else None
    if rule_flag_only:
        return None
    if len(line.tokens) > 4 and not line.tokens[4].startswith("-"):
        return line.tokens[4]
    return None


def _is_policy_line(line: _Line) -> bool:
    """`add <x> <y>` where `<y>` names a policy (`...policy`, any case)."""
    return len(line.lowered) >= 4 and line.lowered[0] == "add" and line.lowered[2].endswith("policy")


def classify(lines: list[str]) -> Classification:
    """The four sets of A.5.1 for one configuration (running or saved).

    Fail-closed: a family line whose quoting does not close, or whose
    expression this module cannot name, is set 4 - never left out.
    """
    read = _read(lines)
    bind_tokens: set[str] = set()
    unreadable_bind = False
    for line in read:
        if line.lowered[:1] == ["bind"]:
            bind_tokens.update(token.strip('"') for token in line.lowered)
            unreadable_bind = unreadable_bind or not line.readable

    # Step 0: named expressions, by their content alone.
    named: dict[str, str] = {}
    named_lines: dict[str, int] = {}
    duplicate: set[str] = set()
    for line in read:
        if len(line.lowered) >= 4 and tuple(line.lowered[1:3]) == _NAMED and line.lowered[0] == "add":
            name = line.lowered[3]
            content = line.tokens[4] if len(line.tokens) > 4 else ""
            form = _bare_form(content) if line.readable and content else FORM_UNDECIDED
            if name in named:
                duplicate.add(name)
            named[name] = form
            named_lines[name] = line.number
    for name in duplicate:
        named[name] = FORM_UNDECIDED

    findings: list[ClassicFinding] = []
    users: dict[str, list[int | None]] = {name: [] for name in named}
    user_sources: dict[str, set[str]] = {name: set() for name in named}
    gateway_names: set[str] = set()

    def record(line: _Line, kind: str, verzameling: int | None, klasse: str, bron: str, expression: str | None):
        if verzameling is not None:
            findings.append(ClassicFinding(line.number, kind, verzameling, klasse, bron))
        if expression is not None:
            refs = _references(expression, named)
            exact = expression.strip().lower()
            if exact in named:
                refs.add(exact)
            for name in refs:
                users[name].append(verzameling)
                user_sources[name].add(bron)

    # Steps 1 and 2: feature first, then the expression form within it.
    for line in read:
        if not line.lowered or line.lowered[0] != "add" or len(line.lowered) < 4:
            continue
        key = (line.lowered[1], line.lowered[2])
        if key == _NAMED:
            continue
        family = _FAMILIES.get(key)
        if family is None and not _is_policy_line(line):
            continue
        if not line.readable:
            kind = family.kind if family is not None else _UNKNOWN_KIND
            klasse = (family.klasse if family is not None else "onbekende familie") + "; regel niet eenduidig leesbaar"
            record(line, kind, SET_UNDECIDED, klasse, _NO_SOURCE, None)
            continue
        if family is None:
            expression = _expression(line, rule_flag_only=False)
            form = _form(expression, named) if expression is not None else FORM_UNDECIDED
            verzameling = None if form == FORM_ADVANCED else SET_UNDECIDED
            record(line, _UNKNOWN_KIND, verzameling, f"onbekende familie; expressievorm {form}", _NO_SOURCE, expression)
            continue
        if family.rule_flag_only and "-rule" not in line.lowered and _persistence(line) != "rule":
            continue  # an lb vserver without a rule is no policy line
        expression = _expression(line, rule_flag_only=family.rule_flag_only)
        flagged = [flag for flag in family.classic_only_flags if flag in line.lowered]
        if flagged:
            form, klasse, bron = FORM_CLASSIC, family.flag_klasse, family.flag_bron
        elif family.classic_only:
            form, klasse, bron = FORM_CLASSIC, family.klasse, family.bron
        else:
            form = _form(expression, named) if expression is not None else FORM_UNDECIDED
            klasse, bron = family.klasse, family.bron
        if form == FORM_ADVANCED:
            record(line, family.kind, None, klasse, bron, expression)
            continue
        if form == FORM_UNDECIDED:
            record(
                line, family.kind, SET_UNDECIDED, f"{family.klasse}; expressievorm onbeslist", _NO_SOURCE, expression
            )
            continue
        if family.verzameling == SET_DEPRECATED:
            record(line, family.kind, SET_DEPRECATED, klasse, bron, expression)
            if key in _GATEWAY_FAMILIES:
                gateway_names.add(line.lowered[3].strip('"'))
            continue
        bound = line.lowered[3].strip('"') in bind_tokens
        if not bound and (unreadable_bind or family.rule_flag_only):
            # Fail-closed (review M-1, M-2): an unreadable bind line may name
            # this object, and `-rule` is a parameter of the vserver, not a
            # bound policy - "unbound" is not proven either way.
            why = "binding niet vast te stellen" if unreadable_bind else "een LB-regel is geen gebonden policy"
            record(line, family.kind, SET_UNDECIDED, f"{klasse}; {why}", bron, expression)
            continue
        record(line, family.kind, SET_BLOCKING if bound else SET_UNBOUND, klasse, bron, expression)

    # The `bind authentication` / `bind vpn` lines of a classic Gateway policy.
    for line in read:
        if tuple(line.lowered[:2]) in _GATEWAY_BIND_PREFIXES and gateway_names & {
            token.strip('"') for token in line.lowered
        }:
            kind = " ".join(line.lowered[:2])
            findings.append(
                ClassicFinding(
                    line.number,
                    kind,
                    SET_DEPRECATED,
                    _GATEWAY_BIND_KLASSE,
                    "CTX296948 tabel 3 (Gateway-rijen 5-12, 15, 16)",
                )
            )

    # Named expressions with classic (or undecided) content follow their users.
    for name, form in named.items():
        if form == FORM_ADVANCED:
            continue
        number = named_lines[name]
        seen = users[name]
        if form == FORM_UNDECIDED or not seen or None in seen:
            klasse = (
                "named expression; inhoud onbeslist"
                if form == FORM_UNDECIDED
                else (
                    "named expression zonder gebruikende regel" if not seen else "named expression; gebruik onbeslist"
                )
            )
            findings.append(ClassicFinding(number, _NAMED_KIND, SET_UNDECIDED, klasse, _NO_SOURCE))
        elif set(seen) <= {SET_BLOCKING, SET_UNBOUND}:
            verzameling = SET_BLOCKING if SET_BLOCKING in seen else SET_UNBOUND
            # The verdict rests on the row of the using feature, never on table
            # 3 row 1, which says classic named expressions keep working.
            bron = "; ".join(sorted(user_sources[name]))
            findings.append(
                ClassicFinding(number, _NAMED_KIND, verzameling, "named expression van een verwijderde feature", bron)
            )
        elif set(seen) == {SET_DEPRECATED}:
            findings.append(
                ClassicFinding(
                    number, _NAMED_KIND, SET_DEPRECATED, "named expression van een deprecated feature", _NAMED_BRON
                )
            )
        else:
            findings.append(
                ClassicFinding(
                    number,
                    _NAMED_KIND,
                    SET_UNDECIDED,
                    "named expression gebruikt door features van verschillende klassen",
                    _NO_SOURCE,
                )
            )

    declared = {line.lowered[3].strip('"') for line in read if line.lowered[:1] == ["add"] and len(line.lowered) >= 4}
    taken = {f.line: index for index, f in enumerate(findings)}
    for line in read:
        rest = _rest_form(line, lines[line.number - 1], declared)
        if rest is None:
            continue
        finding = ClassicFinding(line.number, rest[0], SET_UNDECIDED, rest[1], rest[2])
        if line.number not in taken:
            findings.append(finding)
        elif (
            findings[taken[line.number]].verzameling == SET_UNDECIDED
            and findings[taken[line.number]].bron == _NO_SOURCE
        ):
            # An undecided line without a row gets the row that names its form.
            findings[taken[line.number]] = finding

    return Classification(tuple(sorted(findings, key=lambda f: (f.line, f.verzameling))))


def _rest_form(line: _Line, raw: str, declared: set[str]) -> tuple[str, str, str] | None:
    """(kind, klasse, bron) of a CTX296948 table 2 form outside the class
    list, or None. Read on the raw line too, so a quoted value is no hiding
    place; the output carries only the product's own words."""
    head = tuple(line.lowered[:3])
    if _EVAL_CLASSIC.search(raw):
        return "regel met SYS.EVAL_CLASSIC_EXPR", "classic expressie via SYS.EVAL_CLASSIC_EXPR", _ROW_9
    if head[1:3] == ("policy", "patclass") and head[:1] in (("add",), ("set",), ("bind",)):
        return "policy patclass", "patclass", _ROW_10
    if head[1:3] == ("rewrite", "action") and head[:1] in (("add",), ("set",)):
        if "-pattern" in line.lowered:
            return "rewrite action -pattern", "patroonfunctie in een rewrite-actie", _ROW_8
        if "-bypasssafetycheck" in line.lowered:
            return "rewrite action -bypassSafetyCheck", "bypassSafetyCheck in een rewrite-actie", _ROW_11
    if head == ("set", "cmp", "parameter"):
        for index, token in enumerate(line.lowered):
            if token == "-policytype" and line.lowered[index + 1 : index + 2] == ["classic"]:
                return "set cmp parameter -policyType", "classic policytype voor compressie", _ROW_13
    if _BODY_WITHOUT_ARGUMENT.search(raw):
        return "regel met HTTP.REQ.BODY zonder argument", "HTTP.REQ.BODY zonder lengte", _ROW_12
    if line.lowered[:1] == ["bind"] and len(line.lowered) >= 3:
        family = _FAMILIES.get(_BUILTIN_BIND_FAMILIES.get(line.lowered[1], ("", "")))
        if family is not None:
            skip = False
            for token in line.lowered[2:]:
                if skip:
                    skip = False
                    continue
                if token == "-gotopriorityexpression":
                    skip = True
                    continue
                name = token.strip('"')
                if name.startswith("ns_") and not name.startswith("ns_" + _NS_ADVANCED) and name not in declared:
                    return f"bind {line.lowered[1]} (ingebouwde policy)", _BUILTIN_KLASSE, family.bron
    return None


def _persistence(line: _Line) -> str:
    for index, token in enumerate(line.lowered):
        if token == "-persistencetype" and index + 1 < len(line.lowered):
            return line.lowered[index + 1]
    return ""
