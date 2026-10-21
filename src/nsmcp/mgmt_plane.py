"""Is the management plane of this appliance open?

Four statements side by side, each PASS / FAIL / NIET BEOORDEELD. Mirrors three
NSHC scorecard controls plus the RBAC hardening module:

| dimensie      | NSHC                                                        |
|---------------|-------------------------------------------------------------|
| blootstelling | GJK-L1-001 Management-plane exposure (scorecard r.1637)      |
| transport     | GJK-L1-002 Admin transport en default-certificaten (r.1676)  |
| certificaat   | GJK-L1-002, cert-helft, plus hidden rule NSHC-HR-SSL-001     |
| RBAC          | GJK-L1-003 RBAC en break-glass (r.1727) + NshcRbacHardening  |

THE RULE THAT DECIDES EVERY DIMENSION, and it runs in this order:
1. A field that WAS read and is negative -> FAIL. A read fact outweighs a
   read gap; refusing to conclude while the evidence is on the table is not
   honesty, it is silence.
2. Nothing negative read, and a verdict-steering source unread -> NIET
   BEOORDEELD, with the source named. Never PASS.
3. Everything read, nothing negative -> PASS.

That order is why a NOT_SUPPORTED `config/mgmtparam` (measured: this build
does not serve it) can sit next to a FAIL on transport: telnet is on, and that
is read.

CLOSED-VOCABULARY FIELDS (gui/ssh/telnet/ftp/type/strongpassword/
internaluserlogin/action) run through `_gate`/`_vocab` below - this module's
own copy of the three-way read hidden_rules.py established for exactly this
class of field, built on THIS product's one shared
sentinel and shape-namer (`export.MISSING`/`export.shape_or_missing`, not a
second sentinel). A bool, an int, a list, a dict, an absent key, OR a string
outside the documented vocabulary must never silently read as the favourable
(non-matching) word - hardening rule 6 - so any of those becomes an entry in
a dimension's `unread` list instead, which `_decide()` below turns into NIET
BEOORDEELD rather than a silent PASS. `_int_or_gap` is the same discipline
for a NUMERIC field (`hidden_rules._num_gate`'s counterpart): a genuinely
ABSENT key keeps this appliance's own documented default (systemparameter's
own `timeout` default is 900s when unset), a PRESENT but unparseable value
is a read gap.

FREE-FORM FIELDS THAT ARE COMPARED, NOT MATCHED AGAINST A CLOSED VOCABULARY
(`certkeyname`, `cmdspec`) go through `_string_or_gap` below instead of
`_gate`/`_vocab`: there is no word list to fail out of, only the same
question hardening rule 6 asks of every verdict-driving field - was this
even a usable string. A non-string here must cost the verdict exactly like
an out-of-vocabulary `_vocab` miss does, never read as "does not contain the
watched substring" and therefore safe.

A FIELD THAT IS RENDERED VERBATIM INTO THE ANSWER, outside the masking seam,
is a THIRD class and gets the STRICTEST gate of the three: `type` reaches
this answer inside an `addr (type)` compound next to an already-established
finding, and `_gate`/`_vocab` telling the caller "this is a genuine string"
does not thereby prove it SAFE to print - a genuine string can still carry a
line break. `_enum_text` below is this module's copy of
`hidden_rules._enum_text`: it runs the value through `answer.repeatable_token`
(the SAME bare-NITRO-token shape gate `coverage._state_for` and
`export.shape_of`'s own comment already use for this exact class of value)
before it is echoed, and prints "?" instead of a supplied sentence, path or
multi-line payload.

IDIOM DECISION: `_gate`/`_vocab`/`_num_gate`/`_enum_text` stay a private
copy in this module rather than being HOISTED out of hidden_rules.py into a
shared home (export.py already owns `MISSING`/`shape_or_missing`, the layer
beneath all four) - moving them out is not safe.
`tests/test_hidden_rules.py::test_every_field_reading_helper_is_in_the_extractor_set`
(via `_field_reading_helpers_from_source()`) re-derives the set of
field-reading helpers by parsing `inspect.getsource(nsmcp.hidden_rules)` and
walking `tree.body` for `_gate`/`_vocab`/`_num_gate`/`_shape_or_missing`/
`_enum_text`/`_num_text` as functions ACTUALLY DEFINED at that module's own
top level - not merely bound into its namespace by an import. Moving those
six definitions to export.py and re-importing them under the same names
would make that derivation empty for all but `_raw_field`/`_num` (the two
seeded primitives) and fail that pinned test - a real behaviour change to
hidden_rules.py's own test surface, forbidden by this task's hard
constraint. What IS shared without touching hidden_rules.py at all:
`export.MISSING`, `export.shape_or_missing` (already imported here
earlier) and `answer.repeatable_token` - every
primitive hidden_rules.py's OWN gate family is built on. `_gate`/`_vocab`/
`_int_or_gap`/`_string_or_gap`/`_enum_text` stay this module's own copy of
the IDIOM on top of those shared primitives, the same "one gate, several
private call sites" pattern `coverage._resource_key`/`_binding_file_name`
already established for this product ("Het idioom" section of the
hardening requirements) - not a second, divergent implementation of the
shared primitives themselves.

WHAT THIS ANSWER CANNOT SAY, and says so:
- whether a network ACL or firewall sits in front of the management address.
  The appliance configuration does not see that.
- whether the scanning account itself is a dedicated read-only service
  account. The administrator knows that; the export does not.
"""

from __future__ import annotations

from dataclasses import dataclass

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap, repeatable_token
from nsmcp.export import MISSING, SYSTEMUSER_RESOURCE, shape_or_missing
from nsmcp.knowledge import Knowledge
from nsmcp.ssl_precedence import field_text

NSIP_RESOURCE = "config/nsip"
MGMTPARAM_RESOURCE = "config/mgmtparam"
SYSTEMPARAM_RESOURCE = "config/systemparameter"
CMDPOLICY_RESOURCE = "config/systemcmdpolicy"
NSPARAM_RESOURCE = "config/nsparam"
CERT_BINDING = "sslvserver_sslcertkey_binding.by-parent.json"

DEFAULT_MGMT_CERT = "ns-server-certificate"

DIMENSIONS = ("blootstelling", "transport", "certificaat", "RBAC")
VERDICTS = ("PASS", "FAIL", "NIET BEOORDEELD")

# Same content as hidden_rules._BUILTIN_CMD_POLICIES, deliberately its own
# copy: no shared extraction point exists for it, same "per-module copy of a
# small, stable constant" discipline as disclosure._readable_name mirroring
# impact._readable_name elsewhere in this product.
_BUILTIN_CMD_POLICIES = (
    "operator",
    "read-only",
    "network",
    "sysadmin",
    "superuser",
    "partition-operator",
    "partition-read-only",
    "partition-network",
    "partition-admin",
)

NOT_ASSESSED = (
    NotAssessed(
        subject="netwerk-ACL voor het beheeradres",
        reason=("of er een ACL of firewall voor het beheeradres staat is in de appliance-configuratie niet te zien"),
    ),
    NotAssessed(
        subject="aard van het scanaccount",
        reason=(
            "of het account waarmee gescand is een toegewijd alleen-lezen serviceaccount"
            " is, weet de beheerder; de export niet"
        ),
    ),
)


@dataclass(frozen=True)
class DimensionResult:
    name: str
    verdict: str
    evidence: str
    instances: tuple[str, ...] = ()
    unread: tuple[str, ...] = ()
    reason: str = ""
    # 1.0.2: read gaps that are not a whole unreadable source - the
    # parent cross-check of a binding file (`Export.binding_parents`) - as
    # the export names them, so they stand under NIET VASTGESTELD as such.
    gaps: tuple[ReadGap, ...] = ()


def _raw(row: dict, field: str):
    """Case-insensitive raw lookup on a row already known to be a dict;
    `export.MISSING` when the key is absent. Mirrors hidden_rules._raw_field,
    built on this product's ONE shared sentinel (export.py) rather than a
    second `object()` for the same meaning.
    """
    lowered = field.lower()
    for key, value in row.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return MISSING


def _gate(row: dict, field: str, *words: str) -> tuple[bool, str | None]:
    """The one three-way read every closed-vocabulary field below goes
    through - hidden_rules._gate's own discipline, this module's copy of it
    (see the module docstring). `matched` is True only when the raw value is
    a genuine string equal (stripped, upper-cased) to one of `words`; the
    second element is None whenever the raw value IS a genuine string - even
    one that does not match `words`, which is the caller's own business
    logic, never a shape problem - and otherwise names the raw value's SHAPE,
    never its content.
    """
    raw = _raw(row, field)
    if not isinstance(raw, str):
        return False, shape_or_missing(raw)
    return raw.strip().upper() in words, None


def _vocab(row: dict, field: str, *words: str) -> tuple[str, str | None]:
    """`_gate` for a field whose vocabulary is CLOSED and fully known.

    Returns the matched word, UPPER-CASED, when the raw value is a genuine
    string equal to one of `words`; otherwise "" plus a note that never
    echoes the supplied value - naming the SHAPE when the raw value is not a
    genuine string at all, or simply stating that the field is outside its
    documented vocabulary when it IS a string but not one of `words`. Both
    situations cost the verdict identically (hardening rule 6): an
    out-of-vocabulary reading is exactly as unusable for a PASS/FAIL decision
    as an unreadable one, so a caller that gets a non-None note here must
    treat the field as unread, never as a quiet non-match.
    """
    matched, note = _gate(row, field, *words)
    if note is not None:
        return "", f"{field} niet gelezen als {'/'.join(words)} (gelezen: {note})"
    if not matched:
        return "", f"{field} heeft niet de vorm van {'/'.join(words)}"
    return _raw(row, field).strip().upper(), None


def _string_or_gap(row: dict, field: str) -> tuple[str | None, str | None]:
    """The stripped string at `field`, or a shape note when it is not one -
    `_gate`'s discipline for a field with NO closed vocabulary to match
    against (`certkeyname`, `cmdspec`): the value is only ever COMPARED
    (a substring test) or rendered alongside an already-masked name, never
    matched against a fixed word list, so there is no "heeft niet de vorm
    van ..." half - only the same question every gated field asks: was this
    a genuine string at all. `None` plus a note names ANY non-string
    (bool/int/list/dict/null) or an absent key; a note of None means the raw
    value genuinely is text - matching, empty, or not, which is the
    caller's own business logic, never a shape problem.
    """
    raw = _raw(row, field)
    if not isinstance(raw, str):
        return None, shape_or_missing(raw)
    return field_text(row, field), None


def _enum_text(row: dict, field: str) -> str:
    """A display-only NITRO enumeration rendered for evidence: the token, or
    "?" - hidden_rules._enum_text's own discipline (see the module
    docstring's IDIOM DECISION for why this stays a copy on top of the
    shared `answer.repeatable_token` rather than an import of that private
    helper). `type` reaches this answer as part of an `addr (type)`
    compound OUTSIDE any vocabulary match - `_gate` only established that
    the raw value IS a genuine string, never that it is SAFE to print, so it
    still needs the bare-token shape gate before being echoed. A value with
    a line break, a sentence, or anything longer than a short NITRO token
    becomes "?" here instead of reaching the reader.
    """
    token = repeatable_token(field_text(row, field), max_words=4)
    return token if token else "?"


def _int_or_gap(row: dict, field: str) -> tuple[int | None, str | None]:
    """The whole number at `field` - hidden_rules._num_gate's discipline,
    this module's copy of it, now carrying `_vocab`'s two-way split for the
    refusal TEXT too: `export.shape_of` names EVERY string "een lege of
    alleen-witruimte tekstwaarde", which is
    simply false for a readable, non-empty string that just does not parse
    as a whole number (measured with `timeout="negenhonderd"`). `(None,
    None)` when the key is genuinely ABSENT (this appliance's own documented
    default then applies, e.g. systemparameter.timeout absent means
    NetScaler's own 900-second default - not a read failure); `(value,
    None)` when it parses as a whole number; `(None, <note>)` otherwise -
    the shape claim only when the value truly IS empty/whitespace or not a
    string at all, "heeft niet de vorm van een geheel getal" (no value
    echoed) when it is a genuine non-empty string that simply is not a
    whole number.
    """
    raw = _raw(row, field)
    if raw is MISSING:
        return None, None
    if isinstance(raw, bool):
        return None, _int_gap_note(field, raw)
    if isinstance(raw, int):
        return raw, None
    if isinstance(raw, str):
        try:
            return int(raw.strip()), None
        except ValueError:
            return None, _int_gap_note(field, raw)
    return None, _int_gap_note(field, raw)


def _int_gap_note(field: str, raw) -> str:
    text = raw.strip() if isinstance(raw, str) else ""
    if text:
        return f"{field} heeft niet de vorm van een geheel getal"
    return f"{field} niet gelezen als een geheel getal (gelezen: {shape_or_missing(raw)})"


def _decide(
    name: str, evidence: str, instances: list[str], unread: list[str], detail: str, gaps: tuple[ReadGap, ...] = ()
) -> DimensionResult:
    if instances:
        return DimensionResult(name, "FAIL", evidence, tuple(instances), tuple(unread), detail, gaps)
    if unread or gaps:
        # 1.0.2: a PASS over a known gap in its own source is no PASS -
        # the instance that would fail it can sit in exactly what was unread.
        named = [*unread, *(gap.source for gap in gaps)]
        reason = "verdict-sturende bron niet bruikbaar gelezen: " + ", ".join(dict.fromkeys(named))
        if not unread:
            # Only a partial gap: say what WAS read, and why that is not a PASS.
            reason = f"{detail}, maar niet alles is gelezen ({', '.join(dict.fromkeys(named))}); dus geen PASS"
        return DimensionResult(name, "NIET BEOORDEELD", evidence, (), tuple(unread), reason, gaps)
    return DimensionResult(name, "PASS", evidence, (), (), detail)


def _rows(export, resource: str, unread: list[str]) -> list[dict]:
    """Every row of `resource`, whichever of the two real shapes it is.

    Some of this dimension's sources are lists (`config/nsip`,
    `config/systemcmdpolicy`); the real collector writes others as its
    singleton shape - a bare object under the key, not a one-element list
    (`config/systemparameter`, `config/nsparam` - MEASURED on the real
    export; see export.py's `single()` for the same distinction).
    `objects()` demands a list and reports a read gap on a singleton;
    trying `single()` only on THAT gap - never on a genuine read failure,
    which `single()` reports identically anyway - costs one extra read-only,
    local, side-effect-free attempt and covers both shapes with one caller.
    A resource unusable under both calls appends itself to `unread` exactly
    once.

    `[one] if one is not None else []`: a truthiness check here (`if one`)
    would treat a singleton that WAS read OK but carries no fields at all
    (`{}`, falsy) exactly like a failed
    read - vanishing silently instead of yielding one row whose OWN fields
    then correctly report themselves as "sleutel ontbreekt" through
    `_gate`/`_vocab`/`_int_or_gap`/`_string_or_gap`. `single()` only ever
    returns `None` for the genuinely-established-empty case (manifest
    status EMPTY); a dict, even an empty one, means the read succeeded and
    must count as one row.
    """
    rows, gap = export.objects(resource)
    if gap is None:
        return rows
    one, single_gap = export.single(resource)
    if single_gap is None:
        return [one] if one is not None else []
    unread.append(resource)
    return []


def _exposure(export) -> DimensionResult:
    unread: list[str] = []
    instances: list[str] = []
    for row in _rows(export, NSIP_RESOURCE, unread):
        address = field_text(row, "ipaddress") or "?"
        is_nsip, type_note = _gate(row, "type", "NSIP")
        if type_note:
            unread.append(f"{NSIP_RESOURCE} ({address}, veld type niet gelezen: {type_note})")
            continue
        if is_nsip:
            continue
        kind = _enum_text(row, "type")
        on = []
        gui_word, gui_note = _vocab(row, "gui", "ENABLED", "SECUREONLY", "DISABLED")
        if gui_note:
            unread.append(f"{NSIP_RESOURCE} ({address}, veld gui: {gui_note})")
        elif gui_word in ("ENABLED", "SECUREONLY"):
            on.append("gui")
        ssh_word, ssh_note = _vocab(row, "ssh", "ENABLED", "DISABLED")
        if ssh_note:
            unread.append(f"{NSIP_RESOURCE} ({address}, veld ssh: {ssh_note})")
        elif ssh_word == "ENABLED":
            on.append("ssh")
        if on:
            instances.append(f"{address} ({kind})")
    return _decide(
        "blootstelling",
        NSIP_RESOURCE,
        instances,
        unread,
        "beheerprotocol op een data-plane-adres (SNIP of VIP)"
        if instances
        else "geen beheerprotocol op een data-plane-adres",
    )


def _transport(export) -> DimensionResult:
    unread: list[str] = []
    instances: list[str] = []
    for row in _rows(export, NSIP_RESOURCE, unread):
        address = field_text(row, "ipaddress") or "?"
        kind = _enum_text(row, "type")
        cleartext = []
        for field, label in (("telnet", "telnet"), ("ftp", "FTP")):
            word, note = _vocab(row, field, "ENABLED", "DISABLED")
            if note:
                unread.append(f"{NSIP_RESOURCE} ({address}, veld {field}: {note})")
            elif word == "ENABLED":
                cleartext.append(label)
        if cleartext:
            instances.append(f"{address} ({kind}): {'+'.join(cleartext)} ingeschakeld")
        # The NSIP admin GUI itself running plain HTTP (as opposed to
        # SECUREONLY, HTTPS-only) is its own transport concern, independent
        # of the exposure dimension above (which only cares whether a
        # DATA-PLANE address carries it).
        is_nsip, type_note = _gate(row, "type", "NSIP")
        if type_note:
            unread.append(f"{NSIP_RESOURCE} ({address}, veld type niet gelezen: {type_note})")
        elif is_nsip:
            gui_word, gui_note = _vocab(row, "gui", "ENABLED", "SECUREONLY", "DISABLED")
            if gui_note:
                unread.append(f"{NSIP_RESOURCE} ({address}, veld gui: {gui_note})")
            elif gui_word == "ENABLED":
                instances.append(f"{address} (NSIP): gui=ENABLED, niet SECUREONLY")
    # mgmtparam carries the HTTPS-only setting on builds that serve it. Its
    # absence is a read gap and never a pass: it is verdict-steering. This
    # build's own status is NOT_SUPPORTED (measured) - a fact about the
    # build, not about the appliance's configuration, and it still counts as
    # unread here rather than silently passing.
    _rows(export, MGMTPARAM_RESOURCE, unread)
    return _decide(
        "transport",
        f"{NSIP_RESOURCE}, {MGMTPARAM_RESOURCE}",
        instances,
        unread,
        "cleartext beheerprotocol ingeschakeld" if instances else "geen cleartext beheerprotocol",
    )


def _certificate(export) -> DimensionResult:
    unread: list[str] = []
    bindings, gap = export.bindings(CERT_BINDING)
    if gap is not None:
        unread.append(CERT_BINDING)
        bindings = []
    # 1.0.2: a vserver the binding file has no parent entry for has
    # UNREAD certificate bindings - the default certificate may hang there.
    parent_gaps = export.binding_parents(CERT_BINDING).gaps if gap is None else ()
    instances: list[str] = []
    for b in bindings:
        if not isinstance(b, dict):
            continue
        vserver = field_text(b, "vservername") or "?"
        cert, cert_note = _string_or_gap(b, "certkeyname")
        if cert_note:
            # `certkeyname` has no closed vocabulary, only an exact-name
            # test - a bool/int/list/dict/null/absent value must cost the
            # verdict exactly like an unreadable vocabulary field does,
            # never read as "is not the default name" and therefore safe.
            unread.append(f"{CERT_BINDING} ({vserver}, veld certkeyname: {cert_note})")
            continue
        # Measured (17-9-2026): this used to be a
        # substring test (`DEFAULT_MGMT_CERT in cert.lower()`), so a custom
        # certificate whose name merely CONTAINS the default name as a
        # prefix or suffix - a different string than the appliance's own
        # default certificate - failed this dimension for a name it never
        # actually carries. The identity, not a substring of it.
        if cert.lower() == DEFAULT_MGMT_CERT:
            instances.append(vserver)
    return _decide(
        "certificaat",
        CERT_BINDING,
        instances,
        unread,
        f"{DEFAULT_MGMT_CERT} gebonden aan productieverkeer"
        if instances
        else f"{DEFAULT_MGMT_CERT} hangt aan geen enkele gelezen vserver",
        tuple(parent_gaps),
    )


def _rbac(export) -> DimensionResult:
    unread: list[str] = []
    instances: list[str] = []

    parameters = _rows(export, SYSTEMPARAM_RESOURCE, unread)
    if parameters:
        row = parameters[0]
        strong_word, strong_note = _vocab(row, "strongpassword", "ENABLED", "DISABLED")
        if strong_note:
            unread.append(f"{SYSTEMPARAM_RESOURCE} (veld strongpassword: {strong_note})")
        elif strong_word == "DISABLED":
            instances.append("systemparameter: strongpassword=disabled")
        timeout, timeout_note = _int_or_gap(row, "timeout")
        if timeout_note:
            unread.append(f"{SYSTEMPARAM_RESOURCE} (veld timeout: {timeout_note})")
        elif timeout == 0:
            instances.append("systemparameter: timeout=0")

    for row in _rows(export, CMDPOLICY_RESOURCE, unread):
        name = field_text(row, "policyname")
        if name.lower() in _BUILTIN_CMD_POLICIES:
            continue
        action_word, action_note = _vocab(row, "action", "ALLOW", "DENY")
        if action_note:
            unread.append(f"{CMDPOLICY_RESOURCE} ({name or '?'}, veld action: {action_note})")
            continue
        if action_word != "ALLOW":
            continue
        spec, spec_note = _string_or_gap(row, "cmdspec")
        if spec_note:
            # `cmdspec` must not sit ungated beside a gated `action` in the
            # same loop body - a bool/int/list/dict/null/absent value must
            # cost the verdict exactly like the vocabulary miss above, never
            # silently read as "no shell".
            unread.append(f"{CMDPOLICY_RESOURCE} ({name or '?'}, veld cmdspec: {spec_note})")
            continue
        if "shell" in spec.lower() and "(?!" not in spec:
            instances.append(f"systemcmdpolicy {name or '?'}: ALLOW op 'shell'")

    user_rows, user_gap = export.systemuser_rows()
    if user_gap is not None:
        unread.append(SYSTEMUSER_RESOURCE)
    else:
        for row in user_rows:
            username = field_text(row, "username") or "?"
            timeout, timeout_note = _int_or_gap(row, "timeout")
            if timeout_note:
                unread.append(f"{SYSTEMUSER_RESOURCE} ({username}, veld timeout: {timeout_note})")
            elif timeout == 0:
                instances.append(f"systemuser {username}: timeout=0")

    parameters = _rows(export, NSPARAM_RESOURCE, unread)
    if parameters:
        row = parameters[0]
        internal_word, internal_note = _vocab(row, "internaluserlogin", "ENABLED", "DISABLED")
        if internal_note:
            unread.append(f"{NSPARAM_RESOURCE} (veld internaluserlogin: {internal_note})")
        elif internal_word == "ENABLED":
            instances.append("nsparam: internaluserlogin=ENABLED")

    return _decide(
        "RBAC",
        f"{SYSTEMPARAM_RESOURCE}, {CMDPOLICY_RESOURCE}, {SYSTEMUSER_RESOURCE}, {NSPARAM_RESOURCE}",
        instances,
        unread,
        "een of meer RBAC-hardeningen staan uit" if instances else "RBAC-hardeningen staan aan",
    )


def mgmt_plane_result(export) -> tuple[DimensionResult, ...]:
    return (_exposure(export), _transport(export), _certificate(export), _rbac(export))


def mgmt_plane(export, knowledge: Knowledge) -> Answer:
    findings: list[Finding] = []
    read_gaps: list[ReadGap] = []
    for result in mgmt_plane_result(export):
        detail = result.reason
        if result.instances:
            detail = f"{result.reason}: " + "; ".join(result.instances)
        findings.append(
            Finding(
                subject=result.name,
                outcome=result.verdict,
                certainty=Certainty.NOT_ESTABLISHED if result.verdict == "NIET BEOORDEELD" else Certainty.ESTABLISHED,
                evidence=result.evidence,
                reason=detail,
                subject_is_name=False,
            )
        )
        for source in result.unread:
            read_gaps.append(
                ReadGap(
                    source=source,
                    reason=f"bron voor {result.name} niet bruikbaar gelezen",
                )
            )
        read_gaps.extend(result.gaps)
    return Answer(
        question="staat het beheer van deze doos open",
        findings=findings,
        read_gaps=read_gaps,
        not_assessed=list(NOT_ASSESSED),
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )


def names_in_mgmt_sources(export) -> tuple[str, ...]:
    """Every appliance name and address this answer can print - the TWELFTH
    family of disclosure.names_from_export(): nsip addresses, command-policy
    names, the system user name(s) and the vservers that carry the default
    management certificate; plus the default management certificate's own
    name, which this answer prints UNCONDITIONALLY in both its PASS and its
    FAIL reason text (not only when hidden_rules.NSHC-HR-SSL-001 happens to
    fire on the same export).

    The nsip addresses overlap with the hidden-rules family,
    and that is fine - a name collected twice is replaced once. What does
    NOT overlap: a system USER name and a command-policy name appear in no
    other family, and this answer prints both.
    """
    names: set[str] = set()
    unread: list[str] = []
    for row in _rows(export, NSIP_RESOURCE, unread):
        address = field_text(row, "ipaddress")
        if address:
            names.add(address)
            names.add(f"{address} ({field_text(row, 'type') or '?'})")
    for row in _rows(export, CMDPOLICY_RESOURCE, unread):
        name = field_text(row, "policyname")
        if name:
            names.add(name)
    user_rows, user_gap = export.systemuser_rows()
    if user_gap is None:
        for row in user_rows:
            username = field_text(row, "username")
            if username:
                names.add(username)
    bindings, gap = export.bindings(CERT_BINDING)
    if gap is None:
        for row in bindings:
            if isinstance(row, dict):
                vserver = field_text(row, "vservername")
                if vserver:
                    names.add(vserver)
        # 1.0.2: the parent names a cross-check gap can print.
        names.update(export.binding_parents(CERT_BINDING).names)
    names.add(DEFAULT_MGMT_CERT)
    return tuple(sorted(names))
