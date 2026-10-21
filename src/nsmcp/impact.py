"""What breaks when this certificate expires.

This is the part that lifts the product above monitoring: monitoring reports
THAT something expires, this reports WHAT falls over then. Precisely there the
honesty must be sharpest - an unreadable binding file never means "no impact",
because that is exactly the false-green answer that causes an outage.

The server-versus-client-certificate distinction comes from the ca flag as
NITRO returns it: ca=true is a CA for client authentication and breaks
something quite different from a server certificate. If that flag is absent,
the distinction is not established and we say so.

NITRO returns a boolean flag both as a JSON boolean (true/false) and as a
string ("true"/"false", in varying case) - `_is_true` catches both. But the
ca flag is verdict-bearing: it decides whether it is the server certificate
or client authentication that fails, two genuinely different outages. A value
that is present but has neither recognized form (for example a bare JSON
null, as a collector can write for a field that was not fetched) must
therefore not silently count as "false": that would be fabricated certainty.
Such a form is, like an absent key, not establishable (`_ca_unknown`). The
snicert flag is not held to that bar: it only changes whether the report adds
"via SNI", not which outage it is - an unrecognized form there falls back to
"no SNI mention", an under-marked detail, not a wrong conclusion.

The same failure class applies to certkeyname itself: a binding whose
certkeyname cannot be established (absent, JSON null, empty after
normalization, or simply not text - a list, dict, boolean or number that
`str()` would blindly turn into a string that happens not to match) is a READ
GAP, not a filter miss; and as long as not every binding could be assessed,
the established "no bound virtual servers" statement is withheld. Both sides
of the name comparison run through the same normalization
(`_readable_name`, the same .strip() that mcp_server.py applies to the user
input), so source data with surrounding whitespace cannot silently miss.

Since the chain-aware round this module reads a SECOND source: the
certificate objects themselves (`config/sslcertkey`). A certificate that
issues other certificates carries no sslvserver binding of its own, so the
binding file alone reports it as "nothing bound" - true, but readable as
"nothing hangs on it" for a CA that is in fact indispensable. The relation
sits in the export already: the ISSUED certificate carries the field
`linkcertkeyname` with the name of its issuer. An ABSENT key there is the
normal state (NITRO writes it only when a link exists) and is therefore no
read gap; a PRESENT but unusable value is one, exactly like certkeyname.

The binding file is read TWICE, for two different questions. `bindings()`
answers "which bindings does it carry"; `binding_parents()` answers "is that
list complete" - by cross-checking the parent list against the object source
those parents come from. Without the second question a parent that is missing
ALTOGETHER stays invisible, because it leaves no trace in the file: the flat
list simply comes out shorter and looks complete. That was measured on this
product's own golden export (see export.py::binding_parents).

A THIRD source is the certificate side (`CERT_SIDE_FILE`): every binding of
a certificate, in the aggregate shape, read per kind. It carries the SSL
services on the certificate - the management services of the appliance
itself among them - which the vserver file never shows (route 3 below).

The FOURTH route is the use outside every binding with a virtual server or a
service: a SAML action, a SAML IdP profile and an SSL servicegroup name a
certificate too, and fall over with it (`cert_usage`, route 4 below). A
source of those that this export does not carry is a boundary of the answer,
never "no use".
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap, repeatable_token
from nsmcp.cert_usage import READ as OTHER_READ, CertUse, absent_dimension, join_list, other_usage
from nsmcp.expiry import CERT_BINDING, CERT_CHILDREN, RESOURCE as CERTKEY_RESOURCE, Usage, binding_kind_names
from nsmcp.export import MISSING as _MISSING, shape_of, shape_or_missing
from nsmcp.handelen import DENIED_PREFIXES
from nsmcp.knowledge import Knowledge

# The real NSHC 1.0 collector writes this file as "...by-parent.json" (in the
# by-parent shape that export.py::_flatten_by_parent flattens), not as a bare
# "sslvserver_sslcertkey_binding.json". It is a data file name, not analysis
# logic.
BINDING_FILE = "sslvserver_sslcertkey_binding.by-parent.json"

# The CERTIFICATE-SIDE binding file: every binding of a certificate, one
# document per certificate, with a nested list per bound kind (the
# "aggregate" shape, read per kind through `Export.binding_rows`).
#
# Measured on the golden export (2026-08-27): for `ns-server-certificate` this
# file carries EIGHT `sslcertkey_service_binding` entries (nshttps-127.0.0.1-443,
# nshttps-certauth-*-8443, nsrpcs-*, plus IPv6 variants). That is the
# MANAGEMENT path: whoever takes that certificate away without knowing those
# bindings takes down management HTTPS. BINDING_FILE above shows no bound
# virtual server for it, so before this file was read the answer closed with
# an ESTABLISHED statement - true as worded ("geen gebonden virtuele
# servers"), but readable as "nothing hangs on it".
#
# Route 3 below reads it: every service on the questioned certificate becomes
# a finding, a service on the built-in denylist (`handelen.DENIED_PREFIXES`)
# named as the appliance's own management traffic. Only when the file cannot
# be read does the boundary below (`_other_bindings_dimension`) still stand.
CERT_SIDE_FILE = CERT_BINDING
SERVICE_CHILD = "sslcertkey_service_binding"
# The one kind the LIST shape of the same file carries: its own resource.
LIST_KIND = "sslcertkey_binding"

# The two outcomes of a service on the questioned certificate. A service on
# the built-in denylist (`handelen.DENIED_PREFIXES`: nshttps-, nsrpcs-) is the
# management traffic of the appliance itself, and is named as that.
MANAGEMENT_SERVICE_OUTCOME = "beheerverkeer van de appliance zelf; TLS op deze beheerdienst valt uit"
SERVICE_OUTCOME = "raakt deze SSL-dienst (service); TLS valt uit voor deze dienst"

# The spec promises that impact also covers "whether the chain is complete
# and whether the intermediate CA does not itself fall over earlier". Since
# the chain-aware round the DIRECT issuing relation from the export IS read
# and shown (route 2 in what_breaks below), so this statement must no longer
# claim otherwise - a boundary text that is out of date is a lie about the
# product's own limits. What genuinely remains outside is named literally,
# and that includes the DEPTH limit: route 2 walks exactly one level
# (issuer -> issued certificate -> the services bound to it) and does not
# recurse, so an issued certificate that issues in turn is not followed
# further. The dimension is reported with EVERY impact answer - including a
# read-gap answer, because there it is just as unassessed.
CHAIN_DIMENSION = NotAssessed(
    subject="volledige certificaatketen buiten deze export",
    reason=(
        "deze versie leest de rechtstreekse uitgifterelatie uit de export (het veld"
        " linkcertkeyname op een certificaat) en toont de keten die daaruit volgt,"
        " inclusief de diensten achter het uitgegeven certificaat; die keten wordt een"
        " niveau diep gevolgd, van uitgever naar uitgegeven certificaat naar de diensten"
        " daarachter, en geeft een uitgegeven certificaat zelf weer certificaten uit, dan"
        " blijft die volgende stap ongelezen; buiten bereik blijven: de volledige"
        " ketenvalidatie tot een root, welke rol een certificaat in die keten speelt (de"
        " ruwe velden certificatetype, subject en issuer reizen als bewijs mee, maar de rol"
        " zelf wordt niet afgeleid) en of een client de aangeboden keten daadwerkelijk"
        " afwijst - dat hangt mede af van de vertrouwensopslag van die client; en verder"
        " tussenliggende CA's die niet als certKey op deze appliance staan"
    ),
)

# The SECOND boundary, deliberately its own dimension instead of one more
# clause on the sentence above. Two different limits: the one above is about
# how FAR the chain is followed, this one is about WHICH USERS of a certificate
# are read at all. Merged, the second disappears into a long sentence about
# chains - and it was precisely this one that was missing when a certificate
# carrying eight management-service bindings got an answer that read as
# complete. See CERT_SIDE_FILE above for the measurement.
#
# Reported only when CERT_SIDE_FILE could NOT be read (an export without it,
# or one whose copy is not trusted): then these users of the certificate stay
# unread, and saying so is the honest boundary. When it IS read, the users are
# findings and this boundary does not apply. Not a read gap, the same as
# before the file was read: an export that simply does not carry this file
# still gets an established impact answer about its virtual servers.
#
# The types are named LITERALLY, because a reader looking for "does my service
# hang on this?" searches for the word, not for a category.
OTHER_BINDINGS_SUBJECT = "gebruik van dit certificaat buiten de bindingen met virtuele servers"


def _other_bindings_dimension(unread_reason: str) -> NotAssessed:
    return NotAssessed(
        subject=OTHER_BINDINGS_SUBJECT,
        reason=(
            f"{CERT_SIDE_FILE} is niet gelezen ({unread_reason}); in dat bestand legt de"
            " collector de OVERIGE bindingen van een certificaat vast, dus daardoor blijven"
            " ongelezen: SSL-diensten (services) en servicegroepen waaraan dit certificaat"
            " gebonden is, waaronder de interne diensten waarop het beheerverkeer van de"
            " appliance zelf staat, en verder authenticatie-objecten, CA-bundels en monitors;"
            " een certificaat waarvoor hier geen gebonden virtuele server gevonden is, kan dus"
            " nog altijd aan zulke diensten hangen, en dat is bij een certificaatwissel het pad"
            " dat als eerste stilvalt"
            # Bewust niet het werkwoord voor het omruilen zelf: een geblokkeerd
            # actievoorstel mag dat woord nergens in zijn tekst dragen (drie tests
            # bewaken dat), en een grenstekst reist met elk antwoord mee.
        ),
    )


@dataclass(frozen=True)
class ImpactAnswer(Answer):
    """An Answer that explicitly states WHICH virtual servers are affected.

    A derived collection is an assumption; this is a statement. action.py
    must never derive the affected vservers from the findings list (in the
    empty case what_breaks() sets `subject=certname`, the CERTIFICATE, so
    that derivation fabricates evidence). `Answer` itself stays untouched -
    it is the shared shape all three tools hang on, and `what_expires` has
    nothing to do with vservers. This is an extension of exactly the one
    chain that needs it, and everything an Answer can do (to_text,
    is_complete) keeps working.

    The collection contains only vservers for which an ESTABLISHED finding
    was made, deduplicated and in reading order: a vserver with two bindings
    (for example a regular and an SNI binding) is one vserver to relink, not
    two.
    """

    affected_vservers: tuple[str, ...] = field(default_factory=tuple)
    # The certificates this certificate demonstrably ISSUES (config/sslcertkey,
    # field linkcertkeyname). Deliberately a SECOND collection next to
    # affected_vservers instead of being merged into it: those two drive two
    # DIFFERENT repairs. A vserver is rebound to a new certificate; an issued
    # certificate is re-LINKED to the new CA. Merging them would make
    # action.py propose a vserver rebind for something that is not a vserver -
    # the very class of fabricated advice this field pair exists to prevent.
    # Deduplicated and in reading order, same rule as above.
    issued_certificates: tuple[str, ...] = field(default_factory=tuple)
    # The certificate names in this export that CARRY the asked-for term,
    # for a name config/sslcertkey does not know. A THIRD explicit collection,
    # for the same reason as the two above: `action.what_to_do` builds its own
    # answer and carries no findings over, so a candidate line that lived only
    # in a finding would reach `certificaat_wat_breekt_er` and never
    # `certificaat_wat_moet_ik_doen` - while both take the same half name.
    #
    # THREE states, deliberately, and `None` is not the empty tuple:
    # - None  : no candidate question to answer here - either the name IS in
    #           this export, or config/sslcertkey could not be read and then
    #           nothing about near misses is established either;
    # - ()    : the name is not in this export and NOTHING carries the term
    #           ("geen kandidaten" - a statement, not silence);
    # - (...) : the near misses, sorted and capped.
    name_candidates: tuple[str, ...] | None = None
    # How many certificates config/sslcertkey was read as. Travels WITH the
    # collection above and for the same reason: it is the evidence line under
    # the candidate statement ("config/sslcertkey: 4 certificaten"), and
    # `what_to_do` cannot count a source it never reads. Only meaningful when
    # `name_candidates` is not None; 0 on an answer that carries no candidate
    # question at all.
    certificate_count: int = 0
    # A8. The usage state of the QUESTIONED certificate,
    # from the SAME derivation as certificaat_wat_verloopt_er
    # (expiry.usage_per_certificate). An explicit field, never a `Finding`:
    # an earlier version appended it as one, and that broke
    # action.py (every NOT_ESTABLISHED finding becomes a synthetic ReadGap,
    # so "onbekend" would permanently block a change proposal) and
    # disclosure.py's minimal-level count/verdict. Same discipline as `name_candidates` above.
    #
    # THREE states: `None` means no usage state could be derived at all
    # (primary read failed, or the certificate is not one this export
    # knows); a `Usage` with `.state == "onbekend"` means the state WAS
    # computed and genuinely could not be established - two different facts.
    # `used_by` always travels empty here (see `what_breaks` below) -
    # `disclosure._limit()` does not mask this field, so the names never
    # reach it in the first place.
    usage: Usage | None = None
    # The SSL services (sslcertkey_service_binding in the certificate-side
    # file) that demonstrably hang on this certificate, deduplicated and in
    # reading order - management services of the appliance itself included.
    # A FOURTH explicit collection, for the same reason as the first three:
    # `action.what_to_do` builds its own answer and must not derive what is
    # affected from the findings list. It refuses a proposal when one of
    # these is a management service (the built-in denylist), and names the
    # others as a manual step. At the end of the dataclass, with a default,
    # so no existing keyword or position moves.
    affected_services: tuple[str, ...] = field(default_factory=tuple)
    # The ESTABLISHED uses outside the bindings with virtual servers and
    # services (route 4): a SAML action, a SAML IdP profile or an SSL
    # servicegroup that names this certificate, each with its role. A FIFTH
    # explicit collection, for the reason the four above give: action.py
    # names them as a manual step and must not derive them from the
    # findings. Structured, not text, so the disclosure seam can mask the
    # object name inside each use. At the end, with a default.
    other_uses: tuple[CertUse, ...] = field(default_factory=tuple)

    def _extra_lines(self) -> list[str]:
        """Adds exactly one line: the usage state of the questioned
        certificate, through `Answer._extra_lines()`
        rather than a `to_text()` override that spliced a rendered string
        back in at a hard-coded `len(lines) - 3` index.

        Two invariants: never renders `self.usage.used_by` (stripped to `()`
        at the source, see `what_breaks`, so there is nothing to leak
        through 'beperkt' even though `disclosure._limit()` does not know
        this field exists); never fires for `disclosure._minimal()`'s
        synthetic "empty" copy, which clears `findings`, `read_gaps` AND
        `not_assessed` together to borrow the trailing Kennisbasis/Gegevens
        stamps via a fixed-length slice - a REAL `what_breaks()` answer
        never has all three empty at once (its two unconditional
        `NotAssessed` dimensions alone rule that out).
        """
        if self.usage is None:
            return []
        if not self.findings and not self.read_gaps and not self.not_assessed:
            return []
        if self.usage.state == "onbekend":
            line = f"- gebruiksstand: onbekend - {self.usage.reason}"
        else:
            line = f"- gebruiksstand: {self.usage.state} [{Certainty.ESTABLISHED.value}]"
        return ["", line]


_TRUE_FORMS = {"true", "yes", "1"}
_FALSE_FORMS = {"false", "no", "0"}


def _is_true(value) -> bool:
    return str(value).strip().lower() in _TRUE_FORMS


# The shape of a NITRO enumeration token, as `certificatetype` carries it
# (CLNT_CERT, SRVR_CERT, ROOT_CERT - confirmed against
# `tests/fixtures/lab-export-vpx-20260826/objects/sslcertkey.json`). Uppercase,
# digits and underscores only: no lowercase, no spaces, no punctuation, and
# bounded in length - so a distinguished name, a hostname or an organization
# name cannot pass as one. ONE word, hence `max_words=1`, and no hyphen.
# The shape test itself is `answer.repeatable_token`, shared with dienst.py
# and overzicht.py: three local copies of this regex had already drifted
# apart once (one of them lost its length bound entirely).
def _is_enum_token(value) -> bool:
    return repeatable_token(value, max_words=1, allow_hyphen=False) is not None


def _readable_name(value) -> str | None:
    """Normalizes a name field to the form in which it is compared.

    Returns None as soon as nothing usable remains: an absent key, a JSON
    null, a value that is empty after normalization - AND every form that
    simply is not text (a list, dict, boolean or number). `str(value)`
    would blindly turn such forms into a string that happens not to match;
    that is a silent filter miss, not "cannot be established". Hence the
    isinstance gate up front, in the same style as export.py: first
    establish WHAT something is, then normalize - never the other way
    around. That is not "does not match" but "cannot be established" - the
    difference this whole product runs on.

    The normalization is deliberately the exact same .strip() that
    mcp_server.py (_normalize) applies to the user input, and it is used
    on BOTH sides of the comparison. It goes no further: only surrounding
    whitespace, no case or inner-whitespace folding, because "naam met
    spaties" and "cert_a" are and remain two different certificates.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _ca_unknown(value) -> bool:
    """Is this present ca value neither of the two recognized forms?

    Used only for the ca flag, not for snicert: ca decides between two
    different outages (server certificate or client authentication) and must
    therefore never silently fall back to "false". An empty or unrecognizable
    value (None, "", "onbekend", a number outside 0/1, ...) belongs, like a
    fully absent key, to "cannot be established".
    """
    normalized = str(value).strip().lower()
    return normalized not in _TRUE_FORMS and normalized not in _FALSE_FORMS


def _binding_index(bindings, label: str) -> tuple[dict[str, list[dict]], list[ReadGap]]:
    """Groups the bindings by certkeyname, ONCE, and reports a read gap for
    every binding whose certkeyname cannot be established.

    One pass, two consumers: the direct route (bindings on the questioned
    certificate) and the chain route (bindings on a certificate this one
    issues) read the same index. Walking the list twice would risk the two
    walks drifting apart in exactly the fail-closed rule that matters here.

    `label` is the name of the QUESTIONED certificate, only used in the read
    gap reason - the reason stays literally what it was before this index
    existed.
    """
    index: dict[str, list[dict]] = {}
    gaps: list[ReadGap] = []
    for position, b in enumerate(bindings, start=1):
        raw = b.get("certkeyname", _MISSING)
        name = _readable_name(None if raw is _MISSING else raw)
        if name is None:
            # Fail-closed: without a usable certkeyname it cannot be
            # established WHETHER this binding belongs to this
            # certificate. That ignorance must be visible, not filtered
            # away.
            vserver = _readable_name(b.get("vservername")) or "(naamloos)"
            seen = shape_or_missing(raw)
            gaps.append(
                ReadGap(
                    source=f"{BINDING_FILE} (binding {position}, vservername={vserver})",
                    reason=(
                        f"certkeyname is niet bruikbaar: {seen}; niet vast te stellen of deze"
                        f" binding bij {label!r} hoort"
                    ),
                )
            )
            continue
        index.setdefault(name, []).append(b)
    return index, gaps


def _certificate_facts(certs, target: str | None) -> tuple[set[str], str | None, dict | None, list[ReadGap]]:
    """One pass over the certificate objects, for the four facts route 2
    cannot derive from a single certificate on its own.

    Returns (names present in this export, what the QUESTIONED certificate
    itself names as its issuer, the questioned certificate's own object -
    needed for its role fields in the evidence - and read gaps for entries
    whose shape cannot be read).

    `export.objects()` already refuses a non-object element for the whole
    file, so the shape gate here is unreachable through that path. It is
    still POSITIVE rather than trusting that guarantee: a silent skip is the
    very failure class this module exists to prevent, and a bare `.get()` on
    a string is not a wrong answer but a crash.
    """
    names: set[str] = set()
    target_link: str | None = None
    target_object: dict | None = None
    gaps: list[ReadGap] = []
    for position, c in enumerate(certs, start=1):
        if not isinstance(c, dict):
            gaps.append(
                ReadGap(
                    source=f"{CERTKEY_RESOURCE} (certificaat {position})",
                    reason=(
                        f"deze vermelding is geen object (type={type(c).__name__}); niet vast te"
                        " stellen om welk certificaat het gaat, en dus ook niet of het een"
                        " uitgifterelatie draagt"
                    ),
                )
            )
            continue
        name = _readable_name(c.get("certkey"))
        if name is None:
            continue
        names.add(name)
        if target is not None and name == target:
            target_link = _readable_name(c.get("linkcertkeyname"))
            target_object = c
    return names, target_link, target_object, gaps


def _certificate_role(c: dict) -> str:
    """The RAW role fields of a certificate, as evidence - never as a verdict.

    `certificatetype` is a NITRO enumeration, and it is reproduced only when
    the value really has the SHAPE of such an enumeration (`_ENUM_TOKEN`
    below). "Every element is text" was not enough: an export can be SUPPLIED
    (see export.py), the disclosure layer's name collection does not read this
    field, and text in it therefore reaches the answer unmasked - the exact
    leak `subject`/`issuer` are derived to avoid. Positively testing the shape
    keeps the evidence a reader needs while free text can no longer travel
    through; anything else is named by shape, the same rule as everywhere else
    in this product (see export.py::shape_of).

    `subject`/`issuer` are DERIVED to one fact - are they equal - and never
    reproduced. Those fields carry a full distinguished name, which the
    disclosure layer's name collection does not read and therefore cannot
    mask: putting them in an answer would leak in the 'beperkt' setting. That
    one derived fact is exactly what the reader needs to see whether this is
    a self-signed certificate, without this product having to CLAIM a root or
    intermediate role that the export does not establish.
    """
    raw_type = c.get("certificatetype", _MISSING)
    if raw_type is _MISSING:
        type_text = "certificatetype ontbreekt"
    elif isinstance(raw_type, list) and raw_type and all(_is_enum_token(x) for x in raw_type):
        type_text = f"certificatetype={raw_type!r}"
    elif _is_enum_token(raw_type):
        type_text = f"certificatetype={raw_type!r}"
    else:
        type_text = f"certificatetype heeft geen herkenbare opsommingsvorm ({shape_of(raw_type)})"
    subject = _readable_name(c.get("subject"))
    issuer = _readable_name(c.get("issuer"))
    if subject is None or issuer is None:
        same_text = "subject/issuer niet allebei leesbaar"
    elif subject == issuer:
        same_text = "subject en issuer zijn gelijk"
    else:
        same_text = "subject en issuer verschillen"
    return f"{type_text}, {same_text}"


# At most five, so an answer names a direction instead of dumping the
# certificate catalogue of the appliance into the model's context. The same
# cap and the same reason as `dienst._MAX_CANDIDATES`.
_MAX_CANDIDATES = 5


def _name_candidates(known_names, term: str) -> tuple[str, ...]:
    """The certificate names that CARRY the asked-for term, case-insensitively,
    sorted and capped. Reads the names `_certificate_facts` already collected
    from config/sslcertkey - one pass over that source, not a second one that
    could drift from it."""
    needle = term.lower()
    return tuple(sorted(name for name in known_names if needle in name.lower()))[:_MAX_CANDIDATES]


def candidate_finding(term: str, candidates: tuple[str, ...], certificate_count: int) -> Finding:
    """The candidate line, in ONE place for the two tools that show it.

    Same shape and same wording as `dienst.service_status`'s candidate line
    (there for virtual servers, here for certificates), so a reader who has
    seen one recognizes the other. Public because `action.what_to_do` renders
    the same line on the same question - a second copy of this text would be
    a second thing to keep in step.
    """
    return Finding(
        subject=f"kandidaten (naam bevat '{term}', hoofdletterongevoelig)",
        outcome=", ".join(candidates) if candidates else "geen kandidaten",
        certainty=Certainty.ESTABLISHED,
        evidence=f"{CERTKEY_RESOURCE}: {certificate_count} certificaten",
        # This subject is THIS product's own vocabulary plus the term the
        # caller typed - not an appliance object name. Collecting it as one
        # would write caller input into the operator's pseudonym table (see
        # disclosure._collect_names). The candidate NAMES in the outcome are
        # masked through the structural export collection, exactly like every
        # other name in an answer.
        subject_is_name=False,
        # ONLY at 'volledig'. This line answers a
        # question about the CALLER'S OWN TERM, and below 'volledig' that
        # makes it an adaptive substring oracle: stable pseudonyms plus the
        # probes a, ab, abc ... reconstruct a real certificate name that was
        # never shown. See `Finding.only_in_full` for the full mechanism.
        only_in_full=True,
    )


def what_breaks(export, knowledge: Knowledge, certname: str) -> ImpactAnswer:
    bindings, binding_gap = export.bindings(BINDING_FILE)
    certs, cert_gap = export.objects(CERTKEY_RESOURCE)
    read_gaps: list[ReadGap] = [g for g in (binding_gap, cert_gap) if g is not None]
    findings: list[Finding] = []
    # Passed explicitly to action.py instead of derived there from the
    # findings list: which vservers are affected is known HERE - another
    # module should not have to guess it.
    affected: list[str] = []
    issued: list[str] = []

    target = _readable_name(certname)
    # The name as it appears in a read gap reason: the normalized form when
    # there is one, otherwise the raw argument - never an empty quote.
    label = target or certname

    index: dict[str, list[dict]] = {}
    binding_unassessed = 0
    if binding_gap is None:
        index, index_gaps = _binding_index(bindings, label)
        # The THIRD state of a by-parent file, next to "read" and "unusable
        # outcome": a parent that carries no entry at all. Its bindings were
        # never read, so it cannot be established which certificate hangs on
        # it - and therefore not, for ANY certificate, that this one does
        # not. Counted as unassessed exactly like an unusable certkeyname:
        # the absence of hits is worth nothing while a service's bindings
        # are unread, so the closing "geen gebonden virtuele servers
        # gevonden" statement is withheld. See export.py::binding_parents
        # for what is compared and why it cannot invent an expectation.
        coverage = export.binding_parents(BINDING_FILE)
        binding_unassessed = len(index_gaps) + len(coverage.gaps)
        read_gaps.extend(index_gaps)
        read_gaps.extend(coverage.gaps)

    # --- route 1: bindings directly on this certificate --------------------
    matched = index.get(target, []) if target is not None else []
    for b in matched:
        # Same isinstance gate as certkeyname (see _readable_name): a
        # non-empty list/dict/number is "or"-truthy, so a bare `str(...)`
        # would turn such a form into a literal Python repr (for example
        # "['LB_VS_A']") entering the evidence AND affected_vservers, on
        # which action.py builds a relink advice. A non-text form falls back
        # cleanly to "(naamloos)".
        vserver = _readable_name(b.get("vservername")) or "(naamloos)"
        sni = _is_true(b.get("snicert"))
        evidence = f"{BINDING_FILE}: vservername={vserver}, snicert={b.get('snicert')!r}, ca={b.get('ca')!r}"
        if "ca" not in b or _ca_unknown(b.get("ca")):
            reason = (
                "de ca-vlag ontbreekt in deze binding, dus servercertificaat of clientauthenticatie is niet te onderscheiden"
                if "ca" not in b
                else "de ca-vlag heeft een vorm die niet als true/false te herkennen is, dus servercertificaat of clientauthenticatie is niet te onderscheiden"
            )
            findings.append(
                Finding(
                    subject=vserver,
                    outcome="raakt deze virtuele server; rol niet vast te stellen",
                    certainty=Certainty.NOT_ESTABLISHED,
                    evidence=evidence,
                    reason=reason,
                )
            )
            continue
        if _is_true(b.get("ca")):
            outcome = "clientauthenticatie valt uit (CA-binding)"
        else:
            outcome = "servercertificaat" + (" via SNI" if sni else "") + "; TLS valt uit voor deze dienst"
        findings.append(
            Finding(
                subject=vserver,
                outcome=outcome,
                certainty=Certainty.ESTABLISHED,
                evidence=evidence,
            )
        )
        # Only here, in the ESTABLISHED branch: a vserver whose role is not
        # established is not a vserver to base a relink on. Deduplicated
        # preserving reading order - two bindings on the same vserver
        # (regular + SNI) remain one relink.
        if vserver not in affected:
            affected.append(vserver)

    # --- route 2: certificates ISSUED by this certificate ------------------
    # The measured blind spot. A CA that issues a service certificate carries
    # no sslvserver binding of its own, so route 1 finds nothing - while it
    # is indispensable: when it expires, chain validation fails for every
    # service behind the certificates it issued. The relation sits in the
    # export already: the ISSUED certificate carries `linkcertkeyname` with
    # the name of its issuer.
    cert_unassessed = 0
    # NAMING, never choosing - see `ImpactAnswer.name_candidates` for the
    # three states this variable carries and why it is a collection on the
    # answer instead of only a finding.
    name_candidates: tuple[str, ...] | None = None
    certificate_count = len(certs)
    known_names: set[str] = set()
    if cert_gap is None:
        # One pass up front, three facts the loop below needs and that cannot
        # be derived from a single certificate on its own:
        # - which certificate names ARE in this export (a link pointing at a
        #   name that is not there is a dangling relation, an anomaly in its
        #   own right);
        # - what the QUESTIONED certificate itself points at (needed to
        #   recognize a circular relation: A names B as its issuer while B
        #   names A);
        # - every entry whose shape cannot be read at all.
        known_names, target_link, target_object, shape_gaps = _certificate_facts(certs, target)
        cert_unassessed += len(shape_gaps)
        read_gaps.extend(shape_gaps)
        # Measured in the second practice round: asked about "het
        # zaakportaal-certificaat", the model handed over a half name and got
        # an answer about a certificate that does not exist, with no way
        # forward - while `dienst_status`, which HAD learned to name
        # candidates, let the model correct itself inside the same turn. So
        # this answer names what it read: the certificate names that carry
        # the term. It resolves nothing and picks nothing - that would be
        # this product guessing what was meant.
        if target is not None and target not in known_names:
            name_candidates = _name_candidates(known_names, target)
        # The role fields of the QUESTIONED certificate - the one that
        # expires. That is the role the reader needs to weigh the chain
        # statement: for a self-signed root the failure mechanism sits in
        # the trust stores of the clients, not in the chain this appliance
        # offers. The fields travel as evidence; the role itself is
        # deliberately not derived from them (see CHAIN_DIMENSION).
        issuer_role = (
            f"uitgever {label}: {_certificate_role(target_object)}"
            if target_object is not None
            else f"uitgever {label}: staat niet als certKey in deze export"
        )
        for position, c in enumerate(certs, start=1):
            if not isinstance(c, dict):
                # Already reported as a read gap by `_certificate_facts`; the
                # same positive shape gate as `_readable_name` and
                # `disclosure.py`, here so `c.get(...)` below can never run on
                # something that has no `.get`.
                continue
            raw_link = c.get("linkcertkeyname", _MISSING)
            if raw_link is _MISSING:
                # An ABSENT key is the normal state: NITRO writes this field
                # only when a link really exists (1 of 4 certificates in the
                # live lab fixture). Treating that as a read gap would turn
                # every export into one big read gap. The honesty lives in
                # the WORDING of the closing statement below ("in deze
                # export"), not in a fabricated gap per certificate.
                continue
            link = _readable_name(raw_link)
            if link is None:
                # PRESENT but unusable is a different story: same failure
                # class as an unusable certkeyname on a binding. `str(...)`
                # would blindly build a string that happens not to match, and
                # the relation would vanish from the filter without a trace.
                cert_unassessed += 1
                owner = _readable_name(c.get("certkey")) or "(naamloos)"
                read_gaps.append(
                    ReadGap(
                        source=f"{CERTKEY_RESOURCE} (certificaat {position}, certkey={owner})",
                        reason=(
                            f"linkcertkeyname is niet bruikbaar: {shape_of(raw_link)}; niet vast te"
                            f" stellen of dit certificaat door {label!r} uitgegeven wordt"
                        ),
                    )
                )
                continue
            if link != target:
                continue
            raw_owner = c.get("certkey", _MISSING)
            issued_name = _readable_name(None if raw_owner is _MISSING else raw_owner)
            if issued_name is None:
                # We know THAT something is issued, but not WHAT. Filling in
                # "(naamloos)" here would push an invented certificate name
                # into the evidence line and into a relink advice.
                cert_unassessed += 1
                seen = shape_or_missing(raw_owner)
                read_gaps.append(
                    ReadGap(
                        source=f"{CERTKEY_RESOURCE} (certificaat {position})",
                        reason=(
                            f"linkcertkeyname wijst naar {label!r}, maar certkey is niet bruikbaar:"
                            f" {seen}; niet vast te stellen WELK certificaat hierdoor uitgegeven wordt"
                        ),
                    )
                )
                continue
            if issued_name == target:
                # ZELFVERWIJZING. `link ssl certKey <root> <root>` is on a
                # real appliance not unthinkable for a self-signed root, so
                # this is source data to RECOGNIZE, not to pass on. Reported
                # once, as itself: "wordt uitgegeven door <zichzelf>" is a
                # sentence that says nothing, and a relink advice pointing at
                # the same certificate is an instruction that cannot be
                # carried out. Deliberately NOT added to `issued`, and the
                # chain step below is skipped: the services on this
                # certificate were already reported by route 1, and walking
                # them again here would put the same virtual server in the
                # answer twice as two separate subjects.
                findings.append(
                    Finding(
                        subject=issued_name,
                        outcome=(
                            "verwijst in linkcertkeyname naar zichzelf; daaruit volgt geen"
                            " aparte uitgifterelatie in deze export"
                        ),
                        certainty=Certainty.ESTABLISHED,
                        evidence=(
                            f"{CERTKEY_RESOURCE}: certkey={issued_name}, linkcertkeyname wijst"
                            f" naar dezelfde naam; {_certificate_role(c)}"
                        ),
                    )
                )
                continue
            if target_link is not None and target_link == issued_name:
                # KRINGVERWIJZING: this certificate says it is issued by the
                # questioned one, while the questioned one says it is issued
                # by this one. Both cannot be true, and this product cannot
                # tell which reading is right - so neither becomes an
                # established fact. Without this guard the two contradictory
                # claims were simply accepted, each on its own turn.
                cert_unassessed += 1
                read_gaps.append(
                    ReadGap(
                        source=f"{CERTKEY_RESOURCE} (certificaat {position})",
                        reason=(
                            f"{issued_name} en {label} wijzen elkaar in linkcertkeyname als uitgever"
                            " aan; die twee lezingen kunnen niet allebei kloppen en het is niet vast"
                            " te stellen welke van de twee juist is"
                        ),
                    )
                )
                continue
            # --- the chain, one step further: which services hang on the
            # certificate this one issues. Only when the binding file itself
            # was read usably - otherwise the read gap above already says
            # that this cannot be established. Collected BEFORE the issuing
            # finding is built, because the closing clause of that finding
            # depends on what was found here.
            behind: list[tuple[str, dict]] = []
            seen_behind: list[str] = []
            if binding_gap is None:
                for b in index.get(issued_name, []):
                    vserver = _readable_name(b.get("vservername")) or "(naamloos)"
                    if vserver in seen_behind:
                        # A service with a regular AND an SNI binding on the
                        # same issued certificate is ONE service, not two.
                        continue
                    seen_behind.append(vserver)
                    behind.append((vserver, b))

            # That nothing was found behind it is a statement about THIS
            # EXPORT, and it belongs to the SAME finding as the issuing
            # relation: one subject, one statement. A second finding on the
            # same subject would put two separate statements about one
            # certificate in the answer. Withheld as long as the binding file
            # was unreadable or one binding could not be assessed - then the
            # absence of hits is worth nothing, exactly as on the direct
            # route.
            tail = ""
            tail_evidence = ""
            if binding_gap is None and not behind and not binding_unassessed:
                tail = "; geen gebonden virtuele servers gevonden in deze export voor dit uitgegeven certificaat"
                tail_evidence = f"; {BINDING_FILE}: gelezen en gecontroleerd, geen binding met de naam {issued_name}"
            findings.append(
                Finding(
                    subject=issued_name,
                    # What the export ESTABLISHES is the link, and what
                    # follows from it for what this appliance PRESENTS. That
                    # a client then rejects the connection is a TLS
                    # conclusion which depends on that client's trust store
                    # and on the role of the certificate - a root belongs in
                    # a trust store, not in the presented chain - and this
                    # export establishes neither. The sentence therefore
                    # stops exactly where the measurement stops, and the
                    # rest is named in CHAIN_DIMENSION above. The raw role
                    # fields travel along in the evidence, so the reader can
                    # judge that role themselves without this product
                    # claiming it.
                    outcome=(
                        f"wordt uitgegeven door {label}; verloopt {label}, dan bevat de keten"
                        f" die met dit certificaat wordt aangeboden een verlopen certificaat{tail}"
                    ),
                    certainty=Certainty.ESTABLISHED,
                    evidence=(
                        f"{CERTKEY_RESOURCE}: certkey={issued_name},"
                        f" linkcertkeyname={raw_link!r}; {issuer_role}{tail_evidence}"
                    ),
                )
            )
            if issued_name not in issued:
                issued.append(issued_name)

            # Deliberately NOT added to `affected`: that collection drives a
            # vserver REBIND in action.py, and the repair for an issuing
            # certificate is a re-LINK of the issued certificate. The role of
            # the binding (the ca flag) is deliberately not interpreted here
            # either: the established statement is that this service hangs on
            # the issued certificate, and that holds regardless of the role.
            # The raw ca/snicert values travel along in the evidence, so the
            # reader sees the source data without this product claiming a role
            # it does not need.
            for vserver, b in behind:
                findings.append(
                    Finding(
                        subject=vserver,
                        outcome=(
                            f"raakt deze virtuele server via {issued_name}; de keten die deze"
                            " dienst aanbiedt bevat dan een verlopen certificaat"
                        ),
                        certainty=Certainty.ESTABLISHED,
                        evidence=(
                            f"{BINDING_FILE}: vservername={vserver},"
                            f" certkeyname={issued_name}, snicert={b.get('snicert')!r},"
                            f" ca={b.get('ca')!r};"
                            f" {CERTKEY_RESOURCE}: certkey={issued_name},"
                            f" linkcertkeyname={raw_link!r}; {issuer_role}"
                        ),
                    )
                )

        if issued and target is not None and target not in known_names:
            # DANGLING UITGIFTERELATIE: certificates in this export name this
            # one as their issuer, but this export carries no certKey by that
            # name. What was found stays established - the relation really is
            # in the export - but the ISSUER itself cannot be read here, so
            # nothing about its expiry, its own chain or its replacement can
            # be established. Reported as a deviation of its own, because
            # silence here reads as "everything about this issuer is known".
            read_gaps.append(
                ReadGap(
                    source=CERTKEY_RESOURCE,
                    reason=(
                        f"certificaten in deze export noemen {label} als uitgever, maar {label}"
                        " staat zelf niet als certKey in deze export; over de uitgever zelf is"
                        " hier dus niets vast te stellen"
                    ),
                )
            )

    # --- route 3: the certificate side - SSL services on this certificate --
    # CERT_SIDE_FILE lists every binding of a certificate, per kind. Read per
    # kind (`CERT_CHILDREN`); the services become findings, a management
    # service of the appliance itself (the built-in denylist) named as such.
    # Three honest outcomes besides the findings: the file is not readable
    # (the boundary in NIET BEOORDEELD, as before this file was read), the
    # questioned certificate has no entry in it (a read gap - its other
    # bindings were never read), or its entry carries a kind this version has
    # no rule for (a read gap naming the kind). Only a KNOWN certificate is
    # looked up: for a name this export does not carry there is nothing on
    # this side to say.
    services: list[str] = []
    side_unassessed = 0
    side_read = False
    other_bindings: list[NotAssessed] = []
    side_grouped, side_gap = export.binding_rows(CERT_SIDE_FILE, children=CERT_CHILDREN)
    side_kinds: dict[str, tuple[str, ...]] = {}
    if side_gap is None:
        side_kinds, side_gap = export.binding_child_keys(CERT_SIDE_FILE)
    if side_gap is not None:
        other_bindings.append(_other_bindings_dimension(side_gap.reason))
    elif cert_gap is None and target is not None and target in known_names:
        pairs = side_grouped.get(target, _MISSING)
        if pairs is _MISSING:
            side_unassessed += 1
            read_gaps.append(
                ReadGap(
                    source=CERT_SIDE_FILE,
                    reason=(
                        f"{CERT_SIDE_FILE} draagt geen parent-vermelding voor {label}; de bindingen"
                        " van dit certificaat buiten virtuele servers zijn niet gelezen"
                    ),
                )
            )
        else:
            side_read = True
            unknown = tuple(kind for kind in side_kinds.get(target, ()) if kind not in CERT_CHILDREN)
            if unknown:
                side_unassessed += 1
                read_gaps.append(
                    ReadGap(
                        source=CERT_SIDE_FILE,
                        reason=(
                            f"{CERT_SIDE_FILE} draagt voor {label} een bindingssoort die deze versie"
                            f" niet leest ({binding_kind_names(unknown)}); of dit certificaat daar ook"
                            " uitvalt, is niet vast te stellen"
                        ),
                    )
                )
            position = 0
            for kind, row in pairs or ():
                # The aggregate shape names the kind; the list shape carries
                # every kind under the file's own resource, and there a row
                # WITH a servicename field is a service binding.
                if kind != SERVICE_CHILD and not (kind == LIST_KIND and "servicename" in row):
                    continue
                position += 1
                raw_service = row.get("servicename", _MISSING)
                service = _readable_name(None if raw_service is _MISSING else raw_service)
                if service is None:
                    side_unassessed += 1
                    read_gaps.append(
                        ReadGap(
                            source=f"{CERT_SIDE_FILE} (service-binding {position})",
                            reason=(
                                f"servicename is niet bruikbaar: {shape_or_missing(raw_service)}; niet vast"
                                f" te stellen welke SSL-dienst aan {label!r} hangt"
                            ),
                        )
                    )
                    continue
                if service in services:
                    continue
                services.append(service)
                findings.append(
                    Finding(
                        subject=service,
                        outcome=(
                            MANAGEMENT_SERVICE_OUTCOME if service.startswith(DENIED_PREFIXES) else SERVICE_OUTCOME
                        ),
                        certainty=Certainty.ESTABLISHED,
                        evidence=f"{CERT_SIDE_FILE}: {kind}, servicename={service}",
                    )
                )

    # --- route 4: use outside the bindings - SAML and SSL servicegroups -----
    # Every reference to this certificate from a SAML action, a SAML IdP
    # profile or an SSL servicegroup binding becomes a finding about the
    # certificate, with the object and the role in the outcome. Looked up for
    # ANY asked name, known certificate or not: the reference is in the
    # export either way. A source this export does not carry is a boundary
    # (NIET BEOORDEELD), never "no use"; a source it carries but could not
    # read, and anything inside one that could hide a reference, is a read
    # gap and withholds the closing statement below.
    other = other_usage(export)
    other_uses: list[CertUse] = []
    other_unassessed = 0
    if target is not None:
        other_gaps = other.gaps_for(target, label)
        other_unassessed += len(other_gaps)
        read_gaps.extend(other_gaps)
        for use in other.uses_of(target):
            findings.append(use.finding(label))
            if use.established:
                other_uses.append(use)
            else:
                # A reference whose role is not established is not a use to
                # base a step on - the same rule as route 1's ca flag.
                other_unassessed += 1
    other_absent = [absent_dimension(reading) for reading in other.absent]

    # --- the closing statement ---------------------------------------------
    # Only when EVERY route was fully readable AND fully assessable, and none
    # found anything, is "nothing found" a finding. One unassessed binding or
    # one unassessed link makes the absence of hits worth nothing, and then
    # we stay silent about it. The wording covers the routes that were read
    # and stays a statement about THIS EXPORT, never a verdict about the
    # world: a certificate whose users this export does not show is not a
    # certificate without users. The Dutch disposal wordings that rules out
    # are pinned in tests/test_word_choice.py and deliberately not repeated
    # here - that gate scans the full source of this module, comments
    # included.
    if (
        binding_gap is None
        and cert_gap is None
        and not matched
        and not issued
        and not services
        and not other_uses
        and not binding_unassessed
        and not cert_unassessed
        and not side_unassessed
        and not other_unassessed
    ):
        # The statement names exactly what was read: the certificate side
        # when it was, and each family of the use outside the bindings whose
        # source was read. A source this export does not carry stands in
        # NIET BEOORDEELD instead, never in this sentence.
        other_read = [reading for reading in other.readings if reading.state == OTHER_READ]
        clauses = ["geen gebonden virtuele servers"]
        if side_read:
            clauses.append("geen gebonden SSL-diensten")
        clauses.append("geen uitgegeven certificaten")
        if other_read:
            clauses.append(f"geen gebruik door {join_list((r.family for r in other_read), 'of')}")
        findings.append(
            Finding(
                subject=certname,
                outcome=f"{join_list(clauses, 'en')} gevonden in deze export",
                certainty=Certainty.ESTABLISHED,
                evidence=(
                    f"{BINDING_FILE}: gelezen en gecontroleerd, geen binding met deze naam;"
                    f" {CERTKEY_RESOURCE}: gelezen en gecontroleerd, geen certificaat met"
                    " linkcertkeyname op deze naam"
                    + (
                        f"; {CERT_SIDE_FILE}: gelezen en gecontroleerd, geen service-binding op deze naam"
                        if side_read
                        else ""
                    )
                    + (
                        f"; {join_list((r.evidence_source for r in other_read), 'en')}: gelezen en"
                        " gecontroleerd, geen verwijzing naar deze naam"
                        if other_read
                        else ""
                    )
                ),
            )
        )

    # After the closing statement, deliberately: that statement is the "not
    # found here" half of the answer, and the candidates are the way forward
    # under it - the same reading order as `dienst_status`.
    if name_candidates is not None:
        findings.append(candidate_finding(label, name_candidates, certificate_count))

    # The usage state of the QUESTIONED certificate, from
    # the SAME derivation as certificaat_wat_verloopt_er
    # (expiry.usage_per_certificate) - one source, two consumers.
    # Function-local import - NOT because it avoids a
    # circularity a module-level import would create: `expiry.py` is already
    # imported at module level above (`Usage`, `RESOURCE as CERTKEY_RESOURCE`),
    # which already executes the whole of `expiry.py` at `impact.py` import
    # time, exactly as importing this one function would. Python imports a
    # module once and caches it either way - there is no circularity
    # difference between the two forms here.
    from nsmcp.expiry import usage_per_certificate

    _found_usage = next((u for u in usage_per_certificate(export) if u.certkey == target), None)
    # `disclosure._limit()` never masks `ImpactAnswer.usage` - it only
    # sweeps `findings`/`read_gaps`/
    # `not_assessed`/`affected_vservers`/`issued_certificates` and does not
    # know this field exists. `_extra_lines()` above already never renders
    # `used_by`, but stripping it HERE closes the leak structurally: even a
    # future caller that reads `.usage` off a rendered `ImpactAnswer`
    # directly (bypassing `to_text()`) cannot see a bound-to/issued name
    # through this field, because it is simply not there to see.
    # `used_elsewhere` for the same reason: the names in it are rendered by
    # this answer's own findings, never through this field.
    usage = replace(_found_usage, used_by=(), used_elsewhere=()) if _found_usage is not None else None

    return ImpactAnswer(
        question=f"wat breekt er als {certname} verloopt",
        findings=findings,
        read_gaps=read_gaps,
        not_assessed=[CHAIN_DIMENSION, *other_bindings, *other_absent],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
        affected_vservers=tuple(affected),
        issued_certificates=tuple(issued),
        name_candidates=name_candidates,
        certificate_count=certificate_count,
        usage=usage,
        affected_services=tuple(services),
        other_uses=tuple(other_uses),
    )
