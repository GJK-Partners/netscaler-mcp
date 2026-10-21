"""Certificate use outside the bindings with virtual servers.

Three sources name a certificate by its certkey name without binding it to a
virtual server, and each of them breaks when that certificate is taken away:

- a SAML action (`config/authenticationsamlaction`): `samlidpcertname`, the
  certificate of the identity provider, and `samlsigningcertname`, the
  certificate this appliance signs its requests with;
- a SAML IdP profile (`config/authenticationsamlidpprofile`):
  `samlidpcertname` and `samlspcertname`;
- the binding of a certificate to an SSL servicegroup
  (`sslservicegroup_sslcertkey_binding.by-parent.json`): `certkeyname` and the
  `ca` flag, one parent per servicegroup, in the same list shape as the
  virtual-server binding file. Its parent list comes from
  `config/sslservicegroup`, and the collector writes the file whenever it read
  that source, with zero parents too. Without the file, that parent source
  still decides: not in the export is "niet vastgesteld"; read and empty is
  established (there is no SSL servicegroup to bind a certificate to); read
  with servicegroups, or not usably read, is a read gap.

The field names are read literally, as the collector writes them. An empty or
absent certificate field is how the collector says "not set"; every other
shape is a read gap, never a silent miss.

THREE STATES PER SOURCE, and they are not interchangeable:
- read: the manifest carries it and it was read into something usable;
- not in the export: the manifest does not carry it - an export of a
  collector that did not fetch it yet. That is "niet vastgesteld", never
  "no use": the certificate tools report it as a boundary of the answer (a
  `NotAssessed`), so an older export keeps its established answer about the
  virtual servers, and the usage state of an otherwise idle certificate is
  "onbekend" instead of "los";
- not usably read: the manifest carries it, but the read failed or the key
  was refused at the export boundary. That is a read gap, and a read gap
  blocks the advice.

One derivation, four consumers: `impact.what_breaks`, `expiry` (usage state),
`coverage` (which of the three was read) and `disclosure` (the names).
"""

from __future__ import annotations

from dataclasses import dataclass

from nsmcp.answer import Certainty, Finding, NotAssessed, ReadGap
from nsmcp.export import MISSING, shape_of, shape_or_missing

SAML_ACTION = "config/authenticationsamlaction"
SAML_IDP_PROFILE = "config/authenticationsamlidpprofile"
SERVICEGROUP_BINDING = "sslservicegroup_sslcertkey_binding.by-parent.json"
# The parent source of that file: every SSL servicegroup. The collector
# writes the binding file whenever it read this source, with zero parents
# too; on an older export that did not, this source still says whether
# there was any SSL servicegroup to bind a certificate to.
SERVICEGROUP_RESOURCE = "config/sslservicegroup"

SAML_ACTION_KIND = "SAML-actie"
SAML_IDP_PROFILE_KIND = "IdP-profiel"
SERVICEGROUP_KIND = "SSL-servicegroup"

READ = "gelezen"
ABSENT = "niet in de export"
UNREADABLE = "niet bruikbaar gelezen"


@dataclass(frozen=True)
class _ObjectSource:
    resource: str
    kind: str
    family: str
    fields: tuple[tuple[str, str], ...]


# Which field names which role - literally the NITRO field names.
_OBJECT_SOURCES = (
    _ObjectSource(
        SAML_ACTION,
        SAML_ACTION_KIND,
        "SAML-acties",
        (("samlidpcertname", "IdP-certificaat"), ("samlsigningcertname", "signing-certificaat")),
    ),
    _ObjectSource(
        SAML_IDP_PROFILE,
        SAML_IDP_PROFILE_KIND,
        "SAML-IdP-profielen",
        (("samlidpcertname", "IdP-certificaat"), ("samlspcertname", "SP-certificaat")),
    ),
)
SERVICEGROUP_FAMILY = "SSL-servicegroups"

# Every source, in the order the answers name them: (source as printed, family).
SOURCES = (*((s.resource, s.family) for s in _OBJECT_SOURCES), (SERVICEGROUP_BINDING, SERVICEGROUP_FAMILY))
# The same list as the closing statement of an impact answer names it.


def join_list(items, last_word: str) -> str:
    """'a', 'a en b', 'a, b en c' - or with 'of' - as the answers write a list."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {last_word} {items[-1]}"


FAMILIES_TEXT = join_list((family for _source, family in SOURCES), "of")
SOURCES_TEXT = join_list((source for source, _family in SOURCES), "en")

# The one sentence for a source key the export boundary refused. The key
# itself is not repeated: it is supplied text of a shape this version does not
# read.
REFUSED_KEY_REASON = (
    "de manifestsleutel van deze bron heeft niet de vorm die deze versie leest en is aan de exportgrens"
    " geweigerd; de bron is niet gelezen"
)

_TRUE_FORMS = {"true", "yes", "1"}
_FALSE_FORMS = {"false", "no", "0"}


@dataclass(frozen=True)
class CertUse:
    """One established reference from an object outside the virtual-server
    bindings to a certificate. `role` is empty when the role itself could not
    be established (an SSL servicegroup binding without a usable ca flag):
    the reference stands, what it means does not - `reason` says why."""

    certkey: str
    kind: str
    owner: str
    role: str
    evidence: str
    reason: str = ""

    @property
    def established(self) -> bool:
        return bool(self.role)

    @property
    def outcome(self) -> str:
        if self.kind == SERVICEGROUP_KIND:
            if not self.role:
                return f"gebonden aan SSL-servicegroup {self.owner}; rol niet vast te stellen"
            return f"gebonden aan SSL-servicegroup {self.owner} ({self.role})"
        return f"gebruikt als {self.role} door {self.kind} {self.owner}"

    @property
    def label(self) -> str:
        """How a step or an expiry line names this use: kind, object, role."""
        return f"{self.kind} {self.owner} ({self.role or 'rol niet vastgesteld'})"

    def finding(self, subject: str) -> Finding:
        return Finding(
            subject=subject,
            outcome=self.outcome,
            certainty=Certainty.ESTABLISHED if self.established else Certainty.NOT_ESTABLISHED,
            evidence=self.evidence,
            reason=self.reason,
        )


@dataclass(frozen=True)
class CertGap:
    """A reference to ONE certificate from an object whose own name is not
    usable. The reference is established - that certificate is in use - but
    which object uses it is not. Rendered per consumer, because the answer
    about that certificate can name it and a list over every certificate
    cannot know it is the one being read."""

    certkey: str
    source: str
    kind: str
    field: str
    shape: str

    def gap(self, subject: str) -> ReadGap:
        return ReadGap(
            source=self.source,
            reason=(
                f"deze {self.kind} verwijst in {self.field} naar {subject}, maar draagt geen bruikbare naam"
                f" ({self.shape}); welke {self.kind} dat is, is niet vast te stellen"
            ),
        )


@dataclass(frozen=True)
class SourceReading:
    source: str
    family: str
    state: str
    reason: str = ""
    # What was actually read, when that is not `source` itself: an export
    # whose parent source says there is no SSL servicegroup at all carries
    # no binding file, and the statement then rests on that parent source.
    read_from: str = ""

    @property
    def evidence_source(self) -> str:
        return self.read_from or self.source


@dataclass(frozen=True)
class OtherUsage:
    """Everything the three sources establish, for every certificate at once.

    `shared_gaps` could hide a reference to ANY certificate (a source that
    was not read, a certificate field that cannot be read, a servicegroup
    whose bindings were not read): as long as one stands, "no use" is not
    established for any certificate. `cert_gaps` belong to one certificate.
    `untrusted` names the sources behind the shared gaps.
    """

    readings: tuple[SourceReading, ...] = ()
    uses: tuple[CertUse, ...] = ()
    shared_gaps: tuple[ReadGap, ...] = ()
    cert_gaps: tuple[CertGap, ...] = ()
    untrusted: tuple[str, ...] = ()

    @property
    def absent(self) -> tuple[SourceReading, ...]:
        return tuple(r for r in self.readings if r.state == ABSENT)

    @property
    def all_read(self) -> bool:
        return bool(self.readings) and all(r.state == READ for r in self.readings)

    @property
    def complete(self) -> bool:
        """Every source read, and nothing in them that could hide a use."""
        return self.all_read and not self.shared_gaps

    def uses_of(self, certkey: str) -> tuple[CertUse, ...]:
        return tuple(u for u in self.uses if u.certkey == certkey)

    def gaps_for(self, certkey: str, subject: str) -> tuple[ReadGap, ...]:
        return self.shared_gaps + tuple(g.gap(subject) for g in self.cert_gaps if g.certkey == certkey)


def absent_dimension(reading: SourceReading) -> NotAssessed:
    """The boundary an answer carries for a source this export does not have."""
    return NotAssessed(subject=f"certificaatgebruik door {reading.family}", reason=absent_reason(reading))


def absent_reason(reading: SourceReading) -> str:
    return (
        f"niet vastgesteld: bron {reading.source} niet in de export; welke certificaten {reading.family}"
        " gebruiken, is met deze export niet vast te stellen"
    )


def _text(value) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _refused(keys, wanted: str) -> bool:
    return any(isinstance(key, str) and key.strip() == wanted for key in keys or ())


def _object_state(export, resource: str) -> str:
    """ABSENT when the manifest does not carry the resource; otherwise the
    reader decides between READ and UNREADABLE.

    An export layer without `status` is an older or stubbed one: it cannot
    say it carries the source, so it does not - the same fail-closed default
    `disclosure.names_from_export` gives a missing method."""
    if _refused(getattr(export, "refused_resource_keys", ()), resource):
        return UNREADABLE
    status = getattr(export, "status", None)
    if not callable(status) or status(resource) == "NIET_IN_MANIFEST":
        return ABSENT
    return READ


def _binding_state(export, file_name: str) -> str:
    key = f"bindings/{file_name}"
    if _refused(getattr(export, "refused_file_keys", ()), key):
        return UNREADABLE
    if getattr(export, "manifest_missing", False) is True:
        return READ
    hashes = getattr(export, "file_hashes", None)
    if not isinstance(hashes, dict) or key not in hashes:
        return ABSENT
    return READ


def _ca_role(value) -> tuple[str, str]:
    """(role, reason-if-unknown) from the ca flag, in both forms NITRO writes
    a boolean. An absent or unrecognized flag is not "no": whether the
    certificate hangs there as a CA or as its own certificate is two
    different repairs."""
    if value is MISSING:
        return "", "ontbreekt in"
    normalized = str(value).strip().lower()
    if normalized in _TRUE_FORMS:
        return "CA: ja", ""
    if normalized in _FALSE_FORMS:
        return "CA: nee", ""
    return "", "heeft een vorm die niet als true/false te herkennen is in"


def _read_objects(export, source: _ObjectSource, uses, shared, cert_gaps, untrusted) -> SourceReading:
    state = _object_state(export, source.resource)
    if state == ABSENT:
        return SourceReading(source.resource, source.family, ABSENT)
    if state == UNREADABLE:
        shared.append(ReadGap(source=source.resource, reason=REFUSED_KEY_REASON))
        untrusted.append(source.resource)
        return SourceReading(source.resource, source.family, UNREADABLE, REFUSED_KEY_REASON)
    rows, gap = export.objects(source.resource)
    if gap is not None:
        shared.append(gap)
        untrusted.append(source.resource)
        return SourceReading(source.resource, source.family, UNREADABLE, gap.reason)
    tainted = False
    for position, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            # `Export.objects()` already refuses this for the whole file; the
            # guard is positive here too, so `.get()` never runs on a string.
            tainted = True
            shared.append(
                ReadGap(
                    source=f"{source.resource} ({source.kind} op positie {position})",
                    reason=f"deze vermelding is {shape_of(row)} in plaats van een object; niet vast te stellen"
                    " welk certificaat ze gebruikt",
                )
            )
            continue
        raw_name = row.get("name", MISSING)
        name = _text(None if raw_name is MISSING else raw_name)
        who = f"{source.kind} {name}" if name else f"{source.kind} op positie {position}"
        for field, role in source.fields:
            raw = row.get(field, MISSING)
            if raw is MISSING or (isinstance(raw, str) and not raw.strip()):
                # Not set: the collector omits the field or leaves it empty.
                continue
            cert = _text(raw)
            if cert is None:
                tainted = True
                shared.append(
                    ReadGap(
                        source=f"{source.resource} ({who})",
                        reason=(
                            f"{field} is niet bruikbaar: {shape_of(raw)}; niet vast te stellen welk"
                            f" certificaat {who} hiermee gebruikt"
                        ),
                    )
                )
                continue
            if name is None:
                cert_gaps.append(
                    CertGap(
                        certkey=cert,
                        source=f"{source.resource} ({who})",
                        kind=source.kind,
                        field=field,
                        shape=shape_or_missing(raw_name),
                    )
                )
                continue
            use = CertUse(
                certkey=cert,
                kind=source.kind,
                owner=name,
                role=role,
                evidence=f"{source.resource}: name={name}, {field}={cert}",
            )
            if use not in uses:
                uses.append(use)
    if tainted:
        untrusted.append(source.resource)
    return SourceReading(source.resource, source.family, READ)


def _read_parent_source_only(export, shared, untrusted) -> SourceReading:
    """No binding file in the manifest: the parent source decides.

    Not in the export -> "niet vastgesteld" (an older collector). Read and
    empty -> established: there is no SSL servicegroup, so there is no
    binding either. Read WITH servicegroups -> a read gap: the file their
    bindings belong in is missing. Not usably read -> a read gap with the
    reason: what the collector could not read is never a boundary."""
    file_name = SERVICEGROUP_BINDING
    parent_state = _object_state(export, SERVICEGROUP_RESOURCE)
    if parent_state == ABSENT:
        return SourceReading(file_name, SERVICEGROUP_FAMILY, ABSENT)
    if parent_state == UNREADABLE:
        gap = ReadGap(source=SERVICEGROUP_RESOURCE, reason=REFUSED_KEY_REASON)
        untrusted.append(SERVICEGROUP_RESOURCE)
    else:
        rows, parent_gap = export.objects(SERVICEGROUP_RESOURCE)
        if parent_gap is None and not rows:
            return SourceReading(file_name, SERVICEGROUP_FAMILY, READ, read_from=SERVICEGROUP_RESOURCE)
        if parent_gap is not None:
            gap = ReadGap(
                source=SERVICEGROUP_RESOURCE,
                reason=(
                    f"{parent_gap.reason}; zonder deze parentbron is niet vast te stellen welke SSL-servicegroups"
                    f" er zijn, en {file_name} staat niet in de export"
                ),
            )
            untrusted.append(SERVICEGROUP_RESOURCE)
        else:
            gap = ReadGap(
                source=file_name,
                reason=(
                    f"{SERVICEGROUP_RESOURCE} kent {len(rows)} SSL-servicegroup(s), maar dit bindingsbestand staat"
                    " niet in de export; welke certificaten daaraan hangen, is niet gelezen"
                ),
            )
            untrusted.append(file_name)
    shared.append(gap)
    return SourceReading(file_name, SERVICEGROUP_FAMILY, UNREADABLE, gap.reason)


def _read_servicegroups(export, uses, shared, untrusted) -> SourceReading:
    file_name = SERVICEGROUP_BINDING
    state = _binding_state(export, file_name)
    if state == ABSENT:
        return _read_parent_source_only(export, shared, untrusted)
    if state == UNREADABLE:
        shared.append(ReadGap(source=file_name, reason=REFUSED_KEY_REASON))
        untrusted.append(file_name)
        return SourceReading(file_name, SERVICEGROUP_FAMILY, UNREADABLE, REFUSED_KEY_REASON)
    grouped, gap = export.binding_rows(file_name)
    flat: list = []
    if gap is None:
        flat, gap = export.bindings(file_name)
    if gap is not None:
        shared.append(gap)
        untrusted.append(file_name)
        return SourceReading(file_name, SERVICEGROUP_FAMILY, UNREADABLE, gap.reason)
    before = len(shared)
    # The grouped read keeps one entry per parent NAME: a parent listed twice
    # overwrites the first, and a parent without a usable name is not grouped
    # at all. The flat read keeps every row. A difference between the two is
    # rows that belong to no parent of their own - never a shorter list
    # posing as complete.
    if sum(len(rows) for rows in grouped.values() if rows) != len(flat):
        shared.append(
            ReadGap(
                source=file_name,
                reason=(
                    "niet elke binding in dit bestand is aan een eigen parent-vermelding toe te wijzen (een"
                    " dubbele of naamloze parent); niet vast te stellen aan welke SSL-servicegroup elk"
                    " certificaat hangt"
                ),
            )
        )
    # A parent that is simply not there leaves no trace in the file; the
    # cross-check against the object source the file itself declares is what
    # makes it visible (see `Export.binding_parents`).
    # Called directly, never through a guard: a reader without the
    # cross-check would count the file as read without it.
    shared.extend(export.binding_parents(file_name).gaps)
    for parent, rows in grouped.items():
        for position, row in enumerate(rows or (), start=1):
            where = f"{file_name} (parent {parent}, binding {position})"
            raw_group = row.get("servicegroupname", MISSING)
            if raw_group is not MISSING and _text(raw_group) != parent:
                shared.append(
                    ReadGap(
                        source=where,
                        reason=(
                            f"de binding onder SSL-servicegroup {parent} noemt in servicegroupname een andere"
                            " servicegroup; niet vast te stellen aan welke SSL-servicegroup dit certificaat hangt"
                        ),
                    )
                )
                continue
            raw_cert = row.get("certkeyname", MISSING)
            cert = _text(None if raw_cert is MISSING else raw_cert)
            if cert is None:
                shared.append(
                    ReadGap(
                        source=where,
                        reason=(
                            f"certkeyname is niet bruikbaar: {shape_or_missing(raw_cert)}; niet vast te"
                            f" stellen welk certificaat aan SSL-servicegroup {parent} hangt"
                        ),
                    )
                )
                continue
            role, unknown = _ca_role(row.get("ca", MISSING))
            flag = {"CA: ja": "ja", "CA: nee": "nee"}.get(role, "niet vast te stellen")
            reason = (
                f"de ca-vlag {unknown} de binding met SSL-servicegroup {parent}, dus of dit certificaat daar"
                " als CA-certificaat of als eigen certificaat hangt, is niet te onderscheiden"
                if unknown
                else ""
            )
            use = CertUse(
                certkey=cert,
                kind=SERVICEGROUP_KIND,
                owner=parent,
                role=role,
                evidence=f"{file_name}: servicegroupname={parent}, certkeyname={cert}, ca={flag}",
                reason=reason,
            )
            if use not in uses:
                uses.append(use)
    if len(shared) > before:
        untrusted.append(file_name)
    return SourceReading(file_name, SERVICEGROUP_FAMILY, READ)


def other_usage(export) -> OtherUsage:
    uses: list[CertUse] = []
    shared: list[ReadGap] = []
    cert_gaps: list[CertGap] = []
    untrusted: list[str] = []
    readings = [_read_objects(export, source, uses, shared, cert_gaps, untrusted) for source in _OBJECT_SOURCES]
    readings.append(_read_servicegroups(export, uses, shared, untrusted))
    return OtherUsage(
        readings=tuple(readings),
        uses=tuple(uses),
        shared_gaps=tuple(shared),
        cert_gaps=tuple(cert_gaps),
        untrusted=tuple(dict.fromkeys(untrusted)),
    )


def absent_dimensions(export) -> list[NotAssessed]:
    """The boundaries for the sources this export does not carry - from the
    manifest alone, without reading any content."""
    return [
        absent_dimension(SourceReading(source, family, ABSENT))
        for source, family in SOURCES
        if _source_absent(export, source)
    ]


def _source_absent(export, source: str) -> bool:
    """Not in the manifest - for the servicegroup file: neither the file nor
    its parent source (see `_read_parent_source_only`)."""
    if source != SERVICEGROUP_BINDING:
        return _object_state(export, source) == ABSENT
    return _binding_state(export, source) == ABSENT and _object_state(export, SERVICEGROUP_RESOURCE) == ABSENT


def coverage_findings(export) -> list[Finding]:
    """One line per source for `rapport_dekking`: read, not in the export, or
    not usably read. A label, not an appliance name (`subject_is_name`).

    A SAML object source that is not usably read already has its line in the
    tally of `rapport_dekking` (GEWEIGERD, MISLUKT, ...), under the same
    subject: it gets no second one here - unless its key was refused at the
    export boundary, because that tally line names the key's shape and not
    this source. The servicegroup file keeps its own line - the reason it was
    not usably read (a missing file next to a parent source with
    servicegroups) is not said anywhere else."""
    findings: list[Finding] = []
    for reading in other_usage(export).readings:
        if reading.state == READ:
            findings.append(
                Finding(
                    subject=reading.source,
                    outcome=f"gelezen (certificaatgebruik door {reading.family})",
                    certainty=Certainty.ESTABLISHED,
                    evidence=(
                        "export-manifest.json"
                        if not reading.read_from
                        else f"export-manifest.json: {reading.read_from} gelezen, zonder SSL-servicegroups"
                    ),
                    subject_is_name=False,
                )
            )
            continue
        if (
            reading.state == UNREADABLE
            and reading.source != SERVICEGROUP_BINDING
            and reading.reason != REFUSED_KEY_REASON
        ):
            # A refused key is the exception: its tally line carries the key's
            # SHAPE, not this source's name, so without its own line the
            # source would vanish from the three.
            continue
        findings.append(
            Finding(
                subject=reading.source,
                outcome=reading.state,
                certainty=Certainty.NOT_ESTABLISHED,
                evidence="export-manifest.json",
                reason=absent_reason(reading) if reading.state == ABSENT else reading.reason,
                subject_is_name=False,
            )
        )
    return findings


def names_in_cert_usage_sources(export) -> tuple[str, ...]:
    """Every object name the three sources can put into an answer: the SAML
    action and IdP profile names, and the servicegroups of the binding file -
    its parents, the servicegroup field of its rows and the object source its
    parent list is cross-checked against. A family of
    `disclosure.names_from_export()`.

    The SAML names come through the trusted object read only: a text of this
    module names an action or profile only after that read succeeded. The
    servicegroup file is harvested more tolerantly (`Export.binding_names`),
    because a read gap of the shared reader names a parent. Nothing from a
    source this export does not carry, and nothing from a file whose hash
    does not match."""
    names: set[str] = set()
    for source in _OBJECT_SOURCES:
        if _object_state(export, source.resource) != READ:
            continue
        rows, gap = export.objects(source.resource)
        if gap is not None:
            continue
        for row in rows:
            name = _text(row.get("name")) if isinstance(row, dict) else None
            if name and name != "(naamloos)":
                names.add(name)
    if _binding_state(export, SERVICEGROUP_BINDING) == READ:
        names.update(export.binding_names((SERVICEGROUP_BINDING,)))
        names.update(n for n in export.binding_parents(SERVICEGROUP_BINDING).names if isinstance(n, str))
    if _object_state(export, SERVICEGROUP_RESOURCE) == READ:
        # The parent source itself: over-collecting is the safe direction,
        # and a cross-check gap names a servicegroup from exactly here.
        rows, gap = export.objects(SERVICEGROUP_RESOURCE)
        for row in rows if gap is None else ():
            name = _text(row.get("servicegroupname")) if isinstance(row, dict) else None
            if name:
                names.add(name)
    return tuple(sorted(n.strip() for n in names if isinstance(n, str) and n.strip() and n.strip() != "(naamloos)"))
